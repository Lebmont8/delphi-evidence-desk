#!/usr/bin/env python3
"""Bounded Delphi evidence preparation and crash-safe outbox; stdlib only."""
import argparse
import datetime as dt
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import sqlite3
import unicodedata
import urllib.error
import urllib.parse
import urllib.request
import uuid

UTC = dt.timezone.utc
MAX_JSON = 1024 * 1024
TERMINAL = {"judged", "rejected", "failed", "unmatched"}
STATUSES = TERMINAL | {"queued", "judging"}
class GateError(ValueError):
    pass

def utcnow():
    return dt.datetime.now(UTC)

def stamp(value):
    if not isinstance(value, str):
        raise GateError("Explicit timezone-aware timestamp required")
    try:
        out = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        raise GateError("Invalid timestamp") from None
    if out.tzinfo is None:
        raise GateError("Timestamp needs timezone")
    return out.astimezone(UTC)

def canonical(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":"))

def digest(value):
    return hashlib.sha256(canonical(value).encode()).hexdigest()

def bounded_text(value, name, limit=16000):
    if not isinstance(value, str) or not value.strip() or len(value.encode()) > limit:
        raise GateError(name + " missing or over local size limit")
    if any(ord(c) < 32 and c not in "\n\t" for c in value):
        raise GateError(name + " contains control characters")
    return value.strip()

def public_url(value):
    value = bounded_text(value, "HTTPS source URL", 4096)
    try:
        p = urllib.parse.urlsplit(value)
        port = p.port
        if p.scheme != "https" or not p.hostname or p.username or p.password or port not in (None, 443):
            raise ValueError()
        host = p.hostname.lower()
        if "." not in host or host.endswith((".localhost", ".local", ".internal")):
            raise ValueError()
        try:
            addr = ipaddress.ip_address(host)
        except ValueError:
            addr = None
        if addr is not None:
            raise ValueError()  # Public evidence uses named sources, never raw IPs.
        if p.fragment:
            raise ValueError()
    except ValueError:
        raise GateError("Use credential-free HTTPS source URLs without fragments or raw IPs") from None
    return value

def normalize_fact(value):
    return " ".join(unicodedata.normalize("NFKC", value).casefold().split())

def market_map(snapshot, now):
    if not isinstance(snapshot, dict) or snapshot.get("kind") != "official-market-snapshot":
        raise GateError("Official market snapshot required (fixtures are not live authority)")
    public_url(snapshot.get("source"))
    acquired = stamp(snapshot.get("retrieved_at"))
    if not 0 <= (now - acquired).total_seconds() <= 300:
        raise GateError("Market snapshot stale or from future; refresh from official competition site")
    items = snapshot.get("markets")
    if not isinstance(items, list):
        raise GateError("Snapshot needs market list")
    out = {}
    for m in items:
        if not isinstance(m, dict):
            raise GateError("Malformed market")
        address = bounded_text(m.get("address"), "market address", 128).lower()
        if address in out:
            raise GateError("Duplicate market identity")
        bounded_text(m.get("question"), "market question", 4096)
        stamp(m.get("evidenceCutoffAt"))
        out[address] = m
    return out

def validate(packet, snapshot, now=None):
    now = now or utcnow()
    if not isinstance(packet, dict) or packet.get("schema") != "delphi-evidence-packet/v1":
        raise GateError("Unsupported evidence packet")
    market = bounded_text(packet.get("market"), "market", 128).lower()
    markets = market_map(snapshot, now)
    if market not in markets:
        raise GateError("Market not in fresh official snapshot")
    m = markets[market]
    if m.get("status") != "open" or stamp(m["evidenceCutoffAt"]) <= now:
        raise GateError("Market closed or evidence cutoff reached")
    claim = bounded_text(packet.get("claim"), "dated factual claim", 8000)
    asof = stamp(packet.get("as_of"))
    if asof > now:
        raise GateError("Fact cannot be dated in future")
    bounded_text(packet.get("relevance"), "explanation of market relevance", 4000)
    review = packet.get("review", {})
    for flag in ("public_sources", "rights_checked", "semantic_novelty_checked", "no_private_individuals"):
        if review.get(flag) is not True:
            raise GateError("Explicit review required: " + flag)
    sources = packet.get("sources")
    if not isinstance(sources, list) or not 1 <= len(sources) <= 10:
        raise GateError("Use 1–10 sources (local bound)")
    links = []
    for source in sources:
        if not isinstance(source, dict):
            raise GateError("Malformed source")
        url = public_url(source.get("url"))
        if url in links:
            raise GateError("Duplicate source URL")
        links.append(url)
        published, retrieved = stamp(source.get("published_at")), stamp(source.get("retrieved_at"))
        if published > retrieved or retrieved > now:
            raise GateError("Source dates inconsistent or in future")
        bounded_text(source.get("quote"), "faithful source quote", 8000)
        bounded_text(source.get("title"), "source title", 1024)
        if source.get("access") != "public-basic-fetch":
            raise GateError("Source needs publicly fetchable evidence; login/paywall is not proof")
    # Retrieval time must never silently stand in for publication date.
    note = "As of " + asof.isoformat() + ": " + claim + "\n\nMarket relevance: " + packet["relevance"].strip()
    for i, source in enumerate(sources, 1):
        note += "\n\n[" + str(i) + "] " + source["title"].strip() + " (published " + source["published_at"] + ")\n" + source["quote"].strip()
    if len(note.encode()) > 24000:
        raise GateError("Evidence note exceeds local 24KB bound")
    payload = {"note": note, "links": links, "marketAddress": m["address"]}
    return {"payload": payload, "packet_sha256": digest(packet),
            "payload_sha256": digest(payload), "fact_sha256": digest(normalize_fact(claim)),
            "market": market, "cutoff": m["evidenceCutoffAt"]}

class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None

class EvidenceAPI:
    """Actual v1 contract, pinned SDK14d706f. No terms-acceptance/trading routes."""
    def __init__(self, base_url, api_key, agent_id):
        public_url(base_url)
        p = urllib.parse.urlsplit(base_url)
        if p.path.rstrip("/") != "/v1" or p.query:
            raise GateError("Verified API base must end at /v1")
        if not isinstance(api_key, str) or not api_key or any(ord(x) < 33 or ord(x) > 126 for x in api_key):
            raise GateError("API key missing or malformed")
        if not re.fullmatch(r"[\x20-\x7e]{1,64}", agent_id):
            raise GateError("Registered X-Agent-Id required, printable ASCII1–64")
        self.base, self.key, self.agent_id = base_url.rstrip("/"), api_key, agent_id
        self.opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())

    def request(self, method, path, payload=None, idempotency_key=None):
        if not path.startswith("/") or path.startswith("//"):
            raise GateError("Invalid API path")
        headers = {"Authorization": "Bearer " + self.key, "X-Agent-Id": self.agent_id,
                   "X-Agent-Harness": "delphi-evidence-desk/1", "Accept": "application/json"}
        data = None
        if method == "POST":
            if path != "/submissions" or payload is None or not idempotency_key:
                raise GateError("Only reserved evidence submission POST is implemented")
            boundary = "desk-" + uuid.uuid4().hex
            parts = []
            fields = [("note", payload["note"]), ("marketAddress", payload["marketAddress"])]
            fields.extend(("links[]", link) for link in payload["links"])
            for key, value in fields:
                parts.append(("--" + boundary + '\r\nContent-Disposition: form-data; name="' + key + '"\r\n\r\n' + value + "\r\n").encode())
            parts.append(("--" + boundary + "--\r\n").encode())
            data = b"".join(parts)
            headers.update({"Content-Type": "multipart/form-data; boundary=" + boundary,
                            "Idempotency-Key": idempotency_key})
        elif method != "GET":
            raise GateError("Unsupported method")
        req = urllib.request.Request(self.base + path, data=data, headers=headers, method=method)
        try:
            with self.opener.open(req, timeout=20) as response:
                raw = response.read(MAX_JSON + 1)
                if len(raw) > MAX_JSON:
                    raise GateError("API response exceeds 1MiB")
                result = json.loads(raw)
                if not isinstance(result, dict):
                    raise GateError("Malformed API response")
                return result
        except urllib.error.HTTPError as e:
            # Never echo arbitrary API text, auth headers or exception URLs.
            raise GateError("API HTTP " + str(e.code) + "; inspect scoped receipt, do not blindly resend") from None
        except (urllib.error.URLError, TimeoutError, OSError, ValueError):
            raise GateError("API transport/JSON failure; reconcile outcome before any resend") from None

    def terms(self):
        return self.request("GET", "/terms")
    def limits(self):
        return self.request("GET", "/limits")
    def entry(self, market):
        return self.request("GET", "/markets/" + urllib.parse.quote(market, safe="") + "/entry-state")
    def submit(self, payload, key):
        return self.request("POST", "/submissions", payload, key)
    def submission(self, identity):
        return self.request("GET", "/submissions/" + urllib.parse.quote(identity, safe=""))
    def submissions(self, market, cursor=None):
        query = {"market": market, "agentId": self.agent_id, "limit": 100}
        if cursor is not None:
            query["cursor"] = cursor
        return self.request("GET", "/submissions?" + urllib.parse.urlencode(query))

def clean_submission(raw):
    """Persist only expected response fields; income requires a separate actual payment receipt."""
    if not isinstance(raw, dict) or raw.get("status") not in STATUSES:
        raise GateError("Invalid submission response; reconcile unknown outcome")
    result = {"id": bounded_text(raw.get("id"), "submission ID", 256),
              "status": raw["status"], "createdAt": raw.get("createdAt"),
              "markets": [], "payment_receipt": None, "accepted_as_award": False}
    stamp(result["createdAt"])
    for m in raw.get("markets", []):
        if not isinstance(m, dict):
            raise GateError("Malformed market response")
        result["markets"].append({k: m.get(k) for k in
                                  ("marketAddress", "status", "verdict", "reason", "bounty", "settlementUpTo", "zeroPayReason")})
    return result

class Outbox:
    def __init__(self, path, agent_id):
        self.db = sqlite3.connect(str(path), timeout=10, isolation_level=None)
        self.db.row_factory = sqlite3.Row
        self.agent_id = bounded_text(agent_id, "registered agent identity", 64)
        self.db.execute("PRAGMA synchronous=FULL")
        self.db.executescript("""
        CREATE TABLE IF NOT EXISTS identity (agent_id TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS intents (
            id TEXT PRIMARY KEY, packet_sha TEXT UNIQUE NOT NULL, fact_sha TEXT NOT NULL,
            market TEXT NOT NULL, packet TEXT NOT NULL, payload TEXT NOT NULL,
            payload_sha TEXT NOT NULL, state TEXT NOT NULL, attempted_at TEXT, receipt TEXT,
            UNIQUE(market,fact_sha));
        """)
        self.db.execute("BEGIN IMMEDIATE")
        try:
            row = self.db.execute("SELECT agent_id FROM identity").fetchone()
            if row and row[0] != self.agent_id:
                raise GateError("Outbox belongs to a different registered identity")
            if not row:
                self.db.execute("INSERT INTO identity VALUES (?)", (self.agent_id,))
            self.db.execute("COMMIT")
        except Exception:
            self.db.execute("ROLLBACK")
            self.db.close()
            raise

    def close(self):
        self.db.close()

    def row(self, intent):
        row = self.db.execute("SELECT * FROM intents WHERE id=?", (intent,)).fetchone()
        if not row:
            raise GateError("Unknown intent")
        return dict(row)

    def reserve(self, packet, snapshot, now=None):
        checked = validate(packet, snapshot, now)
        self.db.execute("BEGIN IMMEDIATE")
        try:
            row = self.db.execute("SELECT id FROM intents WHERE packet_sha=?", (checked["packet_sha256"],)).fetchone()
            if row:
                result = row[0]
            else:
                count = self.db.execute("SELECT count(*) FROM intents WHERE market=?", (checked["market"],)).fetchone()[0]
                if count >= 3:
                    raise GateError("Local three-submission market cap reached, including unresolved attempts")
                result = "desk-" + uuid.uuid4().hex
                self.db.execute("INSERT INTO intents (id,packet_sha,fact_sha,market,packet,payload,payload_sha,state) VALUES (?,?,?,?,?,?,?,?)",
                    (result, checked["packet_sha256"], checked["fact_sha256"], checked["market"],
                     canonical(packet), canonical(checked["payload"]), checked["payload_sha256"], "reserved"))
            self.db.execute("COMMIT")
            return result
        except sqlite3.IntegrityError:
            self.db.execute("ROLLBACK")
            raise GateError("Same normalized fact already reserved for this market") from None
        except Exception:
            self.db.execute("ROLLBACK")
            raise

    def dispatch_once(self, intent, api, snapshot, authorization, now=None):
        """Library integration only. Owner controller must reserve external effect first."""
        now = now or utcnow()
        row = self.row(intent)
        if row["state"] != "reserved":
            raise GateError("Intent already attempted; reconcile instead of resend")
        if api.agent_id != self.agent_id:
            raise GateError("API identity differs from outbox")
        for gate in ("registration_verified", "external_effect_reserved", "scope_authorized"):
            if authorization.get(gate) is not True:
                raise GateError("Owner controller prerequisite missing: " + gate)
        if not authorization.get("effect_key") or authorization.get("payload_sha256") != row["payload_sha"]:
            raise GateError("External effect reservation must bind exact payload")
        checked = validate(json.loads(row["packet"]), snapshot, now)
        if checked["payload_sha256"] != row["payload_sha"]:
            raise GateError("Reserved payload changed")
        terms = api.terms()
        if not terms.get("acceptedAt") or terms.get("version") != authorization.get("owner_accepted_terms_version"):
            raise GateError("Owner must review/accept exact current terms; this tool never accepts terms")
        if stamp(terms["acceptedAt"]) > now:
            raise GateError("Terms acceptance timestamp in future")
        limits, entry = api.limits(), api.entry(checked["payload"]["marketAddress"])
        if limits.get("submitsLeftThisHour", 0) <= 0 or entry.get("canSubmit") is not True or entry.get("remainingOnMarket", 0) <= 0:
            raise GateError("Server submission limits/entry-state do not permit dispatch")
        # Durable CAS before network. A crash immediately afterwards is UNKNOWN too.
        changed = self.db.execute("UPDATE intents SET state='unknown',attempted_at=? WHERE id=? AND state='reserved'", (now.isoformat(),intent)).rowcount
        if changed != 1:
            raise GateError("Another process already attempted this intent")
        raw = api.submit(checked["payload"], intent)  # exactly one attempt; no built-in retry
        receipt = clean_submission(raw)
        self.db.execute("UPDATE intents SET state='confirmed',receipt=? WHERE id=?", (canonical(receipt), intent))
        return receipt

    def reconcile(self, intent, api):
        row = self.row(intent)
        if api.agent_id != self.agent_id:
            raise GateError("API identity differs from outbox")
        if row["state"] == "confirmed":
            return json.loads(row["receipt"])
        if row["state"] != "unknown":
            raise GateError("No uncertain dispatch to reconcile")
        payload, matches, seen, cursor = json.loads(row["payload"]), {}, set(), None
        for _ in range(100):
            page = api.submissions(payload["marketAddress"], cursor)
            if not isinstance(page.get("items"), list) or "nextCursor" not in page:
                raise GateError("Incomplete reconciliation page; keep outcome unknown")
            for item in page["items"]:
                markets = item.get("markets", [])
                if (item.get("agentId") == self.agent_id and item.get("note") == payload["note"]
                    and item.get("links") == payload["links"]
                    and stamp(item.get("createdAt")) >= stamp(row["attempted_at"]) - dt.timedelta(seconds=5)
                    and any(str(m.get("marketAddress", "")).lower() == row["market"] for m in markets)):
                    clean = clean_submission(item)
                    matches[clean["id"]] = clean
            cursor = page["nextCursor"]
            if cursor is None:
                break
            if not isinstance(cursor, str) or not cursor or cursor in seen:
                raise GateError("Invalid/repeated pagination cursor; outcome remains unknown")
            seen.add(cursor)
        else:
            raise GateError("Reconciliation bounded at 100pages; outcome remains unknown")
        if len(matches) != 1:
            raise GateError("No unique server receipt; keep unknown, do not resubmit")
        receipt = next(iter(matches.values()))
        self.db.execute("UPDATE intents SET state='confirmed',receipt=? WHERE id=? AND state='unknown'",
                        (canonical(receipt), intent))
        return receipt

    def refresh(self, intent, api):
        """One read, no retry/poll loop; organizer status is not a payment receipt."""
        row = self.row(intent)
        if row["state"] != "confirmed" or api.agent_id != self.agent_id:
            raise GateError("Only confirmed matching-identity receipts can be refreshed")
        previous = json.loads(row["receipt"])
        fresh = clean_submission(api.submission(previous["id"]))
        if fresh["id"] != previous["id"]:
            raise GateError("Receipt identity changed")
        self.db.execute("UPDATE intents SET receipt=? WHERE id=? AND state='confirmed'",
                        (canonical(fresh), intent))
        return fresh

def read_json(path):
    with open(path, "rb") as f:
        raw = f.read(MAX_JSON + 1)
    if len(raw) > MAX_JSON:
        raise GateError("Input exceeds 1MiB")
    return json.loads(raw)

def main(argv=None):
    parser = argparse.ArgumentParser(description="Offline Delphi evidence QA and durable outbox; no live POST CLI")
    commands = parser.add_subparsers(dest="command", required=True)
    for name in ("check", "render", "reserve"):
        p = commands.add_parser(name)
        p.add_argument("packet"); p.add_argument("snapshot")
        if name == "reserve":
            p.add_argument("--db", required=True); p.add_argument("--agent-id", required=True)
    p = commands.add_parser("status")
    p.add_argument("--db", required=True); p.add_argument("--agent-id", required=True)
    args = parser.parse_args(argv)
    box = None
    try:
        if args.command in ("check", "render", "reserve"):
            packet, snapshot = read_json(args.packet), read_json(args.snapshot)
            checked = validate(packet, snapshot)
            if args.command == "render":
                print(json.dumps({"payload": checked["payload"], "submitted": False}, ensure_ascii=False))
            elif args.command == "check":
                print(json.dumps({"valid": True, "payload_sha256": checked["payload_sha256"],
                                  "market": checked["market"], "cutoff": checked["cutoff"], "submitted": False}))
            else:
                box = Outbox(args.db, args.agent_id)
                intent = box.reserve(packet, snapshot)
                print(json.dumps({"intent": intent, "state": box.row(intent)["state"], "submitted": False}))
        else:
            if not Path(args.db).is_file():
                raise GateError("Outbox does not exist")
            box = Outbox(args.db, args.agent_id)
            rows = [dict(r) for r in box.db.execute("SELECT id,market,state,receipt FROM intents")]
            for row in rows:
                row["receipt"] = json.loads(row["receipt"]) if row["receipt"] else None
            print(json.dumps({"intents": rows, "income": None}))
        return 0
    except (GateError, OSError, ValueError, sqlite3.Error):
        # Input may contain secrets; never print raw parser/OS exceptions.
        print(json.dumps({"ok": False, "error": "Input, gate or storage validation failed; inspect locally against README"}))
        return 2
    finally:
        if box:
            box.close()

if __name__ == "__main__":
    raise SystemExit(main())
