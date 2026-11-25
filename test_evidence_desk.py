import copy
import datetime as dt
import io
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import sys
import tempfile
import unittest
import urllib.error
from evidence_desk import *

NOW = dt.datetime(2026, 11, 26, 18, 0, tzinfo=UTC)

def sample():
    packet = {"schema": "delphi-evidence-packet/v1", "market": "fixture-market-a",
        "as_of": "2026-11-26T17:30:00Z", "claim": "Synthetic fixture: agency reports 17 units.",
        "relevance": "Fixture only: count affects the stated threshold.",
        "review": {x: True for x in ("public_sources", "rights_checked", "semantic_novelty_checked", "no_private_individuals")},
        "sources": [{"url": "https://example.org/release", "title": "Synthetic test release",
            "published_at": "2026-11-26T17:30:00Z", "retrieved_at": "2026-11-26T17:35:00Z",
            "quote": "Synthetic fixture reports 17 units.", "access": "public-basic-fetch"}]}
    snapshot = {"kind": "official-market-snapshot", "source": "https://example.org/markets.json",
        "retrieved_at": NOW.isoformat(), "markets": [{"address": "fixture-market-a", "question": "Fixture only: above 10 units?",
        "status": "open", "evidenceCutoffAt": "2026-12-01T17:00:00Z"}]}
    return packet, snapshot

class FakeAPI:
    agent_id = "fixture-agent"
    def __init__(self):
        self.posts = 0; self.pages = []; self.fail = False
        self.terms_value = {"version": "fixture-v1", "acceptedAt": "2026-11-25T17:00:00Z"}
        self.limits_value = {"submitsLeftThisHour": 4, "dailyCapLeft": 2}
        self.entry_value = {"canSubmit": True, "remainingOnMarket": 3}
        self.receipt = None
    def terms(self): return self.terms_value
    def limits(self): return self.limits_value
    def entry(self, market): return self.entry_value
    def submit(self, payload, key):
        self.posts += 1
        self.receipt = {"id": "remote1", "createdAt": NOW.isoformat(), "agentId": self.agent_id,
            "note": payload["note"], "links": payload["links"], "status": "queued",
            "markets": [{"marketAddress": payload["marketAddress"], "status": "queued", "bounty": None}]}
        if self.fail: raise TimeoutError("fixture dropped response after server persisted")
        return self.receipt
    def submission(self, identity): return self.receipt
    def submissions(self, market, cursor=None):
        if self.pages:
            index = int(cursor or "0")
            return self.pages[index]
        return {"items": [self.receipt] if self.receipt else [], "nextCursor": None}

class DeskTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.path = Path(self.temp.name) / "outbox.db"
        self.box = Outbox(self.path, "fixture-agent")
        self.packet, self.snapshot = sample()
        self.api = FakeAPI()
    def tearDown(self):
        self.box.close(); self.temp.cleanup()
    def reserve(self): return self.box.reserve(self.packet, self.snapshot, NOW)
    def auth(self, intent):
        return {"registration_verified": True, "external_effect_reserved": True, "scope_authorized": True,
            "effect_key": "fixture-controller-reservation", "owner_accepted_terms_version": "fixture-v1",
            "payload_sha256": self.box.row(intent)["payload_sha"]}
    def dispatch(self, intent, auth=None):
        return self.box.dispatch_once(intent, self.api, self.snapshot, auth or self.auth(intent), NOW)
    def invalid(self, mutate):
        mutate()
        with self.assertRaises(GateError): validate(self.packet, self.snapshot, NOW)
    def test_valid_packet_provenance(self):
        result = validate(self.packet, self.snapshot, NOW)
        self.assertIn("published 2026-11-26T17:30:00Z", result["payload"]["note"])
        self.assertNotIn("17:35", result["payload"]["note"])
    def test_closed_market(self): self.invalid(lambda: self.snapshot["markets"][0].update(status="closed"))
    def test_cutoff_equal_now(self): self.invalid(lambda: self.snapshot["markets"][0].update(evidenceCutoffAt=NOW.isoformat()))
    def test_unknown_market(self): self.invalid(lambda: self.packet.update(market="missing"))
    def test_stale_snapshot(self): self.invalid(lambda: self.snapshot.update(retrieved_at=(NOW-dt.timedelta(seconds=301)).isoformat()))
    def test_future_snapshot(self): self.invalid(lambda: self.snapshot.update(retrieved_at=(NOW+dt.timedelta(seconds=1)).isoformat()))
    def test_ambiguous_duplicate_market(self): self.invalid(lambda: self.snapshot["markets"].append(copy.deepcopy(self.snapshot["markets"][0])))
    def test_explicit_aware_dates(self): self.invalid(lambda: self.packet.update(as_of="2026-11-26"))
    def test_future_fact(self): self.invalid(lambda: self.packet.update(as_of="2026-11-27T00:00:00Z"))
    def test_publication_after_retrieval(self): self.invalid(lambda: self.packet["sources"][0].update(published_at="2026-11-26T17:40:00Z"))
    def test_retrieval_in_future(self): self.invalid(lambda: self.packet["sources"][0].update(retrieved_at="2026-11-27T00:00:00Z"))
    def test_no_silent_publication_date(self):
        self.packet["sources"][0].pop("published_at")
        with self.assertRaises(GateError): validate(self.packet, self.snapshot, NOW)
    def test_review_cannot_be_string_true(self): self.invalid(lambda: self.packet["review"].update(rights_checked="true"))
    def test_semantic_novelty_review_required(self): self.invalid(lambda: self.packet["review"].update(semantic_novelty_checked=False))
    def test_login_source_refused(self): self.invalid(lambda: self.packet["sources"][0].update(access="login"))
    def test_empty_quote(self): self.invalid(lambda: self.packet["sources"][0].update(quote=""))
    def test_duplicate_urls(self): self.invalid(lambda: self.packet["sources"].append(copy.deepcopy(self.packet["sources"][0])))
    def test_unsafe_urls(self):
        for url in ("http://example.org", "https://u:p@example.org", "https://127.0.0.1/a",
                    "https://host.local/x", "https://example.org:444/x", "https://example.org/#token"):
            with self.subTest(url=url), self.assertRaises(GateError): public_url(url)
    def test_local_size_limit(self): self.invalid(lambda: self.packet.update(claim="x"*8001))
    def test_stable_reserve_across_restart(self):
        first = self.reserve()
        self.box.close(); self.box = Outbox(self.path, "fixture-agent")
        self.assertEqual(first, self.reserve())
        self.assertEqual(self.box.row(first)["state"], "reserved")
    def test_cross_identity_reopen_refused(self):
        with self.assertRaises(GateError): Outbox(self.path, "another-agent")
    def test_same_fact_new_url_is_not_novel(self):
        self.reserve(); self.packet["sources"][0]["url"] = "https://example.org/newurl"
        self.packet["claim"] = "  SYNTHETIC fixture: agency reports 17 units. "
        with self.assertRaises(GateError): self.reserve()
    def test_three_local_slots_including_reservations(self):
        for i in range(3):
            self.packet["claim"] = "Different synthetic fact " + str(i); self.reserve()
        self.packet["claim"] = "Fourth synthetic fact"
        with self.assertRaises(GateError): self.reserve()
    def test_state_committed_before_network_call(self):
        intent = self.reserve()
        original = self.api.submit
        def probe(payload, key):
            connection = sqlite3.connect(self.path)
            self.assertEqual(connection.execute("SELECT state FROM intents WHERE id=?", (intent,)).fetchone()[0], "unknown")
            connection.close()
            return original(payload, key)
        self.api.submit = probe
        receipt = self.dispatch(intent)
        self.assertEqual(receipt["id"], "remote1"); self.assertEqual(self.api.posts, 1)
    def test_exact_payload_authority_required(self):
        intent = self.reserve(); auth = self.auth(intent); auth["payload_sha256"] = "wrong"
        with self.assertRaises(GateError): self.dispatch(intent, auth)
        self.assertEqual(self.api.posts, 0)
    def test_no_registration_no_post(self):
        intent = self.reserve(); auth = self.auth(intent); auth["registration_verified"] = False
        with self.assertRaises(GateError): self.dispatch(intent, auth)
        self.assertEqual(self.api.posts, 0)
    def test_unaccepted_terms_no_post(self):
        intent = self.reserve(); self.api.terms_value["acceptedAt"] = None
        with self.assertRaises(GateError): self.dispatch(intent)
        self.assertEqual(self.api.posts, 0)
    def test_changed_terms_no_post(self):
        intent = self.reserve(); self.api.terms_value["version"] = "fixture-v2"
        with self.assertRaises(GateError): self.dispatch(intent)
        self.assertEqual(self.api.posts, 0)
    def test_limits_no_post(self):
        intent = self.reserve(); self.api.limits_value["submitsLeftThisHour"] = 0
        with self.assertRaises(GateError): self.dispatch(intent)
        self.assertEqual(self.api.posts, 0)
    def test_entry_refusal_no_post(self):
        intent = self.reserve(); self.api.entry_value["canSubmit"] = False
        with self.assertRaises(GateError): self.dispatch(intent)
        self.assertEqual(self.api.posts, 0)
    def test_stale_at_dispatch_no_post(self):
        intent = self.reserve()
        with self.assertRaises(GateError):
            self.box.dispatch_once(intent, self.api, self.snapshot, self.auth(intent), NOW+dt.timedelta(minutes=6))
        self.assertEqual(self.api.posts, 0)
    def test_timeout_never_resends_across_restart(self):
        intent = self.reserve(); self.api.fail = True
        with self.assertRaises(TimeoutError): self.dispatch(intent)
        self.box.close(); self.box = Outbox(self.path, "fixture-agent")
        self.assertEqual(self.box.row(intent)["state"], "unknown")
        with self.assertRaises(GateError): self.dispatch(intent)
        self.assertEqual(self.api.posts, 1)
        self.assertEqual(self.box.reconcile(intent, self.api)["id"], "remote1")
        self.assertEqual(self.api.posts, 1)
    def test_no_match_stays_unknown(self):
        intent = self.reserve(); self.api.fail = True
        with self.assertRaises(TimeoutError): self.dispatch(intent)
        self.api.receipt = None
        with self.assertRaises(GateError): self.box.reconcile(intent, self.api)
        self.assertEqual(self.box.row(intent)["state"], "unknown")
    def test_paginated_receipt(self):
        intent = self.reserve(); self.api.fail = True
        with self.assertRaises(TimeoutError): self.dispatch(intent)
        self.api.pages = [{"items": [], "nextCursor": "1"}, {"items": [self.api.receipt], "nextCursor": None}]
        self.assertEqual(self.box.reconcile(intent, self.api)["id"], "remote1")
    def test_ambiguous_receipt_stays_unknown(self):
        intent = self.reserve(); self.api.fail = True
        with self.assertRaises(TimeoutError): self.dispatch(intent)
        another = copy.deepcopy(self.api.receipt); another["id"] = "remote2"
        self.api.pages = [{"items": [self.api.receipt, another], "nextCursor": None}]
        with self.assertRaises(GateError): self.box.reconcile(intent, self.api)
        self.assertEqual(self.box.row(intent)["state"], "unknown")
    def test_repeated_cursor_stays_unknown(self):
        intent = self.reserve(); self.api.fail = True
        with self.assertRaises(TimeoutError): self.dispatch(intent)
        self.api.pages = [{"items": [], "nextCursor": "0"}]
        with self.assertRaises(GateError): self.box.reconcile(intent, self.api)
    def test_wrong_identity_not_receipt(self):
        intent = self.reserve(); self.api.fail = True
        with self.assertRaises(TimeoutError): self.dispatch(intent)
        self.api.receipt["agentId"] = "different"
        with self.assertRaises(GateError): self.box.reconcile(intent, self.api)
    def test_rejected_is_receipt_not_resend(self):
        intent = self.reserve(); original = self.api.submit
        def reject(payload, key):
            raw = original(payload, key); raw["status"] = "rejected"; return raw
        self.api.submit = reject
        self.assertEqual(self.dispatch(intent)["status"], "rejected")
        with self.assertRaises(GateError): self.dispatch(intent)
        self.assertEqual(self.api.posts, 1)
    def test_malformed_receipt_stays_unknown(self):
        intent = self.reserve(); self.api.submit = lambda p,k: {"status": "invented"}
        with self.assertRaises(GateError): self.dispatch(intent)
        self.assertEqual(self.box.row(intent)["state"], "unknown")
    def test_reported_paid_is_not_verified_income(self):
        raw = {"id": "r", "createdAt": NOW.isoformat(), "status": "judged", "markets": [
            {"marketAddress": "fixture-market-a", "bounty": {"amount": "100", "state": "paid"}}]}
        result = clean_submission(raw)
        self.assertIsNone(result["payment_receipt"]); self.assertFalse(result["accepted_as_award"])
    def test_adapter_wire_contract_no_external_network(self):
        api = EvidenceAPI("https://example.org/v1", "fixture-key-not-real", "fixture-agent")
        captured = []
        class Response:
            def __enter__(self): return self
            def __exit__(self,*a): pass
            def read(self,limit): return b'{"status":"queued"}'
        class Opener:
            def open(self,request,timeout):
                captured.append(request); return Response()
        api.opener = Opener()
        payload = validate(self.packet, self.snapshot, NOW)["payload"]
        api.submit(payload, "stable-key")
        req = captured[0]
        self.assertEqual(req.full_url, "https://example.org/v1/submissions")
        self.assertEqual(req.get_header("Idempotency-key"), "stable-key")
        self.assertEqual(req.get_header("Authorization"), "Bearer fixture-key-not-real")
        self.assertIn(b'name="links[]"', req.data)
        self.assertIn(b'name="marketAddress"', req.data)
        with self.assertRaises(GateError): api.request("POST", "/terms/acceptance", {})
    def test_adapter_error_redacts_arbitrary_body(self):
        api = EvidenceAPI("https://example.org/v1", "fixture-key-not-real", "fixture-agent")
        class Opener:
            def open(self,*a,**k):
                raise urllib.error.HTTPError("https://example.org/v1", 403, "fixture-key-not-real", {}, io.BytesIO(b"fixture-key-not-real"))
        api.opener = Opener()
        with self.assertRaises(GateError) as raised: api.terms()
        self.assertNotIn("fixture-key-not-real", str(raised.exception))
    def test_redirect_disabled(self):
        self.assertIsNone(NoRedirect().redirect_request(None,None,302,"",{}, "https://other.example/"))
    def test_old_remote_content_not_fresh_receipt(self):
        intent = self.reserve(); self.api.fail = True
        with self.assertRaises(TimeoutError): self.dispatch(intent)
        self.api.receipt["createdAt"] = (NOW-dt.timedelta(days=1)).isoformat()
        with self.assertRaises(GateError): self.box.reconcile(intent, self.api)
        self.assertEqual(self.box.row(intent)["state"], "unknown")
    def test_refresh_get_only_and_pending_not_final(self):
        intent = self.reserve(); self.dispatch(intent)
        self.api.receipt["status"] = "judging"
        self.assertEqual(self.box.refresh(intent, self.api)["status"], "judging")
        self.api.receipt["status"] = "judged"
        fresh = self.box.refresh(intent, self.api)
        self.assertIsNone(fresh["payment_receipt"]); self.assertEqual(self.api.posts,1)
    def test_refresh_mismatched_receipt_refused(self):
        intent = self.reserve(); self.dispatch(intent); self.api.receipt["id"] = "other"
        with self.assertRaises(GateError): self.box.refresh(intent, self.api)
        self.assertEqual(json.loads(self.box.row(intent)["receipt"])["id"], "remote1")
    def test_concurrent_dispatchers_only_one_post(self):
        import threading
        intent = self.reserve(); auth = self.auth(intent)
        barrier = threading.Barrier(2, timeout=5)
        original = self.api.terms
        self.api.terms = lambda: (barrier.wait(), original())[1]
        outcomes = []
        def worker():
            box = Outbox(self.path, "fixture-agent")
            try:
                box.dispatch_once(intent, self.api, self.snapshot, auth, NOW)
                outcomes.append("sent")
            except GateError:
                outcomes.append("blocked")
            finally:
                box.close()
        a,b = threading.Thread(target=worker), threading.Thread(target=worker)
        a.start(); b.start(); a.join(8); b.join(8)
        self.assertFalse(a.is_alive() or b.is_alive())
        self.assertCountEqual(outcomes, ["sent", "blocked"])
        self.assertEqual(self.api.posts, 1)
    def test_cli_real_subprocess(self):
        current = utcnow()
        # Synthetic demo is explicitly generated at runtime, never passed off as live evidence.
        self.snapshot["retrieved_at"] = current.isoformat()
        self.snapshot["markets"][0]["evidenceCutoffAt"] = (current+dt.timedelta(days=1)).isoformat()
        self.packet["as_of"] = (current-dt.timedelta(hours=2)).isoformat()
        self.packet["sources"][0]["published_at"] = self.packet["as_of"]
        self.packet["sources"][0]["retrieved_at"] = (current-dt.timedelta(hours=1)).isoformat()
        p,s = Path(self.temp.name)/"packet.json", Path(self.temp.name)/"markets.json"
        p.write_text(json.dumps(self.packet)); s.write_text(json.dumps(self.snapshot))
        command = [sys.executable, "-B", str(Path(__file__).with_name("evidence_desk.py"))]
        first = subprocess.run(command+["check",str(p),str(s)],capture_output=True,text=True)
        self.assertEqual(first.returncode, 0, first.stdout)
        self.assertTrue(json.loads(first.stdout)["valid"])
        live = subprocess.run(command+["submit"],capture_output=True,text=True)
        self.assertNotEqual(live.returncode, 0)
        for _ in range(2):
            reserved = subprocess.run(command+["reserve",str(p),str(s),"--db",str(self.path),"--agent-id","fixture-agent"],capture_output=True,text=True)
            self.assertEqual(reserved.returncode,0,reserved.stdout)
        status = subprocess.run(command+["status","--db",str(self.path),"--agent-id","fixture-agent"],capture_output=True,text=True)
        body = json.loads(status.stdout)
        self.assertEqual(len(body["intents"]),1); self.assertIsNone(body["income"])

if __name__ == "__main__":
    unittest.main(verbosity=2)
