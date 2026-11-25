# Delphi Evidence Desk
A standard-library Python tool for validating source-grounded evidence packets and tracking a durable local submission outbox.

It checks market identity, deadlines, source dates, rights-review flags and packet bounds; renders a reviewable note; and reserves an idempotent local record before an explicitly integrated external adapter is used.

Python 3.10+; no packages are required.
~~~sh
python3 -B -m unittest -v test_evidence_desk
python3 -B evidence_desk.py --help
~~~
The test fixtures are synthetic. Provide your own genuine market snapshot and reviewed public evidence. A reservation is not a submission, acceptance or payment.

No signing, wallet, model API, account registration, terms acceptance, automatic scheduler or live submission CLI is bundled. The tool never turns unverified dates or facts into evidence.

MIT licensed. Original implementation developed with AI assistance.

## Continuous integration
A reference GitHub Actions workflow is included at ci/github-actions.yml. To activate it in your own repository, place it under .github/workflows/. Its presence as a reference does not mean hosted CI is enabled or has passed.
