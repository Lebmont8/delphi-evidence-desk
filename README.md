# Delphi Evidence Desk
Check a market evidence packet before submitting it elsewhere. The Python CLI checks the market ID, deadline, source dates, rights-review flags, and packet limits. It produces a review note and records a local reservation without duplicating an existing one. It does not submit the packet.

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
