# Install PANCITO-RED-TEAM

## Requirements

- Python 3.10 or newer
- Git
- `pytest` for verification
- Velociraptor only for the optional live collection validator

The replay and sealed decision path is dependency-free Python. The inherited
web/agent service has additional dependencies in `requirements.txt`.

## Local environment

Linux/macOS:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e '.[dev]'
```

Windows PowerShell:

```powershell
py -3 -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -e ".[dev]"
```

## Verify the offensive boundary

```bash
python3 -m pytest tests/test_offensive_engagement.py tests/test_offensive_replay.py
python3 -m pytest tests/test_determinism.py
```

Run the full inherited suite with its case store forced to memory:

```bash
VIGIA_CASE_BACKEND=memory python3 -m pytest
```

## Optional inherited service

The service is retained because its case, custody, agent, and Kassandra paths
are connected and tested. Its investigation transport is currently fixture
replay, not a live target transport.

```bash
pip install -r requirements.txt
VIGIA_CASE_BACKEND=memory uvicorn service.app:app --port 8080
```

Use `POST /injection-validation` for the attacker-controlled-evidence check.
Do not deploy the inherited service publicly without configuring identity,
persistent storage, model quotas, and a private Kassandra salt.

## Optional live collection validation

Fetch the signed Velociraptor binary, then validate the collection-to-seal
path:

```bash
scripts/setup_velociraptor.sh
python3 scripts_lib/validate_live_velociraptor.py
```

On Windows, run `scripts/setup_velociraptor.sh` from Git Bash and execute the
validator from an elevated terminal. This validates collection; it does not
expand the offensive replay catalogue or authorize a remote target.
