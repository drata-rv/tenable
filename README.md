# Tenable Nessus (On-Prem) → Drata Custom Connection

Collects CIS compliance-audit check results from an on-premises Tenable Nessus
Professional console and pushes them into a Drata Custom Connection as
host-grain evidence records for Custom Tests.

Read-only against Nessus. Never launches, stops, or configures a scan — it
consumes results that already exist.

The full technical contract (API endpoints, schema, exit codes, acceptance
tests) lives in the Tenable Nessus → Drata Custom Connection MVP build
specification maintained by the Drata Solutions Architects Team; it is not
part of this repository. See the Runbook section there for one-time setup.

## Quick start (offline, no credentials)

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e ".[test]"

cp config/config.example.yaml config/config.yaml
cp config/checks.example.yaml config/checks.yaml

python -m nessus_drata.cli validate-config
python -m nessus_drata.cli gen-schema
python -m nessus_drata.cli run --fixtures tests/fixtures/sample_small.nessus --dry-run
```

## Live usage

Requires `NESSUS_ACCESS_KEY`, `NESSUS_SECRET_KEY`, `DRATA_API_KEY`. Put them
in a gitignored `.env`:

```bash
cp config/.env.example config/.env   # then paste the three values after the "="
```

`.env` is read from next to `--config` (the `config/` folder), then from the
working directory; `--env-file PATH` (before the subcommand) overrides both.
Real environment variables, such as the machine-scope ones set by
`windows/set_machine_env.ps1`, take precedence over the file. Only those three
names are read. See Section 11 (Runbook) of the spec for one-time setup and
Section 9 for the Windows Scheduled Task deployment.

```bash
python -m nessus_drata.cli probe-nessus
python -m nessus_drata.cli probe-drata
python -m nessus_drata.cli run --dry-run
python -m nessus_drata.cli run
```
