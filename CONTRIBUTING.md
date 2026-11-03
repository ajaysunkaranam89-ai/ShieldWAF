# Contributing

Thank you for helping! A Shield WAF is a free, open-source project. Bug reports, ideas, documentation fixes and code are all welcome.

## Before you start
- **Security problems:** do not open a public issue. Follow `SECURITY.md` ("Reporting a vulnerability").
- **Questions and ideas:** open an issue and describe what you want to achieve; small, focused changes are easiest to review.
- By contributing you agree that your contribution is licensed under the project's licence (Apache-2.0).

## How the project is organised
| Path | What |
|---|---|
| `panel/` | the control panel: `app.py` (routes), `engine.py` (renders nginx + ModSecurity configuration), `store.py` (PostgreSQL / SQLite), `security.py`, `alerts.py`, `feeds.py`, `crsupdate.py`, `openapi.py`, `background.py`, `templates/`, `static/`, `njs/` (anti-bot challenge) |
| `Dockerfile`, `db/Dockerfile` | the two images |
| `k8s/shieldwaf.yaml`, `scripts/` | deployment |
| `tests/` | the regression suite |
| `docs/`, `*.md` | documentation |

## Development tips
- Python 3.12, Flask. The panel can run against SQLite for quick local work (no `SHIELD_DB_URL` set); production uses PostgreSQL. Write SQL that works on both (use `?` placeholders, avoid dialect-specific functions, or use the helpers in `store.py`).
- The panel never runs a shell with user input. Keep it that way: validate every value that ends up in an nginx or ModSecurity directive (see `app.validate_site`) and test configuration changes with `nginx -t` (`engine.render` does this).
- Keep security defaults safe: new features should be off or in detect-only mode by default, and any outbound connection must validate its target (see `security.check_upstream`, `feeds.check_url`, `alerts.check_target`).
- No inline JavaScript in templates (the panel's Content-Security-Policy forbids it); put behaviour in `static/app.js`.

## Checks to run before a pull request
```bash
pip install bandit && bandit -r panel -ll        # static analysis
docker build -t shieldwaf:dev . && docker build -t shieldwaf-db:dev db
trivy image --severity HIGH,CRITICAL --ignore-unfixed shieldwaf:dev
bash tests/run.sh                                 # needs a test cluster, takes 15-25 minutes
```
Add a test to `tests/functional_test.py` for every new behaviour, especially for anything security related (also test the *failure* cases: invalid input, wrong role, forged data).

## Style
Clear names, short functions, comments that explain **why**. Documentation changes are as valuable as code changes: if you add a setting, add it to `docs/USER-GUIDE.md`.
