# Third-party software and data

A Shield WAF is licensed under the **Apache License 2.0** (see `LICENSE`). It is built from, and runs, the following open-source
components. Each keeps its own licence; this table is provided in good faith, please check the upstream projects for the authoritative terms.

| Component | Used for | Licence |
|---|---|---|
| [nginx](https://nginx.org) | the proxy engine | BSD-2-Clause |
| [ModSecurity v3 (libmodsecurity)](https://github.com/owasp-modsecurity/ModSecurity) and the [ModSecurity-nginx connector](https://github.com/owasp-modsecurity/ModSecurity-nginx) | the WAF rule engine | Apache-2.0 |
| [OWASP Core Rule Set](https://github.com/coreruleset/coreruleset) | the attack rules (the base image is [owasp/modsecurity-crs](https://hub.docker.com/r/owasp/modsecurity-crs)) | Apache-2.0 |
| [njs (nginx JavaScript)](https://github.com/nginx/njs) | the anti-bot challenge inside nginx | BSD-2-Clause |
| [OpenSSL](https://www.openssl.org) | TLS, certificates, password hashing for the login gate | Apache-2.0 |
| [Alpine Linux](https://alpinelinux.org) | the container operating system | various (mostly MIT, BSD, GPL) |
| [Python](https://www.python.org) | the control panel | PSF-2.0 |
| [Flask](https://flask.palletsprojects.com), Werkzeug, Jinja2 | the web GUI | BSD-3-Clause |
| [Gunicorn](https://gunicorn.org) | the panel web server | MIT |
| [psycopg2](https://www.psycopg.org) | PostgreSQL driver | LGPL-3.0 with exceptions (used as an unmodified installed library) |
| [PostgreSQL](https://www.postgresql.org) | the database | PostgreSQL Licence |
| [Kubernetes](https://kubernetes.io), [kind](https://kind.sigs.k8s.io) | the target platform | Apache-2.0 |

Tools used only for testing and review (not shipped in the image): OWASP ZAP (Apache-2.0), Trivy (Apache-2.0), Bandit (Apache-2.0),
hadolint (GPL-3.0), gitleaks (MIT).

## Data downloaded at run time (not redistributed in this repository)
Your own instance downloads these when you enable the matching feature. You are responsible for complying with their terms:

| Data | Source | Notes |
|---|---|---|
| IP reputation lists | [Spamhaus DROP](https://www.spamhaus.org/drop/) and [FireHOL level 1](https://iplists.firehol.org) (or lists you add) | Read the providers' terms of use, especially for commercial or high-volume use. You can switch the feeds off or add your own under **Threat intel**. |
| Country data | the public allocation files of the five regional internet registries (RIPE NCC, ARIN, APNIC, LACNIC, AFRINIC) | Published openly; shows the *registered* country of an address block. |
| OWASP rule-set releases | github.com/coreruleset/coreruleset | Downloaded only when an administrator stages an update. |

## Logo
The A Shield WAF logo and the screenshots were created for this project and are covered by the same Apache-2.0 licence.
