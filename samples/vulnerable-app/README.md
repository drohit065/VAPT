# vulnerable-app (DELIBERATELY INSECURE)

A tiny Flask + JavaScript app full of intentional security bugs, used to test the VAPT
scanner end to end. **Never deploy or run it.** Every secret in it is fake.

What the scanner should find:

| Check | Examples planted |
|-------|------------------|
| Code flaws (Semgrep) | SQL injection, OS command injection, `eval`, `pickle.loads`, `yaml.load`, SSTI, Flask debug mode, MD5 passwords, `verify=False`, open redirect, `innerHTML` XSS |
| Vulnerable dependencies (Trivy) | old Flask, Jinja2, PyYAML, requests, lodash |
| Hardcoded secrets (Gitleaks) | fake API key, fake JWT signing secret, fake DB password |
| Docker / Terraform (Trivy config) | root container, unpinned base image, public S3 bucket, SSH open to the world |
| AI review (logic flaws) | `/invoices/<id>` returns any user's invoice (IDOR), `/admin/delete` trusts a header (auth bypass) |

Zip it to test the upload path:

```bash
cd samples && zip -r vulnerable-app.zip vulnerable-app
```
