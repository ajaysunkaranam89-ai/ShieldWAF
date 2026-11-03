---
name: Bug report
about: Something does not work as documented
labels: bug
---
**Security problem?** Do not use this form. Follow SECURITY.md (private reporting).

**What happened?**

**What did you expect?**

**Steps to reproduce**
1.
2.

**Environment**
- A Shield WAF version (shown in the panel menu):
- Kubernetes (kind / Docker Desktop / EKS / AKS / GKE / other) and version:
- Browser / OS:

**Logs** (remove anything private)
```
kubectl logs -n shieldwaf deploy/shieldwaf -c panel
kubectl logs -n shieldwaf deploy/shieldwaf -c engine
```
