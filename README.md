# SniffSec 👃🛡️

> **"You code/vibe. We sniff and secure."**

[![npm version](https://img.shields.io/npm/v/sniffsec.svg?style=flat-square&color=0078d4)](https://www.npmjs.com/package/sniffsec)
[![license](https://img.shields.io/badge/license-MIT-green.svg?style=flat-square)](https://github.com/sniffsec-dev/sniffsec/blob/main/LICENSE)
[![security: SniffSec](https://img.shields.io/badge/security-SniffSec%20Protected-blueviolet?style=flat-square)](https://sniffsec.com)

**SniffSec** is the "Invisible Watchdog" for AI-driven development. Built by a Product Security Engineer, it’s designed for **Devs** who ship at the speed of light but don't want to crash on the launchpad.

AI agents (Cursor, Claude, GPT) are elite at coding, but they don't care about your **Next.js build limits** or **STRIPE KEYS**. We do.

### 🛡️ What we sniff out (100+ patterns):
- **Cloud Credentials:** AWS, Azure, Google Cloud, Heroku, DigitalOcean.
- **Payment & SaaS:** Stripe, PayPal, Twilio, SendGrid, Mailgun, Slack.
- **Databases:** MongoDB, PostgreSQL, MySQL, Redis, Elasticsearch, Supabase.
- **AI & Dev Tools:** OpenAI, Anthropic, GitHub (PAT/OAuth), GitLab, Bitbucket.
- **Infrastructure:** Kubernetes, Docker Hub, Hashicorp Vault, Terraform, CircleCI.
- **Environment Risks:** Private Keys (RSA/PEM/PGP), Internal IPs, Localhost leaks, Dev/Stage URLs.
- **Next.js Risks:** API Route misconfigurations (missing "force-dynamic").

---

## 🛠️ Instant Audit

No config. No fluff. Just security.

```bash
npx sniffsec
```
