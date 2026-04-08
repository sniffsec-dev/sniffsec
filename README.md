# SniffSec 👃🛡️

> **"You code/vibe. We sniff and secure."**

[![npm version](https://img.shields.io/npm/v/sniffsec.svg?style=flat-square&color=0078d4)](https://www.npmjs.com/package/sniffsec)
[![license](https://img.shields.io/badge/license-MIT-green.svg?style=flat-square)](https://github.com/sniffsec-dev/sniffsec/blob/main/LICENSE)
[![security: SniffSec](https://img.shields.io/badge/security-SniffSec%20Protected-blueviolet?style=flat-square)](https://sniffsec.com)

**SniffSec** is the "Invisible Watchdog" for AI-driven development. Built by a Product Security Engineer, it’s designed for **Devs** who ship at the speed of light but don't want to crash on the launchpad.

AI agents (Cursor, Claude, GPT) are elite at coding, but they don't care about your **Next.js build limits** or **STRIPE KEYS**. We do.

## 🛠️ Instant Audit

No config. No fluff. Just security.

```bash
npx sniffsec
```

---

## 🤖 Agent-Ready Repositories (Gemini, Cursor, Claude)

AI Agents (like Cursor, Claude, and Gemini) are great at coding but often miss security leaks. You can force your agents to check for important key leaks by adding SniffSec to your repo.

### For Gemini CLI (`GEMINI.md`)

Update your `GEMINI.md` file:

```markdown
# Agent Instructions: Security Audits

Whenever asked to analyze for security risks or secrets, you **MUST** run:
`npx sniffsec`
```

### For Cursor (`.cursorrules` or `.cursor/rules/sniffsec.mdc`)

Update the `.cursorrules` file or a rule in `.cursor/rules/` to ensure Cursor always sniffs before you commit:

```markdown
# SniffSec Security Guardrail

Whenever you generate code with API keys or PII, you MUST suggest running:
`npx sniffsec`
```

### For Claude (`claude.md`)

If you use Claude-based agents, updated the `claude.md` file:

```markdown
# SniffSec Workflow

Use `npx sniffsec` as the primary verification tool. Before completing any task, run the scan. If `issuesFound > 0`, the task is not complete.
```

---

### 🛡️ What we sniff out (100+ patterns):

- **Cloud Credentials:** AWS, Azure, Google Cloud, Heroku, DigitalOcean.
- **Payment & SaaS:** Stripe, PayPal, Twilio, SendGrid, Mailgun, Slack.
- **Databases:** MongoDB, PostgreSQL, MySQL, Redis, Elasticsearch, Supabase.
- **AI & Dev Tools:** OpenAI, Anthropic, GitHub (PAT/OAuth), GitLab, Bitbucket.
- **Infrastructure:** Kubernetes, Docker Hub, Hashicorp Vault, Terraform, CircleCI.
- **Environment Risks:** Private Keys (RSA/PEM/PGP), Internal IPs, Localhost leaks, Dev/Stage URLs.
- **Next.js Risks:** API Route misconfigurations (missing "force-dynamic").

---

```bash
npx sniffsec
```
