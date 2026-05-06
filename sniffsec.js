#!/usr/bin/env node

const fs = require('fs');
const path = require('path');

// ANSI Colors
const RED = '\x1b[31m';
const BLUE = '\x1b[34m';
const BOLD = '\x1b[1m';
const RESET = '\x1b[0m';

const LOG_LEVELS = {
  CRITICAL: `${RED}${BOLD}[CRITICAL]${RESET}`,
};

const RULES = {
  DYNAMIC_GATE: 'Next.js Dynamic-Gate',
  HARDCODED_KEYS: 'Hardcoded API Keys',
};

// Returns true if the matched text looks like an env var reference, not a hardcoded value
function isEnvVarRef(text) {
  return /process\.env\b|\benv\.\w|\bconfig\.\w|\$\{[^}]+\}|getenv\(|os\.environ/.test(text);
}

// Returns true if the value looks like a placeholder, not a real secret
function isPlaceholder(val) {
  if (!val) return false;
  const lower = val.toLowerCase();
  const PLACEHOLDERS = [
    'your-key', 'your_key', 'your-secret', 'your_secret', 'placeholder',
    'xxxx', 'replace', 'changeme', 'change_me', 'example', 'dummy', 'test-key',
    'sample', 'insert', 'todo', 'fixme', 'your-token', 'my-key',
    '12345678', 'enter_', 'add_your',
  ];
  return PLACEHOLDERS.some(p => lower.includes(p)) || /^[x*<>]{4,}$/.test(lower);
}

// Strip JS/TS block and line comments to avoid matching patterns inside comments
function stripComments(content) {
  return content
    .replace(/\/\*[\s\S]*?\*\//g, '')
    .replace(/\/\/.*/g, '');
}

// Return the 1-based line number for a given character offset in content
function lineAt(content, index) {
  return content.slice(0, index).split('\n').length;
}

const SECURITY_PATTERNS = {
  // --- Credentials with strong, unique prefixes (low false-positive risk) ---
  "OpenAI API Key":         /\bsk-[a-zA-Z0-9T]{20}[a-zA-Z0-9]{12,}/g,
  "Anthropic API Key":      /\bsk-ant-[a-zA-Z0-9_-]{80,}/g,
  "Stripe Secret Key":      /\bsk_(live|test)_[a-zA-Z0-9]{24,}\b/g,
  "Stripe Publishable Key": /\bpk_(live|test)_[a-zA-Z0-9]{24,}\b/g,
  "AWS Access Key ID":      /\bAKIA[0-9A-Z]{16}\b/g,
  "AWS Secret Access Key":  /aws(.{0,20})?['"][0-9a-zA-Z\/+]{40}['"]/gi,
  "Google API Key":         /\bAIza[0-9A-Za-z\-_]{35}\b/g,
  "Firebase FCM Secret":    /\bAAAA[A-Za-z0-9_-]{7}:[A-Za-z0-9_-]{140}\b/g,
  "GitHub PAT (classic)":   /\bghp_[a-zA-Z0-9]{36}\b/g,
  "GitHub Fine-Grained PAT":/\bgithub_pat_[a-zA-Z0-9_]{82}\b/g,
  "GitLab Token":           /\bglpat-[0-9a-zA-Z\-_]{20}\b/g,
  "GitLab Runner Token":    /\bGR1348941[0-9a-zA-Z\-]{20}\b/g,
  "Slack Token":            /\bxox[baprs]-[0-9a-zA-Z]{10,48}\b/g,
  "Twilio API Key":         /\bSK[0-9a-fA-F]{32}\b/g,
  "SendGrid API Key":       /\bSG\.[A-Za-z0-9\-_]{22}\.[A-Za-z0-9\-_]{43}\b/g,
  "Shopify Access Token":   /\bshpat_[a-fA-F0-9]{32}\b/g,
  "Facebook Access Token":  /\bEAACEdEose0cBA[0-9A-Za-z]+/g,
  "DigitalOcean Token":     /\bdop_v1_[a-z0-9]{64}\b/g,
  "Linear API Key":         /\blin_api_[a-zA-Z0-9]{40}\b/g,
  "Heroku API Key":         /[hH]eroku.*['"][0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}['"]/g,
  "Sentry DSN":             /https?:\/\/[a-f0-9]{32}@(?:[a-z0-9\-]+\.)?ingest\.sentry\.io\/\d+/g,
  "Discord Bot Token":      /\b[MN][A-Za-z\d]{23}\.[\w\-]{6}\.[\w\-]{27}\b/g,
  "Discord Webhook URL":    /https:\/\/discord\.com\/api\/webhooks\/[0-9]+\/[a-zA-Z0-9_\-]+/g,
  "Riot Games API Key":     /\bRGAPI-[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}\b/g,
  "New Relic Key":          /\bNRII-[a-zA-Z0-9]{20,}\b/g,
  "CircleCI Token":         /\bcircle-token=[a-z0-9]{40}\b/g,
  "Snyk Token":             /\bsnyk_token\s*=\s*[a-f0-9\-]{36}\b/g,
  "Vault Token":            /\bvault.*\bs\.[a-zA-Z0-9]{24}\b/g,
  "Hashicorp Vault URL":    /https?:\/\/[a-z0-9.\-]+:8200\/v1\//g,

  // --- Database URIs with embedded credentials (password:// style = always a leak) ---
  "MongoDB URI":      /mongodb(?:\+srv)?:\/\/[^:@\s]+:[^:@\s]+@[a-zA-Z0-9.\-]+/g,
  "PostgreSQL URI":   /postgres(?:ql)?:\/\/[^:@\s]+:[^:@\s]+@[a-zA-Z0-9.\-]+:[0-9]+/g,
  "MySQL URI":        /mysql:\/\/[^:@\s]+:[^:@\s]+@[a-zA-Z0-9.\-]+:[0-9]+/g,
  "Redis URI":        /redis:\/\/[^:@\s]+:[^:@\s]+@[a-zA-Z0-9.\-]+:[0-9]+/g,
  "JDBC URI":         /jdbc:[a-z]+:\/\/[^:@\s]+:[^:@\s]+@[a-zA-Z0-9.\-]+:[0-9]+/g,
  "Elasticsearch URI":/https?:\/\/[^:@\s]+:[^:@\s]+@[a-zA-Z0-9.\-]+:9200/g,

  // --- Private key material ---
  "Private Key Block":     /-----BEGIN [A-Z ]+ PRIVATE KEY-----/g,
  "PGP Private Key Block": /-----BEGIN PGP PRIVATE KEY BLOCK-----/g,

  // --- Variable-assignment patterns (checked with env var / placeholder guard) ---
  "Password Assignment":   /(password|passwd|pwd)\s*[:=]\s*['"]([^'"]{4,})['"]/gi,
  "API Key Assignment":    /(api_key|apikey|api-key)\s*[:=]\s*['"]([a-zA-Z0-9\-._]{16,})['"]/gi,
  "Secret Assignment":     /(secret|client_secret)\s*[:=]\s*['"]([a-zA-Z0-9\-._]{16,})['"]/gi,
  "Generic_Secret":        /(?:password|secret|token|apiKey|api_key)\s*[:=]\s*['"]([^'"]{8,})['"]/gi,
};

// Patterns that use capture groups — placeholder check runs on the captured value only
const CAPTURE_GROUP_PATTERNS = new Set([
  'Password Assignment', 'API Key Assignment', 'Secret Assignment', 'Generic_Secret'
]);

/**
 * SniffSec CLI v0.1
 * Static Analysis Tool for Vibe Coders
 */
class SniffSec {
  constructor() {
    this.cwd = process.cwd();
    this.stats = { critical: 0 };
  }

  log(level, rule, message, file, lineNumber) {
    const filePath = path.relative(this.cwd, file);
    const loc = lineNumber ? `:${lineNumber}` : '';
    console.log(`${level} ${BOLD}${rule}${RESET}: ${message} ${BLUE}(${filePath}${loc})${RESET}`);
    if (level === LOG_LEVELS.CRITICAL) this.stats.critical++;
  }

  walk(dir, callback) {
    let files;
    try {
      files = fs.readdirSync(dir);
    } catch (err) {
      return;
    }

    const SKIP_DIRS = [
      'node_modules', '.next', '.git', 'dist', 'build', '.Trash', 'Library',
      '.vscode', '.idea', '.github', '.cache', 'coverage', 'tmp', 'temp', 'vendor'
    ];

    for (const file of files) {
      if (SKIP_DIRS.includes(file)) continue;
      const fullPath = path.join(dir, file);
      try {
        const stat = fs.statSync(fullPath);
        if (file.startsWith('.') && stat.isDirectory()) continue;

        if (stat.isDirectory()) {
          this.walk(fullPath, callback);
        } else {
          callback(fullPath);
        }
      } catch (err) {
        continue;
      }
    }
  }

  sniff() {
    console.log(`${BLUE}${BOLD}>>> Sniffing for critical risks...${RESET}\n`);

    this.walk(this.cwd, (filePath) => {
      const ext = path.extname(filePath);
      if (!['.js', '.ts', '.jsx', '.tsx'].includes(ext)) return;
      if (filePath === __filename) return;

      let content;
      try {
        content = fs.readFileSync(filePath, 'utf8');
      } catch (err) {
        return;
      }

      const relativePath = path.relative(this.cwd, filePath);
      const stripped = stripComments(content);

      // Rule #1: Dynamic-Gate
      // Matches any route.ts / route.tsx / route.js inside an app/ directory,
      // not just app/api — Next.js route handlers can live anywhere under app/.
      const isAppRouteHandler =
        /(?:^|\/)app\//.test(relativePath) &&
        /route\.(ts|tsx|js)$/.test(relativePath);

      if (isAppRouteHandler) {
        const usesDynamicData = /\b(cookies|headers)\(\)/.test(stripped);
        const hasForceDynamic = /export\s+const\s+dynamic\s*=\s*['"]force-dynamic['"]/.test(content);
        if (usesDynamicData && !hasForceDynamic) {
          this.log(
            LOG_LEVELS.CRITICAL, RULES.DYNAMIC_GATE,
            'API Route uses cookies/headers but lacks "force-dynamic". This will break on Vercel build.',
            filePath
          );
        }
      }

      // Rule #2: Hardcoded API Keys
      for (const [provider, regex] of Object.entries(SECURITY_PATTERNS)) {
        regex.lastIndex = 0;
        let match;
        while ((match = regex.exec(content)) !== null) {
          const fullMatch = match[0];
          const capturedVal = match[1] || match[2];

          if (CAPTURE_GROUP_PATTERNS.has(provider)) {
            if (!capturedVal) continue;
            if (isEnvVarRef(fullMatch)) continue;
            if (isPlaceholder(capturedVal)) continue;
          } else {
            if (isEnvVarRef(fullMatch)) continue;
            if (isPlaceholder(fullMatch)) continue;
          }

          const line = lineAt(content, match.index);
          this.log(LOG_LEVELS.CRITICAL, RULES.HARDCODED_KEYS, `Hardcoded ${provider} found!`, filePath, line);
        }
      }
    });

    this.summary();
  }

  summary() {
    console.log(`\n${BLUE}${BOLD}>>> Sniff Summary:${RESET}`);
    const countColor = this.stats.critical > 0 ? RED : BLUE;
    console.log(`${countColor}Critical Risks: ${this.stats.critical}${RESET}`);

    if (this.stats.critical > 0) {
      console.log(`\n${RED}${BOLD}STATUS: FAIL. Fix critical risks before shipping.${RESET}`);
      process.exit(1);
    } else {
      console.log(`\n${BLUE}${BOLD}STATUS: PASS. No issues detected.${RESET}`);
      process.exit(0);
    }
  }
}

const sniffer = new SniffSec();
sniffer.sniff();
