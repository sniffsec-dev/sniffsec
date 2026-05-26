#!/usr/bin/env node

const fs = require('fs');
const path = require('path');

// ANSI Colors
const RED = '\x1b[31m';
const GREEN = '\x1b[32m';
const YELLOW = '\x1b[33m';
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

// Generate a clean env var name from the provider label
function toEnvVarName(provider) {
  const OVERRIDES = {
    'Password Assignment': 'PASSWORD',
    'API Key Assignment': 'API_KEY',
    'Secret Assignment': 'APP_SECRET',
    'Generic_Secret': 'SECRET',
    'MongoDB URI': 'MONGODB_URI',
    'PostgreSQL URI': 'DATABASE_URL',
    'MySQL URI': 'DATABASE_URL',
    'Redis URI': 'REDIS_URL',
    'JDBC URI': 'DATABASE_URL',
    'Elasticsearch URI': 'ELASTICSEARCH_URL',
  };
  if (OVERRIDES[provider]) return OVERRIDES[provider];
  return provider.toUpperCase().replace(/[^A-Z0-9]+/g, '_').replace(/^_+|_+$/g, '');
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
  "Password Assignment":   /(password|passwd|pwd)\s*[:=]\s*['"]([^'"]{8,})['"]/gi,
  "API Key Assignment":    /(api_key|apikey|api-key)\s*[:=]\s*['"]([a-zA-Z0-9\-._]{16,})['"]/gi,
  "Secret Assignment":     /(secret|client_secret)\s*[:=]\s*['"]([a-zA-Z0-9\-._]{16,})['"]/gi,
  "Generic_Secret":        /(?:password|secret|token|apiKey|api_key)\s*[:=]\s*['"]([^'"]{8,})['"]/gi,
};

// Patterns that use capture groups — placeholder check runs on the captured value only
const CAPTURE_GROUP_PATTERNS = new Set([
  'Password Assignment', 'API Key Assignment', 'Secret Assignment', 'Generic_Secret'
]);

// URI patterns — placeholder check runs only on the credential portion (user:pass),
// not the hostname, to avoid false negatives from cloud hostnames like
// ep-cool-name-12345678.us-east-2.aws.neon.tech
const URI_PATTERNS = new Set([
  'MongoDB URI', 'PostgreSQL URI', 'MySQL URI', 'Redis URI', 'JDBC URI', 'Elasticsearch URI'
]);

// Patterns that cannot be auto-fixed (private keys need a file, URIs are complex)
const NO_FIX_PATTERNS = new Set([
  'Private Key Block', 'PGP Private Key Block', ...URI_PATTERNS
]);

/**
 * Compute the exact content positions to replace and what to replace with.
 * Returns { start, end, replacement, envVarName } or null if the pattern can't be auto-fixed.
 *
 * Positions are absolute offsets into `content` (the file string).
 * Fixes are applied bottom-to-top (highest start first) to preserve earlier offsets.
 */
function computeFix(content, match, provider) {
  if (NO_FIX_PATTERNS.has(provider)) return null;

  const envVarName = toEnvVarName(provider);
  const envRef = `process.env.${envVarName}`;

  if (CAPTURE_GROUP_PATTERNS.has(provider)) {
    // The secret value is the last capture group.
    // match[2] holds the value for two-group patterns; match[1] for single-group (Generic_Secret).
    const capturedVal = match[2] !== undefined ? match[2] : match[1];
    if (!capturedVal) return null;

    // Find the position of the quoted value within the full match string
    const valIdxInMatch = match[0].lastIndexOf(capturedVal);
    if (valIdxInMatch === -1) return null;

    // Include the surrounding quotes in the replacement range
    const quoteStart = match.index + valIdxInMatch - 1;
    const quoteEnd   = match.index + valIdxInMatch + capturedVal.length + 1;
    return { start: quoteStart, end: quoteEnd, replacement: envRef, envVarName };
  }

  // Strong-prefix patterns: the regex match IS the secret value.
  // Check if it is surrounded by quotes in the source so we can include them in the replacement.
  const before = content[match.index - 1];
  const after  = content[match.index + match[0].length];

  if ((before === '"' || before === "'") && after === before) {
    return {
      start: match.index - 1,
      end: match.index + match[0].length + 1,
      replacement: envRef,
      envVarName,
    };
  }

  // No surrounding quotes found — replace the match itself
  return {
    start: match.index,
    end: match.index + match[0].length,
    replacement: envRef,
    envVarName,
  };
}

/**
 * SniffSec CLI
 * Static Analysis Tool for Vibe Coders
 */
class SniffSec {
  constructor() {
    this.cwd = process.cwd();
    this.stats = { critical: 0 };
    this.fixMode = process.argv.includes('--fix');
    this.findings = []; // populated only in --fix mode
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
    if (this.fixMode) {
      console.log(`${YELLOW}${BOLD}>>> Sniffing for critical risks (--fix mode)...${RESET}\n`);
    } else {
      console.log(`${BLUE}${BOLD}>>> Sniffing for critical risks...${RESET}\n`);
    }

    this.walk(this.cwd, (filePath) => {
      const ext = path.extname(filePath);
      const fileName = path.basename(filePath);
      const SUPPORTED_EXTS = ['.js', '.ts', '.jsx', '.tsx', '.env', '.yaml', '.yml', '.json', '.sh', '.py', '.go', '.rb'];
      const SKIP_FILES = ['package-lock.json', 'yarn.lock', 'pnpm-lock.yaml', '.env.example'];
      if (SKIP_FILES.includes(fileName)) return;
      if (!SUPPORTED_EXTS.includes(ext) && !fileName.startsWith('.env')) return;
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
        const hasForceDynamic = /export\s+const\s+dynamic\s*=\s*['"]force-dynamic['"]/.test(stripped);
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
          } else if (URI_PATTERNS.has(provider)) {
            if (isEnvVarRef(fullMatch)) continue;
            // Extract only the credential (user:pass) between :// and @ — ignore the hostname
            const credPart = (fullMatch.match(/:\/\/([^@]+)@/) || [])[1] || fullMatch;
            if (isPlaceholder(credPart)) continue;
          } else {
            if (isEnvVarRef(fullMatch)) continue;
            if (isPlaceholder(fullMatch)) continue;
          }

          const lineNumber = lineAt(content, match.index);

          if (this.fixMode) {
            const fix = computeFix(content, match, provider);
            this.findings.push({ filePath, provider, lineNumber, fix });
            this.stats.critical++;
          } else {
            this.log(LOG_LEVELS.CRITICAL, RULES.HARDCODED_KEYS, `Hardcoded ${provider} found!`, filePath, lineNumber);
          }
        }
      }
    });

    if (this.fixMode && this.findings.length > 0) {
      this.applyFixes();
    }

    this.summary();
  }

  applyFixes() {
    // Group findings by file
    const byFile = new Map();
    for (const finding of this.findings) {
      if (!byFile.has(finding.filePath)) byFile.set(finding.filePath, []);
      byFile.get(finding.filePath).push(finding);
    }

    const envVarsToAdd = new Set();

    for (const [filePath, findings] of byFile) {
      let content = fs.readFileSync(filePath, 'utf8');

      const fixable   = findings.filter(f => f.fix !== null).sort((a, b) => b.fix.start - a.fix.start);
      const unfixable = findings.filter(f => f.fix === null);

      // Apply fixes from bottom to top so earlier offsets stay valid.
      // Track applied ranges to skip fixes that overlap with an already-applied one
      // (multiple patterns can match the same text — only the first fix wins).
      const appliedRanges = [];

      for (const finding of fixable) {
        const { start, end, replacement, envVarName } = finding.fix;
        const overlaps = appliedRanges.some(([s, e]) => start < e && end > s);
        if (overlaps) continue;

        content = content.slice(0, start) + replacement + content.slice(end);
        appliedRanges.push([start, end]);
        envVarsToAdd.add(envVarName);
        console.log(`${GREEN}${BOLD}[FIXED]${RESET} ${BOLD}${finding.provider}${RESET}: replaced with process.env.${envVarName} ${BLUE}(${path.relative(this.cwd, filePath)}:${finding.lineNumber})${RESET}`);
      }

      for (const finding of unfixable) {
        console.log(`${YELLOW}${BOLD}[MANUAL REQUIRED]${RESET} ${BOLD}${finding.provider}${RESET}: move this value to your .env file manually. ${BLUE}(${path.relative(this.cwd, filePath)}:${finding.lineNumber})${RESET}`);
      }

      if (fixable.length > 0) {
        fs.writeFileSync(filePath, content, 'utf8');
      }
    }

    if (envVarsToAdd.size > 0) {
      this.updateEnvExample(envVarsToAdd);
    }
  }

  updateEnvExample(envVars) {
    const envExamplePath = path.join(this.cwd, '.env.example');
    const existed = fs.existsSync(envExamplePath);
    const existing = existed ? fs.readFileSync(envExamplePath, 'utf8') : '';

    const toAdd = [...envVars].filter(v => !existing.includes(`${v}=`));
    if (toAdd.length === 0) return;

    const newContent = existing
      ? existing.trimEnd() + '\n' + toAdd.map(v => `${v}=`).join('\n') + '\n'
      : toAdd.map(v => `${v}=`).join('\n') + '\n';

    fs.writeFileSync(envExamplePath, newContent, 'utf8');

    console.log(`\n${GREEN}${BOLD}>>> .env.example ${existed ? 'updated' : 'created'}:${RESET}`);
    for (const v of toAdd) {
      console.log(`  ${GREEN}${BOLD}${v}=${RESET}`);
    }
    console.log(`\n${YELLOW}${BOLD}>>> Next step:${RESET} Copy these variable names into your ${BOLD}.env${RESET} file and fill in the actual values.`);
  }

  summary() {
    console.log(`\n${BLUE}${BOLD}>>> Sniff Summary:${RESET}`);
    const countColor = this.stats.critical > 0 ? RED : BLUE;
    console.log(`${countColor}Critical Risks: ${this.stats.critical}${RESET}`);

    if (this.stats.critical > 0) {
      if (this.fixMode) {
        console.log(`\n${GREEN}${BOLD}STATUS: FIXED. Review the changes, then add your secrets to .env.${RESET}`);
        process.exit(0);
      } else {
        console.log(`\n${RED}${BOLD}STATUS: FAIL. Fix critical risks before shipping.${RESET}`);
      console.log(`${YELLOW}TIP: Run ${BOLD}sniffsec --fix${RESET}${YELLOW} to auto-replace hardcoded secrets with env var references.${RESET}`);
        process.exit(1);
      }
    } else {
      console.log(`\n${BLUE}${BOLD}STATUS: PASS. No issues detected.${RESET}`);
      process.exit(0);
    }
  }
}

const sniffer = new SniffSec();
sniffer.sniff();
