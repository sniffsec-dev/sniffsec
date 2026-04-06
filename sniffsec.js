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

/**
 * SniffSec CLI v0.1
 * Static Analysis Tool for Vibe Coders
 */
class SniffSec {
  constructor() {
    this.cwd = process.cwd();
    this.stats = { critical: 0 };
  }

  log(level, rule, message, file) {
    const filePath = path.relative(this.cwd, file);
    console.log(`${level} ${BOLD}${rule}${RESET}: ${message} ${BLUE}(${filePath})${RESET}`);
    this.stats.critical++;
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
        // Skip hidden directories
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

      const content = fs.readFileSync(filePath, 'utf8');
      const relativePath = path.relative(this.cwd, filePath);

      // Rule #1: Dynamic-Gate
      if (relativePath.includes('app/api') && (relativePath.endsWith('route.ts') || relativePath.endsWith('route.js'))) {
        const usesDynamicData = /\b(cookies|headers)\(\)/.test(content);
        const hasForceDynamic = /export\s+const\s+dynamic\s*=\s*['"]force-dynamic['"]/.test(content);
        if (usesDynamicData && !hasForceDynamic) {
          this.log(LOG_LEVELS.CRITICAL, RULES.DYNAMIC_GATE, 'API Route uses cookies/headers but lacks "force-dynamic". This will break on Vercel build.', filePath);
        }
      }

      // Rule #2: Hardcoded API Keys
      const patterns = {
        OpenAI: /sk-[a-zA-Z0-9]{32,}/g,
        Anthropic: /sk-ant-sid01-[a-zA-Z0-9_-]{93}/g,
        Stripe: /sk_(live|test)_[a-zA-Z0-9]{24}/g,
        AWS_Access_Key: /\bAKIA[0-9A-Z]{16}\b/g,
        GitHub_PAT: /\bghp_[a-zA-Z0-9]{36}\b/g,
        Google_API_Key: /\bAIza[0-9A-Za-z-_]{35}\b/g,
        Slack_Token: /xox[baprs]-[0-9a-zA-Z]{10,48}/g,
        Generic_Secret: /(?:password|secret|token|apiKey|api_key)\s*[:=]\s*['"]([^'"]{8,})['"]/gi
      };

      for (const [provider, regex] of Object.entries(patterns)) {
        if (provider === 'Generic_Secret') {
          let match;
          while ((match = regex.exec(content)) !== null) {
            // Basic entropy/heuristic: avoid common placeholders
            const val = match[1].toLowerCase();
            if (['password', '12345678', 'dummy-key', 'your-key-here'].includes(val)) continue;
            this.log(LOG_LEVELS.CRITICAL, RULES.HARDCODED_KEYS, `Potential hardcoded secret assigned to "${match[0].split(/[=:]/)[0].trim()}"`, filePath);
          }
          continue;
        }

        const matches = content.match(regex);
        if (matches) {
          matches.forEach(m => {
            this.log(LOG_LEVELS.CRITICAL, RULES.HARDCODED_KEYS, `Hardcoded ${provider.replace(/_/g, ' ')} found!`, filePath);
          });
        }
      }
    });

    this.summary();
  }

  summary() {
    console.log(`\n${BLUE}${BOLD}>>> Sniff Summary:${RESET}`);
    console.log(`${RED}Critical Risks: ${this.stats.critical}${RESET}`);
    
    if (this.stats.critical > 0) {
      console.log(`\n${RED}${BOLD}STATUS: FAIL. Fix critical risks before shipping.${RESET}`);
      process.exit(1);
    } else {
      console.log(`\n${BLUE}${BOLD}STATUS: PASS. You are vibe-ready.${RESET}`);
      process.exit(0);
    }
  }
}

const sniffer = new SniffSec();
sniffer.sniff();
