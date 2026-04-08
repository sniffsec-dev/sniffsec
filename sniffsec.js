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

const SECURITY_PATTERNS = {
  // Existing Patterns
  OpenAI: /sk-[a-zA-Z0-9]{32,}/g,
  Anthropic: /sk-ant-sid01-[a-zA-Z0-9_-]{93}/g,
  Stripe: /sk_(live|test)_[a-zA-Z0-9]{24}/g,
  AWS_Access_Key: /\bAKIA[0-9A-Z]{16}\b/g,
  GitHub_PAT: /\bghp_[a-zA-Z0-9]{36}\b/g,
  Google_API_Key: /\bAIza[0-9A-Za-z-_]{35}\b/g,
  Slack_Token: /xox[baprs]-[0-9a-zA-Z]{10,48}/g,

  // 100 Patterns from Blog
  "AWS Access Key ID": /AKIA[0-9A-Z]{16}/g,
  "AWS Secret Access Key": /aws(.{0,20})?['\"][0-9a-zA-Z\/+]{40}['\"]/gi,
  "Google API Key (Blog)": /AIza[0-9A-Za-z\-_]{35}/g,
  "Firebase Secret": /AAAA[A-Za-z0-9_-]{7}:[A-Za-z0-9_-]{140}/g,
  "GitHub Token": /ghp_[0-9a-zA-Z]{36}/g,
  "GitLab Token": /glpat-[0-9a-zA-Z\-_]{20}/g,
  "Slack Token (Blog)": /xox[baprs]-[0-9a-zA-Z]{10,48}/g,
  "Stripe Secret Key": /sk_live_[0-9a-zA-Z]{24}/g,
  "Stripe Publishable Key": /pk_live_[0-9a-zA-Z]{24}/g,
  "Twilio API Key": /SK[0-9a-fA-F]{32}/g,
  "SendGrid API Key": /SG\.[ \w\d\-_]{22}\.[ \w\d\-_]{43}/g,
  "Mailgun API Key": /key-[0-9a-zA-Z]{32}/g,
  "Dropbox Access Token": /[a-zA-Z0-9]{64}/g,
  "Shopify Access Token": /shpat_[a-fA-F0-9]{32}/g,
  "Facebook Access Token": /EAACEdEose0cBA[0-9A-Za-z]+/g,
  "Heroku API Key": /[hH]eroku.*['"][0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}['"]/g,
  "DigitalOcean Token": /dop_v1_[a-z0-9]{64}/g,
  "Asana Personal Access Token": /0\/[0-9a-f]{32}/g,
  "Linear API Key": /lin_api_[a-zA-Z0-9]{40}/g,
  "Telegram Bot Token": /[0-9]{9}:[a-zA-Z0-9_-]{35}/g,
  "OAuth Client Secret": /client_secret[‘“\s:=]+[a-zA-Z0-9-_]{20,}/gi,
  "OAuth Client ID": /client_id[‘“\s:=]+[a-zA-Z0-9-_]{20,}/gi,
  "JWT Token": /ey[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*/g,
  "Azure Client Secret": /[a-zA-Z0-9-_~.]{34,}/g,
  "Microsoft Teams Webhook": /https:\/\/outlook\.office\.com\/webhook\/[a-zA-Z0-9-]+@[a-zA-Z0-9-]+\/IncomingWebhook\/[a-zA-Z0-9]+\/[a-zA-Z0-9-]+/g,
  "Basic Auth String": /basic\s+[a-zA-Z0-9=:_\+\/-]+/gi,
  "Password Assignment": /(password|pwd|pass)['"\s:=]+[^\s'"]{4,100}/gi,
  "API Key in Variable": /(api_key|apikey|api-key)['"\s:=]+[a-zA-Z0-9\-._]{16,}/gi,
  "Secret in Variable": /(secret|token|auth)['"\s:=]+[a-zA-Z0-9\-._]{16,}/gi,
  "Authorization Bearer Token": /Bearer\s+[a-zA-Z0-9\-._~+/]+=*/g,
  "MongoDB Connection URI": /mongodb(?:\+srv)?:\/\/[a-zA-Z0-9._%+-]+:[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g,
  "PostgreSQL URI": /postgres(?:ql)?:\/\/[a-zA-Z0-9._%+-]+:[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+:[0-9]+/g,
  "MySQL URI": /mysql:\/\/[a-zA-Z0-9._%+-]+:[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+:[0-9]+/g,
  "Redis URI": /redis:\/\/(?:[a-zA-Z0-9._%+-]+:[a-zA-Z0-9._%+-]+@)?[a-zA-Z0-9.-]+:[0-9]+/g,
  "Elasticsearch URI": /https?:\/\/[a-zA-Z0-9._%+-]+:[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+:9200/g,
  "Supabase DB Key": /supabase_?key[‘“\s:=]+[a-zA-Z0-9]{50,}/gi,
  "Firebase URL": /https:\/\/[a-z0-9-]+\.firebaseio\.com/g,
  "JDBC URL": /jdbc:[a-z]+:\/\/[a-zA-Z0-9._%+-]+:[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+:[0-9]+/g,
  "AWS RDS Hostname": /[a-z0-9-]+\.rds\.amazonaws\.com/g,
  "Cloud SQL URI (GCP)": /https:\/\/www\.googleapis\.com\/sql\/v1beta4\/projects\/[a-z0-9-]+\/instances\/[a-z0-9-]+/g,
  "Algolia API Key": /algolia_?key[‘“\s:=]+[a-zA-Z0-9]{32}/gi,
  "Firebase API Key": /AIza[0-9A-Za-z\-_]{35}/g,
  "Cloudinary URL": /cloudinary:\/\/ [0-9]{15}:[a-zA-Z0-9]+@[a-zA-Z]+/g,
  "Sentry DSN": /https?:\/\/[a-f0-9]+@(?:[a-z0-9-]+\.)?ingest\.sentry\.io\/\d+/g,
  "Netlify Token": /[a-zA-Z0-9_-]{40,}/g,
  "GitHub OAuth App Secret": /github_?client_?secret[‘“\s:=]+[a-zA-Z0-9]{40}/gi,
  "Segment API Key": /segment_?write_?key[‘“\s:=]+[a-zA-Z0-9]{32}/gi,
  "Intercom Access Token": /intercom_?token[‘“\s:=]+[a-zA-Z0-9]{60}/gi,
  "Amplitude API Key": /amplitude_?api_?key[‘“\s:=]+[a-zA-Z0-9]{32}/gi,
  "Plaid Client Secret": /plaid_?secret[‘“\s:=]+[a-zA-Z0-9]{30}/gi,
  "Docker Hub Password": /docker_?password[‘“\s:=]+[a-zA-Z0-9_-]{8,}/gi,
  "AWS IAM Role ARN": /arn:aws:iam::\d{12}:role\/[a-zA-Z0-9_-]+/g,
  "AWS S3 Bucket URL": /https?:\/\/[a-z0-9.-]+\.s3\.amazonaws\.com/g,
  "Kubernetes Secret Name": /k8s_?secret[‘“\s:=]+[a-z0-9-]+/gi,
  "Helm Secret Value": /helm_?secret[‘“\s:=]+[a-zA-Z0-9]{10,}/gi,
  "GitHub Actions Secret Reference": /\$\{\{\s*secrets\.[A-Z0-9_]+\s*\}\}/g,
  "GitHub Actions Encrypted Value": /github_?encrypted_?value[‘“\s:=]+[a-zA-Z0-9\+\/]{50,}/gi,
  "K8s Service Account Token": /[a-zA-Z0-9_-]{100,}/g,
  "Vault Token": /s\.[a-zA-Z0-9]{24}/g,
  "Hashicorp Vault URL": /https?:\/\/[a-z0-9.-]+:8200\/v1\//g,
  "CircleCI Token": /circle-token=[a-z0-9]{40}/g,
  "Travis CI Token": /travis_?token[‘“\s:=]+[a-z0-9]{30}/gi,
  "Jenkins Crumb Token": /jenkins_?crumb[‘“\s:=]+[a-f0-9]{32}/gi,
  "Azure DevOps Token": /[a-z0-9]{52}/g,
  "GitHub Personal Access Token": /ghp_[a-zA-Z0-9]{36}/g,
  "GitHub Fine-Grained Token": /github_pat_[a-zA-Z0-9_]{82}/g,
  "Bitbucket OAuth Key": /bitbucket_?key[‘“\s:=]+[a-zA-Z0-9]{20}/gi,
  "Bitbucket OAuth Secret": /bitbucket_?secret[‘“\s:=]+[a-zA-Z0-9]{20}/gi,
  "GitLab Runner Token": /GR1348941[0-9a-zA-Z\-]{20}/g,
  "Netlify Access Token": /[a-zA-Z0-9_-]{40,}/g,
  "Bugsnag API Key": /[a-f0-9]{32}/g,
  "Datadog API Key": /[a-z0-9]{32}/g,
  "Loggly Token": /[a-z0-9]{30}-[a-z0-9]{10}/g,
  "New Relic Key": /NRII-[a-zA-Z0-9]{20,}/g,
  "Mixpanel Token": /mixpanel_?token[‘“\s:=]+[a-f0-9]{32}/gi,
  "Heap Analytics App ID": /heap_?app_?id[‘“\s:=]+[a-z0-9]{10}/gi,
  "Keen IO Project ID": /keen_?project_?id[‘“\s:=]+[a-f0-9]{24}/gi,
  "Keen IO Write Key": /keen_?write_?key[‘“\s:=]+[a-f0-9]{128}/gi,
  "Snyk Token": /snyk_token\s*=\s*[a-f0-9\-]{36}/g,
  "Rollbar Access Token": /access_token['"]?\s*:\s*['"][a-z0-9]{32}['"]/g,
  "Twitch API Key": /twitch_?client_?id[‘“\s:=]+[a-z0-9]{30}/gi,
  "Discord Bot Token": /[MN][A-Za-z\d]{23}\.[\w-]{6}\.[\w-]{27}/g,
  "Discord Webhook URL": /https:\/\/discord\.com\/api\/webhooks\/[0-9]+\/[a-zA-Z0-9_-]+/g,
  "Steam Web API Key": /steam_?api_?key[‘“\s:=]+[A-F0-9]{32}/gi,
  "Riot Games API Key": /RGAPI-[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}/g,
  "Private IP (Internal)": /\b(10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})\b/g,
  "Localhost Reference": /localhost:[0-9]{2,5}/g,
  "Dev/Stage URL": /(dev|staging|test)\.[a-z0-9.-]+\.(com|net|io|org)/g,
  "Internal Subdomain URL": /internal\.[a-z0-9.-]+\.(com|net|io|org)/g,
  "Preprod URLs": /(preprod|qa|uat)\.[a-z0-9.-]+\.(com|net|io|org)/g,
  "Private Key Block": /-----BEGIN [A-Z ]+ PRIVATE KEY-----/g,
  "PEM File Content": /-----BEGIN [A-Z ]+-----/g,
  "PGP Private Key Block": /-----BEGIN PGP PRIVATE KEY BLOCK-----/g,
  "Base64 High Entropy String": /[A-Za-z0-9+/]{40,}={0,2}/g,
  "API Key Generic Detector": /(api_key|apikey|api-key)['"\s:=]+[a-zA-Z0-9\-._]{16,}/gi,
  "Bearer Token Generic": /Bearer\s+[a-zA-Z0-9\-._~+/]+=*/g,
  "Session ID": /session_?id[‘“\s:=]+[a-zA-Z0-9_-]{20,}/gi,
  "Cookie Name Generic": /set-cookie[‘“\s:=]+[a-zA-Z0-9_-]+=[a-zA-Z0-9_-]+/gi,
  "CSRF Token": /csrf_?token[‘“\s:=]+[a-zA-Z0-9_-]{20,}/gi,
  "JWT in Local Storage": /localStorage\.setItem\(.+ey[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*/g,
  "Generic_Secret": /(?:password|secret|token|apiKey|api_key)\s*[:=]\s*['"]([^'"]{8,})['"]/gi
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
      for (const [provider, regex] of Object.entries(SECURITY_PATTERNS)) {
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
      console.log(`\n${BLUE}${BOLD}STATUS: PASS. No issues detected.${RESET}`);
      process.exit(0);
    }
  }
}

const sniffer = new SniffSec();
sniffer.sniff();
