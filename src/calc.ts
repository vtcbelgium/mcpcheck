// MCP (Model Context Protocol) Security & Rug-Pull Scanner
// Deterministic 100% client-side schema and config auditor

export type FindingSeverity = 'critical' | 'high' | 'medium' | 'low' | 'info';

export interface Finding {
  severity: FindingSeverity;
  title: string;
  description: string;
  serverName?: string;
  recommendation: string;
}

export interface McpAuditResult {
  validJson: boolean;
  totalServers: number;
  findings: Finding[];
  passedRiskFree: boolean;
}

const TOXIC_COMMANDS = [
  'curl', 'wget', 'nc', 'netcat', 'ncat', 'bash -i', '/bin/sh', 'powershell -enc',
  'rm -rf', 'dd if=', 'mkfs', 'del /f /s /q', 'format c:',
];

const SUSPICIOUS_ENV_KEYS = [
  'AWS_SECRET_ACCESS_KEY', 'OPENAI_API_KEY', 'ANTHROPIC_API_KEY', 'GITHUB_TOKEN',
  'GH_TOKEN', 'SSH_PRIVATE_KEY', 'DATABASE_URL', 'SECRET_KEY',
];

export function auditMcpConfig(rawText: string): McpAuditResult {
  const findings: Finding[] = [];

  if (!rawText.trim()) {
    return { validJson: false, totalServers: 0, findings: [], passedRiskFree: false };
  }

  let parsed: any;
  try {
    parsed = JSON.parse(rawText);
  } catch (err: any) {
    findings.push({
      severity: 'critical',
      title: 'Invalid JSON Syntax',
      description: `Failed to parse MCP configuration: ${err.message}`,
      recommendation: 'Fix JSON formatting before running agent sessions.',
    });
    return { validJson: false, totalServers: 0, findings, passedRiskFree: false };
  }

  // Handle standard formats: { mcpServers: { ... } } or root servers object { ... }
  const servers = parsed.mcpServers || parsed.servers || parsed;

  if (typeof servers !== 'object' || servers === null || Array.isArray(servers)) {
    findings.push({
      severity: 'high',
      title: 'Malformed MCP Servers Object',
      description: 'Expected "mcpServers" to be a key-value dictionary of server definitions.',
      recommendation: 'Ensure your config has the standard structure: { "mcpServers": { "server-name": { ... } } }',
    });
    return { validJson: true, totalServers: 0, findings, passedRiskFree: false };
  }

  const serverKeys = Object.keys(servers);

  for (const name of serverKeys) {
    const s = servers[name];
    if (typeof s !== 'object' || s === null) continue;

    const command: string = (s.command || '').toLowerCase();
    const args: string[] = Array.isArray(s.args) ? s.args.map((a: any) => String(a)) : [];
    const env: Record<string, string> = typeof s.env === 'object' && s.env !== null ? s.env : {};

    // Check 1: Insecure Shell Execution
    if (command === 'sh' || command === 'bash' || command === 'cmd' || command === 'cmd.exe' || command === 'powershell' || command === 'powershell.exe' || command === 'pwsh') {
      findings.push({
        severity: 'high',
        serverName: name,
        title: `Spawning Raw Shell Wrapper (${command})`,
        description: `Server "${name}" directly invokes a system shell rather than a pinned binary executable. This facilitates shell escape and arbitrary parameter chaining.`,
        recommendation: 'Target the pinned binary directly (e.g. `npx`, `python`, `node`) without intermediate shell interpreters.',
      });
    }

    // Check 2: Toxic Commands in Args
    const fullArgLine = args.join(' ').toLowerCase();
    for (const toxic of TOXIC_COMMANDS) {
      if (fullArgLine.includes(toxic) || command.includes(toxic)) {
        findings.push({
          severity: 'critical',
          serverName: name,
          title: `Dangerous Payload Detected: "${toxic}"`,
          description: `Server "${name}" command line contains suspicious payload patterns known for network exfiltration or destructive file operations.`,
          recommendation: 'Audit this tool entry immediately and isolate it in a disposable sandbox container before running.',
        });
      }
    }

    // Check 3: Hardcoded Secrets in Config
    for (const [k, v] of Object.entries(env)) {
      const isSensitiveKey = SUSPICIOUS_ENV_KEYS.some(sk => k.toUpperCase().includes(sk));
      if (isSensitiveKey && v && !v.startsWith('$') && !v.startsWith('{') && v.length > 8) {
        findings.push({
          severity: 'critical',
          serverName: name,
          title: `Plaintext Secret in Env: ${k}`,
          description: `Server "${name}" appears to store unencrypted credentials in plaintext within config file (${k}=${v.substring(0, 4)}...).`,
          recommendation: 'Migrate secret values to secure environment variables or keychain secrets.',
        });
      }
    }

    // Check 4: Unpinned npx / uvx execution (Supply chain risk)
    if (command === 'npx' || command === 'uvx' || command === 'bunx') {
      const unversionedPkg = args.find(a => {
        if (a.startsWith('-')) return false;
        // If scoped (@org/pkg), check if there is an @version after the scope
        if (a.startsWith('@')) {
          const slashIdx = a.indexOf('/');
          if (slashIdx === -1) return true;
          return !a.slice(slashIdx + 1).includes('@');
        }
        return !a.includes('@');
      });
      if (unversionedPkg) {
        findings.push({
          severity: 'medium',
          serverName: name,
          title: `Unpinned Package Execution: "${unversionedPkg}"`,
          description: `Server "${name}" runs via dynamic package manager without an explicit version lock (e.g. \`pkg@1.2.3\`). A malicious upstream publish could compromise your agent environment.`,
          recommendation: `Pin the package to an immutable version tag: e.g. \`${unversionedPkg}@x.y.z\`.`,
        });
      }
    }

    // Check 5: SSE / WebSocket URL risks
    if (s.url && typeof s.url === 'string') {
      if (s.url.startsWith('http://')) {
        findings.push({
          severity: 'high',
          serverName: name,
          title: 'Unencrypted HTTP Transport',
          description: `Server "${name}" connects to an unencrypted endpoint (${s.url}). Tokens and tool parameters are vulnerable to eavesdropping and MITM.`,
          recommendation: 'Use encrypted HTTPS or WSS connections for all remote MCP endpoints.',
        });
      }
    }
  }

  // If no high/critical findings, add info
  if (findings.length === 0) {
    findings.push({
      severity: 'info',
      title: 'No Immediate Vulnerabilities Found',
      description: `Scanned ${serverKeys.length} server definition(s). All command invocations and parameters adhere to standard security seatbelts.`,
      recommendation: 'Keep MCP tool scopes minimal and review new tool schemas regularly with Aegis.',
    });
  }

  const passedRiskFree = !findings.some(f => f.severity === 'critical' || f.severity === 'high');

  return {
    validJson: true,
    totalServers: serverKeys.length,
    findings,
    passedRiskFree,
  };
}
