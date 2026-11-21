export type AssetNodeType = 'root' | 'subdomain' | 'port' | 'web' | 'technology' | 'api' | 'config' | 'cve' | 'finding' | 'tls' | 'dns' | 'group';

export interface AssetTreeNode {
  id: string;
  label: string;
  type: AssetNodeType;
  status?: string;
  meta?: string;
  historyId?: number;
  findingId?: string;
  children: AssetTreeNode[];
}

export interface AssetHistoryEntry {
  id: number;
  scanType: string;
  target: string;
  result: string;
  createdAt?: string;
}

function hostFromTarget(target: string): string {
  try {
    const parsed = new URL(/^[a-z][a-z0-9+.-]*:\/\//i.test(target) ? target : `https://${target}`);
    return parsed.hostname.replace(/^www\./i, '').toLowerCase();
  } catch {
    return target.trim().split(/[/:?#]/)[0].replace(/^www\./i, '').toLowerCase();
  }
}

function rootDomain(host: string): string {
  const parts = host.split('.').filter(Boolean);
  return parts.length > 2 ? parts.slice(-2).join('.') : host;
}

function safeResult(entry: AssetHistoryEntry): any {
  try { return JSON.parse(entry.result || 'null'); } catch { return null; }
}

function pushUnique(parent: AssetTreeNode, node: AssetTreeNode): void {
  if (!parent.children.some((child) => child.id === node.id)) parent.children.push(node);
}

function group(parent: AssetTreeNode, id: string, label: string, historyId?: number): AssetTreeNode {
  const existing = parent.children.find((child) => child.id === id);
  if (existing) return existing;
  const node: AssetTreeNode = { id, label, type: 'group', historyId, children: [] };
  parent.children.push(node);
  return node;
}

function addFindings(parent: AssetTreeNode, findings: any[], historyId: number): void {
  for (const finding of Array.isArray(findings) ? findings : []) {
    const id = String(finding?.id || finding?.title || '').trim();
    if (!id) continue;
    pushUnique(parent, {
      id: `finding:${historyId}:${id}`,
      label: String(finding?.title || id),
      type: 'finding',
      status: String(finding?.severity || 'info').toLowerCase(),
      meta: finding?.recommendation ? String(finding.recommendation) : undefined,
      historyId,
      findingId: id,
      children: [],
    });
  }
}

function addWebResult(root: AssetTreeNode, result: any, historyId: number): void {
  const url = String(result?.finalUrl || result?.url || '').trim();
  if (!url) return;
  const endpoint: AssetTreeNode = {
    id: `web:${historyId}:${url}`,
    label: url,
    type: 'web',
    status: result?.grade ? `Grade ${result.grade}` : undefined,
    meta: typeof result?.riskScore === 'number' ? `Risk ${result.riskScore}/100` : undefined,
    historyId,
    children: [],
  };
  const technologies = [...(Array.isArray(result?.technologies) ? result.technologies : []), ...(Array.isArray(result?.edgeServices) ? result.edgeServices : [])];
  for (const technology of technologies) {
    pushUnique(endpoint, { id: `tech:${historyId}:${url}:${technology}`, label: String(technology), type: 'technology', historyId, children: [] });
  }
  const attackSurface = result?.attackSurface || {};
  for (const api of [...(Array.isArray(attackSurface.apiPaths) ? attackSurface.apiPaths : []), ...(Array.isArray(attackSurface.endpoints) ? attackSurface.endpoints : [])]) {
    pushUnique(endpoint, { id: `api:${historyId}:${url}:${api}`, label: String(api), type: 'api', historyId, children: [] });
  }
  for (const leak of Array.isArray(result?.configLeaks) ? result.configLeaks : []) {
    pushUnique(endpoint, { id: `config:${historyId}:${url}:${leak.id || leak.type || leak.key || JSON.stringify(leak)}`, label: String(leak.title || leak.type || leak.key || 'Configuration exposure'), type: 'config', status: String(leak.severity || 'review'), historyId, children: [] });
  }
  for (const advisory of Array.isArray(result?.advisoryMatches) ? result.advisoryMatches : []) {
    const cve = String(advisory.cve || advisory.id || advisory.product || 'CVE advisory');
    pushUnique(endpoint, { id: `cve:${historyId}:${url}:${cve}`, label: cve, type: 'cve', status: String(advisory.severity || 'review'), meta: String(advisory.title || advisory.description || ''), historyId, children: [] });
  }
  addFindings(endpoint, result?.findings, historyId);
  const host = hostFromTarget(url);
  const webGroup = group(root, `web-group:${host}`, 'Web endpoints', historyId);
  pushUnique(webGroup, endpoint);
}

export function buildAssetTree(entries: AssetHistoryEntry[]): AssetTreeNode[] {
  const roots = new Map<string, AssetTreeNode>();
  for (const entry of entries || []) {
    const parsed = safeResult(entry);
    const targetHost = hostFromTarget(entry.target);
    const rootName = rootDomain(targetHost || entry.target || 'unknown');
    let root = roots.get(rootName);
    if (!root) {
      root = { id: `root:${rootName}`, label: rootName || 'Unknown target', type: 'root', children: [] };
      roots.set(rootName, root);
    }
    const scanType = String(entry.scanType || '').toLowerCase();
    if (scanType.includes('subdomain')) {
      const result = parsed || {};
      const subdomains = group(root, `subdomains:${rootName}`, 'Subdomains', entry.id);
      for (const name of Array.isArray(result.names) ? result.names : []) {
        const clue = Array.isArray(result.takeoverClues) ? result.takeoverClues.find((item: any) => item?.subdomain === name) : undefined;
        pushUnique(subdomains, { id: `subdomain:${entry.id}:${name}`, label: String(name), type: 'subdomain', status: clue?.status, meta: clue?.provider, historyId: entry.id, children: [] });
      }
      continue;
    }
    if (scanType.includes('port')) {
      const ports = group(root, `ports:${rootName}`, 'Open ports / services', entry.id);
      for (const finding of Array.isArray(parsed) ? parsed : []) {
        if (typeof finding?.port !== 'number') continue;
        const label = `${finding.port}/${finding.protocol || 'tcp'} · ${finding.service || 'unknown service'}`;
        const portNode: AssetTreeNode = { id: `port:${entry.id}:${finding.port}`, label, type: 'port', status: finding.version || undefined, meta: finding.banner || finding.fingerprint || undefined, historyId: entry.id, children: [] };
        for (const advisory of [...(Array.isArray(finding?.advisoryMatches) ? finding.advisoryMatches : []), ...(Array.isArray(finding?.cves) ? finding.cves : [])]) {
          const cve = String(advisory?.cve || advisory?.id || advisory).trim();
          if (cve) pushUnique(portNode, { id: `port-cve:${entry.id}:${finding.port}:${cve}`, label: cve, type: 'cve', status: String(advisory?.severity || 'review'), historyId: entry.id, children: [] });
        }
        pushUnique(ports, portNode);
      }
      continue;
    }
    if (scanType.includes('http')) {
      for (const result of Array.isArray(parsed) ? parsed : [parsed]) addWebResult(root, result, entry.id);
      continue;
    }
    if (scanType.includes('tls')) {
      const tls = group(root, `tls:${rootName}`, 'TLS inspections', entry.id);
      pushUnique(tls, { id: `tls:${entry.id}`, label: `${entry.target} · ${parsed?.tlsVersion || 'TLS'}`, type: 'tls', status: parsed?.cipherSuite, meta: parsed?.negotiatedProtocol, historyId: entry.id, children: [] });
      continue;
    }
    if (scanType.includes('dns')) {
      const dns = group(root, `dns:${rootName}`, 'DNS intelligence', entry.id);
      for (const recordType of ['a', 'aaaa', 'mx', 'ns', 'txt', 'spf', 'dmarc']) {
        const values = Array.isArray(parsed?.[recordType]) ? parsed[recordType] : [];
        for (const value of values.slice(0, 30)) pushUnique(dns, { id: `dns:${entry.id}:${recordType}:${value}`, label: `${recordType.toUpperCase()} · ${value}`, type: 'dns', historyId: entry.id, children: [] });
      }
      continue;
    }
    const miscellaneous = group(root, `other:${rootName}`, 'Other observations', entry.id);
    addFindings(miscellaneous, parsed?.findings, entry.id);
  }
  return [...roots.values()].sort((a, b) => a.label.localeCompare(b.label));
}

export function filterAssetTree(nodes: AssetTreeNode[], query: string): AssetTreeNode[] {
  const needle = query.trim().toLowerCase();
  if (!needle) return nodes;
  const visit = (node: AssetTreeNode): AssetTreeNode | null => {
    const children = node.children.map(visit).filter((child): child is AssetTreeNode => child !== null);
    if (node.label.toLowerCase().includes(needle) || node.status?.toLowerCase().includes(needle) || children.length) return { ...node, children };
    return null;
  };
  return nodes.map(visit).filter((node): node is AssetTreeNode => node !== null);
}

function escapeXML(value: string): string {
  return value.replace(/[&<>"']/g, (char) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&apos;' }[char] || char));
}

export function assetTreeToSVG(nodes: AssetTreeNode[]): string {
  const lines: string[] = [];
  const walk = (node: AssetTreeNode, depth: number) => {
    const prefix = `${'  '.repeat(depth)}${node.type === 'root' ? '◆' : '└─'} ${node.label}${node.status ? ` [${node.status}]` : ''}`;
    lines.push(prefix);
    node.children.forEach((child) => walk(child, depth + 1));
  };
  nodes.forEach((node) => walk(node, 0));
  const width = 1400;
  const lineHeight = 24;
  const height = Math.max(120, (lines.length + 1) * lineHeight + 32);
  const text = lines.map((line, index) => `<text x="24" y="${48 + index * lineHeight}" fill="#dbeafe" font-family="ui-monospace, SFMono-Regular, Menlo, monospace" font-size="15">${escapeXML(line)}</text>`).join('');
  return `<svg xmlns="http://www.w3.org/2000/svg" width="${width}" height="${height}" viewBox="0 0 ${width} ${height}"><rect width="100%" height="100%" fill="#020617"/><text x="24" y="24" fill="#34d399" font-family="ui-sans-serif, system-ui" font-size="16" font-weight="700">Codexa Scanner · Visual Attack Surface</text>${text}</svg>`;
}
