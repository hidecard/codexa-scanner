import { useState, useEffect, useRef } from 'react';
import {
  StartPortScan,
  StopPortScan,
  StartCIDRSweep,
  AnalyzeBulkURLs,
  ExportJSON,
  ExportPortsCSV,
  ExportText,
  ExportPDF,
  EnumerateSubdomains,
  FuzzPaths,
  InspectTLS,
  IPInformation,
  DNSIntelligence,
  SearchScanHistory,
  DiffLatestPortScans,
  DiffLatestWebAuditScans,
  DeleteScanHistoryEntry,
  ClearScanHistory,
  GetRemediationKnowledge,
  PauseScans,
  ResumeScans,
  IsScansPaused,
  CreateWorkspace,
  ListWorkspaces,
  DeleteWorkspace,
  GetWorkspaceScans,
  UpdateHistoryWorkspace,
  GetFindingTags,
  GetFindingNotes,
  SetFindingTag,
  SetFindingNote,
  DeleteFindingTag,
  DeleteFindingNote,
  ImportNmapXML,
  ImportNmapXMLFile,
  ImportNmapXMLToWorkspace,
  ImportSubdomains,
  ImportSubdomainsFile,
  ImportSubdomainsToWorkspace,
  InspectHTTP,
  ReplayHTTPRequest,
  SyncLatestCVEs,
  GetLatestThreatFeed,
  SyncLiveCVEFeed,
  GetCachedCVEFeed,
  GetHistoryDBPath,
  IsHistoryDBReady,
} from '../wailsjs/go/main/App';
import { EventsOn, EventsOff, BrowserOpenURL } from '../wailsjs/runtime/runtime';
import { main } from '../wailsjs/go/models';
import { AssetTreeNode, assetTreeToSVG, buildAssetTree, filterAssetTree } from './assetTree';
type ActiveTab = 'dashboard' | 'scanner' | 'analyzer' | 'subdomains' | 'fuzzer' | 'tls' | 'dns' | 'ip' | 'history' | 'assetTree' | 'playbook' | 'workspaces' | 'import' | 'inspector' | 'about' | 'cvefeed';
type GuideLang = 'en' | 'my';

type NavGroup = 'dashboard' | 'network' | 'web' | 'assessment' | 'reports' | 'settings';

const NAV_GROUPS: Record<NavGroup, { label: string; tabs: { id: ActiveTab; label: string }[] }> = {
  dashboard: { label: 'Dashboard', tabs: [{ id: 'dashboard', label: 'Dashboard' }] },
  network: { label: 'Network Intelligence', tabs: [
    { id: 'subdomains', label: 'Subdomains' },
    { id: 'fuzzer', label: 'Path Fuzzer' },
    { id: 'tls', label: 'TLS' },
    { id: 'dns', label: 'DNS' },
    { id: 'ip', label: 'IP Info' },
  ] },
  web: { label: 'Web Security', tabs: [
    { id: 'analyzer', label: 'Web Audit' },
    { id: 'inspector', label: 'Inspector' },
  ] },
  assessment: { label: 'Assessment', tabs: [
    { id: 'scanner', label: 'Ports' },
    { id: 'cvefeed', label: 'CVE Feed' },
  ] },
  reports: { label: 'Reports & History', tabs: [
    { id: 'history', label: 'History' },
    { id: 'assetTree', label: 'Asset Tree' },
    { id: 'playbook', label: 'Playbook' },
  ] },
  settings: { label: 'Settings', tabs: [
    { id: 'workspaces', label: 'Workspaces' },
    { id: 'import', label: 'Import' },
    { id: 'about', label: 'About' },
  ] },
};

const GROUP_ORDER: NavGroup[] = ['dashboard', 'network', 'web', 'assessment', 'reports', 'settings'];

function shellQuote(value: string): string {
  return `'${value.replace(/'/g, `'\\''`)}'`;
}

function verificationCommands(result: main.BulkHeaderResult): { label: string; command: string }[] {
  let parsed: URL;
  try {
    parsed = new URL(result.finalUrl || result.url);
  } catch {
    return [];
  }
  if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') return [];
  const host = parsed.hostname.replace(/^\[|\]$/g, '');
  const port = parsed.port || (parsed.protocol === 'https:' ? '443' : '80');
  // Do not copy credentials or potentially sensitive query/fragment values into a terminal.
  parsed.username = '';
  parsed.password = '';
  parsed.search = '';
  parsed.hash = '';
  const safeURL = parsed.toString();
  const signals = (result.findings || []).map((finding) => `${finding.id} ${finding.title}`).join(' ').toLowerCase();
  const commands: { label: string; command: string }[] = [];
  if (result.findings?.length) {
    commands.push({ label: 'HTTP response headers', command: `curl -sS -I --max-time 10 -- ${shellQuote(safeURL)}` });
  }
  if (/tls|certificate|cipher|https/.test(signals) || result.tls) {
    const connectHost = host.includes(':') ? `[${host}]` : host;
    const serverName = host.includes(':') || /^\d{1,3}(?:\.\d{1,3}){3}$/.test(host) ? '' : `-servername ${shellQuote(host)} `;
    commands.push({ label: 'TLS certificate and negotiation', command: `openssl s_client -connect ${shellQuote(`${connectHost}:${port}`)} ${serverName}-brief </dev/null` });
  }
  if (/dns|spf|dmarc|dkim|cname|subdomain/.test(signals)) {
    commands.push({ label: 'DNS records', command: `dig ${shellQuote(host)} A +noall +answer && dig ${shellQuote(host)} TXT +noall +answer` });
  }
  return commands;
}

function AssetTreeBranch({ node, depth, expanded, onToggle, onSelect }: { node: AssetTreeNode; depth: number; expanded: Set<string>; onToggle: (id: string) => void; onSelect: (node: AssetTreeNode) => void }) {
  const hasChildren = node.children.length > 0;
  const isExpanded = expanded.has(node.id);
  const statusColor = node.status && /critical|high|unclaimed|open/i.test(node.status) ? 'text-rose-300' : node.status ? 'text-amber-300' : 'text-slate-500';
  return (
    <div className="min-w-0">
      <div className="flex min-w-0 items-center gap-1" style={{ paddingLeft: `${depth * 16}px` }}>
        {hasChildren ? <button type="button" onClick={() => onToggle(node.id)} className="w-5 shrink-0 rounded text-slate-400 hover:bg-slate-800" aria-label={`${isExpanded ? 'Collapse' : 'Expand'} ${node.label}`}>{isExpanded ? '▾' : '▸'}</button> : <span className="w-5 shrink-0" />}
        <button type="button" onClick={() => onSelect(node)} className="min-w-0 flex-1 rounded px-2 py-1 text-left text-xs hover:bg-slate-800">
          <span className={`mr-2 inline-block rounded border border-slate-700 px-1.5 py-0.5 text-[10px] uppercase ${node.type === 'root' ? 'text-emerald-300' : node.type === 'finding' || node.type === 'cve' ? 'text-rose-300' : 'text-sky-300'}`}>{node.type}</span>
          <span className="break-all text-slate-200">{node.label}</span>
          {node.status && <span className={`ml-2 ${statusColor}`}>{node.status}</span>}
          {node.meta && <span className="ml-2 break-all text-[11px] text-slate-500">{node.meta}</span>}
        </button>
      </div>
      {hasChildren && isExpanded && <div>{node.children.map((child) => <AssetTreeBranch key={child.id} node={child} depth={depth + 1} expanded={expanded} onToggle={onToggle} onSelect={onSelect} />)}</div>}
    </div>
  );
}

export default function App() {
  const [activeTab, setActiveTab] = useState<ActiveTab>('dashboard');
  const [expandedGroups, setExpandedGroups] = useState<Set<NavGroup>>(new Set());
  const navRef = useRef<HTMLNavElement>(null);

  useEffect(() => {
    const handleClickOutside = (event: MouseEvent) => {
      if (navRef.current && !navRef.current.contains(event.target as Node)) {
        setExpandedGroups(new Set());
      }
    };
    document.addEventListener('mousedown', handleClickOutside);
    return () => document.removeEventListener('mousedown', handleClickOutside);
  }, []);

  // --- Port Scanner States ---
  const [target, setTarget] = useState('scanme.nmap.org');
  const [startPort, setStartPort] = useState(1);
  const [endPort, setEndPort] = useState(1024);
  const [scopeConfirmed, setScopeConfirmed] = useState(false);
  const [workers, setWorkers] = useState(200);
  const [timeoutMs, setTimeoutMs] = useState(800);
  const [isScanning, setIsScanning] = useState(false);
  const [progress, setProgress] = useState(0);
  const [findings, setFindings] = useState<main.PortFinding[]>([]);
  const [scanError, setScanError] = useState('');
  const [resolvedScanTarget, setResolvedScanTarget] = useState('');
  const [httpError, setHttpError] = useState('');

  // --- CIDR Sweep States ---
  const [cidrTarget, setCidrTarget] = useState('192.168.1.0/24');
  const [cidrStartPort, setCidrStartPort] = useState(1);
  const [cidrEndPort, setCidrEndPort] = useState(1024);
  const [cidrScopeConfirmed, setCidrScopeConfirmed] = useState(false);
  const [cidrWorkers, setCidrWorkers] = useState(10);
  const [cidrTimeoutMs, setCidrTimeoutMs] = useState(800);
  const [cidrRps, setCidrRps] = useState(0);
  const [cidrJitterMs, setCidrJitterMs] = useState(0);
  const [isCIDRScanning, setIsCIDRScanning] = useState(false);
  const [cidrProgress, setCidrProgress] = useState(0);
  const [cidrResults, setCidrResults] = useState<main.CIDRSweepResult | null>(null);
  const [cidrError, setCidrError] = useState('');

  // --- Bulk HTTP Analyzer States ---
  const [bulkUrls, setBulkUrls] = useState('https://example.com\nhttps://google.com\nhttps://github.com');
  const [scopeFileText, setScopeFileText] = useState('');
  const [scopeFileName, setScopeFileName] = useState('');
  const [excludeFileText, setExcludeFileText] = useState('');
  const [excludeFileName, setExcludeFileName] = useState('');
  const [httpThreads, setHttpThreads] = useState(10);
  const [httpDelayMs, setHttpDelayMs] = useState(0);
  const [allowPrivateHTTPTargets, setAllowPrivateHTTPTargets] = useState(false);
  const [isAnalyzing, setIsAnalyzing] = useState(false);
  const [httpResults, setHttpResults] = useState<main.BulkHeaderResult[]>([]);
  const [copiedVerificationCommand, setCopiedVerificationCommand] = useState('');

  // --- Authorized recon modules ---
  const [subdomain, setSubdomain] = useState('example.com');
  const [subdomainWordlist, setSubdomainWordlist] = useState('www\napi\nmail\ndev\nstaging');
  const [useDNSBrute, setUseDNSBrute] = useState(false);
  const [subdomainResult, setSubdomainResult] = useState<main.SubdomainResult | null>(null);
  const [fuzzBaseURL, setFuzzBaseURL] = useState('https://example.com');
  const [fuzzWordlist, setFuzzWordlist] = useState('/admin\n/dashboard\n/robots.txt\n/.well-known/security.txt');
  const [fuzzConcurrency, setFuzzConcurrency] = useState(5);
  const [fuzzDelayMs, setFuzzDelayMs] = useState(0);
  const [fuzzResult, setFuzzResult] = useState<main.PathFuzzResult | null>(null);
  const [tlsTarget, setTlsTarget] = useState('example.com:443');
  const [tlsResult, setTlsResult] = useState<main.TLSInspection | null>(null);
  const [dnsDomain, setDnsDomain] = useState('example.com');
  const [includeRDAP, setIncludeRDAP] = useState(false);
  const [dnsResult, setDnsResult] = useState<main.DNSIntelligenceResult | null>(null);
  const [ipTarget, setIpTarget] = useState('8.8.8.8');
  const [ipResult, setIpResult] = useState<main.IPInformationResult | null>(null);
  const [historyTarget, setHistoryTarget] = useState('scanme.nmap.org');
  const [historyEntries, setHistoryEntries] = useState<main.HistoryEntry[]>([]);
  const [assetTreeQuery, setAssetTreeQuery] = useState('');
  const [assetTreeExpanded, setAssetTreeExpanded] = useState<Set<string>>(new Set());
  const [assetTreeSelected, setAssetTreeSelected] = useState<AssetTreeNode | null>(null);
  const [selectedHistoryIds, setSelectedHistoryIds] = useState<number[]>([]);
  const [historySearch, setHistorySearch] = useState('');
  const [historyTypeFilter, setHistoryTypeFilter] = useState<'all' | 'port' | 'http' | 'subdomain' | 'fuzzer' | 'tls' | 'dns' | 'ip'>('all');
  const [portDiff, setPortDiff] = useState<main.PortScanDiff | null>(null);
  const [webAuditDiff, setWebAuditDiff] = useState<main.WebAuditDiff | null>(null);
  const [isReconBusy, setIsReconBusy] = useState(false);
  const [reconError, setReconError] = useState('');
  const [isHistoryBusy, setIsHistoryBusy] = useState(false);
  const [historyError, setHistoryError] = useState('');

  // Phase 17
  const [httpRps, setHttpRps] = useState(0);
  const [httpJitterMs, setHttpJitterMs] = useState(0);
  const [fuzzRps, setFuzzRps] = useState(0);
  const [fuzzJitterMs, setFuzzJitterMs] = useState(0);
  const [requestUserAgent, setRequestUserAgent] = useState('');
  const [requestTimeout, setRequestTimeout] = useState(10);
  const [customHeaders, setCustomHeaders] = useState('Authorization: Bearer ***\nCookie: session=***');
  const [customHeadersOpen, setCustomHeadersOpen] = useState(false);
  const [proxyURL, setProxyURL] = useState('');
  const [isPaused, setIsPaused] = useState(false);
  const [commandPaletteOpen, setCommandPaletteOpen] = useState(false);
  const [paletteQuery, setPaletteQuery] = useState('');
  const [remediationKB, setRemediationKB] = useState<any | null>(null);
  const [playbookLang, setPlaybookLang] = useState<GuideLang>('en');
  const [playbookStack, setPlaybookStack] = useState('Next.js');
  const [playbookQuery, setPlaybookQuery] = useState('');
  const [findingDrawerId, setFindingDrawerId] = useState<string | null>(null);
  const [findingDrawerHistoryId, setFindingDrawerHistoryId] = useState<number | null>(null);
  const selectedHistoryEntries = historyEntries.filter((entry) => selectedHistoryIds.includes(entry.id));
  const assetTreeNodes = filterAssetTree(buildAssetTree(historyEntries), assetTreeQuery);
  const [detectedTechStack, setDetectedTechStack] = useState('Next.js');

  // Phase 15 - Import & HTTP Inspector
  const [importNmapFile, setImportNmapFile] = useState<File | null>(null);
  const [importNmapText, setImportNmapText] = useState('');
  const [importSubdomainsFile, setImportSubdomainsFile] = useState<File | null>(null);
  const [importSubdomainsText, setImportSubdomainsText] = useState('');
  const [importWorkspaceID, setImportWorkspaceID] = useState<number | null>(null);
  const [nmapImportResult, setNmapImportResult] = useState<main.NmapImportResult | null>(null);
  const [subdomainImportResult, setSubdomainImportResult] = useState<main.SubdomainImportResult | null>(null);
  const [importError, setImportError] = useState('');

  const [inspectURL, setInspectURL] = useState('');
  const [inspectMethod, setInspectMethod] = useState<'GET' | 'HEAD' | 'OPTIONS'>('GET');
  const [inspectHeaders, setInspectHeaders] = useState('');
  const [inspectAllowPrivate, setInspectAllowPrivate] = useState(false);
  const [inspectTimeout, setInspectTimeout] = useState(10);
  const [inspectResult, setInspectResult] = useState<main.HTTPInspectorResponse | null>(null);
  const [inspectError, setInspectError] = useState('');
  const [isInspecting, setIsInspecting] = useState(false);

  // Phase 16 - Workspaces & Analyst Triage
  const [workspaces, setWorkspaces] = useState<main.Workspace[]>([]);
  const [selectedWorkspaceID, setSelectedWorkspaceID] = useState<number | null>(null);
  const [newWorkspaceName, setNewWorkspaceName] = useState('');
  const [newWorkspaceDesc, setNewWorkspaceDesc] = useState('');
  const [workspaceError, setWorkspaceError] = useState('');
  const [findingTags, setFindingTags] = useState<main.FindingTag[]>([]);
  const [findingNotes, setFindingNotes] = useState<main.FindingNote[]>([]);
  const [newTag, setNewTag] = useState<'verified' | 'false_positive' | 'needs_review' | 'accepted_risk'>('verified');
  const [newNote, setNewNote] = useState('');
  const [tagNoteHistoryID, setTagNoteHistoryID] = useState<number | null>(null);
  const [tagNoteFindingID, setTagNoteFindingID] = useState<string>('');
  const [threatFeed, setThreatFeed] = useState<main.ThreatFeedItem[]>([]);
  const [threatFeedDays, setThreatFeedDays] = useState(7);
  const [isThreatFeedBusy, setIsThreatFeedBusy] = useState(false);
  const [threatFeedStatus, setThreatFeedStatus] = useState('');
  const [threatFeedError, setThreatFeedError] = useState('');
  const [isHistoryDBReady, setIsHistoryDBReady] = useState(false);

  // CVE Feed Tab State
  const [cveFeedSummary, setCVEFeedSummary] = useState<main.CVEFeedSummary | null>(null);
  const [cveFeedFilter, setCVEFeedFilter] = useState<'ALL' | 'KEV' | 'CRITICAL' | 'AFFECTED'>('ALL');
  const [cveFeedSearch, setCVEFeedSearch] = useState('');
  const [isCVEFeedLoading, setIsCVEFeedLoading] = useState(false);
  const [cveFeedError, setCVEFeedError] = useState('');
  const [cveFeedLastSynced, setCVEFeedLastSynced] = useState('');
  const [cveFeedStatus, setCVEFeedStatus] = useState('');

  const errorMessage = (error: unknown, fallback: string) => {
    if (error instanceof Error && error.message) return error.message;
    if (typeof error === 'string' && error) return error;
    return fallback;
  };
  const loadRuleFile = async (file: File | undefined, setText: (value: string) => void, setName: (value: string) => void) => {
    if (!file) return;
    setText(await file.text());
    setName(file.name);
  };

  const parseCustomHeaders = (input: string): { [key: string]: string } => {
    const out: { [key: string]: string } = {};
    for (const rawLine of input.split(/\r?\n/)) {
      const line = rawLine.trim();
      if (!line || line.startsWith('#')) continue;
      const idx = line.indexOf(':');
      if (idx <= 0) continue;
      const name = line.slice(0, idx).trim();
      const value = line.slice(idx + 1).trim();
      if (!name || !value) continue;
      out[name] = value;
    }
    return out;
  };

  // Real-time Wails Event Listeners
  useEffect(() => {
    EventsOn('port:found', (finding: main.PortFinding) => {
      setFindings((prev) => [...prev, finding].sort((a, b) => a.port - b.port));
    });

    EventsOn('scan:progress', (pct: number) => {
      setProgress(pct);
    });

    EventsOn('scan:done', (status: string) => {
      setIsScanning(false);
      setIsPaused(false);
      if (status === 'completed') {
        setProgress(100);
      } else if (status === 'cancelled') {
        setProgress((current) => Math.min(current, 99));
        setScanError('Scan cancelled.');
      } else if (status === 'failed') {
        setScanError((current) => current || 'Scan failed unexpectedly. Check the application log for details.');
      }
    });
    EventsOn('scan:target', (address: string) => setResolvedScanTarget(address));
    EventsOn('scan:error', (message: string) => setScanError(message));
    EventsOn('scan:control', (state: string) => setIsPaused(state === 'paused'));

    // CIDR Sweep events
    EventsOn('cidr:progress', (pct: number) => setCidrProgress(pct));
    EventsOn('cidr:sweep-done', (result: main.CIDRSweepResult) => {
      setIsCIDRScanning(false);
      setIsPaused(false);
      setCidrResults(result);
      setCidrProgress(100);
    });
    EventsOn('scan:status', (status: string) => {
      if (status === 'running' && isCIDRScanning) {
        // already running
      }
    });

    return () => {
      EventsOff('port:found');
      EventsOff('scan:progress');
      EventsOff('scan:done');
      EventsOff('scan:target');
      EventsOff('scan:error');
      EventsOff('scan:control');
      EventsOff('cidr:progress');
      EventsOff('cidr:sweep-done');
    };
  }, []);

  useEffect(() => {
    void (async () => { try { setRemediationKB(await GetRemediationKnowledge()); } catch {} })();
  }, []);
  const refreshThreatFeed = async (days = threatFeedDays) => {
    try { 
      const feed = await GetLatestThreatFeed(days); 
      setThreatFeed(feed); 
      setThreatFeedError('');
      setIsHistoryDBReady(true);
    } catch (error) { 
      const msg = errorMessage(error, 'Unable to load local CVE cache.');
      setThreatFeedError(msg);
      setIsHistoryDBReady(!msg.includes('SQLite cache is not available'));
    }
  };
  const syncThreatFeed = async () => {
    if (!isHistoryDBReady) {
      setThreatFeedError('Local SQLite database is not ready. Please wait for initialization or check application logs.');
      return;
    }
    setIsThreatFeedBusy(true); setThreatFeedStatus('Syncing CISA KEV and NVD…'); setThreatFeedError('');
    try { 
      const result = await SyncLatestCVEs(); 
      await refreshThreatFeed(threatFeedDays); 
      if (result.usedCacheOnly) {
        const warningMsg = result.warnings?.length ? ` · ${result.warnings.join('; ')}` : '';
        setThreatFeedStatus(`Using existing local cache (remote sync unavailable)${warningMsg}`);
      } else {
        setThreatFeedStatus(`${result.stored} CVEs cached locally${result.warnings?.length ? ` · ${result.warnings.length} source warning(s)` : ''}`);
      }
    }
    catch (error) { await refreshThreatFeed(threatFeedDays); setThreatFeedStatus('Using existing local cache (remote sync unavailable).'); setThreatFeedError(errorMessage(error, 'Feed sync failed; bundled advisory data and local cache remain active.')); }
    finally { setIsThreatFeedBusy(false); }
  };
  useEffect(() => { void refreshThreatFeed(7); }, []);

  const loadCVEFeed = async () => {
    setIsCVEFeedLoading(true);
    setCVEFeedError('');
    try {
      const summary = await GetCachedCVEFeed(cveFeedFilter, cveFeedFilter === 'AFFECTED');
      setCVEFeedSummary(summary);
      if (summary.lastSyncedAt) {
        const d = new Date(summary.lastSyncedAt);
        setCVEFeedLastSynced(d.toLocaleString());
      }
      setCVEFeedStatus(`Loaded ${summary.totalCached} CVEs from local cache (${summary.kevCount} KEV, ${summary.affectedCount} affecting your assets)`);
    } catch (error) {
      setCVEFeedError(errorMessage(error, 'Failed to load CVE feed'));
    } finally {
      setIsCVEFeedLoading(false);
    }
  };

  const syncCVEFeed = async () => {
    setIsCVEFeedLoading(true);
    setCVEFeedStatus('Syncing CISA KEV and NVD…');
    setCVEFeedError('');
    try {
      const summary = await SyncLiveCVEFeed('');
      setCVEFeedSummary(summary);
      if (summary.lastSyncedAt) {
        const d = new Date(summary.lastSyncedAt);
        setCVEFeedLastSynced(d.toLocaleString());
      }
      if (summary.syncError) {
        setCVEFeedStatus(`Sync completed with warnings: ${summary.syncError}`);
      } else {
        setCVEFeedStatus(`Synced ${summary.totalCached} CVEs (${summary.kevCount} KEV, ${summary.affectedCount} affecting your assets)`);
      }
    } catch (error) {
      setCVEFeedError(errorMessage(error, 'Sync failed'));
    } finally {
      setIsCVEFeedLoading(false);
    }
  };

  useEffect(() => {
    void (async () => {
      try {
        const ws = await ListWorkspaces();
        setWorkspaces(ws || []);
      } catch {}
    })();
  }, []);

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === 'k') { e.preventDefault(); setCommandPaletteOpen(v => !v); setPaletteQuery(''); }
      if (e.key === 'Escape') { setCommandPaletteOpen(false); setFindingDrawerId(null); }
    };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, []);

  const togglePause = async () => {
    try { if (isPaused) { await ResumeScans(); setIsPaused(false); } else { await PauseScans(); setIsPaused(true); } } catch {}
  };
  const detectStackFromResult = (res?: main.BulkHeaderResult | null) => {
    const techs = ((res?.technologies || []).concat(res?.edgeServices || [])).map(t => (t || '').toLowerCase()).join(' ');
    if (techs.includes('next')) return 'Next.js';
    if (techs.includes('laravel') || techs.includes('php')) return 'Laravel';
    if (techs.includes('express') || techs.includes('node')) return 'Express';
    if (techs.includes('nginx')) return 'Nginx';
    if (techs.includes('apache')) return 'Apache';
    if (techs.includes('supabase')) return 'Supabase';
    return 'Next.js';
  };
  const openFindingGuide = (id: string, res?: main.BulkHeaderResult | null, historyId?: number) => {
    const stack = detectStackFromResult(res);
    setDetectedTechStack(stack); setPlaybookStack(stack); setFindingDrawerId(id);
    if (historyId !== undefined) setFindingDrawerHistoryId(historyId);
  };
  const lookupGuide = (id: string | null) => {
    if (!id || !remediationKB?.entries) return null;
    const entries = remediationKB.entries as any[];
    let e = entries.find((x: any) => x.id === id);
    if (!e) {
      const prefixes = ['client-secret-pattern-', 'cookie-secure-missing', 'cookie-httponly-missing', 'cookie-samesite-missing', 'db-error-'];
      const p = prefixes.find(px => id.startsWith(px));
      if (p) e = entries.find((x: any) => x.id === p);
    }
    if (!e) e = entries.find((x: any) => x.id === 'generic-finding');
    return e || null;
  };
  const guideText = (obj: any, key: string) => (obj?.[key]?.[playbookLang] || obj?.[key]?.en || '');
  const guideList = (obj: any, key: string): string[] => (obj?.[key]?.[playbookLang] || obj?.[key]?.en || []);

  const handleStartScan = async () => {
    const confirmedScope = scopeConfirmed;
    setScopeConfirmed(false);
    setScanError('');
    setResolvedScanTarget('');
    setFindings([]);
    setProgress(0);
    setIsScanning(true);

    try {
      const status = await StartPortScan(
        target,
        Number(startPort),
        Number(endPort),
        Number(workers),
        Number(timeoutMs),
        confirmedScope
      );

      if (status !== 'STARTED') {
        setScanError(status);
        setIsScanning(false);
      }
    } catch (error) {
      setScanError(errorMessage(error, 'Unable to start the port scan. Try again.'));
      setIsScanning(false);
    }
  };

  const handleStopScan = async () => {
    try {
      await StopPortScan();
    } catch (error) {
      setScanError(errorMessage(error, 'Unable to stop the port scan. Try again.'));
    }
  };

  const handleStartCIDRSweep = async () => {
    const confirmedScope = cidrScopeConfirmed;
    setCidrScopeConfirmed(false);
    setCidrError('');
    setCidrResults(null);
    setCidrProgress(0);
    setIsCIDRScanning(true);

    try {
      const status = await StartCIDRSweep(
        cidrTarget,
        Number(cidrStartPort),
        Number(cidrEndPort),
        Number(cidrWorkers),
        Number(cidrTimeoutMs),
        confirmedScope,
        Number(cidrRps),
        Number(cidrJitterMs)
      );

      if (status !== 'STARTED') {
        setCidrError(status);
        setIsCIDRScanning(false);
      }
    } catch (error) {
      setCidrError(errorMessage(error, 'Unable to start the CIDR sweep. Try again.'));
      setIsCIDRScanning(false);
    }
  };

  const handleStopCIDRSweep = async () => {
    try {
      await StopPortScan();
    } catch (error) {
      setCidrError(errorMessage(error, 'Unable to stop the CIDR sweep. Try again.'));
    }
  };

  const handleBulkAnalyze = async () => {
    const allowPrivateForBatch = allowPrivateHTTPTargets;
    setAllowPrivateHTTPTargets(false);
    setIsAnalyzing(true);
    setHttpResults([]);
    setHttpError('');
    try {
      const headers = parseCustomHeaders(customHeaders);
      const res = await AnalyzeBulkURLs(bulkUrls, Number(httpThreads), allowPrivateForBatch, Number(httpDelayMs), Number(httpRps), Number(httpJitterMs), requestUserAgent, Number(requestTimeout), headers, proxyURL, scopeFileText, excludeFileText);
      setHttpResults(res || []);
    } catch (error) {
      setHttpError(errorMessage(error, 'Unable to analyze the URLs. Check the inputs and try again.'));
    } finally {
      setIsAnalyzing(false);
    }
  };

  const runSubdomainDiscovery = async () => {
    setIsReconBusy(true);
    setReconError('');
    try {
      setSubdomainResult(await EnumerateSubdomains(subdomain, subdomainWordlist.split(/\r?\n/), useDNSBrute));
    } catch (error) {
      setReconError(errorMessage(error, 'Unable to enumerate subdomains. Try again.'));
    } finally {
      setIsReconBusy(false);
    }
  };
  const runPathFuzzer = async () => {
    setIsReconBusy(true);
    setReconError('');
    try {
      setFuzzResult(await FuzzPaths(fuzzBaseURL, fuzzWordlist.split(/\r?\n/), Number(fuzzConcurrency), Number(fuzzDelayMs), Number(fuzzRps), Number(fuzzJitterMs), requestUserAgent, Number(requestTimeout), proxyURL));
    } catch (error) {
      setReconError(errorMessage(error, 'Unable to run path checks. Try again.'));
    } finally {
      setIsReconBusy(false);
    }
  };
  const runTLSInspector = async () => {
    setIsReconBusy(true);
    setReconError('');
    try {
      setTlsResult(await InspectTLS(tlsTarget));
    } catch (error) {
      setReconError(errorMessage(error, 'Unable to inspect TLS. Check the target and try again.'));
    } finally {
      setIsReconBusy(false);
    }
  };
  const runDNSIntelligence = async () => {
    setIsReconBusy(true);
    setReconError('');
    try {
      setDnsResult(await DNSIntelligence(dnsDomain, includeRDAP));
    } catch (error) {
      setReconError(errorMessage(error, 'Unable to inspect DNS records. Check the domain and try again.'));
    } finally {
      setIsReconBusy(false);
    }
  };
  const runIPInformation = async () => {
    setIsReconBusy(true);
    setReconError('');
    try {
      setIpResult(await IPInformation(ipTarget));
    } catch (error) {
      setReconError(errorMessage(error, 'Unable to inspect the IP address. Check the input and try again.'));
    } finally {
      setIsReconBusy(false);
    }
  };
  const refreshHistory = async () => {
    setIsHistoryBusy(true);
    setHistoryError('');
    try {
      const entries = await SearchScanHistory(50, historyTypeFilter === 'all' ? '' : historyTypeFilter, historySearch.trim());
      const nextEntries = entries || [];
      setHistoryEntries(nextEntries);
      setSelectedHistoryIds((previous) => previous.filter((id) => nextEntries.some((entry) => entry.id === id)));
      const target = historyTarget.trim();
      setPortDiff(target ? await DiffLatestPortScans(target) : null);
      setWebAuditDiff(target ? await DiffLatestWebAuditScans(target) : null);
    } catch (error) {
      setHistoryError(errorMessage(error, 'Unable to load local scan history. Try again.'));
      setHistoryEntries([]);
      setPortDiff(null);
      setWebAuditDiff(null);
    } finally {
      setIsHistoryBusy(false);
    }
  };

  const runWebAuditDiff = async () => {
    setIsHistoryBusy(true);
    setHistoryError('');
    try {
      const target = historyTarget.trim();
      setWebAuditDiff(target ? await DiffLatestWebAuditScans(target) : null);
    } catch (error) {
      setHistoryError(errorMessage(error, 'Unable to compare Web Audit snapshots. Try again.'));
      setWebAuditDiff(null);
    } finally {
      setIsHistoryBusy(false);
    }
  };

  const handleDeleteHistoryEntry = async (id: number) => {
    if (!window.confirm('Delete this history entry? This cannot be undone.')) return;
    setIsHistoryBusy(true);
    setHistoryError('');
    try {
      await DeleteScanHistoryEntry(id);
      await refreshHistory();
    } catch (error) {
      setHistoryError(errorMessage(error, 'Unable to delete the history entry. Try again.'));
      setIsHistoryBusy(false);
    }
  };

  const handleClearHistory = async () => {
    if (!window.confirm('Clear all local scan history? This cannot be undone.')) return;
    setIsHistoryBusy(true);
    setHistoryError('');
    try {
      await ClearScanHistory();
      setHistoryEntries([]);
      setSelectedHistoryIds([]);
      setPortDiff(null);
      setWebAuditDiff(null);
    } catch (error) {
      setHistoryError(errorMessage(error, 'Unable to clear local scan history. Try again.'));
    } finally {
      setIsHistoryBusy(false);
    }
  };

  const toggleHistorySelection = (id: number) => {
    setSelectedHistoryIds((previous) => previous.includes(id) ? previous.filter((value) => value !== id) : [...previous, id]);
  };

  const exportEngagementReport = (format: 'json' | 'pdf') => {
    if (!selectedHistoryEntries.length) return;
    const filename = format === 'json' ? 'engagement_report.json' : 'engagement_report.pdf';
    const payload = JSON.stringify(selectedHistoryEntries);
    if (format === 'json') void ExportJSON(filename, payload);
    else void ExportPDF(filename, payload);
  };
  const toggleAssetTreeNode = (id: string) => {
    setAssetTreeExpanded((previous) => {
      const next = new Set(previous);
      if (next.has(id)) next.delete(id); else next.add(id);
      return next;
    });
  };
  const selectAssetTreeNode = (node: AssetTreeNode) => {
    setAssetTreeSelected(node);
    if (node.findingId) {
      setFindingDrawerId(node.findingId);
      setFindingDrawerHistoryId(node.historyId ?? null);
    }
  };
  const expandAllAssetTree = () => {
    const ids = new Set<string>();
    const visit = (nodes: AssetTreeNode[]) => nodes.forEach((node) => { ids.add(node.id); visit(node.children); });
    visit(assetTreeNodes);
    setAssetTreeExpanded(ids);
  };
  const downloadAssetTreeFile = (filename: string, content: string | Blob, type: string) => {
    const blob = content instanceof Blob ? content : new Blob([content], { type });
    const url = URL.createObjectURL(blob);
    const anchor = document.createElement('a');
    anchor.href = url;
    anchor.download = filename;
    anchor.click();
    URL.revokeObjectURL(url);
  };
  const exportAssetTreeSVG = () => downloadAssetTreeFile('codexa-asset-tree.svg', assetTreeToSVG(assetTreeNodes), 'image/svg+xml');
  const exportAssetTreeJSON = () => downloadAssetTreeFile('codexa-asset-tree.json', JSON.stringify(assetTreeNodes, null, 2), 'application/json');
  const exportAssetTreePNG = async () => {
    const svgBlob = new Blob([assetTreeToSVG(assetTreeNodes)], { type: 'image/svg+xml' });
    const url = URL.createObjectURL(svgBlob);
    const image = new Image();
    image.onload = () => {
      const canvas = document.createElement('canvas');
      canvas.width = 1400;
      canvas.height = Math.max(120, assetTreeNodes.length * 120 + 64);
      const context = canvas.getContext('2d');
      if (context) {
        context.fillStyle = '#020617';
        context.fillRect(0, 0, canvas.width, canvas.height);
        context.drawImage(image, 0, 0, canvas.width, canvas.height);
        canvas.toBlob((blob) => { if (blob) downloadAssetTreeFile('codexa-asset-tree.png', blob, 'image/png'); }, 'image/png');
      }
      URL.revokeObjectURL(url);
    };
    image.src = url;
  };

  useEffect(() => {
    void refreshHistory();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);
  const addSubdomainsToHTTP = () => {
    if (!subdomainResult) return;
    setBulkUrls(subdomainResult.names.slice(0, 100).map((name) => `https://${name}`).join('\n'));
    setActiveTab('analyzer');
  };

  // Phase 15 - Import handlers
  const handleImportNmap = async (useWorkspace: boolean) => {
    setImportError('');
    const file = importNmapFile;
    const text = importNmapText;
    if (!file && !text.trim()) {
      setImportError('Select a file or paste Nmap XML content');
      return;
    }
    try {
      let result: main.NmapImportResult;
      if (file) {
        result = useWorkspace && importWorkspaceID ? await ImportNmapXMLToWorkspace(await file.text(), importWorkspaceID) : await ImportNmapXMLFile(file.name);
      } else {
        result = useWorkspace && importWorkspaceID ? await ImportNmapXMLToWorkspace(text, importWorkspaceID) : await ImportNmapXML(text);
      }
      setNmapImportResult(result);
      if (result.Errors?.length) setImportError(result.Errors.join('; '));
      await refreshHistory();
    } catch (error) {
      setImportError(errorMessage(error, 'Import failed'));
    }
  };

  const handleImportSubdomains = async (useWorkspace: boolean) => {
    setImportError('');
    const file = importSubdomainsFile;
    const text = importSubdomainsText;
    if (!file && !text.trim()) {
      setImportError('Select a file or paste subdomain list');
      return;
    }
    try {
      let result: main.SubdomainImportResult;
      if (file) {
        result = useWorkspace && importWorkspaceID ? await ImportSubdomainsToWorkspace(await file.text(), importWorkspaceID) : await ImportSubdomainsFile(file.name);
      } else {
        result = useWorkspace && importWorkspaceID ? await ImportSubdomainsToWorkspace(text, importWorkspaceID) : await ImportSubdomains(text);
      }
      setSubdomainImportResult(result);
      if (result.Errors?.length) setImportError(result.Errors.join('; '));
      await refreshHistory();
    } catch (error) {
      setImportError(errorMessage(error, 'Import failed'));
    }
  };

  // Phase 15 - HTTP Inspector handlers
  const handleInspect = async () => {
    if (!inspectURL.trim()) {
      setInspectError('URL is required');
      return;
    }
    setInspectError('');
    setIsInspecting(true);
    try {
      const headers = parseCustomHeaders(inspectHeaders);
      const req: main.HTTPInspectorRequest = {
        url: inspectURL.trim(),
        method: inspectMethod,
        headers,
        allowPrivate: inspectAllowPrivate,
        timeoutSeconds: inspectTimeout,
      };
      const result = await InspectHTTP(req);
      setInspectResult(result);
      if (result.Error) setInspectError(result.Error);
    } catch (error) {
      setInspectError(errorMessage(error, 'Inspection failed'));
    } finally {
      setIsInspecting(false);
    }
  };

  const handleReplay = async (modifications: Partial<main.HTTPInspectorRequest>) => {
    if (!inspectResult?.Request) return;
    setInspectError('');
    setIsInspecting(true);
    try {
      const originalReq: main.HTTPInspectorRequest = {
        url: inspectResult.Request.URL,
        method: inspectResult.Request.Method,
        headers: inspectResult.Request.Headers,
        allowPrivate: inspectAllowPrivate,
        timeoutSeconds: inspectTimeout,
      };
      const result = await ReplayHTTPRequest(originalReq, modifications as main.HTTPInspectorRequest);
      setInspectResult(result);
      if (result.Error) setInspectError(result.Error);
    } catch (error) {
      setInspectError(errorMessage(error, 'Replay failed'));
    } finally {
      setIsInspecting(false);
    }
  };

  // Phase 16 - Workspace handlers
  const loadWorkspaces = async () => {
    try {
      const ws = await ListWorkspaces();
      setWorkspaces(ws || []);
    } catch (error) {
      setWorkspaceError(errorMessage(error, 'Failed to load workspaces'));
    }
  };

  const handleCreateWorkspace = async () => {
    if (!newWorkspaceName.trim()) {
      setWorkspaceError('Workspace name is required');
      return;
    }
    setWorkspaceError('');
    try {
      const id = await CreateWorkspace(newWorkspaceName.trim(), newWorkspaceDesc.trim());
      setNewWorkspaceName('');
      setNewWorkspaceDesc('');
      await loadWorkspaces();
      setSelectedWorkspaceID(id);
    } catch (error) {
      setWorkspaceError(errorMessage(error, 'Failed to create workspace'));
    }
  };

  const handleDeleteWorkspace = async (id: number) => {
    if (!window.confirm('Delete this workspace? This will unassign all associated scan history entries.')) return;
    setWorkspaceError('');
    try {
      await DeleteWorkspace(id);
      await loadWorkspaces();
      if (selectedWorkspaceID === id) setSelectedWorkspaceID(null);
    } catch (error) {
      setWorkspaceError(errorMessage(error, 'Failed to delete workspace'));
    }
  };

  const handleAssignHistoryToWorkspace = async (historyID: number) => {
    if (selectedWorkspaceID === null) return;
    try {
      await UpdateHistoryWorkspace(historyID, selectedWorkspaceID);
      await refreshHistory();
    } catch (error) {
      setWorkspaceError(errorMessage(error, 'Failed to assign to workspace'));
    }
  };

  const handleSetFindingTag = async (findingID: string, tag: string) => {
    if (tagNoteHistoryID === null) return;
    try {
      await SetFindingTag(tagNoteHistoryID, findingID, tag);
      const tags = await GetFindingTags(tagNoteHistoryID);
      setFindingTags(tags);
    } catch (error) {
      setWorkspaceError(errorMessage(error, 'Failed to set tag'));
    }
  };

  const handleDeleteFindingTag = async (findingID: string) => {
    if (tagNoteHistoryID === null) return;
    try {
      await DeleteFindingTag(tagNoteHistoryID, findingID);
      const tags = await GetFindingTags(tagNoteHistoryID);
      setFindingTags(tags);
    } catch (error) {
      setWorkspaceError(errorMessage(error, 'Failed to delete tag'));
    }
  };

  const handleSetFindingNote = async (findingID: string, note: string) => {
    if (tagNoteHistoryID === null) return;
    try {
      await SetFindingNote(tagNoteHistoryID, findingID, note);
      const notes = await GetFindingNotes(tagNoteHistoryID);
      setFindingNotes(notes);
    } catch (error) {
      setWorkspaceError(errorMessage(error, 'Failed to set note'));
    }
  };

  const handleDeleteFindingNote = async (findingID: string) => {
    if (tagNoteHistoryID === null) return;
    try {
      await DeleteFindingNote(tagNoteHistoryID, findingID);
      const notes = await GetFindingNotes(tagNoteHistoryID);
      setFindingNotes(notes);
    } catch (error) {
      setWorkspaceError(errorMessage(error, 'Failed to delete note'));
    }
  };

  const getGradeColor = (grade: string) => {
    if (grade.startsWith('A')) return 'bg-emerald-950 text-emerald-400 border-emerald-700';
    if (grade === 'B') return 'bg-sky-950 text-sky-400 border-sky-700';
    if (grade === 'C') return 'bg-amber-950 text-amber-400 border-amber-700';
    return 'bg-rose-950 text-rose-400 border-rose-700';
  };

  const getSeverityColor = (severity: string) => {
    if (severity === 'critical' || severity === 'high') return 'border-rose-800 bg-rose-950/50 text-rose-300';
    if (severity === 'medium') return 'border-amber-800 bg-amber-950/40 text-amber-300';
    if (severity === 'low') return 'border-sky-800 bg-sky-950/40 text-sky-300';
    return 'border-slate-700 bg-slate-800/50 text-slate-300';
  };

  const getTLSProbeLabel = (status: string) => {
    if (status === 'supported') return 'Supported';
    if (status === 'not_supported') return 'Not supported';
    return 'Inconclusive';
  };

  const getTLSProbeColor = (status: string) => {
    if (status === 'supported') return 'border-rose-700 bg-rose-950/40 text-rose-300';
    if (status === 'not_supported') return 'border-emerald-800 bg-emerald-950/40 text-emerald-300';
    return 'border-amber-800 bg-amber-950/40 text-amber-300';
  };

  const formatHistoryResult = (raw: string) => {
    try { return JSON.stringify(JSON.parse(raw), null, 2); }
    catch { return raw; }
  };

  const escapeHtml = (value: unknown) => String(value ?? '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');

  const buildWebAuditSummary = (results: main.BulkHeaderResult[]) => {
    const sev = { critical: 0, high: 0, medium: 0, low: 0, info: 0 } as Record<string, number>;
    let riskTotal = 0;
    let graded = 0;
    let errors = 0;
    for (const r of results) {
      if (r.error) { errors += 1; continue; }
      if (typeof r.riskScore === 'number') { riskTotal += r.riskScore; graded += 1; }
      for (const f of r.findings || []) {
        const s = String(f.severity || 'info').toLowerCase();
        sev[s] = (sev[s] || 0) + 1;
      }
    }
    const avgRisk = graded ? Math.round(riskTotal / graded) : 0;
    return { sev, avgRisk, errors, targets: results.length, findings: Object.values(sev).reduce((a, b) => a + b, 0) };
  };

  const buildWebAuditHTML = (results: main.BulkHeaderResult[]) => {
    const summary = buildWebAuditSummary(results);
    const rows = results.map((r) => `
      <section class="card">
        <h2>${escapeHtml(r.url || '(unknown target)')}</h2>
        ${r.error ? `<p class="error"><strong>Error:</strong> ${escapeHtml(r.error)}</p>` : `
        <p><strong>Status:</strong> ${escapeHtml(r.statusCode)} &nbsp; <strong>Grade:</strong> ${escapeHtml(r.grade)} &nbsp; <strong>Risk:</strong> ${escapeHtml(r.riskScore)}/100</p>
        ${r.finalUrl && r.finalUrl !== r.url ? `<p><strong>Final URL:</strong> ${escapeHtml(r.finalUrl)}</p>` : ''}
        ${r.title ? `<p><strong>Title:</strong> ${escapeHtml(r.title)}</p>` : ''}
        ${(r.findings || []).length ? `<h3>Findings &amp; remediation</h3><ul>${(r.findings || []).map((f) => `<li><strong>[${escapeHtml(f.severity)}]</strong> ${escapeHtml(f.title)}${f.evidence ? `<br/><em>Evidence:</em> ${escapeHtml(f.evidence)}` : ''}${f.description ? `<br/>${escapeHtml(f.description)}` : ''}${f.recommendation ? `<br/><em>Remediation:</em> ${escapeHtml(f.recommendation)}` : ''}</li>`).join('')}</ul>` : '<p>No passive findings reported.</p>'}
        ${(r.missing || []).length ? `<p><strong>Missing headers:</strong> ${r.missing.map(escapeHtml).join(', ')}</p>` : ''}
        `}
      </section>`).join('');
    return `<!doctype html><html lang="en"><head><meta charset="utf-8"/><meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>Codexa Scanner - Web Audit Report</title>
<style>body{font-family:system-ui,-apple-system,Segoe UI,Roboto,sans-serif;background:#020617;color:#e2e8f0;margin:24px;line-height:1.5}h1{color:#34d399;margin:0 0 4px} .muted{color:#94a3b8} .grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(140px,1fr));gap:10px;margin:16px 0} .stat{background:#0f172a;border:1px solid #1e293b;border-radius:10px;padding:12px} .card{background:#0f172a;border:1px solid #1e293b;border-radius:12px;padding:14px;margin:12px 0} .error{color:#fca5a5} ul{margin:8px 0 0 18px} li{margin:6px 0} a{color:#34d399}</style></head><body>
<h1>Web Audit Summary Report</h1>
<p class="muted">Generated ${escapeHtml(new Date().toISOString())} · Codexa Scanner · Developed by <a href="https://arkaryan.net/">H!D3-C4rD</a></p>
<div class="grid">
  <div class="stat"><div class="muted">Targets</div><div><strong>${summary.targets}</strong></div></div>
  <div class="stat"><div class="muted">Errors</div><div><strong>${summary.errors}</strong></div></div>
  <div class="stat"><div class="muted">Avg Risk</div><div><strong>${summary.avgRisk}/100</strong></div></div>
  <div class="stat"><div class="muted">Findings</div><div><strong>${summary.findings}</strong></div></div>
  <div class="stat"><div class="muted">Critical/High</div><div><strong>${summary.sev.critical + summary.sev.high}</strong></div></div>
  <div class="stat"><div class="muted">Med/Low/Info</div><div><strong>${summary.sev.medium}/${summary.sev.low}/${summary.sev.info}</strong></div></div>
</div>
${rows || '<p>No results.</p>'}
<p class="muted">Bounded passive analysis of observed responses; findings are heuristics, not proof of exploitability. Review and redact sensitive data before sharing.</p>
</body></html>`;
  };

  const buildWebAuditMarkdown = (results: main.BulkHeaderResult[]) => {
    const summary = buildWebAuditSummary(results);
    const lines: string[] = [];
    lines.push('# Web Audit Summary Report');
    lines.push('');
    lines.push(`- Generated: ${new Date().toISOString()}`);
    lines.push('- Tool: Codexa Scanner');
    lines.push('- Developed by: [H!D3-C4rD](https://arkaryan.net/)');
    lines.push('');
    lines.push('## Summary');
    lines.push(`- Targets: ${summary.targets} (errors: ${summary.errors})`);
    lines.push(`- Average risk: ${summary.avgRisk}/100`);
    lines.push(`- Findings: ${summary.findings} (critical ${summary.sev.critical}, high ${summary.sev.high}, medium ${summary.sev.medium}, low ${summary.sev.low}, info ${summary.sev.info})`);
    lines.push('');
    for (const r of results) {
      lines.push(`## ${r.url || '(unknown target)'}`);
      if (r.error) {
        lines.push(`- Error: ${r.error}`);
        lines.push('');
        continue;
      }
      lines.push(`- Status: ${r.statusCode} | Grade: ${r.grade} | Risk: ${r.riskScore}/100`);
      if (r.finalUrl && r.finalUrl !== r.url) lines.push(`- Final URL: ${r.finalUrl}`);
      if (r.title) lines.push(`- Title: ${r.title}`);
      if ((r.missing || []).length) lines.push(`- Missing headers: ${r.missing.join(', ')}`);
      if ((r.findings || []).length) {
        lines.push('- Findings & remediation:');
        for (const f of r.findings || []) {
          lines.push(`  - **[${f.severity}] ${f.title}**${f.evidence ? ` (evidence: ${f.evidence})` : ''}`);
          if (f.description) lines.push(`    - ${f.description}`);
          if (f.recommendation) lines.push(`    - Remediation: ${f.recommendation}`);
        }
      } else {
        lines.push('- No passive findings reported.');
      }
      lines.push('');
    }
    lines.push('> Bounded passive analysis of observed responses; findings are heuristics, not proof of exploitability. Review and redact sensitive data before sharing.');
    return lines.join('\n');
  };

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100 px-3 py-4 font-sans sm:px-5 sm:py-6 lg:px-8 app-shell">
      {/* Top Navbar */}
      <header className="mb-5 flex flex-col gap-4 border-b border-slate-800 pb-4 sm:mb-6 lg:flex-row lg:items-center lg:justify-between">
        <div className="flex min-w-0 items-center gap-3">
          <img src="/logo.svg" alt="" className="h-10 w-10 shrink-0 rounded-xl ring-1 ring-emerald-500/30 shadow-sm shadow-emerald-950/40" />
          <div className="min-w-0">
            <div className="flex items-center gap-2">
              <h1 className="text-base font-bold tracking-[0.14em] text-emerald-400 sm:text-lg">CODEXA SCANNER</h1>
              <span className={`h-2.5 w-2.5 rounded-full ${isScanning || isAnalyzing || isReconBusy || isHistoryBusy ? 'bg-amber-400 animate-ping' : 'bg-emerald-500'}`} title={isScanning || isAnalyzing || isReconBusy || isHistoryBusy ? 'Busy' : 'Ready'} />
            </div>
            <p className="text-[11px] leading-relaxed text-slate-500 sm:text-xs">Authorized Network &amp; Web Security Assessment</p>
          </div>
        </div>

        <nav ref={navRef} aria-label="Scanner modules" className="flex flex-wrap gap-2 w-full lg:w-auto lg:max-w-[72%]">
          {GROUP_ORDER.map((group) => {
            const groupData = NAV_GROUPS[group];
            const isExpanded = expandedGroups.has(group);
            const isGroupActive = groupData.tabs.some((t) => t.id === activeTab);
            const isSingleTab = groupData.tabs.length === 1;

            if (isSingleTab) {
              const tab = groupData.tabs[0];
              return (
                <button
                  key={group}
                  type="button"
                  onClick={() => { setActiveTab(tab.id); if (tab.id === 'history' || tab.id === 'assetTree') void refreshHistory(); if (tab.id === 'workspaces') void loadWorkspaces(); }}
                  aria-pressed={activeTab === tab.id}
                  className={`rounded-lg px-3 py-2 text-[11px] font-semibold transition-colors whitespace-nowrap ${
                    activeTab === tab.id ? 'bg-emerald-600 text-white shadow-sm shadow-emerald-950/60' : 'text-slate-400 hover:bg-slate-800 hover:text-white'
                  }`}
                >
                  {tab.label}
                </button>
              );
            }

            return (
              <div key={group} className="relative flex items-center">
                <button
                  type="button"
                  onClick={(e) => {
                    e.stopPropagation();
                    setExpandedGroups((prev) => {
                      const next = new Set(prev);
                      // Close all other groups, toggle this one
                      if (next.has(group)) {
                        next.delete(group);
                      } else {
                        next.clear();
                        next.add(group);
                      }
                      return next;
                    });
                  }}
                  aria-expanded={isExpanded}
                  className={`flex items-center gap-1.5 rounded-lg px-3 py-2 text-[11px] font-semibold transition-colors whitespace-nowrap ${
                    isGroupActive ? 'bg-emerald-600 text-white shadow-sm shadow-emerald-950/60' : 'text-slate-400 hover:bg-slate-800 hover:text-white'
                  }`}
                >
                  {groupData.label}
                  <span className={`text-[10px] transition-transform ${isExpanded ? 'rotate-180' : ''}`}>▼</span>
                </button>
                {isExpanded && (
                  <div className="absolute top-full left-0 mt-1 z-10 flex flex-col gap-1 rounded-lg border border-slate-700 bg-slate-900 p-1.5 shadow-lg min-w-[140px]">
                    {groupData.tabs.map((tab) => (
                      <button
                        key={tab.id}
                        type="button"
                        onClick={(e) => {
                          e.stopPropagation();
                          setActiveTab(tab.id);
                          if (tab.id === 'assetTree') void refreshHistory();
                          setExpandedGroups((prev) => {
                            const next = new Set(prev);
                            next.delete(group);
                            return next;
                          });
                          if (tab.id === 'history') void refreshHistory();
                          if (tab.id === 'workspaces') void loadWorkspaces();
                        }}
                        aria-pressed={activeTab === tab.id}
                        className={`rounded px-2.5 py-1.5 text-[11px] font-medium transition-colors text-left ${
                          activeTab === tab.id ? 'bg-emerald-600 text-white' : 'text-slate-300 hover:bg-slate-800 hover:text-white'
                        }`}
                      >
                        {tab.label}
                      </button>
                    ))}
                  </div>
                )}
              </div>
            );
          })}
          <button type="button" onClick={() => setCommandPaletteOpen(true)} title="Command palette (Ctrl/Cmd+K)" className="rounded-lg border border-slate-700 px-3 py-2 text-[11px] font-semibold text-slate-300 hover:bg-slate-800">⌘K</button>
        </nav>
      </header>
      <main className="mx-auto w-full max-w-screen-2xl">
      {reconError && (
        <div role="alert" className="mb-4 rounded-lg border border-rose-800 bg-rose-950/50 px-3 py-2 text-xs text-rose-300">
          {reconError}
        </div>
      )}

      {activeTab === 'dashboard' && (
        (() => {
          const recent = historyEntries.slice(0, 8);
          const latestPort = historyEntries.find((e) => e.scanType === 'port');
          const latestHTTP = historyEntries.find((e) => e.scanType === 'http');
          let latestPortCount = 0;
          let latestPortParseError = false;
          if (latestPort) {
            try {
              const parsed = JSON.parse(latestPort.result);
              latestPortCount = Array.isArray(parsed) ? parsed.length : 0;
            } catch {
              latestPortParseError = true;
            }
          }
          const httpSeverity: Record<string, number> = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
          let latestHTTPTargets = 0;
          let latestHTTPAvgRisk = 0;
          let latestHTTPParseError = false;
          if (latestHTTP) {
            try {
              const parsed = JSON.parse(latestHTTP.result);
              const results = Array.isArray(parsed) ? parsed : [];
              latestHTTPTargets = results.length;
              let riskTotal = 0;
              let riskCount = 0;
              for (const r of results) {
                if (typeof r?.riskScore === 'number') { riskTotal += r.riskScore; riskCount += 1; }
                const findings = Array.isArray(r?.findings) ? r.findings : [];
                for (const f of findings) {
                  const sev = String(f?.severity || '').toLowerCase();
                  if (sev in httpSeverity) httpSeverity[sev] += 1;
                  else if (sev) httpSeverity.info += 1;
                }
              }
              latestHTTPAvgRisk = riskCount ? Math.round(riskTotal / riskCount) : 0;
            } catch {
              latestHTTPParseError = true;
            }
          }
          const totalFindings = Object.values(httpSeverity).reduce((a, b) => a + b, 0);
          const scannedStackText = httpResults.flatMap((r) => (r.technologies || []).concat(r.edgeServices || [])).join(' ').toLowerCase();
          const matchedFeedTargets = (item: main.ThreatFeedItem) => {
            const product = (item.product || '').toLowerCase().replace(/[-_]/g, ' ');
            if (!product || !scannedStackText) return 0;
            return httpResults.filter((r) => (r.technologies || []).concat(r.edgeServices || []).join(' ').toLowerCase().includes(product)).length;
          };
          const hasData = historyEntries.length > 0 || httpResults.length > 0 || findings.length > 0;
          const exportHistoryJSON = () => void ExportJSON('scan_history.json', JSON.stringify(historyEntries));
          const exportHistoryPDF = () => void ExportPDF('scan_history.pdf', JSON.stringify(historyEntries));

          // Re-scan & Compare: re-run latest port scan and web audit for a target, then diff
          const handleRescanAndCompare = async () => {
            if (!historyTarget.trim()) {
              setHistoryError('Enter a target to re-scan and compare');
              return;
            }
            setIsHistoryBusy(true);
            setHistoryError('');
            try {
              // Get latest port scan target
              const latestPort = historyEntries.find((e) => e.scanType === 'port' && e.target === historyTarget.trim());
              const latestHTTP = historyEntries.find((e) => e.scanType === 'http' && e.target === historyTarget.trim());

              if (latestPort) {
                try {
                  const parsed = JSON.parse(latestPort.result);
                  const ports = Array.isArray(parsed) ? parsed.map((p: any) => p.port).filter((p: number) => p > 0) : [];
                  if (ports.length) {
                    await StartPortScan(historyTarget.trim(), Math.min(...ports), Math.max(...ports), 200, 800, true);
                  }
                } catch {}
              }

              if (latestHTTP) {
                try {
                  const parsed = JSON.parse(latestHTTP.result);
                  const urls = Array.isArray(parsed) ? parsed.map((r: any) => r.url).filter((u: string) => u) : [];
                  if (urls.length) {
                    await AnalyzeBulkURLs(urls.join('\n'), 10, true, 0, 0, 0, '', 10, {}, '', '', '');
                  }
                } catch {}
              }

              // Wait a bit for scans to complete, then refresh diffs
              setTimeout(async () => {
                try {
                  const [portDiffResult, webAuditDiffResult] = await Promise.all([
                    DiffLatestPortScans(historyTarget.trim()),
                    DiffLatestWebAuditScans(historyTarget.trim()),
                  ]);
                  setPortDiff(portDiffResult);
                  setWebAuditDiff(webAuditDiffResult);
                } catch {}
                setIsHistoryBusy(false);
              }, 5000);
            } catch (error) {
              setHistoryError(errorMessage(error, 'Re-scan failed'));
              setIsHistoryBusy(false);
            }
          };

          const Stat = ({ label, value, note }: { label: string; value: string | number; note?: string }) => (
            <div className="rounded-xl border border-slate-800 bg-slate-900 p-4">
              <div className="text-[11px] uppercase tracking-wide text-slate-500">{label}</div>
              <div className="mt-1 text-2xl font-bold text-slate-100">{value}</div>
              {note ? <div className="mt-1 text-xs text-slate-400">{note}</div> : null}
            </div>
          );
return (
            <div className="space-y-4">
              <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-4">
                <Stat label="History records" value={historyEntries.length} note={historyEntries.length ? 'Latest 50 loaded from local SQLite' : 'No local records loaded'} />
                <Stat label="Latest port scan" value={latestPort ? latestPortCount : '—'} note={latestPort ? `${latestPort.target}${latestPortParseError ? ' (result unreadable)' : ' open ports in snapshot'}` : 'No port scan saved yet'} />
                <Stat label="Latest Web Audit" value={latestHTTP ? `${latestHTTPTargets} target(s)` : '—'} note={latestHTTP ? (latestHTTPParseError ? 'Result unreadable' : `Avg risk ${latestHTTPAvgRisk}/100`) : 'No Web Audit saved yet'} />
                <Stat label="Finding severity (latest Web Audit)" value={totalFindings} note={latestHTTP ? 'Counts from stored findings' : 'No findings summary available'} />
              </div>

              <div className="grid gap-4 xl:grid-cols-2">
                    <div className="rounded-xl border border-slate-800 bg-slate-900 p-4 space-y-3">
                      <h3 className="text-sm font-bold">Open ports / findings breakdown</h3>
                      <div className="grid gap-2 sm:grid-cols-2">
                        <div className="rounded-lg bg-slate-950 p-3">
                          <div className="text-[11px] text-slate-500">Open ports (latest saved port scan)</div>
                          <div className="mt-1 text-xl font-bold text-emerald-300">{latestPort ? (latestPortParseError ? 'n/a' : latestPortCount) : '—'}</div>
                          <div className="text-xs text-slate-400 break-all">{latestPort ? latestPort.target : 'Run a port scan to populate'}</div>
                        </div>
                        <div className="rounded-lg bg-slate-950 p-3">
                          <div className="text-[11px] text-slate-500">Current session (unsaved) context</div>
                          <div className="mt-1 text-xs text-slate-300">Ports found now: <strong>{findings.length}</strong></div>
                          <div className="text-xs text-slate-300">Web Audit results now: <strong>{httpResults.length}</strong></div>
                        </div>
                      </div>
                      <div className="space-y-2">
                        {(['critical', 'high', 'medium', 'low', 'info'] as const).map((sev) => {
                          const count = httpSeverity[sev];
                          const pct = totalFindings ? Math.round((count / totalFindings) * 100) : 0;
                          return (
                            <div key={sev}>
                              <div className="mb-1 flex items-center justify-between text-xs"><span className="uppercase text-slate-400">{sev}</span><span className="text-slate-300">{count}</span></div>
                              <div className="h-2 overflow-hidden rounded bg-slate-800"><div className={`h-full ${sev === 'critical' || sev === 'high' ? 'bg-rose-500' : sev === 'medium' ? 'bg-amber-500' : sev === 'low' ? 'bg-sky-500' : 'bg-slate-500'}`} style={{ width: `${pct}%` }} /></div>
                            </div>
                          );
                        })}
                        {!latestHTTP && <p className="text-xs text-slate-500">No saved Web Audit findings to chart yet.</p>}
                      </div>
                    </div>

                    <div className="rounded-xl border border-slate-800 bg-slate-900 p-4 space-y-3">
                      <h3 className="text-sm font-bold">Recent scans &amp; report links</h3>
                      {recent.length ? recent.map((entry) => (
                        <div key={entry.id} className="flex flex-col gap-2 rounded-lg bg-slate-950 p-3 sm:flex-row sm:items-center sm:justify-between">
                          <div className="min-w-0">
                            <div className="flex flex-wrap items-center gap-2 text-xs"><span className="rounded bg-slate-800 px-2 py-0.5 text-emerald-300">{entry.scanType}</span><span className="break-all text-slate-200">{entry.target}</span></div>
                            <div className="mt-1 text-[11px] text-slate-500">{new Date(entry.createdAt).toLocaleString()}</div>
                          </div>
                          <button onClick={() => void ExportJSON(`scan_${entry.scanType}_${entry.id}.json`, entry.result)} className="shrink-0 rounded border border-slate-700 px-2.5 py-1.5 text-[11px] text-slate-300 hover:bg-slate-800">Export</button>
                        </div>
                      )) : <p className="text-xs text-slate-500">No recent scan records.</p>}
                      {portDiff && (portDiff.newPorts.length || portDiff.removedPorts.length) ? (
                        <div className="rounded-lg border border-slate-800 bg-slate-950 p-3 text-xs">
                          <div className="font-semibold text-slate-300">Latest port diff · {portDiff.target}</div>
                          <div className="mt-2 flex flex-wrap gap-2">{portDiff.newPorts.map((p) => <span key={`dn-${p}`} className="rounded border border-rose-800 bg-rose-950/50 px-2 py-0.5 text-rose-300">New {p}</span>)}{portDiff.removedPorts.map((p) => <span key={`dr-${p}`} className="rounded border border-slate-700 px-2 py-0.5 text-slate-300">Closed {p}</span>)}</div>
                        </div>
                      ) : portDiff?.target ? <p className="text-xs text-slate-500">No port changes for {portDiff.target} (or fewer than two snapshots).</p> : null}
                    </div>
                  </div>
                </div>
          );
        })()
      )}

      {/* ========================================= */}
      {/* TAB 1: REAL-TIME PORT SCANNER             */}
      {/* ========================================= */}
      {activeTab === 'scanner' && (
        <div className="space-y-4">
          <div className="grid grid-cols-2 gap-3 rounded-xl border border-slate-800 bg-slate-900 p-3 sm:grid-cols-3 sm:p-4 xl:grid-cols-6">
            <div className="col-span-full sm:col-span-3 xl:col-span-2">
              <label className="block text-xs text-slate-400 mb-1">Target IP / Hostname</label>
              <input
                value={target}
                onChange={(e) => { setTarget(e.target.value); setScopeConfirmed(false); }}
                disabled={isScanning}
                className="min-w-0 w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-2.5 text-sm outline-none transition focus:border-emerald-500 focus:ring-2 focus:ring-emerald-500/20"
              />
            </div>

            <div>
              <label className="block text-xs text-slate-400 mb-1">Start Port</label>
              <input
                type="number"
                value={startPort}
                onChange={(e) => { setStartPort(Number(e.target.value)); setScopeConfirmed(false); }}
                disabled={isScanning}
                className="min-w-0 w-full rounded-lg border border-slate-700 bg-slate-950 px-2.5 py-2.5 text-sm outline-none transition focus:border-emerald-500 focus:ring-2 focus:ring-emerald-500/20"
              />
            </div>

            <div>
              <label className="block text-xs text-slate-400 mb-1">End Port</label>
              <input
                type="number"
                value={endPort}
                onChange={(e) => { setEndPort(Number(e.target.value)); setScopeConfirmed(false); }}
                disabled={isScanning}
                className="min-w-0 w-full rounded-lg border border-slate-700 bg-slate-950 px-2.5 py-2.5 text-sm outline-none transition focus:border-emerald-500 focus:ring-2 focus:ring-emerald-500/20"
              />
            </div>

            <div className="col-span-full">
              <label className="block text-xs text-slate-400 mb-1">Presets</label>
              <div className="flex flex-wrap gap-2">
                {([
                  ['Top 100', 1, 100],
                  ['Top 1000', 1, 1000],
                  ['Web Ports', 80, 8443],
                  ['Full (1-1024)', 1, 1024],
                ] as [string, number, number][]).map(([label, s, e]) => (
                  <button key={label} type="button" disabled={isScanning} onClick={() => { setStartPort(s); setEndPort(e); setScopeConfirmed(false); }} className="rounded-lg border border-slate-700 bg-slate-950 px-3 py-1.5 text-xs text-slate-300 hover:bg-slate-800 disabled:opacity-40">{label}</button>
                ))}
                <span className="self-center text-[11px] text-slate-500">Web Ports preset sets 80–8443; use target service ports as needed (common: 80,443,8080,8443).</span>
              </div>
            </div>

            <div>
              <label className="block text-xs text-slate-400 mb-1">Workers (max 512)</label>
              <input
                type="number"
                min={1}
                max={512}
                value={workers}
                onChange={(e) => setWorkers(Number(e.target.value))}
                disabled={isScanning}
                className="min-w-0 w-full rounded-lg border border-slate-700 bg-slate-950 px-2.5 py-2.5 text-sm outline-none transition focus:border-emerald-500 focus:ring-2 focus:ring-emerald-500/20"
              />
            </div>

            <div>
              <label className="block text-xs text-slate-400 mb-1">Timeout (ms, max 30,000)</label>
              <input
                type="number"
                min={1}
                max={30000}
                value={timeoutMs}
                onChange={(e) => setTimeoutMs(Number(e.target.value))}
                disabled={isScanning}
                className="min-w-0 w-full rounded-lg border border-slate-700 bg-slate-950 px-2.5 py-2.5 text-sm outline-none transition focus:border-emerald-500 focus:ring-2 focus:ring-emerald-500/20"
              />
            </div>
          </div>

          <label className="flex cursor-pointer items-start gap-3 rounded-xl border border-amber-900/60 bg-amber-950/20 p-3 text-xs leading-relaxed text-slate-300">
            <input
              type="checkbox"
              checked={scopeConfirmed}
              onChange={(e) => setScopeConfirmed(e.target.checked)}
              disabled={isScanning}
              className="mt-0.5 accent-emerald-500"
            />
            <span>
              <span className="font-semibold text-amber-200">Scope confirmation required.</span>{' '}
              I own or have permission to scan this exact target and port range. Authorized private and lab targets are allowed.
            </span>
          </label>

          {/* Action Buttons & Progress */}
          <div className="flex flex-col gap-2 sm:flex-row sm:items-center sm:gap-3">
            {!isScanning ? (
              <button
                onClick={handleStartScan}
                disabled={!scopeConfirmed}
                className="min-h-11 flex-1 rounded-xl bg-emerald-600 py-2.5 text-sm font-semibold text-white transition hover:bg-emerald-500 focus:outline-none focus:ring-2 focus:ring-emerald-400 focus:ring-offset-2 focus:ring-offset-slate-950 disabled:cursor-not-allowed disabled:opacity-50 disabled:hover:bg-emerald-600"
              >
                Start Live Scan
              </button>
            ) : (
              <button
                onClick={handleStopScan}
                className="min-h-11 flex-1 rounded-xl bg-rose-600 py-2.5 text-sm font-semibold text-white transition hover:bg-rose-500 focus:outline-none focus:ring-2 focus:ring-rose-400 focus:ring-offset-2 focus:ring-offset-slate-950"
              >
                Stop Scan ({progress}%)
              </button>
            )}

            {findings.length > 0 && (
              <>
                <button
                  onClick={() => ExportPortsCSV(findings)}
                  className="min-h-11 rounded-xl border border-slate-700 bg-slate-800 px-4 py-2.5 text-xs font-semibold hover:bg-slate-700 focus:outline-none focus:ring-2 focus:ring-emerald-500/60"
                >
                  Export CSV
                </button>
                <button
                  onClick={() => ExportJSON('port_scan.json', JSON.stringify(findings))}
                  className="min-h-11 rounded-xl border border-slate-700 bg-slate-800 px-4 py-2.5 text-xs font-semibold hover:bg-slate-700 focus:outline-none focus:ring-2 focus:ring-emerald-500/60"
                >
                  Export JSON
                </button>
              </>
            )}
          </div>

          {/* Progress Bar */}
          {(isScanning || progress > 0) && (
            <div className="w-full bg-slate-900 rounded-full h-2 overflow-hidden border border-slate-800">
              <div
                className="bg-emerald-500 h-2 transition-all duration-200"
                style={{ width: `${progress}%` }}
              />
            </div>
          )}

          {resolvedScanTarget && (
            <p className="text-xs text-slate-500">
              Pinned scan address: <span className="font-mono text-emerald-300">{resolvedScanTarget}</span>
            </p>
          )}
          {scanError && <p className="text-rose-400 text-xs">{scanError}</p>}

          {/* Real-time Results Table */}
          <div className="overflow-hidden rounded-xl border border-slate-800 bg-slate-900">
            <div className="flex flex-col gap-1 border-b border-slate-800 bg-slate-900/80 px-4 py-3 text-xs text-slate-400 sm:flex-row sm:justify-between">
              <span>Live Open Ports & Service Banners</span>
              <span className="text-emerald-400 font-bold">{findings.length} Open Ports Found</span>
            </div>

            <div>
              <table className="responsive-port-table w-full text-left text-xs">
                <thead className="bg-slate-950 text-slate-400 sticky top-0">
                  <tr>
                    <th className="py-2.5 px-4">PORT</th>
                    <th className="py-2.5 px-4">STATE</th>
                    <th className="py-2.5 px-4">SERVICE</th>
                    <th className="py-2.5 px-4">GRABBED BANNER / VERSION</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800/60 font-mono">
                  {findings.length === 0 ? (
                    <tr>
                      <td colSpan={4} className="py-8 text-center text-slate-500 font-sans">
                        {isScanning ? 'Probing ports...' : 'No open ports displayed yet.'}
                      </td>
                    </tr>
                  ) : (
                    findings.map((item) => (
                      <tr key={item.port} className="hover:bg-slate-800/40">
                        <td data-label="Port" className="py-2.5 px-4 font-bold text-emerald-400">{item.port}/tcp</td>
                        <td data-label="State" className="py-2.5 px-4">
                          <span className="bg-emerald-950 text-emerald-400 border border-emerald-800 px-2 py-0.5 rounded text-[10px]">
                            OPEN
                          </span>
                        </td>
                        <td data-label="Service" className="py-2.5 px-4 text-sky-300">{item.service}</td>
                        <td data-label="Banner / version" className="break-all py-2.5 px-4 text-slate-300 sm:truncate sm:break-normal sm:max-w-md">
                          {item.banner || <span className="text-slate-600">-</span>}
                        </td>
                      </tr>
                    ))
                  )}
                </tbody>
              </table>
</div>
          </div>

          {/* CIDR /24 Sweep Section */}
          <div className="border-t border-slate-800 pt-4 space-y-4">
            <h3 className="text-sm font-semibold text-slate-300">CIDR /24 Subnet Sweep (Bounded, Opt-in)</h3>
            <div className="grid grid-cols-2 gap-3 rounded-xl border border-slate-800 bg-slate-900 p-3 sm:grid-cols-3 sm:p-4 xl:grid-cols-6">
              <div className="col-span-full sm:col-span-3 xl:col-span-2">
                <label className="block text-xs text-slate-400 mb-1">Target CIDR (IPv4 /24 only)</label>
                <input
                  value={cidrTarget}
                  onChange={(e) => { setCidrTarget(e.target.value); setCidrScopeConfirmed(false); }}
                  disabled={isCIDRScanning}
                  placeholder="192.168.1.0/24"
                  className="min-w-0 w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-2.5 text-sm outline-none transition focus:border-emerald-500 focus:ring-2 focus:ring-emerald-500/20"
                />
              </div>

              <div>
                <label className="block text-xs text-slate-400 mb-1">Start Port</label>
                <input
                  type="number"
                  value={cidrStartPort}
                  onChange={(e) => { setCidrStartPort(Number(e.target.value)); setCidrScopeConfirmed(false); }}
                  disabled={isCIDRScanning}
                  className="min-w-0 w-full rounded-lg border border-slate-700 bg-slate-950 px-2.5 py-2.5 text-sm outline-none transition focus:border-emerald-500 focus:ring-2 focus:ring-emerald-500/20"
                />
              </div>

              <div>
                <label className="block text-xs text-slate-400 mb-1">End Port</label>
                <input
                  type="number"
                  value={cidrEndPort}
                  onChange={(e) => { setCidrEndPort(Number(e.target.value)); setCidrScopeConfirmed(false); }}
                  disabled={isCIDRScanning}
                  className="min-w-0 w-full rounded-lg border border-slate-700 bg-slate-950 px-2.5 py-2.5 text-sm outline-none transition focus:border-emerald-500 focus:ring-2 focus:ring-emerald-500/20"
                />
              </div>

              <div>
                <label className="block text-xs text-slate-400 mb-1">Workers (max 50)</label>
                <input
                  type="number"
                  min={1}
                  max={50}
                  value={cidrWorkers}
                  onChange={(e) => setCidrWorkers(Number(e.target.value))}
                  disabled={isCIDRScanning}
                  className="min-w-0 w-full rounded-lg border border-slate-700 bg-slate-950 px-2.5 py-2.5 text-sm outline-none transition focus:border-emerald-500 focus:ring-2 focus:ring-emerald-500/20"
                />
              </div>

              <div>
                <label className="block text-xs text-slate-400 mb-1">Timeout (ms, max 30,000)</label>
                <input
                  type="number"
                  min={1}
                  max={30000}
                  value={cidrTimeoutMs}
                  onChange={(e) => setCidrTimeoutMs(Number(e.target.value))}
                  disabled={isCIDRScanning}
                  className="min-w-0 w-full rounded-lg border border-slate-700 bg-slate-950 px-2.5 py-2.5 text-sm outline-none transition focus:border-emerald-500 focus:ring-2 focus:ring-emerald-500/20"
                />
              </div>

              <div>
                <label className="block text-xs text-slate-400 mb-1">RPS (0 = unlimited, max 50)</label>
                <input
                  type="number"
                  min={0}
                  max={50}
                  value={cidrRps}
                  onChange={(e) => setCidrRps(Number(e.target.value))}
                  disabled={isCIDRScanning}
                  className="min-w-0 w-full rounded-lg border border-slate-700 bg-slate-950 px-2.5 py-2.5 text-sm outline-none transition focus:border-emerald-500 focus:ring-2 focus:ring-emerald-500/20"
                  title="Requests per second cap for port connections"
                />
              </div>

              <div>
                <label className="block text-xs text-slate-400 mb-1">Jitter (ms, 0-5000)</label>
                <input
                  type="number"
                  min={0}
                  max={5000}
                  value={cidrJitterMs}
                  onChange={(e) => setCidrJitterMs(Number(e.target.value))}
                  disabled={isCIDRScanning}
                  className="min-w-0 w-full rounded-lg border border-slate-700 bg-slate-950 px-2.5 py-2.5 text-sm outline-none transition focus:border-emerald-500 focus:ring-2 focus:ring-emerald-500/20"
                  title="Random extra delay per connection to avoid rate limits"
                />
              </div>
            </div>

            <label className="flex cursor-pointer items-start gap-3 rounded-xl border border-amber-900/60 bg-amber-950/20 p-3 text-xs leading-relaxed text-slate-300">
              <input
                type="checkbox"
                checked={cidrScopeConfirmed}
                onChange={(e) => setCidrScopeConfirmed(e.target.checked)}
                disabled={isCIDRScanning}
                className="mt-0.5 accent-emerald-500"
              />
              <span>
                <span className="font-semibold text-amber-200">Scope confirmation required.</span>{' '}
                I own or have permission to scan this entire /24 CIDR range and port range. Authorized private and lab networks only.
              </span>
            </label>

            {/* Action Buttons & Progress */}
            <div className="flex flex-col gap-2 sm:flex-row sm:items-center sm:gap-3">
              {!isCIDRScanning ? (
                <button
                  onClick={handleStartCIDRSweep}
                  disabled={!cidrScopeConfirmed}
                  className="min-h-11 flex-1 rounded-xl bg-emerald-600 py-2.5 text-sm font-semibold text-white transition hover:bg-emerald-500 focus:outline-none focus:ring-2 focus:ring-emerald-400 focus:ring-offset-2 focus:ring-offset-slate-950 disabled:cursor-not-allowed disabled:opacity-50 disabled:hover:bg-emerald-600"
                >
                  Start CIDR /24 Sweep
                </button>
              ) : (
                <button
                  onClick={handleStopCIDRSweep}
                  className="min-h-11 flex-1 rounded-xl bg-rose-600 py-2.5 text-sm font-semibold text-white transition hover:bg-rose-500 focus:outline-none focus:ring-2 focus:ring-rose-400 focus:ring-offset-2 focus:ring-offset-slate-950"
                >
                  Stop Sweep ({cidrProgress}%)
                </button>
              )}

              {cidrResults && cidrResults.liveHosts > 0 && (
                <>
                  <button
                    onClick={() => ExportJSON(`cidr_sweep_${cidrTarget.replace(/\//g, '_')}.json`, JSON.stringify(cidrResults))}
                    className="min-h-11 rounded-xl border border-slate-700 bg-slate-800 px-4 py-2.5 text-xs font-semibold hover:bg-slate-700 focus:outline-none focus:ring-2 focus:ring-emerald-500/60"
                  >
                    Export JSON
                  </button>
                </>
              )}
            </div>

            {/* Progress Bar */}
            {(isCIDRScanning || cidrProgress > 0) && (
              <div className="w-full bg-slate-900 rounded-full h-2 overflow-hidden border border-slate-800">
                <div
                  className="bg-emerald-500 h-2 transition-all duration-200"
                  style={{ width: `${cidrProgress}%` }}
                />
              </div>
            )}

            {cidrError && <p className="text-rose-400 text-xs">{cidrError}</p>}

            {/* CIDR Sweep Results */}
            {cidrResults && (
              <div className="overflow-hidden rounded-xl border border-slate-800 bg-slate-900">
                <div className="flex flex-col gap-1 border-b border-slate-800 bg-slate-900/80 px-4 py-3 text-xs text-slate-400 sm:flex-row sm:justify-between">
                  <span>CIDR Sweep Results · {cidrResults.cidr}</span>
                  <span className="text-emerald-400 font-bold">
                    {cidrResults.liveHosts} Live Hosts / {cidrResults.scanned} Scanned
                  </span>
                </div>
                <div className="max-h-96 overflow-auto">
                  <table className="w-full text-left text-xs">
                    <thead className="bg-slate-950 text-slate-400 sticky top-0">
                      <tr>
                        <th className="py-2.5 px-4">IP</th>
                        <th className="py-2.5 px-4">HOSTNAME</th>
                        <th className="py-2.5 px-4">OPEN PORTS</th>
                        <th className="py-2.5 px-4">SERVICES / BANNERS</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-slate-800/60 font-mono">
                      {cidrResults.hosts.length === 0 ? (
                        <tr>
                          <td colSpan={4} className="py-8 text-center text-slate-500 font-sans">
                            {isCIDRScanning ? 'Sweeping subnet...' : 'No live hosts found.'}
                          </td>
                        </tr>
                      ) : (
                        cidrResults.hosts
                          .filter((h) => h.ports.length > 0)
                          .map((host) => (
                            <tr key={host.ip} className="hover:bg-slate-800/40">
                              <td data-label="IP" className="py-2.5 px-4 font-bold text-emerald-400">{host.ip}</td>
                              <td data-label="Hostname" className="py-2.5 px-4 text-sky-300">{host.hostname || <span className="text-slate-600">-</span>}</td>
                              <td data-label="Open Ports" className="py-2.5 px-4 text-amber-300">
                                {host.ports.map((p) => p.port).join(', ')}
                              </td>
                              <td data-label="Services" className="break-all py-2.5 px-4 text-slate-300 sm:truncate sm:max-w-md">
                                {host.ports.map((p) => (
                                  <div key={p.port} className="whitespace-nowrap">
                                    <span className="text-sky-300">{p.service}</span>:{p.port}/tcp{' '}
                                    {p.banner ? <span className="text-slate-400">{p.banner}</span> : <span className="text-slate-600">-</span>}
                                  </div>
                                ))}
                              </td>
                            </tr>
                          ))
                      )}
                    </tbody>
                  </table>
                </div>
              </div>
            )}
          </div>
        </div>
      )}

      {/* ========================================= */}
      {/* TAB 2: BULK HTTP SECURITY ANALYZER        */}
      {/* ========================================= */}
      {activeTab === 'analyzer' && (
        <div className="space-y-4">
          <div className="bg-slate-900 p-4 rounded-xl border border-slate-800 space-y-3">
            <div className="flex flex-col gap-2 sm:flex-row sm:items-center sm:justify-between">
              <label className="text-xs text-slate-400">Authorized HTTP/HTTPS URLs (one per line, max 100)</label>
              <div className="flex flex-wrap items-center gap-3">
                <label className="flex items-center gap-2 text-xs text-slate-400"><span>Concurrency</span><input type="number" min={1} max={20} value={httpThreads} onChange={(e)=>setHttpThreads(Number(e.target.value))} disabled={isAnalyzing} className="w-16 rounded border border-slate-700 bg-slate-950 px-2 py-1.5 text-center text-xs text-slate-200" /></label>
                <label className="flex items-center gap-2 text-xs text-slate-400"><span>Delay (ms)</span><input type="number" min={0} max={5000} step={50} value={httpDelayMs} onChange={(e)=>setHttpDelayMs(Number(e.target.value))} disabled={isAnalyzing} className="w-20 rounded border border-slate-700 bg-slate-950 px-2 py-1.5 text-center text-xs text-slate-200" /></label>
                <label className="flex items-center gap-2 text-xs text-slate-400"><span>RPS</span><input type="number" min={0} max={50} value={httpRps} onChange={(e)=>setHttpRps(Number(e.target.value))} disabled={isAnalyzing} className="w-16 rounded border border-slate-700 bg-slate-950 px-2 py-1.5 text-center text-xs text-slate-200" title="Requests per second cap (0 = unlimited)" /></label>
                <label className="flex items-center gap-2 text-xs text-slate-400"><span>Jitter (ms)</span><input type="number" min={0} max={5000} step={50} value={httpJitterMs} onChange={(e)=>setHttpJitterMs(Number(e.target.value))} disabled={isAnalyzing} className="w-20 rounded border border-slate-700 bg-slate-950 px-2 py-1.5 text-center text-xs text-slate-200" /></label>
              </div>
            </div>
            <div className="grid gap-2 sm:grid-cols-2 lg:grid-cols-4">
              <label className="text-xs text-slate-400">User-Agent preset
                <select value={requestUserAgent} onChange={(e)=>setRequestUserAgent(e.target.value)} disabled={isAnalyzing} className="mt-1 w-full rounded border border-slate-700 bg-slate-950 px-2 py-2 text-xs text-slate-200">
                  <option value="">Default (Codexa Scanner)</option>
                  <option value="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36">Browser-like (Chrome)</option>
                  <option value="Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)">Crawler-like (Googlebot)</option>
                  <option value="curl/8.7.1">CLI (curl)</option>
                </select>
              </label>
              <label className="text-xs text-slate-400">Timeout preset
                <select value={requestTimeout} onChange={(e)=>setRequestTimeout(Number(e.target.value))} disabled={isAnalyzing} className="mt-1 w-full rounded border border-slate-700 bg-slate-950 px-2 py-2 text-xs text-slate-200">
                  <option value={5}>5s</option><option value={10}>10s (default)</option><option value={20}>20s</option><option value={30}>30s</option>
                </select>
              </label>
              <div className="flex items-end gap-2 sm:col-span-2">
                <button type="button" onClick={togglePause} className={`min-h-10 rounded-lg border px-3 py-2 text-xs font-semibold ${isPaused ? 'border-amber-700 bg-amber-950/40 text-amber-300' : 'border-slate-700 bg-slate-800 text-slate-200 hover:bg-slate-700'}`}>{isPaused ? 'Resume scans' : 'Pause scans'}</button>
                <span className="text-[11px] text-slate-500">Applies to Web Audit &amp; Path Fuzzer.</span>
              </div>
            </div>

            <details className="rounded-lg border border-slate-800 bg-slate-950/40">
              <summary className="cursor-pointer select-none px-3 py-2 text-xs font-semibold text-slate-300 hover:text-slate-100">
                Authorized session headers (optional, one-shot scope)
              </summary>
              <div className="space-y-2 border-t border-slate-800 p-3">
                <textarea
                  rows={3}
                  value={customHeaders}
                  onChange={(e) => setCustomHeaders(e.target.value)}
                  disabled={isAnalyzing}
                  placeholder={'Authorization: Bearer ***\nCookie: session=***\nX-API-Key: ***'}
                  className="min-h-24 w-full resize-y rounded-lg border border-slate-700 bg-slate-950 p-3 text-xs font-mono outline-none transition focus:border-emerald-500 focus:ring-2 focus:ring-emerald-500/20"
                />
                <p className="text-[11px] leading-relaxed text-slate-500">
                  One line per header as <code className="text-slate-400">Name: value</code>. For authorized authenticated testing only. Sensitive header values (Authorization, Cookie, X-API-Key, etc.) are redacted before persistence and export; hop-by-hop and transport-controlled headers are ignored. This is a per-run opt-in and does not change target-scope validation.
                </p>
              </div>
            </details>

            <details className="rounded-lg border border-slate-800 bg-slate-950/40">
              <summary className="cursor-pointer select-none px-3 py-2 text-xs font-semibold text-slate-300 hover:text-slate-100">
                Opt-in proxy routing (optional, one-shot scope)
              </summary>
              <div className="space-y-2 border-t border-slate-800 p-3">
                <label className="text-xs text-slate-400">Proxy URL (HTTP/HTTPS/SOCKS5)
                  <input
                    type="text"
                    value={proxyURL}
                    onChange={(e) => setProxyURL(e.target.value)}
                    disabled={isAnalyzing}
                    placeholder="http://127.0.0.1:8080  |  socks5://127.0.0.1:1080  |  https://proxy.example:8443"
                    className="mt-1 w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-xs font-mono outline-none transition focus:border-emerald-500 focus:ring-2 focus:ring-emerald-500/20"
                  />
                </label>
                <p className="text-[11px] leading-relaxed text-slate-500">
                  Route Web Audit & Path Fuzzer traffic through a local inspection proxy (e.g., Burp, OWASP ZAP, mitmproxy). Supported schemes: <code className="text-slate-400">http</code>, <code className="text-slate-400">https</code>, <code className="text-slate-400">socks5</code>, <code className="text-slate-400">socks5h</code>. No embedded credentials in proxy URL; use the headers section above for Proxy-Authorization if needed. This is a per-run opt-in; target scope validation and private-network checks still apply.
                </p>
              </div>
            </details>

            <textarea
              rows={4}
              value={bulkUrls}
              onChange={(e) => { setBulkUrls(e.target.value); setAllowPrivateHTTPTargets(false); }}
              placeholder="https://your-authorized-site.example&#10;http://your-lab-host.example"
              className="min-h-28 w-full resize-y rounded-lg border border-slate-700 bg-slate-950 p-3 text-xs font-mono outline-none transition focus:border-emerald-500 focus:ring-2 focus:ring-emerald-500/20"
            />

            <div className="grid gap-2 sm:grid-cols-2">
              <label className="rounded-lg border border-slate-800 bg-slate-950/60 p-3 text-xs text-slate-400">
                Scope file <span className="text-slate-600">(scope.txt, optional)</span>
                <input type="file" accept=".txt,text/plain" disabled={isAnalyzing} onChange={(e) => void loadRuleFile(e.target.files?.[0], setScopeFileText, setScopeFileName)} className="mt-2 block w-full text-[11px] text-slate-400 file:mr-2 file:rounded file:border-0 file:bg-slate-800 file:px-2 file:py-1 file:text-[11px] file:text-slate-200" />
                <span className="mt-2 block break-all text-[11px] text-emerald-400">{scopeFileName || 'No scope file loaded'}</span>
                <span className="mt-1 block text-[11px] text-slate-600">Only matching hostnames are scanned. Supports exact hosts and *.example.com.</span>
              </label>
              <label className="rounded-lg border border-slate-800 bg-slate-950/60 p-3 text-xs text-slate-400">
                Exclusion file <span className="text-slate-600">(exclude.txt, optional)</span>
                <input type="file" accept=".txt,text/plain" disabled={isAnalyzing} onChange={(e) => void loadRuleFile(e.target.files?.[0], setExcludeFileText, setExcludeFileName)} className="mt-2 block w-full text-[11px] text-slate-400 file:mr-2 file:rounded file:border-0 file:bg-slate-800 file:px-2 file:py-1 file:text-[11px] file:text-slate-200" />
                <span className="mt-2 block break-all text-[11px] text-amber-300">{excludeFileName || 'No exclusion file loaded'}</span>
                <span className="mt-1 block text-[11px] text-slate-600">Matching hosts are skipped. Blank lines and # comments are ignored.</span>
              </label>
            </div>

            <label className="flex cursor-pointer items-start gap-3 rounded-xl border border-amber-900/60 bg-amber-950/20 p-3 text-xs leading-relaxed text-slate-300">
              <input
                type="checkbox"
                checked={allowPrivateHTTPTargets}
                onChange={(e) => setAllowPrivateHTTPTargets(e.target.checked)}
                disabled={isAnalyzing}
                className="mt-0.5 accent-emerald-500"
              />
              <span>
                <span className="font-semibold text-amber-200">Private/lab access (optional).</span>{' '}
                Allow authorized RFC1918, IPv6 ULA, and loopback targets for this analysis. Link-local and reserved/special-use addresses stay blocked.
              </span>
            </label>
            <p className="text-[11px] leading-relaxed text-slate-500">
              Bounded active requests: main GET, observed redirects, and read-only security.txt/robots.txt fetches. Passive analysis: findings and clues derived from observed responses. Redirects stay on each URL’s hostname and allowed ports; cross-host redirects and HTTPS-to-HTTP downgrades are blocked. HTTP-to-HTTPS on standard ports is allowed.
            </p>
            {httpError && <p role="alert" className="rounded-lg border border-rose-800 bg-rose-950/50 px-3 py-2 text-xs text-rose-300">{httpError}</p>}

            <div className="flex flex-wrap gap-2">
              <button
                onClick={handleBulkAnalyze}
                disabled={isAnalyzing}
                className="flex-1 min-w-[180px] bg-emerald-600 hover:bg-emerald-500 disabled:bg-slate-700 text-white font-semibold py-2 rounded-lg text-xs transition"
              >
                {isAnalyzing ? 'Analyzing Targets...' : 'Analyze All Targets'}
              </button>

              {httpResults.length > 0 && (
                <>
                  <button
                    onClick={() => ExportJSON('http_security_audit.json', JSON.stringify(httpResults))}
                    className="bg-slate-800 hover:bg-slate-700 border border-slate-700 px-3 py-2 rounded-lg text-xs font-semibold"
                  >
                    Export JSON
                  </button>
                  <button
                    onClick={() => ExportText('http_security_audit.html', buildWebAuditHTML(httpResults), 'HTML Files (*.html)', '*.html')}
                    className="bg-slate-800 hover:bg-slate-700 border border-slate-700 px-3 py-2 rounded-lg text-xs font-semibold"
                  >
                    Export HTML
                  </button>
                  <button
                    onClick={() => ExportText('http_security_audit.md', buildWebAuditMarkdown(httpResults), 'Markdown Files (*.md)', '*.md')}
                    className="bg-slate-800 hover:bg-slate-700 border border-slate-700 px-3 py-2 rounded-lg text-xs font-semibold"
                  >
                    Export Markdown
                  </button>
                  <button
                    onClick={() => ExportPDF('http_security_audit.pdf', JSON.stringify(httpResults))}
                    className="bg-slate-800 hover:bg-slate-700 border border-slate-700 px-3 py-2 rounded-lg text-xs font-semibold"
                  >
                    Export PDF
                  </button>
                </>
              )}
            </div>
          </div>

          {/* Results Cards */}
          <div className="space-y-3">
            {httpResults.map((res, idx) => (
              <div key={idx} className="min-w-0 space-y-3 rounded-xl border border-slate-800 bg-slate-900 p-3 sm:p-4">
                <div className="flex flex-col gap-2 sm:flex-row sm:items-center sm:justify-between">
                  <div className="flex min-w-0 flex-wrap items-center gap-2 sm:gap-3">
                    <span className="min-w-0 break-all font-mono text-sm font-bold text-slate-200">{res.url}</span>
                    {!res.error && (
                      <span className="text-xs bg-slate-800 text-slate-300 px-2 py-0.5 rounded">
                        HTTP {res.statusCode}
                      </span>
                    )}
                    {res.assessment && (
                      <span className="text-[10px] rounded border border-sky-900 bg-sky-950/40 px-2 py-0.5 text-sky-300">
                        {res.assessment}
                      </span>
                    )}
                  </div>
                  {!res.error && (
                    <span className={`px-2.5 py-0.5 rounded border text-xs font-bold ${getGradeColor(res.grade)}`}>
                      Grade {res.grade} · Risk {res.riskScore}/100
                    </span>
                  )}
                </div>

                {res.error ? (
                  <>
                    <p className="text-rose-400 text-xs">{res.error}</p>
                    {res.findings?.map((finding) => (
                      <div key={finding.id} className={`rounded-lg border p-3 ${getSeverityColor(finding.severity)}`}>
                        <div className="flex items-center gap-2 text-xs font-bold uppercase">
                          <span>{finding.severity}</span><span>{finding.title}</span>
                        </div>
                        <p className="mt-1 text-xs text-slate-300">{finding.description}</p>
                        <p className="mt-1 text-xs text-slate-400">Fix: {finding.recommendation}</p>
                      </div>
                    ))}
                  </>
                ) : (
                  <>
                    <div className="flex flex-wrap gap-x-4 gap-y-2 text-xs text-slate-400">
                      <span>Title: <strong className="text-slate-200">{res.title || 'N/A'}</strong></span>
                      <span>Server: <strong className="text-amber-300">{res.server || 'Hidden'}</strong></span>
                      {res.finalUrl && res.finalUrl !== res.url && <span>Final URL: <strong className="text-slate-200">{res.finalUrl}</strong></span>}
                      {res.poweredBy && (
                        <span>Powered-By: <strong className="text-amber-300">{res.poweredBy}</strong></span>
                      )}
                    </div>
                    {res.redirects && res.redirects.length > 0 && (
                      <details className="rounded-lg border border-slate-800 bg-slate-950 p-3">
                        <summary className="cursor-pointer text-xs font-semibold text-slate-300">Redirect chain ({res.redirects.length} hop{res.redirects.length === 1 ? '' : 's'})</summary>
                        <div className="mt-2 space-y-2">
                          {res.redirects.map((hop, hopIndex) => (
                            <div key={`${hop.from}-${hop.to}-${hopIndex}`} className="rounded border border-slate-800 px-2 py-2 text-[11px]">
                              <div className="text-amber-300">HTTP {hop.statusCode || 'redirect'}</div>
                              <div className="break-all text-slate-400">{hop.from}</div>
                              <div className="text-slate-600">â†“</div>
                              <div className="break-all text-slate-200">{hop.to}</div>
                            </div>
                          ))}
                        </div>
                      </details>
                    )}

                    {(res.technologies?.length || res.edgeServices?.length) ? (
                      <div className="flex flex-wrap gap-1.5 text-[10px]">
                        {res.technologies?.map((technology) => <span key={technology} className="rounded border border-sky-900 bg-sky-950/50 px-2 py-1 text-sky-300">{technology}</span>)}
                        {res.edgeServices?.map((edge) => <span key={edge} className="rounded border border-violet-900 bg-violet-950/50 px-2 py-1 text-violet-300">Edge/WAF clue: {edge}</span>)}
                      </div>
                    ) : null}

                    {res.wafDetections && res.wafDetections.length > 0 ? (
                      <div className="rounded-lg border border-amber-900 bg-amber-950/30 p-3 space-y-2">
                        <div className="text-[11px] font-semibold uppercase tracking-wide text-amber-300">WAF / CDN Detection ({res.wafDetections.length})</div>
                        {res.wafDetections.map((waf) => (
                          <div key={waf.name} className="rounded border border-amber-800 bg-amber-950/50 p-2 space-y-1">
                            <div className="flex items-center gap-2 text-xs">
                              <span className="font-bold uppercase">{waf.category}</span>
                              <span className="text-amber-200">{waf.name}</span>
                              <span className={`rounded px-1.5 py-0.5 text-[10px] ${waf.confidence === 'high' ? 'bg-emerald-900 text-emerald-300' : waf.confidence === 'medium' ? 'bg-amber-900 text-amber-300' : 'bg-slate-700 text-slate-300'}`}>
                                {waf.confidence}
                              </span>
                            </div>
                            {waf.headers?.length && <div className="text-[10px] text-slate-400">Headers: {waf.headers.join(', ')}</div>}
                            {waf.cookies?.length && <div className="text-[10px] text-slate-400">Cookies: {waf.cookies.join(', ')}</div>}
                            {waf.bodyMatches?.length && <div className="text-[10px] text-slate-400">Body matches: {waf.bodyMatches.join(', ')}</div>}
                            {waf.note && <div className="text-[10px] text-slate-300">{waf.note}</div>}
                          </div>
                        ))}
                      </div>
                    ) : null}

                    {res.tls && (
                      <div className="rounded-lg border border-emerald-900 bg-emerald-950/30 px-3 py-2 text-xs text-emerald-200 space-y-1">
                        <div>TLS {res.tls.version} · {res.tls.cipherSuite} · {res.tls.verified ? 'Certificate verified' : 'Certificate not verified'}</div>
                        <div>{res.tls.verificationSummary || (res.tls.verified ? 'Verified by system trust store' : 'Not verified by system trust store')}</div>
                        <div>Leaf: {res.tls.subject || 'unknown'} · Issuer: {res.tls.issuer || 'unknown'}</div>
                        <div>Valid: {res.tls.notBefore ? new Date(res.tls.notBefore).toLocaleDateString() : 'n/a'} – {new Date(res.tls.expiresAt).toLocaleDateString()} ({res.tls.daysRemaining} days remaining) · SANs: {res.tls.sanCount ?? 0}</div>
                        {res.tls.chainSubjects?.length ? <div className="text-emerald-300/90">Presented chain: {res.tls.chainSubjects.join(' â†’ ')}</div> : null}
                      </div>
                    )}

                    <div className="flex flex-wrap gap-1.5 text-[10px]">
                      <span className="text-slate-500">Checked:</span>
                      {res.present && Object.keys(res.present).map((header) => (
                        <span key={header} className="rounded border border-emerald-900 bg-emerald-950/50 px-2 py-0.5 text-emerald-300">{header}</span>
                      ))}
                      {res.missing?.map((header) => (
                        <span key={header} className="rounded border border-rose-900 bg-rose-950/40 px-2 py-0.5 text-rose-300">Missing: {header}</span>
                      ))}
                    </div>

                    {res.findings?.length ? (
                      <div className="space-y-2 pt-1">
                        <div className="text-[11px] font-semibold uppercase tracking-wide text-slate-500">Passive findings ({res.findings.length})</div>
                        {res.findings.map((finding) => (
                          <div key={finding.id} className={`rounded-lg border p-3 ${getSeverityColor(finding.severity)}`}>
                            <div className="flex flex-wrap items-center justify-between gap-2">
                              <div className="flex items-center gap-2 text-xs font-bold uppercase">
                                <span>{finding.severity}</span><span>{finding.title}</span>
                              </div>
                              <button type="button" onClick={() => openFindingGuide(finding.id, res)} className="rounded border border-slate-600 bg-slate-900/60 px-2 py-1 text-[11px] font-semibold text-emerald-300 hover:bg-slate-800">Why &amp; how to fix</button>
                            </div>
                            <p className="mt-1 text-xs text-slate-300">{finding.description}</p>
                            {finding.evidence && <p className="mt-1 break-all text-[11px] text-slate-400">Evidence: {finding.evidence}</p>}
                            <p className="mt-1 text-xs text-slate-400">Fix: {finding.recommendation}</p>
                          </div>
                        ))}
                      </div>
                    ) : (
                      <p className="text-xs text-emerald-400">No issues found by these passive checks. This is not proof that the site is vulnerability-free.</p>
                    )}

                    {verificationCommands(res).length > 0 && (
                      <details className="rounded-lg border border-slate-800 bg-slate-950 p-3">
                        <summary className="cursor-pointer text-xs font-semibold text-slate-300">Safe CLI verification commands (copy only)</summary>
                        <p className="mt-2 text-[11px] text-slate-500">Read-only diagnostics derived from observed findings. Codexa Scanner does not run these commands; review scope and targets before use.</p>
                        <div className="mt-2 space-y-2">
                          {verificationCommands(res).map(({ label, command }) => (
                            <div key={label} className="rounded border border-slate-800 p-2">
                              <div className="mb-1 flex items-center justify-between gap-2 text-[11px] text-slate-400">
                                <span>{label}</span>
                                <button type="button" onClick={async () => {
                                  try {
                                    await navigator.clipboard.writeText(command);
                                    setCopiedVerificationCommand(command);
                                  } catch {
                                    setCopiedVerificationCommand('');
                                  }
                                }} className="rounded border border-slate-700 px-2 py-1 text-emerald-300 hover:bg-slate-800">
                                  {copiedVerificationCommand === command ? 'Copied' : 'Copy'}
                                </button>
                              </div>
                              <code className="block break-all text-[11px] text-slate-200">{command}</code>
                            </div>
                          ))}
                        </div>
                      </details>
                    )}

                    {(res.securityTxt || res.robotsTxt) && (
                      <div className="space-y-2 pt-1">
                        <div className="text-[11px] font-semibold uppercase tracking-wide text-slate-500">Resource inspectors</div>
                        {([
                          ['security.txt', res.securityTxt],
                          ['robots.txt', res.robotsTxt],
                        ] as [string, main.WebResourceInspector | undefined][]).map(([label, inspector]) => {
                          if (!inspector) return null;
                          return (
                            <details key={label} className="rounded-lg border border-slate-800 bg-slate-950 p-3">
                              <summary className="cursor-pointer text-xs font-semibold text-slate-300">
                                {label}: {inspector.error ? 'error' : inspector.found ? `found (HTTP ${inspector.statusCode})` : `not found${inspector.statusCode ? ` (HTTP ${inspector.statusCode})` : ''}`}
                              </summary>
                              <div className="mt-2 space-y-2 text-xs text-slate-300">
                                <div className="break-all text-[11px] text-slate-400">{inspector.url}</div>
                                {inspector.note && <p className="text-amber-300">{inspector.note}</p>}
                                {inspector.error ? (
                                  <p className="text-rose-300">{inspector.error}</p>
                                ) : inspector.found ? (
                                  <pre className="max-h-48 overflow-auto whitespace-pre-wrap break-all rounded border border-slate-800 bg-slate-900 p-2 text-[11px] text-slate-200">{inspector.body}</pre>
                                ) : (
                                  <p className="text-slate-400">No readable resource returned at this path.</p>
                                )}
                              </div>
                            </details>
                          );
                        })}
                      </div>
                    )}

                    {res.clientSideAudit && (
                      <details className="rounded-lg border border-slate-800 bg-slate-950 p-3">
                        <summary className="cursor-pointer text-xs font-semibold text-slate-300">
                          Client-side exposure audit (bounded passive): {res.clientSideAudit.scriptsScanned}/{res.clientSideAudit.scriptsFetched} scripts scanned
                          {res.clientSideAudit.truncated ? ' · capped' : ''}
                        </summary>
                        <div className="mt-2 space-y-3 text-xs text-slate-300">
                          {res.clientSideAudit.notes?.length ? <ul className="list-disc pl-4 text-[11px] text-slate-400">{res.clientSideAudit.notes.map((n, i) => <li key={i}>{n}</li>)}</ul> : null}
                          {res.clientSideAudit.reflectedParamProbe && (
                            <div className="rounded border border-slate-800 bg-slate-900 p-2">
                              <div className="font-semibold text-slate-200">Reflected parameter probe (harmless, passive)</div>
                              <div className="text-[11px] text-slate-400">Result: {res.clientSideAudit.reflectedParamProbe.kind}{res.clientSideAudit.reflectedParamProbe.statusCode ? ` (HTTP ${res.clientSideAudit.reflectedParamProbe.statusCode})` : ''}</div>
                              {res.clientSideAudit.reflectedParamProbe.note && <div className="text-[11px] text-slate-400">{res.clientSideAudit.reflectedParamProbe.note}</div>}
                              {res.clientSideAudit.reflectedParamProbe.context && <div className="text-[11px] text-amber-300">{res.clientSideAudit.reflectedParamProbe.context}</div>}
                            </div>
                          )}
                          {res.clientSideAudit.secretFindings?.length ? (
                            <div>
                              <div className="font-semibold text-rose-300">Secret/token pattern clues (redacted)</div>
                              <div className="mt-1 space-y-1">{res.clientSideAudit.secretFindings.map((c, i) => <div key={i} className="break-all rounded bg-slate-900 p-2 text-[11px]"><span className="text-slate-200">{c.kind}</span>: {c.value} {c.scriptUrl ? <span className="text-slate-500">· {c.scriptUrl}</span> : null}{c.note ? <div className="text-slate-500">{c.note}</div> : null}</div>)}</div>
                            </div>
                          ) : null}
                          {res.clientSideAudit.sourceMapClues?.length ? (
                            <div>
                              <div className="font-semibold text-amber-300">Source map clues</div>
                              <div className="mt-1 space-y-1">{res.clientSideAudit.sourceMapClues.map((c, i) => <div key={i} className="break-all rounded bg-slate-900 p-2 text-[11px]"><div>{c.value}</div>{c.scriptUrl ? <div className="text-slate-500">Script: {c.scriptUrl}</div> : null}<div className="text-slate-400">Reachable: {c.reachable == null ? 'n/a' : c.reachable ? `yes (HTTP ${c.statusCode || 'n/a'})` : `no/not confirmed${c.statusCode ? ` (HTTP ${c.statusCode})` : ''}`}</div>{c.note ? <div className="text-slate-500">{c.note}</div> : null}</div>)}</div>
                            </div>
                          ) : null}
                          {res.clientSideAudit.endpointClues?.length ? (
                            <div>
                              <div className="font-semibold text-sky-300">API/BaaS endpoint clues</div>
                              <div className="mt-1 flex flex-wrap gap-1">{res.clientSideAudit.endpointClues.slice(0, 30).map((c, i) => <span key={i} className="break-all rounded border border-slate-700 bg-slate-900 px-2 py-1 text-[11px]" title={c.note || ''}>{c.kind}: {c.value}</span>)}</div>
                              {res.clientSideAudit.endpointClues.length > 30 && <div className="text-[11px] text-slate-500">+{res.clientSideAudit.endpointClues.length - 30} more in JSON/export</div>}
                            </div>
                          ) : null}
                          {res.clientSideAudit.domSinks?.length ? (
                            <div>
                              <div className="font-semibold text-orange-300">DOM sink clues (passive)</div>
                              <div className="mt-1 space-y-1">{res.clientSideAudit.domSinks.slice(0, 20).map((c, i) => <div key={i} className="break-all rounded bg-slate-900 p-2 text-[11px]"><span className="text-slate-200">{c.value}</span> {c.scriptUrl ? <span className="text-slate-500">· {c.scriptUrl}:{c.line || '?'}</span> : null}{c.context ? <div className="text-slate-500">{c.context}</div> : null}</div>)}</div>
                              {res.clientSideAudit.domSinks.length > 20 && <div className="text-[11px] text-slate-500">+{res.clientSideAudit.domSinks.length - 20} more in JSON/export</div>}
                            </div>
                          ) : null}
                          {!res.clientSideAudit.secretFindings?.length && !res.clientSideAudit.sourceMapClues?.length && !res.clientSideAudit.endpointClues?.length && !res.clientSideAudit.domSinks?.length && <div className="text-[11px] text-slate-500">No client-side clue patterns matched by these bounded passive checks.</div>}
                        </div>
                      </details>
                    )}

                    {res.missing && res.missing.length > 0 && (
                      <div className="pt-1 flex flex-wrap gap-1.5">
                        <span className="text-[11px] text-slate-500 mr-1">Missing Headers:</span>
                        {res.missing.map((h) => (
                          <span key={h} className="text-[10px] bg-rose-950/70 text-rose-300 border border-rose-800/60 px-2 py-0.5 rounded font-mono">
                            {h}
                          </span>
                        ))}
                      </div>
                    )}
                  </>
                )}
              </div>
            ))}
          </div>
        </div>
      )}
      {activeTab === 'subdomains' && (
        <div className="space-y-4">
          <div className="rounded-xl border border-slate-800 bg-slate-900 p-4 space-y-3">
            <div>
              <label className="mb-1 block text-xs text-slate-400">Authorized root domain</label>
              <input value={subdomain} onChange={(e) => setSubdomain(e.target.value)} placeholder="example.com" className="w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-sm" />
            </div>
            <label className="flex items-center gap-2 text-xs text-slate-300">
              <input type="checkbox" checked={useDNSBrute} onChange={(e) => setUseDNSBrute(e.target.checked)} />
              Also perform bounded DNS wordlist lookups (up to 500 labels)
            </label>
            {useDNSBrute && <textarea rows={4} value={subdomainWordlist} onChange={(e) => setSubdomainWordlist(e.target.value)} className="w-full rounded-lg border border-slate-700 bg-slate-950 p-3 text-xs font-mono" />}
            <button onClick={runSubdomainDiscovery} disabled={isReconBusy} className="w-full rounded-lg bg-emerald-600 py-2 text-xs font-semibold disabled:bg-slate-700">{isReconBusy ? 'Enumeratingâ€¦' : 'Query Certificate Transparency'}</button>
            <p className="text-[11px] text-slate-500">Passive results come from crt.sh. DNS wordlist checks are optional active queries; use only within authorized scope.</p>
          </div>
          {subdomainResult && <div className="space-y-3 rounded-xl border border-slate-800 bg-slate-900 p-3 sm:p-4">
            <div className="flex flex-col gap-2 sm:flex-row sm:items-center sm:justify-between"><h2 className="break-all text-sm font-bold">{subdomainResult.names.length} names · {subdomainResult.domain}</h2><button onClick={addSubdomainsToHTTP} disabled={!subdomainResult.names.length} className="min-h-10 rounded-lg border border-slate-700 px-3 py-2 text-xs text-emerald-300 transition hover:bg-slate-800 disabled:opacity-40">Send first 100 to Web Audit</button></div>
            {subdomainResult.errors?.map((e, i) => <p key={i} className="text-xs text-amber-300">{e}</p>)}
            <div className="space-y-1 font-mono text-xs">{subdomainResult.names.map((name) => <div key={name} className="break-all rounded bg-slate-950 px-3 py-1.5 text-slate-200">{name}</div>)}</div>
          </div>}
        </div>
      )}
      {activeTab === 'fuzzer' && (
        <div className="space-y-4">
          <div className="rounded-xl border border-slate-800 bg-slate-900 p-4 space-y-3">
            <label className="block text-xs text-slate-400">Authorized base URL</label>
            <input value={fuzzBaseURL} onChange={(e) => setFuzzBaseURL(e.target.value)} placeholder="https://your-site.example" className="w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-sm" />
            <div className="flex flex-wrap items-center gap-3 justify-between">
              <label className="text-xs text-slate-400">Path wordlist (max 500)</label>
              <div className="flex flex-wrap items-center gap-3">
                <label className="flex items-center gap-2 text-xs text-slate-400"><span>Concurrency</span><input type="number" min={1} max={20} value={fuzzConcurrency} onChange={(e)=>setFuzzConcurrency(Number(e.target.value))} className="w-20 shrink-0 rounded border border-slate-700 bg-slate-950 px-2 py-2 text-xs" /></label>
                <label className="flex items-center gap-2 text-xs text-slate-400"><span>Delay (ms)</span><input type="number" min={0} max={5000} step={50} value={fuzzDelayMs} onChange={(e)=>setFuzzDelayMs(Number(e.target.value))} className="w-24 shrink-0 rounded border border-slate-700 bg-slate-950 px-2 py-2 text-xs" /></label>
                <label className="flex items-center gap-2 text-xs text-slate-400"><span>RPS</span><input type="number" min={0} max={50} value={fuzzRps} onChange={(e)=>setFuzzRps(Number(e.target.value))} className="w-16 shrink-0 rounded border border-slate-700 bg-slate-950 px-2 py-2 text-xs" /></label>
                <label className="flex items-center gap-2 text-xs text-slate-400"><span>Jitter</span><input type="number" min={0} max={5000} step={50} value={fuzzJitterMs} onChange={(e)=>setFuzzJitterMs(Number(e.target.value))} className="w-20 shrink-0 rounded border border-slate-700 bg-slate-950 px-2 py-2 text-xs" /></label>
                <button type="button" onClick={togglePause} className={`min-h-10 rounded-lg border px-3 py-2 text-xs font-semibold ${isPaused ? 'border-amber-700 bg-amber-950/40 text-amber-300' : 'border-slate-700 bg-slate-800 text-slate-200 hover:bg-slate-700'}`}>{isPaused ? 'Resume' : 'Pause'}</button>
              </div>
            </div>
            <details className="rounded-lg border border-slate-800 bg-slate-950/40">
              <summary className="cursor-pointer select-none px-3 py-2 text-xs font-semibold text-slate-300 hover:text-slate-100">
                Opt-in proxy routing (optional, one-shot scope)
              </summary>
              <div className="space-y-2 border-t border-slate-800 p-3">
                <label className="text-xs text-slate-400">Proxy URL (HTTP/HTTPS/SOCKS5)
                  <input
                    type="text"
                    value={proxyURL}
                    onChange={(e) => setProxyURL(e.target.value)}
                    disabled={isReconBusy}
                    placeholder="http://127.0.0.1:8080  |  socks5://127.0.0.1:1080  |  https://proxy.example:8443"
                    className="mt-1 w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-xs font-mono outline-none transition focus:border-emerald-500 focus:ring-2 focus:ring-emerald-500/20"
                  />
                </label>
                <p className="text-[11px] leading-relaxed text-slate-500">
                  Route Path Fuzzer traffic through a local inspection proxy (e.g., Burp, OWASP ZAP, mitmproxy). Supported schemes: <code className="text-slate-400">http</code>, <code className="text-slate-400">https</code>, <code className="text-slate-400">socks5</code>, <code className="text-slate-400">socks5h</code>. No embedded credentials in proxy URL; use the Web Audit headers section for Proxy-Authorization if needed. This is a per-run opt-in; target scope validation and private-network checks still apply.
                </p>
              </div>
            </details>
            <div className="space-y-1">
              <div className="text-[11px] text-slate-500">Framework presets (HEAD-only, bounded; use within authorized scope):</div>
              <div className="flex flex-wrap gap-2">
                {([
                  ['Next.js', '/_next/static/\n/api/health\n/api/auth/session\n/openapi.json\n/robots.txt\n/sitemap.xml'],
                  ['Vite/SPA', '/assets/\n/vite.svg\n/manifest.json\n/robots.txt\n/env.js'],
                  ['Laravel', '/.env\n/.env.example\n/storage/logs/laravel.log\n/telescope\n/api/health\n/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php'],
                  ['Django', '/admin/login/\n/api/\n/__debug__/\n/static/\n/robots.txt'],
                  ['Spring', '/actuator/health\n/actuator/env\n/swagger-ui.html\n/v3/api-docs\n/openapi.json'],
                  ['Env/VCS/API', '/.env\n/.env.local\n/.env.production\n/.git/HEAD\n/docker-compose.yml\n/graphql\n/openapi.json\n/swagger.json'],
                ] as [string, string][]).map(([label, paths]) => (
                  <button key={label} type="button" onClick={() => setFuzzWordlist((prev) => Array.from(new Set([...(prev || '').split(/\r?\n/).map(s => s.trim()).filter(Boolean), ...paths.split(/\r?\n/).map(s => s.trim()).filter(Boolean)])).join('\n'))} className="rounded border border-slate-700 bg-slate-950 px-2 py-1 text-[11px] text-slate-300 hover:bg-slate-800">{label}</button>
                ))}
                <button type="button" onClick={() => setFuzzWordlist('/admin\n/dashboard\n/robots.txt\n/.well-known/security.txt')} className="rounded border border-slate-700 px-2 py-1 text-[11px] text-slate-400 hover:bg-slate-800">Reset default</button>
              </div>
            </div>
            <textarea rows={7} value={fuzzWordlist} onChange={(e) => setFuzzWordlist(e.target.value)} className="w-full rounded-lg border border-slate-700 bg-slate-950 p-3 text-xs font-mono" />
            <button onClick={runPathFuzzer} disabled={isReconBusy} className="w-full rounded-lg bg-emerald-600 py-2 text-xs font-semibold disabled:bg-slate-700">{isReconBusy ? 'Checking pathsâ€¦' : 'Run HEAD-only Path Checks'}</button>
            <p className="text-[11px] text-slate-500">Sends bounded HEAD requests only, follows no redirects, and never reads or displays response bodies. A randomized missing-path check filters likely catch-all responses.</p>
          </div>
          {fuzzResult && <div className="space-y-2 rounded-xl border border-slate-800 bg-slate-900 p-3 sm:p-4">
            {fuzzResult.error && <p className="text-xs text-rose-300">{fuzzResult.error}</p>}
            <h2 className="break-all text-sm font-bold">{fuzzResult.paths.length} candidate paths · {fuzzResult.baseUrl}</h2>
            {fuzzResult.paths.map((item) => <div key={item.url} className="flex flex-wrap justify-between gap-2 rounded bg-slate-950 px-3 py-2 font-mono text-xs"><span className="min-w-0 break-all">{item.url}</span><span className="shrink-0 text-emerald-300">HTTP {item.statusCode} · {item.contentLength >= 0 ? `${item.contentLength} B` : 'size unknown'}</span></div>)}
          </div>}
        </div>
      )}
      {activeTab === 'tls' && (
        <div className="space-y-4">
          <div className="rounded-xl border border-slate-800 bg-slate-900 p-4 space-y-3">
            <label className="block text-xs text-slate-400">Authorized hostname or host:port</label>
            <input value={tlsTarget} onChange={(e) => setTlsTarget(e.target.value)} placeholder="example.com:443" className="w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-sm" />
            <button onClick={runTLSInspector} disabled={isReconBusy} className="w-full rounded-lg bg-emerald-600 py-2 text-xs font-semibold disabled:bg-slate-700">{isReconBusy ? 'Inspecting TLSâ€¦' : 'Inspect Certificate & Protocols'}</button>
            <p className="text-[11px] text-slate-500">Protocol probes perform bounded TLS handshakes only. HTTP/2 is reported from negotiated ALPN; HTTP/3 is reported only when the HTTPS response advertises an h3 Alt-Svc value, not as proof of a successful QUIC connection. Legacy TLS 1.2 cipher probes are handshake-only. “Not supported” requires an explicit TLS protocol_version alert; other connection, handshake, and local-policy errors are “Inconclusive.”</p>
          </div>
          {tlsResult && <div className="rounded-xl border border-slate-800 bg-slate-900 p-4 space-y-3">
            <h2 className="break-all text-sm font-bold">TLS details · {tlsResult.host}:{tlsResult.port}</h2>
            {tlsResult.validationError && <p className="break-all text-xs text-amber-300">{tlsResult.validationError}</p>}
            <div className="grid gap-2 text-xs md:grid-cols-2">
              <div className="rounded bg-slate-950 p-3">Negotiated: {tlsResult.tlsVersion || 'Unavailable'} · {tlsResult.cipherSuite || 'No cipher'}{tlsResult.negotiatedProtocol ? ` · ${tlsResult.negotiatedProtocol}` : ''}</div>
              <div className={`rounded p-3 ${tlsResult.trusted ? 'bg-emerald-950 text-emerald-300' : 'bg-rose-950 text-rose-300'}`}>{tlsResult.trusted ? 'Certificate trusted' : 'Certificate not verified'}{tlsResult.selfSigned ? ' · Self-signed' : ''}</div>
              {tlsResult.subject && <div className="rounded bg-slate-950 p-3">Subject: {tlsResult.subject}<br />Issuer: {tlsResult.issuer}</div>}
              {tlsResult.notAfter && <div className="rounded bg-slate-950 p-3">Expires: {new Date(tlsResult.notAfter).toLocaleString()} · {tlsResult.daysRemaining} day(s) remaining</div>}
              <div className={`rounded p-3 ${tlsResult.http2Supported ? 'bg-emerald-950 text-emerald-300' : 'bg-slate-950 text-slate-400'}`}>HTTP/2: {tlsResult.http2Supported ? 'Negotiated via ALPN' : 'Not negotiated'}</div>
              <div className={`rounded p-3 ${tlsResult.http3Advertised ? 'bg-sky-950 text-sky-300' : 'bg-slate-950 text-slate-400'}`}>HTTP/3: {tlsResult.http3Advertised ? `Advertised · ${tlsResult.http3Advertisement}` : 'Not advertised by Alt-Svc'}</div>
            </div>
            {tlsResult.weakCipherWarning && <p className="rounded border border-amber-800 bg-amber-950/40 p-3 text-xs text-amber-300">{tlsResult.weakCipherWarning}</p>}
            {tlsResult.weakTls12Ciphers?.length ? <div className="rounded border border-rose-800 bg-rose-950/30 p-3 text-xs text-rose-300"><div className="font-semibold">Accepted legacy TLS 1.2 ciphers</div><div className="mt-1 break-all font-mono">{tlsResult.weakTls12Ciphers.join(' · ')}</div></div> : null}
            {(tlsResult.tls10Status || tlsResult.tls11Status) && (
              <div className="grid gap-2 sm:grid-cols-2">
                {[
                  { label: 'TLS 1.0', status: tlsResult.tls10Status, error: tlsResult.tls10Error },
                  { label: 'TLS 1.1', status: tlsResult.tls11Status, error: tlsResult.tls11Error },
                ].map((probe) => (
                  <div key={probe.label} className="rounded-lg border border-slate-800 bg-slate-950 p-3">
                    <span className={`inline-flex rounded border px-2 py-1 text-xs font-semibold ${getTLSProbeColor(probe.status)}`}>
                      {probe.label} · {getTLSProbeLabel(probe.status)}
                    </span>
                    {probe.error && <p className="mt-2 break-all text-[11px] leading-relaxed text-slate-400">{probe.error}</p>}
                  </div>
                ))}
              </div>
            )}
            <div><div className="mb-1 text-xs font-semibold text-slate-400">Certificate SANs</div><div className="flex flex-wrap gap-1">{tlsResult.sans.map((name) => <span key={name} className="rounded bg-slate-950 px-2 py-1 font-mono text-[11px]">{name}</span>)}</div></div>
          </div>}
        </div>
      )}
      {activeTab === 'dns' && (
        <div className="space-y-4">
          <div className="rounded-xl border border-slate-800 bg-slate-900 p-4 space-y-3">
            <label className="block text-xs text-slate-400">Authorized domain</label>
            <input value={dnsDomain} onChange={(e) => setDnsDomain(e.target.value)} placeholder="example.com" className="w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-sm" />
            <label className="flex items-center gap-2 text-xs text-slate-300"><input type="checkbox" checked={includeRDAP} onChange={(e) => setIncludeRDAP(e.target.checked)} />Include RDAP network/country registration lookups (external request)</label>
            <button onClick={runDNSIntelligence} disabled={isReconBusy} className="w-full rounded-lg bg-emerald-600 py-2 text-xs font-semibold disabled:bg-slate-700">{isReconBusy ? 'Resolving recordsâ€¦' : 'Inspect DNS Records'}</button>
          </div>
          {dnsResult && <div className="rounded-xl border border-slate-800 bg-slate-900 p-4 space-y-3">
            <h2 className="text-sm font-bold">DNS intelligence · {dnsResult.domain}</h2>
            {dnsResult.errors?.map((e, i) => <p key={i} className="text-xs text-amber-300">{e}</p>)}
            {([['A', dnsResult.a], ['AAAA', dnsResult.aaaa], ['MX', dnsResult.mx], ['NS', dnsResult.ns], ['TXT', dnsResult.txt], ['SPF', dnsResult.spf], ['DMARC', dnsResult.dmarc]] as [string, string[]][]).map(([label, values]) => <div key={label} className="rounded bg-slate-950 p-3"><div className="mb-1 text-[11px] font-bold text-emerald-300">{label}</div>{values.length ? values.map((v, i) => <div key={i} className="break-all text-xs text-slate-200">{v}</div>) : <div className="text-xs text-slate-600">No record found</div>}</div>)}
            <div className="rounded bg-slate-950 p-3"><div className="mb-1 text-[11px] font-bold text-emerald-300">Reverse DNS (PTR)</div>{Object.entries(dnsResult.ptr).map(([ip, names]) => <div key={ip} className="text-xs">{ip}: {names.join(', ')}</div>)}</div>
            {dnsResult.rdap?.map((item) => <div key={item.ip} className="rounded bg-slate-950 p-3 text-xs">RDAP {item.ip} · Registry {item.networkHandle || 'unknown'} · {item.name || 'unknown network'} · {item.country || 'country unknown'}</div>)}
          </div>}
        </div>
      )}
      {activeTab === 'ip' && (
        <div className="space-y-4">
          <div className="rounded-xl border border-slate-800 bg-slate-900 p-4 space-y-3">
            <label className="block text-xs text-slate-400">Authorized IPv4 or IPv6 address</label>
            <input value={ipTarget} onChange={(e) => setIpTarget(e.target.value)} placeholder="8.8.8.8 or 2001:4860:4860::8888" className="w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-sm" />
            <button onClick={runIPInformation} disabled={isReconBusy} className="w-full rounded-lg bg-emerald-600 py-2 text-xs font-semibold disabled:bg-slate-700">{isReconBusy ? 'Inspecting IPâ€¦' : 'Inspect IP Information'}</button>
            <p className="text-[11px] leading-relaxed text-slate-500">The module shows local address classification, PTR results, and public-IP RDAP registration metadata. It does not provide geolocation or infer an ASN/provider beyond the labeled RDAP response.</p>
          </div>
          {ipResult && <div className="rounded-xl border border-slate-800 bg-slate-900 p-4 space-y-3">
            <div className="flex flex-wrap items-center gap-2"><h2 className="text-sm font-bold">IP information · {ipResult.ip || ipTarget}</h2>{ipResult.addressClass && <span className="rounded border border-sky-800 bg-sky-950/50 px-2 py-1 text-[11px] text-sky-300">{ipResult.addressClass}</span>}</div>
            {ipResult.errors?.map((error, index) => <p key={index} className="text-xs text-amber-300">{error}</p>)}
            <div className="rounded bg-slate-950 p-3"><div className="mb-1 text-[11px] font-bold text-emerald-300">Reverse DNS (PTR)</div>{ipResult.reverseDns.length ? ipResult.reverseDns.map((name) => <div key={name} className="break-all text-xs text-slate-200">{name}</div>) : <div className="text-xs text-slate-600">No PTR name returned</div>}</div>
            {ipResult.rdap && <div className="rounded bg-slate-950 p-3 text-xs"><div className="mb-1 text-[11px] font-bold text-emerald-300">RDAP registration metadata</div><div>Network handle: {ipResult.rdap.networkHandle || 'unknown'}</div><div>Network name: {ipResult.rdap.name || 'unknown'}</div><div>Registry country field: {ipResult.rdap.country || 'not supplied'}</div><div className="mt-1 text-[11px] text-slate-500">Source: {ipResult.rdap.source}</div></div>}
            <div className="text-[11px] text-slate-500">Sources: {ipResult.sources.join(' · ')}</div>
          </div>}
        </div>
      )}
      {activeTab === 'assetTree' && (
        <div className="space-y-4">
          <div className="rounded-xl border border-slate-800 bg-slate-900 p-4 space-y-3">
            <div className="flex flex-wrap items-start justify-between gap-3">
              <div>
                <h2 className="text-sm font-bold">Visual Attack Surface</h2>
                <p className="mt-1 text-xs leading-relaxed text-slate-400">Read-only tree built from locally stored scan history. It groups roots, subdomains, open services, web endpoints, technologies, API/config clues, CVE matches, TLS and DNS observations. It does not run new scans.</p>
              </div>
              <span className="rounded border border-slate-700 bg-slate-950 px-2 py-1 text-[11px] text-slate-400">{assetTreeNodes.length} root(s) · {historyEntries.length} history record(s)</span>
            </div>
            <div className="flex flex-wrap gap-2">
              <input value={assetTreeQuery} onChange={(event) => setAssetTreeQuery(event.target.value)} placeholder="Filter assets, technologies, CVEs…" className="min-h-10 min-w-[220px] flex-1 rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-xs" />
              <button type="button" onClick={expandAllAssetTree} disabled={!assetTreeNodes.length} className="min-h-10 rounded-lg border border-slate-700 bg-slate-800 px-3 py-2 text-xs font-semibold disabled:opacity-40">Expand all</button>
              <button type="button" onClick={() => setAssetTreeExpanded(new Set())} disabled={!assetTreeNodes.length} className="min-h-10 rounded-lg border border-slate-700 bg-slate-800 px-3 py-2 text-xs font-semibold disabled:opacity-40">Collapse all</button>
              <button type="button" onClick={exportAssetTreeJSON} disabled={!assetTreeNodes.length} className="min-h-10 rounded-lg border border-slate-700 bg-slate-800 px-3 py-2 text-xs font-semibold disabled:opacity-40">Export JSON</button>
              <button type="button" onClick={exportAssetTreeSVG} disabled={!assetTreeNodes.length} className="min-h-10 rounded-lg border border-sky-800 bg-sky-950/40 px-3 py-2 text-xs font-semibold text-sky-300 disabled:opacity-40">Export SVG</button>
              <button type="button" onClick={() => void exportAssetTreePNG()} disabled={!assetTreeNodes.length} className="min-h-10 rounded-lg border border-sky-800 bg-sky-950/40 px-3 py-2 text-xs font-semibold text-sky-300 disabled:opacity-40">Export PNG</button>
            </div>
          </div>
          {!assetTreeNodes.length ? (
            <div className="rounded-xl border border-dashed border-slate-700 bg-slate-900/60 p-8 text-center text-xs text-slate-400">No matching asset data. Run or import an authorized scan, then refresh History.</div>
          ) : (
            <div className="grid gap-4 xl:grid-cols-[minmax(0,1fr)_20rem]">
              <div className="rounded-xl border border-slate-800 bg-slate-900 p-3 sm:p-4">
                {assetTreeNodes.map((node) => <AssetTreeBranch key={node.id} node={node} depth={0} expanded={assetTreeExpanded} onToggle={toggleAssetTreeNode} onSelect={selectAssetTreeNode} />)}
              </div>
              <aside className="rounded-xl border border-slate-800 bg-slate-900 p-4">
                <h3 className="text-sm font-bold">Selected node</h3>
                {assetTreeSelected ? (
                  <div className="mt-3 space-y-2 text-xs">
                    <div className="rounded bg-slate-950 p-3"><div className="text-[10px] uppercase text-slate-500">Type</div><div className="mt-1 text-sky-300">{assetTreeSelected.type}</div></div>
                    <div className="rounded bg-slate-950 p-3"><div className="text-[10px] uppercase text-slate-500">Asset</div><div className="mt-1 break-all text-slate-200">{assetTreeSelected.label}</div></div>
                    {assetTreeSelected.status && <div className="rounded bg-slate-950 p-3"><div className="text-[10px] uppercase text-slate-500">Status</div><div className="mt-1 text-amber-300">{assetTreeSelected.status}</div></div>}
                    {assetTreeSelected.meta && <div className="rounded bg-slate-950 p-3"><div className="text-[10px] uppercase text-slate-500">Metadata</div><div className="mt-1 break-all text-slate-400">{assetTreeSelected.meta}</div></div>}
                    {assetTreeSelected.findingId && <button type="button" onClick={() => { setFindingDrawerId(assetTreeSelected.findingId || null); setFindingDrawerHistoryId(assetTreeSelected.historyId ?? null); }} className="w-full rounded-lg bg-emerald-600 px-3 py-2 text-xs font-semibold text-white hover:bg-emerald-500">Open remediation guide</button>}
                  </div>
                ) : <p className="mt-3 text-xs leading-relaxed text-slate-500">Click a node to inspect its metadata. Finding and CVE-linked nodes can open the remediation drawer where a guide is available.</p>}
              </aside>
            </div>
          )}
        </div>
      )}
      {activeTab === 'history' && (
        <div className="space-y-4">
          <div className="rounded-xl border border-slate-800 bg-slate-900 p-4 space-y-3">
            <p className="text-xs text-slate-400">Scan results are stored locally in the operating system's user configuration folder (up to 2,000 entries). Targets/results are saved with bounded redaction (credentials, sensitive URL query/fragments, and sensitive keys); review before sharing.</p>
            {historyError && <p role="alert" className="rounded-lg border border-rose-800 bg-rose-950/50 px-3 py-2 text-xs text-rose-300">{historyError}</p>}
            <div className="grid gap-2 sm:grid-cols-2 lg:grid-cols-4">
              <input value={historySearch} onChange={(e) => setHistorySearch(e.target.value)} placeholder="Search targetâ€¦" className="min-h-11 rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-sm" />
              <select value={historyTypeFilter} onChange={(e) => setHistoryTypeFilter(e.target.value as typeof historyTypeFilter)} className="min-h-11 rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-sm">
                <option value="all">All types</option>
                <option value="port">port</option>
                <option value="http">http</option>
                <option value="subdomain">subdomain</option>
                <option value="fuzzer">fuzzer</option>
                <option value="tls">tls</option>
                <option value="dns">dns</option>
                <option value="ip">ip</option>
              </select>
              <input value={historyTarget} onChange={(e) => setHistoryTarget(e.target.value)} placeholder="Target for port diff" className="min-h-11 rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-sm" />
              <div className="flex flex-wrap gap-2">
                <button onClick={() => void refreshHistory()} disabled={isHistoryBusy} className="min-h-11 flex-1 rounded-lg bg-emerald-600 px-3 py-2 text-xs font-semibold transition hover:bg-emerald-500 disabled:bg-slate-700">{isHistoryBusy ? 'Loadingâ€¦' : 'Refresh / Search'}</button>
              </div>
            </div>
            <div className="flex flex-wrap gap-2">
              <button onClick={() => void runWebAuditDiff()} disabled={isHistoryBusy || !historyTarget.trim()} className="min-h-10 rounded-lg border border-slate-700 bg-slate-800 px-3 py-2 text-xs font-semibold disabled:opacity-40">Compare Web Audit Diff</button>
              <button onClick={() => void ExportJSON('scan_history.json', JSON.stringify(historyEntries))} disabled={!historyEntries.length} className="min-h-10 rounded-lg border border-slate-700 bg-slate-800 px-3 py-2 text-xs font-semibold disabled:opacity-40">Export History JSON</button>
              <button onClick={() => void ExportPDF('scan_history.pdf', JSON.stringify(historyEntries))} disabled={!historyEntries.length} className="min-h-10 rounded-lg border border-slate-700 bg-slate-800 px-3 py-2 text-xs font-semibold disabled:opacity-40">Export History PDF</button>
              <button onClick={() => exportEngagementReport('json')} disabled={!selectedHistoryEntries.length} className="min-h-10 rounded-lg border border-sky-800 bg-sky-950/40 px-3 py-2 text-xs font-semibold text-sky-300 disabled:opacity-40">Engagement JSON ({selectedHistoryEntries.length})</button>
              <button onClick={() => exportEngagementReport('pdf')} disabled={!selectedHistoryEntries.length} className="min-h-10 rounded-lg border border-sky-800 bg-sky-950/40 px-3 py-2 text-xs font-semibold text-sky-300 disabled:opacity-40">Engagement PDF ({selectedHistoryEntries.length})</button>
              <button onClick={() => void handleClearHistory()} disabled={isHistoryBusy} className="min-h-10 rounded-lg border border-rose-800 bg-rose-950/40 px-3 py-2 text-xs font-semibold text-rose-300 hover:bg-rose-950 disabled:opacity-40">Clear All History</button>
            </div>
            <p className="text-[11px] leading-relaxed text-slate-500">Select history records below to build one consolidated engagement report across targets and scan types. JSON/PDF exports use the shared versioned report envelope and bounded redaction.</p>
          </div>
          {portDiff && portDiff.target ? <div className="rounded-xl border border-slate-800 bg-slate-900 p-4"><h2 className="mb-2 text-sm font-bold">Port diff · {portDiff.target}</h2><p className="text-xs text-slate-400">Latest: {portDiff.latestAt ? new Date(portDiff.latestAt).toLocaleString() : '—'} · Previous: {portDiff.previousAt ? new Date(portDiff.previousAt).toLocaleString() : '—'}</p><div className="mt-2 flex flex-wrap gap-2">{portDiff.newPorts.map((port) => <span key={`new-${port}`} className="rounded border border-rose-700 bg-rose-950 px-2 py-1 text-xs text-rose-300">NEW PORT DETECTED · {port}</span>)}{portDiff.removedPorts.map((port) => <span key={`removed-${port}`} className="rounded border border-slate-600 px-2 py-1 text-xs text-slate-300">Closed · {port}</span>)}{!portDiff.newPorts.length && !portDiff.removedPorts.length && <span className="text-xs text-slate-500">No changes yet, or fewer than two port scans are saved.</span>}</div></div> : null}
          {webAuditDiff && webAuditDiff.target ? <div className="rounded-xl border border-slate-800 bg-slate-900 p-4 space-y-2"><h2 className="text-sm font-bold">Web Audit diff · {webAuditDiff.target}</h2><p className="text-xs text-slate-400">Latest: {webAuditDiff.latestAt ? new Date(webAuditDiff.latestAt).toLocaleString() : '—'} · Previous: {webAuditDiff.previousAt ? new Date(webAuditDiff.previousAt).toLocaleString() : '—'}</p>{webAuditDiff.note && <p className="text-xs text-slate-500">{webAuditDiff.note}</p>}{webAuditDiff.urlDiffs?.map((d) => (<div key={d.url} className="rounded-lg border border-slate-800 bg-slate-950 p-3 text-xs space-y-1"><div className="font-semibold text-slate-200 break-all">{d.url}</div><div className="flex flex-wrap gap-2">{d.gradeChanged ? <span className="rounded bg-amber-950 border border-amber-800 px-2 py-0.5 text-amber-300">Grade {d.previousGrade || '—'} â†’ {d.latestGrade || '—'}</span> : <span className="text-slate-500">Grade unchanged ({d.latestGrade || '—'})</span>}<span className="rounded bg-slate-800 px-2 py-0.5">Risk {d.previousRiskScore} â†’ {d.latestRiskScore} ({d.riskScoreDelta >= 0 ? '+' : ''}{d.riskScoreDelta})</span>{d.statusChanged && <span className="rounded bg-slate-800 px-2 py-0.5">Status {d.previousStatus} â†’ {d.latestStatus}</span>}{d.certDaysDelta != null && <span className="rounded bg-slate-800 px-2 py-0.5">Cert days {d.previousCertDays ?? 'n/a'} â†’ {d.latestCertDays ?? 'n/a'} ({d.certDaysDelta >= 0 ? '+' : ''}{d.certDaysDelta})</span>}</div><div className="flex flex-wrap gap-2">{d.newMissingHeaders?.map((h) => <span key={`nm-${h}`} className="rounded border border-rose-800 bg-rose-950/40 px-2 py-0.5 text-rose-300">New missing: {h}</span>)}{d.resolvedMissingHeaders?.map((h) => <span key={`rm-${h}`} className="rounded border border-emerald-800 bg-emerald-950/40 px-2 py-0.5 text-emerald-300">Resolved missing: {h}</span>)}{d.newFindingIds?.map((id) => <span key={`nf-${id}`} className="rounded border border-rose-800 bg-rose-950/40 px-2 py-0.5 text-rose-300">New finding: {id}</span>)}{d.resolvedFindingIds?.map((id) => <span key={`rf-${id}`} className="rounded border border-emerald-800 bg-emerald-950/40 px-2 py-0.5 text-emerald-300">Resolved finding: {id}</span>)}</div>{!d.gradeChanged && d.riskScoreDelta === 0 && !d.statusChanged && d.certDaysDelta == null && !(d.newMissingHeaders?.length) && !(d.resolvedMissingHeaders?.length) && !(d.newFindingIds?.length) && !(d.resolvedFindingIds?.length) && <span className="text-slate-500">No compared changes detected.</span>}</div>))}</div> : null}
          <div className="space-y-2">
            {!isHistoryBusy && historyEntries.length === 0 ? (
              <div className="rounded-xl border border-dashed border-slate-700 bg-slate-900/60 p-6 text-center text-xs text-slate-400">No history records match the current search/filter. Run scans or clear filters to see stored results.</div>
            ) : historyEntries.map((entry) => (
              <details key={entry.id} className="rounded-xl border border-slate-800 bg-slate-900 p-3">
                <summary className="cursor-pointer break-all text-xs leading-relaxed">
                  <input type="checkbox" checked={selectedHistoryIds.includes(entry.id)} onChange={() => toggleHistorySelection(entry.id)} onClick={(event) => event.stopPropagation()} className="mr-2 accent-sky-500" aria-label={`Select ${entry.target} for engagement report`} />
                  <span className="mr-2 rounded bg-slate-800 px-2 py-1 text-emerald-300">{entry.scanType}</span>{entry.target}
                  <span className="ml-3 text-slate-500">{new Date(entry.createdAt).toLocaleString()}</span>
                </summary>
                <div className="mt-3 flex flex-wrap gap-2">
                  <button onClick={() => void ExportJSON(`scan_${entry.scanType}_${entry.id}.json`, entry.result)} className="rounded border border-slate-700 px-2.5 py-1.5 text-[11px] text-slate-300 hover:bg-slate-800">Export</button>
                  <button onClick={() => void handleDeleteHistoryEntry(entry.id)} disabled={isHistoryBusy} className="rounded border border-rose-800 bg-rose-950/30 px-2.5 py-1.5 text-[11px] text-rose-300 hover:bg-rose-950 disabled:opacity-40">Delete</button>
                </div>
                <pre className="mt-3 whitespace-pre-wrap break-all rounded bg-slate-950 p-3 text-[10px] text-slate-300">{formatHistoryResult(entry.result)}</pre>
              </details>
            ))}
          </div>
        </div>
      )}
      {activeTab === 'playbook' && (
        <div className="space-y-4">
          <div className="rounded-xl border border-slate-800 bg-slate-900 p-4 space-y-3">
            <div className="flex flex-wrap items-center justify-between gap-2">
              <h2 className="text-sm font-bold">Security Playbook (Bilingual Remediation Guide)</h2>
              <div className="flex items-center gap-2 text-xs">
                <span className="text-slate-400">Language:</span>
                <button type="button" onClick={()=>setPlaybookLang('en')} className={`rounded px-2 py-1 ${playbookLang==='en'?'bg-emerald-600 text-white':'bg-slate-800 text-slate-300'}`}>EN</button>
                <button type="button" onClick={()=>setPlaybookLang('my')} className={`rounded px-2 py-1 ${playbookLang==='my'?'bg-emerald-600 text-white':'bg-slate-800 text-slate-300'}`}>မြန်မာ</button>
              </div>
            </div>
            <p className="text-xs text-slate-400">Embedded remediation knowledge (EN/မြန်မာ) mapped to finding IDs with mechanism, common mistakes, attack scenario, where to fix, and stack-specific before/after/deploy/verify guidance. For authorized remediation only.</p>
            <input value={playbookQuery} onChange={(e)=>setPlaybookQuery(e.target.value)} placeholder="Search finding id or title..." className="w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-sm" />
          </div>
          <div className="grid gap-3 lg:grid-cols-2">
            {((remediationKB?.entries || []) as any[]).filter((e:any)=>{
              const q=playbookQuery.toLowerCase().trim(); if(!q) return true;
              return (e.id||'').toLowerCase().includes(q) || (e.title?.en||'').toLowerCase().includes(q) || (e.title?.my||'').includes(playbookQuery);
            }).map((e:any)=>(
              <button key={e.id} type="button" onClick={()=>{ setFindingDrawerId(e.id); setPlaybookStack(detectedTechStack); }} className="text-left rounded-xl border border-slate-800 bg-slate-900 p-4 hover:border-emerald-700">
                <div className="font-mono text-[11px] text-emerald-400">{e.id}</div>
                <div className="mt-1 text-sm font-semibold">{playbookLang==='my' ? (e.title?.my || e.title?.en) : (e.title?.en || e.title?.my)}</div>
                <div className="mt-2 line-clamp-3 text-xs text-slate-400">{guideText(e,'mechanism')}</div>
              </button>
            ))}
          </div>
        </div>
      )}

      {commandPaletteOpen && (
        <div className="fixed inset-0 z-50 flex items-start justify-center bg-black/60 p-4 pt-[10vh]" onClick={()=>setCommandPaletteOpen(false)}>
          <div className="w-full max-w-xl rounded-xl border border-slate-700 bg-slate-900 p-3 shadow-2xl" onClick={(e)=>e.stopPropagation()}>
            <input autoFocus value={paletteQuery} onChange={(e)=>setPaletteQuery(e.target.value)} placeholder="Go to module or action... (Ctrl/Cmd+K)" className="w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-sm outline-none focus:border-emerald-500" />
            <div className="mt-2 max-h-72 space-y-1 overflow-auto">
              {GROUP_ORDER.map((group) => {
                const groupData = NAV_GROUPS[group];
                const isSingleTab = groupData.tabs.length === 1;
                if (isSingleTab) {
                  const tab = groupData.tabs[0];
                  return (
                    <button key={group} type="button" onClick={()=>{ setActiveTab(tab.id); if(tab.id==='history' || tab.id==='assetTree') void refreshHistory(); if(tab.id==='workspaces') void loadWorkspaces(); setCommandPaletteOpen(false); }} className="w-full rounded px-3 py-2 text-left text-sm hover:bg-slate-800">{tab.label} <span className="text-xs text-slate-500">module</span></button>
                  );
                }
                return (
                  <div key={group}>
                    <span className="px-3 py-1 text-[11px] text-slate-500">{groupData.label}</span>
                    {groupData.tabs.map((tab) => (
                      <button key={tab.id} type="button" onClick={()=>{ setActiveTab(tab.id); if(tab.id==='history' || tab.id==='assetTree') void refreshHistory(); if(tab.id==='workspaces') void loadWorkspaces(); setCommandPaletteOpen(false); }} className="w-full rounded px-3 py-2 text-left text-sm hover:bg-slate-800">{tab.label} <span className="text-xs text-slate-500">module</span></button>
                    ))}
                  </div>
                );
              })}
              <hr className="border-slate-800 my-1" />
              <span className="px-3 py-1 text-[11px] text-slate-500">Actions</span>
              <button type="button" onClick={()=>{ void refreshHistory(); setActiveTab('history'); setCommandPaletteOpen(false); }} className="w-full rounded px-3 py-2 text-left text-sm hover:bg-slate-800">Refresh History <span className="text-xs text-slate-500">action</span></button>
              <button type="button" onClick={()=>{ void togglePause(); setCommandPaletteOpen(false); }} className="w-full rounded px-3 py-2 text-left text-sm hover:bg-slate-800">{isPaused?'Resume scans':'Pause scans'} <span className="text-xs text-slate-500">action</span></button>
              <hr className="border-slate-800 my-1" />
              <span className="px-3 py-1 text-[11px] text-slate-500">CVE Feed</span>
              <button type="button" onClick={()=>{ setActiveTab('cvefeed'); void loadCVEFeed(); setCommandPaletteOpen(false); }} className="w-full rounded px-3 py-2 text-left text-sm hover:bg-slate-800">Open CVE Feed <span className="text-xs text-slate-500">module</span></button>
              <button type="button" onClick={()=>{ void syncCVEFeed(); setCommandPaletteOpen(false); }} className="w-full rounded px-3 py-2 text-left text-sm hover:bg-slate-800">Sync Live CVE Feed <span className="text-xs text-slate-500">action</span></button>
              <hr className="border-slate-800 my-1" />
              <span className="px-3 py-1 text-[11px] text-slate-500">Workspaces</span>
              <button type="button" onClick={()=>{ setActiveTab('workspaces'); setCommandPaletteOpen(false); }} className="w-full rounded px-3 py-2 text-left text-sm hover:bg-slate-800">Open Workspaces tab <span className="text-xs text-slate-500">action</span></button>
              <button type="button" onClick={()=>{ setActiveTab('workspaces'); setCommandPaletteOpen(false); }} className="w-full rounded px-3 py-2 text-left text-sm hover:bg-slate-800">Create Workspace <span className="text-xs text-slate-500">action</span></button>
              <button type="button" onClick={()=>{ setActiveTab('workspaces'); setCommandPaletteOpen(false); }} className="w-full rounded px-3 py-2 text-left text-sm hover:bg-slate-800">Assign History to Workspace <span className="text-xs text-slate-500">action</span></button>
              <hr className="border-slate-800 my-1" />
              <span className="px-3 py-1 text-[11px] text-slate-500">Import & Inspector</span>
              <button type="button" onClick={()=>{ setActiveTab('import'); setCommandPaletteOpen(false); }} className="w-full rounded px-3 py-2 text-left text-sm hover:bg-slate-800">Import Nmap XML / Subdomains <span className="text-xs text-slate-500">action</span></button>
              <button type="button" onClick={()=>{ setActiveTab('inspector'); setCommandPaletteOpen(false); }} className="w-full rounded px-3 py-2 text-left text-sm hover:bg-slate-800">HTTP Inspector & Replay <span className="text-xs text-slate-500">action</span></button>
            </div>
            <div className="mt-2 text-[11px] text-slate-500">Esc to close</div>
          </div>
        </div>
      )}

      {findingDrawerId && (() => {
        const g = lookupGuide(findingDrawerId);
        const stacks: string[] = (remediationKB?.stacks && remediationKB.stacks.length) ? remediationKB.stacks : ['Next.js','Laravel','Express','Nginx','Apache','Supabase'];
        const stackFix = g?.stacks?.[playbookStack] || g?.stacks?.[detectedTechStack] || null;
        return (
          <div className="fixed inset-0 z-50 flex justify-end bg-black/50" onClick={()=>setFindingDrawerId(null)}>
            <div className="h-full w-full max-w-2xl overflow-y-auto border-l border-slate-700 bg-slate-900 p-4 sm:p-5" onClick={(e)=>e.stopPropagation()}>
              <div className="flex items-start justify-between gap-3">
                <div>
                  <div className="font-mono text-[11px] text-emerald-400">{findingDrawerId}</div>
                  <h3 className="text-lg font-bold">{g ? (playbookLang==='my' ? (g.title?.my || g.title?.en) : (g.title?.en || g.title?.my)) : 'Remediation guide'}</h3>
                </div>
                <div className="flex items-center gap-2">
                  <button type="button" onClick={()=>setPlaybookLang('en')} className={`rounded px-2 py-1 text-xs ${playbookLang==='en'?'bg-emerald-600':'bg-slate-800'}`}>EN</button>
                  <button type="button" onClick={()=>setPlaybookLang('my')} className={`rounded px-2 py-1 text-xs ${playbookLang==='my'?'bg-emerald-600':'bg-slate-800'}`}>မြန်မာ</button>
                  <button type="button" onClick={()=>setFindingDrawerId(null)} className="rounded border border-slate-700 px-2 py-1 text-xs">Close</button>
                </div>
              </div>
              {!g ? <p className="mt-4 text-sm text-slate-400">No embedded guide for this finding ID.</p> : (
                <div className="mt-4 space-y-4 text-sm">
                  <section className="rounded border border-slate-800 bg-slate-950/50 p-3"><div className="flex flex-wrap gap-2 text-xs"><span className="rounded bg-rose-950/60 px-2 py-1 text-rose-300">Severity: {g.severity || 'review'}</span><span className="rounded bg-sky-950/60 px-2 py-1 text-sky-300">Priority: {g.priority || 'P2'}</span><span className="rounded bg-amber-950/60 px-2 py-1 text-amber-300">Change risk: {g.changeRisk || 'unknown'}</span></div></section>
                  <section><h4 className="font-semibold text-emerald-300">Mechanism</h4><p className="mt-1 whitespace-pre-wrap text-slate-300">{guideText(g,'mechanism')}</p></section>
                  <section><h4 className="font-semibold text-emerald-300">Root cause</h4><p className="mt-1 whitespace-pre-wrap text-slate-300">{guideText(g,'rootCause')}</p></section>
                  <section><h4 className="font-semibold text-rose-300">Potential impact</h4><p className="mt-1 whitespace-pre-wrap text-slate-300">{guideText(g,'impact')}</p></section>
                  <section><h4 className="font-semibold text-emerald-300">Prerequisites before changing</h4><ul className="mt-1 list-disc pl-5 text-slate-300">{guideList(g,'prerequisites').map((x:string,i:number)=><li key={i}>{x}</li>)}</ul><ul className="mt-2 list-disc pl-5 text-xs text-slate-400">{guideList(g,'implementationNotes').map((x:string,i:number)=><li key={i}>{x}</li>)}</ul></section>
                  <section><h4 className="font-semibold text-emerald-300">Common developer mistakes</h4><ul className="mt-1 list-disc pl-5 text-slate-300">{guideList(g,'commonMistakes').map((x:string,i:number)=><li key={i}>{x}</li>)}</ul></section>
                  <section><h4 className="font-semibold text-emerald-300">Attack scenario</h4><p className="mt-1 whitespace-pre-wrap text-slate-300">{guideText(g,'attackScenario')}</p></section>
                  <section><h4 className="font-semibold text-emerald-300">Step-by-step safe walkthrough</h4><ol className="mt-1 list-decimal pl-5 text-slate-300">{guideList(g,'attackSteps').map((x:string,i:number)=><li key={i}>{x}</li>)}</ol></section>
                  <section><h4 className="font-semibold text-amber-300">False-positive / scope note</h4><p className="mt-1 whitespace-pre-wrap text-slate-300">{guideText(g,'falsePositiveNotes')}</p></section>
                  <section><h4 className="font-semibold text-emerald-300">Where to fix</h4><p className="mt-1 whitespace-pre-wrap text-slate-300">{guideText(g,'whereToFix')}</p></section>
                  <section>
                    <div className="flex flex-wrap items-center gap-2"><h4 className="font-semibold text-emerald-300">Stack-specific fix</h4><span className="text-[11px] text-slate-500">Detected: {detectedTechStack}</span></div>
                    <div className="mt-2 flex flex-wrap gap-1">{stacks.map(s=> <button key={s} type="button" onClick={()=>setPlaybookStack(s)} className={`rounded border px-2 py-1 text-xs ${playbookStack===s?'border-emerald-600 bg-emerald-950/40 text-emerald-300':'border-slate-700 text-slate-300'}`}>{s}</button>)}</div>
                    {stackFix ? (
                      <div className="mt-3 space-y-2">
                        <div className="text-xs text-slate-400">Target file/path: <span className="font-mono text-slate-200">{stackFix.file}</span></div>
                        <div className="text-xs text-slate-400">Code location: <span className="text-slate-200">{stackFix.location}</span></div>
                        <div><div className="text-xs font-semibold text-rose-300">Before</div><pre className="mt-1 whitespace-pre-wrap break-all rounded border border-slate-800 bg-slate-950 p-2 text-[11px] text-slate-200">{stackFix.before}</pre></div>
                        <div><div className="text-xs font-semibold text-emerald-300">After</div><pre className="mt-1 whitespace-pre-wrap break-all rounded border border-slate-800 bg-slate-950 p-2 text-[11px] text-slate-200">{stackFix.after}</pre></div>
                        <div><div className="text-xs font-semibold text-sky-300">Deploy / apply</div><p className="mt-1 whitespace-pre-wrap text-xs text-slate-300">{stackFix.deploy}</p></div>
                        <div><div className="text-xs font-semibold text-sky-300">Verify</div><p className="mt-1 whitespace-pre-wrap text-xs text-slate-300">{stackFix.verify}</p></div>
                        <div><div className="text-xs font-semibold text-amber-300">Rollback / recovery</div><p className="mt-1 whitespace-pre-wrap text-xs text-slate-300">{stackFix.rollback}</p></div>
                      </div>
                    ) : <p className="mt-2 text-xs text-slate-400">No stack-specific snippet available for this stack.</p>}
                  </section>
                  <section><h4 className="font-semibold text-emerald-300">Verification checklist</h4><ol className="mt-1 list-decimal pl-5 text-slate-300">{guideList(g,'verificationSteps').map((x:string,i:number)=><li key={i}>{x}</li>)}</ol></section>
                  {!!g.relatedFindings?.length && <section><h4 className="font-semibold text-emerald-300">Related finding IDs</h4><div className="mt-1 flex flex-wrap gap-1">{g.relatedFindings.map((x:string)=><span key={x} className="rounded border border-slate-700 px-2 py-1 text-xs text-slate-300">{x}</span>)}</div></section>}
                  {!!g.references?.length && <section><h4 className="font-semibold text-emerald-300">Further reading</h4><ul className="mt-1 list-disc pl-5 text-slate-300">{g.references.map((x:string,i:number)=><li key={i}>{x}</li>)}</ul></section>}
                </div>
)}
            </div>
          </div>
        );
      })()}

      {/* ========================================= */}
      {/* TAB: WORKSPACES */}
      {/* ========================================= */}
      {activeTab === 'workspaces' && (
        <div className="space-y-4">
          <div className="rounded-xl border border-slate-800 bg-slate-900 p-4 space-y-4">
            <h2 className="text-sm font-bold">Engagement Workspaces</h2>
            <p className="text-xs text-slate-400">Organize scan history by client/engagement. Assign history entries to workspaces for isolated multi-client management.</p>
            
            <div className="flex flex-wrap gap-3">
              <input
                value={newWorkspaceName}
                onChange={(e) => setNewWorkspaceName(e.target.value)}
                placeholder="Workspace name (e.g., Client Corp - Q4 2026)"
                className="flex-1 min-w-[200px] rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-sm outline-none focus:border-emerald-500"
              />
              <input
                value={newWorkspaceDesc}
                onChange={(e) => setNewWorkspaceDesc(e.target.value)}
                placeholder="Description (optional)"
                className="flex-1 min-w-[200px] rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-sm outline-none focus:border-emerald-500"
              />
              <button onClick={handleCreateWorkspace} disabled={!newWorkspaceName.trim()} className="rounded-lg bg-emerald-600 px-4 py-2 text-sm font-semibold text-white hover:bg-emerald-500 disabled:opacity-40">Create Workspace</button>
            </div>
            
            {workspaceError && <p className="text-rose-400 text-xs">{workspaceError}</p>}
            
            {workspaces.length === 0 ? (
              <p className="text-slate-500 text-sm">No workspaces yet. Create one above.</p>
            ) : (
              <div className="space-y-2">
                {workspaces.map((ws) => (
                  <div key={ws.id} className={`flex flex-col gap-2 sm:flex-row sm:items-center sm:justify-between rounded-lg border p-3 ${selectedWorkspaceID === ws.id ? 'border-emerald-600 bg-emerald-950/20' : 'border-slate-800 bg-slate-900'}`}>
                    <div className="min-w-0">
                      <div className="flex items-center gap-2 text-sm">
                        <span className="font-semibold text-slate-100">{ws.name}</span>
                        {selectedWorkspaceID === ws.id && <span className="rounded bg-emerald-600 px-2 py-0.5 text-[10px] text-white">Active</span>}
                      </div>
                      {ws.description && <div className="mt-1 text-xs text-slate-400 truncate">{ws.description}</div>}
                      <div className="mt-1 text-[11px] text-slate-500">Created: {new Date(ws.createdAt).toLocaleString()}</div>
                    </div>
                    <div className="flex flex-wrap gap-2">
                      <button
                        onClick={() => setSelectedWorkspaceID(selectedWorkspaceID === ws.id ? null : ws.id)}
                        className={`rounded border px-3 py-1.5 text-xs font-semibold ${selectedWorkspaceID === ws.id ? 'bg-emerald-600 border-emerald-600 text-white' : 'border-slate-700 text-slate-300 hover:bg-slate-800'}`}
                      >
                        {selectedWorkspaceID === ws.id ? 'Deselect' : 'Select'}
                      </button>
                      <button
                        onClick={() => handleDeleteWorkspace(ws.id)}
                        className="rounded border border-rose-800 bg-rose-950/30 px-3 py-1.5 text-xs text-rose-300 hover:bg-rose-950"
                      >
                        Delete
                      </button>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>

          {selectedWorkspaceID && (
            <div className="rounded-xl border border-slate-800 bg-slate-900 p-4 space-y-4">
              <h3 className="text-sm font-bold">Assign History Entries to Selected Workspace</h3>
              <p className="text-xs text-slate-400">Select history entries below and assign them to the active workspace.</p>
              <div className="space-y-2 max-h-96 overflow-auto">
                {historyEntries.map((entry) => (
                  <div key={entry.id} className="flex items-center gap-2 rounded-lg border border-slate-800 bg-slate-900 p-2 sm:flex-row sm:justify-between">
                    <div className="flex items-center gap-2 min-w-0">
                      <input
                        type="checkbox"
                        checked={selectedHistoryIds.includes(entry.id)}
                        onChange={() => toggleHistorySelection(entry.id)}
                        className="accent-emerald-500"
                      />
                      <span className="rounded bg-slate-800 px-2 py-0.5 text-[10px] text-emerald-300">{entry.scanType}</span>
                      <span className="truncate text-sm text-slate-200">{entry.target}</span>
                    </div>
                    <button
                      onClick={() => handleAssignHistoryToWorkspace(entry.id)}
                      disabled={selectedWorkspaceID === null}
                      className="shrink-0 rounded border border-slate-700 bg-slate-800 px-3 py-1.5 text-xs font-semibold hover:bg-slate-700 disabled:opacity-40"
                    >
                      Assign
                    </button>
                  </div>
                ))}
              </div>
            </div>
          )}

          {selectedWorkspaceID && (
            <div className="rounded-xl border border-slate-800 bg-slate-900 p-4 space-y-4">
              <h3 className="text-sm font-bold">Workspace Scan History</h3>
              <button onClick={async () => { const scans = await GetWorkspaceScans(selectedWorkspaceID!, 50); setHistoryEntries(scans); }} className="rounded border border-slate-700 bg-slate-800 px-3 py-1.5 text-xs font-semibold hover:bg-slate-700">Load Workspace Scans</button>
              <div className="space-y-2 max-h-96 overflow-auto">
                {historyEntries.map((entry) => (
                  <details key={entry.id} className="rounded-lg border border-slate-800 bg-slate-900">
                    <summary className="flex flex-col gap-1 sm:flex-row sm:items-center sm:justify-between p-3 cursor-pointer">
                      <div className="flex items-center gap-2 min-w-0">
                        <span className="rounded bg-slate-800 px-2 py-0.5 text-[10px] text-emerald-300">{entry.scanType}</span>
                        <span className="truncate text-sm text-slate-200">{entry.target}</span>
                      </div>
                      <div className="text-[11px] text-slate-500">{new Date(entry.createdAt).toLocaleString()}</div>
                    </summary>
                    <pre className="m-3 whitespace-pre-wrap break-all rounded bg-slate-950 p-3 text-[10px] text-slate-300">{formatHistoryResult(entry.result)}</pre>
                  </details>
                ))}
              </div>
            </div>
          )}
        </div>
      )}

      {/* ========================================= */}
      {/* TAB: IMPORT (Nmap XML & Subdomains) */}
      {/* ========================================= */}
      {activeTab === 'import' && (
        <div className="space-y-4">
          <div className="rounded-xl border border-slate-800 bg-slate-900 p-4 space-y-4">
            <h2 className="text-sm font-bold">Import External Tool Output</h2>
            <p className="text-xs text-slate-400">Import Nmap XML (-oX) and newline-delimited subdomain lists (subfinder, amass) into local history. Results are stored and can be assigned to workspaces.</p>
          </div>

          {/* Nmap XML Import */}
          <div className="rounded-xl border border-slate-800 bg-slate-900 p-4 space-y-4">
            <h3 className="text-sm font-bold">Nmap XML Import</h3>
            <div className="space-y-3">
              <label className="block text-xs text-slate-400">File or Paste XML</label>
              <input
                type="file"
                accept=".xml"
                onChange={(e) => e.target.files?.[0] && setImportNmapFile(e.target.files[0])}
                className="w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-sm outline-none focus:border-emerald-500"
              />
              <textarea
                value={importNmapText}
                onChange={(e) => setImportNmapText(e.target.value)}
                placeholder="Or paste Nmap XML content here..."
                rows={6}
                className="w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-sm outline-none focus:border-emerald-500 font-mono text-[11px]"
              />
              <div className="flex flex-wrap gap-2">
                <button onClick={() => handleImportNmap(false)} className="rounded-lg bg-emerald-600 px-4 py-2 text-sm font-semibold text-white hover:bg-emerald-500">Import to Default</button>
                {selectedWorkspaceID && (
                  <button onClick={() => handleImportNmap(true)} className="rounded-lg border border-emerald-600 bg-slate-800 px-4 py-2 text-sm font-semibold text-emerald-300 hover:bg-emerald-950/20">Import to Selected Workspace</button>
                )}
              </div>
              {importError && <p className="text-rose-400 text-xs">{importError}</p>}
            </div>
            {nmapImportResult && (
              <div className="mt-4 rounded-lg bg-slate-950 p-3 space-y-1 text-xs">
                <div className="font-semibold text-slate-200">Import Result</div>
                <div className="grid grid-cols-4 gap-2 text-slate-300">
                  <span>Hosts processed: <strong>{nmapImportResult.hostsProcessed}</strong></span>
                  <span>Hosts up: <strong>{nmapImportResult.hostsUp}</strong></span>
                  <span>Open ports: <strong>{nmapImportResult.portsFound}</strong></span>
                  <span>Web endpoints: <strong>{nmapImportResult.webEndpointsFound}</strong></span>
                </div>
                {nmapImportResult.errors?.length && <p className="mt-2 text-rose-400">Errors: {nmapImportResult.errors.join('; ')}</p>}
              </div>
            )}
          </div>

          {/* Subdomain Import */}
          <div className="rounded-xl border border-slate-800 bg-slate-900 p-4 space-y-4">
            <h3 className="text-sm font-bold">Subdomain List Import</h3>
            <p className="text-xs text-slate-400">Import newline-delimited subdomains (e.g., from subfinder, amass). Each line: subdomain.example.com</p>
            <div className="space-y-3">
              <label className="block text-xs text-slate-400">File or Paste List</label>
              <input
                type="file"
                accept=".txt"
                onChange={(e) => e.target.files?.[0] && setImportSubdomainsFile(e.target.files[0])}
                className="w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-sm outline-none focus:border-emerald-500"
              />
              <textarea
                value={importSubdomainsText}
                onChange={(e) => setImportSubdomainsText(e.target.value)}
                placeholder="Or paste subdomains here (one per line)..."
                rows={6}
                className="w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-sm outline-none focus:border-emerald-500 font-mono text-[11px]"
              />
              <div className="flex flex-wrap gap-2">
                <button onClick={() => handleImportSubdomains(false)} className="rounded-lg bg-emerald-600 px-4 py-2 text-sm font-semibold text-white hover:bg-emerald-500">Import to Default</button>
                {selectedWorkspaceID && (
                  <button onClick={() => handleImportSubdomains(true)} className="rounded-lg border border-emerald-600 bg-slate-800 px-4 py-2 text-sm font-semibold text-emerald-300 hover:bg-emerald-950/20">Import to Selected Workspace</button>
                )}
              </div>
              {importError && <p className="text-rose-400 text-xs">{importError}</p>}
            </div>
            {subdomainImportResult && (
              <div className="mt-4 rounded-lg bg-slate-950 p-3 space-y-1 text-xs">
                <div className="font-semibold text-slate-200">Import Result</div>
                <div className="grid grid-cols-4 gap-2 text-slate-300">
                  <span>Loaded: <strong>{subdomainImportResult.subdomainsLoaded}</strong></span>
                  <span>Duplicates removed: <strong>{subdomainImportResult.duplicatesRemoved}</strong></span>
                  <span>Invalid entries: <strong>{subdomainImportResult.invalidEntries}</strong></span>
                </div>
                {subdomainImportResult.errors?.length && <p className="mt-2 text-rose-400">Errors: {subdomainImportResult.errors.join('; ')}</p>}
              </div>
            )}
          </div>
        </div>
      )}

      {/* ========================================= */}
      {/* TAB: HTTP INSPECTOR & REPLAY */}
      {/* ========================================= */}
      {activeTab === 'inspector' && (
        <div className="space-y-4">
          <div className="rounded-xl border border-slate-800 bg-slate-900 p-4 space-y-4">
            <h2 className="text-sm font-bold">Raw HTTP Inspector & Bounded Replay</h2>
            <p className="text-xs text-slate-400">Inspect raw request/response headers and body for any URL. Replay with modified headers/method within the same host/port scope. Safe methods only (GET, HEAD, OPTIONS).</p>
          </div>

          <div className="rounded-xl border border-slate-800 bg-slate-900 p-4 space-y-4">
            <h3 className="text-sm font-bold">Inspect URL</h3>
            <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
              <div className="col-span-2 sm:col-span-3">
                <label className="block text-xs text-slate-400 mb-1">URL</label>
                <input
                  value={inspectURL}
                  onChange={(e) => setInspectURL(e.target.value)}
                  placeholder="https://example.com/path?query=value"
                  className="min-w-0 w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-2.5 text-sm outline-none transition focus:border-emerald-500"
                />
              </div>
              <div>
                <label className="block text-xs text-slate-400 mb-1">Method</label>
                <select value={inspectMethod} onChange={(e) => setInspectMethod(e.target.value as 'GET' | 'HEAD' | 'OPTIONS')} className="w-full rounded-lg border border-slate-700 bg-slate-950 px-2.5 py-2.5 text-sm outline-none focus:border-emerald-500">
                  <option value="GET">GET</option>
                  <option value="HEAD">HEAD</option>
                  <option value="OPTIONS">OPTIONS</option>
                </select>
              </div>
              <div className="col-span-2 sm:col-span-3">
                <label className="block text-xs text-slate-400 mb-1">Headers (one per line: Key: Value)</label>
                <textarea
                  value={inspectHeaders}
                  onChange={(e) => setInspectHeaders(e.target.value)}
                  placeholder="Authorization: Bearer token\nX-Custom-Header: value"
                  rows={3}
                  className="w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-sm outline-none focus:border-emerald-500 font-mono text-[11px]"
                />
              </div>
              <div>
                <label className="block text-xs text-slate-400 mb-1">Timeout (s)</label>
                <input
                  type="number"
                  min={3}
                  max={60}
                  value={inspectTimeout}
                  onChange={(e) => setInspectTimeout(Number(e.target.value))}
                  className="w-full rounded-lg border border-slate-700 bg-slate-950 px-2.5 py-2.5 text-sm outline-none focus:border-emerald-500"
                />
              </div>
              <div>
                <label className="flex cursor-pointer items-center gap-2 text-xs text-slate-300">
                  <input type="checkbox" checked={inspectAllowPrivate} onChange={(e) => setInspectAllowPrivate(e.target.checked)} className="accent-emerald-500" />
                  <span>Allow private/loopback targets</span>
                </label>
              </div>
              <div className="flex flex-wrap gap-2">
                <button onClick={handleInspect} disabled={isInspecting || !inspectURL.trim()} className="rounded-lg bg-emerald-600 px-4 py-2 text-sm font-semibold text-white hover:bg-emerald-500 disabled:opacity-40">{isInspecting ? 'Inspecting...' : 'Inspect'}</button>
                <button onClick={() => { setInspectURL(''); setInspectHeaders(''); setInspectResult(null); setInspectError(''); }} className="rounded-lg border border-slate-700 bg-slate-800 px-4 py-2 text-sm font-semibold text-slate-300 hover:bg-slate-700">Clear</button>
              </div>
              {inspectError && <p className="text-rose-400 text-xs">{inspectError}</p>}
            </div>
          </div>

          {inspectResult && (
            <div className="rounded-xl border border-slate-800 bg-slate-900 p-4 space-y-4">
              <h3 className="text-sm font-bold">Inspection Result</h3>
              <div className="space-y-3">
                {inspectResult.Request && (
                  <details className="rounded-lg border border-slate-800 bg-slate-950">
                    <summary className="p-3 cursor-pointer font-semibold text-emerald-300">REQUEST {inspectResult.Request.Method} {inspectResult.Request.URL}</summary>
                    <div className="px-3 pb-3 space-y-1 font-mono text-[11px] text-slate-300">
                      {Object.entries(inspectResult.Request.Headers).map(([k, v]) => (
                        <div key={k} className="border-b border-slate-800 py-1"><span className="text-slate-500">{k}:</span> {v}</div>
                      ))}
                      {inspectResult.Request.Body && (
                        <div className="mt-2 pt-2 border-t border-slate-800">
                          <div className="text-xs text-slate-500">Body:</div>
                          <pre className="mt-1 whitespace-pre-wrap break-all text-slate-200">{inspectResult.Request.Body}</pre>
                        </div>
                      )}
                    </div>
                  </details>
                )}
                {inspectResult.Response && (
                  <details className="rounded-lg border border-slate-800 bg-slate-950">
                    <summary className="p-3 cursor-pointer font-semibold text-emerald-300">RESPONSE HTTP/1.1 {inspectResult.Response.StatusCode} {inspectResult.Response.BodyTruncated ? '(body truncated to 64 KiB)' : ''}</summary>
                    <div className="px-3 pb-3 space-y-1 font-mono text-[11px] text-slate-300">
                      {Object.entries(inspectResult.Response.Headers).map(([k, v]) => (
                        <div key={k} className="border-b border-slate-800 py-1"><span className="text-slate-500">{k}:</span> {v}</div>
                      ))}
                      <div className="mt-2 pt-2 border-t border-slate-800">
                        <div className="text-xs text-slate-500">Body:</div>
                        <pre className="mt-1 whitespace-pre-wrap break-all text-slate-200">{inspectResult.Response.Body || '(empty)'}</pre>
                      </div>
                      {inspectResult.Response.TLS && (
                        <div className="mt-2 pt-2 border-t border-slate-800 text-xs">
                          <div className="text-sky-400">TLS: {inspectResult.Response.TLS.Version} {inspectResult.Response.TLS.CipherSuite} (verified: {inspectResult.Response.TLS.Verified ? 'yes' : 'no'})</div>
                          <div className="text-slate-400">Subject: {inspectResult.Response.TLS.Subject}</div>
                          <div className="text-slate-400">Issuer: {inspectResult.Response.TLS.Issuer}</div>
                          <div className="text-slate-400">Expires: {inspectResult.Response.TLS.ExpiresAt} ({inspectResult.Response.TLS.DaysRemaining} days)</div>
                        </div>
                      )}
                    </div>
                  </details>
                )}
              </div>

              <div className="pt-4 border-t border-slate-800">
                <h4 className="text-xs font-semibold text-slate-400 mb-2">Bounded Replay (same host/port scope)</h4>
                <div className="grid grid-cols-2 gap-2 sm:grid-cols-4">
                  <button
                    onClick={() => handleReplay({ method: 'HEAD' })}
                    className="rounded border border-slate-700 bg-slate-800 px-3 py-1.5 text-xs font-semibold hover:bg-slate-700"
                  >
                    Replay as HEAD
                  </button>
                  <button
                    onClick={() => handleReplay({ method: 'OPTIONS' })}
                    className="rounded border border-slate-700 bg-slate-800 px-3 py-1.5 text-xs font-semibold hover:bg-slate-700"
                  >
                    Replay as OPTIONS
                  </button>
                  <button
                    onClick={() => handleReplay({ headers: { ...parseCustomHeaders(inspectHeaders), 'X-Test-Replay': 'true' } })}
                    className="rounded border border-slate-700 bg-slate-800 px-3 py-1.5 text-xs font-semibold hover:bg-slate-700"
                  >
                    Replay + Test Header
                  </button>
                  <button
                    onClick={() => handleReplay({ headers: { ...parseCustomHeaders(inspectHeaders), 'User-Agent': 'Codexa Replay Test' } })}
                    className="rounded border border-slate-700 bg-slate-800 px-3 py-1.5 text-xs font-semibold hover:bg-slate-700"
                  >
                    Replay + Custom UA
                  </button>
                </div>
              </div>
            </div>
          )}
        </div>
      )}

      {/* ========================================= */}
      {/* TAB: ABOUT */}
      {/* ========================================= */}
      {activeTab === 'about' && (
        <div className="space-y-4">
          <div className="rounded-xl border border-slate-800 bg-slate-900 p-4 space-y-4">
            <div className="flex items-center gap-4">
              <img src="/logo.svg" alt="" className="h-16 w-16 rounded-xl ring-1 ring-emerald-500/30 shadow-sm shadow-emerald-950/40" />
              <div>
                <h2 className="text-xl font-bold tracking-[0.14em] text-emerald-400">CODEXA SCANNER</h2>
                <p className="text-sm text-slate-400">Authorized Network & Web Security Assessment</p>
                <p className="text-xs text-slate-500 mt-1">Version 1.1.7</p>
              </div>
            </div>
            <hr className="border-slate-800" />
            <p className="text-sm text-slate-300">
              Codexa Scanner is a desktop application for authorized network reconnaissance and HTTP security-header inspection.
              Built with Go, Wails v2, React, and TypeScript. Designed for defensive security work, education, and authorized testing only.
            </p>
            <p className="text-xs text-slate-500">
              Developed by <a href="https://arkaryan.net/" target="_blank" rel="noopener noreferrer" className="text-emerald-400 hover:text-emerald-300 underline">H!D3-C4rD</a>
            </p>
          </div>

          <div className="rounded-xl border border-slate-800 bg-slate-900 p-4 space-y-4">
            <h3 className="text-sm font-bold text-emerald-300">Core Modules</h3>
            <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-3">
              {[
                ['Port Scanner', 'Concurrent TCP port checks with capped workers, live progress, cancellation, and deterministic target resolution. Active protocol fingerprinting (SSH, SMTP, TLS, HTTP, Redis) with version extraction.'],
                ['CIDR /24 Sweep', 'Bounded subnet live-host/port sweep with scope confirmation, reverse DNS, pause/resume, RPS/jitter rate limiting, JSON export, and history persistence.'],
                ['Web Audit', 'Bulk HTTP/HTTPS checks with redirect-chain disclosure, headers/cookies/TLS/CSP diagnostics, security.txt/robots.txt inspectors, client-side exposure audit (secrets, source maps, endpoints, DOM sinks, reflected params), GraphQL/OpenAPI introspection, cloud storage bucket exposure, rate-limit/cache-control audit, webhook/OAuth posture, attack surface mapper (forms, params, scripts, storage).'],
                ['Subdomain Discovery', 'Certificate Transparency enumeration with optional DNS wordlist. 15+ cloud provider takeover clues (GitHub Pages, Vercel, Netlify, AWS, Azure, Firebase, etc.) with CNAME resolution status and remediation guidance.'],
                ['Path Fuzzer', 'HEAD-only bounded path checks with framework/env/API presets, request delay, RPS/jitter rate limiting, status/Content-Length baseline comparison.'],
                ['TLS Inspector', 'Certificate trust/expiry/SANs, negotiated protocol/cipher, HTTP/2 ALPN, HTTP/3 Alt-Svc, TLS 1.2 legacy cipher probes. TLS 1.0/1.1 reports Supported/Not supported/Inconclusive.'],
                ['DNS/Email Intelligence', 'A, AAAA, MX, NS, TXT, SPF, DMARC, PTR records. RDAP registration metadata. Email policy parser: DKIM (12 selectors), SPF, DMARC, overall rating (strong/moderate/weak/missing).'],
                ['IP Information', 'Source-labeled public/private/special-use classification, reverse DNS, public-IP RDAP metadata. No geolocation.'],
                ['History & Reports', 'SQLite history (2,000 records), latest-two port diff, cross-target/scan-type selection, engagement JSON/PDF reports, bounded redaction, search/filter/delete/clear. Workspaces for multi-client isolation. Analyst finding tags (Verified/False Positive/Needs Review/Accepted Risk) and notes.'],
              ].map(([title, desc]) => (
                <div key={title} className="rounded-lg border border-slate-800 bg-slate-950/50 p-3">
                  <h4 className="font-semibold text-slate-100">{title}</h4>
                  <p className="mt-1 text-xs text-slate-400">{desc}</p>
                </div>
              ))}
            </div>
          </div>

          <div className="rounded-xl border border-slate-800 bg-slate-900 p-4 space-y-4">
            <h3 className="text-sm font-bold text-emerald-300">CLI & Automation</h3>
            <div className="grid gap-3 sm:grid-cols-2">
              <div className="rounded-lg border border-slate-800 bg-slate-950/50 p-3">
                <h4 className="font-semibold text-slate-100">Headless Web Audit CLI</h4>
                <p className="mt-1 text-xs text-slate-400"><code>audit --url https://example.com --fail-on high --json report.json --sarif report.sarif</code></p>
                <p className="mt-1 text-xs text-slate-400">Reuses target validation and bounded checks. Redacted JSON/SARIF 2.1.0. CI exit codes (0/1/2). <code>--allow-private</code> for lab targets.</p>
              </div>
              <div className="rounded-lg border border-slate-800 bg-slate-950/50 p-3">
                <h4 className="font-semibold text-slate-100">Custom Request Headers & Proxy</h4>
                <p className="mt-1 text-xs text-slate-400">Authorization, Cookie, X-API-Key with automatic redaction. HTTP/SOCKS5 proxy routing (http/https/socks5/socks5h).</p>
              </div>
              <div className="rounded-lg border border-slate-800 bg-slate-950/50 p-3">
                <h4 className="font-semibold text-slate-100">Extensible Rule Packs</h4>
                <p className="mt-1 text-xs text-slate-400"><code>--rules rules.yaml</code> for custom secret patterns, header rules, path wordlists. YAML/JSON supported.</p>
              </div>
              <div className="rounded-lg border border-slate-800 bg-slate-950/50 p-3">
                <h4 className="font-semibold text-slate-100">External Tool Import</h4>
                <p className="mt-1 text-xs text-slate-400">Nmap XML (<code>-oX</code>) and newline-delimited subdomain lists (subfinder, amass) with workspace targeting.</p>
              </div>
            </div>
          </div>

          <div className="rounded-xl border border-slate-800 bg-slate-900 p-4 space-y-4">
            <h3 className="text-sm font-bold text-emerald-300">Key Features</h3>
            <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-3">
              {[
                'Strict scope controls: per-scan target validation, redirect-chain pinning, cross-host blocking, private-target opt-in',
                'Global rate limiting: RPS caps (0-50), random jitter (0-5000ms), pause/resume for Web Audit, Path Fuzzer, CIDR sweep',
                'Command palette (Ctrl/Cmd+K): fast navigation across modules, workspaces, reports, and actions',
                'Bilingual remediation guide (EN/မြန်မာ): mechanism, common mistakes, attack scenarios, file/location, before/after diffs, deploy/verify across 6 stacks',
                'Workspace persistence: SQLite workspaces table with foreign keys, CRUD operations, history assignment, workspace-scoped views',
                'Analyst triage: finding tags (Verified/False Positive/Needs Review/Accepted Risk) and notes persisted in SQLite',
                'HTTP Inspector & Replay: raw request/response, TLS details, bounded replay (GET/HEAD/OPTIONS with modified headers within scope)',
                'Shared versioned report model with bounded redaction for credentials, URL query/fragments, sensitive result keys',
                'Cross-platform desktop: Wails v2 (Go + React + TypeScript), Linux .deb, Windows .exe, macOS .dmg (unsigned)',
              ].map((feature, i) => (
                <div key={i} className="rounded-lg border border-slate-800 bg-slate-950/50 p-3">
                  <p className="text-xs text-slate-300">{feature}</p>
                </div>
              ))}
            </div>
          </div>

          <div className="rounded-xl border border-rose-900/60 bg-rose-950/30 p-4 space-y-2">
            <h3 className="text-sm font-bold text-rose-300">⚠ Authorized Use Only</h3>
            <p className="text-xs text-slate-400">
              Use only against systems you own or have explicit written permission to assess. Port scanning and HTTP requests may be logged, trigger defensive controls, or violate policy or law when performed without authorization. All checks are passive and non-exploitative; results are indicators for review, not proof of exploitability or a substitute for a professional assessment.
            </p>
          </div>

          <div className="rounded-xl border border-slate-800 bg-slate-900 p-4 space-y-2 text-xs text-slate-500">
            <p>Built with: Go 1.22+, Wails v2, React 18, TypeScript, Vite, Tailwind CSS</p>
            <p>Licensed for authorized testing, education, and defensive security work.</p>
            <p>Repository: <a href="https://github.com/hidecard/codexa-scanner" target="_blank" rel="noopener noreferrer" className="text-emerald-400 hover:text-emerald-300 underline">github.com/hidecard/codexa-scanner</a></p>
          </div>
        </div>
      )}

      {/* ========================================= */}
      {/* TAB: CVE FEED */}
      {/* ========================================= */}
      {activeTab === 'cvefeed' && (
        <div className="space-y-4">
          <div className="rounded-xl border border-slate-800 bg-slate-900 p-4 space-y-4">
            <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
              <div>
                <h2 className="text-sm font-bold text-slate-100">Live CVE Feed & Asset Correlation</h2>
                <p className="text-xs text-slate-400">CISA KEV + NVD Critical/High CVEs cached locally. Matched against your scanned assets.</p>
              </div>
              <div className="flex flex-wrap gap-2">
                <button onClick={() => void syncCVEFeed()} disabled={isCVEFeedLoading} className="min-h-10 rounded-lg bg-cyan-700 px-3 py-2 text-xs font-semibold hover:bg-cyan-600 disabled:opacity-50">{isCVEFeedLoading ? 'Syncing…' : 'Sync Now'}</button>
                <button onClick={() => void loadCVEFeed()} disabled={isCVEFeedLoading} className="min-h-10 rounded-lg border border-slate-700 bg-slate-800 px-3 py-2 text-xs font-semibold disabled:opacity-40">Refresh</button>
              </div>
            </div>
            {cveFeedLastSynced && <p className="text-xs text-cyan-300">Last synced: {cveFeedLastSynced}</p>}
            {cveFeedStatus && <p className="text-xs text-emerald-300">{cveFeedStatus}</p>}
            {cveFeedError && <p className="rounded border border-amber-800 bg-amber-950/30 px-2 py-2 text-xs text-amber-300">{cveFeedError}</p>}
          </div>

          <div className="rounded-xl border border-slate-800 bg-slate-900 p-4 space-y-3">
            <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
              <div className="flex flex-wrap gap-2">
                {(['ALL', 'KEV', 'CRITICAL', 'AFFECTED'] as const).map((f) => (
                  <button key={f} type="button" onClick={() => { setCVEFeedFilter(f); void loadCVEFeed(); }} className={`rounded-lg px-3 py-1.5 text-xs font-semibold transition-colors ${cveFeedFilter === f ? 'bg-emerald-600 text-white shadow-sm shadow-emerald-950/60' : 'bg-slate-950 border border-slate-700 text-slate-300 hover:bg-slate-800'}`}>
                    {f === 'ALL' ? 'All Recent' : f === 'KEV' ? '⚠️ CISA Exploited' : f === 'CRITICAL' ? '🔴 Critical Only' : '🎯 Affects My Targets'}
                  </button>
                ))}
              </div>
              <div className="flex flex-wrap gap-2">
                <input type="text" value={cveFeedSearch} onChange={(e) => setCVEFeedSearch(e.target.value)} placeholder="Search CVE ID or product (nginx, wordpress...)" className="min-w-[250px] rounded-lg border border-slate-700 bg-slate-950 px-3 py-1.5 text-xs text-slate-300 outline-none focus:border-emerald-500" />
              </div>
            </div>
          </div>

          <div className="rounded-xl border border-slate-800 bg-slate-900 p-4">
            {cveFeedSummary?.items && cveFeedSummary.items.length > 0 ? (
              <>
                <div className="mb-3 flex flex-wrap gap-2 text-xs">
                  <span className="rounded bg-emerald-950/50 px-2 py-1 text-emerald-300">Total: {cveFeedSummary.totalCached}</span>
                  <span className="rounded bg-rose-950/50 px-2 py-1 text-rose-300">CISA KEV: {cveFeedSummary.kevCount}</span>
                  <span className="rounded bg-amber-950/50 px-2 py-1 text-amber-300">Affects Your Assets: {cveFeedSummary.affectedCount}</span>
                </div>
                <div className="grid gap-3 md:grid-cols-2 lg:grid-cols-3">
                  {cveFeedSummary.items
                    .filter((item) => {
                      if (!cveFeedSearch) return true;
                      const search = cveFeedSearch.toLowerCase();
                      return item.cveId.toLowerCase().includes(search) || item.product.toLowerCase().includes(search) || item.vendor.toLowerCase().includes(search) || item.title.toLowerCase().includes(search);
                    })
                    .slice(0, 50)
                    .map((item) => (
                      <div key={item.cveId} className="rounded-lg border border-slate-800 bg-slate-950 p-3 space-y-2">
                        <div className="flex flex-wrap items-center gap-1.5 text-[11px]">
                          <span className="font-mono text-cyan-300">{item.cveId}</span>
                          {item.isKev && <span className="rounded bg-rose-950 px-1.5 py-0.5 font-semibold text-rose-300">KEV Active</span>}
                          {item.matchedTargets?.length > 0 && <span className="rounded bg-amber-950 px-1.5 py-0.5 font-semibold text-amber-300">Affects {item.matchedTargets.length} Target{item.matchedTargets.length === 1 ? '' : 's'}</span>}
                          <span className={`rounded bg-slate-800 px-1.5 py-0.5 text-slate-300 ${item.severity === 'CRITICAL' ? 'text-rose-300' : item.severity === 'HIGH' ? 'text-amber-300' : ''}`}>
                            {item.severity}{item.cvssScore ? ` · CVSS ${item.cvssScore}` : ''}
                          </span>
                        </div>
                        <div className="text-xs font-semibold text-slate-200">{item.vendor ? `${item.vendor} / ` : ''}{item.product}</div>
                        <div className="text-xs text-slate-400 line-clamp-1">{item.title}</div>
                        <div className="text-[11px] text-slate-500 line-clamp-2">{item.description}</div>
                        {item.matchedTargets?.length > 0 && (
                          <div className="text-[10px] text-emerald-300 font-mono">
                            Affected: {item.matchedTargets?.slice(0, 3).join(', ')}{item.matchedTargets && item.matchedTargets.length > 3 ? ` +${item.matchedTargets.length - 3} more` : ''}
                          </div>
                        )}
                        <div className="flex flex-wrap gap-1.5 pt-1">
                          {item.references?.slice(0, 2).map((ref, idx) => (
                            <button key={idx} type="button" onClick={() => void BrowserOpenURL(ref)} className="text-[10px] text-sky-400 hover:underline" title="Open reference">{new URL(ref).hostname}</button>
                          ))}
                          {item.references && item.references.length > 2 && <span className="text-[10px] text-slate-500">+{item.references.length - 2} more</span>}
                        </div>
                      </div>
                    ))}
                </div>
                {cveFeedSummary.items.length > 50 && <p className="mt-3 text-xs text-slate-500 text-center">Showing 50 of {cveFeedSummary.items.length} entries. Use search to filter.</p>}
              </>
            ) : (
              <p className="text-center text-xs text-slate-500 py-8">No CVE feed data. Click "Sync Now" to fetch from CISA KEV and NVD, or "Refresh" to load local cache.</p>
            )}
          </div>
        </div>
      )}

      </main>
      <footer className="mt-8 border-t border-slate-800 pt-3 text-center text-[11px] tracking-wide text-slate-500">
        Developed by{' '}
        <button type="button" onClick={() => BrowserOpenURL('https://arkaryan.net/')} className="text-emerald-400 hover:text-emerald-300 underline underline-offset-2">
          H!D3-C4rD
        </button>
      </footer>
    </div>
  );
}
