import { useState, useEffect } from 'react';
import {
  StartPortScan,
  StopPortScan,
  AnalyzeBulkURLs,
  ExportJSON,
  ExportPortsCSV,
  ExportText,
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
} from '../wailsjs/go/main/App';
import { EventsOn, EventsOff, BrowserOpenURL } from '../wailsjs/runtime/runtime';
import { main } from '../wailsjs/go/models';

type ActiveTab = 'dashboard' | 'scanner' | 'analyzer' | 'subdomains' | 'fuzzer' | 'tls' | 'dns' | 'ip' | 'history';

export default function App() {
  const [activeTab, setActiveTab] = useState<ActiveTab>('dashboard');

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

  // --- Bulk HTTP Analyzer States ---
  const [bulkUrls, setBulkUrls] = useState('https://example.com\nhttps://google.com\nhttps://github.com');
  const [httpThreads, setHttpThreads] = useState(10);
  const [httpDelayMs, setHttpDelayMs] = useState(0);
  const [allowPrivateHTTPTargets, setAllowPrivateHTTPTargets] = useState(false);
  const [isAnalyzing, setIsAnalyzing] = useState(false);
  const [httpResults, setHttpResults] = useState<main.BulkHeaderResult[]>([]);

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
  const [historySearch, setHistorySearch] = useState('');
  const [historyTypeFilter, setHistoryTypeFilter] = useState<'all' | 'port' | 'http' | 'subdomain' | 'fuzzer' | 'tls' | 'dns' | 'ip'>('all');
  const [portDiff, setPortDiff] = useState<main.PortScanDiff | null>(null);
  const [webAuditDiff, setWebAuditDiff] = useState<main.WebAuditDiff | null>(null);
  const [isReconBusy, setIsReconBusy] = useState(false);
  const [reconError, setReconError] = useState('');
  const [isHistoryBusy, setIsHistoryBusy] = useState(false);
  const [historyError, setHistoryError] = useState('');

  const errorMessage = (error: unknown, fallback: string) => {
    if (error instanceof Error && error.message) return error.message;
    if (typeof error === 'string' && error) return error;
    return fallback;
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

    return () => {
      EventsOff('port:found');
      EventsOff('scan:progress');
      EventsOff('scan:done');
      EventsOff('scan:target');
      EventsOff('scan:error');
    };
  }, []);

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

  const handleBulkAnalyze = async () => {
    const allowPrivateForBatch = allowPrivateHTTPTargets;
    setAllowPrivateHTTPTargets(false);
    setIsAnalyzing(true);
    setHttpResults([]);
    setHttpError('');
    try {
      const res = await AnalyzeBulkURLs(bulkUrls, Number(httpThreads), allowPrivateForBatch, Number(httpDelayMs));
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
      setFuzzResult(await FuzzPaths(fuzzBaseURL, fuzzWordlist.split(/\r?\n/), Number(fuzzConcurrency), Number(fuzzDelayMs)));
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
      setHistoryEntries(entries || []);
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
      setPortDiff(null);
      setWebAuditDiff(null);
    } catch (error) {
      setHistoryError(errorMessage(error, 'Unable to clear local scan history. Try again.'));
    } finally {
      setIsHistoryBusy(false);
    }
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

        <nav aria-label="Scanner modules" className="grid w-full grid-cols-2 gap-1.5 rounded-xl border border-slate-800 bg-slate-900 p-1.5 sm:grid-cols-4 lg:w-auto lg:max-w-[72%] lg:grid-cols-4 xl:grid-cols-8">
          <button
            type="button"
            onClick={() => { setActiveTab('dashboard'); void refreshHistory(); }}
            aria-pressed={activeTab === 'dashboard'}
            className={`rounded-lg px-2.5 py-2 text-[11px] font-semibold transition-colors sm:px-3 ${
              activeTab === 'dashboard' ? 'bg-emerald-600 text-white shadow-sm shadow-emerald-950/60' : 'text-slate-400 hover:bg-slate-800 hover:text-white'
            }`}
          >
            Dashboard
          </button>
          <button
            type="button"
            onClick={() => setActiveTab('scanner')}
            aria-pressed={activeTab === 'scanner'}
            className={`rounded-lg px-2.5 py-2 text-[11px] font-semibold transition-colors sm:px-3 ${
              activeTab === 'scanner' ? 'bg-emerald-600 text-white shadow-sm shadow-emerald-950/60' : 'text-slate-400 hover:bg-slate-800 hover:text-white'
            }`}
          >
            Ports
          </button>
          <button
            type="button"
            onClick={() => setActiveTab('analyzer')}
            aria-pressed={activeTab === 'analyzer'}
            className={`rounded-lg px-2.5 py-2 text-[11px] font-semibold transition-colors sm:px-3 ${
              activeTab === 'analyzer' ? 'bg-emerald-600 text-white shadow-sm shadow-emerald-950/60' : 'text-slate-400 hover:bg-slate-800 hover:text-white'
            }`}
          >
            Web Audit
          </button>
          {([
            ['subdomains', 'Subdomains'], ['fuzzer', 'Path Fuzzer'], ['tls', 'TLS'], ['dns', 'DNS'], ['ip', 'IP Info'], ['history', 'History'],
          ] as const).map(([tab, label]) => (
            <button key={tab} type="button" aria-pressed={activeTab === tab} onClick={() => { setActiveTab(tab); if (tab === 'history') void refreshHistory(); }}
              className={`rounded-lg px-2.5 py-2 text-[11px] font-semibold transition-colors sm:px-3 ${activeTab === tab ? 'bg-emerald-600 text-white shadow-sm shadow-emerald-950/60' : 'text-slate-400 hover:bg-slate-800 hover:text-white'}`}>
              {label}
            </button>
          ))}
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
          const hasData = historyEntries.length > 0 || httpResults.length > 0 || findings.length > 0;
          const exportHistoryJSON = () => void ExportJSON('scan_history.json', JSON.stringify(historyEntries));
          const Stat = ({ label, value, note }: { label: string; value: string | number; note?: string }) => (
            <div className="rounded-xl border border-slate-800 bg-slate-900 p-4">
              <div className="text-[11px] uppercase tracking-wide text-slate-500">{label}</div>
              <div className="mt-1 text-2xl font-bold text-slate-100">{value}</div>
              {note ? <div className="mt-1 text-xs text-slate-400">{note}</div> : null}
            </div>
          );
          return (
            <div className="space-y-4">
              <div className="rounded-xl border border-slate-800 bg-slate-900 p-4">
                <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
                  <div>
                    <h2 className="text-sm font-bold text-slate-100">Dashboard</h2>
                    <p className="text-xs text-slate-400">Summary from locally stored history and current in-app results. Run a scan or refresh history to populate.</p>
                  </div>
                  <div className="flex flex-wrap gap-2">
                    <button onClick={() => void refreshHistory()} disabled={isHistoryBusy} className="min-h-10 rounded-lg bg-emerald-600 px-3 py-2 text-xs font-semibold disabled:bg-slate-700">{isHistoryBusy ? 'Loading…' : 'Refresh'}</button>
                    <button onClick={exportHistoryJSON} disabled={!historyEntries.length} className="min-h-10 rounded-lg border border-slate-700 bg-slate-800 px-3 py-2 text-xs font-semibold disabled:opacity-40">Export History JSON</button>
                    <button onClick={() => setActiveTab('history')} className="min-h-10 rounded-lg border border-slate-700 px-3 py-2 text-xs text-slate-300 hover:bg-slate-800">Open History</button>
                  </div>
                </div>
                {historyError && <p role="alert" className="mt-3 rounded-lg border border-rose-800 bg-rose-950/50 px-3 py-2 text-xs text-rose-300">{historyError}</p>}
              </div>

              {!hasData && !isHistoryBusy ? (
                <div className="rounded-xl border border-dashed border-slate-700 bg-slate-900/60 p-8 text-center">
                  <p className="text-sm font-semibold text-slate-200">No scan data yet</p>
                  <p className="mt-2 text-xs text-slate-400">Start with an authorized port scan or Web Audit. History-backed summaries appear here once results are stored locally.</p>
                  <div className="mt-4 flex flex-wrap justify-center gap-2">
                    <button onClick={() => setActiveTab('scanner')} className="rounded-lg bg-emerald-600 px-3 py-2 text-xs font-semibold">Open Ports</button>
                    <button onClick={() => setActiveTab('analyzer')} className="rounded-lg border border-slate-700 px-3 py-2 text-xs text-slate-300 hover:bg-slate-800">Open Web Audit</button>
                  </div>
                </div>
              ) : (
                <>
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
                </>
              )}
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
                <label className="flex items-center gap-2 text-xs text-slate-400">
                  <span>Concurrency</span>
                  <input
                    type="number"
                    min={1}
                    max={20}
                    value={httpThreads}
                    onChange={(e) => setHttpThreads(Number(e.target.value))}
                    disabled={isAnalyzing}
                    className="w-16 rounded border border-slate-700 bg-slate-950 px-2 py-1.5 text-center text-xs text-slate-200 focus:border-emerald-500 focus:outline-none"
                  />
                </label>
                <label className="flex items-center gap-2 text-xs text-slate-400">
                  <span>Delay (ms)</span>
                  <input
                    type="number"
                    min={0}
                    max={5000}
                    step={50}
                    value={httpDelayMs}
                    onChange={(e) => setHttpDelayMs(Number(e.target.value))}
                    disabled={isAnalyzing}
                    className="w-20 rounded border border-slate-700 bg-slate-950 px-2 py-1.5 text-center text-xs text-slate-200 focus:border-emerald-500 focus:outline-none"
                  />
                </label>
              </div>
            </div>

            <textarea
              rows={4}
              value={bulkUrls}
              onChange={(e) => { setBulkUrls(e.target.value); setAllowPrivateHTTPTargets(false); }}
              placeholder="https://your-authorized-site.example&#10;http://your-lab-host.example"
              className="min-h-28 w-full resize-y rounded-lg border border-slate-700 bg-slate-950 p-3 text-xs font-mono outline-none transition focus:border-emerald-500 focus:ring-2 focus:ring-emerald-500/20"
            />

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
                              <div className="text-slate-600">↓</div>
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

                    {res.tls && (
                      <div className="rounded-lg border border-emerald-900 bg-emerald-950/30 px-3 py-2 text-xs text-emerald-200 space-y-1">
                        <div>TLS {res.tls.version} · {res.tls.cipherSuite} · {res.tls.verified ? 'Certificate verified' : 'Certificate not verified'}</div>
                        <div>{res.tls.verificationSummary || (res.tls.verified ? 'Verified by system trust store' : 'Not verified by system trust store')}</div>
                        <div>Leaf: {res.tls.subject || 'unknown'} · Issuer: {res.tls.issuer || 'unknown'}</div>
                        <div>Valid: {res.tls.notBefore ? new Date(res.tls.notBefore).toLocaleDateString() : 'n/a'} – {new Date(res.tls.expiresAt).toLocaleDateString()} ({res.tls.daysRemaining} days remaining) · SANs: {res.tls.sanCount ?? 0}</div>
                        {res.tls.chainSubjects?.length ? <div className="text-emerald-300/90">Presented chain: {res.tls.chainSubjects.join(' → ')}</div> : null}
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
                            <div className="flex items-center gap-2 text-xs font-bold uppercase">
                              <span>{finding.severity}</span><span>{finding.title}</span>
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
            <button onClick={runSubdomainDiscovery} disabled={isReconBusy} className="w-full rounded-lg bg-emerald-600 py-2 text-xs font-semibold disabled:bg-slate-700">{isReconBusy ? 'Enumerating…' : 'Query Certificate Transparency'}</button>
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
                <label className="flex items-center gap-2 text-xs text-slate-400"><span>Concurrency</span><input type="number" min={1} max={20} value={fuzzConcurrency} onChange={(e) => setFuzzConcurrency(Number(e.target.value))} className="w-20 shrink-0 rounded border border-slate-700 bg-slate-950 px-2 py-2 text-xs" /></label>
                <label className="flex items-center gap-2 text-xs text-slate-400"><span>Delay (ms)</span><input type="number" min={0} max={5000} step={50} value={fuzzDelayMs} onChange={(e) => setFuzzDelayMs(Number(e.target.value))} className="w-24 shrink-0 rounded border border-slate-700 bg-slate-950 px-2 py-2 text-xs" /></label>
              </div>
            </div>
            <textarea rows={7} value={fuzzWordlist} onChange={(e) => setFuzzWordlist(e.target.value)} className="w-full rounded-lg border border-slate-700 bg-slate-950 p-3 text-xs font-mono" />
            <button onClick={runPathFuzzer} disabled={isReconBusy} className="w-full rounded-lg bg-emerald-600 py-2 text-xs font-semibold disabled:bg-slate-700">{isReconBusy ? 'Checking paths…' : 'Run HEAD-only Path Checks'}</button>
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
            <button onClick={runTLSInspector} disabled={isReconBusy} className="w-full rounded-lg bg-emerald-600 py-2 text-xs font-semibold disabled:bg-slate-700">{isReconBusy ? 'Inspecting TLS…' : 'Inspect Certificate & Protocols'}</button>
            <p className="text-[11px] text-slate-500">Protocol probes perform TLS handshakes only. “Not supported” requires an explicit TLS protocol_version alert; connection, handshake, and local-policy errors are “Inconclusive.” Certificate details are independently checked against the system trust store.</p>
          </div>
          {tlsResult && <div className="rounded-xl border border-slate-800 bg-slate-900 p-4 space-y-3">
            <h2 className="break-all text-sm font-bold">TLS details · {tlsResult.host}:{tlsResult.port}</h2>
            {tlsResult.validationError && <p className="break-all text-xs text-amber-300">{tlsResult.validationError}</p>}
            <div className="grid gap-2 text-xs md:grid-cols-2">
              <div className="rounded bg-slate-950 p-3">Negotiated: {tlsResult.tlsVersion || 'Unavailable'} · {tlsResult.cipherSuite || 'No cipher'}</div>
              <div className={`rounded p-3 ${tlsResult.trusted ? 'bg-emerald-950 text-emerald-300' : 'bg-rose-950 text-rose-300'}`}>{tlsResult.trusted ? 'Certificate trusted' : 'Certificate not verified'}{tlsResult.selfSigned ? ' · Self-signed' : ''}</div>
              {tlsResult.subject && <div className="rounded bg-slate-950 p-3">Subject: {tlsResult.subject}<br />Issuer: {tlsResult.issuer}</div>}
              {tlsResult.notAfter && <div className="rounded bg-slate-950 p-3">Expires: {new Date(tlsResult.notAfter).toLocaleString()} · {tlsResult.daysRemaining} day(s) remaining</div>}
            </div>
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
            <button onClick={runDNSIntelligence} disabled={isReconBusy} className="w-full rounded-lg bg-emerald-600 py-2 text-xs font-semibold disabled:bg-slate-700">{isReconBusy ? 'Resolving records…' : 'Inspect DNS Records'}</button>
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
            <button onClick={runIPInformation} disabled={isReconBusy} className="w-full rounded-lg bg-emerald-600 py-2 text-xs font-semibold disabled:bg-slate-700">{isReconBusy ? 'Inspecting IP…' : 'Inspect IP Information'}</button>
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
      {activeTab === 'history' && (
        <div className="space-y-4">
          <div className="rounded-xl border border-slate-800 bg-slate-900 p-4 space-y-3">
            <p className="text-xs text-slate-400">Scan results are stored locally in the operating system's user configuration folder (up to 2,000 entries). Targets/results are saved with bounded redaction (credentials, sensitive URL query/fragments, and sensitive keys); review before sharing.</p>
            {historyError && <p role="alert" className="rounded-lg border border-rose-800 bg-rose-950/50 px-3 py-2 text-xs text-rose-300">{historyError}</p>}
            <div className="grid gap-2 sm:grid-cols-2 lg:grid-cols-4">
              <input value={historySearch} onChange={(e) => setHistorySearch(e.target.value)} placeholder="Search target…" className="min-h-11 rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-sm" />
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
                <button onClick={() => void refreshHistory()} disabled={isHistoryBusy} className="min-h-11 flex-1 rounded-lg bg-emerald-600 px-3 py-2 text-xs font-semibold transition hover:bg-emerald-500 disabled:bg-slate-700">{isHistoryBusy ? 'Loading…' : 'Refresh / Search'}</button>
              </div>
            </div>
            <div className="flex flex-wrap gap-2">
              <button onClick={() => void runWebAuditDiff()} disabled={isHistoryBusy || !historyTarget.trim()} className="min-h-10 rounded-lg border border-slate-700 bg-slate-800 px-3 py-2 text-xs font-semibold disabled:opacity-40">Compare Web Audit Diff</button>
              <button onClick={() => void ExportJSON('scan_history.json', JSON.stringify(historyEntries))} disabled={!historyEntries.length} className="min-h-10 rounded-lg border border-slate-700 bg-slate-800 px-3 py-2 text-xs font-semibold disabled:opacity-40">Export History JSON</button>
              <button onClick={() => void handleClearHistory()} disabled={isHistoryBusy} className="min-h-10 rounded-lg border border-rose-800 bg-rose-950/40 px-3 py-2 text-xs font-semibold text-rose-300 hover:bg-rose-950 disabled:opacity-40">Clear All History</button>
            </div>
          </div>
          {portDiff && portDiff.target ? <div className="rounded-xl border border-slate-800 bg-slate-900 p-4"><h2 className="mb-2 text-sm font-bold">Port diff · {portDiff.target}</h2><p className="text-xs text-slate-400">Latest: {portDiff.latestAt ? new Date(portDiff.latestAt).toLocaleString() : '—'} · Previous: {portDiff.previousAt ? new Date(portDiff.previousAt).toLocaleString() : '—'}</p><div className="mt-2 flex flex-wrap gap-2">{portDiff.newPorts.map((port) => <span key={`new-${port}`} className="rounded border border-rose-700 bg-rose-950 px-2 py-1 text-xs text-rose-300">NEW PORT DETECTED · {port}</span>)}{portDiff.removedPorts.map((port) => <span key={`removed-${port}`} className="rounded border border-slate-600 px-2 py-1 text-xs text-slate-300">Closed · {port}</span>)}{!portDiff.newPorts.length && !portDiff.removedPorts.length && <span className="text-xs text-slate-500">No changes yet, or fewer than two port scans are saved.</span>}</div></div> : null}
          {webAuditDiff && webAuditDiff.target ? <div className="rounded-xl border border-slate-800 bg-slate-900 p-4 space-y-2"><h2 className="text-sm font-bold">Web Audit diff · {webAuditDiff.target}</h2><p className="text-xs text-slate-400">Latest: {webAuditDiff.latestAt ? new Date(webAuditDiff.latestAt).toLocaleString() : '—'} · Previous: {webAuditDiff.previousAt ? new Date(webAuditDiff.previousAt).toLocaleString() : '—'}</p>{webAuditDiff.note && <p className="text-xs text-slate-500">{webAuditDiff.note}</p>}{webAuditDiff.urlDiffs?.map((d) => (<div key={d.url} className="rounded-lg border border-slate-800 bg-slate-950 p-3 text-xs space-y-1"><div className="font-semibold text-slate-200 break-all">{d.url}</div><div className="flex flex-wrap gap-2">{d.gradeChanged ? <span className="rounded bg-amber-950 border border-amber-800 px-2 py-0.5 text-amber-300">Grade {d.previousGrade || '—'} → {d.latestGrade || '—'}</span> : <span className="text-slate-500">Grade unchanged ({d.latestGrade || '—'})</span>}<span className="rounded bg-slate-800 px-2 py-0.5">Risk {d.previousRiskScore} → {d.latestRiskScore} ({d.riskScoreDelta >= 0 ? '+' : ''}{d.riskScoreDelta})</span>{d.statusChanged && <span className="rounded bg-slate-800 px-2 py-0.5">Status {d.previousStatus} → {d.latestStatus}</span>}{d.certDaysDelta != null && <span className="rounded bg-slate-800 px-2 py-0.5">Cert days {d.previousCertDays ?? 'n/a'} → {d.latestCertDays ?? 'n/a'} ({d.certDaysDelta >= 0 ? '+' : ''}{d.certDaysDelta})</span>}</div><div className="flex flex-wrap gap-2">{d.newMissingHeaders?.map((h) => <span key={`nm-${h}`} className="rounded border border-rose-800 bg-rose-950/40 px-2 py-0.5 text-rose-300">New missing: {h}</span>)}{d.resolvedMissingHeaders?.map((h) => <span key={`rm-${h}`} className="rounded border border-emerald-800 bg-emerald-950/40 px-2 py-0.5 text-emerald-300">Resolved missing: {h}</span>)}{d.newFindingIds?.map((id) => <span key={`nf-${id}`} className="rounded border border-rose-800 bg-rose-950/40 px-2 py-0.5 text-rose-300">New finding: {id}</span>)}{d.resolvedFindingIds?.map((id) => <span key={`rf-${id}`} className="rounded border border-emerald-800 bg-emerald-950/40 px-2 py-0.5 text-emerald-300">Resolved finding: {id}</span>)}</div>{!d.gradeChanged && d.riskScoreDelta === 0 && !d.statusChanged && d.certDaysDelta == null && !(d.newMissingHeaders?.length) && !(d.resolvedMissingHeaders?.length) && !(d.newFindingIds?.length) && !(d.resolvedFindingIds?.length) && <span className="text-slate-500">No compared changes detected.</span>}</div>))}</div> : null}
          <div className="space-y-2">
            {!isHistoryBusy && historyEntries.length === 0 ? (
              <div className="rounded-xl border border-dashed border-slate-700 bg-slate-900/60 p-6 text-center text-xs text-slate-400">No history records match the current search/filter. Run scans or clear filters to see stored results.</div>
            ) : historyEntries.map((entry) => (
              <details key={entry.id} className="rounded-xl border border-slate-800 bg-slate-900 p-3">
                <summary className="cursor-pointer break-all text-xs leading-relaxed">
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
