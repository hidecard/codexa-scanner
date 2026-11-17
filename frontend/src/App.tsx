import { useState, useEffect } from 'react';
import {
  StartPortScan,
  StopPortScan,
  AnalyzeBulkURLs,
  ExportJSON,
  ExportPortsCSV,
  EnumerateSubdomains,
  FuzzPaths,
  InspectTLS,
  DNSIntelligence,
  GetScanHistory,
  DiffLatestPortScans,
} from '../wailsjs/go/main/App';
import { EventsOn, EventsOff } from '../wailsjs/runtime/runtime';
import { main } from '../wailsjs/go/models';

export default function App() {
  const [activeTab, setActiveTab] = useState<'scanner' | 'analyzer' | 'subdomains' | 'fuzzer' | 'tls' | 'dns' | 'history'>('scanner');

  // --- Port Scanner States ---
  const [target, setTarget] = useState('scanme.nmap.org');
  const [startPort, setStartPort] = useState(1);
  const [endPort, setEndPort] = useState(1024);
  const [workers, setWorkers] = useState(200);
  const [timeoutMs, setTimeoutMs] = useState(800);
  const [isScanning, setIsScanning] = useState(false);
  const [progress, setProgress] = useState(0);
  const [findings, setFindings] = useState<main.PortFinding[]>([]);
  const [scanError, setScanError] = useState('');
  const [resolvedScanTarget, setResolvedScanTarget] = useState('');

  // --- Bulk HTTP Analyzer States ---
  const [bulkUrls, setBulkUrls] = useState('https://example.com\nhttps://google.com\nhttps://github.com');
  const [httpThreads, setHttpThreads] = useState(10);
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
  const [fuzzResult, setFuzzResult] = useState<main.PathFuzzResult | null>(null);
  const [tlsTarget, setTlsTarget] = useState('example.com:443');
  const [tlsResult, setTlsResult] = useState<main.TLSInspection | null>(null);
  const [dnsDomain, setDnsDomain] = useState('example.com');
  const [includeRDAP, setIncludeRDAP] = useState(false);
  const [dnsResult, setDnsResult] = useState<main.DNSIntelligenceResult | null>(null);
  const [historyTarget, setHistoryTarget] = useState('scanme.nmap.org');
  const [historyEntries, setHistoryEntries] = useState<main.HistoryEntry[]>([]);
  const [portDiff, setPortDiff] = useState<main.PortScanDiff | null>(null);
  const [isReconBusy, setIsReconBusy] = useState(false);

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
    setScanError('');
    setResolvedScanTarget('');
    setFindings([]);
    setProgress(0);
    setIsScanning(true);

    const status = await StartPortScan(
      target.trim(),
      Number(startPort),
      Number(endPort),
      Number(workers),
      Number(timeoutMs)
    );

    if (status !== 'STARTED') {
      setScanError(status);
      setIsScanning(false);
    }
  };

  const handleStopScan = async () => {
    await StopPortScan();
  };

  const handleBulkAnalyze = async () => {
    setIsAnalyzing(true);
    setHttpResults([]);
    const res = await AnalyzeBulkURLs(bulkUrls, Number(httpThreads));
    setHttpResults(res || []);
    setIsAnalyzing(false);
  };

  const runSubdomainDiscovery = async () => {
    setIsReconBusy(true);
    try {
      setSubdomainResult(await EnumerateSubdomains(subdomain, subdomainWordlist.split(/\r?\n/), useDNSBrute));
    } finally { setIsReconBusy(false); }
  };
  const runPathFuzzer = async () => {
    setIsReconBusy(true);
    try {
      setFuzzResult(await FuzzPaths(fuzzBaseURL, fuzzWordlist.split(/\r?\n/), Number(fuzzConcurrency)));
    } finally { setIsReconBusy(false); }
  };
  const runTLSInspector = async () => {
    setIsReconBusy(true);
    try { setTlsResult(await InspectTLS(tlsTarget)); }
    finally { setIsReconBusy(false); }
  };
  const runDNSIntelligence = async () => {
    setIsReconBusy(true);
    try { setDnsResult(await DNSIntelligence(dnsDomain, includeRDAP)); }
    finally { setIsReconBusy(false); }
  };
  const refreshHistory = async () => {
    setHistoryEntries(await GetScanHistory(50));
    setPortDiff(await DiffLatestPortScans(historyTarget));
  };
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

  const formatHistoryResult = (raw: string) => {
    try { return JSON.stringify(JSON.parse(raw), null, 2); }
    catch { return raw; }
  };

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100 px-3 py-4 font-sans sm:px-5 sm:py-6 lg:px-8 app-shell">
      {/* Top Navbar */}
      <header className="mb-5 flex flex-col gap-4 border-b border-slate-800 pb-4 sm:mb-6 lg:flex-row lg:items-center lg:justify-between">
        <div className="flex min-w-0 items-center gap-3">
          <div className={`w-3 h-3 rounded-full ${isScanning || isAnalyzing || isReconBusy ? 'bg-amber-400 animate-ping' : 'bg-emerald-500'}`} />
          <div className="min-w-0">
            <h1 className="text-base font-bold tracking-[0.14em] text-emerald-400 sm:text-lg">CODEXA SCANNER</h1>
            <p className="text-[11px] leading-relaxed text-slate-500 sm:text-xs">Authorized Network & Web Security Assessment</p>
          </div>
        </div>

        <nav aria-label="Scanner modules" className="grid w-full grid-cols-2 gap-1.5 rounded-xl border border-slate-800 bg-slate-900 p-1.5 sm:grid-cols-4 lg:w-auto lg:max-w-[68%] lg:grid-cols-4 xl:grid-cols-7">
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
            ['subdomains', 'Subdomains'], ['fuzzer', 'Path Fuzzer'], ['tls', 'TLS'], ['dns', 'DNS'], ['history', 'History'],
          ] as const).map(([tab, label]) => (
            <button key={tab} type="button" aria-pressed={activeTab === tab} onClick={() => { setActiveTab(tab); if (tab === 'history') void refreshHistory(); }}
              className={`rounded-lg px-2.5 py-2 text-[11px] font-semibold transition-colors sm:px-3 ${activeTab === tab ? 'bg-emerald-600 text-white shadow-sm shadow-emerald-950/60' : 'text-slate-400 hover:bg-slate-800 hover:text-white'}`}>
              {label}
            </button>
          ))}
        </nav>
      </header>
      <main className="mx-auto w-full max-w-screen-2xl">

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
                onChange={(e) => setTarget(e.target.value)}
                disabled={isScanning}
                className="min-w-0 w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-2.5 text-sm outline-none transition focus:border-emerald-500 focus:ring-2 focus:ring-emerald-500/20"
              />
            </div>

            <div>
              <label className="block text-xs text-slate-400 mb-1">Start Port</label>
              <input
                type="number"
                value={startPort}
                onChange={(e) => setStartPort(Number(e.target.value))}
                disabled={isScanning}
                className="min-w-0 w-full rounded-lg border border-slate-700 bg-slate-950 px-2.5 py-2.5 text-sm outline-none transition focus:border-emerald-500 focus:ring-2 focus:ring-emerald-500/20"
              />
            </div>

            <div>
              <label className="block text-xs text-slate-400 mb-1">End Port</label>
              <input
                type="number"
                value={endPort}
                onChange={(e) => setEndPort(Number(e.target.value))}
                disabled={isScanning}
                className="min-w-0 w-full rounded-lg border border-slate-700 bg-slate-950 px-2.5 py-2.5 text-sm outline-none transition focus:border-emerald-500 focus:ring-2 focus:ring-emerald-500/20"
              />
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

          {/* Action Buttons & Progress */}
          <div className="flex flex-col gap-2 sm:flex-row sm:items-center sm:gap-3">
            {!isScanning ? (
              <button
                onClick={handleStartScan}
                className="min-h-11 flex-1 rounded-xl bg-emerald-600 py-2.5 text-sm font-semibold text-white transition hover:bg-emerald-500 focus:outline-none focus:ring-2 focus:ring-emerald-400 focus:ring-offset-2 focus:ring-offset-slate-950"
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
              <div className="flex items-center gap-2">
                <span className="text-xs text-slate-400">Threads:</span>
                <input
                  type="number"
                  value={httpThreads}
                  onChange={(e) => setHttpThreads(Number(e.target.value))}
                  className="w-16 bg-slate-950 border border-slate-700 rounded px-2 py-1 text-xs"
                />
              </div>
            </div>

            <textarea
              rows={4}
              value={bulkUrls}
              onChange={(e) => setBulkUrls(e.target.value)}
              placeholder="https://your-authorized-site.example&#10;http://your-lab-host.example"
              className="min-h-28 w-full resize-y rounded-lg border border-slate-700 bg-slate-950 p-3 text-xs font-mono outline-none transition focus:border-emerald-500 focus:ring-2 focus:ring-emerald-500/20"
            />

            <div className="flex gap-3">
              <button
                onClick={handleBulkAnalyze}
                disabled={isAnalyzing}
                className="flex-1 bg-emerald-600 hover:bg-emerald-500 disabled:bg-slate-700 text-white font-semibold py-2 rounded-lg text-xs transition"
              >
                {isAnalyzing ? 'Analyzing Targets...' : 'Analyze All Targets'}
              </button>

              {httpResults.length > 0 && (
                <button
                  onClick={() => ExportJSON('http_security_audit.json', JSON.stringify(httpResults))}
                  className="bg-slate-800 hover:bg-slate-700 border border-slate-700 px-4 py-2 rounded-lg text-xs font-semibold"
                >
                  Export JSON Report
                </button>
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

                    {(res.technologies?.length || res.edgeServices?.length) ? (
                      <div className="flex flex-wrap gap-1.5 text-[10px]">
                        {res.technologies?.map((technology) => <span key={technology} className="rounded border border-sky-900 bg-sky-950/50 px-2 py-1 text-sky-300">{technology}</span>)}
                        {res.edgeServices?.map((edge) => <span key={edge} className="rounded border border-violet-900 bg-violet-950/50 px-2 py-1 text-violet-300">Edge/WAF clue: {edge}</span>)}
                      </div>
                    ) : null}

                    {res.tls && (
                      <div className="rounded-lg border border-emerald-900 bg-emerald-950/30 px-3 py-2 text-xs text-emerald-200">
                        TLS {res.tls.version} · {res.tls.cipherSuite} · Certificate {res.tls.verified ? 'verified' : 'not verified'} · Expires {new Date(res.tls.expiresAt).toLocaleDateString()} ({res.tls.daysRemaining} days)
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
            <div className="flex items-center justify-between gap-3"><label className="text-xs text-slate-400">Path wordlist (max 500)</label><input type="number" min={1} max={20} value={fuzzConcurrency} onChange={(e) => setFuzzConcurrency(Number(e.target.value))} className="w-20 shrink-0 rounded border border-slate-700 bg-slate-950 px-2 py-2 text-xs" /></div>
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
            <p className="text-[11px] text-slate-500">Protocol probes perform TLS handshakes only. Certificate details are independently checked against the system trust store; legacy-protocol support depends on local Go crypto policy.</p>
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
            <div className="flex flex-wrap gap-2 text-xs"><span className={`rounded border px-2 py-1 ${tlsResult.tls10Accepted ? 'border-rose-700 text-rose-300' : 'border-emerald-800 text-emerald-300'}`}>TLS 1.0 {tlsResult.tls10Accepted ? 'accepted' : 'not negotiated'}</span><span className={`rounded border px-2 py-1 ${tlsResult.tls11Accepted ? 'border-rose-700 text-rose-300' : 'border-emerald-800 text-emerald-300'}`}>TLS 1.1 {tlsResult.tls11Accepted ? 'accepted' : 'not negotiated'}</span></div>
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
      {activeTab === 'history' && (
        <div className="space-y-4">
          <div className="rounded-xl border border-slate-800 bg-slate-900 p-4 space-y-3">
            <p className="text-xs text-slate-400">Scan results are stored locally in the operating system's user configuration folder (up to 2,000 entries).</p>
            <div className="flex flex-col gap-2 sm:flex-row sm:flex-wrap"><input value={historyTarget} onChange={(e) => setHistoryTarget(e.target.value)} placeholder="target hostname" className="min-h-11 min-w-0 w-full flex-1 rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-sm sm:min-w-64" /><button onClick={() => void refreshHistory()} className="min-h-11 w-full rounded-lg bg-emerald-600 px-4 py-2 text-xs font-semibold transition hover:bg-emerald-500 sm:w-auto">Refresh History & Compare Ports</button></div>
          </div>
          {portDiff && <div className="rounded-xl border border-slate-800 bg-slate-900 p-4"><h2 className="mb-2 text-sm font-bold">Port diff · {portDiff.target}</h2><p className="text-xs text-slate-400">Latest: {portDiff.latestAt ? new Date(portDiff.latestAt).toLocaleString() : '—'} · Previous: {portDiff.previousAt ? new Date(portDiff.previousAt).toLocaleString() : '—'}</p><div className="mt-2 flex flex-wrap gap-2">{portDiff.newPorts.map((port) => <span key={`new-${port}`} className="rounded border border-rose-700 bg-rose-950 px-2 py-1 text-xs text-rose-300">NEW PORT DETECTED · {port}</span>)}{portDiff.removedPorts.map((port) => <span key={`removed-${port}`} className="rounded border border-slate-600 px-2 py-1 text-xs text-slate-300">Closed · {port}</span>)}{!portDiff.newPorts.length && !portDiff.removedPorts.length && <span className="text-xs text-slate-500">No changes yet, or fewer than two port scans are saved.</span>}</div></div>}
          <div className="space-y-2">{historyEntries.map((entry) => <details key={entry.id} className="rounded-xl border border-slate-800 bg-slate-900 p-3"><summary className="cursor-pointer break-all text-xs leading-relaxed"><span className="mr-2 rounded bg-slate-800 px-2 py-1 text-emerald-300">{entry.scanType}</span>{entry.target}<span className="ml-3 text-slate-500">{new Date(entry.createdAt).toLocaleString()}</span></summary><pre className="mt-3 whitespace-pre-wrap break-all rounded bg-slate-950 p-3 text-[10px] text-slate-300">{formatHistoryResult(entry.result)}</pre></details>)}</div>
        </div>
      )}
      </main>
      <footer className="mt-8 border-t border-slate-800 pt-3 text-center text-[11px] tracking-wide text-slate-500">Develop by H!D3-C4rD</footer>
    </div>
  );
}
