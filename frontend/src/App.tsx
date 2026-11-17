import { useState, useEffect } from 'react';
import {
  StartPortScan,
  StopPortScan,
  AnalyzeBulkURLs,
  ExportJSON,
  ExportPortsCSV,
} from '../wailsjs/go/main/App';
import { EventsOn, EventsOff } from '../wailsjs/runtime/runtime';
import { main } from '../wailsjs/go/models';

export default function App() {
  const [activeTab, setActiveTab] = useState<'scanner' | 'analyzer'>('scanner');

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

  // --- Bulk HTTP Analyzer States ---
  const [bulkUrls, setBulkUrls] = useState('https://example.com\nhttps://google.com\nhttps://github.com');
  const [httpThreads, setHttpThreads] = useState(10);
  const [isAnalyzing, setIsAnalyzing] = useState(false);
  const [httpResults, setHttpResults] = useState<main.BulkHeaderResult[]>([]);

  // Real-time Wails Event Listeners
  useEffect(() => {
    EventsOn('port:found', (finding: main.PortFinding) => {
      setFindings((prev) => [...prev, finding].sort((a, b) => a.port - b.port));
    });

    EventsOn('scan:progress', (pct: number) => {
      setProgress(pct);
    });

    EventsOn('scan:done', () => {
      setIsScanning(false);
      setProgress(100);
    });

    return () => {
      EventsOff('port:found');
      EventsOff('scan:progress');
      EventsOff('scan:done');
    };
  }, []);

  const handleStartScan = async () => {
    setScanError('');
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
    setIsScanning(false);
  };

  const handleBulkAnalyze = async () => {
    setIsAnalyzing(true);
    setHttpResults([]);
    const res = await AnalyzeBulkURLs(bulkUrls, Number(httpThreads));
    setHttpResults(res || []);
    setIsAnalyzing(false);
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

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100 p-6 font-sans">
      {/* Top Navbar */}
      <div className="flex items-center justify-between border-b border-slate-800 pb-4 mb-6">
        <div className="flex items-center gap-3">
          <div className={`w-3 h-3 rounded-full ${isScanning || isAnalyzing ? 'bg-amber-400 animate-ping' : 'bg-emerald-500'}`} />
          <div>
            <h1 className="text-lg font-bold tracking-wider text-emerald-400">CODEXA SCANNER</h1>
            <p className="text-xs text-slate-500">Authorized Network & Web Security Assessment</p>
          </div>
        </div>

        <div className="flex gap-2 bg-slate-900 p-1 rounded-lg border border-slate-800">
          <button
            onClick={() => setActiveTab('scanner')}
            className={`px-4 py-1.5 rounded-md text-xs font-semibold transition ${
              activeTab === 'scanner' ? 'bg-emerald-600 text-white' : 'text-slate-400 hover:text-white'
            }`}
          >
            Port Scanner & Banner Grabber
          </button>
          <button
            onClick={() => setActiveTab('analyzer')}
            className={`px-4 py-1.5 rounded-md text-xs font-semibold transition ${
              activeTab === 'analyzer' ? 'bg-emerald-600 text-white' : 'text-slate-400 hover:text-white'
            }`}
          >
            Passive Web Security Checks
          </button>
        </div>
      </div>

      {/* ========================================= */}
      {/* TAB 1: REAL-TIME PORT SCANNER             */}
      {/* ========================================= */}
      {activeTab === 'scanner' && (
        <div className="space-y-4">
          <div className="grid grid-cols-6 gap-3 bg-slate-900 p-4 rounded-xl border border-slate-800">
            <div className="col-span-2">
              <label className="block text-xs text-slate-400 mb-1">Target IP / Hostname</label>
              <input
                value={target}
                onChange={(e) => setTarget(e.target.value)}
                disabled={isScanning}
                className="w-full bg-slate-950 border border-slate-700 rounded-lg px-3 py-2 text-sm focus:border-emerald-500 outline-none"
              />
            </div>

            <div>
              <label className="block text-xs text-slate-400 mb-1">Start Port</label>
              <input
                type="number"
                value={startPort}
                onChange={(e) => setStartPort(Number(e.target.value))}
                disabled={isScanning}
                className="w-full bg-slate-950 border border-slate-700 rounded-lg px-3 py-2 text-sm"
              />
            </div>

            <div>
              <label className="block text-xs text-slate-400 mb-1">End Port</label>
              <input
                type="number"
                value={endPort}
                onChange={(e) => setEndPort(Number(e.target.value))}
                disabled={isScanning}
                className="w-full bg-slate-950 border border-slate-700 rounded-lg px-3 py-2 text-sm"
              />
            </div>

            <div>
              <label className="block text-xs text-slate-400 mb-1">Workers</label>
              <input
                type="number"
                value={workers}
                onChange={(e) => setWorkers(Number(e.target.value))}
                disabled={isScanning}
                className="w-full bg-slate-950 border border-slate-700 rounded-lg px-3 py-2 text-sm"
              />
            </div>

            <div>
              <label className="block text-xs text-slate-400 mb-1">Timeout (ms)</label>
              <input
                type="number"
                value={timeoutMs}
                onChange={(e) => setTimeoutMs(Number(e.target.value))}
                disabled={isScanning}
                className="w-full bg-slate-950 border border-slate-700 rounded-lg px-3 py-2 text-sm"
              />
            </div>
          </div>

          {/* Action Buttons & Progress */}
          <div className="flex items-center gap-3">
            {!isScanning ? (
              <button
                onClick={handleStartScan}
                className="flex-1 bg-emerald-600 hover:bg-emerald-500 text-white font-semibold py-2.5 rounded-xl text-sm transition"
              >
                Start Live Scan
              </button>
            ) : (
              <button
                onClick={handleStopScan}
                className="flex-1 bg-rose-600 hover:bg-rose-500 text-white font-semibold py-2.5 rounded-xl text-sm transition"
              >
                Stop Scan ({progress}%)
              </button>
            )}

            {findings.length > 0 && (
              <>
                <button
                  onClick={() => ExportPortsCSV(findings)}
                  className="bg-slate-800 hover:bg-slate-700 border border-slate-700 px-4 py-2.5 rounded-xl text-xs font-semibold"
                >
                  Export CSV
                </button>
                <button
                  onClick={() => ExportJSON('port_scan.json', JSON.stringify(findings))}
                  className="bg-slate-800 hover:bg-slate-700 border border-slate-700 px-4 py-2.5 rounded-xl text-xs font-semibold"
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

          {scanError && <p className="text-rose-400 text-xs">{scanError}</p>}

          {/* Real-time Results Table */}
          <div className="bg-slate-900 border border-slate-800 rounded-xl overflow-hidden">
            <div className="px-4 py-2.5 bg-slate-900/80 border-b border-slate-800 flex justify-between text-xs text-slate-400">
              <span>Live Open Ports & Service Banners</span>
              <span className="text-emerald-400 font-bold">{findings.length} Open Ports Found</span>
            </div>

            <div className="max-h-80 overflow-y-auto">
              <table className="w-full text-left text-xs">
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
                        <td className="py-2.5 px-4 font-bold text-emerald-400">{item.port}/tcp</td>
                        <td className="py-2.5 px-4">
                          <span className="bg-emerald-950 text-emerald-400 border border-emerald-800 px-2 py-0.5 rounded text-[10px]">
                            OPEN
                          </span>
                        </td>
                        <td className="py-2.5 px-4 text-sky-300">{item.service}</td>
                        <td className="py-2.5 px-4 text-slate-300 truncate max-w-md">
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
            <div className="flex justify-between items-center">
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
              className="w-full bg-slate-950 border border-slate-700 rounded-lg p-3 text-xs font-mono focus:border-emerald-500 outline-none"
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
          <div className="space-y-3 max-h-96 overflow-y-auto pr-1">
                {httpResults.map((res, idx) => (
              <div key={idx} className="bg-slate-900 border border-slate-800 rounded-xl p-4 space-y-2">
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-3">
                    <span className="font-mono text-sm font-bold text-slate-200">{res.url}</span>
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
                    <div className="flex flex-wrap gap-4 text-xs text-slate-400">
                      <span>Title: <strong className="text-slate-200">{res.title || 'N/A'}</strong></span>
                      <span>Server: <strong className="text-amber-300">{res.server || 'Hidden'}</strong></span>
                      {res.finalUrl && res.finalUrl !== res.url && <span>Final URL: <strong className="text-slate-200">{res.finalUrl}</strong></span>}
                      {res.poweredBy && (
                        <span>Powered-By: <strong className="text-amber-300">{res.poweredBy}</strong></span>
                      )}
                    </div>

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
      <footer className="mt-8 border-t border-slate-800 pt-3 text-center text-[11px] tracking-wide text-slate-500">Develop by H!D3-C4rD</footer>
    </div>
  );
}
