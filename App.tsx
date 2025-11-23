import React, { useState, useMemo } from 'react';
import { FileUpload } from './components/FileUpload';
import { StatCard } from './components/StatCard';
import { parseTrafficCSV, parseWatchGuardXML } from './services/parserService';
import { performAudit } from './services/auditService';
import { generateSecurityReport } from './services/geminiService';
import { PolicyRule, TrafficLog, AuditSummary } from './types';
import { BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, Cell } from 'recharts';

enum AppStep {
  UPLOAD = 0,
  DASHBOARD = 1,
  REPORT = 2
}

const App: React.FC = () => {
  const [step, setStep] = useState<AppStep>(AppStep.UPLOAD);
  const [loading, setLoading] = useState(false);
  const [reportText, setReportText] = useState("");

  // Raw Data State
  const [policies, setPolicies] = useState<PolicyRule[]>([]);
  const [wgLogs, setWgLogs] = useState<TrafficLog[]>([]);
  const [winLogs, setWinLogs] = useState<TrafficLog[]>([]);
  
  // File Status
  const [filesLoaded, setFilesLoaded] = useState({
    config: false,
    wgLogs: false,
    winLogs: false
  });

  const handleConfigUpload = async (text: string) => {
    try {
      const data = await parseWatchGuardXML(text);
      setPolicies(data);
      setFilesLoaded(prev => ({ ...prev, config: true }));
    } catch (e) {
      alert("Error parsing XML");
    }
  };

  const handleWgLogUpload = async (text: string) => {
    try {
      const data = await parseTrafficCSV(text, 'WatchGuard');
      setWgLogs(data);
      setFilesLoaded(prev => ({ ...prev, wgLogs: true }));
    } catch (e) {
      alert("Error parsing WG CSV");
    }
  };

  const handleWinLogUpload = async (text: string) => {
    try {
      const data = await parseTrafficCSV(text, 'Windows');
      setWinLogs(data);
      setFilesLoaded(prev => ({ ...prev, winLogs: true }));
    } catch (e) {
      alert("Error parsing Windows CSV");
    }
  };

  // Computed Audit Results
  const auditResults: AuditSummary | null = useMemo(() => {
    if (policies.length === 0 && wgLogs.length === 0 && winLogs.length === 0) return null;
    return performAudit(policies, wgLogs, winLogs);
  }, [policies, wgLogs, winLogs]);

  const canProceed = filesLoaded.config && filesLoaded.wgLogs && filesLoaded.winLogs;

  const handleGenerateReport = async () => {
    if (!auditResults) return;
    setLoading(true);
    setStep(AppStep.REPORT);
    const text = await generateSecurityReport(auditResults);
    setReportText(text);
    setLoading(false);
  };

  const chartData = auditResults ? [
    { name: 'Policies', value: auditResults.policyCount },
    { name: 'Gateway Logs', value: auditResults.totalWatchGuardLogs },
    { name: 'Endpoint Logs', value: auditResults.totalWindowsLogs },
    { name: 'Blind Spots', value: auditResults.blindSpots.length },
    { name: 'Violations', value: auditResults.violations.length },
  ] : [];

  return (
    <div className="min-h-screen bg-slate-900 text-slate-100 font-sans selection:bg-cyan-500 selection:text-white">
      {/* Header */}
      <header className="border-b border-slate-800 bg-slate-950/50 sticky top-0 z-10 backdrop-blur-md">
        <div className="max-w-7xl mx-auto px-6 py-4 flex justify-between items-center">
          <div className="flex items-center gap-3">
            <div className="w-8 h-8 bg-cyan-500 rounded-lg shadow-[0_0_15px_rgba(34,211,238,0.5)] flex items-center justify-center">
              <svg className="w-5 h-5 text-slate-950" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
              </svg>
            </div>
            <h1 className="text-xl font-bold tracking-tight text-white">
              Sentinel <span className="text-cyan-400">Auditor</span>
            </h1>
          </div>
          <nav className="flex gap-4 text-sm font-medium">
            <button 
              onClick={() => setStep(AppStep.UPLOAD)}
              className={`px-3 py-1 rounded transition ${step === AppStep.UPLOAD ? 'text-cyan-400 bg-cyan-950/30' : 'text-slate-400 hover:text-white'}`}
            >
              Data Source
            </button>
            <button 
              onClick={() => canProceed && setStep(AppStep.DASHBOARD)}
              disabled={!canProceed}
              className={`px-3 py-1 rounded transition ${step === AppStep.DASHBOARD ? 'text-cyan-400 bg-cyan-950/30' : 'text-slate-400 hover:text-white disabled:opacity-30'}`}
            >
              Dashboard
            </button>
            <button 
               onClick={() => canProceed && auditResults && handleGenerateReport()}
               disabled={!canProceed}
               className={`px-3 py-1 rounded transition ${step === AppStep.REPORT ? 'text-cyan-400 bg-cyan-950/30' : 'text-slate-400 hover:text-white disabled:opacity-30'}`}
            >
              AI Report
            </button>
          </nav>
        </div>
      </header>

      {/* Main Content */}
      <main className="max-w-7xl mx-auto px-6 py-10">
        
        {/* Step 0: Upload */}
        {step === AppStep.UPLOAD && (
          <div className="space-y-8 animate-fade-in">
            <div className="text-center space-y-2 mb-12">
              <h2 className="text-3xl font-bold text-white">Triangulation Audit Initialization</h2>
              <p className="text-slate-400 max-w-2xl mx-auto">
                Upload your WatchGuard configuration XML and traffic logs to begin the security gap analysis. 
                Data is processed locally in your browser.
              </p>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
              <FileUpload 
                label="WatchGuard Config (XML)" 
                accept=".xml" 
                onFileSelect={handleConfigUpload}
                color={filesLoaded.config ? "green" : "cyan"}
              />
              <FileUpload 
                label="WatchGuard Logs (CSV)" 
                accept=".csv" 
                onFileSelect={handleWgLogUpload}
                color={filesLoaded.wgLogs ? "green" : "cyan"}
              />
              <FileUpload 
                label="Windows Server Logs (CSV)" 
                accept=".csv" 
                onFileSelect={handleWinLogUpload}
                color={filesLoaded.winLogs ? "green" : "cyan"}
              />
            </div>

            {canProceed && (
              <div className="flex justify-center mt-12">
                <button 
                  onClick={() => setStep(AppStep.DASHBOARD)}
                  className="bg-cyan-500 hover:bg-cyan-400 text-slate-950 px-8 py-3 rounded-full font-bold shadow-lg shadow-cyan-500/20 transition-all transform hover:scale-105 flex items-center gap-2"
                >
                  <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M9 5l7 7-7 7" /></svg>
                  Initialize Comparator Engine
                </button>
              </div>
            )}
          </div>
        )}

        {/* Step 1: Dashboard */}
        {step === AppStep.DASHBOARD && auditResults && (
          <div className="space-y-8">
             <div className="flex justify-between items-end border-b border-slate-800 pb-4">
              <div>
                <h2 className="text-2xl font-bold text-white">Audit Dashboard</h2>
                <p className="text-slate-400 text-sm">Real-time analysis of traffic anomalies and blind spots.</p>
              </div>
              <button 
                onClick={handleGenerateReport}
                className="bg-indigo-600 hover:bg-indigo-500 text-white px-4 py-2 rounded text-sm font-medium flex items-center gap-2"
              >
                <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M19.428 15.428a2 2 0 00-1.022-.547l-2.384-.477a6 6 0 00-3.86.517l-.318.158a6 6 0 01-3.86.517L6.05 15.21a2 2 0 00-1.806.547M8 4h8l-1 1v5.172a2 2 0 00.586 1.414l5 5c1.26 1.26.367 3.414-1.415 3.414H4.828c-1.782 0-2.674-2.154-1.414-3.414l5-5A2 2 0 009 10.172V5L8 4z" /></svg>
                Generate AI Report
              </button>
            </div>

            {/* Stats Grid */}
            <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
              <StatCard title="Policies Parsed" value={auditResults.policyCount} />
              <StatCard title="Total Traffic Flows" value={auditResults.totalWatchGuardLogs + auditResults.totalWindowsLogs} />
              <StatCard title="Blind Spots Detected" value={auditResults.blindSpots.length} alert={auditResults.blindSpots.length > 0} subtitle="Traffic on Endpoint not Gateway" />
              <StatCard title="Policy Violations" value={auditResults.violations.length} alert={auditResults.violations.length > 0} subtitle="High risk flows" />
            </div>

            {/* Main Viz Area */}
            <div className="grid grid-cols-1 lg:grid-cols-3 gap-6 h-96">
              {/* Chart */}
              <div className="lg:col-span-2 bg-slate-800 border border-slate-700 rounded-lg p-4 flex flex-col">
                <h3 className="text-slate-400 text-sm font-medium mb-4">Traffic Composition & Anomalies</h3>
                <div className="flex-1 w-full h-full min-h-0">
                  <ResponsiveContainer width="100%" height="100%">
                    <BarChart data={chartData} layout="vertical">
                      <XAxis type="number" hide />
                      <YAxis dataKey="name" type="category" width={100} tick={{fill: '#94a3b8', fontSize: 12}} />
                      <Tooltip 
                        contentStyle={{backgroundColor: '#1e293b', borderColor: '#334155', color: '#f1f5f9'}}
                        itemStyle={{color: '#fff'}}
                        cursor={{fill: 'rgba(255,255,255,0.05)'}}
                      />
                      <Bar dataKey="value" radius={[0, 4, 4, 0]}>
                        {chartData.map((entry, index) => (
                          <Cell key={`cell-${index}`} fill={['#64748b', '#64748b', '#64748b', '#f87171', '#fbbf24'][index]} />
                        ))}
                      </Bar>
                    </BarChart>
                  </ResponsiveContainer>
                </div>
              </div>

              {/* Blind Spot List */}
              <div className="bg-slate-800 border border-slate-700 rounded-lg p-4 overflow-hidden flex flex-col">
                <h3 className="text-red-400 text-sm font-medium mb-4 flex items-center gap-2">
                  <span className="w-2 h-2 rounded-full bg-red-500 animate-pulse"></span>
                  Top Blind Spots
                </h3>
                <div className="overflow-y-auto space-y-3 flex-1 pr-2">
                  {auditResults.blindSpots.length === 0 && <p className="text-slate-500 text-sm italic">No blind spots detected.</p>}
                  {auditResults.blindSpots.map((spot, idx) => (
                    <div key={idx} className="bg-slate-900/50 p-3 rounded border border-slate-700/50 text-xs">
                      <div className="font-mono text-cyan-300 mb-1">{spot.windowsLog.sourceIp} &rarr; {spot.windowsLog.destIp}</div>
                      <div className="text-slate-400">{spot.description}</div>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          </div>
        )}

        {/* Step 2: Report */}
        {step === AppStep.REPORT && (
          <div className="max-w-4xl mx-auto space-y-6">
            <div className="flex justify-between items-center">
              <h2 className="text-2xl font-bold text-white">Executive Audit Report</h2>
              <button onClick={() => setStep(AppStep.DASHBOARD)} className="text-slate-400 hover:text-white text-sm underline">Back to Dashboard</button>
            </div>

            {loading ? (
              <div className="h-64 flex flex-col items-center justify-center space-y-4 bg-slate-800 rounded-lg border border-slate-700">
                <div className="w-12 h-12 border-4 border-cyan-500/30 border-t-cyan-500 rounded-full animate-spin"></div>
                <p className="text-cyan-400 animate-pulse">Consulting Gemini AI Security Engine...</p>
              </div>
            ) : (
              <div className="bg-slate-800 rounded-lg border border-slate-700 p-8 shadow-2xl">
                 <div className="prose prose-invert prose-slate max-w-none">
                    <pre className="whitespace-pre-wrap font-sans text-sm leading-relaxed text-slate-300">
                      {reportText}
                    </pre>
                 </div>
              </div>
            )}
          </div>
        )}

      </main>
    </div>
  );
};

export default App;
