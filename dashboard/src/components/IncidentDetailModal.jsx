import React, { useState, useEffect } from 'react';
import { 
  Shield, X, Check, RefreshCw, Terminal, AlertTriangle, 
  ExternalLink, CheckCircle2, ChevronRight, Eye, Search 
} from 'lucide-react';
import { PieChart, Pie, Cell, ResponsiveContainer } from 'recharts';
import { 
  normalizeStatus, 
  getCloseSlaDetails, 
  renderCloseSlaTooltip,
  getApprovalAuditDetails,
  renderApprovalAuditTooltip
} from './IncidentTriageQueue';

export const factorColors = [
  '#f43f5e', // Detection Severity (Rose / Red)
  '#3b82f6', // Behavioral Anomaly (Blue)
  '#10b981', // Asset Criticality (Emerald)
  '#f59e0b', // Identity Risk (Amber)
  '#8b5cf6', // Correlation Chain (Purple)
  '#06b6d4', // Cyan (Extra)
];

export default function IncidentDetailModal({
  incident,
  onClose,
  theme = 'dark',
  isInbox = false,
  inboxStatus = 'waiting',
  auditInfo = null,
  onOpenFpForm = null,
  onApprove = null,
  onReject = null,
  onConfirmTruePositive = null,
  onOpenFpModal = null
}) {
  const isDark = theme === 'dark' || (typeof document !== 'undefined' && document.documentElement.classList.contains('dark'));

  const [aggregates, setAggregates] = useState([]);
  const [aggregatesLoading, setAggregatesLoading] = useState(false);
  const [selectedAggregateId, setSelectedAggregateId] = useState(null);
  const [aggregateLogs, setAggregateLogs] = useState([]);
  const [logsLoading, setLogsLoading] = useState(false);
  const [selectedLogId, setSelectedLogId] = useState(null);
  const [logSearch, setLogSearch] = useState('');
  const [mlPrediction, setMlPrediction] = useState(null);
  const [mlLoading, setMlLoading] = useState(false);

  const incidentId = incident?.id || incident?.triage_id || incident?.incident_id;

  const fetchMlPrediction = async (triageId) => {
    if (!triageId) return;
    try {
      setMlLoading(true);
      setMlPrediction(null);
      const res = await fetch(`/api/triage/${triageId}/ml-prediction`);
      if (res.ok) {
        const data = await res.json();
        setMlPrediction(data);
      }
    } catch (err) {
      console.warn("Fetch ML prediction error:", err);
    } finally {
      setMlLoading(false);
    }
  };

  const fetchAggregates = async (triageId) => {
    if (!triageId) return;
    try {
      setAggregatesLoading(true);
      setSelectedAggregateId(null);
      setAggregateLogs([]);
      setLogSearch('');
      const res = await fetch(`/api/triage/${triageId}/aggregates`);
      if (res.ok) {
        const data = await res.json();
        const list = data.aggregates || [];
        setAggregates(list);
        if (list.length > 0) {
          fetchAggregateLogs(list[0].aggregation_id);
        }
      }
    } catch (err) {
      console.warn("Fetch aggregates error:", err);
    } finally {
      setAggregatesLoading(false);
    }
  };

  const fetchAggregateLogs = async (aggregationId) => {
    try {
      setSelectedAggregateId(aggregationId);
      setSelectedLogId(null);
      setLogsLoading(true);
      const res = await fetch(`/api/aggregates/${aggregationId}/logs`);
      if (res.ok) {
        const data = await res.json();
        setAggregateLogs(data.logs || []);
      }
    } catch (err) {
      console.warn("Fetch logs error:", err);
    } finally {
      setLogsLoading(false);
    }
  };

  useEffect(() => {
    if (incidentId) {
      fetchAggregates(incidentId);
      fetchMlPrediction(incidentId);
    }
  }, [incidentId]);

  if (!incident) return null;

  const filteredLogs = logSearch.trim() === ''
    ? aggregateLogs
    : aggregateLogs.filter(l => 
        (l.payload && l.payload.toLowerCase().includes(logSearch.toLowerCase())) ||
        (l.source_ip && l.source_ip.toLowerCase().includes(logSearch.toLowerCase())) ||
        (l.agent_name && l.agent_name.toLowerCase().includes(logSearch.toLowerCase()))
      );

  const prioColor = incident.priority === 'P0' ? 'text-rose-500' :
    incident.priority === 'P1' ? 'text-orange-500' :
    incident.priority === 'P2' ? 'text-amber-500' :
    incident.priority === 'P3' ? 'text-emerald-500' :
    'text-sky-500';

  const factorsList = (incident.factors && incident.factors.length > 0) ? incident.factors : [
    { name: "Detection Severity", pts: "+25", desc: `Base correlation target severity ${incident.priority || 'P1'}` },
    { name: "Behavioral Anomaly", pts: "+20", desc: "Multi-stage attack sequence validated with correlated events" },
    { name: "Asset Criticality", pts: "+25", desc: `Target host ${incident.asset || incident.target_host || 'target'} is evaluated` },
    { name: "Identity Risk", pts: "+10", desc: "Compromised account credential weight" },
    { name: "Correlation Chain", pts: "+20", desc: "Confirmed sequential attack stages" }
  ];

  return (
    <div className="fixed inset-0 bg-black/80 backdrop-blur-sm z-50 flex items-center justify-center p-3 md:p-6 animate-in fade-in duration-150">
      <div className={`border rounded-xl max-w-6xl w-full shadow-2xl flex flex-col max-h-[92vh] overflow-hidden ${
        isDark ? 'bg-[#0b0f19] border-slate-700/80' : 'bg-white border-slate-200'
      }`}>
        
        {/* Modal Header matching reference screenshot */}
        <div className={`p-4 border-b flex items-start justify-between shrink-0 ${
          isDark ? 'border-slate-800 bg-[#090d16]' : 'border-slate-200 bg-white'
        }`}>
          <div className="space-y-1">
            <div className="flex items-center gap-2 flex-wrap">
              <span className={`text-xs font-bold font-mono ${prioColor}`}>
                {incident.priority || 'P1'}
              </span>
              <span className="font-mono text-xs text-slate-400 font-semibold">
                {incident.id || incident.triage_id}
              </span>
              <span className="text-xs text-slate-400 font-mono ml-1">
                {(() => {
                  const t = incident.timeAgo || incident.waktuMuncul || 'Recent';
                  return t && t !== 'Recent' && !t.includes('WIB') ? `${t} WIB` : t;
                })()}
              </span>
            </div>
            <h3 className={`text-base font-bold tracking-tight ${isDark ? 'text-white' : 'text-slate-900'}`}>
              {incident.title || incident.judul_insiden || 'Security Incident'}
            </h3>
            <div className={`text-xs font-mono space-y-0.5 pt-0.5 ${isDark ? 'text-slate-400' : 'text-slate-600'}`}>
              <div className="flex items-center">
                <span className="w-16 shrink-0">Asset</span>
                <span className="mr-1.5">:</span>
                <strong className={isDark ? 'text-slate-200' : 'text-slate-800'}>
                  {incident.asset || incident.target_host || '-'}
                </strong>
              </div>
              <div className="flex items-center">
                <span className="w-16 shrink-0">Attacker</span>
                <span className="mr-1.5">:</span>
                <strong className="text-rose-500">
                  {incident.attackerIp || incident.attacker_source_ip || '127.0.0.1'}
                </strong>
              </div>
            </div>
          </div>

          {/* Action buttons & Status Badge in Top-Right */}
          <div className="flex items-center gap-2.5">
            {/* If in Inbox Pengajuan FP: show Eye icon + Status badge (actions handled in FP form) */}
            {isInbox ? (
              <div className="flex items-center gap-2">

                {/* Eye icon button to view False Positive reason & suppression form (borderless & grayish-black) */}
                <button
                  type="button"
                  onClick={() => {
                    if (onOpenFpForm) {
                      const enriched = {
                        ...incident,
                        aggregates,
                        aggregation_id: aggregates[0]?.aggregation_id || incident.aggregation_id,
                        rule_ids: (aggregates && aggregates.length > 0)
                          ? aggregates.map(a => a.rule_id).filter(Boolean)
                          : (incident.rule_ids || [5502, 5501])
                      };
                      onOpenFpForm(enriched);
                    }
                  }}
                  className="p-1 text-slate-500 hover:text-slate-800 dark:text-slate-400 dark:hover:text-slate-200 active:text-blue-500 transition-colors cursor-pointer border-0 bg-transparent hover:bg-transparent active:bg-transparent focus:bg-transparent flex items-center justify-center group focus:outline-none focus:ring-0"
                  title="Lihat Formulir Alasan & Pengajuan Supresi FP"
                >
                  <Eye className="w-5 h-5 transition-transform group-hover:scale-110 group-active:scale-95" />
                </button>

                {/* Status Badge (APPROVE / DEPLOY / EXPIRED / REJECT / WAITING) with hover SLA Audit Tooltip */}
                {(() => {
                  const normalized = String(inboxStatus || incident?.bundleStatus || incident?.policyStatus || incident?.status || '').toLowerCase();
                  if (normalized === 'deploy') {
                    return (
                      <div className="relative inline-block group/status select-none">
                        <span className="status-badge inline-block px-3.5 py-1.5 rounded-md border border-blue-600 bg-blue-600 text-white font-bold text-xs tracking-wider uppercase shadow-xs cursor-help">
                          STATUS: DEPLOY
                        </span>
                        {renderApprovalAuditTooltip(
                          auditInfo || getApprovalAuditDetails(incident),
                          'top-full mt-2.5 right-0'
                        )}
                      </div>
                    );
                  }
                  if (normalized === 'expired') {
                    return (
                      <div className="relative inline-block group/status select-none">
                        <span className="status-badge inline-block px-3.5 py-1.5 rounded-md border border-rose-600 bg-rose-600 text-white font-bold text-xs tracking-wider uppercase shadow-xs cursor-help">
                          STATUS: EXPIRED
                        </span>
                        {renderApprovalAuditTooltip(
                          auditInfo || getApprovalAuditDetails(incident),
                          'top-full mt-2.5 right-0'
                        )}
                      </div>
                    );
                  }
                  if (normalized === 'approve' || normalized === 'approved') {
                    return (
                      <div className="relative inline-block group/status select-none">
                        <span className="status-badge inline-block px-3.5 py-1.5 rounded-md border border-emerald-500 bg-emerald-500 text-white font-bold text-xs tracking-wider uppercase shadow-xs cursor-help">
                          STATUS: APPROVE
                        </span>
                        {renderApprovalAuditTooltip(
                          auditInfo || getApprovalAuditDetails(incident),
                          'top-full mt-2.5 right-0'
                        )}
                      </div>
                    );
                  }
                  if (normalized === 'reject' || normalized === 'rejected') {
                    return (
                      <div className="relative inline-block group/status select-none">
                        <span className="status-badge inline-block px-3.5 py-1.5 rounded-md border border-red-500 bg-red-500 text-white font-bold text-xs tracking-wider uppercase shadow-xs cursor-help">
                          STATUS: REJECT
                        </span>
                        {renderApprovalAuditTooltip(
                          auditInfo || getApprovalAuditDetails(incident),
                          'top-full mt-2.5 right-0'
                        )}
                      </div>
                    );
                  }
                  return (
                    <div className="relative inline-block group/status select-none">
                      <span className="status-badge inline-block px-3.5 py-1.5 rounded-md border border-amber-500 bg-amber-500 text-white font-bold text-xs tracking-wider uppercase shadow-xs cursor-help">
                        STATUS: WAITING
                      </span>
                      {renderApprovalAuditTooltip(
                        auditInfo || getApprovalAuditDetails(incident),
                        'top-full mt-2.5 right-0'
                      )}
                    </div>
                  );
                })()}
              </div>
            ) : (
              /* If in Ticket Queue or Verified TP */
              <>
                {normalizeStatus(incident.status) !== 'CLOSE' && (
                  <>
                    {onConfirmTruePositive && (
                      <button
                        type="button"
                        onClick={() => onConfirmTruePositive(incident.id || incident.triage_id)}
                        className="px-3 py-1.5 rounded-lg text-white font-semibold text-xs flex items-center gap-1.5 shadow-sm transition-all cursor-pointer bg-emerald-600 hover:bg-emerald-500 border-0"
                      >
                        <Check className="w-3.5 h-3.5" />
                        <span>True Positive</span>
                      </button>
                    )}
                    {onOpenFpModal && (
                      <button
                        type="button"
                        onClick={() => onOpenFpModal(incident)}
                        className="px-3 py-1.5 rounded-lg text-white font-semibold text-xs flex items-center gap-1.5 shadow-sm transition-all cursor-pointer bg-red-600 hover:bg-red-500 border-0"
                      >
                        <X className="w-3.5 h-3.5" />
                        <span>False Positive</span>
                      </button>
                    )}
                  </>
                )}

                {/* Standard Status Badge */}
                {(() => {
                  const normalized = String(incident?.bundleStatus || incident?.policyStatus || incident?.status || '').toLowerCase();
                  if (normalized === 'deploy') {
                    return (
                      <div className="relative inline-block group/status">
                        <span 
                          style={{ color: '#FFFFFF' }}
                          className="status-badge px-3 py-1 rounded-md text-xs font-bold font-mono text-white !text-white uppercase tracking-wider shadow-xs select-none inline-block bg-blue-600 border border-blue-600"
                        >
                          STATUS: DEPLOY
                        </span>
                      </div>
                    );
                  }
                  if (normalized === 'expired') {
                    return (
                      <div className="relative inline-block group/status">
                        <span 
                          style={{ color: '#FFFFFF' }}
                          className="status-badge px-3 py-1 rounded-md text-xs font-bold font-mono text-white !text-white uppercase tracking-wider shadow-xs select-none inline-block bg-rose-600 border border-rose-600"
                        >
                          STATUS: EXPIRED
                        </span>
                      </div>
                    );
                  }
                  if (normalized === 'approve' || normalized === 'approved') {
                    return (
                      <div className="relative inline-block group/status">
                        <span 
                          style={{ color: '#FFFFFF' }}
                          className="status-badge px-3 py-1 rounded-md text-xs font-bold font-mono text-white !text-white uppercase tracking-wider shadow-xs select-none inline-block bg-emerald-500 border border-emerald-500"
                        >
                          STATUS: APPROVE
                        </span>
                      </div>
                    );
                  }
                  const effectiveModalStatus = normalizeStatus(mlPrediction?.triage_status || incident?.status);
                  return (
                    <div className="relative inline-block group/status">
                      <span 
                        style={{ color: '#FFFFFF' }}
                        className={`status-badge px-3 py-1 rounded-md text-xs font-bold font-mono text-white !text-white uppercase tracking-wider shadow-xs select-none inline-block ${
                          effectiveModalStatus === 'CLOSE' ? 'bg-emerald-500 border border-emerald-500 cursor-help' :
                          effectiveModalStatus === 'INVESTIGATE' ? 'bg-orange-500 border border-orange-500' :
                          effectiveModalStatus === 'GROUNDTRUTH' ? 'bg-amber-600 border border-amber-600' :
                          'bg-red-500 border border-red-500'
                        }`}
                      >
                        STATUS: {effectiveModalStatus}
                      </span>
                      {effectiveModalStatus === 'CLOSE' && (
                        renderCloseSlaTooltip(getCloseSlaDetails(incident), incident.priority, 'top-full mt-2.5 right-0')
                      )}
                    </div>
                  );
                })()}
              </>
            )}

            {/* Close Modal X Button */}
            <button
              type="button"
              onClick={onClose}
              className="p-1.5 rounded-lg text-slate-400 hover:text-slate-600 dark:hover:text-white transition-colors cursor-pointer border-0 bg-transparent active:bg-transparent focus:outline-none focus:ring-0 ml-1"
              title="Tutup Modal"
            >
              <X className="w-5 h-5" />
            </button>
          </div>
        </div>

        {/* Scrollable Content Body */}
        <div className="flex-1 overflow-y-auto p-4 space-y-4">
          
          {/* Dynamic Risk Score Assessment - Gauge & 3-Column Table */}
          <div className={`p-4 border rounded-xl ${
            isDark ? 'bg-[#070b14] border-slate-800/80' : 'bg-white border-slate-200 shadow-2xs'
          }`}>
            <div className="flex items-center justify-between text-xs font-semibold mb-3 border-b border-slate-200 dark:border-slate-800/60 pb-2.5">
              <span className={`text-sm font-bold tracking-tight ${isDark ? 'text-slate-100' : 'text-slate-900'}`}>
                Dynamic Risk Score Assessment
              </span>
              <div className="flex items-center gap-1.5 font-mono text-xs">
                <span className={isDark ? 'text-slate-400' : 'text-slate-500'}>TOTAL SCORE:</span>
                <span 
                  className={`font-mono font-extrabold text-sm ${isDark ? 'text-white' : 'text-slate-900'}`}
                  style={{ color: isDark ? '#FFFFFF' : '#000000' }}
                >
                  {incident.score || incident.skor_risiko || 45} / 100 PTS
                </span>
              </div>
            </div>

            <div className="flex flex-row items-center gap-6 pt-1 w-full overflow-x-auto">
              {/* Left: Circular Donut Gauge */}
              <div className="w-52 shrink-0 flex flex-col items-center justify-center">
                <div className="w-48 h-48 relative">
                  {(() => {
                    const activeFactors = factorsList
                      .map((f, idx) => {
                        const num = Math.max(0, parseInt(String(f.pts || '0').replace(/[^0-9]/g, '')) || 0);
                        return {
                          name: f.name,
                          value: num,
                          rawPts: f.pts,
                          desc: f.desc,
                          color: factorColors[idx % factorColors.length]
                        };
                      })
                      .filter(item => item.value > 0);

                    const totalScore = Number(incident.score || incident.skor_risiko || 0);
                    const factorSum = activeFactors.reduce((acc, curr) => acc + curr.value, 0);
                    const effectiveScore = totalScore > 0 ? totalScore : factorSum;
                    const scoreRatio = Math.min(1, Math.max(0, effectiveScore / 100));
                    const startAngle = 90;
                    const endAngle = 90 - (scoreRatio * 360);

                    return (
                      <ResponsiveContainer width="100%" height="100%">
                        <PieChart>
                          <Pie
                            data={[{ value: 100 }]}
                            cx="50%"
                            cy="50%"
                            innerRadius={46}
                            outerRadius={68}
                            startAngle={90}
                            endAngle={-270}
                            fill={isDark ? '#1a2336' : '#e2e8f0'}
                            stroke="none"
                            dataKey="value"
                            isAnimationActive={false}
                          />
                          {activeFactors.length > 0 && scoreRatio > 0 && (
                            <Pie
                              data={activeFactors}
                              cx="50%"
                              cy="50%"
                              innerRadius={46}
                              outerRadius={68}
                              startAngle={startAngle}
                              endAngle={endAngle}
                              paddingAngle={scoreRatio < 1 ? 2.5 : 3}
                              dataKey="value"
                              stroke="none"
                            >
                              {activeFactors.map((entry, index) => (
                                <Cell key={`cell-${index}`} fill={entry.color} stroke="none" />
                              ))}
                            </Pie>
                          )}
                        </PieChart>
                      </ResponsiveContainer>
                    );
                  })()}
                  <div className="absolute inset-0 flex flex-col items-center justify-center pointer-events-none">
                    <span className={`text-2xl font-extrabold font-mono tracking-tight ${isDark ? 'text-white' : 'text-slate-900'}`}>
                      {incident.score || incident.skor_risiko || 45}
                    </span>
                    <span className="text-[10px] font-mono uppercase tracking-wider text-slate-400 font-bold">
                      RISK
                    </span>
                  </div>
                </div>
              </div>

              {/* Right: 3-Column Factors Table matching image */}
              <div className="flex-1 w-full overflow-x-auto">
                <table className="w-full text-left text-xs border-collapse">
                  <thead>
                    <tr className={`border-b text-[11px] font-semibold uppercase tracking-wider ${
                      isDark ? 'border-slate-800 text-slate-400 bg-slate-900/40' : 'border-slate-200 text-slate-500 bg-slate-50/80'
                    }`}>
                      <th className="py-2 px-3">Faktor Risiko</th>
                      <th className="py-2 px-3 text-center">Skor</th>
                      <th className="py-2 px-3">Keterangan</th>
                    </tr>
                  </thead>
                  <tbody className={`divide-y text-xs ${
                    isDark ? 'divide-slate-800/60' : 'divide-slate-100'
                  }`}>
                    {factorsList.map((f, i) => {
                      const color = factorColors[i % factorColors.length];
                      return (
                        <tr key={i} className={`transition-colors ${
                          isDark ? 'hover:bg-slate-800/30' : 'hover:bg-slate-50/70'
                        }`}>
                          <td className="py-2.5 px-3 font-medium whitespace-nowrap">
                            <div className="flex items-center gap-2">
                              <span className="w-2.5 h-2.5 rounded-full shrink-0" style={{ backgroundColor: color }} />
                              <span className={isDark ? 'text-slate-200' : 'text-slate-800 font-semibold'}>
                                {f.name}
                              </span>
                            </div>
                          </td>
                          <td className="py-2.5 px-3 text-center font-mono font-bold text-emerald-500 whitespace-nowrap">
                            {f.pts}
                          </td>
                          <td className={`py-2.5 px-3 text-[11px] leading-relaxed ${
                            isDark ? 'text-slate-400' : 'text-slate-600'
                          }`}>
                            {f.desc}
                          </td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              </div>
            </div>
          </div>

          {/* Machine Learning Assessment Card */}
          <div className={`p-4 border rounded-xl transition-all ${
            isDark ? 'bg-[#070b14] border-slate-800/80' : 'bg-white border-slate-200 shadow-2xs'
          }`}>
            {/* Header */}
            <div className="flex items-center justify-between text-xs font-semibold mb-3 border-b border-slate-200 dark:border-slate-800/60 pb-2.5">
              <div className="flex items-center gap-2">
                <span className={`text-sm font-bold tracking-tight block ${isDark ? 'text-slate-100' : 'text-slate-900'}`}>
                  Machine Learning Assessment
                </span>
              </div>

              {mlLoading && (
                <div className="flex items-center gap-1.5 text-xs text-slate-400 font-mono">
                  <RefreshCw className="w-3.5 h-3.5 animate-spin text-indigo-400" />
                  <span>Menganalisis Telemetri ML...</span>
                </div>
              )}
            </div>

            {/* Content Body */}
            {mlLoading ? (
              <div className={`p-6 border rounded-lg text-xs flex items-center justify-center gap-2 font-mono ${
                isDark ? 'bg-slate-900/30 border-slate-800 text-slate-400' : 'bg-slate-50 border-slate-200 text-slate-500'
              }`}>
                <RefreshCw className="w-4 h-4 animate-spin text-indigo-400" /> Mengevaluasi Model Machine Learning...
              </div>
            ) : mlPrediction ? (
              <div className="space-y-3">
                {/* Probability Distribution Bar */}
                <div className={`p-3.5 rounded-lg border ${
                  isDark ? 'bg-slate-900/40 border-slate-800/80' : 'bg-slate-50/80 border-slate-200'
                }`}>
                  <div className="flex items-center justify-between text-xs mb-1.5">
                    <span className={`font-semibold text-[11px] ${isDark ? 'text-slate-300' : 'text-slate-700'}`}>
                      Distribusi Probabilitas Terkalibrasi (Isotonic Regression)
                    </span>
                    <span className="text-[10px] font-mono text-slate-400">
                      Ambang Batas Auto-Close: 85.0%
                    </span>
                  </div>

                  {/* Dual Progress Bar */}
                  <div className="space-y-1.5">
                    <div className="h-3 w-full bg-slate-800 rounded-full overflow-hidden flex relative">
                      <div 
                        className="bg-emerald-500 h-full transition-all duration-500" 
                        style={{ width: `${mlPrediction.benign_probability}%` }}
                        title={`P(Benign): ${mlPrediction.benign_probability}%`}
                      />
                      <div 
                        className="bg-rose-500 h-full transition-all duration-500" 
                        style={{ width: `${mlPrediction.threat_probability}%` }}
                        title={`P(Threat): ${mlPrediction.threat_probability}%`}
                      />
                    </div>
                    
                    <div className="flex justify-between items-center text-[10px] font-mono">
                      <span className="text-emerald-500 font-bold flex items-center gap-1">
                        <span className="w-1.5 h-1.5 rounded-full bg-emerald-500 inline-block" />
                        P(Benign): {mlPrediction.benign_probability}%
                      </span>
                      <span className="text-rose-500 font-bold flex items-center gap-1">
                        P(Threat): {mlPrediction.threat_probability}%
                        <span className="w-1.5 h-1.5 rounded-full bg-rose-500 inline-block" />
                      </span>
                    </div>
                  </div>
                </div>
              </div>
            ) : (
              <div className="p-4 text-xs text-slate-400 text-center font-mono">
                Data Machine Learning tidak tersedia untuk tiket ini.
              </div>
            )}
          </div>

          {/* Related Aggregated Alert Flows */}
          <div>
            <div className={`flex items-center justify-between text-xs font-semibold mb-2 ${
              isDark ? 'text-slate-200' : 'text-slate-800'
            }`}>
              <span className="flex items-center gap-1.5">
                <span>Aggregated Alert Flows ({aggregates.length})</span>
              </span>
              <span className="text-[11px] text-slate-400 font-normal">
                Pilih agregat untuk melihat log mentah forensik
              </span>
            </div>

            {aggregatesLoading ? (
              <div className={`p-4 border rounded-lg text-xs flex items-center justify-center gap-2 font-mono ${
                isDark ? 'bg-[#070b14] border-slate-800 text-slate-400' : 'bg-slate-50 border-slate-200 text-slate-500'
              }`}>
                <RefreshCw className="w-4 h-4 animate-spin text-blue-500" /> Memuat data agregat...
              </div>
            ) : aggregates.length === 0 ? (
              <div className={`p-4 border rounded-lg text-xs text-center font-mono ${
                isDark ? 'bg-[#070b14] border-slate-800 text-slate-500' : 'bg-slate-50 border-slate-200 text-slate-400'
              }`}>
                Tidak ada data agregat tersambung untuk insiden ini.
              </div>
            ) : (
              <div className="grid grid-cols-1 md:grid-cols-2 gap-2">
                {aggregates.map((agg) => {
                  const isSelected = agg.aggregation_id === selectedAggregateId;
                  return (
                    <div
                      key={agg.aggregation_id}
                      onClick={() => fetchAggregateLogs(agg.aggregation_id)}
                      className={`p-3 rounded-lg border text-xs transition-all cursor-pointer ${
                        isSelected
                          ? (isDark ? 'bg-slate-800/90 border-slate-600 text-white shadow-sm' : 'bg-slate-100 border-slate-300 text-slate-900 shadow-xs')
                          : (isDark ? 'bg-[#070b14] border-slate-800/80 hover:border-slate-700 text-slate-300' : 'bg-white border-slate-200 hover:border-slate-300 shadow-2xs')
                      }`}
                    >
                      <div className="flex items-center justify-between mb-1">
                        <div className="flex items-center gap-1.5 flex-wrap">
                          <span 
                            className={`font-mono font-bold text-[11px] ${
                              isDark ? 'text-white' : 'text-slate-900'
                            }`}
                          >
                            Rule {agg.rule_id}
                          </span>
                          {agg.mitre_technique_id && (
                            <span className="px-1.5 py-0.2 rounded text-[9px] font-mono bg-purple-500/20 text-purple-400 border border-purple-500/30">
                              {agg.mitre_technique_id}
                            </span>
                          )}

                        </div>
                        <span className={`font-mono text-[11px] font-medium ${
                          isDark ? 'text-slate-400' : 'text-slate-500'
                        }`}>
                          {agg.event_count} Events
                        </span>
                      </div>
                      <div className={`font-medium truncate ${
                        isDark ? 'text-slate-200' : 'text-slate-800'
                      }`}>
                        {agg.rule_description}
                      </div>
                      {agg.normalized_activity && (
                        <div className="mt-1.5 flex items-center">
                          <span className={`px-2 py-0.5 rounded text-[10px] font-mono font-bold tracking-tight border shadow-2xs ${
                            agg.normalized_activity.includes('[200') || agg.normalized_activity.includes('[SUCCESS')
                              ? (isDark ? 'bg-emerald-950/70 text-emerald-400 border-emerald-800/70' : 'bg-emerald-50 text-emerald-700 border-emerald-300')
                              : agg.normalized_activity.includes('[40') || agg.normalized_activity.includes('[50') || agg.normalized_activity.includes('[FAILED') || agg.normalized_activity.includes('[FAILURE')
                              ? (isDark ? 'bg-amber-950/70 text-amber-400 border-amber-800/70' : 'bg-amber-50 text-amber-700 border-amber-300')
                              : (isDark ? 'bg-blue-950/70 text-blue-400 border-blue-800/70' : 'bg-blue-50 text-blue-700 border-blue-300')
                          }`}>
                            {agg.normalized_activity}
                          </span>
                        </div>
                      )}
                      <div className={`flex items-center justify-between text-[10px] mt-1.5 font-mono ${
                        isDark ? 'text-slate-400' : 'text-slate-500'
                      }`}>
                        <span className="truncate max-w-[180px]" title={agg.log_source}>
                          Log: <strong className={isDark ? 'text-slate-300' : 'text-slate-700'}>{agg.log_source || 'system'}</strong>
                        </span>
                        <span className="truncate max-w-[140px] text-right">
                          {agg.target}
                        </span>
                      </div>
                    </div>
                  );
                })}
              </div>
            )}
          </div>



          {/* Full Raw Log Evidence Inspector */}
          <div className={`border rounded-lg overflow-hidden ${
            isDark ? 'bg-[#070b14] border-slate-800/90' : 'bg-white border-slate-200 shadow-2xs'
          }`}>
            <div className={`p-3 border-b flex items-center justify-between flex-wrap gap-2 ${
              isDark ? 'border-slate-800 bg-[#090d16]' : 'border-slate-200 bg-slate-50/70'
            }`}>
              <div className="flex items-center gap-2">
                <Terminal className={`w-3.5 h-3.5 ${isDark ? 'text-slate-400' : 'text-slate-500'}`} />
                <span className={`text-xs font-semibold ${isDark ? 'text-slate-200' : 'text-slate-800'}`}>
                  Forensic Evidence Logs ({filteredLogs.length} Events)
                </span>
              </div>
              <div className="w-64 relative flex items-center bg-white dark:bg-[#090d16] border-2 border-[#3B5BFF] rounded-full h-[34px] pl-3 pr-1 shadow-2xs group focus-within:ring-2 focus-within:ring-[#3B5BFF]/30 transition-all">
                <Search className="w-3.5 h-3.5 text-slate-400 shrink-0 mr-2 stroke-[2]" />
                <input
                  type="text"
                  value={logSearch}
                  onChange={(e) => setLogSearch(e.target.value)}
                  placeholder="Search payload, IP, agent..."
                  className="w-full bg-transparent text-slate-800 dark:text-slate-200 placeholder:text-slate-400 text-xs font-normal focus:outline-none"
                />
                {logSearch && (
                  <button
                    type="button"
                    onClick={() => setLogSearch('')}
                    className="text-slate-400 hover:text-slate-600 dark:hover:text-slate-200 cursor-pointer p-0.5 mr-1"
                    title="Hapus pencarian"
                  >
                    <X className="w-3 h-3" />
                  </button>
                )}
                <div className="w-6 h-6 rounded-full bg-[#3B5BFF] flex items-center justify-center shrink-0 shadow-xs">
                  <Search className="w-3 h-3 text-white" strokeWidth={2.5} />
                </div>
              </div>
            </div>

            <div className={`max-h-[460px] overflow-y-auto font-mono text-[11px] divide-y ${
              isDark ? 'divide-slate-800/40' : 'divide-slate-100'
            }`}>
              {logsLoading ? (
                <div className="p-4 text-center text-slate-400 flex items-center justify-center gap-2">
                  <RefreshCw className="w-3.5 h-3.5 animate-spin text-blue-500" /> Loading raw telemetry payload...
                </div>
              ) : filteredLogs.length === 0 ? (
                <div className="p-4 text-center text-slate-400">
                  {aggregates.length === 0 ? 'Pilih agregat untuk melihat log mentah forensik.' : 'No raw logs found matching search criteria.'}
                </div>
              ) : (
                filteredLogs.map((log) => {
                  const isSelected = selectedLogId === log.event_id;
                  return (
                    <div 
                      key={log.event_id} 
                      onClick={() => setSelectedLogId(isSelected ? null : log.event_id)}
                      className={`p-2.5 flex items-start gap-3 transition-colors cursor-pointer ${
                        isSelected
                          ? (isDark ? 'bg-slate-800/70' : 'bg-slate-100')
                          : (isDark ? 'hover:bg-slate-900/40' : 'hover:bg-slate-50/80')
                      }`}
                    >
                      <span className={`shrink-0 w-6 font-semibold ${
                        isDark ? 'text-slate-500' : 'text-slate-400'
                      }`}>
                        #{log.seq}
                      </span>
                      <span className={`shrink-0 ${
                        isDark ? 'text-slate-400' : 'text-slate-600'
                      }`}>
                        {log.timestamp ? (log.timestamp.includes('WIB') ? log.timestamp : `${log.timestamp} WIB`) : '-'}
                      </span>
                      {(log.source_ip && log.source_ip !== '-') || (log.destination_ip && log.destination_ip !== '-') ? (
                        <>
                          <span className={`shrink-0 ${isDark ? 'text-sky-400' : 'text-sky-600 font-medium'}`}>
                            {log.source_ip}
                          </span>
                          <span className={isDark ? 'text-slate-500' : 'text-slate-400'}>
                            →
                          </span>
                          <span className={`shrink-0 ${isDark ? 'text-slate-300' : 'text-slate-600'}`}>
                            {log.destination_ip}
                          </span>
                        </>
                      ) : (
                        <span className={`shrink-0 px-2 py-0.5 rounded text-[10px] font-sans ${
                          isDark ? 'bg-slate-800 text-slate-300 border border-slate-700/60' : 'bg-slate-100 text-slate-700 border border-slate-200'
                        }`}>
                          Host: {log.agent_name || incident?.asset || 'Local Agent'}
                        </span>
                      )}
                      <div 
                        className={`flex-1 break-all whitespace-pre-wrap leading-relaxed font-mono ${
                          isDark ? 'text-slate-200' : 'text-slate-900'
                        }`}
                      >
                        {log.payload}
                      </div>
                    </div>
                  );
                })
              )}
            </div>
          </div>

        </div>
      </div>
    </div>
  );
}
