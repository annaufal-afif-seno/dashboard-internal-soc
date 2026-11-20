import { mapTo6CategoryTaxonomy } from '../utils/categoryConstants';
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




const formatDateTimeWib = (dateInput) => {
  if (!dateInput) return '';
  if (typeof dateInput === 'string' && dateInput.includes('WIB')) {
    return dateInput;
  }
  try {
    let d;
    if (typeof dateInput === 'number' || (!isNaN(dateInput) && !isNaN(parseFloat(dateInput)))) {
      const num = parseFloat(dateInput);
      d = new Date(num > 1e11 ? num : num * 1000);
    } else {
      d = new Date(dateInput);
    }
    if (isNaN(d.getTime())) return String(dateInput);
    return new Intl.DateTimeFormat('id-ID', {
      day: '2-digit',
      month: 'short',
      year: 'numeric',
      hour: '2-digit',
      minute: '2-digit',
      second: '2-digit',
      timeZone: 'Asia/Jakarta',
      hour12: false
    }).format(d).replace(/\./g, ':') + ' WIB';
  } catch (e) {
    return String(dateInput);
  }
};

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
  const [expandedClusterIds, setExpandedClusterIds] = useState({});
  const [clusterAlertsMap, setClusterAlertsMap] = useState({});
  const [clusterAlertsLoading, setClusterAlertsLoading] = useState({});

  const toggleExpandCluster = async (clusterId) => {
    setExpandedClusterIds(prev => {
      const isExpanded = !!prev[clusterId];
      return { ...prev, [clusterId]: !isExpanded };
    });

    if (!clusterAlertsMap[clusterId] || clusterAlertsMap[clusterId].length === 0) {
      setClusterAlertsLoading(prev => ({ ...prev, [clusterId]: true }));
      try {
        const res = await fetch(`/api/aggregates/${encodeURIComponent(clusterId)}/logs`);
        if (res.ok) {
          const data = await res.json();
          const logs = data.logs || [];
          setClusterAlertsMap(prev => ({ ...prev, [clusterId]: logs }));
        }
      } catch (err) {
        console.warn("Fetch cluster logs error:", err);
      } finally {
        setClusterAlertsLoading(prev => ({ ...prev, [clusterId]: false }));
      }
    }
  };


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

                          DEPLOY

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

                          EXPIRED

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

                          APPROVE

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

                          REJECT

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

                        WAITING

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

                          DEPLOY

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

                          EXPIRED

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

                          APPROVE

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

                        {effectiveModalStatus}

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



                    {/* Nested Forensic Table: List Cluster -> List Alerts (Policy Bundle Style) */}
          <div className="space-y-2 mt-4 font-trebuchet">
            <div className="flex items-center justify-between pb-1 border-b border-slate-200 dark:border-slate-800">
              <div className="flex items-center gap-2">
                <span className="text-sm font-bold tracking-tight text-slate-900 dark:text-white">
                  Detail
                </span>
              </div>
            </div>

            {aggregatesLoading ? (
              <div className="flex items-center justify-center py-8 text-xs text-slate-400 gap-2 font-mono">
                <RefreshCw className="w-4 h-4 animate-spin text-indigo-500" />
                <span>Memuat daftar kluster forensik...</span>
              </div>
            ) : aggregates.length === 0 ? (
              <div className="text-center py-8 text-xs text-slate-400 italic border rounded-xl border-dashed border-slate-300 dark:border-slate-800">
                Tidak ada kluster terikat pada tiket ini.
              </div>
            ) : (
              <div className="border rounded-xl overflow-hidden border-slate-200 dark:border-slate-800 shadow-2xs">
                <div className="overflow-x-auto">
                  <table className="w-full text-left text-xs border-collapse">
                    <thead>
                      <tr className={isDark ? 'bg-slate-800/80 text-slate-200 border-b border-slate-700' : 'bg-slate-100 text-slate-900 border-b border-slate-300'}>
                        <th className="px-3 py-2.5 font-bold uppercase tracking-wider text-[10.5px] whitespace-nowrap text-slate-900 dark:text-white min-w-[190px]">CLUSTER ID</th>
                        <th className="px-3 py-2.5 font-bold uppercase tracking-wider text-[10.5px] whitespace-nowrap text-slate-900 dark:text-white">KATEGORI</th>
                        <th className="px-3 py-2.5 font-bold uppercase tracking-wider text-[10.5px] whitespace-nowrap text-slate-900 dark:text-white">SUB KATEGORY</th>
                        <th className="px-3 py-2.5 font-bold uppercase tracking-wider text-[10.5px] whitespace-nowrap text-slate-900 dark:text-white">AGENT</th>
                        <th className="px-3 py-2.5 font-bold uppercase tracking-wider text-[10.5px] whitespace-nowrap text-slate-900 dark:text-white">ACTOR</th>
                        <th className="px-3 py-2.5 font-bold uppercase tracking-wider text-[10.5px] whitespace-nowrap text-slate-900 dark:text-white">ACTIVITY</th>
                      </tr>
                    </thead>
                    <tbody className={`divide-y ${
                      isDark ? 'divide-slate-800/60 bg-[#060a14]' : 'divide-slate-200 bg-white'
                    }`}>
                      {aggregates.map((cluster, cIdx) => {
                        const clusterId = cluster.aggregation_id || `cluster-${cIdx}`;
                        const isClusterExpanded = !!expandedClusterIds[clusterId];
                        const alerts = clusterAlertsMap[clusterId] || (selectedAggregateId === clusterId ? aggregateLogs : []);
                        const isAlertsLoading = !!clusterAlertsLoading[clusterId] || (selectedAggregateId === clusterId && logsLoading);

                        return (
                          <React.Fragment key={`${clusterId}-${cIdx}`}>
                            <tr
                              onClick={() => toggleExpandCluster(clusterId)}
                              className={`transition-colors cursor-pointer select-none ${
                                isClusterExpanded
                                  ? (isDark ? 'bg-slate-800/70 border-b border-indigo-500/30' : 'bg-slate-100/90 border-b border-slate-300')
                                  : (isDark ? 'hover:bg-slate-800/40' : 'hover:bg-slate-50')
                              }`}
                              title="Klik baris untuk melihat rincian alert"
                            >
                              {/* 1. CLUSTER ID */}
                              <td className="px-3 py-2.5 whitespace-nowrap text-xs font-bold text-slate-900 dark:text-white">
                                <div className="flex items-center gap-1.5">
                                  {isClusterExpanded ? (
                                    <ChevronDown className="w-3.5 h-3.5 text-slate-600 dark:text-slate-300 shrink-0 stroke-[2.5]" />
                                  ) : (
                                    <ChevronRight className="w-3.5 h-3.5 text-slate-400 shrink-0 stroke-[2.5]" />
                                  )}
                                  <div>
                                    <span className="text-slate-900 dark:text-white font-mono font-bold select-all">
                                      {cluster.aggregation_id}
                                    </span>
                                    {(cluster.window_start || cluster.created_at || cluster.timestamp) && (
                                      <div className="text-[10px] text-slate-500 dark:text-slate-400 font-normal mt-0.5 font-sans">
                                        {formatDateTimeWib(cluster.window_start || cluster.created_at || cluster.timestamp)}
                                      </div>
                                    )}
                                  </div>
                                </div>
                              </td>

                              {/* 2. KATEGORI */}
                              <td className="px-3 py-2.5 whitespace-nowrap text-xs font-semibold text-slate-900 dark:text-white">
                                {mapTo6CategoryTaxonomy(cluster.category || cluster.normalized_category, cluster.subcategory || cluster.sub_category).category}
                              </td>

                              {/* 3. SUB KATEGORY */}
                              <td className="px-3 py-2.5 whitespace-nowrap text-xs font-normal text-slate-900 dark:text-white">
                                {mapTo6CategoryTaxonomy(cluster.category || cluster.normalized_category, cluster.subcategory || cluster.sub_category).subcategory}
                              </td>

                              {/* 4. AGENT */}
                              <td className="px-3 py-2.5 whitespace-nowrap text-xs font-normal text-slate-900 dark:text-white" title={cluster.target || cluster.agent_name}>
                                {cluster.target || cluster.agent_name || cluster.agent || cluster.source_ip || '-'}
                              </td>

                              {/* 5. ACTOR */}
                              <td className="px-3 py-2.5 whitespace-nowrap text-xs font-normal text-slate-900 dark:text-white">
                                {cluster.actor || cluster.source_ip || cluster.username || 'Internal / N/A'}
                              </td>

                              {/* 6. ACTIVITY */}
                              <td className="px-3 py-2.5 whitespace-nowrap text-xs font-normal text-slate-900 dark:text-white">
                                {cluster.normalized_activity || cluster.activity || cluster.rule_description || '-'}
                              </td>
                            </tr>

                            {/* Sub-tabel Detail Alert per Cluster */}
                            {isClusterExpanded && (
                              <tr className={isDark ? 'bg-slate-900/60' : 'bg-slate-50/70'}>
                                <td colSpan={6} className="px-4 py-3 border-t border-b border-slate-200 dark:border-slate-800">
                                  <div className="flex items-center justify-between pb-2 mb-2 border-b border-slate-200 dark:border-slate-800">
                                    <div className="flex items-center gap-2">
                                      <span className="text-xs font-bold tracking-wider text-slate-900 dark:text-white">
                                        Detail
                                      </span>
                                    </div>
                                    {isAlertsLoading && (
                                      <div className="flex items-center gap-1.5 text-xs text-indigo-500">
                                        <RefreshCw className="w-3.5 h-3.5 animate-spin" />
                                        <span>Memuat alert...</span>
                                      </div>
                                    )}
                                  </div>

                                  {isAlertsLoading && alerts.length === 0 ? (
                                    <div className="flex items-center justify-center py-5 text-xs text-slate-400 gap-2 font-mono">
                                      <RefreshCw className="w-4 h-4 animate-spin text-indigo-400" />
                                      <span>Memuat rincian raw alert...</span>
                                    </div>
                                  ) : alerts.length === 0 ? (
                                    <div className="text-center py-5 text-xs text-slate-400 italic">
                                      Tidak ada raw alert evidence ditemukan untuk kluster ini.
                                    </div>
                                  ) : (
                                    <div className="overflow-x-auto">
                                      <table className="w-full text-left text-xs border-collapse">
                                        <thead>
                                          <tr className={isDark ? 'bg-slate-800/80 text-slate-200 border-b border-slate-700' : 'bg-slate-100 text-slate-900 border-b border-slate-300'}>
                                            <th className="px-3 py-2 font-bold uppercase tracking-wider text-[10.5px] whitespace-nowrap text-slate-900 dark:text-white min-w-[150px]">ALERT ID</th>
                                            <th className="px-3 py-2 font-bold uppercase tracking-wider text-[10.5px] whitespace-nowrap text-slate-900 dark:text-white">AGENT</th>
                                            <th className="px-3 py-2 font-bold uppercase tracking-wider text-[10.5px] whitespace-nowrap text-slate-900 dark:text-white">ACTOR</th>
                                            <th className="px-3 py-2 font-bold uppercase tracking-wider text-[10.5px] whitespace-nowrap text-slate-900 dark:text-white">RULE ID</th>
                                            <th className="px-3 py-2 font-bold uppercase tracking-wider text-[10.5px] whitespace-nowrap text-slate-900 dark:text-white">FULL LOG</th>
                                          </tr>
                                        </thead>
                                        <tbody className="divide-y divide-slate-200 dark:divide-slate-800">
                                          {alerts.map((al, aIdx) => (
                                            <tr key={`${al.alert_id || al.event_id || aIdx}-${aIdx}`} className={isDark ? 'hover:bg-slate-800/30' : 'hover:bg-slate-50'}>
                                              {/* 1. ALERT ID */}
                                              <td className="px-3 py-2 text-xs font-bold whitespace-nowrap text-slate-900 dark:text-white select-all">
                                                <div className="font-mono">{al.alert_id || al.event_id || `ALERT-${aIdx}`}</div>
                                                {(al.timestamp || al.event_timestamp || al.created_at) && (
                                                      <div className="text-[10px] text-slate-500 dark:text-slate-400 font-normal mt-0.5 font-sans">
                                                    {formatDateTimeWib(al.timestamp || al.event_timestamp || al.created_at)}
                                                  </div>
                                                )}
                                              </td>

                                              {/* 2. AGENT */}
                                              <td className="px-3 py-2 text-xs whitespace-nowrap text-slate-900 dark:text-white">
                                                {al.agent_name || al.agent || cluster.target || '-'}
                                              </td>

                                              {/* 3. ACTOR */}
                                              <td className="px-3 py-2 text-xs whitespace-nowrap text-slate-900 dark:text-white">
                                                {al.actor || al.username || al.source_ip || cluster.actor || '-'}
                                              </td>

                                              {/* 4. RULE ID */}
                                              <td className="px-3 py-2 text-xs font-bold whitespace-nowrap text-slate-900 dark:text-white font-mono">
                                                {al.rule_id || cluster.rule_id || '-'}
                                              </td>

                                              {/* 5. FULL LOG */}
                                              <td className="px-3 py-2 text-xs font-mono text-slate-900 dark:text-white select-all break-all min-w-[320px]">
                                                {al.full_log || al.raw_payload || al.payload || al.rule_description || '-'}
                                              </td>
                                            </tr>
                                          ))}
                                        </tbody>
                                      </table>
                                    </div>
                                  )}
                                </td>
                              </tr>
                            )}
                          </React.Fragment>
                        );
                      })}
                    </tbody>
                  </table>
                </div>
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}
