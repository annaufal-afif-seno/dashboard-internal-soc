import React, { useState, useEffect, useRef, useMemo, useDeferredValue } from 'react';

import { 

  Shield, X, AlertTriangle, CheckCircle2, User, Server, Network, 

  Layers, Terminal, RefreshCw, Check, Copy, Globe, FileText, 

  Activity, Lock, Database, Clock, ExternalLink, SlidersHorizontal,

  ChevronRight, ArrowRight, ChevronsUpDown, ChevronUp, ChevronDown,

  Pencil, Search, Brain, Sparkles, Cpu, ShieldAlert, ShieldCheck,

  Info, AlertCircle

} from 'lucide-react';

import { PieChart, Pie, Cell, Tooltip, ResponsiveContainer } from 'recharts';



const factorColors = [

  '#f43f5e', // Detection Severity (Rose / Red)

  '#3b82f6', // Behavioral Anomaly (Blue)

  '#10b981', // Asset Criticality (Emerald)

  '#f59e0b', // Identity Risk (Amber)

  '#8b5cf6', // Correlation Chain (Purple)

  '#06b6d4', // Cyan (Extra)

];



const CustomFactorTooltip = ({ active, payload }) => {

  if (active && payload && payload.length) {

    const data = payload[0].payload;

    return (

      <div className="custom-pie-tooltip text-xs font-sans z-50">

        <div className="flex items-center gap-2 mb-1.5">

          <span className="w-2.5 h-2.5 rounded-full shrink-0" style={{ backgroundColor: data.color }} />

          <span className="font-bold tooltip-title text-xs">{data.name}</span>

          <span className="font-mono font-bold text-amber-500 ml-auto">{data.rawPts} PTS</span>

        </div>

        <div className="text-[11px] tooltip-desc leading-relaxed max-w-xs">{data.desc}</div>

      </div>

    );

  }

  return null;

};



export const getLoggedInUsername = () => {

  try {

    const raw = localStorage.getItem('wazuh_soc_user');

    if (raw) {

      const u = JSON.parse(raw);

      return u.username || u.name || 'analyst_secops';

    }

  } catch {}

  return 'analyst_secops';

};



// Persistent In-Memory Caches for Instant Modal Render (< 1ms)

const mlPredictionCache = new Map();

const aggregatesCache = new Map();

const aggregateLogsCache = new Map();



export const normalizeStatus = (status, resolutionOutcome) => {

  const s = (status || '').toUpperCase();

  if (s === 'GROUNDTRUTH' || s === 'GROUND_TRUTH') return 'GROUNDTRUTH';

  if (s === 'CLOSE' || s === 'CLOSED' || s === 'RESOLVED' || s === 'AUTO_CLOSED') return 'CLOSE';

  if (s === 'INVESTIGATING' || s === 'INVESTIGATE') return 'INVESTIGATE';

  return 'OPEN';

};



export const SLA_INTERVALS_MS = {

  P0: 15 * 60 * 1000,          // 15 menit

  P1: 60 * 60 * 1000,          // 60 menit (1 jam)

  P2: 4 * 60 * 60 * 1000,      // 4 jam

  P3: 24 * 60 * 60 * 1000,     // 24 jam (1 hari)

  P4: 7 * 24 * 60 * 60 * 1000, // 7 hari

};



const MONTH_NAMES = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'];



export const getDeadlineDate = (inc) => {

  if (!inc) return null;

  const prio = (inc.priority || 'P1').toUpperCase();

  const slaMs = SLA_INTERVALS_MS[prio] || SLA_INTERVALS_MS.P1;



  // 1. Jika backend sudah menyediakan batas_deadline_sla / deadlineSLA

  if (inc.deadlineSLA && inc.deadlineSLA !== 'None') {

    const d = new Date(String(inc.deadlineSLA).replace(' ', 'T'));

    if (!isNaN(d.getTime())) {

      return d;

    }

  }



  // 2. Waktu tiket muncul + waktu SLA sesuai prioritas 0-4

  const raw = inc.timeAgo || inc.created_at || inc.createdAt || inc.waktu_muncul;

  if (!raw) return null;



  let baseDate = null;

  if (/^[A-Za-z]{3}\s+\d{1,2},\s*\d{1,2}:\d{2}/.test(raw)) {

    const year = 2026;

    baseDate = new Date(raw.replace(',', ' ' + year));

  } else {

    baseDate = new Date(String(raw).replace(' ', 'T'));

  }



  if (isNaN(baseDate.getTime())) return null;

  return new Date(baseDate.getTime() + slaMs);

};



export const formatDeadline = (inc) => {

  const d = getDeadlineDate(inc);

  if (!d) {

    if (!inc?.timeAgo) return '-';

    return inc.timeAgo.includes('WIB') ? inc.timeAgo : `${inc.timeAgo} WIB`;

  }

  const pad = (n) => String(n).padStart(2, '0');

  return `${MONTH_NAMES[d.getMonth()]} ${d.getDate()}, ${pad(d.getHours())}:${pad(d.getMinutes())} WIB`;

};



const INDO_DAYS = ['Minggu', 'Senin', 'Selasa', 'Rabu', 'Kamis', 'Jumat', 'Sabtu'];

const INDO_MONTHS = ['Jan', 'Feb', 'Mar', 'Apr', 'Mei', 'Jun', 'Jul', 'Agu', 'Sep', 'Okt', 'Nov', 'Des'];



export const parseDateTime = (val) => {

  if (!val) return null;

  if (val instanceof Date) return isNaN(val.getTime()) ? null : val;

  if (typeof val === 'string') {

    const trimmed = val.trim();

    if (!trimmed || trimmed === 'None' || trimmed === 'null' || trimmed === 'undefined') return null;

    if (/^[A-Za-z]{3}\s+\d{1,2},\s*\d{1,2}:\d{2}/.test(trimmed)) {

      const d = new Date(trimmed.replace(',', ' 2026'));

      if (!isNaN(d.getTime())) return d;

    }

    const d = new Date(trimmed.replace(' ', 'T'));

    if (!isNaN(d.getTime())) return d;

  }

  return null;

};



export const formatIndoFullDateTime = (val) => {

  const d = parseDateTime(val);

  if (!d) return '-';

  const pad = (n) => String(n).padStart(2, '0');

  const dayName = INDO_DAYS[d.getDay()];

  const dateNum = d.getDate();

  const monthName = INDO_MONTHS[d.getMonth()];

  const year = d.getFullYear();

  const hours = pad(d.getHours());

  const mins = pad(d.getMinutes());

  const secs = pad(d.getSeconds());

  return `${dayName}, ${dateNum} ${monthName} ${year}, ${hours}:${mins}:${secs} WIB`;

};



export const getCloseSlaDetails = (inc) => {

  if (!inc) return null;



  // 1. Open date

  const openDate = parseDateTime(inc.waktuOpen) || 

                   parseDateTime(inc.waktu_muncul) || 

                   parseDateTime(inc.created_at) || 

                   parseDateTime(inc.createdAt) || 

                   parseDateTime(inc.timeAgo);



  // 2. Investigate date

  let investigateDate = parseDateTime(inc.waktuInvestigate) || parseDateTime(inc.investigated_at);



  // 3. Close date

  let closeDate = parseDateTime(inc.waktuClose) || 

                  parseDateTime(inc.resolved_at) || 

                  parseDateTime(inc.resolvedAt);



  if (!closeDate && normalizeStatus(inc.status) === 'CLOSE') {

    closeDate = parseDateTime(inc.updated_at) || 

                parseDateTime(inc.updatedAt) || 

                (investigateDate ? new Date(investigateDate.getTime() + 45 * 1000) : null) || 

                new Date();

  }



  if (!investigateDate) {

    if (openDate && closeDate && closeDate.getTime() > openDate.getTime()) {

      const midMs = openDate.getTime() + (closeDate.getTime() - openDate.getTime()) * 0.4;

      investigateDate = new Date(midMs);

    } else if (openDate) {

      investigateDate = new Date(openDate.getTime() + 3 * 60 * 1000);

    }

  }



  // 4. Deadline date

  const deadlineDate = getDeadlineDate(inc);



  // 5. On Time & Late calculation

  let onTime = true;

  let lateStr = 'none';



  if (closeDate && deadlineDate) {

    const diffMs = closeDate.getTime() - deadlineDate.getTime();

    if (diffMs > 0) {

      onTime = false;

      const totalSecs = Math.floor(diffMs / 1000);

      const days = Math.floor(totalSecs / 86400);

      const hours = Math.floor((totalSecs % 86400) / 3600);

      const minutes = Math.floor((totalSecs % 3600) / 60);

      const seconds = totalSecs % 60;



      const parts = [];

      if (days > 0) parts.push(`${days} hari`);

      if (hours > 0) parts.push(`${hours} jam`);

      if (minutes > 0) parts.push(`${minutes} menit`);

      if (parts.length === 0 || (days === 0 && hours === 0)) parts.push(`${seconds} detik`);

      lateStr = parts.join(' ');

    } else {

      onTime = true;

      lateStr = 'none';

    }

  }



  return {

    openFormatted: openDate ? formatIndoFullDateTime(openDate) : '-',

    investigateFormatted: investigateDate ? formatIndoFullDateTime(investigateDate) : '-',

    closeFormatted: closeDate ? formatIndoFullDateTime(closeDate) : '-',

    onTime: onTime ? 'true' : 'false',

    late: lateStr

  };

};



export const renderCloseSlaTooltip = (slaInfo, prio, positionClasses = 'top-full mt-2.5 right-0') => {

  if (!slaInfo) return null;

  const isBottom = positionClasses.includes('bottom-full');

  return (

    <div className={`absolute ${positionClasses} hidden group-hover/status:block z-50 w-80 p-3.5 rounded-xl bg-white border border-slate-200 shadow-xl text-left pointer-events-none transition-all duration-200 animate-in fade-in`}>

      <div className={`absolute ${isBottom ? '-bottom-1.5 border-b border-r' : '-top-1.5 border-t border-l'} right-6 w-3 h-3 bg-white border-slate-200 rotate-45`}></div>

      

      <div className="text-[11px] font-mono space-y-2 select-none text-slate-800">

        <div className="flex items-center justify-between border-b border-slate-100 pb-1.5">

          <span className="font-bold text-slate-900 tracking-wider uppercase text-[10px]">

            SLA Incident Audit

          </span>

          <span className="text-[10px] text-slate-500 font-semibold">{prio || 'P1'} SLA</span>

        </div>



        <div className="space-y-1 text-slate-700">

          <div className="flex justify-between items-baseline gap-2">

            <span className="text-slate-400 shrink-0 font-semibold">open:</span>

            <span className="text-slate-900 font-medium text-right">{slaInfo.openFormatted}</span>

          </div>

          <div className="flex justify-between items-baseline gap-2">

            <span className="text-slate-400 shrink-0 font-semibold">investigate:</span>

            <span className="text-slate-900 font-medium text-right">{slaInfo.investigateFormatted}</span>

          </div>

          <div className="flex justify-between items-baseline gap-2">

            <span className="text-slate-400 shrink-0 font-semibold">close:</span>

            <span className="text-slate-900 font-medium text-right">{slaInfo.closeFormatted}</span>

          </div>

        </div>



        <div className="border-t border-slate-100 pt-1.5 space-y-1">

          <div className="flex items-center justify-between">

            <span className="text-slate-400 font-semibold">on time:</span>

            <span className={`font-bold ${

              slaInfo.onTime === 'true' 

                ? 'text-emerald-600' 

                : 'text-rose-600'

            }`}>

              {slaInfo.onTime}

            </span>

          </div>

          <div className="flex items-center justify-between">

            <span className="text-slate-400 font-semibold">late:</span>

            <span className={`font-medium ${

              slaInfo.onTime === 'true' ? 'text-slate-700' : 'text-rose-600 font-bold'

            }`}>

              {slaInfo.late}

            </span>

          </div>

        </div>

      </div>

    </div>

  );

};



export const getApprovalAuditDetails = (req, decisionMap = {}) => {

  if (!req) return null;

  const tid = req.triage_id || (req.id && String(req.id).startsWith('TRG-') ? req.id : null) || req.id || req.incident_id;

  const decision = (tid && decisionMap[tid]) || (req.id && decisionMap[req.id]) || (req.incident_id && decisionMap[req.incident_id]);



  // Current status

  let status = 'waiting';

  if (decision) {

    status = typeof decision === 'object' ? (decision.status || 'waiting') : decision;

  } else {

    const s = String(req.fp_status || req.suppression_status || req.status || req.triage_status || '').toLowerCase();

    if (s === 'approve' || s === 'approved' || req.is_approved) status = 'approve';

    else if (s === 'reject' || s === 'rejected' || req.is_rejected) status = 'reject';

    else {

      const outcome = String(req.resolution_outcome || req.resolutionOutcome || '').toUpperCase();

      if (outcome === 'REJECTED') status = 'reject';

      else if (outcome === 'APPROVED' || outcome === 'RESOLVED_SUPPRESSED') status = 'approve';

      else {

        const tStatus = String(req.triage_status || req.status || '').toUpperCase();

        if (tStatus === 'APPROVED' || tStatus === 'APPROVE') status = 'approve';

        else if (tStatus === 'REJECTED' || tStatus === 'REJECT') status = 'reject';

      }

    }

  }



  // 1. Waiting Approval timestamp: when ticket was requested for FP

  let waitingDate = null;

  if (typeof decision === 'object' && decision?.requestedAt) {

    waitingDate = parseDateTime(decision.requestedAt);

  }

  if (!waitingDate) {

    waitingDate = parseDateTime(req.created_at) || 

                  parseDateTime(req.waktu_muncul) || 

                  parseDateTime(req.waktuOpen) || 

                  parseDateTime(req.timeAgo);

  }

  if (!waitingDate) {

    waitingDate = new Date();

  }



  // 2. Approve timestamp

  let approveDate = null;

  if (status === 'approve') {

    if (typeof decision === 'object' && decision?.approvedAt) {

      approveDate = parseDateTime(decision.approvedAt);

    }

    if (!approveDate) {

      approveDate = parseDateTime(req.resolved_at) || 

                    parseDateTime(req.updated_at) || 

                    parseDateTime(req.waktu_close) ||

                    (waitingDate ? new Date(waitingDate.getTime() + 12 * 60 * 1000) : new Date());

    }

  }



  // 3. Reject timestamp

  let rejectDate = null;

  if (status === 'reject') {

    if (typeof decision === 'object' && decision?.rejectedAt) {

      rejectDate = parseDateTime(decision.rejectedAt);

    }

    if (!rejectDate) {

      rejectDate = parseDateTime(req.resolved_at) || 

                   parseDateTime(req.updated_at) || 

                   parseDateTime(req.waktu_close) ||

                   (waitingDate ? new Date(waitingDate.getTime() + 8 * 60 * 1000) : new Date());

    }

  }



  return {

    status,

    waitingFormatted: waitingDate ? formatIndoFullDateTime(waitingDate) : '-',

    approveFormatted: status === 'approve' && approveDate ? formatIndoFullDateTime(approveDate) : 'none',

    rejectFormatted: status === 'reject' && rejectDate ? formatIndoFullDateTime(rejectDate) : 'none',

    reviewer: (typeof decision === 'object' && decision?.reviewer) ? decision.reviewer : (req.assigned_analyst || 'soc_lead_alice')

  };

};



export const renderApprovalAuditTooltip = (auditInfo, positionClasses = 'top-full mt-2.5 right-0') => {

  if (!auditInfo) return null;

  const isBottom = positionClasses.includes('bottom-full');

  return (

    <div className={`absolute ${positionClasses} hidden group-hover/status:block z-50 w-80 p-3.5 rounded-xl bg-white border border-slate-200 shadow-xl text-left pointer-events-none transition-all duration-200 animate-in fade-in`}>

      <div className={`absolute ${isBottom ? '-bottom-1.5 border-b border-r' : '-top-1.5 border-t border-l'} right-6 w-3 h-3 bg-white border-slate-200 rotate-45`}></div>

      

      <div className="text-[11px] font-mono space-y-2 select-none text-slate-800">

        <div className="flex items-center justify-between border-b border-slate-100 pb-1.5">

          <span className="font-bold text-slate-900 tracking-wider uppercase text-[10px]">

            SLA Incident Audit

          </span>

          <span className={`text-[10px] font-bold uppercase tracking-wider ${

            auditInfo.status === 'approve' 

              ? 'text-emerald-600' 

              : auditInfo.status === 'reject' 

                ? 'text-rose-600' 

                : 'text-amber-600'

          }`}>

            {auditInfo.status === 'approve' ? 'APPROVED' : auditInfo.status === 'reject' ? 'REJECTED' : 'WAITING APPROVAL'}

          </span>

        </div>



        <div className="space-y-1 text-slate-700">

          <div className="flex justify-between items-baseline gap-2">

            <span className="text-slate-400 shrink-0 font-semibold">waiting approval:</span>

            <span className="text-slate-900 font-medium text-right">{auditInfo.waitingFormatted}</span>

          </div>

          <div className="flex justify-between items-baseline gap-2">

            <span className="text-slate-400 shrink-0 font-semibold">approve:</span>

            <span className={`text-right ${

              auditInfo.approveFormatted === 'none' 

                ? 'text-slate-400 font-normal italic' 

                : 'text-slate-900 font-medium'

            }`}>

              {auditInfo.approveFormatted}

            </span>

          </div>

          <div className="flex justify-between items-baseline gap-2">

            <span className="text-slate-400 shrink-0 font-semibold">reject:</span>

            <span className={`text-right ${

              auditInfo.rejectFormatted === 'none' 

                ? 'text-slate-400 font-normal italic' 

                : 'text-slate-900 font-medium'

            }`}>

              {auditInfo.rejectFormatted}

            </span>

          </div>

        </div>

      </div>

    </div>

  );

};



// Global in-memory cache for instant zero-latency tab switching without mock data

export const globalTriageCache = {};



export default function IncidentTriageQueue({ 

  viewMode = 'active', 

  theme = 'dark', 

  selectedTenant = 'ALL',

  timeRange = 'semua',

  customStartDate = '2026-10-16',

  customEndDate = '2026-09-30',

  initialSearch = '',

  onClearInitialSearch

}) {

  const isDark = theme === 'dark' || (typeof document !== 'undefined' && document.documentElement.classList.contains('dark'));

  const cacheKey = `${viewMode}_${selectedTenant}_${timeRange}_${customStartDate}_${customEndDate}`;

  const [incidents, setIncidents] = useState(() => globalTriageCache[cacheKey] || []);

  const [loading, setLoading] = useState(false);

  const [selectedIncident, setSelectedIncident] = useState(null);

  const [aggregates, setAggregates] = useState([]);

  const [aggregatesLoading, setAggregatesLoading] = useState(false);

  const [selectedAggregateId, setSelectedAggregateId] = useState(null);

  const [aggregateLogs, setAggregateLogs] = useState([]);

  const [logsLoading, setLogsLoading] = useState(false);

  const [selectedLogId, setSelectedLogId] = useState(null);

  const [logSearch, setLogSearch] = useState('');

  const [searchQuery, setSearchQuery] = useState(initialSearch || '');

  const [selectedPriority, setSelectedPriority] = useState('ALL');

  const [selectedStatusFilter, setSelectedStatusFilter] = useState('ALL');

  const [isStatusDropdownOpen, setIsStatusDropdownOpen] = useState(false);

  const statusDropdownRef = useRef(null);



  useEffect(() => {

    const handleClickOutside = (event) => {

      if (statusDropdownRef.current && !statusDropdownRef.current.contains(event.target)) {

        setIsStatusDropdownOpen(false);

      }

    };

    document.addEventListener('mousedown', handleClickOutside);

    return () => document.removeEventListener('mousedown', handleClickOutside);

  }, []);



  useEffect(() => {

    if (initialSearch) {

      setSearchQuery(initialSearch);

      setSelectedPriority('ALL');

      setSelectedStatusFilter('ALL');

      if (onClearInitialSearch) {

        onClearInitialSearch();

      }

    }

  }, [initialSearch]);

  const [networkError, setNetworkError] = useState(false);

  const [updating, setUpdating] = useState(false);

  const [toastMsg, setToastMsg] = useState(null);

  const [totalServerCount, setTotalServerCount] = useState(null);



  // Ground Truth Justification Modal State

  const [showGtModal, setShowGtModal] = useState(false);

  const [gtTicket, setGtTicket] = useState(null);

  const [gtVerdict, setGtVerdict] = useState('TRUE_POSITIVE');

  const [gtAnalystId, setGtAnalystId] = useState(() => getLoggedInUsername() || 'soc_analyst_alice');

  const [gtNotes, setGtNotes] = useState('');

  const [submittingGt, setSubmittingGt] = useState(false);



  // False Positive Modal State (4-Section Form CEM v3.0)

  const [showFpModal, setShowFpModal] = useState(false);

  // Bagian A

  const [fpSuppressionId, setFpSuppressionId] = useState('');

  const [fpRefTicket, setFpRefTicket] = useState('');

  const [fpAggId, setFpAggId] = useState('');

  const [fpCurrentRisk, setFpCurrentRisk] = useState(0);

  // Bagian B (Scope)

  const [fpRuleName, setFpRuleName] = useState('');

  const [fpSids, setFpSids] = useState('');

  const [fpCategory, setFpCategory] = useState('AUTH_FAILURE');

  const [fpActor, setFpActor] = useState('');

  const [fpTarget, setFpTarget] = useState('');

  const [fpUsername, setFpUsername] = useState('');

  // Bagian C (Safety Ceilings)

  const [fpMaxCount, setFpMaxCount] = useState(500);

  const [fpMaxRiskScore, setFpMaxRiskScore] = useState(60);

  // Bagian D (Governance & 4-Eyes)

  const [fpClass, setFpClass] = useState('S2_FALSE_POSITIVE');

  const [fpOwner, setFpOwner] = useState(() => getLoggedInUsername());

  const [fpApprover, setFpApprover] = useState('');

  const [fpExpiration, setFpExpiration] = useState(() => {

    const d = new Date();

    d.setDate(d.getDate() + 90);

    return d.toISOString().split('T')[0];

  });

  const [fpReason, setFpReason] = useState('');

  const [submittingFp, setSubmittingFp] = useState(false);



  // Machine Learning Tier-1 & Ground Truth States

  const [mlPrediction, setMlPrediction] = useState(null);

  const [mlLoading, setMlLoading] = useState(false);

  const [groundTruthNotes, setGroundTruthNotes] = useState('');

  const [isSubmittingGt, setIsSubmittingGt] = useState(false);



  const fetchMlPrediction = async (triageId) => {

    const isCached = mlPredictionCache.has(triageId);

    if (!isCached) {

      setMlLoading(true);

    }

    try {

      const res = await fetch(`/api/triage/${triageId}/ml-prediction`);

      if (res.ok) {

        const data = await res.json();

        mlPredictionCache.set(triageId, data);

        if (data.incident_id) mlPredictionCache.set(data.incident_id, data);

        setMlPrediction(data);

        if (data.resolution_outcome) {
          setSelectedIncident(prev => prev ? { ...prev, resolution_outcome: data.resolution_outcome } : prev);

          try {
            Object.keys(globalTriageCache).forEach(k => {
              if (globalTriageCache[k] && Array.isArray(globalTriageCache[k])) {
                globalTriageCache[k] = globalTriageCache[k].map(inc => {
                  if (inc.id === triageId || inc.triage_id === triageId || inc.incident_id === triageId || inc.incident_id === data.incident_id) {
                    return {
                      ...inc,
                      status: data.triage_status,
                      resolution_outcome: data.resolution_outcome !== undefined ? data.resolution_outcome : inc.resolution_outcome
                    };
                  }
                  return inc;
                });
              }
            });
          } catch (cErr) {
            console.debug('Failed to sync globalTriageCache:', cErr);
          }

        }

        if (data.ground_truth?.analyst_notes) {

          setGroundTruthNotes(data.ground_truth.analyst_notes);

        } else {

          setGroundTruthNotes('');

        }

      }

    } catch (err) {

      console.warn("Fetch ML prediction error:", err);

    } finally {

      setMlLoading(false);

    }

  };



  const fetchAggregates = async (triageId) => {

    const isCached = aggregatesCache.has(triageId);

    if (!isCached) {

      setAggregatesLoading(true);

      setSelectedAggregateId(null);

      setAggregateLogs([]);

      setLogSearch('');

    }

    try {

      const res = await fetch(`/api/triage/${triageId}/aggregates`);

      if (res.ok) {

        const data = await res.json();

        const list = data.aggregates || [];

        aggregatesCache.set(triageId, list);

        setAggregates(list);

        if (list.length > 0 && !selectedAggregateId) {

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

      if (aggregateLogsCache.has(aggregationId)) {

        setAggregateLogs(aggregateLogsCache.get(aggregationId));

        setLogsLoading(false);

      } else {

        setLogsLoading(true);

      }

      const res = await fetch(`/api/aggregates/${aggregationId}/logs`);

      if (res.ok) {

        const data = await res.json();

        const logs = data.logs || [];

        aggregateLogsCache.set(aggregationId, logs);

        setAggregateLogs(logs);

      }

    } catch (err) {

      console.warn("Fetch logs error:", err);

    } finally {

      setLogsLoading(false);

    }

  };



  const handleOpenIncident = (inc) => {

    setSelectedIncident(inc);



    // Instant zero-delay cache lookup

    if (mlPredictionCache.has(inc.id)) {

      setMlPrediction(mlPredictionCache.get(inc.id));

      setMlLoading(false);

    } else {

      setMlLoading(true);

      setMlPrediction(null);

    }



    if (aggregatesCache.has(inc.id)) {

      const list = aggregatesCache.get(inc.id) || [];

      setAggregates(list);

      setAggregatesLoading(false);

      if (list.length > 0) {

        const firstAggId = list[0].aggregation_id;

        setSelectedAggregateId(firstAggId);

        if (aggregateLogsCache.has(firstAggId)) {

          setAggregateLogs(aggregateLogsCache.get(firstAggId));

          setLogsLoading(false);

        } else {

          fetchAggregateLogs(firstAggId);

        }

      }

    } else {

      setAggregatesLoading(true);

      setAggregates([]);

      setSelectedAggregateId(null);

      setAggregateLogs([]);

    }



    fetchAggregates(inc.id);

    fetchMlPrediction(inc.id);

  };



  const openFpModal = (inc) => {

    const targetAsset = inc.asset || 'Host';

    const sidsList = aggregates.map(a => a.rule_id).filter((v, i, a) => a.indexOf(v) === i);

    const sidsStr = sidsList.length > 0 ? sidsList.join(', ') : '31101';

    const primaryAgg = aggregates[0] || {};

    const cat = primaryAgg.category || 'AUTH_FAILURE';



    setFpSuppressionId(`SUP-2026-${Math.floor(100 + Math.random() * 900)}`);

    setFpRefTicket(inc.id);

    setFpAggId(inc.aggregation_id || primaryAgg.aggregation_id || `agg_${inc.id}`);

    setFpCurrentRisk(inc.score || primaryAgg.max_inline_risk_score || 45);



    setFpRuleName(`Supresi [${targetAsset}]: Rule ${sidsStr}`);

    setFpSids(sidsStr);

    setFpCategory(cat);

    setFpActor(inc.attackerIp || primaryAgg.actor || primaryAgg.source_ip || '');

    setFpTarget(targetAsset);

    setFpUsername(inc.user || primaryAgg.username || '');



    setFpMaxCount(500);

    setFpMaxRiskScore(60);



    setFpClass('S2_FALSE_POSITIVE');

    setFpOwner(getLoggedInUsername());

    setFpApprover('');

    setFpReason(groundTruthNotes || '');

    const d = new Date();

    d.setDate(d.getDate() + 90);

    setFpExpiration(d.toISOString().split('T')[0]);

    setShowFpModal(true);

  };



  const copyToClipboard = (text, sectionName) => {

    navigator.clipboard.writeText(text);

    setCopiedSection(sectionName);

    setTimeout(() => setCopiedSection(null), 2500);

  };



  const fetchQueue = async () => {

    try {

      if (!globalTriageCache[cacheKey]) {

        setLoading(true);

      }

      const params = new URLSearchParams({

        view: viewMode,

        limit: '1000'

      });

      if (selectedTenant && selectedTenant !== 'ALL') {

        params.append('tenant_id', selectedTenant);

      }

      if (timeRange) {

        params.append('range', timeRange);

        if (timeRange === 'custom') {

          params.append('start', customStartDate);

          params.append('end', customEndDate);

        }

      }

      if (deferredSearch && deferredSearch.trim()) {

        params.append('search', deferredSearch.trim());

      }

      const res = await fetch(`/api/triage/queue?${params.toString()}`);

      if (res.ok) {

        setNetworkError(false);

        const json = await res.json();

        if (json.incidents) {

          const mapped = json.incidents.map(inc => ({

            ...inc,

            status: normalizeStatus(inc.status || inc.triage_status, inc.resolutionOutcome || inc.resolution_outcome)

          }));

          globalTriageCache[cacheKey] = mapped;

          setIncidents(mapped);

          if (json.total !== undefined) {

            setTotalServerCount(json.total);

          }

        }

      } else {

        setNetworkError(true);

      }

    } catch (err) {

      console.warn("Could not reach triage queue:", err);

      setNetworkError(true);

    } finally {

      setLoading(false);

    }

  };



  useEffect(() => {

    if (globalTriageCache[cacheKey]) {

      setIncidents(globalTriageCache[cacheKey]);

    }

    fetchQueue();

    const interval = setInterval(fetchQueue, 20000);

    return () => clearInterval(interval);

  }, [viewMode, selectedTenant, timeRange, customStartDate, customEndDate, cacheKey]);



  const handleUpdateTicket = async (triageId, newStatus, outcome = null, customNotes = null, fpReasonVal = null, authorAnalyst = null) => {

    const normStatus = normalizeStatus(newStatus);

    const nowIso = new Date().toISOString();

    // Optimistic local update

    setIncidents(prev => {

      const updated = prev.map(inc => {

        if (inc.id === triageId) {

          return { 

            ...inc, 

            status: normStatus, 

            ...(outcome ? { resolutionOutcome: outcome } : {}),

            ...(authorAnalyst ? { assignedAnalyst: authorAnalyst, assigned_analyst: authorAnalyst } : {}),

            ...(normStatus === 'CLOSE' ? { waktuClose: inc.waktuClose || nowIso, waktuInvestigate: inc.waktuInvestigate || nowIso } : {}),

            ...(normStatus === 'INVESTIGATE' ? { waktuInvestigate: inc.waktuInvestigate || nowIso } : {})

          };

        }

        return inc;

      });

      globalTriageCache[cacheKey] = updated;

      return updated;

    });

    if (selectedIncident && selectedIncident.id === triageId) {

      setSelectedIncident(prev => ({ 

        ...prev, 

        status: normStatus, 

        ...(outcome ? { resolutionOutcome: outcome } : {}),

        ...(authorAnalyst ? { assignedAnalyst: authorAnalyst, assigned_analyst: authorAnalyst } : {}),

        ...(normStatus === 'CLOSE' ? { waktuClose: prev.waktuClose || nowIso, waktuInvestigate: prev.waktuInvestigate || nowIso } : {}),

        ...(normStatus === 'INVESTIGATE' ? { waktuInvestigate: prev.waktuInvestigate || nowIso } : {})

      }));

    }



    try {

      setUpdating(true);

      mlPredictionCache.delete(triageId);

      const res = await fetch(`/api/triage/${triageId}/update`, {

        method: 'POST',

        headers: { 

          'Content-Type': 'application/json',

          'X-API-Key': 'wazuh-soc-secure-key-2026'

        },

        body: JSON.stringify({

          triage_status: normStatus,

          assigned_analyst: authorAnalyst || getLoggedInUsername(),

          resolution_outcome: outcome,

          notes: customNotes || `Status changed to ${normStatus} via SOC Triage Dashboard.`,

          false_positive_reason: fpReasonVal

        })

      });

      if (res.ok) {

        setToastMsg(`Tiket ${triageId} diperbarui: ${outcome || normStatus}`);

        setTimeout(() => setToastMsg(null), 4000);

      }

    } catch (err) {

      console.warn("Update error:", err);

    } finally {

      setUpdating(false);

    }

  };



  const handlePenClick = (e, inc) => {

    e.stopPropagation();

    handleOpenIncident(inc);

  };



  const handleConfirmTruePositive = async (triageId, customNotes = null) => {

    const nowIso = new Date().toISOString();

    const finalNotes = customNotes || groundTruthNotes || 'Terverifikasi sebagai TRUE POSITIVE oleh analis SOC.';

    setIsSubmittingGt(true);

    try {

      await handleUpdateTicket(triageId, 'CLOSE', 'TRUE_POSITIVE_ACTIONABLE', finalNotes);

      setSelectedIncident(prev => prev ? { 

        ...prev, 

        status: 'CLOSE', 

        resolutionOutcome: 'TRUE_POSITIVE_ACTIONABLE',

        waktuClose: prev.waktuClose || nowIso,

        waktuInvestigate: prev.waktuInvestigate || nowIso

      } : null);

      await fetchMlPrediction(triageId);

      setToastMsg(`Tiket ${triageId} diverifikasi sebagai TRUE POSITIVE & Status diubah menjadi CLOSE.`);

    } finally {

      setIsSubmittingGt(false);

    }

  };



  const handleConfirmFalsePositive = async (triageId) => {

    const authorUser = getLoggedInUsername();

    const reasonText = groundTruthNotes.trim() || 'Diverifikasi sebagai FALSE POSITIVE oleh analis SOC. Otomatis diteruskan ke Ground Truth Review.';

    setIsSubmittingGt(true);

    try {

      await handleUpdateTicket(

        triageId, 

        'CLOSE', 

        'BENIGN', 

        reasonText,

        reasonText,

        authorUser

      );

      setSelectedIncident(prev => prev ? { 

        ...prev, 

        status: 'CLOSE', 

        resolutionOutcome: 'BENIGN',

        waktuClose: prev.waktuClose || new Date().toISOString(),

        waktuInvestigate: prev.waktuInvestigate || new Date().toISOString()

      } : null);

      await fetchMlPrediction(triageId);

      setToastMsg(`Tiket ${triageId} diverifikasi sebagai FALSE POSITIVE & otomatis masuk ke Ground Truth Review.`);

    } finally {

      setIsSubmittingGt(false);

    }

  };



  const handleSubmitGroundTruth = async (e) => {

    e.preventDefault();

    if (!gtTicket) return;

    if (!gtNotes.trim()) {

      alert("Harap masukkan catatan / justifikasi analisis.");

      return;

    }

    setSubmittingGt(true);

    try {

      const ticketId = gtTicket.id || gtTicket.triage_id;

      mlPredictionCache.delete(ticketId);

      const res = await fetch(`/api/triage/${ticketId}/submit-ground-truth`, {

        method: 'POST',

        headers: { 'Content-Type': 'application/json' },

        body: JSON.stringify({

          verdict: gtVerdict,

          notes: gtNotes,

          analyst_id: gtAnalystId || getLoggedInUsername() || 'soc_analyst_alice'

        })

      });

      const data = await res.json();

      if (res.ok) {

        setToastMsg(`Justifikasi tiket ${ticketId} berhasil dikirim! Status berubah menjadi WAITING dan tiket telah masuk ke Ground Truth Review.`);

        setTimeout(() => setToastMsg(null), 5000);

        setShowGtModal(false);

        setGtTicket(null);



        // Update local incidents array so it immediately shows WAITING

        setIncidents(prev => prev.map(inc => {

          if (inc.id === ticketId || inc.triage_id === ticketId) {

            return {

              ...inc,

              ground_truth_status: 'WAITING',

              groundTruthStatus: 'WAITING',

              groundTruthVerdict: gtVerdict,

              analystNotes: gtNotes,

              assignedAnalyst: gtAnalystId || inc.assignedAnalyst

            };

          }

          return inc;

        }));

        globalTriageCache[viewMode] = null;

      } else {

        alert(data.detail || 'Gagal mengirim justifikasi ground truth.');

      }

    } catch (err) {

      alert('Koneksi gagal: ' + err.message);

    } finally {

      setSubmittingGt(false);

    }

  };



  const handleApplySuppressionAndFp = async (e) => {

    e.preventDefault();

    if (!fpReason.trim()) {

      alert("Harap masukkan alasan administratif / forensik False Positive.");

      return;

    }

    const authorUser = fpOwner.trim() || getLoggedInUsername();

    if (fpApprover.trim() && authorUser.toLowerCase() === fpApprover.trim().toLowerCase()) {

      alert("Separation of Duties Violation: Pembuat (Author) dan Penyetuju (Approver) harus dua orang yang berbeda.");

      return;

    }

    try {

      setSubmittingFp(true);

      const parsedSids = fpSids

        .split(',')

        .map(s => parseInt(s.trim(), 10))

        .filter(n => !isNaN(n));

      const targetSids = parsedSids.length > 0 ? parsedSids : [31101];



      const scopeDef = {

        source_ip: fpActor.trim() || null,

        target_host: fpTarget.trim() || null,

        username: fpUsername.trim() || null,

        categories: fpCategory ? [fpCategory] : ["AUTH_FAILURE"],

        max_count: parseInt(fpMaxCount, 10) || 500,

        max_risk_score: parseInt(fpMaxRiskScore, 10) || 60,

        referenced_ticket_id: fpRefTicket,

        aggregation_id: fpAggId

      };



      // Pengajuan FP: Tiket ditutup di triage dan dikirim ke Inbox Permohonan FP untuk disahkan oleh SOC Lead

      await handleUpdateTicket(

        selectedIncident.id,

        'CLOSE',

        'BENIGN',

        `Diajukan sebagai FALSE POSITIVE oleh ${authorUser}: ${fpReason}. Menunggu verifikasi SOC Lead di Inbox Permohonan FP.`,

        fpReason,

        authorUser

      );



      setSelectedIncident(prev => prev ? { 

        ...prev, 

        status: 'CLOSE', 

        resolutionOutcome: 'BENIGN',

        waktuClose: prev.waktuClose || new Date().toISOString(),

        waktuInvestigate: prev.waktuInvestigate || new Date().toISOString()

      } : null);

      setShowFpModal(false);

      if (selectedIncident?.id) {

        fetchMlPrediction(selectedIncident.id);

      }

      setToastMsg(`Tiket ${selectedIncident.id} diajukan sebagai FP (status: CLOSE) & masuk ke Inbox Permohonan FP.`);

    } catch (err) {

      alert("Error: " + err.message);

    } finally {

      setSubmittingFp(false);

    }

  };



  const [currentPage, setCurrentPage] = useState(1);

  const pageSize = 20;



  const deferredSearch = useDeferredValue(searchQuery);



  const { countP0, countP1, countP2, countP3, countP4, countOpen, countInvestigate, countClose, countGroundtruth } = useMemo(() => {

    let p0 = 0, p1 = 0, p2 = 0, p3 = 0, p4 = 0;

    let open = 0, inv = 0, cls = 0, gt = 0;

    for (let idx = 0; idx < incidents.length; idx++) {

      const i = incidents[idx];

      if (i.priority === 'P0') p0++;

      else if (i.priority === 'P1') p1++;

      else if (i.priority === 'P2') p2++;

      else if (i.priority === 'P3') p3++;

      else if (i.priority === 'P4') p4++;



      const st = normalizeStatus(i.status, i.resolution_outcome || i.resolutionOutcome);

      if (st === 'OPEN') open++;

      else if (st === 'INVESTIGATE') inv++;

      else if (st === 'CLOSE') cls++;

      else if (st === 'GROUNDTRUTH') gt++;

    }

    return {

      countP0: p0, countP1: p1, countP2: p2, countP3: p3, countP4: p4,

      countOpen: open, countInvestigate: inv, countClose: cls, countGroundtruth: gt

    };

  }, [incidents]);



  const priorityFiltered = useMemo(() => {

    let list = incidents;

    if (selectedTenant && selectedTenant !== 'ALL') {

      const lowerTenant = selectedTenant.toLowerCase();

      list = list.filter(i => {

        const t = (i.tenant_id || i.tenant || '').toLowerCase();

        return t === lowerTenant;

      });

    }



    if (selectedPriority === 'ALL' && selectedStatusFilter === 'ALL') {

      return list;

    }

    return list.filter(i => {

      if (selectedPriority !== 'ALL' && i.priority !== selectedPriority) {

        return false;

      }

      if (selectedStatusFilter !== 'ALL') {

        if (viewMode === 'groundtruth') {

          const gtSt = (i.ground_truth_status || i.groundTruthStatus || 'ACT NEED').toUpperCase();

          if (gtSt !== selectedStatusFilter.toUpperCase()) {

            return false;

          }

        } else {

          const norm = normalizeStatus(i.status, i.resolution_outcome || i.resolutionOutcome);

          if (norm !== selectedStatusFilter) {

            return false;

          }

        }

      }

      return true;

    });

  }, [incidents, selectedPriority, selectedStatusFilter, selectedTenant, viewMode]);



  const filteredIncidents = useMemo(() => {

    const trimmed = deferredSearch.trim();

    if (!trimmed) return priorityFiltered;

    const q = trimmed.toLowerCase();



    const matchIncident = (i) => {

      const matchId = (i.id && i.id.toLowerCase().includes(q)) || 

                      (i.triage_id && i.triage_id.toLowerCase().includes(q)) || 

                      (i.incident_id && i.incident_id.toLowerCase().includes(q));

      const matchAgg = (i.aggregation_id && i.aggregation_id.toLowerCase().includes(q)) ||

                       (Array.isArray(i.aggregation_ids) && i.aggregation_ids.some(a => a && a.toLowerCase().includes(q)));

      const matchCum = (i.cumulative_id && i.cumulative_id.toLowerCase().includes(q)) ||

                       (Array.isArray(i.cumulative_ids) && i.cumulative_ids.some(c => c && c.toLowerCase().includes(q)));

      const matchMeta = (i.title && i.title.toLowerCase().includes(q)) ||

                        (i.asset && i.asset.toLowerCase().includes(q)) ||

                        (i.attackerIp && i.attackerIp.toLowerCase().includes(q)) ||

                        ((i.tenant_id || i.tenant) && (i.tenant_id || i.tenant).toLowerCase().includes(q)) ||

                        (i.user && i.user.toLowerCase().includes(q)) ||

                        (i.priority && i.priority.toLowerCase().includes(q)) ||

                        (i.timeAgo && i.timeAgo.toLowerCase().includes(q)) ||

                        ((i.ground_truth_status || i.groundTruthStatus || 'ACT NEED').toLowerCase().includes(q)) ||

                        (normalizeStatus(i.status, i.resolution_outcome || i.resolutionOutcome).toLowerCase().includes(q));

      return Boolean(matchId || matchAgg || matchCum || matchMeta);

    };



    const matchesInCurrent = priorityFiltered.filter(matchIncident);

    if (matchesInCurrent.length > 0) {

      return matchesInCurrent;

    }

    // Cross-status search fallback: if searching specifically for a ticket, aggregate, or IP,

    // match across all incidents so the ticket is never hidden due to an active tab filter!

    return incidents.filter(matchIncident);

  }, [priorityFiltered, incidents, deferredSearch]);



  const priorityTabs = [

    { id: 'ALL', label: 'All', count: totalServerCount ? totalServerCount.toLocaleString() : incidents.length.toLocaleString() },

    { id: 'P0', label: 'P0', count: countP0 },

    { id: 'P1', label: 'P1', count: countP1 },

    { id: 'P2', label: 'P2', count: countP2 },

    { id: 'P3', label: 'P3', count: countP3 },

    { id: 'P4', label: 'P4', count: countP4 },

  ];



  const statusOptions = viewMode === 'groundtruth' ? [

    { id: 'ALL', label: 'All Groundtruth', color: null },

    { id: 'ACT NEED', label: 'Act Need', color: 'bg-orange-500' },

    { id: 'WAITING', label: 'Waiting Review', color: 'bg-yellow-400' },

    { id: 'APPROVE', label: 'Approve', color: 'bg-emerald-500' },

    { id: 'REJECT', label: 'Reject', color: 'bg-red-500' },

  ] : [

    { id: 'ALL', label: 'All Status', color: null },

    { id: 'OPEN', label: 'Open', color: 'bg-red-500' },

    { id: 'INVESTIGATE', label: 'Investigate', color: 'bg-yellow-400' },

    { id: 'CLOSE', label: 'Close', color: 'bg-emerald-500' },

    { id: 'GROUNDTRUTH', label: 'Groundtruth', color: 'bg-orange-500' },

  ];



  const currentStatusObj = statusOptions.find(opt => opt.id === selectedStatusFilter);

  const statusDropdownLabel = selectedStatusFilter === 'ALL' ? 'Status' : (currentStatusObj ? currentStatusObj.label : 'Status');

  const isStatusActive = selectedStatusFilter !== 'ALL';



  const handlePriorityChange = (priorityId) => {

    setSelectedPriority(priorityId);

    if (priorityId === 'ALL') {

      setSelectedStatusFilter('ALL');

    }

    setCurrentPage(1);

  };



  const handleStatusFilterChange = (statusId) => {

    setSelectedStatusFilter(prev => prev === statusId ? 'ALL' : statusId);

    setCurrentPage(1);

  };



  const [sortField, setSortField] = useState('score');

  const [sortDirection, setSortDirection] = useState('desc');



  const handleSort = (field) => {

    if (sortField === field) {

      setSortDirection(prev => prev === 'asc' ? 'desc' : 'asc');

    } else {

      setSortField(field);

      setSortDirection('asc');

    }

  };



  const renderSortIcon = (field) => {

    if (sortField !== field) {

      return <ChevronsUpDown className="w-3.5 h-3.5 text-blue-500/70 group-hover:text-blue-600 shrink-0 transition-colors" />;

    }

    if (sortDirection === 'asc') {

      return <ChevronUp className="w-3.5 h-3.5 text-blue-600 dark:text-blue-400 shrink-0 stroke-[2.5]" />;

    }

    return <ChevronDown className="w-3.5 h-3.5 text-blue-600 dark:text-blue-400 shrink-0 stroke-[2.5]" />;

  };



  const sortedIncidents = [...filteredIncidents].sort((a, b) => {

    if (!sortField) return 0;

    let aVal = a[sortField];

    let bVal = b[sortField];



    if (sortField === 'score') {

      aVal = Number(a.score || 0);

      bVal = Number(b.score || 0);

      return sortDirection === 'asc' ? aVal - bVal : bVal - aVal;

    }

    if (sortField === 'eventCount') {

      aVal = Number(a.eventCount || 0);

      bVal = Number(b.eventCount || 0);

      return sortDirection === 'asc' ? aVal - bVal : bVal - aVal;

    }

    if (sortField === 'deadline' || sortField === 'timeAgo') {

      const timeA = getDeadlineDate(a)?.getTime() || 0;

      const timeB = getDeadlineDate(b)?.getTime() || 0;

      return sortDirection === 'asc' ? timeA - timeB : timeB - timeA;

    }

    if (sortField === 'priority') {

      const pWeight = { P0: 0, P1: 1, P2: 2, P3: 3, P4: 4 };

      aVal = pWeight[a.priority] ?? 99;

      bVal = pWeight[b.priority] ?? 99;

      return sortDirection === 'asc' ? aVal - bVal : bVal - aVal;

    }



    aVal = String(aVal || '').toLowerCase();

    bVal = String(bVal || '').toLowerCase();

    if (aVal < bVal) return sortDirection === 'asc' ? -1 : 1;

    if (aVal > bVal) return sortDirection === 'asc' ? 1 : -1;

    return 0;

  });



  const totalPages = Math.max(1, Math.ceil(sortedIncidents.length / pageSize));

  const paginatedIncidents = sortedIncidents.slice((currentPage - 1) * pageSize, currentPage * pageSize);





  const selectedAggregate = aggregates.find(a => a.aggregation_id === selectedAggregateId);

  const filteredLogs = logSearch.trim() === ''

    ? aggregateLogs

    : aggregateLogs.filter(l => 

        (l.payload && l.payload.toLowerCase().includes(logSearch.toLowerCase())) ||

        (l.source_ip && l.source_ip.toLowerCase().includes(logSearch.toLowerCase())) ||

        (l.agent_name && l.agent_name.toLowerCase().includes(logSearch.toLowerCase()))

      );



  return (

    <div className="w-full space-y-4">

      {/* Toast Notification */}

      {toastMsg && (

        <div className="p-3.5 bg-slate-900 border border-slate-700/80 rounded-lg text-slate-200 text-xs flex items-center justify-between shadow-lg">

          <div className="flex items-center gap-2">

            <Check className="w-4 h-4 text-emerald-400" />

            <span>{toastMsg}</span>

          </div>

          <button onClick={() => setToastMsg(null)} className="text-slate-400 hover:text-white">

            <X className="w-4 h-4" />

          </button>

        </div>

      )}



      {/* Main Incident Queue Panel */}

      <div className={`border rounded-xl overflow-hidden ${

        isDark 

          ? 'bg-[#0a0e1a] border-slate-800' 

          : 'bg-white border-slate-200 shadow-xs'

      }`}>

        {/* Header Bar matching referenced screenshot */}

        <div className={`px-6 py-3.5 border-b flex items-center justify-between gap-5 flex-wrap md:flex-nowrap ${

          isDark ? 'border-slate-800' : 'border-slate-200'

        }`}>

          {/* Left Title */}

          <div className="shrink-0">

            <h2 className={`text-base font-bold tracking-tight ${

              isDark ? 'text-white' : 'text-slate-900'

            }`}>

              {viewMode === 'verified_tp' ? 'Verified Threat' : viewMode === 'groundtruth' ? 'Groundtruth' : 'Ticket Queue'}

            </h2>

          </div>



          {/* Center Search Bar with Electric Blue Border & Right Action Circle Button */}

          <div className="flex-1 flex justify-center max-w-sm mx-auto md:mx-4 w-full md:w-auto order-3 md:order-2">

            <div className="w-full relative flex items-center bg-white dark:bg-[#090d16] border-2 border-[#3B5BFF] rounded-full h-[38px] pl-3.5 pr-1.5 shadow-2xs group focus-within:ring-2 focus-within:ring-[#3B5BFF]/30 transition-all">

              <Search className="w-4 h-4 text-slate-400 shrink-0 mr-2.5 stroke-[2]" />

              <input

                type="text"

                value={searchQuery}

                onChange={(e) => {

                  setSearchQuery(e.target.value);

                  setCurrentPage(1);

                }}

                placeholder="Search ID Tiket, Aggregat, Cumulative, Host, IP..."

                className="w-full bg-transparent text-slate-800 dark:text-slate-200 placeholder:text-slate-400 text-xs sm:text-[13px] font-normal focus:outline-none"

              />

              {searchQuery && (

                <button

                  type="button"

                  onClick={() => { setSearchQuery(''); setCurrentPage(1); }}

                  className="text-slate-400 hover:text-slate-600 dark:hover:text-slate-200 cursor-pointer p-1 mr-1"

                  title="Hapus pencarian"

                >

                  <X className="w-3.5 h-3.5" />

                </button>

              )}

              <button

                type="button"

                className="w-7 h-7 rounded-full bg-[#3B5BFF] hover:bg-[#2D4BEB] flex items-center justify-center shrink-0 cursor-pointer transition-transform hover:scale-105 shadow-xs"

                title="Search"

              >

                <Search 

                  className="w-3.5 h-3.5 text-white"

                  color="#FFFFFF"

                  strokeWidth={2.5}

                  style={{ stroke: '#FFFFFF', color: '#FFFFFF' }}

                />

              </button>

            </div>

          </div>



          {/* Right Priority Filters & Status Dropdown matching referenced style */}

          <div className="flex items-center gap-5 sm:gap-6 select-none shrink-0 order-2 md:order-3">

            <div className="flex items-center gap-5 sm:gap-6 overflow-x-auto pb-1 md:pb-0">

              {priorityTabs.map(tab => {

                const isActive = selectedPriority === tab.id && selectedStatusFilter === 'ALL';

                return (

                  <button

                    key={tab.id}

                    onClick={() => handlePriorityChange(tab.id)}

                    title={`Filter ${tab.label} (${tab.count} tiket)`}

                    className="relative flex flex-col items-center justify-center py-1 cursor-pointer transition-colors group whitespace-nowrap"

                  >

                    <span className={`text-xs sm:text-[13px] transition-colors ${

                      isActive 

                        ? (isDark ? 'text-white font-bold' : 'text-slate-900 font-bold')

                        : (isDark ? 'text-slate-400 hover:text-slate-200 font-medium' : 'text-slate-500 hover:text-slate-900 font-medium')

                    }`}>

                      {tab.label}

                    </span>

                    {isActive ? (

                      <span className={`w-full min-w-[22px] h-[2px] mt-1.5 transition-all ${

                        isDark ? 'bg-white' : 'bg-slate-900'

                      }`}></span>

                    ) : (

                      <span className="w-full min-w-[22px] h-[2px] mt-1.5 bg-transparent"></span>

                    )}

                  </button>

                );

              })}

            </div>



            {/* Status Dropdown Menu (Open, Investigate, Close, Groundtruth) */}

            <div className="relative" ref={statusDropdownRef}>

              <button

                type="button"

                onClick={() => setIsStatusDropdownOpen(prev => !prev)}

                title="Filter status: Open, Investigate, Close, Groundtruth"

                className={`flex items-center justify-between gap-2 px-3 py-1.5 rounded-md text-xs font-mono font-medium border transition-all cursor-pointer shadow-xs ${

                  isStatusActive

                    ? (isDark 

                        ? 'bg-slate-800 border-slate-700 text-white font-semibold hover:bg-slate-750 hover:border-slate-600' 

                        : 'bg-slate-100 border-slate-300 text-slate-900 font-semibold hover:bg-slate-200 hover:border-slate-400')

                    : (isDark

                        ? 'bg-[#0c101c] border-slate-800 text-slate-300 hover:bg-slate-800/80 hover:border-slate-700 hover:text-white'

                        : 'bg-white border-slate-200 text-slate-700 hover:bg-slate-100 hover:border-slate-300 hover:text-slate-900')

                }`}

              >

                <span className="flex items-center gap-1.5">

                  {currentStatusObj?.color && (

                    <span className={`w-2 h-2 rounded-full ${currentStatusObj.color} shrink-0`} />

                  )}

                  <span>{statusDropdownLabel}</span>

                </span>

                <ChevronDown className={`w-3.5 h-3.5 shrink-0 transition-transform duration-200 ${

                  isDark ? 'text-slate-400' : 'text-slate-500'

                } ${

                  isStatusDropdownOpen ? 'rotate-180' : ''

                }`} />

              </button>



              {/* Dropdown Menu */}

              {isStatusDropdownOpen && (

                <div className={`absolute right-0 mt-1.5 w-44 rounded-xl shadow-2xl border z-50 font-mono text-xs overflow-hidden animate-in fade-in zoom-in-95 ${

                  isDark

                    ? 'bg-[#0c101c] border-slate-700 text-slate-200 shadow-black/80'

                    : 'bg-white border-slate-200 text-slate-800 shadow-slate-400/30'

                }`}>

                  <div className="py-1">

                    {statusOptions.map((opt) => {

                      const isSelected = selectedStatusFilter === opt.id;

                      return (

                        <button

                          key={opt.id}

                          type="button"

                          onClick={() => {

                            handleStatusFilterChange(opt.id);

                            setIsStatusDropdownOpen(false);

                          }}

                          className={`w-full text-left px-3.5 py-2.5 flex items-center justify-between transition-colors cursor-pointer ${

                            isSelected

                              ? (isDark ? 'bg-slate-800 text-white font-semibold' : 'bg-slate-100 text-slate-900 font-semibold')

                              : (isDark ? 'text-slate-300 hover:bg-slate-800/60 hover:text-white' : 'text-slate-700 hover:bg-slate-100 hover:text-slate-900')

                          }`}

                        >

                          <span className="flex items-center gap-2">

                            {opt.color && <span className={`w-2 h-2 rounded-full ${opt.color} shrink-0`} />}

                            <span>{opt.label}</span>

                          </span>

                          {isSelected && (

                            <Check className={`w-3.5 h-3.5 stroke-[2.5] ${isDark ? 'text-slate-200' : 'text-slate-800'}`} />

                          )}

                        </button>

                      );

                    })}

                  </div>

                </div>

              )}

            </div>

          </div>

        </div>



        {/* High-Density Incident Table */}

        <div className="overflow-x-auto w-full">

          <table className="w-full table-fixed text-left text-xs border-collapse">

            <thead className={`border-b text-xs font-semibold ${

              isDark 

                ? 'bg-[#0b101d] text-slate-300 border-slate-800' 

                : 'bg-[#F0F5FA] text-slate-700 border-slate-200/80'

            }`}>

              <tr>

                <th 

                  onClick={() => handleSort('id')}

                  className="w-[17%] px-3 py-3 cursor-pointer select-none group hover:bg-slate-200/50 dark:hover:bg-slate-800/60 transition-colors"

                  title="Urutkan ID Insiden"

                >

                  <div className="flex items-center gap-1">

                    <span className={sortField === 'id' || sortField === 'title' ? 'text-blue-600 dark:text-blue-400 font-bold' : 'group-hover:text-slate-900 dark:group-hover:text-white transition-colors'}>Incident</span>

                    {renderSortIcon(sortField === 'id' ? 'id' : 'title')}

                  </div>

                </th>

                <th 

                  onClick={() => handleSort('priority')}

                  className="w-[6%] px-2 py-3 text-center cursor-pointer select-none group hover:bg-slate-200/50 dark:hover:bg-slate-800/60 transition-colors"

                  title="Urutkan Priority"

                >

                  <div className="flex items-center justify-center gap-1">

                    <span className={sortField === 'priority' ? 'text-blue-600 dark:text-blue-400 font-bold' : 'group-hover:text-slate-900 dark:group-hover:text-white transition-colors'}>Priority</span>

                    {renderSortIcon('priority')}

                  </div>

                </th>

                <th 

                  onClick={() => handleSort('deadline')}

                  className="w-[15%] px-2 py-3 cursor-pointer select-none group hover:bg-slate-200/50 dark:hover:bg-slate-800/60 transition-colors"

                  title="Urutkan Deadline"

                >

                  <div className="flex items-center gap-1">

                    <span className={sortField === 'deadline' || sortField === 'timeAgo' ? 'text-blue-600 dark:text-blue-400 font-bold' : 'group-hover:text-slate-900 dark:group-hover:text-white transition-colors'}>Deadline</span>

                    {renderSortIcon('deadline')}

                  </div>

                </th>

                <th 

                  onClick={() => handleSort('asset')}

                  className="w-[17%] px-2 py-3 cursor-pointer select-none group hover:bg-slate-200/50 dark:hover:bg-slate-800/60 transition-colors"

                  title="Urutkan Target Host"

                >

                  <div className="flex items-center gap-1">

                    <span className={sortField === 'asset' ? 'text-blue-600 dark:text-blue-400 font-bold' : 'group-hover:text-slate-900 dark:group-hover:text-white transition-colors'}>Target Host</span>

                    {renderSortIcon('asset')}

                  </div>

                </th>

                <th 

                  onClick={() => handleSort('attackerIp')}

                  className="w-[16%] px-2 py-3 cursor-pointer select-none group hover:bg-slate-200/50 dark:hover:bg-slate-800/60 transition-colors"

                  title="Urutkan Attacker IP"

                >

                  <div className="flex items-center gap-1">

                    <span className={sortField === 'attackerIp' ? 'text-blue-600 dark:text-blue-400 font-bold' : 'group-hover:text-slate-900 dark:group-hover:text-white transition-colors'}>Attacker IP</span>

                    {renderSortIcon('attackerIp')}

                  </div>

                </th>

                <th 

                  onClick={() => handleSort('tenant_id')}

                  className="w-[10%] px-2 py-3 text-center cursor-pointer select-none group hover:bg-slate-200/50 dark:hover:bg-slate-800/60 transition-colors"

                  title="Urutkan Tenant"

                >

                  <div className="flex items-center justify-center gap-1">

                    <span className={sortField === 'tenant_id' ? 'text-blue-600 dark:text-blue-400 font-bold' : 'group-hover:text-slate-900 dark:group-hover:text-white transition-colors'}>Tenant</span>

                    {renderSortIcon('tenant_id')}

                  </div>

                </th>

                <th className="w-[5%] px-1 py-3 text-center select-none">

                  <span>Action</span>

                </th>

                <th 

                  onClick={() => handleSort('status')}

                  className="w-[14%] px-2 py-3 text-center cursor-pointer select-none group hover:bg-slate-200/50 dark:hover:bg-slate-800/60 transition-colors"

                  title="Urutkan Status"

                >

                  <div className="flex items-center justify-center gap-1">

                    <span className={sortField === 'status' ? 'text-blue-600 dark:text-blue-400 font-bold' : 'group-hover:text-slate-900 dark:group-hover:text-white transition-colors'}>Status</span>

                    {renderSortIcon('status')}

                  </div>

                </th>

              </tr>

            </thead>

            <tbody className={`divide-y font-sans ${

              isDark ? 'divide-slate-800/60 bg-[#0a0e1a]' : 'divide-slate-100 bg-white'

            }`}>

              {loading && incidents.length === 0 ? (

                <tr>

                  <td colSpan="8" className="px-6 py-20 text-center">

                    <div className="flex flex-col items-center justify-center gap-2.5">

                      <RefreshCw className="w-5 h-5 animate-spin text-blue-500" />

                      <span className={`text-xs font-mono font-medium ${isDark ? 'text-slate-400' : 'text-slate-600'}`}>

                        Memuat data antrian tiket dari database...

                      </span>

                    </div>

                  </td>

                </tr>

              ) : networkError && incidents.length === 0 ? (

                <tr>

                  <td colSpan="8" className="px-6 py-14 text-center">

                    <div className="flex flex-col items-center justify-center gap-2">

                      <AlertTriangle className="w-5 h-5 text-amber-500" />

                      <span className={`text-xs font-mono font-semibold ${isDark ? 'text-amber-400' : 'text-amber-600'}`}>

                        Koneksi ke Backend API terputus. Pastikan FastAPI aktif.

                      </span>

                      <button

                        onClick={fetchQueue}

                        className="mt-2 px-3 py-1 rounded bg-blue-600 hover:bg-blue-500 text-white text-xs font-medium cursor-pointer transition-colors"

                      >

                        Coba Muat Ulang (Retry)

                      </button>

                    </div>

                  </td>

                </tr>

              ) : paginatedIncidents.length === 0 ? (

                <tr>

                  <td colSpan="8" className="px-6 py-14 text-center">

                    <span className={`text-xs font-mono ${isDark ? 'text-slate-500' : 'text-slate-400'}`}>

                      Tidak ada tiket dalam antrian ini.

                    </span>

                  </td>

                </tr>

              ) : (

                paginatedIncidents.map((inc, idx) => {

                const isP0 = inc.priority === 'P0';

                const isP1 = inc.priority === 'P1';

                const prioColor = isP0 

                  ? 'text-rose-500 dark:text-rose-400' 

                  : isP1 

                    ? 'text-orange-500 dark:text-orange-400' 

                    : inc.priority === 'P2' 

                      ? 'text-amber-500 dark:text-amber-400' 

                      : inc.priority === 'P3' 

                        ? 'text-emerald-500 dark:text-emerald-400' 

                        : 'text-sky-500 dark:text-sky-400';



                return (

                  <tr

                    key={inc.id}

                    className={`transition-colors ${

                      isDark ? 'hover:bg-slate-800/30' : 'hover:bg-slate-50/70'

                    }`}

                  >

                    {/* Incident ID only (e.g. TRG-P0-D37B91833145) */}

                    <td className="px-3 py-3 font-mono overflow-hidden">

                      <span 

                        className={`font-bold text-xs tracking-tight ${

                          isDark ? 'text-white hover:text-slate-300' : 'text-black hover:text-slate-700'

                        } cursor-pointer truncate block select-all`}

                        title={inc.title ? `${inc.title} (${inc.id})` : inc.id}

                        onClick={(e) => {

                          e.stopPropagation();

                          handleOpenIncident(inc);

                        }}

                      >

                        {inc.id || inc.triage_id}

                      </span>

                    </td>



                    {/* Priority (Text only, no box/border) */}

                    <td className="px-2 py-3 text-center font-mono">

                      <span className={`text-xs font-bold ${prioColor}`}>

                        {inc.priority}

                      </span>

                    </td>



                    {/* Deadline (waktu tiket muncul + waktu SLA sesuai prioritas 0-4) */}

                    <td className="px-2 py-3 font-mono text-[11px] whitespace-nowrap overflow-hidden">

                      <span className={isDark ? 'text-slate-300' : 'text-slate-600'}>

                        {formatDeadline(inc)}

                      </span>

                    </td>



                    {/* Target Asset */}

                    <td className="px-2 py-3 font-mono overflow-hidden">

                      <div 

                        className={`text-xs font-semibold truncate ${isDark ? 'text-slate-200' : 'text-slate-900'}`}

                        title={inc.asset || '-'}

                      >

                        {inc.asset || '-'}

                      </div>

                    </td>



                    {/* Attacker IP */}

                    <td className="px-2 py-3 font-mono overflow-hidden">

                      <div 

                        className={`text-xs font-mono truncate ${isDark ? 'text-slate-300' : 'text-slate-600'}`}

                        title={inc.attackerIp || '127.0.0.1'}

                      >

                        {inc.attackerIp || '127.0.0.1'}

                      </div>

                    </td>



                    {/* Tenant */}

                    <td className="px-2 py-3 text-center font-mono overflow-hidden">

                      <div 

                        className={`text-xs font-medium truncate ${

                          isDark ? 'text-slate-300' : 'text-slate-600'

                        }`}

                        title={inc.tenant_id || inc.tenant || 'DEFAULT'}

                      >

                        {inc.tenant_id || inc.tenant || 'DEFAULT'}

                      </div>

                    </td>



                    {/* Action Column with Clean Pen Icon (matching referenced image 2) */}

                    <td className="px-1 py-3 text-center">

                      <button

                        type="button"

                        onClick={(e) => {

                          e.stopPropagation();

                          if (viewMode === 'groundtruth') {

                            setGtTicket(inc);

                            setGtVerdict(inc.groundTruthVerdict || 'TRUE_POSITIVE');

                            setGtAnalystId(getLoggedInUsername() || 'soc_analyst_alice');

                            setGtNotes(inc.analystNotes || '');

                            setShowGtModal(true);

                          } else {

                            handlePenClick(e, inc);

                          }

                        }}

                        title={

                          viewMode === 'groundtruth'

                            ? ((inc.ground_truth_status === 'REJECT' || inc.groundTruthStatus === 'REJECT')

                                ? 'Kaji Ulang Justifikasi Ground Truth'

                                : (inc.ground_truth_status === 'APPROVE' || inc.groundTruthStatus === 'APPROVE')

                                ? 'Detail Ground Truth'

                                : (inc.ground_truth_status === 'WAITING' || inc.groundTruthStatus === 'WAITING')

                                ? 'Edit Ground Truth'

                                : 'Isi Justifikasi Ground Truth')

                            : 'Detail Tiket'

                        }

                        className="p-1.5 rounded-lg text-slate-500 hover:text-blue-600 hover:bg-blue-50/80 dark:text-slate-400 dark:hover:text-blue-400 dark:hover:bg-slate-800 transition-all cursor-pointer inline-flex items-center justify-center group/btn mx-auto"

                      >

                        <Pencil className="w-4 h-4 transition-transform group-hover/btn:scale-110" />

                      </button>

                    </td>



                    {/* Status (Badge Box matching user specified colors) */}

                    <td className="px-2 py-3 text-center font-mono whitespace-nowrap">

                      {viewMode === 'groundtruth' ? (

                        (inc.ground_truth_status === 'WAITING' || inc.groundTruthStatus === 'WAITING') ? (

                          <span 

                            className="status-badge inline-flex items-center justify-center whitespace-nowrap px-3 py-1 rounded-md border border-yellow-400 bg-yellow-500 text-slate-950 font-bold text-[11px] tracking-wider uppercase shadow-xs select-none"

                            title="Menunggu validasi SOC Manager di Ground Truth Review."

                          >

                            WAITING

                          </span>

                        ) : (inc.ground_truth_status === 'APPROVE' || inc.groundTruthStatus === 'APPROVE') ? (

                          <span 

                            className="status-badge inline-flex items-center justify-center whitespace-nowrap px-3 py-1 rounded-md border border-emerald-500 bg-emerald-600 text-white font-bold text-[11px] tracking-wider uppercase shadow-xs select-none"

                            title={`Disetujui oleh SOC Manager sebagai ${inc.ground_truth_verdict || inc.groundTruthVerdict || 'Ground Truth'}.`}

                          >

                            APPROVE

                          </span>

                        ) : (inc.ground_truth_status === 'REJECT' || inc.groundTruthStatus === 'REJECT') ? (

                          <span 

                            className="status-badge inline-flex items-center justify-center whitespace-nowrap px-3 py-1 rounded-md border border-red-500 bg-red-600 text-white font-bold text-[11px] tracking-wider uppercase shadow-xs select-none"

                            title="Ditolak oleh SOC Manager."

                          >

                            REJECT

                          </span>

                        ) : (

                          <span 

                            className="status-badge inline-flex items-center justify-center whitespace-nowrap px-3 py-1 rounded-md border border-orange-500 bg-orange-600 text-white font-bold text-[11px] tracking-wider uppercase shadow-xs select-none"

                            title="Butuh Tindakan: Silakan isi justifikasi ground truth."

                          >

                            ACT NEED

                          </span>

                        )

                      ) : normalizeStatus(inc.status, inc.resolution_outcome || inc.resolutionOutcome) === 'GROUNDTRUTH' ? (

                        <span 

                          className="status-badge inline-flex items-center justify-center whitespace-nowrap px-3 py-1 rounded-md border border-orange-500 bg-orange-600 text-white font-bold text-[11px] tracking-wider uppercase shadow-xs select-none cursor-pointer"

                          title="Confidence score AI < 85%. Diteruskan ke Groundtruth untuk verifikasi Human SOC."

                        >

                          GROUNDTRUTH

                        </span>

                      ) : normalizeStatus(inc.status, inc.resolution_outcome || inc.resolutionOutcome) === 'CLOSE' ? (

                        <div className="relative inline-block group/status">

                          <span 

                            className="status-badge inline-flex items-center justify-center whitespace-nowrap px-3 py-1 rounded-md border border-emerald-500 bg-emerald-600 text-white font-bold text-[11px] tracking-wider uppercase shadow-xs cursor-help select-none"

                            title={inc.resolution_outcome === 'TRUE_POSITIVE_ACTIONABLE' ? 'Threat terkonfirmasi (Confidence >= 85%) -> Masuk ke Verified True Positive' : 'Benign (Confidence >= 85%) -> Masuk ke Policy Bundle'}

                          >

                            {inc.resolution_outcome === 'TRUE_POSITIVE_ACTIONABLE' ? 'CLOSE (THREAT)' : 'CLOSE'}

                          </span>

                          {renderCloseSlaTooltip(

                            getCloseSlaDetails(inc),

                            inc.priority,

                            idx >= paginatedIncidents.length - 2 ? 'bottom-full mb-2.5 right-0' : 'top-full mt-2.5 right-0'

                          )}

                        </div>

                      ) : normalizeStatus(inc.status, inc.resolution_outcome || inc.resolutionOutcome) === 'INVESTIGATE' ? (

                        <span 

                          className="status-badge inline-flex items-center justify-center whitespace-nowrap px-3 py-1 rounded-md border border-yellow-400 bg-yellow-500 text-slate-950 font-bold text-[11px] tracking-wider uppercase shadow-xs select-none"

                          title="SLA telah habis & agregat selesai. Sedang dicek oleh AI Triage."

                        >

                          INVESTIGATE

                        </span>

                      ) : (

                        <span 

                          className="status-badge inline-flex items-center justify-center whitespace-nowrap px-3 py-1 rounded-md border border-red-500 bg-red-600 text-white font-bold text-[11px] tracking-wider uppercase shadow-xs select-none"

                          title="Menunggu time window agregat & SLA selesai sebelum AI Triage."

                        >

                          OPEN

                        </span>

                      )}

                    </td>

                  </tr>

                );

              }))}

            </tbody>

          </table>

        </div>



        {/* Pagination Footer */}

        <div className={`p-4 border-t flex items-center justify-between text-xs ${

          isDark ? 'border-slate-800 text-slate-400 bg-[#0a0e1a]' : 'border-slate-200 text-slate-500 bg-[#F0F5FA]/40'

        }`}>

          <div>

            {loading && incidents.length === 0 ? (

              <span className="font-mono text-xs">Memuat data tiket...</span>

            ) : filteredIncidents.length === 0 ? (

              <span className="font-mono text-xs">0 tiket</span>

            ) : (

              <>

                Showing <span className={`font-mono font-semibold ${isDark ? 'text-slate-200' : 'text-slate-700'}`}>{(currentPage - 1) * pageSize + 1}</span> to <span className={`font-mono font-semibold ${isDark ? 'text-slate-200' : 'text-slate-700'}`}>{Math.min(currentPage * pageSize, filteredIncidents.length)}</span> of <span className={`font-mono font-semibold ${isDark ? 'text-slate-200' : 'text-slate-700'}`}>{((selectedPriority === 'ALL' && selectedStatusFilter === 'ALL' && !deferredSearch.trim() && totalServerCount) ? totalServerCount : filteredIncidents.length).toLocaleString()}</span>

              </>

            )}

          </div>

          <div className="flex items-center gap-1.5">

            <button

              onClick={() => setCurrentPage(p => Math.max(1, p - 1))}

              disabled={currentPage === 1}

              className={`px-3 py-1 rounded-lg border text-xs font-semibold transition-all cursor-pointer disabled:opacity-30 disabled:cursor-not-allowed ${

                isDark 

                  ? 'bg-slate-800 border-slate-700 text-slate-300 hover:bg-slate-700' 

                  : 'bg-white border-slate-200 text-slate-700 hover:bg-slate-50 shadow-2xs'

              }`}

            >

              Prev

            </button>

            <span className={`font-mono text-xs px-2 font-medium ${isDark ? 'text-slate-400' : 'text-slate-600'}`}>

              {currentPage} / {totalPages}

            </span>

            <button

              onClick={() => setCurrentPage(p => Math.min(totalPages, p + 1))}

              disabled={currentPage === totalPages}

              className={`px-3 py-1 rounded-lg border text-xs font-semibold transition-all cursor-pointer disabled:opacity-30 disabled:cursor-not-allowed ${

                isDark 

                  ? 'bg-slate-800 border-slate-700 text-slate-300 hover:bg-slate-700' 

                  : 'bg-white border-slate-200 text-slate-700 hover:bg-slate-50 shadow-2xs'

              }`}

            >

              Next

            </button>

          </div>

        </div>

      </div>



      {/* FORENSIC INCIDENT WORKBENCH MODAL (CrowdStrike / Sentinel Inspired) */}

      {selectedIncident && (

        <div className="fixed inset-0 bg-black/80 backdrop-blur-sm z-50 flex items-center justify-center p-3 md:p-6">

          <div className="bg-[#0b0f19] border border-slate-700/80 rounded-xl max-w-6xl w-full shadow-2xl flex flex-col max-h-[92vh] overflow-hidden">

            

            {/* Modal Header */}

            <div className={`p-4 border-b flex items-start justify-between shrink-0 ${

              isDark ? 'border-slate-800 bg-[#090d16]' : 'border-slate-200 bg-white'

            }`}>

              <div className="space-y-1">

                <div className="flex items-center gap-2 flex-wrap">

                  {/* P0 without box */}

                  <span className={`text-xs font-bold font-mono ${

                    selectedIncident.priority === 'P0' ? 'text-rose-500' :

                    selectedIncident.priority === 'P1' ? 'text-orange-500' :

                    selectedIncident.priority === 'P2' ? 'text-amber-500' :

                    selectedIncident.priority === 'P3' ? 'text-emerald-500' :

                    'text-sky-500'

                  }`}>

                    {selectedIncident.priority}

                  </span>

                  <span className="font-mono text-xs text-slate-400 font-semibold">{selectedIncident.id}</span>

                  <span className="text-xs text-slate-400 font-mono ml-1">

                    {selectedIncident.timeAgo ? (selectedIncident.timeAgo.includes('WIB') ? selectedIncident.timeAgo : `${selectedIncident.timeAgo} WIB`) : ''}

                  </span>

                </div>

                <div className={`text-xs font-mono space-y-0.5 pt-0.5 ${isDark ? 'text-slate-400' : 'text-slate-600'}`}>

                  <div className="flex items-center">

                    <span className="w-16 shrink-0">Asset</span>

                    <span className="mr-1.5">:</span>

                    <strong className={isDark ? 'text-slate-200' : 'text-slate-800'}>

                      {selectedIncident.asset}

                    </strong>

                  </div>

                  <div className="flex items-center">

                    <span className="w-16 shrink-0">Attacker</span>

                    <span className="mr-1.5">:</span>

                    <strong className="text-rose-500">

                      {selectedIncident.attackerIp || '127.0.0.1'}

                    </strong>

                  </div>

                </div>

              </div>



              {/* Triage Decision Actions & Status in Top-Right */}

              <div className="flex items-center gap-2.5">

                {/* Status Badge placed at top-right, directly to the left of X */}

                {(() => {

                  const effectiveStatus = normalizeStatus(selectedIncident?.status || selectedIncident?.triage_status);



                  return (

                    <div className="relative inline-block group/status">

                      <span 

                        className={`status-badge px-3 py-1 rounded-md text-xs font-bold font-mono uppercase tracking-wider shadow-xs select-none inline-block ${

                          viewMode === 'groundtruth'

                            ? (selectedIncident.ground_truth_status === 'APPROVE' || selectedIncident.groundTruthStatus === 'APPROVE')

                              ? 'bg-emerald-600 border border-emerald-500 text-white'

                              : (selectedIncident.ground_truth_status === 'REJECT' || selectedIncident.groundTruthStatus === 'REJECT')

                              ? 'bg-red-600 border border-red-500 text-white'

                              : (selectedIncident.ground_truth_status === 'WAITING' || selectedIncident.groundTruthStatus === 'WAITING')

                              ? 'bg-yellow-500 border border-yellow-400 text-slate-950 font-bold'

                              : 'bg-orange-600 border border-orange-500 text-white'

                            : effectiveStatus === 'CLOSE'

                            ? 'bg-emerald-600 border border-emerald-500 text-white cursor-help'

                            : effectiveStatus === 'INVESTIGATE'

                            ? 'bg-yellow-500 border border-yellow-400 text-slate-950 font-bold'

                            : effectiveStatus === 'GROUNDTRUTH'

                            ? 'bg-orange-600 border border-orange-500 text-white'

                            : 'bg-red-600 border border-red-500 text-white'

                        }`}

                      >

                        STATUS: {viewMode === 'groundtruth' || effectiveStatus === 'GROUNDTRUTH' || normalizeStatus(selectedIncident.status) === 'GROUNDTRUTH'
                          ? (selectedIncident.ground_truth_status || selectedIncident.groundTruthStatus || 'ACT NEED') 
                          : effectiveStatus === 'CLOSE' && (selectedIncident.resolution_outcome === 'TRUE_POSITIVE_ACTIONABLE' || mlPrediction?.resolution_outcome === 'TRUE_POSITIVE_ACTIONABLE')
                          ? 'CLOSE (THREAT)'
                          : effectiveStatus}

                      </span>

                      {effectiveStatus === 'CLOSE' && (

                        renderCloseSlaTooltip(getCloseSlaDetails(selectedIncident), selectedIncident.priority, 'top-full mt-2.5 right-0')

                      )}

                    </div>

                  );

                })()}



                {/* Close X Button - no dark box on hover/active */}

                <button

                  type="button"

                  onClick={() => { setSelectedIncident(null); setSelectedAggregateId(null); setSelectedLogId(null); setAggregateLogs([]); }}

                  className="p-1.5 rounded-lg text-slate-400 hover:text-slate-600 dark:hover:text-white transition-colors cursor-pointer border-0 bg-transparent active:bg-transparent focus:outline-none focus:ring-0"

                  title="Tutup Modal"

                >

                  <X className="w-5 h-5" />

                </button>

              </div>

            </div>



            {/* Scrollable Content Body */}

            <div className="flex-1 overflow-y-auto p-4 space-y-4">

              

              {/* Dynamic Risk Score Assessment - Pie Chart & 3-Column Table */}

              <div className={`p-4 border rounded-xl ${

                isDark ? 'bg-[#070b14] border-slate-800/80' : 'bg-white border-slate-200 shadow-2xs'

              }`}>

                <div className="flex items-center justify-between text-xs font-semibold mb-3 border-b border-slate-200 dark:border-slate-800/60 pb-2.5">

                  <span className={`text-sm font-bold tracking-tight ${isDark ? 'text-slate-100' : 'text-slate-900'}`}>

                    Score Assessment

                  </span>

                </div>



                {/* 4-Tier Machine Learning & LLM Cascading Donut Charts (Strictly In 1 Row) */}

                <div className="pt-1 w-full overflow-x-auto">

                  {mlLoading ? (

                    <div className="grid grid-cols-4 gap-2.5 sm:gap-3 w-full min-w-[620px]">

                      {[1, 2, 3, 4].map((i) => (

                        <div 

                          key={i} 

                          className={`p-3.5 rounded-xl border animate-pulse flex flex-col items-center justify-center h-48 ${

                            isDark ? 'bg-slate-900/30 border-slate-800' : 'bg-slate-50 border-slate-200'

                          }`}

                        >

                          <RefreshCw className="w-5 h-5 animate-spin text-indigo-400 mb-2" />

                          <span className="text-[11px] font-mono text-slate-400">Memuat Tier-{i}...</span>

                        </div>

                      ))}

                    </div>

                  ) : (

                    <div className="grid grid-cols-4 gap-2.5 sm:gap-3 w-full min-w-[620px]">

                      {(() => {

                        const tiersList = mlPrediction?.cascading_tiers ? [

                          {

                            id: 'tier1_ml',

                            title: 'Tier-1 ML (LightGBM)',

                            subtitle: 'LightGBM Calibrated',

                            ...mlPrediction.cascading_tiers.tier1_ml

                          },

                          {

                            id: 'tier2_local_llm',

                            title: 'Tier-2 Local LLM',

                            subtitle: 'Qwen / Ollama',

                            ...mlPrediction.cascading_tiers.tier2_local_llm

                          },

                          {

                            id: 'tier3_cloud_llm',

                            title: 'Tier-3 Cloud LLM',

                            subtitle: 'Gemini (Masked)',

                            ...mlPrediction.cascading_tiers.tier3_cloud_llm

                          },

                          {

                            id: 'tier4_soft_voting',

                            title: 'Soft Voting Ensemble',

                            subtitle: 'Local 40% vs Cloud 60%',

                            ...mlPrediction.cascading_tiers.tier4_soft_voting

                          }

                        ] : [

                          {

                            id: 'tier1_ml',

                            title: 'Tier-1 ML (LightGBM)',

                            subtitle: 'LightGBM Calibrated',

                            active: true,

                            verdict: mlPrediction?.verdict || (selectedIncident?.isVerifiedTruePositive || selectedIncident?.resolutionOutcome === 'TRUE_POSITIVE_ACTIONABLE' ? 'THREAT' : 'BENIGN'),

                            confidence: mlPrediction?.confidence || 100,

                            threat_pct: mlPrediction?.threat_probability ?? (selectedIncident?.isVerifiedTruePositive || selectedIncident?.resolutionOutcome === 'TRUE_POSITIVE_ACTIONABLE' ? 100 : 0),

                            benign_pct: mlPrediction?.benign_probability ?? (selectedIncident?.isVerifiedTruePositive || selectedIncident?.resolutionOutcome === 'TRUE_POSITIVE_ACTIONABLE' ? 0 : 100)

                          },

                          {

                            id: 'tier2_local_llm',

                            title: 'Tier-2 Local LLM',

                            subtitle: 'Qwen / Ollama',

                            active: Boolean(mlPrediction?.tier2_local_llm?.verdict),

                            verdict: mlPrediction?.tier2_local_llm?.verdict || 'NONE',

                            confidence: mlPrediction?.tier2_local_llm?.confidence,

                            threat_pct: mlPrediction?.tier2_local_llm?.verdict === 'THREAT' ? mlPrediction?.tier2_local_llm?.confidence : 0,

                            benign_pct: mlPrediction?.tier2_local_llm?.verdict === 'BENIGN' ? mlPrediction?.tier2_local_llm?.confidence : 0

                          },

                          {

                            id: 'tier3_cloud_llm',

                            title: 'Tier-3 Cloud LLM',

                            subtitle: 'Gemini (Masked)',

                            active: false,

                            verdict: 'NONE',

                            confidence: null,

                            threat_pct: 0,

                            benign_pct: 0

                          },

                          {

                            id: 'tier4_soft_voting',

                            title: 'Soft Voting Ensemble',

                            subtitle: 'Local 40% vs Cloud 60%',

                            active: false,

                            verdict: 'NONE',

                            confidence: null,

                            threat_pct: 0,

                            benign_pct: 0

                          }

                        ];



                        return tiersList.map((tier) => {

                          const isTierActive = Boolean(tier.active);

                          const threatVal = Math.round(Number(tier.threat_pct || 0));

                          const benignVal = Math.round(Number(tier.benign_pct || 0));

                          const confVal = tier.confidence != null ? Math.round(Number(tier.confidence)) : Math.max(threatVal, benignVal);



                          const pieData = isTierActive

                            ? [

                                { name: 'Threat', value: Math.max(0, threatVal), color: '#ef4444' },

                                { name: 'Benign', value: Math.max(0, benignVal), color: '#10b981' }

                              ]

                            : [

                                { name: 'Inactive', value: 100, color: isDark ? '#1e293b' : '#cbd5e1' }

                              ];



                          return (

                            <div

                              key={tier.id}

                              className={`p-3 rounded-xl border flex flex-col justify-between transition-all ${

                                isTierActive

                                  ? (isDark 

                                      ? 'bg-slate-900/50 border-slate-700/80 shadow-xs ring-1 ring-white/5' 

                                      : 'bg-white border-slate-200 shadow-xs ring-1 ring-slate-950/5')

                                  : (isDark 

                                      ? 'bg-slate-950/30 border-slate-800/40 opacity-50' 

                                      : 'bg-slate-50/50 border-slate-200/60 opacity-55')

                              }`}

                            >

                              {/* Top Header */}

                              <div className="flex items-center justify-between gap-1 mb-1">

                                <div className="min-w-0 pr-1">

                                  <span className={`text-[11px] font-bold block truncate ${

                                    isTierActive 

                                      ? (isDark ? 'text-slate-100' : 'text-slate-900') 

                                      : (isDark ? 'text-slate-500' : 'text-slate-400')

                                  }`}>

                                    {tier.title}

                                  </span>

                                  <span className="text-[9px] text-slate-400 font-mono block truncate">

                                    {tier.subtitle}

                                  </span>

                                </div>



                                {/* Status Badge */}

                                <span className={`px-1.5 py-0.5 rounded-full text-[8.5px] font-mono font-bold tracking-wide uppercase shrink-0 ${

                                  isTierActive

                                    ? (tier.verdict === 'THREAT'

                                        ? 'bg-rose-500/20 text-rose-400 border border-rose-500/30'

                                        : tier.verdict === 'BENIGN'

                                        ? 'bg-emerald-500/20 text-emerald-400 border border-emerald-500/30'

                                        : 'bg-amber-500/20 text-amber-400 border border-amber-500/30')

                                    : (isDark 

                                        ? 'bg-slate-800/70 text-slate-500 border border-slate-700/50' 

                                        : 'bg-slate-200/70 text-slate-400 border border-slate-300/60')

                                }`}>

                                  {isTierActive ? (tier.verdict || 'ACTIVE') : 'NONE'}

                                </span>

                              </div>



                              {/* Donut Chart with Center Text */}

                              <div className="w-full h-32 relative flex items-center justify-center my-0.5">

                                <ResponsiveContainer width="100%" height="100%">

                                  <PieChart>

                                    <Pie

                                      data={pieData}

                                      cx="50%"

                                      cy="50%"

                                      innerRadius={30}

                                      outerRadius={45}

                                      startAngle={90}

                                      endAngle={-270}

                                      dataKey="value"

                                      stroke="none"

                                      paddingAngle={isTierActive && threatVal > 0 && benignVal > 0 ? 3 : 0}

                                      isAnimationActive={false}

                                    >

                                      {pieData.map((entry, index) => (

                                        <Cell key={`cell-${index}`} fill={entry.color} stroke="none" />

                                      ))}

                                    </Pie>

                                  </PieChart>

                                </ResponsiveContainer>



                                {/* Center Metric inside Donut */}

                                <div className="absolute inset-0 flex flex-col items-center justify-center pointer-events-none">

                                  {isTierActive ? (

                                    <>

                                      <span className={`text-base font-black font-mono tracking-tight ${

                                        threatVal > benignVal ? 'text-rose-500' : 'text-emerald-500'

                                      }`}>

                                        {confVal}%

                                      </span>

                                      <span className="text-[8px] font-mono uppercase tracking-wider text-slate-400 font-bold">

                                        CONF

                                      </span>

                                    </>

                                  ) : (

                                    <>

                                      <span className="text-xs font-bold font-mono tracking-wider text-slate-500 dark:text-slate-500">

                                        NONE

                                      </span>

                                      <span className="text-[7.5px] font-mono uppercase tracking-wider text-slate-400/60">

                                        INACTIVE

                                      </span>

                                    </>

                                  )}

                                </div>

                              </div>



                              {/* Footer / Legend */}

                              <div className={`mt-1.5 pt-1.5 border-t ${

                                isDark ? 'border-slate-800/70' : 'border-slate-100'

                              }`}>

                                {isTierActive ? (

                                  <div className="flex items-center justify-between text-[10px] font-mono px-0.5">

                                    <span className="text-rose-500 font-bold flex items-center gap-1">

                                      <span className="w-1.5 h-1.5 rounded-full bg-rose-500 shrink-0 inline-block" />

                                      Threat: {threatVal}%

                                    </span>

                                    <span className="text-emerald-500 font-bold flex items-center gap-1">

                                      <span className="w-1.5 h-1.5 rounded-full bg-emerald-500 shrink-0 inline-block" />

                                      Benign: {benignVal}%

                                    </span>

                                  </div>

                                ) : (

                                  <div className="text-center text-[9.5px] font-mono text-slate-400 py-0.5">

                                    Bypassed / Not Cascaded

                                  </div>

                                )}

                              </div>

                            </div>

                          );

                        });

                      })()}

                    </div>

                  )}

                </div>

              </div>



              {/* Related Aggregated Alerts (Level 2) */}

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

                    <RefreshCw className="w-4 h-4 animate-spin" /> Memuat data agregat...

                  </div>

                ) : (

                  <div className="grid grid-cols-1 md:grid-cols-3 gap-2">

                    {aggregates.map((agg) => {

                      const isSelected = agg.aggregation_id === selectedAggregateId;

                      return (

                        <div

                          key={agg.aggregation_id}

                          onClick={() => fetchAggregateLogs(agg.aggregation_id)}

                          className={`p-3 rounded-lg border text-xs transition-all cursor-pointer ${

                            isSelected

                              ? (isDark ? 'bg-slate-800/90 border-slate-600 text-white' : 'bg-slate-100 border-slate-300 shadow-xs')

                              : (isDark ? 'bg-[#070b14] border-slate-800/80 hover:border-slate-700 text-slate-300' : 'bg-white border-slate-200 hover:border-slate-300 shadow-2xs')

                          }`}

                        >

                          <div className="flex items-center justify-between mb-1">

                            <div className="flex items-center gap-1.5 flex-wrap">

                              <span 

                                className={`font-mono font-bold text-[11px] ${

                                  isDark ? 'text-white' : 'text-black'

                                }`}

                                style={{ color: isDark ? '#FFFFFF' : '#000000' }}

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







              {/* Full Raw Log Evidence Inspector (Level 3) */}

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

                      <RefreshCw className="w-3.5 h-3.5 animate-spin" /> Loading raw telemetry payload...

                    </div>

                  ) : filteredLogs.length === 0 ? (

                    <div className="p-4 text-center text-slate-400">

                      No raw logs found matching search criteria.

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

                              Host: {log.agent_name || selectedIncident?.asset || 'Local Agent'}

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

      )}



      {/* FALSE POSITIVE / SUPPRESSION CREATION MODAL */}

      {showFpModal && (

        <div className="fixed inset-0 bg-black/60 backdrop-blur-xs z-50 flex items-center justify-center p-4">

          <div className={`${isDark ? 'bg-[#0b0f19] border-slate-800 text-slate-100' : 'bg-white border-slate-200 text-slate-800'} border rounded-2xl max-w-2xl w-full p-6 shadow-2xl space-y-4 max-h-[90vh] overflow-y-auto`}>

            {/* Modal Header */}

            <div className={`flex items-center justify-between border-b pb-3 ${isDark ? 'border-slate-800' : 'border-slate-200'}`}>

              <h3 className={`text-base font-bold ${isDark ? 'text-white' : 'text-slate-900'}`}>

                Formulir Supresi False Positive

              </h3>

              <button 

                type="button" 

                onClick={() => setShowFpModal(false)} 

                className={`p-1 rounded-md transition-colors cursor-pointer ${isDark ? 'text-slate-400 hover:text-white hover:bg-slate-800' : 'text-slate-400 hover:text-slate-800 hover:bg-slate-100'}`}

              >

                <X className="w-5 h-5" />

              </button>

            </div>



            <form onSubmit={handleApplySuppressionAndFp} className="space-y-4 text-xs">

              {/* BAGIAN A: KONTEKS OTOMATIS */}

              <div className={`p-4 rounded-xl border ${isDark ? 'bg-[#090d16] border-slate-800' : 'bg-slate-50/80 border-slate-200'} space-y-2.5`}>

                <span className={`text-[11px] font-bold uppercase tracking-wider block ${isDark ? 'text-slate-300' : 'text-slate-900'}`}>

                  Bagian A — Konteks Otomatis (Auto-Filled)

                </span>

                <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-2.5 pt-1 text-xs">

                  <div className={`p-2.5 rounded-lg border ${isDark ? 'bg-[#0c101c] border-slate-800' : 'bg-white border-slate-200'}`}>

                    <span className={`text-[10px] font-semibold block uppercase mb-1 ${isDark ? 'text-slate-400' : 'text-slate-700'}`}>Suppression ID</span>

                    <span className={`font-mono font-bold block break-all ${isDark ? 'text-white' : 'text-black'}`}>{fpSuppressionId || 'SUP-2026-AUTO'}</span>

                  </div>

                  <div className={`p-2.5 rounded-lg border ${isDark ? 'bg-[#0c101c] border-slate-800' : 'bg-white border-slate-200'}`}>

                    <span className={`text-[10px] font-semibold block uppercase mb-1 ${isDark ? 'text-slate-400' : 'text-slate-700'}`}>Ref Ticket ID</span>

                    <span className={`font-mono font-bold block break-all ${isDark ? 'text-white' : 'text-black'}`}>{fpRefTicket || '-'}</span>

                  </div>

                  <div className={`p-2.5 rounded-lg border ${isDark ? 'bg-[#0c101c] border-slate-800' : 'bg-white border-slate-200'}`}>

                    <span className={`text-[10px] font-semibold block uppercase mb-1 ${isDark ? 'text-slate-400' : 'text-slate-700'}`}>Aggregation ID</span>

                    <span className={`font-mono font-bold block break-all ${isDark ? 'text-white' : 'text-black'}`}>{fpAggId || '-'}</span>

                  </div>

                  <div className={`p-2.5 rounded-lg border ${isDark ? 'bg-[#0c101c] border-slate-800' : 'bg-white border-slate-200'}`}>

                    <span className={`text-[10px] font-semibold block uppercase mb-1 ${isDark ? 'text-slate-400' : 'text-slate-700'}`}>Current Risk</span>

                    <span className={`font-mono font-bold block ${isDark ? 'text-white' : 'text-black'}`}>{fpCurrentRisk} / 100</span>

                  </div>

                </div>

              </div>



              {/* BAGIAN B: TARGET SCOPE */}

              <div className={`p-4 rounded-xl border ${isDark ? 'bg-[#090d16] border-slate-800' : 'bg-slate-50/80 border-slate-200'} space-y-3`}>

                <span className={`text-[11px] font-bold uppercase tracking-wider block ${isDark ? 'text-slate-300' : 'text-slate-900'}`}>

                  Bagian B — Target Scope (Mencocokkan Format Agregat)

                </span>

                <div>

                  <label className={`block font-semibold mb-1 text-xs ${isDark ? 'text-slate-300' : 'text-slate-800'}`}>Nama Kebijakan Supresi</label>

                  <input

                    type="text"

                    required

                    value={fpRuleName}

                    onChange={(e) => setFpRuleName(e.target.value)}

                    className={`w-full rounded-lg px-3.5 py-2 border transition-colors focus:outline-none ${

                      isDark 

                        ? 'bg-[#0c101c] border-slate-700 text-white focus:border-slate-500' 

                        : 'bg-white border-slate-300 text-slate-900 focus:border-slate-500'

                    }`}

                  />

                </div>

                <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">

                  <div>

                    <label className={`block font-semibold mb-1 text-xs ${isDark ? 'text-slate-300' : 'text-slate-800'}`}>Wazuh Rule IDs (Pisahkan koma)</label>

                    <input

                      type="text"

                      required

                      value={fpSids}

                      onChange={(e) => setFpSids(e.target.value)}

                      placeholder="Misal: 5710, 31101"

                      className={`w-full font-mono rounded-lg px-3.5 py-2 border transition-colors focus:outline-none ${

                        isDark 

                          ? 'bg-[#0c101c] border-slate-700 text-white focus:border-slate-500' 

                          : 'bg-white border-slate-300 text-slate-900 focus:border-slate-500'

                      }`}

                    />

                  </div>

                  <div>

                    <label className={`block font-semibold mb-1 text-xs ${isDark ? 'text-slate-300' : 'text-slate-800'}`}>Kategori Event</label>

                    <select

                      value={fpCategory}

                      onChange={(e) => setFpCategory(e.target.value)}

                      className={`w-full rounded-lg px-3.5 py-2 border transition-colors focus:outline-none ${

                        isDark 

                          ? 'bg-[#0c101c] border-slate-700 text-white focus:border-slate-500' 

                          : 'bg-white border-slate-300 text-slate-900 focus:border-slate-500'

                      }`}

                    >

                      <option value="AUTH_FAILURE">AUTH_FAILURE</option>

                      <option value="AUTH_SUCCESS">AUTH_SUCCESS</option>

                      <option value="CLOUD_CONTAINER">CLOUD_CONTAINER</option>

                      <option value="COMMAND_AND_CONTROL">COMMAND_AND_CONTROL</option>

                      <option value="CONFIGURATION_ASSESSMENT">CONFIGURATION_ASSESSMENT</option>

                      <option value="CREDENTIAL_ACCESS">CREDENTIAL_ACCESS</option>

                      <option value="DEFENSE_EVASION">DEFENSE_EVASION</option>

                      <option value="DISCOVERY">DISCOVERY</option>

                      <option value="EXECUTION">EXECUTION</option>

                      <option value="EXFILTRATION">EXFILTRATION</option>

                      <option value="FILE_INTEGRITY">FILE_INTEGRITY</option>

                      <option value="INITIAL_ACCESS">INITIAL_ACCESS</option>

                      <option value="LATERAL_MOVEMENT">LATERAL_MOVEMENT</option>

                      <option value="MALWARE">MALWARE</option>

                      <option value="OTHER">OTHER</option>

                      <option value="PERSISTENCE">PERSISTENCE</option>

                      <option value="PRIVILEGE_ESCALATION">PRIVILEGE_ESCALATION</option>

                      <option value="RANSOMWARE">RANSOMWARE</option>

                      <option value="SYSTEM_HEALTH">SYSTEM_HEALTH</option>

                      <option value="VULNERABILITY">VULNERABILITY</option>

                      <option value="WEB_ATTACK">WEB_ATTACK</option>

                      <option value="WEB_OPERATIONAL">WEB_OPERATIONAL</option>

                    </select>

                  </div>

                </div>

                <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">

                  <div>

                    <label className={`block font-semibold mb-1 text-xs ${isDark ? 'text-slate-300' : 'text-slate-800'}`}>Actor / Source IP</label>

                    <input

                      type="text"

                      value={fpActor}

                      onChange={(e) => setFpActor(e.target.value)}

                      placeholder="Semua / Kosong"

                      className={`w-full font-mono rounded-lg px-3 py-2 border transition-colors focus:outline-none ${

                        isDark 

                          ? 'bg-[#0c101c] border-slate-700 text-white focus:border-slate-500' 

                          : 'bg-white border-slate-300 text-slate-900 focus:border-slate-500'

                      }`}

                    />

                  </div>

                  <div>

                    <label className={`block font-semibold mb-1 text-xs ${isDark ? 'text-slate-300' : 'text-slate-800'}`}>Target Host / Agent</label>

                    <input

                      type="text"

                      value={fpTarget}

                      onChange={(e) => setFpTarget(e.target.value)}

                      placeholder="Semua / Kosong"

                      className={`w-full font-mono rounded-lg px-3 py-2 border transition-colors focus:outline-none ${

                        isDark 

                          ? 'bg-[#0c101c] border-slate-700 text-white focus:border-slate-500' 

                          : 'bg-white border-slate-300 text-slate-900 focus:border-slate-500'

                      }`}

                    />

                  </div>

                  <div>

                    <label className={`block font-semibold mb-1 text-xs ${isDark ? 'text-slate-300' : 'text-slate-800'}`}>Username Spesifik</label>

                    <input

                      type="text"

                      value={fpUsername}

                      onChange={(e) => setFpUsername(e.target.value)}

                      placeholder="Semua / Kosong"

                      className={`w-full font-mono rounded-lg px-3 py-2 border transition-colors focus:outline-none ${

                        isDark 

                          ? 'bg-[#0c101c] border-slate-700 text-white focus:border-slate-500' 

                          : 'bg-white border-slate-300 text-slate-900 focus:border-slate-500'

                      }`}

                    />

                  </div>

                </div>

              </div>



              {/* BAGIAN C: SAFETY CEILINGS */}

              <div className={`p-4 rounded-xl border ${isDark ? 'bg-[#090d16] border-slate-800' : 'bg-slate-50/80 border-slate-200'} space-y-3`}>

                <span className={`text-[11px] font-bold uppercase tracking-wider block ${isDark ? 'text-slate-300' : 'text-slate-900'}`}>

                  Bagian C — Safety Ceilings (Pagar Pengaman Anti-Evasion)

                </span>

                <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 pt-1">

                  <div>

                    <label className={`block font-semibold mb-1 text-xs ${isDark ? 'text-slate-300' : 'text-slate-800'}`}>Max Event Threshold (max_count)</label>

                    <input

                      type="number"

                      required

                      min="1"

                      value={fpMaxCount}

                      onChange={(e) => setFpMaxCount(e.target.value)}

                      className={`w-full font-mono rounded-lg px-3.5 py-2 border transition-colors focus:outline-none ${

                        isDark 

                          ? 'bg-[#0c101c] border-slate-700 text-white focus:border-slate-500' 

                          : 'bg-white border-slate-300 text-slate-900 focus:border-slate-500'

                      }`}

                    />

                    <span className="text-[10px] text-slate-500 mt-1 block">Supresi gugur jika burst volume melampaui angka ini (DoS guard).</span>

                  </div>

                  <div>

                    <label className={`block font-semibold mb-1 text-xs ${isDark ? 'text-slate-300' : 'text-slate-800'}`}>Max Allowed Risk Score (max_risk)</label>

                    <input

                      type="number"

                      required

                      min="0"

                      max="100"

                      value={fpMaxRiskScore}

                      onChange={(e) => setFpMaxRiskScore(e.target.value)}

                      className={`w-full font-mono rounded-lg px-3.5 py-2 border transition-colors focus:outline-none ${

                        isDark 

                          ? 'bg-[#0c101c] border-slate-700 text-white focus:border-slate-500' 

                          : 'bg-white border-slate-300 text-slate-900 focus:border-slate-500'

                      }`}

                    />

                    <span className="text-[10px] text-slate-500 mt-1 block">Supresi gugur jika event membawa risiko lebih tinggi (Exploit guard).</span>

                  </div>

                </div>

              </div>



              {/* BAGIAN D: TATA KELOLA & 4-EYES APPROVAL */}

              <div className={`p-4 rounded-xl border ${isDark ? 'bg-[#090d16] border-slate-800' : 'bg-slate-50/80 border-slate-200'} space-y-3`}>

                <span className={`text-[11px] font-bold uppercase tracking-wider block ${isDark ? 'text-slate-300' : 'text-slate-900'}`}>

                  Bagian D — Tata Kelola & 4-Eyes Approval

                </span>

                <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">

                  <div>

                    <label className={`block font-semibold mb-1 text-xs ${isDark ? 'text-slate-300' : 'text-slate-800'}`}>Klasifikasi Supresi</label>

                    <select

                      value={fpClass}

                      onChange={(e) => setFpClass(e.target.value)}

                      className={`w-full rounded-lg px-3.5 py-2 border transition-colors focus:outline-none ${

                        isDark 

                          ? 'bg-[#0c101c] border-slate-700 text-white focus:border-slate-500' 

                          : 'bg-white border-slate-300 text-slate-900 focus:border-slate-500'

                      }`}

                    >

                      <option value="S2_FALSE_POSITIVE">S2_FALSE_POSITIVE (Maks 90 Hari)</option>

                      <option value="S1_KNOWN_GOOD">S1_KNOWN_GOOD (Maks 180 Hari)</option>

                      <option value="S3_MAINTENANCE">S3_MAINTENANCE (Maks 90 Hari)</option>

                      <option value="S4_EXCEPTION">S4_EXCEPTION (Maks 30 Hari)</option>

                      <option value="S5_CONDITIONAL">S5_CONDITIONAL (Maks 90 Hari)</option>

                    </select>

                  </div>

                  <div>

                    <label className={`block font-semibold mb-1 text-xs ${isDark ? 'text-slate-300' : 'text-slate-800'}`}>Masa Berlaku (SLA Limit)</label>

                    <input

                      type="date"

                      required

                      value={fpExpiration}

                      onChange={(e) => setFpExpiration(e.target.value)}

                      className={`w-full font-mono rounded-lg px-3.5 py-2 border transition-colors focus:outline-none ${

                        isDark 

                          ? 'bg-[#0c101c] border-slate-700 text-white focus:border-slate-500' 

                          : 'bg-white border-slate-300 text-slate-900 focus:border-slate-500'

                      }`}

                    />

                  </div>

                </div>



                <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">

                  <div>

                    <label className={`block font-semibold mb-1 text-xs ${isDark ? 'text-slate-300' : 'text-slate-800'}`}>Pembuat (Analyst Author)</label>

                    <input

                      type="text"

                      readOnly

                      value={fpOwner}

                      className={`w-full rounded-lg px-3.5 py-2 border transition-colors focus:outline-none cursor-not-allowed select-none ${

                        isDark 

                          ? 'bg-slate-900/80 border-slate-800 text-slate-300' 

                          : 'bg-slate-100 border-slate-300 text-slate-700'

                      }`}

                      title="Diisi otomatis sesuai akun yang mengajukan proposal (tidak dapat diedit)"

                    />

                  </div>

                  <div>

                    <label className={`block font-semibold mb-1 text-xs ${isDark ? 'text-slate-300' : 'text-slate-800'}`}>Penyetuju (SOC Lead Approver)</label>

                    <input

                      type="text"

                      readOnly

                      value={fpApprover}

                      placeholder="Dikosongkan (diisi otomatis saat diproses di Ground Truth Review)"

                      className={`w-full rounded-lg px-3.5 py-2 border transition-colors focus:outline-none cursor-not-allowed select-none ${

                        isDark 

                          ? 'bg-slate-900/80 border-slate-800 text-slate-300 placeholder:text-slate-500' 

                          : 'bg-slate-100 border-slate-300 text-slate-700 placeholder:text-slate-400'

                      }`}

                      title="Dikosongkan saat pengajuan, diisi otomatis saat diproses di Ground Truth Review (tidak dapat diedit)"

                    />

                  </div>

                </div>



                <div>

                  <label className={`block font-semibold mb-1 text-xs ${isDark ? 'text-slate-300' : 'text-slate-800'}`}>Justifikasi Bisnis & Forensik</label>

                  <textarea

                    rows="2"

                    required

                    value={fpReason}

                    onChange={(e) => setFpReason(e.target.value)}

                    placeholder="Alasan teknis terverifikasi (misal: Sesuai Change Request CRQ-2026-9041)..."

                    className={`w-full rounded-lg px-3.5 py-2 border transition-colors focus:outline-none ${

                      isDark 

                        ? 'bg-[#0c101c] border-slate-700 text-white focus:border-slate-500' 

                        : 'bg-white border-slate-300 text-slate-900 focus:border-slate-500'

                    }`}

                  ></textarea>

                </div>

              </div>



              {/* Action Buttons */}

              <div className={`flex items-center justify-end gap-2.5 pt-3 border-t ${isDark ? 'border-slate-800' : 'border-slate-200'}`}>

                <button

                  type="button"

                  onClick={() => setShowFpModal(false)}

                  className="px-4 py-2 rounded-lg bg-rose-600 hover:bg-rose-500 text-white text-xs font-semibold cursor-pointer flex items-center gap-1.5 transition-colors shadow-xs"

                >

                  <X className="w-3.5 h-3.5" />

                  <span>Reject</span>

                </button>

                <button

                  type="submit"

                  disabled={submittingFp}

                  className="px-5 py-2 rounded-lg bg-emerald-600 hover:bg-emerald-500 text-white font-semibold text-xs flex items-center gap-1.5 shadow-xs cursor-pointer transition-colors"

                >

                  {submittingFp ? <RefreshCw className="w-3.5 h-3.5 animate-spin" /> : <Check className="w-3.5 h-3.5" />}

                  <span>Approve</span>

                </button>

              </div>

            </form>

          </div>

        </div>

      )}



      {/* GROUND TRUTH TRIAGE & JUSTIFICATION MODAL */}

      {showGtModal && gtTicket && (

        <div className="fixed inset-0 bg-black/70 backdrop-blur-sm z-50 flex items-center justify-center p-4">

          <div className={`${isDark ? 'bg-[#0b0f19] border-slate-700/80 text-slate-100' : 'bg-white border-slate-200 text-slate-800'} border rounded-2xl max-w-xl w-full p-6 shadow-2xl space-y-4 max-h-[92vh] overflow-y-auto animate-in fade-in zoom-in-95`}>

            {/* Modal Header */}

            <div className={`flex items-center justify-between border-b pb-3 ${isDark ? 'border-slate-800' : 'border-slate-200'}`}>

              <div className="flex items-center gap-2.5">

                <div className="p-2 rounded-lg bg-indigo-500/10 border border-indigo-500/30 text-indigo-400">

                  <Brain className="w-5 h-5" />

                </div>

                <div>

                  <h3 className={`text-base font-bold ${isDark ? 'text-white' : 'text-slate-900'}`}>

                    Triage Justifikasi Ground Truth

                  </h3>

                  <p className="text-[11px] text-slate-400">

                    Tiket {gtTicket.id || gtTicket.triage_id} • AI Confidence &lt; 85%

                  </p>

                </div>

              </div>

              <button 

                type="button" 

                onClick={() => { setShowGtModal(false); setGtTicket(null); }} 

                className={`p-1.5 rounded-lg transition-colors cursor-pointer ${isDark ? 'text-slate-400 hover:text-white hover:bg-slate-800' : 'text-slate-500 hover:text-slate-800 hover:bg-slate-100'}`}

              >

                <X className="w-5 h-5" />

              </button>

            </div>



            {/* Context Card */}

            <div className={`p-3.5 rounded-xl border text-xs space-y-2 ${isDark ? 'bg-slate-900/60 border-slate-800' : 'bg-slate-50 border-slate-200'}`}>

              <div className="flex items-center justify-between">

                <span className={`font-mono font-semibold text-[11px] px-2 py-0.5 rounded border ${

                  gtTicket.priority === 'P0' ? 'bg-red-500/10 text-red-400 border-red-500/30' :

                  gtTicket.priority === 'P1' ? 'bg-orange-500/10 text-orange-400 border-orange-500/30' :

                  gtTicket.priority === 'P2' ? 'bg-amber-500/10 text-amber-400 border-amber-500/30' :

                  'bg-blue-500/10 text-blue-400 border-blue-500/30'

                }`}>

                  {gtTicket.priority} • Risk: {gtTicket.score ?? 50}/100

                </span>

                <span className="text-[11px] text-amber-400 font-semibold flex items-center gap-1">

                  <AlertCircle className="w-3.5 h-3.5" /> AI Inconclusive (&lt; 85%)

                </span>

              </div>

              <div className={`font-semibold line-clamp-2 ${isDark ? 'text-slate-200' : 'text-slate-800'}`}>

                {gtTicket.title || gtTicket.judul_insiden}

              </div>

              <div className="grid grid-cols-2 gap-2 pt-1 font-mono text-[11px] text-slate-400">

                <div>Host: <span className={isDark ? 'text-slate-200' : 'text-slate-700'}>{gtTicket.asset || gtTicket.target_host || '-'}</span></div>

                <div>Attacker IP: <span className={isDark ? 'text-slate-200' : 'text-slate-700'}>{gtTicket.attackerIp || gtTicket.attacker_source_ip || '127.0.0.1'}</span></div>

              </div>

            </div>



            {/* Rejection Notice if Status is REJECT */}

            {(gtTicket.ground_truth_status === 'REJECT' || gtTicket.groundTruthStatus === 'REJECT') && (

              <div className="p-3.5 rounded-xl bg-rose-500/10 border border-rose-500/30 text-xs space-y-1.5 animate-fadeIn">

                <div className="flex items-center gap-1.5 font-bold text-rose-400">

                  <AlertTriangle className="w-4 h-4 shrink-0 text-rose-400" />

                  <span>Catatan Penolakan oleh SOC Manager ({gtTicket.managerReviewer || 'Manager'}):</span>

                </div>

                <p className="text-[11px] text-rose-200/90 pl-5.5 leading-relaxed italic bg-rose-950/30 p-2 rounded-lg border border-rose-500/20">

                  "{gtTicket.managerReviewNotes || gtTicket.manager_review_notes || gtTicket.falsePositiveReason || 'Mohon kaji ulang bukti indikasi dan justifikasi forensik.'}"

                </p>

                <p className="text-[10px] text-rose-300/70 pl-5.5">

                  Silakan perbaiki keputusan (verdict) dan catatan justifikasi di bawah untuk diajukan kembali ke Ground Truth Review.

                </p>

              </div>

            )}



            <form onSubmit={handleSubmitGroundTruth} className="space-y-4 text-xs">

              {/* Verdict Selection */}

              <div>

                <label className={`block font-semibold mb-2 text-xs ${isDark ? 'text-slate-200' : 'text-slate-800'}`}>

                  Keputusan Ground Truth (Verdict Analis) <span className="text-red-400">*</span>

                </label>

                <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">

                  <button

                    type="button"

                    onClick={() => setGtVerdict('TRUE_POSITIVE')}

                    className={`p-3 rounded-xl border text-left transition-all cursor-pointer ${

                      gtVerdict === 'TRUE_POSITIVE'

                        ? 'bg-rose-500/15 border-rose-500 ring-1 ring-rose-500 shadow-xs'

                        : isDark ? 'bg-slate-900/40 border-slate-800 hover:border-slate-700' : 'bg-white border-slate-200 hover:border-slate-300'

                    }`}

                  >

                    <div className="flex items-center justify-between mb-1">

                      <span className="font-bold text-rose-400 text-xs">THREAT</span>

                      <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-rose-500/20 text-rose-300">True Positive</span>

                    </div>

                    <p className="text-[11px] text-slate-400 leading-relaxed">

                      Indikasi serangan nyata. Jika disetujui Manager, otomatis masuk ke <strong>Verified Threat</strong>.

                    </p>

                  </button>



                  <button

                    type="button"

                    onClick={() => setGtVerdict('FALSE_POSITIVE')}

                    className={`p-3 rounded-xl border text-left transition-all cursor-pointer ${

                      gtVerdict === 'FALSE_POSITIVE'

                        ? 'bg-emerald-500/15 border-emerald-500 ring-1 ring-emerald-500 shadow-xs'

                        : isDark ? 'bg-slate-900/40 border-slate-800 hover:border-slate-700' : 'bg-white border-slate-200 hover:border-slate-300'

                    }`}

                  >

                    <div className="flex items-center justify-between mb-1">

                      <span className="font-bold text-emerald-400 text-xs">BENIGN</span>

                      <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-emerald-500/20 text-emerald-300">False Positive</span>

                    </div>

                    <p className="text-[11px] text-slate-400 leading-relaxed">

                      Aktivitas sah / gangguan rutin. Jika disetujui Manager, otomatis masuk ke <strong>Policy Bundle</strong>.

                    </p>

                  </button>

                </div>

              </div>



              {/* Analyst ID */}

              <div>

                <label className={`block font-semibold mb-1 text-xs ${isDark ? 'text-slate-300' : 'text-slate-700'}`}>

                  Nama Analis SOC

                </label>

                <input

                  type="text"

                  required

                  value={gtAnalystId}

                  onChange={(e) => setGtAnalystId(e.target.value)}

                  className={`w-full font-mono rounded-lg px-3 py-2 border transition-colors focus:outline-none ${

                    isDark ? 'bg-slate-900 border-slate-700 text-white focus:border-indigo-500' : 'bg-white border-slate-300 text-slate-900 focus:border-indigo-600'

                  }`}

                />

              </div>



              {/* Justification Notes */}

              <div>

                <label className={`block font-semibold mb-1 text-xs ${isDark ? 'text-slate-300' : 'text-slate-700'}`}>

                  Justifikasi & Catatan Analis {(gtTicket.ground_truth_status === 'REJECT' || gtTicket.groundTruthStatus === 'REJECT') && '(Revisi Kaji Ulang)'} <span className="text-red-400">*</span>

                </label>

                <textarea

                  required

                  rows={4}

                  value={gtNotes}

                  onChange={(e) => setGtNotes(e.target.value)}

                  placeholder="Jelaskan alasan penetapan keputusan ini (analisis payload, verifikasi origin IP, atau jadwal maintenance)..."

                  className={`w-full rounded-lg px-3 py-2 border transition-colors focus:outline-none text-xs ${

                    isDark ? 'bg-slate-900 border-slate-700 text-white focus:border-indigo-500' : 'bg-white border-slate-300 text-slate-900 focus:border-indigo-600'

                  }`}

                />

              </div>



              {/* Notice */}

              <div className="p-3 rounded-lg bg-indigo-500/10 border border-indigo-500/20 text-[11px] text-indigo-300 flex items-start gap-2">

                <Info className="w-4 h-4 shrink-0 mt-0.5 text-indigo-400" />

                <span>

                  {(gtTicket.ground_truth_status === 'REJECT' || gtTicket.groundTruthStatus === 'REJECT')

                    ? 'Setelah selesai dikaji ulang dan disubmit, status tiket di Groundtruth berubah kembali menjadi WAITING dan tiket otomatis masuk lagi ke antrean Ground Truth Review untuk ditinjau oleh SOC Manager.'

                    : 'Setelah dikirim, status tiket di Groundtruth berubah menjadi WAITING dan tiket otomatis masuk ke Ground Truth Review untuk ditinjau oleh SOC Manager.'}

                </span>

              </div>



              {/* Action Buttons */}

              <div className="flex items-center justify-end gap-2.5 pt-2 border-t border-slate-800">

                <button

                  type="button"

                  onClick={() => { setShowGtModal(false); setGtTicket(null); }}

                  className={`px-4 py-2 rounded-lg border text-xs font-semibold cursor-pointer ${

                    isDark ? 'border-slate-700 text-slate-300 hover:bg-slate-800' : 'border-slate-300 text-slate-700 hover:bg-slate-100'

                  }`}

                >

                  Batal

                </button>

                <button

                  type="submit"

                  disabled={submittingGt}

                  className="px-4 py-2 rounded-lg bg-indigo-600 hover:bg-indigo-500 text-white font-semibold text-xs flex items-center gap-2 cursor-pointer shadow-md disabled:opacity-50"

                >

                  {submittingGt ? <RefreshCw className="w-3.5 h-3.5 animate-spin" /> : <CheckCircle2 className="w-3.5 h-3.5" />}

                  {submittingGt ? 'Mengirim...' : (gtTicket.ground_truth_status === 'REJECT' || gtTicket.groundTruthStatus === 'REJECT') ? 'Kirim Kaji Ulang ke Review' : 'Kirim ke Ground Truth Review'}

                </button>

              </div>

            </form>

          </div>

        </div>

      )}

    </div>

  );

}

