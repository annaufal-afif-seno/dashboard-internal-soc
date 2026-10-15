import React, { useState, useEffect, useRef, useMemo, useDeferredValue } from 'react';
import { 
  Shield, X, AlertTriangle, CheckCircle2, User, Server, Network, 
  Layers, Terminal, RefreshCw, Check, Copy, Globe, FileText, 
  Activity, Lock, Database, Clock, ExternalLink, SlidersHorizontal,
  ChevronRight, ArrowRight, ChevronsUpDown, ChevronUp, ChevronDown,
  Pencil, Search, Brain, Sparkles, Cpu, ShieldAlert, ShieldCheck
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

export const normalizeStatus = (status, resolutionOutcome) => {
  const s = (status || '').toUpperCase();
  if (s === 'FP REJECT' || s === 'FP_REJECT') return 'FP REJECT';
  if (s === 'CLOSE' || s === 'CLOSED' || s === 'RESOLVED') return 'CLOSE';
  if (s === 'INVESTIGATING' || s === 'INVESTIGATE') return 'INVESTIGATE';
  return 'OPEN';
};

export const SLA_INTERVALS_MS = {
  P0: 15 * 60 * 1000,          // 15 menit
  P1: 30 * 60 * 1000,          // 30 menit
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
    else if (s === 'reject' || s === 'rejected' || s === 'fp reject' || s === 'fp_reject' || req.is_rejected) status = 'reject';
    else {
      const outcome = String(req.resolution_outcome || req.resolutionOutcome || '').toUpperCase();
      if (outcome === 'REJECTED') status = 'reject';
      else if (outcome === 'APPROVED' || outcome === 'RESOLVED_SUPPRESSED') status = 'approve';
      else {
        const tStatus = String(req.triage_status || req.status || '').toUpperCase();
        if (tStatus === 'APPROVED' || tStatus === 'APPROVE') status = 'approve';
        else if (tStatus === 'REJECTED' || tStatus === 'REJECT' || tStatus === 'FP REJECT' || tStatus === 'FP_REJECT') status = 'reject';
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
export const globalTriageCache = {
  active: null,
  verified_tp: null
};

export default function IncidentTriageQueue({ viewMode = 'active', theme = 'dark' }) {
  const isDark = theme === 'dark' || (typeof document !== 'undefined' && document.documentElement.classList.contains('dark'));
  const [incidents, setIncidents] = useState(() => globalTriageCache[viewMode] || []);
  const [loading, setLoading] = useState(false);
  const [selectedIncident, setSelectedIncident] = useState(null);
  const [aggregates, setAggregates] = useState([]);
  const [aggregatesLoading, setAggregatesLoading] = useState(false);
  const [selectedAggregateId, setSelectedAggregateId] = useState(null);
  const [aggregateLogs, setAggregateLogs] = useState([]);
  const [logsLoading, setLogsLoading] = useState(false);
  const [selectedLogId, setSelectedLogId] = useState(null);
  const [logSearch, setLogSearch] = useState('');
  const [searchQuery, setSearchQuery] = useState('');
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
  const [networkError, setNetworkError] = useState(false);
  const [updating, setUpdating] = useState(false);
  const [toastMsg, setToastMsg] = useState(null);

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
    try {
      setMlLoading(true);
      setMlPrediction(null);
      const res = await fetch(`/api/triage/${triageId}/ml-prediction`);
      if (res.ok) {
        const data = await res.json();
        setMlPrediction(data);
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

  const handleOpenIncident = (inc) => {
    setSelectedIncident(inc);
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
      if (!globalTriageCache[viewMode]) {
        setLoading(true);
      }
      const res = await fetch(`/api/triage/queue?view=${viewMode}&limit=300`);
      if (res.ok) {
        setNetworkError(false);
        const json = await res.json();
        if (json.incidents) {
          const mapped = json.incidents.map(inc => ({
            ...inc,
            status: normalizeStatus(inc.status || inc.triage_status, inc.resolutionOutcome || inc.resolution_outcome)
          }));
          globalTriageCache[viewMode] = mapped;
          setIncidents(mapped);
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
    fetchQueue();
    const interval = setInterval(fetchQueue, 20000);
    return () => clearInterval(interval);
  }, [viewMode]);

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
      globalTriageCache[viewMode] = updated;
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

  const handlePenClick = async (e, inc) => {
    e.stopPropagation();
    const currStatus = normalizeStatus(inc.status);
    
    // Jika status masih OPEN, otomatis ubah status ke INVESTIGATE
    let targetStatus = currStatus;
    if (currStatus === 'OPEN') {
      targetStatus = 'INVESTIGATE';
      await handleUpdateTicket(inc.id, 'INVESTIGATE', null, 'Status diubah ke INVESTIGATE saat analis membuka tiket.');
    }
    
    // Munculkan detail tiketnya
    const updatedInc = { 
      ...inc, 
      status: targetStatus,
      waktuInvestigate: inc.waktuInvestigate || new Date().toISOString()
    };
    handleOpenIncident(updatedInc);
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
        'FALSE_POSITIVE_TUNING_REQ', 
        reasonText,
        reasonText,
        authorUser
      );
      setSelectedIncident(prev => prev ? { 
        ...prev, 
        status: 'CLOSE', 
        resolutionOutcome: 'FALSE_POSITIVE_TUNING_REQ',
        waktuClose: prev.waktuClose || new Date().toISOString(),
        waktuInvestigate: prev.waktuInvestigate || new Date().toISOString()
      } : null);
      await fetchMlPrediction(triageId);
      setToastMsg(`Tiket ${triageId} diverifikasi sebagai FALSE POSITIVE & otomatis masuk ke Ground Truth Review.`);
    } finally {
      setIsSubmittingGt(false);
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
        'FALSE_POSITIVE_TUNING_REQ',
        `Diajukan sebagai FALSE POSITIVE oleh ${authorUser}: ${fpReason}. Menunggu verifikasi SOC Lead di Inbox Permohonan FP.`,
        fpReason,
        authorUser
      );

      setSelectedIncident(prev => prev ? { 
        ...prev, 
        status: 'CLOSE', 
        resolutionOutcome: 'FALSE_POSITIVE_TUNING_REQ',
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

  const { countP0, countP1, countP2, countP3, countP4, countOpen, countInvestigate, countFpReject, countClose } = useMemo(() => {
    let p0 = 0, p1 = 0, p2 = 0, p3 = 0, p4 = 0;
    let open = 0, inv = 0, fpRej = 0, cls = 0;
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
      else if (st === 'FP REJECT') fpRej++;
      else if (st === 'CLOSE') cls++;
    }
    return {
      countP0: p0, countP1: p1, countP2: p2, countP3: p3, countP4: p4,
      countOpen: open, countInvestigate: inv, countFpReject: fpRej, countClose: cls
    };
  }, [incidents]);

  const priorityFiltered = useMemo(() => {
    if (selectedPriority === 'ALL' && selectedStatusFilter === 'ALL') {
      return incidents;
    }
    return incidents.filter(i => {
      if (selectedPriority !== 'ALL' && i.priority !== selectedPriority) {
        return false;
      }
      if (selectedStatusFilter !== 'ALL') {
        const norm = normalizeStatus(i.status, i.resolution_outcome || i.resolutionOutcome);
        if (norm !== selectedStatusFilter) {
          return false;
        }
      }
      return true;
    });
  }, [incidents, selectedPriority, selectedStatusFilter]);

  const filteredIncidents = useMemo(() => {
    const trimmed = deferredSearch.trim();
    if (!trimmed) return priorityFiltered;
    const q = trimmed.toLowerCase();
    return priorityFiltered.filter(i => {
      return (
        (i.title && i.title.toLowerCase().includes(q)) ||
        (i.id && i.id.toLowerCase().includes(q)) ||
        (i.asset && i.asset.toLowerCase().includes(q)) ||
        (i.attackerIp && i.attackerIp.toLowerCase().includes(q)) ||
        ((i.tenant_id || i.tenant) && (i.tenant_id || i.tenant).toLowerCase().includes(q)) ||
        (i.user && i.user.toLowerCase().includes(q)) ||
        (i.priority && i.priority.toLowerCase().includes(q)) ||
        (i.timeAgo && i.timeAgo.toLowerCase().includes(q)) ||
        (normalizeStatus(i.status, i.resolution_outcome || i.resolutionOutcome).toLowerCase().includes(q))
      );
    });
  }, [priorityFiltered, deferredSearch]);

  const priorityTabs = [
    { id: 'ALL', label: 'All', count: incidents.length },
    { id: 'P0', label: 'P0', count: countP0 },
    { id: 'P1', label: 'P1', count: countP1 },
    { id: 'P2', label: 'P2', count: countP2 },
    { id: 'P3', label: 'P3', count: countP3 },
    { id: 'P4', label: 'P4', count: countP4 },
  ];

  const statusOptions = [
    { id: 'OPEN', label: 'Open' },
    { id: 'INVESTIGATE', label: 'Investigate' },
    { id: 'FP REJECT', label: 'FP Reject' },
    { id: 'CLOSE', label: 'Close' },
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
    <div className="max-w-7xl mx-auto space-y-4">
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
              {viewMode === 'verified_tp' ? 'Verified Threat' : 'Ticket Queue'}
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
                placeholder="Search..."
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

            {/* Status Dropdown Menu (Open, Investigate, FP Reject, Close) */}
            <div className="relative" ref={statusDropdownRef}>
              <button
                type="button"
                onClick={() => setIsStatusDropdownOpen(prev => !prev)}
                title="Filter status: Open, Investigate, FP Reject, Close"
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
                <span>{statusDropdownLabel}</span>
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
                          <span>{opt.label}</span>
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
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs border-collapse">
            <thead className={`border-b text-xs font-semibold ${
              isDark 
                ? 'bg-[#0b101d] text-slate-300 border-slate-800' 
                : 'bg-[#F0F5FA] text-slate-700 border-slate-200/80'
            }`}>
              <tr>
                <th 
                  onClick={() => handleSort('title')}
                  className="px-5 py-3.5 cursor-pointer select-none group hover:bg-slate-200/50 dark:hover:bg-slate-800/60 transition-colors"
                  title="Urutkan Insiden"
                >
                  <div className="flex items-center gap-1.5">
                    <span className={sortField === 'title' ? 'text-blue-600 dark:text-blue-400 font-bold' : 'group-hover:text-slate-900 dark:group-hover:text-white transition-colors'}>Incident</span>
                    {renderSortIcon('title')}
                  </div>
                </th>
                <th 
                  onClick={() => handleSort('priority')}
                  className="px-4 py-3.5 cursor-pointer select-none group hover:bg-slate-200/50 dark:hover:bg-slate-800/60 transition-colors"
                  title="Urutkan Priority"
                >
                  <div className="flex items-center gap-1.5">
                    <span className={sortField === 'priority' ? 'text-blue-600 dark:text-blue-400 font-bold' : 'group-hover:text-slate-900 dark:group-hover:text-white transition-colors'}>Priority</span>
                    {renderSortIcon('priority')}
                  </div>
                </th>
                <th 
                  onClick={() => handleSort('score')}
                  className="px-4 py-3.5 cursor-pointer select-none group hover:bg-slate-200/50 dark:hover:bg-slate-800/60 transition-colors"
                  title="Urutkan Score"
                >
                  <div className="flex items-center gap-1.5">
                    <span className={sortField === 'score' ? 'text-blue-600 dark:text-blue-400 font-bold' : 'group-hover:text-slate-900 dark:group-hover:text-white transition-colors'}>Score</span>
                    {renderSortIcon('score')}
                  </div>
                </th>
                <th 
                  onClick={() => handleSort('deadline')}
                  className="px-4 py-3.5 cursor-pointer select-none group hover:bg-slate-200/50 dark:hover:bg-slate-800/60 transition-colors"
                  title="Urutkan Deadline"
                >
                  <div className="flex items-center gap-1.5">
                    <span className={sortField === 'deadline' || sortField === 'timeAgo' ? 'text-blue-600 dark:text-blue-400 font-bold' : 'group-hover:text-slate-900 dark:group-hover:text-white transition-colors'}>Deadline</span>
                    {renderSortIcon('deadline')}
                  </div>
                </th>
                <th 
                  onClick={() => handleSort('asset')}
                  className="px-4 py-3.5 cursor-pointer select-none group hover:bg-slate-200/50 dark:hover:bg-slate-800/60 transition-colors"
                  title="Urutkan Target Host"
                >
                  <div className="flex items-center gap-1.5">
                    <span className={sortField === 'asset' ? 'text-blue-600 dark:text-blue-400 font-bold' : 'group-hover:text-slate-900 dark:group-hover:text-white transition-colors'}>Target Host</span>
                    {renderSortIcon('asset')}
                  </div>
                </th>
                <th 
                  onClick={() => handleSort('attackerIp')}
                  className="px-4 py-3.5 cursor-pointer select-none group hover:bg-slate-200/50 dark:hover:bg-slate-800/60 transition-colors"
                  title="Urutkan Attacker IP"
                >
                  <div className="flex items-center gap-1.5">
                    <span className={sortField === 'attackerIp' ? 'text-blue-600 dark:text-blue-400 font-bold' : 'group-hover:text-slate-900 dark:group-hover:text-white transition-colors'}>Attacker IP</span>
                    {renderSortIcon('attackerIp')}
                  </div>
                </th>
                <th 
                  onClick={() => handleSort('tenant_id')}
                  className="px-4 py-3.5 text-center cursor-pointer select-none group hover:bg-slate-200/50 dark:hover:bg-slate-800/60 transition-colors"
                  title="Urutkan Tenant"
                >
                  <div className="flex items-center justify-center gap-1.5">
                    <span className={sortField === 'tenant_id' ? 'text-blue-600 dark:text-blue-400 font-bold' : 'group-hover:text-slate-900 dark:group-hover:text-white transition-colors'}>Tenant</span>
                    {renderSortIcon('tenant_id')}
                  </div>
                </th>
                <th className="px-4 py-3.5 text-center">
                  <span>Action</span>
                </th>
                <th 
                  onClick={() => handleSort('status')}
                  className="px-5 py-3.5 text-center cursor-pointer select-none group hover:bg-slate-200/50 dark:hover:bg-slate-800/60 transition-colors"
                  title="Urutkan Status"
                >
                  <div className="flex items-center justify-center gap-1.5">
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
                  <td colSpan="9" className="px-6 py-20 text-center">
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
                  <td colSpan="9" className="px-6 py-14 text-center">
                    <div className="flex flex-col items-center justify-center gap-2">
                      <AlertTriangle className="w-5 h-5 text-amber-500" />
                      <span className={`text-xs font-mono font-semibold ${isDark ? 'text-amber-400' : 'text-amber-600'}`}>
                        Koneksi ke Backend API (port 8000) terputus. Pastikan FastAPI aktif.
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
                  <td colSpan="9" className="px-6 py-14 text-center">
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
                    {/* Narrative & ID */}
                    <td className="px-5 py-4">
                      <div className={`font-bold text-xs tracking-tight ${
                        isDark ? 'text-white' : 'text-slate-900'
                      }`}>
                        {inc.title}
                      </div>
                      <div className={`text-[11px] font-mono mt-0.5 ${
                        isDark ? 'text-slate-400' : 'text-slate-500'
                      }`}>
                        {inc.id}
                      </div>
                    </td>

                    {/* Priority (Text only, no box/border) */}
                    <td className="px-4 py-4 font-mono">
                      <span className={`text-xs font-bold ${prioColor}`}>
                        {inc.priority}
                      </span>
                    </td>

                    {/* Score */}
                    <td className="px-4 py-4 font-mono">
                      <span className={`font-semibold text-xs ${isDark ? 'text-slate-200' : 'text-slate-700'}`}>
                        {inc.score}
                      </span>
                    </td>

                    {/* Deadline (waktu tiket muncul + waktu SLA sesuai prioritas 0-4) */}
                    <td className="px-4 py-4 font-mono text-xs whitespace-nowrap">
                      <span className={isDark ? 'text-slate-300' : 'text-slate-600'}>
                        {formatDeadline(inc)}
                      </span>
                    </td>

                    {/* Target Asset */}
                    <td className="px-4 py-4 font-mono">
                      <span className={`text-xs font-semibold ${isDark ? 'text-slate-200' : 'text-slate-900'}`}>
                        {inc.asset || '-'}
                      </span>
                    </td>

                    {/* Attacker IP */}
                    <td className={`px-4 py-4 font-mono text-xs ${isDark ? 'text-slate-300' : 'text-slate-600'}`}>
                      {inc.attackerIp || '127.0.0.1'}
                    </td>

                    {/* Tenant */}
                    <td className="px-4 py-4 text-center font-mono">
                      <span className={`text-xs font-medium ${
                        isDark ? 'text-slate-300' : 'text-slate-600'
                      }`}>
                        {inc.tenant_id || inc.tenant || 'DEFAULT'}
                      </span>
                    </td>

                    {/* Action Column with Pen Icon */}
                    <td className="px-4 py-4 text-center">
                      <button
                        type="button"
                        onClick={(e) => handlePenClick(e, inc)}
                        title="Investigasi & Buka Detail Tiket"
                        className="p-1.5 rounded-lg text-slate-500 hover:text-blue-600 hover:bg-blue-50/80 dark:text-slate-400 dark:hover:text-blue-400 dark:hover:bg-slate-800 transition-all cursor-pointer inline-flex items-center justify-center group/btn"
                      >
                        <Pencil className="w-4 h-4 transition-transform group-hover/btn:scale-110" />
                      </button>
                    </td>

                    {/* Status (Badge Box matching referenced style) */}
                    <td className="px-5 py-3 text-center font-mono">
                      {normalizeStatus(inc.status, inc.resolution_outcome || inc.resolutionOutcome) === 'CLOSE' ? (
                        <div className="relative inline-block group/status">
                          <span 
                            className="status-badge inline-block px-3.5 py-1.5 rounded-md border border-emerald-500 bg-emerald-500 text-white font-bold text-xs tracking-wider uppercase shadow-xs cursor-help select-none"
                          >
                            CLOSE
                          </span>
                          {renderCloseSlaTooltip(
                            getCloseSlaDetails(inc),
                            inc.priority,
                            idx >= paginatedIncidents.length - 2 ? 'bottom-full mb-2.5 right-0' : 'top-full mt-2.5 right-0'
                          )}
                        </div>
                      ) : normalizeStatus(inc.status, inc.resolution_outcome || inc.resolutionOutcome) === 'FP REJECT' ? (
                        <span 
                          className="status-badge inline-block px-3.5 py-1.5 rounded-md border border-purple-500 bg-purple-600 text-white font-bold text-xs tracking-wider uppercase shadow-xs animate-pulse"
                          title="Pengajuan False Positive Ditolak oleh Lead - Segera Investigasi Ulang!"
                        >
                          FP REJECT
                        </span>
                      ) : normalizeStatus(inc.status, inc.resolution_outcome || inc.resolutionOutcome) === 'INVESTIGATE' ? (
                        <span 
                          className="status-badge inline-block px-3.5 py-1.5 rounded-md border border-orange-500 bg-orange-500 text-white font-bold text-xs tracking-wider uppercase shadow-xs"
                        >
                          INVESTIGATE
                        </span>
                      ) : (
                        <span 
                          className="status-badge inline-block px-3.5 py-1.5 rounded-md border border-red-500 bg-red-500 text-white font-bold text-xs tracking-wider uppercase shadow-xs"
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
                Showing <span className={`font-mono font-semibold ${isDark ? 'text-slate-200' : 'text-slate-700'}`}>{(currentPage - 1) * pageSize + 1}</span> to <span className={`font-mono font-semibold ${isDark ? 'text-slate-200' : 'text-slate-700'}`}>{Math.min(currentPage * pageSize, filteredIncidents.length)}</span> of <span className={`font-mono font-semibold ${isDark ? 'text-slate-200' : 'text-slate-700'}`}>{filteredIncidents.length}</span>
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
                <h3 className={`text-base font-bold tracking-tight ${isDark ? 'text-white' : 'text-slate-900'}`}>
                  {selectedIncident.title}
                </h3>
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
                {normalizeStatus(selectedIncident.status) !== 'CLOSE' && (
                  <>
                    <button
                      type="button"
                      onClick={() => handleConfirmTruePositive(selectedIncident.id)}
                      className="px-3 py-1.5 rounded-lg text-white font-semibold text-xs flex items-center gap-1.5 shadow-sm transition-all cursor-pointer bg-emerald-600 hover:bg-emerald-500 border-0"
                    >
                      <Check className="w-3.5 h-3.5" />
                      <span>True Positive</span>
                    </button>
                    <button
                      type="button"
                      onClick={() => handleConfirmFalsePositive(selectedIncident.id)}
                      className="px-3 py-1.5 rounded-lg text-white font-semibold text-xs flex items-center gap-1.5 shadow-sm transition-all cursor-pointer bg-red-600 hover:bg-red-500 border-0"
                    >
                      <X className="w-3.5 h-3.5" />
                      <span>False Positive</span>
                    </button>
                  </>
                )}

                {/* Status Badge placed at top-right, directly to the left of X */}
                <div className="relative inline-block group/status">
                  <span 
                    style={{ color: '#FFFFFF' }}
                    className={`status-badge px-3 py-1 rounded-md text-xs font-bold font-mono text-white !text-white uppercase tracking-wider shadow-xs select-none inline-block ${
                      normalizeStatus(selectedIncident.status) === 'CLOSE' ? 'bg-emerald-500 border border-emerald-500 cursor-help' :
                      normalizeStatus(selectedIncident.status) === 'INVESTIGATE' ? 'bg-orange-500 border border-orange-500' :
                      'bg-red-500 border border-red-500'
                    }`}
                  >
                    STATUS: {normalizeStatus(selectedIncident.status)}
                  </span>
                  {normalizeStatus(selectedIncident.status) === 'CLOSE' && (
                    renderCloseSlaTooltip(getCloseSlaDetails(selectedIncident), selectedIncident.priority, 'top-full mt-2.5 right-0')
                  )}
                </div>

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
                  {/* Title without heartbeat icon */}
                  <span className={`text-sm font-bold tracking-tight ${isDark ? 'text-slate-100' : 'text-slate-900'}`}>
                    Dynamic Risk Score Assessment
                  </span>
                  {/* TOTAL SCORE without yellow box, text color black */}
                  <div className="flex items-center gap-1.5 font-mono text-xs">
                    <span className={isDark ? 'text-slate-400' : 'text-slate-500'}>TOTAL SCORE:</span>
                    <span 
                      className={`font-mono font-extrabold text-sm ${isDark ? 'text-white' : 'text-slate-900'}`}
                      style={{ color: isDark ? '#FFFFFF' : '#000000' }}
                    >
                      {selectedIncident.score} / 100 PTS
                    </span>
                  </div>
                </div>

                <div className="flex flex-row items-center gap-6 pt-1 w-full overflow-x-auto">
                  {/* Left: Pie Chart */}
                  <div className="w-52 shrink-0 flex flex-col items-center justify-center">
                    <div className="w-48 h-48 relative">
                      {(() => {
                        const activeFactors = (selectedIncident.factors || [])
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

                        const totalScore = Number(selectedIncident.score || 0);
                        const factorSum = activeFactors.reduce((acc, curr) => acc + curr.value, 0);
                        const effectiveScore = totalScore > 0 ? totalScore : factorSum;
                        const scoreRatio = Math.min(1, Math.max(0, effectiveScore / 100));
                        const startAngle = 90;
                        const endAngle = 90 - (scoreRatio * 360);

                        return (
                          <ResponsiveContainer width="100%" height="100%">
                            <PieChart>
                              {/* Background Track (representing 100 PTS capacity) */}
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
                              {/* Foreground Active Risk Factors */}
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
                      {/* Center Score Metric - RISK (PTS removed) */}
                      <div className="absolute inset-0 flex flex-col items-center justify-center pointer-events-none">
                        <span className={`text-2xl font-extrabold font-mono tracking-tight ${isDark ? 'text-white' : 'text-slate-900'}`}>
                          {selectedIncident.score}
                        </span>
                        <span className="text-[10px] font-mono uppercase tracking-wider text-slate-400 font-bold">
                          RISK
                        </span>
                      </div>
                    </div>
                  </div>

                  {/* Right: 3-Column Table */}
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
                        {(selectedIncident.factors || []).map((f, i) => {
                          const color = factorColors[i % factorColors.length];
                          return (
                            <tr key={i} className={`transition-colors ${
                              isDark ? 'hover:bg-slate-800/30' : 'hover:bg-slate-50/70'
                            }`}>
                              {/* Col 1: Factor with Color Indicator */}
                              <td className="py-2.5 px-3 font-medium whitespace-nowrap">
                                <div className="flex items-center gap-2">
                                  <span className="w-2.5 h-2.5 rounded-full shrink-0" style={{ backgroundColor: color }} />
                                  <span className={isDark ? 'text-slate-200' : 'text-slate-800 font-semibold'}>
                                    {f.name}
                                  </span>
                                </div>
                              </td>
                              {/* Col 2: Score / Pts */}
                              <td className="py-2.5 px-3 text-center font-mono font-bold text-emerald-500 whitespace-nowrap">
                                {f.pts}
                              </td>
                              {/* Col 3: Description */}
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

              {/* Machine Learning Tier-1 Triage Assessment Card */}
              <div className={`p-4 border rounded-xl transition-all ${
                isDark ? 'bg-[#070b14] border-slate-800/80' : 'bg-white border-slate-200 shadow-2xs'
              }`}>
                {/* Header */}
                <div className="flex items-center justify-between text-xs font-semibold mb-3 border-b border-slate-200 dark:border-slate-800/60 pb-2.5">
                  <div className="flex items-center gap-2.5 flex-wrap">
                    <span className={`text-sm font-bold tracking-tight block ${isDark ? 'text-slate-100' : 'text-slate-900'}`}>
                      Machine Learning Assessment
                    </span>
                    {mlPrediction && !mlLoading && (
                      <span className={`px-2 py-0.5 rounded-full text-[10px] font-mono font-bold tracking-wide uppercase flex items-center gap-1 ${
                        mlPrediction.verdict === 'THREAT' && mlPrediction.is_auto_close_eligible
                          ? 'bg-rose-500/20 text-rose-400 border border-rose-500/30'
                          : mlPrediction.verdict === 'BENIGN' && mlPrediction.is_auto_close_eligible
                          ? 'bg-emerald-500/20 text-emerald-400 border border-emerald-500/30'
                          : 'bg-amber-500/20 text-amber-400 border border-amber-500/30 animate-pulse'
                      }`}>
                        {mlPrediction.verdict === 'THREAT' && mlPrediction.is_auto_close_eligible
                          ? `🛡️ VERIFIED THREAT (${mlPrediction.confidence.toFixed(1)}%)`
                          : mlPrediction.verdict === 'BENIGN' && mlPrediction.is_auto_close_eligible
                          ? `✅ BENIGN NOISE (${mlPrediction.confidence.toFixed(1)}%)`
                          : `⚠️ GREY ZONE / BUTUH AUDIT SOC (${mlPrediction.confidence.toFixed(1)}%)`}
                      </span>
                    )}
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
                    <RefreshCw className="w-4 h-4 animate-spin text-indigo-400" /> Mengevaluasi Model Machine Learning Tier-1...
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

                    {/* Kotak Catatan Ground Truth (Hanya tampil untuk tiket yang membutuhkan Ground Truth) */}
                    {normalizeStatus(selectedIncident.status) !== 'CLOSE' && (!mlPrediction.is_auto_close_eligible) && (
                      <div className={`p-3.5 rounded-lg border ${
                        isDark ? 'bg-slate-900/40 border-slate-800/80' : 'bg-slate-50/80 border-slate-200'
                      }`}>
                        <div className="flex items-center justify-between mb-2">
                          <label className={`text-xs font-semibold flex items-center gap-1.5 ${
                            isDark ? 'text-slate-200' : 'text-slate-800'
                          }`}>
                            <Pencil className="w-3.5 h-3.5 text-indigo-400" />
                            <span>Catatan Ground Truth Analis (Justifikasi Verifikasi)</span>
                          </label>
                          <span className="text-[10px] text-slate-400 font-mono">
                            Ketik catatan lalu klik True Positive atau False Positive di atas
                          </span>
                        </div>
                        <textarea
                          value={groundTruthNotes}
                          onChange={(e) => setGroundTruthNotes(e.target.value)}
                          placeholder="Tuliskan catatan analisis ground truth / justifikasi verifikasi di sini sebelum mengonfirmasi True Positive atau False Positive di atas..."
                          rows={3}
                          className={`w-full px-3 py-2 text-xs rounded-lg border font-mono resize-y transition-all focus:outline-hidden focus:ring-1 focus:ring-indigo-500 ${
                            isDark 
                              ? 'bg-slate-950/80 border-slate-700/80 text-slate-200 placeholder-slate-500' 
                              : 'bg-white border-slate-300 text-slate-800 placeholder-slate-400'
                          }`}
                        />
                      </div>
                    )}
                  </div>
                ) : (
                  <div className="p-4 text-xs text-slate-400 text-center font-mono">
                    Data Machine Learning tidak tersedia untuk tiket ini.
                  </div>
                )}
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
                  <input
                    type="text"
                    value={logSearch}
                    onChange={(e) => setLogSearch(e.target.value)}
                    placeholder="Search payload, IP, agent..."
                    className={`px-2.5 py-1 border rounded text-xs w-52 focus:outline-none focus:border-blue-500 ${
                      isDark ? 'bg-slate-950 border-slate-800 text-slate-200' : 'bg-white border-slate-200 text-slate-800 placeholder:text-slate-400'
                    }`}
                  />
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
    </div>
  );
}
