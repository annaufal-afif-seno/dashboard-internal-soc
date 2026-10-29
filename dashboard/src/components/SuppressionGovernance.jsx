import React, { useState, useEffect, useMemo } from 'react';
import { 
  Filter, Plus, X, ShieldCheck, Check, AlertCircle, RefreshCw, 
  Inbox, Shield, FileText, CheckCircle2, AlertTriangle, Clock, 
  User, History, ArrowRight, Search, ChevronsUpDown, ChevronUp, ChevronDown,
  Pencil
} from 'lucide-react';
import { 
  normalizeStatus, 
  formatDeadline, 
  getDeadlineDate, 
  getCloseSlaDetails, 
  renderCloseSlaTooltip,
  globalTriageCache,
  getApprovalAuditDetails,
  renderApprovalAuditTooltip,
  getLoggedInUsername
} from './IncidentTriageQueue';
import IncidentDetailModal from './IncidentDetailModal';
import PolicyBundlesView from './PolicyBundlesView';

const fallbackRules = [
  {
    id: "SUP-2026-001",
    name: "Routine Container AppArmor Denials",
    classification: "KNOWN GOOD",
    ownerLetter: "C",
    owner: "Cloud Infra Team",
    approver: "soc_lead_alice",
    sids: ["52002", "52004"],
    expiration: "2027-01-01",
    daysRemaining: 115,
    cycle: "ANNUAL",
    status: "ACTIVE",
    statusColor: "emerald"
  },
  {
    id: "SUP-2026-002",
    name: "Scheduled OS Package Upgrades (dpkg)",
    classification: "MAINTENANCE",
    ownerLetter: "P",
    owner: "Platform Ops",
    approver: "soc_lead_alice",
    sids: ["2901", "2902", "550"],
    expiration: "2026-12-15",
    daysRemaining: 98,
    cycle: "SEMI-ANNUAL",
    status: "ACTIVE",
    statusColor: "emerald"
  },
  {
    id: "SUP-2026-003",
    name: "Approved Nessus Vulnerability Scanner",
    classification: "KNOWN GOOD",
    ownerLetter: "S",
    owner: "SecOps Team",
    approver: "soc_lead_alice",
    sids: ["5710", "31101", "5712"],
    expiration: "2026-11-30",
    daysRemaining: 83,
    cycle: "QUARTERLY",
    status: "ACTIVE",
    statusColor: "emerald"
  }
];

export default function SuppressionGovernance({ initialTab = 'inbox', theme = 'dark' }) {
  const [activeTab, setActiveTab] = useState(initialTab);
  const isDark = theme === 'dark' || (typeof document !== 'undefined' && document.documentElement.classList.contains('dark'));

  useEffect(() => {
    if (initialTab) setActiveTab(initialTab);
  }, [initialTab]);

  const [rules, setRules] = useState(fallbackRules);
  const [tuningRequests, setTuningRequests] = useState([]);
  const [auditLogs, setAuditLogs] = useState([]);
  const [availableGroups, setAvailableGroups] = useState([]);

  const [loading, setLoading] = useState(true);
  const [submitting, setSubmitting] = useState(false);
  const [errorMessage, setErrorMessage] = useState(null);
  const [showModal, setShowModal] = useState(false);
  const [showToast, setShowToast] = useState(false);
  const [toastContent, setToastContent] = useState('');
  const [selectedDetailIncident, setSelectedDetailIncident] = useState(null);

  // Persisted decision map for FP tuning approval/rejection (waiting, approve, reject)
  const [decisionMap, setDecisionMap] = useState(() => {
    try {
      const saved = localStorage.getItem('wazuh_fp_decisions');
      return saved ? JSON.parse(saved) : {};
    } catch {
      return {};
    }
  });

  const getFpStatus = (req) => {
    if (!req) return 'waiting';

    // 1. Direct bundleStatus or policyStatus passed from Policy Bundles
    if (req.bundleStatus) return String(req.bundleStatus).toLowerCase();
    if (req.policyStatus) return String(req.policyStatus).toLowerCase();

    const tid = req.triage_id || (req.id && String(req.id).startsWith('TRG-') ? req.id : null) || req.id || req.incident_id;

    // 2. Check localStorage policy bundle expirations & deploy toggles
    try {
      if (tid) {
        const expMap = JSON.parse(localStorage.getItem('wazuh_policy_bundle_expirations') || '{}');
        const togMap = JSON.parse(localStorage.getItem('wazuh_policy_bundle_toggles') || '{}');
        const expDate = expMap[tid] || (req.id && expMap[req.id]) || (req.incident_id && expMap[req.incident_id]);
        if (expDate) {
          const expObj = new Date(expDate);
          const today = new Date();
          today.setHours(0, 0, 0, 0);
          if (expObj <= today) return 'expired';
        }
        const togVal = togMap[tid] !== undefined 
          ? togMap[tid] 
          : (req.id && togMap[req.id] !== undefined 
            ? togMap[req.id] 
            : (req.incident_id && togMap[req.incident_id] !== undefined ? togMap[req.incident_id] : undefined));
        if (togVal !== undefined) {
          return togVal ? 'deploy' : 'approve';
        }
      }
    } catch {}

    const directStatus = String(req.status || '').toLowerCase();
    if (directStatus === 'deploy' || directStatus === 'expired') return directStatus;

    if (tid && decisionMap[tid]) {
      const entry = decisionMap[tid];
      if (typeof entry === 'object' && entry !== null) {
        return entry.status || 'waiting';
      }
      return entry;
    }
    if (req.incident_id && decisionMap[req.incident_id]) {
      const entry = decisionMap[req.incident_id];
      if (typeof entry === 'object' && entry !== null) {
        return entry.status || 'waiting';
      }
      return entry;
    }
    if (req.existing_suppression_id) return 'approve';
    if (tid && rules && rules.some(r => r.ticketId === tid || r.id === req.existing_suppression_id || (r.scopeDefinition && r.scopeDefinition.referenced_ticket_id === tid))) return 'approve';

    const s = String(req.fp_status || req.suppression_status || '').toLowerCase();
    if (s === 'approve' || s === 'approved' || req.is_approved) return 'approve';
    if (s === 'reject' || s === 'rejected' || req.is_rejected) return 'reject';

    const outcome = String(req.resolution_outcome || req.resolutionOutcome || '').toUpperCase();
    if (outcome === 'REJECTED' || outcome === 'REJECT') return 'reject';
    if (outcome === 'APPROVED' || outcome === 'APPROVE' || outcome === 'RESOLVED_SUPPRESSED') return 'approve';

    const tStatus = String(req.triage_status || req.status || '').toUpperCase();
    if (tStatus === 'APPROVED' || tStatus === 'APPROVE') return 'approve';
    if (tStatus === 'REJECTED' || tStatus === 'REJECT') return 'reject';

    return 'waiting';
  };

  // Search, Priority Filter, Sort & Pagination States (matching Ticket Queue & Verified True Positives)
  const [searchQuery, setSearchQuery] = useState('');
  const [selectedPriority, setSelectedPriority] = useState('ALL');
  const [sortField, setSortField] = useState('title');
  const [sortDirection, setSortDirection] = useState('asc');
  const [currentPage, setCurrentPage] = useState(1);
  const pageSize = 10;

  const countP0 = tuningRequests.filter(r => r.priority === 'P0').length;
  const countP1 = tuningRequests.filter(r => r.priority === 'P1').length;
  const countP2 = tuningRequests.filter(r => r.priority === 'P2').length;
  const countP3 = tuningRequests.filter(r => r.priority === 'P3').length;
  const countP4 = tuningRequests.filter(r => r.priority === 'P4').length;

  const priorityTabs = [
    { id: 'ALL', label: 'All', count: tuningRequests.length },
    { id: 'P0', label: 'P0', count: countP0 },
    { id: 'P1', label: 'P1', count: countP1 },
    { id: 'P2', label: 'P2', count: countP2 },
    { id: 'P3', label: 'P3', count: countP3 },
    { id: 'P4', label: 'P4', count: countP4 },
  ];

  const handlePriorityChange = (priorityId) => {
    setSelectedPriority(priorityId);
    setCurrentPage(1);
  };

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
      return <ChevronsUpDown className="w-3.5 h-3.5 text-slate-400 group-hover:text-slate-600 dark:group-hover:text-slate-200 transition-colors" />;
    }
    return sortDirection === 'asc' ? (
      <ChevronUp className="w-3.5 h-3.5 text-blue-600 dark:text-blue-400" />
    ) : (
      <ChevronDown className="w-3.5 h-3.5 text-blue-600 dark:text-blue-400" />
    );
  };

  const filteredRequests = useMemo(() => {
    let result = tuningRequests;
    if (selectedPriority !== 'ALL') {
      result = result.filter(req => req.priority === selectedPriority);
    }
    if (searchQuery.trim()) {
      const q = searchQuery.toLowerCase().trim();
      result = result.filter(req => {
        const tid = (req.triage_id || req.incident_id || req.id || '').toLowerCase();
        const title = (req.judul_insiden || req.title || '').toLowerCase();
        const host = (req.target_host || req.asset || '').toLowerCase();
        const ip = (req.attacker_source_ip || req.attackerIp || '').toLowerCase();
        const analyst = (req.assigned_analyst || '').toLowerCase();
        const tenant = (req.tenant_id || req.tenant || '').toLowerCase();
        const priority = (req.priority || '').toLowerCase();
        const fpStatus = getFpStatus(req);
        const ruleIds = Array.isArray(req.rule_ids) ? req.rule_ids.join(' ').toLowerCase() : '';
        return tid.includes(q) || title.includes(q) || host.includes(q) || ip.includes(q) || analyst.includes(q) || tenant.includes(q) || priority.includes(q) || fpStatus.includes(q) || ruleIds.includes(q);
      });
    }

    result.sort((a, b) => {
      if (sortField === 'score') {
        const aVal = Number(a.skor_risiko || a.score || 0);
        const bVal = Number(b.skor_risiko || b.score || 0);
        return sortDirection === 'asc' ? aVal - bVal : bVal - aVal;
      }
      if (sortField === 'priority') {
        const pWeight = { P0: 0, P1: 1, P2: 2, P3: 3, P4: 4 };
        const aVal = pWeight[a.priority] ?? 99;
        const bVal = pWeight[b.priority] ?? 99;
        return sortDirection === 'asc' ? aVal - bVal : bVal - aVal;
      }
      if (sortField === 'title') {
        const aVal = String(a.judul_insiden || a.title || a.triage_id || a.incident_id || '').toLowerCase();
        const bVal = String(b.judul_insiden || b.title || b.triage_id || b.incident_id || '').toLowerCase();
        if (aVal < bVal) return sortDirection === 'asc' ? -1 : 1;
        if (aVal > bVal) return sortDirection === 'asc' ? 1 : -1;
        return 0;
      }
      if (sortField === 'asset') {
        const aVal = String(a.target_host || a.asset || '').toLowerCase();
        const bVal = String(b.target_host || b.asset || '').toLowerCase();
        if (aVal < bVal) return sortDirection === 'asc' ? -1 : 1;
        if (aVal > bVal) return sortDirection === 'asc' ? 1 : -1;
        return 0;
      }
      if (sortField === 'attackerIp') {
        const aVal = String(a.attacker_source_ip || a.attackerIp || '').toLowerCase();
        const bVal = String(b.attacker_source_ip || b.attackerIp || '').toLowerCase();
        if (aVal < bVal) return sortDirection === 'asc' ? -1 : 1;
        if (aVal > bVal) return sortDirection === 'asc' ? 1 : -1;
        return 0;
      }
      if (sortField === 'tenant_id') {
        const aVal = String(a.tenant_id || a.tenant || 'DEFAULT').toLowerCase();
        const bVal = String(b.tenant_id || b.tenant || 'DEFAULT').toLowerCase();
        if (aVal < bVal) return sortDirection === 'asc' ? -1 : 1;
        if (aVal > bVal) return sortDirection === 'asc' ? 1 : -1;
        return 0;
      }
      if (sortField === 'status') {
        const aVal = getFpStatus(a);
        const bVal = getFpStatus(b);
        if (aVal < bVal) return sortDirection === 'asc' ? -1 : 1;
        if (aVal > bVal) return sortDirection === 'asc' ? 1 : -1;
        return 0;
      }

      let aVal = String(a[sortField] || '').toLowerCase();
      let bVal = String(b[sortField] || '').toLowerCase();
      if (aVal < bVal) return sortDirection === 'asc' ? -1 : 1;
      if (aVal > bVal) return sortDirection === 'asc' ? 1 : -1;
      return 0;
    });

    return result;
  }, [tuningRequests, searchQuery, sortField, sortDirection, decisionMap, selectedPriority]);

  const totalPages = Math.ceil(filteredRequests.length / pageSize) || 1;
  const paginatedRequests = filteredRequests.slice((currentPage - 1) * pageSize, currentPage * pageSize);

  // Audit Trail States: Search, Sort & Pagination
  const [auditSearchQuery, setAuditSearchQuery] = useState('');
  const [auditSortField, setAuditSortField] = useState('recorded_at');
  const [auditSortDirection, setAuditSortDirection] = useState('desc');
  const [auditCurrentPage, setAuditCurrentPage] = useState(1);
  const auditPageSize = 10;

  const handleAuditSort = (field) => {
    if (auditSortField === field) {
      setAuditSortDirection(prev => prev === 'asc' ? 'desc' : 'asc');
    } else {
      setAuditSortField(field);
      setAuditSortDirection('asc');
    }
  };

  const renderAuditSortIcon = (field) => {
    if (auditSortField !== field) {
      return <ChevronsUpDown className="w-3.5 h-3.5 text-slate-400 group-hover:text-slate-600 dark:group-hover:text-slate-200 transition-colors" />;
    }
    return auditSortDirection === 'asc' ? (
      <ChevronUp className="w-3.5 h-3.5 text-blue-600 dark:text-blue-400" />
    ) : (
      <ChevronDown className="w-3.5 h-3.5 text-blue-600 dark:text-blue-400" />
    );
  };

  const renderAuditActionBadge = (action) => {
    const act = String(action || '').toUpperCase();
    let badgeColor = 'bg-slate-500 text-white';
    if (act === 'APPROVED') {
      badgeColor = 'bg-emerald-500 text-white';
    } else if (act === 'CREATED') {
      badgeColor = 'bg-sky-500 text-white';
    } else if (act === 'MODIFIED') {
      badgeColor = 'bg-amber-500 text-white';
    } else if (act === 'REVIEWED') {
      badgeColor = 'bg-orange-500 text-white';
    } else if (act === 'EXTENDED') {
      badgeColor = 'bg-purple-600 text-white';
    } else if (act === 'REJECTED') {
      badgeColor = 'bg-rose-500 text-white';
    } else if (act === 'REVOKED') {
      badgeColor = 'bg-red-700 text-white';
    } else if (act === 'EXPIRED') {
      badgeColor = 'bg-slate-500 text-white';
    }

    return (
      <span className={`px-2.5 py-1 rounded-md text-[11px] font-bold tracking-wide uppercase shadow-2xs inline-block text-center min-w-[76px] ${badgeColor}`}>
        {act}
      </span>
    );
  };

  const filteredAuditLogs = useMemo(() => {
    let result = [...auditLogs];
    if (auditSearchQuery.trim()) {
      const q = auditSearchQuery.toLowerCase().trim();
      result = result.filter(log => {
        const lid = String(log.log_id || '').toLowerCase();
        const action = String(log.action || '').toLowerCase();
        const sid = String(log.suppression_id || '').toLowerCase();
        const ruleName = String(log.rule_name || '').toLowerCase();
        const user = String(log.performed_by || '').toLowerCase();
        const notes = String(log.notes || '').toLowerCase();
        const rec = String(log.recorded_at || '').toLowerCase();
        const origTicket = String(log.origin_ticket_id || '').toLowerCase();
        return lid.includes(q) || action.includes(q) || sid.includes(q) || ruleName.includes(q) || user.includes(q) || notes.includes(q) || rec.includes(q) || origTicket.includes(q);
      });
    }

    result.sort((a, b) => {
      let aVal = a[auditSortField];
      let bVal = b[auditSortField];

      if (auditSortField === 'log_id') {
        const an = Number(aVal || 0);
        const bn = Number(bVal || 0);
        return auditSortDirection === 'asc' ? an - bn : bn - an;
      }
      if (auditSortField === 'recorded_at') {
        const at = aVal ? new Date(aVal).getTime() : 0;
        const bt = bVal ? new Date(bVal).getTime() : 0;
        return auditSortDirection === 'asc' ? at - bt : bt - at;
      }

      const as = String(aVal || '').toLowerCase();
      const bs = String(bVal || '').toLowerCase();
      if (as < bs) return auditSortDirection === 'asc' ? -1 : 1;
      if (as > bs) return auditSortDirection === 'asc' ? 1 : -1;
      return 0;
    });

    return result;
  }, [auditLogs, auditSearchQuery, auditSortField, auditSortDirection]);

  const totalAuditPages = Math.ceil(filteredAuditLogs.length / auditPageSize) || 1;
  const paginatedAuditLogs = filteredAuditLogs.slice((auditCurrentPage - 1) * auditPageSize, auditCurrentPage * auditPageSize);

  // Active Suppression Rules States: Search, Category Filter, Sort, Pagination & Edit
  const [ruleSearchQuery, setRuleSearchQuery] = useState('');
  const [selectedRuleCategory, setSelectedRuleCategory] = useState('ALL');
  const [ruleSortField, setRuleSortField] = useState('name');
  const [ruleSortDirection, setRuleSortDirection] = useState('asc');
  const [ruleCurrentPage, setRuleCurrentPage] = useState(1);
  const rulePageSize = 10;

  const [selectedEditRule, setSelectedEditRule] = useState(null);
  const [editRuleFormData, setEditRuleFormData] = useState({
    name: '',
    sids: '',
    targetHost: '',
    actorIp: '',
    expiration: '',
    reason: '',
    reviewer: 'soc_lead_alice'
  });
  const [editingRuleSubmitting, setEditingRuleSubmitting] = useState(false);
  const [editRuleError, setEditRuleError] = useState(null);

  const countKnownGood = rules.filter(r => (r.classification || '').toUpperCase().includes('KNOWN GOOD')).length;
  const countMaintenance = rules.filter(r => (r.classification || '').toUpperCase().includes('MAINTENANCE')).length;
  const countFalsePositive = rules.filter(r => (r.classification || '').toUpperCase().includes('FALSE POSITIVE')).length;
  const countConditional = rules.filter(r => (r.classification || '').toUpperCase().includes('CONDITIONAL')).length;
  const countException = rules.filter(r => (r.classification || '').toUpperCase().includes('EXCEPTION')).length;

  const ruleCategoryTabs = [
    { id: 'ALL', label: 'All', count: rules.length },
    { id: 'FALSE POSITIVE', label: 'False Positive', count: countFalsePositive },
    { id: 'KNOWN GOOD', label: 'Known Good', count: countKnownGood },
    { id: 'MAINTENANCE', label: 'Maintenance', count: countMaintenance },
    { id: 'CONDITIONAL', label: 'Conditional', count: countConditional },
    { id: 'EXCEPTION', label: 'Exception', count: countException },
  ];

  const handleRuleSort = (field) => {
    if (ruleSortField === field) {
      setRuleSortDirection(prev => prev === 'asc' ? 'desc' : 'asc');
    } else {
      setRuleSortField(field);
      setRuleSortDirection('asc');
    }
  };

  const renderRuleSortIcon = (field) => {
    if (ruleSortField !== field) {
      return <ChevronsUpDown className="w-3.5 h-3.5 text-slate-400 group-hover:text-slate-600 dark:group-hover:text-slate-200 transition-colors" />;
    }
    return ruleSortDirection === 'asc' ? (
      <ChevronUp className="w-3.5 h-3.5 text-blue-600 dark:text-blue-400" />
    ) : (
      <ChevronDown className="w-3.5 h-3.5 text-blue-600 dark:text-blue-400" />
    );
  };

  const filteredRules = useMemo(() => {
    let result = [...rules];
    if (selectedRuleCategory !== 'ALL') {
      result = result.filter(r => (r.classification || '').toUpperCase().includes(selectedRuleCategory));
    }
    if (ruleSearchQuery.trim()) {
      const q = ruleSearchQuery.toLowerCase().trim();
      result = result.filter(r => {
        const id = String(r.id || '').toLowerCase();
        const name = String(r.name || '').toLowerCase();
        const cls = String(r.classification || '').toLowerCase();
        const host = String(r.targetHost || '').toLowerCase();
        const ip = String(r.actorIp || '').toLowerCase();
        const owner = String(r.owner || '').toLowerCase();
        const approver = String(r.approver || '').toLowerCase();
        const sids = Array.isArray(r.sids) ? r.sids.join(' ').toLowerCase() : String(r.sids || '').toLowerCase();
        const exp = String(r.expiration || '').toLowerCase();
        const status = String(r.status || '').toLowerCase();
        return id.includes(q) || name.includes(q) || cls.includes(q) || host.includes(q) || ip.includes(q) || owner.includes(q) || approver.includes(q) || sids.includes(q) || exp.includes(q) || status.includes(q);
      });
    }

    result.sort((a, b) => {
      let aVal = a[ruleSortField];
      let bVal = b[ruleSortField];

      if (ruleSortField === 'daysRemaining') {
        const an = Number(a.daysRemaining || 0);
        const bn = Number(b.daysRemaining || 0);
        return ruleSortDirection === 'asc' ? an - bn : bn - an;
      }
      if (ruleSortField === 'expiration') {
        const at = a.expiration ? new Date(a.expiration).getTime() : 0;
        const bt = b.expiration ? new Date(b.expiration).getTime() : 0;
        return ruleSortDirection === 'asc' ? at - bt : bt - at;
      }

      const as = String(aVal || '').toLowerCase();
      const bs = String(bVal || '').toLowerCase();
      if (as < bs) return ruleSortDirection === 'asc' ? -1 : 1;
      if (as > bs) return ruleSortDirection === 'asc' ? 1 : -1;
      return 0;
    });

    return result;
  }, [rules, selectedRuleCategory, ruleSearchQuery, ruleSortField, ruleSortDirection]);

  const totalRulePages = Math.ceil(filteredRules.length / rulePageSize) || 1;
  const paginatedRules = filteredRules.slice((ruleCurrentPage - 1) * rulePageSize, ruleCurrentPage * rulePageSize);

  const handleOpenEditRule = (rule) => {
    setSelectedEditRule(rule);
    setEditRuleFormData({
      name: rule.name || '',
      sids: Array.isArray(rule.sids) ? rule.sids.join(', ') : String(rule.sids || ''),
      targetHost: rule.targetHost || (rule.name.includes('[') && rule.name.includes(']') ? rule.name.split('[')[1].split(']')[0] : ''),
      actorIp: rule.actorIp || '',
      urlPath: rule.scopeDefinition?.url_path || rule.scopeDefinition?.url || '',
      programName: rule.scopeDefinition?.program_name || '',
      username: rule.scopeDefinition?.username || '',
      expiration: rule.expiration || new Date(Date.now() + 90 * 86400000).toISOString().split('T')[0],
      reason: rule.businessReason || '',
      reviewer: getLoggedInUsername() || rule.approver || 'soc_lead_alice'
    });
    setEditRuleError(null);
  };

  const handleSaveRuleChanges = async (e) => {
    if (e) e.preventDefault();
    if (!selectedEditRule) return;
    setEditingRuleSubmitting(true);
    setEditRuleError(null);
    try {
      const parsedSids = editRuleFormData.sids.split(',').map(s => parseInt(s.trim(), 10)).filter(n => !isNaN(n));
      const res = await fetch(`/api/suppression/rules/${selectedEditRule.id}`, {
        method: 'PUT',
        headers: {
          'Content-Type': 'application/json',
          'X-API-Key': 'wazuh-soc-secure-key-2026'
        },
        body: JSON.stringify({
          name: editRuleFormData.name,
          sids: parsedSids.length > 0 ? parsedSids : selectedEditRule.sids,
          expiration: editRuleFormData.expiration,
          reason: editRuleFormData.reason,
          reviewer: editRuleFormData.reviewer || 'soc_lead_alice',
          scope_definition: {
            ...(selectedEditRule.scopeDefinition || {}),
            target_host: editRuleFormData.targetHost || undefined,
            source_ip: editRuleFormData.actorIp || undefined,
            username: editRuleFormData.username ? editRuleFormData.username.trim() : undefined,
            url_path: editRuleFormData.urlPath ? editRuleFormData.urlPath.trim() : undefined,
            program_name: editRuleFormData.programName ? editRuleFormData.programName.trim() : undefined,
            match_sids: parsedSids.length > 0 ? parsedSids : selectedEditRule.sids
          },
          is_review_only: false
        })
      });

      if (res.ok) {
        const json = await res.json();
        const actions = (json.actions || []).join(' & ');
        await refreshAll();
        setSelectedEditRule(null);
        setToastContent(`Aturan ${selectedEditRule.id} berhasil diperbarui (${actions}). Log audit GRC telah dicatat.`);
        setShowToast(true);
        setTimeout(() => setShowToast(false), 4000);
      } else {
        const err = await res.json();
        setEditRuleError(err.detail || "Gagal memperbarui aturan supresi.");
      }
    } catch (err) {
      console.warn("Rule update error:", err);
      setEditRuleError(err.message || "Terjadi kesalahan jaringan.");
    } finally {
      setEditingRuleSubmitting(false);
    }
  };

  const handleReviewRuleOnly = async () => {
    if (!selectedEditRule) return;
    setEditingRuleSubmitting(true);
    setEditRuleError(null);
    try {
      const res = await fetch(`/api/suppression/rules/${selectedEditRule.id}`, {
        method: 'PUT',
        headers: {
          'Content-Type': 'application/json',
          'X-API-Key': 'wazuh-soc-secure-key-2026'
        },
        body: JSON.stringify({
          reviewer: editRuleFormData.reviewer || 'soc_lead_alice',
          is_review_only: true
        })
      });

      if (res.ok) {
        await refreshAll();
        setSelectedEditRule(null);
        setToastContent(`Aturan ${selectedEditRule.id} berhasil diverifikasi (REVIEWED). Kepatuhan audit regulasi telah dicatat.`);
        setShowToast(true);
        setTimeout(() => setShowToast(false), 4000);
      } else {
        const err = await res.json();
        setEditRuleError(err.detail || "Gagal mencatat audit review.");
      }
    } catch (err) {
      console.warn("Rule review error:", err);
      setEditRuleError(err.message || "Terjadi kesalahan jaringan.");
    } finally {
      setEditingRuleSubmitting(false);
    }
  };

  const [formData, setFormData] = useState({
    name: '',
    classification: 'S2_FALSE_POSITIVE',
    sids: '',
    targetHost: '',
    actorIp: '',
    username: 'root',
    category: 'AUTH_FAILURE',
    maxCount: 500,
    maxRiskScore: 60,
    owner: 'analyst_john',
    approver: 'soc_lead_alice',
    expiration: new Date(Date.now() + 60 * 86400000).toISOString().split('T')[0],
    reason: '',
    ticketId: null,
    aggregationId: '',
    suppressionId: '',
    currentRisk: 80,
    groupId: ''
  });

  const fetchRules = async () => {
    try {
      const res = await fetch('/api/suppression/rules');
      if (res.ok) {
        const json = await res.json();
        if (json.rules && json.rules.length > 0) {
          setRules(json.rules);
        }
      }
    } catch (err) {
      console.warn("Fetch rules error:", err);
    }
  };

  const fetchTuningRequests = async () => {
    try {
      const res = await fetch('/api/suppression/tuning-requests?limit=2000');
      if (res.ok) {
        const json = await res.json();
        setTuningRequests(json.requests || []);
      }
    } catch (err) {
      console.warn("Fetch tuning requests error:", err);
    }
  };

  const fetchAuditLogs = async () => {
    try {
      const res = await fetch('/api/suppression/audit-logs');
      if (res.ok) {
        const json = await res.json();
        setAuditLogs(json.logs || []);
      }
    } catch (err) {
      console.warn("Fetch audit logs error:", err);
    }
  };

  const fetchAvailableGroups = async () => {
    try {
      const res = await fetch('/api/suppression/groups');
      if (res.ok) {
        const json = await res.json();
        setAvailableGroups(json.groups || []);
      }
    } catch (err) {
      console.warn("Fetch groups error:", err);
    }
  };

  const fetchTriageQueue = async () => {
    if (globalTriageCache?.active && globalTriageCache.active.length > 0) return;
    try {
      const res = await fetch('/api/triage/queue?view=active');
      if (res.ok) {
        const json = await res.json();
        if (json.incidents) {
          globalTriageCache.active = json.incidents;
        }
      }
    } catch (e) {
      console.warn("Could not fetch triage queue cache:", e);
    }
  };

  const refreshAll = async () => {
    setLoading(true);
    await Promise.all([fetchRules(), fetchTuningRequests(), fetchAuditLogs(), fetchAvailableGroups(), fetchTriageQueue()]);
    setLoading(false);
  };

  useEffect(() => {
    refreshAll();
  }, []);

  const handleOpenIncidentDetail = async (req) => {
    const tid = req.triage_id || (req.id && String(req.id).startsWith('TRG-') ? req.id : null) || req.ticket_id || req.ticketId || req.id || req.incident_id;
    let inc = globalTriageCache?.active?.find(i => i.id === tid || i.triage_id === tid);
    if (!inc) {
      try {
        const res = await fetch('/api/triage/queue?view=active');
        if (res.ok) {
          const json = await res.json();
          if (json.incidents) {
            globalTriageCache.active = json.incidents;
            inc = json.incidents.find(i => i.id === tid || i.triage_id === tid);
          }
        }
      } catch (e) {
        console.warn("Queue lookup err:", e);
      }
    }
    if (!inc) {
      const hostVal = req.target_host || req.target || req.asset || '-';
      const actorVal = req.attacker_source_ip || req.actor || req.attackerIp || '127.0.0.1';
      const sidsVal = req.rule_ids || req.sids || [5502, 5501];
      inc = {
        id: tid,
        triage_id: tid,
        incident_id: req.incident_id || tid,
        title: req.judul_insiden || req.incidentTitle || req.title || req.name || 'Security Incident',
        priority: req.priority || 'P1',
        score: req.skor_risiko || req.score || 80,
        asset: hostVal,
        attackerIp: actorVal,
        timeAgo: req.created_at ? new Date(req.created_at).toLocaleDateString('en-GB', { day: '2-digit', month: 'short', year: 'numeric' }) + ', ' + new Date(req.created_at).toLocaleTimeString('id-ID') + ' WIB' : '17 Jul 2026, 09:10:18 WIB',
        status: req.bundleStatus || req.policyStatus || req.status || req.triage_status || 'RESOLVED',
        bundleStatus: req.bundleStatus,
        policyStatus: req.policyStatus,
        tenant: req.tenant_id || req.tenant || 'DEFAULT',
        rule_ids: sidsVal,
        ...req,
        factors: [
          { name: "Detection Severity", pts: "+20", desc: `Base correlation target severity ${req.priority || 'P1'}` },
          { name: "Behavioral Anomaly", pts: "+20", desc: "Multi-stage attack sequence validated with correlated events" },
          { name: "Asset Criticality", pts: "+20", desc: `Target host ${hostVal} is rated HIGH (20 pts)` },
          { name: "Identity Risk", pts: "+0", desc: "Compromised account credential weight" },
          { name: "Correlation Chain", pts: "+20", desc: "Confirmed sequential attack stages" }
        ]
      };
    } else {
      inc = {
        ...inc,
        ...req,
        id: tid,
        triage_id: inc.triage_id || inc.id || tid,
        status: req.bundleStatus || req.policyStatus || getFpStatus(req),
        bundleStatus: req.bundleStatus,
        policyStatus: req.policyStatus
      };
    }
    setSelectedDetailIncident(inc);
  };

  const handleRejectFromModal = async (inc) => {
    const tid = inc.triage_id || (inc.id && String(inc.id).startsWith('TRG-') ? inc.id : null) || inc.id || inc.incident_id;
    const nowIso = new Date().toISOString();
    const prevEntry = decisionMap[tid];
    const reqTime = (typeof prevEntry === 'object' && prevEntry?.requestedAt) 
      ? prevEntry.requestedAt 
      : (inc.created_at || inc.waktu_muncul || inc.waktuOpen || new Date().toISOString());

    const updatedMap = { 
      ...decisionMap, 
      [tid]: {
        status: 'reject',
        approvedAt: null,
        rejectedAt: nowIso,
        requestedAt: reqTime,
        reviewer: 'soc_lead_alice'
      }
    };
    if (inc.incident_id && inc.incident_id !== tid) {
      updatedMap[inc.incident_id] = updatedMap[tid];
    }
    setDecisionMap(updatedMap);
    try {
      localStorage.setItem('wazuh_fp_decisions', JSON.stringify(updatedMap));
    } catch (e) {
      console.warn(e);
    }
    try {
      await fetch(`/api/triage/${tid}/update`, {
        method: 'POST',
        headers: { 
          'Content-Type': 'application/json',
          'X-API-Key': 'wazuh-soc-secure-key-2026'
        },
        body: JSON.stringify({
          triage_status: 'CLOSED',
          resolution_outcome: 'REJECTED',
          assigned_analyst: 'soc_lead_alice',
          notes: `Pengajuan False Positive ditolak oleh reviewer soc_lead_alice.`,
          false_positive_reason: inc.falsePositiveReason || inc.false_positive_reason || 'Ditolak oleh reviewer'
        })
      });
    } catch (tErr) {
      console.warn("Ticket reject sync warning:", tErr);
    }
    globalTriageCache.active = null;
    await refreshAll();
    setSelectedDetailIncident(null);
    setToastContent(`Pengajuan FP untuk tiket ${tid} DITOLAK.`);
    setShowToast(true);
    setTimeout(() => setShowToast(false), 4000);
  };

  const handleOpenModalForTicket = (req) => {
    const sidsVal = req.rule_ids ? req.rule_ids.join(', ') : (req.sids || '5502, 5501');
    const hostVal = req.target_host || req.asset || 'Learning-acadcsirt-dimas';
    const ipVal = req.attacker_source_ip || req.attackerIp || 'user:root';
    const tidVal = req.triage_id || req.incident_id || req.id || 'TRG-AUTO';
    const aggIdVal = req.aggregation_id || (req.aggregates && req.aggregates[0]?.aggregation_id) || `agg_${(tidVal || '0000').toLowerCase().replace(/[^a-z0-9]/g, '')}`;
    const decisionEntry = (tidVal && decisionMap[tidVal]) || (req.id && decisionMap[req.id]) || (req.incident_id && decisionMap[req.incident_id]);
    const storedSuppId = (decisionEntry && typeof decisionEntry === 'object' && decisionEntry.suppression_id) ? decisionEntry.suppression_id : null;
    const nextSeqId = `SUP-2026-${String((rules?.length || 44) + 1).padStart(3, '0')}`;
    const suppIdVal = storedSuppId || req.suppression_id || req.suppressionId || nextSeqId;
    const riskVal = req.score || req.skor_risiko || 80;
    const authorVal = req.assigned_analyst || req.assignedAnalyst || req.owner || 'analyst_john';
    const loggedInUser = getLoggedInUsername();
    const approverVal = loggedInUser || 'soc_lead_alice';
    const reasonVal = req.false_positive_reason || req.falsePositiveReason || req.reason || req.notes || 'Alasan teknis terverifikasi (misal: Sesuai Change Request CRQ-2026-9041)...';
    const userVal = req.username || (ipVal.includes(':') ? ipVal.split(':')[1] : (ipVal || 'root'));
    const urlVal = req.url_path || req.url || req.path || (req.data && (req.data.url || req.data.url_path)) || '';
    const programVal = req.program_name || req.process_name || (req.data && (req.data.program_name || req.data.process_name)) || '';
    const reqTime = req.created_at || req.waktu_muncul || req.waktuOpen || req.timeAgo || new Date().toISOString();

    // Auto-match Policy Bundle (Group) based on host or SIDs
    let matchedGroupId = '';
    if (availableGroups && availableGroups.length > 0) {
      const match = availableGroups.find(g => {
        const shared = typeof g.shared_scope === 'string' ? JSON.parse(g.shared_scope || '{}') : (g.shared_scope || {});
        if (shared.hostname && hostVal && hostVal.toLowerCase().includes(shared.hostname.toLowerCase())) return true;
        if (g.group_name && hostVal && g.group_name.toLowerCase().includes(hostVal.toLowerCase())) return true;
        return false;
      });
      if (match) matchedGroupId = match.group_id;
    }

    const effectiveStatus = (req.bundleStatus || req.policyStatus || (req.status && (req.status === 'DEPLOY' || req.status === 'EXPIRED' || req.status === 'APPROVE') ? req.status : null) || getFpStatus(req) || 'APPROVE').toUpperCase();

    setFormData({
      name: `Supresi [${hostVal}]: Rule ${sidsVal}`,
      classification: 'S2_FALSE_POSITIVE',
      sids: String(sidsVal),
      targetHost: hostVal,
      actorIp: ipVal,
      username: userVal,
      urlPath: urlVal,
      programName: programVal,
      category: req.category || 'AUTH_FAILURE',
      maxCount: 500,
      maxRiskScore: 60,
      owner: authorVal,
      approver: approverVal,
      expiration: new Date(Date.now() + 90 * 86400000).toISOString().split('T')[0],
      reason: reasonVal,
      ticketId: tidVal,
      aggregationId: aggIdVal,
      suppressionId: suppIdVal,
      currentRisk: riskVal,
      requestedAt: reqTime,
      groupId: matchedGroupId,
      tenantId: req.tenant_id || req.tenant || 'TenantA',
      status: effectiveStatus,
      bundleStatus: req.bundleStatus,
      policyStatus: req.policyStatus
    });
    setErrorMessage(null);
    setShowModal(true);
  };

  const handleOpenManualModal = () => {
    const loggedInUser = getLoggedInUsername();
    const nextSeqId = `SUP-2026-${String((rules?.length || 44) + 1).padStart(3, '0')}`;
    setFormData({
      name: '',
      classification: 'S2_FALSE_POSITIVE',
      sids: '',
      targetHost: '',
      actorIp: '',
      username: 'root',
      urlPath: '',
      programName: '',
      category: 'AUTH_FAILURE',
      maxCount: 500,
      maxRiskScore: 60,
      owner: loggedInUser || 'analyst_john',
      approver: '',
      expiration: new Date(Date.now() + 90 * 86400000).toISOString().split('T')[0],
      reason: '',
      ticketId: null,
      aggregationId: `agg_${Math.random().toString(36).substring(2, 14)}`,
      suppressionId: nextSeqId,
      currentRisk: 60,
      requestedAt: new Date().toISOString()
    });
    setErrorMessage(null);
    setShowModal(true);
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    setErrorMessage(null);
    if (!formData.name || !formData.sids) return;

    if (formData.owner.trim().toLowerCase() === formData.approver.trim().toLowerCase()) {
      setErrorMessage("Separation of Duties: Pembuat dan Penyetuju harus dua analis yang berbeda.");
      return;
    }

    const today = new Date();
    today.setHours(0, 0, 0, 0);
    const exp = new Date(formData.expiration);
    const diffDays = Math.ceil((exp - today) / (1000 * 60 * 60 * 24));

    if (diffDays <= 0) {
      setErrorMessage("Tanggal kedaluwarsa harus berada di masa depan.");
      return;
    }
    if (diffDays > 180) {
      setErrorMessage(`SLA Governance: Durasi supresi maksimal 180 hari. Durasi dipilih: ${diffDays} hari.`);
      return;
    }

    const parsedSids = formData.sids.split(',').map(s => parseInt(s.trim(), 10)).filter(n => !isNaN(n));
    if (parsedSids.length === 0) {
      setErrorMessage("Harap masukkan minimal satu nomor Rule ID.");
      return;
    }

    try {
      setSubmitting(true);
      const res = await fetch('/api/suppression/rules', {
        method: 'POST',
        headers: { 
          'Content-Type': 'application/json',
          'X-API-Key': 'wazuh-soc-secure-key-2026'
        },
        body: JSON.stringify({
          suppression_id: formData.suppressionId,
          name: formData.name,
          classification: formData.classification,
          sids: parsedSids,
          owner: formData.owner,
          approver: formData.approver,
          expiration: formData.expiration,
          reason: formData.reason || 'Operational noise suppression',
          referenced_ticket_id: formData.ticketId || undefined,
          group_id: formData.groupId || undefined,
          status: 'WAITING',
          scope_definition: {
            tenant_id: formData.tenantId || undefined,
            match_sids: parsedSids,
            target_host: formData.targetHost ? formData.targetHost.trim() : undefined,
            source_ip: formData.actorIp ? formData.actorIp.trim() : undefined,
            username: formData.username ? formData.username.trim() : undefined,
            url_path: formData.urlPath ? formData.urlPath.trim() : undefined,
            program_name: formData.programName ? formData.programName.trim() : undefined,
            max_count: parseInt(formData.maxCount, 10) || 500,
            max_risk_score: parseInt(formData.maxRiskScore, 10) || 60
          }
        })
      });

      if (res.ok) {
        const resData = await res.json();
        const createdId = resData.rule?.suppression_id || "SUP-POLICY";

        if (formData.ticketId) {
          const nowIso = new Date().toISOString();
          const prevEntry = decisionMap[formData.ticketId];
          const reqTime = (typeof prevEntry === 'object' && prevEntry?.requestedAt) 
            ? prevEntry.requestedAt 
            : (formData.requestedAt || new Date().toISOString());

          const updatedMap = { 
            ...decisionMap, 
            [formData.ticketId]: {
              status: 'approve',
              suppression_id: createdId,
              approvedAt: nowIso,
              rejectedAt: null,
              requestedAt: reqTime,
              reviewer: formData.approver || 'soc_lead_alice'
            }
          };
          if (formData.incident_id && formData.incident_id !== formData.ticketId) {
            updatedMap[formData.incident_id] = updatedMap[formData.ticketId];
          }
          setDecisionMap(updatedMap);
          try {
            localStorage.setItem('wazuh_fp_decisions', JSON.stringify(updatedMap));
          } catch (e) {
            console.warn(e);
          }
          try {
            await fetch(`/api/triage/${formData.ticketId}/update`, {
              method: 'POST',
              headers: { 
                'Content-Type': 'application/json',
                'X-API-Key': 'wazuh-soc-secure-key-2026'
              },
              body: JSON.stringify({
                triage_status: 'RESOLVED',
                assigned_analyst: formData.owner,
                resolution_outcome: 'BENIGN',
                notes: `Aturan supresi ${createdId} disahkan oleh ${formData.approver}.`,
                false_positive_reason: formData.reason
              })
            });
          } catch (tErr) {
            console.warn("Ticket sync warning:", tErr);
          }
        }

        await refreshAll();
        setShowModal(false);
        setSelectedDetailIncident(null);
        setToastContent(`Kebijakan Supresi ${createdId} berhasil disahkan (Approve).`);
        setShowToast(true);
        setTimeout(() => setShowToast(false), 4000);
      } else {
        const errJson = await res.json();
        setErrorMessage(errJson.detail || "Gagal menerbitkan aturan supresi.");
      }
    } catch (err) {
      console.warn("Suppression error:", err);
    } finally {
      setSubmitting(false);
    }
  };

  const handleRejectTicket = async () => {
    if (!formData.ticketId) {
      setShowModal(false);
      return;
    }
    setErrorMessage(null);
    try {
      setSubmitting(true);
      const nowIso = new Date().toISOString();
      const prevEntry = decisionMap[formData.ticketId];
      const reqTime = (typeof prevEntry === 'object' && prevEntry?.requestedAt) 
        ? prevEntry.requestedAt 
        : (formData.requestedAt || new Date().toISOString());

      const updatedMap = { 
        ...decisionMap, 
        [formData.ticketId]: {
          status: 'reject',
          approvedAt: null,
          rejectedAt: nowIso,
          requestedAt: reqTime,
          reviewer: formData.approver || 'soc_lead_alice'
        }
      };
      setDecisionMap(updatedMap);
      try {
        localStorage.setItem('wazuh_fp_decisions', JSON.stringify(updatedMap));
      } catch (e) {
        console.warn(e);
      }

      try {
        await fetch(`/api/triage/${formData.ticketId}/update`, {
          method: 'POST',
          headers: { 
            'Content-Type': 'application/json',
            'X-API-Key': 'wazuh-soc-secure-key-2026'
          },
          body: JSON.stringify({
            triage_status: 'CLOSED',
            resolution_outcome: 'REJECTED',
            assigned_analyst: formData.approver || getLoggedInUsername() || 'soc_lead_alice',
            notes: `Pengajuan False Positive ditolak oleh ${formData.approver || getLoggedInUsername() || 'soc_lead_alice'}.`,
            false_positive_reason: formData.reason || 'Ditolak oleh reviewer'
          })
        });
      } catch (tErr) {
        console.warn("Ticket reject sync warning:", tErr);
      }

      globalTriageCache.active = null;
      await refreshAll();
      setShowModal(false);
      setSelectedDetailIncident(null);
      setToastContent(`Pengajuan FP untuk tiket ${formData.ticketId} DITOLAK.`);
      setShowToast(true);
      setTimeout(() => setShowToast(false), 4000);
    } catch (err) {
      console.warn("Suppression reject error:", err);
      setErrorMessage("Gagal menolak pengajuan tiket.");
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <div className="max-w-7xl mx-auto space-y-4">
      {/* Toast */}
      {showToast && (
        <div className="p-3 bg-slate-900 border border-slate-700/80 rounded-lg text-slate-200 text-xs flex items-center justify-between shadow-lg">
          <div className="flex items-center gap-2">
            <Check className="w-4 h-4 text-emerald-400" />
            <span>{toastContent}</span>
          </div>
          <button onClick={() => setShowToast(false)} className="text-slate-400 hover:text-white">
            <X className="w-4 h-4" />
          </button>
        </div>
      )}

      {/* VIEW 1: INBOX PENGAJUAN FALSE POSITIVE */}
      {activeTab === 'inbox' && (
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
            <div className="shrink-0 order-1">
              <h2 className={`text-base font-bold tracking-tight ${
                isDark ? 'text-white' : 'text-slate-900'
              }`}>
                Ground Truth Review
              </h2>
            </div>

            {/* Center Search Bar with Electric Blue Border & Right Action Circle Button */}
            <div className="flex-1 flex justify-center max-w-2xl mx-auto md:mx-4 w-full md:w-auto order-3 md:order-2">
              <div className={`w-full relative flex items-center bg-white dark:bg-[#090d16] border-2 border-[#3B5BFF] rounded-full h-[38px] pl-3.5 pr-1.5 shadow-2xs group focus-within:ring-2 focus-within:ring-[#3B5BFF]/30 transition-all`}>
                <Search className="w-4 h-4 text-slate-400 shrink-0 mr-2.5 stroke-[2]" />
                <input
                  type="text"
                  value={searchQuery}
                  onChange={(e) => {
                    setSearchQuery(e.target.value);
                    setCurrentPage(1);
                  }}
                  placeholder="Search..."
                  className={`w-full bg-transparent text-xs sm:text-[13px] font-normal focus:outline-none placeholder:text-slate-400 ${
                    isDark ? 'text-slate-200' : 'text-slate-800'
                  }`}
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

            {/* Right Priority Filters matching referenced style */}
            <div className="flex items-center gap-6 sm:gap-7 select-none shrink-0 order-2 md:order-3">
              {priorityTabs.map(tab => {
                const isActive = selectedPriority === tab.id;
                return (
                  <button
                    key={tab.id}
                    onClick={() => handlePriorityChange(tab.id)}
                    title={`Filter ${tab.label} (${tab.count} pengajuan)`}
                    className="relative flex flex-col items-center justify-center py-1 cursor-pointer transition-colors group"
                  >
                    <span className={`text-xs sm:text-[13px] transition-colors ${
                      isActive 
                        ? (isDark ? 'text-white font-bold' : 'text-slate-900 font-bold')
                        : (isDark ? 'text-slate-400 hover:text-slate-200 font-medium' : 'text-slate-500 hover:text-slate-800 font-medium')
                    }`}>
                      {tab.label}
                    </span>
                    {isActive ? (
                      <span className={`w-full min-w-[22px] h-[2px] mt-1.5 transition-all ${
                        isDark ? 'bg-slate-200' : 'bg-slate-900'
                      }`}></span>
                    ) : (
                      <span className="w-full min-w-[22px] h-[2px] mt-1.5 bg-transparent"></span>
                    )}
                  </button>
                );
              })}
            </div>
          </div>

          {loading && tuningRequests.length === 0 ? (
            <div className="py-14 text-center">
              <div className="flex flex-col items-center justify-center gap-2.5">
                <RefreshCw className="w-5 h-5 animate-spin text-blue-500" />
                <span className={`text-xs font-mono font-medium ${isDark ? 'text-slate-400' : 'text-slate-600'}`}>
                  Memuat data pengajuan dari database...
                </span>
              </div>
            </div>
          ) : filteredRequests.length === 0 ? (
            <div className="py-14 text-center space-y-2">
              <CheckCircle2 className={`w-8 h-8 mx-auto ${isDark ? 'text-slate-600' : 'text-slate-300'}`} />
              <div className={`text-xs font-semibold ${isDark ? 'text-slate-300' : 'text-slate-700'}`}>
                {searchQuery || selectedPriority !== 'ALL' ? 'Tidak ada hasil yang cocok dengan filter' : 'Tidak ada pengajuan pending'}
              </div>
              <div className={`text-[11px] max-w-sm mx-auto ${isDark ? 'text-slate-400' : 'text-slate-500'}`}>
                {searchQuery || selectedPriority !== 'ALL' ? 'Silakan periksa kembali kata kunci pencarian atau filter prioritas Anda.' : 'Saat analis menandai tiket sebagai False Positive di antrian triase, tiket tersebut akan muncul di sini untuk ditinjau.'}
              </div>
            </div>
          ) : (
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
                  {paginatedRequests.map((req, idx) => {
                    const isP0 = req.priority === 'P0';
                    const isP1 = req.priority === 'P1';
                    const prioColor = isP0 
                      ? 'text-rose-500 dark:text-rose-400' 
                      : isP1 
                        ? 'text-orange-500 dark:text-orange-400' 
                        : req.priority === 'P2' 
                          ? 'text-amber-500 dark:text-amber-400' 
                          : req.priority === 'P3' 
                            ? 'text-emerald-500 dark:text-emerald-400' 
                            : 'text-sky-500 dark:text-sky-400';

                    const currentStatus = getFpStatus(req);

                    return (
                      <tr 
                        key={req.triage_id} 
                        className={`transition-colors ${
                          isDark ? 'hover:bg-slate-800/30' : 'hover:bg-slate-50/70'
                        }`}
                      >
                        {/* Narrative & ID */}
                        <td className="px-5 py-4">
                          <div className={`font-bold text-xs tracking-tight ${
                            isDark ? 'text-white' : 'text-slate-900'
                          }`}>
                            {req.judul_insiden || req.title || 'Security Incident'}
                          </div>
                          <div className={`text-[11px] font-mono mt-0.5 ${
                            isDark ? 'text-slate-400' : 'text-slate-500'
                          }`}>
                            {req.triage_id || req.incident_id || '-'}
                          </div>
                        </td>

                        {/* Priority */}
                        <td className="px-4 py-4 font-mono">
                          <span className={`text-xs font-bold ${prioColor}`}>
                            {req.priority || 'P1'}
                          </span>
                        </td>

                        {/* Score */}
                        <td className="px-4 py-4 font-mono">
                          <span className={`font-semibold text-xs ${isDark ? 'text-slate-200' : 'text-slate-700'}`}>
                            {req.skor_risiko || req.score || 45}
                          </span>
                        </td>

                        {/* Target Host */}
                        <td className="px-4 py-4 font-mono">
                          <span className={`text-xs font-semibold ${isDark ? 'text-slate-200' : 'text-slate-900'}`}>
                            {req.target_host || req.asset || '-'}
                          </span>
                        </td>

                        {/* Attacker IP */}
                        <td className={`px-4 py-4 font-mono text-xs ${isDark ? 'text-slate-300' : 'text-slate-600'}`}>
                          {req.attacker_source_ip || req.attackerIp || '127.0.0.1'}
                        </td>

                        {/* Tenant */}
                        <td className="px-4 py-4 text-center font-mono">
                          <span className={`text-xs font-medium ${
                            isDark ? 'text-slate-300' : 'text-slate-600'
                          }`}>
                            {req.tenant_id || req.tenant || 'DEFAULT'}
                          </span>
                        </td>

                        {/* Action Column with Pen Icon */}
                        <td className="px-4 py-4 text-center">
                          <button
                            type="button"
                            onClick={() => handleOpenIncidentDetail(req)}
                            title="Investigasi & Buka Detail Tiket"
                            className="p-1.5 rounded-lg text-slate-500 hover:text-blue-600 hover:bg-blue-50/80 dark:text-slate-400 dark:hover:text-blue-400 dark:hover:bg-slate-800 transition-all cursor-pointer inline-flex items-center justify-center group/btn"
                          >
                            <Pencil className="w-4 h-4 transition-transform group-hover/btn:scale-110" />
                          </button>
                        </td>

                        {/* Status (waiting, approve, reject) with SLA Audit Tooltip */}
                        <td className="px-5 py-3 text-center font-mono">
                          <div className="relative inline-block group/status">
                            {currentStatus === 'approve' ? (
                              <span 
                                className="status-badge inline-block px-3.5 py-1.5 rounded-md border border-emerald-500 bg-emerald-500 text-white font-bold text-xs tracking-wider uppercase shadow-xs cursor-help"
                              >
                                approve
                              </span>
                            ) : currentStatus === 'reject' ? (
                              <span 
                                className="status-badge inline-block px-3.5 py-1.5 rounded-md border border-red-500 bg-red-500 text-white font-bold text-xs tracking-wider uppercase shadow-xs cursor-help"
                              >
                                reject
                              </span>
                            ) : (
                              <button 
                                type="button"
                                onClick={() => handleOpenModalForTicket(req)}
                                title="Klik untuk evaluasi (Approve / Reject) permohonan supresi FP"
                                className="status-badge inline-block px-3.5 py-1.5 rounded-md border border-amber-500 bg-amber-500 hover:bg-amber-600 text-white font-bold text-xs tracking-wider uppercase shadow-xs cursor-pointer transition-colors"
                              >
                                waiting
                              </button>
                            )}
                            {renderApprovalAuditTooltip(
                              getApprovalAuditDetails(req, decisionMap),
                              idx >= 5 ? 'bottom-full mb-2.5 right-0' : 'top-full mt-2.5 right-0'
                            )}
                          </div>
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          )}

          {/* Pagination Footer matching reference */}
          <div className={`p-4 border-t flex items-center justify-between text-xs ${
            isDark ? 'border-slate-800 text-slate-400 bg-[#0a0e1a]' : 'border-slate-200 text-slate-500 bg-[#F0F5FA]/40'
          }`}>
            <div>
              {loading && tuningRequests.length === 0 ? (
                <span className="font-mono text-xs">Memuat data pengajuan...</span>
              ) : filteredRequests.length === 0 ? (
                <span className="font-mono text-xs">0 pengajuan</span>
              ) : (
                <>
                  Showing <span className={`font-mono font-semibold ${isDark ? 'text-slate-200' : 'text-slate-700'}`}>{(currentPage - 1) * pageSize + 1}</span> to <span className={`font-mono font-semibold ${isDark ? 'text-slate-200' : 'text-slate-700'}`}>{Math.min(currentPage * pageSize, filteredRequests.length)}</span> of <span className={`font-mono font-semibold ${isDark ? 'text-slate-200' : 'text-slate-700'}`}>{filteredRequests.length}</span>
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
                {currentPage} / {totalPages || 1}
              </span>
              <button
                onClick={() => setCurrentPage(p => Math.min(totalPages, p + 1))}
                disabled={currentPage === totalPages || totalPages <= 1}
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
      )}

      {/* VIEW 2: APPROVE SUPPRESSION POLICIES */}
      {activeTab === 'rules' && (
        <div className={`border rounded-xl overflow-hidden ${
          isDark 
            ? 'bg-[#0a0e1a] border-slate-800' 
            : 'bg-white border-slate-200 shadow-xs'
        }`}>
          {/* Header Bar matching referenced screenshot: Title, Centered Search, Filter Tabs */}
          <div className={`px-6 py-3.5 border-b flex items-center justify-between gap-5 flex-wrap md:flex-nowrap ${
            isDark ? 'border-slate-800' : 'border-slate-200'
          }`}>
            {/* Left Title */}
            <div className="shrink-0 order-1">
              <h2 className={`text-base font-bold tracking-tight ${
                isDark ? 'text-white' : 'text-slate-900'
              }`}>
                Approve Suppression Policies
              </h2>
            </div>

            {/* Center Search Bar with Electric Blue Border & Right Action Circle Button */}
            <div className="flex-1 flex justify-center max-w-sm mx-auto md:mx-4 w-full md:w-auto order-3 md:order-2">
              <div className={`w-full relative flex items-center bg-white dark:bg-[#090d16] border-2 border-[#3B5BFF] rounded-full h-[38px] pl-3.5 pr-1.5 shadow-2xs group focus-within:ring-2 focus-within:ring-[#3B5BFF]/30 transition-all`}>
                <Search className="w-4 h-4 text-slate-400 shrink-0 mr-2.5 stroke-[2]" />
                <input
                  type="text"
                  value={ruleSearchQuery}
                  onChange={(e) => {
                    setRuleSearchQuery(e.target.value);
                    setRuleCurrentPage(1);
                  }}
                  placeholder="Search..."
                  className={`w-full bg-transparent text-xs sm:text-[13px] font-normal focus:outline-none placeholder:text-slate-400 ${
                    isDark ? 'text-slate-200' : 'text-slate-800'
                  }`}
                />
                {ruleSearchQuery && (
                  <button
                    type="button"
                    onClick={() => { setRuleSearchQuery(''); setRuleCurrentPage(1); }}
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

            {/* Right Category Filter Tabs matching referenced style */}
            <div className="flex items-center gap-6 sm:gap-7 select-none shrink-0 order-2 md:order-3 overflow-x-auto pb-1 md:pb-0">
              {ruleCategoryTabs.map(tab => {
                const isActive = selectedRuleCategory === tab.id;
                return (
                  <button
                    key={tab.id}
                    onClick={() => {
                      setSelectedRuleCategory(tab.id);
                      setRuleCurrentPage(1);
                    }}
                    title={`Filter ${tab.label} (${tab.count} aturan)`}
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
          </div>

          {filteredRules.length === 0 ? (
            <div className="py-14 text-center space-y-2">
              <CheckCircle2 className={`w-8 h-8 mx-auto ${isDark ? 'text-slate-600' : 'text-slate-300'}`} />
              <div className={`text-xs font-semibold ${isDark ? 'text-slate-300' : 'text-slate-700'}`}>
                {ruleSearchQuery || selectedRuleCategory !== 'ALL' ? 'Tidak ada kebijakan supresi yang cocok dengan filter' : 'Belum ada kebijakan supresi yang diapprove'}
              </div>
              <div className={`text-[11px] max-w-sm mx-auto ${isDark ? 'text-slate-400' : 'text-slate-500'}`}>
                {ruleSearchQuery || selectedRuleCategory !== 'ALL' ? 'Silakan periksa kembali kata kunci pencarian atau filter kategori aturan Anda.' : 'Pengajuan False Positive yang disetujui akan otomatis muncul di sini.'}
              </div>
            </div>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full text-left text-xs border-collapse">
                <thead className={`border-b text-xs font-semibold ${
                  isDark 
                    ? 'bg-[#0b101d] text-slate-300 border-slate-800' 
                    : 'bg-[#F0F5FA] text-slate-700 border-slate-200/80'
                }`}>
                  <tr>
                    {/* 1. Name */}
                    <th 
                      onClick={() => handleRuleSort('name')}
                      className="px-5 py-3.5 cursor-pointer select-none group hover:bg-slate-200/50 dark:hover:bg-slate-800/60 transition-colors"
                      title="Urutkan Name"
                    >
                      <div className="flex items-center gap-1.5">
                        <span className={ruleSortField === 'name' ? 'text-blue-600 dark:text-blue-400 font-bold' : 'group-hover:text-slate-900 dark:group-hover:text-white transition-colors'}>Name</span>
                        {renderRuleSortIcon('name')}
                      </div>
                    </th>

                    {/* 2. Classification */}
                    <th 
                      onClick={() => handleRuleSort('classification')}
                      className="px-4 py-3.5 cursor-pointer select-none group hover:bg-slate-200/50 dark:hover:bg-slate-800/60 transition-colors"
                      title="Urutkan Classification"
                    >
                      <div className="flex items-center gap-1.5">
                        <span className={ruleSortField === 'classification' ? 'text-blue-600 dark:text-blue-400 font-bold' : 'group-hover:text-slate-900 dark:group-hover:text-white transition-colors'}>Classification</span>
                        {renderRuleSortIcon('classification')}
                      </div>
                    </th>

                    {/* 3. Target Host */}
                    <th 
                      onClick={() => handleRuleSort('targetHost')}
                      className="px-4 py-3.5 cursor-pointer select-none group hover:bg-slate-200/50 dark:hover:bg-slate-800/60 transition-colors"
                      title="Urutkan Target Host"
                    >
                      <div className="flex items-center gap-1.5">
                        <span className={ruleSortField === 'targetHost' ? 'text-blue-600 dark:text-blue-400 font-bold' : 'group-hover:text-slate-900 dark:group-hover:text-white transition-colors'}>Target Host</span>
                        {renderRuleSortIcon('targetHost')}
                      </div>
                    </th>

                    {/* 4. Target SIDs */}
                    <th className="px-4 py-3.5">
                      <span>Target SIDs</span>
                    </th>

                    {/* 5. Author & Sign-off */}
                    <th 
                      onClick={() => handleRuleSort('owner')}
                      className="px-4 py-3.5 cursor-pointer select-none group hover:bg-slate-200/50 dark:hover:bg-slate-800/60 transition-colors"
                      title="Urutkan Author & Sign-off"
                    >
                      <div className="flex items-center gap-1.5">
                        <span className={ruleSortField === 'owner' ? 'text-blue-600 dark:text-blue-400 font-bold' : 'group-hover:text-slate-900 dark:group-hover:text-white transition-colors'}>Author & Sign-off</span>
                        {renderRuleSortIcon('owner')}
                      </div>
                    </th>

                    {/* 6. Expiration & SLA */}
                    <th 
                      onClick={() => handleRuleSort('expiration')}
                      className="px-4 py-3.5 cursor-pointer select-none group hover:bg-slate-200/50 dark:hover:bg-slate-800/60 transition-colors"
                      title="Urutkan Expiration & SLA"
                    >
                      <div className="flex items-center gap-1.5">
                        <span className={ruleSortField === 'expiration' ? 'text-blue-600 dark:text-blue-400 font-bold' : 'group-hover:text-slate-900 dark:group-hover:text-white transition-colors'}>Expiration & SLA</span>
                        {renderRuleSortIcon('expiration')}
                      </div>
                    </th>

                    {/* 7. Action */}
                    <th className="px-4 py-3.5 text-center">
                      <span>Action</span>
                    </th>

                    {/* 8. Status */}
                    <th 
                      onClick={() => handleRuleSort('status')}
                      className="px-5 py-3.5 text-center cursor-pointer select-none group hover:bg-slate-200/50 dark:hover:bg-slate-800/60 transition-colors"
                      title="Urutkan Status"
                    >
                      <div className="flex items-center justify-center gap-1.5">
                        <span className={ruleSortField === 'status' ? 'text-blue-600 dark:text-blue-400 font-bold' : 'group-hover:text-slate-900 dark:group-hover:text-white transition-colors'}>Status</span>
                        {renderRuleSortIcon('status')}
                      </div>
                    </th>
                  </tr>
                </thead>
                <tbody className={`divide-y font-sans ${
                  isDark ? 'divide-slate-800/60 bg-[#0a0e1a]' : 'divide-slate-100 bg-white'
                }`}>
                  {paginatedRules.map((r) => {
                    const isExp = (r.daysRemaining !== undefined && r.daysRemaining <= 0) || r.status === 'EXPIRED';
                    const isExpiring = !isExp && ((r.daysRemaining !== undefined && r.daysRemaining <= 14) || r.status === 'EXPIRING');

                    return (
                      <tr key={r.id} className={`transition-colors ${
                        isDark ? 'hover:bg-slate-800/40' : 'hover:bg-slate-50/80'
                      }`}>
                        {/* 1. Name */}
                        <td className="px-5 py-4">
                          <div className={`font-semibold text-xs leading-snug ${isDark ? 'text-slate-100' : 'text-slate-900'}`}>
                            {r.name}
                          </div>
                          <div className="text-[11px] font-mono font-medium text-black dark:text-white mt-0.5">
                            {r.id}
                          </div>
                        </td>

                        {/* 2. Classification */}
                        <td className="px-4 py-4">
                          <span className={`text-xs font-bold uppercase tracking-wide ${
                            (r.classification || '').toUpperCase().includes('FALSE POSITIVE')
                              ? 'text-purple-600 dark:text-purple-400'
                              : (r.classification || '').toUpperCase().includes('KNOWN GOOD')
                              ? 'text-blue-600 dark:text-blue-400'
                              : (r.classification || '').toUpperCase().includes('MAINTENANCE')
                              ? 'text-amber-600 dark:text-amber-400'
                              : (r.classification || '').toUpperCase().includes('CONDITIONAL')
                              ? 'text-indigo-600 dark:text-indigo-400'
                              : (r.classification || '').toUpperCase().includes('EXCEPTION')
                              ? 'text-teal-600 dark:text-teal-400'
                              : 'text-slate-600 dark:text-slate-400'
                          }`}>
                            {r.classification || 'POLICY'}
                          </span>
                        </td>

                        {/* 3. Target Host */}
                        <td className="px-4 py-4 font-mono">
                          <span className={`text-xs font-semibold ${isDark ? 'text-slate-200' : 'text-slate-900'}`}>
                            {r.targetHost || (r.name && r.name.includes('[') && r.name.includes(']') ? r.name.split('[')[1].split(']')[0] : 'Global / Any')}
                          </span>
                          {r.actorIp && (
                            <div className={`text-[10px] mt-0.5 ${isDark ? 'text-slate-400' : 'text-slate-500'}`}>
                              IP: {r.actorIp}
                            </div>
                          )}
                        </td>

                        {/* 4. Target SIDs */}
                        <td className="px-4 py-4 font-mono">
                          <span className={`text-xs font-semibold ${isDark ? 'text-slate-300' : 'text-slate-700'}`}>
                            {Array.isArray(r.sids) && r.sids.length > 0 ? r.sids.join(', ') : (r.sids || '-')}
                          </span>
                        </td>

                        {/* 5. Author & Sign-off */}
                        <td className="px-4 py-4">
                          <div className={`text-xs font-medium ${isDark ? 'text-slate-200' : 'text-slate-800'}`}>
                            {r.owner || 'SOC Analyst'}
                          </div>
                          <div className={`text-[10px] font-mono mt-0.5 ${isDark ? 'text-slate-400' : 'text-slate-500'}`}>
                            Sign: {r.approver || 'soc_lead'}
                          </div>
                        </td>

                        {/* 6. Expiration & SLA */}
                        <td className="px-4 py-4 font-mono">
                          <div className={`text-xs font-semibold ${isDark ? 'text-slate-200' : 'text-slate-800'}`}>
                            {r.expiration || 'Permanent'}
                          </div>
                          <div className={`text-[10px] mt-0.5 font-medium ${
                            isExp
                              ? 'text-red-500 dark:text-red-400 font-bold' 
                              : isExpiring
                              ? 'text-amber-500 dark:text-amber-400 font-semibold' 
                              : isDark ? 'text-slate-400' : 'text-slate-500'
                          }`}>
                            {(r.daysRemaining !== undefined && r.daysRemaining !== null) ? `${r.daysRemaining}d remaining` : 'No expiry'}
                          </div>
                        </td>

                        {/* 7. Action with Pen Icon */}
                        <td className="px-4 py-4 text-center">
                          <button
                            type="button"
                            onClick={() => handleOpenEditRule(r)}
                            title="Edit Parameter / Tinjau Aturan (GRC Audit)"
                            className="p-1.5 rounded-lg text-slate-500 hover:text-blue-600 hover:bg-blue-50/80 dark:text-slate-400 dark:hover:text-blue-400 dark:hover:bg-slate-800 transition-all cursor-pointer inline-flex items-center justify-center group/btn"
                          >
                            <Pencil className="w-4 h-4 transition-transform group-hover/btn:scale-110" />
                          </button>
                        </td>

                        {/* 8. Status Badge */}
                        <td className="px-5 py-4 text-center font-mono">
                          {r.status === 'WAITING' || r.rawStatus === 'WAITING' ? (
                            <span className="status-badge inline-block px-3.5 py-1.5 rounded-md border border-amber-500 bg-amber-500 text-white font-bold text-xs tracking-wider uppercase shadow-xs">
                              WAITING
                            </span>
                          ) : isExp || r.status === 'EXPIRED' ? (
                            <span className="status-badge inline-block px-3.5 py-1.5 rounded-md border border-slate-500 bg-slate-500 text-white font-bold text-xs tracking-wider uppercase shadow-xs">
                              EXPIRED
                            </span>
                          ) : isExpiring ? (
                            <span className="status-badge inline-block px-3.5 py-1.5 rounded-md border border-amber-500 bg-amber-500 text-white font-bold text-xs tracking-wider uppercase shadow-xs">
                              EXPIRING
                            </span>
                          ) : (
                            <span className="status-badge inline-block px-3.5 py-1.5 rounded-md border border-emerald-500 bg-emerald-500 text-white font-bold text-xs tracking-wider uppercase shadow-xs">
                              ACTIVE
                            </span>
                          )}
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          )}

          {/* Pagination Footer */}
          <div className={`p-4 border-t flex items-center justify-between text-xs ${
            isDark ? 'border-slate-800 text-slate-400 bg-[#0a0e1a]' : 'border-slate-200 text-slate-500 bg-[#F0F5FA]/40'
          }`}>
            <div>
              {filteredRules.length === 0 ? (
                <span className="font-mono text-xs">0 kebijakan</span>
              ) : (
                <>
                  Showing <span className={`font-mono font-semibold ${isDark ? 'text-slate-200' : 'text-slate-700'}`}>{(ruleCurrentPage - 1) * rulePageSize + 1}</span> to <span className={`font-mono font-semibold ${isDark ? 'text-slate-200' : 'text-slate-700'}`}>{Math.min(ruleCurrentPage * rulePageSize, filteredRules.length)}</span> of <span className={`font-mono font-semibold ${isDark ? 'text-slate-200' : 'text-slate-700'}`}>{filteredRules.length}</span>
                </>
              )}
            </div>
            <div className="flex items-center gap-1.5">
              <button
                type="button"
                onClick={() => setRuleCurrentPage(p => Math.max(1, p - 1))}
                disabled={ruleCurrentPage === 1}
                className={`px-3 py-1 rounded-lg border text-xs font-semibold transition-all cursor-pointer disabled:opacity-30 disabled:cursor-not-allowed ${
                  isDark 
                    ? 'bg-slate-800 border-slate-700 text-slate-300 hover:bg-slate-700' 
                    : 'bg-white border-slate-200 text-slate-700 hover:bg-slate-50 shadow-2xs'
                }`}
              >
                Prev
              </button>
              <span className={`font-mono text-xs px-2 font-medium ${isDark ? 'text-slate-400' : 'text-slate-600'}`}>
                {ruleCurrentPage} / {totalRulePages || 1}
              </span>
              <button
                type="button"
                onClick={() => setRuleCurrentPage(p => Math.min(totalRulePages, p + 1))}
                disabled={ruleCurrentPage === totalRulePages || totalRulePages <= 1}
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
      )}

      {/* VIEW 3: AUDIT TRAIL GRC */}
      {activeTab === 'audit' && (
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
                Compliance Audit Trail ({filteredAuditLogs.length})
              </h2>
              <p className={`text-[11px] mt-0.5 font-mono ${
                isDark ? 'text-slate-400' : 'text-slate-500'
              }`}>
                Database: suppression.suppression_audit_log (Immutable Record)
              </p>
            </div>

            {/* Right Search Bar matching Image 2 reference */}
            <div className="flex-1 flex justify-end max-w-md ml-auto w-full md:w-auto">
              <div className={`w-full relative flex items-center bg-white dark:bg-[#090d16] border-2 border-[#3B5BFF] rounded-full h-[38px] pl-3.5 pr-1.5 shadow-2xs group focus-within:ring-2 focus-within:ring-[#3B5BFF]/30 transition-all`}>
                <Search className="w-4 h-4 text-slate-400 shrink-0 mr-2.5 stroke-[2]" />
                <input
                  type="text"
                  value={auditSearchQuery}
                  onChange={(e) => {
                    setAuditSearchQuery(e.target.value);
                    setAuditCurrentPage(1);
                  }}
                  placeholder="Search audit trail..."
                  className={`w-full bg-transparent text-xs sm:text-[13px] font-normal focus:outline-none placeholder:text-slate-400 ${
                    isDark ? 'text-slate-200' : 'text-slate-800'
                  }`}
                />
                {auditSearchQuery && (
                  <button
                    type="button"
                    onClick={() => { setAuditSearchQuery(''); setAuditCurrentPage(1); }}
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
          </div>

          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs border-collapse">
              <thead className={`border-b text-xs font-semibold ${
                isDark 
                  ? 'bg-[#0b101d] text-slate-300 border-slate-800' 
                  : 'bg-[#F0F5FA] text-slate-700 border-slate-200/80'
              }`}>
                <tr>
                  <th 
                    onClick={() => handleAuditSort('log_id')}
                    className="py-3 px-4 cursor-pointer select-none group w-24"
                  >
                    <div className="flex items-center gap-1.5">
                      <span className={auditSortField === 'log_id' ? (isDark ? 'text-blue-400 font-bold' : 'text-blue-600 font-bold') : ''}>Audit ID</span>
                      {renderAuditSortIcon('log_id')}
                    </div>
                  </th>
                  <th 
                    onClick={() => handleAuditSort('action')}
                    className="py-3 px-4 cursor-pointer select-none group w-32"
                  >
                    <div className="flex items-center gap-1.5">
                      <span className={auditSortField === 'action' ? (isDark ? 'text-blue-400 font-bold' : 'text-blue-600 font-bold') : ''}>Action</span>
                      {renderAuditSortIcon('action')}
                    </div>
                  </th>
                  <th 
                    onClick={() => handleAuditSort('suppression_id')}
                    className="py-3 px-4 cursor-pointer select-none group min-w-[200px]"
                  >
                    <div className="flex items-center gap-1.5">
                      <span className={auditSortField === 'suppression_id' ? (isDark ? 'text-blue-400 font-bold' : 'text-blue-600 font-bold') : ''}>Policy ID</span>
                      {renderAuditSortIcon('suppression_id')}
                    </div>
                  </th>
                  <th className="py-3 px-4 select-none min-w-[150px]">
                    <div className="flex items-center gap-1.5">
                      <span className={isDark ? 'text-blue-400 font-bold' : 'text-blue-600 font-bold'}>Tiket Asal</span>
                    </div>
                  </th>
                  <th 
                    onClick={() => handleAuditSort('performed_by')}
                    className="py-3 px-4 cursor-pointer select-none group min-w-[160px]"
                  >
                    <div className="flex items-center gap-1.5">
                      <span className={auditSortField === 'performed_by' ? (isDark ? 'text-blue-400 font-bold' : 'text-blue-600 font-bold') : ''}>Performed By</span>
                      {renderAuditSortIcon('performed_by')}
                    </div>
                  </th>
                  <th 
                    onClick={() => handleAuditSort('notes')}
                    className="py-3 px-4 cursor-pointer select-none group min-w-[240px]"
                  >
                    <div className="flex items-center gap-1.5">
                      <span className={auditSortField === 'notes' ? (isDark ? 'text-blue-400 font-bold' : 'text-blue-600 font-bold') : ''}>Justification / Notes</span>
                      {renderAuditSortIcon('notes')}
                    </div>
                  </th>
                  <th 
                    onClick={() => handleAuditSort('recorded_at')}
                    className="py-3 px-4 cursor-pointer select-none group text-right w-44"
                  >
                    <div className="flex items-center justify-end gap-1.5">
                      <span className={auditSortField === 'recorded_at' ? (isDark ? 'text-blue-400 font-bold' : 'text-blue-600 font-bold') : ''}>Recorded At</span>
                      {renderAuditSortIcon('recorded_at')}
                    </div>
                  </th>
                </tr>
              </thead>
              <tbody className={`divide-y text-xs ${
                isDark ? 'divide-slate-800/40 bg-[#0a0e1a]' : 'divide-slate-100 bg-white'
              }`}>
                {paginatedAuditLogs.map((log) => (
                  <tr key={log.log_id} className={`transition-colors ${
                    isDark ? 'hover:bg-slate-800/30' : 'hover:bg-slate-50/70'
                  }`}>
                    <td className={`py-3.5 px-4 font-mono font-medium ${isDark ? 'text-slate-400' : 'text-slate-600'}`}>
                      #{log.log_id}
                    </td>
                    <td className="py-3.5 px-4">
                      {renderAuditActionBadge(log.action)}
                    </td>
                    <td className="py-3.5 px-4">
                      <div className={`font-semibold text-xs ${
                        isDark ? 'text-slate-200' : 'text-slate-900'
                      }`}>
                        {log.rule_name || log.suppression_id}
                      </div>
                      <div className={`font-mono text-[11px] mt-0.5 ${
                        isDark ? 'text-slate-400' : 'text-slate-500'
                      }`}>
                        {log.suppression_id}
                      </div>
                    </td>
                    <td className="py-3.5 px-4 font-mono">
                      {log.origin_ticket_id ? (
                        <button
                          type="button"
                          onClick={() => handleOpenIncidentDetail({
                            triage_id: log.origin_ticket_id,
                            incident_id: log.origin_ticket_id,
                            id: log.origin_ticket_id,
                            title: log.rule_name || `Tiket ${log.origin_ticket_id}`,
                            target_host: log.target_host || '-',
                            attacker_source_ip: log.source_ip || 'Internal / N/A'
                          })}
                          className="inline-flex items-center gap-1 px-2 py-0.5 rounded bg-blue-500/10 hover:bg-blue-500/20 text-blue-400 hover:text-blue-300 border border-blue-500/30 text-[11px] font-semibold cursor-pointer transition-colors"
                          title="Klik untuk membuka investigasi insiden"
                        >
                          <span>🎟️</span>
                          <span className="underline decoration-blue-500/40">{log.origin_ticket_id}</span>
                        </button>
                      ) : (
                        <span className={isDark ? 'text-slate-600' : 'text-slate-400'}>-</span>
                      )}
                    </td>
                    <td className={`py-3.5 px-4 font-sans font-medium ${isDark ? 'text-slate-300' : 'text-slate-700'}`}>
                      {log.performed_by || 'system'}
                    </td>
                    <td className={`py-3.5 px-4 font-sans max-w-sm truncate ${isDark ? 'text-slate-400' : 'text-slate-600'}`} title={log.notes || ''}>
                      {log.notes || '-'}
                    </td>
                    <td className={`py-3.5 px-4 text-right font-mono text-[11px] ${isDark ? 'text-slate-400' : 'text-slate-500'}`}>
                      {log.recorded_at ? new Date(log.recorded_at).toLocaleDateString('id-ID', {
                        day: '2-digit',
                        month: '2-digit',
                        year: 'numeric'
                      }) : '-'}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>

          {filteredAuditLogs.length === 0 && (
            <div className="py-12 text-center space-y-2">
              <CheckCircle2 className={`w-8 h-8 mx-auto ${isDark ? 'text-slate-600' : 'text-slate-300'}`} />
              <div className={`text-xs font-semibold ${isDark ? 'text-slate-300' : 'text-slate-700'}`}>
                {auditSearchQuery ? 'Tidak ada log audit yang cocok dengan pencarian' : 'Tidak ada catatan log audit'}
              </div>
              <div className={`text-[11px] max-w-sm mx-auto ${isDark ? 'text-slate-400' : 'text-slate-500'}`}>
                {auditSearchQuery ? 'Silakan periksa kembali kata kunci pencarian Anda.' : 'Belum ada aktivitas supresi yang tercatat di sistem audit log.'}
              </div>
            </div>
          )}

          {/* Pagination Controls matching Image 2 reference */}
          <div className={`px-6 py-3 border-t flex items-center justify-between flex-wrap gap-4 ${
            isDark ? 'border-slate-800 bg-[#090d16]' : 'border-slate-200 bg-slate-50/50'
          }`}>
            <div className={`text-xs ${isDark ? 'text-slate-400' : 'text-slate-500'}`}>
              {filteredAuditLogs.length === 0 ? (
                <span className="font-mono text-xs">0 log audit</span>
              ) : (
                <>
                  Showing <span className={`font-mono font-semibold ${isDark ? 'text-slate-200' : 'text-slate-700'}`}>{(auditCurrentPage - 1) * auditPageSize + 1}</span> to <span className={`font-mono font-semibold ${isDark ? 'text-slate-200' : 'text-slate-700'}`}>{Math.min(auditCurrentPage * auditPageSize, filteredAuditLogs.length)}</span> of <span className={`font-mono font-semibold ${isDark ? 'text-slate-200' : 'text-slate-700'}`}>{filteredAuditLogs.length}</span>
                </>
              )}
            </div>
            <div className="flex items-center gap-1.5">
              <button
                onClick={() => setAuditCurrentPage(p => Math.max(1, p - 1))}
                disabled={auditCurrentPage === 1}
                className={`px-3 py-1 rounded-lg border text-xs font-semibold transition-all cursor-pointer disabled:opacity-30 disabled:cursor-not-allowed ${
                  isDark 
                    ? 'bg-slate-800 border-slate-700 text-slate-300 hover:bg-slate-700' 
                    : 'bg-white border-slate-200 text-slate-700 hover:bg-slate-50 shadow-2xs'
                }`}
              >
                Prev
              </button>
              <span className={`font-mono text-xs px-2 font-medium ${isDark ? 'text-slate-400' : 'text-slate-600'}`}>
                {auditCurrentPage} / {totalAuditPages || 1}
              </span>
              <button
                onClick={() => setAuditCurrentPage(p => Math.min(totalAuditPages, p + 1))}
                disabled={auditCurrentPage === totalAuditPages || totalAuditPages <= 1}
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
      )}

      {/* VIEW 4: POLICY BUNDLES (GRUP KEBIJAKAN SUPRESI) */}
      {activeTab === 'groups' && (
        <PolicyBundlesView 
          isDark={isDark} 
          rules={rules} 
          tuningRequests={tuningRequests}
          decisionMap={decisionMap}
          onRefreshRules={refreshAll} 
          onOpenModalForTicket={handleOpenModalForTicket}
          onOpenEditRule={handleOpenEditRule}
          onOpenManualModal={handleOpenManualModal}
          onOpenIncidentDetail={handleOpenIncidentDetail}
          theme={theme}
        />
      )}

      {/* FALSE POSITIVE / SUPPRESSION CREATION MODAL (4-SECTION FORM CEM v3.0) */}
      {showModal && (
        <div className="fixed inset-0 bg-black/60 backdrop-blur-xs z-[70] flex items-center justify-center p-4">
          <div className={`${isDark ? 'bg-[#0b0f19] border-slate-800 text-slate-100' : 'bg-white border-slate-200 text-slate-800'} border rounded-2xl max-w-2xl w-full p-6 shadow-2xl space-y-4 max-h-[90vh] overflow-y-auto`}>
            {/* Modal Header */}
            <div className={`flex items-center justify-between border-b pb-3 ${isDark ? 'border-slate-800' : 'border-slate-200'}`}>
              <div className="flex items-center gap-3">
                <h3 className={`text-base font-bold ${isDark ? 'text-white' : 'text-slate-900'}`}>
                  Formulir Supresi False Positive
                </h3>
                {(() => {
                  const s = String(formData.status || 'APPROVE').toUpperCase();
                  if (s === 'DEPLOY') {
                    return (
                      <span className="status-badge inline-block px-3 py-1 rounded-md border border-blue-600 bg-blue-600 text-white font-bold text-xs tracking-wider uppercase shadow-xs">
                        STATUS: DEPLOY
                      </span>
                    );
                  }
                  if (s === 'EXPIRED') {
                    return (
                      <span className="status-badge inline-block px-3 py-1 rounded-md border border-rose-600 bg-rose-600 text-white font-bold text-xs tracking-wider uppercase shadow-xs">
                        STATUS: EXPIRED
                      </span>
                    );
                  }
                  if (s === 'REJECT') {
                    return (
                      <span className="status-badge inline-block px-3 py-1 rounded-md border border-red-500 bg-red-500 text-white font-bold text-xs tracking-wider uppercase shadow-xs">
                        STATUS: REJECT
                      </span>
                    );
                  }
                  if (s === 'WAITING') {
                    return (
                      <span className="status-badge inline-block px-3 py-1 rounded-md border border-amber-500 bg-amber-500 text-white font-bold text-xs tracking-wider uppercase shadow-xs">
                        STATUS: WAITING
                      </span>
                    );
                  }
                  return (
                    <span className="status-badge inline-block px-3 py-1 rounded-md border border-emerald-500 bg-emerald-500 text-white font-bold text-xs tracking-wider uppercase shadow-xs">
                      STATUS: APPROVE
                    </span>
                  );
                })()}
              </div>
              <button 
                type="button" 
                onClick={() => setShowModal(false)} 
                className={`p-1 rounded-md transition-colors cursor-pointer ${isDark ? 'text-slate-400 hover:text-white hover:bg-slate-800' : 'text-slate-400 hover:text-slate-800 hover:bg-slate-100'}`}
              >
                <X className="w-5 h-5" />
              </button>
            </div>

            <form onSubmit={handleSubmit} className="space-y-4 text-xs">
              {/* BAGIAN A: KONTEKS OTOMATIS */}
              <div className={`p-4 rounded-xl border ${isDark ? 'bg-[#090d16] border-slate-800' : 'bg-slate-50/80 border-slate-200'} space-y-2.5`}>
                <span className={`text-[11px] font-bold uppercase tracking-wider block ${isDark ? 'text-slate-300' : 'text-slate-900'}`}>
                  Bagian A — Konteks Otomatis (Auto-Filled)
                </span>
                <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-2.5 pt-1 text-xs">
                  <div className={`p-2.5 rounded-lg border ${isDark ? 'bg-[#0c101c] border-slate-800' : 'bg-white border-slate-200'}`}>
                    <span className={`text-[10px] font-semibold block uppercase mb-1 ${isDark ? 'text-slate-400' : 'text-slate-700'}`}>Suppression ID</span>
                    <span className={`font-mono font-bold block break-all ${isDark ? 'text-white' : 'text-black'}`}>{formData.suppressionId || 'SUP-2026-AUTO'}</span>
                  </div>
                  <div className={`p-2.5 rounded-lg border ${isDark ? 'bg-[#0c101c] border-slate-800' : 'bg-white border-slate-200'}`}>
                    <span className={`text-[10px] font-semibold block uppercase mb-1 ${isDark ? 'text-slate-400' : 'text-slate-700'}`}>Ref Ticket ID</span>
                    <span className={`font-mono font-bold block break-all ${isDark ? 'text-white' : 'text-black'}`}>{formData.ticketId || '-'}</span>
                  </div>
                  <div className={`p-2.5 rounded-lg border ${isDark ? 'bg-[#0c101c] border-slate-800' : 'bg-white border-slate-200'}`}>
                    <span className={`text-[10px] font-semibold block uppercase mb-1 ${isDark ? 'text-slate-400' : 'text-slate-700'}`}>Aggregation ID</span>
                    <span className={`font-mono font-bold block break-all ${isDark ? 'text-white' : 'text-black'}`}>{formData.aggregationId || '-'}</span>
                  </div>
                  <div className={`p-2.5 rounded-lg border ${isDark ? 'bg-[#0c101c] border-slate-800' : 'bg-white border-slate-200'}`}>
                    <span className={`text-[10px] font-semibold block uppercase mb-1 ${isDark ? 'text-slate-400' : 'text-slate-700'}`}>Current Risk</span>
                    <span className={`font-mono font-bold block ${isDark ? 'text-white' : 'text-black'}`}>{formData.currentRisk || 60} / 100</span>
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
                    value={formData.name}
                    onChange={(e) => setFormData({...formData, name: e.target.value})}
                    className={`w-full rounded-lg px-3.5 py-2 border transition-colors focus:outline-none ${
                      isDark 
                        ? 'bg-[#0c101c] border-slate-700 text-white focus:border-slate-500' 
                        : 'bg-white border-slate-300 text-slate-900 focus:border-slate-500'
                    }`}
                  />
                </div>

                {/* Policy Bundle (Group) Selection & Auto-Match */}
                <div>
                  <div className="flex items-center justify-between mb-1">
                    <label className={`block font-semibold text-xs ${isDark ? 'text-slate-300' : 'text-slate-800'}`}>
                      Policy Bundle (Grup Supresi)
                    </label>
                    {formData.groupId && (
                      <span className="text-[10px] text-emerald-400 font-bold bg-emerald-500/10 px-1.5 py-0.2 rounded border border-emerald-500/20">
                        ⚡ Auto-Match Terdeteksi
                      </span>
                    )}
                  </div>
                  <select
                    value={formData.groupId || ''}
                    onChange={(e) => setFormData({...formData, groupId: e.target.value})}
                    className={`w-full rounded-lg px-3.5 py-2 border transition-colors focus:outline-none text-xs font-medium ${
                      isDark 
                        ? 'bg-[#0c101c] border-slate-700 text-white focus:border-slate-500' 
                        : 'bg-white border-slate-300 text-slate-900 focus:border-slate-500'
                    }`}
                  >
                    <option value="">-- Standalone (Tanpa Policy Bundle) --</option>
                    {availableGroups.map(g => (
                      <option key={g.group_id} value={g.group_id}>
                        {g.group_id}: {g.group_name} ({g.group_type} • {g.tenant_id})
                      </option>
                    ))}
                  </select>
                  <p className="text-[10px] text-slate-400 mt-1">
                    Aturan akan dikonsolidasi ke dalam bundle terpilih untuk mengurangi fragmentasi dan auto-sync ke Wazuh XML level="0".
                  </p>
                </div>

                <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                  <div>
                    <label className={`block font-semibold mb-1 text-xs ${isDark ? 'text-slate-300' : 'text-slate-800'}`}>Wazuh Rule IDs (Pisahkan koma)</label>
                    <input
                      type="text"
                      required
                      value={formData.sids}
                      onChange={(e) => setFormData({...formData, sids: e.target.value})}
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
                      value={formData.category || 'AUTH_FAILURE'}
                      onChange={(e) => setFormData({...formData, category: e.target.value})}
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
                      value={formData.actorIp}
                      onChange={(e) => setFormData({...formData, actorIp: e.target.value})}
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
                      value={formData.targetHost}
                      onChange={(e) => setFormData({...formData, targetHost: e.target.value})}
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
                      value={formData.username || ''}
                      onChange={(e) => setFormData({...formData, username: e.target.value})}
                      placeholder="Semua / Kosong"
                      className={`w-full font-mono rounded-lg px-3 py-2 border transition-colors focus:outline-none ${
                        isDark 
                          ? 'bg-[#0c101c] border-slate-700 text-white focus:border-slate-500' 
                          : 'bg-white border-slate-300 text-slate-900 focus:border-slate-500'
                      }`}
                    />
                  </div>
                </div>

                {/* Granular Parameters: URL Path & Program Name */}
                <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                  <div>
                    <label className={`block font-semibold mb-1 text-xs ${isDark ? 'text-slate-300' : 'text-slate-800'}`}>
                      URL Path / Endpoint Web (Opsional)
                    </label>
                    <input
                      type="text"
                      value={formData.urlPath || ''}
                      onChange={(e) => setFormData({...formData, urlPath: e.target.value})}
                      placeholder="Misal: /healthz atau ^/api/v1/ping$"
                      className={`w-full font-mono rounded-lg px-3 py-2 border transition-colors focus:outline-none ${
                        isDark 
                          ? 'bg-[#0c101c] border-slate-700 text-white focus:border-slate-500' 
                          : 'bg-white border-slate-300 text-slate-900 focus:border-slate-500'
                      }`}
                    />
                    <span className="text-[10px] text-slate-500 mt-0.5 block">Disinkronkan ke tag &lt;field name="url"&gt; di rule Wazuh.</span>
                  </div>
                  <div>
                    <label className={`block font-semibold mb-1 text-xs ${isDark ? 'text-slate-300' : 'text-slate-800'}`}>
                      Program / Process Name (Opsional)
                    </label>
                    <input
                      type="text"
                      value={formData.programName || ''}
                      onChange={(e) => setFormData({...formData, programName: e.target.value})}
                      placeholder="Misal: nginx, mysqld, dockerd"
                      className={`w-full font-mono rounded-lg px-3 py-2 border transition-colors focus:outline-none ${
                        isDark 
                          ? 'bg-[#0c101c] border-slate-700 text-white focus:border-slate-500' 
                          : 'bg-white border-slate-300 text-slate-900 focus:border-slate-500'
                      }`}
                    />
                    <span className="text-[10px] text-slate-500 mt-0.5 block">Disinkronkan ke tag &lt;program_name&gt; di rule Wazuh.</span>
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
                      value={formData.maxCount}
                      onChange={(e) => setFormData({...formData, maxCount: e.target.value})}
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
                      value={formData.maxRiskScore}
                      onChange={(e) => setFormData({...formData, maxRiskScore: e.target.value})}
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
                      value={formData.classification}
                      onChange={(e) => setFormData({...formData, classification: e.target.value})}
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
                      value={formData.expiration}
                      onChange={(e) => setFormData({...formData, expiration: e.target.value})}
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
                      value={formData.owner}
                      className={`w-full rounded-lg px-3.5 py-2 border transition-colors focus:outline-none cursor-not-allowed select-none ${
                        isDark 
                          ? 'bg-slate-900/80 border-slate-800 text-slate-300' 
                          : 'bg-slate-100 border-slate-300 text-slate-700'
                      }`}
                      title="Diambil otomatis dari analis yang mengajukan proposal (tidak dapat diedit)"
                    />
                  </div>
                  <div>
                    <label className={`block font-semibold mb-1 text-xs ${isDark ? 'text-slate-300' : 'text-slate-800'}`}>Penyetuju (SOC Lead Approver)</label>
                    <input
                      type="text"
                      readOnly
                      value={formData.approver}
                      placeholder="Wajib berbeda dari pembuat"
                      className={`w-full rounded-lg px-3.5 py-2 border transition-colors focus:outline-none cursor-not-allowed select-none ${
                        isDark 
                          ? 'bg-slate-900/80 border-slate-800 text-slate-300 placeholder:text-slate-500' 
                          : 'bg-slate-100 border-slate-300 text-slate-700 placeholder:text-slate-400'
                      }`}
                      title="Diisi otomatis sesuai akun yang sedang login memproses persetujuan (tidak dapat diedit)"
                    />
                  </div>
                </div>

                <div>
                  <label className={`block font-semibold mb-1 text-xs ${isDark ? 'text-slate-300' : 'text-slate-800'}`}>Justifikasi Bisnis & Forensik</label>
                  <textarea
                    rows="2"
                    required
                    value={formData.reason}
                    onChange={(e) => setFormData({...formData, reason: e.target.value})}
                    placeholder="Alasan teknis terverifikasi (misal: Sesuai Change Request CRQ-2026-9041)..."
                    className={`w-full rounded-lg px-3.5 py-2 border transition-colors focus:outline-none ${
                      isDark 
                        ? 'bg-[#0c101c] border-slate-700 text-white focus:border-slate-500' 
                        : 'bg-white border-slate-300 text-slate-900 focus:border-slate-500'
                    }`}
                  ></textarea>
                </div>
              </div>

              {errorMessage && (
                <div className="p-3 bg-red-50 border border-red-200 dark:bg-red-950/60 dark:border-red-800/60 rounded-lg text-red-700 dark:text-red-300 text-xs flex items-center gap-1.5">
                  <AlertCircle className="w-4 h-4 shrink-0 text-red-600 dark:text-red-400" />
                  <span>{errorMessage}</span>
                </div>
              )}

              {/* Action Buttons */}
              <div className={`flex items-center justify-end gap-2.5 pt-3 border-t ${isDark ? 'border-slate-800' : 'border-slate-200'}`}>
                <button
                  type="button"
                  disabled={submitting}
                  onClick={formData.ticketId ? handleRejectTicket : () => setShowModal(false)}
                  className="px-4 py-2 rounded-lg bg-rose-600 hover:bg-rose-500 text-white text-xs font-semibold cursor-pointer flex items-center gap-1.5 transition-colors shadow-xs"
                >
                  <X className="w-3.5 h-3.5" />
                  <span>Reject</span>
                </button>
                <button
                  type="submit"
                  disabled={submitting}
                  className="px-5 py-2 rounded-lg bg-emerald-600 hover:bg-emerald-500 text-white font-semibold text-xs flex items-center gap-1.5 shadow-xs cursor-pointer transition-colors"
                >
                  {submitting ? <RefreshCw className="w-3.5 h-3.5 animate-spin" /> : <Check className="w-3.5 h-3.5" />}
                  <span>Approve</span>
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* EDIT / REVIEW SUPPRESSION RULE MODAL */}
      {selectedEditRule && (
        <div className="fixed inset-0 bg-black/60 backdrop-blur-xs z-[70] flex items-center justify-center p-4">
          <div className={`${isDark ? 'bg-[#0b0f19] border-slate-800 text-slate-100' : 'bg-white border-slate-200 text-slate-800'} border rounded-2xl max-w-2xl w-full p-6 shadow-2xl space-y-4 max-h-[90vh] overflow-y-auto`}>
            {/* Modal Header */}
            <div className={`flex items-center justify-between border-b pb-3 ${isDark ? 'border-slate-800' : 'border-slate-200'}`}>
              <h3 className={`text-base font-bold ${isDark ? 'text-white' : 'text-slate-900'}`}>
                Edit Parameter & Review Aturan: {selectedEditRule.id}
              </h3>
              <button 
                type="button"
                onClick={() => setSelectedEditRule(null)} 
                className={`p-1 rounded-md transition-colors cursor-pointer ${isDark ? 'text-slate-400 hover:text-white hover:bg-slate-800' : 'text-slate-400 hover:text-slate-800 hover:bg-slate-100'}`}
              >
                <X className="w-5 h-5" />
              </button>
            </div>

            <form onSubmit={handleSaveRuleChanges} className="space-y-4 text-xs">
              {/* Context Summary Cards - Bagian 1 */}
              <div className={`p-4 rounded-xl border ${isDark ? 'bg-[#090d16] border-slate-800' : 'bg-slate-50/80 border-slate-200'} space-y-2.5`}>
                <span className={`text-[11px] font-bold uppercase tracking-wider block ${isDark ? 'text-slate-300' : 'text-slate-900'}`}>
                  Informasi Kebijakan
                </span>
                <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-2.5 pt-1 text-xs">
                  <div className={`p-2.5 rounded-lg border ${isDark ? 'bg-[#0c101c] border-slate-800' : 'bg-white border-slate-200'}`}>
                    <span className={`text-[10px] font-semibold block uppercase mb-1 ${isDark ? 'text-slate-400' : 'text-slate-700'}`}>Policy ID</span>
                    <span className={`font-mono font-bold block break-all ${isDark ? 'text-white' : 'text-black'}`}>{selectedEditRule.id}</span>
                  </div>
                  <div className={`p-2.5 rounded-lg border ${isDark ? 'bg-[#0c101c] border-slate-800' : 'bg-white border-slate-200'}`}>
                    <span className={`text-[10px] font-semibold block uppercase mb-1 ${isDark ? 'text-slate-400' : 'text-slate-700'}`}>Classification</span>
                    <span className={`font-mono font-bold block break-all ${isDark ? 'text-white' : 'text-black'}`}>{selectedEditRule.classification || 'POLICY'}</span>
                  </div>
                  <div className={`p-2.5 rounded-lg border ${isDark ? 'bg-[#0c101c] border-slate-800' : 'bg-white border-slate-200'}`}>
                    <span className={`text-[10px] font-semibold block uppercase mb-1 ${isDark ? 'text-slate-400' : 'text-slate-700'}`}>Author</span>
                    <span className={`font-mono font-bold block break-all ${isDark ? 'text-white' : 'text-black'}`}>{selectedEditRule.owner || 'SOC Analyst'}</span>
                  </div>
                  <div className={`p-2.5 rounded-lg border ${isDark ? 'bg-[#0c101c] border-slate-800' : 'bg-white border-slate-200'}`}>
                    <span className={`text-[10px] font-semibold block uppercase mb-1 ${isDark ? 'text-slate-400' : 'text-slate-700'}`}>Current Status</span>
                    <span className={`font-mono font-bold block break-all ${isDark ? 'text-white' : 'text-black'}`}>{selectedEditRule.status || 'ACTIVE'}</span>
                  </div>
                </div>
              </div>

              {/* Editable Scope & Parameters - Bagian 2 */}
              <div className={`p-4 rounded-xl border ${isDark ? 'bg-[#090d16] border-slate-800' : 'bg-slate-50/80 border-slate-200'} space-y-3`}>
                <span className={`text-[11px] font-bold uppercase tracking-wider block ${isDark ? 'text-slate-300' : 'text-slate-900'}`}>
                  Parameter Aturan Supresi
                </span>
                
                <div>
                  <label className={`block font-semibold mb-1 text-xs ${isDark ? 'text-slate-300' : 'text-slate-800'}`}>Nama Aturan Supresi (Rule Name)</label>
                  <input
                    type="text"
                    required
                    value={editRuleFormData.name}
                    onChange={(e) => setEditRuleFormData({ ...editRuleFormData, name: e.target.value })}
                    className={`w-full rounded-lg px-3.5 py-2 border transition-colors focus:outline-none ${
                      isDark 
                        ? 'bg-[#0c101c] border-slate-700 text-white focus:border-slate-500' 
                        : 'bg-white border-slate-300 text-slate-900 focus:border-slate-500'
                    }`}
                  />
                </div>

                <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                  <div>
                    <label className={`block font-semibold mb-1 text-xs ${isDark ? 'text-slate-300' : 'text-slate-800'}`}>Target Host / Agent</label>
                    <input
                      type="text"
                      value={editRuleFormData.targetHost}
                      onChange={(e) => setEditRuleFormData({ ...editRuleFormData, targetHost: e.target.value })}
                      placeholder="Semua host / Global"
                      className={`w-full font-mono rounded-lg px-3.5 py-2 border transition-colors focus:outline-none ${
                        isDark 
                          ? 'bg-[#0c101c] border-slate-700 text-white focus:border-slate-500' 
                          : 'bg-white border-slate-300 text-slate-900 focus:border-slate-500'
                      }`}
                    />
                  </div>
                  <div>
                    <label className={`block font-semibold mb-1 text-xs ${isDark ? 'text-slate-300' : 'text-slate-800'}`}>Actor / Source IP</label>
                    <input
                      type="text"
                      value={editRuleFormData.actorIp}
                      onChange={(e) => setEditRuleFormData({ ...editRuleFormData, actorIp: e.target.value })}
                      placeholder="Semua IP / N/A"
                      className={`w-full font-mono rounded-lg px-3.5 py-2 border transition-colors focus:outline-none ${
                        isDark 
                          ? 'bg-[#0c101c] border-slate-700 text-white focus:border-slate-500' 
                          : 'bg-white border-slate-300 text-slate-900 focus:border-slate-500'
                      }`}
                    />
                  </div>
                </div>

                <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
                  <div>
                    <label className={`block font-semibold mb-1 text-xs ${isDark ? 'text-slate-300' : 'text-slate-800'}`}>Username Spesifik</label>
                    <input
                      type="text"
                      value={editRuleFormData.username || ''}
                      onChange={(e) => setEditRuleFormData({ ...editRuleFormData, username: e.target.value })}
                      placeholder="Semua / Global"
                      className={`w-full font-mono rounded-lg px-3.5 py-2 border transition-colors focus:outline-none ${
                        isDark 
                          ? 'bg-[#0c101c] border-slate-700 text-white focus:border-slate-500' 
                          : 'bg-white border-slate-300 text-slate-900 focus:border-slate-500'
                      }`}
                    />
                  </div>
                  <div>
                    <label className={`block font-semibold mb-1 text-xs ${isDark ? 'text-slate-300' : 'text-slate-800'}`}>URL Path / Endpoint</label>
                    <input
                      type="text"
                      value={editRuleFormData.urlPath || ''}
                      onChange={(e) => setEditRuleFormData({ ...editRuleFormData, urlPath: e.target.value })}
                      placeholder="/healthz atau ^/api/.*"
                      className={`w-full font-mono rounded-lg px-3.5 py-2 border transition-colors focus:outline-none ${
                        isDark 
                          ? 'bg-[#0c101c] border-slate-700 text-white focus:border-slate-500' 
                          : 'bg-white border-slate-300 text-slate-900 focus:border-slate-500'
                      }`}
                    />
                  </div>
                  <div>
                    <label className={`block font-semibold mb-1 text-xs ${isDark ? 'text-slate-300' : 'text-slate-800'}`}>Program / Process</label>
                    <input
                      type="text"
                      value={editRuleFormData.programName || ''}
                      onChange={(e) => setEditRuleFormData({ ...editRuleFormData, programName: e.target.value })}
                      placeholder="nginx, mysqld"
                      className={`w-full font-mono rounded-lg px-3.5 py-2 border transition-colors focus:outline-none ${
                        isDark 
                          ? 'bg-[#0c101c] border-slate-700 text-white focus:border-slate-500' 
                          : 'bg-white border-slate-300 text-slate-900 focus:border-slate-500'
                      }`}
                    />
                  </div>
                </div>

                <div>
                  <label className={`block font-semibold mb-1 text-xs ${isDark ? 'text-slate-300' : 'text-slate-800'}`}>Target Wazuh Rule IDs (Pisahkan koma)</label>
                  <input
                    type="text"
                    required
                    value={editRuleFormData.sids}
                    onChange={(e) => setEditRuleFormData({ ...editRuleFormData, sids: e.target.value })}
                    placeholder="Contoh: 5710, 31101"
                    className={`w-full font-mono rounded-lg px-3.5 py-2 border transition-colors focus:outline-none ${
                      isDark 
                        ? 'bg-[#0c101c] border-slate-700 text-white focus:border-slate-500' 
                        : 'bg-white border-slate-300 text-slate-900 focus:border-slate-500'
                    }`}
                  />
                </div>
              </div>

              {/* Review & Expiration Management - Bagian 3 */}
              <div className={`p-4 rounded-xl border ${isDark ? 'bg-[#090d16] border-slate-800' : 'bg-slate-50/80 border-slate-200'} space-y-3`}>
                <span className={`text-[11px] font-bold uppercase tracking-wider block ${isDark ? 'text-slate-300' : 'text-slate-900'}`}>
                  Masa Berlaku & Verifikator
                </span>
                <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                  <div>
                    <label className={`block font-semibold mb-1 text-xs ${isDark ? 'text-slate-300' : 'text-slate-800'}`}>Tanggal Kedaluwarsa (Expiration)</label>
                    <input
                      type="date"
                      required
                      value={editRuleFormData.expiration}
                      onChange={(e) => setEditRuleFormData({ ...editRuleFormData, expiration: e.target.value })}
                      className={`w-full font-mono rounded-lg px-3.5 py-2 border transition-colors focus:outline-none ${
                        isDark 
                          ? 'bg-[#0c101c] border-slate-700 text-white focus:border-slate-500' 
                          : 'bg-white border-slate-300 text-slate-900 focus:border-slate-500'
                      }`}
                    />
                    <span className="text-[10px] text-slate-500 mt-1 block">Jika dimundurkan, aksi EXTENDED akan dicatat pada GRC log.</span>
                  </div>
                  <div>
                    <label className={`block font-semibold mb-1 text-xs ${isDark ? 'text-slate-300' : 'text-slate-800'}`}>Petugas / Auditor (Reviewer)</label>
                    <input
                      type="text"
                      readOnly
                      value={editRuleFormData.reviewer}
                      className={`w-full rounded-lg px-3.5 py-2 border transition-colors focus:outline-none cursor-not-allowed select-none ${
                        isDark 
                          ? 'bg-slate-900/80 border-slate-800 text-slate-300' 
                          : 'bg-slate-100 border-slate-300 text-slate-700'
                      }`}
                      title="Diisi otomatis sesuai akun yang sedang login melakukan peninjauan/review (tidak dapat diedit)"
                    />
                    <span className="text-[10px] text-slate-500 mt-1 block">Nama operator / lead yang bertanggung jawab atas peninjauan.</span>
                  </div>
                </div>

                <div>
                  <label className={`block font-semibold mb-1 text-xs ${isDark ? 'text-slate-300' : 'text-slate-800'}`}>Alasan Perubahan / Catatan Audit</label>
                  <textarea
                    rows={2}
                    value={editRuleFormData.reason}
                    onChange={(e) => setEditRuleFormData({ ...editRuleFormData, reason: e.target.value })}
                    placeholder="Catatan justifikasi teknis atau rujukan tiket insiden / RFC..."
                    className={`w-full rounded-lg px-3.5 py-2 border transition-colors focus:outline-none resize-none ${
                      isDark 
                        ? 'bg-[#0c101c] border-slate-700 text-white focus:border-slate-500' 
                        : 'bg-white border-slate-300 text-slate-900 focus:border-slate-500'
                    }`}
                  />
                </div>
              </div>

              {editRuleError && (
                <div className="p-3 bg-red-50 border border-red-200 dark:bg-red-950/60 dark:border-red-800/60 rounded-lg text-red-700 dark:text-red-300 text-xs flex items-center gap-1.5">
                  <AlertCircle className="w-4 h-4 shrink-0 text-red-600 dark:text-red-400" />
                  <span>{editRuleError}</span>
                </div>
              )}

              {/* Action Buttons */}
              <div className={`flex items-center justify-end gap-2.5 pt-3 border-t ${isDark ? 'border-slate-800' : 'border-slate-200'}`}>
                <button
                  type="button"
                  disabled={editingRuleSubmitting}
                  onClick={() => setSelectedEditRule(null)}
                  className={`px-4 py-2 rounded-lg border font-semibold text-xs cursor-pointer transition-colors ${
                    isDark 
                      ? 'bg-slate-800 border-slate-700 text-slate-300 hover:bg-slate-700' 
                      : 'bg-slate-100 border-slate-200 text-slate-700 hover:bg-slate-200'
                  }`}
                >
                  Batal
                </button>
                <button
                  type="submit"
                  disabled={editingRuleSubmitting}
                  className="px-5 py-2 rounded-lg bg-blue-600 hover:bg-blue-500 text-white font-semibold text-xs flex items-center justify-center gap-1.5 shadow-xs cursor-pointer transition-colors"
                >
                  {editingRuleSubmitting ? <RefreshCw className="w-3.5 h-3.5 animate-spin" /> : <Check className="w-3.5 h-3.5" />}
                  <span>Simpan Perubahan Parameter</span>
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* INCIDENT INVESTIGATION WORKBENCH MODAL (Matching Ticket Queue / Verified TP) */}
      {selectedDetailIncident && (
        <IncidentDetailModal
          incident={selectedDetailIncident}
          onClose={() => setSelectedDetailIncident(null)}
          theme={theme}
          isInbox={true}
          inboxStatus={getFpStatus(selectedDetailIncident)}
          auditInfo={getApprovalAuditDetails(selectedDetailIncident, decisionMap)}
          onOpenFpForm={(inc) => handleOpenModalForTicket({
            ...inc,
            bundleStatus: selectedDetailIncident.bundleStatus || inc.bundleStatus,
            policyStatus: selectedDetailIncident.policyStatus || inc.policyStatus,
            status: selectedDetailIncident.bundleStatus || selectedDetailIncident.policyStatus || inc.status
          })}
          onApprove={() => handleOpenModalForTicket(selectedDetailIncident)}
          onReject={() => handleRejectFromModal(selectedDetailIncident)}
        />
      )}
    </div>
  );
}
