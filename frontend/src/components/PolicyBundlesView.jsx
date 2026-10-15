import React, { useState, useEffect, useMemo } from 'react';
import { 
  Layers, Plus, X, Search, Check, AlertCircle, RefreshCw, 
  Shield, FileText, CheckCircle2, ChevronDown, ChevronUp,
  Copy, CheckCheck, Play, Server, Database, Globe, Tag,
  ExternalLink, Boxes, ArrowRight, ArrowLeft, Clock, ShieldCheck,
  Code, Filter, Terminal, Sparkles, Pencil, Calendar, Trash2,
  AlertTriangle, Loader2
} from 'lucide-react';

export default function PolicyBundlesView({ 
  isDark = true, 
  rules = [], 
  tuningRequests = [], 
  decisionMap = {},
  onRefreshRules, 
  onOpenModalForTicket, 
  onOpenEditRule, 
  onOpenManualModal,
  onOpenIncidentDetail
}) {
  const [groups, setGroups] = useState([]);
  const [sharedLists, setSharedLists] = useState([]);
  const [loading, setLoading] = useState(true);
  const [searchQuery, setSearchQuery] = useState('');
  const [selectedType, setSelectedType] = useState('ALL');
  const [selectedTenant, setSelectedTenant] = useState('ALL');
  const [expandedGroupId, setExpandedGroupId] = useState(null);
  const [groupDetails, setGroupDetails] = useState({});
  const [detailLoading, setDetailLoading] = useState(false);

  // Dedicated Tenant View & False Positive Tuning Tickets State (Mockup 1 & 2)
  const [selectedTenantView, setSelectedTenantView] = useState(null);
  const [apiTenants, setApiTenants] = useState([]);
  const [internalTuningRequests, setInternalTuningRequests] = useState([]);
  const [sessionAppliedTenants, setSessionAppliedTenants] = useState({});
  const [activeRightTab, setActiveRightTab] = useState('XML'); // 'XML' | 'CDB'
  const [tenantFilterStatus, setTenantFilterStatus] = useState('ALL'); // 'ALL' | 'ACTIVE' | 'WAITING' | 'EXPIRED'
  const [applyingTenant, setApplyingTenant] = useState(false);
  const [copiedCodeSnippet, setCopiedCodeSnippet] = useState(false);
  const [isEditingCode, setIsEditingCode] = useState(false);
  const [customCodeSnippets, setCustomCodeSnippets] = useState({});
  const [currentDraftCode, setCurrentDraftCode] = useState('');
  const [backupDraftCode, setBackupDraftCode] = useState('');

  // Per-item individual DEPLOY on/off toggle and expiration tracking
  const [itemDeployToggles, setItemDeployToggles] = useState(() => {
    try {
      const saved = localStorage.getItem('wazuh_policy_bundle_toggles');
      return saved ? JSON.parse(saved) : {};
    } catch {
      return {};
    }
  });

  const [itemExpirations, setItemExpirations] = useState(() => {
    try {
      const saved = localStorage.getItem('wazuh_policy_bundle_expirations');
      return saved ? JSON.parse(saved) : {};
    } catch {
      return {};
    }
  });

  const [extendModalItem, setExtendModalItem] = useState(null);
  const [newExpirationDate, setNewExpirationDate] = useState('');
  const [extendingLoading, setExtendingLoading] = useState(false);

  useEffect(() => {
    try {
      localStorage.setItem('wazuh_policy_bundle_toggles', JSON.stringify(itemDeployToggles));
    } catch (e) {
      console.warn(e);
    }
  }, [itemDeployToggles]);

  useEffect(() => {
    try {
      localStorage.setItem('wazuh_policy_bundle_expirations', JSON.stringify(itemExpirations));
    } catch (e) {
      console.warn(e);
    }
  }, [itemExpirations]);

  // Modals state
  const [showNewGroupModal, setShowNewGroupModal] = useState(false);
  const [newGroupForm, setNewGroupForm] = useState({
    group_name: '',
    group_type: 'USE_CASE',
    tenant_id: 'TenantC',
    description: '',
    target_hostname: '',
    mitre_tactics: '',
    auto_merge: true,
    priority: 'P2',
    owner: 'admin_secops'
  });

  const [showSyncModal, setShowSyncModal] = useState(false);
  const [syncData, setSyncData] = useState(null);
  const [syncLoading, setSyncLoading] = useState(false);
  const [copiedCode, setCopiedCode] = useState(false);

  const [showCdbModal, setShowCdbModal] = useState(false);
  const [newCdbForm, setNewCdbForm] = useState({
    list_name: '',
    list_type: 'IP',
    valuesText: '',
    description: ''
  });

  const [showMergeModal, setShowMergeModal] = useState(false);
  const [targetGroupForMerge, setTargetGroupForMerge] = useState(null);
  const [selectedRulesForMerge, setSelectedRulesForMerge] = useState([]);

  // Review & Edit Modals state
  const [showReviewModal, setShowReviewModal] = useState(false);
  const [targetGroupForReview, setTargetGroupForReview] = useState(null);
  const [reviewForm, setReviewForm] = useState({
    extend_days: 90,
    new_status: 'ACTIVE',
    notes: 'Periodical SLA review approved by SOC Lead'
  });

  const [showEditGroupModal, setShowEditGroupModal] = useState(false);
  const [editGroupForm, setEditGroupForm] = useState({
    group_id: '',
    group_name: '',
    description: '',
    tenant_id: 'TenantC',
    auto_merge: true,
    priority: 'P2',
    status: 'ACTIVE'
  });

  const [toast, setToast] = useState(null);

  const showNotification = (msg, type = 'success') => {
    setToast({ msg, type });
    setTimeout(() => setToast(null), 4000);
  };

  const fetchGroups = async () => {
    try {
      setLoading(true);
      const res = await fetch('http://localhost:8000/api/suppression/groups');
      if (res.ok) {
        const data = await res.json();
        setGroups(data.groups || []);
      }
    } catch (err) {
      console.warn('Fetch groups error:', err);
    } finally {
      setLoading(false);
    }
  };

  const fetchSharedLists = async () => {
    try {
      const res = await fetch('http://localhost:8000/api/suppression/shared-lists');
      if (res.ok) {
        const data = await res.json();
        setSharedLists(data.lists || []);
      }
    } catch (err) {
      console.warn('Fetch shared lists error:', err);
    }
  };

  const fetchTuningRequests = async () => {
    try {
      const res = await fetch('http://localhost:8000/api/suppression/tuning-requests');
      if (res.ok) {
        const data = await res.json();
        setInternalTuningRequests(data.requests || []);
      }
    } catch (err) {
      console.warn('Fetch tuning requests error:', err);
    }
  };

  const fetchApiTenants = async () => {
    try {
      const res = await fetch('http://localhost:8000/api/suppression/tenants');
      if (res.ok) {
        const data = await res.json();
        if (data.tenants && Array.isArray(data.tenants)) {
          setApiTenants(data.tenants);
        }
      }
    } catch (err) {
      console.warn('Fetch api tenants error:', err);
    }
  };

  useEffect(() => {
    fetchGroups();
    fetchSharedLists();
    fetchTuningRequests();
    fetchApiTenants();
  }, []);

  const handleToggleExpand = async (groupId) => {
    if (expandedGroupId === groupId) {
      setExpandedGroupId(null);
      return;
    }
    setExpandedGroupId(groupId);
    if (!groupDetails[groupId]) {
      try {
        setDetailLoading(true);
        const res = await fetch(`http://localhost:8000/api/suppression/groups/${groupId}`);
        if (res.ok) {
          const detail = await res.json();
          setGroupDetails(prev => ({ ...prev, [groupId]: detail }));
        }
      } catch (err) {
        console.warn('Fetch group detail error:', err);
      } finally {
        setDetailLoading(false);
      }
    }
  };

  const handleTriggerSync = async (groupId, groupName) => {
    try {
      setSyncLoading(true);
      setShowSyncModal(true);
      const res = await fetch(`http://localhost:8000/api/suppression/groups/${groupId}/sync-wazuh`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-API-Key': 'wazuh-soc-secure-key-2026'
        }
      });
      if (res.ok) {
        const data = await res.json();
        setSyncData({ ...data, group_name: groupName });
      } else {
        showNotification('Gagal melakukan sync dengan Wazuh API', 'error');
        setShowSyncModal(false);
      }
    } catch (err) {
      console.warn('Sync error:', err);
      showNotification('Koneksi sync ke Wazuh gagal', 'error');
      setShowSyncModal(false);
    } finally {
      setSyncLoading(false);
    }
  };

  const handleCreateGroup = async (e) => {
    e.preventDefault();
    try {
      const sharedScope = {};
      if (newGroupForm.target_hostname) {
        sharedScope.hostname = newGroupForm.target_hostname.trim();
      }
      const tactics = newGroupForm.mitre_tactics
        ? newGroupForm.mitre_tactics.split(',').map(t => t.trim()).filter(Boolean)
        : [];

      const res = await fetch('http://localhost:8000/api/suppression/groups', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-API-Key': 'wazuh-soc-secure-key-2026'
        },
        body: JSON.stringify({
          group_name: newGroupForm.group_name.trim(),
          group_type: newGroupForm.group_type,
          tenant_id: newGroupForm.tenant_id,
          description: newGroupForm.description,
          mitre_tactics: tactics,
          shared_scope: sharedScope,
          auto_merge: newGroupForm.auto_merge,
          priority: newGroupForm.priority,
          owner: newGroupForm.owner || 'admin_secops'
        })
      });

      if (res.ok) {
        const data = await res.json();
        showNotification(`Policy Bundle ${data.group?.group_id} berhasil dibuat!`);
        setShowNewGroupModal(false);
        setNewGroupForm({
          group_name: '',
          group_type: 'USE_CASE',
          tenant_id: 'TenantC',
          description: '',
          target_hostname: '',
          mitre_tactics: '',
          auto_merge: true,
          priority: 'P2',
          owner: 'admin_secops'
        });
        await fetchGroups();
      } else {
        const errJson = await res.json();
        showNotification(`Gagal: ${errJson.detail || 'Terjadi kesalahan'}`, 'error');
      }
    } catch (err) {
      showNotification('Gagal membuat grup kebijakan', 'error');
    }
  };

  const handleOpenReviewModal = (group) => {
    setTargetGroupForReview(group);
    setReviewForm({
      extend_days: 90,
      new_status: group.status || 'ACTIVE',
      notes: `Review berkala bundle ${group.group_id} disetujui oleh SOC Lead`
    });
    setShowReviewModal(true);
  };

  const handleExecuteReview = async (e) => {
    e.preventDefault();
    if (!targetGroupForReview) return;
    try {
      const res = await fetch(`http://localhost:8000/api/suppression/groups/${targetGroupForReview.group_id}/review`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-API-Key': 'wazuh-soc-secure-key-2026'
        },
        body: JSON.stringify({
          extend_days: parseInt(reviewForm.extend_days, 10) || 90,
          new_status: reviewForm.new_status,
          notes: reviewForm.notes,
          performed_by: 'admin_secops'
        })
      });
      if (res.ok) {
        const data = await res.json();
        showNotification(`Bundle ${targetGroupForReview.group_id}: ${data.updated_rules_count} aturan anak berhasil diperpanjang (+${data.extend_days} hari)!`);
        setShowReviewModal(false);
        setGroupDetails(prev => {
          const next = { ...prev };
          delete next[targetGroupForReview.group_id];
          return next;
        });
        await fetchGroups();
        if (onRefreshRules) onRefreshRules();
      } else {
        showNotification('Gagal melakukan review bundle', 'error');
      }
    } catch (err) {
      showNotification('Terjadi kesalahan saat review', 'error');
    }
  };

  const handleOpenEditModal = (group) => {
    setEditGroupForm({
      group_id: group.group_id,
      group_name: group.group_name || '',
      description: group.description || '',
      tenant_id: group.tenant_id || 'TenantC',
      auto_merge: group.auto_merge ?? true,
      priority: group.priority || 'P2',
      status: group.status || 'ACTIVE'
    });
    setShowEditGroupModal(true);
  };

  const handleExecuteEditGroup = async (e) => {
    e.preventDefault();
    try {
      const res = await fetch(`http://localhost:8000/api/suppression/groups/${editGroupForm.group_id}`, {
        method: 'PUT',
        headers: {
          'Content-Type': 'application/json',
          'X-API-Key': 'wazuh-soc-secure-key-2026'
        },
        body: JSON.stringify({
          group_name: editGroupForm.group_name.trim(),
          description: editGroupForm.description,
          auto_merge: editGroupForm.auto_merge,
          priority: editGroupForm.priority,
          status: editGroupForm.status
        })
      });
      if (res.ok) {
        showNotification(`Bundle ${editGroupForm.group_id} berhasil diperbarui!`);
        setShowEditGroupModal(false);
        await fetchGroups();
      } else {
        showNotification('Gagal memperbarui bundle', 'error');
      }
    } catch (err) {
      showNotification('Terjadi kesalahan update', 'error');
    }
  };

  const handleArchiveGroup = async (group) => {
    if (!window.confirm(`Nonaktifkan / Hapus supresi bundle ${group.group_id} (${group.group_name}) beserta semua aturan di dalamnya?`)) return;
    try {
      const res = await fetch(`http://localhost:8000/api/suppression/groups/${group.group_id}/review`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-API-Key': 'wazuh-soc-secure-key-2026'
        },
        body: JSON.stringify({
          extend_days: 0,
          new_status: 'ARCHIVED',
          notes: 'Bundle dinonaktifkan / dicabut oleh admin_secops',
          performed_by: 'admin_secops'
        })
      });
      if (res.ok) {
        showNotification(`Bundle ${group.group_id} dan seluruh aturannya telah dinonaktifkan (ARCHIVED).`);
        await fetchGroups();
        if (onRefreshRules) onRefreshRules();
      } else {
        showNotification('Gagal menonaktifkan bundle', 'error');
      }
    } catch (err) {
      showNotification('Terjadi kesalahan', 'error');
    }
  };

  const handleUnlinkRule = async (ruleId, groupId) => {
    if (!window.confirm(`Lepas aturan ${ruleId} dari bundle ini agar kembali menjadi aturan mandiri?`)) return;
    try {
      const res = await fetch(`http://localhost:8000/api/suppression/rules/${ruleId}/unlink-group`, {
        method: 'POST',
        headers: {
          'X-API-Key': 'wazuh-soc-secure-key-2026'
        }
      });
      if (res.ok) {
        showNotification(`Aturan ${ruleId} berhasil dilepas dari bundle.`);
        setGroupDetails(prev => {
          const next = { ...prev };
          delete next[groupId];
          return next;
        });
        await fetchGroups();
        if (onRefreshRules) onRefreshRules();
      } else {
        showNotification('Gagal melepas aturan', 'error');
      }
    } catch (err) {
      showNotification('Terjadi kesalahan unlink', 'error');
    }
  };

  const handleCreateCdbList = async (e) => {
    e.preventDefault();
    try {
      const values = newCdbForm.valuesText
        .split('\n')
        .map(v => v.trim())
        .filter(Boolean);

      const res = await fetch('http://localhost:8000/api/suppression/shared-lists', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-API-Key': 'wazuh-soc-secure-key-2026'
        },
        body: JSON.stringify({
          list_name: newCdbForm.list_name.trim(),
          list_type: newCdbForm.list_type,
          values: values,
          description: newCdbForm.description,
          referenced_by: []
        })
      });

      if (res.ok) {
        const data = await res.json();
        showNotification(`Shared CDB List ${data.list?.list_id} (${values.length} entri) berhasil dibuat!`);
        setShowCdbModal(false);
        setNewCdbForm({ list_name: '', list_type: 'IP', valuesText: '', description: '' });
        await fetchSharedLists();
      } else {
        showNotification('Gagal membuat shared list', 'error');
      }
    } catch (err) {
      showNotification('Gagal membuat shared list', 'error');
    }
  };

  const handleOpenMergeModal = (group) => {
    setTargetGroupForMerge(group);
    setSelectedRulesForMerge([]);
    setShowMergeModal(true);
  };

  const handleExecuteMerge = async () => {
    if (!targetGroupForMerge || selectedRulesForMerge.length === 0) return;
    try {
      const res = await fetch(`http://localhost:8000/api/suppression/groups/${targetGroupForMerge.group_id}/merge`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-API-Key': 'wazuh-soc-secure-key-2026'
        },
        body: JSON.stringify({
          suppression_ids: selectedRulesForMerge,
          performed_by: 'admin_secops'
        })
      });
      if (res.ok) {
        const data = await res.json();
        showNotification(`${data.merged_count} aturan berhasil digabungkan ke ${targetGroupForMerge.group_id}!`);
        setShowMergeModal(false);
        setGroupDetails(prev => {
          const next = { ...prev };
          delete next[targetGroupForMerge.group_id];
          return next;
        });
        await fetchGroups();
        if (onRefreshRules) onRefreshRules();
      } else {
        showNotification('Gagal menggabungkan aturan', 'error');
      }
    } catch (err) {
      showNotification('Terjadi kesalahan saat merge', 'error');
    }
  };

  const copyToClipboard = (text) => {
    navigator.clipboard.writeText(text);
    setCopiedCode(true);
    setTimeout(() => setCopiedCode(false), 2000);
  };

  // Format tenant identifier into clean human-readable name matching the wireframe sketch
  const formatTenantDisplay = (t) => {
    if (!t) return '';
    if (t === 'TenantA') return 'Tenant A';
    if (t === 'TenantB') return 'Tenant B';
    if (t === 'TenantC') return 'Tenant C';
    if (t === 'TenantD') return 'Tenant D';
    if (t === 'SOC_CORE') return 'SOC Core';
    return t.replace(/^(Tenant)([A-Z0-9]+)$/i, '$1 $2').replace(/_/g, ' ');
  };

  const activeTuningRequests = (tuningRequests && tuningRequests.length > 0)
    ? tuningRequests
    : internalTuningRequests;

  // Dynamic discovery of ALL tenants present in API, tuningRequests, rules, and groups
  const discoveredTenants = useMemo(() => {
    const tenantSet = new Set(['TenantA', 'TenantB', 'TenantC', 'TenantD', 'SOC_CORE']);

    apiTenants.forEach(t => {
      if (t && t !== 'DEFAULT' && t !== 'ALL') tenantSet.add(t);
    });

    activeTuningRequests.forEach(req => {
      const t = req.tenant_id || req.tenant;
      if (t && t !== 'DEFAULT' && t !== 'ALL') tenantSet.add(t);
    });

    rules.forEach(r => {
      const t = r.tenantId || r.tenant_id;
      if (t && t !== 'DEFAULT' && t !== 'ALL') tenantSet.add(t);
    });

    groups.forEach(g => {
      const t = g.tenant_id;
      if (t && t !== 'DEFAULT' && t !== 'ALL') tenantSet.add(t);
    });

    const priorityOrder = { 'TenantA': 1, 'TenantB': 2, 'TenantC': 3, 'TenantD': 4, 'SOC_CORE': 5 };
    return Array.from(tenantSet).sort((a, b) => {
      const pA = priorityOrder[a] || 99;
      const pB = priorityOrder[b] || 99;
      if (pA !== pB) return pA - pB;
      return a.localeCompare(b);
    });
  }, [apiTenants, activeTuningRequests, rules, groups]);

  // Helper for Mockup 2: items for selected tenant
  const getTenantTableItems = (tenantName) => {
    if (!tenantName) return [];

    const isAppliedInSession = !!sessionAppliedTenants[tenantName];

    // Rules for this tenant
    const tRules = rules.filter(r => {
      const t = r.tenantId || r.tenant_id || 'DEFAULT';
      return t === tenantName || (tenantName === 'TenantA' && t === 'DEFAULT');
    });

    // Approved tickets for this tenant (originating from approved false positives)
    const reqs = activeTuningRequests.filter(req => {
      const t = req.tenant_id || req.tenant || 'DEFAULT';
      const matches = t === tenantName || (tenantName === 'TenantA' && t === 'DEFAULT');
      if (!matches) return false;

      const dec = decisionMap[req.triage_id] || decisionMap[req.incident_id];
      if (dec && (dec.status === 'reject' || dec.status === 'REJECT')) return false;

      const isApprovedInDecision = dec && (dec.status === 'approve' || dec.status === 'APPROVED');
      const isApprovedInReq = req.is_approved || String(req.fp_status || '').toLowerCase() === 'approve' || String(req.triage_status || '').toUpperCase() === 'APPROVED';
      const hasLinkedRule = !!req.existing_suppression_id || tRules.some(r => 
        r.ticketId === req.triage_id || 
        r.ticketId === req.incident_id ||
        r.id === req.existing_suppression_id ||
        r.id === req.suppression_id ||
        r.scopeDefinition?.referenced_ticket_id === req.triage_id
      );

      return isApprovedInDecision || isApprovedInReq || hasLinkedRule;
    });

    const items = [];

    // Map requests
    reqs.forEach((req, idx) => {
      const linkedRule = tRules.find(r => 
        r.ticketId === req.triage_id || 
        r.ticketId === req.incident_id ||
        r.id === req.existing_suppression_id ||
        r.id === req.suppression_id ||
        r.scopeDefinition?.referenced_ticket_id === req.triage_id
      );

      const itemKey = req.triage_id || req.incident_id || req.suppression_id || `SUP-${idx}`;

      // 1. Expiration check: check custom expiration or DB expiration
      let isExpired = false;
      const currentExpDate = itemExpirations[itemKey] || linkedRule?.expires_date || linkedRule?.expiration || req.expires_date;
      if (currentExpDate) {
        const expObj = new Date(currentExpDate);
        const today = new Date();
        today.setHours(0, 0, 0, 0);
        if (expObj <= today) {
          isExpired = true;
        }
      } else if (linkedRule) {
        if ((linkedRule.daysRemaining !== undefined && linkedRule.daysRemaining <= 0) || linkedRule.status === 'EXPIRED') {
          isExpired = true;
        }
      }

      // 2. Lifecycle Status: FP approved -> default APPROVE; toggle ON -> DEPLOY; expired -> EXPIRED
      let itemStatus = 'APPROVE';
      if (isExpired) {
        itemStatus = 'EXPIRED';
      } else if (itemDeployToggles[itemKey] !== undefined) {
        itemStatus = itemDeployToggles[itemKey] ? 'DEPLOY' : 'APPROVE';
      } else if (isAppliedInSession) {
        itemStatus = 'DEPLOY';
      } else if (linkedRule?.status === 'ACTIVE' || linkedRule?.status === 'DEPLOY' || linkedRule?.status === 'TUNED_IN_WAZUH_XML') {
        itemStatus = 'DEPLOY';
      } else {
        itemStatus = 'APPROVE';
      }

      // Classification label without S1-S5 prefix (cukup FALSE POSITIVE, KNOWN GOOD, dll)
      let classi = 'FALSE POSITIVE';
      const rLower = (req.false_positive_reason || '').toLowerCase();
      if (rLower.includes('known') || rLower.includes('healthcheck') || rLower.includes('benign')) {
        classi = 'KNOWN GOOD';
      } else if (rLower.includes('admin') || rLower.includes('sudo') || rLower.includes('elevat')) {
        classi = 'CONDITIONAL';
      } else if (rLower.includes('scanner') || rLower.includes('pentest')) {
        classi = 'EXCEPTION';
      } else if (rLower.includes('maint') || rLower.includes('patch')) {
        classi = 'MAINTENANCE';
      }

      items.push({
        id: req.suppression_id || req.triage_id || `SUP-2026-${100 + idx}`,
        ticketNo: req.triage_id || req.incident_id || `TRG-${tenantName}-${idx + 1}`,
        incidentTitle: req.judul_insiden || 'Security Incident Tuning',
        classi,
        actor: req.attacker_source_ip && req.attacker_source_ip !== '-' ? req.attacker_source_ip : 'Internal / N/A',
        target: req.target_host && req.target_host !== '-' ? req.target_host : '-',
        status: itemStatus,
        isExpired,
        expirationDate: currentExpDate,
        sids: req.rule_ids && req.rule_ids.length > 0 ? req.rule_ids : (req.sids || [5502, 5501]),
        raw: req,
        isRule: false
      });
    });

    // Also include any rules in tRules not already matched
    tRules.forEach((r, idx) => {
      const exists = items.some(it => it.id === r.id || it.ticketNo === r.ticketId);
      if (!exists) {
        const ruleKey = r.ticketId || r.id || `RULE-${idx}`;
        let isExp = false;
        const currentExpDate = itemExpirations[ruleKey] || r.expires_date || r.expiration;
        if (currentExpDate) {
          const expObj = new Date(currentExpDate);
          const today = new Date();
          today.setHours(0, 0, 0, 0);
          if (expObj <= today) {
            isExp = true;
          }
        } else if ((r.daysRemaining !== undefined && r.daysRemaining <= 0) || r.status === 'EXPIRED') {
          isExp = true;
        }

        let ruleStatus = 'APPROVE';
        if (isExp) {
          ruleStatus = 'EXPIRED';
        } else if (itemDeployToggles[ruleKey] !== undefined) {
          ruleStatus = itemDeployToggles[ruleKey] ? 'DEPLOY' : 'APPROVE';
        } else if (isAppliedInSession) {
          ruleStatus = 'DEPLOY';
        } else if (r.status === 'ACTIVE' || r.status === 'DEPLOY' || r.status === 'TUNED_IN_WAZUH_XML') {
          ruleStatus = 'DEPLOY';
        } else {
          ruleStatus = 'APPROVE';
        }

        let classiRule = 'KNOWN GOOD';
        if (r.classification) {
          classiRule = r.classification.replace(/^S\d+\s*•\s*/i, '').replace(/^S\d+_/i, '').replace(/_/g, ' ').toUpperCase();
        }

        items.push({
          id: r.id || `SUP-${idx}`,
          ticketNo: r.ticketId || r.id,
          incidentTitle: r.name || 'Suppression Rule',
          classi: classiRule,
          actor: r.actorIp || 'Internal / N/A',
          target: r.targetHost || '-',
          status: ruleStatus,
          isExpired: isExp,
          expirationDate: currentExpDate,
          sids: r.sids || [5501],
          raw: r,
          isRule: true
        });
      }
    });

    return items;
  };

  // Calculate real metrics for Mockup 1 (huruf x diisi oleh angka aslinya)
  const getTenantStats = (tenantName) => {
    const items = getTenantTableItems(tenantName);
    const deployCount = items.filter(it => it.status === 'DEPLOY').length;
    const approveCount = items.filter(it => it.status === 'APPROVE').length;
    const expiredCount = items.filter(it => it.status === 'EXPIRED').length;

    return {
      totalTickets: items.length,
      deployCount,
      approveCount,
      expiredCount,
      activeCount: deployCount,
      waitingCount: approveCount
    };
  };



  // Helper for generating Wazuh XML rule level="0"
  const generateTenantXml = (tenantName, items) => {
    const safeTenant = (tenantName || 'default').toLowerCase().replace(/[^a-z0-9]/g, '_');
    const lines = [
      `<!-- ===================================================================== -->`,
      `<!-- Wazuh Analysisd Suppression Rules for ${tenantName} -->`,
      `<!-- Level="0" Drop Rule Engine / Local Analysisd Mute -->`,
      `<!-- ===================================================================== -->`,
      `<group name="suppression,asoc_tuned,${safeTenant}">`,
      ``
    ];

    let startId = 100200 + (tenantName === 'TenantA' ? 10 : tenantName === 'TenantB' ? 30 : tenantName === 'TenantC' ? 50 : 70);

    items.forEach((item, i) => {
      const sidsStr = Array.isArray(item.sids) && item.sids.length > 0 ? item.sids.join(', ') : '5501, 5502';
      lines.push(`  <!-- Item ${i + 1}: ${item.incidentTitle.substring(0, 45)} [${item.ticketNo}] -->`);
      lines.push(`  <rule id="${startId + i}" level="0">`);
      lines.push(`    <if_sid>${sidsStr}</if_sid>`);
      if (item.target && item.target !== '-' && item.target !== 'Internal / N/A') {
        lines.push(`    <hostname>${item.target}</hostname>`);
      }
      if (item.actor && item.actor !== '-' && item.actor !== 'Internal / N/A') {
        lines.push(`    <srcip>${item.actor}</srcip>`);
      }
      lines.push(`    <description>ASOC Tuned Suppression: ${item.incidentTitle.substring(0, 60)} [${item.ticketNo}]</description>`);
      lines.push(`  </rule>`);
      lines.push(``);
    });

    lines.push(`</group>`);
    return lines.join('\n');
  };

  // Helper for generating CDB List whitelist
  const generateTenantCdb = (tenantName, items) => {
    const safeTenant = (tenantName || 'default').toLowerCase().replace(/[^a-z0-9]/g, '_');
    const lines = [
      `# =====================================================================`,
      `# Wazuh Constant Database (CDB) Whitelist for ${tenantName}`,
      `# Target File: /var/ossec/etc/lists/asoc-whitelist-${safeTenant}`,
      `# =====================================================================`,
      ``,
      `# Source IPs:`
    ];

    const ips = new Set();
    const hosts = new Set();

    items.forEach(it => {
      if (it.actor && it.actor !== '-' && it.actor !== 'Internal / N/A') ips.add(it.actor);
      if (it.target && it.target !== '-' && it.target !== 'Internal / N/A') hosts.add(it.target);
    });

    if (ips.size > 0) {
      ips.forEach(ip => lines.push(`${ip}:`));
    } else {
      lines.push(`# (None)`);
    }

    lines.push(``);
    lines.push(`# Target Hostnames:`);
    if (hosts.size > 0) {
      hosts.forEach(h => lines.push(`${h}:`));
    } else {
      lines.push(`# (None)`);
    }

    return lines.join('\n');
  };

  const handleStartEdit = (currentContent) => {
    setCurrentDraftCode(currentContent);
    setBackupDraftCode(currentContent);
    setIsEditingCode(true);
  };

  const handleCancelEdit = () => {
    setCurrentDraftCode(backupDraftCode);
    setIsEditingCode(false);
    showNotification('Editan kode dibatalkan, kembali ke versi awal.', 'info');
  };

  // Apply to Wazuh handler (supports both generated and custom edited XML/CDB)
  const handleApplyTenant = async (tenantName) => {
    try {
      setApplyingTenant(true);
      const payload = {};

      if (isEditingCode) {
        if (activeRightTab === 'XML') {
          payload.custom_xml = currentDraftCode;
          setCustomCodeSnippets(prev => ({
            ...prev,
            [tenantName]: { ...prev[tenantName], xml: currentDraftCode }
          }));
        } else {
          payload.custom_cdb = currentDraftCode;
          setCustomCodeSnippets(prev => ({
            ...prev,
            [tenantName]: { ...prev[tenantName], cdb: currentDraftCode }
          }));
        }
      } else if (customCodeSnippets[tenantName]) {
        if (customCodeSnippets[tenantName].xml) payload.custom_xml = customCodeSnippets[tenantName].xml;
        if (customCodeSnippets[tenantName].cdb) payload.custom_cdb = customCodeSnippets[tenantName].cdb;
      }

      const res = await fetch(`http://localhost:8000/api/suppression/tenants/${tenantName}/apply`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify(payload)
      });
      if (res.ok) {
        const data = await res.json();
        setSessionAppliedTenants(prev => ({ ...prev, [tenantName]: true }));
        setIsEditingCode(false);
        showNotification(`✓ ${data.message || `Berhasil meng-apply aturan supresi ke Wazuh Manager untuk ${tenantName}`}`);
        if (onRefreshRules) onRefreshRules();
        fetchTuningRequests();
        fetchGroups();
      } else {
        showNotification('Gagal meng-apply supresi ke Wazuh', 'error');
      }
    } catch (err) {
      showNotification('Terjadi kesalahan saat apply ke Wazuh', 'error');
    } finally {
      setApplyingTenant(false);
    }
  };

  const handleActionClick = (item) => {
    if (onOpenIncidentDetail) {
      const ticketId = item.ticketNo || item.id || item.raw?.triage_id || item.raw?.ticketId || item.raw?.incident_id;
      const matchedReq = (tuningRequests || []).find(req => 
        req.triage_id === ticketId || 
        req.incident_id === ticketId ||
        req.id === ticketId ||
        req.suppression_id === item.id ||
        req.existing_suppression_id === item.id ||
        (item.raw && (req.triage_id === item.raw.ticketId || req.incident_id === item.raw.ticketId))
      );

      const targetData = matchedReq || item.raw || item;
      onOpenIncidentDetail({
        ...targetData,
        triage_id: ticketId,
        id: ticketId,
        incident_id: targetData.incident_id || ticketId,
        judul_insiden: item.incidentTitle || targetData.judul_insiden || targetData.title || targetData.name,
        title: item.incidentTitle || targetData.judul_insiden || targetData.title || targetData.name,
        target_host: item.target || targetData.target_host || targetData.targetHost,
        asset: item.target || targetData.target_host || targetData.targetHost,
        attacker_source_ip: item.actor || targetData.attacker_source_ip || targetData.actorIp,
        attackerIp: item.actor || targetData.attacker_source_ip || targetData.actorIp,
        tenant_id: selectedTenantView || targetData.tenant_id || targetData.tenant,
        rule_ids: item.sids || targetData.rule_ids || targetData.sids,
        status: item.status,
        bundleStatus: item.status,
        policyStatus: item.status,
        isExpired: item.isExpired,
        expirationDate: item.expirationDate
      });
    } else if (item.isRule && onOpenEditRule) {
      onOpenEditRule(item.raw);
    } else if (onOpenModalForTicket) {
      onOpenModalForTicket(item.raw || item);
    } else {
      showNotification(`Tiket ${item.ticketNo} siap ditinjau.`);
    }
  };

  const handleToggleDeploy = async (item) => {
    if (item.status === 'EXPIRED' || item.isExpired) {
      setExtendModalItem(item);
      const defaultDate = new Date();
      defaultDate.setDate(defaultDate.getDate() + 90);
      setNewExpirationDate(defaultDate.toISOString().split('T')[0]);
      return;
    }

    const currentIsDeploy = item.status === 'DEPLOY';
    const nextIsDeploy = !currentIsDeploy;
    const itemKey = item.ticketNo || item.id;
    const allKeys = [
      itemKey,
      item.ticketNo,
      item.id,
      item.raw?.triage_id,
      item.raw?.incident_id
    ].filter(Boolean);

    // Optimistic local update
    setItemDeployToggles(prev => {
      const updated = { ...prev };
      allKeys.forEach(k => { updated[k] = nextIsDeploy; });
      return updated;
    });

    // If item has a linked rule in DB or is a rule, update status in backend
    const ruleId = item.isRule ? item.id : (item.raw?.existing_suppression_id || item.raw?.suppression_id || (item.id && String(item.id).startsWith('SUP-') ? item.id : null));
    if (ruleId) {
      try {
        await fetch(`http://localhost:8000/api/suppression/rules/${ruleId}`, {
          method: 'PUT',
          headers: { 
            'Content-Type': 'application/json',
            'X-API-Key': 'wazuh-soc-secure-key-2026'
          },
          body: JSON.stringify({
            status: nextIsDeploy ? 'DEPLOY' : 'APPROVE',
            reviewer: 'soc_analyst',
            reason: nextIsDeploy 
              ? `Status diaktifkan (DEPLOY) ke Wazuh via toggle oleh soc_analyst` 
              : `Status dinonaktifkan (APPROVE) via toggle oleh soc_analyst`
          })
        });
        if (onRefreshRules) onRefreshRules();
      } catch (err) {
        console.warn("Could not sync toggle to backend:", err);
      }
    }

    showNotification(
      nextIsDeploy 
        ? `Tiket ${item.ticketNo} dialihkan ke DEPLOY (Aktif)` 
        : `Tiket ${item.ticketNo} dialihkan ke APPROVE (Menunggu deploy)`,
      'success'
    );
  };

  const handleSaveExtendExpiration = async (e) => {
    if (e) e.preventDefault();
    if (!extendModalItem || !newExpirationDate) return;

    try {
      setExtendingLoading(true);
      const itemKey = extendModalItem.ticketNo || extendModalItem.id;
      const ruleId = extendModalItem.isRule 
        ? extendModalItem.id 
        : (extendModalItem.raw?.existing_suppression_id || extendModalItem.raw?.suppression_id || (extendModalItem.id && String(extendModalItem.id).startsWith('SUP-') ? extendModalItem.id : null));

      if (ruleId) {
        const res = await fetch(`http://localhost:8000/api/suppression/rules/${ruleId}`, {
          method: 'PUT',
          headers: { 
            'Content-Type': 'application/json',
            'X-API-Key': 'wazuh-soc-secure-key-2026'
          },
          body: JSON.stringify({
            expiration: newExpirationDate,
            status: 'APPROVE',
            reviewer: 'soc_analyst',
            reason: `Perpanjangan masa berlaku supresi hingga ${newExpirationDate} oleh soc_analyst`
          })
        });
        if (!res.ok) {
          throw new Error("Gagal memperbarui masa berlaku di server.");
        }
      }

      const allKeys = [
        itemKey,
        extendModalItem.ticketNo,
        extendModalItem.id,
        extendModalItem.raw?.triage_id,
        extendModalItem.raw?.incident_id
      ].filter(Boolean);

      // Record new expiration date in local state
      setItemExpirations(prev => {
        const next = { ...prev };
        allKeys.forEach(k => { next[k] = newExpirationDate; });
        return next;
      });
      // Reset toggle to false (APPROVE) so analyst can now toggle it ON
      setItemDeployToggles(prev => {
        const next = { ...prev };
        allKeys.forEach(k => { next[k] = false; });
        return next;
      });

      showNotification(`✓ Masa berlaku tiket ${extendModalItem.ticketNo} diperpanjang hingga ${newExpirationDate}. Status kini APPROVE dan tombol Deploy dapat diaktifkan.`, 'success');
      setExtendModalItem(null);
      if (onRefreshRules) onRefreshRules();
    } catch (err) {
      showNotification(`Gagal memperpanjang masa berlaku: ${err.message}`, 'error');
    } finally {
      setExtendingLoading(false);
    }
  };

  return (
    <div className="space-y-4">
      {/* Toast Notification */}
      {toast && (
        <div className={`p-3 rounded-lg text-xs flex items-center justify-between shadow-lg border ${
          toast.type === 'error' 
            ? 'bg-rose-950/90 border-rose-700 text-rose-200' 
            : 'bg-emerald-950/90 border-emerald-700 text-emerald-200'
        }`}>
          <div className="flex items-center gap-2">
            {toast.type === 'error' ? <AlertCircle className="w-4 h-4 text-rose-400" /> : <CheckCircle2 className="w-4 h-4 text-emerald-400" />}
            <span>{toast.msg}</span>
          </div>
          <button onClick={() => setToast(null)} className="p-1 hover:opacity-80">
            <X className="w-3.5 h-3.5" />
          </button>
        </div>
      )}

      {/* ===================================================================== */}
      {/* MOCKUP 1: MAIN POLICY BUNDLE PAGE (2x2 GRID PER TENANT) */}
      {/* ===================================================================== */}
      {!selectedTenantView && (
        <div className="space-y-4">
          {/* Dynamic Grid of Tenant Boxes matching Sketch */}
          <div className="grid grid-cols-1 md:grid-cols-2 gap-6 pt-1">
            {discoveredTenants.map(tenantName => {
              const stats = getTenantStats(tenantName);
              const displayName = formatTenantDisplay(tenantName);
              return (
                <div
                  key={tenantName}
                  onClick={() => setSelectedTenantView(tenantName)}
                  className={`group rounded-2xl border p-6 transition-all cursor-pointer shadow-lg hover:shadow-2xl relative ${
                    isDark 
                      ? 'bg-[#0a0f1d] border-slate-800 hover:border-indigo-500/70 hover:bg-[#0c1224]' 
                      : 'bg-white border-slate-200 hover:border-indigo-400 shadow-sm'
                  }`}
                >
                  {/* Card Header: Title on Left, detail button on Right */}
                  <div className="flex items-center justify-between border-b pb-4 mb-5 border-slate-800/80">
                    <div className="flex items-center gap-2.5">
                      <h3 className={`text-xl font-black tracking-wider uppercase ${isDark ? 'text-white' : 'text-slate-900'}`}>
                        {displayName.toUpperCase()}
                      </h3>
                      {tenantName === 'SOC_CORE' && (
                        <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-blue-500/10 text-blue-400 border border-blue-500/30 font-bold uppercase tracking-wider">
                          Internal
                        </span>
                      )}
                    </div>
                    <button
                      type="button"
                      onClick={(e) => {
                        e.stopPropagation();
                        setSelectedTenantView(tenantName);
                      }}
                      className="text-xs font-semibold px-3 py-1 rounded-lg bg-indigo-500/10 hover:bg-indigo-500/25 text-indigo-400 border border-indigo-500/30 transition-all flex items-center gap-1.5 group-hover:scale-105 cursor-pointer"
                    >
                      <span>detail</span>
                      <ArrowRight className="w-3.5 h-3.5" />
                    </button>
                  </div>

                  {/* Card Body: 4 rows with real numbers replacing x */}
                  <div className="space-y-3.5 font-mono text-sm">
                    <div className="flex items-center justify-between py-1 border-b border-slate-800/40">
                      <span className={`font-medium ${isDark ? 'text-slate-300' : 'text-slate-700'}`}>
                        suppression ticket
                      </span>
                      <span className={`text-base font-black px-2.5 py-0.5 rounded ${
                        isDark ? 'bg-slate-800 text-slate-100' : 'bg-slate-100 text-slate-900'
                      }`}>
                        {stats.totalTickets}
                      </span>
                    </div>

                    <div className="flex items-center justify-between py-1 border-b border-slate-800/40">
                      <span className="font-semibold text-blue-400 flex items-center gap-2">
                        <span className="w-2 h-2 rounded-full bg-blue-400"></span>
                        DEPLOY
                      </span>
                      <span className="text-base font-black text-blue-400 px-2.5 py-0.5 rounded bg-blue-500/10 border border-blue-500/20">
                        {stats.deployCount}
                      </span>
                    </div>

                    <div className="flex items-center justify-between py-1 border-b border-slate-800/40">
                      <span className="font-semibold text-emerald-400 flex items-center gap-2">
                        <span className="w-2 h-2 rounded-full bg-emerald-400"></span>
                        APPROVE
                      </span>
                      <span className="text-base font-black text-emerald-400 px-2.5 py-0.5 rounded bg-emerald-500/10 border border-emerald-500/20">
                        {stats.approveCount}
                      </span>
                    </div>

                    <div className="flex items-center justify-between py-1">
                      <span className="font-medium text-rose-400 flex items-center gap-2">
                        <span className="w-2 h-2 rounded-full bg-rose-500"></span>
                        EXPIRED
                      </span>
                      <span className="text-base font-black text-rose-400 px-2.5 py-0.5 rounded bg-rose-500/10 border border-rose-500/20">
                        {stats.expiredCount}
                      </span>
                    </div>
                  </div>
                </div>
              );
            })}
          </div>
        </div>
      )}

      {/* ===================================================================== */}
      {/* MOCKUP 2: SUB-FITUR PER TENANT (SPLIT VIEW TABLE & WAZUH APPLY) */}
      {/* ===================================================================== */}
      {selectedTenantView && (() => {
        const rawItems = getTenantTableItems(selectedTenantView);
        const filteredItems = rawItems.filter(it => {
          if (tenantFilterStatus === 'DEPLOY' || tenantFilterStatus === 'ACTIVE') return it.status === 'DEPLOY';
          if (tenantFilterStatus === 'APPROVE' || tenantFilterStatus === 'WAITING') return it.status === 'APPROVE';
          if (tenantFilterStatus === 'EXPIRED') return it.status === 'EXPIRED';
          return true;
        });

        const generatedXml = generateTenantXml(selectedTenantView, rawItems);
        const generatedCdb = generateTenantCdb(selectedTenantView, rawItems);
        const xmlSnippet = customCodeSnippets[selectedTenantView]?.xml ?? generatedXml;
        const cdbSnippet = customCodeSnippets[selectedTenantView]?.cdb ?? generatedCdb;
        const currentActiveCode = activeRightTab === 'XML' ? xmlSnippet : cdbSnippet;
        const displayedCode = isEditingCode ? currentDraftCode : currentActiveCode;

        return (
          <div className="space-y-4">
            {/* Header matching Sketch: suppression / policy bundle / Tenant A */}
            <div className={`p-4 rounded-xl border flex items-center justify-between gap-4 flex-wrap md:flex-nowrap ${
              isDark ? 'bg-[#0a0f1d] border-slate-800' : 'bg-white border-slate-200 shadow-xs'
            }`}>
              <div className="flex items-center gap-2">
                <span className="text-xs sm:text-sm font-mono uppercase tracking-wider text-slate-400">suppression</span>
                <span className="text-slate-600 font-bold">/</span>
                <button 
                  onClick={() => {
                    setIsEditingCode(false);
                    setSelectedTenantView(null);
                  }}
                  className="text-xs sm:text-sm font-mono uppercase tracking-wider text-slate-400 hover:text-white transition-colors cursor-pointer"
                >
                  policy bundle
                </button>
                <span className="text-slate-600 font-bold">/</span>
                <span className="text-xs sm:text-sm font-bold uppercase tracking-wider text-indigo-400 font-mono">
                  {formatTenantDisplay(selectedTenantView)}
                </span>
              </div>

              {/* Right Controls matching sketch: [ All v ] filter dropdown and [ X ] close button */}
              <div className="flex items-center gap-3">
                <div className="relative">
                  <select
                    value={tenantFilterStatus}
                    onChange={(e) => setTenantFilterStatus(e.target.value)}
                    className={`px-3 py-1.5 rounded-lg border text-xs font-semibold cursor-pointer appearance-none pr-8 ${
                      isDark 
                        ? 'bg-slate-900 border-slate-700 text-slate-200 focus:border-indigo-500' 
                        : 'bg-white border-slate-300 text-slate-800'
                    }`}
                  >
                    <option value="ALL">All</option>
                    <option value="DEPLOY">DEPLOY</option>
                    <option value="APPROVE">APPROVE</option>
                    <option value="EXPIRED">EXPIRED</option>
                  </select>
                  <ChevronDown className="w-3.5 h-3.5 text-slate-400 absolute right-2.5 top-1/2 -translate-y-1/2 pointer-events-none" />
                </div>

                <button
                  type="button"
                  onClick={() => {
                    setIsEditingCode(false);
                    setSelectedTenantView(null);
                  }}
                  className={`p-1.5 rounded-lg border text-slate-400 hover:text-white transition-all cursor-pointer ${
                    isDark ? 'bg-slate-800/80 border-slate-700 hover:bg-slate-700' : 'bg-slate-100 border-slate-300 hover:bg-slate-200'
                  }`}
                  title="Kembali ke Daftar Tenant"
                >
                  <X className="w-4 h-4" />
                </button>
              </div>
            </div>

            {/* Split Screen Layout matching Sketch: Left Table (7 cols) + Right Wazuh Config (5 cols) */}
            <div className="grid grid-cols-1 lg:grid-cols-12 gap-3.5 items-start">
              {/* LEFT PANEL: TABLE OF TICKETS/POLICIES */}
              <div className={`lg:col-span-7 rounded-2xl border overflow-hidden ${
                isDark ? 'bg-[#0a0f1d] border-slate-800' : 'bg-white border-slate-200 shadow-xs'
              }`}>
                <div className="overflow-x-auto">
                  <table className="w-full text-left text-[10px] border-collapse">
                    <thead className={`border-b text-[10px] font-semibold ${
                      isDark ? 'bg-[#0c1224] text-slate-300 border-slate-800' : 'bg-slate-50 text-slate-700 border-slate-200'
                    }`}>
                      <tr>
                        <th className="px-2.5 py-2.5 font-bold uppercase tracking-wider text-[10px]">NO Ticket</th>
                        <th className="px-2 py-2.5 font-bold uppercase tracking-wider text-[10px]">classification</th>
                        <th className="px-2 py-2.5 font-bold uppercase tracking-wider text-[10px]">actor</th>
                        <th className="px-2 py-2.5 font-bold uppercase tracking-wider text-[10px]">target</th>
                        <th className="px-1 py-2.5 text-center font-bold uppercase tracking-wider text-[10px] w-7">action</th>
                        <th className="px-2 py-2.5 text-center font-bold uppercase tracking-wider text-[10px]">status</th>
                        <th className="px-2 py-2.5 text-center font-bold uppercase tracking-wider text-[10px]">deploy</th>
                      </tr>
                    </thead>
                    <tbody className={`divide-y font-sans ${
                      isDark ? 'divide-slate-800/60 bg-[#0a0e1a]' : 'divide-slate-100 bg-white'
                    }`}>
                      {filteredItems.length === 0 ? (
                        <tr>
                          <td colSpan={7} className="py-12 text-center text-slate-400 text-xs">
                            Tidak ada tiket atau kebijakan yang cocok dengan filter.
                          </td>
                        </tr>
                      ) : (
                        filteredItems.map((item, idx) => (
                          <tr key={`${item.id}-${idx}`} className={`transition-colors ${
                            isDark ? 'hover:bg-slate-800/40' : 'hover:bg-slate-50'
                          }`}>
                            {/* 1. NO Ticket */}
                            <td className="px-2.5 py-2.5 font-mono">
                              <div className="font-bold text-[10.5px] text-indigo-400 break-all leading-tight">
                                {item.ticketNo}
                              </div>
                              <div className="text-[9.5px] text-slate-400 font-sans leading-tight mt-0.5 break-words">
                                {item.incidentTitle}
                              </div>
                            </td>

                            {/* 2. Classification */}
                            <td className="px-2 py-2.5">
                              <span className={`text-[10px] font-bold uppercase tracking-tight leading-tight block ${
                                item.classi.includes('FALSE POSITIVE') ? 'text-purple-400' :
                                item.classi.includes('KNOWN GOOD') ? 'text-blue-400' :
                                item.classi.includes('CONDITIONAL') ? 'text-indigo-400' :
                                item.classi.includes('EXCEPTION') ? 'text-teal-400' :
                                item.classi.includes('MAINTENANCE') ? 'text-amber-400' :
                                'text-slate-400'
                              }`}>
                                {item.classi}
                              </span>
                            </td>

                            {/* 3. Actor */}
                            <td className="px-2 py-2.5 font-mono text-[10px] text-slate-300 break-all leading-tight">
                              {item.actor}
                            </td>

                            {/* 4. Target */}
                            <td className="px-2 py-2.5 font-mono text-[10px] text-slate-300 break-words leading-tight" title={item.target}>
                              {item.target}
                            </td>

                            {/* 5. Action */}
                            <td className="px-1 py-2.5 text-center">
                              <button
                                type="button"
                                onClick={() => handleActionClick(item)}
                                className="p-1 text-slate-400 hover:text-blue-500 active:text-blue-600 dark:hover:text-blue-400 bg-transparent hover:bg-transparent active:bg-transparent focus:bg-transparent focus:outline-none focus:ring-0 border-0 transition-all cursor-pointer inline-flex items-center justify-center group"
                                title="Edit / Tinjau Parameter Supresi"
                              >
                                <Pencil className="w-3.5 h-3.5 transition-transform group-hover:scale-110 group-active:scale-95" />
                              </button>
                            </td>

                            {/* 6. Status */}
                            <td className="px-2 py-2.5 text-center font-mono">
                              {item.status === 'DEPLOY' ? (
                                <span className="inline-block px-2.5 py-1 rounded-md bg-blue-600 text-white font-bold text-[10px] tracking-wider uppercase shadow-xs whitespace-nowrap">
                                  DEPLOY
                                </span>
                              ) : item.status === 'APPROVE' ? (
                                <span className="inline-block px-2.5 py-1 rounded-md bg-emerald-500 text-white font-bold text-[10px] tracking-wider uppercase shadow-xs whitespace-nowrap">
                                  APPROVE
                                </span>
                              ) : (
                                <button
                                  type="button"
                                  onClick={() => {
                                    setExtendModalItem(item);
                                    const defaultDate = new Date();
                                    defaultDate.setDate(defaultDate.getDate() + 90);
                                    setNewExpirationDate(defaultDate.toISOString().split('T')[0]);
                                  }}
                                  title="Tiket Expired. Klik untuk memperpanjang tanggal expired."
                                  className="inline-block px-2.5 py-1 rounded-md bg-rose-600 hover:bg-rose-500 text-white font-bold text-[10px] tracking-wider uppercase shadow-xs transition-colors cursor-pointer whitespace-nowrap"
                                >
                                  EXPIRED
                                </button>
                              )}
                            </td>

                            {/* 7. Deploy Toggle Switch */}
                            <td className="px-2 py-2.5 text-center">
                              {item.status === 'EXPIRED' || item.isExpired ? (
                                <div className="flex flex-col items-center justify-center gap-0.5">
                                  <button
                                    type="button"
                                    onClick={() => {
                                      setExtendModalItem(item);
                                      const defaultDate = new Date();
                                      defaultDate.setDate(defaultDate.getDate() + 90);
                                      setNewExpirationDate(defaultDate.toISOString().split('T')[0]);
                                    }}
                                    className="group relative inline-flex h-4.5 w-8 shrink-0 cursor-not-allowed items-center rounded-full bg-slate-800 border border-rose-500/40 p-0.5 opacity-50 transition-colors"
                                    title="Expired: Tombol OFF dan terkunci. Ubah tanggal expired terlebih dahulu untuk mengaktifkan."
                                  >
                                    <span className="sr-only">Expired toggle disabled</span>
                                    <span className="inline-block h-3.5 w-3.5 transform rounded-full bg-slate-500 shadow-xs transition-transform translate-x-0" />
                                  </button>
                                  <button 
                                    type="button"
                                    onClick={() => {
                                      setExtendModalItem(item);
                                      const defaultDate = new Date();
                                      defaultDate.setDate(defaultDate.getDate() + 90);
                                      setNewExpirationDate(defaultDate.toISOString().split('T')[0]);
                                    }}
                                    className="text-[9px] font-mono text-rose-400 hover:text-rose-300 underline cursor-pointer leading-none"
                                  >
                                    extend
                                  </button>
                                </div>
                              ) : (
                                <div className="flex items-center justify-center">
                                  <button
                                    type="button"
                                    role="switch"
                                    aria-checked={item.status === 'DEPLOY'}
                                    onClick={() => handleToggleDeploy(item)}
                                    className={`group relative inline-flex h-4.5 w-8 shrink-0 cursor-pointer items-center rounded-full p-0.5 transition-colors duration-200 ease-in-out focus:outline-none ${
                                      item.status === 'DEPLOY' 
                                        ? 'bg-blue-600 border border-blue-500 shadow-xs shadow-blue-500/30' 
                                        : 'bg-slate-700 hover:bg-slate-600 border border-slate-600'
                                    }`}
                                    title={item.status === 'DEPLOY' ? "Status DEPLOY (ON) - Klik untuk matikan ke APPROVE" : "Status APPROVE (OFF) - Klik untuk aktifkan ke DEPLOY"}
                                  >
                                    <span className="sr-only">Toggle Deploy</span>
                                    <span
                                      className={`pointer-events-none inline-block h-3.5 w-3.5 transform rounded-full bg-white shadow-xs ring-0 transition duration-200 ease-in-out ${
                                        item.status === 'DEPLOY' ? 'translate-x-3.5' : 'translate-x-0'
                                      }`}
                                    />
                                  </button>
                                </div>
                              )}
                            </td>
                          </tr>
                        ))
                      )}
                    </tbody>
                  </table>
                </div>

                <div className={`p-3 border-t flex items-center justify-between text-[11px] ${
                  isDark ? 'border-slate-800 text-slate-400 bg-[#090d16]' : 'border-slate-200 text-slate-500 bg-slate-50'
                }`}>
                  <span>Total: <strong>{filteredItems.length}</strong> tiket/kebijakan</span>
                  <span className="font-mono text-[10px] text-slate-500">
                    Isolation: {selectedTenantView} ({formatTenantDisplay(selectedTenantView)})
                  </span>
                </div>
              </div>

              {/* RIGHT PANEL: WAZUH XML RULE & CDB LIST PREVIEW & APPLY */}
              <div className={`lg:col-span-5 rounded-2xl border flex flex-col justify-between overflow-hidden ${
                isDark ? 'bg-[#0a0f1d] border-slate-800' : 'bg-white border-slate-200 shadow-xs'
              }`}>
                {/* Right Top Header Tabs matching Sketch: [ XML Rule ] | [ CDB List ] */}
                <div>
                  <div className={`p-3 border-b flex items-center justify-between ${
                    isDark ? 'border-slate-800 bg-[#0c1224]' : 'border-slate-200 bg-slate-50'
                  }`}>
                    <div className="flex items-center gap-1.5">
                      <button
                        type="button"
                        onClick={() => {
                          if (isEditingCode && activeRightTab !== 'XML') {
                            setCustomCodeSnippets(prev => ({
                              ...prev,
                              [selectedTenantView]: { ...prev[selectedTenantView], cdb: currentDraftCode }
                            }));
                            setCurrentDraftCode(xmlSnippet);
                          }
                          setActiveRightTab('XML');
                        }}
                        className={`px-3 py-1 rounded-lg text-xs font-bold font-mono transition-all cursor-pointer ${
                          activeRightTab === 'XML'
                            ? 'bg-indigo-600 text-white shadow-xs'
                            : isDark ? 'text-slate-400 hover:text-slate-200' : 'text-slate-600 hover:text-slate-900'
                        }`}
                      >
                        XML Rule
                      </button>
                      <button
                        type="button"
                        onClick={() => {
                          if (isEditingCode && activeRightTab !== 'CDB') {
                            setCustomCodeSnippets(prev => ({
                              ...prev,
                              [selectedTenantView]: { ...prev[selectedTenantView], xml: currentDraftCode }
                            }));
                            setCurrentDraftCode(cdbSnippet);
                          }
                          setActiveRightTab('CDB');
                        }}
                        className={`px-3 py-1 rounded-lg text-xs font-bold font-mono transition-all cursor-pointer ${
                          activeRightTab === 'CDB'
                            ? 'bg-indigo-600 text-white shadow-xs'
                            : isDark ? 'text-slate-400 hover:text-slate-200' : 'text-slate-600 hover:text-slate-900'
                        }`}
                      >
                        CDB List
                      </button>
                    </div>
                  </div>

                  {/* Monospace Code Preview or Editable Textarea Box (Latar Putih, Tulisan Hitam) */}
                  <div className="p-3">
                    {isEditingCode ? (
                      <div className="relative">
                        <textarea
                          value={currentDraftCode}
                          onChange={(e) => setCurrentDraftCode(e.target.value)}
                          rows={20}
                          spellCheck={false}
                          placeholder={`Ketik / edit ${activeRightTab === 'XML' ? 'Wazuh XML rule' : 'CDB list whitelist'} di sini...`}
                          className="code-terminal-box w-full p-3.5 rounded-xl border border-slate-300 focus:border-slate-400 focus:ring-1 focus:ring-slate-300 font-mono text-[11px] leading-relaxed max-h-[460px] min-h-[380px] overflow-y-auto selection:bg-slate-200 outline-none resize-none font-normal shadow-xs"
                          style={{ backgroundColor: '#ffffff', color: '#0f172a', colorScheme: 'light' }}
                        />
                      </div>
                    ) : (
                      <pre 
                        className="code-terminal-box p-3.5 rounded-xl border border-slate-300 font-mono text-[11px] leading-relaxed overflow-x-auto max-h-[460px] min-h-[380px] overflow-y-auto selection:bg-slate-200 whitespace-pre shadow-xs"
                        style={{ backgroundColor: '#ffffff', color: '#0f172a', colorScheme: 'light' }}
                      >
                        {displayedCode}
                      </pre>
                    )}
                  </div>
                </div>

                {/* Right Bottom Footer: edit button or cancel + apply buttons */}
                <div className={`p-3.5 border-t flex items-center justify-end gap-3 ${
                  isDark ? 'border-slate-800 bg-[#090d16]' : 'border-slate-200 bg-slate-50'
                }`}>
                  <div className="flex items-center gap-2">
                    {!isEditingCode ? (
                      /* TOMBOL EDIT */
                      <button
                        type="button"
                        onClick={() => handleStartEdit(currentActiveCode)}
                        className="px-5 py-2 rounded-xl bg-blue-600 hover:bg-blue-500 text-white font-mono font-bold text-xs flex items-center gap-2 shadow-lg shadow-blue-950/40 transition-all cursor-pointer hover:scale-[1.02] active:scale-[0.98]"
                        title="Edit / Modifikasi XML Rule atau CDB List secara langsung"
                      >
                        <Pencil className="w-3.5 h-3.5" />
                        <span>edit</span>
                      </button>
                    ) : (
                      /* 2 KOTAK BARU: CANCEL DAN APPLY */
                      <>
                        <button
                          type="button"
                          onClick={handleCancelEdit}
                          disabled={applyingTenant}
                          className="px-4 py-2 rounded-xl bg-red-600 hover:bg-red-500 text-white border border-red-500 font-mono font-bold text-xs flex items-center gap-1.5 shadow-md shadow-red-950/40 transition-all cursor-pointer hover:scale-[1.02] active:scale-[0.98]"
                          title="Batalkan perubahan dan kembalikan ke versi sebelum diedit"
                        >
                          <X className="w-3.5 h-3.5" />
                          <span>cancel</span>
                        </button>

                        <button
                          type="button"
                          onClick={() => handleApplyTenant(selectedTenantView)}
                          disabled={applyingTenant}
                          className="px-5 py-2 rounded-xl bg-emerald-600 hover:bg-emerald-500 text-white font-mono font-bold text-xs flex items-center gap-2 shadow-lg shadow-emerald-950/40 transition-all cursor-pointer disabled:opacity-50 hover:scale-[1.02] active:scale-[0.98]"
                          title="Apply aturan kustom langsung ke Wazuh Manager"
                        >
                          {applyingTenant ? (
                            <>
                              <RefreshCw className="w-3.5 h-3.5 animate-spin" />
                              <span>Applying...</span>
                            </>
                          ) : (
                            <>
                              <Check className="w-4 h-4 stroke-[2.5]" />
                              <span>apply</span>
                            </>
                          )}
                        </button>
                      </>
                    )}
                  </div>
                </div>
              </div>
            </div>
          </div>
        );
      })()}

{/* ========================================================================= */}
      {/* MODAL 1: WAZUH NATIVE SYNC PREVIEW (XML & CDB EXPLANATION) */}
      {/* ========================================================================= */}
      {showSyncModal && (
        <div className="fixed inset-0 bg-black/70 backdrop-blur-xs z-[70] flex items-center justify-center p-4">
          <div className={`${isDark ? 'bg-[#0b0f19] border-slate-800 text-slate-100' : 'bg-white border-slate-200 text-slate-800'} border rounded-2xl max-w-3xl w-full p-6 shadow-2xl space-y-4 max-h-[90vh] overflow-y-auto`}>
            {/* Header */}
            <div className={`flex items-center justify-between border-b pb-3 ${isDark ? 'border-slate-800' : 'border-slate-200'}`}>
              <div className="flex items-center gap-2.5">
                <div className="p-2 rounded-lg bg-emerald-500/10 border border-emerald-500/30 text-emerald-400">
                  <Terminal className="w-5 h-5" />
                </div>
                <div>
                  <h3 className={`text-base font-bold ${isDark ? 'text-white' : 'text-slate-900'}`}>
                    Wazuh Native Rule & CDB Sync Preview
                  </h3>
                  <p className="text-[11px] text-slate-400">
                    Otomatisasi pembuatan Child Rule XML level="0" & CDB lists untuk Wazuh Analysisd
                  </p>
                </div>
              </div>
              <button 
                type="button" 
                onClick={() => setShowSyncModal(false)} 
                className="p-1 rounded-md text-slate-400 hover:text-white hover:bg-slate-800 cursor-pointer"
              >
                <X className="w-5 h-5" />
              </button>
            </div>

            {syncLoading ? (
              <div className="py-16 text-center space-y-3">
                <RefreshCw className="w-8 h-8 mx-auto animate-spin text-emerald-400" />
                <div className="text-xs text-slate-400">Mengenerate konfigurasi native Wazuh...</div>
              </div>
            ) : syncData ? (
              <div className="space-y-4 text-xs">
                {/* Status Notice */}
                <div className="p-3.5 rounded-xl bg-emerald-950/40 border border-emerald-700/60 text-emerald-200 space-y-1">
                  <div className="flex items-center gap-2 font-bold text-emerald-400">
                    <CheckCircle2 className="w-4 h-4" />
                    <span>Sync Configuration Ready for Wazuh Manager</span>
                  </div>
                  <p className="text-[11px] leading-relaxed text-emerald-300">
                    Aturan di bawah ini akan di-drop pada level <strong>Wazuh Rule Engine (level="0")</strong> sehingga tidak membebani pipeline ingest, OpenSearch indexing, dan deduplikasi. Log mentah tetap tersimpan di <code>wazuh-archives-*</code> untuk kebutuhan forensik & GRC audit trail.
                  </p>
                </div>

                {/* XML Rule Block */}
                <div>
                  <div className="flex items-center justify-between mb-1.5">
                    <span className="font-semibold text-slate-300">
                      📄 /var/ossec/etc/rules/suppression_auto_grp.xml
                    </span>
                    <button
                      onClick={() => copyToClipboard(syncData.xml_rule)}
                      className="px-2 py-0.5 rounded bg-slate-800 hover:bg-slate-700 text-slate-300 border border-slate-700 flex items-center gap-1 font-mono text-[10px] cursor-pointer"
                    >
                      {copiedCode ? <CheckCheck className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                      <span>{copiedCode ? 'Disalin!' : 'Salin XML'}</span>
                    </button>
                  </div>
                  <pre 
                    className="code-terminal-box p-4 rounded-xl border border-slate-800 font-mono text-[11.5px] leading-relaxed overflow-x-auto !text-white"
                    style={{ backgroundColor: '#080c14', color: '#f8fafc', colorScheme: 'dark' }}
                  >
                    {syncData.xml_rule}
                  </pre>
                </div>

                {/* CDB Files Block */}
                {syncData.cdb_files && Object.keys(syncData.cdb_files).length > 0 && (
                  <div>
                    <span className="font-semibold text-slate-300 block mb-1.5">
                      📋 Constant Database (CDB) Lists Terkait
                    </span>
                    {Object.entries(syncData.cdb_files).map(([path, content]) => (
                      <div key={path} className="mb-2">
                        <span className="font-mono text-[10px] text-slate-300 block mb-1">{path}</span>
                        <pre 
                          className="code-terminal-box p-3 rounded-lg border border-slate-800 font-mono text-[11px] !text-white"
                          style={{ backgroundColor: '#080c14', color: '#f8fafc', colorScheme: 'dark' }}
                        >
                          {content || '(Kosong)'}
                        </pre>
                      </div>
                    ))}
                  </div>
                )}

                {/* Footer notes */}
                <div className="p-3 rounded-lg bg-slate-900 border border-slate-800 text-slate-400 text-[11px] space-y-1">
                  <div className="font-semibold text-slate-300">💡 Alur Eksekusi di Produksi:</div>
                  <div>1. File XML di-push otomatis ke Wazuh Manager via API endpoint <code>/rules/files/...</code></div>
                  <div>2. File CDB di-compile & reload: <code>/var/ossec/bin/wazuh-logtest</code></div>
                  <div>3. Service direstart halus: <code>systemctl restart wazuh-manager</code></div>
                </div>

                {/* Close Button */}
                <div className="flex justify-end pt-2">
                  <button
                    onClick={() => setShowSyncModal(false)}
                    className="px-4 py-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-white font-semibold cursor-pointer"
                  >
                    Tutup Preview
                  </button>
                </div>
              </div>
            ) : null}
          </div>
        </div>
      )}

      {/* ========================================================================= */}
      {/* MODAL 2: REVIEW & EXTEND BUNDLE (BULK EXTEND +90 HARI) */}
      {/* ========================================================================= */}
      {showReviewModal && targetGroupForReview && (
        <div className="fixed inset-0 bg-black/70 backdrop-blur-xs z-[70] flex items-center justify-center p-4">
          <div className={`${isDark ? 'bg-[#0b0f19] border-slate-800 text-slate-100' : 'bg-white border-slate-200 text-slate-800'} border rounded-2xl max-w-lg w-full p-6 shadow-2xl space-y-4 max-h-[90vh] overflow-y-auto`}>
            <div className={`flex items-center justify-between border-b pb-3 ${isDark ? 'border-slate-800' : 'border-slate-200'}`}>
              <div>
                <h3 className={`text-base font-bold ${isDark ? 'text-white' : 'text-slate-900'}`}>
                  Review & Perpanjang Policy Bundle
                </h3>
                <p className="text-xs text-slate-400">
                  Bundle: <strong>{targetGroupForReview.group_id} — {targetGroupForReview.group_name}</strong>
                </p>
              </div>
              <button 
                type="button" 
                onClick={() => setShowReviewModal(false)} 
                className="p-1 rounded-md text-slate-400 hover:text-white hover:bg-slate-800 cursor-pointer"
              >
                <X className="w-5 h-5" />
              </button>
            </div>

            <div className="p-3 rounded-lg bg-blue-950/30 border border-blue-800/40 text-blue-200 text-xs leading-relaxed">
              💡 <strong>Bulk Action:</strong> Tindakan ini akan memperbarui tanggal kedaluwarsa seluruh <strong>{targetGroupForReview.rule_count || 0} aturan anak</strong> di dalam bundle ini secara serentak hanya dalam 1 kali klik.
            </div>

            <form onSubmit={handleExecuteReview} className="space-y-3.5 text-xs">
              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="block font-semibold mb-1">Perpanjang Masa Berlaku</label>
                  <select
                    value={reviewForm.extend_days}
                    onChange={(e) => setReviewForm({ ...reviewForm, extend_days: e.target.value })}
                    className={`w-full px-3 py-2 rounded-lg border font-semibold ${
                      isDark ? 'bg-[#0c101c] border-slate-700 text-emerald-400' : 'bg-white border-slate-300 text-emerald-600'
                    }`}
                  >
                    <option value="30">+30 Hari (1 Bulan)</option>
                    <option value="90">+90 Hari (Triwulan / Quarterly)</option>
                    <option value="180">+180 Hari (Semester / Semi-Annual)</option>
                    <option value="365">+365 Hari (Tahunan / Annual)</option>
                  </select>
                </div>

                <div>
                  <label className="block font-semibold mb-1">Status Kebijakan</label>
                  <select
                    value={reviewForm.new_status}
                    onChange={(e) => setReviewForm({ ...reviewForm, new_status: e.target.value })}
                    className={`w-full px-3 py-2 rounded-lg border font-semibold ${
                      isDark ? 'bg-[#0c101c] border-slate-700 text-white' : 'bg-white border-slate-300 text-slate-900'
                    }`}
                  >
                    <option value="ACTIVE">ACTIVE (Aktif Normal)</option>
                    <option value="UNDER_REVIEW">UNDER_REVIEW (Sedang Dievaluasi)</option>
                    <option value="ARCHIVED">ARCHIVED (Nonaktifkan / Cabut)</option>
                  </select>
                </div>
              </div>

              <div>
                <label className="block font-semibold mb-1">Catatan Hasil Review (GRC Audit Trail)</label>
                <textarea
                  rows={3}
                  required
                  value={reviewForm.notes}
                  onChange={(e) => setReviewForm({ ...reviewForm, notes: e.target.value })}
                  placeholder="Konteks evaluasi teknis, misal: Operasional normal sesuai Change Request..."
                  className={`w-full px-3 py-2 rounded-lg border ${
                    isDark ? 'bg-[#0c101c] border-slate-700 text-white' : 'bg-white border-slate-300 text-slate-900'
                  }`}
                />
              </div>

              <div className="flex items-center justify-end gap-2 pt-3 border-t border-slate-800">
                <button
                  type="button"
                  onClick={() => setShowReviewModal(false)}
                  className="px-3.5 py-1.5 rounded-lg border border-slate-700 hover:bg-slate-800 text-slate-300 font-semibold cursor-pointer"
                >
                  Batal
                </button>
                <button
                  type="submit"
                  className="px-4 py-1.5 rounded-lg bg-emerald-600 hover:bg-emerald-500 text-white font-semibold cursor-pointer"
                >
                  Simpan & Terapkan ke Seluruh Aturan
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* ========================================================================= */}
      {/* MODAL 3: EDIT POLICY BUNDLE METADATA */}
      {/* ========================================================================= */}
      {showEditGroupModal && (
        <div className="fixed inset-0 bg-black/70 backdrop-blur-xs z-[70] flex items-center justify-center p-4">
          <div className={`${isDark ? 'bg-[#0b0f19] border-slate-800 text-slate-100' : 'bg-white border-slate-200 text-slate-800'} border rounded-2xl max-w-lg w-full p-6 shadow-2xl space-y-4 max-h-[90vh] overflow-y-auto`}>
            <div className={`flex items-center justify-between border-b pb-3 ${isDark ? 'border-slate-800' : 'border-slate-200'}`}>
              <h3 className={`text-base font-bold ${isDark ? 'text-white' : 'text-slate-900'}`}>
                Edit Policy Bundle ({editGroupForm.group_id})
              </h3>
              <button 
                type="button" 
                onClick={() => setShowEditGroupModal(false)} 
                className="p-1 rounded-md text-slate-400 hover:text-white hover:bg-slate-800 cursor-pointer"
              >
                <X className="w-5 h-5" />
              </button>
            </div>

            <form onSubmit={handleExecuteEditGroup} className="space-y-3.5 text-xs">
              <div>
                <label className="block font-semibold mb-1">Nama Policy Bundle</label>
                <input
                  type="text"
                  required
                  value={editGroupForm.group_name}
                  onChange={(e) => setEditGroupForm({ ...editGroupForm, group_name: e.target.value })}
                  className={`w-full px-3 py-2 rounded-lg border font-medium ${
                    isDark ? 'bg-[#0c101c] border-slate-700 text-white' : 'bg-white border-slate-300 text-slate-900'
                  }`}
                />
              </div>

              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="block font-semibold mb-1">Prioritas</label>
                  <select
                    value={editGroupForm.priority}
                    onChange={(e) => setEditGroupForm({ ...editGroupForm, priority: e.target.value })}
                    className={`w-full px-3 py-2 rounded-lg border ${
                      isDark ? 'bg-[#0c101c] border-slate-700 text-white' : 'bg-white border-slate-300 text-slate-900'
                    }`}
                  >
                    <option value="P0">P0 (Critical)</option>
                    <option value="P1">P1 (High)</option>
                    <option value="P2">P2 (Medium)</option>
                    <option value="P3">P3 (Low)</option>
                  </select>
                </div>

                <div>
                  <label className="block font-semibold mb-1">Status Bundle</label>
                  <select
                    value={editGroupForm.status}
                    onChange={(e) => setEditGroupForm({ ...editGroupForm, status: e.target.value })}
                    className={`w-full px-3 py-2 rounded-lg border font-semibold ${
                      isDark ? 'bg-[#0c101c] border-slate-700 text-white' : 'bg-white border-slate-300 text-slate-900'
                    }`}
                  >
                    <option value="ACTIVE">ACTIVE</option>
                    <option value="UNDER_REVIEW">UNDER_REVIEW</option>
                    <option value="ARCHIVED">ARCHIVED</option>
                  </select>
                </div>
              </div>

              <div>
                <label className="block font-semibold mb-1">Deskripsi Teknis</label>
                <textarea
                  rows={2}
                  value={editGroupForm.description}
                  onChange={(e) => setEditGroupForm({ ...editGroupForm, description: e.target.value })}
                  className={`w-full px-3 py-2 rounded-lg border ${
                    isDark ? 'bg-[#0c101c] border-slate-700 text-white' : 'bg-white border-slate-300 text-slate-900'
                  }`}
                />
              </div>

              <div className="flex items-center gap-2 pt-1">
                <input
                  type="checkbox"
                  id="edit_auto_merge"
                  checked={editGroupForm.auto_merge}
                  onChange={(e) => setEditGroupForm({ ...editGroupForm, auto_merge: e.target.checked })}
                  className="rounded text-indigo-600 focus:ring-indigo-500 w-4 h-4 cursor-pointer"
                />
                <label htmlFor="edit_auto_merge" className="font-semibold text-slate-300 cursor-pointer">
                  Aktifkan Auto-Merge (Otomatis gabungkan proposal baru yang cocok)
                </label>
              </div>

              <div className="flex items-center justify-end gap-2 pt-3 border-t border-slate-800">
                <button
                  type="button"
                  onClick={() => setShowEditGroupModal(false)}
                  className="px-3.5 py-1.5 rounded-lg border border-slate-700 hover:bg-slate-800 text-slate-300 font-semibold cursor-pointer"
                >
                  Batal
                </button>
                <button
                  type="submit"
                  className="px-4 py-1.5 rounded-lg bg-indigo-600 hover:bg-indigo-500 text-white font-semibold cursor-pointer"
                >
                  Simpan Perubahan
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* ========================================================================= */}
      {/* MODAL 4: BUAT POLICY BUNDLE BARU */}
      {/* ========================================================================= */}
      {showNewGroupModal && (
        <div className="fixed inset-0 bg-black/70 backdrop-blur-xs z-[70] flex items-center justify-center p-4">
          <div className={`${isDark ? 'bg-[#0b0f19] border-slate-800 text-slate-100' : 'bg-white border-slate-200 text-slate-800'} border rounded-2xl max-w-xl w-full p-6 shadow-2xl space-y-4 max-h-[90vh] overflow-y-auto`}>
            <div className={`flex items-center justify-between border-b pb-3 ${isDark ? 'border-slate-800' : 'border-slate-200'}`}>
              <h3 className={`text-base font-bold ${isDark ? 'text-white' : 'text-slate-900'}`}>
                Buat Policy Bundle (Grup Supresi) Baru
              </h3>
              <button 
                type="button" 
                onClick={() => setShowNewGroupModal(false)} 
                className="p-1 rounded-md text-slate-400 hover:text-white hover:bg-slate-800 cursor-pointer"
              >
                <X className="w-5 h-5" />
              </button>
            </div>

            <form onSubmit={handleCreateGroup} className="space-y-3.5 text-xs">
              <div>
                <label className="block font-semibold mb-1">Nama Policy Bundle</label>
                <input
                  type="text"
                  required
                  value={newGroupForm.group_name}
                  onChange={(e) => setNewGroupForm({ ...newGroupForm, group_name: e.target.value })}
                  placeholder="Misal: Container Security Baseline atau hportal-prod-159 Tuning"
                  className={`w-full px-3 py-2 rounded-lg border font-medium ${
                    isDark ? 'bg-[#0c101c] border-slate-700 text-white' : 'bg-white border-slate-300 text-slate-900'
                  }`}
                />
              </div>

              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="block font-semibold mb-1">Tipe Grup Kebijakan</label>
                  <select
                    value={newGroupForm.group_type}
                    onChange={(e) => setNewGroupForm({ ...newGroupForm, group_type: e.target.value })}
                    className={`w-full px-3 py-2 rounded-lg border ${
                      isDark ? 'bg-[#0c101c] border-slate-700 text-white' : 'bg-white border-slate-300 text-slate-900'
                    }`}
                  >
                    <option value="USE_CASE">USE_CASE (Palantir ADS Bundle)</option>
                    <option value="ASSET_GROUP">ASSET_GROUP (Host/Cluster specific)</option>
                    <option value="TENANT">TENANT (Per-Tenant baseline)</option>
                    <option value="ACTOR">ACTOR (Scanner / Pen-test IP)</option>
                    <option value="MITRE_TACTIC">MITRE_TACTIC (Technique-based)</option>
                    <option value="MAINTENANCE">MAINTENANCE (Temporal window)</option>
                  </select>
                </div>

                <div>
                  <label className="block font-semibold mb-1">Scope Tenant</label>
                  <select
                    value={newGroupForm.tenant_id}
                    onChange={(e) => setNewGroupForm({ ...newGroupForm, tenant_id: e.target.value })}
                    className={`w-full px-3 py-2 rounded-lg border ${
                      isDark ? 'bg-[#0c101c] border-slate-700 text-white' : 'bg-white border-slate-300 text-slate-900'
                    }`}
                  >
                    {Array.from(new Set([...availableTenants, 'TenantA', 'TenantB', 'TenantC', 'TenantD', 'SOC_CORE', 'DEFAULT'])).map(t => (
                      <option key={t} value={t}>{t}</option>
                    ))}
                    {!['TenantA', 'TenantB', 'TenantC', 'TenantD', 'SOC_CORE', 'DEFAULT', ...availableTenants].includes(newGroupForm.tenant_id) && newGroupForm.tenant_id && (
                      <option value={newGroupForm.tenant_id}>{newGroupForm.tenant_id}</option>
                    )}
                  </select>
                </div>
              </div>

              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="block font-semibold mb-1">Target Host / Pattern (Opsional)</label>
                  <input
                    type="text"
                    value={newGroupForm.target_hostname}
                    onChange={(e) => setNewGroupForm({ ...newGroupForm, target_hostname: e.target.value })}
                    placeholder="Misal: hportal-prod-159"
                    className={`w-full px-3 py-2 rounded-lg border font-mono ${
                      isDark ? 'bg-[#0c101c] border-slate-700 text-white' : 'bg-white border-slate-300 text-slate-900'
                    }`}
                  />
                </div>

                <div>
                  <label className="block font-semibold mb-1">MITRE Tactics (Opsional)</label>
                  <input
                    type="text"
                    value={newGroupForm.mitre_tactics}
                    onChange={(e) => setNewGroupForm({ ...newGroupForm, mitre_tactics: e.target.value })}
                    placeholder="Misal: TA0001, TA0008"
                    className={`w-full px-3 py-2 rounded-lg border font-mono ${
                      isDark ? 'bg-[#0c101c] border-slate-700 text-white' : 'bg-white border-slate-300 text-slate-900'
                    }`}
                  />
                </div>
              </div>

              <div>
                <label className="block font-semibold mb-1">Deskripsi / Rationale Teknis</label>
                <textarea
                  rows={2}
                  value={newGroupForm.description}
                  onChange={(e) => setNewGroupForm({ ...newGroupForm, description: e.target.value })}
                  placeholder="Konteks mengapa aturan-aturan ini dikelompokkan bersama..."
                  className={`w-full px-3 py-2 rounded-lg border ${
                    isDark ? 'bg-[#0c101c] border-slate-700 text-white' : 'bg-white border-slate-300 text-slate-900'
                  }`}
                />
              </div>

              <div className="flex items-center gap-2 pt-1">
                <input
                  type="checkbox"
                  id="auto_merge"
                  checked={newGroupForm.auto_merge}
                  onChange={(e) => setNewGroupForm({ ...newGroupForm, auto_merge: e.target.checked })}
                  className="rounded text-indigo-600 focus:ring-indigo-500 w-4 h-4 cursor-pointer"
                />
                <label htmlFor="auto_merge" className="font-semibold text-slate-300 cursor-pointer">
                  Aktifkan Auto-Merge (Otomatis gabungkan proposal baru yang cocok ke bundle ini)
                </label>
              </div>

              <div className="flex items-center justify-end gap-2 pt-3 border-t border-slate-800">
                <button
                  type="button"
                  onClick={() => setShowNewGroupModal(false)}
                  className="px-3.5 py-1.5 rounded-lg border border-slate-700 hover:bg-slate-800 text-slate-300 font-semibold cursor-pointer"
                >
                  Batal
                </button>
                <button
                  type="submit"
                  className="px-4 py-1.5 rounded-lg bg-indigo-600 hover:bg-indigo-500 text-white font-semibold cursor-pointer"
                >
                  Simpan Policy Bundle
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* ========================================================================= */}
      {/* MODAL 5: KELOLA CDB SHARED LISTS */}
      {/* ========================================================================= */}
      {showCdbModal && (
        <div className="fixed inset-0 bg-black/70 backdrop-blur-xs z-[70] flex items-center justify-center p-4">
          <div className={`${isDark ? 'bg-[#0b0f19] border-slate-800 text-slate-100' : 'bg-white border-slate-200 text-slate-800'} border rounded-2xl max-w-2xl w-full p-6 shadow-2xl space-y-4 max-h-[90vh] overflow-y-auto`}>
            <div className={`flex items-center justify-between border-b pb-3 ${isDark ? 'border-slate-800' : 'border-slate-200'}`}>
              <div className="flex items-center gap-2">
                <Server className="w-5 h-5 text-cyan-400" />
                <h3 className={`text-base font-bold ${isDark ? 'text-white' : 'text-slate-900'}`}>
                  Constant Database (CDB) Shared Lists
                </h3>
              </div>
              <button 
                type="button" 
                onClick={() => setShowCdbModal(false)} 
                className="p-1 rounded-md text-slate-400 hover:text-white hover:bg-slate-800 cursor-pointer"
              >
                <X className="w-5 h-5" />
              </button>
            </div>

            <p className="text-xs text-slate-400 leading-relaxed">
              CDB Lists adalah daftar statis terkompilasi di Wazuh Manager (<code>/var/ossec/etc/lists/</code>) yang digunakan untuk mencocokkan IP scanner, hostname trusted, atau username layanan dengan performa O(1) tanpa membuat banyak rule XML.
            </p>

            {/* List of existing CDB lists */}
            <div className="space-y-2">
              <span className="font-semibold text-xs text-slate-300 block">Daftar List Aktif:</span>
              {sharedLists.length === 0 ? (
                <div className="p-4 rounded-xl border border-dashed border-slate-800 text-center text-xs text-slate-500">
                  Belum ada shared CDB list. Tambahkan di bawah.
                </div>
              ) : (
                <div className="space-y-2">
                  {sharedLists.map(sl => {
                    const vals = typeof sl.values === 'string' ? JSON.parse(sl.values) : (sl.values || []);
                    return (
                      <div key={sl.list_id} className="p-3 rounded-lg border border-slate-800 bg-[#090d16] flex items-center justify-between gap-3 text-xs">
                        <div>
                          <div className="flex items-center gap-2">
                            <span className="font-mono font-bold text-cyan-400">{sl.list_id}</span>
                            <span className="font-bold text-slate-200">{sl.list_name}</span>
                            <span className="px-1.5 py-0.2 rounded bg-slate-800 text-slate-400 font-mono text-[10px]">{sl.list_type}</span>
                          </div>
                          <div className="text-[11px] text-slate-400 mt-1">{sl.description || `${vals.length} entri`}</div>
                        </div>
                        <div className="font-mono text-xs text-slate-300 bg-slate-800/80 px-2 py-1 rounded">
                          {vals.length} values
                        </div>
                      </div>
                    );
                  })}
                </div>
              )}
            </div>

            {/* Form to add a new list */}
            <form onSubmit={handleCreateCdbList} className="space-y-3 pt-3 border-t border-slate-800 text-xs">
              <span className="font-semibold text-slate-300 block">+ Tambah Shared List Baru:</span>
              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="block font-medium mb-1">Nama List</label>
                  <input
                    type="text"
                    required
                    value={newCdbForm.list_name}
                    onChange={(e) => setNewCdbForm({ ...newCdbForm, list_name: e.target.value })}
                    placeholder="Misal: trusted-scanners"
                    className={`w-full px-3 py-1.5 rounded-lg border font-mono ${
                      isDark ? 'bg-[#0c101c] border-slate-700 text-white' : 'bg-white border-slate-300 text-slate-900'
                    }`}
                  />
                </div>
                <div>
                  <label className="block font-medium mb-1">Tipe Data</label>
                  <select
                    value={newCdbForm.list_type}
                    onChange={(e) => setNewCdbForm({ ...newCdbForm, list_type: e.target.value })}
                    className={`w-full px-3 py-1.5 rounded-lg border ${
                      isDark ? 'bg-[#0c101c] border-slate-700 text-white' : 'bg-white border-slate-300 text-slate-900'
                    }`}
                  >
                    <option value="IP">IP Address / Subnet</option>
                    <option value="HOSTNAME">Hostname</option>
                    <option value="USERNAME">Username</option>
                    <option value="CIDR">CIDR Subnet</option>
                  </select>
                </div>
              </div>

              <div>
                <label className="block font-medium mb-1">Nilai / Entries (1 per baris)</label>
                <textarea
                  rows={3}
                  required
                  value={newCdbForm.valuesText}
                  onChange={(e) => setNewCdbForm({ ...newCdbForm, valuesText: e.target.value })}
                  placeholder="192.168.30.114&#10;103.19.110.156&#10;10.10.50.0/24"
                  className={`w-full px-3 py-2 rounded-lg border font-mono text-[11px] ${
                    isDark ? 'bg-[#0c101c] border-slate-700 text-cyan-300' : 'bg-white border-slate-300 text-slate-900'
                  }`}
                />
              </div>

              <div className="flex items-center justify-end gap-2 pt-2">
                <button
                  type="button"
                  onClick={() => setShowCdbModal(false)}
                  className="px-3 py-1.5 rounded-lg border border-slate-700 hover:bg-slate-800 text-slate-300 cursor-pointer"
                >
                  Tutup
                </button>
                <button
                  type="submit"
                  className="px-4 py-1.5 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-white font-semibold cursor-pointer"
                >
                  Simpan CDB List
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* ========================================================================= */}
      {/* MODAL 6: MERGE RULES TO GROUP */}
      {/* ========================================================================= */}
      {showMergeModal && targetGroupForMerge && (
        <div className="fixed inset-0 bg-black/70 backdrop-blur-xs z-[70] flex items-center justify-center p-4">
          <div className={`${isDark ? 'bg-[#0b0f19] border-slate-800 text-slate-100' : 'bg-white border-slate-200 text-slate-800'} border rounded-2xl max-w-xl w-full p-6 shadow-2xl space-y-4 max-h-[90vh] overflow-y-auto`}>
            <div className={`flex items-center justify-between border-b pb-3 ${isDark ? 'border-slate-800' : 'border-slate-200'}`}>
              <div>
                <h3 className={`text-base font-bold ${isDark ? 'text-white' : 'text-slate-900'}`}>
                  Gabungkan Aturan ke {targetGroupForMerge.group_id}
                </h3>
                <p className="text-xs text-slate-400">
                  Target Bundle: <strong>{targetGroupForMerge.group_name}</strong>
                </p>
              </div>
              <button 
                type="button" 
                onClick={() => setShowMergeModal(false)} 
                className="p-1 rounded-md text-slate-400 hover:text-white hover:bg-slate-800 cursor-pointer"
              >
                <X className="w-5 h-5" />
              </button>
            </div>

            <p className="text-xs text-slate-400">
              Pilih aturan supresi aktif di bawah untuk dimasukkan ke dalam Policy Bundle ini:
            </p>

            {/* Candidates list from rules props */}
            <div className="max-h-60 overflow-y-auto space-y-1.5 border border-slate-800 rounded-xl p-2 bg-[#090d16]">
              {rules.length === 0 ? (
                <div className="py-4 text-center text-xs text-slate-500">Tidak ada aturan yang tersedia.</div>
              ) : (
                rules.map(r => {
                  const isSelected = selectedRulesForMerge.includes(r.id);
                  const isAlreadyInGroup = r.groupId === targetGroupForMerge.group_id;

                  return (
                    <label 
                      key={r.id}
                      className={`flex items-center justify-between p-2 rounded-lg border text-xs cursor-pointer transition-colors ${
                        isAlreadyInGroup
                          ? 'opacity-40 bg-slate-900 border-slate-800 cursor-not-allowed'
                          : isSelected
                            ? 'bg-indigo-600/20 border-indigo-500/50 text-indigo-200'
                            : 'bg-[#0c101c] border-slate-800 text-slate-300 hover:bg-slate-800/60'
                      }`}
                    >
                      <div className="flex items-center gap-2.5">
                        <input
                          type="checkbox"
                          disabled={isAlreadyInGroup}
                          checked={isSelected}
                          onChange={(e) => {
                            if (e.target.checked) {
                              setSelectedRulesForMerge(prev => [...prev, r.id]);
                            } else {
                              setSelectedRulesForMerge(prev => prev.filter(id => id !== r.id));
                            }
                          }}
                          className="rounded text-indigo-600 w-3.5 h-3.5"
                        />
                        <div>
                          <div className="font-bold flex items-center gap-2">
                            <span className="font-mono text-indigo-400">{r.id}</span>
                            <span className="truncate max-w-[240px]">{r.name}</span>
                          </div>
                          <div className="text-[10px] text-slate-500">
                            SIDs: {Array.isArray(r.sids) ? r.sids.join(', ') : r.sids} {r.groupName ? `(Grup: ${r.groupName})` : '(Belum digrup)'}
                          </div>
                        </div>
                      </div>

                      {isAlreadyInGroup && (
                        <span className="text-[10px] text-emerald-400 font-semibold">Sudah di bundle ini</span>
                      )}
                    </label>
                  );
                })
              )}
            </div>

            <div className="flex items-center justify-between pt-2">
              <span className="text-xs text-slate-400">
                {selectedRulesForMerge.length} aturan dipilih
              </span>
              <div className="flex items-center gap-2">
                <button
                  type="button"
                  onClick={() => setShowMergeModal(false)}
                  className="px-3 py-1.5 rounded-lg border border-slate-700 hover:bg-slate-800 text-slate-300 text-xs font-semibold cursor-pointer"
                >
                  Batal
                </button>
                <button
                  type="button"
                  disabled={selectedRulesForMerge.length === 0}
                  onClick={handleExecuteMerge}
                  className="px-4 py-1.5 rounded-lg bg-indigo-600 hover:bg-indigo-500 disabled:opacity-40 disabled:cursor-not-allowed text-white text-xs font-semibold cursor-pointer"
                >
                  Gabungkan Aturan
                </button>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* MODAL EXTEND EXPIRATION (Buka Kunci Tombol Deploy) */}
      {extendModalItem && (
        <div className="fixed inset-0 z-50 bg-black/75 backdrop-blur-xs flex items-center justify-center p-4">
          <div className="bg-[#0f172a] border border-slate-700 rounded-2xl w-full max-w-lg p-6 space-y-5 shadow-2xl animate-in fade-in zoom-in-95 duration-150">
            <div className="flex items-start justify-between">
              <div className="flex items-center gap-3">
                <div className="p-2.5 rounded-xl bg-rose-500/10 border border-rose-500/20 text-rose-400">
                  <Calendar className="w-5 h-5" />
                </div>
                <div>
                  <h3 className="text-base font-bold text-white flex items-center gap-2">
                    Perpanjang Masa Berlaku Supresi
                  </h3>
                  <p className="text-xs text-slate-400 font-mono">
                    Tiket: <span className="text-indigo-400 font-semibold">{extendModalItem.ticketNo}</span> • {extendModalItem.incidentTitle}
                  </p>
                </div>
              </div>
              <button
                type="button"
                onClick={() => setExtendModalItem(null)}
                className="p-1.5 rounded-lg text-slate-400 hover:text-white hover:bg-slate-800 transition-colors cursor-pointer"
              >
                <X className="w-5 h-5" />
              </button>
            </div>

            <div className="p-3.5 rounded-xl bg-amber-500/10 border border-amber-500/20 text-xs text-amber-200/90 leading-relaxed">
              <div className="font-semibold text-amber-300 mb-1 flex items-center gap-1.5">
                <AlertTriangle className="w-4 h-4 text-amber-400" />
                Aturan Kadaluarsa (EXPIRED) — Deploy Switch Terkunci
              </div>
              Tombol switch Deploy otomatis <strong>OFF</strong> dan terkunci ketika supresi telah kadaluarsa demi kepatuhan SLA & audit keamanan. Perpanjang tanggal expired di bawah ini untuk mengembalikan status ke <strong>APPROVE</strong> dan membuka kunci tombol Deploy.
            </div>

            <form onSubmit={handleSaveExtendExpiration} className="space-y-4">
              <div>
                <label className="block text-xs font-semibold text-slate-300 mb-1.5">
                  Pilih Durasi Perpanjangan Cepat:
                </label>
                <div className="grid grid-cols-4 gap-2">
                  {[
                    { label: '+30 Hari', days: 30 },
                    { label: '+60 Hari', days: 60 },
                    { label: '+90 Hari', days: 90 },
                    { label: '+180 Hari', days: 180 },
                  ].map(({ label, days }) => {
                    const targetD = new Date();
                    targetD.setDate(targetD.getDate() + days);
                    const iso = targetD.toISOString().split('T')[0];
                    const isActive = newExpirationDate === iso;
                    return (
                      <button
                        key={days}
                        type="button"
                        onClick={() => setNewExpirationDate(iso)}
                        className={`py-1.5 px-2 rounded-lg text-xs font-semibold border transition-all cursor-pointer ${
                          isActive
                            ? 'bg-indigo-600 border-indigo-500 text-white shadow-xs'
                            : 'bg-slate-800/80 border-slate-700 text-slate-300 hover:bg-slate-700 hover:border-slate-600'
                        }`}
                      >
                        {label}
                      </button>
                    );
                  })}
                </div>
              </div>

              <div>
                <label className="block text-xs font-semibold text-slate-300 mb-1.5">
                  Tanggal Kadaluarsa Baru (YYYY-MM-DD):
                </label>
                <input
                  type="date"
                  required
                  min={new Date(Date.now() + 86400000).toISOString().split('T')[0]}
                  value={newExpirationDate}
                  onChange={(e) => setNewExpirationDate(e.target.value)}
                  className="w-full px-3.5 py-2.5 rounded-xl bg-slate-900 border border-slate-700 text-white font-mono text-sm focus:outline-none focus:border-indigo-500"
                />
                <p className="text-[11px] text-slate-400 mt-1">
                  Maksimal SLA supresi adalah 180 hari sesuai governance SOC.
                </p>
              </div>

              <div className="flex items-center justify-end gap-3 pt-3 border-t border-slate-800">
                <button
                  type="button"
                  onClick={() => setExtendModalItem(null)}
                  disabled={extendingLoading}
                  className="px-4 py-2 rounded-xl border border-slate-700 hover:bg-slate-800 text-slate-300 text-xs font-semibold transition-colors cursor-pointer"
                >
                  Batal
                </button>
                <button
                  type="submit"
                  disabled={extendingLoading || !newExpirationDate}
                  className="px-5 py-2 rounded-xl bg-indigo-600 hover:bg-indigo-500 disabled:opacity-50 disabled:cursor-not-allowed text-white text-xs font-bold transition-all shadow-md shadow-indigo-600/20 flex items-center gap-2 cursor-pointer"
                >
                  {extendingLoading ? (
                    <>
                      <Loader2 className="w-4 h-4 animate-spin" />
                      <span>Menyimpan...</span>
                    </>
                  ) : (
                    <>
                      <Check className="w-4 h-4" />
                      <span>Simpan & Buka Kunci Deploy</span>
                    </>
                  )}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
}
