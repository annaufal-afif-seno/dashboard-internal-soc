import { mapTo6CategoryTaxonomy } from '../utils/categoryConstants';
import React, { useMemo, useState, useRef, useEffect } from 'react';

import { ResponsiveContainer, PieChart, Pie, Cell, Tooltip } from 'recharts';

import {
  Search, RefreshCw, AlertTriangle, ChevronLeft, ChevronRight,
  ChevronsLeft, ChevronsRight, Copy, Check, X, Terminal,
  Layers, Flag, ChevronDown, ChevronUp
} from 'lucide-react';

const PALETTE = ['#10b981', '#0284c7', '#f59e0b', '#8b5cf6', '#f43f5e', '#64748b'];



const FILTER_FIELDS = [

  { id: 'cluster-tenant', label: 'tenant', title: 'Tenant' },

  { id: 'cluster-rule-id', label: 'rule.id', title: 'Rule ID' },

  { id: 'cluster-agent', label: 'agent', title: 'Agent' },

  { id: 'cluster-actor', label: 'actor', title: 'Actor' },

  { id: 'cluster-activity', label: 'activity', title: 'Activity' }

];



const CustomDonutTooltip = ({ active, payload, isDark, mode }) => {

  if (active && payload && payload.length) {

    const item = payload[0];

    const pct = item.payload.pct ?? (item.payload.value ? ((item.payload.value / item.payload.total) * 100).toFixed(1) : 0);

    const unitLabel = mode === 'interval' ? 'interval' : 'alerts';



    return (

      <div className={`px-2.5 py-1.5 rounded-lg font-mono border shadow-xl flex flex-col gap-1 z-50 whitespace-nowrap min-w-[170px] ${

        isDark ? 'bg-slate-900/95 border-slate-700 text-white shadow-black/80' : 'bg-white border-slate-200 text-slate-900 shadow-slate-300/40'

      }`}>

        <div className="flex items-center gap-1.5 text-[11px] pb-1 border-b border-slate-700/40">

          <span className="w-2 h-2 rounded-full shrink-0" style={{ backgroundColor: item.payload.color || item.color }} />

          <span className="font-bold truncate max-w-[220px]">{item.name}</span>

        </div>

        <div className="flex items-center justify-between gap-3 text-[10px] leading-tight">

          <span className={isDark ? 'text-slate-400' : 'text-slate-500'}>Porsi:</span>

          <span className="font-bold font-mono text-emerald-400">{pct}%</span>

        </div>

        {item.payload.value && (

          <div className="flex items-center justify-between gap-3 text-[10px] leading-tight whitespace-nowrap">

            <span className={isDark ? 'text-slate-400' : 'text-slate-500'}>Jumlah:</span>

            <span className="font-bold font-mono text-slate-200 whitespace-nowrap">

              {item.payload.value.toLocaleString()} <span className="text-[9px] font-normal text-slate-400">{unitLabel}</span>

            </span>

          </div>

        )}

      </div>

    );

  }

  return null;

};




export default function ClusteringOverview({


  theme = 'dark',

  timeRange,

  customStartDate = '2026-10-16',

  customEndDate = '2026-09-30',

  selectedTenant,

  currentUser,

  isReadOnly = false,

  onNavigate

}) {

  const isDark = theme === 'dark';



  // --- Alert Table States (Sinkron dengan Filter Donut Cluster) ---

  const [alerts, setAlerts] = useState([]);

  


  const [alertsLoading, setAlertsLoading] = useState(false);

  const [alertsTotal, setAlertsTotal] = useState(0);

  const [alertsPage, setAlertsPage] = useState(1);

  const [alertsLimit, setAlertsLimit] = useState(25);

  const [alertsLevelFilter, setAlertsLevelFilter] = useState('ALL');

  const [isFlagFilterActive, setIsFlagFilterActive] = useState(false);

  // Subtable detail per alert states
  const [expandedClusterId, setExpandedClusterId] = useState(null);
  const [clusterLogsMap, setClusterLogsMap] = useState({});
  const [clusterLogsLoading, setClusterLogsLoading] = useState({});

  const handleToggleClusterDetail = async (clusterItem) => {
    const clusterId = clusterItem.aggregation_id || clusterItem.cluster_id || clusterItem.id;
    if (expandedClusterId === clusterId) {
      setExpandedClusterId(null);
      return;
    }
    setExpandedClusterId(clusterId);

    if (!clusterLogsMap[clusterId]) {
      setClusterLogsLoading(prev => ({ ...prev, [clusterId]: true }));
      try {
        const res = await fetch(`/api/aggregates/${clusterId}/logs`);
        if (res.ok) {
          const data = await res.json();
          setClusterLogsMap(prev => ({ ...prev, [clusterId]: data.logs || [] }));
        } else {
          setClusterLogsMap(prev => ({ ...prev, [clusterId]: [] }));
        }
      } catch (err) {
        console.error('Failed to fetch cluster logs:', err);
        setClusterLogsMap(prev => ({ ...prev, [clusterId]: [] }));
      } finally {
        setClusterLogsLoading(prev => ({ ...prev, [clusterId]: false }));
      }
    }
  };

  // Flagging Selection & Recheck Modal State
  const [isFlagSelectionMode, setIsFlagSelectionMode] = useState(false);
  const [selectedClusterItems, setSelectedClusterItems] = useState({});

  const handleToggleFlagSelectionMode = () => {
    setIsFlagSelectionMode(prev => {
      const next = !prev;
      if (!next) {
        setSelectedClusterItems({});
      }
      return next;
    });
  };

  const handleToggleSelectCluster = (clusterItem, e) => {
    if (e) e.stopPropagation();
    const cid = clusterItem.aggregation_id || clusterItem.cluster_id || clusterItem.id;
    setSelectedClusterItems(prev => {
      const next = { ...prev };
      if (next[cid]) {
        delete next[cid];
      } else {
        next[cid] = clusterItem;
      }
      return next;
    });
  };

  const handleToggleSelectAll = (e) => {
    if (e) e.stopPropagation();
    const currentIds = alerts.map(al => al.aggregation_id || al.cluster_id || al.id);
    const allSelected = currentIds.length > 0 && currentIds.every(id => !!selectedClusterItems[id]);

    setSelectedClusterItems(prev => {
      const next = { ...prev };
      if (allSelected) {
        currentIds.forEach(id => delete next[id]);
      } else {
        alerts.forEach(al => {
          const id = al.aggregation_id || al.cluster_id || al.id;
          next[id] = al;
        });
      }
      return next;
    });
  };

  const handleOpenSuppressionModalFromSelection = () => {
    const selectedList = Object.values(selectedClusterItems);
    if (selectedList.length === 0) return;

    const uniqueTenants = Array.from(new Set(selectedList.map(c => c.tenant_id || c.tenant || 'DEFAULT').filter(Boolean)));
    const uniqueAgents = Array.from(new Set(selectedList.map(c => c.agent || c.target).filter(a => a && a !== '-')));
    const uniqueRuleIds = Array.from(new Set(selectedList.map(c => String(c.rule_id)).filter(r => r && r !== '-')));
    const uniqueActors = Array.from(new Set(selectedList.map(c => c.actor).filter(a => a && a !== '-')));
    const uniqueActivities = Array.from(new Set(selectedList.map(c => c.activity || c.rule_description).filter(a => a && a !== '-')));

    setSuppForm({
      username: getLoggedInUsername(),
      tenant: uniqueTenants.join(', '),
      agent: uniqueAgents.join(', '),
      ruleId: uniqueRuleIds.join(', '),
      actor: uniqueActors.join(', '),
      activity: uniqueActivities.join(', '),
      expiredDate: '',
      reason: ''
    });
    setSuppSuccessMsg(null);
    setSuppErrorMsg(null);
    setShowSuppressionModal(true);
  };

  // Suppression Form Modal State
  const [showSuppressionModal, setShowSuppressionModal] = useState(false);
  const getLoggedInUsername = () => {
    try {
      if (currentUser?.username) return currentUser.username;
      const u = JSON.parse(localStorage.getItem('wazuh_soc_user'));
      return u?.username || u?.name || 'admin_secops';
    } catch (e) {
      return 'admin_secops';
    }
  };

  const [suppForm, setSuppForm] = useState({
    username: '',
    tenant: '',
    agent: '',
    ruleId: '',
    actor: '',
    activity: '',
    expiredDate: '',
    reason: ''
  });
  const [suppSubmitting, setSuppSubmitting] = useState(false);
  const [suppSuccessMsg, setSuppSuccessMsg] = useState(null);
  const [suppErrorMsg, setSuppErrorMsg] = useState(null);

  const handleOpenSuppressionModal = () => {
    const today = new Date();
    today.setDate(today.getDate() + 30);
    const defaultExp = today.toISOString().split('T')[0];

    const initialTenant = selectedAlert?.tenant_id || effectiveTenant || selectedTenant || 'DEFAULT';
    const initialAgent = selectedAlert?.target || effectiveAgent || '';
    const initialRuleId = selectedAlert?.rule_id 
      ? String(selectedAlert.rule_id) 
      : (effectiveRuleId ? effectiveRuleId.replace(/^[^\d]*/, '').trim() : '');
    const initialActor = selectedAlert?.actor || effectiveActor || '';
    const initialActivity = effectiveActivity || selectedAlert?.rule_description || '';

    setSuppForm({
      username: getLoggedInUsername(),
      tenant: initialTenant === 'ALL' ? 'DEFAULT' : initialTenant,
      agent: initialAgent,
      ruleId: initialRuleId,
      actor: initialActor,
      activity: initialActivity,
      expiredDate: defaultExp,
      reason: ''
    });
    setSuppSuccessMsg(null);
    setSuppErrorMsg(null);
    setShowSuppressionModal(true);
  };

  const handleSubmitSuppression = async (e) => {
    e.preventDefault();
    if (!suppForm.reason.trim()) {
      setSuppErrorMsg('Suppression reason is required.');
      return;
    }
    if (!suppForm.expiredDate) {
      setSuppErrorMsg('Expiration date is required.');
      return;
    }

    setSuppSubmitting(true);
    setSuppErrorMsg(null);
    try {
      const selectedList = Object.values(selectedClusterItems);

      // Jika ada beberapa cluster yang dipilih dari mode ceklis, buat ATURAN TERPISAH per cluster di Policy Bundle
      if (selectedList.length > 1) {
        const createdRuleIds = [];
        for (const cluster of selectedList) {
          const cTenant = cluster.tenant_id || cluster.tenant || 'DEFAULT';
          const cAgent = cluster.agent || cluster.target || '';
          const cRuleId = cluster.rule_id ? String(cluster.rule_id).replace(/[^\d]/g, '').trim() : '';
          const sids = cRuleId && !isNaN(parseInt(cRuleId, 10)) ? [parseInt(cRuleId, 10)] : [0];
          const cActor = cluster.actor || '';
          const cActivity = cluster.activity || cluster.rule_description || '';
          const cAggId = cluster.aggregation_id || cluster.cluster_id || cluster.id || '';

          const payload = {
            name: `Noise Rule: ${cTenant} - ${cAgent || 'Agent'} - Rule ${cRuleId || 'ALL'}`,
            classification: 'S2_FALSE_POSITIVE',
            sids: sids,
            owner: suppForm.username?.trim() || getLoggedInUsername(),
            approver: 'soc-lead',
            expiration: suppForm.expiredDate,
            reason: suppForm.reason.trim(),
            status: 'WAITING',
            enforcement_mode: 'WAZUH_XML',
            scope_definition: {
              tenant_id: cTenant !== 'ALL' ? cTenant : undefined,
              agent: cAgent || undefined,
              target_host: cAgent || undefined,
              rule_id: cRuleId || undefined,
              match_sids: sids,
              actor: cActor || undefined,
              source_ip: cActor || undefined,
              activity: cActivity || undefined,
              aggregation_id: cAggId || undefined,
              username: suppForm.username?.trim() || getLoggedInUsername(),
              author: suppForm.username?.trim() || getLoggedInUsername(),
              reason: suppForm.reason.trim(),
              business_reason: suppForm.reason.trim(),
              created_date: new Date().toISOString().split('T')[0],
              category: mapTo6CategoryTaxonomy(cluster.category, cluster.classification_groups).category,
              subcategory: mapTo6CategoryTaxonomy(cluster.category, cluster.classification_groups).subcategory,
            }
          };

          const res = await fetch('/api/suppression/rules', {
            method: 'POST',
            headers: {
              'Content-Type': 'application/json',
              'X-API-Key': 'wazuh-soc-secure-key-2026'
            },
            body: JSON.stringify(payload)
          });

          if (!res.ok) {
            const errData = await res.json().catch(() => ({}));
            throw new Error(errData.detail || `Gagal menyimpan aturan supresi untuk ${cAggId} (HTTP ${res.status})`);
          }

          const resData = await res.json();
          if (resData.rule?.suppression_id) {
            createdRuleIds.push(resData.rule.suppression_id);
          }
        }

        setSuppSuccessMsg(`Berhasil mengajukan ${createdRuleIds.length} aturan supresi terpisah ke Policy Bundle! (${createdRuleIds.join(', ')})`);
        setSelectedClusterItems({});
        setIsFlagSelectionMode(false);
        setTimeout(() => {
          setShowSuppressionModal(false);
        }, 2200);
      } else {
        // Single cluster / manual entry
        const cleanRuleId = suppForm.ruleId ? suppForm.ruleId.replace(/^[^\d]*/, '').trim() : '';
        const sids = cleanRuleId && !isNaN(parseInt(cleanRuleId, 10)) ? [parseInt(cleanRuleId, 10)] : [0];
        
        const payload = {
          name: `Noise Proposal: ${suppForm.tenant || 'ALL'} - Rule ${cleanRuleId || 'ALL'}`,
          classification: 'S2_FALSE_POSITIVE',
          sids: sids,
          owner: suppForm.username?.trim() || getLoggedInUsername(),
          approver: 'soc-lead',
          expiration: suppForm.expiredDate,
          reason: suppForm.reason.trim(),
          status: 'WAITING',
          enforcement_mode: 'WAZUH_XML',
          scope_definition: {
            tenant_id: suppForm.tenant || undefined,
            agent: suppForm.agent || undefined,
            target_host: suppForm.agent || undefined,
            rule_id: cleanRuleId || undefined,
            match_sids: sids,
            actor: suppForm.actor || undefined,
            source_ip: suppForm.actor || undefined,
            activity: suppForm.activity || undefined,
            aggregation_id: selectedAlert?.aggregation_id || (selectedList[0]?.aggregation_id) || undefined,
            username: suppForm.username?.trim() || getLoggedInUsername(),
            author: suppForm.username?.trim() || getLoggedInUsername(),
            reason: suppForm.reason.trim(),
            business_reason: suppForm.reason.trim(),
            created_date: new Date().toISOString().split('T')[0],
            category: mapTo6CategoryTaxonomy(selectedAlert?.category, selectedAlert?.classification_groups).category,
            subcategory: mapTo6CategoryTaxonomy(selectedAlert?.category, selectedAlert?.classification_groups).subcategory,
          }
        };

        const res = await fetch('/api/suppression/rules', {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'X-API-Key': 'wazuh-soc-secure-key-2026'
          },
          body: JSON.stringify(payload)
        });

        if (!res.ok) {
          const errData = await res.json().catch(() => ({}));
          throw new Error(errData.detail || `Failed to save suppression rule (HTTP ${res.status})`);
        }

        const resData = await res.json();
        const ruleId = resData.rule?.suppression_id || 'SUP-2026';
        setSuppSuccessMsg(`Usulan aturan Wazuh ${ruleId} berhasil diajukan ke Policy Bundle!`);
        setSelectedClusterItems({});
        setIsFlagSelectionMode(false);
        setTimeout(() => {
          setShowSuppressionModal(false);
        }, 1800);
      }
    } catch (err) {
      setSuppErrorMsg(err.message || 'An error occurred while saving the suppression rule.');
    } finally {
      setSuppSubmitting(false);
    }
  };


  const [alertsSearchInput, setAlertsSearchInput] = useState('');

  const [alertsSearchQuery, setAlertsSearchQuery] = useState('');

  const [selectedAlert, setSelectedAlert] = useState(null);

  const [copiedId, setCopiedId] = useState(null);

  const handleCopyLog = (text, id) => {
    if (!text) return;
    const str = String(text);
    if (navigator.clipboard && navigator.clipboard.writeText) {
      navigator.clipboard.writeText(str).catch(() => {
        try {
          const textarea = document.createElement('textarea');
          textarea.value = str;
          textarea.style.position = 'fixed';
          textarea.style.opacity = '0';
          document.body.appendChild(textarea);
          textarea.select();
          document.execCommand('copy');
          document.body.removeChild(textarea);
        } catch (e) {
          console.error('Failed to copy', e);
        }
      });
    } else {
      try {
        const textarea = document.createElement('textarea');
        textarea.value = str;
        textarea.style.position = 'fixed';
        textarea.style.opacity = '0';
        document.body.appendChild(textarea);
        textarea.select();
        document.execCommand('copy');
        document.body.removeChild(textarea);
      } catch (e) {
        console.error('Failed to copy', e);
      }
    }
    setCopiedId(id);
    setTimeout(() => setCopiedId(null), 2500);
  };

  const [alertsNetworkError, setAlertsNetworkError] = useState(false);



  // Mode: 'interval' (15m window clusters) vs 'cumulative' (lifetime raw alerts)

  const [clusterMode, setClusterMode] = useState('interval');



  // Multi-Filter State: Object pemetaan { [chartId]: { name, color } }

  const [activeFilters, setActiveFilters] = useState({});



  // State untuk Popover "+ Add filter"

  const [isAddFilterOpen, setIsAddFilterOpen] = useState(false);
  const [selectedFieldId, setSelectedFieldId] = useState('cluster-tenant');
  const [searchValue, setSearchValue] = useState('');
  const [isSuggestionsOpen, setIsSuggestionsOpen] = useState(false);

  const [clusterOverview, setClusterOverview] = useState(null);
  const [clusterLoading, setClusterLoading] = useState(false);

  const popoverRef = useRef(null);
  const suggestionsRef = useRef(null);



  // Close popover when clicked outside

  useEffect(() => {

    function handleClickOutside(event) {

      if (popoverRef.current && !popoverRef.current.contains(event.target)) {

        setIsAddFilterOpen(false);

        setIsSuggestionsOpen(false);

      }

    }

    if (isAddFilterOpen) {

      document.addEventListener('mousedown', handleClickOutside);

    }

    return () => {

      document.removeEventListener('mousedown', handleClickOutside);

    };

  }, [isAddFilterOpen]);



  // Dynamic cluster overview fetcher
  const fetchClusterOverview = async () => {
    setClusterLoading(true);
    try {
      const params = new URLSearchParams({
        mode: clusterMode,
        range: timeRange || 'semua'
      });
      if (selectedTenant && selectedTenant !== 'ALL') {
        params.append('tenant_id', selectedTenant);
      }
      if (timeRange === 'custom' && customStartDate && customEndDate) {
        params.append('start', customStartDate);
        params.append('end', customEndDate);
      }
      if (activeFilters['cluster-tenant']?.name) {
        params.append('filter_tenant', activeFilters['cluster-tenant'].name);
      }
      if (activeFilters['cluster-rule-id']?.name) {
        params.append('filter_rule', activeFilters['cluster-rule-id'].name);
      }
      if (activeFilters['cluster-agent']?.name) {
        params.append('filter_agent', activeFilters['cluster-agent'].name);
      }
      if (activeFilters['cluster-actor']?.name) {
        params.append('filter_actor', activeFilters['cluster-actor'].name);
      }
      if (activeFilters['cluster-activity']?.name) {
        params.append('filter_activity', activeFilters['cluster-activity'].name);
      }

      const res = await fetch(`/api/clustering/overview?${params.toString()}`);
      if (res.ok) {
        const json = await res.json();
        setClusterOverview(json);
      }
    } catch (err) {
      console.error('Error fetching cluster overview:', err);
    } finally {
      setClusterLoading(false);
    }
  };

  useEffect(() => {
    fetchClusterOverview();
  }, [clusterMode, selectedTenant, timeRange, customStartDate, customEndDate, activeFilters]);

  // Update default search value when field changes
  const handleFieldChange = (newFieldId) => {
    setSelectedFieldId(newFieldId);
    const available = (clusterOverview?.[newFieldId]?.data || [])
      .map(d => d.name)
      .filter(n => n && !n.toLowerCase().startsWith('lainnya'));
    setSearchValue(available.length > 0 ? available[0] : '');
    setIsSuggestionsOpen(false);
  };

  // Filtered options based on user typing
  const currentFieldOptions = useMemo(() => {
    if (!clusterOverview || !clusterOverview[selectedFieldId]?.data) return [];
    return clusterOverview[selectedFieldId].data
      .map(d => d.name)
      .filter(n => n && !n.toLowerCase().startsWith('lainnya'));
  }, [clusterOverview, selectedFieldId]);

  const filteredOptions = useMemo(() => {
    if (!searchValue || searchValue.trim() === '') return currentFieldOptions;
    const q = searchValue.toLowerCase().trim();
    return currentFieldOptions.filter(opt => opt.toLowerCase().includes(q));
  }, [currentFieldOptions, searchValue]);



  const applyAddFilter = () => {

    const val = searchValue.trim();

    if (!val) return;



    setActiveFilters(prev => ({

      ...prev,

      [selectedFieldId]: { name: val, color: '#0284c7' }

    }));



    setIsAddFilterOpen(false);

    setIsSuggestionsOpen(false);

  };



  const handleSliceClick = (chartId, item) => {
    if (!item || !item.name) return;
    if (item.name.toLowerCase().startsWith('lainnya')) return;

    setActiveFilters((prev) => {
      const next = { ...prev };
      if (next[chartId] && next[chartId].name === item.name) {
        delete next[chartId]; // Toggle off jika diklik kembali item yang sama
      } else {
        next[chartId] = { name: item.name, color: item.color }; // Terapkan filter
      }
      return next;
    });
  };



  const removeFilter = (chartId) => {

    setActiveFilters((prev) => {

      const next = { ...prev };

      delete next[chartId];

      return next;

    });

  };



    const getCardData = (chartId) => {
    if (clusterOverview && clusterOverview[chartId]) {
      return clusterOverview[chartId];
    }
    const titles = {
      'cluster-tenant': 'TENANT',
      'cluster-rule-id': 'RULE.ID',
      'cluster-agent': 'AGENT',
      'cluster-actor': 'ACTOR',
      'cluster-activity': 'ACTIVITY'
    };
    return {
      id: chartId,
      title: titles[chartId] || chartId.toUpperCase(),
      total: 0,
      unit: clusterMode === 'interval' ? 'interval' : 'alerts',
      data: []
    };
  };

  const activeRow1 = [

    getCardData('cluster-tenant'),

    getCardData('cluster-rule-id'),

    getCardData('cluster-agent')

  ].filter(Boolean);



  // --- Cluster Filter Linkage (Sinkronisasi Filter Aktif ke API Alert) ---

  const effectiveTenant = activeFilters['cluster-tenant'] 

    ? activeFilters['cluster-tenant'].name 

    : (selectedTenant && selectedTenant !== 'ALL' ? selectedTenant : null);



  const effectiveRuleId = activeFilters['cluster-rule-id'] ? activeFilters['cluster-rule-id'].name : null;

  const effectiveAgent = activeFilters['cluster-agent'] ? activeFilters['cluster-agent'].name : null;

  const effectiveActor = activeFilters['cluster-actor'] ? activeFilters['cluster-actor'].name : null;

  const effectiveActivity = activeFilters['cluster-activity'] ? activeFilters['cluster-activity'].name : null;



  // Reset ke halaman 1 setiap kali filter cluster / pencarian / tingkat keparahan berubah

  useEffect(() => {
    setAlertsPage(1);
    setExpandedClusterId(null);
  }, [effectiveTenant, effectiveRuleId, effectiveAgent, effectiveActor, effectiveActivity, alertsLevelFilter, alertsSearchQuery, timeRange, customStartDate, customEndDate, clusterMode]);

  const fetchClusterAlerts = async () => {
    setAlertsLoading(true);
    try {
      const params = new URLSearchParams({
        page: String(alertsPage),
        limit: String(alertsLimit),
      });

      if (clusterMode !== 'interval') {
        params.append('level_filter', alertsLevelFilter);
      }

      if (effectiveTenant) {
        params.append('tenant_id', effectiveTenant);
      }
      if (effectiveRuleId) {
        params.append('rule_id', effectiveRuleId);
      }
      if (effectiveAgent) {
        params.append('agent', effectiveAgent);
      }
      if (effectiveActor) {
        params.append('actor', effectiveActor);
      }
      if (effectiveActivity) {
        params.append('activity', effectiveActivity);
      }
      if (timeRange) {
        params.append('range', timeRange);
        if (timeRange === 'custom') {
          params.append('start', customStartDate);
          params.append('end', customEndDate);
        }
      }
      if (alertsSearchQuery.trim()) {
        params.append('search', alertsSearchQuery.trim());
      }

      const endpoint = clusterMode === 'interval'
        ? '/api/telemetry/aggregates'
        : (clusterMode === 'cumulative' ? '/api/telemetry/cumulative' : '/api/raw-alerts');

      const res = await fetch(`${endpoint}?${params.toString()}`);
      if (res.ok) {
        setAlertsNetworkError(false);
        const data = await res.json();
        const items = data.aggregates || data.clusters || data.cumulative || data.alerts || [];
        setAlerts(items);
        if (data.total !== undefined) {
          setAlertsTotal(data.total);
        }
      } else {
        setAlertsNetworkError(true);
      }
    } catch (err) {
      console.error('Failed to fetch cluster alerts:', err);
      setAlertsNetworkError(true);
    } finally {
      setAlertsLoading(false);
    }
  };

  useEffect(() => {
    fetchClusterAlerts();
  }, [clusterMode, alertsPage, alertsLimit, alertsLevelFilter, alertsSearchQuery, effectiveTenant, effectiveRuleId, effectiveAgent, effectiveActor, effectiveActivity, timeRange, customStartDate, customEndDate]);



  const handleSearchSubmit = (e) => {

    if (e) e.preventDefault();

    setAlertsSearchQuery(alertsSearchInput);

    setAlertsPage(1);

  };



  const levelTabs = [

    { id: 'ALL', label: 'All' },

    { id: 'CRITICAL', label: 'Critical' },

    { id: 'HIGH', label: 'High' },

    { id: 'MEDIUM', label: 'Medium' },

    { id: 'LOW', label: 'Low' }

  ];



  const getLevelBadge = (lvl) => {

    const num = Number(lvl) || 0;

    if (num >= 15) {

      return <span className="font-bold font-mono text-xs text-rose-500">{num}</span>;

    }

    if (num >= 12) {

      return <span className="font-bold font-mono text-xs text-amber-500">{num}</span>;

    }

    if (num >= 7) {

      return <span className="font-bold font-mono text-xs text-yellow-500">{num}</span>;

    }

    return <span className="font-bold font-mono text-xs text-emerald-500">{num}</span>;

  };



  const activeRow2 = [

    getCardData('cluster-actor'),

    getCardData('cluster-activity')

  ].filter(Boolean);



  const getFilterBadgeLabel = (chartId, filterName) => {

    switch (chartId) {

      case 'cluster-tenant': return `tenant: ${filterName}`;

      case 'cluster-rule-id': return `rule.id: ${filterName}`;

      case 'cluster-agent': return `agent: ${filterName}`;

      case 'cluster-actor': return `actor: ${filterName}`;

      case 'cluster-activity': return `activity: ${filterName}`;

      default: return filterName;

    }

  };



  const renderDonutCard = (cluster) => {

    return (

      <div 

        key={cluster.id}

        id={cluster.id}

        data-chart-id={cluster.id}

        className={`p-5 rounded-xl border flex flex-col justify-between transition-colors min-w-0 ${

          isDark ? 'bg-[#0a0e1a] border-slate-800' : 'bg-white border-slate-200 shadow-xs'

        }`}

      >

        {/* Card Title - Standar identik untuk semua kotak */}

        <div className="w-full text-center pb-2 border-b border-slate-200 dark:border-slate-800/80 mb-2">

          <h3 className={`text-xs font-bold uppercase tracking-wider ${

            isDark ? 'text-slate-100' : 'text-slate-800'

          }`}>

            {cluster.title}

          </h3>

        </div>



        {/* Content: Loading, Donut Chart, or Empty State */}
        {clusterLoading ? (
          <div className="flex flex-col items-center justify-center my-auto py-10 gap-2.5">
            <div className="w-6 h-6 border-2 border-sky-500 border-t-transparent rounded-full animate-spin" />
            <span className="text-xs text-slate-400 font-medium">Memuat data clustering...</span>
          </div>
        ) : !cluster.data || cluster.data.length === 0 ? (
          <div className="flex flex-col items-center justify-center my-auto py-10 gap-1.5 text-center px-4">
            <span className="text-xs font-semibold text-slate-400">Tidak ada data untuk filter ini</span>
            <span className="text-[11px] text-slate-500">Coba hapus filter atau periksa kata kunci</span>
          </div>
        ) : (
        <div className="flex items-center justify-center gap-6 my-auto py-2">

          {/* Left: Donut Chart */}

          <div className="w-36 h-36 shrink-0 relative flex items-center justify-center">

            <ResponsiveContainer width="100%" height="100%">

              <PieChart>

                <Pie

                  data={cluster.data}

                  cx="50%"

                  cy="50%"

                  innerRadius={46}

                  outerRadius={66}

                  paddingAngle={cluster.data.length > 1 ? 2.5 : 0}

                  dataKey="value"

                  stroke="none"

                  strokeWidth={0}

                  isAnimationActive={false}

                  cursor="pointer"

                  onClick={(entry) => {

                    if (entry && entry.name) {

                      handleSliceClick(cluster.id, entry);

                    }

                  }}

                >

                  {cluster.data.map((entry, index) => {
                    const isActiveSlice = activeFilters[cluster.id]?.name === entry.name;
                    const hasChartFilter = !!activeFilters[cluster.id];
                    return (
                    <Cell 

                      key={`cell-${cluster.id}-${index}`} 

                      fill={entry.color} 

                      stroke={isActiveSlice ? '#fff' : 'none'}

                      strokeWidth={isActiveSlice ? 2.5 : 0}

                      opacity={hasChartFilter && !isActiveSlice ? 0.35 : 1}

                      cursor="pointer"

                      onClick={(e) => {

                        e?.stopPropagation?.();

                        handleSliceClick(cluster.id, entry);

                      }}

                      className="cursor-pointer transition-opacity"

                    />
                    );
                  })}

                </Pie>

                <Tooltip content={<CustomDonutTooltip isDark={isDark} mode={clusterMode} />} />

              </PieChart>

            </ResponsiveContainer>

          </div>



          {/* Right: Legend Stack with (xx%) - Format standar seragam */}

          <div className="flex flex-col gap-2 min-w-0">

            {cluster.data.map((item, idx) => {

              return (

                <div 

                  key={idx} 

                  onClick={() => handleSliceClick(cluster.id, item)}

                  className={`flex items-center gap-2.5 text-xs min-w-0 cursor-pointer transition-all ${
                    activeFilters[cluster.id]?.name === item.name
                      ? 'opacity-100'
                      : activeFilters[cluster.id] ? 'opacity-40 hover:opacity-70' : 'opacity-100 hover:opacity-80'
                  }`}

                  title={`Klik untuk memfilter ${item.name} (${item.pct}%)`}

                >

                  <span 

                    className={`w-2.5 h-2.5 rounded-full shrink-0 transition-transform ${activeFilters[cluster.id]?.name === item.name ? 'scale-125 ring-2 ring-white/60' : ''}`}

                    style={{ backgroundColor: item.color }} 

                  />

                  <span className={`truncate ${
                    activeFilters[cluster.id]?.name === item.name
                      ? (isDark ? 'text-white font-bold' : 'text-slate-900 font-bold')
                      : (isDark ? 'text-slate-300 font-medium' : 'text-slate-700 font-medium')
                  }`}>

                    {item.name} <span className={isDark ? 'text-slate-400 font-mono' : 'text-slate-500 font-mono'}>({item.pct}%)</span>

                  </span>

                </div>

              );

            })}

          </div>

        </div>
        )}

      </div>

    );

  };



  const activeFilterEntries = Object.entries(activeFilters);



  return (

    <div 
      className="space-y-6 clustering-trebuchet-wrapper"
      style={{ fontFamily: "'Trebuchet MS', 'Lucida Sans Unicode', 'Lucida Grande', 'Lucida Sans', Arial, sans-serif" }}
    >
      <style>{`
        .clustering-trebuchet-wrapper,
        .clustering-trebuchet-wrapper *,
        .clustering-trebuchet-wrapper text,
        .clustering-trebuchet-wrapper tspan,
        .clustering-trebuchet-wrapper input,
        .clustering-trebuchet-wrapper select,
        .clustering-trebuchet-wrapper textarea,
        .clustering-trebuchet-wrapper button {
          font-family: 'Trebuchet MS', 'Lucida Sans Unicode', 'Lucida Grande', 'Lucida Sans', Arial, sans-serif !important;
        }
      `}</style>

      {/* Header Banner dengan Multi-Filter Badges di Samping Judul Clustering */}

      <div className={`p-4 rounded-xl border flex items-center justify-between transition-colors ${

        isDark ? 'bg-[#0a0e1a] border-slate-800' : 'bg-white border-slate-200 shadow-xs'

      }`}>

        <div className="flex items-center gap-2.5 flex-wrap relative">

          <h2 className={`text-base font-bold tracking-tight shrink-0 mr-1 ${isDark ? 'text-white' : 'text-slate-900'}`}>

            Clustering

          </h2>



          {/* Tombol [⊕ Add filter] Gaya Asli Wazuh / OpenSearch */}

          <div className="relative inline-block" ref={popoverRef}>

            <button

              type="button"

              onClick={() => {

                setIsAddFilterOpen(prev => !prev);

                setIsSuggestionsOpen(false);

              }}

              className="inline-flex items-center gap-1.5 px-2 py-1 text-[13px] font-medium text-[#0077cc] hover:text-[#005fa3] hover:bg-sky-50 dark:hover:bg-sky-950/40 rounded transition-colors cursor-pointer"

              title="Tambah filter baru secara manual"

            >

              <svg 

                className="w-3.5 h-3.5 text-[#0077cc]" 

                viewBox="0 0 24 24" 

                fill="none" 

                stroke="currentColor" 

                strokeWidth="2.2" 

                strokeLinecap="round" 

                strokeLinejoin="round"

              >

                <circle cx="12" cy="12" r="10" />

                <line x1="12" y1="8" x2="12" y2="16" />

                <line x1="8" y1="12" x2="16" y2="12" />

              </svg>

              <span>Add filter</span>

            </button>



            {/* Popover Dialog Filter Builder */}

            {isAddFilterOpen && (

              <div className={`absolute left-0 top-full mt-2 w-80 rounded-lg border shadow-2xl z-50 p-4 flex flex-col gap-3 font-sans ${

                isDark ? 'bg-slate-900 border-slate-700 text-slate-100 shadow-black/80' : 'bg-white border-slate-200 text-slate-800 shadow-slate-300/60'

              }`}>

                <div className="flex items-center justify-between border-b pb-2 dark:border-slate-800">

                  <span className="text-xs font-bold uppercase tracking-wider text-[#0077cc]">

                    Add Filter

                  </span>

                  <button

                    type="button"

                    onClick={() => {

                      setIsAddFilterOpen(false);

                      setIsSuggestionsOpen(false);

                    }}

                    className="text-slate-400 hover:text-slate-200 text-xs cursor-pointer p-0.5"

                  >

                    ✕

                  </button>

                </div>



                {/* Pilih Field */}

                <div className="flex flex-col gap-1 text-xs">

                  <label className="text-[11px] font-semibold text-slate-400">Field</label>

                  <select

                    value={selectedFieldId}

                    onChange={(e) => handleFieldChange(e.target.value)}

                    className={`w-full px-2.5 py-1.5 rounded border text-xs cursor-pointer outline-none ${

                      isDark ? 'bg-slate-800 border-slate-700 text-white focus:border-[#0077cc]' : 'bg-white border-slate-300 text-slate-800 focus:border-[#0077cc]'

                    }`}

                  >

                    {FILTER_FIELDS.map(f => (

                      <option key={f.id} value={f.id}>{f.label} ({f.title})</option>

                    ))}

                  </select>

                </div>



                {/* Operator (Default 'is') */}

                <div className="flex flex-col gap-1 text-xs">

                  <label className="text-[11px] font-semibold text-slate-400">Operator</label>

                  <div className={`px-2.5 py-1.5 rounded border text-xs font-mono font-medium ${

                    isDark ? 'bg-slate-800/60 border-slate-700/60 text-slate-300' : 'bg-slate-100 border-slate-200 text-slate-600'

                  }`}>

                    is

                  </div>

                </div>



                {/* Input Value: Bisa Diketik & Memuat Semua Opsi Data */}

                <div className="flex flex-col gap-1 text-xs relative" ref={suggestionsRef}>

                  <label className="text-[11px] font-semibold text-slate-400">

                    Value <span className="font-normal text-[10px] text-slate-500">(Bisa diketik atau dipilih)</span>

                  </label>

                  

                  <div className="relative flex items-center">

                    <input

                      type="text"

                      value={searchValue}

                      onChange={(e) => {

                        setSearchValue(e.target.value);

                        setIsSuggestionsOpen(true);

                      }}

                      onFocus={() => setIsSuggestionsOpen(true)}

                      onKeyDown={(e) => {

                        if (e.key === 'Enter') {

                          e.preventDefault();

                          applyAddFilter();

                        }

                      }}

                      placeholder="Ketik atau pilih nilai filter..."

                      className={`w-full pl-2.5 pr-7 py-1.5 rounded border text-xs font-mono outline-none transition-all ${

                        isDark 

                          ? 'bg-slate-800 border-slate-700 text-white focus:border-[#0077cc]' 

                          : 'bg-white border-slate-300 text-slate-800 focus:border-[#0077cc]'

                      }`}

                    />

                    <button

                      type="button"

                      onClick={() => setIsSuggestionsOpen(prev => !prev)}

                      className="absolute right-2 text-slate-400 hover:text-slate-200 cursor-pointer text-[10px]"

                      title="Lihat semua opsi"

                    >

                      {isSuggestionsOpen ? '▲' : '▼'}

                    </button>

                  </div>



                  {/* Dropdown Suggestions List (Dapat di-scroll dan menyaring sesuai ketikan) */}

                  {isSuggestionsOpen && (

                    <div className={`absolute left-0 top-full mt-1 w-full max-h-52 overflow-y-auto rounded-md border shadow-xl z-50 py-1 text-xs font-mono ${

                      isDark ? 'bg-slate-800 border-slate-700 text-slate-200' : 'bg-white border-slate-300 text-slate-800 shadow-slate-200'

                    }`}>

                      {filteredOptions.length > 0 ? (

                        filteredOptions.map((opt, idx) => (

                          <div

                            key={idx}

                            onClick={() => {

                              setSearchValue(opt);

                              setIsSuggestionsOpen(false);

                            }}

                            className={`px-3 py-1.5 cursor-pointer truncate flex items-center justify-between transition-colors ${

                              searchValue === opt 

                                ? (isDark ? 'bg-sky-900/50 text-sky-300 font-bold' : 'bg-sky-50 text-[#0077cc] font-bold')

                                : (isDark ? 'hover:bg-slate-700/70' : 'hover:bg-slate-100')

                            }`}

                            title={opt}

                          >

                            <span className="truncate">{opt}</span>

                            {searchValue === opt && <span className="text-[11px] text-[#0077cc] ml-2">✓</span>}

                          </div>

                        ))

                      ) : (

                        <div className="px-3 py-2 text-slate-400 text-[11px] italic">

                          Tekan Enter/Save untuk memakai nilai custom: "{searchValue}"

                        </div>

                      )}

                    </div>

                  )}

                </div>



                {/* Tombol Simpan & Batal */}

                <div className="flex items-center justify-end gap-2 pt-2 border-t dark:border-slate-800 mt-1">

                  <button

                    type="button"

                    onClick={() => {

                      setIsAddFilterOpen(false);

                      setIsSuggestionsOpen(false);

                    }}

                    className={`px-3 py-1 rounded text-xs transition-colors cursor-pointer ${

                      isDark ? 'hover:bg-slate-800 text-slate-400' : 'hover:bg-slate-100 text-slate-600'

                    }`}

                  >

                    Cancel

                  </button>

                  <button

                    type="button"

                    onClick={applyAddFilter}

                    className="px-4 py-1 rounded text-xs font-semibold bg-[#0077cc] hover:bg-[#005fa3] text-white shadow-xs transition-colors cursor-pointer"

                  >

                    Save

                  </button>

                </div>

              </div>

            )}

          </div>



          {/* Deretan Filter Badges Gaya Wazuh / OpenSearch (Bisa Multi-Filter Bersamaan) */}

          {activeFilterEntries.map(([chartId, filter]) => (

            <div 

              key={chartId}

              className={`inline-flex items-center gap-2 px-2.5 py-1 text-[13px] font-sans rounded-[2px] border border-l-4 shadow-xs transition-all ${

                isDark 

                  ? 'bg-slate-900 border-slate-700 border-l-slate-400 text-slate-200' 

                  : 'bg-white border-slate-300 border-l-[#94a3b8] text-slate-800'

              }`}

            >

              <span>

                {getFilterBadgeLabel(chartId, filter.name)}

              </span>

              <button

                type="button"

                onClick={() => removeFilter(chartId)}

                className={`ml-1.5 text-xs font-normal hover:opacity-100 transition-opacity cursor-pointer leading-none ${

                  isDark ? 'text-slate-400 hover:text-white' : 'text-slate-500 hover:text-slate-900'

                }`}

                title={`Hapus filter ${filter.name}`}

              >

                ✕

              </button>

            </div>

          ))}



          {/* Tombol Clear All jika ada 2 atau lebih filter aktif */}

          {activeFilterEntries.length >= 2 && (

            <button

              type="button"

              onClick={() => setActiveFilters({})}

              className={`text-xs font-mono px-2 py-1 rounded cursor-pointer transition-colors ${

                isDark ? 'text-slate-400 hover:text-rose-400 hover:bg-slate-800/60' : 'text-slate-500 hover:text-rose-600 hover:bg-slate-100'

              }`}

              title="Reset semua filter aktif"

            >

              Hapus Semua (✕)

            </button>

          )}

        </div>



        {/* Toggle Switch Mode: Interval (15m) vs Cumulative */}

        <div className={`p-1 rounded-lg border flex items-center gap-1 shrink-0 ml-4 ${

          isDark ? 'bg-slate-900/90 border-slate-700/80' : 'bg-slate-100 border-slate-200'

        }`}>

          <button

            type="button"

            onClick={() => {
            setClusterMode('interval');
            setAlertsLevelFilter('ALL');
            setAlertsPage(1);
          }}

            className={`px-3 py-1 rounded-md text-xs font-mono font-semibold transition-all duration-200 cursor-pointer ${

              clusterMode === 'interval'

                ? (isDark ? 'bg-slate-800 text-white shadow-xs border border-slate-600' : 'bg-white text-slate-900 shadow-xs border border-slate-200')

                : (isDark ? 'text-slate-400 hover:text-slate-200' : 'text-slate-500 hover:text-slate-900')

            }`}

          >

            Interval (15m)

          </button>

          <button

            type="button"

            onClick={() => {
            setClusterMode('cumulative');
            setAlertsLevelFilter('ALL');
            setAlertsPage(1);
          }}

            className={`px-3 py-1 rounded-md text-xs font-mono font-semibold transition-all duration-200 cursor-pointer ${

              clusterMode === 'cumulative'

                ? (isDark ? 'bg-slate-800 text-white shadow-xs border border-slate-600' : 'bg-white text-slate-900 shadow-xs border border-slate-200')

                : (isDark ? 'text-slate-400 hover:text-slate-200' : 'text-slate-500 hover:text-slate-900')

            }`}

          >

            Cumulative

          </button>

        </div>

      </div>



      {/* Baris 1: 3 Pie Chart (TENANT, RULE.ID, AGENT) */}

      <div className="grid grid-cols-3 gap-4 w-full min-w-0">

        {activeRow1.map((cluster) => renderDonutCard(cluster))}

      </div>



      {/* Baris 2: 2 Pie Chart (ACTOR, ACTIVITY) */}

      <div className="grid grid-cols-2 gap-4 w-full min-w-0">

        {activeRow2.map((cluster) => renderDonutCard(cluster))}

      </div>

    

      {/* ========================================================================= */}

      {/* BARIS 3: TABEL RAW ALERTS DENGAN SINKRONISASI FILTER CLUSTER              */}

      {/* Sesuai Referensi Gambar User: Side-by-Side Detail Panel & Clean Header    */}

      {/* ========================================================================= */}

      <div className="flex gap-4 items-start w-full mt-2 min-w-0">

        {/* Sisi Kiri: Tabel Raw Alerts */}

        <div className={`flex-1 min-w-0 rounded-xl border shadow-xs overflow-hidden transition-colors ${

          isDark ? 'bg-[#0a0e1a] border-slate-800' : 'bg-white border-slate-200'

        }`}>

          {/* Table Header: Judul di Kiri, Search Bar di Tengah, Icon Flag Merah di Pojok Kanan (Tanpa Lingkaran) */}

          <div className={`p-4 border-b flex items-center justify-between gap-4 transition-colors ${

            isDark ? 'border-slate-800/80 bg-[#070b14]' : 'border-slate-100 bg-slate-50/50'

          }`}>

            {/* Sisi Kiri: Judul Raw Alerts */}

            <div className="shrink-0 w-36 sm:w-44">
              <h3 className={`text-base font-bold tracking-tight ${isDark ? 'text-white' : 'text-slate-900'}`}>
                {clusterMode === 'interval' ? 'Interval Clusters' : (clusterMode === 'cumulative' ? 'Cumulative Clusters' : 'Alert')}
              </h3>
            </div>



            {/* Bagian Tengah: Search Bar Tepat di Tengah */}

            <div className="flex-1 flex items-center justify-center max-w-xl mx-auto">

              <form onSubmit={handleSearchSubmit} className="relative w-full">

                <div className="w-full relative flex items-center bg-white dark:bg-[#090d16] border-2 border-[#3B5BFF] rounded-full h-[38px] pl-3.5 pr-1.5 shadow-2xs group focus-within:ring-2 focus-within:ring-[#3B5BFF]/30 transition-all">

                  <Search className="w-4 h-4 text-slate-400 shrink-0 mr-2.5 stroke-[2]" />

                  <input

                    type="text"

                    value={alertsSearchInput}

                    onChange={(e) => {
                      const val = e.target.value;
                      setAlertsSearchInput(val);
                      if (val === '') {
                        setAlertsSearchQuery('');
                        setAlertsPage(1);
                      }
                    }}

                    placeholder="Search ID, IP, Host, Rule, agg_..., cum_..., TRG-..."

                    className="w-full bg-transparent text-slate-800 dark:text-slate-200 placeholder:text-slate-400 text-xs sm:text-[13px] font-normal focus:outline-none"

                  />

                  {alertsSearchInput && (

                    <button

                      type="button"

                      onClick={() => {

                        setAlertsSearchInput('');

                        setAlertsSearchQuery('');

                        setAlertsPage(1);

                      }}

                      className="text-slate-400 hover:text-slate-600 dark:hover:text-slate-200 cursor-pointer p-1 mr-1"

                      title="Hapus pencarian"

                    >

                      <X className="w-3.5 h-3.5" />

                    </button>

                  )}

                  <button

                    type="submit"

                    className="w-7 h-7 rounded-full bg-[#3B5BFF] hover:bg-[#2D4BEB] flex items-center justify-center shrink-0 cursor-pointer transition-transform hover:scale-105 shadow-xs"

                    title="Search"

                  >

                    <Search className="w-3.5 h-3.5 text-white" color="#FFFFFF" strokeWidth={2.5} style={{ stroke: "#FFFFFF", color: "#FFFFFF" }} />

                  </button>

                </div>

              </form>

            </div>




            {/* Sisi Kanan (Pojok Kanan): Tombol Recheck & Icon Flag Merah */}
            <div className="shrink-0 flex justify-end items-center gap-2.5">
              {isFlagSelectionMode && (
                <button
                  type="button"
                  onClick={handleOpenSuppressionModalFromSelection}
                  disabled={Object.keys(selectedClusterItems).length === 0}
                  className={`px-3 py-1.5 text-xs font-semibold rounded-lg flex items-center gap-1.5 transition-all shadow-sm ${
                    Object.keys(selectedClusterItems).length > 0
                      ? 'bg-blue-600 hover:bg-blue-500 text-white cursor-pointer ring-2 ring-blue-400/40'
                      : 'bg-slate-200 text-slate-400 dark:bg-slate-800 dark:text-slate-500 cursor-not-allowed opacity-60'
                  }`}
                  title={Object.keys(selectedClusterItems).length === 0 ? "Pilih minimal 1 cluster untuk di-recheck" : "Buka form supresi untuk cluster yang dipilih"}
                >
                  <RefreshCw className="w-3.5 h-3.5" />
                  <span>Recheck {Object.keys(selectedClusterItems).length > 0 ? `(${Object.keys(selectedClusterItems).length})` : ''}</span>
                </button>
              )}

              <button
                type="button"
                onClick={handleToggleFlagSelectionMode}
                className={`p-1.5 rounded-lg cursor-pointer transition-all flex items-center justify-center ${
                  isFlagSelectionMode
                    ? 'bg-red-500/20 ring-2 ring-red-500/60 scale-110 shadow-sm'
                    : 'hover:scale-125'
                }`}
                title={isFlagSelectionMode ? "Tutup Mode Flagging Cluster" : "Mode Ceklis Flagging Cluster (Tandai Noise)"}
              >
                <Flag className="w-5 h-5 fill-red-500 text-red-500 opacity-90 group-hover:opacity-100 transition-all drop-shadow-[0_0_6px_rgba(239,68,68,0.5)]" />
              </button>
            </div>

          </div>



          {/* Tabel Data Identik Referensi Gambar */}

          <div className="overflow-x-auto w-full">

            <table className="w-full text-left text-xs border-collapse">
              <thead>
                <tr className={`border-b text-[11px] font-bold uppercase tracking-wider ${
                  isDark ? 'bg-slate-900/60 border-slate-800 text-slate-400' : 'bg-slate-50 border-slate-200 text-slate-600'
                }`}>
                  <th className="w-8 px-2 py-3 text-center select-none whitespace-nowrap"></th>
                  {isFlagSelectionMode && (
                    <th className="w-8 px-2 py-3 text-center select-none whitespace-nowrap">
                      <input
                        type="checkbox"
                        checked={alerts.length > 0 && alerts.every(al => !!selectedClusterItems[al.aggregation_id || al.cluster_id || al.id])}
                        onChange={handleToggleSelectAll}
                        className="w-4 h-4 rounded text-blue-600 cursor-pointer accent-blue-600 align-middle"
                        title="Pilih / Batal Pilih Semua"
                      />
                    </th>
                  )}
                  <th className="px-3 py-3 select-none whitespace-nowrap">Timestamp Start</th>
                  {clusterMode === 'cumulative' ? (
                    <th className="px-3 py-3 select-none whitespace-nowrap">Last Update</th>
                  ) : (
                    <th className="px-3 py-3 select-none whitespace-nowrap">Timestamp Stop</th>
                  )}
                  <th className="px-3 py-3 select-none whitespace-nowrap">Cluster ID</th>
                  <th className="px-3 py-3 select-none whitespace-nowrap">Tenant</th>
                  <th className="px-3 py-3 select-none whitespace-nowrap">Agent</th>
                  <th className="px-2 py-3 text-center select-none whitespace-nowrap">Rule ID</th>
                  {clusterMode !== 'cumulative' && (
                    <th className="px-3 py-3 select-none whitespace-nowrap">Actor</th>
                  )}
                  <th className="px-3 py-3 select-none whitespace-nowrap min-w-[200px]">Activity</th>
                </tr>
              </thead>
              <tbody className={`divide-y font-sans ${
                isDark ? 'divide-slate-800/60 bg-[#0a0e1a]' : 'divide-slate-100 bg-white'
              }`}>
                {alertsLoading && alerts.length === 0 ? (
                  <tr>
                    <td colSpan={clusterMode === 'cumulative' ? (isFlagSelectionMode ? 9 : 8) : (isFlagSelectionMode ? 10 : 9)} className="px-6 py-16 text-center">
                      <div className="flex flex-col items-center justify-center gap-2.5">
                        <RefreshCw className="w-5 h-5 animate-spin text-blue-500" />
                        <span className={`text-xs font-mono font-medium ${isDark ? 'text-slate-400' : 'text-slate-600'}`}>
                          Memuat data cluster yang cocok...
                        </span>
                      </div>
                    </td>
                  </tr>
                ) : alertsNetworkError && alerts.length === 0 ? (
                  <tr>
                    <td colSpan={clusterMode === 'cumulative' ? (isFlagSelectionMode ? 9 : 8) : (isFlagSelectionMode ? 10 : 9)} className="px-6 py-12 text-center">
                      <div className="flex flex-col items-center justify-center gap-2">
                        <AlertTriangle className="w-5 h-5 text-amber-500" />
                        <span className={`text-xs font-mono font-semibold ${isDark ? 'text-amber-400' : 'text-amber-600'}`}>
                          Gagal memuat cluster dari backend API.
                        </span>
                        <button
                          onClick={fetchClusterAlerts}
                          className="mt-2 px-3 py-1 rounded bg-blue-600 hover:bg-blue-500 text-white text-xs font-medium cursor-pointer"
                        >
                          Coba Lagi
                        </button>
                      </div>
                    </td>
                  </tr>
                ) : alerts.length === 0 ? (
                  <tr>
                    <td colSpan={clusterMode === 'cumulative' ? (isFlagSelectionMode ? 9 : 8) : (isFlagSelectionMode ? 10 : 9)} className="px-6 py-12 text-center">
                      <span className={`text-xs font-mono ${isDark ? 'text-slate-500' : 'text-slate-400'}`}>
                        Tidak ada cluster yang cocok dengan filter yang dipilih.
                      </span>
                    </td>
                  </tr>
                ) : (
                  alerts.map((al) => {
                    const clusterId = al.aggregation_id || al.cluster_id || al.id;
                    const isExpanded = expandedClusterId === clusterId;
                    const isSelected = selectedAlert && (
                      selectedAlert.aggregation_id === clusterId || 
                      selectedAlert.cluster_id === clusterId || 
                      selectedAlert.id === clusterId
                    );

                    const tzOpts = { timeZone: 'Asia/Jakarta', month: 'short', day: '2-digit', hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: false };
                    const formatFeDate = (d) => {
                      if (!d) return '-';
                      try {
                        return new Date(d).toLocaleString('en-US', tzOpts) + ' WIB';
                      } catch (e) {
                        return String(d);
                      }
                    };

                    const startDisplay = al.timestamp_start || al.start || formatFeDate(al.first_seen_at || al.window_start);
                    const stopDisplay = al.timestamp_stop || al.stop || formatFeDate(al.window_end);
                    const lastUpdateDisplay = al.last_update || formatFeDate(al.last_seen_at);

                    const isClusterChecked = !!selectedClusterItems[clusterId];

                    return (
                      <React.Fragment key={clusterId}>
                        <tr
                          onClick={() => handleToggleClusterDetail(al)}
                          className={`transition-colors align-middle h-10 cursor-pointer ${
                            isClusterChecked
                              ? (isDark ? 'bg-blue-900/30 border-l-4 border-l-blue-400' : 'bg-blue-100/70 border-l-4 border-l-blue-500')
                              : (isSelected || isExpanded)
                              ? (isDark ? 'bg-blue-600/15 border-l-4 border-l-blue-500' : 'bg-blue-50/80 border-l-4 border-l-blue-600')
                              : (isDark ? 'hover:bg-slate-800/40' : 'hover:bg-slate-50/80')
                          }`}
                        >
                          {/* 0. Chevron Expand Indicator */}
                          <td className="w-8 px-2 py-2 text-center select-none text-slate-400">
                            {isExpanded ? (
                              <ChevronDown className="w-4 h-4 mx-auto text-blue-500" />
                            ) : (
                              <ChevronRight className="w-4 h-4 mx-auto hover:text-blue-500 transition-colors" />
                            )}
                          </td>

                          {/* 0b. Checkbox Flag Selection */}
                          {isFlagSelectionMode && (
                            <td 
                              className="w-8 px-2 py-2 text-center select-none"
                              onClick={(e) => e.stopPropagation()}
                            >
                              <input
                                type="checkbox"
                                checked={isClusterChecked}
                                onChange={(e) => handleToggleSelectCluster(al, e)}
                                className="w-4 h-4 rounded text-blue-600 cursor-pointer accent-blue-600 align-middle"
                              />
                            </td>
                          )}

                          {/* 1. Timestamp Start */}
                          <td className="px-3 py-2 font-mono text-[11px] whitespace-nowrap overflow-hidden">
                            <span className={isDark ? 'text-slate-300' : 'text-slate-600'}>
                              {startDisplay}
                            </span>
                          </td>

                          {/* 2. Timestamp Stop / Last Update */}
                          <td className="px-3 py-2 font-mono text-[11px] whitespace-nowrap overflow-hidden">
                            <span className={isDark ? 'text-slate-300' : 'text-slate-600'}>
                              {clusterMode === 'cumulative' ? lastUpdateDisplay : stopDisplay}
                            </span>
                          </td>

                          {/* 3. Cluster ID (yang interval) */}
                          <td className="px-3 py-2 font-mono whitespace-nowrap overflow-hidden">
                            <span 
                              className="font-bold text-[11px] tracking-tight text-blue-600 dark:text-blue-400 hover:text-blue-700 dark:hover:text-blue-300 hover:underline cursor-pointer select-all truncate block"
                              title={`Klik untuk melihat detail per alert (${clusterId})`}
                              onClick={() => handleToggleClusterDetail(al)}
                            >
                              {clusterId}
                            </span>
                          </td>

                          {/* 4. Tenant */}
                          <td className="px-3 py-2 font-mono whitespace-nowrap overflow-hidden">
                            <span 
                              className={`text-[11px] font-semibold truncate block ${isDark ? 'text-slate-200' : 'text-slate-800'}`}
                              title={al.tenant_id || 'DEFAULT'}
                            >
                              {al.tenant_id || 'DEFAULT'}
                            </span>
                          </td>

                          {/* 5. Agent */}
                          <td className="px-3 py-2 font-mono whitespace-nowrap overflow-hidden">
                            <span 
                              className={`text-[11px] font-mono font-medium truncate block ${isDark ? 'text-slate-300' : 'text-slate-700'}`}
                              title={al.agent || al.target || '-'}
                            >
                              {al.agent || al.target || '-'}
                            </span>
                          </td>

                          {/* 6. Rule ID */}
                          <td className="px-2 py-2 text-center font-mono whitespace-nowrap overflow-hidden">
                            <span className={`text-[11px] font-bold px-1.5 py-0.5 rounded ${isDark ? 'bg-slate-800 text-slate-200 border border-slate-700' : 'bg-slate-100 text-slate-800 border border-slate-300'}`}>
                              {al.rule_id || '-'}
                            </span>
                          </td>

                          {/* 7. Actor (interval only) */}
                          {clusterMode !== 'cumulative' && (
                            <td className="px-3 py-2 font-mono whitespace-nowrap overflow-hidden">
                              <div 
                                className={`text-[11px] font-mono truncate block ${isDark ? 'text-slate-300' : 'text-slate-600'}`}
                                title={al.actor || '-'}
                              >
                                {al.actor || '-'}
                              </div>
                            </td>
                          )}

                          {/* 8. Activity */}
                          <td className="px-3 py-2 whitespace-nowrap overflow-hidden max-w-[260px]">
                            <span 
                              className={`text-[11px] font-medium truncate block ${isDark ? 'text-slate-200' : 'text-slate-800'}`}
                              title={al.activity || al.rule_description || '-'}
                            >
                              {al.activity || al.rule_description || '-'}
                            </span>
                          </td>

                        </tr>

                        {/* DETAIL PER ALERT SUBTABLE */}
                        {isExpanded && (
                          <tr onClick={(e) => e.stopPropagation()} className={isDark ? 'bg-slate-900/90 border-b border-slate-800' : 'bg-slate-50 border-b border-slate-200'}>
                            <td colSpan={clusterMode === 'cumulative' ? (isFlagSelectionMode ? 9 : 8) : (isFlagSelectionMode ? 10 : 9)} className="p-3 sm:p-4">
                              <div className={`p-4 rounded-xl border shadow-sm ${
                                isDark ? 'bg-[#070b14] border-slate-700/80' : 'bg-white border-slate-200'
                              }`}>
                                <div className="flex items-center justify-between mb-3 pb-2 border-b border-slate-200 dark:border-slate-800">
                                  <div className="flex items-center gap-2 flex-wrap">
                                    <span className="font-bold text-xs uppercase tracking-wider text-slate-800 dark:text-slate-200">
                                      Detail
                                    </span>
                                  </div>
                                  <button
                                    type="button"
                                    onClick={() => setExpandedClusterId(null)}
                                    className="text-slate-400 hover:text-slate-600 dark:hover:text-slate-200 text-xs font-medium cursor-pointer"
                                  >
                                    ✕ Tutup
                                  </button>
                                </div>

                                {clusterLogsLoading[clusterId] ? (
                                  <div className="py-8 flex flex-col items-center justify-center gap-2">
                                    <RefreshCw className="w-5 h-5 animate-spin text-blue-500" />
                                    <span className="text-xs font-mono text-slate-500">Memuat detail per alert...</span>
                                  </div>
                                ) : (
                                  <div className="overflow-x-auto w-full">
                                    <table className="w-full text-left text-xs border-collapse">
                                      <thead>
                                        <tr className={`border-b text-[10.5px] font-bold uppercase tracking-wider ${
                                          isDark ? 'bg-slate-800/80 text-slate-300 border-slate-700' : 'bg-slate-100 text-slate-700 border-slate-200'
                                        }`}>
                                          <th className="px-3 py-2 whitespace-nowrap min-w-[150px]">ALERT ID</th>
                                          <th className="px-3 py-2 whitespace-nowrap min-w-[130px]">AGENT</th>
                                          <th className="px-3 py-2 whitespace-nowrap min-w-[130px]">ACTOR</th>
                                          <th className="px-2 py-2 text-center whitespace-nowrap min-w-[80px]">RULE ID</th>
                                          <th className="px-3 py-2 whitespace-nowrap min-w-[320px]">FULL LOG</th>
                                        </tr>
                                      </thead>
                                      <tbody className={`divide-y font-mono ${
                                        isDark ? 'divide-slate-800 bg-[#060a12]' : 'divide-slate-100 bg-white'
                                      }`}>
                                        {(clusterLogsMap[clusterId] || []).length === 0 ? (
                                          <tr>
                                            <td colSpan="5" className="px-4 py-6 text-center text-xs text-slate-500 font-sans">
                                              Tidak ada detail alert untuk cluster ini.
                                            </td>
                                          </tr>
                                        ) : (
                                          (clusterLogsMap[clusterId] || []).map((logItem, lIdx) => (
                                            <tr key={`${logItem.alert_id || logItem.event_id}-${lIdx}`} className={isDark ? 'hover:bg-slate-800/40' : 'hover:bg-slate-50'}>
                                              {/* 1. ALERT ID */}
                                              <td className="px-3 py-2.5 text-xs font-bold whitespace-nowrap text-blue-600 dark:text-blue-400 select-all">
                                                <div>{logItem.alert_id || logItem.event_id || '-'}</div>
                                                {logItem.timestamp && (
                                                  <div className="text-[10px] text-slate-500 dark:text-slate-400 font-normal mt-0.5">
                                                    {logItem.timestamp}
                                                  </div>
                                                )}
                                              </td>
                                              {/* 2. AGENT */}
                                              <td className="px-3 py-2.5 text-xs font-sans text-slate-800 dark:text-slate-200 whitespace-nowrap">
                                                {logItem.agent || logItem.agent_name || '-'}
                                              </td>
                                              {/* 3. ACTOR */}
                                              <td className="px-3 py-2.5 text-xs text-slate-800 dark:text-slate-200 whitespace-nowrap">
                                                {logItem.actor || logItem.source_ip || '-'}
                                              </td>
                                              {/* 4. RULE ID */}
                                              <td className="px-2 py-2.5 text-xs text-center font-bold text-slate-800 dark:text-slate-200 whitespace-nowrap">
                                                <span className="px-2 py-0.5 rounded bg-slate-100 dark:bg-slate-800 border border-slate-300 dark:border-slate-700 text-[11px]">
                                                  {logItem.rule_id || '-'}
                                                </span>
                                              </td>
                                              {/* 5. FULL LOG */}
                                              <td className="px-3 py-2.5 text-xs text-slate-700 dark:text-slate-300 select-all break-all min-w-[320px]">
                                                <div className="max-h-28 overflow-y-auto whitespace-pre-wrap bg-slate-50 dark:bg-slate-950/70 p-2 rounded border border-slate-200 dark:border-slate-800 font-mono text-[11px]">
                                                  {logItem.full_log || logItem.payload || '-'}
                                                </div>
                                              </td>
                                            </tr>
                                          ))
                                        )}
                                      </tbody>
                                    </table>
                                  </div>
                                )}
                              </div>
                            </td>
                          </tr>
                        )}
                      </React.Fragment>
                    );
                  })
                )}
              </tbody>
            </table>

          </div>



          {/* Table Footer: Pagination Controls */}

          <div className={`p-3.5 border-t flex flex-wrap items-center justify-between gap-3 text-xs ${

            isDark ? 'border-slate-800 bg-[#070b14] text-slate-400' : 'border-slate-200 bg-slate-50 text-slate-600'

          }`}>

            {/* Info baris */}

            <div className="flex items-center gap-2 font-mono text-[11px]">

              <span>

                Menampilkan {alerts.length > 0 ? ((alertsPage - 1) * alertsLimit) + 1 : 0} - {Math.min(alertsTotal, alertsPage * alertsLimit)} dari {alertsTotal.toLocaleString()} {clusterMode === 'interval' ? 'cluster' : 'alert'}

              </span>

            </div>



            {/* Navigasi Halaman */}

            <div className="flex items-center gap-1.5">

              <button

                type="button"

                onClick={() => setAlertsPage(1)}

                disabled={alertsPage <= 1 || alertsLoading}

                className={`p-1.5 rounded border transition-colors cursor-pointer disabled:opacity-30 disabled:cursor-not-allowed ${

                  isDark ? 'border-slate-700 hover:bg-slate-800 text-slate-300' : 'border-slate-200 hover:bg-slate-200 text-slate-700'

                }`}

                title="Halaman Pertama"

              >

                <ChevronsLeft className="w-3.5 h-3.5" />

              </button>

              <button

                type="button"

                onClick={() => setAlertsPage(p => Math.max(1, p - 1))}

                disabled={alertsPage <= 1 || alertsLoading}

                className={`p-1.5 rounded border transition-colors cursor-pointer disabled:opacity-30 disabled:cursor-not-allowed ${

                  isDark ? 'border-slate-700 hover:bg-slate-800 text-slate-300' : 'border-slate-200 hover:bg-slate-200 text-slate-700'

                }`}

                title="Halaman Sebelumnya"

              >

                <ChevronLeft className="w-3.5 h-3.5" />

              </button>



              <span className="px-2.5 py-1 font-mono text-xs font-semibold">

                Halaman {alertsPage} dari {Math.max(1, Math.ceil(alertsTotal / alertsLimit))}

              </span>



              <button

                type="button"

                onClick={() => setAlertsPage(p => Math.min(Math.max(1, Math.ceil(alertsTotal / alertsLimit)), p + 1))}

                disabled={alertsPage >= Math.max(1, Math.ceil(alertsTotal / alertsLimit)) || alertsLoading}

                className={`p-1.5 rounded border transition-colors cursor-pointer disabled:opacity-30 disabled:cursor-not-allowed ${

                  isDark ? 'border-slate-700 hover:bg-slate-800 text-slate-300' : 'border-slate-200 hover:bg-slate-200 text-slate-700'

                }`}

                title="Halaman Berikutnya"

              >

                <ChevronRight className="w-3.5 h-3.5" />

              </button>

              <button

                type="button"

                onClick={() => setAlertsPage(Math.max(1, Math.ceil(alertsTotal / alertsLimit)))}

                disabled={alertsPage >= Math.max(1, Math.ceil(alertsTotal / alertsLimit)) || alertsLoading}

                className={`p-1.5 rounded border transition-colors cursor-pointer disabled:opacity-30 disabled:cursor-not-allowed ${

                  isDark ? 'border-slate-700 hover:bg-slate-800 text-slate-300' : 'border-slate-200 hover:bg-slate-200 text-slate-700'

                }`}

                title="Halaman Terakhir"

              >

                <ChevronsRight className="w-3.5 h-3.5" />

              </button>

            </div>



            {/* Page size dropdown */}

            <div className="flex items-center gap-1.5 text-xs font-mono">

              <span>Per halaman:</span>

              <select

                value={alertsLimit}

                onChange={(e) => {

                  setAlertsLimit(Number(e.target.value));

                  setAlertsPage(1);

                }}

                className={`px-2 py-1 rounded border text-xs font-mono outline-none cursor-pointer ${

                  isDark ? 'bg-slate-900 border-slate-700 text-slate-200' : 'bg-white border-slate-200 text-slate-800'

                }`}

              >

                <option value={25}>25</option>

                <option value={50}>50</option>

                <option value={100}>100</option>

              </select>

            </div>

          </div>

        </div>



        {/* Sisi Kanan: Side Detail Panel (Persis Image 1 Referensi User) */}

        {selectedAlert && (

          <div className={`w-[360px] md:w-[400px] xl:w-[430px] shrink-0 sticky top-2 self-start border rounded-xl p-5 shadow-lg space-y-4 max-h-[calc(100vh-100px)] overflow-y-auto animate-in fade-in slide-in-from-right-4 duration-200 ${

            isDark ? 'bg-[#0f172a] border-slate-700 text-white shadow-xl' : 'bg-white border-slate-200 text-black shadow-md'

          }`}>

            {/* Header: >_ Detail & Close Button */}

            <div className={`flex items-center justify-between pb-3 border-b ${

              isDark ? 'border-slate-800' : 'border-slate-200'

            }`}>

              <div className="flex items-center gap-2.5">

                <div className={`p-2 rounded-xl border ${

                  isDark ? 'bg-slate-800 border-slate-700 text-white' : 'bg-slate-100 border-slate-300 text-black'

                }`}>

                  <Terminal className="w-4 h-4" />

                </div>

                <div>

                  <h3 className={`font-bold text-base ${isDark ? 'text-white' : 'text-black'}`}>

                    Detail

                  </h3>

                </div>

              </div>

              <button

                type="button"

                onClick={() => setSelectedAlert(null)}

                className={`p-1.5 rounded-lg cursor-pointer transition-colors ${

                  isDark ? 'hover:bg-slate-800 text-slate-400 hover:text-white' : 'hover:bg-slate-100 text-slate-500 hover:text-black'

                }`}

                title="Tutup Detail"

              >

                <X className="w-4 h-4" />

              </button>

            </div>



            <div className="space-y-3.5 text-xs">

              {/* Box 1: Primary Details Box */}

              <div className={`p-3.5 rounded-xl border space-y-2.5 text-[11px] ${

                isDark ? 'bg-slate-950/70 border-slate-800' : 'bg-slate-50 border-slate-200'

              }`}>

                <div>
                  <span className={`block text-[10px] uppercase font-semibold tracking-wider ${isDark ? 'text-slate-400' : 'text-slate-500'}`}>ALERT ID:</span>
                  <div className="flex items-center justify-between mt-0.5">
                    <span className={`font-mono font-bold text-xs ${isDark ? 'text-white' : 'text-black'} select-all break-all`}>
                      {selectedAlert.id}
                    </span>
                    <button
                      type="button"
                      onClick={() => handleCopyLog(selectedAlert.id, 'copy_id')}
                      className={`p-1 rounded cursor-pointer transition-colors ${
                        isDark ? 'text-slate-400 hover:text-white' : 'text-slate-500 hover:text-black'
                      }`}
                      title="Salin Alert ID"
                    >
                      {copiedId === 'copy_id' ? (
                        <Check className="w-3.5 h-3.5 text-emerald-500" />
                      ) : (
                        <Copy className="w-3.5 h-3.5" />
                      )}
                    </button>
                  </div>
                </div>

                <div className="grid grid-cols-2 gap-2 pt-1 border-t border-slate-200 dark:border-slate-800/80">
                  <div>
                    <span className={`block text-[10px] uppercase font-semibold ${isDark ? 'text-slate-400' : 'text-slate-500'}`}>TIMESTAMP:</span>
                    <span className={`font-mono font-bold ${isDark ? 'text-white' : 'text-black'}`}>{selectedAlert.timestamp}</span>
                  </div>
                  <div>
                    <span className={`block text-[10px] uppercase font-semibold ${isDark ? 'text-slate-400' : 'text-slate-500'}`}>TENANT:</span>
                    <span className={`font-mono font-bold ${isDark ? 'text-white' : 'text-black'}`}>{selectedAlert.tenant_id || 'DEFAULT'}</span>
                  </div>
                </div>

                <div className="grid grid-cols-2 gap-2 pt-1 border-t border-slate-200 dark:border-slate-800/80">
                  <div className="overflow-hidden">
                    <span className={`block text-[10px] uppercase font-semibold ${isDark ? 'text-slate-400' : 'text-slate-500'}`}>ACTOR:</span>
                    <span className={`font-mono font-bold break-all ${isDark ? 'text-white' : 'text-black'}`}>{selectedAlert.actor || '-'}</span>
                  </div>
                  <div className="overflow-hidden">
                    <span className={`block text-[10px] uppercase font-semibold ${isDark ? 'text-slate-400' : 'text-slate-500'}`}>TARGET:</span>
                    <span className={`font-mono font-bold break-all ${isDark ? 'text-white' : 'text-black'}`}>{selectedAlert.target || '-'}</span>
                  </div>
                </div>

                <div className="grid grid-cols-2 gap-2 pt-1 border-t border-slate-200 dark:border-slate-800/80">
                  <div>
                    <span className={`block text-[10px] uppercase font-semibold ${isDark ? 'text-slate-400' : 'text-slate-500'}`}>RULE ID:</span>
                    <span className={`font-mono font-bold ${isDark ? 'text-white' : 'text-black'}`}>
                      {selectedAlert.rule_id ? `Rule ${selectedAlert.rule_id}` : '-'}
                    </span>
                  </div>
                  <div>
                    <span className={`block text-[10px] uppercase font-semibold ${isDark ? 'text-slate-400' : 'text-slate-500'}`}>LEVEL:</span>
                    <span className={`font-mono font-bold ${isDark ? 'text-white' : 'text-black'}`}>
                      {selectedAlert.rule_level !== undefined && selectedAlert.rule_level !== null ? `Lv ${selectedAlert.rule_level}` : '-'}
                    </span>
                  </div>
                </div>

                <div className="pt-1 border-t border-slate-200 dark:border-slate-800/80">
                  <span className={`block text-[10px] uppercase font-semibold ${isDark ? 'text-slate-400' : 'text-slate-500'}`}>RULE DESCRIPTION:</span>
                  <span className={`font-medium block mt-0.5 leading-relaxed ${isDark ? 'text-white' : 'text-black'}`}>
                    {selectedAlert.rule_description || '-'}
                  </span>
                </div>


              </div>



              {/* Box 2: Lineage Box */}

              <div className={`p-3.5 rounded-xl border ${

                isDark ? 'bg-slate-950 border-slate-800' : 'bg-slate-50 border-slate-200'

              }`}>

                <div className="mb-2">

                  <span className={`text-[12px] font-bold uppercase tracking-wider ${

                    isDark ? 'text-white' : 'text-black'

                  }`}>

                    LINEAGE

                  </span>

                </div>



                <div className="space-y-2">

                  {/* ID Aggregat Alert */}

                  <div className={`p-2.5 rounded-lg border ${

                    isDark ? 'bg-slate-900 border-slate-800' : 'bg-white border-slate-200 shadow-2xs'

                  }`}>

                    <div className="flex items-center justify-between">

                      <span className={`text-[10px] font-semibold uppercase tracking-wider ${

                        isDark ? 'text-slate-400' : 'text-slate-500'

                      }`}>

                        INTERVAL CLUSTER ID

                      </span>

                      <button

                        type="button"

                        onClick={() => handleCopyLog(selectedAlert.aggregation_id, 'copy_agg')}

                        className={`p-0.5 rounded cursor-pointer transition-colors ${

                          isDark ? 'text-slate-400 hover:text-white' : 'text-slate-500 hover:text-black'

                        }`}

                        title="Salin Interval Cluster ID"

                      >

                        {copiedId === 'copy_agg' ? (

                          <Check className="w-3.5 h-3.5 text-emerald-500" />

                        ) : (

                          <Copy className="w-3.5 h-3.5" />

                        )}

                      </button>

                    </div>

                    <span 

                      className={`font-mono text-[11px] font-bold break-all block mt-1 select-all ${

                        isDark ? 'text-white' : 'text-black'

                      }`}

                      title={selectedAlert.aggregation_id}

                    >

                      {selectedAlert.aggregation_id || '-'}

                    </span>

                  </div>



                  {/* Cumulative ID */}

                  <div className={`p-2.5 rounded-lg border ${

                    isDark ? 'bg-slate-900 border-slate-800' : 'bg-white border-slate-200 shadow-2xs'

                  }`}>

                    <div className="flex items-center justify-between">

                      <span className={`text-[10px] font-semibold uppercase tracking-wider ${

                        isDark ? 'text-slate-400' : 'text-slate-500'

                      }`}>

                        CUMULATIVE CLUSTER ID

                      </span>

                      <button

                        type="button"

                        onClick={() => handleCopyLog(selectedAlert.cumulative_id, 'copy_cum')}

                        className={`p-0.5 rounded cursor-pointer transition-colors ${

                          isDark ? 'text-slate-400 hover:text-white' : 'text-slate-500 hover:text-black'

                        }`}

                        title="Salin Cumulative Cluster ID"

                      >

                        {copiedId === 'copy_cum' ? (

                          <Check className="w-3.5 h-3.5 text-emerald-500" />

                        ) : (

                          <Copy className="w-3.5 h-3.5" />

                        )}

                      </button>

                    </div>

                    <span 

                      className={`font-mono text-[11px] font-bold break-all block mt-1 select-all ${

                        isDark ? 'text-white' : 'text-black'

                      }`}

                      title={selectedAlert.cumulative_id}

                    >

                      {selectedAlert.cumulative_id || '-'}

                    </span>

                  </div>



                  {/* TICKET ID */}
                  <div className={`p-2.5 rounded-lg border ${
                    isDark ? 'bg-slate-900 border-slate-800' : 'bg-white border-slate-200 shadow-2xs'
                  }`}>
                    <div className="flex items-center justify-between">
                      <span className={`text-[10px] font-semibold uppercase tracking-wider ${
                        isDark ? 'text-slate-400' : 'text-slate-500'
                      }`}>
                        TICKET ID
                      </span>
                      <button
                        type="button"
                        onClick={() => handleCopyLog(selectedAlert.ticket_id, 'copy_tkt')}
                        className={`p-0.5 rounded cursor-pointer transition-colors ${
                          isDark ? 'text-slate-400 hover:text-white' : 'text-slate-500 hover:text-black'
                        }`}
                        title="Salin Ticket ID"
                      >
                        {copiedId === 'copy_tkt' ? (
                          <Check className="w-3.5 h-3.5 text-emerald-500" />
                        ) : (
                          <Copy className="w-3.5 h-3.5" />
                        )}
                      </button>
                    </div>
                    <span 
                      className={`font-mono text-[11px] font-bold break-all block mt-1 select-all ${
                        isDark ? 'text-white' : 'text-black'
                      }`}
                      title={selectedAlert.ticket_id}
                    >
                      {selectedAlert.ticket_id || '-'}
                    </span>
                  </div>
                </div>
              </div>

              {/* Box 3: Full Log Payload */}
              <div className="space-y-1.5">
                <div className="flex items-center justify-between text-xs font-semibold">
                  <span className={`uppercase font-bold tracking-wider text-[11px] ${
                    isDark ? 'text-slate-300' : 'text-slate-700'
                  }`}>
                    FULL LOG PAYLOAD:
                  </span>
                  <button
                    type="button"
                    onClick={() => handleCopyLog(selectedAlert.full_log || '', 'copy_full_payload')}
                    className={`p-0.5 rounded cursor-pointer transition-colors ${
                      isDark ? 'text-slate-400 hover:text-white' : 'text-slate-500 hover:text-black'
                    }`}
                    title="Salin Full Log Payload"
                  >
                    {copiedId === 'copy_full_payload' ? (
                      <Check className="w-3.5 h-3.5 text-emerald-500" />
                    ) : (
                      <Copy className="w-3.5 h-3.5" />
                    )}
                  </button>

                </div>

                <pre className="raw-log-viewer cluster-raw-log p-3 rounded-lg border border-slate-300 font-mono text-[10.5px] leading-relaxed overflow-x-auto max-h-56 whitespace-pre-wrap break-all shadow-2xs select-all">

                  {selectedAlert.full_log || 'Tidak ada raw payload teks tambahan.'}

                </pre>

              </div>

            </div>

          </div>

        )}

      </div>

      {/* SUPPRESSION FORM MODAL (Formulir Supresi dari Icon Bendera Merah) */}
      {showSuppressionModal && (
        <div className="fixed inset-0 bg-black/70 backdrop-blur-xs z-50 flex items-center justify-center p-4">
          <div style={{ fontFamily: "'Trebuchet MS', 'Lucida Sans Unicode', 'Lucida Grande', 'Lucida Sans', Arial, sans-serif" }} className={`${isDark ? 'bg-[#0b0f19] border-slate-800 text-slate-100' : 'bg-white border-slate-200 text-slate-800'} border rounded-2xl max-w-xl w-full p-6 shadow-2xl space-y-4 max-h-[92vh] overflow-y-auto animate-in fade-in duration-150`}>
            
            {/* Modal Header */}
            <div className={`flex items-center justify-between border-b pb-3.5 ${isDark ? 'border-slate-800' : 'border-slate-200'}`}>
              <div className="flex items-center gap-2.5">
                <Flag className="w-5 h-5 fill-red-500 text-red-500 shrink-0" />
                <div>
                  <h3 className={`text-base font-bold leading-tight ${isDark ? 'text-white' : 'text-slate-900'}`}>
                    Tandai Noise & Usul Aturan Wazuh (CDB / XML)
                  </h3>
                  <p className={`text-[11px] mt-0.5 ${isDark ? 'text-slate-400' : 'text-slate-500'}`}>
                    {Object.keys(selectedClusterItems).length > 1
                      ? `Menandai ${Object.keys(selectedClusterItems).length} cluster terpilih. Setiap cluster akan otomatis diajukan sebagai aturan supresi terpisah di Policy Bundle.`
                      : 'Menandai kluster sebagai noise operasional untuk Policy Bundle (Wazuh). Kluster & tiket tetap diproses normal dalam pipeline.'}
                  </p>
                </div>
              </div>
              <button
                type="button"
                onClick={() => setShowSuppressionModal(false)}
                className={`p-1.5 rounded-lg transition-colors cursor-pointer ${isDark ? 'text-slate-400 hover:text-white hover:bg-slate-800' : 'text-slate-400 hover:text-slate-800 hover:bg-slate-100'}`}
                title="Close"
              >
                <X className="w-5 h-5" />
              </button>
            </div>

            {/* Success / Error Alerts */}
            {suppSuccessMsg && (
              <div className="p-3 rounded-lg bg-emerald-500/10 border border-emerald-500/30 text-emerald-400 text-xs flex items-center gap-2">
                <Check className="w-4 h-4 shrink-0 text-emerald-400" />
                <span>{suppSuccessMsg}</span>
              </div>
            )}
            {suppErrorMsg && (
              <div className="p-3 rounded-lg bg-rose-500/10 border border-rose-500/30 text-rose-400 text-xs flex items-center gap-2">
                <AlertTriangle className="w-4 h-4 shrink-0 text-rose-400" />
                <span>{suppErrorMsg}</span>
              </div>
            )}

            {/* Form */}
            <form onSubmit={handleSubmitSuppression} className="space-y-4 text-xs">
              
              {/* 5 Cluster Dimensions Grid */}
              <div className={`p-4 rounded-xl border ${isDark ? 'bg-[#070b14] border-slate-800/80' : 'bg-slate-50 border-slate-200'} space-y-3`}>
                <span className={`text-[11px] font-bold uppercase tracking-wider block ${isDark ? 'text-slate-300' : 'text-slate-700'}`}>
                  5 Cluster Dimensions
                </span>

                <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                  {/* Tenant */}
                  <div>
                    <label className={`block text-[11px] font-semibold mb-1 ${isDark ? 'text-slate-300' : 'text-slate-700'}`}>
                      Tenant
                    </label>
                    <input
                      type="text"
                      value={suppForm.tenant}
                      onChange={(e) => setSuppForm({ ...suppForm, tenant: e.target.value })}
                      placeholder="e.g. TenantD, DEFAULT"
                      className={`w-full px-3 py-2 rounded-lg border text-xs focus:outline-none focus:ring-1 focus:ring-blue-500 transition-colors ${
                        isDark ? 'bg-[#0f1422] border-slate-700 text-white placeholder:text-slate-500' : 'bg-white border-slate-300 text-slate-800 placeholder:text-slate-400'
                      }`}
                    />
                  </div>

                  {/* Agent */}
                  <div>
                    <label className={`block text-[11px] font-semibold mb-1 ${isDark ? 'text-slate-300' : 'text-slate-700'}`}>
                      Agent
                    </label>
                    <input
                      type="text"
                      value={suppForm.agent}
                      onChange={(e) => setSuppForm({ ...suppForm, agent: e.target.value })}
                      placeholder="e.g. isif-rproxy-155"
                      className={`w-full px-3 py-2 rounded-lg border text-xs focus:outline-none focus:ring-1 focus:ring-blue-500 transition-colors ${
                        isDark ? 'bg-[#0f1422] border-slate-700 text-white placeholder:text-slate-500' : 'bg-white border-slate-300 text-slate-800 placeholder:text-slate-400'
                      }`}
                    />
                  </div>

                  {/* Rule ID */}
                  <div>
                    <label className={`block text-[11px] font-semibold mb-1 ${isDark ? 'text-slate-300' : 'text-slate-700'}`}>
                      Rule ID
                    </label>
                    <input
                      type="text"
                      value={suppForm.ruleId}
                      onChange={(e) => setSuppForm({ ...suppForm, ruleId: e.target.value })}
                      placeholder="e.g. 31301"
                      className={`w-full px-3 py-2 rounded-lg border text-xs focus:outline-none focus:ring-1 focus:ring-blue-500 transition-colors ${
                        isDark ? 'bg-[#0f1422] border-slate-700 text-white placeholder:text-slate-500' : 'bg-white border-slate-300 text-slate-800 placeholder:text-slate-400'
                      }`}
                    />
                  </div>

                  {/* Actor */}
                  <div>
                    <label className={`block text-[11px] font-semibold mb-1 ${isDark ? 'text-slate-300' : 'text-slate-700'}`}>
                      Actor
                    </label>
                    <input
                      type="text"
                      value={suppForm.actor}
                      onChange={(e) => setSuppForm({ ...suppForm, actor: e.target.value })}
                      placeholder="e.g. 34.104.184.175 / user:ubuntu"
                      className={`w-full px-3 py-2 rounded-lg border text-xs focus:outline-none focus:ring-1 focus:ring-blue-500 transition-colors ${
                        isDark ? 'bg-[#0f1422] border-slate-700 text-white placeholder:text-slate-500' : 'bg-white border-slate-300 text-slate-800 placeholder:text-slate-400'
                      }`}
                    />
                  </div>

                  {/* Activity */}
                  <div className="sm:col-span-2">
                    <label className={`block text-[11px] font-semibold mb-1 ${isDark ? 'text-slate-300' : 'text-slate-700'}`}>
                      Activity
                    </label>
                    <input
                      type="text"
                      value={suppForm.activity}
                      onChange={(e) => setSuppForm({ ...suppForm, activity: e.target.value })}
                      placeholder="e.g. GET /.env* [111], AUTH LOGIN [SUCCESS]"
                      className={`w-full px-3 py-2 rounded-lg border text-xs focus:outline-none focus:ring-1 focus:ring-blue-500 transition-colors ${
                        isDark ? 'bg-[#0f1422] border-slate-700 text-white placeholder:text-slate-500' : 'bg-white border-slate-300 text-slate-800 placeholder:text-slate-400'
                      }`}
                    />
                  </div>
                </div>
              </div>

              {/* Expired Date & Alasan */}
              <div className={`p-4 rounded-xl border ${isDark ? 'bg-[#070b14] border-slate-800/80' : 'bg-slate-50 border-slate-200'} space-y-3`}>
                <span className={`text-[11px] font-bold uppercase tracking-wider block ${isDark ? 'text-slate-300' : 'text-slate-700'}`}>
                  Validity & Justification
                </span>

                <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                  {/* Username (Otomatis Terisi Sesuai User yang Sedang Login) */}
                  <div>
                    <label className={`block text-[11px] font-semibold mb-1 ${isDark ? 'text-slate-300' : 'text-slate-700'}`}>
                      Username <span className="text-red-500">*</span>
                    </label>
                    <input
                      type="text"
                      required
                      value={suppForm.username}
                      onChange={(e) => setSuppForm({ ...suppForm, username: e.target.value })}
                      placeholder="e.g. admin_secops"
                      className={`w-full px-3 py-2 rounded-lg border text-xs focus:outline-none focus:ring-1 focus:ring-blue-500 transition-colors ${
                        isDark ? 'bg-[#0f1422] border-slate-700 text-white placeholder:text-slate-500' : 'bg-white border-slate-300 text-slate-800 placeholder:text-slate-400'
                      }`}
                    />
                  </div>

                  {/* Expired Date */}
                  <div>
                    <label className={`block text-[11px] font-semibold mb-1 ${isDark ? 'text-slate-300' : 'text-slate-700'}`}>
                      Expiration Date <span className="text-red-500">*</span>
                    </label>
                    <input
                      type="date"
                      required
                      value={suppForm.expiredDate}
                      onChange={(e) => setSuppForm({ ...suppForm, expiredDate: e.target.value })}
                      className={`w-full px-3 py-2 rounded-lg border text-xs focus:outline-none focus:ring-1 focus:ring-blue-500 transition-colors ${
                        isDark ? 'bg-[#0f1422] border-slate-700 text-white' : 'bg-white border-slate-300 text-slate-800'
                      }`}
                    />
                  </div>
                </div>
                <span className={`text-[10px] block mt-1 ${isDark ? 'text-slate-500' : 'text-slate-400'}`}>
                  Maximum suppression SLA validity is 90 days from creation date.
                </span>

                {/* Alasan */}
                <div>
                  <label className={`block text-[11px] font-semibold mb-1 ${isDark ? 'text-slate-300' : 'text-slate-700'}`}>
                    Suppression Reason <span className="text-red-500">*</span>
                  </label>
                  <textarea
                    rows={3}
                    required
                    value={suppForm.reason}
                    onChange={(e) => setSuppForm({ ...suppForm, reason: e.target.value })}
                    placeholder="Enter administrative or technical justification for suppressing this alert (e.g., internal system testing, scheduled vulnerability scanning, benign operational noise)..."
                    className={`w-full px-3 py-2 rounded-lg border text-xs focus:outline-none focus:ring-1 focus:ring-blue-500 transition-colors resize-none ${
                      isDark ? 'bg-[#0f1422] border-slate-700 text-white placeholder:text-slate-500' : 'bg-white border-slate-300 text-slate-800 placeholder:text-slate-400'
                    }`}
                  />
                </div>
              </div>

              {/* Action Buttons */}
              <div className={`flex items-center justify-end gap-2.5 pt-2 border-t ${isDark ? 'border-slate-800' : 'border-slate-200'}`}>
                <button
                  type="button"
                  onClick={() => setShowSuppressionModal(false)}
                  className={`px-4 py-2 rounded-lg text-xs font-semibold cursor-pointer transition-colors ${
                    isDark ? 'bg-slate-800 hover:bg-slate-700 text-slate-300' : 'bg-slate-200 hover:bg-slate-300 text-slate-700'
                  }`}
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={suppSubmitting}
                  className="px-5 py-2 rounded-lg bg-red-600 hover:bg-red-500 text-white font-semibold text-xs flex items-center gap-1.5 shadow-xs cursor-pointer transition-colors disabled:opacity-50"
                >
                  {suppSubmitting ? (
                    <RefreshCw className="w-3.5 h-3.5 animate-spin" />
                  ) : (
                    <Flag className="w-3.5 h-3.5 fill-white" />
                  )}
                  <span>{suppSubmitting ? 'Menyimpan...' : Object.keys(selectedClusterItems).length > 1 ? `Ajukan ${Object.keys(selectedClusterItems).length} Aturan Terpisah ke Policy Bundle` : 'Ajukan Usul Aturan Wazuh'}</span>
                </button>
              </div>

            </form>
          </div>
        </div>
      )}



          </div>


        );
}
