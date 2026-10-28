import React, { useMemo, useState, useRef, useEffect } from 'react';

import { ResponsiveContainer, PieChart, Pie, Cell, Tooltip } from 'recharts';

import { 

  Search, RefreshCw, AlertTriangle, ChevronLeft, ChevronRight, 

  ChevronsLeft, ChevronsRight, Copy, Check, X, Terminal, 

  Layers, ExternalLink, Flag

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

  customStartDate = '2026-07-01',

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

  const [alertsSearchInput, setAlertsSearchInput] = useState('');

  const [alertsSearchQuery, setAlertsSearchQuery] = useState('');

  const [selectedAlert, setSelectedAlert] = useState(null);

  const [copiedId, setCopiedId] = useState(null);

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

  }, [effectiveTenant, effectiveRuleId, effectiveAgent, effectiveActor, effectiveActivity, alertsLevelFilter, alertsSearchQuery, timeRange, customStartDate, customEndDate]);



  const fetchClusterAlerts = async () => {

    setAlertsLoading(true);

    try {

      const params = new URLSearchParams({

        page: String(alertsPage),

        limit: String(alertsLimit),

        level_filter: alertsLevelFilter

      });

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



      const res = await fetch(`/api/raw-alerts?${params.toString()}`);

      if (res.ok) {

        setAlertsNetworkError(false);

        const data = await res.json();

        setAlerts(data.alerts || []);

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

  }, [alertsPage, alertsLimit, alertsLevelFilter, alertsSearchQuery, effectiveTenant, effectiveRuleId, effectiveAgent, effectiveActor, effectiveActivity, timeRange, customStartDate, customEndDate]);



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

                  {cluster.data.map((entry, index) => (

                    <Cell 

                      key={`cell-${cluster.id}-${index}`} 

                      fill={entry.color} 

                      stroke="none" 

                      strokeWidth={0}

                      cursor="pointer"

                      onClick={(e) => {

                        e?.stopPropagation?.();

                        handleSliceClick(cluster.id, entry);

                      }}

                      className="cursor-pointer hover:opacity-80 transition-opacity"

                    />

                  ))}

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

                  className="flex items-center gap-2.5 text-xs min-w-0 cursor-pointer hover:opacity-80 transition-opacity"

                  title={`Klik untuk memfilter ${item.name} (${item.pct}%)`}

                >

                  <span 

                    className="w-2.5 h-2.5 rounded-full shrink-0" 

                    style={{ backgroundColor: item.color }} 

                  />

                  <span className={`truncate font-medium ${

                    isDark ? 'text-slate-300' : 'text-slate-700'

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

    <div className="space-y-6">

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

            onClick={() => setClusterMode('interval')}

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

            onClick={() => setClusterMode('cumulative')}

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

            <div className="shrink-0 w-28 sm:w-36">

              <h3 className={`text-base font-bold tracking-tight ${isDark ? 'text-white' : 'text-slate-900'}`}>

                Raw Alerts

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

                    onChange={(e) => setAlertsSearchInput(e.target.value)}

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

                    <Search className="w-3.5 h-3.5 text-white" strokeWidth={2.5} />

                  </button>

                </div>

              </form>

            </div>




            {/* Sisi Kanan (Pojok Kanan): Icon Flag Merah Murni Tanpa Lingkaran */}
            <div className="shrink-0 w-28 sm:w-36 flex justify-end items-center">
              <button
                type="button"
                onClick={() => {
                  const nextFlag = !isFlagFilterActive;
                  setIsFlagFilterActive(nextFlag);
                  setAlertsLevelFilter(nextFlag ? 'CRITICAL' : 'ALL');
                  setAlertsPage(1);
                }}
                className="p-1 cursor-pointer transition-transform hover:scale-125 group flex items-center justify-center"
                title={isFlagFilterActive || alertsLevelFilter === 'CRITICAL' ? 'Filter Flag Merah Aktif (Menampilkan Critical Alert)' : 'Filter Flag Merah (Critical Alert)'}
              >
                <Flag className={`w-5 h-5 transition-all ${
                  isFlagFilterActive || alertsLevelFilter === 'CRITICAL'
                    ? 'fill-red-600 text-red-600 drop-shadow-[0_0_8px_rgba(239,68,68,0.7)]'
                    : 'fill-red-500 text-red-500 opacity-85 group-hover:opacity-100'
                }`} />
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

                  <th className="px-3 py-3 select-none whitespace-nowrap">Timestamp</th>

                  <th className="px-3 py-3 select-none whitespace-nowrap">ID</th>

                  <th className="px-3 py-3 select-none whitespace-nowrap">Tenant</th>

                  <th className="px-2 py-3 text-center select-none whitespace-nowrap">Rule ID</th>

                  <th className="px-3 py-3 select-none whitespace-nowrap min-w-[180px]">Rule Desc</th>

                  <th className="px-2 py-3 text-center select-none whitespace-nowrap">Level</th>

                  <th className="px-3 py-3 select-none whitespace-nowrap">Actor</th>

                  <th className="px-3 py-3 select-none whitespace-nowrap">Target</th>

                </tr>

              </thead>

              <tbody className={`divide-y font-sans ${

                isDark ? 'divide-slate-800/60 bg-[#0a0e1a]' : 'divide-slate-100 bg-white'

              }`}>

                {alertsLoading && alerts.length === 0 ? (

                  <tr>

                    <td colSpan="8" className="px-6 py-16 text-center">

                      <div className="flex flex-col items-center justify-center gap-2.5">

                        <RefreshCw className="w-5 h-5 animate-spin text-blue-500" />

                        <span className={`text-xs font-mono font-medium ${isDark ? 'text-slate-400' : 'text-slate-600'}`}>

                          Memuat data alert yang cocok dengan cluster...

                        </span>

                      </div>

                    </td>

                  </tr>

                ) : alertsNetworkError && alerts.length === 0 ? (

                  <tr>

                    <td colSpan="8" className="px-6 py-12 text-center">

                      <div className="flex flex-col items-center justify-center gap-2">

                        <AlertTriangle className="w-5 h-5 text-amber-500" />

                        <span className={`text-xs font-mono font-semibold ${isDark ? 'text-amber-400' : 'text-amber-600'}`}>

                          Gagal memuat alert dari backend API.

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

                    <td colSpan="8" className="px-6 py-12 text-center">

                      <span className={`text-xs font-mono ${isDark ? 'text-slate-500' : 'text-slate-400'}`}>

                        Tidak ada alert yang cocok dengan filter cluster yang dipilih.

                      </span>

                    </td>

                  </tr>

                ) : (

                  alerts.map((al) => {

                    const isSelected = selectedAlert && selectedAlert.id === al.id;

                    return (

                      <tr

                        key={al.id}

                        className={`transition-colors align-middle h-10 ${

                          isSelected

                            ? (isDark ? 'bg-blue-600/15 border-l-4 border-l-blue-500' : 'bg-blue-50/80 border-l-4 border-l-blue-600')

                            : (isDark ? 'hover:bg-slate-800/30' : 'hover:bg-slate-50/70')

                        }`}

                      >

                        {/* Timestamp */}

                        <td className="px-3 py-2 font-mono text-[11px] whitespace-nowrap overflow-hidden">

                          <span className={isDark ? 'text-slate-300' : 'text-slate-600'}>

                            {al.timestamp}

                          </span>

                        </td>



                        {/* ID (Warna Biru / Solid Pill Saat Terpilih, Clickable, Exact Image 1 Style) */}

                        <td className="px-3 py-2 font-mono whitespace-nowrap overflow-hidden">

                          {isSelected ? (

                            <span 

                              className="font-bold text-[11px] tracking-tight bg-blue-600 text-white px-2 py-0.5 rounded select-all truncate inline-block cursor-pointer shadow-xs"

                              title="Klik untuk menutup detail"

                              onClick={() => setSelectedAlert(null)}

                            >

                              {al.id}

                            </span>

                          ) : (

                            <span 

                              className="font-bold text-[11px] tracking-tight text-blue-600 dark:text-blue-400 hover:text-blue-700 dark:hover:text-blue-300 hover:underline cursor-pointer select-all truncate block"

                              title={`Buka detail alert (${al.id})`}

                              onClick={() => setSelectedAlert(al)}

                            >

                              {al.id}

                            </span>

                          )}

                        </td>



                        {/* Tenant */}

                        <td className="px-3 py-2 font-mono whitespace-nowrap overflow-hidden">

                          <span 

                            className={`text-[11px] font-semibold truncate block ${isDark ? 'text-slate-200' : 'text-slate-800'}`}

                            title={al.tenant_id || 'DEFAULT'}

                          >

                            {al.tenant_id || 'DEFAULT'}

                          </span>

                        </td>



                        {/* Rule ID */}

                        <td className="px-2 py-2 text-center font-mono whitespace-nowrap overflow-hidden">

                          <span className={`text-[11px] font-semibold ${isDark ? 'text-slate-300' : 'text-slate-700'}`}>

                            {al.rule_id || '-'}

                          </span>

                        </td>



                        {/* Rule Desc */}

                        <td className="px-3 py-2 whitespace-nowrap overflow-hidden max-w-[260px]">

                          <span 

                            className={`text-[11px] font-medium truncate block ${isDark ? 'text-slate-200' : 'text-slate-800'}`}

                            title={al.rule_description || `Wazuh Rule ${al.rule_id}`}

                          >

                            {al.rule_description || `Wazuh Rule ${al.rule_id}`}

                          </span>

                        </td>



                        {/* Level */}

                        <td className="px-2 py-2 text-center font-mono whitespace-nowrap">

                          {getLevelBadge(al.rule_level)}

                        </td>



                        {/* Actor */}

                        <td className="px-3 py-2 font-mono whitespace-nowrap overflow-hidden">

                          <div 

                            className={`text-[11px] font-mono truncate block ${isDark ? 'text-slate-300' : 'text-slate-600'}`}

                            title={al.actor || '-'}

                          >

                            {al.actor || '-'}

                          </div>

                        </td>



                        {/* Target */}

                        <td className="px-3 py-2 font-mono whitespace-nowrap overflow-hidden">

                          <div 

                            className={`text-[11px] font-mono font-medium truncate block uppercase ${

                              isDark ? 'text-slate-300' : 'text-slate-700'

                            }`}

                            title={al.target || '-'}

                          >

                            {al.target || '-'}

                          </div>

                        </td>

                      </tr>

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

                Menampilkan {alerts.length > 0 ? ((alertsPage - 1) * alertsLimit) + 1 : 0} - {Math.min(alertsTotal, alertsPage * alertsLimit)} dari {alertsTotal.toLocaleString()} alert

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

                  <span className={`block text-[10px] uppercase font-semibold tracking-wider ${isDark ? 'text-slate-400' : 'text-slate-500'}`}>ID ALERT:</span>

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

                      title="Salin ID Alert"

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

                  <div>

                    <span className={`block text-[10px] uppercase font-semibold ${isDark ? 'text-slate-400' : 'text-slate-500'}`}>RULE & LEVEL:</span>

                    <span className={`font-mono font-bold ${isDark ? 'text-white' : 'text-black'}`}>

                      Rule {selectedAlert.rule_id} · Lv {selectedAlert.rule_level}

                    </span>

                  </div>

                  <div>

                    <span className={`block text-[10px] uppercase font-semibold ${isDark ? 'text-slate-400' : 'text-slate-500'}`}>ACTOR (IP):</span>

                    <span className={`font-mono font-bold ${isDark ? 'text-white' : 'text-black'}`}>{selectedAlert.actor || '-'}</span>

                  </div>

                </div>



                <div className="pt-1 border-t border-slate-200 dark:border-slate-800/80">

                  <span className={`block text-[10px] uppercase font-semibold ${isDark ? 'text-slate-400' : 'text-slate-500'}`}>TARGET (AGENT/HOST):</span>

                  <span className={`font-mono font-bold ${isDark ? 'text-white' : 'text-black'}`}>{selectedAlert.target || '-'}</span>

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

                        ID AGGREGAT ALERT

                      </span>

                      <button

                        type="button"

                        onClick={() => handleCopyLog(selectedAlert.aggregation_id, 'copy_agg')}

                        className={`p-0.5 rounded cursor-pointer transition-colors ${

                          isDark ? 'text-slate-400 hover:text-white' : 'text-slate-500 hover:text-black'

                        }`}

                        title="Salin ID Aggregat"

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

                        CUMULATIVE ID

                      </span>

                      <button

                        type="button"

                        onClick={() => handleCopyLog(selectedAlert.cumulative_id, 'copy_cum')}

                        className={`p-0.5 rounded cursor-pointer transition-colors ${

                          isDark ? 'text-slate-400 hover:text-white' : 'text-slate-500 hover:text-black'

                        }`}

                        title="Salin Cumulative ID"

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



                  {/* ID Tiket (Triage) */}

                  <div className={`p-2.5 rounded-lg border ${

                    isDark ? 'bg-slate-900 border-slate-800' : 'bg-white border-slate-200 shadow-2xs'

                  }`}>

                    <div className="flex items-center justify-between">

                      <span className={`text-[10px] font-semibold uppercase tracking-wider ${

                        isDark ? 'text-slate-400' : 'text-slate-500'

                      }`}>

                        ID TIKET (TRIAGE)

                      </span>

                      <div className="flex items-center gap-1">

                        {selectedAlert.ticket_id && typeof onNavigate === 'function' && (

                          <button

                            type="button"

                            onClick={() => onNavigate('triage', { search: selectedAlert.ticket_id })}

                            className="p-0.5 rounded cursor-pointer transition-colors text-blue-500 hover:text-blue-400"

                            title="Buka tiket ini di Ticket Queue"

                          >

                            <ExternalLink className="w-3.5 h-3.5" />

                          </button>

                        )}

                        <button

                          type="button"

                          onClick={() => handleCopyLog(selectedAlert.ticket_id, 'copy_tkt')}

                          className={`p-0.5 rounded cursor-pointer transition-colors ${

                            isDark ? 'text-slate-400 hover:text-white' : 'text-slate-500 hover:text-black'

                          }`}

                          title="Salin ID Tiket"

                        >

                          {copiedId === 'copy_tkt' ? (

                            <Check className="w-3.5 h-3.5 text-emerald-500" />

                          ) : (

                            <Copy className="w-3.5 h-3.5" />

                          )}

                        </button>

                      </div>

                    </div>

                    {selectedAlert.ticket_id && typeof onNavigate === 'function' ? (

                      <button

                        type="button"

                        onClick={() => onNavigate('triage', { search: selectedAlert.ticket_id })}

                        className="font-mono text-[11px] font-bold break-all block mt-1 text-blue-500 hover:text-blue-400 hover:underline cursor-pointer text-left"

                      >

                        {selectedAlert.ticket_id}

                      </button>

                    ) : (

                      <span 

                        className={`font-mono text-[11px] font-bold break-all block mt-1 select-all ${

                          isDark ? 'text-white' : 'text-black'

                        }`}

                        title={selectedAlert.ticket_id}

                      >

                        {selectedAlert.ticket_id || '-'}

                      </span>

                    )}

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

                    className="flex items-center gap-1 text-[11px] font-mono text-blue-500 hover:text-blue-400 cursor-pointer"

                  >

                    {copiedId === 'copy_full_payload' ? (

                      <>

                        <Check className="w-3.5 h-3.5 text-emerald-500" />

                        <span className="text-emerald-500 font-bold">Tersalin!</span>

                      </>

                    ) : (

                      <>

                        <Copy className="w-3.5 h-3.5" />

                        <span>Salin Payload</span>

                      </>

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

    </div>

  );

}