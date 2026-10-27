import React, { useState, useEffect, useMemo, useCallback } from 'react';

import { 

  Search, X, ChevronsUpDown, ChevronUp, ChevronDown, 

  Plus, Play, RefreshCw, Check, Shield, AlertTriangle,

  Server, UserX, Database, Layers, ArrowUpDown, Filter,

  Terminal, ExternalLink, Copy, Sparkles, ArrowRight, ShieldCheck, Zap,

  FolderPlus, Folder, CheckCircle2, Target, Calendar

} from 'lucide-react';



export default function ThreatCampaignEntityTable({

  type = 'actor', // 'actor' | 'victim'

  title = type === 'actor' ? 'Actor' : 'Victim',

  theme = 'dark',

  selectedTenant = 'ALL',

  timeRange = 'semua',

  customStartDate = null,

  customEndDate = null,

  currentUser = null,

  isReadOnly = false,

  onNavigate = null

}) {

  const isDark = theme === 'dark';



  // Search State

  const [searchInput, setSearchInput] = useState('');

  const [searchQuery, setSearchQuery] = useState('');



  // Data Source is always 'raw'

  const dataSource = 'raw';



  // Sorting State (default: timestamp desc)

  const [sortField, setSortField] = useState('timestamp');

  const [sortOrder, setSortOrder] = useState('desc');



  // Pagination State

  const [currentPage, setCurrentPage] = useState(1);

  const pageSize = 15;



  // Data from Backend API

  const [items, setItems] = useState([]);

  const [totalItems, setTotalItems] = useState(0);

  const [isLoading, setIsLoading] = useState(false);

  const [apiError, setApiError] = useState(null);



  // Selected Alert for Right Side Detail Panel

  const [selectedAlert, setSelectedAlert] = useState(null);

  const [copiedId, setCopiedId] = useState(null);



  // Tools: Add Modal & Run State

  const [isAddModalOpen, setIsAddModalOpen] = useState(false);

  const [isRunning, setIsRunning] = useState(false);

  const [runFeedback, setRunFeedback] = useState('');



  // AI Clustering Pattern States (Bottom Box from User Wireframe)

  const [attackPatterns, setAttackPatterns] = useState([]);

  const [ambientDots, setAmbientDots] = useState([]);

  const [selectedPatternIdx, setSelectedPatternIdx] = useState(0);

  const [activeClusterPattern, setActiveClusterPattern] = useState(null);

  const [showClusterBox, setShowClusterBox] = useState(false);

  const [hoveredNode, setHoveredNode] = useState(null);



  // Custom Threat Campaign states

  const [customFolder, setCustomFolder] = useState('');

  const [customFile, setCustomFile] = useState('');

  const [customDesc, setCustomDesc] = useState('');

  const [existingFolders, setExistingFolders] = useState([]);

  const [isSavingCustom, setIsSavingCustom] = useState(false);

  const [customSuccessToast, setCustomSuccessToast] = useState(null);



  const [addForm, setAddForm] = useState({

    timestamp: '',

    wazuh_id: '',

    mitre: '',

    category: '',

    target_or_actor: ''

  });



  // Debounced search trigger (350ms delay)

  useEffect(() => {

    const timer = setTimeout(() => {

      setSearchQuery(searchInput.trim());

      setCurrentPage(1);

    }, 350);

    return () => clearTimeout(timer);

  }, [searchInput]);



  // Fetch raw entities from backend API

  const fetchData = useCallback(async () => {

    setIsLoading(true);

    setApiError(null);

    try {

      const params = new URLSearchParams({

        entity_type: type,

        data_source: dataSource,

        sort_field: sortField,

        sort_order: sortOrder,

        page: String(currentPage),

        limit: String(pageSize),

        time_range: timeRange || 'semua'

      });



      if (selectedTenant && selectedTenant.toLowerCase() !== 'all') {

        params.append('tenant_id', selectedTenant);

      }

      if (searchQuery) {

        params.append('q', searchQuery);

      }

      if (customStartDate && customEndDate) {

        params.append('custom_start', customStartDate);

        params.append('custom_end', customEndDate);

      }



      const res = await fetch(`/api/threat-campaign/entities?${params.toString()}`);

      if (!res.ok) {

        throw new Error(`HTTP error ${res.status}: ${res.statusText}`);

      }



      const result = await res.json();

      if (result.status === 'success') {

        setItems(result.data || []);

        setTotalItems(result.total || 0);

      } else {

        throw new Error(result.detail || 'Gagal mengambil data kampanye ancaman.');

      }

    } catch (err) {

      console.error('Fetch threat campaign entities error:', err);

      setApiError(err.message || 'Gagal memuat data dari server.');

    } finally {

      setIsLoading(false);

    }

  }, [type, dataSource, sortField, sortOrder, currentPage, pageSize, timeRange, selectedTenant, searchQuery, customStartDate, customEndDate]);



  // Trigger fetch when dependencies change

  useEffect(() => {

    fetchData();

  }, [fetchData]);



  // Handle Sort

  const handleSort = (field) => {

    if (sortField === field) {

      setSortOrder(prev => (prev === 'asc' ? 'desc' : 'asc'));

    } else {

      setSortField(field);

      setSortOrder('desc');

    }

    setCurrentPage(1);

  };



  const renderSortIcon = (field) => {

    if (sortField !== field) {

      return <ChevronsUpDown className="w-3.5 h-3.5 text-slate-400 opacity-50 group-hover:opacity-100" />;

    }

    return sortOrder === 'asc' 

      ? <ChevronUp className="w-3.5 h-3.5 text-blue-500 font-bold" />

      : <ChevronDown className="w-3.5 h-3.5 text-blue-500 font-bold" />;

  };



  // Copy helper

  const handleCopyLog = (text, id) => {

    if (!text) return;

    navigator.clipboard.writeText(text);

    setCopiedId(id);

    setTimeout(() => setCopiedId(null), 2500);

  };



  // Select alert and open detail panel (with async lineage backfill if needed)

  const handleSelectAlert = async (item) => {

    const alertId = item.wazuh_id || item.id;

    if (selectedAlert && (selectedAlert.id === alertId || selectedAlert.wazuh_id === alertId)) {

      setSelectedAlert(null);

      return;

    }



    const initialAlert = {

      id: alertId,

      wazuh_id: alertId,

      timestamp: item.timestamp_formatted || (item.timestamp ? new Date(item.timestamp).toLocaleString('id-ID') : '-'),

      tenant_id: item.tenant_id || 'DEFAULT',

      rule_id: item.rule_id || '-',

      rule_level: item.rule_level ?? 5,

      actor: item.actor || '-',

      target: item.target || '-',

      rule_description: item.rule_description || 'Wazuh raw security event',

      aggregation_id: item.aggregation_id || '',

      cumulative_id: item.cumulative_id || '',

      ticket_id: item.ticket_id || '',

      full_log: item.full_log || ''

    };

    setSelectedAlert(initialAlert);



    // If lineage is empty, fetch asynchronously from backend lineage endpoint

    if (alertId && (!initialAlert.aggregation_id || !initialAlert.ticket_id)) {

      try {

        const res = await fetch(`/api/raw-alerts/${encodeURIComponent(alertId)}/lineage`);

        if (res.ok) {

          const lin = await res.json();

          setSelectedAlert(prev => {

            if (!prev || (prev.id !== alertId && prev.wazuh_id !== alertId)) return prev;

            return {

              ...prev,

              aggregation_id: lin.aggregation_id || prev.aggregation_id,

              cumulative_id: lin.cumulative_id || prev.cumulative_id,

              ticket_id: lin.ticket_id || prev.ticket_id

            };

          });

        }

      } catch (err) {

        console.warn('Could not fetch lineage:', err);

      }

    }

  };



  // Run AI Clustering & Multi-Stage Pattern Reconstruction

  const handleRun = async () => {

    setIsRunning(true);

    setRunFeedback('');

    try {

      const params = new URLSearchParams({

        entity_type: type,

        time_range: timeRange || 'semua',

        limit_events: '1200'

      });

      if (selectedTenant && selectedTenant.toLowerCase() !== 'all') {

        params.append('tenant_id', selectedTenant);

      }

      if (searchQuery) {

        params.append('q', searchQuery);

      }

      if (customStartDate && customEndDate) {

        params.append('custom_start', customStartDate);

        params.append('custom_end', customEndDate);

      }



      // Concurrently run clustering reconstruction and refresh raw table

      const [reconRes, _] = await Promise.all([

        fetch(`/api/threat-campaign/reconstruct-attack-paths?${params.toString()}`),

        fetchData()

      ]);



      if (!reconRes.ok) {

        throw new Error(`HTTP ${reconRes.status}: Gagal merekonstruksi alur clustering`);

      }



      const reconData = await reconRes.json();

      const patterns = reconData.top_patterns || reconData.data || [];

      const dots = reconData.ambient_dots || [];



      setAttackPatterns(patterns);

      setAmbientDots(dots);

      setShowClusterBox(true);



      if (patterns.length > 0) {

        // Automatically activate Pattern #1 so table filters to its alerts

        const topPattern = patterns[0];

        setSelectedPatternIdx(0);

        setActiveClusterPattern(topPattern);

        setCurrentPage(1);

        setRunFeedback(`Clustering AI selesai: Menampilkan alur pola teratas (${topPattern.score_display || '99/100'}). Tabel otomatis terfilter.`);

      } else {

        setActiveClusterPattern(null);

        setRunFeedback(`Analisis selesai: Tidak terdeteksi pola clustering pada rentang waktu ini.`);

      }

    } catch (err) {

      console.error('Clustering reconstruction error:', err);

      setRunFeedback(`Gagal menjalankan clustering: ${err.message}`);

    } finally {

      setIsRunning(false);

      setTimeout(() => setRunFeedback(''), 6000);

    }

  };



  // Handle selecting a clustering pattern from the Top 3 list

  const handleSelectClusterPattern = (pattern, idx) => {

    setSelectedPatternIdx(idx);

    setActiveClusterPattern(pattern);

    setCurrentPage(1);

  };



  // Reset filter back to all raw alerts

  const handleResetClusterFilter = () => {

    setActiveClusterPattern(null);

    setCurrentPage(1);

  };



  // Add Custom Campaign Dossier Handlers

  const handleOpenAddModal = async () => {

    const activeTarget = searchQuery || (items[0]?.target || 'isif-rproxy-155');

    setCustomFolder('');

    setCustomFile(`Campaign_${activeTarget.replace(/[^a-zA-Z0-9_-]/g, '_')}_${new Date().toISOString().slice(0, 10)}`);

    setCustomDesc('');

    setIsAddModalOpen(true);



    try {

      const res = await fetch('/api/threat-campaign/custom-campaigns');

      if (res.ok) {

        const json = await res.json();

        setExistingFolders(json.folders || []);

        if (json.folders && json.folders.length > 0) {

          setCustomFolder(json.folders[0]);

        }

      }

    } catch (e) {

      console.error('Error fetching existing folders:', e);

    }

  };



  const handleAcceptCustomCampaign = async (e) => {

    e.preventDefault();

    if (!customFolder.trim() || !customFile.trim()) {

      alert('Nama Folder dan Nama File wajib diisi.');

      return;

    }



    setIsSavingCustom(true);

    try {

      const activeTarget = searchQuery || (items[0]?.target || 'Unknown_Victim');

      const payload = {

        folder_name: customFolder.trim(),

        file_name: customFile.trim(),

        victim_target: activeTarget,

        time_range: timeRange || 'semua',

        custom_start: customStartDate,

        custom_end: customEndDate,

        tenant_id: selectedTenant || 'ALL',

        total_alerts: totalItems || items.length,

        description: customDesc.trim()

      };



      const res = await fetch('/api/threat-campaign/custom-campaigns', {

        method: 'POST',

        headers: { 'Content-Type': 'application/json' },

        body: JSON.stringify(payload)

      });



      if (!res.ok) {

        const errJson = await res.json().catch(() => ({}));

        throw new Error(errJson.detail || `HTTP ${res.status}`);

      }



      setIsAddModalOpen(false);

      setCustomSuccessToast({

        folder: customFolder.trim(),

        file: customFile.trim(),

        alerts: totalItems || items.length

      });

      setTimeout(() => setCustomSuccessToast(null), 6000);

    } catch (err) {

      alert(`Gagal menyimpan campaign: ${err.message}`);

    } finally {

      setIsSavingCustom(false);

    }

  };



  // Compute items to display in the main table:

  // If activeClusterPattern is chosen, display its cluster_alerts; otherwise display normal fetched items

  const isFilteredByCluster = Boolean(activeClusterPattern);



  const displayItems = useMemo(() => {

    if (!isFilteredByCluster) {

      return items;

    }

    const clusterList = activeClusterPattern.cluster_alerts || [];

    let filtered = [...clusterList];



    // In-memory sort for cluster alerts (safe, strictly symmetric arithmetic comparison)

    filtered.sort((a, b) => {

      if (sortField === 'timestamp') {

        const parseTs = (item) => {

          if (item.timestamp) {

            const t = new Date(item.timestamp).getTime();

            if (!isNaN(t) && t > 0) return t;

          }

          if (item.timestamp_formatted) {

            const cleaned = item.timestamp_formatted.replace(' WIB', ' +0700');

            const t = Date.parse(cleaned);

            if (!isNaN(t) && t > 0) return t;

          }

          return 0;

        };

        const timeA = parseTs(a);

        const timeB = parseTs(b);

        const safeA = isNaN(timeA) ? 0 : timeA;

        const safeB = isNaN(timeB) ? 0 : timeB;

        return sortOrder === 'asc' ? safeA - safeB : safeB - safeA;

      }

      const valA = String(a[sortField] || '');

      const valB = String(b[sortField] || '');

      return sortOrder === 'asc' ? valA.localeCompare(valB) : valB.localeCompare(valA);

    });



    const start = (currentPage - 1) * pageSize;

    return filtered.slice(start, start + pageSize);

  }, [isFilteredByCluster, activeClusterPattern, items, sortField, sortOrder, currentPage, pageSize]);



  const currentTotalCount = isFilteredByCluster 

    ? (activeClusterPattern.cluster_alerts?.length || 0)

    : totalItems;



  const totalPages = Math.max(1, Math.ceil(currentTotalCount / pageSize));



  // Current active pattern for the 2D cluster canvas

  const currentCanvasPattern = activeClusterPattern || attackPatterns[selectedPatternIdx] || attackPatterns[0];



  return (

    <div className="space-y-4">

      {/* Run Feedback Alert */}

      {runFeedback && (

        <div className={`p-3 rounded-xl border text-xs font-semibold flex items-center justify-between gap-2 transition-all ${

          isDark ? 'bg-emerald-950/60 border-emerald-700/60 text-emerald-300' : 'bg-emerald-50 border-emerald-300 text-emerald-800'

        }`}>

          <div className="flex items-center gap-2">

            <Check className="w-4 h-4 text-emerald-400 shrink-0" />

            <span>{runFeedback}</span>

          </div>

          <button 

            type="button" 

            onClick={() => setRunFeedback('')}

            className="text-emerald-400 hover:text-emerald-200 cursor-pointer"

          >

            <X className="w-3.5 h-3.5" />

          </button>

        </div>

      )}



      {/* Main Flex Layout: Table on Left, Detail Drawer on Right */}

      <div className="flex gap-4 items-start">

        {/* Main Table Card (Top of the wireframe) */}

        <div className={`border rounded-2xl shadow-xl overflow-hidden transition-all duration-200 ${

          selectedAlert ? 'flex-1 min-w-0' : 'w-full'

        } ${

          isDark ? 'bg-[#0b0f19] border-slate-800 text-slate-100' : 'bg-white border-slate-200 text-slate-800'

        }`}>

          

          {/* Header Bar: Satu Baris Sempurna (Title, Search, Add, Run) */}

          <div className={`px-4 py-3 border-b flex flex-row items-center justify-between gap-3 w-full ${

            isDark ? 'border-slate-800' : 'border-slate-200'

          }`}>

            {/* 1. Left: Title */}

            <div className="flex items-center gap-2 shrink-0">

              <h2 className="text-base font-bold tracking-tight">

                {title}

              </h2>

            </div>



            {/* 2. Middle: Search Bar */}

            <div className="flex-1 max-w-xl mx-2">

              <div className="w-full relative flex items-center bg-white dark:bg-[#090d16] border-2 border-[#3B5BFF] rounded-full h-[38px] pl-3.5 pr-1.5 shadow-2xs group focus-within:ring-2 focus-within:ring-[#3B5BFF]/30 transition-all">

                <Search className="w-4 h-4 text-slate-400 shrink-0 mr-2.5 stroke-[2]" />

                <input

                  type="text"

                  value={searchInput}

                  onChange={(e) => setSearchInput(e.target.value)}

                  placeholder={type === 'actor' ? 'Search actor...' : 'Search victim...'}

                  className="w-full bg-transparent text-slate-800 dark:text-slate-200 placeholder:text-slate-400 text-xs sm:text-[13px] font-normal focus:outline-none"

                />

                {searchInput && (

                  <button

                    type="button"

                    onClick={() => setSearchInput('')}

                    className="text-slate-400 hover:text-slate-600 dark:hover:text-slate-200 cursor-pointer p-1 mr-1"

                    title="Clear search"

                  >

                    <X className="w-3.5 h-3.5" />

                  </button>

                )}

                <button

                  type="button"

                  onClick={fetchData}

                  className="w-7 h-7 rounded-full bg-[#3B5BFF] hover:bg-[#2D4BEB] flex items-center justify-center shrink-0 cursor-pointer transition-transform hover:scale-105 shadow-xs"

                  title="Search"

                >

                  <Search className="w-3.5 h-3.5 text-white" strokeWidth={2.5} />

                </button>

              </div>

            </div>



            {/* 3. Right: Add */}

            <div className="flex items-center gap-2 shrink-0">

              {/* + Add Button */}

              {!isReadOnly && (

                <button

                  type="button"

                  onClick={handleOpenAddModal}

                  className={`flex items-center gap-1 px-3 py-1.5 rounded-lg border text-xs font-semibold cursor-pointer transition-colors shadow-2xs ${

                    isDark ? 'border-slate-700 bg-slate-900 hover:bg-slate-800 text-slate-200' : 'border-slate-300 bg-white hover:bg-slate-50 text-slate-700'

                  }`}

                >

                  <Plus className="w-3.5 h-3.5 text-blue-500" />

                  <span>Add</span>

                </button>

              )}





            </div>

          </div>



          {/* Custom Campaign Saved Toast */}

          {customSuccessToast && (

            <div className="p-3.5 bg-emerald-500/10 border-b border-emerald-500/20 text-emerald-400 text-xs flex items-center justify-between animate-in fade-in">

              <div className="flex items-center gap-2">

                <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0" />

                <span>

                  Berhasil disimpan! Dossier <strong>{customSuccessToast.file}</strong> ({(customSuccessToast.alerts || 0).toLocaleString()} alerts) tersimpan di folder <strong>{customSuccessToast.folder}</strong>. Tersedia di menu <strong>Threat Campaign &gt; Custom</strong>.

                </span>

              </div>

              <button

                type="button"

                onClick={() => setCustomSuccessToast(null)}

                className="text-emerald-400 hover:text-white cursor-pointer ml-2"

              >

                <X className="w-4 h-4" />

              </button>

            </div>

          )}



          {/* Error Notification */}

          {apiError && (

            <div className={`p-3 text-xs flex items-center gap-2 ${

              isDark ? 'bg-rose-950/60 text-rose-300 border-b border-rose-900/50' : 'bg-rose-50 text-rose-800 border-b border-rose-200'

            }`}>

              <AlertTriangle className="w-4 h-4 text-rose-400 shrink-0" />

              <span>{apiError}</span>

            </div>

          )}



          {/* Table Content */}

          <div className="overflow-x-auto min-h-[320px]">

            <table className="w-full text-left text-xs border-collapse">

              <thead>

                <tr className={`border-b select-none ${

                  isDark ? 'bg-[#0e1424] border-slate-800 text-slate-300' : 'bg-slate-50 border-slate-200 text-slate-700'

                }`}>

                  {/* 1. Timestamp */}

                  <th 

                    onClick={() => handleSort('timestamp')}

                    className="py-3 px-4 font-semibold w-[22%] cursor-pointer group"

                  >

                    <div className="flex items-center gap-1.5">

                      <span>Timestamp</span>

                      {renderSortIcon('timestamp')}

                    </div>

                  </th>



                  {/* 2. ID */}

                  <th 

                    onClick={() => handleSort('wazuh_id')}

                    className="py-3 px-4 font-semibold w-[20%] cursor-pointer group"

                  >

                    <div className="flex items-center gap-1.5">

                      <span>ID</span>

                      {renderSortIcon('wazuh_id')}

                    </div>

                  </th>



                  {/* 3. MITRE */}

                  <th 

                    onClick={() => handleSort('mitre')}

                    className="py-3 px-4 font-semibold w-[16%] cursor-pointer group"

                  >

                    <div className="flex items-center gap-1.5">

                      <span>MITRE</span>

                      {renderSortIcon('mitre')}

                    </div>

                  </th>



                  {/* 4. Category */}

                  <th 

                    onClick={() => handleSort('category')}

                    className="py-3 px-4 font-semibold w-[20%] cursor-pointer group"

                  >

                    <div className="flex items-center gap-1.5">

                      <span>Category</span>

                      {renderSortIcon('category')}

                    </div>

                  </th>



                  {/* 5. Target or Actor */}

                  <th 

                    onClick={() => handleSort(type === 'actor' ? 'target' : 'actor')}

                    className="py-3 px-4 font-semibold w-[22%] cursor-pointer group"

                  >

                    <div className="flex items-center gap-1.5">

                      <span>{type === 'actor' ? 'Target' : 'Actor'}</span>

                      {renderSortIcon(type === 'actor' ? 'target' : 'actor')}

                    </div>

                  </th>

                </tr>

              </thead>



              <tbody className={`divide-y ${isDark ? 'divide-slate-800/80' : 'divide-slate-200'}`}>

                {isLoading ? (

                  <tr>

                    <td colSpan={5} className="py-16 text-center">

                      <div className="flex flex-col items-center justify-center gap-2 text-slate-400">

                        <RefreshCw className="w-6 h-6 animate-spin text-blue-500" />

                        <span className="text-xs">Memuat data aktivitas {title}...</span>

                      </div>

                    </td>

                  </tr>

                ) : displayItems.length === 0 ? (

                  <tr>

                    <td colSpan={5} className="py-20 text-center">

                      <div className="flex flex-col items-center justify-center gap-2 text-slate-400">

                        <Search className="w-8 h-8 stroke-1 text-slate-500 opacity-60 mb-1" />

                        <span className="font-mono text-xs text-slate-400">

                          {isFilteredByCluster 

                            ? 'Tidak ada alert dalam klaster ini.'

                            : searchQuery 

                            ? `Tidak ada data ${type} yang cocok dengan "${searchQuery}".` 

                            : `Tidak ada data ${type} dalam antrian ini.`}

                        </span>

                        {isFilteredByCluster && (

                          <button

                            type="button"

                            onClick={handleResetClusterFilter}

                            className="text-xs text-blue-400 hover:underline mt-1 cursor-pointer"

                          >

                            Tampilkan seluruh aktivitas

                          </button>

                        )}

                      </div>

                    </td>

                  </tr>

                ) : (

                  displayItems.map((item, idx) => {

                    const targetOrActorVal = type === 'actor' ? item.target : item.actor;

                    const itemAlertId = item.wazuh_id || item.id;

                    const isSelected = selectedAlert && (selectedAlert.id === itemAlertId || selectedAlert.wazuh_id === itemAlertId);



                    return (

                      <tr 

                        key={item.id || `${item.wazuh_id}_${idx}`} 

                        className={`transition-colors align-middle ${

                          isSelected

                            ? (isDark ? 'bg-blue-600/15 border-l-4 border-l-blue-500' : 'bg-blue-50/80 border-l-4 border-l-blue-600')

                            : (isDark ? 'hover:bg-slate-850/60' : 'hover:bg-slate-50')

                        }`}

                      >

                        {/* 1. Timestamp */}

                        <td className="py-2.5 px-4 font-mono text-[11px] text-slate-400 whitespace-nowrap">

                          {item.timestamp_formatted || (item.timestamp ? new Date(item.timestamp).toLocaleString('id-ID') : '-')}

                        </td>



                        {/* 2. ID Wazuh (Clickable) */}

                        <td className="py-2.5 px-4 font-mono whitespace-nowrap overflow-hidden">

                          <span 

                            className="font-bold text-[11px] tracking-tight text-blue-600 dark:text-blue-400 hover:text-blue-700 dark:hover:text-blue-300 hover:underline cursor-pointer select-all truncate block"

                            title={`Buka detail alert (${item.wazuh_id || item.id || '-'})`}

                            onClick={() => handleSelectAlert(item)}

                          >

                            {item.wazuh_id || item.id || '-'}

                          </span>

                        </td>



                        {/* 3. MITRE (Teks polos) */}

                        <td className="py-2.5 px-4 whitespace-nowrap font-mono text-xs font-medium text-slate-900 dark:text-slate-100">

                          {item.mitre || 'T1082'}

                        </td>



                        {/* 4. 3-Layer Taxonomy & Stateful Lifecycle Attributes */}

                        <td className="py-2 px-4 whitespace-nowrap text-xs text-slate-900 dark:text-slate-100">

                          <div className="flex flex-col gap-1">

                            <div className="flex items-center gap-1.5 flex-wrap">

                              {/* Layer 1: Domain Badge */}

                              <span className={`text-[10px] font-bold px-1.5 py-0.5 rounded border uppercase tracking-wider ${

                                (item.domain || item.primary_category) === 'ATTACK'

                                  ? 'bg-rose-500/20 text-rose-400 border-rose-500/30'

                                  : (item.domain || item.primary_category) === 'VULNERABILITY'

                                  ? 'bg-amber-500/20 text-amber-400 border-amber-500/30'

                                  : 'bg-sky-500/20 text-sky-400 border-sky-500/30'

                              }`}>

                                {item.domain || item.primary_category || 'SYSTEM'}

                              </span>



                              {/* Layer 2: Target Category */}

                              {item.target_category && (

                                <span className="text-[10px] px-1.5 py-0.5 rounded bg-slate-200 dark:bg-slate-800 text-slate-700 dark:text-slate-300 font-mono font-medium" title="Target Domain">

                                  {item.target_category.replace(/_/g, ' ')}

                                </span>

                              )}



                              {/* Layer 3: Action / TTP */}

                              {(item.action_ttp || item.subcategory) && (

                                <span className="text-[10px] px-1.5 py-0.5 rounded bg-slate-100 dark:bg-slate-900 text-slate-600 dark:text-slate-400 font-mono" title="Aksi / TTP Spesifik">

                                  {item.action_ttp || item.subcategory}

                                </span>

                              )}

                            </div>



                            <div className="flex items-center gap-1.5 flex-wrap">

                              {/* Lifecycle Role Pill */}

                              {item.lifecycle_role === 'OPEN_STATE' ? (

                                <span className="text-[9px] font-semibold px-1 py-0.2 rounded bg-purple-500/20 text-purple-300 border border-purple-500/30" title="Stateful Open Event">

                                  ⚡ OPEN

                                </span>

                              ) : item.lifecycle_role === 'CLOSE_STATE' ? (

                                <span className="text-[9px] font-semibold px-1 py-0.2 rounded bg-emerald-500/20 text-emerald-300 border border-emerald-500/30" title="Stateful Close Event">

                                  ✓ CLOSE

                                </span>

                              ) : null}



                              {/* Disposition Pill */}

                              {item.disposition === 'ACTIONABLE' ? (

                                <span className="inline-flex items-center gap-1 text-[9px] font-bold px-1.5 py-0.5 rounded bg-rose-500/20 text-rose-400 border border-rose-500/40 animate-pulse">

                                  ● ACTIONABLE

                                </span>

                              ) : item.disposition === 'PENDING_PAIR' ? (

                                <span className="inline-flex items-center gap-1 text-[9px] font-bold px-1.5 py-0.5 rounded bg-indigo-500/20 text-indigo-300 border border-indigo-500/30">

                                  ⏳ PENDING_PAIR

                                </span>

                              ) : item.disposition === 'REVIEW' ? (

                                <span className="inline-flex items-center gap-1 text-[9px] font-bold px-1.5 py-0.5 rounded bg-amber-500/20 text-amber-400 border border-amber-500/30">

                                  ● REVIEW

                                </span>

                              ) : (

                                <span className="inline-flex items-center gap-1 text-[9px] font-semibold px-1.5 py-0.5 rounded bg-emerald-500/15 text-emerald-400 border border-emerald-500/30">

                                  ● SAFE

                                </span>

                              )}



                              {/* Confidence Score */}

                              {item.confidence_score !== undefined && item.confidence_score !== null && (

                                <span className="text-[9px] text-slate-400 font-mono font-normal">

                                  {item.confidence_score}%

                                </span>

                              )}

                            </div>

                          </div>

                        </td>



                        {/* 5. Target or Actor (With Subnet & Outlier Badge) */}

                        <td className="py-2.5 px-4 whitespace-nowrap font-mono text-xs font-semibold text-slate-900 dark:text-slate-100">

                          <div className="flex items-center gap-1.5 flex-wrap">

                            <span>{targetOrActorVal || '-'}</span>

                            {type === 'victim' && item.who_subnet && item.who_subnet !== item.actor && (

                              <span className="text-[10px] px-1.5 py-0.2 rounded bg-slate-800 text-cyan-400 font-mono font-normal" title="Normalisasi Subnet /24">

                                {item.who_subnet}

                              </span>

                            )}

                            {item.is_outlier && (

                              <span className="text-[9px] px-1.5 py-0.2 rounded font-bold bg-rose-500/20 text-rose-400 border border-rose-500/30" title="DBSCAN Behavioral Anomaly Outlier (-1)">

                                Outlier (-1)

                              </span>

                            )}

                          </div>

                        </td>

                      </tr>

                    );

                  })

                )}

              </tbody>

            </table>

          </div>



          {/* Table Footer with Pagination */}

          <div className={`p-4 border-t flex items-center justify-between text-xs select-none ${

            isDark ? 'border-slate-800 text-slate-400' : 'border-slate-200 text-slate-600'

          }`}>

            <span className="text-[11px] text-slate-500 font-mono">

              Total {currentTotalCount} record{currentTotalCount !== 1 ? 's' : ''} {isFilteredByCluster ? '(terfilter klaster)' : ''}

            </span>



            {/* Pagination Controls */}

            <div className="flex items-center gap-2">

              <button

                type="button"

                disabled={currentPage <= 1 || isLoading}

                onClick={() => setCurrentPage(prev => Math.max(1, prev - 1))}

                className={`px-3 py-1.5 rounded-lg border font-semibold transition-colors cursor-pointer disabled:opacity-40 disabled:cursor-not-allowed ${

                  isDark ? 'border-slate-800 hover:bg-slate-850 text-slate-300' : 'border-slate-300 hover:bg-slate-100 text-slate-700'

                }`}

              >

                Previous

              </button>



              <span className="px-2 text-xs font-mono font-semibold text-slate-400">

                {currentPage} / {totalPages}

              </span>



              <button

                type="button"

                disabled={currentPage >= totalPages || isLoading}

                onClick={() => setCurrentPage(prev => Math.min(totalPages, prev + 1))}

                className={`px-3 py-1.5 rounded-lg border font-semibold transition-colors cursor-pointer disabled:opacity-40 disabled:cursor-not-allowed ${

                  isDark ? 'border-slate-800 hover:bg-slate-850 text-slate-300' : 'border-slate-300 hover:bg-slate-100 text-slate-700'

                }`}

              >

                Next

              </button>

            </div>

          </div>

        </div>



        {/* Right: Side Detail Panel */}

        {selectedAlert && (

          <div className={`w-[360px] md:w-[400px] xl:w-[440px] shrink-0 sticky top-2 self-start border rounded-xl p-5 shadow-lg space-y-4 max-h-[calc(100vh-100px)] overflow-y-auto animate-in fade-in slide-in-from-right-4 duration-200 ${

            isDark ? 'bg-[#0f172a] border-slate-700 text-white shadow-xl' : 'bg-white border-slate-200 text-black shadow-md'

          }`}>

            {/* Header */}

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

              {/* Primary Details Box */}

              <div className={`p-3.5 rounded-xl border space-y-2.5 text-[11px] ${

                isDark ? 'bg-slate-950/70 border-slate-800' : 'bg-slate-50 border-slate-200'

              }`}>

                <div>

                  <span className={`block text-[10px] uppercase font-semibold tracking-wider ${isDark ? 'text-slate-400' : 'text-slate-500'}`}>ID Alert:</span>

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

                        <Check className="w-3.5 h-3.5 text-emerald-400" />

                      ) : (

                        <Copy className="w-3.5 h-3.5 text-slate-400" />

                      )}

                    </button>

                  </div>

                </div>



                <div className="grid grid-cols-2 gap-2 pt-1 border-t border-slate-800/60">

                  <div>

                    <span className={`block text-[10px] uppercase font-semibold tracking-wider ${isDark ? 'text-slate-400' : 'text-slate-500'}`}>Timestamp:</span>

                    <span className={`font-mono text-[11px] ${isDark ? 'text-slate-200' : 'text-slate-700'}`}>{selectedAlert.timestamp}</span>

                  </div>

                  <div>

                    <span className={`block text-[10px] uppercase font-semibold tracking-wider ${isDark ? 'text-slate-400' : 'text-slate-500'}`}>Tenant:</span>

                    <span className={`font-mono text-[11px] font-semibold ${isDark ? 'text-slate-200' : 'text-slate-700'}`}>{selectedAlert.tenant_id}</span>

                  </div>

                </div>



                <div className="grid grid-cols-2 gap-2 pt-1 border-t border-slate-800/60">

                  <div>

                    <span className={`block text-[10px] uppercase font-semibold tracking-wider ${isDark ? 'text-slate-400' : 'text-slate-500'}`}>Rule ID / Level:</span>

                    <span className={`font-mono text-[11px] ${isDark ? 'text-slate-200' : 'text-slate-700'}`}>{selectedAlert.rule_id} (Lvl {selectedAlert.rule_level})</span>

                  </div>

                  <div>

                    <span className={`block text-[10px] uppercase font-semibold tracking-wider ${isDark ? 'text-slate-400' : 'text-slate-500'}`}>Actor:</span>

                    <span className={`font-mono text-[11px] truncate block ${isDark ? 'text-slate-200' : 'text-slate-700'}`} title={selectedAlert.actor}>{selectedAlert.actor}</span>

                  </div>

                </div>



                <div className="pt-1 border-t border-slate-800/60">

                  <span className={`block text-[10px] uppercase font-semibold tracking-wider ${isDark ? 'text-slate-400' : 'text-slate-500'}`}>Target Asset:</span>

                  <span className={`font-mono text-[11px] font-bold ${isDark ? 'text-blue-400' : 'text-blue-600'}`}>{selectedAlert.target}</span>

                </div>



                <div className="pt-1 border-t border-slate-800/60">

                  <span className={`block text-[10px] uppercase font-semibold tracking-wider ${isDark ? 'text-slate-400' : 'text-slate-500'}`}>Description:</span>

                  <span className={`text-[11px] leading-relaxed block ${isDark ? 'text-slate-300' : 'text-slate-700'}`}>{selectedAlert.rule_description}</span>

                </div>



                <div className="grid grid-cols-2 gap-2 pt-1 border-t border-slate-800/60">

                  <div>

                    <span className={`block text-[10px] uppercase font-semibold tracking-wider ${isDark ? 'text-slate-400' : 'text-slate-500'}`}>3-Layer Taxonomy:</span>

                    <span className={`font-mono text-[11px] font-bold ${isDark ? 'text-white' : 'text-black'}`}>

                      {selectedAlert.domain || selectedAlert.primary_category || 'SYSTEM'} ➔ {selectedAlert.target_category || 'Host_Telemetry'}

                    </span>

                    <span className="block font-mono text-[10px] text-slate-400">

                      TTP: {selectedAlert.action_ttp || selectedAlert.subcategory || 'General'} {selectedAlert.lifecycle_role ? `(${selectedAlert.lifecycle_role})` : ''}

                    </span>

                  </div>

                  <div>

                    <span className={`block text-[10px] uppercase font-semibold tracking-wider ${isDark ? 'text-slate-400' : 'text-slate-500'}`}>Disposition & Conf:</span>

                    <span className={`inline-flex items-center gap-1 font-mono text-[11px] font-bold ${

                      selectedAlert.disposition === 'ACTIONABLE' ? 'text-rose-400' : selectedAlert.disposition === 'PENDING_PAIR' ? 'text-indigo-400' : selectedAlert.disposition === 'REVIEW' ? 'text-amber-400' : 'text-emerald-400'

                    }`}>

                      {selectedAlert.disposition || 'SAFE'} ({selectedAlert.confidence_score || 50}%)

                    </span>

                  </div>

                </div>

              </div>



              {/* Tahap 1: Cluster Dimensions & Forensics Box (Cluster v1) */}

              <div className={`p-3.5 rounded-xl border space-y-2 text-[11px] ${

                isDark ? 'bg-slate-950/70 border-slate-800' : 'bg-slate-50 border-slate-200'

              }`}>

                <div className="flex items-center justify-between">

                  <h4 className={`font-bold uppercase tracking-wider text-[10px] flex items-center gap-1.5 ${isDark ? 'text-indigo-400' : 'text-indigo-600'}`}>

                    <Layers className="w-3.5 h-3.5" />

                    Tahap 1: Cluster Telemetry (v1)

                  </h4>

                  {selectedAlert.is_high_value && (

                    <span className="px-1.5 py-0.5 rounded text-[9px] font-bold bg-rose-500/20 text-rose-400 border border-rose-500/30 animate-pulse">

                      HIGH-VALUE BYPASS

                    </span>

                  )}

                </div>



                <div className="space-y-1.5 font-mono text-[10px]">

                  <div>

                    <span className="text-slate-400 block text-[9px] uppercase">Composite Cluster Key:</span>

                    <span className={`break-all font-semibold ${isDark ? 'text-slate-200' : 'text-slate-700'}`}>

                      {selectedAlert.composite_cluster_key || selectedAlert.composite_key || 'N/A'}

                    </span>

                  </div>



                  <div className="grid grid-cols-2 gap-2 pt-1 border-t border-slate-800/40">

                    <div>

                      <span className="text-slate-400 block text-[9px] uppercase">Actor Dimension (Who):</span>

                      <span className="text-blue-400 font-bold">{selectedAlert.who_cluster || selectedAlert.who_subnet || selectedAlert.actor}</span>

                    </div>

                    <div>

                      <span className="text-slate-400 block text-[9px] uppercase">Path Family (What):</span>

                      <span className="text-emerald-400 font-bold truncate block" title={selectedAlert.what_cluster || selectedAlert.clean_path}>

                        {selectedAlert.what_cluster || selectedAlert.clean_path || selectedAlert.rule_id}

                      </span>

                    </div>

                  </div>



                  {selectedAlert.bypass_reason && (

                    <div className="pt-1 border-t border-slate-800/40">

                      <span className="text-slate-400 block text-[9px] uppercase">Bypass Reason:</span>

                      <span className="text-amber-400 font-semibold">{selectedAlert.bypass_reason}</span>

                    </div>

                  )}



                  {selectedAlert.success_indicator && selectedAlert.success_indicator !== 'none' && (

                    <div className="flex items-center justify-between pt-1 border-t border-slate-800/40">

                      <span className="text-slate-400">Success Indicator:</span>

                      <span className={`font-bold uppercase ${selectedAlert.success_indicator === 'confirmed' ? 'text-rose-400' : 'text-amber-400'}`}>

                        {selectedAlert.success_indicator}

                      </span>

                    </div>

                  )}



                  {selectedAlert.pkg_activity_nearby && (

                    <div className="pt-1 border-t border-slate-800/40 text-sky-400 text-[10px]">

                      ℹ️ Aktivitas Paket (dpkg/apt) terdeteksi pada host dalam ±5 mnt

                    </div>

                  )}



                  {selectedAlert.wazuh_query_pointer && Object.keys(selectedAlert.wazuh_query_pointer).length > 0 && (

                    <div className="pt-1 border-t border-slate-800/40">

                      <span className="text-slate-400 block text-[9px] uppercase">Wazuh Indexer Query Pointer:</span>

                      <span className="text-[9px] text-slate-500 font-mono block truncate" title={JSON.stringify(selectedAlert.wazuh_query_pointer)}>

                        Index: {selectedAlert.wazuh_query_pointer.index_pattern || 'wazuh-alerts-*'} (30-day forensic pointer)

                      </span>

                    </div>

                  )}

                </div>

              </div>



              {/* Silsilah Tiket / Agregat Box */}

              <div className={`p-3.5 rounded-xl border space-y-2 text-[11px] ${

                isDark ? 'bg-slate-950/70 border-slate-800' : 'bg-slate-50 border-slate-200'

              }`}>

                <h4 className={`font-bold uppercase tracking-wider text-[10px] ${isDark ? 'text-slate-400' : 'text-slate-500'}`}>

                  Silsilah Agregasi & Tiket

                </h4>

                <div className="space-y-1.5 font-mono text-[10px]">

                  <div className="flex justify-between items-center py-0.5 border-b border-slate-800/40">

                    <span className="text-slate-400">Aggregation ID:</span>

                    <span className={`font-bold ${selectedAlert.aggregation_id ? 'text-blue-400' : 'text-slate-500'}`}>

                      {selectedAlert.aggregation_id || 'Tidak terkorelasi'}

                    </span>

                  </div>

                  <div className="flex justify-between items-center py-0.5 border-b border-slate-800/40">

                    <span className="text-slate-400">Ticket ID:</span>

                    <span className={`font-bold ${selectedAlert.ticket_id ? 'text-emerald-400' : 'text-slate-500'}`}>

                      {selectedAlert.ticket_id || 'Belum dibuatkan tiket'}

                    </span>

                  </div>

                </div>

              </div>



              {/* Full Raw Log Box */}

              {selectedAlert.full_log && (

                <div className={`p-3.5 rounded-xl border space-y-1.5 ${

                  isDark ? 'bg-slate-950/70 border-slate-800' : 'bg-slate-50 border-slate-200'

                }`}>

                  <div className="flex items-center justify-between">

                    <span className={`text-[10px] uppercase font-semibold tracking-wider ${isDark ? 'text-slate-400' : 'text-slate-500'}`}>Raw Log Payload:</span>

                    <button

                      type="button"

                      onClick={() => handleCopyLog(selectedAlert.full_log, 'copy_log')}

                      className={`text-[10px] flex items-center gap-1 cursor-pointer transition-colors ${

                        isDark ? 'text-slate-400 hover:text-white' : 'text-slate-500 hover:text-black'

                      }`}

                      title="Salin raw log"

                    >

                      {copiedId === 'copy_log' ? (

                        <>

                          <Check className="w-3 h-3 text-emerald-400" />

                          <span className="text-emerald-400">Tersalin</span>

                        </>

                      ) : (

                        <>

                          <Copy className="w-3 h-3" />

                          <span>Salin</span>

                        </>

                      )}

                    </button>

                  </div>

                  <pre className={`p-2 rounded-lg font-mono text-[10px] overflow-x-auto whitespace-pre-wrap break-all max-h-[160px] ${

                    isDark ? 'bg-[#090d16] text-slate-300' : 'bg-white border text-slate-700'

                  }`}>

                    {selectedAlert.full_log}

                  </pre>

                </div>

              )}

            </div>

          </div>

        )}

      </div>



      {/* ========================================================================= */}

      {/* BOTTOM SECTION (SESUAI WIREFRAME USER):                                   */}

      {/* Kotak yang ada titik-titik (alert) + terbentuk jalur (clustering pattern)  */}

      {/* dan di sebelah kanan: "Top Clustering Pattern : 99/100, 98/100, 97/100"    */}

      {/* ========================================================================= */}

      {showClusterBox && attackPatterns.length > 0 && (

        <div className={`border rounded-2xl shadow-xl overflow-hidden transition-all duration-200 ${

          isDark ? 'bg-[#0b0f19] border-slate-800 text-slate-100' : 'bg-white border-slate-200 text-slate-800'

        }`}>

          {/* Header Bar */}

          <div className={`px-4 py-3 border-b flex items-center justify-between gap-3 ${

            isDark ? 'border-slate-800 bg-[#0e1424]' : 'border-slate-200 bg-slate-50'

          }`}>

            <h3 className="text-sm font-bold tracking-tight text-slate-900 dark:text-slate-100">

              Attack Clustering & Path Reconstruction

            </h3>



            <button

              type="button"

              onClick={() => setShowClusterBox(false)}

              className={`p-1.5 rounded-lg cursor-pointer transition-colors ${

                isDark ? 'hover:bg-slate-800 text-slate-400 hover:text-white' : 'hover:bg-slate-200 text-slate-500 hover:text-black'

              }`}

              title="Tutup Panel Clustering"

            >

              <X className="w-4 h-4" />

            </button>

          </div>



          {/* Main 2-Column Layout (Canvas on Left, Top Clustering Pattern on Right) */}

          <div className="grid grid-cols-1 lg:grid-cols-12 min-h-[380px]">

            {/* LEFT COLUMN: The 2D Canvas with Dots & Connected Pathway (~65% = 8 cols) */}

            <div className={`lg:col-span-8 p-4 relative flex flex-col justify-between select-none ${

              isDark ? 'bg-[#070b14]' : 'bg-slate-50/50'

            }`}>

              <div className="flex items-center justify-between pb-2 text-xs">

                <div className="flex items-center gap-2">

                  <span className="w-2 h-2 rounded-full bg-blue-500 animate-ping" />

                  <span className="font-semibold text-slate-800 dark:text-slate-200">

                    Cluster Path Map

                  </span>

                </div>

                <div className="flex items-center gap-3 text-[10px] text-slate-400 font-mono">

                  <div className="flex items-center gap-1">

                    <span className="w-2 h-2 rounded-full bg-blue-500" />

                    <span>Active Pattern Node</span>

                  </div>

                  <div className="flex items-center gap-1">

                    <span className="w-1.5 h-1.5 rounded-full bg-slate-500" />

                    <span>Raw Alert Dot</span>

                  </div>

                </div>

              </div>



              {/* The SVG Visualization Box */}

              <div className={`relative w-full h-[320px] rounded-xl border overflow-hidden flex items-center justify-center ${

                isDark ? 'bg-[#090e1a] border-slate-800/80 shadow-inner' : 'bg-white border-slate-200 shadow-inner'

              }`}>

                {/* SVG Visual Canvas */}

                <svg 

                  className="w-full h-full"

                  viewBox="0 0 700 360"

                  preserveAspectRatio="none"

                >

                  <defs>

                    {/* Subtle grid pattern */}

                    <pattern id="grid-pattern" width="35" height="35" patternUnits="userSpaceOnUse">

                      <path d="M 35 0 L 0 0 0 35" fill="none" stroke="currentColor" strokeOpacity={isDark ? "0.06" : "0.04"} strokeWidth="1" />

                    </pattern>



                    {/* Glowing filter for cluster lines */}

                    <filter id="glow" x="-20%" y="-20%" width="140%" height="140%">

                      <feGaussianBlur stdDeviation="3" result="blur" />

                      <feComposite in="SourceGraphic" in2="blur" operator="over" />

                    </filter>

                  </defs>



                  {/* Grid background */}

                  <rect width="700" height="360" fill="url(#grid-pattern)" />



                  {/* 1. Ambient Background Dots (Raw Alert Dots) */}

                  {ambientDots.map((dot, dIdx) => (

                    <circle

                      key={dot.id || dIdx}

                      cx={`${dot.x}%`}

                      cy={`${dot.y}%`}

                      r={isDark ? 2.5 : 3.5}

                      className={`cursor-pointer transition-transform hover:scale-150 ${

                        isDark ? 'fill-slate-600/70 hover:fill-blue-400' : 'fill-slate-400/90 hover:fill-blue-600'

                      }`}

                      onMouseEnter={() => setHoveredNode({

                        id: dot.id,

                        title: dot.stage_name,

                        rule_desc: dot.rule_desc,

                        mitre: dot.mitre,

                        timestamp: dot.timestamp,

                        x: dot.x,

                        y: dot.y

                      })}

                      onMouseLeave={() => setHoveredNode(null)}

                      onClick={() => handleSelectAlert({

                        id: dot.id,

                        wazuh_id: dot.id,

                        timestamp: dot.timestamp,

                        rule_description: dot.rule_desc,

                        mitre: dot.mitre

                      })}

                    />

                  ))}



                  {/* 2. Connected Pathway Lines (Terbentuk Jalur Hasil Clustering AI) */}

                  {currentCanvasPattern?.steps && currentCanvasPattern.steps.map((st, idx) => {

                    if (idx === 0) return null;

                    const prev = currentCanvasPattern.steps[idx - 1];

                    const x1 = (prev.x / 100) * 700;

                    const y1 = (prev.y / 100) * 360;

                    const x2 = (st.x / 100) * 700;

                    const y2 = (st.y / 100) * 360;



                    return (

                      <g key={`path_line_${idx}`}>

                        {/* Glow halo line */}

                        <line

                          x1={x1}

                          y1={y1}

                          x2={x2}

                          y2={y2}

                          stroke="#38bdf8"

                          strokeWidth="6"

                          strokeOpacity="0.25"

                          filter="url(#glow)"

                        />

                        {/* Core animated line */}

                        <line

                          x1={x1}

                          y1={y1}

                          x2={x2}

                          y2={y2}

                          stroke="#38bdf8"

                          strokeWidth="2.5"

                          strokeDasharray="6 3"

                          className="animate-pulse"

                        />

                      </g>

                    );

                  })}



                  {/* 3. Active Pattern Nodes (Glowing Constellation Dots) */}

                  {currentCanvasPattern?.steps && currentCanvasPattern.steps.map((st, idx) => {

                    const cx = (st.x / 100) * 700;

                    const cy = (st.y / 100) * 360;



                    return (

                      <g

                        key={`step_point_${idx}`}

                        className="cursor-pointer"

                        onMouseEnter={() => setHoveredNode({

                          id: st.wazuh_id,

                          title: st.stage_name,

                          rule_desc: st.rule_desc,

                          mitre: st.mitre_id,

                          timestamp: st.timestamp,

                          step_num: st.step,

                          x: st.x,

                          y: st.y

                        })}

                        onMouseLeave={() => setHoveredNode(null)}

                        onClick={() => handleSelectAlert({

                          id: st.wazuh_id,

                          wazuh_id: st.wazuh_id,

                          timestamp: st.timestamp,

                          tenant_id: selectedTenant || 'DEFAULT',

                          rule_id: st.rule_id,

                          rule_level: 8,

                          actor: st.actor,

                          target: st.target,

                          rule_description: st.rule_desc,

                          full_log: `[AI Correlated Attack Step #${st.step} - ${st.stage_name}]: ${st.rule_desc}`

                        })}

                      >

                        {/* Outer pulsing ring */}

                        <circle

                          cx={cx}

                          cy={cy}

                          r={12}

                          className="fill-blue-500/20 stroke-blue-400 stroke-1 animate-ping"

                          style={{ animationDuration: '3.5s' }}

                        />

                        {/* Node border ring */}

                        <circle

                          cx={cx}

                          cy={cy}

                          r={7}

                          className="fill-blue-600 stroke-white stroke-2 shadow-lg"

                        />

                        {/* Inner center dot */}

                        <circle

                          cx={cx}

                          cy={cy}

                          r={3}

                          fill="#ffffff"

                        />

                        {/* Step number badge */}

                        <rect

                          x={cx - 16}

                          y={cy - 24}

                          width={32}

                          height={14}

                          rx={4}

                          className="fill-slate-900 stroke-blue-500 stroke-1"

                        />

                        <text

                          x={cx}

                          y={cy - 14}

                          textAnchor="middle"

                          className="text-[9px] font-mono font-bold fill-blue-300 pointer-events-none"

                        >

                          {st.mitre_id}

                        </text>

                      </g>

                    );

                  })}

                </svg>



                {/* Floating Tooltip when hovering over a node */}

                {hoveredNode && (

                  <div 

                    className="absolute pointer-events-none z-30 p-2.5 rounded-xl border shadow-2xl bg-slate-950/95 border-blue-500/50 text-white text-[11px] space-y-1 max-w-[240px] animate-in fade-in duration-150"

                    style={{ 

                      left: `${Math.min(72, Math.max(8, hoveredNode.x))}%`, 

                      top: `${Math.min(68, Math.max(10, hoveredNode.y))}%` 

                    }}

                  >

                    <div className="flex items-center justify-between border-b border-slate-800 pb-1">

                      <span className="font-bold text-blue-400">{hoveredNode.mitre || 'Alert Point'}</span>

                      <span className="font-mono text-[9px] text-slate-400">ID: {hoveredNode.id?.slice(0, 10)}</span>

                    </div>

                    <div className="font-semibold text-slate-200 line-clamp-2">

                      {hoveredNode.rule_desc || hoveredNode.title}

                    </div>

                    <div className="text-[10px] text-slate-400 font-mono">

                      {hoveredNode.timestamp}

                    </div>

                    <div className="text-[9px] text-emerald-400 pt-0.5">

                      Klik untuk melihat detail lengkap di panel kanan

                    </div>

                  </div>

                )}

              </div>



              {/* Canvas bottom hint */}

              <div className="pt-2 text-[10px] text-slate-500 flex items-center justify-between">

                <span>Titik saling terhubung berdasarkan korelasi urutan waktu MITRE Kill-Chain.</span>

                <span className="font-mono">Total {ambientDots.length} titik telemetri</span>

              </div>

            </div>



            {/* RIGHT COLUMN: Incident Storyline & Multi-Session Progression (~35% = 4 cols) */}

            <div className={`lg:col-span-4 p-4 flex flex-col justify-between border-t lg:border-t-0 lg:border-l ${

              isDark ? 'border-slate-800 bg-[#0a0f1d]' : 'border-slate-200 bg-white'

            }`}>

              <div className="space-y-3">

                {/* Header */}

                <div className="pb-2.5 border-b border-slate-800/80 flex items-center justify-between">

                  <div className="flex items-center gap-2">

                    <span className="px-1.5 py-0.5 rounded text-[10px] font-bold font-mono bg-blue-600 text-white shadow-xs">

                      INCIDENT #{selectedPatternIdx + 1}

                    </span>

                    <h3 className="font-bold text-sm tracking-tight text-slate-900 dark:text-slate-100">

                      Attack Storyline & Progression

                    </h3>

                  </div>

                  {isFilteredByCluster ? (

                    <button

                      type="button"

                      onClick={handleResetClusterFilter}

                      className="text-[11px] text-slate-400 hover:text-blue-400 cursor-pointer underline"

                      title="Kembalikan tabel ke seluruh alert"

                    >

                      Reset Filter

                    </button>

                  ) : (

                    <button

                      type="button"

                      onClick={() => handleSelectClusterPattern(attackPatterns[selectedPatternIdx] || attackPatterns[0], selectedPatternIdx)}

                      className="text-[11px] text-blue-500 hover:text-blue-400 font-semibold cursor-pointer underline"

                      title="Terapkan filter klaster ini ke tabel"

                    >

                      Filter Tabel

                    </button>

                  )}

                </div>



                {/* Multi-Session Selector Tabs */}

                {attackPatterns.length > 1 && (

                  <div className="grid grid-cols-3 gap-1.5 p-1 rounded-xl bg-slate-900/60 border border-slate-800">

                    {attackPatterns.map((p, pIdx) => {

                      const isCurrent = selectedPatternIdx === pIdx;

                      return (

                        <button

                          key={p.pattern_id || pIdx}

                          type="button"

                          onClick={() => handleSelectClusterPattern(p, pIdx)}

                          className={`py-1.5 px-2 rounded-lg text-xs font-semibold transition-all cursor-pointer flex flex-col items-center justify-center gap-0.5 ${

                            isCurrent

                              ? 'bg-blue-600 text-white shadow-sm ring-1 ring-blue-400'

                              : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/60'

                          }`}

                        >

                          <div className="flex items-center gap-1.5">

                            <span className="text-[11px] font-bold">Inc #{pIdx + 1}</span>

                            <span className={`text-[10px] font-mono px-1 rounded font-bold ${

                              isCurrent ? 'bg-blue-700 text-white' : 'bg-slate-800 text-slate-300'

                            }`}>

                              {p.score_display || `${p.confidence}/100`}

                            </span>

                          </div>

                          <span className={`text-[9px] truncate max-w-full font-normal ${

                            isCurrent ? 'text-blue-100' : 'text-slate-500'

                          }`}>

                            {p.duration || 'Session'}

                          </span>

                        </button>

                      );

                    })}

                  </div>

                )}



                {/* Selected Incident Details Card */}

                {(() => {

                  const pat = attackPatterns[selectedPatternIdx] || attackPatterns[0];

                  if (!pat) return null;

                  const isSelected = Boolean(activeClusterPattern && activeClusterPattern.pattern_id === pat.pattern_id);



                  return (

                    <div className="space-y-3">

                      {/* Pattern Card Header */}

                      <div 

                        onClick={() => handleSelectClusterPattern(pat, selectedPatternIdx)}

                        className={`p-3.5 rounded-xl border transition-all cursor-pointer ${

                          isSelected

                            ? (isDark ? 'bg-blue-600/15 border-blue-500/70 shadow-md ring-1 ring-blue-500/40' : 'bg-blue-50/80 border-blue-600 shadow-md ring-1 ring-blue-600/30')

                            : (isDark ? 'bg-slate-900/60 border-slate-800 hover:border-slate-700' : 'bg-slate-50 border-slate-200 hover:bg-slate-100')

                        }`}

                      >

                        <div className="flex items-start justify-between gap-2 mb-2">

                          <div>

                            <span className="text-[10px] font-bold font-mono tracking-wider uppercase text-rose-500 bg-rose-500/10 px-1.5 py-0.5 rounded mr-1.5">

                              {pat.severity || 'CRITICAL'}

                            </span>

                            <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-slate-800 text-blue-300 font-semibold mr-1.5">

                              {pat.incident_id || 'INCIDENT'}

                            </span>

                            {pat.is_outlier && (

                              <span className="text-[9px] font-bold px-1.5 py-0.5 rounded bg-rose-500/20 text-rose-400 border border-rose-500/30 mr-1.5" title="DBSCAN Statistical Outlier">

                                Outlier (-1)

                              </span>

                            )}

                            <span className="text-[11px] text-slate-400 font-medium block sm:inline mt-1 sm:mt-0">

                              {pat.stages_count} tahapan • {pat.cluster_alerts?.length || 60} alert

                            </span>

                          </div>

                          <div className="text-right shrink-0">

                            <span className="font-mono text-base font-extrabold tracking-tight text-emerald-500 dark:text-emerald-400">

                              {pat.score_display || `${pat.confidence}/100`}

                            </span>

                            <span className="block text-[8px] uppercase font-semibold text-slate-400 tracking-wider">

                              MATCH SCORE

                            </span>

                          </div>

                        </div>



                        <div className="text-[10px] text-slate-400 font-mono mb-1.5 flex items-center gap-1.5">

                          <span className="text-blue-400">Batasan:</span>

                          <span>{pat.boundary_type} ({pat.duration})</span>

                        </div>



                        <h4 className="text-xs font-bold text-slate-900 dark:text-slate-100 mb-1.5 leading-snug">

                          {pat.title}

                        </h4>



                        <p className="text-[11px] text-slate-400 leading-relaxed">

                          {pat.summary}

                        </p>

                      </div>



                      {/* Stage Progression Steps */}

                      <div className="space-y-1.5 pt-1">

                        <span className="text-[10px] font-bold uppercase tracking-wider text-slate-400 block mb-1">

                          Tahapan Rekonstruksi (Kill-Chain):

                        </span>

                        <div className="space-y-1.5 max-h-[190px] overflow-y-auto pr-0.5">

                          {(pat.steps || []).map((step, sIdx) => (

                            <div 

                              key={step.step || sIdx}

                              className={`p-2 rounded-lg border text-xs flex items-center justify-between gap-2 ${

                                isDark ? 'bg-slate-900/40 border-slate-800/80' : 'bg-slate-50/60 border-slate-200/80'

                              }`}

                            >

                              <div className="flex items-center gap-2 min-w-0">

                                <span className="w-5 h-5 rounded-full bg-blue-500/20 text-blue-400 font-mono text-[10px] font-bold flex items-center justify-center shrink-0">

                                  {step.step}

                                </span>

                                <div className="truncate">

                                  <span className="font-semibold text-slate-200 block truncate text-[11px]">

                                    {step.stage_name}

                                  </span>

                                  <span className="text-[10px] font-mono text-slate-400">

                                    {step.mitre_id}

                                  </span>

                                </div>

                              </div>

                              <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-slate-800 text-slate-300 font-medium shrink-0">

                                {step.event_count} alert

                              </span>

                            </div>

                          ))}

                        </div>

                      </div>



                      {/* Immediate Playbook Recommendations */}

                      {pat.recommendations && pat.recommendations.length > 0 && (

                        <div className="pt-1">

                          <span className="text-[10px] font-bold uppercase tracking-wider text-slate-400 block mb-1">

                            Rekomendasi Tindakan SOC:

                          </span>

                          <ul className="space-y-1">

                            {pat.recommendations.slice(0, 2).map((rec, rIdx) => (

                              <li key={rIdx} className="text-[11px] text-slate-300 flex items-start gap-1.5 leading-snug">

                                <span className="text-emerald-400 font-bold shrink-0 mt-0.5">•</span>

                                <span>{rec}</span>

                              </li>

                            ))}

                          </ul>

                        </div>

                      )}

                    </div>

                  );

                })()}

              </div>



              {/* Explanatory Callout */}

              <div className="pt-2.5 border-t border-slate-800/80 text-[11px] text-slate-500 dark:text-slate-400">

                <div className="flex items-start gap-1.5 text-blue-400">

                  <Check className="w-3.5 h-3.5 shrink-0 mt-0.5" />

                  <span className="leading-relaxed">

                    Tabel di bawah otomatis memfilter <strong>{activeClusterPattern ? '60 alert' : 'seluruh aktivitas'}</strong> dari rantai pola serangan ini.

                  </span>

                </div>

              </div>

            </div>

          </div>

        </div>

      )}



      {/* Add Manual Entry Modal */}

      {isAddModalOpen && (

        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/70 backdrop-blur-xs animate-in fade-in duration-150">

          <div className={`w-full max-w-lg rounded-2xl border p-6 shadow-2xl space-y-5 ${

            isDark ? 'bg-[#0f172a] border-slate-700 text-white' : 'bg-white border-slate-200 text-slate-900'

          }`}>

            {/* Header */}

            <div className="flex items-center justify-between pb-3 border-b border-slate-700/50">

              <div className="flex items-center gap-2.5">

                <div className="p-2 rounded-xl bg-blue-600/20 text-blue-400 border border-blue-500/30">

                  <FolderPlus className="w-5 h-5 text-blue-500" />

                </div>

                <div>

                  <h3 className="font-bold text-sm">

                    Simpan ke Threat Campaign

                  </h3>

                  <p className="text-[11px] text-slate-400">

                    Kelompokkan alert korban dan rentang waktu ini ke dalam folder campaign

                  </p>

                </div>

              </div>

              <button

                type="button"

                onClick={() => setIsAddModalOpen(false)}

                className="text-slate-400 hover:text-white transition-colors cursor-pointer"

              >

                <X className="w-5 h-5" />

              </button>

            </div>



            {/* Context Summary Cards */}

            <div className={`p-3.5 rounded-xl border grid grid-cols-3 gap-3 text-xs ${

              isDark ? 'bg-[#090d16] border-slate-800' : 'bg-slate-50 border-slate-200'

            }`}>

              <div>

                <span className="text-[10px] uppercase font-semibold text-slate-400 tracking-wider block mb-1">

                  Target Korban

                </span>

                <span className="font-mono font-bold text-rose-400 break-all text-[11px]">

                  {searchQuery || (items[0]?.target || 'Semua Korban')}

                </span>

              </div>

              <div>

                <span className="text-[10px] uppercase font-semibold text-slate-400 tracking-wider block mb-1">

                  Time Range

                </span>

                <span className="font-semibold text-blue-400 text-[11px]">

                  {timeRange === 'custom' 

                    ? `${customStartDate?.slice(5, 10)} - ${customEndDate?.slice(5, 10)}` 

                    : (timeRange === 'hari' ? '24 Jam' : (timeRange === 'minggu' ? '7 Hari' : (timeRange === 'bulan' ? '30 Hari' : 'Semua Waktu')))}

                </span>

              </div>

              <div>

                <span className="text-[10px] uppercase font-semibold text-slate-400 tracking-wider block mb-1">

                  Total Alert

                </span>

                <span className="font-mono font-bold text-emerald-400 text-xs">

                  {(totalItems || items.length).toLocaleString()}

                </span>

              </div>

            </div>



            {/* Form */}

            <form onSubmit={handleAcceptCustomCampaign} className="space-y-4 text-xs">

              <div>

                <label className="block text-[11px] font-semibold text-slate-300 mb-1.5 flex items-center justify-between">

                  <span>Nama Folder</span>

                  <span className="text-[10px] font-normal text-slate-400">Ketik baru atau pilih folder yang sudah ada</span>

                </label>

                <div className="relative">

                  <input

                    type="text"

                    list="campaign-folders-list"

                    value={customFolder}

                    onChange={(e) => setCustomFolder(e.target.value)}

                    placeholder="Contoh: Kampus Bali / ELSA Incidents"

                    className={`w-full px-3.5 py-2.5 rounded-xl border text-xs focus:outline-none focus:border-blue-500 font-medium ${

                      isDark ? 'bg-[#090d16] border-slate-700 text-white placeholder-slate-500' : 'bg-slate-50 border-slate-300 text-slate-900'

                    }`}

                    required

                  />

                  <datalist id="campaign-folders-list">

                    {existingFolders.map((f, idx) => (

                      <option key={idx} value={f} />

                    ))}

                  </datalist>

                </div>

                {existingFolders.length > 0 && (

                  <div className="flex flex-wrap items-center gap-1.5 mt-2">

                    <span className="text-[10px] text-slate-400">Pilihan:</span>

                    {existingFolders.slice(0, 4).map((f, idx) => (

                      <button

                        key={idx}

                        type="button"

                        onClick={() => setCustomFolder(f)}

                        className={`text-[10px] px-2 py-0.5 rounded-md border transition-colors cursor-pointer ${

                          customFolder === f 

                            ? 'bg-blue-600/30 border-blue-500 text-blue-300' 

                            : (isDark ? 'bg-slate-800 border-slate-700 text-slate-300 hover:bg-slate-700' : 'bg-slate-100 border-slate-200 text-slate-700 hover:bg-slate-200')

                        }`}

                      >

                        {f}

                      </button>

                    ))}

                  </div>

                )}

              </div>



              <div>

                <label className="block text-[11px] font-semibold text-slate-300 mb-1.5">

                  Nama File / Campaign

                </label>

                <input

                  type="text"

                  value={customFile}

                  onChange={(e) => setCustomFile(e.target.value)}

                  placeholder="Contoh: Campaign_ELSA_Web_Exploitation"

                  className={`w-full px-3.5 py-2.5 rounded-xl border text-xs focus:outline-none focus:border-blue-500 font-medium font-mono ${

                    isDark ? 'bg-[#090d16] border-slate-700 text-white placeholder-slate-500' : 'bg-slate-50 border-slate-300 text-slate-900'

                  }`}

                  required

                />

              </div>



              <div>

                <label className="block text-[11px] font-semibold text-slate-300 mb-1.5">

                  Deskripsi / Catatan Analis (Opsional)

                </label>

                <textarea

                  rows={2}

                  value={customDesc}

                  onChange={(e) => setCustomDesc(e.target.value)}

                  placeholder="Tambahkan catatan investigasi atau konteks serangan..."

                  className={`w-full px-3.5 py-2 rounded-xl border text-xs focus:outline-none focus:border-blue-500 ${

                    isDark ? 'bg-[#090d16] border-slate-700 text-white placeholder-slate-500' : 'bg-slate-50 border-slate-300 text-slate-900'

                  }`}

                />

              </div>



              {/* Action Buttons */}

              <div className="flex items-center justify-end gap-2.5 pt-3 border-t border-slate-700/50">

                <button

                  type="button"

                  onClick={() => setIsAddModalOpen(false)}

                  className={`px-4 py-2 rounded-xl border text-xs font-semibold cursor-pointer transition-colors ${

                    isDark ? 'border-slate-700 hover:bg-slate-800 text-slate-300' : 'border-slate-300 hover:bg-slate-100 text-slate-700'

                  }`}

                >

                  Batal

                </button>

                <button

                  type="submit"

                  disabled={isSavingCustom}

                  className="px-5 py-2 rounded-xl bg-blue-600 hover:bg-blue-500 disabled:opacity-50 text-white text-xs font-semibold cursor-pointer shadow-md flex items-center gap-1.5"

                >

                  {isSavingCustom ? (

                    <>

                      <RefreshCw className="w-3.5 h-3.5 animate-spin" />

                      <span>Menyimpan...</span>

                    </>

                  ) : (

                    <>

                      <Check className="w-3.5 h-3.5" />

                      <span>Accept</span>

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

