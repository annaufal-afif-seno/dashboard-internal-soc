import React, { useState, useEffect, useMemo, useRef, useCallback } from 'react';

import { 

  ShieldAlert, Activity, Network, Layers, Clock, Database, 

  ExternalLink, Search, RefreshCw, AlertTriangle, CheckCircle2, 

  ArrowRight, Filter, Shield, Cpu, Sparkles, Terminal, Eye, FileText,

  ChevronDown, ChevronUp, ChevronLeft, ChevronRight, ListFilter, ArrowUpDown, ArrowUp, ArrowDown,

  Copy, Check, X, Folder, Target, FolderPlus, Trash2

} from 'lucide-react';



export default function ThreatCampaignsView({

  theme = 'dark',

  selectedTenant = 'ALL',

  currentUser = null,

  isReadOnly = false,

  onNavigate = null

}) {

  const isDark = theme === 'dark';



  const [campaigns, setCampaigns] = useState([]);

  const [selectedClusterId, setSelectedClusterId] = useState(null);

  const [clusterDetail, setClusterDetail] = useState(null);

  const [loading, setLoading] = useState(true);

  const [error, setError] = useState(null);

  const [searchTerm, setSearchTerm] = useState('');

  

  // Local tenant filter

  const [tenantFilter, setTenantFilter] = useState(selectedTenant || 'ALL');



  // Custom Threat Campaigns State (opened via 'Custom' button)

  const [isCustomModalOpen, setIsCustomModalOpen] = useState(false);

  const [customCampaigns, setCustomCampaigns] = useState([]);

  const [customFolders, setCustomFolders] = useState([]);

  const [loadingCustom, setLoadingCustom] = useState(false);

  const [selectedCustomFolder, setSelectedCustomFolder] = useState('ALL');

  const [customSearchQuery, setCustomSearchQuery] = useState('');

  const [deletingId, setDeletingId] = useState(null);

  const [customToast, setCustomToast] = useState(null);



  const fetchCustomCampaigns = useCallback(async () => {

    setLoadingCustom(true);

    try {

      const res = await fetch('/api/threat-campaign/custom-campaigns');

      if (res.ok) {

        const json = await res.json();

        setCustomCampaigns(json.data || []);

        setCustomFolders(json.folders || []);

      }

    } catch (e) {

      console.error('Failed to load custom campaigns:', e);

    } finally {

      setLoadingCustom(false);

    }

  }, []);



  useEffect(() => {

    if (isCustomModalOpen) {

      fetchCustomCampaigns();

    }

  }, [isCustomModalOpen, fetchCustomCampaigns]);



  const handleDeleteCustomCampaign = async (id, e) => {

    e.stopPropagation();

    if (!window.confirm('Apakah Anda yakin ingin menghapus custom campaign ini?')) return;

    setDeletingId(id);

    try {

      const res = await fetch(`/api/threat-campaign/custom-campaigns/${id}`, { method: 'DELETE' });

      if (res.ok) {

        setCustomCampaigns(prev => prev.filter(c => c.id !== id));

        setCustomToast('Custom campaign berhasil dihapus');

        setTimeout(() => setCustomToast(null), 3000);

      }

    } catch (e) {

      console.error('Failed to delete campaign:', e);

    } finally {

      setDeletingId(null);

    }

  };



  const handleOpenCustomCampaign = (camp) => {

    setIsCustomModalOpen(false);

    if (onNavigate) {

      onNavigate('threat_victim', { search: camp.victim_target });

    }

  };



  // Filtered & grouped custom campaigns

  const filteredCustomCampaigns = useMemo(() => {

    let list = customCampaigns;

    if (selectedCustomFolder !== 'ALL') {

      list = list.filter(c => c.folder_name === selectedCustomFolder);

    }

    if (customSearchQuery.trim()) {

      const q = customSearchQuery.toLowerCase();

      list = list.filter(c => 

        (c.file_name && c.file_name.toLowerCase().includes(q)) ||

        (c.folder_name && c.folder_name.toLowerCase().includes(q)) ||

        (c.victim_target && c.victim_target.toLowerCase().includes(q)) ||

        (c.description && c.description.toLowerCase().includes(q))

      );

    }

    return list;

  }, [customCampaigns, selectedCustomFolder, customSearchQuery]);



  const groupedCustomCampaigns = useMemo(() => {

    const groups = {};

    for (const c of filteredCustomCampaigns) {

      const f = c.folder_name || 'Uncategorized';

      if (!groups[f]) groups[f] = [];

      groups[f].push(c);

    }

    return groups;

  }, [filteredCustomCampaigns]);



  // Mode Raw Events (Server-side paginated table matching Victim feature)

  const [rawEvents, setRawEvents] = useState([]);

  const [totalRawEvents, setTotalRawEvents] = useState(0);

  const [totalCampaignRaw, setTotalCampaignRaw] = useState(0);

  const [categories, setCategories] = useState([]);

  const [tableLoading, setTableLoading] = useState(false);



  const [selectedCategory, setSelectedCategory] = useState('ALL');

  const [searchInput, setSearchInput] = useState('');

  const [searchQuery, setSearchQuery] = useState('');

  const [currentPage, setCurrentPage] = useState(1);

  const [pageSize, setPageSize] = useState(25);

  const [sortField, setSortField] = useState('timestamp');

  const [sortOrder, setSortOrder] = useState('asc'); // 'asc' for chronological

  const [selectedAlert, setSelectedAlert] = useState(null);

  const [copiedId, setCopiedId] = useState(null);

  const handleCopyLog = (text, id) => {

    if (!text) return;

    navigator.clipboard.writeText(String(text));

    setCopiedId(id);

    setTimeout(() => setCopiedId(null), 2500);

  };

  const [isCategoryDropdownOpen, setIsCategoryDropdownOpen] = useState(false);

  const categoryDropdownRef = useRef(null);



  useEffect(() => {

    const handleClickOutside = (event) => {

      if (categoryDropdownRef.current && !categoryDropdownRef.current.contains(event.target)) {

        setIsCategoryDropdownOpen(false);

      }

    };

    document.addEventListener('mousedown', handleClickOutside);

    return () => document.removeEventListener('mousedown', handleClickOutside);

  }, []);



  const categoryOptions = useMemo(() => {

    const opts = [{ id: 'ALL', label: 'All Phase' }];

    (categories || []).forEach(catObj => {

      const id = catObj.category;

      if (id && id !== 'ALL') {

        const label = id

          .replace(/_/g, ' ')

          .toLowerCase()

          .replace(/\b\w/g, l => l.toUpperCase());

        opts.push({ id, label });

      }

    });

    return opts;

  }, [categories]);



  const selectedCategoryLabel = useMemo(() => {

    if (!selectedCategory || selectedCategory === 'ALL') return 'All Phase';

    const found = categoryOptions.find(o => o.id === selectedCategory);

    return found?.label || selectedCategory.replace(/_/g, ' ').toLowerCase().replace(/\b\w/g, l => l.toUpperCase());

  }, [selectedCategory, categoryOptions]);

  const toggleCampaign = (clusterId) => {

    if (selectedClusterId === clusterId) {

      setSelectedClusterId(null);

      setSelectedAlert(null);

    } else {

      setSelectedClusterId(clusterId);

      setSelectedAlert(null);

      setSelectedCategory('ALL');

      setCurrentPage(1);

      setIsCategoryDropdownOpen(false);

    }

  };





  // Fetch campaigns list

  const fetchCampaigns = async (overrideTenant = null) => {

    try {

      setLoading(true);

      setError(null);

      const activeTenant = overrideTenant !== null ? overrideTenant : tenantFilter;

      const tenantParam = activeTenant && activeTenant.toUpperCase() !== 'ALL' ? `&tenant_id=${encodeURIComponent(activeTenant)}` : '';

      const res = await fetch(`/api/campaign-clusters?limit=100${tenantParam}`);

      if (!res.ok) throw new Error(`HTTP ${res.status}: Gagal memuat daftar kampanye.`);

      const data = await res.json();

      const list = data.data || [];

      setCampaigns(list);



      // Keep selectedClusterId only if already chosen and still present in list

      if (list.length > 0 && selectedClusterId) {

        if (!list.some(c => c.cluster_id === selectedClusterId)) {

          setSelectedClusterId(null);

        }

      }

    } catch (err) {

      console.error('Error fetching campaign clusters:', err);

      setError(err.message);

    } finally {

      setLoading(false);

    }

  };



  // Fetch cluster details

  const fetchClusterDetail = async (clusterId) => {

    if (!clusterId) return;

    try {

      const res = await fetch(`/api/campaign-clusters/${encodeURIComponent(clusterId)}`);

      if (res.ok) {

        const data = await res.json();

        setClusterDetail(data);

      }

    } catch (err) {

      console.error('Error fetching cluster detail:', err);

    }

  };



  // Fetch raw events with server-side pagination (Mode Raw Events: 81.919+ rows)

  const fetchRawEvents = useCallback(async () => {

    if (!selectedClusterId) return;

    try {

      setTableLoading(true);

      const params = new URLSearchParams({

        page: String(currentPage),

        limit: String(pageSize),

        sort_field: sortField,

        sort_order: sortOrder

      });



      if (selectedCategory && selectedCategory !== 'ALL') {

        params.append('category', selectedCategory);

      }

      if (searchQuery) {

        params.append('q', searchQuery);

      }



      const res = await fetch(`/api/campaign-clusters/${encodeURIComponent(selectedClusterId)}/raw-events?${params.toString()}`);

      if (!res.ok) throw new Error(`HTTP ${res.status}: Gagal memuat raw events.`);

      const result = await res.json();

      setRawEvents(result.data || []);

      setTotalRawEvents(result.total || 0);

      setTotalCampaignRaw(result.total_campaign || result.total || 0);

      if (result.categories && result.categories.length > 0) {

        setCategories(result.categories);

      }

    } catch (err) {

      console.error('Error fetching campaign raw events:', err);

    } finally {

      setTableLoading(false);

    }

  }, [selectedClusterId, currentPage, pageSize, selectedCategory, searchQuery, sortField, sortOrder]);



  useEffect(() => {

    if (selectedTenant) {

      setTenantFilter(selectedTenant);

    }

  }, [selectedTenant]);



  useEffect(() => {

    fetchCampaigns(tenantFilter);

  }, [tenantFilter]);



  useEffect(() => {

    if (selectedClusterId) {

      fetchClusterDetail(selectedClusterId);

    }

  }, [selectedClusterId]);



  // Debounced search trigger (350ms delay)

  useEffect(() => {

    const timer = setTimeout(() => {

      setSearchQuery(searchInput.trim());

      setCurrentPage(1);

    }, 350);

    return () => clearTimeout(timer);

  }, [searchInput]);



  // Fetch raw events whenever parameters change

  useEffect(() => {

    fetchRawEvents();

  }, [fetchRawEvents]);



  // Reset pagination and search when switching campaigns

  useEffect(() => {

    setSelectedCategory('ALL');

    setSearchInput('');

    setSearchQuery('');

    setCurrentPage(1);

    setSelectedAlert(null);

    setSortField('timestamp');

    setSortOrder('asc');

  }, [selectedClusterId]);



  const filteredCampaigns = useMemo(() => {

    if (!searchTerm) return campaigns;

    const term = searchTerm.toLowerCase();

    return campaigns.filter(c => 

      c.cluster_id.toLowerCase().includes(term) ||

      (c.target_host && c.target_host.toLowerCase().includes(term)) ||

      (c.campaign_title && c.campaign_title.toLowerCase().includes(term)) ||

      (c.priority && c.priority.toLowerCase().includes(term)) ||

      (c.cluster_status && c.cluster_status.toLowerCase().includes(term))

    );

  }, [campaigns, searchTerm]);



  const selectedCampaign = useMemo(() => {

    return campaigns.find(c => c.cluster_id === selectedClusterId) || clusterDetail?.cluster || null;

  }, [campaigns, selectedClusterId, clusterDetail]);



  // Color resolver for categories

  const getCategoryColor = (category, isDark, isSelected) => {

    const cat = (category || '').trim().toUpperCase();

    switch (cat) {

      // 1. PIVOT_COMPROMISE (Titik Tembus Utama)

      case 'PIVOT_COMPROMISE':

      case 'PIVOT COMPROMISE':

      case 'INITIAL_ACCESS':

      case 'INITIAL ACCESS':

      case 'WEB_ATTACK':

        if (isSelected) {

          return isDark 

            ? 'bg-rose-900/90 text-rose-100 border-rose-400 ring-1 ring-rose-400 shadow-sm' 

            : 'bg-rose-200 text-rose-950 border-rose-600 ring-1 ring-rose-600 shadow-sm';

        }

        return isDark 

          ? 'bg-rose-950/40 text-rose-300 border-rose-800/70 hover:bg-rose-900/50 hover:border-rose-500' 

          : 'bg-rose-50 text-rose-800 border-rose-200 hover:bg-rose-100';



      // 2. PRECURSOR_RECON (Pengintaian / Scanning)

      case 'PRECURSOR_RECON':

      case 'PRECURSOR RECON':

      case 'DISCOVERY':

        if (isSelected) {

          return isDark 

            ? 'bg-purple-900/90 text-purple-100 border-purple-400 ring-1 ring-purple-400 shadow-sm' 

            : 'bg-purple-200 text-purple-950 border-purple-600 ring-1 ring-purple-600 shadow-sm';

        }

        return isDark 

          ? 'bg-purple-950/40 text-purple-300 border-purple-800/70 hover:bg-purple-900/50 hover:border-purple-500' 

          : 'bg-purple-50 text-purple-800 border-purple-200 hover:bg-purple-100';



      // 3. BRUTE_FORCE_SPRAY (Password Spraying)

      case 'BRUTE_FORCE_SPRAY':

      case 'BRUTE FORCE SPRAY':

      case 'CREDENTIAL_ACCESS':

      case 'CREDENTIAL ACCESS':

      case 'AUTH_FAILURE':

      case 'AUTH FAILURE':

        if (isSelected) {

          return isDark 

            ? 'bg-red-900/90 text-red-100 border-red-400 ring-1 ring-red-400 shadow-sm' 

            : 'bg-red-200 text-red-950 border-red-600 ring-1 ring-red-600 shadow-sm';

        }

        return isDark 

          ? 'bg-red-950/40 text-red-300 border-red-800/70 hover:bg-red-900/50 hover:border-red-500' 

          : 'bg-red-50 text-red-800 border-red-200 hover:bg-red-100';



      // 4. PRIVILEGE_ESCALATION

      case 'PRIVILEGE_ESCALATION':

      case 'PRIVILEGE ESCALATION':

        if (isSelected) {

          return isDark 

            ? 'bg-orange-900/90 text-orange-100 border-orange-400 ring-1 ring-orange-400 shadow-sm' 

            : 'bg-orange-200 text-orange-950 border-orange-600 ring-1 ring-orange-600 shadow-sm';

        }

        return isDark 

          ? 'bg-orange-950/40 text-orange-300 border-orange-800/70 hover:bg-orange-900/50 hover:border-orange-500' 

          : 'bg-orange-50 text-orange-800 border-orange-200 hover:bg-orange-100';



      // 5. EXECUTION

      case 'EXECUTION':

        if (isSelected) {

          return isDark 

            ? 'bg-amber-900/90 text-amber-100 border-amber-400 ring-1 ring-amber-400 shadow-sm' 

            : 'bg-amber-200 text-amber-950 border-amber-600 ring-1 ring-amber-600 shadow-sm';

        }

        return isDark 

          ? 'bg-amber-950/40 text-amber-300 border-amber-800/70 hover:bg-amber-900/50 hover:border-amber-500' 

          : 'bg-amber-50 text-amber-800 border-amber-200 hover:bg-amber-100';



      // 6. PERSISTENCE

      case 'PERSISTENCE':

        if (isSelected) {

          return isDark 

            ? 'bg-emerald-900/90 text-emerald-100 border-emerald-400 ring-1 ring-emerald-400 shadow-sm' 

            : 'bg-emerald-200 text-emerald-950 border-emerald-600 ring-1 ring-emerald-600 shadow-sm';

        }

        return isDark 

          ? 'bg-emerald-950/40 text-emerald-300 border-emerald-800/70 hover:bg-emerald-900/50 hover:border-emerald-500' 

          : 'bg-emerald-50 text-emerald-800 border-emerald-200 hover:bg-emerald-100';



      // 7. DEFENSE_EVASION

      case 'DEFENSE_EVASION':

      case 'DEFENSE EVASION':

        if (isSelected) {

          return isDark 

            ? 'bg-indigo-900/90 text-indigo-100 border-indigo-400 ring-1 ring-indigo-400 shadow-sm' 

            : 'bg-indigo-200 text-indigo-950 border-indigo-600 ring-1 ring-indigo-600 shadow-sm';

        }

        return isDark 

          ? 'bg-indigo-950/40 text-indigo-300 border-indigo-800/70 hover:bg-indigo-900/50 hover:border-indigo-500' 

          : 'bg-indigo-50 text-indigo-800 border-indigo-200 hover:bg-indigo-100';



      // 8. LATERAL_MOVE

      case 'LATERAL_MOVE':

      case 'LATERAL MOVE':

      case 'LATERAL_MOVEMENT':

        if (isSelected) {

          return isDark 

            ? 'bg-violet-900/90 text-violet-100 border-violet-400 ring-1 ring-violet-400 shadow-sm' 

            : 'bg-violet-200 text-violet-950 border-violet-600 ring-1 ring-violet-600 shadow-sm';

        }

        return isDark 

          ? 'bg-violet-950/40 text-violet-300 border-violet-800/70 hover:bg-violet-900/50 hover:border-violet-500' 

          : 'bg-violet-50 text-violet-800 border-violet-200 hover:bg-violet-100';



      // 9. C2_EXFIL

      case 'C2_EXFIL':

      case 'C2 EXFIL':

      case 'EXFILTRATION':

        if (isSelected) {

          return isDark 

            ? 'bg-fuchsia-900/90 text-fuchsia-100 border-fuchsia-400 ring-1 ring-fuchsia-400 shadow-sm' 

            : 'bg-fuchsia-200 text-fuchsia-950 border-fuchsia-600 ring-1 ring-fuchsia-600 shadow-sm';

        }

        return isDark 

          ? 'bg-fuchsia-950/40 text-fuchsia-300 border-fuchsia-800/70 hover:bg-fuchsia-900/50 hover:border-fuchsia-500' 

          : 'bg-fuchsia-50 text-fuchsia-800 border-fuchsia-200 hover:bg-fuchsia-100';



      // 10. IMPACT_DISRUPTION

      case 'IMPACT_DISRUPTION':

      case 'IMPACT DISRUPTION':

      case 'RANSOMWARE':

        if (isSelected) {

          return isDark 

            ? 'bg-rose-950 text-rose-100 border-rose-500 ring-1 ring-rose-500 shadow-sm' 

            : 'bg-rose-300 text-rose-950 border-rose-700 ring-1 ring-rose-700 shadow-sm';

        }

        return isDark 

          ? 'bg-rose-950/60 text-rose-300 border-rose-900 hover:bg-rose-900/50 hover:border-rose-500' 

          : 'bg-rose-100 text-rose-900 border-rose-300 hover:bg-rose-200';



      // 11. GENERAL_ACTIVITY

      case 'GENERAL_ACTIVITY':

      case 'GENERAL ACTIVITY':

      case 'WEB_OPERATIONAL':

      case 'WEB OPERATIONAL':

      case 'SYSTEM_HEALTH':

      case 'AUTH_SUCCESS':

        if (isSelected) {

          return isDark 

            ? 'bg-blue-900/90 text-blue-100 border-blue-400 ring-1 ring-blue-400 shadow-sm' 

            : 'bg-blue-200 text-blue-950 border-blue-600 ring-1 ring-blue-600 shadow-sm';

        }

        return isDark 

          ? 'bg-blue-950/40 text-blue-300 border-blue-800/70 hover:bg-blue-900/50 hover:border-blue-500' 

          : 'bg-blue-50 text-blue-800 border-blue-200 hover:bg-blue-100';



      default:

        if (isSelected) {

          return isDark 

            ? 'bg-slate-700 text-white border-slate-300 ring-1 ring-slate-400' 

            : 'bg-slate-300 text-slate-900 border-slate-600 ring-1 ring-slate-600';

        }

        return isDark 

          ? 'bg-slate-800 text-slate-300 border-slate-700 hover:bg-slate-700' 

          : 'bg-slate-100 text-slate-700 border-slate-300 hover:bg-slate-200';

    }

  };



  // Sort handler

  const handleSort = (field) => {

    if (sortField === field) {

      setSortOrder(prev => prev === 'asc' ? 'desc' : 'asc');

    } else {

      setSortField(field);

      setSortOrder(field === 'timestamp' ? 'asc' : 'desc');

    }

    setCurrentPage(1);

  };



  const renderSortIcon = (field) => {

    if (sortField !== field) {

      return <ArrowUpDown className="w-3 h-3 text-slate-500 opacity-60" />;

    }

    return sortOrder === 'asc' ? (

      <ArrowUp className="w-3 h-3 text-blue-500 font-bold" />

    ) : (

      <ArrowDown className="w-3 h-3 text-blue-500 font-bold" />

    );

  };





  // Pagination calculations

  const totalPages = Math.max(1, Math.ceil(totalRawEvents / pageSize));



  return (

    <div className="space-y-4 font-sans text-xs">

      

            {/* TOP HEADER: Graph Conclusion with Search Bar beside it */}
      <div className={`px-5 py-3.5 rounded-xl border shadow-sm flex items-center justify-between gap-4 flex-wrap md:flex-nowrap ${
        isDark ? 'bg-[#090d16] border-slate-800' : 'bg-white border-slate-200'
      }`}>
        <h1 className={`text-base font-bold font-mono tracking-wider shrink-0 ${isDark ? 'text-white' : 'text-slate-900'}`}>
          Graph Conclusion
        </h1>

        {/* Search Bar positioned right beside Graph Conclusion */}
        <div className="flex-1 max-w-md ml-auto">
          <div className="w-full relative flex items-center bg-white dark:bg-[#090d16] border-2 border-[#3B5BFF] rounded-full h-[38px] pl-3.5 pr-1.5 shadow-2xs group focus-within:ring-2 focus-within:ring-[#3B5BFF]/30 transition-all">
            <Search className="w-4 h-4 text-slate-400 shrink-0 mr-2.5 stroke-[2]" />
            <input
              type="text"
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              placeholder="Cari ID, host, status, atau judul..."
              className="w-full bg-transparent text-slate-800 dark:text-slate-200 placeholder:text-slate-400 text-xs sm:text-[13px] font-normal focus:outline-none"
            />
            {searchTerm && (
              <button
                type="button"
                onClick={() => setSearchTerm('')}
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
              <Search className="w-3.5 h-3.5 text-white" strokeWidth={2.5} />
            </button>
          </div>
        </div>
      </div>

      {/* ERROR BANNER */}

      {error && (

        <div className="p-3 rounded-xl bg-red-500/10 border border-red-500/30 text-red-400 text-xs flex items-center gap-2">

          <AlertTriangle className="w-4 h-4 shrink-0" />

          <span>{error}</span>

        </div>

      )}



            {/* DETECTED CAMPAIGNS WORKSPACE (Full Width Accordion) */}

      <div className={`p-4 rounded-xl border ${

        isDark ? 'bg-[#090d16] border-slate-800' : 'bg-white border-slate-200 shadow-sm'

      }`}>

        {loading && campaigns.length === 0 ? (

          <div className="p-12 text-center text-slate-400 flex flex-col items-center gap-2">

            <RefreshCw className="w-5 h-5 animate-spin text-cyan-400" />

            <span>Memuat daftar kampanye serangan...</span>

          </div>

        ) : filteredCampaigns.length === 0 ? (

          <div className="p-12 text-center text-slate-400">

            Tidak ada kampanye yang cocok dengan pencarian.

          </div>

        ) : (

          <div className="space-y-3">

            {filteredCampaigns.map((c) => {

              const isSelected = c.cluster_id === selectedClusterId;

              const isThreat = c.cluster_status === 'CONFIRMED_THREAT';

              const isInvestigation = c.cluster_status === 'UNDER_INVESTIGATION';

              const isBenign = c.cluster_status === 'FALSE_CORRELATION';

              const phase = c.causality_dag?.incident_phase || (isBenign ? 'BENIGN_OPERATIONAL' : 'POST_COMPROMISE');

              const icsScore = c.causality_dag?.incident_confidence_score ?? (isBenign ? 7 : 85);



              return (

                <div

                  key={c.cluster_id}

                  className={`rounded-xl border transition-all duration-200 overflow-hidden ${

                    isDark 

                      ? 'bg-[#0b101d] border-slate-800 hover:border-slate-700' 

                      : 'bg-white border-slate-200 hover:border-slate-300 shadow-2xs'

                  }`}

                >

                  {/* Clickable Header Box for Campaign */}

                  <div

                    onClick={() => toggleCampaign(c.cluster_id)}

                    className="p-4 cursor-pointer select-none group"

                    title={isSelected ? "Klik kotak ini untuk menutup" : "Klik kotak ini untuk membuka rantai serangan di bawah"}

                  >

                    <div className="flex items-center justify-between gap-3 mb-1.5 flex-wrap">

                      <div className="flex items-center gap-2.5">

                        <span className={`font-mono font-bold text-sm tracking-tight ${

                          isDark ? 'text-white' : 'text-slate-900'

                        }`}>

                          {c.cluster_id}

                        </span>

                      </div>



                      {/* Right Indicator: Status + Chevron icon */}

                      <div className="flex items-center gap-2.5">

                        <span className={`font-mono font-bold text-xs uppercase tracking-wider ${

                          isThreat 

                            ? 'text-red-500' 

                            : isInvestigation 

                            ? 'text-amber-500' 

                            : 'text-emerald-500'

                        }`}>

                          {isThreat ? 'THREAT' : isInvestigation ? 'INVESTIGATING' : 'BENIGN'}

                        </span>



                        <div className={`p-1.5 rounded-lg transition-colors ${

                          isDark 

                            ? 'bg-slate-800/60 text-slate-400 group-hover:bg-slate-700 group-hover:text-slate-200' 

                            : 'bg-slate-100 text-slate-500 group-hover:bg-slate-200 group-hover:text-slate-700'

                        }`}>

                          {isSelected ? (

                            <ChevronUp className="w-4 h-4" />

                          ) : (

                            <ChevronDown className="w-4 h-4" />

                          )}

                        </div>

                      </div>

                    </div>



                    {/* Forensic Narrative Summary underneath Campaign ID (Unboxed, no title) */}

                    {c.narrative_summary && (

                      <p className={`my-2 text-justify text-xs leading-relaxed ${

                        isDark ? 'text-slate-300' : 'text-slate-600'

                      }`}>

                        {c.narrative_summary}

                      </p>

                    )}



                    {/* Campaign Meta & Metrics */}

                    <div className="flex items-center justify-between text-[11px] text-slate-400 font-mono flex-wrap gap-2 pt-2 border-t border-slate-700/20">

                      <div className="flex items-center gap-3">

                        <span>

                          Target: <strong className={`font-mono font-bold ${isDark ? 'text-white' : 'text-slate-900'}`}>{c.target_host}</strong>

                        </span>

                        <span>&bull;</span>

                        <span className={`font-mono font-bold ${

                          phase === 'POST_COMPROMISE'

                            ? 'text-red-600 dark:text-red-400'

                            : phase === 'ACTIVE_INTRUSION'

                            ? 'text-orange-600 dark:text-orange-400'

                            : phase === 'PRECURSOR_PROBING'

                            ? 'text-cyan-600 dark:text-cyan-400'

                            : 'text-slate-500'

                        }`}>

                          {phase}

                        </span>

                      </div>



                      <div className="flex items-center gap-3">

                        <span className="text-cyan-500 font-bold" title="Incident Confidence Score">

                          ICS {icsScore}%

                        </span>

                        <span>&bull;</span>

                        <span className={isThreat ? 'text-red-500 font-bold' : isInvestigation ? 'text-orange-500 font-bold' : 'text-slate-500 font-bold'} title="Incident Severity Score">

                          ISS {c.campaign_risk_score}

                        </span>

                        <span>&bull;</span>

                        <span>{c.total_distinct_actors || 1} Actors</span>

                        <span>&bull;</span>

                        <span className="font-bold text-slate-300 dark:text-slate-200">

                          {(c.total_raw_events_count || 0).toLocaleString()} Logs

                        </span>

                      </div>

                    </div>

                  </div>



                  {/* UNDERNEATH THAT CAMPAIGN BOX (di bawah kotak tersebut): The Forensic Table and Details */}

                  {isSelected && (

                    <div 

                      onClick={(e) => e.stopPropagation()} 

                      className={`p-4 border-t transition-all ${

                        isDark ? 'border-slate-800 bg-[#070b14]' : 'border-slate-200 bg-slate-50/70'

                      }`}

                    >

                      <div className="flex gap-4 items-stretch">

                        {/* Main Table Card (Exact matching styling with Victim feature) */}

              <div className={`border rounded-2xl shadow-xl overflow-hidden transition-all duration-200 flex flex-col justify-between ${

                selectedAlert ? 'flex-1 min-w-0' : 'w-full'

              } ${

                isDark ? 'bg-[#0b0f19] border-slate-800 text-slate-100' : 'bg-white border-slate-200 text-slate-800'

              }`}>

                

                {/* Header Bar: Forensic Title + Dynamic L2 Category Dropdown Filter + Search Bar */}

                <div className={`px-4 py-3 border-b flex flex-row items-center justify-between gap-3 w-full ${

                  isDark ? 'border-slate-800' : 'border-slate-200'

                }`}>

                  <div className="shrink-0 flex items-center gap-3">

                    <h2 className={`text-base font-bold tracking-tight font-mono ${isDark ? 'text-white' : 'text-slate-900'}`}>

                      Forensic

                    </h2>



                    {/* L2 Category Filter Dropdown (matching Image 2 style, no counts, Title Case) */}

                    <div className="relative" ref={categoryDropdownRef}>

                      <button

                        type="button"

                        onClick={() => setIsCategoryDropdownOpen(prev => !prev)}

                        className={`flex items-center justify-between gap-2 px-3 py-1.5 rounded-lg text-xs font-mono font-medium border transition-all cursor-pointer shadow-xs ${

                          selectedCategory !== 'ALL'

                            ? (isDark 

                                ? 'bg-slate-800 border-slate-700 text-white font-semibold' 

                                : 'bg-slate-100 border-slate-300 text-slate-900 font-semibold')

                            : (isDark

                                ? 'bg-[#0e1424] border-slate-800 text-slate-300 hover:bg-slate-800/80 hover:border-slate-700 hover:text-white'

                                : 'bg-white border-slate-200 text-slate-700 hover:bg-slate-50 hover:border-slate-300 hover:text-slate-900')

                        }`}

                      >

                        <span className="truncate max-w-[170px]">{selectedCategoryLabel}</span>

                        <ChevronDown className={`w-3.5 h-3.5 shrink-0 transition-transform duration-200 ${

                          isCategoryDropdownOpen ? 'rotate-180 text-blue-500' : (isDark ? 'text-slate-400' : 'text-slate-500')

                        }`} />

                      </button>



                      {/* Dropdown Menu matching Image 2 */}

                      {isCategoryDropdownOpen && (

                        <div className={`absolute left-0 mt-1.5 w-56 rounded-xl shadow-2xl border z-50 font-mono text-xs overflow-hidden animate-in fade-in zoom-in-95 transition-all duration-150 ${

                          isDark

                            ? 'bg-[#0c101c] border-slate-700 text-slate-200 shadow-black/80'

                            : 'bg-white border-slate-200 text-slate-800 shadow-slate-400/30'

                        }`}>

                          <div className="py-1">

                            {categoryOptions.map((opt) => {

                              const isSelected = (selectedCategory === opt.id) || (opt.id === 'ALL' && (!selectedCategory || selectedCategory === 'ALL'));

                              return (

                                <button

                                  key={opt.id}

                                  type="button"

                                  onClick={() => {

                                    setSelectedCategory(opt.id);

                                    setCurrentPage(1);

                                    setIsCategoryDropdownOpen(false);

                                  }}

                                  className={`w-full text-left px-3.5 py-2.5 flex items-center justify-between transition-colors cursor-pointer ${

                                    isSelected

                                      ? (isDark 

                                          ? 'bg-slate-700/80 text-white font-semibold' 

                                          : 'bg-slate-100/90 text-slate-900 font-semibold')

                                      : (isDark 

                                          ? 'hover:bg-slate-800/60 text-slate-300 hover:text-white' 

                                          : 'hover:bg-slate-50 text-slate-700 hover:text-slate-900')

                                  }`}

                                >

                                  <span>{opt.label}</span>

                                  {isSelected && (

                                    <Check className="w-4 h-4 text-blue-500 shrink-0 stroke-[2.5]" />

                                  )}

                                </button>

                              );

                            })}

                          </div>

                        </div>

                      )}

                    </div>

                  </div>



                  {/* Search Bar matching Victim view */}

                  <div className="flex-1 max-w-md mx-2">

                    <div className="w-full relative flex items-center bg-white dark:bg-[#090d16] border-2 border-[#3B5BFF] rounded-full h-[38px] pl-3.5 pr-1.5 shadow-2xs group focus-within:ring-2 focus-within:ring-[#3B5BFF]/30 transition-all">

                      <Search className="w-4 h-4 text-slate-400 shrink-0 mr-2.5 stroke-[2]" />

                      <input

                        type="text"

                        value={searchInput}

                        onChange={(e) => setSearchInput(e.target.value)}

                        placeholder="Search ID, mitre, category, actor..."

                        className="w-full bg-transparent text-slate-800 dark:text-slate-200 placeholder:text-slate-400 text-xs sm:text-[13px] font-normal focus:outline-none"

                      />

                      {searchInput && (

                        <button

                          type="button"

                          onClick={() => {

                            setSearchInput('');

                            setSearchQuery('');

                            setCurrentPage(1);

                          }}

                          className="text-slate-400 hover:text-slate-600 dark:hover:text-slate-200 cursor-pointer p-1 mr-1"

                          title="Clear search"

                        >

                          <X className="w-3.5 h-3.5" />

                        </button>

                      )}

                      <button

                        type="button"

                        onClick={() => {

                          setSearchQuery(searchInput);

                          setCurrentPage(1);

                        }}

                        className="w-7 h-7 rounded-full bg-[#3B5BFF] hover:bg-[#2D4BEB] flex items-center justify-center shrink-0 cursor-pointer transition-transform hover:scale-105 shadow-xs"

                        title="Search"

                      >

                        <Search className="w-3.5 h-3.5 text-white" strokeWidth={2.5} />

                      </button>

                    </div>

                  </div>

                </div>



                {/* Table Content (Exact columns matching Victim Feature: Timestamp, ID, MITRE, Category, Actor) */}

                <div className="flex-1 overflow-x-auto min-h-[360px]">

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



                        {/* 5. Actor */}

                        <th 

                          onClick={() => handleSort('actor')}

                          className="py-3 px-4 font-semibold w-[22%] cursor-pointer group"

                        >

                          <div className="flex items-center gap-1.5">

                            <span>Actor</span>

                            {renderSortIcon('actor')}

                          </div>

                        </th>

                      </tr>

                    </thead>



                    <tbody className={`divide-y ${isDark ? 'divide-slate-800/80' : 'divide-slate-200'}`}>

                      {tableLoading ? (

                        <tr>

                          <td colSpan={5} className="py-20 text-center">

                            <div className="flex flex-col items-center justify-center gap-2 text-slate-400">

                              <RefreshCw className="w-6 h-6 animate-spin text-blue-500" />

                              <span className="text-xs">Memuat data log mentah Wazuh...</span>

                            </div>

                          </td>

                        </tr>

                      ) : rawEvents.length === 0 ? (

                        <tr>

                          <td colSpan={5} className="py-20 text-center text-slate-400 font-mono text-xs">

                            Tidak ada data log mentah yang cocok dengan kriteria filter saat ini.

                          </td>

                        </tr>

                      ) : (

                        rawEvents.map((m, idx) => {

                          const itemAlertId = m.wazuh_id || m.id || '-';

                          const isAlertSelected = selectedAlert && (selectedAlert.id === m.id) && (selectedAlert.timestamp === m.timestamp);



                          return (

                            <tr 

                              key={`${itemAlertId}_${idx}`} 

                              className={`transition-colors align-middle ${

                                isAlertSelected

                                  ? (isDark ? 'bg-blue-600/15 border-l-4 border-l-blue-500' : 'bg-blue-50/80 border-l-4 border-l-blue-600')

                                  : (isDark ? 'hover:bg-slate-850/60' : 'hover:bg-slate-50')

                              }`}

                            >

                              {/* 1. Timestamp */}

                              <td className="py-2.5 px-4 font-mono text-[11px] text-slate-400 whitespace-nowrap">

                                {m.timestamp_formatted || (m.timestamp ? new Date(m.timestamp).toLocaleString('id-ID') : '-')}

                              </td>



                              {/* 2. ID Wazuh (Clickable in blue font) */}

                              <td className="py-2.5 px-4 font-mono whitespace-nowrap overflow-hidden">

                                <span 

                                  className="font-bold text-[11px] tracking-tight text-blue-600 dark:text-blue-400 hover:text-blue-700 dark:hover:text-blue-300 hover:underline cursor-pointer select-all truncate block"

                                  title={`Buka detail alert (${itemAlertId})`}

                                  onClick={() => setSelectedAlert(prev => (prev?.id === m.id && prev?.timestamp === m.timestamp) ? null : m)}

                                >

                                  {itemAlertId}

                                </span>

                              </td>



                              {/* 3. MITRE (Teks polos monospace) */}

                              <td className="py-2.5 px-4 whitespace-nowrap font-mono text-xs font-medium text-slate-900 dark:text-slate-100">

                                {m.mitre || 'T1082'}

                              </td>



                              {/* 4. Category (L2 Role / Phase) */}

                              <td className="py-2.5 px-4 whitespace-nowrap text-xs font-semibold uppercase tracking-wider text-slate-900 dark:text-slate-100">

                                {m.category || '-'}

                              </td>



                              {/* 5. Actor (Teks polos monospace) */}

                              <td className="py-2.5 px-4 whitespace-nowrap font-mono text-xs font-semibold text-slate-900 dark:text-slate-100">

                                {m.actor || '-'}

                              </td>

                            </tr>

                          );

                        })

                      )}

                    </tbody>

                  </table>

                </div>



                {/* Table Footer with Pagination matching Victim View */}

                <div className={`p-4 border-t flex items-center justify-between text-xs select-none shrink-0 ${

                  isDark ? 'border-slate-800 text-slate-400' : 'border-slate-200 text-slate-600'

                }`}>

                  <span className="text-[11px] text-slate-500 font-mono">

                    Total {totalRawEvents.toLocaleString()} record{totalRawEvents !== 1 ? 's' : ''} {selectedCategory !== 'ALL' ? `(terfilter ${selectedCategory})` : ''}

                  </span>



                  {/* Pagination Controls */}

                  <div className="flex items-center gap-2">

                    <button

                      type="button"

                      disabled={currentPage <= 1 || tableLoading}

                      onClick={() => setCurrentPage(prev => Math.max(1, prev - 1))}

                      className={`px-3 py-1.5 rounded-lg border font-semibold transition-colors cursor-pointer disabled:opacity-40 disabled:cursor-not-allowed ${

                        isDark ? 'border-slate-800 hover:bg-slate-850 text-slate-300' : 'border-slate-300 hover:bg-slate-100 text-slate-700'

                      }`}

                    >

                      Previous

                    </button>



                    <span className="px-2 font-mono text-xs text-slate-400 font-semibold">

                      {currentPage} / {totalPages.toLocaleString()}

                    </span>



                    <button

                      type="button"

                      disabled={currentPage >= totalPages || tableLoading}

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



                            {/* Right: Forensic Slide-Over Detail Drawer (Proportional & Clean Hierarchy) */}

              {selectedAlert && (

                <div className={`w-[410px] xl:w-[440px] shrink-0 border rounded-2xl p-4.5 flex flex-col justify-between space-y-4 shadow-xl animate-in slide-in-from-right-4 duration-150 ${

                  isDark 

                    ? 'bg-[#0a0e1a] border-slate-800 text-white' 

                    : 'bg-white border-slate-200 text-black shadow-lg'

                }`}>

                  {/* Header */}

                  <div className={`flex items-center justify-between pb-3 border-b shrink-0 ${

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



                  <div className="flex-1 flex flex-col space-y-3.5 text-xs min-h-0 pt-0.5">

                    {/* Primary Details Box */}

                    <div className={`p-4 rounded-xl border space-y-3 text-[11px] shrink-0 ${

                      isDark ? 'bg-slate-950/70 border-slate-800' : 'bg-slate-50 border-slate-200'

                    }`}>

                      {/* ID Alert */}

                      <div>

                        <span className={`block text-[10px] uppercase font-semibold tracking-wider ${isDark ? 'text-slate-400' : 'text-slate-500'}`}>

                          ID Alert:

                        </span>

                        <div className="flex items-center justify-between mt-1">

                          <span className={`font-mono font-bold text-xs select-all break-all ${isDark ? 'text-blue-400' : 'text-blue-600'}`}>

                            {selectedAlert.wazuh_id || selectedAlert.id}

                          </span>

                          <button

                            type="button"

                            onClick={() => handleCopyLog(selectedAlert.wazuh_id || selectedAlert.id, 'copy_id')}

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



                      {/* Timestamp & Tenant (Independent flex spacing - no collision) */}

                      <div className="grid grid-cols-12 gap-2 pt-2.5 border-t border-slate-200 dark:border-slate-800/80 items-start">

                        <div className="col-span-8">

                          <span className={`block text-[10px] uppercase font-semibold tracking-wider ${isDark ? 'text-slate-400' : 'text-slate-500'}`}>

                            Timestamp:

                          </span>

                          <span className={`font-mono font-bold text-xs block mt-0.5 ${isDark ? 'text-white' : 'text-slate-900'} whitespace-nowrap`}>

                            {selectedAlert.timestamp_formatted || (selectedAlert.timestamp ? new Date(selectedAlert.timestamp).toLocaleString('id-ID') : '-')}

                          </span>

                        </div>

                        <div className="col-span-4 text-right">

                          <span className={`block text-[10px] uppercase font-semibold tracking-wider ${isDark ? 'text-slate-400' : 'text-slate-500'}`}>

                            Tenant:

                          </span>

                          <span className="font-mono font-bold text-xs block mt-0.5 text-cyan-600 dark:text-cyan-400 truncate" title={selectedAlert.tenant_id}>

                            {selectedAlert.tenant_id || selectedCampaign?.tenant_id || 'DEFAULT'}

                          </span>

                        </div>

                      </div>



                      {/* Rule & Level + Actor */}

                      <div className="grid grid-cols-12 gap-2 pt-2.5 border-t border-slate-200 dark:border-slate-800/80 items-start">

                        <div className="col-span-6">

                          <span className={`block text-[10px] uppercase font-semibold tracking-wider ${isDark ? 'text-slate-400' : 'text-slate-500'}`}>

                            Rule & Level:

                          </span>

                          <span className={`font-mono font-bold text-xs block mt-0.5 ${isDark ? 'text-amber-400' : 'text-amber-600'}`}>

                            Rule {selectedAlert.rule_id} &bull; Lv {selectedAlert.rule_level || 3}

                          </span>

                        </div>

                        <div className="col-span-6 text-right">

                          <span className={`block text-[10px] uppercase font-semibold tracking-wider ${isDark ? 'text-slate-400' : 'text-slate-500'}`}>

                            Actor (IP / User):

                          </span>

                          <span className={`font-mono font-bold text-xs block mt-0.5 truncate ${isDark ? 'text-rose-400' : 'text-rose-600'}`} title={selectedAlert.actor}>

                            {selectedAlert.actor || '-'}

                          </span>

                        </div>

                      </div>



                      {/* Target (Agent/Host) */}

                      <div className="pt-2.5 border-t border-slate-200 dark:border-slate-800/80">

                        <span className={`block text-[10px] uppercase font-semibold tracking-wider ${isDark ? 'text-slate-400' : 'text-slate-500'}`}>

                          Target (Agent/Host):

                        </span>

                        <span className={`font-mono font-bold text-xs block mt-0.5 ${isDark ? 'text-white' : 'text-slate-900'} break-all`}>

                          {selectedAlert.target || selectedCampaign?.target_host || '-'}

                        </span>

                      </div>



                      {/* Rule Description */}

                      <div className="pt-2.5 border-t border-slate-200 dark:border-slate-800/80">

                        <span className={`block text-[10px] uppercase font-semibold tracking-wider ${isDark ? 'text-slate-400' : 'text-slate-500'}`}>

                          Rule Description:

                        </span>

                        <span className={`font-medium text-xs block mt-1 leading-relaxed ${isDark ? 'text-slate-300' : 'text-slate-700'}`}>

                          {selectedAlert.rule_description || selectedAlert.evidence_summary || '-'}

                        </span>

                      </div>

                    </div>



                    {/* Lineage Box */}

                    <div className={`p-4 rounded-xl border space-y-2.5 shrink-0 ${

                      isDark ? 'bg-slate-950 border-slate-800' : 'bg-slate-50 border-slate-200'

                    }`}>

                      <div className="mb-2">

                        <span className={`text-[12px] font-bold uppercase tracking-wider ${

                          isDark ? 'text-white' : 'text-black'

                        }`}>

                          Lineage

                        </span>

                      </div>



                      <div className="space-y-2">

                        {/* ID Campaign */}

                        <div className={`p-2.5 rounded-lg border ${

                          isDark ? 'bg-slate-900 border-slate-800' : 'bg-white border-slate-200 shadow-2xs'

                        }`}>

                          <div className="flex items-center justify-between">

                            <span className={`text-[10px] font-semibold uppercase tracking-wider ${

                              isDark ? 'text-purple-400' : 'text-purple-600'

                            }`}>

                              ID Campaign

                            </span>

                            <button

                              type="button"

                              onClick={() => handleCopyLog(selectedAlert.campaign_id || selectedClusterId || selectedCampaign?.cluster_id, 'copy_camp')}

                              className={`p-0.5 rounded cursor-pointer transition-colors ${

                                isDark ? 'text-slate-400 hover:text-white' : 'text-slate-500 hover:text-black'

                              }`}

                              title="Salin ID Campaign"

                            >

                              {copiedId === 'copy_camp' ? (

                                <Check className="w-3.5 h-3.5 text-emerald-500" />

                              ) : (

                                <Copy className="w-3.5 h-3.5" />

                              )}

                            </button>

                          </div>

                          <span 

                            className={`font-mono text-[11px] font-bold break-all block mt-1 select-all ${

                              isDark ? 'text-purple-300' : 'text-purple-700'

                            }`}

                            title={selectedAlert.campaign_id || selectedClusterId || selectedCampaign?.cluster_id}

                          >

                            {selectedAlert.campaign_id || selectedClusterId || selectedCampaign?.cluster_id || '-'}

                          </span>

                        </div>



                        {/* ID Aggregat Alert */}

                        <div className={`p-2.5 rounded-lg border ${

                          isDark ? 'bg-slate-900 border-slate-800' : 'bg-white border-slate-200 shadow-2xs'

                        }`}>

                          <div className="flex items-center justify-between">

                            <span className={`text-[10px] font-semibold uppercase tracking-wider ${

                              isDark ? 'text-slate-400' : 'text-slate-500'

                            }`}>

                              ID Aggregat Alert

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

                              Cumulative ID

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

                              ID Tiket (Triage)

                            </span>

                            <div className="flex items-center gap-1">

                              {selectedAlert.ticket_id && (

                                <button

                                  type="button"

                                  onClick={() => {

                                    if (typeof onNavigate === 'function') {

                                      onNavigate('triage', { search: selectedAlert.ticket_id });

                                    }

                                  }}

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

                              title="Klik untuk membuka tiket ini di Ticket Queue"

                            >

                              {selectedAlert.ticket_id} ↗

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



                    {/* Full Log Payload */}

                    <div className="flex-1 flex flex-col min-h-[140px] pt-0.5">

                      <div className="flex items-center justify-between mb-1.5 shrink-0">

                        <span className={`text-[11px] font-semibold uppercase tracking-wider ${

                          isDark ? 'text-slate-400' : 'text-slate-500'

                        }`}>

                          Full Log Payload:

                        </span>

                        <button

                          type="button"

                          onClick={() => handleCopyLog(selectedAlert.full_log, selectedAlert.wazuh_id || selectedAlert.id)}

                          className={`flex items-center gap-1 text-[11px] font-mono font-bold cursor-pointer transition-colors ${

                            isDark ? 'text-white hover:text-slate-300' : 'text-black hover:text-slate-700'

                          }`}

                        >

                          {copiedId === (selectedAlert.wazuh_id || selectedAlert.id) ? (

                            <>

                              <Check className="w-3.5 h-3.5 text-emerald-500" />

                              <span>Tersalin!</span>

                            </>

                          ) : (

                            <>

                              <Copy className="w-3.5 h-3.5" />

                              <span>Salin Payload</span>

                            </>

                          )}

                        </button>

                      </div>

                      <pre className={`raw-log-viewer flex-1 p-3 rounded-xl border font-mono text-[10.5px] leading-relaxed break-all whitespace-pre-wrap select-all overflow-y-auto ${

                        isDark 

                          ? 'bg-black border-slate-800 text-white' 

                          : 'bg-slate-50 border-slate-300 text-black'

                      }`}>

                        {selectedAlert.full_log || 'Tidak ada payload log mentah.'}

                      </pre>

                    </div>

                  </div>

                </div>

              )}

                      </div>

                    </div>

                  )}

                </div>

              );

            })}

          </div>

        )}

      </div>



      {/* CUSTOM THREAT CAMPAIGNS MODAL / DOSSIER EXPLORER */}

      {isCustomModalOpen && (

        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/70 backdrop-blur-xs animate-in fade-in duration-200">

          <div className={`w-full max-w-4xl max-h-[85vh] rounded-2xl border shadow-2xl flex flex-col overflow-hidden ${

            isDark ? 'bg-[#0f172a] border-slate-700 text-white' : 'bg-white border-slate-200 text-slate-900'

          }`}>

            {/* Modal Header */}

            <div className={`p-4 border-b flex items-center justify-between shrink-0 ${

              isDark ? 'bg-[#0b1120] border-slate-800' : 'bg-slate-50 border-slate-200'

            }`}>

              <div className="flex items-center gap-3">

                <div className="p-2 rounded-xl bg-blue-600 text-white shadow-sm">

                  <Folder className="w-5 h-5" />

                </div>

                <div>

                  <h2 className="text-sm font-bold tracking-wide">

                    Custom Threat Campaigns

                  </h2>

                  <p className="text-[11px] text-slate-400">

                    Daftar dossier kampanye yang telah disimpan dari eksplorasi Victim

                  </p>

                </div>

              </div>

              <div className="flex items-center gap-2">

                <button

                  type="button"

                  onClick={fetchCustomCampaigns}

                  disabled={loadingCustom}

                  className={`p-1.5 rounded-lg border text-xs cursor-pointer transition-colors ${

                    isDark ? 'border-slate-700 hover:bg-slate-800 text-slate-300' : 'border-slate-300 hover:bg-slate-100 text-slate-700'

                  }`}

                  title="Refresh"

                >

                  <RefreshCw className={`w-4 h-4 ${loadingCustom ? 'animate-spin' : ''}`} />

                </button>

                <button

                  type="button"

                  onClick={() => setIsCustomModalOpen(false)}

                  className="p-1.5 rounded-lg text-slate-400 hover:text-white cursor-pointer transition-colors"

                >

                  <X className="w-5 h-5" />

                </button>

              </div>

            </div>



            {/* Notification Toast */}

            {customToast && (

              <div className="px-4 py-2 bg-emerald-500/10 border-b border-emerald-500/20 text-emerald-400 text-xs flex items-center gap-2">

                <CheckCircle2 className="w-4 h-4 shrink-0" />

                <span>{customToast}</span>

              </div>

            )}



            {/* Folder Filter & Search Bar */}

            <div className={`px-4 py-3 border-b flex flex-wrap items-center justify-between gap-3 shrink-0 ${

              isDark ? 'bg-[#090d16] border-slate-800' : 'bg-white border-slate-200'

            }`}>

              {/* Folder Pills */}

              <div className="flex items-center gap-1.5 overflow-x-auto pb-1 max-w-full">

                <button

                  type="button"

                  onClick={() => setSelectedCustomFolder('ALL')}

                  className={`px-3 py-1 rounded-lg text-xs font-semibold cursor-pointer whitespace-nowrap transition-colors ${

                    selectedCustomFolder === 'ALL'

                      ? 'bg-blue-600 text-white shadow-xs'

                      : (isDark ? 'bg-slate-800 text-slate-300 hover:bg-slate-700' : 'bg-slate-100 text-slate-700 hover:bg-slate-200')

                  }`}

                >

                  Semua Folder ({customCampaigns.length})

                </button>

                {customFolders.map(folder => {

                  const count = customCampaigns.filter(c => c.folder_name === folder).length;

                  return (

                    <button

                      key={folder}

                      type="button"

                      onClick={() => setSelectedCustomFolder(folder)}

                      className={`px-3 py-1 rounded-lg text-xs font-semibold cursor-pointer whitespace-nowrap transition-colors flex items-center gap-1.5 ${

                        selectedCustomFolder === folder

                          ? 'bg-blue-600 text-white shadow-xs'

                          : (isDark ? 'bg-slate-800 text-slate-300 hover:bg-slate-700' : 'bg-slate-100 text-slate-700 hover:bg-slate-200')

                      }`}

                    >

                      <Folder className="w-3 h-3 text-amber-400" />

                      <span>{folder}</span>

                      <span className="text-[10px] px-1.5 py-0.2 rounded-full bg-slate-900/40 text-slate-300">

                        {count}

                      </span>

                    </button>

                  );

                })}

              </div>



              {/* Search in custom campaigns */}

              <div className="relative min-w-[240px]">

                <div className="w-full relative flex items-center bg-white dark:bg-[#090d16] border-2 border-[#3B5BFF] rounded-full h-[38px] pl-3.5 pr-1.5 shadow-2xs group focus-within:ring-2 focus-within:ring-[#3B5BFF]/30 transition-all">

                  <Search className="w-4 h-4 text-slate-400 shrink-0 mr-2.5 stroke-[2]" />

                  <input

                    type="text"

                    value={customSearchQuery}

                    onChange={(e) => setCustomSearchQuery(e.target.value)}

                    placeholder="Cari file, folder, korban..."

                    className="w-full bg-transparent text-slate-800 dark:text-slate-200 placeholder:text-slate-400 text-xs sm:text-[13px] font-normal focus:outline-none"

                  />

                  {customSearchQuery && (

                    <button

                      type="button"

                      onClick={() => setCustomSearchQuery('')}

                      className="text-slate-400 hover:text-slate-600 dark:hover:text-slate-200 cursor-pointer p-1 mr-1"

                      title="Clear search"

                    >

                      <X className="w-3.5 h-3.5" />

                    </button>

                  )}

                  <button

                    type="button"

                    className="w-7 h-7 rounded-full bg-[#3B5BFF] hover:bg-[#2D4BEB] flex items-center justify-center shrink-0 cursor-pointer transition-transform hover:scale-105 shadow-xs"

                    title="Search"

                  >

                    <Search className="w-3.5 h-3.5 text-white" strokeWidth={2.5} />

                  </button>

                </div>

              </div>

            </div>



            {/* Campaign Dossier List Content */}

            <div className="flex-1 overflow-y-auto p-4 space-y-4">

              {loadingCustom ? (

                <div className="flex flex-col items-center justify-center py-16 gap-3 text-slate-400">

                  <RefreshCw className="w-6 h-6 animate-spin text-blue-500" />

                  <span className="text-xs">Memuat custom campaigns...</span>

                </div>

              ) : filteredCustomCampaigns.length === 0 ? (

                <div className="flex flex-col items-center justify-center py-16 text-center space-y-3">

                  <div className={`p-4 rounded-2xl ${isDark ? 'bg-slate-800/60' : 'bg-slate-100'}`}>

                    <Folder className="w-10 h-10 text-slate-400" />

                  </div>

                  <div>

                    <h4 className="font-semibold text-sm">Belum Ada Custom Campaign</h4>

                    <p className="text-xs text-slate-400 max-w-sm mt-1">

                      Buka tab <strong>Victim</strong>, cari target korban beserta rentang waktunya, lalu klik tombol <strong>+ Add</strong> untuk menyimpan dossier campaign ke dalam folder.

                    </p>

                  </div>

                </div>

              ) : (

                /* Grouped by Folder */

                Object.entries(groupedCustomCampaigns).map(([folderName, items]) => (

                  <div 

                    key={folderName}

                    className={`rounded-xl border overflow-hidden ${

                      isDark ? 'bg-[#090d16] border-slate-800' : 'bg-white border-slate-200 shadow-xs'

                    }`}

                  >

                    {/* Folder Banner */}

                    <div className={`px-4 py-2.5 border-b flex items-center justify-between ${

                      isDark ? 'bg-slate-900/60 border-slate-800 text-slate-200' : 'bg-slate-50 border-slate-200 text-slate-800'

                    }`}>

                      <div className="flex items-center gap-2">

                        <Folder className="w-4 h-4 text-amber-400 fill-amber-400/20" />

                        <span className="font-bold text-xs uppercase tracking-wider">{folderName}</span>

                        <span className={`text-[10px] px-2 py-0.5 rounded-full font-semibold ${

                          isDark ? 'bg-slate-800 text-slate-400' : 'bg-slate-200 text-slate-600'

                        }`}>

                          {items.length} Campaign File

                        </span>

                      </div>

                    </div>



                    {/* Files inside Folder */}

                    <div className="divide-y divide-slate-800/50">

                      {items.map((camp) => (

                        <div

                          key={camp.id}

                          className={`p-4 flex flex-col md:flex-row md:items-center justify-between gap-3 transition-colors ${

                            isDark ? 'hover:bg-slate-900/30' : 'hover:bg-slate-50'

                          }`}

                        >

                          <div className="space-y-1.5">

                            <div className="flex items-center gap-2 flex-wrap">

                              <span className="font-mono font-bold text-xs text-blue-400">

                                {camp.file_name}

                              </span>

                              <span className={`text-[10px] px-2 py-0.5 rounded font-mono ${

                                isDark ? 'bg-slate-800 text-slate-400' : 'bg-slate-100 text-slate-600'

                              }`}>

                                ID: {camp.id}

                              </span>

                            </div>



                            <div className="flex flex-wrap items-center gap-2 text-[11px] text-slate-400">

                              <span className="flex items-center gap-1 font-semibold text-rose-400 bg-rose-500/10 px-2 py-0.5 rounded border border-rose-500/20">

                                <Target className="w-3 h-3" />

                                {camp.victim_target}

                              </span>

                              <span className="flex items-center gap-1 text-slate-300 bg-slate-800 px-2 py-0.5 rounded">

                                <Clock className="w-3 h-3 text-cyan-400" />

                                {camp.time_range === 'custom' 

                                  ? `${camp.custom_start?.slice(0, 10)} - ${camp.custom_end?.slice(0, 10)}` 

                                  : camp.time_range}

                              </span>

                              <span className="flex items-center gap-1 font-semibold text-emerald-400 bg-emerald-500/10 px-2 py-0.5 rounded border border-emerald-500/20">

                                <ShieldAlert className="w-3 h-3" />

                                {(camp.total_alerts || 0).toLocaleString()} alerts

                              </span>

                              <span className="text-[10px] text-slate-500">

                                Dibuat: {camp.created_at ? new Date(camp.created_at).toLocaleString('id-ID') : '-'}

                              </span>

                            </div>



                            {camp.description && (

                              <p className="text-[11px] text-slate-400 italic">

                                "{camp.description}"

                              </p>

                            )}

                          </div>



                          {/* Actions */}

                          <div className="flex items-center gap-2 shrink-0">

                            <button

                              type="button"

                              onClick={() => handleOpenCustomCampaign(camp)}

                              className="px-3 py-1.5 rounded-lg bg-blue-600 hover:bg-blue-500 text-white text-xs font-semibold cursor-pointer shadow-xs transition-colors flex items-center gap-1"

                              title="Buka alert korban ini di halaman Victim"

                            >

                              <ExternalLink className="w-3.5 h-3.5" />

                              <span>Lihat Alerts</span>

                            </button>

                            <button

                              type="button"

                              onClick={(e) => handleDeleteCustomCampaign(camp.id, e)}

                              disabled={deletingId === camp.id}

                              className={`p-1.5 rounded-lg border text-rose-400 hover:bg-rose-500/10 border-rose-500/30 cursor-pointer transition-colors ${

                                deletingId === camp.id ? 'opacity-50' : ''

                              }`}

                              title="Hapus campaign ini"

                            >

                              <X className="w-4 h-4" />

                            </button>

                          </div>

                        </div>

                      ))}

                    </div>

                  </div>

                ))

              )}

            </div>

          </div>

        </div>

      )}



    </div>

  );

}

