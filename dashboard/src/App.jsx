import React, { useState, useEffect, useRef, useMemo } from 'react';

import { 

  Shield, LayoutGrid, Filter, AlertCircle, ChevronDown, Database, 

  Layers, Inbox, CheckCircle2, ShieldAlert, History, Activity, 

  Sliders, User, UserCheck, RefreshCw, BarChart2, Radio, Sun, Moon,

  Users, Globe, Server, Calendar, Lock, X, AlertTriangle, LogOut,

  Menu, Brain, Building2, Network, UserX, Target

} from 'lucide-react';

import PipelineOverview from './components/PipelineOverview';

import SuppressionGovernance from './components/SuppressionGovernance';

import IncidentTriageQueue, { globalTriageCache, normalizeStatus } from './components/IncidentTriageQueue';

import ThreatCampaignsView from './components/ThreatCampaignsView';

import ThreatCampaignEntityTable from './components/ThreatCampaignEntityTable';

import SystemMaintenance, { initialRbacMatrixData } from './components/SystemMaintenance';

import GroundTruthReview from './components/GroundTruthReview';

import LoginPage from './components/LoginPage';

import RawAlertsQueue from './components/RawAlertsQueue';

import ClusteringOverview from './components/ClusteringOverview';

import VulnerabilityOverview from './components/VulnerabilityOverview';

import SystemIntegrityOverview from './components/SystemIntegrityOverview';

import AttackOverview from './components/AttackOverview';

import logoImg from './assets/logo.png';

import { canAccessTab, isTabReadOnly, normalizeRole } from './utils/rbac';



export default function App() {

  const [currentUser, setCurrentUser] = useState(() => {

    try {

      const saved = localStorage.getItem('wazuh_soc_user');

      return saved ? JSON.parse(saved) : null;

    } catch {

      return null;

    }

  });



  const handleLogout = () => {

    localStorage.removeItem('wazuh_soc_token');

    localStorage.removeItem('wazuh_soc_user');

    setCurrentUser(null);

  };



  const userRole = normalizeRole(currentUser?.role || 'ADMIN');

  const hasAccess = (tabId) => canAccessTab(userRole, tabId, initialRbacMatrixData);

  const isReadOnly = (tabId) => isTabReadOnly(userRole, tabId, initialRbacMatrixData);



  const [activeTab, setActiveTab] = useState('analytics');



  // Auto-redirect if active tab is restricted for current role

  useEffect(() => {

    if (currentUser && !hasAccess(activeTab)) {

      const candidateTabs = [

        'analytics', 'raw_alerts', 'triage', 'verified_tp',

        'groundtruth_queue', 'ground_truth_review', 'suppression_groups',

        'suppression_audit', 'graph_conclusion', 'threat_actor', 'threat_victim',

        'system_rbac', 'system_database', 'system_api'

      ];

      const firstAllowed = candidateTabs.find(t => hasAccess(t)) || 'analytics';

      setActiveTab(firstAllowed);

    }

  }, [userRole, currentUser]);



  const [fpPendingCount, setFpPendingCount] = useState(0);

  const [activeTicketCount, setActiveTicketCount] = useState(0);

  const [gtWaitingCount, setGtWaitingCount] = useState(0);

  const [triageSearch, setTriageSearch] = useState('');



  const handleNavigate = (tab, options = {}) => {

    if (options && options.search) {

      setTriageSearch(options.search);

    }

    setActiveTab(tab);

  };

  const [timeRange, setTimeRange] = useState('semua'); // 'hari', 'minggu', 'bulan', 'semua', 'custom'

  const [customStartDate, setCustomStartDate] = useState('2026-10-16 00:00');

  const [customEndDate, setCustomEndDate] = useState('2026-10-20 23:59');

  const [tempStartDate, setTempStartDate] = useState('2026-10-16');

  const [tempStartTime, setTempStartTime] = useState('00:00');

  const [tempEndDate, setTempEndDate] = useState('2026-10-20');

  const [tempEndTime, setTempEndTime] = useState('23:59');

  const [isTimeDropdownOpen, setIsTimeDropdownOpen] = useState(false);

  const timeDropdownRef = useRef(null);



  const handleSetEndToNow = () => {

    const now = new Date();

    const pad = (n) => String(n).padStart(2, '0');

    const yyyy = now.getFullYear();

    const mm = pad(now.getMonth() + 1);

    const dd = pad(now.getDate());

    const hh = pad(now.getHours());

    const min = pad(now.getMinutes());

    setTempEndDate(`${yyyy}-${mm}-${dd}`);

    setTempEndTime(`${hh}:${min}`);

  };



  const handleOpenCustomRange = () => {

    const parseDT = (val, defaultDate, defaultTime) => {

      if (!val) return { date: defaultDate, time: defaultTime };

      const parts = val.trim().split(/[T ]+/);

      return {

        date: parts[0] || defaultDate,

        time: parts[1] ? parts[1].slice(0, 5) : defaultTime

      };

    };



    const s = parseDT(customStartDate, '2026-10-16', '00:00');

    const e = parseDT(customEndDate, '2026-10-20', '23:59');



    setTempStartDate(s.date);

    setTempStartTime(s.time);

    setTempEndDate(e.date);

    setTempEndTime(e.time);

    setTimeRange('custom');

  };



  const handleApplyCustomRange = () => {

    const sDate = tempStartDate || '2026-10-16';

    const sTime = tempStartTime ? tempStartTime.trim() : '00:00';

    const eDate = tempEndDate || '2026-10-20';

    const eTime = tempEndTime ? tempEndTime.trim() : '23:59';



    const fullStart = `${sDate} ${sTime}`;

    const fullEnd = `${eDate} ${eTime}`;



    setCustomStartDate(fullStart);

    setCustomEndDate(fullEnd);

    setTimeRange('custom');

    setIsTimeDropdownOpen(false);

  };



  // Tenant Multi-Tenancy Filter State

  const [selectedTenant, setSelectedTenant] = useState(() => {

    return localStorage.getItem('wazuh_selected_tenant') || 'ALL';

  });

  const [isTenantDropdownOpen, setIsTenantDropdownOpen] = useState(false);

  const tenantDropdownRef = useRef(null);



  const [isSidebarOpen, setIsSidebarOpen] = useState(() => {

    return localStorage.getItem('asoc_sidebar_open') !== 'false';

  });



  const toggleSidebar = () => {

    setIsSidebarOpen(prev => {

      const next = !prev;

      localStorage.setItem('asoc_sidebar_open', String(next));

      return next;

    });

  };



  const [theme, setTheme] = useState(() => {

    return localStorage.getItem('wazuh_soc_theme') || 'dark';

  });

  const isDark = theme === 'dark';



  useEffect(() => {

    localStorage.setItem('wazuh_selected_tenant', selectedTenant);

  }, [selectedTenant]);



  useEffect(() => {

    const handleClickOutside = (event) => {

      if (timeDropdownRef.current && !timeDropdownRef.current.contains(event.target)) {

        setIsTimeDropdownOpen(false);

      }

      if (tenantDropdownRef.current && !tenantDropdownRef.current.contains(event.target)) {

        setIsTenantDropdownOpen(false);

      }

    };

    document.addEventListener('mousedown', handleClickOutside);

    return () => document.removeEventListener('mousedown', handleClickOutside);

  }, []);



  const [tenantOptions, setTenantOptions] = useState([
    { id: 'ALL', label: 'all' },
    { id: 'DEFAULT', label: 'DEFAULT' },
    { id: 'TenantA', label: 'TenantA' },
    { id: 'TenantB', label: 'TenantB' },
    { id: 'TenantC', label: 'TenantC' },
    { id: 'TenantD', label: 'TenantD' },
  ]);

  useEffect(() => {
    fetch('/api/tenants')
      .then(res => res.json())
      .then(data => {
        if (data && data.tenants && Array.isArray(data.tenants) && data.tenants.length > 0) {
          const dynamicOptions = [{ id: 'ALL', label: 'all' }, ...data.tenants.map(t => ({ id: t, label: t }))];
          setTenantOptions(dynamicOptions);
        }
      })
      .catch(err => console.warn('Could not fetch dynamic tenants, using defaults:', err));
  }, []);



  const getTenantLabel = () => {

    if (selectedTenant === 'ALL') return 'all';

    return selectedTenant;

  };



  const timeOptions = [

    { id: 'semua', label: 'All Time', description: 'Seluruh Telemetri (Juli s.d. Oktober 2026)' },

    { id: 'bulan', label: 'Last 30 Days', description: '30 Hari Terakhir' },

    { id: 'minggu', label: 'Last 7 Days', description: '7 Hari Terakhir' },

    { id: 'hari', label: 'Today', description: 'Hari Ini' },

    { id: 'custom', label: 'Custom Range...', description: 'Pilih rentang tanggal' },

  ];



  const getTimeRangeLabel = () => {

    switch (timeRange) {

      case 'hari':

        return 'Today';

      case 'minggu':

        return 'Last 7 Days';

      case 'bulan':

        return 'Last 30 Days';

      case 'semua':

        return 'All Time';

      case 'custom': {

        const formatPart = (val, defaultTime) => {

          if (!val) return '';

          const parts = val.trim().split(/[T ]+/);

          const d = parts[0];

          const t = parts[1] ? parts[1].slice(0, 5) : defaultTime;

          return `${d} ${t}`;

        };

        const s = formatPart(customStartDate, '00:00');

        const e = formatPart(customEndDate, '23:59');

        return `${s} → ${e}`;

      }

      default:

        return 'Last 7 Days';

    }

  };



  useEffect(() => {

    const root = document.documentElement;

    root.setAttribute('data-theme', theme);

    if (theme === 'light') {

      root.classList.add('light');

      root.classList.remove('dark');

    } else {

      root.classList.add('dark');

      root.classList.remove('light');

    }

    localStorage.setItem('wazuh_soc_theme', theme);

  }, [theme]);



  const toggleTheme = () => {

    setTheme(prev => (prev === 'dark' ? 'light' : 'dark'));

  };



  const fetchCounters = async () => {

    try {

      const fpRes = await fetch('/api/suppression/tuning-requests');

      if (fpRes.ok) {

        const fpJson = await fpRes.json();

        setFpPendingCount(fpJson.total || 0);

      }



      const tRes = await fetch('/api/triage/counts');

      if (tRes.ok) {

        const tJson = await tRes.json();

        setActiveTicketCount(tJson.active_count ?? tJson.total ?? 0);

      }



      const gtRes = await fetch('/api/ground-truth/queue');

      if (gtRes.ok) {

        const gtJson = await gtRes.json();

        setGtWaitingCount(gtJson.total_pending || 0);

      }

    } catch (err) {

      console.warn("Counters polling:", err);

    }

  };



  useEffect(() => {

    fetchCounters();

    const interval = setInterval(fetchCounters, 15000);

    return () => clearInterval(interval);

  }, []);



  // Self-Service Password Change State

  const [isPasswordModalOpen, setIsPasswordModalOpen] = useState(false);

  const [pwForm, setPwForm] = useState({

    username: currentUser?.username || 'admin_secops',

    current_password: '',

    new_password: '',

    confirm_password: ''

  });

  const [pwError, setPwError] = useState('');

  const [pwSuccess, setPwSuccess] = useState('');

  const [pwSubmitting, setPwSubmitting] = useState(false);



  const handleSelfChangePassword = async (e) => {

    e.preventDefault();

    setPwError('');

    setPwSuccess('');



    if (pwForm.new_password !== pwForm.confirm_password) {

      setPwError('Konfirmasi kata sandi baru tidak cocok.');

      return;

    }



    if (pwForm.new_password.length < 8) {

      setPwError('Kata sandi baru minimal harus 8 karakter.');

      return;

    }



    try {

      setPwSubmitting(true);

      const res = await fetch('/api/system/rbac/change-password', {

        method: 'POST',

        headers: { 'Content-Type': 'application/json' },

        body: JSON.stringify({

          username: pwForm.username.trim(),

          current_password: pwForm.current_password,

          new_password: pwForm.new_password

        })

      });

      const data = await res.json();

      if (!res.ok) {

        setPwError(data.detail || 'Gagal mengubah kata sandi.');

      } else {

        setPwSuccess(data.message || 'Kata sandi berhasil diperbarui.');

        setPwForm({

          username: pwForm.username,

          current_password: '',

          new_password: '',

          confirm_password: ''

        });

        setTimeout(() => {

          setIsPasswordModalOpen(false);

          setPwSuccess('');

        }, 1500);

      }

    } catch (err) {

      setPwError('Koneksi backend gagal: ' + err.message);

    } finally {

      setPwSubmitting(false);

    }

  };



  const navItemClass = (tabId) => `

    w-full flex items-center justify-between px-3 py-2 rounded-lg text-xs font-medium transition-colors cursor-pointer text-left

    ${activeTab === tabId 

      ? (theme === 'dark' 

          ? 'bg-slate-800/80 text-white font-semibold shadow-sm border border-slate-700/60' 

          : 'bg-blue-50 text-blue-700 font-semibold shadow-sm border border-blue-200')

      : (theme === 'dark' 

          ? 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/30' 

          : 'text-slate-600 hover:text-slate-900 hover:bg-slate-100')

    }

  `;



  const getBreadcrumb = () => {

    switch (activeTab) {

      case 'analytics':

        return { category: 'MAIN', subcategory: 'ANALYTICS' };

      case 'raw_alerts':

        return { category: 'MAIN', subcategory: 'RAW ALERT' };

      case 'clustering':

        return { category: 'MAIN', subcategory: 'CLUSTERING' };

      case 'category_attack':

        return { category: 'CATEGORIES', subcategory: 'ATTACK' };

      case 'category_vulnerability':

        return { category: 'CATEGORIES', subcategory: 'VULNERABILITY' };

      case 'category_system':

        return { category: 'CATEGORIES', subcategory: 'SYSTEM' };

      case 'triage':

        return { category: 'INCIDENT TRIAGE', subcategory: 'TICKET QUEUE' };

      case 'verified_tp':

        return { category: 'INCIDENT TRIAGE', subcategory: 'VERIFIED THREAT' };

      case 'graph_conclusion':

      case 'threat_campaigns':

        return { category: 'INCIDENT TRIAGE', subcategory: 'GRAPH CONCLUSION' };

      case 'groundtruth_queue':

        return { category: 'INCIDENT TRIAGE', subcategory: 'GROUNDTRUTH' };

      case 'ground_truth_review':

      case 'suppression_inbox':

        return { category: 'SUPPRESSION & TUNING', subcategory: 'GROUND TRUTH REVIEW' };

      case 'suppression_rules':

        return { category: 'SUPPRESSION & TUNING', subcategory: 'APPROVE SUPPRESSION POLICIES' };

      case 'suppression_groups':

        return { category: 'SUPPRESSION', subcategory: 'POLICY BUNDLE' };

      case 'suppression_audit':

        return { category: 'MAIN', subcategory: 'COMPLIANCE AUDIT' };

      case 'system_rbac':

        return { category: 'SYSTEM MAINTENANCE', subcategory: 'MANAJEMEN AKUN & RBAC' };

      case 'system_database':

        return { category: 'SYSTEM MAINTENANCE', subcategory: 'DATABASE & STORAGE HEALTH' };

      case 'system_api':

        return { category: 'SYSTEM MAINTENANCE', subcategory: 'API & QUOTA THREAT INTEL' };

      default:

        return { category: 'MAIN', subcategory: 'ANALYTICS' };

    }

  };



  if (!currentUser) {

    return <LoginPage onLoginSuccess={(user) => setCurrentUser(user)} />;

  }



  return (

    <div className={`min-h-screen font-sans flex antialiased ${

      theme === 'dark' ? 'bg-[#070b14] text-slate-100' : 'bg-[#f1f5f9] text-slate-800'

    }`}>

      {/* Enterprise Left Navigation Rail */}

      {isSidebarOpen && (

        <aside className={`w-64 p-3.5 ${

          theme === 'dark' 

            ? 'bg-[#090d16] border-slate-800/70' 

            : 'bg-white border-slate-200 shadow-sm'

        } border-r flex flex-col justify-between min-h-screen sticky top-0 h-screen select-none shrink-0 overflow-y-auto z-40 transition-all`}>

          <div className="space-y-6">

            {/* Logo & Workspace Brand */}

            <div className={`flex items-center justify-between gap-2 px-2 py-1.5 border-b pb-3 ${

              theme === 'dark' ? 'border-slate-800/60' : 'border-slate-200'

            }`}>

              <div className="flex items-center gap-2.5 min-w-0">

                <img 

                  src={logoImg} 

                  alt="Wazuh ASOC Logo" 

                  className="w-8 h-8 object-contain shrink-0" 

                />

                <div className="min-w-0">

                  <div className={`font-bold text-xs tracking-tight ${

                    theme === 'dark' ? 'text-slate-100' : 'text-slate-900'

                  }`}>

                    WAZUH ASOC

                  </div>

                  <div className={`text-[10px] tracking-wider uppercase font-medium mt-0.5 ${

                    theme === 'dark' ? 'text-slate-500' : 'text-slate-400'

                  }`}>Enterprise SecOps</div>

                </div>

              </div>



              {/* Hamburger Button (3 horizontal lines) beside WAZUH ASOC ENTERPRISE SECOPS */}

              <button

                type="button"

                onClick={toggleSidebar}

                className={`w-8 h-8 rounded-lg border flex items-center justify-center transition-colors cursor-pointer shrink-0 focus:outline-none ${

                  theme === 'dark'

                    ? 'bg-slate-800/80 hover:bg-slate-700 border-slate-700 text-slate-300 hover:text-white'

                    : 'bg-white hover:bg-slate-100 border-slate-200 text-slate-700 hover:text-slate-900 shadow-xs'

                }`}

                title="Sembunyikan Menu Navigasi"

              >

                <Menu className="w-4 h-4 stroke-[2]" />

              </button>

            </div>



          {/* Group 1: MAIN */}

          {(hasAccess('analytics') || hasAccess('raw_alerts') || hasAccess('clustering') || hasAccess('suppression_audit')) && (

            <div>

              <div className="px-2 mb-1.5 text-[10px] font-semibold text-slate-400 tracking-wider uppercase">

                Main

              </div>

              <nav className="space-y-0.5">

                {hasAccess('analytics') && (

                  <button

                    onClick={() => setActiveTab('analytics')}

                    className={navItemClass('analytics')}

                  >

                    <div className="flex items-center gap-2.5 truncate">

                      <LayoutGrid className="w-3.5 h-3.5 shrink-0" />

                      <span className="truncate">Analytics</span>

                    </div>

                    {isReadOnly('analytics') && (

                      <span className="text-[9px] px-1 py-0.2 rounded font-mono font-bold bg-amber-500/10 text-amber-500 border border-amber-500/20 ml-auto shrink-0">RO</span>

                    )}

                  </button>

                )}



                {hasAccess('raw_alerts') && (

                  <button

                    onClick={() => setActiveTab('raw_alerts')}

                    className={navItemClass('raw_alerts')}

                  >

                    <div className="flex items-center gap-2.5 truncate">

                      <Radio className="w-3.5 h-3.5 shrink-0" />

                      <span className="truncate">Raw Alert</span>

                    </div>

                    {isReadOnly('raw_alerts') && (

                      <span className="text-[9px] px-1 py-0.2 rounded font-mono font-bold bg-amber-500/10 text-amber-500 border border-amber-500/20 ml-auto shrink-0">RO</span>

                    )}

                  </button>

                )}



                {hasAccess('clustering') && (

                  <button

                    onClick={() => setActiveTab('clustering')}

                    className={navItemClass('clustering')}

                  >

                    <div className="flex items-center gap-2.5 truncate">

                      <Layers className="w-3.5 h-3.5 shrink-0" />

                      <span className="truncate">Clustering</span>

                    </div>

                    {isReadOnly('clustering') && (

                      <span className="text-[9px] px-1 py-0.2 rounded font-mono font-bold bg-amber-500/10 text-amber-500 border border-amber-500/20 ml-auto shrink-0">RO</span>

                    )}

                  </button>

                )}



                {hasAccess('suppression_audit') && (

                  <button

                    onClick={() => setActiveTab('suppression_audit')}

                    className={navItemClass('suppression_audit')}

                  >

                    <div className="flex items-center gap-2.5 truncate">

                      <History className="w-3.5 h-3.5 shrink-0" />

                      <span className="truncate">Compliance Audit</span>

                    </div>

                    {isReadOnly('suppression_audit') && (

                      <span className="text-[9px] px-1 py-0.2 rounded font-mono font-bold bg-amber-500/10 text-amber-500 border border-amber-500/20 ml-auto shrink-0">RO</span>

                    )}

                  </button>

                )}

              </nav>

            </div>

          )}



          {/* Group: CATEGORIES */}

          {(hasAccess('category_attack') || hasAccess('category_vulnerability') || hasAccess('category_system')) && (

            <div>

              <div className="px-2 mb-1.5 text-[10px] font-semibold text-slate-400 tracking-wider uppercase">

                Categories

              </div>

              <nav className="space-y-0.5">

                {hasAccess('category_attack') && (

                  <button

                    onClick={() => setActiveTab('category_attack')}

                    className={navItemClass('category_attack')}

                  >

                    <div className="flex items-center gap-2.5 truncate">

                      <ShieldAlert className="w-3.5 h-3.5 shrink-0" />

                      <span className="truncate">Attack</span>

                    </div>

                    {isReadOnly('category_attack') && (

                      <span className="text-[9px] px-1 py-0.2 rounded font-mono font-bold bg-amber-500/10 text-amber-500 border border-amber-500/20 ml-auto shrink-0">RO</span>

                    )}

                  </button>

                )}



                {hasAccess('category_vulnerability') && (

                  <button

                    onClick={() => setActiveTab('category_vulnerability')}

                    className={navItemClass('category_vulnerability')}

                  >

                    <div className="flex items-center gap-2.5 truncate">

                      <AlertTriangle className="w-3.5 h-3.5 shrink-0" />

                      <span className="truncate">Vulnerability</span>

                    </div>

                    {isReadOnly('category_vulnerability') && (

                      <span className="text-[9px] px-1 py-0.2 rounded font-mono font-bold bg-amber-500/10 text-amber-500 border border-amber-500/20 ml-auto shrink-0">RO</span>

                    )}

                  </button>

                )}



                {hasAccess('category_system') && (

                  <button

                    onClick={() => setActiveTab('category_system')}

                    className={navItemClass('category_system')}

                  >

                    <div className="flex items-center gap-2.5 truncate">

                      <Server className="w-3.5 h-3.5 shrink-0" />

                      <span className="truncate">System</span>

                    </div>

                    {isReadOnly('category_system') && (

                      <span className="text-[9px] px-1 py-0.2 rounded font-mono font-bold bg-amber-500/10 text-amber-500 border border-amber-500/20 ml-auto shrink-0">RO</span>

                    )}

                  </button>

                )}

              </nav>

            </div>

          )}



          {/* Group 2: INCIDENT TRIAGE & SOC QUEUE */}

          {(hasAccess('triage') || hasAccess('verified_tp') || hasAccess('groundtruth_queue') || hasAccess('graph_conclusion') || hasAccess('threat_campaigns')) && (

            <div>

              <div className="px-2 mb-1.5 text-[10px] font-semibold text-slate-400 tracking-wider uppercase">

                Incident Triage

              </div>

              <nav className="space-y-0.5">

                {hasAccess('triage') && (

                  <button

                    onClick={() => setActiveTab('triage')}

                    className={navItemClass('triage')}

                  >

                    <div className="flex items-center gap-2.5 truncate">

                      <Inbox className="w-3.5 h-3.5 shrink-0" />

                      <span className="truncate">Ticket Queue</span>

                    </div>

                    {isReadOnly('triage') && (

                      <span className="text-[9px] px-1 py-0.2 rounded font-mono font-bold bg-amber-500/10 text-amber-500 border border-amber-500/20 ml-auto shrink-0">RO</span>

                    )}

                  </button>

                )}



                {hasAccess('groundtruth_queue') && (

                  <button

                    onClick={() => setActiveTab('groundtruth_queue')}

                    className={navItemClass('groundtruth_queue')}

                  >

                    <div className="flex items-center gap-2.5 truncate">

                      <Brain className="w-3.5 h-3.5 shrink-0" />

                      <span className="truncate">Groundtruth</span>

                    </div>

                    {isReadOnly('groundtruth_queue') && (

                      <span className="text-[9px] px-1 py-0.2 rounded font-mono font-bold bg-amber-500/10 text-amber-500 border border-amber-500/20 ml-auto shrink-0">RO</span>

                    )}

                  </button>

                )}



                {hasAccess('verified_tp') && (

                  <button

                    onClick={() => setActiveTab('verified_tp')}

                    className={navItemClass('verified_tp')}

                  >

                    <div className="flex items-center gap-2.5 truncate">

                      <CheckCircle2 className="w-3.5 h-3.5 shrink-0" />

                      <span className="truncate">Verified Threat</span>

                    </div>

                    {isReadOnly('verified_tp') && (

                      <span className="text-[9px] px-1 py-0.2 rounded font-mono font-bold bg-amber-500/10 text-amber-500 border border-amber-500/20 ml-auto shrink-0">RO</span>

                    )}

                  </button>

                )}



                {(hasAccess('graph_conclusion') || hasAccess('threat_campaigns')) && (

                  <button

                    onClick={() => setActiveTab('graph_conclusion')}

                    className={navItemClass('graph_conclusion')}

                  >

                    <div className="flex items-center gap-2.5 truncate">

                      <Network className="w-3.5 h-3.5 shrink-0" />

                      <span className="truncate">Graph Conclusion</span>

                    </div>

                    {isReadOnly('graph_conclusion') && (

                      <span className="text-[9px] px-1 py-0.2 rounded font-mono font-bold bg-amber-500/10 text-amber-500 border border-amber-500/20 ml-auto shrink-0">RO</span>

                    )}

                  </button>

                )}

              </nav>

            </div>

          )}



          {/* Group 3: SUPPRESSION & TUNING GOVERNANCE */}

          {(hasAccess('ground_truth_review') || hasAccess('suppression_groups')) && (

            <div>

              <div className="px-2 mb-1.5 text-[10px] font-semibold text-slate-400 tracking-wider uppercase">

                Suppression & Tuning

              </div>

              <nav className="space-y-0.5">

                {hasAccess('ground_truth_review') && (

                  <button

                    onClick={() => setActiveTab('ground_truth_review')}

                    className={navItemClass('ground_truth_review')}

                  >

                    <div className="flex items-center gap-2.5 truncate">

                      <Sliders className="w-3.5 h-3.5 shrink-0" />

                      <span className="truncate">Ground Truth Review</span>

                    </div>

                    {gtWaitingCount > 0 && (

                      <span className="px-1.5 py-0.5 rounded-full text-[10px] font-bold bg-amber-500/20 text-amber-400 border border-amber-500/30">

                        {gtWaitingCount}

                      </span>

                    )}

                    {isReadOnly('ground_truth_review') && (

                      <span className="text-[9px] px-1 py-0.2 rounded font-mono font-bold bg-amber-500/10 text-amber-500 border border-amber-500/20 ml-auto shrink-0">RO</span>

                    )}

                  </button>

                )}



                {hasAccess('suppression_groups') && (

                  <button

                    onClick={() => setActiveTab('suppression_groups')}

                    className={navItemClass('suppression_groups')}

                  >

                    <div className="flex items-center gap-2.5 truncate">

                      <Layers className="w-3.5 h-3.5 shrink-0" />

                      <span className="truncate">Policy Bundle</span>

                    </div>

                    {isReadOnly('suppression_groups') && (

                      <span className="text-[9px] px-1 py-0.2 rounded font-mono font-bold bg-amber-500/10 text-amber-500 border border-amber-500/20 ml-auto shrink-0">RO</span>

                    )}

                  </button>

                )}

              </nav>

            </div>

          )}





          {/* Group 5: SYSTEM & SOC MAINTENANCE */}

          {(hasAccess('system_rbac') || hasAccess('system_database') || hasAccess('system_api')) && (

            <div>

              <div className="px-2 mb-1.5 text-[10px] font-semibold text-slate-400 tracking-wider uppercase">

                System Maintenance

              </div>

              <nav className="space-y-0.5">

                {hasAccess('system_rbac') && (

                  <button

                    onClick={() => setActiveTab('system_rbac')}

                    className={navItemClass('system_rbac')}

                  >

                    <div className="flex items-center gap-2.5 truncate">

                      <Users className="w-3.5 h-3.5 shrink-0" />

                      <span className="truncate">Manajemen Akun & RBAC</span>

                    </div>

                    {isReadOnly('system_rbac') && (

                      <span className="text-[9px] px-1 py-0.2 rounded font-mono font-bold bg-amber-500/10 text-amber-500 border border-amber-500/20 ml-auto shrink-0">RO</span>

                    )}

                  </button>

                )}



                {hasAccess('system_database') && (

                  <button

                    onClick={() => setActiveTab('system_database')}

                    className={navItemClass('system_database')}

                  >

                    <div className="flex items-center gap-2.5 truncate">

                      <Database className="w-3.5 h-3.5 shrink-0" />

                      <span className="truncate">Database & Storage Health</span>

                    </div>

                    {isReadOnly('system_database') && (

                      <span className="text-[9px] px-1 py-0.2 rounded font-mono font-bold bg-amber-500/10 text-amber-500 border border-amber-500/20 ml-auto shrink-0">RO</span>

                    )}

                  </button>

                )}



                {hasAccess('system_api') && (

                  <button

                    onClick={() => setActiveTab('system_api')}

                    className={navItemClass('system_api')}

                  >

                    <div className="flex items-center gap-2.5 truncate">

                      <Globe className="w-3.5 h-3.5 shrink-0" />

                      <span className="truncate">API & Quota Threat Intel</span>

                    </div>

                    {isReadOnly('system_api') && (

                      <span className="text-[9px] px-1 py-0.2 rounded font-mono font-bold bg-amber-500/10 text-amber-500 border border-amber-500/20 ml-auto shrink-0">RO</span>

                    )}

                  </button>

                )}

              </nav>

            </div>

          )}

        </div>



        {/* Footer: User Profile & Logout (Menggantikan 19 Tables Active) */}

        <div className={`pt-3 border-t mt-auto ${theme === 'dark' ? 'border-slate-800/60' : 'border-slate-200'}`}>

          <div className={`p-2.5 rounded-xl border space-y-2.5 transition-colors ${

            theme === 'dark' 

              ? 'bg-[#0c101c] border-slate-800/80' 

              : 'bg-white border-slate-200 shadow-sm'

          }`}>

            {/* User Info & Password Modal Trigger */}

            <div className="flex items-center justify-between gap-2">

              <button

                type="button"

                onClick={() => {

                  setPwForm(prev => ({ ...prev, username: currentUser?.username || 'admin_secops' }));

                  setPwError('');

                  setPwSuccess('');

                  setIsPasswordModalOpen(true);

                }}

                className="flex items-center gap-2 min-w-0 text-left hover:opacity-85 transition-opacity cursor-pointer group flex-1"

                title="Klik untuk Ganti Kata Sandi Akun"

              >

                <div className={`w-8 h-8 rounded-lg flex items-center justify-center text-xs font-bold shrink-0 ${

                  theme === 'dark'

                    ? 'bg-blue-500/20 text-blue-400 border border-blue-500/30'

                    : 'bg-blue-50 text-blue-600 border border-blue-200'

                }`}>

                  <User className="w-4 h-4" />

                </div>

                <div className="min-w-0 flex-1">

                  <div className={`text-xs font-semibold truncate ${

                    theme === 'dark' ? 'text-slate-200' : 'text-slate-800'

                  }`}>

                    <span className="truncate">@{currentUser?.username || 'admin_secops'}</span>

                  </div>

                  <div className={`text-[9px] font-mono font-medium tracking-wide truncate mt-0.5 ${

                    theme === 'dark' ? 'text-slate-400' : 'text-slate-500'

                  }`}>

                    <span>{currentUser?.role || 'ADMIN'}</span>

                  </div>

                </div>

              </button>

            </div>



            {/* Tombol Keluar (Logout) */}

            <button

              type="button"

              onClick={handleLogout}

              className={`w-full py-1.5 px-2.5 rounded-lg border text-xs font-semibold flex items-center justify-center gap-1.5 transition-colors cursor-pointer ${

                theme === 'dark'

                  ? 'bg-red-500/10 hover:bg-red-500/20 border-red-500/30 text-red-300 hover:text-red-200'

                  : 'bg-red-50 hover:bg-red-100 border-red-200 text-red-700'

              }`}

              title="Keluar dari Dashboard (Logout)"

            >

              <LogOut className="w-3.5 h-3.5" />

              <span>Keluar</span>

            </button>

          </div>

        </div>

      </aside>

    )}



      {/* Main Viewport */}

      <div className={`flex-1 flex flex-col min-w-0 relative ${

        theme === 'dark' ? 'bg-[#070b14]' : 'bg-[#f1f5f9]'

      }`}>

        {/* Sleek Top Navbar */}

        <header className={`h-14 border-b px-6 flex items-center justify-between sticky top-0 backdrop-blur-sm z-30 transition-colors ${

          theme === 'dark' 

            ? 'bg-[#070b14]/95 border-slate-800/70 text-slate-100' 

            : 'bg-white/95 border-slate-200 shadow-xs text-slate-800'

        }`}>

          {/* Left: Reopen Hamburger (if closed) & Breadcrumb */}

          <div className="flex items-center gap-3">

            {!isSidebarOpen && (

              <button

                type="button"

                onClick={toggleSidebar}

                className={`w-9 h-9 rounded-lg border flex items-center justify-center transition-colors cursor-pointer shadow-xs focus:outline-none ${

                  theme === 'dark'

                    ? 'bg-[#0c101c] hover:bg-slate-800 border-slate-800 text-slate-200 hover:text-white'

                    : 'bg-white hover:bg-slate-50 border-slate-200 text-slate-700 hover:text-slate-900'

                }`}

                title="Tampilkan Menu Fitur (Buka Sidebar)"

              >

                <Menu className="w-4 h-4 stroke-[2]" />

              </button>

            )}



            {/* Breadcrumb & Context: KATEGORI / SUBKATEGORI */}

            <div className="flex items-center gap-2 text-xs">

              <span className={`font-semibold tracking-wider uppercase ${

                theme === 'dark' ? 'text-slate-400' : 'text-slate-500'

              }`}>

                {getBreadcrumb().category}

              </span>

              <span className={theme === 'dark' ? 'text-slate-600 font-bold' : 'text-slate-400 font-bold'}>/</span>

              <span className={`font-bold tracking-wider uppercase ${

                theme === 'dark' ? 'text-slate-100' : 'text-slate-900'

              }`}>

                {getBreadcrumb().subcategory}

              </span>

            </div>

          </div>



          {/* Right Controls: Theme Switcher & Operator Profile */}

          <div className="flex items-center gap-2.5">

            {/* Theme Toggle Button */}

            <button

              onClick={toggleTheme}

              className="p-1.5 bg-transparent border-0 shadow-none cursor-pointer flex items-center justify-center transition-colors text-slate-600 dark:text-slate-300 hover:text-indigo-600 dark:hover:text-amber-400 focus:outline-none"

              title={theme === 'dark' ? 'Beralih ke Mode Terang' : 'Beralih ke Mode Gelap'}

            >

              {theme === 'dark' ? (

                <Sun className="w-4 h-4 text-amber-400" />

              ) : (

                <Moon className="w-4 h-4 text-indigo-600" />

              )}

            </button>



            {/* Multi-Tenant Filter Dropdown (Format Identical to Time Filter) */}

            <div className="relative" ref={tenantDropdownRef}>

              <button

                type="button"

                onClick={() => setIsTenantDropdownOpen(prev => !prev)}

                className={`flex items-center justify-between gap-2.5 px-3 py-1.5 rounded-md text-xs font-mono font-medium border transition-all cursor-pointer min-w-[165px] shadow-xs ${

                  theme === 'dark'

                    ? 'bg-[#0c101c] border-slate-800 text-slate-200 hover:bg-slate-800/80 hover:border-slate-700'

                    : 'bg-white border-slate-200 text-slate-800 hover:bg-slate-50 hover:border-slate-300'

                }`}

                title="Pilih Tenant"

              >

                <div className="flex items-center gap-2 truncate">

                  <Building2 className="w-3.5 h-3.5 text-indigo-500 shrink-0" />

                  <span className="truncate">{getTenantLabel()}</span>

                </div>

                <ChevronDown className={`w-3.5 h-3.5 text-slate-400 shrink-0 transition-transform duration-200 ${

                  isTenantDropdownOpen ? 'rotate-180 text-indigo-500' : ''

                }`} />

              </button>



              {/* Tenant Dropdown Menu matching Time Filter style */}

              {isTenantDropdownOpen && (

                <div className={`absolute right-0 mt-1 w-64 max-h-72 overflow-y-auto custom-scrollbar rounded-md shadow-2xl border z-50 font-mono text-xs animate-in fade-in zoom-in-95 ${

                  theme === 'dark'

                    ? 'bg-[#0c101c] border-slate-700 text-slate-200 shadow-black/80'

                    : 'bg-white border-slate-300 text-slate-800 shadow-slate-400/30'

                }`}>

                  <div className="py-1">

                    {tenantOptions.map((opt) => {

                      const isSelected = selectedTenant === opt.id;

                      return (

                        <button

                          key={opt.id}

                          type="button"

                          onClick={() => {

                            setSelectedTenant(opt.id);

                            setIsTenantDropdownOpen(false);

                          }}

                          className={`w-full text-left px-3.5 py-2 flex items-center justify-between transition-colors cursor-pointer ${

                            isSelected

                              ? (theme === 'dark' 

                                  ? 'bg-slate-700/80 text-white font-semibold' 

                                  : 'bg-slate-200/90 text-slate-900 font-semibold')

                              : (theme === 'dark' 

                                  ? 'hover:bg-slate-800/60 text-slate-300 hover:text-white' 

                                  : 'hover:bg-slate-100 text-slate-700 hover:text-slate-900')

                          }`}

                        >

                          <span>{opt.label}</span>

                          {isSelected && (

                            <span className={`text-xs ${theme === 'dark' ? 'text-indigo-400' : 'text-indigo-600'}`}>✓</span>

                          )}

                        </button>

                      );

                    })}

                  </div>

                </div>

              )}

            </div>



            {/* Time Range Filter Dropdown (Wazuh Style) */}

            <div className="relative" ref={timeDropdownRef}>

              <button

                type="button"

                onClick={() => setIsTimeDropdownOpen(prev => !prev)}

                className={`flex items-center justify-between gap-2.5 px-3 py-1.5 rounded-md text-xs font-mono font-medium border transition-all cursor-pointer min-w-[165px] shadow-xs ${

                  theme === 'dark'

                    ? 'bg-[#0c101c] border-slate-800 text-slate-200 hover:bg-slate-800/80 hover:border-slate-700'

                    : 'bg-white border-slate-200 text-slate-800 hover:bg-slate-50 hover:border-slate-300'

                }`}

              >

                <div className="flex items-center gap-2 truncate">

                  <Calendar className="w-3.5 h-3.5 text-blue-500 shrink-0" />

                  <span className="truncate">{getTimeRangeLabel()}</span>

                </div>

                <ChevronDown className={`w-3.5 h-3.5 text-slate-400 shrink-0 transition-transform duration-200 ${

                  isTimeDropdownOpen ? 'rotate-180 text-blue-500' : ''

                }`} />

              </button>



              {/* Dropdown Menu matching Image 1 & Image 2 style */}

              {isTimeDropdownOpen && (

                <div className={`absolute right-0 mt-1 ${timeRange === 'custom' ? 'w-[330px]' : 'w-64'} rounded-xl shadow-2xl border z-50 font-mono text-xs overflow-hidden animate-in fade-in zoom-in-95 transition-all duration-150 ${

                  theme === 'dark'

                    ? 'bg-[#0c101c] border-slate-700 text-slate-200 shadow-black/80'

                    : 'bg-white border-slate-300 text-slate-800 shadow-slate-400/30'

                }`}>

                  <div className="py-1">

                    {timeOptions.map((opt) => {

                      const isSelected = timeRange === opt.id;

                      return (

                        <button

                          key={opt.id}

                          type="button"

                          onClick={() => {

                            if (opt.id === 'custom') {

                              handleOpenCustomRange();

                            } else {

                              setTimeRange(opt.id);

                              setIsTimeDropdownOpen(false);

                            }

                          }}

                          className={`w-full text-left px-3.5 py-2 flex items-center justify-between transition-colors cursor-pointer ${

                            isSelected

                              ? (theme === 'dark' 

                                  ? 'bg-slate-700/80 text-white font-semibold' 

                                  : 'bg-slate-200/90 text-slate-900 font-semibold')

                              : (theme === 'dark' 

                                  ? 'hover:bg-slate-800/60 text-slate-300 hover:text-white' 

                                  : 'hover:bg-slate-100 text-slate-700 hover:text-slate-900')

                          }`}

                        >

                          <span>{opt.label}</span>

                          {isSelected && (

                            <span className={`text-xs ${theme === 'dark' ? 'text-blue-400' : 'text-blue-600'}`}>✓</span>

                          )}

                        </button>

                      );

                    })}

                  </div>



                  {/* Inline Custom Date & Time Range Inputs when Custom Range is active */}

                  {timeRange === 'custom' && (

                    <div className={`p-3.5 border-t space-y-3 ${

                      theme === 'dark' ? 'border-slate-800 bg-[#070b14]' : 'border-slate-100 bg-slate-50'

                    }`}>

                      {/* START DATE & TIME */}

                      <div>

                        <label className="block text-[10px] uppercase text-slate-400 font-semibold tracking-wider mb-1.5">

                          Start Date & Time

                        </label>

                        <div className="flex items-center gap-2">

                          <input

                            type="date"

                            value={tempStartDate}

                            onChange={(e) => setTempStartDate(e.target.value)}

                            className={`flex-1 px-2.5 py-1.5 rounded-lg border text-xs font-mono focus:outline-none focus:border-blue-500 ${

                              theme === 'dark'

                                ? 'bg-[#0c101c] border-slate-700 text-slate-200'

                                : 'bg-white border-slate-300 text-slate-800'

                            }`}

                          />

                          <input

                            type="time"

                            step="60"

                            value={tempStartTime}

                            onChange={(e) => setTempStartTime(e.target.value)}

                            className={`w-24 px-2 py-1.5 rounded-lg border text-xs font-mono text-center focus:outline-none focus:border-blue-500 ${

                              theme === 'dark'

                                ? 'bg-[#0c101c] border-slate-700 text-slate-200'

                                : 'bg-white border-slate-300 text-slate-800'

                            }`}

                          />

                        </div>

                      </div>



                      {/* END DATE & TIME */}

                      <div>

                        <label className="block text-[10px] uppercase text-slate-400 font-semibold tracking-wider mb-1.5">

                          End Date & Time

                        </label>

                        <div className="flex items-center gap-2">

                          <input

                            type="date"

                            value={tempEndDate}

                            onChange={(e) => setTempEndDate(e.target.value)}

                            className={`flex-1 px-2.5 py-1.5 rounded-lg border text-xs font-mono focus:outline-none focus:border-blue-500 ${

                              theme === 'dark'

                                ? 'bg-[#0c101c] border-slate-700 text-slate-200'

                                : 'bg-white border-slate-300 text-slate-800'

                            }`}

                          />

                          <input

                            type="time"

                            step="60"

                            value={tempEndTime}

                            onChange={(e) => setTempEndTime(e.target.value)}

                            className={`w-24 px-2 py-1.5 rounded-lg border text-xs font-mono text-center focus:outline-none focus:border-blue-500 ${

                              theme === 'dark'

                                ? 'bg-[#0c101c] border-slate-700 text-slate-200'

                                : 'bg-white border-slate-300 text-slate-800'

                            }`}

                          />

                        </div>

                      </div>



                      {/* Apply Range Button */}

                      <button

                        type="button"

                        onClick={handleApplyCustomRange}

                        className="w-full py-2 px-3 rounded-lg bg-blue-600 hover:bg-blue-500 text-white text-xs font-semibold transition-all cursor-pointer shadow-sm active:scale-[0.99]"

                      >

                        Apply Range

                      </button>

                    </div>

                  )}

                </div>

              )}

            </div>



          </div>

        </header>



        {/* Dynamic Main Workspace */}

        <main className="p-6 flex-1 overflow-x-hidden">

          {!hasAccess(activeTab) ? (

            <div className="flex flex-col items-center justify-center min-h-[50vh] text-center p-8 animate-in fade-in">

              <div className="w-16 h-16 rounded-2xl bg-rose-500/10 border border-rose-500/20 flex items-center justify-center text-rose-500 mb-4 shadow-lg shadow-rose-500/5">

                <ShieldAlert className="w-8 h-8" />

              </div>

              <h2 className={`text-xl font-bold mb-2 ${theme === 'dark' ? 'text-white' : 'text-slate-900'}`}>

                403 - Akses Dibatasi (Separation of Duties)

              </h2>

              <p className={`text-sm max-w-md mb-6 leading-relaxed ${theme === 'dark' ? 'text-slate-400' : 'text-slate-600'}`}>

                Role akun Anda (<span className="font-semibold text-rose-500">{userRole.replace(/_/g, ' ')}</span>) tidak memiliki wewenang untuk mengakses modul <span className="font-semibold">{getBreadcrumb().subcategory}</span>.

              </p>

              <button

                type="button"

                onClick={() => setActiveTab('analytics')}

                className="px-4 py-2 rounded-lg text-xs font-semibold bg-blue-600 hover:bg-blue-500 text-white transition-all shadow-md cursor-pointer"

              >

                Kembali ke Analytics

              </button>

            </div>

          ) : (

            <>

              {activeTab === 'analytics' && (

                <PipelineOverview 

                  onNavigate={handleNavigate} 

                  timeRange={timeRange}

                  customStartDate={customStartDate}

                  customEndDate={customEndDate}

                  selectedTenant={selectedTenant}

                  theme={theme}

                  isReadOnly={isReadOnly('analytics')}

                  currentUser={currentUser}

                />

              )}

              {activeTab === 'raw_alerts' && (

                <RawAlertsQueue 

                  theme={theme} 

                  onNavigate={handleNavigate} 

                  selectedTenant={selectedTenant}

                  timeRange={timeRange}

                  customStartDate={customStartDate}

                  customEndDate={customEndDate}

                  isReadOnly={isReadOnly('raw_alerts')}

                  currentUser={currentUser}

                />

              )}

              {activeTab === 'clustering' && (

                <ClusteringOverview 

                  theme={theme}

                  timeRange={timeRange}

                  customStartDate={customStartDate}

                  customEndDate={customEndDate}

                  selectedTenant={selectedTenant}

                  currentUser={currentUser}

                  isReadOnly={isReadOnly('clustering')}

                  onNavigate={(tab) => setActiveTab(tab)}

                />

              )}

              {activeTab === 'category_attack' && (

                <AttackOverview

                  theme={theme}

                  selectedTenant={selectedTenant}

                  timeRange={timeRange}

                />

              )}

              {activeTab === 'category_vulnerability' && (

                <VulnerabilityOverview

                  theme={theme}

                  selectedTenant={selectedTenant}

                  timeRange={timeRange}

                  customStartDate={customStartDate}

                  customEndDate={customEndDate}

                />

              )}

              {activeTab === 'category_system' && (

                <SystemIntegrityOverview

                  theme={theme}

                  selectedTenant={selectedTenant}

                  timeRange={timeRange}

                />

              )}

              {activeTab === 'triage' && (

                <IncidentTriageQueue 

                  viewMode="active" 

                  theme={theme} 

                  selectedTenant={selectedTenant}

                  timeRange={timeRange}

                  customStartDate={customStartDate}

                  customEndDate={customEndDate}

                  isReadOnly={isReadOnly('triage')}

                  currentUser={currentUser}

                  initialSearch={triageSearch}

                  onClearInitialSearch={() => setTriageSearch('')}

                />

              )}

              {activeTab === 'verified_tp' && (

                <IncidentTriageQueue 

                  viewMode="verified_tp" 

                  theme={theme} 

                  selectedTenant={selectedTenant}

                  timeRange={timeRange}

                  customStartDate={customStartDate}

                  customEndDate={customEndDate}

                  isReadOnly={isReadOnly('verified_tp')}

                  currentUser={currentUser}

                />

              )}

              {(activeTab === 'graph_conclusion' || activeTab === 'threat_campaigns') && (

                <ThreatCampaignsView

                  theme={theme}

                  selectedTenant={selectedTenant}

                  currentUser={currentUser}

                  isReadOnly={isReadOnly('graph_conclusion')}

                  onNavigate={handleNavigate}

                />

              )}

              {activeTab === 'groundtruth_queue' && (

                <IncidentTriageQueue 

                  viewMode="groundtruth" 

                  theme={theme} 

                  selectedTenant={selectedTenant}

                  timeRange={timeRange}

                  customStartDate={customStartDate}

                  customEndDate={customEndDate}

                  isReadOnly={isReadOnly('groundtruth_queue')}

                  currentUser={currentUser}

                />

              )}

              {activeTab === 'ground_truth_review' && (

                <GroundTruthReview 

                  theme={theme} 

                  currentUser={currentUser} 

                  selectedTenant={selectedTenant} 

                  isReadOnly={isReadOnly('ground_truth_review')}

                />

              )}

              {activeTab === 'suppression_inbox' && (

                <SuppressionGovernance 

                  initialTab="inbox" 

                  theme={theme} 

                  selectedTenant={selectedTenant} 

                  isReadOnly={isReadOnly('ground_truth_review')}

                  currentUser={currentUser}

                />

              )}

              {activeTab === 'suppression_rules' && (

                <SuppressionGovernance 

                  initialTab="rules" 

                  theme={theme} 

                  selectedTenant={selectedTenant} 

                  isReadOnly={isReadOnly('suppression_groups')}

                  currentUser={currentUser}

                />

              )}

              {activeTab === 'suppression_groups' && (

                <SuppressionGovernance 

                  initialTab="groups" 

                  theme={theme} 

                  selectedTenant={selectedTenant} 

                  isReadOnly={isReadOnly('suppression_groups')}

                  currentUser={currentUser}

                />

              )}

              {activeTab === 'suppression_audit' && (

                <SuppressionGovernance 

                  initialTab="audit" 

                  theme={theme} 

                  selectedTenant={selectedTenant} 

                  isReadOnly={isReadOnly('suppression_audit')}

                  currentUser={currentUser}

                />

              )}

              {activeTab === 'system_rbac' && (

                <SystemMaintenance 

                  initialTab="rbac" 

                  theme={theme} 

                  isReadOnly={isReadOnly('system_rbac')}

                  currentUser={currentUser}

                />

              )}

              {activeTab === 'system_database' && (

                <SystemMaintenance 

                  initialTab="database" 

                  theme={theme} 

                  isReadOnly={isReadOnly('system_database')}

                  currentUser={currentUser}

                />

              )}

              {activeTab === 'system_api' && (

                <SystemMaintenance 

                  initialTab="api_quota" 

                  theme={theme} 

                  isReadOnly={isReadOnly('system_api')}

                  currentUser={currentUser}

                />

              )}

            </>

          )}

        </main>

      </div>



      {/* Self-Service Password Change Modal */}

      {isPasswordModalOpen && (

        <div className="fixed inset-0 z-50 bg-black/70 backdrop-blur-sm flex items-center justify-center p-4">

          <div className={`${isDark ? 'bg-[#0f1422] border-slate-700/80 text-white' : 'bg-white border-slate-200 text-slate-900'} border rounded-2xl w-full max-w-md p-6 shadow-2xl relative`}>

            <div className={`flex items-center justify-between pb-4 border-b ${isDark ? 'border-slate-800' : 'border-slate-200'} mb-4`}>

              <div>

                <h3 className={`text-base font-bold ${isDark ? 'text-slate-100' : 'text-slate-900'}`}>

                  Ganti Kata Sandi Akun

                </h3>

              </div>

              <button

                onClick={() => setIsPasswordModalOpen(false)}

                className={`${isDark ? 'text-slate-400 hover:text-slate-200 hover:bg-slate-800' : 'text-slate-500 hover:text-slate-700 hover:bg-slate-100'} p-1 rounded-lg transition-colors cursor-pointer`}

              >

                <X className="w-5 h-5" />

              </button>

            </div>



            {pwError && (

              <div className="p-3 mb-4 rounded-lg bg-red-500/10 border border-red-500/30 text-red-500 dark:text-red-300 text-xs flex items-center gap-2">

                <AlertTriangle className="w-4 h-4 shrink-0" />

                <span>{pwError}</span>

              </div>

            )}



            {pwSuccess && (

              <div className="p-3 mb-4 rounded-lg bg-emerald-500/10 border border-emerald-500/30 text-emerald-600 dark:text-emerald-300 text-xs flex items-center gap-2">

                <CheckCircle2 className="w-4 h-4 shrink-0" />

                <span>{pwSuccess}</span>

              </div>

            )}



            <form onSubmit={handleSelfChangePassword} className="space-y-3.5 text-xs">

              <div>

                <label className={`block font-medium mb-1 ${isDark ? 'text-slate-300' : 'text-slate-700'}`}>Username</label>

                <input

                  type="text"

                  value={pwForm.username}

                  onChange={(e) => setPwForm({ ...pwForm, username: e.target.value })}

                  placeholder="Username akun Anda"

                  className={`w-full px-3 py-2 rounded-lg border font-mono transition-colors focus:outline-none ${

                    isDark 

                      ? 'bg-[#080b13] border-slate-700 text-slate-100 focus:border-indigo-500' 

                      : 'bg-slate-50 border-slate-300 text-slate-900 focus:border-blue-600 focus:bg-white'

                  }`}

                  required

                />

              </div>



              <div>

                <label className={`block font-medium mb-1 ${isDark ? 'text-slate-300' : 'text-slate-700'}`}>Kata Sandi Saat Ini</label>

                <input

                  type="password"

                  value={pwForm.current_password}

                  onChange={(e) => setPwForm({ ...pwForm, current_password: e.target.value })}

                  placeholder="Masukkan kata sandi lama Anda"

                  className={`w-full px-3 py-2 rounded-lg border font-mono transition-colors focus:outline-none ${

                    isDark 

                      ? 'bg-[#080b13] border-slate-700 text-slate-100 focus:border-indigo-500' 

                      : 'bg-slate-50 border-slate-300 text-slate-900 focus:border-blue-600 focus:bg-white'

                  }`}

                  required

                />

              </div>



              <div>

                <label className={`block font-medium mb-1 ${isDark ? 'text-slate-300' : 'text-slate-700'}`}>Kata Sandi Baru</label>

                <input

                  type="password"

                  value={pwForm.new_password}

                  onChange={(e) => setPwForm({ ...pwForm, new_password: e.target.value })}

                  placeholder="Minimal 8 karakter"

                  className={`w-full px-3 py-2 rounded-lg border font-mono transition-colors focus:outline-none ${

                    isDark 

                      ? 'bg-[#080b13] border-slate-700 text-slate-100 focus:border-indigo-500' 

                      : 'bg-slate-50 border-slate-300 text-slate-900 focus:border-blue-600 focus:bg-white'

                  }`}

                  required

                  minLength={8}

                />

              </div>



              <div>

                <label className={`block font-medium mb-1 ${isDark ? 'text-slate-300' : 'text-slate-700'}`}>Konfirmasi Kata Sandi Baru</label>

                <input

                  type="password"

                  value={pwForm.confirm_password}

                  onChange={(e) => setPwForm({ ...pwForm, confirm_password: e.target.value })}

                  placeholder="Ulangi kata sandi baru"

                  className={`w-full px-3 py-2 rounded-lg border font-mono transition-colors focus:outline-none ${

                    isDark 

                      ? 'bg-[#080b13] border-slate-700 text-slate-100 focus:border-indigo-500' 

                      : 'bg-slate-50 border-slate-300 text-slate-900 focus:border-blue-600 focus:bg-white'

                  }`}

                  required

                  minLength={8}

                />

              </div>



              <div className={`pt-3 flex justify-end gap-2 border-t ${isDark ? 'border-slate-800' : 'border-slate-200'}`}>

                <button

                  type="button"

                  onClick={() => setIsPasswordModalOpen(false)}

                  className="px-4 py-2 rounded-lg bg-red-600 hover:bg-red-700 text-white font-semibold transition-colors cursor-pointer shadow-xs"

                >

                  Batal

                </button>

                <button

                  type="submit"

                  disabled={pwSubmitting}

                  className="px-4 py-2 rounded-lg bg-blue-600 hover:bg-blue-700 text-white font-semibold flex items-center gap-1.5 transition-colors disabled:opacity-50 cursor-pointer shadow-xs"

                >

                  {pwSubmitting ? 'Memproses...' : 'Simpan Kata Sandi'}

                </button>

              </div>

            </form>

          </div>

        </div>

      )}

    </div>

  );

}

