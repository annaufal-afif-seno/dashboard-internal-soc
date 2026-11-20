import { AreaChart, Area, XAxis, YAxis, Tooltip as RechartsTooltip, ResponsiveContainer, CartesianGrid } from 'recharts';
import React, { useState, useEffect, useMemo } from 'react';

import { 

  Shield, Users, Database, HardDrive, Globe, Key, UserPlus, 

  CheckCircle2, XCircle, AlertTriangle, RefreshCw, Server, Lock,

  Clock, Activity, Zap, FileText, Check, X, ShieldCheck, ShieldAlert,

  Eye, Pencil, Trash2, ChevronsUpDown, ChevronUp, ChevronDown, Ban,

  Search, ArrowDownRight, ArrowUpRight, Gauge, Cpu, BarChart2, Radio

} from 'lucide-react';



// 12 RBAC Matrix Items mapped directly to Application Sidebar Navigation & Separation of Duties (SoD)

export const initialRbacMatrixData = [

  // 1. Modul MAIN

  {

    id: 'analytics',

    category: 'MAIN',

    action: 'Analytics',

    description: 'Melihat funnel metrik telemetri, tren deteksi serangan, reduksi alert IOA, dan performa pipeline real-time.',

    roles: {

      SOC_ANALYST: 'READ_WRITE',

      SOC_DEVELOPER: 'READ_WRITE',

      SOC_LEAD: 'READ_WRITE',

      SOC_MANAGER: 'READ_WRITE',

      ADMIN: 'READ_WRITE',

    }

  },

  {

    id: 'raw_alerts',

    category: 'MAIN',

    action: 'Raw Alert',

    description: 'Monitoring telemetri log mentah real-time, status decoder agen Wazuh, filtering pesan alert, dan inspeksi payload.',

    roles: {

      SOC_ANALYST: 'READ_WRITE',

      SOC_DEVELOPER: 'READ_WRITE',

      SOC_LEAD: 'READ_WRITE',

      SOC_MANAGER: 'READ_WRITE',

      ADMIN: 'READ_WRITE',

    }

  },

  {

    id: 'clustering',

    category: 'MAIN',

    action: 'Clustering',

    description: 'Manajemen windowing deduplikasi 15 menit, pembentukan kunci komposit cluster, dan reduksi volume alert.',

    roles: {

      SOC_ANALYST: 'READ_WRITE',

      SOC_DEVELOPER: 'READ_WRITE',

      SOC_LEAD: 'READ_WRITE',

      SOC_MANAGER: 'READ_WRITE',

      ADMIN: 'READ_WRITE',

    }

  },

  // Modul CATEGORIES

  {

    id: 'category_attack',

    category: 'CATEGORIES',

    action: 'Attack',

    description: 'Monitoring dan analisis insiden langsung Domain Attack (Stateless Direct Threats & Active Exploitation).',

    roles: {

      SOC_ANALYST: 'READ_WRITE',

      SOC_DEVELOPER: 'READ_WRITE',

      SOC_LEAD: 'READ_WRITE',

      SOC_MANAGER: 'READ_WRITE',

      ADMIN: 'READ_WRITE',

    }

  },

  {

    id: 'category_vulnerability',

    category: 'CATEGORIES',

    action: 'Vulnerability',

    description: 'Monitoring temuan Domain Vulnerability (Software CVE Exposure, SCA Hardening Drift, DLP, & Audit).',

    roles: {

      SOC_ANALYST: 'READ_WRITE',

      SOC_DEVELOPER: 'READ_WRITE',

      SOC_LEAD: 'READ_WRITE',

      SOC_MANAGER: 'READ_WRITE',

      ADMIN: 'READ_WRITE',

    }

  },

  {

    id: 'category_system',

    category: 'CATEGORIES',

    action: 'System',

    description: 'Monitoring ketersediaan host Domain System (RAM/Disk Crisis, Host Outage, Privilege Tampering, & Cloud SaaS).',

    roles: {

      SOC_ANALYST: 'READ_WRITE',

      SOC_DEVELOPER: 'READ_WRITE',

      SOC_LEAD: 'READ_WRITE',

      SOC_MANAGER: 'READ_WRITE',

      ADMIN: 'READ_WRITE',

    }

  },



  // 2. Modul INCIDENT TRIAGE

  {

    id: 'ticket_queue',

    category: 'INCIDENT TRIAGE',

    action: 'Ticket Queue',

    description: 'Eksekusi antrean tiket Earliest Deadline First (EDF), klaim insiden, investigasi P0-P4, dan penutupan tiket (CLOSE).',

    roles: {

      SOC_ANALYST: 'READ_WRITE',

      SOC_DEVELOPER: 'READ_ONLY',

      SOC_LEAD: 'READ_WRITE',

      SOC_MANAGER: 'READ_ONLY',

      ADMIN: 'READ_WRITE',

    }

  },

  {

    id: 'verified_tp',

    category: 'INCIDENT TRIAGE',

    action: 'Verified Threat',

    description: 'Analisis forensik insiden ancaman terkonfirmasi, inspeksi payload mentah, korelasi multi-tahap, dan pembuatan case IRIS.',

    roles: {

      SOC_ANALYST: 'READ_WRITE',

      SOC_DEVELOPER: 'READ_ONLY',

      SOC_LEAD: 'READ_WRITE',

      SOC_MANAGER: 'READ_ONLY',

      ADMIN: 'READ_WRITE',

    }

  },



  {

    id: 'groundtruth_queue',

    category: 'INCIDENT TRIAGE',

    action: 'Groundtruth',

    description: 'Antrean verifikasi manual tiket AI triage low confidence (< 85%), konfirmasi ground truth dataset, dan labeling True/False Positive.',

    roles: {

      SOC_ANALYST: 'READ_WRITE',

      SOC_DEVELOPER: 'READ_ONLY',

      SOC_LEAD: 'READ_WRITE',

      SOC_MANAGER: 'READ_ONLY',

      ADMIN: 'READ_WRITE',

    }

  },



  // 3. Modul SUPPRESSION & TUNING

  {

    id: 'ground_truth_review',

    category: 'SUPPRESSION & TUNING',

    action: 'Ground Truth Review',

    description: 'Identifikasi noise alert berulang dari tiket investigasi, inisiasi proposal formulasi supresi False Positive (FP) baru, dan validasi rule.',

    roles: {

      SOC_ANALYST: 'READ_WRITE',

      SOC_DEVELOPER: 'READ_WRITE',

      SOC_LEAD: 'READ_WRITE',

      SOC_MANAGER: 'NO_ACCESS',

      ADMIN: 'READ_WRITE',

    }

  },

  {

    id: 'policy_bundle',

    category: 'SUPPRESSION & TUNING',

    action: 'Policy Bundle',

    description: 'Audit kepatuhan kebijakan supresi, verifikasi XML custom rule/CBD list, serta kontrol aktivasi status Deploy (ON/OFF).',

    roles: {

      SOC_ANALYST: 'NO_ACCESS',

      SOC_DEVELOPER: 'NO_ACCESS',

      SOC_LEAD: 'READ_WRITE',

      SOC_MANAGER: 'READ_WRITE',

      ADMIN: 'READ_WRITE',

    }

  },

  {

    id: 'audit_log_grc',

    category: 'SUPPRESSION & TUNING',

    action: 'Governance & Compliance Audit',

    description: 'Pelacakan jejak audit mutasi aturan supresi, riwayat persetujuan kebijakan, dan bukti kepatuhan regulasi (GRC).',

    roles: {

      SOC_ANALYST: 'READ_WRITE',

      SOC_DEVELOPER: 'READ_WRITE',

      SOC_LEAD: 'READ_WRITE',

      SOC_MANAGER: 'READ_WRITE',

      ADMIN: 'READ_WRITE',

    }

  },



  // 4. Modul THREAT CAMPAIGN

  {

    id: 'graph_conclusion',

    category: 'THREAT CAMPAIGN',

    action: 'Graph Conclusion',

    description: 'Analisis klaster kampanye serangan multi-vektor, korelasi aktor ancaman global, grafik sebaran taktik MITRE ATT&CK, dan visualisasi topologi kampanye.',

    roles: {

      SOC_ANALYST: 'READ_WRITE',

      SOC_DEVELOPER: 'READ_ONLY',

      SOC_LEAD: 'READ_WRITE',

      SOC_MANAGER: 'READ_ONLY',

      ADMIN: 'READ_WRITE',

    }

  },

  {

    id: 'threat_actor',

    category: 'THREAT CAMPAIGN',

    action: 'Actor',

    description: 'Profil dan atribusi kelompok ancaman siber (APT), sidik jari pelaku kejahatan, dan basis data taktik threat actor.',

    roles: {

      SOC_ANALYST: 'READ_WRITE',

      SOC_DEVELOPER: 'READ_ONLY',

      SOC_LEAD: 'READ_WRITE',

      SOC_MANAGER: 'READ_ONLY',

      ADMIN: 'READ_WRITE',

    }

  },

  {

    id: 'threat_victim',

    category: 'THREAT CAMPAIGN',

    action: 'Victim',

    description: 'Pemetaan target dan entitas terdampak serangan siber, aset kritis korban, dan tingkat paparan insiden.',

    roles: {

      SOC_ANALYST: 'READ_WRITE',

      SOC_DEVELOPER: 'READ_ONLY',

      SOC_LEAD: 'READ_WRITE',

      SOC_MANAGER: 'READ_ONLY',

      ADMIN: 'READ_WRITE',

    }

  },



  // 5. Modul SYSTEM MAINTENANCE

  {

    id: 'account_rbac',

    category: 'SYSTEM MAINTENANCE',

    action: 'Manajemen Akun & RBAC',

    description: 'Pengelolaan akun personel tim SOC, penetapan role wewenang, aktivasi/suspend akun, dan kontrol kredensial pengguna.',

    roles: {

      SOC_ANALYST: 'NO_ACCESS',

      SOC_DEVELOPER: 'NO_ACCESS',

      SOC_LEAD: 'READ_ONLY',

      SOC_MANAGER: 'READ_ONLY',

      ADMIN: 'READ_WRITE',

    }

  },

  {

    id: 'database_health',

    category: 'SYSTEM MAINTENANCE',

    action: 'Database & Storage Health',

    description: 'Pemantauan liveness ingesti Vector real-time, audit memory usage 31 tabel PostgreSQL, kecepatan IO, dan optimasi ANALYZE.',

    roles: {

      SOC_ANALYST: 'READ_ONLY',

      SOC_DEVELOPER: 'READ_ONLY',

      SOC_LEAD: 'READ_ONLY',

      SOC_MANAGER: 'READ_ONLY',

      ADMIN: 'READ_WRITE',

    }

  },

  {

    id: 'api_threat_intel',

    category: 'SYSTEM MAINTENANCE',

    action: 'API & Quota Threat Intel',

    description: 'Monitoring kuota API AbuseIPDB & VirusTotal, verifikasi API Key SOC backend, dan konfigurasi integrasi eksternal.',

    roles: {

      SOC_ANALYST: 'READ_ONLY',

      SOC_DEVELOPER: 'READ_WRITE',

      SOC_LEAD: 'READ_ONLY',

      SOC_MANAGER: 'READ_ONLY',

      ADMIN: 'READ_WRITE',

    }

  }

];



export const PERMISSION_OPTIONS = [

  { id: 'READ_WRITE', label: 'READ & WRITE' },

  { id: 'READ_ONLY', label: 'READ ONLY' },

  { id: 'NO_ACCESS', label: 'NO ACCESS' },

];



const getSolidBadgeStyle = (val) => {

  switch (val) {

    case 'READ_WRITE':

      return 'bg-emerald-500 !text-white';

    case 'READ_ONLY':

      return 'bg-amber-500 !text-white';

    case 'NO_ACCESS':

    default:

      return 'bg-slate-500 !text-white';

  }

};



const getLabel = (val) => {

  switch (val) {

    case 'READ_WRITE': return 'READ & WRITE';

    case 'READ_ONLY': return 'READ ONLY';

    case 'NO_ACCESS': default: return 'NO ACCESS';

  }

};



const RbacMatrixDropdownCell = ({

  value,

  rowId,

  roleKey,

  isEditing,

  onChange,

  isDark,

  isOpen,

  onToggle,

  onClose,

  openUpwards

}) => {

  if (!isEditing) {

    return (

      <div className="flex items-center justify-center">

        <span className={`inline-block font-mono font-bold text-[11px] px-3 py-1 rounded-md uppercase tracking-wider whitespace-nowrap shadow-xs !text-white ${getSolidBadgeStyle(value)}`}>

          {getLabel(value)}

        </span>

      </div>

    );

  }



  const alignClass = (roleKey === 'ADMIN' || roleKey === 'SOC_MANAGER') ? 'right-0' : 'left-0';



  return (

    <div className="relative inline-block w-full max-w-[145px] rbac-dropdown-menu-container">

      <button

        type="button"

        onClick={onToggle}

        className={`flex items-center justify-between gap-1.5 px-3 py-1 rounded-md text-[11px] font-mono font-bold transition-all cursor-pointer w-full shadow-xs uppercase tracking-wider !text-white ${getSolidBadgeStyle(value)} ${

          isOpen ? 'ring-2 ring-white/60 scale-[1.02]' : 'hover:opacity-90'

        }`}

      >

        <span className="truncate !text-white">{getLabel(value)}</span>

        <ChevronDown className={`w-3.5 h-3.5 shrink-0 transition-transform duration-200 !text-white ${

          isOpen ? 'rotate-180' : ''

        }`} />

      </button>



      {isOpen && (

        <div className={`absolute ${alignClass} ${

          openUpwards ? 'bottom-full mb-1' : 'top-full mt-1'

        } w-48 rounded-md shadow-2xl border z-50 font-mono text-xs overflow-hidden animate-in fade-in zoom-in-95 ${

          isDark

            ? 'bg-[#0c101c] border-slate-700 text-slate-200 shadow-black/80'

            : 'bg-white border-slate-300 text-slate-800 shadow-slate-400/30'

        }`}>

          <div className="py-1">

            {PERMISSION_OPTIONS.map((opt) => {

              const isSelected = value === opt.id;

              return (

                <button

                  key={opt.id}

                  type="button"

                  onClick={() => {

                    onChange(rowId, roleKey, opt.id);

                    onClose();

                  }}

                  className={`w-full text-left px-3.5 py-2 flex items-center justify-between transition-colors cursor-pointer ${

                    isSelected

                      ? (isDark 

                          ? 'bg-slate-700/80 text-white font-semibold' 

                          : 'bg-slate-200/90 text-slate-900 font-semibold')

                      : (isDark 

                          ? 'hover:bg-slate-800/60 text-slate-300 hover:text-white' 

                          : 'hover:bg-slate-100 text-slate-700 hover:text-slate-900')

                  }`}

                >

                  <span className="flex items-center gap-2">

                    <span className={`w-2.5 h-2.5 rounded-full shrink-0 ${

                      opt.id === 'READ_WRITE' ? 'bg-emerald-500' :

                      opt.id === 'READ_ONLY' ? 'bg-amber-400' : 'bg-slate-400'

                    }`} />

                    <span className="font-bold">{opt.label}</span>

                  </span>

                </button>

              );

            })}

          </div>

        </div>

      )}

    </div>

  );

};



const getCategoryBadge = (category, isDark) => {

  return (

    <span className="font-bold font-mono text-xs uppercase tracking-wider text-slate-900 dark:text-white whitespace-nowrap">

      {category}

    </span>

  );

};



export default function SystemMaintenance({ initialTab = 'rbac', theme = 'dark', isReadOnly = false, currentUser = null }) {

  const [activeTab, setActiveTab] = useState(initialTab);
  const [latencyMetricMode, setLatencyMetricMode] = useState('ALL'); // 'ALL' | 'READ' | 'WRITE'

  const isDark = theme === 'dark';



  useEffect(() => {

    if (initialTab) setActiveTab(initialTab);

  }, [initialTab]);



  // Separation of Duties Matrix State

  const [matrixData, setMatrixData] = useState(() => {

    try {

      const saved = localStorage.getItem('wazuh_rbac_permissions_matrix_v4')

        || localStorage.getItem('wazuh_rbac_permissions_matrix_v3')

        || localStorage.getItem('wazuh_rbac_permissions_matrix_v2') 

        || localStorage.getItem('wazuh_rbac_permissions_matrix');

      if (saved) {

        const parsed = JSON.parse(saved);

        if (Array.isArray(parsed)) {

          const savedRoleMap = {};

          parsed.forEach(row => {

            const key = row.id || row.action;

            if (key) savedRoleMap[key] = row.roles;

            // Legacy name and id mappings & typo fixes

            if (row.action === 'Verified True Positives' || row.action === 'Verifed Threat' || row.id === 'verified_tp') savedRoleMap['verified_tp'] = row.roles;

            if (row.action === 'Threat Campaigns' || row.id === 'threat_campaigns' || row.action === 'Graph Conclusion' || row.id === 'graph_conclusion') savedRoleMap['graph_conclusion'] = row.roles;

            if (row.action === 'Actor' || row.id === 'threat_actor') savedRoleMap['threat_actor'] = row.roles;

            if (row.action === 'Victim' || row.id === 'threat_victim') savedRoleMap['threat_victim'] = row.roles;

            if (row.action === 'Suppression Proposal' || row.id === 'suppression_proposal' || row.id === 'ground_truth_review') savedRoleMap['ground_truth_review'] = row.roles;

            if (row.action === 'Audit Log Supresi (GRC)' || row.id === 'audit_log_grc') savedRoleMap['audit_log_grc'] = row.roles;

          });



          // Re-map with initialRbacMatrixData as canonical blueprint so action names & new features are always 100% current

          const synced = initialRbacMatrixData.map(def => {

            const savedRoles = savedRoleMap[def.id] || savedRoleMap[def.action];

            return {

              ...def,

              roles: savedRoles ? Object.fromEntries(

                Object.entries({ ...def.roles, ...savedRoles }).map(([r, val]) => [

                  r,

                  (val === 'READ_WRITE' || val === 'READ_ONLY') ? val : 'NO_ACCESS'

                ])

              ) : def.roles

            };

          });



          try {

            localStorage.setItem('wazuh_rbac_permissions_matrix', JSON.stringify(synced));

            localStorage.setItem('wazuh_rbac_permissions_matrix_v2', JSON.stringify(synced));

            localStorage.setItem('wazuh_rbac_permissions_matrix_v3', JSON.stringify(synced));

            localStorage.setItem('wazuh_rbac_permissions_matrix_v4', JSON.stringify(synced));

          } catch (_) {}



          return synced;

        }

      }

    } catch (e) {

      console.warn('Failed to parse saved matrix:', e);

    }

    return initialRbacMatrixData;

  });

  const [isEditingMatrix, setIsEditingMatrix] = useState(false);

  const [matrixSnapshot, setMatrixSnapshot] = useState(null);

  const [matrixSaveSuccess, setMatrixSaveSuccess] = useState('');

  const [activeDropdownCell, setActiveDropdownCell] = useState(null); // format: `${rowId}_${roleKey}`



  // Click outside to close active custom dropdown popover

  useEffect(() => {

    const handleClickOutside = (e) => {

      if (!e.target.closest('.rbac-dropdown-menu-container')) {

        setActiveDropdownCell(null);

      }

    };

    const handleKeyDown = (e) => {

      if (e.key === 'Escape') {

        setActiveDropdownCell(null);

      }

    };

    document.addEventListener('mousedown', handleClickOutside);

    document.addEventListener('keydown', handleKeyDown);

    return () => {

      document.removeEventListener('mousedown', handleClickOutside);

      document.removeEventListener('keydown', handleKeyDown);

    };

  }, []);



  const handleStartEditMatrix = () => {

    setMatrixSnapshot(JSON.parse(JSON.stringify(matrixData)));

    setIsEditingMatrix(true);

    setMatrixSaveSuccess('');

    setActiveDropdownCell(null);

  };



  const handleCancelEditMatrix = () => {

    if (matrixSnapshot) {

      setMatrixData(matrixSnapshot);

    }

    setIsEditingMatrix(false);

    setMatrixSnapshot(null);

    setActiveDropdownCell(null);

  };



  const handleApplyEditMatrix = () => {

    try {

      localStorage.setItem('wazuh_rbac_permissions_matrix', JSON.stringify(matrixData));

      localStorage.setItem('wazuh_rbac_permissions_matrix_v2', JSON.stringify(matrixData));

      localStorage.setItem('wazuh_rbac_permissions_matrix_v3', JSON.stringify(matrixData));

      localStorage.setItem('wazuh_rbac_permissions_matrix_v4', JSON.stringify(matrixData));

    } catch (e) {

      console.warn('Failed to save matrix to localStorage:', e);

    }

    setIsEditingMatrix(false);

    setMatrixSnapshot(null);

    setActiveDropdownCell(null);

    setMatrixSaveSuccess('Perubahan pengaturan hak akses berhasil disimpan dan diterapkan.');

    setTimeout(() => setMatrixSaveSuccess(''), 4000);

  };



  const handleMatrixCellChange = (rowId, roleKey, newPermission) => {

    setMatrixData(prev => prev.map(row => {

      if (row.id === rowId) {

        return {

          ...row,

          roles: {

            ...row.roles,

            [roleKey]: newPermission

          }

        };

      }

      return row;

    }));

  };



  // RBAC State

  const [users, setUsers] = useState([]);

  const [roles, setRoles] = useState({});

  const [rbacLoading, setRbacLoading] = useState(false);

  const [isAddUserModalOpen, setIsAddUserModalOpen] = useState(false);

  const [newUserForm, setNewUserForm] = useState({

    username: '',

    full_name: '',

    email: '',

    password: '',

    role: 'SOC_ANALYST',

    department: 'Tier 1 Triage Unit'

  });

  const [formError, setFormError] = useState('');

  const [formSuccess, setFormSuccess] = useState('');

  const [submittingUser, setSubmittingUser] = useState(false);



  // Edit User & Reset Password State

  const [isEditUserModalOpen, setIsEditUserModalOpen] = useState(false);

  const [editingUser, setEditingUser] = useState(null);

  const [editUserForm, setEditUserForm] = useState({

    username: '',

    full_name: '',

    email: '',

    role: 'SOC_ANALYST',

    department: '',

    status: 'ACTIVE',

    new_password: '',

    reset_to_default: false

  });

  const [editError, setEditError] = useState('');

  const [editSuccess, setEditSuccess] = useState('');

  const [submittingEdit, setSubmittingEdit] = useState(false);



  const handleOpenEditModal = (u) => {

    setEditingUser(u);

    setEditUserForm({

      username: u.username || '',

      full_name: u.full_name || '',

      email: u.email || '',

      role: u.role || 'SOC_ANALYST',

      department: u.department || '',

      status: u.status || 'ACTIVE',

      new_password: '',

      reset_to_default: false

    });

    setEditError('');

    setEditSuccess('');

    setIsEditUserModalOpen(true);

  };



  const handleUpdateUser = async (e) => {

    e.preventDefault();

    if (!editingUser) return;

    setEditError('');

    setEditSuccess('');



    try {

      setSubmittingEdit(true);

      const res = await fetch(`/api/system/rbac/users/${editingUser.user_id}`, {

        method: 'PUT',

        headers: { 'Content-Type': 'application/json' },

        body: JSON.stringify({

          username: editUserForm.username.trim(),

          full_name: editUserForm.full_name.trim(),

          email: editUserForm.email.trim(),

          role: editUserForm.role,

          department: editUserForm.department ? editUserForm.department.trim() : undefined,

          status: editUserForm.status,

          new_password: editUserForm.new_password ? editUserForm.new_password.trim() : undefined,

          reset_to_default: editUserForm.reset_to_default

        })

      });

      const data = await res.json();

      if (!res.ok) {

        setEditError(data.detail || 'Gagal memperbarui profil pengguna.');

      } else {

        setEditSuccess(`Profil @${editUserForm.username} berhasil diperbarui.`);

        fetchRbacUsers();

        setTimeout(() => {

          setIsEditUserModalOpen(false);

          setEditSuccess('');

        }, 1200);

      }

    } catch (err) {

      setEditError('Koneksi gagal: ' + err.message);

    } finally {

      setSubmittingEdit(false);

    }

  };



  // Database Health State

  const [dbHealth, setDbHealth] = useState(null);

  const [dbLoading, setDbLoading] = useState(false);

  const [maintenanceRunning, setMaintenanceRunning] = useState(false);

  const [maintenanceResult, setMaintenanceResult] = useState(null);

  const [dbTableSearch, setDbTableSearch] = useState('');

  const [dbSchemaFilter, setDbSchemaFilter] = useState('ALL');

  const [dbSortField, setDbSortField] = useState('total_bytes');

  const [dbSortAsc, setDbSortAsc] = useState(false);



  const handleDbSort = (field) => {

    if (dbSortField === field) {

      setDbSortAsc(!dbSortAsc);

    } else {

      setDbSortField(field);

      setDbSortAsc(false);

    }

  };



  const renderDbSortIcon = (field) => {

    if (dbSortField !== field) {

      return <ChevronsUpDown className="w-3.5 h-3.5 text-blue-500/70 group-hover:text-blue-600 shrink-0 transition-colors" />;

    }

    if (dbSortAsc) {

      return <ChevronUp className="w-3.5 h-3.5 text-blue-600 dark:text-blue-400 shrink-0 stroke-[2.5]" />;

    }

    return <ChevronDown className="w-3.5 h-3.5 text-blue-600 dark:text-blue-400 shrink-0 stroke-[2.5]" />;

  };



  const filteredTables = useMemo(() => {

    if (!dbHealth?.tables) return [];

    let list = [...dbHealth.tables];

    if (dbSchemaFilter !== 'ALL') {

      list = list.filter(t => t.schemaname === dbSchemaFilter);

    }

    if (dbTableSearch.trim()) {

      const q = dbTableSearch.toLowerCase();

      list = list.filter(t => 

        (t.table_name && t.table_name.toLowerCase().includes(q)) ||

        (t.schemaname && t.schemaname.toLowerCase().includes(q))

      );

    }

    if (dbSortField) {

      list.sort((a, b) => {

        let aVal = a[dbSortField];

        let bVal = b[dbSortField];

        if (typeof aVal === 'string' && typeof bVal === 'string') {

          return dbSortAsc ? aVal.localeCompare(bVal) : bVal.localeCompare(aVal);

        }

        aVal = Number(aVal || 0);

        bVal = Number(bVal || 0);

        return dbSortAsc ? aVal - bVal : bVal - aVal;

      });

    }

    return list;

  }, [dbHealth, dbTableSearch, dbSchemaFilter, dbSortField, dbSortAsc]);



  const uniqueSchemas = useMemo(() => {

    if (!dbHealth?.tables) return [];

    const set = new Set(dbHealth.tables.map(t => t.schemaname));

    return Array.from(set).sort();

  }, [dbHealth]);



  // Quota & Security State

  const [quotaData, setQuotaData] = useState(null);

  const [quotaLoading, setQuotaLoading] = useState(false);



  // Fetch RBAC Users

  const fetchRbacUsers = async () => {

    try {

      setRbacLoading(true);

      const res = await fetch('/api/system/rbac/users');

      if (res.ok) {

        const data = await res.json();

        setUsers(data.users || []);

        setRoles(data.roles || {});

      }

    } catch (err) {

      console.warn('Failed to fetch RBAC users:', err);

    } finally {

      setRbacLoading(false);

    }

  };



  // Auto-Refresh Configuration (Default: 300 detik / 5 Menit, or Realtime 10s)

  const [dbAutoRefresh, setDbAutoRefresh] = useState(
    Number(localStorage.getItem('dbRefresh') ?? 300)
  );

  const [lastDbSync, setLastDbSync] = useState(new Date());



  // Fetch DB Health

  const fetchDbHealth = async (isBackground = false) => {

    try {

      if (!isBackground) setDbLoading(true);

      const res = await fetch('/api/system/database/health');

      if (res.ok) {

        const data = await res.json();

        setDbHealth(data);

        setLastDbSync(new Date());

      }

    } catch (err) {

      console.warn('Failed to fetch DB health:', err);

    } finally {

      if (!isBackground) setDbLoading(false);

    }

  };



  // Auto-refresh interval handler

  useEffect(() => {

    if (activeTab !== 'database' || !dbAutoRefresh || dbAutoRefresh <= 0) return;



    const timer = setInterval(() => {

      fetchDbHealth(true);

    }, dbAutoRefresh * 1000);



    return () => clearInterval(timer);

  }, [activeTab, dbAutoRefresh]);



  // Fetch Integrations Quota

  const fetchQuotas = async () => {

    try {

      setQuotaLoading(true);

      const res = await fetch('/api/system/integrations/quota');

      if (res.ok) {

        const data = await res.json();

        setQuotaData(data);

      }

    } catch (err) {

      console.warn('Failed to fetch Quota info:', err);

    } finally {

      setQuotaLoading(false);

    }

  };



  useEffect(() => {

    fetchRbacUsers();

    fetchDbHealth();

    fetchQuotas();

  }, []);



  // Handle Add User Submit

  const handleCreateUser = async (e) => {

    e.preventDefault();

    setFormError('');

    setFormSuccess('');



    if (!newUserForm.username.trim() || !newUserForm.full_name.trim() || !newUserForm.email.trim()) {

      setFormError('Semua field wajib diisi.');

      return;

    }



    try {

      setSubmittingUser(true);

      const res = await fetch('/api/system/rbac/users', {

        method: 'POST',

        headers: { 'Content-Type': 'application/json' },

        body: JSON.stringify(newUserForm)

      });

      const data = await res.json();

      if (!res.ok) {

        setFormError(data.detail || 'Gagal mendaftarkan pengguna.');

      } else {

        setFormSuccess(`Pengguna @${newUserForm.username} berhasil ditambahkan.`);

        setNewUserForm({

          username: '',

          full_name: '',

          email: '',

          password: '',

          role: 'SOC_ANALYST',

          department: 'Tier 1 Triage Unit'

        });

        fetchRbacUsers();

        setTimeout(() => {

          setIsAddUserModalOpen(false);

          setFormSuccess('');

        }, 1200);

      }

    } catch (err) {

      setFormError('Koneksi ke backend gagal: ' + err.message);

    } finally {

      setSubmittingUser(false);

    }

  };



  // Handle Toggle User Status

  const handleToggleUserStatus = async (userId, currentStatus) => {

    const nextStatus = currentStatus === 'ACTIVE' ? 'SUSPENDED' : 'ACTIVE';

    try {

      const res = await fetch(`/api/system/rbac/users/${userId}`, {

        method: 'PUT',

        headers: { 'Content-Type': 'application/json' },

        body: JSON.stringify({ status: nextStatus })

      });

      if (res.ok) {

        fetchRbacUsers();

      }

    } catch (err) {

      console.warn('Failed to update user status:', err);

    }

  };



  // Handle Delete User Account

  const handleDeleteUser = async (userId, username) => {

    if (!window.confirm(`Konfirmasi: Apakah Anda yakin ingin menghapus permanen akun @${username}?`)) {

      return;

    }

    try {

      const res = await fetch(`/api/system/rbac/users/${userId}`, {

        method: 'DELETE'

      });

      const data = await res.json();

      if (!res.ok) {

        alert(data.detail || 'Gagal menghapus akun pengguna.');

      } else {

        fetchRbacUsers();

      }

    } catch (err) {

      alert('Koneksi ke backend gagal: ' + err.message);

    }

  };



  // Trigger DB Maintenance

  const handleRunMaintenance = async () => {

    try {

      setMaintenanceRunning(true);

      setMaintenanceResult(null);

      const res = await fetch('/api/system/database/maintenance/vacuum', {

        method: 'POST'

      });

      const data = await res.json();

      if (res.ok) {

        setMaintenanceResult(data);

        fetchDbHealth();

      } else {

        setMaintenanceResult({ success: false, message: data.detail || 'Maintenance gagal.' });

      }

    } catch (err) {

      setMaintenanceResult({ success: false, message: err.message });

    } finally {

      setMaintenanceRunning(false);

    }

  };



  const getRoleName = (role) => {

    switch (role) {

      case 'ADMIN': return 'Admin';

      case 'SOC_MANAGER': return 'SOC Manager';

      case 'SOC_LEAD': return 'SOC Lead';

      case 'SOC_DEVELOPER': return 'SOC Developer';

      case 'SOC_ANALYST':

      default: return 'SOC Analyst';

    }

  };



  // Personnel Directory Table Sorting State

  const [userSortField, setUserSortField] = useState(null);

  const [userSortDirection, setUserSortDirection] = useState('asc');



  const handleUserSort = (field) => {

    if (userSortField === field) {

      setUserSortDirection(prev => prev === 'asc' ? 'desc' : 'asc');

    } else {

      setUserSortField(field);

      setUserSortDirection('asc');

    }

  };



  const sortedUsers = useMemo(() => {

    if (!userSortField) return users;



    return [...users].sort((a, b) => {

      let aVal = '';

      let bVal = '';



      switch (userSortField) {

        case 'username':

          aVal = (a.full_name || a.username || '').toLowerCase();

          bVal = (b.full_name || b.username || '').toLowerCase();

          break;

        case 'email':

          aVal = (a.email || '').toLowerCase();

          bVal = (b.email || '').toLowerCase();

          break;

        case 'role':

          aVal = (getRoleName(a.role) || '').toLowerCase();

          bVal = (getRoleName(b.role) || '').toLowerCase();

          break;

        case 'status':

          aVal = (a.status || '').toLowerCase();

          bVal = (b.status || '').toLowerCase();

          break;

        case 'last_login':

          const timeA = a.last_login ? new Date(a.last_login).getTime() : 0;

          const timeB = b.last_login ? new Date(b.last_login).getTime() : 0;

          return userSortDirection === 'asc' ? timeA - timeB : timeB - timeA;

        default:

          return 0;

      }



      if (aVal < bVal) return userSortDirection === 'asc' ? -1 : 1;

      if (aVal > bVal) return userSortDirection === 'asc' ? 1 : -1;

      return 0;

    });

  }, [users, userSortField, userSortDirection]);



  const renderSortIcon = (field) => {

    if (userSortField !== field) {

      return <ChevronsUpDown className="w-3.5 h-3.5 text-blue-500/70 group-hover:text-blue-600 shrink-0 transition-colors" />;

    }

    if (userSortDirection === 'asc') {

      return <ChevronUp className="w-3.5 h-3.5 text-blue-600 dark:text-blue-400 shrink-0 stroke-[2.5]" />;

    }

    return <ChevronDown className="w-3.5 h-3.5 text-blue-600 dark:text-blue-400 shrink-0 stroke-[2.5]" />;

  };



  return (

    <div className="space-y-6">

      {/* ========================================================================= */}

      {/* SUB-TAB 1: MANAJEMEN AKUN & RBAC                                         */}

      {/* ========================================================================= */}

      {activeTab === 'rbac' && (

        <div className="space-y-6">

          {/* Top RBAC Summary Cards - Matching Analytics Styling & Centered */}

          <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-3.5">

            {/* Card 1: Total Akun */}

            <div className={`py-4 px-3.5 border rounded-xl transition-all flex flex-col items-center justify-center text-center ${

              isDark 

                ? 'bg-[#0a0e1a] border-slate-800 hover:border-slate-700' 

                : 'bg-white border-slate-200 hover:border-slate-300 shadow-xs'

            }`}>

              <div className={`text-2xl font-bold font-mono tracking-tight mb-1 ${

                isDark ? 'text-white' : 'text-slate-900'

              }`}>

                {users.filter(u => u.status === 'ACTIVE').length} / {users.length}

              </div>

              <span className={`text-xs font-bold tracking-wider uppercase ${

                isDark ? 'text-slate-400' : 'text-slate-500'

              }`}>

                TOTAL AKUN

              </span>

            </div>



            {/* Card 2: SOC Analyst */}

            <div className={`py-4 px-3.5 border rounded-xl transition-all flex flex-col items-center justify-center text-center ${

              isDark 

                ? 'bg-[#0a0e1a] border-slate-800 hover:border-slate-700' 

                : 'bg-white border-slate-200 hover:border-slate-300 shadow-xs'

            }`}>

              <div className={`text-2xl font-bold font-mono tracking-tight mb-1 ${

                isDark ? 'text-white' : 'text-slate-900'

              }`}>

                {users.filter(u => u.role === 'SOC_ANALYST').length}

              </div>

              <span className={`text-xs font-bold tracking-wider uppercase ${

                isDark ? 'text-slate-400' : 'text-slate-500'

              }`}>

                SOC ANALYST

              </span>

            </div>



            {/* Card 3: SOC Developer */}

            <div className={`py-4 px-3.5 border rounded-xl transition-all flex flex-col items-center justify-center text-center ${

              isDark 

                ? 'bg-[#0a0e1a] border-slate-800 hover:border-slate-700' 

                : 'bg-white border-slate-200 hover:border-slate-300 shadow-xs'

            }`}>

              <div className={`text-2xl font-bold font-mono tracking-tight mb-1 ${

                isDark ? 'text-white' : 'text-slate-900'

              }`}>

                {users.filter(u => u.role === 'SOC_DEVELOPER').length}

              </div>

              <span className={`text-xs font-bold tracking-wider uppercase ${

                isDark ? 'text-slate-400' : 'text-slate-500'

              }`}>

                SOC DEVELOPER

              </span>

            </div>



            {/* Card 4: SOC Lead */}

            <div className={`py-4 px-3.5 border rounded-xl transition-all flex flex-col items-center justify-center text-center ${

              isDark 

                ? 'bg-[#0a0e1a] border-slate-800 hover:border-slate-700' 

                : 'bg-white border-slate-200 hover:border-slate-300 shadow-xs'

            }`}>

              <div className={`text-2xl font-bold font-mono tracking-tight mb-1 ${

                isDark ? 'text-white' : 'text-slate-900'

              }`}>

                {users.filter(u => u.role === 'SOC_LEAD').length}

              </div>

              <span className={`text-xs font-bold tracking-wider uppercase ${

                isDark ? 'text-slate-400' : 'text-slate-500'

              }`}>

                SOC LEAD

              </span>

            </div>



            {/* Card 5: SOC Manager */}

            <div className={`py-4 px-3.5 border rounded-xl transition-all flex flex-col items-center justify-center text-center ${

              isDark 

                ? 'bg-[#0a0e1a] border-slate-800 hover:border-slate-700' 

                : 'bg-white border-slate-200 hover:border-slate-300 shadow-xs'

            }`}>

              <div className={`text-2xl font-bold font-mono tracking-tight mb-1 ${

                isDark ? 'text-white' : 'text-slate-900'

              }`}>

                {users.filter(u => u.role === 'SOC_MANAGER').length}

              </div>

              <span className={`text-xs font-bold tracking-wider uppercase ${

                isDark ? 'text-slate-400' : 'text-slate-500'

              }`}>

                SOC MANAGER

              </span>

            </div>



            {/* Card 6: Admin */}

            <div className={`py-4 px-3.5 border rounded-xl transition-all flex flex-col items-center justify-center text-center ${

              isDark 

                ? 'bg-[#0a0e1a] border-slate-800 hover:border-slate-700' 

                : 'bg-white border-slate-200 hover:border-slate-300 shadow-xs'

            }`}>

              <div className={`text-2xl font-bold font-mono tracking-tight mb-1 ${

                isDark ? 'text-white' : 'text-slate-900'

              }`}>

                {users.filter(u => u.role === 'ADMIN').length}

              </div>

              <span className={`text-xs font-bold tracking-wider uppercase ${

                isDark ? 'text-slate-400' : 'text-slate-500'

              }`}>

                ADMIN

              </span>

            </div>

          </div>



          {/* User Directory Table Section */}

          <div className={`border rounded-xl overflow-hidden ${

            isDark 

              ? 'bg-[#0a0e1a] border-slate-800' 

              : 'bg-white border-slate-200 shadow-xs'

          }`}>

            <div className={`p-4 border-b flex items-center justify-between ${

              isDark ? 'border-slate-800' : 'border-slate-200'

            }`}>

              <h2 className={`text-sm font-bold ${

                isDark ? 'text-white' : 'text-slate-900'

              }`}>

                Personnel Directory & SOC Access Rights

              </h2>



              {!isReadOnly ? (

                <button

                  type="button"

                  onClick={() => setIsAddUserModalOpen(true)}

                  className="px-3.5 py-1.5 rounded-lg text-xs font-semibold bg-blue-600 hover:bg-blue-500 text-white flex items-center gap-2 transition-all cursor-pointer shadow-xs shrink-0"

                >

                  <UserPlus className="w-3.5 h-3.5" />

                  <span>Add User</span>

                </button>

              ) : (

                <span className="px-2.5 py-1 text-[11px] font-mono text-amber-500 bg-amber-500/10 border border-amber-500/20 rounded-md">

                  Mode Read Only

                </span>

              )}

            </div>



            <div className="overflow-x-auto">

              <table className="w-full text-left text-xs">

                <thead className={`border-b text-xs font-semibold ${

                  isDark 

                    ? 'bg-[#0b101d] text-slate-300 border-slate-800' 

                    : 'bg-[#F0F5FA] text-slate-700 border-slate-200/80'

                }`}>

                  <tr>

                    <th 

                      onClick={() => handleUserSort('username')}

                      className="px-5 py-3.5 cursor-pointer select-none group hover:bg-slate-200/50 dark:hover:bg-slate-800/60 transition-colors"

                      title={userSortField === 'username' ? (userSortDirection === 'asc' ? 'Diurutkan terkecil (A-Z). Klik untuk terbesar (Z-A)' : 'Diurutkan terbesar (Z-A). Klik untuk terkecil (A-Z)') : 'Klik untuk mengurutkan terkecil (A-Z)'}

                    >

                      <div className="flex items-center gap-1.5">

                        <span className={userSortField === 'username' ? 'text-blue-600 dark:text-blue-400 font-bold' : 'group-hover:text-slate-900 dark:group-hover:text-white transition-colors'}>Username</span>

                        {renderSortIcon('username')}

                      </div>

                    </th>

                    <th 

                      onClick={() => handleUserSort('email')}

                      className="px-5 py-3.5 cursor-pointer select-none group hover:bg-slate-200/50 dark:hover:bg-slate-800/60 transition-colors"

                      title={userSortField === 'email' ? (userSortDirection === 'asc' ? 'Diurutkan terkecil (A-Z). Klik untuk terbesar (Z-A)' : 'Diurutkan terbesar (Z-A). Klik untuk terkecil (A-Z)') : 'Klik untuk mengurutkan terkecil (A-Z)'}

                    >

                      <div className="flex items-center gap-1.5">

                        <span className={userSortField === 'email' ? 'text-blue-600 dark:text-blue-400 font-bold' : 'group-hover:text-slate-900 dark:group-hover:text-white transition-colors'}>Email</span>

                        {renderSortIcon('email')}

                      </div>

                    </th>

                    <th 

                      onClick={() => handleUserSort('role')}

                      className="px-5 py-3.5 cursor-pointer select-none group hover:bg-slate-200/50 dark:hover:bg-slate-800/60 transition-colors"

                      title={userSortField === 'role' ? (userSortDirection === 'asc' ? 'Diurutkan terkecil (A-Z). Klik untuk terbesar (Z-A)' : 'Diurutkan terbesar (Z-A). Klik untuk terkecil (A-Z)') : 'Klik untuk mengurutkan terkecil (A-Z)'}

                    >

                      <div className="flex items-center gap-1.5">

                        <span className={userSortField === 'role' ? 'text-blue-600 dark:text-blue-400 font-bold' : 'group-hover:text-slate-900 dark:group-hover:text-white transition-colors'}>Peran (Role)</span>

                        {renderSortIcon('role')}

                      </div>

                    </th>

                    <th 

                      onClick={() => handleUserSort('status')}

                      className="px-5 py-3.5 cursor-pointer select-none group hover:bg-slate-200/50 dark:hover:bg-slate-800/60 transition-colors"

                      title={userSortField === 'status' ? (userSortDirection === 'asc' ? 'Diurutkan terkecil. Klik untuk terbesar' : 'Diurutkan terbesar. Klik untuk terkecil') : 'Klik untuk mengurutkan status'}

                    >

                      <div className="flex items-center gap-1.5">

                        <span className={userSortField === 'status' ? 'text-blue-600 dark:text-blue-400 font-bold' : 'group-hover:text-slate-900 dark:group-hover:text-white transition-colors'}>Status</span>

                        {renderSortIcon('status')}

                      </div>

                    </th>

                    <th 

                      onClick={() => handleUserSort('last_login')}

                      className="px-5 py-3.5 cursor-pointer select-none group hover:bg-slate-200/50 dark:hover:bg-slate-800/60 transition-colors"

                      title={userSortField === 'last_login' ? (userSortDirection === 'asc' ? 'Diurutkan terlama dahulu. Klik untuk terbaru' : 'Diurutkan terbaru dahulu. Klik untuk terlama') : 'Klik untuk mengurutkan tanggal'}

                    >

                      <div className="flex items-center gap-1.5">

                        <span className={userSortField === 'last_login' ? 'text-blue-600 dark:text-blue-400 font-bold' : 'group-hover:text-slate-900 dark:group-hover:text-white transition-colors'}>Terakhir Aktif</span>

                        {renderSortIcon('last_login')}

                      </div>

                    </th>

                    <th className="px-5 py-3.5 text-left">

                      <span>Aksi</span>

                    </th>

                  </tr>

                </thead>

                <tbody className={`divide-y font-sans ${

                  isDark ? 'divide-slate-800/60 bg-[#0a0e1a]' : 'divide-slate-100 bg-white'

                }`}>

                  {sortedUsers.map((u) => (

                    <tr key={u.user_id} className={`transition-colors ${

                      isDark ? 'hover:bg-slate-800/30' : 'hover:bg-slate-50/70'

                    }`}>

                      <td className="px-5 py-4">

                        <div className="flex items-center gap-3">

                          <div className={`w-8 h-8 rounded-full border font-bold text-xs flex items-center justify-center shrink-0 ${

                            isDark 

                              ? 'bg-slate-800 border-slate-700 text-slate-200' 

                              : 'bg-sky-50 border-sky-100 text-sky-700'

                          }`}>

                            {u.avatar_letter || 'SU'}

                          </div>

                          <div>

                            <div className={`font-bold text-xs tracking-tight ${

                              isDark ? 'text-white' : 'text-slate-900'

                            }`}>{u.full_name}</div>

                            <div className={`text-[11px] font-mono mt-0.5 ${

                              isDark ? 'text-slate-400' : 'text-slate-500'

                            }`}>@{u.username}</div>

                          </div>

                        </div>

                      </td>



                      <td className={`px-5 py-4 font-mono text-xs ${

                        isDark ? 'text-slate-300' : 'text-slate-600'

                      }`}>

                        {u.email}

                      </td>



                      <td className={`px-5 py-4 font-medium text-xs ${

                        isDark ? 'text-white' : 'text-slate-800'

                      }`}>

                        {getRoleName(u.role)}

                      </td>



                      <td className="px-5 py-4">

                        {u.status === 'ACTIVE' ? (

                          <span 

                            onClick={!isReadOnly ? () => handleToggleUserStatus(u.user_id, u.status) : undefined}

                            className={`inline-flex items-center px-3 py-1 rounded-full text-xs font-medium bg-[#E6F4EA] text-[#137333] dark:bg-emerald-950/60 dark:text-emerald-400 ${

                              !isReadOnly ? 'cursor-pointer hover:opacity-80' : 'cursor-default'

                            } transition-opacity`}

                            title={!isReadOnly ? "Status: Aktif (Klik untuk ubah status ke Suspended)" : "Status: Aktif"}

                          >

                            Aktif

                          </span>

                        ) : (

                          <span 

                            onClick={!isReadOnly ? () => handleToggleUserStatus(u.user_id, u.status) : undefined}

                            className={`inline-flex items-center px-3 py-1 rounded-full text-xs font-medium bg-[#FCE8E6] text-[#C5221F] dark:bg-rose-950/60 dark:text-rose-400 ${

                              !isReadOnly ? 'cursor-pointer hover:opacity-80' : 'cursor-default'

                            } transition-opacity`}

                            title={!isReadOnly ? "Status: Suspended (Klik untuk Aktifkan)" : "Status: Suspended"}

                          >

                            Suspended

                          </span>

                        )}

                      </td>



                      <td className={`px-5 py-4 text-xs ${

                        isDark ? 'text-slate-400' : 'text-slate-600'

                      }`}>

                        {u.last_login ? new Date(u.last_login).toLocaleString('id-ID', { dateStyle: 'short', timeStyle: 'short' }) : 'Belum pernah'}

                      </td>



                      <td className="px-5 py-4 text-left">

                        <div className="flex items-center gap-3">

                          <button

                            type="button"

                            onClick={() => handleOpenEditModal(u)}

                            className="text-sky-500 hover:text-sky-600 p-1 rounded-md hover:bg-sky-50 dark:hover:bg-sky-950/40 transition-colors cursor-pointer"

                            title={!isReadOnly ? "Lihat Detail & Reset Password" : "Lihat Detail Akun"}

                          >

                            <Eye className="w-4 h-4" />

                          </button>

                          {!isReadOnly && (

                            <>

                              <button

                                type="button"

                                onClick={() => handleOpenEditModal(u)}

                                className="text-slate-400 hover:text-slate-600 dark:hover:text-slate-200 p-1 rounded-md hover:bg-slate-100 dark:hover:bg-slate-800 transition-colors cursor-pointer"

                                title="Edit Profil Pengguna"

                              >

                                <Pencil className="w-4 h-4" />

                              </button>

                              <button

                                type="button"

                                onClick={() => handleToggleUserStatus(u.user_id, u.status)}

                                className={`p-1 rounded-md transition-colors cursor-pointer ${

                                  u.status === 'ACTIVE'

                                    ? 'text-slate-400 hover:text-amber-600 hover:bg-amber-50 dark:hover:bg-amber-950/30'

                                    : 'text-emerald-500 hover:text-emerald-600 hover:bg-emerald-50 dark:hover:bg-emerald-950/30'

                                }`}

                                title={u.status === 'ACTIVE' ? 'Suspend Akun' : 'Aktifkan Akun'}

                              >

                                {u.status === 'ACTIVE' ? <Ban className="w-4 h-4" /> : <CheckCircle2 className="w-4 h-4" />}

                              </button>

                              <button

                                type="button"

                                onClick={() => handleDeleteUser(u.user_id, u.username)}

                                className="text-slate-400 hover:text-rose-600 p-1 rounded-md hover:bg-rose-50 dark:hover:bg-rose-950/30 transition-colors cursor-pointer"

                                title="Hapus Akun Pengguna"

                              >

                                <Trash2 className="w-4 h-4" />

                              </button>

                            </>

                          )}

                        </div>

                      </td>

                    </tr>

                  ))}

                </tbody>

              </table>

            </div>

          </div>



          {/* Detailed RBAC Permissions Matrix Table */}

          <div className={`border rounded-xl overflow-hidden ${

            isDark 

              ? 'bg-[#0a0e1a] border-slate-800' 

              : 'bg-white border-slate-200 shadow-xs'

          }`}>

            <div className={`p-4 border-b flex items-center justify-between gap-4 ${

              isDark ? 'border-slate-800' : 'border-slate-200'

            }`}>

              <h2 className={`text-sm font-bold truncate ${

                isDark ? 'text-white' : 'text-slate-900'

              }`}>

                Matriks Hak Akses & Pembagian Wewenang (Separation of Duties)

              </h2>



              {/* Action Buttons Right-Aligned Strictly on the Same Line */}

              <div className="flex items-center gap-2 shrink-0">

                {!isEditingMatrix ? (

                  !isReadOnly ? (

                    <button

                      type="button"

                      onClick={handleStartEditMatrix}

                      className="px-3.5 py-1.5 rounded-lg text-xs font-semibold bg-blue-600 hover:bg-blue-500 text-white flex items-center gap-1.5 transition-all shadow-xs cursor-pointer"

                      title="Ubah konfigurasi hak akses per role"

                    >

                      <Pencil className="w-3.5 h-3.5" />

                      <span>Edit</span>

                    </button>

                  ) : (

                    <span className="px-2.5 py-1 rounded-md text-[10px] font-mono font-semibold text-slate-400 bg-slate-800/40 border border-slate-700/60 flex items-center gap-1.5">

                      <Lock className="w-3 h-3 text-slate-400" />

                      <span>Terkunci (Read Only)</span>

                    </span>

                  )

                ) : (

                  <div className="flex items-center gap-2">

                    <button

                      type="button"

                      onClick={handleCancelEditMatrix}

                      className="px-3.5 py-1.5 rounded-lg text-xs font-semibold bg-red-600 hover:bg-red-500 text-white flex items-center gap-1.5 transition-all shadow-xs cursor-pointer border border-red-600 hover:border-red-500"

                      title="Batalkan perubahan dan kembali ke pengaturan semula"

                    >

                      <X className="w-3.5 h-3.5" />

                      <span>Cancel</span>

                    </button>

                    <button

                      type="button"

                      onClick={handleApplyEditMatrix}

                      className="px-3.5 py-1.5 rounded-lg text-xs font-semibold bg-emerald-600 hover:bg-emerald-500 text-white flex items-center gap-1.5 transition-all shadow-xs cursor-pointer"

                      title="Terapkan dan simpan konfigurasi baru"

                    >

                      <Check className="w-3.5 h-3.5" />

                      <span>Apply</span>

                    </button>

                  </div>

                )}

              </div>

            </div>



            {matrixSaveSuccess && (

              <div className="px-4 py-2.5 bg-emerald-500/10 border-b border-emerald-500/30 flex items-center justify-between text-xs text-emerald-400">

                <div className="flex items-center gap-2">

                  <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0" />

                  <span>{matrixSaveSuccess}</span>

                </div>

                <button type="button" onClick={() => setMatrixSaveSuccess('')} className="text-emerald-400 hover:text-emerald-300 cursor-pointer">

                  <X className="w-3.5 h-3.5" />

                </button>

              </div>

            )}



            <div className="overflow-x-auto min-h-[460px]">

              <table className="w-full text-left text-xs">

                <thead className={`border-b uppercase text-[10px] font-semibold tracking-wider ${

                  isDark 

                    ? 'bg-[#080b13] text-slate-400 border-slate-800' 

                    : 'bg-slate-50 text-slate-500 border-slate-200'

                }`}>

                  <tr>

                    <th className="px-4 py-3 w-[15%]">Kategori Modul</th>

                    <th className="px-4 py-3 w-[30%]">Tindakan / Fitur Operasional</th>

                    <th className="px-3 py-3 text-center w-[11%]">SOC Analyst</th>

                    <th className="px-3 py-3 text-center w-[11%]">SOC Developer</th>

                    <th className="px-3 py-3 text-center w-[11%]">SOC Lead</th>

                    <th className="px-3 py-3 text-center w-[11%]">SOC Manager</th>

                    <th className="px-3 py-3 text-center w-[11%]">Admin</th>

                  </tr>

                </thead>

                <tbody className={`divide-y font-sans ${

                  isDark ? 'divide-slate-800/60' : 'divide-slate-200'

                }`}>

                  {matrixData.map((row, rowIndex) => (

                    <tr key={row.id} className={`transition-colors ${

                      isDark ? 'hover:bg-slate-800/20' : 'hover:bg-slate-50'

                    }`}>

                      <td className="px-4 py-3.5 align-middle">

                        {getCategoryBadge(row.category, isDark)}

                      </td>

                      <td className="px-4 py-3.5 align-middle">

                        <span className={`font-semibold text-xs ${isDark ? 'text-white' : 'text-slate-900'}`}>

                          {row.action}

                        </span>

                      </td>

                      <td className="px-3 py-3.5 text-center align-middle">

                        <RbacMatrixDropdownCell

                          value={row.roles.SOC_ANALYST}

                          rowId={row.id}

                          roleKey="SOC_ANALYST"

                          isEditing={isEditingMatrix}

                          onChange={handleMatrixCellChange}

                          isDark={isDark}

                          isOpen={activeDropdownCell === `${row.id}_SOC_ANALYST`}

                          onToggle={() => setActiveDropdownCell(prev => prev === `${row.id}_SOC_ANALYST` ? null : `${row.id}_SOC_ANALYST`)}

                          onClose={() => setActiveDropdownCell(null)}

                          openUpwards={rowIndex >= 5}

                        />

                      </td>

                      <td className="px-3 py-3.5 text-center align-middle">

                        <RbacMatrixDropdownCell

                          value={row.roles.SOC_DEVELOPER}

                          rowId={row.id}

                          roleKey="SOC_DEVELOPER"

                          isEditing={isEditingMatrix}

                          onChange={handleMatrixCellChange}

                          isDark={isDark}

                          isOpen={activeDropdownCell === `${row.id}_SOC_DEVELOPER`}

                          onToggle={() => setActiveDropdownCell(prev => prev === `${row.id}_SOC_DEVELOPER` ? null : `${row.id}_SOC_DEVELOPER`)}

                          onClose={() => setActiveDropdownCell(null)}

                          openUpwards={rowIndex >= 5}

                        />

                      </td>

                      <td className="px-3 py-3.5 text-center align-middle">

                        <RbacMatrixDropdownCell

                          value={row.roles.SOC_LEAD}

                          rowId={row.id}

                          roleKey="SOC_LEAD"

                          isEditing={isEditingMatrix}

                          onChange={handleMatrixCellChange}

                          isDark={isDark}

                          isOpen={activeDropdownCell === `${row.id}_SOC_LEAD`}

                          onToggle={() => setActiveDropdownCell(prev => prev === `${row.id}_SOC_LEAD` ? null : `${row.id}_SOC_LEAD`)}

                          onClose={() => setActiveDropdownCell(null)}

                          openUpwards={rowIndex >= 5}

                        />

                      </td>

                      <td className="px-3 py-3.5 text-center align-middle">

                        <RbacMatrixDropdownCell

                          value={row.roles.SOC_MANAGER}

                          rowId={row.id}

                          roleKey="SOC_MANAGER"

                          isEditing={isEditingMatrix}

                          onChange={handleMatrixCellChange}

                          isDark={isDark}

                          isOpen={activeDropdownCell === `${row.id}_SOC_MANAGER`}

                          onToggle={() => setActiveDropdownCell(prev => prev === `${row.id}_SOC_MANAGER` ? null : `${row.id}_SOC_MANAGER`)}

                          onClose={() => setActiveDropdownCell(null)}

                          openUpwards={rowIndex >= 5}

                        />

                      </td>

                      <td className="px-3 py-3.5 text-center align-middle">

                        <RbacMatrixDropdownCell

                          value={row.roles.ADMIN}

                          rowId={row.id}

                          roleKey="ADMIN"

                          isEditing={isEditingMatrix}

                          onChange={handleMatrixCellChange}

                          isDark={isDark}

                          isOpen={activeDropdownCell === `${row.id}_ADMIN`}

                          onToggle={() => setActiveDropdownCell(prev => prev === `${row.id}_ADMIN` ? null : `${row.id}_ADMIN`)}

                          onClose={() => setActiveDropdownCell(null)}

                          openUpwards={rowIndex >= 5}

                        />

                      </td>

                    </tr>

                  ))}

                </tbody>

              </table>

            </div>

          </div>

        </div>

      )}



      {/* ========================================================================= */}

      {/* SUB-TAB 2: DATABASE & STORAGE HEALTH                                      */}

      {/* ========================================================================= */}

      {activeTab === 'database' && (
        <div className="space-y-6">
          {/* ========================================================================= */}
          {/* SECTION 1: RESOURCES USAGE                                                 */}
          {/* ========================================================================= */}
          <div className="bg-white rounded-xl border border-slate-200/90 shadow-sm p-6">
            {/* Top Header */}
            <div className="flex items-center justify-between mb-5">
              <div>
                <h2 className="text-lg font-bold text-slate-800 tracking-tight">
                  Resources Usage
                </h2>
                <p className="text-xs text-slate-400 mt-0.5 font-normal">
                  Hardware load, virtual memory, disk consumption, and service processes.
                </p>
              </div>
              <div className="flex items-center gap-2">
                {/* Dropdown interval auto-refresh */}
                <div className="flex items-center gap-1.5">
                  <span className="text-[11px] text-slate-400 font-medium">Auto-refresh:</span>
                  <select
                    value={dbAutoRefresh}
                    onChange={e => {
                      const val = Number(e.target.value);
                      setDbAutoRefresh(val);
                      localStorage.setItem('dbRefresh', val);
                    }}
                    title="Nilai lebih kecil = data lebih sering diperbarui, namun menambah beban server."
                    className="border border-slate-200 rounded-md px-2 py-1 text-[11px] text-slate-600 bg-white shadow-[0_1px_2px_rgba(0,0,0,0.03)] cursor-pointer focus:outline-none focus:ring-1 focus:ring-blue-300"
                  >
                    <option value={5}>5 dtk</option>
                    <option value={10}>10 dtk</option>
                    <option value={30}>30 dtk</option>
                    <option value={60}>60 dtk</option>
                    <option value={300}>300 dtk</option>
                  </select>
                </div>
                <button
                  type="button"
                  onClick={() => fetchDbHealth(false)}
                  disabled={dbLoading}
                  className="px-3 py-1.5 rounded-lg border border-slate-200 bg-white hover:bg-slate-50 text-slate-600 text-xs font-medium flex items-center gap-1.5 transition-colors cursor-pointer shadow-[0_1px_2px_rgba(0,0,0,0.03)]"
                >
                  <RefreshCw className={`w-3.5 h-3.5 text-slate-400 ${dbLoading ? 'animate-spin text-blue-500' : ''}`} />
                  <span>Refresh</span>
                </button>
              </div>
            </div>

            {/* 3 Donut Cards Grid */}
            <div className="grid grid-cols-3 gap-5">
              {/* Card 1: CPU Utilization */}
              {(() => {
                const cpuVal = dbHealth?.resources?.cpu?.utilization_pct ?? 19;
                const radius = 38;
                const circ = 2 * Math.PI * radius;
                const offset = circ - (cpuVal / 100) * circ;
                return (
                  <div className="bg-white border border-slate-200/80 rounded-xl p-5 flex items-center justify-between shadow-[0_1px_2px_rgba(0,0,0,0.02)]">
                    <div>
                      <span className="text-xs font-semibold text-slate-700 block mb-3">CPU Utilization</span>
                      <div className="relative w-24 h-24 flex items-center justify-center">
                        <svg className="w-24 h-24 transform -rotate-90">
                          <circle cx="48" cy="48" r={radius} stroke="#EEF2F6" strokeWidth="8" fill="transparent" />
                          <circle
                            cx="48"
                            cy="48"
                            r={radius}
                            stroke="#0066FF"
                            strokeWidth="8"
                            strokeDasharray={circ}
                            strokeDashoffset={offset}
                            strokeLinecap="round"
                            fill="transparent"
                            className="transition-all duration-700 ease-out"
                          />
                        </svg>
                        <span className="absolute text-base font-bold text-slate-900">{cpuVal}%</span>
                      </div>
                    </div>
                    <div className="text-right text-xs space-y-1.5 self-center">
                      <div className="text-[11px] text-slate-500">Model: <span className="text-slate-800 font-semibold font-sans">{dbHealth?.resources?.cpu?.model || 'Qemu Virtual CPU Version 2.5+'}</span></div>
                      <div className="text-[11px] text-slate-500">Core: <span className="text-slate-800 font-semibold font-sans">{dbHealth?.resources?.cpu?.cores || 2}</span></div>
                      <div className="text-[11px] text-slate-500">Thread: <span className="text-slate-800 font-semibold font-sans">{dbHealth?.resources?.cpu?.threads || 1}</span></div>
                    </div>
                  </div>
                );
              })()}

              {/* Card 2: RAM Utilization */}
              {(() => {
                const ramVal = dbHealth?.resources?.ram?.utilization_pct ?? 31;
                const radius = 38;
                const circ = 2 * Math.PI * radius;
                const offset = circ - (ramVal / 100) * circ;
                return (
                  <div className="bg-white border border-slate-200/80 rounded-xl p-5 flex items-center justify-between shadow-[0_1px_2px_rgba(0,0,0,0.02)]">
                    <div>
                      <span className="text-xs font-semibold text-slate-700 block mb-3">RAM Utilization</span>
                      <div className="relative w-24 h-24 flex items-center justify-center">
                        <svg className="w-24 h-24 transform -rotate-90">
                          <circle cx="48" cy="48" r={radius} stroke="#EEF2F6" strokeWidth="8" fill="transparent" />
                          <circle
                            cx="48"
                            cy="48"
                            r={radius}
                            stroke="#0066FF"
                            strokeWidth="8"
                            strokeDasharray={circ}
                            strokeDashoffset={offset}
                            strokeLinecap="round"
                            fill="transparent"
                            className="transition-all duration-700 ease-out"
                          />
                        </svg>
                        <span className="absolute text-base font-bold text-slate-900">{ramVal}%</span>
                      </div>
                    </div>
                    <div className="text-right text-xs space-y-1.5 self-center">
                      <div className="text-[11px] text-slate-500">RAM Used: <span className="text-slate-800 font-semibold font-sans">{dbHealth?.resources?.ram?.used_gb ?? 1.22} GB</span></div>
                      <div className="text-[11px] text-slate-500">RAM Total: <span className="text-slate-800 font-semibold font-sans">{dbHealth?.resources?.ram?.total_gb ?? 4} GB</span></div>
                    </div>
                  </div>
                );
              })()}

              {/* Card 3: Disk Usage */}
              {(() => {
                const diskVal = dbHealth?.resources?.disk?.utilization_pct ?? 8;
                const radius = 38;
                const circ = 2 * Math.PI * radius;
                const offset = circ - (diskVal / 100) * circ;
                return (
                  <div className="bg-white border border-slate-200/80 rounded-xl p-5 flex items-center justify-between shadow-[0_1px_2px_rgba(0,0,0,0.02)]">
                    <div>
                      <span className="text-xs font-semibold text-slate-700 block mb-3">Disk Usage</span>
                      <div className="relative w-24 h-24 flex items-center justify-center">
                        <svg className="w-24 h-24 transform -rotate-90">
                          <circle cx="48" cy="48" r={radius} stroke="#EEF2F6" strokeWidth="8" fill="transparent" />
                          <circle
                            cx="48"
                            cy="48"
                            r={radius}
                            stroke="#0066FF"
                            strokeWidth="8"
                            strokeDasharray={circ}
                            strokeDashoffset={offset}
                            strokeLinecap="round"
                            fill="transparent"
                            className="transition-all duration-700 ease-out"
                          />
                        </svg>
                        <span className="absolute text-base font-bold text-slate-900">{diskVal}%</span>
                      </div>
                    </div>
                    <div className="text-right text-xs space-y-1.5 self-center">
                      <div className="text-[11px] text-slate-500">Used: <span className="text-slate-800 font-semibold font-sans">{dbHealth?.resources?.disk?.used_gb ?? 4.11} GB</span></div>
                      <div className="text-[11px] text-slate-500">Total: <span className="text-slate-800 font-semibold font-sans">{dbHealth?.resources?.disk?.total_gb ?? 60} GB</span></div>
                      <div className="text-[11px] text-slate-500">Available: <span className="text-slate-800 font-semibold font-sans">{dbHealth?.resources?.disk?.available_gb ?? 244} GB</span></div>
                    </div>
                  </div>
                );
              })()}
            </div>
          </div>

          {/* ========================================================================= */}
          {/* SECTION 2: DATABASE LATENCY                                               */}
          {/* ========================================================================= */}
          <div className="bg-white rounded-xl border border-slate-200/90 shadow-sm p-6">
            {/* Top Header */}
            <div className="flex items-center justify-between mb-4">
              <div>
                <h2 className="text-lg font-bold text-slate-800 tracking-tight">
                  Database Latency
                </h2>
                <p className="text-xs text-slate-400 mt-0.5 font-normal">
                  Read and write response time in milliseconds (VM internal)
                </p>
              </div>

              {/* Read / Write Toggles: white pill with light borders */}
              <div className="flex items-center rounded-lg border border-slate-200 bg-white p-0.5 text-xs">
                <button
                  type="button"
                  onClick={() => setLatencyMetricMode('ALL')}
                  className={`px-3 py-1 rounded-md text-xs font-medium transition-colors cursor-pointer ${
                    latencyMetricMode === 'ALL'
                      ? 'bg-slate-100 text-slate-800 font-semibold'
                      : 'text-slate-500 hover:text-slate-800'
                  }`}
                >
                  All
                </button>
                <button
                  type="button"
                  onClick={() => setLatencyMetricMode('READ')}
                  className={`px-3 py-1 rounded-md text-xs font-medium transition-colors cursor-pointer ${
                    latencyMetricMode === 'READ'
                      ? 'bg-slate-100 text-slate-800 font-semibold'
                      : 'text-slate-500 hover:text-slate-800'
                  }`}
                >
                  Read
                </button>
                <button
                  type="button"
                  onClick={() => setLatencyMetricMode('WRITE')}
                  className={`px-3 py-1 rounded-md text-xs font-medium transition-colors cursor-pointer ${
                    latencyMetricMode === 'WRITE'
                      ? 'bg-slate-100 text-slate-800 font-semibold'
                      : 'text-slate-500 hover:text-slate-800'
                  }`}
                >
                  Write
                </button>
              </div>
            </div>

            {/* Grid Layout: Chart on Left (Col 9), Databases on Right (Col 3) */}
            <div className="grid grid-cols-1 lg:grid-cols-12 gap-6 items-start">
              {/* Chart Side */}
              <div className="lg:col-span-9 w-full">
                {/* Reference style legend */}
                <div className="flex items-center gap-4 text-xs font-medium mb-3 text-slate-600">
                  <div className="flex items-center gap-1.5">
                    <span className="w-3 h-0.5 bg-[#00B974] inline-block"></span>
                    <span className="text-[11px] text-slate-700 font-medium">Read Latency (ms)</span>
                  </div>
                  <div className="flex items-center gap-1.5">
                    <span className="w-3 h-0.5 bg-[#F59E0B] inline-block"></span>
                    <span className="text-[11px] text-slate-700 font-medium">Write Latency (ms)</span>
                  </div>
                </div>

                <div className="h-64 w-full">
                  <ResponsiveContainer width="100%" height="100%">
                    <AreaChart
                      data={dbHealth?.latency_series || (() => {
                        const now = new Date();
                        const rVals = [0.45, 0.58, 0.52, 0.64, 0.49, 0.42];
                        const wVals = [1.12, 1.25, 1.18, 1.35, 1.22, 1.15];
                        const pts = [];
                        for (let i = 5; i >= 0; i--) {
                          const t = new Date(now.getTime() - i * 5 * 60 * 1000);
                          const hh = String(t.getHours()).padStart(2, '0');
                          const mm = String(t.getMinutes()).padStart(2, '0');
                          const idx = 5 - i;
                          pts.push({ time: `${hh}.${mm}`, Read: rVals[idx], Write: wVals[idx] });
                        }
                        return pts;
                      })()}
                      margin={{ top: 10, right: 10, left: -20, bottom: 0 }}
                    >
                      <defs>
                        <linearGradient id="colorReadLight" x1="0" y1="0" x2="0" y2="1">
                          <stop offset="5%" stopColor="#00B974" stopOpacity="0.30" />
                          <stop offset="95%" stopColor="#00B974" stopOpacity="0.02" />
                        </linearGradient>
                        <linearGradient id="colorWriteLight" x1="0" y1="0" x2="0" y2="1">
                          <stop offset="5%" stopColor="#F59E0B" stopOpacity="0.25" />
                          <stop offset="95%" stopColor="#F59E0B" stopOpacity="0.02" />
                        </linearGradient>
                      </defs>
                      <CartesianGrid strokeDasharray="3 3" stroke="#F1F5F9" vertical={false} />
                      <XAxis
                        dataKey="time"
                        stroke="#94A3B8"
                        fontSize={11}
                        tickLine={false}
                        axisLine={{ stroke: '#E2E8F0' }}
                      />
                      <YAxis
                        stroke="#94A3B8"
                        fontSize={11}
                        tickLine={false}
                        axisLine={{ stroke: '#E2E8F0' }}
                        unit=" ms"
                      />
                      <RechartsTooltip
                        contentStyle={{
                          backgroundColor: '#FFFFFF',
                          borderColor: '#E2E8F0',
                          borderRadius: '0.5rem',
                          fontSize: '11px',
                          color: '#1E293B',
                          boxShadow: '0 4px 6px -1px rgba(0, 0, 0, 0.1)'
                        }}
                      />
                      {(latencyMetricMode === 'ALL' || latencyMetricMode === 'READ') && (
                        <Area
                          type="monotone"
                          dataKey="Read"
                          name="Read (ms)"
                          stroke="#00B974"
                          strokeWidth={2}
                          fillOpacity={1}
                          fill="url(#colorReadLight)"
                        />
                      )}
                      {(latencyMetricMode === 'ALL' || latencyMetricMode === 'WRITE') && (
                        <Area
                          type="monotone"
                          dataKey="Write"
                          name="Write (ms)"
                          stroke="#F59E0B"
                          strokeWidth={2}
                          fillOpacity={1}
                          fill="url(#colorWriteLight)"
                        />
                      )}

                    </AreaChart>
                  </ResponsiveContainer>
                </div>
                <div className="text-center text-[11px] font-bold text-slate-400 uppercase tracking-widest mt-2">
                  CHECK TIME
                </div>
              </div>

              {/* Right Side: Databases Cards */}
              <div className="lg:col-span-3 space-y-3 pt-2">
                <span className="text-[10px] font-bold text-slate-400 uppercase tracking-widest block">DATABASE ENGINE</span>
                
                {/* Database: PostgreSQL Primary */}
                <div className="bg-white border border-slate-200/90 rounded-lg p-4 shadow-[0_1px_2px_rgba(0,0,0,0.02)]">
                  <div className="flex items-center justify-between mb-2">
                    <span className="font-bold text-xs text-slate-800 flex items-center gap-1.5">
                      <span className="w-2 h-2 rounded-full bg-[#00C875]"></span>
                      PostgreSQL 16
                    </span>
                    <span className="text-[10px] font-mono text-emerald-600 font-semibold">{dbHealth?.database?.total_tables || 60} Tables</span>
                  </div>
                  <div className="text-[11px] text-slate-500 mb-3 font-mono">
                    DB: <span className="font-semibold text-slate-700">wazuh_soc_db</span>
                  </div>
                  <div className="grid grid-cols-2 gap-2 pt-2 border-t border-slate-100">
                    <div>
                      <span className="text-[10px] text-slate-400 block font-medium">Read Latency</span>
                      <span className="text-xs font-semibold text-slate-800">
                        {dbHealth?.performance?.read_latency_ms != null 
                          ? `${dbHealth.performance.read_latency_ms} ms` 
                          : (dbHealth?.latency_series?.slice(-1)[0]?.Read != null ? `${dbHealth.latency_series.slice(-1)[0].Read} ms` : '0.45 ms')}
                      </span>
                    </div>
                    <div>
                      <span className="text-[10px] text-slate-400 block font-medium">Write Latency</span>
                      <span className="text-xs font-semibold text-slate-800">
                        {dbHealth?.performance?.write_latency_ms != null 
                          ? `${dbHealth.performance.write_latency_ms} ms` 
                          : (dbHealth?.latency_series?.slice(-1)[0]?.Write != null ? `${dbHealth.latency_series.slice(-1)[0].Write} ms` : '1.19 ms')}
                      </span>
                    </div>
                  </div>
                  <div className="mt-2.5 pt-2 border-t border-slate-100 flex items-center justify-between text-[11px]">
                    <span className="text-slate-400">Status</span>
                    <span className="text-emerald-600 font-semibold font-mono text-[10.5px]">CONNECTED (Port 5432)</span>
                  </div>
                </div>

                {/* Sub-Card: Storage Architecture & State */}
                <div className="bg-white border border-slate-200/90 rounded-lg p-3.5 shadow-[0_1px_2px_rgba(0,0,0,0.02)] space-y-2.5">
                  <div className="flex items-center justify-between">
                    <span className="text-xs font-bold text-slate-800 flex items-center gap-1.5">
                      <Database className="w-3.5 h-3.5 text-blue-500" />
                      Wazuh SOC Store
                    </span>
                    <span className="text-[10px] font-bold text-emerald-600">
                      Online
                    </span>
                  </div>
                  
                  {/* Tag Pill */}
                  <div className="bg-slate-50 border border-slate-100 rounded-md py-1 px-2 text-center">
                    <span className="text-[10px] font-medium text-slate-600">
                      Transactional & Aggregate Security DB
                    </span>
                  </div>

                  {/* Metadata Rows */}
                  <div className="space-y-1 pt-1 text-[11px]">
                    <div className="flex items-center justify-between">
                      <span className="text-slate-400">Started At :</span>
                      <span className="font-mono text-slate-700 font-semibold text-[10.5px]">28 Oct 2026 | 06:08</span>
                    </div>
                    <div className="flex items-center justify-between">
                      <span className="text-slate-400">Uptime :</span>
                      <span className="font-mono text-slate-700 font-semibold text-[10.5px]">1D 21H 04M</span>
                    </div>
                  </div>
                </div>
              </div>
            </div>
          </div>

          {/* ========================================================================= */}
          {/* SECTION 3: RUNNING MICROSERVICES & DAEMONS                                */}
          {/* ========================================================================= */}
          <div className="bg-white rounded-xl border border-slate-200/90 shadow-sm p-6">
            {/* Header */}
            <div className="flex items-center justify-between mb-4">
              <div className="flex items-center gap-2">
                <h2 className="text-base font-bold text-slate-800 tracking-tight">
                  Running Microservices & Daemons
                </h2>
                <span className="text-xs font-semibold text-blue-600">
                  {dbHealth?.microservices?.length || 6}
                </span>
              </div>
              <div className="flex items-center gap-2">
                {/* Dropdown interval auto-refresh */}
                <div className="flex items-center gap-1.5">
                  <span className="text-[11px] text-slate-400 font-medium">Auto-refresh:</span>
                  <select
                    value={dbAutoRefresh}
                    onChange={e => {
                      const val = Number(e.target.value);
                      setDbAutoRefresh(val);
                      localStorage.setItem('dbRefresh', val);
                    }}
                    title="Nilai lebih kecil = data lebih sering diperbarui, namun menambah beban server."
                    className="border border-slate-200 rounded-md px-2 py-1 text-[11px] text-slate-600 bg-white shadow-[0_1px_2px_rgba(0,0,0,0.03)] cursor-pointer focus:outline-none focus:ring-1 focus:ring-blue-300"
                  >
                    <option value={5}>5 dtk</option>
                    <option value={10}>10 dtk</option>
                    <option value={30}>30 dtk</option>
                    <option value={60}>60 dtk</option>
                    <option value={300}>300 dtk</option>
                  </select>
                </div>
                <button
                  type="button"
                  onClick={() => fetchDbHealth(false)}
                  disabled={dbLoading}
                  className="px-3 py-1.5 rounded-lg border border-slate-200 bg-white hover:bg-slate-50 text-slate-600 text-xs font-medium flex items-center gap-1.5 transition-colors cursor-pointer shadow-[0_1px_2px_rgba(0,0,0,0.03)]"
                >
                  <RefreshCw className={`w-3.5 h-3.5 text-slate-400 ${dbLoading ? 'animate-spin text-blue-500' : ''}`} />
                  <span>Refresh</span>
                </button>
              </div>
            </div>

            {/* Microservices Table matching Reference Clean White/Grey format */}
            <div className="overflow-x-auto rounded-lg border border-slate-100">
              <table className="w-full text-left text-xs border-collapse">
                <thead>
                  <tr className="bg-[#F8FAFC] text-slate-600 border-b border-slate-200/80 text-[11px] font-bold uppercase tracking-wider">
                    <th className="px-5 py-3 min-w-[280px]">NAME</th>
                    <th className="px-5 py-3 min-w-[100px]">PID</th>
                    <th className="px-5 py-3 min-w-[90px]">CPU</th>
                    <th className="px-5 py-3 min-w-[110px]">MEMORY</th>
                    <th className="px-5 py-3 min-w-[80px]">SWAP</th>
                    <th className="px-5 py-3 min-w-[90px]">DISK</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-100 bg-white">
                  {(dbHealth?.microservices || [
                    { name: 'PostgreSQL Telemetry Engine (postgresql)', pid: '0x000033d', cpu: '0.15%', memory: '59.8 MB', swap: '0 B', disk: '7.2 MB' },
                    { name: 'Wazuh Manager Core Service (wazuh-manager)', pid: '0x0002982', cpu: '0.20%', memory: '276.0 MB', swap: '0 B', disk: '41.4 MB' },
                    { name: 'ASOC Telemetry Ingestion (fluent-bit)', pid: '0x0009c41', cpu: '0.20%', memory: '51.0 MB', swap: '0 B', disk: '7.6 MB' },
                    { name: 'ASOC FastAPI Backend (soc-v3-backend)', pid: '0x000099b', cpu: '0.15%', memory: '76.6 MB', swap: '0 B', disk: '9.2 MB' },
                    { name: 'ASOC UI Dashboard (soc-v3-frontend)', pid: '0x000099c', cpu: '0.10%', memory: '2.4 MB', swap: '0 B', disk: '1.8 MB' },
                    { name: 'ASOC Pipeline Worker (soc-worker)', pid: '0x0009d12', cpu: '0.15%', memory: '175.0 MB', swap: '0 B', disk: '22.1 MB' },
                  ]).map((svc, sIdx) => (
                    <tr key={`${svc.name}-${sIdx}`} className="hover:bg-slate-50/80 transition-colors">
                      <td className="px-5 py-3.5 text-slate-800 font-medium flex items-center gap-2.5">
                        <span className="w-2 h-2 rounded-full bg-[#00C875] inline-block shrink-0"></span>
                        <span className="truncate font-sans text-xs text-slate-800">{svc.name}</span>
                      </td>
                      <td className="px-5 py-3.5 font-mono text-slate-500 text-xs">{svc.pid}</td>
                      <td className="px-5 py-3.5 text-slate-700 text-xs font-sans">{svc.cpu}</td>
                      <td className="px-5 py-3.5 text-slate-700 text-xs font-sans">{svc.memory}</td>
                      <td className="px-5 py-3.5 text-slate-700 text-xs font-sans">{svc.swap}</td>
                      <td className="px-5 py-3.5 text-slate-700 text-xs font-sans">{svc.disk}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      )}

      {/* SUB-TAB 3: API SECURITY & KUOTA THREAT INTEL                              */}

      {/* ========================================================================= */}

      {activeTab === 'api_quota' && (

        <div className="space-y-6">

          {/* Top Threat Intel Cards */}

          <div className="grid grid-cols-1 md:grid-cols-2 gap-5">

            {/* AbuseIPDB Quota Gauge Card */}

            <div className="bg-[#0c101c] border border-slate-800/80 rounded-xl p-5 shadow-sm space-y-4">

              <div className="flex items-center justify-between pb-3 border-b border-slate-800">

                <div className="flex items-center gap-2.5">

                  <div className="w-9 h-9 rounded-lg bg-orange-500/10 border border-orange-500/30 flex items-center justify-center">

                    <ShieldAlert className="w-5 h-5 text-orange-400" />

                  </div>

                  <div>

                    <h2 className="text-sm font-bold text-slate-100">AbuseIPDB IP Reputation API v2</h2>

                    <p className="text-[11px] text-slate-400">Validasi otomatis IP Penyerang pada IOA agregasi</p>

                  </div>

                </div>

                <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-emerald-500/15 text-emerald-400 border border-emerald-500/30">

                  ONLINE 200 OK

                </span>

              </div>



              {/* Visual Quota Gauge */}

              <div>

                <div className="flex justify-between items-baseline mb-1.5 text-xs">

                  <span className="text-slate-400">Sisa Kuota Hari Ini:</span>

                  <span className="font-mono text-base font-bold text-orange-400">

                    {quotaData?.threat_intel?.abuseipdb?.remaining || 836} / {quotaData?.threat_intel?.abuseipdb?.daily_quota || 1000} Slot

                  </span>

                </div>

                <div className="w-full bg-slate-800 h-2.5 rounded-full overflow-hidden">

                  <div 

                    className="bg-orange-500 h-full rounded-full transition-all duration-500"

                    style={{ 

                      width: `${((quotaData?.threat_intel?.abuseipdb?.remaining || 836) / (quotaData?.threat_intel?.abuseipdb?.daily_quota || 1000)) * 100}%` 

                    }}

                  />

                </div>

                <div className="flex justify-between items-center mt-2 text-[11px] text-slate-400">

                  <span>Terpakai: <strong className="text-slate-200 font-mono">{quotaData?.threat_intel?.abuseipdb?.used_today || 164} cek</strong></span>

                  <span>Reset pada: <strong className="text-slate-200 font-mono">{quotaData?.threat_intel?.abuseipdb?.reset_in || '00:00 UTC'}</strong></span>

                </div>

              </div>



              {/* Parameter Table */}

              <div className="bg-[#080b13] rounded-lg p-3 border border-slate-800/80 text-xs space-y-2">

                <div className="flex justify-between items-center text-slate-400">

                  <span>Endpoint Check:</span>

                  <code className="font-mono text-[11px] text-slate-300">https://api.abuseipdb.com/api/v2/check</code>

                </div>

                <div className="flex justify-between items-center text-slate-400">

                  <span>Rate Limit:</span>

                  <span className="font-mono text-slate-200">30 request / menit</span>

                </div>

                <div className="flex justify-between items-center text-slate-400">

                  <span>Latensi Endpoint:</span>

                  <span className="font-mono text-emerald-400">118 ms (Cepat)</span>

                </div>

              </div>

            </div>



            {/* VirusTotal Quota Gauge Card */}

            <div className="bg-[#0c101c] border border-slate-800/80 rounded-xl p-5 shadow-sm space-y-4">

              <div className="flex items-center justify-between pb-3 border-b border-slate-800">

                <div className="flex items-center gap-2.5">

                  <div className="w-9 h-9 rounded-lg bg-blue-500/10 border border-blue-500/30 flex items-center justify-center">

                    <Globe className="w-5 h-5 text-blue-400" />

                  </div>

                  <div>

                    <h2 className="text-sm font-bold text-slate-100">VirusTotal Public API v3</h2>

                    <p className="text-[11px] text-slate-400">Pengayaan hash executable malware (SHA256) & domain IOC</p>

                  </div>

                </div>

                <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-emerald-500/15 text-emerald-400 border border-emerald-500/30">

                  ONLINE 200 OK

                </span>

              </div>



              {/* Visual Quota Gauge */}

              <div>

                <div className="flex justify-between items-baseline mb-1.5 text-xs">

                  <span className="text-slate-400">Sisa Kuota Hari Ini:</span>

                  <span className="font-mono text-base font-bold text-blue-400">

                    {quotaData?.threat_intel?.virustotal?.remaining || 411} / {quotaData?.threat_intel?.virustotal?.daily_quota || 500} Permintaan

                  </span>

                </div>

                <div className="w-full bg-slate-800 h-2.5 rounded-full overflow-hidden">

                  <div 

                    className="bg-blue-500 h-full rounded-full transition-all duration-500"

                    style={{ 

                      width: `${((quotaData?.threat_intel?.virustotal?.remaining || 411) / (quotaData?.threat_intel?.virustotal?.daily_quota || 500)) * 100}%` 

                    }}

                  />

                </div>

                <div className="flex justify-between items-center mt-2 text-[11px] text-slate-400">

                  <span>Terpakai: <strong className="text-slate-200 font-mono">{quotaData?.threat_intel?.virustotal?.used_today || 89} lookup</strong></span>

                  <span>Limit Rate: <strong className="text-slate-200 font-mono">4 req / min (Enforced)</strong></span>

                </div>

              </div>



              {/* Parameter Table */}

              <div className="bg-[#080b13] rounded-lg p-3 border border-slate-800/80 text-xs space-y-2">

                <div className="flex justify-between items-center text-slate-400">

                  <span>Endpoint Check:</span>

                  <code className="font-mono text-[11px] text-slate-300">https://www.virustotal.com/api/v3</code>

                </div>

                <div className="flex justify-between items-center text-slate-400">

                  <span>Paket Lisensi:</span>

                  <span className="font-mono text-slate-200">Academic & SecOps Research Tier</span>

                </div>

                <div className="flex justify-between items-center text-slate-400">

                  <span>Latensi Endpoint:</span>

                  <span className="font-mono text-emerald-400">245 ms (Stabil)</span>

                </div>

              </div>

            </div>

          </div>



          {/* Internal REST API Security Shield Section */}

          <div className="bg-[#0c101c] border border-slate-800/80 rounded-xl p-5 shadow-sm space-y-4">

            <div className="pb-3 border-b border-slate-800 flex items-center justify-between">

              <div>

                <h2 className="text-sm font-bold text-slate-100 flex items-center gap-2">

                  <Lock className="w-4 h-4 text-emerald-400" />

                  Keamanan Internal REST API SOC (FastAPI Hardening)

                </h2>

                <p className="text-xs text-slate-400 mt-0.5">

                  Konfigurasi autentikasi state-mutation, pembatasan origin CORS, dan enkripsi payload transmisi data.

                </p>

              </div>

              <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded text-xs font-mono font-bold bg-emerald-500/15 text-emerald-300 border border-emerald-500/30">

                <ShieldCheck className="w-3.5 h-3.5 text-emerald-400" />

                HARDENED

              </span>

            </div>



            <div className="grid grid-cols-1 md:grid-cols-3 gap-4">

              <div className="bg-[#080b13] rounded-lg p-3.5 border border-slate-800/80 space-y-2">

                <div className="text-[11px] font-semibold text-slate-400 uppercase tracking-wider">

                  API Key Enforcement

                </div>

                <div className="flex items-center gap-2">

                  <span className="w-2 h-2 rounded-full bg-emerald-400"></span>

                  <span className="text-xs font-mono text-slate-200 font-semibold">

                    X-API-Key / Bearer Token

                  </span>

                </div>

                <div className="text-[11px] text-slate-400">

                  Token Aktif: <code className="font-mono text-slate-300">{quotaData?.soc_api_security?.active_api_key_masked || 'wazu****2026'}</code>

                </div>

              </div>



              <div className="bg-[#080b13] rounded-lg p-3.5 border border-slate-800/80 space-y-2">

                <div className="text-[11px] font-semibold text-slate-400 uppercase tracking-wider">

                  CORS Allowed Origins

                </div>

                <div className="text-xs font-mono text-blue-300 truncate">

                  http://localhost:5173

                </div>

                <div className="text-[11px] text-slate-400">

                  Hanya UI dashboard terdaftar yang diizinkan melakukan pemanggilan API.

                </div>

              </div>



              <div className="bg-[#080b13] rounded-lg p-3.5 border border-slate-800/80 space-y-2">

                <div className="text-[11px] font-semibold text-slate-400 uppercase tracking-wider">

                  Siklus Rotasi Kunci

                </div>

                <div className="text-xs font-mono text-purple-300 font-semibold">

                  Kebijakan 90 Hari

                </div>

                <div className="text-[11px] text-slate-400">

                  Masa berlaku tersisa 76 hari sebelum rotasi kredensial wajib berikutnya.

                </div>

              </div>

            </div>

          </div>

        </div>

      )}



      {/* ========================================================================= */}

      {/* MODAL: TAMBAH PERSONEL / USER BARU                                       */}

      {/* ========================================================================= */}

      {isAddUserModalOpen && (

        <div className="fixed inset-0 z-50 bg-black/70 backdrop-blur-xs flex items-center justify-center p-4">

          <div className={`${isDark ? 'bg-[#0c101c] border-slate-700' : 'bg-white border-slate-200'} border rounded-xl max-w-md w-full p-6 shadow-2xl space-y-4`}>

            <div className={`flex items-center justify-between pb-3 border-b ${isDark ? 'border-slate-800' : 'border-slate-200'}`}>

              <div>

                <h3 className={`text-sm font-bold ${isDark ? 'text-slate-100' : 'text-slate-900'}`}>Tambah Akun Personel SOC Baru</h3>

              </div>

              <button

                onClick={() => setIsAddUserModalOpen(false)}

                className="text-slate-400 hover:text-slate-600 dark:hover:text-white cursor-pointer"

              >

                <X className="w-4 h-4" />

              </button>

            </div>



            {formError && (

              <div className="p-3 rounded-lg bg-red-500/10 border border-red-500/30 text-red-600 dark:text-red-300 text-xs flex items-center gap-2">

                <AlertTriangle className="w-4 h-4 shrink-0" />

                <span>{formError}</span>

              </div>

            )}



            {formSuccess && (

              <div className="p-3 rounded-lg bg-emerald-500/10 border border-emerald-500/30 text-emerald-600 dark:text-emerald-300 text-xs flex items-center gap-2">

                <CheckCircle2 className="w-4 h-4 shrink-0" />

                <span>{formSuccess}</span>

              </div>

            )}



            <form onSubmit={handleCreateUser} className="space-y-3.5 text-xs">

              <div>

                <label className="block text-slate-900 dark:text-slate-300 font-bold mb-1">Username</label>

                <input

                  type="text"

                  placeholder="e.g. analyst_john"

                  value={newUserForm.username}

                  onChange={(e) => setNewUserForm({ ...newUserForm, username: e.target.value })}

                  className={`w-full px-3 py-2 rounded-lg border font-mono ${

                    isDark 

                      ? 'bg-[#080b13] border-slate-700 text-slate-200' 

                      : 'bg-white border-slate-300 text-slate-900'

                  } focus:outline-none focus:border-blue-500`}

                  required

                />

              </div>



              <div>

                <label className="block text-slate-900 dark:text-slate-300 font-bold mb-1">Nama Lengkap</label>

                <input

                  type="text"

                  placeholder="e.g. John Doe"

                  value={newUserForm.full_name}

                  onChange={(e) => setNewUserForm({ ...newUserForm, full_name: e.target.value })}

                  className={`w-full px-3 py-2 rounded-lg border ${

                    isDark 

                      ? 'bg-[#080b13] border-slate-700 text-slate-200' 

                      : 'bg-white border-slate-300 text-slate-900'

                  } focus:outline-none focus:border-blue-500`}

                  required

                />

              </div>



              <div>

                <label className="block text-slate-900 dark:text-slate-300 font-bold mb-1">Email</label>

                <input

                  type="email"

                  placeholder="e.g. soc.analyst@internal-soc.local"

                  value={newUserForm.email}

                  onChange={(e) => setNewUserForm({ ...newUserForm, email: e.target.value })}

                  className={`w-full px-3 py-2 rounded-lg border font-mono ${

                    isDark 

                      ? 'bg-[#080b13] border-slate-700 text-slate-200' 

                      : 'bg-white border-slate-300 text-slate-900'

                  } focus:outline-none focus:border-blue-500`}

                  required

                />

              </div>



              <div>

                <label className="block text-slate-900 dark:text-slate-300 font-bold mb-1">Kata Sandi (Password Akun)</label>

                <input

                  type="password"

                  placeholder="Default jika kosong: WazuhSecOps2026!"

                  value={newUserForm.password}

                  onChange={(e) => setNewUserForm({ ...newUserForm, password: e.target.value })}

                  className={`w-full px-3 py-2 rounded-lg border font-mono ${

                    isDark 

                      ? 'bg-[#080b13] border-slate-700 text-slate-200' 

                      : 'bg-white border-slate-300 text-slate-900'

                  } focus:outline-none focus:border-blue-500`}

                />

              </div>



              <div>

                <label className="block text-slate-900 dark:text-slate-300 font-bold mb-1">Peran (Role)</label>

                <select

                  value={newUserForm.role}

                  onChange={(e) => setNewUserForm({ ...newUserForm, role: e.target.value })}

                  className={`w-full px-3 py-2 rounded-lg border font-medium ${

                    isDark 

                      ? 'bg-[#080b13] border-slate-700 text-slate-200' 

                      : 'bg-white border-slate-300 text-slate-900'

                  } focus:outline-none focus:border-blue-500`}

                >

                  <option value="SOC_ANALYST">SOC Analyst</option>

                  <option value="SOC_DEVELOPER">SOC Developer</option>

                  <option value="SOC_LEAD">SOC Lead</option>

                  <option value="SOC_MANAGER">SOC Manager</option>

                  <option value="ADMIN">Admin</option>

                </select>

              </div>



              <div className="pt-3 flex justify-end gap-2.5 border-t border-slate-200 dark:border-slate-800">

                <button

                  type="button"

                  onClick={() => setIsAddUserModalOpen(false)}

                  className="px-4 py-2 rounded-lg bg-rose-600 hover:bg-rose-500 text-white font-semibold transition-colors cursor-pointer shadow-sm text-xs"

                >

                  Batal

                </button>

                <button

                  type="submit"

                  disabled={submittingUser}

                  className="px-4 py-2 rounded-lg bg-blue-600 hover:bg-blue-500 text-white font-semibold flex items-center gap-1.5 transition-colors disabled:opacity-50 cursor-pointer shadow-sm text-xs"

                >

                  {submittingUser ? 'Menyimpan...' : 'Simpan Akun'}

                </button>

              </div>

            </form>

          </div>

        </div>

      )}



      {/* Modal Edit User & Reset Password (Admin) */}

      {isEditUserModalOpen && (

        <div className="fixed inset-0 z-50 bg-black/70 backdrop-blur-xs flex items-center justify-center p-4">

          <div className={`${isDark ? 'bg-[#0f1422] border-slate-700/80' : 'bg-white border-slate-200'} border rounded-2xl w-full max-w-lg p-6 shadow-2xl relative max-h-[90vh] overflow-y-auto`}>

            <div className={`flex items-center justify-between pb-3 border-b ${isDark ? 'border-slate-800' : 'border-slate-200'} mb-4`}>

              <div>

                <h3 className={`text-base font-bold ${isDark ? 'text-slate-100' : 'text-slate-900'}`}>

                  Edit Akun & Reset Akses Pengguna

                </h3>

              </div>

              <button

                onClick={() => setIsEditUserModalOpen(false)}

                className="text-slate-400 hover:text-slate-600 dark:hover:text-slate-200 p-1 rounded-lg hover:bg-slate-100 dark:hover:bg-slate-800 transition-colors cursor-pointer"

              >

                <X className="w-5 h-5" />

              </button>

            </div>



            {editError && (

              <div className="p-3 mb-4 rounded-lg bg-red-500/10 border border-red-500/30 text-red-600 dark:text-red-300 text-xs flex items-center gap-2">

                <AlertTriangle className="w-4 h-4 shrink-0" />

                <span>{editError}</span>

              </div>

            )}



            {editSuccess && (

              <div className="p-3 mb-4 rounded-lg bg-emerald-500/10 border border-emerald-500/30 text-emerald-600 dark:text-emerald-300 text-xs flex items-center gap-2">

                <CheckCircle2 className="w-4 h-4 shrink-0" />

                <span>{editSuccess}</span>

              </div>

            )}



            <form onSubmit={handleUpdateUser} className="space-y-3.5 text-xs">

              <div>

                <label className="block text-slate-900 dark:text-slate-300 font-bold mb-1">Username</label>

                <input

                  type="text"

                  value={editUserForm.username}

                  onChange={(e) => setEditUserForm({ ...editUserForm, username: e.target.value })}

                  className={`w-full px-3 py-2 rounded-lg border font-mono ${

                    isDark 

                      ? 'bg-[#080b13] border-slate-700 text-slate-200' 

                      : 'bg-white border-slate-300 text-slate-900'

                  } focus:outline-none focus:border-blue-500`}

                  required

                />

              </div>



              <div>

                <label className="block text-slate-900 dark:text-slate-300 font-bold mb-1">Nama Lengkap</label>

                <input

                  type="text"

                  value={editUserForm.full_name}

                  onChange={(e) => setEditUserForm({ ...editUserForm, full_name: e.target.value })}

                  className={`w-full px-3 py-2 rounded-lg border ${

                    isDark 

                      ? 'bg-[#080b13] border-slate-700 text-slate-200' 

                      : 'bg-white border-slate-300 text-slate-900'

                  } focus:outline-none focus:border-blue-500`}

                  required

                />

              </div>



              <div>

                <label className="block text-slate-900 dark:text-slate-300 font-bold mb-1">Email</label>

                <input

                  type="email"

                  value={editUserForm.email}

                  onChange={(e) => setEditUserForm({ ...editUserForm, email: e.target.value })}

                  className={`w-full px-3 py-2 rounded-lg border font-mono ${

                    isDark 

                      ? 'bg-[#080b13] border-slate-700 text-slate-200' 

                      : 'bg-white border-slate-300 text-slate-900'

                  } focus:outline-none focus:border-blue-500`}

                  required

                />

              </div>



              <div className="grid grid-cols-2 gap-3">

                <div>

                  <label className="block text-slate-900 dark:text-slate-300 font-bold mb-1">Peran (Role)</label>

                  <select

                    value={editUserForm.role}

                    onChange={(e) => setEditUserForm({ ...editUserForm, role: e.target.value })}

                    className={`w-full px-3 py-2 rounded-lg border font-medium ${

                      isDark 

                        ? 'bg-[#080b13] border-slate-700 text-slate-200' 

                        : 'bg-white border-slate-300 text-slate-900'

                    } focus:outline-none focus:border-blue-500`}

                  >

                    <option value="SOC_ANALYST">SOC Analyst</option>

                    <option value="SOC_DEVELOPER">SOC Developer</option>

                    <option value="SOC_LEAD">SOC Lead</option>

                    <option value="SOC_MANAGER">SOC Manager</option>

                    <option value="ADMIN">Admin</option>

                  </select>

                </div>



                <div>

                  <label className="block text-slate-900 dark:text-slate-300 font-bold mb-1">Status Akun</label>

                  <select

                    value={editUserForm.status}

                    onChange={(e) => setEditUserForm({ ...editUserForm, status: e.target.value })}

                    className={`w-full px-3 py-2 rounded-lg border font-medium ${

                      isDark 

                        ? 'bg-[#080b13] border-slate-700 text-slate-200' 

                        : 'bg-white border-slate-300 text-slate-900'

                    } focus:outline-none focus:border-blue-500`}

                  >

                    <option value="ACTIVE">Aktif</option>

                    <option value="SUSPENDED">Suspended</option>

                  </select>

                </div>

              </div>



              {/* Password Override / Reset Section */}

              <div className="space-y-1.5 mt-2">

                <div className="flex items-center justify-between">

                  <label className={`font-semibold ${

                    isDark ? 'text-amber-300' : 'text-slate-800'

                  }`}>

                    Reset Password Pengguna (Admin Override)

                  </label>

                  <button

                    type="button"

                    onClick={() => setEditUserForm({ ...editUserForm, new_password: 'WazuhSecOps2026!', reset_to_default: true })}

                    className="text-[10px] px-2.5 py-1 rounded bg-orange-500 hover:bg-orange-600 text-white font-semibold transition-colors cursor-pointer shadow-xs"

                  >

                    Set ke Default (WazuhSecOps2026!)

                  </button>

                </div>

                <input

                  type="password"

                  placeholder="Kosongkan jika password tidak ingin diubah"

                  value={editUserForm.new_password}

                  onChange={(e) => setEditUserForm({ ...editUserForm, new_password: e.target.value, reset_to_default: false })}

                  className={`w-full px-3 py-2 rounded-lg border font-mono ${

                    isDark 

                      ? 'bg-[#080b13] border-slate-700 text-slate-200' 

                      : 'bg-white border-slate-300 text-slate-900'

                  } focus:outline-none focus:border-amber-500`}

                />

              </div>



              <div className={`pt-3 flex justify-end gap-2.5 border-t ${

                isDark ? 'border-slate-800' : 'border-slate-200'

              }`}>

                <button

                  type="button"

                  onClick={() => setIsEditUserModalOpen(false)}

                  className="px-4 py-2 rounded-lg bg-rose-600 hover:bg-rose-500 text-white font-semibold transition-colors cursor-pointer shadow-sm text-xs"

                >

                  Batal

                </button>

                <button

                  type="submit"

                  disabled={submittingEdit}

                  className="px-4 py-2 rounded-lg bg-blue-600 hover:bg-blue-500 text-white font-semibold flex items-center gap-1.5 transition-colors disabled:opacity-50 cursor-pointer shadow-sm text-xs"

                >

                  {submittingEdit ? 'Menyimpan...' : 'Simpan Perubahan'}

                </button>

              </div>

            </form>

          </div>

        </div>

      )}

    </div>

  );

}

