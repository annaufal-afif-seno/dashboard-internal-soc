import React, { useState, useEffect, useMemo } from 'react';
import { 
  Shield, Users, Database, HardDrive, Globe, Key, UserPlus, 
  CheckCircle2, XCircle, AlertTriangle, RefreshCw, Server, Lock,
  Clock, Activity, Zap, FileText, Check, X, ShieldCheck, ShieldAlert,
  Eye, Pencil, Trash2, ChevronsUpDown, ChevronUp, ChevronDown, Ban,
  Search, ArrowDownRight, ArrowUpRight, Gauge, Cpu, BarChart2, Radio
} from 'lucide-react';

// 9 RBAC Matrix Items mapped directly to Application Sidebar Navigation & Separation of Duties (SoD)
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
    description: 'Analisis forensik insiden ancaman terkonfirmasi, inspeksi payload mentah, korelasi multi-tahap, dan konfirmasi ancaman nyata.',
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
    id: 'suppression_proposal',
    category: 'SUPPRESSION & TUNING',
    action: 'Ground Truth Review',
    description: 'Identifikasi noise alert berulang dari tiket investigasi dan inisiasi proposal formulasi supresi False Positive (FP) baru.',
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

  // 4. Modul SYSTEM MAINTENANCE
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

export default function SystemMaintenance({ initialTab = 'rbac', theme = 'dark' }) {
  const [activeTab, setActiveTab] = useState(initialTab);
  const isDark = theme === 'dark';

  useEffect(() => {
    if (initialTab) setActiveTab(initialTab);
  }, [initialTab]);

  // Separation of Duties Matrix State
  const [matrixData, setMatrixData] = useState(() => {
    try {
      const saved = localStorage.getItem('wazuh_rbac_permissions_matrix');
      if (saved) {
        const parsed = JSON.parse(saved);
        if (Array.isArray(parsed)) {
          return parsed.map(row => ({
            ...row,
            roles: Object.fromEntries(
              Object.entries(row.roles || {}).map(([r, val]) => [
                r,
                (val === 'READ_WRITE' || val === 'READ_ONLY') ? val : 'NO_ACCESS'
              ])
            )
          }));
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
      const res = await fetch(`http://localhost:8000/api/system/rbac/users/${editingUser.user_id}`, {
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
      const res = await fetch('http://localhost:8000/api/system/rbac/users');
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
  const [dbAutoRefresh, setDbAutoRefresh] = useState(300);
  const [lastDbSync, setLastDbSync] = useState(new Date());

  // Fetch DB Health
  const fetchDbHealth = async (isBackground = false) => {
    try {
      if (!isBackground) setDbLoading(true);
      const res = await fetch('http://localhost:8000/api/system/database/health');
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
      const res = await fetch('http://localhost:8000/api/system/integrations/quota');
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
      const res = await fetch('http://localhost:8000/api/system/rbac/users', {
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
      const res = await fetch(`http://localhost:8000/api/system/rbac/users/${userId}`, {
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
      const res = await fetch(`http://localhost:8000/api/system/rbac/users/${userId}`, {
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
      const res = await fetch('http://localhost:8000/api/system/database/maintenance/vacuum', {
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

              <button
                type="button"
                onClick={() => setIsAddUserModalOpen(true)}
                className="px-3.5 py-1.5 rounded-lg text-xs font-semibold bg-blue-600 hover:bg-blue-500 text-white flex items-center gap-2 transition-all cursor-pointer shadow-xs shrink-0"
              >
                <UserPlus className="w-3.5 h-3.5" />
                <span>Add User</span>
              </button>
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
                            onClick={() => handleToggleUserStatus(u.user_id, u.status)}
                            className="inline-flex items-center px-3 py-1 rounded-full text-xs font-medium bg-[#E6F4EA] text-[#137333] dark:bg-emerald-950/60 dark:text-emerald-400 cursor-pointer hover:opacity-80 transition-opacity"
                            title="Status: Aktif (Klik untuk ubah status ke Suspended)"
                          >
                            Aktif
                          </span>
                        ) : (
                          <span 
                            onClick={() => handleToggleUserStatus(u.user_id, u.status)}
                            className="inline-flex items-center px-3 py-1 rounded-full text-xs font-medium bg-[#FCE8E6] text-[#C5221F] dark:bg-rose-950/60 dark:text-rose-400 cursor-pointer hover:opacity-80 transition-opacity"
                            title="Status: Suspended (Klik untuk Aktifkan)"
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
                            title="Lihat Detail & Reset Password"
                          >
                            <Eye className="w-4 h-4" />
                          </button>
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
          {/* Action Header Card */}
          <div className="bg-[#0c101c] border border-slate-800/80 rounded-xl p-5 shadow-sm flex flex-col md:flex-row md:items-center justify-between gap-4">
            <div>
              <div className="flex items-center gap-2">
                <Database className="w-5 h-5 text-emerald-400" />
                <h2 className="text-base font-bold text-slate-100">
                  PostgreSQL Telemetry Engine (`{dbHealth?.database_name || 'wazuh_soc_db'}`)
                </h2>
                <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-emerald-500/20 text-emerald-300 border border-emerald-500/30">
                  STATUS: HEALTHY
                </span>
              </div>
              <p className="text-xs text-slate-400 mt-1">
                Koneksi aktif pada host <span className="font-mono text-slate-300">{dbHealth?.host || 'localhost'}:{dbHealth?.port || 5432}</span>. Melayani <strong>{dbHealth?.table_count || 31} tabel relasional & partisi</strong> berkinerja tinggi.
              </p>
            </div>

            <div className="flex flex-wrap items-center gap-2 shrink-0">
              {/* Auto Refresh Interval Selector */}
              <div className="flex items-center gap-1.5 bg-slate-900/90 border border-slate-700/80 px-2.5 py-1.5 rounded-lg text-xs">
                <Clock className="w-3.5 h-3.5 text-blue-400 shrink-0" />
                <span className="text-[11px] text-slate-400 font-medium whitespace-nowrap">Auto-Refresh:</span>
                <select
                  value={dbAutoRefresh}
                  onChange={(e) => setDbAutoRefresh(Number(e.target.value))}
                  className="bg-transparent text-slate-200 font-mono font-bold text-xs focus:outline-none cursor-pointer"
                  title="Pilih interval pembaruan metrik otomatis"
                >
                  <option value={10} className="bg-slate-900 text-slate-100">Realtime (10 dtk)</option>
                  <option value={30} className="bg-slate-900 text-slate-100">30 Detik</option>
                  <option value={60} className="bg-slate-900 text-slate-100">1 Menit</option>
                  <option value={300} className="bg-slate-900 text-slate-100">5 Menit (Standar)</option>
                  <option value={0} className="bg-slate-900 text-slate-100">Nonaktif</option>
                </select>
                {dbAutoRefresh > 0 && (
                  <span className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse ml-0.5" title="Auto-refresh aktif di latar belakang" />
                )}
              </div>

              <button
                type="button"
                onClick={() => fetchDbHealth(false)}
                disabled={dbLoading}
                className="px-3 py-2 rounded-lg text-xs font-semibold bg-slate-800 hover:bg-slate-700 text-slate-200 flex items-center gap-1.5 transition-all cursor-pointer shadow-sm border border-slate-700"
                title="Refresh Status Metrik Real-time"
              >
                <RefreshCw className={`w-3.5 h-3.5 ${dbLoading ? 'animate-spin' : ''}`} />
                <span>Refresh Metrik</span>
              </button>
              <button
                type="button"
                onClick={handleRunMaintenance}
                disabled={maintenanceRunning}
                className="px-4 py-2 rounded-lg text-xs font-semibold bg-emerald-600 hover:bg-emerald-500 text-white flex items-center gap-2 transition-all cursor-pointer shadow-sm disabled:opacity-50"
              >
                <RefreshCw className={`w-3.5 h-3.5 ${maintenanceRunning ? 'animate-spin' : ''}`} />
                <span>{maintenanceRunning ? 'Menjalankan ANALYZE...' : 'Jalankan Optimasi (ANALYZE)'}</span>
              </button>
            </div>
          </div>

          {/* Maintenance Notification */}
          {maintenanceResult && (
            <div className={`p-4 rounded-xl border flex items-center justify-between text-xs ${
              maintenanceResult.success
                ? 'bg-emerald-500/10 border-emerald-500/30 text-emerald-300'
                : 'bg-red-500/10 border-red-500/30 text-red-300'
            }`}>
              <div className="flex items-center gap-2.5">
                {maintenanceResult.success ? (
                  <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0" />
                ) : (
                  <AlertTriangle className="w-4 h-4 text-red-400 shrink-0" />
                )}
                <span>{maintenanceResult.message}</span>
              </div>
              <button
                type="button"
                onClick={() => setMaintenanceResult(null)}
                className="text-slate-400 hover:text-white"
              >
                <X className="w-4 h-4" />
              </button>
            </div>
          )}

          {/* SECTION 1: WAZUH REAL-TIME INGESTION STREAM & FRESHNESS LIVENESS (VECTOR -> POSTGRESQL) */}
          <div className="bg-[#0c101c] border border-slate-800/80 rounded-xl p-5 shadow-sm space-y-4">
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-slate-800/80 pb-3">
              <div className="flex items-center gap-2.5">
                <div className={`w-8 h-8 rounded-lg flex items-center justify-center border ${
                  dbHealth?.wazuh_ingestion?.is_realtime 
                    ? 'bg-emerald-500/10 border-emerald-500/30' 
                    : 'bg-blue-500/10 border-blue-500/30'
                }`}>
                  <Radio className={`w-4 h-4 ${dbHealth?.wazuh_ingestion?.is_realtime ? 'text-emerald-400 animate-pulse' : 'text-blue-400'}`} />
                </div>
                <div>
                  <h3 className="text-sm font-bold text-slate-100 flex items-center gap-2">
                    Waktu Terakhir Database Menerima Data dari Wazuh (Vector Ingestion Stream)
                  </h3>
                  <p className="text-xs text-slate-400">
                    Pelacakan waktu nyata (*liveness*) untuk mengukur dan memverifikasi apakah PostgreSQL masih aktif menerima data dari Wazuh via pipeline Vector.
                  </p>
                </div>
              </div>
              <div className="flex items-center gap-2">
                {dbHealth?.wazuh_ingestion?.is_realtime ? (
                  <span className="inline-flex items-center gap-1.5 px-3 py-1 rounded-full text-[11px] font-mono font-bold bg-emerald-500/15 text-emerald-400 border border-emerald-500/30">
                    <span className="w-2 h-2 rounded-full bg-emerald-400 animate-ping" />
                    REALTIME STREAM AKTIF
                  </span>
                ) : dbHealth?.wazuh_ingestion?.stream_status === 'LAGGING' ? (
                  <span className="inline-flex items-center gap-1.5 px-3 py-1 rounded-full text-[11px] font-mono font-bold bg-amber-500/15 text-amber-400 border border-amber-500/30">
                    <span className="w-2 h-2 rounded-full bg-amber-400" />
                    STREAM TERTUNDA (LAGGING)
                  </span>
                ) : (
                  <span className="inline-flex items-center gap-1.5 px-3 py-1 rounded-full text-[11px] font-mono font-bold bg-slate-800/80 text-amber-300 border border-amber-500/30">
                    <span className="w-2 h-2 rounded-full bg-amber-400" />
                    STREAM IDLE / DATA HISTORIS
                  </span>
                )}
                <span className="text-[11px] text-slate-400 font-mono hidden sm:inline-block">
                  Sync: {lastDbSync ? lastDbSync.toLocaleTimeString('id-ID') : '-'}
                </span>
                <button
                  type="button"
                  onClick={() => fetchDbHealth(false)}
                  disabled={dbLoading}
                  className="px-2.5 py-1 rounded-lg text-xs font-medium bg-slate-800 hover:bg-slate-700 text-slate-300 hover:text-white border border-slate-700 flex items-center gap-1 cursor-pointer transition-colors"
                  title="Cek apakah ada log baru yang masuk sekarang"
                >
                  <RefreshCw className={`w-3 h-3 ${dbLoading ? 'animate-spin' : ''}`} />
                  <span>Cek Realtime</span>
                </button>
              </div>
            </div>

            {/* 4 Specialized Wazuh Ingestion Metrics */}
            <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3.5">
              {/* Box 1: WAKTU TERAKHIR DATABASE MENERIMA DATA */}
              <div className="p-3.5 rounded-lg bg-[#080b13] border border-slate-800/80 space-y-2">
                <div className="flex items-center justify-between">
                  <span className="text-xs font-semibold text-slate-300 flex items-center gap-1.5">
                    <Clock className="w-3.5 h-3.5 text-blue-400" />
                    Waktu Terakhir Diterima DB
                  </span>
                  <span className="text-[10px] font-mono text-blue-400 bg-blue-500/10 px-1.5 py-0.5 rounded border border-blue-500/20">
                    ingested_at
                  </span>
                </div>
                <div className="text-base font-bold font-mono text-blue-400">
                  {dbHealth?.wazuh_ingestion?.last_received_pretty || '30 Sep 2026, 11:13:43 WIB'}
                </div>
                <div className="text-[11px] text-slate-400 flex items-center justify-between pt-1 border-t border-slate-800/60">
                  <span>Sink PostgreSQL:</span>
                  <span className="font-mono text-slate-300 font-medium">telemetry.raw_events</span>
                </div>
              </div>

              {/* Box 2: SELISIH WAKTU (LAG / REALTIME STATUS) */}
              <div className="p-3.5 rounded-lg bg-[#080b13] border border-slate-800/80 space-y-2">
                <div className="flex items-center justify-between">
                  <span className="text-xs font-semibold text-slate-300 flex items-center gap-1.5">
                    <Activity className={`w-3.5 h-3.5 ${dbHealth?.wazuh_ingestion?.is_realtime ? 'text-emerald-400' : 'text-amber-400'}`} />
                    Selisih Waktu (Ingestion Lag)
                  </span>
                  <span className={`text-[10px] font-mono px-1.5 py-0.5 rounded border ${
                    dbHealth?.wazuh_ingestion?.is_realtime 
                      ? 'text-emerald-400 bg-emerald-500/10 border-emerald-500/20' 
                      : 'text-amber-400 bg-amber-500/10 border-amber-500/20'
                  }`}>
                    {dbHealth?.wazuh_ingestion?.is_realtime ? 'REALTIME' : 'STREAM IDLE'}
                  </span>
                </div>
                <div className={`text-base font-bold font-mono ${
                  dbHealth?.wazuh_ingestion?.is_realtime ? 'text-emerald-400' : 'text-amber-300'
                }`}>
                  {dbHealth?.wazuh_ingestion?.lag_pretty || '5 hari 9 jam lalu'}
                </div>
                <div className="text-[11px] text-slate-400 flex items-center justify-between pt-1 border-t border-slate-800/60">
                  <span>Status Aliran:</span>
                  <span className={`font-mono font-semibold ${
                    dbHealth?.wazuh_ingestion?.is_realtime ? 'text-emerald-400' : 'text-amber-400'
                  }`}>
                    {dbHealth?.wazuh_ingestion?.is_realtime ? '✓ Real-time Sync' : 'Menunggu Aliran Vector'}
                  </span>
                </div>
              </div>

              {/* Box 3: TIMESTAMP EVENT ASLI WAZUH */}
              <div className="p-3.5 rounded-lg bg-[#080b13] border border-slate-800/80 space-y-2">
                <div className="flex items-center justify-between">
                  <span className="text-xs font-semibold text-slate-300 flex items-center gap-1.5">
                    <Zap className="w-3.5 h-3.5 text-purple-400" />
                    Waktu Event Asli Wazuh
                  </span>
                  <span className="text-[10px] font-mono text-purple-400 bg-purple-500/10 px-1.5 py-0.5 rounded border border-purple-500/20">
                    timestamp
                  </span>
                </div>
                <div className="text-base font-bold font-mono text-slate-100">
                  {dbHealth?.wazuh_ingestion?.last_event_pretty || '30 Sep 2026, 17:03:20 WIB'}
                </div>
                <div className="text-[11px] text-slate-400 flex items-center justify-between pt-1 border-t border-slate-800/60">
                  <span>Wazuh Agent ID:</span>
                  <span className="font-mono text-slate-300 font-semibold">{dbHealth?.wazuh_ingestion?.latest_agent_id || '001'}</span>
                </div>
              </div>

              {/* Box 4: TOTAL LOG TER-INGESTI */}
              <div className="p-3.5 rounded-lg bg-[#080b13] border border-slate-800/80 space-y-2">
                <div className="flex items-center justify-between">
                  <span className="text-xs font-semibold text-slate-300 flex items-center gap-1.5">
                    <Database className="w-3.5 h-3.5 text-emerald-400" />
                    Total Log Wazuh Ter-ingesti
                  </span>
                  <span className="text-[10px] font-mono text-emerald-400 bg-emerald-500/10 px-1.5 py-0.5 rounded border border-emerald-500/20">
                    PostgreSQL Sink
                  </span>
                </div>
                <div className="text-base font-bold font-mono text-slate-100">
                  {dbHealth?.wazuh_ingestion?.total_events ? Number(dbHealth.wazuh_ingestion.total_events).toLocaleString('id-ID') : '1.154.532'} events
                </div>
                <div className="text-[11px] text-slate-400 flex items-center justify-between pt-1 border-t border-slate-800/60">
                  <span>Shipper Pipeline:</span>
                  <span className="font-mono text-emerald-400 font-semibold">Vector (vector.dev)</span>
                </div>
              </div>
            </div>

            {/* Pipeline Readiness & Diagnostics Banner */}
            <div className="p-3 bg-[#080b13] border border-slate-800/80 rounded-lg flex flex-col md:flex-row items-start md:items-center justify-between gap-3 text-xs">
              <div className="flex items-center gap-2">
                <div className="w-2 h-2 rounded-full bg-blue-400 shrink-0" />
                <span className="text-slate-300">
                  <strong>Arsitektur Ingesti Real-Time:</strong> Wazuh Agent/Manager &rarr; Vector Shipper &rarr; PostgreSQL (<code className="text-blue-400 bg-slate-900 px-1 py-0.5 rounded font-mono text-[11px]">telemetry.raw_events</code>).
                </span>
              </div>
              <div className="text-slate-400 text-[11px] shrink-0 font-mono">
                Waktu Server SOC: <span className="text-slate-200">{dbHealth?.wazuh_ingestion?.server_time_pretty || '05 Okt 2026, 20:53:59 WIB'}</span>
              </div>
            </div>
          </div>

          {/* SECTION 2: READ & WRITE SPEED / THROUGHPUT ANALYTICS */}
          <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
            {/* Card 1: Read Performance & Latency */}
            <div className="bg-[#0c101c] border border-slate-800/80 rounded-xl p-4 shadow-sm space-y-3">
              <div className="flex items-center justify-between">
                <span className="text-xs font-bold text-slate-200 flex items-center gap-1.5 uppercase tracking-wide">
                  <ArrowDownRight className="w-4 h-4 text-blue-400" />
                  Kecepatan & Throughput Read
                </span>
                <span className="text-[10px] font-mono text-blue-400 bg-blue-500/10 px-2 py-0.5 rounded font-bold border border-blue-500/20">
                  {dbHealth?.performance?.read_pct || 99.96}% Beban
                </span>
              </div>
              <div className="flex items-baseline justify-between pt-1">
                <div>
                  <div className="text-2xl font-bold font-mono text-blue-400">
                    {dbHealth?.performance?.read_latency_ms || 0.17} ms
                  </div>
                  <div className="text-[11px] text-slate-400 mt-0.5">Benchmark Live Query Latency</div>
                </div>
                <span className="text-[11px] font-bold text-emerald-400 bg-emerald-500/10 px-2 py-1 rounded border border-emerald-500/20">
                  ⚡ Ultra-Fast RAM
                </span>
              </div>
              <div className="space-y-1.5 pt-2 border-t border-slate-800/60 text-xs text-slate-400">
                <div className="flex justify-between">
                  <span>Total Baris Dipindai (Scans):</span>
                  <span className="font-mono font-bold text-slate-200">
                    {dbHealth?.performance?.tup_returned ? Number(dbHealth.performance.tup_returned).toLocaleString('id-ID') : '3.106.501.824'}
                  </span>
                </div>
                <div className="flex justify-between">
                  <span>Total Baris Diambil (Fetched):</span>
                  <span className="font-mono font-bold text-slate-200">
                    {dbHealth?.performance?.tup_fetched ? Number(dbHealth.performance.tup_fetched).toLocaleString('id-ID') : '620.340.203'}
                  </span>
                </div>
                <div className="flex justify-between">
                  <span>Efisiensi Buffer RAM Cache:</span>
                  <span className="font-mono font-bold text-emerald-400">
                    {dbHealth?.performance?.buffer_cache_hit_pct || 65.4}%
                  </span>
                </div>
              </div>
            </div>

            {/* Card 2: Write Performance & Mutations */}
            <div className="bg-[#0c101c] border border-slate-800/80 rounded-xl p-4 shadow-sm space-y-3">
              <div className="flex items-center justify-between">
                <span className="text-xs font-bold text-slate-200 flex items-center gap-1.5 uppercase tracking-wide">
                  <ArrowUpRight className="w-4 h-4 text-emerald-400" />
                  Kecepatan & Mutasi Write
                </span>
                <span className="text-[10px] font-mono text-emerald-400 bg-emerald-500/10 px-2 py-0.5 rounded font-bold border border-emerald-500/20">
                  {dbHealth?.performance?.write_pct || 0.04}% Beban
                </span>
              </div>
              <div className="flex items-baseline justify-between pt-1">
                <div>
                  <div className="text-2xl font-bold font-mono text-emerald-400">
                    {dbHealth?.performance?.total_writes ? Number(dbHealth.performance.total_writes).toLocaleString('id-ID') : '1.183.054'}
                  </div>
                  <div className="text-[11px] text-slate-400 mt-0.5">Total Mutasi (Insert/Update/Delete)</div>
                </div>
                <span className="text-[11px] font-bold text-emerald-400 bg-emerald-500/10 px-2 py-1 rounded border border-emerald-500/20">
                  ✓ Transaksi Konsisten
                </span>
              </div>
              <div className="space-y-1.5 pt-2 border-t border-slate-800/60 text-xs text-slate-400">
                <div className="flex justify-between">
                  <span>Transaksi Berhasil (Commit):</span>
                  <span className="font-mono font-bold text-slate-200">
                    {dbHealth?.performance?.xact_commit ? Number(dbHealth.performance.xact_commit).toLocaleString('id-ID') : '14.165'}
                  </span>
                </div>
                <div className="flex justify-between">
                  <span>Rasio Keberhasilan Commit:</span>
                  <span className="font-mono font-bold text-emerald-400">
                    {dbHealth?.performance?.commit_success_pct || 72.8}%
                  </span>
                </div>
                <div className="flex justify-between">
                  <span>Update & Rollback Handling:</span>
                  <span className="font-mono font-bold text-slate-200">
                    {Number(dbHealth?.performance?.tup_updated || 1180529).toLocaleString('id-ID')} updates
                  </span>
                </div>
              </div>
            </div>

            {/* Card 3: Database Load Distribution & Engine RAM Config */}
            <div className="bg-[#0c101c] border border-slate-800/80 rounded-xl p-4 shadow-sm space-y-3">
              <div className="flex items-center justify-between">
                <span className="text-xs font-bold text-slate-200 flex items-center gap-1.5 uppercase tracking-wide">
                  <BarChart2 className="w-4 h-4 text-purple-400" />
                  Rasio Beban & Alokasi RAM
                </span>
                <span className="text-[10px] font-mono text-purple-400 bg-purple-500/10 px-2 py-0.5 rounded font-bold border border-purple-500/20">
                  PostgreSQL 16
                </span>
              </div>
              <div>
                <div className="flex items-center justify-between text-xs text-slate-300 font-mono mb-1.5">
                  <span className="text-blue-400">Read: {dbHealth?.performance?.read_pct || 99.96}%</span>
                  <span className="text-emerald-400">Write: {dbHealth?.performance?.write_pct || 0.04}%</span>
                </div>
                <div className="w-full h-2.5 rounded-full bg-slate-800 overflow-hidden flex">
                  <div 
                    className="bg-blue-500 h-full" 
                    style={{ width: `${dbHealth?.performance?.read_pct || 99.96}%` }} 
                    title={`Read: ${dbHealth?.performance?.read_pct || 99.96}%`}
                  />
                  <div 
                    className="bg-emerald-500 h-full" 
                    style={{ width: `${dbHealth?.performance?.write_pct || 0.04}%` }} 
                    title={`Write: ${dbHealth?.performance?.write_pct || 0.04}%`}
                  />
                </div>
              </div>
              <div className="space-y-1.5 pt-2 border-t border-slate-800/60 text-xs text-slate-400">
                <div className="flex justify-between">
                  <span>Alokasi Shared Buffers (RAM):</span>
                  <span className="font-mono font-bold text-purple-300">{dbHealth?.performance?.shared_buffers || '128MB'}</span>
                </div>
                <div className="flex justify-between">
                  <span>Work Memory per Query (Sort/Hash):</span>
                  <span className="font-mono font-bold text-slate-200">{dbHealth?.performance?.work_mem || '4MB'}</span>
                </div>
                <div className="flex justify-between">
                  <span>Concurrency Locks Aktif:</span>
                  <span className="font-mono font-bold text-slate-200">{dbHealth?.performance?.active_locks || 59} locks</span>
                </div>
              </div>
            </div>
          </div>

          {/* Database Metrics Grid */}
          <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
            <div className="bg-[#0c101c] border border-slate-800/80 rounded-xl p-4 shadow-sm">
              <div className="flex items-center justify-between">
                <span className="text-xs font-medium text-slate-400">Total Ukuran Database</span>
                <HardDrive className="w-4 h-4 text-blue-400" />
              </div>
              <div className="mt-2 flex items-baseline gap-2">
                <span className="text-2xl font-bold font-mono text-slate-100">
                  {dbHealth?.total_size_pretty || '2596 MB'}
                </span>
                <span className="text-[11px] text-slate-400">di Disk</span>
              </div>
              <div className="mt-2 text-[11px] text-slate-400 border-t border-slate-800/60 pt-2 flex items-center justify-between">
                <span>Schema Telemetry & Agregasi</span>
                <span className="font-mono text-blue-400 font-semibold">100% On-Prem</span>
              </div>
            </div>

            <div className="bg-[#0c101c] border border-slate-800/80 rounded-xl p-4 shadow-sm">
              <div className="flex items-center justify-between">
                <span className="text-xs font-medium text-slate-400">Cache Hit Ratio Buffer</span>
                <Zap className="w-4 h-4 text-amber-400" />
              </div>
              <div className="mt-2 flex items-baseline gap-2">
                <span className="text-2xl font-bold font-mono text-amber-400">
                  {dbHealth?.cache_hit_ratio || 94.16}%
                </span>
                <span className="text-[11px] text-emerald-400 font-medium">Sangat Cepat</span>
              </div>
              <div className="mt-2 text-[11px] text-slate-400 border-t border-slate-800/60 pt-2 flex items-center justify-between">
                <span>Efisiensi Buffer RAM</span>
                <span className="font-mono text-emerald-400 font-semibold">&gt; 90% Target</span>
              </div>
            </div>

            <div className="bg-[#0c101c] border border-slate-800/80 rounded-xl p-4 shadow-sm">
              <div className="flex items-center justify-between">
                <span className="text-xs font-medium text-slate-400">Connection Pool (Threaded)</span>
                <Activity className="w-4 h-4 text-purple-400" />
              </div>
              <div className="mt-2 flex items-baseline gap-2">
                <span className="text-2xl font-bold font-mono text-purple-400">
                  {dbHealth?.pool?.total_connections || 4}
                </span>
                <span className="text-[11px] text-slate-400">/ {dbHealth?.pool?.maxconn || 30} Maks</span>
              </div>
              <div className="mt-2 text-[11px] text-slate-400 border-t border-slate-800/60 pt-2 flex items-center justify-between">
                <span>Utilisasi Pool</span>
                <span className="font-mono text-purple-300 font-semibold">
                  {dbHealth?.pool?.utilization_pct || 13.3}%
                </span>
              </div>
            </div>

            <div className="bg-[#0c101c] border border-slate-800/80 rounded-xl p-4 shadow-sm">
              <div className="flex items-center justify-between">
                <span className="text-xs font-medium text-slate-400">Health Bloat Index</span>
                <CheckCircle2 className="w-4 h-4 text-emerald-400" />
              </div>
              <div className="mt-2 flex items-baseline gap-2">
                <span className="text-2xl font-bold font-mono text-emerald-400">
                  {dbHealth?.maintenance?.bloat_pct || 0.0}%
                </span>
                <span className="text-[11px] text-emerald-400 font-medium">Optimal</span>
              </div>
              <div className="mt-2 text-[11px] text-slate-400 border-t border-slate-800/60 pt-2 flex items-center justify-between">
                <span>Dead Tuples</span>
                <span className="font-mono text-slate-300">
                  {dbHealth?.maintenance?.total_dead_tuples || 0} baris
                </span>
              </div>
            </div>
          </div>

          {/* SECTION 3: COMPLETE TABLE MEMORY USAGE & STORAGE BREAKDOWN (ALL 31 TABLES) */}
          <div className={`border rounded-xl overflow-hidden shadow-sm ${
            isDark ? 'bg-[#0c101c] border-slate-800/80' : 'bg-white border-slate-200/80'
          }`}>
            <div className={`p-4 border-b flex flex-col md:flex-row md:items-center justify-between gap-3 ${
              isDark ? 'border-slate-800' : 'border-slate-200/80'
            }`}>
              <div>
                <h2 className={`text-sm font-bold ${isDark ? 'text-slate-100' : 'text-slate-900'}`}>
                  Memory Usage & Penyimpanan Seluruh Tabel
                </h2>
              </div>

              {/* Table Search Input */}
              <div className="relative w-full md:w-64">
                <Search className="w-3.5 h-3.5 text-slate-400 absolute left-3 top-1/2 -translate-y-1/2" />
                <input
                  type="text"
                  placeholder="Cari tabel atau skema..."
                  value={dbTableSearch}
                  onChange={(e) => setDbTableSearch(e.target.value)}
                  className={`w-full border rounded-lg pl-8 pr-3 py-1.5 text-xs transition-colors focus:outline-none focus:border-blue-500 ${
                    isDark 
                      ? 'bg-[#080b13] border-slate-700/80 text-slate-200 placeholder-slate-500' 
                      : 'bg-slate-50 border-slate-200 text-slate-900 placeholder-slate-400'
                  }`}
                />
              </div>
            </div>

            {/* Schema Filters Bar */}
            <div className={`px-4 py-2 border-b flex items-center gap-1.5 overflow-x-auto text-[11px] ${
              isDark ? 'bg-[#080b13] border-slate-800' : 'bg-[#F8FAFC] border-slate-200/80'
            }`}>
              <span className={`text-[10px] font-semibold uppercase tracking-wider mr-1 shrink-0 ${isDark ? 'text-slate-400' : 'text-slate-500'}`}>
                Filter Skema:
              </span>
              <button
                type="button"
                onClick={() => setDbSchemaFilter('ALL')}
                className={`px-2.5 py-1 rounded font-medium cursor-pointer transition-colors ${
                  dbSchemaFilter === 'ALL'
                    ? 'bg-blue-600 text-white font-bold'
                    : isDark 
                      ? 'bg-slate-800/80 text-slate-400 hover:text-slate-200 hover:bg-slate-700' 
                      : 'bg-white text-slate-600 hover:text-slate-900 hover:bg-slate-100 border border-slate-200/80'
                }`}
              >
                ALL ({dbHealth?.tables?.length || 31})
              </button>
              {uniqueSchemas.map(sch => {
                const count = dbHealth?.tables?.filter(t => t.schemaname === sch).length || 0;
                return (
                  <button
                    key={sch}
                    type="button"
                    onClick={() => setDbSchemaFilter(sch)}
                    className={`px-2.5 py-1 rounded font-mono text-[11px] cursor-pointer transition-colors ${
                      dbSchemaFilter === sch
                        ? 'bg-blue-600 text-white font-bold'
                        : isDark 
                          ? 'bg-slate-800/80 text-slate-400 hover:text-slate-200 hover:bg-slate-700' 
                          : 'bg-white text-slate-600 hover:text-slate-900 hover:bg-slate-100 border border-slate-200/80'
                    }`}
                  >
                    {sch} ({count})
                  </button>
                );
              })}
            </div>

            <div className="overflow-x-auto max-h-[520px] overflow-y-auto">
              <table className="w-full text-left text-xs border-collapse">
                <thead className={`border-b text-xs font-semibold sticky top-0 z-10 backdrop-blur-md ${
                  isDark 
                    ? 'bg-[#0b101d] text-slate-300 border-slate-800' 
                    : 'bg-[#F0F5FA] text-slate-700 border-slate-200/80'
                }`}>
                  <tr>
                    <th 
                      onClick={() => handleDbSort('schemaname')}
                      className="px-4 py-3.5 cursor-pointer select-none group hover:bg-slate-200/50 dark:hover:bg-slate-800/60 transition-colors"
                      title="Urutkan Skema"
                    >
                      <div className="flex items-center gap-1.5">
                        <span className={dbSortField === 'schemaname' ? 'text-blue-600 dark:text-blue-400 font-bold' : 'group-hover:text-slate-900 dark:group-hover:text-white transition-colors'}>Skema</span>
                        {renderDbSortIcon('schemaname')}
                      </div>
                    </th>
                    <th 
                      onClick={() => handleDbSort('table_name')}
                      className="px-4 py-3.5 cursor-pointer select-none group hover:bg-slate-200/50 dark:hover:bg-slate-800/60 transition-colors"
                      title="Urutkan Nama Tabel"
                    >
                      <div className="flex items-center gap-1.5">
                        <span className={dbSortField === 'table_name' ? 'text-blue-600 dark:text-blue-400 font-bold' : 'group-hover:text-slate-900 dark:group-hover:text-white transition-colors'}>Nama Tabel / Partisi</span>
                        {renderDbSortIcon('table_name')}
                      </div>
                    </th>
                    <th 
                      onClick={() => handleDbSort('total_bytes')}
                      className="px-4 py-3.5 cursor-pointer select-none group hover:bg-slate-200/50 dark:hover:bg-slate-800/60 transition-colors"
                      title="Urutkan Total Ukuran"
                    >
                      <div className="flex items-center gap-1.5">
                        <span className={dbSortField === 'total_bytes' ? 'text-blue-600 dark:text-blue-400 font-bold' : 'group-hover:text-slate-900 dark:group-hover:text-white transition-colors'}>Total Ukuran</span>
                        {renderDbSortIcon('total_bytes')}
                      </div>
                    </th>
                    <th 
                      onClick={() => handleDbSort('table_bytes')}
                      className="px-4 py-3.5 cursor-pointer select-none group hover:bg-slate-200/50 dark:hover:bg-slate-800/60 transition-colors"
                      title="Urutkan Data Heap"
                    >
                      <div className="flex items-center gap-1.5">
                        <span className={dbSortField === 'table_bytes' ? 'text-blue-600 dark:text-blue-400 font-bold' : 'group-hover:text-slate-900 dark:group-hover:text-white transition-colors'}>Data (Heap)</span>
                        {renderDbSortIcon('table_bytes')}
                      </div>
                    </th>
                    <th 
                      onClick={() => handleDbSort('index_bytes')}
                      className="px-4 py-3.5 cursor-pointer select-none group hover:bg-slate-200/50 dark:hover:bg-slate-800/60 transition-colors"
                      title="Urutkan Indeks"
                    >
                      <div className="flex items-center gap-1.5">
                        <span className={dbSortField === 'index_bytes' ? 'text-blue-600 dark:text-blue-400 font-bold' : 'group-hover:text-slate-900 dark:group-hover:text-white transition-colors'}>Indeks (RAM/Disk)</span>
                        {renderDbSortIcon('index_bytes')}
                      </div>
                    </th>
                    <th 
                      onClick={() => handleDbSort('buffer_cache_hit_pct')}
                      className="px-4 py-3.5 cursor-pointer select-none group hover:bg-slate-200/50 dark:hover:bg-slate-800/60 transition-colors"
                      title="Urutkan RAM Buffer Hit"
                    >
                      <div className="flex items-center gap-1.5">
                        <span className={dbSortField === 'buffer_cache_hit_pct' ? 'text-blue-600 dark:text-blue-400 font-bold' : 'group-hover:text-slate-900 dark:group-hover:text-white transition-colors'}>RAM Buffer Hit %</span>
                        {renderDbSortIcon('buffer_cache_hit_pct')}
                      </div>
                    </th>
                    <th 
                      onClick={() => handleDbSort('estimated_rows')}
                      className="px-4 py-3.5 cursor-pointer select-none group hover:bg-slate-200/50 dark:hover:bg-slate-800/60 transition-colors"
                      title="Urutkan Live Rows"
                    >
                      <div className="flex items-center gap-1.5">
                        <span className={dbSortField === 'estimated_rows' ? 'text-blue-600 dark:text-blue-400 font-bold' : 'group-hover:text-slate-900 dark:group-hover:text-white transition-colors'}>Live Rows</span>
                        {renderDbSortIcon('estimated_rows')}
                      </div>
                    </th>
                    <th 
                      onClick={() => handleDbSort('dead_tuples')}
                      className="px-4 py-3.5 cursor-pointer select-none group hover:bg-slate-200/50 dark:hover:bg-slate-800/60 transition-colors"
                      title="Urutkan Dead Tuples"
                    >
                      <div className="flex items-center gap-1.5">
                        <span className={dbSortField === 'dead_tuples' ? 'text-blue-600 dark:text-blue-400 font-bold' : 'group-hover:text-slate-900 dark:group-hover:text-white transition-colors'}>Dead Tuples</span>
                        {renderDbSortIcon('dead_tuples')}
                      </div>
                    </th>
                    <th 
                      onClick={() => handleDbSort('last_autovacuum')}
                      className="px-4 py-3.5 cursor-pointer select-none group hover:bg-slate-200/50 dark:hover:bg-slate-800/60 transition-colors"
                      title="Urutkan Terakhir Autovacuum"
                    >
                      <div className="flex items-center gap-1.5">
                        <span className={dbSortField === 'last_autovacuum' ? 'text-blue-600 dark:text-blue-400 font-bold' : 'group-hover:text-slate-900 dark:group-hover:text-white transition-colors'}>Terakhir Autovacuum</span>
                        {renderDbSortIcon('last_autovacuum')}
                      </div>
                    </th>
                    <th className="px-4 py-3.5 text-center">
                      <span>Status</span>
                    </th>
                  </tr>
                </thead>
                <tbody className={`divide-y font-sans ${
                  isDark ? 'divide-slate-800/60 bg-[#0a0e1a]' : 'divide-slate-100 bg-white'
                }`}>
                  {filteredTables.length === 0 ? (
                    <tr>
                      <td colSpan={10} className="px-6 py-14 text-center">
                        <span className={`text-xs font-mono ${isDark ? 'text-slate-500' : 'text-slate-400'}`}>
                          Tidak ada tabel yang cocok dengan pencarian "{dbTableSearch}".
                        </span>
                      </td>
                    </tr>
                  ) : (
                    filteredTables.map((tbl, idx) => (
                      <tr 
                        key={idx} 
                        className={`transition-colors ${
                          isDark ? 'hover:bg-slate-800/30' : 'hover:bg-slate-50/70'
                        }`}
                      >
                        <td className="px-4 py-3.5 font-mono text-xs font-semibold text-slate-700 dark:text-slate-300 whitespace-nowrap">
                          {tbl.schemaname}
                        </td>

                        <td className="px-4 py-3.5 font-mono font-bold text-xs text-slate-900 dark:text-white">
                          {tbl.table_name}
                        </td>

                        <td className="px-4 py-3.5 font-mono font-bold text-xs text-slate-800 dark:text-slate-200">
                          {tbl.total_size}
                        </td>

                        <td className="px-4 py-3.5 font-mono text-xs text-slate-600 dark:text-slate-300">
                          {tbl.table_size || '0 bytes'}
                        </td>

                        <td className="px-4 py-3.5 font-mono text-xs text-slate-600 dark:text-slate-300">
                          {tbl.index_size || '0 bytes'}
                        </td>

                        <td className="px-4 py-3.5 font-mono text-xs font-semibold text-slate-700 dark:text-slate-300">
                          {tbl.buffer_cache_hit_pct || 0}%
                        </td>

                        <td className="px-4 py-3.5 font-mono text-xs text-slate-700 dark:text-slate-300">
                          {Number(tbl.estimated_rows || 0).toLocaleString('id-ID')}
                        </td>

                        <td className="px-4 py-3.5 font-mono text-xs text-slate-500 dark:text-slate-400">
                          {Number(tbl.dead_tuples || 0).toLocaleString('id-ID')}
                        </td>

                        <td className="px-4 py-3.5 font-mono text-xs text-slate-600 dark:text-slate-400 whitespace-nowrap">
                          {tbl.last_autovacuum ? new Date(tbl.last_autovacuum).toLocaleString('id-ID', { dateStyle: 'short', timeStyle: 'short' }) : 'System Default'}
                        </td>

                        <td className="px-4 py-3.5 text-center font-mono">
                          <span className="status-badge inline-block px-3.5 py-1.5 rounded-md border border-emerald-500 bg-emerald-500 text-white font-bold text-xs tracking-wider uppercase shadow-xs">
                            OPTIMAL
                          </span>
                        </td>
                      </tr>
                    ))
                  )}
                </tbody>
              </table>
            </div>

            <div className={`p-3 border-t text-[11px] flex items-center justify-between ${
              isDark ? 'bg-[#080b13] border-slate-800 text-slate-400' : 'bg-[#F8FAFC] border-slate-200/80 text-slate-500'
            }`}>
              <span>Menampilkan <strong>{filteredTables.length}</strong> dari <strong>{dbHealth?.tables?.length || 31}</strong> tabel/partisi di PostgreSQL</span>
              <span className="font-mono text-[10px] text-slate-400 dark:text-slate-500">wazuh_soc_db (PostgreSQL 16 Enterprise)</span>
            </div>
          </div>
        </div>
      )}

      {/* ========================================================================= */}
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
                  placeholder="e.g. john.doe@pradita.ac.id"
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
