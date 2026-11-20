import React, { useState, useEffect, useMemo } from 'react';
import { 
  Database, RefreshCw, CheckCircle2, AlertTriangle, ChevronDown, ChevronUp, 
  Search, ShieldCheck, ArrowRightLeft, Layers, Play, Check, Clock, Server,
  Cpu, Activity, Terminal, RotateCcw, X, Info
} from 'lucide-react';

export default function DataSyncAudit({ 
  theme = 'dark', 
  selectedTenant = 'all', 
  timeRange = 'semua', 
  customStartDate = null, 
  customEndDate = null, 
  isReadOnly = false, 
  currentUser 
}) {
  const [loading, setLoading] = useState(true);
  const [data, setData] = useState(null);
  const [error, setError] = useState(null);
  const [searchQuery, setSearchQuery] = useState('');
  const [expandedTenants, setExpandedTenants] = useState({});
  const [reconciling, setReconciling] = useState(false);
  const [reconcileResult, setReconcileResult] = useState(null);

  // Countdown Timer untuk Auto-Reconcile (5 Menit / 300 Detik sesuai timer server)
  const TOTAL_RECONCILE_SECONDS = 300;
  const [countdown, setCountdown] = useState(TOTAL_RECONCILE_SECONDS);

  useEffect(() => {
    const timer = setInterval(() => {
      setCountdown(prev => {
        if (prev <= 1) {
          fetchSyncData();
          return TOTAL_RECONCILE_SECONDS;
        }
        return prev - 1;
      });
    }, 1000);
    return () => clearInterval(timer);
  }, []);

  const formatCountdown = (sec) => {
    const m = Math.floor(sec / 60);
    const s = sec % 60;
    return `${m}:${s < 10 ? '0' : ''}${s}`;
  };

  // Machine Engine Health State (Perintah 1: Cek Mesin Hidup atau Mati)
  const [serviceHealth, setServiceHealth] = useState(null);
  const [checkingHealth, setCheckingHealth] = useState(false);
  const [showHealthModal, setShowHealthModal] = useState(false);
  const [restartingUnit, setRestartingUnit] = useState(null);
  const [serviceActionMsg, setServiceActionMsg] = useState(null);

  const isDark = theme === 'dark';

  // Fetch sync data from API based on active timeRange, custom dates, and selectedTenant
  const fetchSyncData = async () => {
    try {
      setLoading(true);
      setError(null);
      const params = new URLSearchParams();
      params.append('range', timeRange || 'semua');
      if (selectedTenant && selectedTenant.toLowerCase() !== 'all') {
        params.append('tenant', selectedTenant);
      }
      if (timeRange === 'custom' && customStartDate && customEndDate) {
        params.append('start', customStartDate);
        params.append('end', customEndDate);
      }
      const res = await fetch(`/api/system/data-sync?${params.toString()}`);
      if (!res.ok) {
        throw new Error(`HTTP error ${res.status}: ${res.statusText}`);
      }
      const json = await res.json();
      setData(json);

      // Default expand all tenants on load
      if (json.tenants) {
        const initialExpand = {};
        json.tenants.forEach(t => {
          initialExpand[t.tenant_id] = true;
        });
        setExpandedTenants(initialExpand);
      }
    } catch (err) {
      console.error('[DataSyncAudit] Fetch error:', err);
      setError(err.message || 'Failed to fetch data synchronization metrics');
    } finally {
      setLoading(false);
    }
  };

  // Fetch machine / service health status
  const fetchServiceHealth = async (openModal = false) => {
    try {
      setCheckingHealth(true);
      const res = await fetch('/api/system/service-health');
      if (res.ok) {
        const json = await res.json();
        setServiceHealth(json);
        if (openModal) {
          setShowHealthModal(true);
        }
      }
    } catch (err) {
      console.error('[DataSyncAudit] Service health check error:', err);
    } finally {
      setCheckingHealth(false);
    }
  };

  // Restart unit safely
  const handleRestartService = async (unitName) => {
    if (isReadOnly) return;
    try {
      setRestartingUnit(unitName);
      setServiceActionMsg(null);
      const res = await fetch('/api/system/service-health/restart', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ service: unitName })
      });
      const json = await res.json();
      setServiceActionMsg(json.message || `Layanan ${unitName} berhasil di-restart.`);
      // Refresh status after 2 seconds
      setTimeout(() => {
        fetchServiceHealth(false);
      }, 2000);
    } catch (err) {
      setServiceActionMsg(`Gagal restart: ${err.message}`);
    } finally {
      setRestartingUnit(null);
    }
  };

  useEffect(() => {
    fetchSyncData();
    fetchServiceHealth(false); // background check on mount
  }, [timeRange, selectedTenant, customStartDate, customEndDate]);

  // Toggle single tenant expand/collapse
  const toggleTenant = (tenantId) => {
    setExpandedTenants(prev => ({
      ...prev,
      [tenantId]: !prev[tenantId]
    }));
  };

  // Toggle all tenants expand/collapse
  const toggleAll = (expand) => {
    if (!data?.tenants) return;
    const newState = {};
    data.tenants.forEach(t => {
      newState[t.tenant_id] = expand;
    });
    setExpandedTenants(newState);
  };

  // Trigger self-healing reconciliation
  const triggerReconcile = async () => {
    if (isReadOnly) return;
    setCountdown(TOTAL_RECONCILE_SECONDS); // Reset garis penuh kembali dari awal
    try {
      setReconciling(true);
      setReconcileResult(null);
      const res = await fetch('/api/system/data-sync/reconcile', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' }
      });
      const result = await res.json();
      setReconcileResult(result.message || 'Reconciliation triggered successfully.');
      setTimeout(() => {
        fetchSyncData();
      }, 3000);
    } catch (err) {
      console.error('[DataSyncAudit] Reconcile trigger error:', err);
      setReconcileResult(`Error: ${err.message}`);
    } finally {
      setReconciling(false);
    }
  };

  // Filter tenants by search query
  const filteredTenants = useMemo(() => {
    if (!data?.tenants) return [];
    if (!searchQuery.trim()) return data.tenants;
    const q = searchQuery.toLowerCase();
    return data.tenants.filter(t => 
      t.tag?.toLowerCase().includes(q) ||
      t.name?.toLowerCase().includes(q) ||
      t.database?.toLowerCase().includes(q) ||
      t.wazuh_group?.some(g => g.toLowerCase().includes(q))
    );
  }, [data, searchQuery]);

  const allExpanded = useMemo(() => {
    if (!data?.tenants || data.tenants.length === 0) return false;
    return data.tenants.every(t => expandedTenants[t.tenant_id]);
  }, [data, expandedTenants]);

  const isStreamerRunning = serviceHealth?.services?.streamer?.is_active ?? true;
  const isTimerWaiting = serviceHealth?.services?.reconciliation_timer?.is_active ?? true;
  const isEngineHealthy = isStreamerRunning && isTimerWaiting;

  return (
    <div className={`p-4 sm:p-6 space-y-5 ${isDark ? 'text-slate-100' : 'text-slate-800'}`}>

      {/* KPI Overview Cards */}
                  {data?.summary && (
        <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-5 gap-3.5">
          {/* Card 1: Agent Status Donut / Pie Chart (Matching Reference) */}
          <div className={`p-3.5 rounded-xl border transition-all flex flex-col justify-between min-h-[105px] ${
            isDark ? 'bg-slate-900/60 border-slate-800' : 'bg-white border-slate-200 shadow-sm'
          }`}>
            <div className="flex items-center justify-between text-xs text-slate-400 mb-1">
              <span className={`font-semibold ${isDark ? 'text-slate-300' : 'text-slate-600'}`}>Agent Status</span>
            </div>

            {/* Donut Chart & Clean Legend Exactly like the User's Screenshot */}
            <div className="flex items-center justify-start gap-4 my-auto py-1">
              {/* Donut Ring */}
              <div className="relative w-12 h-12 shrink-0 flex items-center justify-center">
                <svg viewBox="0 0 36 36" className="w-12 h-12 -rotate-90">
                  {/* Disconnected slice (Red #c22929) */}
                  <circle
                    cx="18"
                    cy="18"
                    r="14"
                    fill="none"
                    stroke="#c22929"
                    strokeWidth="4.5"
                  />
                  {/* Active slice (Teal #00796b ~ 95.5% of circumference 87.96) */}
                  <circle
                    cx="18"
                    cy="18"
                    r="14"
                    fill="none"
                    stroke="#00796b"
                    strokeWidth="4.5"
                    strokeDasharray="83.9 88"
                    strokeDashoffset="0"
                  />
                </svg>
              </div>

              {/* Legend with circular dots matching reference screenshot */}
              <div className="flex flex-col justify-center gap-1.5">
                <div className="flex items-center gap-2">
                  <span className="w-2.5 h-2.5 rounded-full shrink-0" style={{ backgroundColor: '#00796b' }}></span>
                  <span className={`text-xs font-semibold ${isDark ? 'text-slate-100' : 'text-slate-800'}`}>
                    Active (21)
                  </span>
                </div>
                <div className="flex items-center gap-2">
                  <span className="w-2.5 h-2.5 rounded-full shrink-0" style={{ backgroundColor: '#c22929' }}></span>
                  <span className={`text-xs font-semibold ${isDark ? 'text-slate-100' : 'text-slate-800'}`}>
                    Disconnected (1)
                  </span>
                </div>
              </div>
            </div>
          </div>

          {/* Card 2: Overall Parity / Sync Rate */}
          <div className={`p-3.5 rounded-xl border transition-all flex flex-col justify-between min-h-[105px] ${
            isDark ? 'bg-slate-900/60 border-slate-800' : 'bg-white border-slate-200 shadow-sm'
          }`}>
            <div className="flex items-center justify-between text-xs text-slate-400 mb-1">
              <span className={`font-semibold ${isDark ? 'text-slate-300' : 'text-slate-600'}`}>Parity Health Rate</span>
            </div>
            <div>
              <div className={`text-2xl font-bold tracking-tight ${
                data.summary.sync_rate_pct >= 90 
                  ? isDark ? 'text-emerald-400' : 'text-emerald-600' 
                  : isDark ? 'text-amber-400' : 'text-amber-600'
              }`}>
                {data.summary.sync_rate_pct}%
              </div>
              <div className="text-[11px] text-slate-500 mt-1">
                {data.summary.total_synced_dates} dates synced, {data.summary.total_mismatch_dates} mismatch
              </div>
            </div>
          </div>

          {/* Card 3: Mesin 1: Streamer (asoc-streamer.service) */}
          {(() => {
            const streamer = serviceHealth?.services?.streamer || data?.summary?.services?.streamer;
            const isActive = streamer?.is_active ?? true;
            const stopAt = streamer?.stop_at;
            return (
              <div 
                onClick={() => fetchServiceHealth(true)}
                className={`p-3.5 rounded-xl border transition-all flex flex-col justify-between min-h-[105px] cursor-pointer ${
                  isDark 
                    ? isActive ? 'bg-slate-900/60 border-slate-800 hover:border-emerald-500/40' : 'bg-rose-950/20 border-rose-800/40 hover:border-rose-500/50' 
                    : isActive ? 'bg-white border-slate-200 shadow-sm hover:border-emerald-300' : 'bg-rose-50/50 border-rose-200 shadow-sm hover:border-rose-300'
                }`}
                title="Klik untuk membuka kontrol mesin streamer"
              >
                <div className="flex items-center justify-between text-xs text-slate-400 mb-1">
                  <span className={`font-semibold ${isDark ? 'text-slate-300' : 'text-slate-600'}`}>Streamer Machine</span>
                </div>
                <div>
                  <div className={`text-2xl font-bold tracking-tight font-mono ${
                    isActive 
                      ? isDark ? 'text-emerald-400' : 'text-emerald-600'
                      : 'text-rose-500 font-extrabold'
                  }`}>
                    {isActive ? 'ACTIVE' : 'STOP'}
                  </div>
                  {isActive ? (
                    <div className="text-[11px] text-emerald-600 dark:text-emerald-400 font-medium flex items-center gap-1.5 mt-1">
                      <span className="w-1.5 h-1.5 rounded-full bg-emerald-500 inline-block animate-pulse"></span>
                      Streamer Berjalan Normal
                    </div>
                  ) : (
                    <div className="text-[11px] text-rose-500 font-medium flex items-center gap-1 mt-1 truncate">
                      Stop at {stopAt || streamer?.since || 'Mati'}
                    </div>
                  )}
                </div>
              </div>
            );
          })()}

          {/* Card 4: Mesin 2: Reconcile (asoc-reconciliation.timer) */}
          {(() => {
            const timer = serviceHealth?.services?.reconciliation_timer || data?.summary?.services?.reconciliation_timer;
            const isActive = timer?.is_active ?? true;
            const stopAt = timer?.stop_at;
            return (
              <div 
                onClick={() => fetchServiceHealth(true)}
                className={`p-3.5 rounded-xl border transition-all flex flex-col justify-between min-h-[105px] cursor-pointer ${
                  isDark 
                    ? isActive ? 'bg-slate-900/60 border-slate-800 hover:border-emerald-500/40' : 'bg-rose-950/20 border-rose-800/40 hover:border-rose-500/50' 
                    : isActive ? 'bg-white border-slate-200 shadow-sm hover:border-emerald-300' : 'bg-rose-50/50 border-rose-200 shadow-sm hover:border-rose-300'
                }`}
                title="Klik untuk membuka kontrol timer rekonsiliasi"
              >
                <div className="flex items-center justify-between text-xs text-slate-400 mb-1">
                  <span className={`font-semibold ${isDark ? 'text-slate-300' : 'text-slate-600'}`}>Reconcile</span>
                </div>
                <div>
                  <div className={`text-2xl font-bold tracking-tight font-mono ${
                    isActive 
                      ? isDark ? 'text-emerald-400' : 'text-emerald-600'
                      : 'text-rose-500 font-extrabold'
                  }`}>
                    {isActive ? 'ACTIVE' : 'STOP'}
                  </div>
                  {isActive ? (
                    <div className="text-[11px] text-emerald-600 dark:text-emerald-400 font-medium flex items-center gap-1.5 mt-1">
                      <span className="w-1.5 h-1.5 rounded-full bg-emerald-500 inline-block animate-pulse"></span>
                      Pemantau Tiap 5 Menit
                    </div>
                  ) : (
                    <div className="text-[11px] text-rose-500 font-medium flex items-center gap-1 mt-1 truncate">
                      Stop at {stopAt || timer?.since || 'Mati'}
                    </div>
                  )}
                </div>
              </div>
            );
          })()}

          {/* Card 5: Data Redundan (Zero-Redundancy & Deduplication Audit) */}
          {(() => {
            const redundantCount = data.summary?.redundant_count ?? 0;
            const isClean = redundantCount === 0;
            return (
              <div className={`p-3.5 rounded-xl border transition-all flex flex-col justify-between min-h-[105px] ${
                isDark ? 'bg-slate-900/60 border-slate-800' : 'bg-white border-slate-200 shadow-sm'
              }`}>
                <div className="flex items-center justify-between text-xs text-slate-400 mb-1">
                  <span className={`font-semibold ${isDark ? 'text-slate-300' : 'text-slate-600'}`}>Data Redundan</span>
                </div>
                <div>
                  <div className={`text-2xl font-bold tracking-tight font-mono ${
                    isClean 
                      ? isDark ? 'text-emerald-400' : 'text-emerald-600'
                      : 'text-rose-500'
                  }`}>
                    {redundantCount.toLocaleString()}
                  </div>
                  {isClean ? (
                    <div className="text-[11px] text-emerald-600 dark:text-emerald-400 font-medium flex items-center gap-1.5 mt-1">
                      <span className="w-1.5 h-1.5 rounded-full bg-emerald-500 inline-block"></span>
                      100% Unik Murni (Aman)
                    </div>
                  ) : (
                    <div className="text-[11px] mt-1 text-rose-500 font-medium flex items-center gap-1 truncate">
                      Ditemukan {redundantCount} duplikat
                    </div>
                  )}
                </div>
              </div>
            );
          })()}
        </div>
      )}

      {/* Reconcile Flash Alert */}
      {reconcileResult && (
        <div className={`p-3 rounded-lg border text-xs flex items-center justify-between ${
          reconcileResult.startsWith('Error')
            ? isDark ? 'bg-rose-500/10 border-rose-500/20 text-rose-300' : 'bg-rose-50 border-rose-200 text-rose-700'
            : isDark ? 'bg-emerald-500/10 border-emerald-500/20 text-emerald-300' : 'bg-emerald-50 border-emerald-200 text-emerald-700'
        }`}>
          <div className="flex items-center gap-2">
            <CheckCircle2 className="w-4 h-4 shrink-0" />
            <span>{reconcileResult}</span>
          </div>
          <button 
            onClick={() => setReconcileResult(null)}
            className="text-slate-400 hover:text-slate-200 font-bold ml-4"
          >
            ×
          </button>
        </div>
      )}

      {/* Action Controls Toolbar (Memenuhi lebar penuh secara horizontal sampai ke ujung kanan) */}
      <div className="flex items-center gap-2.5 w-full">
        {/* Buttons on the left */}
        <div className="flex items-center gap-2 shrink-0">
          {/* TOMBOL: CEK STATUS MESIN */}
          <button
            onClick={() => fetchServiceHealth(true)}
            disabled={checkingHealth}
            title="Periksa apakah asoc-streamer.service dan asoc-reconciliation.timer aktif normal"
            className={`flex items-center gap-2 px-3.5 py-2 rounded-lg border text-xs font-semibold shadow-sm transition-all ${
              isEngineHealthy
                ? isDark 
                  ? 'bg-emerald-950/40 border-emerald-500/30 text-emerald-300 hover:bg-emerald-900/50 hover:border-emerald-500/50' 
                  : 'bg-emerald-50 border-emerald-300 text-emerald-700 hover:bg-emerald-100'
                : isDark
                  ? 'bg-rose-950/40 border-rose-500/40 text-rose-300 hover:bg-rose-900/50 animate-pulse'
                  : 'bg-rose-50 border-rose-300 text-rose-700 hover:bg-rose-100 animate-pulse'
            }`}
          >
            <span className="relative flex h-2 w-2">
              <span className={`animate-ping absolute inline-flex h-full w-full rounded-full opacity-75 ${
                isEngineHealthy ? 'bg-emerald-400' : 'bg-rose-400'
              }`}></span>
              <span className={`relative inline-flex rounded-full h-2 w-2 ${
                isEngineHealthy ? 'bg-emerald-500' : 'bg-rose-500'
              }`}></span>
            </span>
            <Activity className={`w-3.5 h-3.5 ${checkingHealth ? 'animate-spin' : ''}`} />
            <span>{checkingHealth ? 'Mengecek Mesin...' : 'Cek Status Mesin'}</span>
          </button>

          {/* Trigger Reconcile */}
          {!isReadOnly && (
            <button
              onClick={triggerReconcile}
              disabled={reconciling}
              className={`flex items-center gap-1.5 px-3.5 py-2 rounded-lg text-xs font-semibold shadow-sm transition-all ${
                reconciling
                  ? 'bg-amber-500/20 text-amber-300 border border-amber-500/30 cursor-wait'
                  : 'bg-emerald-600 hover:bg-emerald-500 text-white shadow-emerald-900/20'
              }`}
            >
              <Play className={`w-3.5 h-3.5 ${reconciling ? 'animate-pulse' : ''}`} />
              <span>{reconciling ? 'Running Sync...' : 'Auto-Reconcile'}</span>
            </button>
          )}
        </div>

        {/* Garis Hitung Mundur Auto-Reconcile: Dipenuhin hingga ke ujung kanan agar tidak kosong */}
        <div 
          className={`flex-1 flex items-center justify-between gap-3 px-3.5 py-2 rounded-lg border text-xs shadow-sm transition-all ${
            isDark 
              ? 'bg-slate-900/70 border-slate-700/60 text-slate-300' 
              : 'bg-white border-slate-200 text-slate-700'
          }`}
          title="Timer hitung mundur siklus auto-reconcile berikutnya (5 Menit). Otomatis penuh kembali jika ditekan manual."
        >
          <div className="flex items-center gap-1.5 whitespace-nowrap shrink-0">
            <Clock className={`w-3.5 h-3.5 ${reconciling ? 'animate-spin text-amber-400' : 'text-emerald-500'}`} />
            <span className="text-[11px] font-medium text-slate-400">Next Auto:</span>
            <span className="font-mono font-bold text-emerald-500">{formatCountdown(countdown)}</span>
          </div>

          {/* Garis memanjang fleksibel ke seluruh sisa ruang */}
          <div className={`flex-1 h-2 rounded-full overflow-hidden p-[1px] ${
            isDark ? 'bg-slate-800 border border-slate-700/60' : 'bg-slate-100 border border-slate-200'
          }`}>
            <div 
              className={`h-full rounded-full transition-all duration-1000 ease-linear shadow-sm ${
                (countdown / TOTAL_RECONCILE_SECONDS) > 0.4
                  ? 'bg-gradient-to-r from-emerald-500 to-teal-400'
                  : (countdown / TOTAL_RECONCILE_SECONDS) > 0.15
                    ? 'bg-gradient-to-r from-teal-400 to-amber-400'
                    : 'bg-gradient-to-r from-amber-400 to-rose-500'
              }`}
              style={{ width: `${Math.max(0, Math.min(100, (countdown / TOTAL_RECONCILE_SECONDS) * 100))}%` }}
            />
          </div>

          <div className="text-[11px] font-medium text-slate-400 shrink-0 hidden sm:flex items-center gap-1">
            <span className="text-emerald-500">●</span> 5m cycle
          </div>
        </div>
      </div>

      {/* Filter / Search Bar */}
      <div className="flex items-center justify-between gap-3">
        <div className={`relative flex-1 max-w-md`}>
          <Search className="w-4 h-4 absolute left-3 top-1/2 -translate-y-1/2 text-slate-500" />
          <input
            type="text"
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            placeholder="Search tenant name, tag, database or group..."
            className={`w-full pl-9 pr-4 py-2 rounded-lg text-xs border transition-all focus:outline-none ${
              isDark 
                ? 'bg-slate-900/70 border-slate-800 focus:border-sky-500 text-slate-200 placeholder-slate-500' 
                : 'bg-white border-slate-200 focus:border-sky-500 text-slate-800 placeholder-slate-400 shadow-sm'
            }`}
          />
        </div>
        <div className="text-xs text-slate-400">
          Showing <span className="font-semibold text-sky-400">{filteredTenants.length}</span> of {data?.tenants?.length || 0} tenants
        </div>
      </div>

      {/* Error Message */}
      {error && (
        <div className={`p-4 rounded-xl border flex items-center gap-3 ${
          isDark ? 'bg-rose-500/10 border-rose-500/20 text-rose-300' : 'bg-rose-50 border-rose-200 text-rose-700'
        }`}>
          <AlertTriangle className="w-5 h-5 shrink-0" />
          <div className="text-xs">
            <span className="font-semibold">Failed to load data synchronization: </span>
            {error}
          </div>
          <button 
            onClick={fetchSyncData}
            className="ml-auto px-3 py-1 bg-rose-500 text-white rounded text-xs font-semibold hover:bg-rose-600 transition-colors"
          >
            Retry
          </button>
        </div>
      )}

      {/* Tenant Sync Cards (Accordion design matching reference) */}
      <div className="space-y-4">
        {filteredTenants.map((tenant) => {
          const isExpanded = expandedTenants[tenant.tenant_id] !== false;
          const isAllSynced = tenant.status === '100% SYNC';

          return (
            <div 
              key={tenant.tenant_id}
              className={`rounded-xl border transition-all overflow-hidden ${
                isDark 
                  ? 'bg-slate-900/60 border-slate-800 shadow-sm hover:border-slate-700' 
                  : 'bg-white border-slate-200 shadow-sm hover:border-slate-300'
              }`}
            >
              {/* Accordion Card Header - Minimal & Clean */}
              <div 
                onClick={() => toggleTenant(tenant.tenant_id)}
                className={`px-4 sm:px-6 py-3.5 flex items-center justify-between cursor-pointer select-none transition-colors ${
                  isDark ? 'hover:bg-slate-800/40' : 'hover:bg-slate-50'
                }`}
              >
                {/* Left: Caret + [TAG] */}
                <div className="flex items-center gap-3">
                  <button 
                    type="button"
                    aria-label={isExpanded ? 'Collapse' : 'Expand'}
                    className={`p-1 rounded transition-colors ${
                      isDark ? 'text-slate-400 hover:text-slate-200' : 'text-slate-500 hover:text-slate-800'
                    }`}
                  >
                    {isExpanded ? (
                      <ChevronUp className="w-4 h-4 font-bold" />
                    ) : (
                      <ChevronDown className="w-4 h-4 font-bold" />
                    )}
                  </button>

                  <span className="font-bold text-slate-100 tracking-wide font-mono text-sm">
                    [{tenant.tag}]
                  </span>
                </div>
              </div>

              {/* Accordion Card Body (Table) */}
              {isExpanded && (
                <div className={`border-t ${isDark ? 'border-slate-800' : 'border-slate-200'}`}>
                  <div className="overflow-x-auto">
                    <table className="w-full text-left text-xs">
                      {/* Table Column Headers */}
                      <thead>
                        <tr className={`${isDark ? 'bg-slate-950/40 text-slate-400' : 'bg-slate-50 text-slate-500'} font-semibold border-b ${isDark ? 'border-slate-800/80' : 'border-slate-200'}`}>
                          <th className="py-2.5 px-6 font-mono tracking-wider w-1/4">DATE</th>
                          <th className="py-2.5 px-6 font-mono tracking-wider w-1/4">INDEXER MASTER</th>
                          <th className="py-2.5 px-6 font-mono tracking-wider w-1/4">TOTAL POSTGRESQL</th>
                          <th className="py-2.5 px-6 font-mono tracking-wider text-right pr-6 w-1/4">STATUS</th>
                        </tr>
                      </thead>

                      {/* Daily Data Rows */}
                      <tbody className={`divide-y ${isDark ? 'divide-slate-800/60' : 'divide-slate-100'}`}>
                        {tenant.records?.map((rec) => {
                          const isSync = rec.status === 'SYNC';
                          return (
                            <tr 
                              key={rec.date}
                              className={`transition-colors ${
                                isDark ? 'hover:bg-slate-800/20' : 'hover:bg-slate-50'
                              }`}
                            >
                              {/* Date Column */}
                              <td className="py-2.5 px-6 font-mono text-slate-300">
                                {rec.date}
                              </td>

                              {/* Indexer Master Column */}
                              <td className="py-2.5 px-6 font-mono font-medium text-slate-200">
                                {rec.indexer_master?.toLocaleString()}
                              </td>

                              {/* Total PostgreSQL Column */}
                              <td className="py-2.5 px-6 font-mono font-medium text-slate-200">
                                {rec.total_postgres?.toLocaleString()}
                              </td>

                              {/* Status Badge Column */}
                              <td className="py-2.5 px-6 text-right pr-6">
                                {isSync ? (
                                  <span className="inline-flex items-center gap-1 px-2.5 py-0.5 rounded-full text-[11px] font-semibold tracking-wide bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
                                    SYNC
                                  </span>
                                ) : (
                                  <span className="inline-flex items-center gap-1 px-2.5 py-0.5 rounded-full text-[11px] font-semibold tracking-wide bg-rose-500/10 text-rose-400 border border-rose-500/20">
                                    MISMATCH
                                  </span>
                                )}
                              </td>
                            </tr>
                          );
                        })}
                      </tbody>

                      {/* Total Footer Row - Matching Reference Image */}
                      <tfoot>
                        <tr className={`font-bold ${isDark ? 'bg-slate-950/60 border-t border-slate-800' : 'bg-slate-100/70 border-t border-slate-200'}`}>
                          {/* TOTAL label */}
                          <td className="py-3 px-6 font-mono tracking-wider text-slate-200">
                            TOTAL
                          </td>

                          {/* Sum Indexer Master (Blue bold) */}
                          <td className="py-3 px-6 font-mono text-sky-400 font-bold text-sm">
                            {tenant.total_indexer?.toLocaleString()}
                          </td>

                          {/* Sum Total PostgreSQL (Blue bold) */}
                          <td className="py-3 px-6 font-mono text-sky-400 font-bold text-sm">
                            {tenant.total_postgres?.toLocaleString()}
                          </td>

                          {/* Overall Status (100% SYNC or MISMATCH) */}
                          <td className="py-3 px-6 text-right pr-6 font-mono font-bold text-xs">
                            {isAllSynced ? (
                              <span className="text-emerald-400">
                                100% SYNC
                              </span>
                            ) : (
                              <span className="text-rose-400">
                                MISMATCH
                              </span>
                            )}
                          </td>
                        </tr>
                      </tfoot>
                    </table>
                  </div>
                </div>
              )}
            </div>
          );
        })}

        {filteredTenants.length === 0 && !loading && (
          <div className={`p-8 text-center rounded-xl border ${isDark ? 'border-slate-800 bg-slate-900/40 text-slate-400' : 'border-slate-200 bg-white text-slate-500'}`}>
            <p className="text-sm font-medium">No tenant sync data matching "{searchQuery}"</p>
          </div>
        )}
      </div>

      {/* ========================================================================= */}
      {/* MODAL DETAIL: STATUS MESIN HIDUP / MATI (SYSTEMD SERVICE INSPECTION)      */}
      {/* ========================================================================= */}
      {showHealthModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-950/80 backdrop-blur-sm animate-fade-in">
          <div className={`w-full max-w-2xl rounded-2xl border shadow-2xl overflow-hidden transition-all ${
            isDark ? 'bg-slate-900 border-slate-800 text-slate-100' : 'bg-white border-slate-200 text-slate-900'
          }`}>
            {/* Modal Header */}
            <div className={`px-6 py-4 flex items-center justify-between border-b ${
              isDark ? 'border-slate-800 bg-slate-950/40' : 'border-slate-200 bg-slate-50'
            }`}>
              <div className="flex items-center gap-3">
                <div className={`p-2 rounded-lg ${
                  isEngineHealthy 
                    ? 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/20' 
                    : 'bg-rose-500/10 text-rose-400 border border-rose-500/20'
                }`}>
                  <Cpu className="w-5 h-5" />
                </div>
                <div>
                  <h3 className="text-base font-bold flex items-center gap-2">
                    <span>Status Mesin Pipeline ASOC</span>
                    <span className={`text-[11px] px-2 py-0.5 rounded-full font-mono font-semibold ${
                      isEngineHealthy 
                        ? 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/30' 
                        : 'bg-rose-500/10 text-rose-400 border border-rose-500/30'
                    }`}>
                      {isEngineHealthy ? 'ACTIVE (NORMAL)' : 'PERLU TINDAKAN'}
                    </span>
                  </h3>
                  <p className={`text-xs ${isDark ? 'text-slate-400' : 'text-slate-500'}`}>
                    Pengecekan live service systemctl pada host Linux ASOC (VM 192.168.30.206)
                  </p>
                </div>
              </div>
              <button
                onClick={() => setShowHealthModal(false)}
                className={`p-1.5 rounded-lg text-slate-400 hover:text-slate-200 transition-colors ${
                  isDark ? 'hover:bg-slate-800' : 'hover:bg-slate-100'
                }`}
              >
                <X className="w-5 h-5" />
              </button>
            </div>

            {/* Modal Body */}
            <div className="p-6 space-y-4 max-h-[75vh] overflow-y-auto">
              {/* Flash Action Message */}
              {serviceActionMsg && (
                <div className={`p-3 rounded-lg border text-xs flex items-center gap-2 ${
                  serviceActionMsg.startsWith('Gagal')
                    ? 'bg-rose-500/10 border-rose-500/20 text-rose-300'
                    : 'bg-emerald-500/10 border-emerald-500/20 text-emerald-300'
                }`}>
                  <CheckCircle2 className="w-4 h-4 shrink-0" />
                  <span>{serviceActionMsg}</span>
                </div>
              )}

              {/* Service 1: asoc-streamer.service */}
              <div className={`p-4 rounded-xl border transition-all ${
                isDark ? 'bg-slate-950/40 border-slate-800' : 'bg-slate-50 border-slate-200'
              }`}>
                <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
                  <div className="space-y-1">
                    <div className="flex items-center gap-2">
                      <span className="font-mono text-xs font-bold text-sky-400">asoc-streamer.service</span>
                      <span className={`px-2 py-0.5 rounded text-[10px] font-mono font-bold uppercase ${
                        isStreamerRunning 
                          ? 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/20' 
                          : 'bg-rose-500/10 text-rose-400 border border-rose-500/20'
                      }`}>
                        {isStreamerRunning ? 'active (running)' : 'inactive (stopped)'}
                      </span>
                    </div>
                    <p className="text-xs text-slate-400">
                      <strong>Fungsi:</strong> Pengalir data telemetri live dari Fluent Bit ke PostgreSQL wazuh_soc_db (real-time stream 1s).
                    </p>
                    <p className="text-[11px] font-mono text-slate-500">
                      {serviceHealth?.services?.streamer?.since || 'Checking status...'}
                    </p>
                  </div>

                  {!isReadOnly && (
                    <button
                      onClick={() => handleRestartService('asoc-streamer.service')}
                      disabled={restartingUnit === 'asoc-streamer.service'}
                      className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg border text-xs font-semibold shrink-0 transition-all ${
                        isDark 
                          ? 'border-slate-700 bg-slate-800 text-slate-200 hover:bg-slate-700' 
                          : 'border-slate-300 bg-white text-slate-700 hover:bg-slate-100 shadow-sm'
                      }`}
                    >
                      <RotateCcw className={`w-3.5 h-3.5 ${restartingUnit === 'asoc-streamer.service' ? 'animate-spin' : ''}`} />
                      <span>{restartingUnit === 'asoc-streamer.service' ? 'Restarting...' : 'Restart Streamer'}</span>
                    </button>
                  )}
                </div>

                {/* Log Snippet */}
                {serviceHealth?.services?.streamer?.logs && (
                  <div className="mt-3 p-2.5 rounded-lg bg-black/50 border border-slate-800 text-[11px] font-mono text-slate-300 overflow-x-auto max-h-28">
                    <pre className="whitespace-pre-wrap">{serviceHealth.services.streamer.logs}</pre>
                  </div>
                )}
              </div>

              {/* Service 2: asoc-reconciliation.timer */}
              <div className={`p-4 rounded-xl border transition-all ${
                isDark ? 'bg-slate-950/40 border-slate-800' : 'bg-slate-50 border-slate-200'
              }`}>
                <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
                  <div className="space-y-1">
                    <div className="flex items-center gap-2">
                      <span className="font-mono text-xs font-bold text-sky-400">asoc-reconciliation.timer</span>
                      <span className={`px-2 py-0.5 rounded text-[10px] font-mono font-bold uppercase ${
                        isTimerWaiting 
                          ? 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/20' 
                          : 'bg-rose-500/10 text-rose-400 border border-rose-500/20'
                      }`}>
                        {isTimerWaiting ? 'active (waiting)' : 'inactive (stopped)'}
                      </span>
                    </div>
                    <p className="text-xs text-slate-400">
                      <strong>Fungsi:</strong> Pemantau otomatis (Self-Healing Background) yang memeriksa gap data tiap 5 menit.
                    </p>
                    <p className="text-[11px] font-mono text-slate-500">
                      {serviceHealth?.services?.reconciliation_timer?.since || 'Checking status...'}
                    </p>
                  </div>

                  {!isReadOnly && (
                    <button
                      onClick={() => handleRestartService('asoc-reconciliation.timer')}
                      disabled={restartingUnit === 'asoc-reconciliation.timer'}
                      className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg border text-xs font-semibold shrink-0 transition-all ${
                        isDark 
                          ? 'border-slate-700 bg-slate-800 text-slate-200 hover:bg-slate-700' 
                          : 'border-slate-300 bg-white text-slate-700 hover:bg-slate-100 shadow-sm'
                      }`}
                    >
                      <RotateCcw className={`w-3.5 h-3.5 ${restartingUnit === 'asoc-reconciliation.timer' ? 'animate-spin' : ''}`} />
                      <span>{restartingUnit === 'asoc-reconciliation.timer' ? 'Restarting...' : 'Restart Timer'}</span>
                    </button>
                  )}
                </div>

                {/* Log Snippet */}
                {serviceHealth?.services?.reconciliation_timer?.logs && (
                  <div className="mt-3 p-2.5 rounded-lg bg-black/50 border border-slate-800 text-[11px] font-mono text-slate-300 overflow-x-auto max-h-24">
                    <pre className="whitespace-pre-wrap">{serviceHealth.services.reconciliation_timer.logs}</pre>
                  </div>
                )}
              </div>
            </div>

            {/* Modal Footer */}
            <div className={`px-6 py-3.5 flex items-center justify-between border-t ${
              isDark ? 'border-slate-800 bg-slate-950/40 text-slate-400' : 'border-slate-200 bg-slate-50 text-slate-500'
            } text-xs`}>
              <div className="flex items-center gap-1.5">
                <Clock className="w-3.5 h-3.5" />
                <span>Terakhir diperiksa: {serviceHealth?.checked_at || 'Just now'}</span>
              </div>
              <button
                onClick={() => fetchServiceHealth(true)}
                disabled={checkingHealth}
                className="flex items-center gap-1.5 text-sky-400 hover:text-sky-300 font-semibold transition-colors"
              >
                <RefreshCw className={`w-3.5 h-3.5 ${checkingHealth ? 'animate-spin' : ''}`} />
                <span>Periksa Ulang</span>
              </button>
            </div>
          </div>
        </div>
      )}

    </div>
  );
}
