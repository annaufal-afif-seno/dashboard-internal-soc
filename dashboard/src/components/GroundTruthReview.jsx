import React, { useState, useEffect, useMemo } from 'react';
import {
  CheckCircle2, AlertTriangle, ShieldCheck, ShieldAlert,
  Search, RefreshCw, UserCheck, ChevronUp, ChevronDown, ChevronsUpDown,
  Check, X, Pencil, Globe, Server, Clock, Layers
} from 'lucide-react';
import { formatDeadline, getDeadlineDate } from './IncidentTriageQueue';

export default function GroundTruthReview({ theme = 'dark', currentUser = null }) {
  const isDark = theme === 'dark' || (typeof document !== 'undefined' && document.documentElement.classList.contains('dark'));
  const [records, setRecords] = useState([]);
  const [loading, setLoading] = useState(false);
  const [searchQuery, setSearchQuery] = useState('');
  const [selectedPriority, setSelectedPriority] = useState('ALL');
  const [selectedTicket, setSelectedTicket] = useState(null);
  const [actionType, setActionType] = useState('APPROVE'); // 'APPROVE' or 'REJECT'
  const [managerNotes, setManagerNotes] = useState('');
  const [submitting, setSubmitting] = useState(false);
  const [toastMsg, setToastMsg] = useState('');
  const [currentPage, setCurrentPage] = useState(1);
  const pageSize = 25;

  const [sortField, setSortField] = useState('deadline');
  const [sortDirection, setSortDirection] = useState('desc');

  const showToast = (msg) => {
    setToastMsg(msg);
    setTimeout(() => setToastMsg(''), 5000);
  };

  const fetchQueue = async () => {
    setLoading(true);
    try {
      const res = await fetch('/api/ground-truth/queue');
      if (res.ok) {
        const data = await res.json();
        const mapped = (data.records || []).map(r => ({
          ...r,
          id: r.triage_id || r.incident_id,
          asset: r.target_host,
          attackerIp: r.attacker_source_ip,
          tenant: r.tenant_id,
          timeAgo: r.created_at || r.updated_at
        }));
        setRecords(mapped);
      }
    } catch (err) {
      console.error('Failed to fetch Ground Truth queue:', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchQueue();
    const interval = setInterval(fetchQueue, 15000);
    return () => clearInterval(interval);
  }, []);

  const handleOpenReviewModal = (ticket, initialAction = 'APPROVE') => {
    setSelectedTicket(ticket);
    setActionType(initialAction);
    setManagerNotes(
      initialAction === 'APPROVE'
        ? 'Divalidasi oleh SOC Manager. Ground truth diverifikasi akurat.'
        : 'Hasil analisis belum memadai. Indikator dan payload memerlukan pemeriksaan ulang.'
    );
  };

  const handleExecuteAction = async (targetAction = actionType) => {
    if (!selectedTicket) return;
    setSubmitting(true);
    const triageId = selectedTicket.triage_id || selectedTicket.id;
    const isTp = selectedTicket.ground_truth_verdict === 'TRUE_POSITIVE';

    try {
      const endpoint = targetAction === 'APPROVE'
        ? `/api/ground-truth/${triageId}/approve`
        : `/api/ground-truth/${triageId}/reject`;

      const managerName = currentUser?.username || 'soc_manager';
      const notesToSubmit = managerNotes.trim() || (
        targetAction === 'APPROVE' 
          ? 'Divalidasi oleh SOC Manager. Ground truth diverifikasi akurat.' 
          : 'Ditolak oleh SOC Manager untuk dikaji ulang.'
      );

      const res = await fetch(endpoint, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          manager_notes: notesToSubmit,
          manager_id: managerName
        })
      });

      const data = await res.json();
      if (res.ok) {
        // Tiket langsung hilang dari antrian Ground Truth Review
        setRecords(prev => prev.filter(r => r.triage_id !== triageId && r.id !== triageId));
        setSelectedTicket(null);

        if (targetAction === 'APPROVE') {
          showToast(`Tiket ${triageId} berhasil di-APPROVE. Diteruskan ke ${isTp ? 'Verified Threat' : 'Policy Bundle'}.`);
        } else {
          showToast(`Tiket ${triageId} telah di-REJECT. Dikembalikan ke antrian Ground Truth untuk dikaji ulang.`);
        }
        fetchQueue();
      } else {
        alert(data.detail || 'Operasi gagal dieksekusi.');
      }
    } catch (err) {
      alert(`Gagal menghubungi server: ${err.message}`);
    } finally {
      setSubmitting(false);
    }
  };

  // Priority counts calculation
  const { countP0, countP1, countP2, countP3, countP4 } = useMemo(() => {
    let p0 = 0, p1 = 0, p2 = 0, p3 = 0, p4 = 0;
    for (const r of records) {
      if (r.priority === 'P0') p0++;
      else if (r.priority === 'P1') p1++;
      else if (r.priority === 'P2') p2++;
      else if (r.priority === 'P3') p3++;
      else if (r.priority === 'P4') p4++;
    }
    return { countP0: p0, countP1: p1, countP2: p2, countP3: p3, countP4: p4 };
  }, [records]);

  const priorityTabs = [
    { id: 'ALL', label: 'All', count: records.length },
    { id: 'P0', label: 'P0', count: countP0 },
    { id: 'P1', label: 'P1', count: countP1 },
    { id: 'P2', label: 'P2', count: countP2 },
    { id: 'P3', label: 'P3', count: countP3 },
    { id: 'P4', label: 'P4', count: countP4 },
  ];

  // Filtering
  const filteredRecords = useMemo(() => {
    let list = records;
    if (selectedPriority !== 'ALL') {
      list = list.filter(r => r.priority === selectedPriority);
    }
    const q = searchQuery.trim().toLowerCase();
    if (q) {
      list = list.filter(r =>
        (r.id && r.id.toLowerCase().includes(q)) ||
        (r.title && r.title.toLowerCase().includes(q)) ||
        (r.target_host && r.target_host.toLowerCase().includes(q)) ||
        (r.attacker_source_ip && r.attacker_source_ip.toLowerCase().includes(q)) ||
        (r.tenant_id && r.tenant_id.toLowerCase().includes(q)) ||
        (r.priority && r.priority.toLowerCase().includes(q)) ||
        (r.assigned_analyst && r.assigned_analyst.toLowerCase().includes(q))
      );
    }
    return list;
  }, [records, selectedPriority, searchQuery]);

  // Sorting
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
      return <ChevronsUpDown className="w-3.5 h-3.5 text-blue-500/70 group-hover:text-blue-600 shrink-0 transition-colors" />;
    }
    if (sortDirection === 'asc') {
      return <ChevronUp className="w-3.5 h-3.5 text-blue-600 dark:text-blue-400 shrink-0 stroke-[2.5]" />;
    }
    return <ChevronDown className="w-3.5 h-3.5 text-blue-600 dark:text-blue-400 shrink-0 stroke-[2.5]" />;
  };

  const sortedRecords = useMemo(() => {
    return [...filteredRecords].sort((a, b) => {
      if (!sortField) return 0;
      let aVal = a[sortField];
      let bVal = b[sortField];

      if (sortField === 'deadline' || sortField === 'timeAgo') {
        const timeA = getDeadlineDate(a)?.getTime() || 0;
        const timeB = getDeadlineDate(b)?.getTime() || 0;
        return sortDirection === 'asc' ? timeA - timeB : timeB - timeA;
      }
      if (sortField === 'priority') {
        const pWeight = { P0: 0, P1: 1, P2: 2, P3: 3, P4: 4 };
        aVal = pWeight[a.priority] ?? 99;
        bVal = pWeight[b.priority] ?? 99;
        return sortDirection === 'asc' ? aVal - bVal : bVal - aVal;
      }

      aVal = String(aVal || '').toLowerCase();
      bVal = String(bVal || '').toLowerCase();
      if (aVal < bVal) return sortDirection === 'asc' ? -1 : 1;
      if (aVal > bVal) return sortDirection === 'asc' ? 1 : -1;
      return 0;
    });
  }, [filteredRecords, sortField, sortDirection]);

  const totalPages = Math.max(1, Math.ceil(sortedRecords.length / pageSize));
  const paginatedRecords = sortedRecords.slice((currentPage - 1) * pageSize, currentPage * pageSize);

  return (
    <div className="w-full space-y-4">
      {/* Toast Notification */}
      {toastMsg && (
        <div className="p-3.5 bg-slate-900 border border-slate-700/80 rounded-lg text-slate-200 text-xs flex items-center justify-between shadow-lg">
          <div className="flex items-center gap-2">
            <Check className="w-4 h-4 text-emerald-400" />
            <span>{toastMsg}</span>
          </div>
          <button onClick={() => setToastMsg('')} className="text-slate-400 hover:text-white cursor-pointer">
            <X className="w-4 h-4" />
          </button>
        </div>
      )}

      {/* Main Panel matching Groundtruth Format */}
      <div className={`border rounded-xl overflow-hidden ${
        isDark 
          ? 'bg-[#0a0e1a] border-slate-800' 
          : 'bg-white border-slate-200 shadow-xs'
      }`}>
        {/* Header Bar */}
        <div className={`px-6 py-3.5 border-b flex items-center justify-between gap-5 flex-wrap md:flex-nowrap ${
          isDark ? 'border-slate-800' : 'border-slate-200'
        }`}>
          {/* Left Title */}
          <div className="shrink-0">
            <h2 className={`text-base font-bold tracking-tight ${
              isDark ? 'text-white' : 'text-slate-900'
            }`}>
              Ground Truth Review
            </h2>
          </div>

          {/* Center Search Bar with Electric Blue Border */}
          <div className="flex-1 flex justify-center max-w-sm mx-auto md:mx-4 w-full md:w-auto order-3 md:order-2">
            <div className="w-full relative flex items-center bg-white dark:bg-[#090d16] border-2 border-[#3B5BFF] rounded-full h-[38px] pl-3.5 pr-1.5 shadow-2xs group focus-within:ring-2 focus-within:ring-[#3B5BFF]/30 transition-all">
              <Search className="w-4 h-4 text-slate-400 shrink-0 mr-2.5 stroke-[2]" />
              <input
                type="text"
                value={searchQuery}
                onChange={(e) => {
                  setSearchQuery(e.target.value);
                  setCurrentPage(1);
                }}
                placeholder="Search ticket, host, IP..."
                className="w-full bg-transparent text-slate-800 dark:text-slate-200 placeholder:text-slate-400 text-xs sm:text-[13px] font-normal focus:outline-none"
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
                  strokeWidth={2.5}
                />
              </button>
            </div>
          </div>

          {/* Right Priority Filters & Refresh */}
          <div className="flex items-center gap-5 sm:gap-6 select-none shrink-0 order-2 md:order-3">
            <div className="flex items-center gap-5 sm:gap-6 overflow-x-auto pb-1 md:pb-0">
              {priorityTabs.map(tab => {
                const isActive = selectedPriority === tab.id;
                return (
                  <button
                    key={tab.id}
                    onClick={() => {
                      setSelectedPriority(tab.id);
                      setCurrentPage(1);
                    }}
                    title={`Filter ${tab.label} (${tab.count} tiket)`}
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

            <button
              onClick={fetchQueue}
              disabled={loading}
              title="Refresh antrian Ground Truth Review"
              className={`p-1.5 rounded-lg border text-xs font-semibold transition-all cursor-pointer ${
                isDark 
                  ? 'bg-slate-800 border-slate-700 text-slate-300 hover:bg-slate-700 hover:text-white' 
                  : 'bg-white border-slate-200 text-slate-700 hover:bg-slate-100 hover:text-slate-900 shadow-2xs'
              }`}
            >
              <RefreshCw className={`w-4 h-4 ${loading ? 'animate-spin text-blue-500' : ''}`} />
            </button>
          </div>
        </div>

        {/* High-Density Incident Table (Identical to Groundtruth: 8 Columns, Fixed Width 100%) */}
        <div className="overflow-x-auto w-full">
          <table className="w-full table-fixed text-left text-xs border-collapse">
            <thead className={`border-b text-xs font-semibold ${
              isDark 
                ? 'bg-[#0b101d] text-slate-300 border-slate-800' 
                : 'bg-[#F0F5FA] text-slate-700 border-slate-200/80'
            }`}>
              <tr>
                <th 
                  onClick={() => handleSort('id')}
                  className="w-[17%] px-3 py-3 cursor-pointer select-none group hover:bg-slate-200/50 dark:hover:bg-slate-800/60 transition-colors"
                  title="Urutkan ID Insiden"
                >
                  <div className="flex items-center gap-1">
                    <span className={sortField === 'id' ? 'text-blue-600 dark:text-blue-400 font-bold' : 'group-hover:text-slate-900 dark:group-hover:text-white transition-colors'}>Incident</span>
                    {renderSortIcon('id')}
                  </div>
                </th>
                <th 
                  onClick={() => handleSort('priority')}
                  className="w-[6%] px-2 py-3 text-center cursor-pointer select-none group hover:bg-slate-200/50 dark:hover:bg-slate-800/60 transition-colors"
                  title="Urutkan Priority"
                >
                  <div className="flex items-center justify-center gap-1">
                    <span className={sortField === 'priority' ? 'text-blue-600 dark:text-blue-400 font-bold' : 'group-hover:text-slate-900 dark:group-hover:text-white transition-colors'}>Priority</span>
                    {renderSortIcon('priority')}
                  </div>
                </th>
                <th 
                  onClick={() => handleSort('deadline')}
                  className="w-[15%] px-2 py-3 cursor-pointer select-none group hover:bg-slate-200/50 dark:hover:bg-slate-800/60 transition-colors"
                  title="Urutkan Deadline"
                >
                  <div className="flex items-center gap-1">
                    <span className={sortField === 'deadline' || sortField === 'timeAgo' ? 'text-blue-600 dark:text-blue-400 font-bold' : 'group-hover:text-slate-900 dark:group-hover:text-white transition-colors'}>Deadline</span>
                    {renderSortIcon('deadline')}
                  </div>
                </th>
                <th 
                  onClick={() => handleSort('target_host')}
                  className="w-[17%] px-2 py-3 cursor-pointer select-none group hover:bg-slate-200/50 dark:hover:bg-slate-800/60 transition-colors"
                  title="Urutkan Target Host"
                >
                  <div className="flex items-center gap-1">
                    <span className={sortField === 'target_host' ? 'text-blue-600 dark:text-blue-400 font-bold' : 'group-hover:text-slate-900 dark:group-hover:text-white transition-colors'}>Target Host</span>
                    {renderSortIcon('target_host')}
                  </div>
                </th>
                <th 
                  onClick={() => handleSort('attacker_source_ip')}
                  className="w-[16%] px-2 py-3 cursor-pointer select-none group hover:bg-slate-200/50 dark:hover:bg-slate-800/60 transition-colors"
                  title="Urutkan Attacker IP"
                >
                  <div className="flex items-center gap-1">
                    <span className={sortField === 'attacker_source_ip' ? 'text-blue-600 dark:text-blue-400 font-bold' : 'group-hover:text-slate-900 dark:group-hover:text-white transition-colors'}>Attacker IP</span>
                    {renderSortIcon('attacker_source_ip')}
                  </div>
                </th>
                <th 
                  onClick={() => handleSort('tenant_id')}
                  className="w-[10%] px-2 py-3 text-center cursor-pointer select-none group hover:bg-slate-200/50 dark:hover:bg-slate-800/60 transition-colors"
                  title="Urutkan Tenant"
                >
                  <div className="flex items-center justify-center gap-1">
                    <span className={sortField === 'tenant_id' ? 'text-blue-600 dark:text-blue-400 font-bold' : 'group-hover:text-slate-900 dark:group-hover:text-white transition-colors'}>Tenant</span>
                    {renderSortIcon('tenant_id')}
                  </div>
                </th>
                <th className="w-[5%] px-1 py-3 text-center select-none">
                  <span>Action</span>
                </th>
                <th className="w-[14%] px-2 py-3 text-center select-none">
                  <span>Status</span>
                </th>
              </tr>
            </thead>
            <tbody className={`divide-y font-sans ${
              isDark ? 'divide-slate-800/60 bg-[#0a0e1a]' : 'divide-slate-100 bg-white'
            }`}>
              {loading && records.length === 0 ? (
                <tr>
                  <td colSpan="8" className="px-6 py-20 text-center">
                    <div className="flex flex-col items-center justify-center gap-2.5">
                      <RefreshCw className="w-5 h-5 animate-spin text-blue-500" />
                      <span className={`text-xs font-mono font-medium ${isDark ? 'text-slate-400' : 'text-slate-600'}`}>
                        Memuat data antrian tiket Ground Truth Review...
                      </span>
                    </div>
                  </td>
                </tr>
              ) : paginatedRecords.length === 0 ? (
                <tr>
                  <td colSpan="8" className="px-6 py-14 text-center">
                    <span className={`text-xs font-mono ${isDark ? 'text-slate-500' : 'text-slate-400'}`}>
                      Tidak ada tiket berstatus WAITING untuk validasi saat ini.
                    </span>
                  </td>
                </tr>
              ) : (
                paginatedRecords.map((t) => {
                  const isP0 = t.priority === 'P0';
                  const isP1 = t.priority === 'P1';
                  const prioColor = isP0 
                    ? 'text-rose-500 dark:text-rose-400' 
                    : isP1 
                      ? 'text-orange-500 dark:text-orange-400' 
                      : t.priority === 'P2' 
                        ? 'text-amber-500 dark:text-amber-400' 
                        : t.priority === 'P3' 
                          ? 'text-emerald-500 dark:text-emerald-400' 
                          : 'text-sky-500 dark:text-sky-400';

                  return (
                    <tr
                      key={t.id || t.triage_id}
                      className={`transition-colors ${
                        isDark ? 'hover:bg-slate-800/30' : 'hover:bg-slate-50/70'
                      }`}
                    >
                      {/* Incident ID only (Black text font-bold) */}
                      <td className="px-3 py-3 font-mono overflow-hidden">
                        <span 
                          className={`font-bold text-xs tracking-tight ${
                            isDark ? 'text-white hover:text-slate-300' : 'text-black hover:text-slate-700'
                          } cursor-pointer truncate block select-all`}
                          title={t.title ? `${t.title} (${t.id})` : t.id}
                          onClick={(e) => {
                            e.stopPropagation();
                            handleOpenReviewModal(t);
                          }}
                        >
                          {t.id || t.triage_id}
                        </span>
                      </td>

                      {/* Priority (Text only) */}
                      <td className="px-2 py-3 text-center font-mono">
                        <span className={`text-xs font-bold ${prioColor}`}>
                          {t.priority}
                        </span>
                      </td>

                      {/* Deadline */}
                      <td className="px-2 py-3 font-mono text-[11px] whitespace-nowrap overflow-hidden">
                        <span className={isDark ? 'text-slate-300' : 'text-slate-600'}>
                          {formatDeadline(t)}
                        </span>
                      </td>

                      {/* Target Host */}
                      <td className="px-2 py-3 font-mono overflow-hidden">
                        <div 
                          className={`text-xs font-semibold truncate ${isDark ? 'text-slate-200' : 'text-slate-900'}`}
                          title={t.target_host || '-'}
                        >
                          {t.target_host || '-'}
                        </div>
                      </td>

                      {/* Attacker IP */}
                      <td className="px-2 py-3 font-mono overflow-hidden">
                        <div 
                          className={`text-xs font-mono truncate ${isDark ? 'text-slate-300' : 'text-slate-600'}`}
                          title={t.attacker_source_ip || '127.0.0.1'}
                        >
                          {t.attacker_source_ip || '127.0.0.1'}
                        </div>
                      </td>

                      {/* Tenant */}
                      <td className="px-2 py-3 text-center font-mono overflow-hidden">
                        <div 
                          className={`text-xs font-medium truncate ${
                            isDark ? 'text-slate-300' : 'text-slate-600'
                          }`}
                          title={t.tenant_id || 'DEFAULT'}
                        >
                          {t.tenant_id || 'DEFAULT'}
                        </div>
                      </td>

                      {/* Action Column with Clean Pencil Icon */}
                      <td className="px-1 py-3 text-center">
                        <button
                          type="button"
                          onClick={(e) => {
                            e.stopPropagation();
                            handleOpenReviewModal(t);
                          }}
                          title="Review & Validasi Ground Truth (Approve / Reject)"
                          className="p-1.5 rounded-lg text-slate-500 hover:text-blue-600 hover:bg-blue-50/80 dark:text-slate-400 dark:hover:text-blue-400 dark:hover:bg-slate-800 transition-all cursor-pointer inline-flex items-center justify-center group/btn mx-auto"
                        >
                          <Pencil className="w-4 h-4 transition-transform group-hover/btn:scale-110" />
                        </button>
                      </td>

                      {/* Status: WAITING Badge (Kuning) */}
                      <td className="px-2 py-3 text-center font-mono whitespace-nowrap">
                        <span 
                          className="status-badge inline-flex items-center justify-center whitespace-nowrap px-3 py-1 rounded-md border border-yellow-400 bg-yellow-500 text-slate-950 font-bold text-[11px] tracking-wider uppercase shadow-xs select-none"
                          title="Menunggu validasi SOC Manager di Ground Truth Review."
                        >
                          WAITING
                        </span>
                      </td>
                    </tr>
                  );
                })
              )}
            </tbody>
          </table>
        </div>

        {/* Pagination Footer */}
        <div className={`p-4 border-t flex items-center justify-between text-xs ${
          isDark ? 'border-slate-800 text-slate-400 bg-[#0a0e1a]' : 'border-slate-200 text-slate-500 bg-[#F0F5FA]/40'
        }`}>
          <div>
            {loading && records.length === 0 ? (
              <span className="font-mono text-xs">Memuat data tiket...</span>
            ) : filteredRecords.length === 0 ? (
              <span className="font-mono text-xs">0 tiket</span>
            ) : (
              <>
                Showing <span className={`font-mono font-semibold ${isDark ? 'text-slate-200' : 'text-slate-700'}`}>{(currentPage - 1) * pageSize + 1}</span> to <span className={`font-mono font-semibold ${isDark ? 'text-slate-200' : 'text-slate-700'}`}>{Math.min(currentPage * pageSize, filteredRecords.length)}</span> of <span className={`font-mono font-semibold ${isDark ? 'text-slate-200' : 'text-slate-700'}`}>{filteredRecords.length}</span>
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
              {currentPage} / {totalPages}
            </span>
            <button
              onClick={() => setCurrentPage(p => Math.min(totalPages, p + 1))}
              disabled={currentPage === totalPages}
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

      {/* Ground Truth Validation & Review Modal (SOC Manager) */}
      {selectedTicket && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/70 backdrop-blur-xs">
          <div className={`w-full max-w-xl rounded-2xl border p-6 shadow-2xl space-y-4 ${
            isDark ? 'bg-[#0f172a] border-slate-700 text-slate-200' : 'bg-white border-slate-200 text-slate-800'
          }`}>
            {/* Modal Header */}
            <div className="flex items-center justify-between pb-3 border-b border-slate-700/60">
              <div className="flex items-center gap-2.5">
                <div className="p-2 rounded-xl bg-amber-500/10 border border-amber-500/30 text-amber-400">
                  <UserCheck className="w-5 h-5" />
                </div>
                <div>
                  <h3 className="font-bold text-sm sm:text-base">
                    Validasi Ground Truth: <span className="font-mono text-blue-500">{selectedTicket.id || selectedTicket.triage_id}</span>
                  </h3>
                  <p className="text-[11px] text-slate-400">
                    Otorisasi Keputusan Manajerial SOC ({currentUser?.username || 'soc_manager'})
                  </p>
                </div>
              </div>
              <button
                onClick={() => setSelectedTicket(null)}
                className="p-1.5 rounded-lg hover:bg-slate-800 text-slate-400 hover:text-white cursor-pointer"
              >
                <X className="w-4 h-4" />
              </button>
            </div>

            {/* Modal Body */}
            <div className="space-y-3.5 text-xs">
              {/* Telemetry & Target Details */}
              <div className={`p-3.5 rounded-xl border space-y-2 ${
                isDark ? 'bg-slate-950/70 border-slate-800' : 'bg-slate-50 border-slate-200'
              }`}>
                <div className="flex items-center justify-between text-[11px] border-b pb-2 border-slate-700/40">
                  <span className="text-slate-400">Prioritas & Deadline</span>
                  <div className="flex items-center gap-2">
                    <span className="font-bold text-rose-500 font-mono">{selectedTicket.priority}</span>
                    <span className="text-slate-400 font-mono">{formatDeadline(selectedTicket)}</span>
                  </div>
                </div>

                <div className="grid grid-cols-2 gap-2 text-[11px]">
                  <div>
                    <span className="text-slate-400 block font-semibold">Target Host:</span>
                    <span className="font-mono text-slate-200 font-medium">{selectedTicket.target_host || '-'}</span>
                  </div>
                  <div>
                    <span className="text-slate-400 block font-semibold">Attacker IP:</span>
                    <span className="font-mono text-slate-200 font-medium">{selectedTicket.attacker_source_ip || '127.0.0.1'}</span>
                  </div>
                </div>

                <div className="text-[11px]">
                  <span className="text-slate-400 block font-semibold">Judul / Aturan Deteksi:</span>
                  <span className="text-slate-300 font-medium">{selectedTicket.title || selectedTicket.rule_code || 'Analisis Korelasi'}</span>
                </div>
              </div>

              {/* Hasil Justifikasi Analis */}
              <div className={`p-3.5 rounded-xl border space-y-2.5 ${
                selectedTicket.ground_truth_verdict === 'TRUE_POSITIVE'
                  ? 'bg-rose-500/10 border-rose-500/30'
                  : 'bg-emerald-500/10 border-emerald-500/30'
              }`}>
                <div className="flex items-center justify-between">
                  <span className="text-[11px] font-semibold tracking-wider uppercase text-slate-400">
                    Justifikasi Analis Ground Truth:
                  </span>
                  {selectedTicket.ground_truth_verdict === 'TRUE_POSITIVE' ? (
                    <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-md text-[11px] font-bold bg-rose-500/20 text-rose-400 border border-rose-500/40">
                      <ShieldAlert className="w-3.5 h-3.5" />
                      TRUE POSITIVE (THREAT)
                    </span>
                  ) : (
                    <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-md text-[11px] font-bold bg-emerald-500/20 text-emerald-400 border border-emerald-500/40">
                      <ShieldCheck className="w-3.5 h-3.5" />
                      FALSE POSITIVE (BENIGN)
                    </span>
                  )}
                </div>

                <div className="text-[11px] text-slate-300">
                  <span className="text-slate-400 font-semibold">Dianalisis Oleh: </span>
                  <span className="font-mono font-medium">{selectedTicket.assigned_analyst || 'analyst'}</span>
                </div>

                <div>
                  <span className="text-slate-400 block text-[11px] font-semibold mb-1">Catatan Analis:</span>
                  <div className="p-2.5 rounded-lg bg-black/30 border border-slate-700/60 font-mono text-[11px] italic text-slate-200">
                    "{selectedTicket.analyst_notes || 'Tidak ada catatan analis spesifik.'}"
                  </div>
                </div>
              </div>

              {/* Input Catatan Manajer */}
              <div>
                <label className="block text-[11px] font-semibold text-slate-400 mb-1">
                  Catatan Evaluasi SOC Manager (Opsional):
                </label>
                <textarea
                  value={managerNotes}
                  onChange={(e) => setManagerNotes(e.target.value)}
                  rows="2"
                  className={`w-full p-2.5 rounded-lg border text-xs focus:outline-hidden focus:ring-1 ${
                    isDark 
                      ? 'bg-slate-950 border-slate-700 text-slate-200 focus:border-blue-500' 
                      : 'bg-white border-slate-300 text-slate-800 focus:border-blue-500'
                  }`}
                  placeholder="Masukkan arahan atau catatan validasi manajer..."
                />
              </div>
            </div>

            {/* Modal Actions: REJECT and APPROVE buttons */}
            <div className="flex items-center justify-between pt-3 border-t border-slate-700/60">
              <button
                type="button"
                onClick={() => setSelectedTicket(null)}
                disabled={submitting}
                className="px-4 py-2 rounded-xl text-xs font-semibold text-slate-400 hover:text-slate-200 cursor-pointer"
              >
                Batal
              </button>

              <div className="flex items-center gap-2.5">
                {/* Tombol REJECT */}
                <button
                  type="button"
                  onClick={() => handleExecuteAction('REJECT')}
                  disabled={submitting}
                  className="px-4 py-2 rounded-xl text-xs font-bold text-white bg-red-600 hover:bg-red-500 shadow-lg shadow-red-900/30 transition-all flex items-center gap-1.5 cursor-pointer disabled:opacity-50"
                  title="Tolak Ground Truth (Status di Ground Truth menjadi REJECT & perlu dikaji ulang)"
                >
                  <X className="w-3.5 h-3.5 stroke-[3]" />
                  <span>{submitting ? 'Memproses...' : 'Tolak (REJECT)'}</span>
                </button>

                {/* Tombol APPROVE */}
                <button
                  type="button"
                  onClick={() => handleExecuteAction('APPROVE')}
                  disabled={submitting}
                  className="px-5 py-2 rounded-xl text-xs font-bold text-white bg-emerald-600 hover:bg-emerald-500 shadow-lg shadow-emerald-900/30 transition-all flex items-center gap-1.5 cursor-pointer disabled:opacity-50"
                  title="Setujui Ground Truth (Status di Ground Truth menjadi APPROVE)"
                >
                  <Check className="w-3.5 h-3.5 stroke-[3]" />
                  <span>{submitting ? 'Memproses...' : 'Setujui (APPROVE)'}</span>
                </button>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
