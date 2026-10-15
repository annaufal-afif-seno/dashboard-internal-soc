import React, { useState, useEffect } from 'react';
import {
  CheckCircle2, XCircle, AlertTriangle, ShieldCheck, ShieldAlert,
  Search, RefreshCw, UserCheck, MessageSquare, ArrowRight,
  Server, Globe, Clock, Layers, Filter, Check, X, Info
} from 'lucide-react';

export default function GroundTruthReview({ theme = 'dark', currentUser = null }) {
  const isDark = theme === 'dark';
  const [records, setRecords] = useState([]);
  const [loading, setLoading] = useState(false);
  const [searchTerm, setSearchTerm] = useState('');
  const [statusFilter, setStatusFilter] = useState('ALL'); // 'ALL', 'TRUE_POSITIVE', 'FALSE_POSITIVE'
  const [selectedTicket, setSelectedTicket] = useState(null);
  const [actionType, setActionType] = useState(null); // 'APPROVE' or 'REJECT'
  const [managerNotes, setManagerNotes] = useState('');
  const [submitting, setSubmitting] = useState(false);
  const [toastMsg, setToastMsg] = useState('');

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
        setRecords(data.records || []);
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

  const handleOpenActionModal = (ticket, type) => {
    setSelectedTicket(ticket);
    setActionType(type);
    setManagerNotes(
      type === 'APPROVE'
        ? 'Divalidasi oleh SOC Manager. Ground truth diverifikasi akurat.'
        : 'Hasil analisis belum memadai. Indikator dan payload memerlukan pemeriksaan ulang.'
    );
  };

  const handleExecuteAction = async () => {
    if (!selectedTicket || !actionType) return;
    setSubmitting(true);
    try {
      const endpoint = actionType === 'APPROVE'
        ? `/api/ground-truth/${selectedTicket.triage_id}/approve`
        : `/api/ground-truth/${selectedTicket.triage_id}/reject`;

      const managerName = currentUser?.username || 'soc_manager';

      const res = await fetch(endpoint, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          manager_notes: managerNotes,
          manager_id: managerName
        })
      });

      const data = await res.json();
      if (res.ok) {
        if (actionType === 'APPROVE') {
          showToast(`Tiket ${selectedTicket.triage_id} berhasil di-APPROVE. Terdaftar di dataset ML.`);
        } else {
          showToast(`Tiket ${selectedTicket.triage_id} DITOLAK. Tiket baru ${data.spawned_ticket?.triage_id || ''} (FP Reject) telah diterbitkan di antrean.`);
        }
        setSelectedTicket(null);
        setActionType(null);
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

  const filteredRecords = records.filter(r => {
    const matchesSearch = 
      (r.triage_id && r.triage_id.toLowerCase().includes(searchTerm.toLowerCase())) ||
      (r.incident_id && r.incident_id.toLowerCase().includes(searchTerm.toLowerCase())) ||
      (r.target_host && r.target_host.toLowerCase().includes(searchTerm.toLowerCase())) ||
      (r.attacker_source_ip && r.attacker_source_ip.toLowerCase().includes(searchTerm.toLowerCase())) ||
      (r.rule_code && r.rule_code.toLowerCase().includes(searchTerm.toLowerCase()));

    const matchesStatus = 
      statusFilter === 'ALL' || r.ground_truth_verdict === statusFilter;

    return matchesSearch && matchesStatus;
  });

  return (
    <div className="space-y-6 max-w-[1600px] mx-auto p-4 md:p-6">
      {/* Toast Notification */}
      {toastMsg && (
        <div className="fixed top-6 right-6 z-50 flex items-center gap-3 px-4 py-3 rounded-xl border border-emerald-500/40 bg-emerald-950/90 text-emerald-200 shadow-xl backdrop-blur-md animate-fade-in">
          <CheckCircle2 className="w-5 h-5 text-emerald-400 shrink-0" />
          <span className="text-sm font-medium">{toastMsg}</span>
        </div>
      )}

      {/* Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 pb-4 border-b border-slate-700/60">
        <div>
          <div className="flex items-center gap-3 mb-1">
            <div className="p-2 rounded-xl bg-amber-500/10 border border-amber-500/30 text-amber-400">
              <UserCheck className="w-5 h-5" />
            </div>
            <h1 className={`text-xl font-bold ${isDark ? 'text-slate-100' : 'text-slate-900'}`}>
              Ground Truth Validation Queue (SOC Manager)
            </h1>
          </div>
          <p className="text-xs text-slate-400">
            Validasi manajerial terhadap keputusan True/False Positive analis sebelum deployment supresi Wazuh atau retraining ML.
          </p>
        </div>

        <div className="flex items-center gap-2.5">
          <button
            onClick={fetchQueue}
            disabled={loading}
            className={`flex items-center gap-2 px-3 py-1.5 rounded-lg border text-xs font-semibold transition-all ${
              isDark 
                ? 'bg-slate-800 border-slate-700 text-slate-300 hover:bg-slate-700' 
                : 'bg-white border-slate-200 text-slate-700 hover:bg-slate-50'
            }`}
          >
            <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} />
            Refresh
          </button>
        </div>
      </div>

      {/* Filter and Metrics Summary */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        <div className={`p-4 rounded-xl border ${isDark ? 'bg-slate-900/60 border-slate-800' : 'bg-white border-slate-200'}`}>
          <div className="text-xs text-slate-400 mb-1">Total Tiket Menunggu</div>
          <div className="text-2xl font-bold font-mono text-amber-400">{records.length}</div>
        </div>
        <div className={`p-4 rounded-xl border ${isDark ? 'bg-slate-900/60 border-slate-800' : 'bg-white border-slate-200'}`}>
          <div className="text-xs text-slate-400 mb-1">Usulan True Positive (Threat)</div>
          <div className="text-2xl font-bold font-mono text-rose-400">
            {records.filter(r => r.ground_truth_verdict === 'TRUE_POSITIVE').length}
          </div>
        </div>
        <div className={`p-4 rounded-xl border ${isDark ? 'bg-slate-900/60 border-slate-800' : 'bg-white border-slate-200'}`}>
          <div className="text-xs text-slate-400 mb-1">Usulan False Positive (Benign)</div>
          <div className="text-2xl font-bold font-mono text-emerald-400">
            {records.filter(r => r.ground_truth_verdict === 'FALSE_POSITIVE').length}
          </div>
        </div>
        <div className={`p-4 rounded-xl border ${isDark ? 'bg-slate-900/60 border-slate-800' : 'bg-white border-slate-200'}`}>
          <div className="text-xs text-slate-400 mb-1">Peran Akses Aktif</div>
          <div className="text-sm font-semibold text-purple-400 flex items-center gap-1.5 mt-1">
            <UserCheck className="w-4 h-4" />
            SOC Manager ({currentUser?.username || 'soc_manager'})
          </div>
        </div>
      </div>

      {/* Controls: Search & Tabs */}
      <div className="flex flex-col md:flex-row items-center justify-between gap-3">
        <div className="relative w-full md:w-80">
          <Search className="w-4 h-4 text-slate-400 absolute left-3 top-1/2 -translate-y-1/2" />
          <input
            type="text"
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            placeholder="Cari ID tiket, host, IP..."
            className={`w-full pl-9 pr-3 py-2 rounded-lg border text-xs focus:outline-hidden focus:ring-1 ${
              isDark 
                ? 'bg-slate-900 border-slate-800 text-slate-200 focus:border-blue-500' 
                : 'bg-white border-slate-200 text-slate-800 focus:border-blue-500'
            }`}
          />
        </div>

        <div className="flex items-center gap-1.5 self-start md:self-auto">
          {['ALL', 'TRUE_POSITIVE', 'FALSE_POSITIVE'].map((f) => (
            <button
              key={f}
              onClick={() => setStatusFilter(f)}
              className={`px-3 py-1.5 rounded-lg text-xs font-semibold transition-all ${
                statusFilter === f
                  ? 'bg-blue-600 text-white shadow-xs'
                  : isDark
                    ? 'bg-slate-800/80 text-slate-400 hover:text-slate-200'
                    : 'bg-slate-100 text-slate-600 hover:text-slate-900'
              }`}
            >
              {f === 'ALL' ? 'Semua' : f === 'TRUE_POSITIVE' ? 'True Positive' : 'False Positive'}
            </button>
          ))}
        </div>
      </div>

      {/* Main Table */}
      <div className={`rounded-xl border overflow-hidden ${isDark ? 'bg-slate-900/40 border-slate-800' : 'bg-white border-slate-200'}`}>
        <div className="overflow-x-auto">
          <table className="w-full text-left border-collapse">
            <thead>
              <tr className={`border-b text-[11px] font-semibold tracking-wider uppercase ${
                isDark ? 'border-slate-800 bg-slate-950/60 text-slate-400' : 'border-slate-200 bg-slate-50 text-slate-600'
              }`}>
                <th className="px-4 py-3">Prioritas / Skor</th>
                <th className="px-4 py-3">Tiket & Insiden</th>
                <th className="px-4 py-3">Aktor (IP) & Target (Host)</th>
                <th className="px-4 py-3">Ground Truth Analis</th>
                <th className="px-4 py-3">Catatan Analis</th>
                <th className="px-4 py-3 text-center">Aksi Manajer</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60 text-xs">
              {filteredRecords.length === 0 ? (
                <tr>
                  <td colSpan="6" className="text-center py-12 text-slate-400">
                    Tidak ada tiket berstatus WAITING untuk validasi saat ini.
                  </td>
                </tr>
              ) : (
                filteredRecords.map((t) => {
                  const isTp = t.ground_truth_verdict === 'TRUE_POSITIVE';
                  return (
                    <tr 
                      key={t.triage_id}
                      className={`transition-colors ${
                        isDark ? 'hover:bg-slate-800/30' : 'hover:bg-slate-50/80'
                      }`}
                    >
                      {/* Priority / Score */}
                      <td className="px-4 py-3">
                        <div className="flex items-center gap-2">
                          <span className={`px-2 py-0.5 rounded font-mono font-bold text-[11px] ${
                            t.priority === 'P0' ? 'bg-rose-500/20 text-rose-400 border border-rose-500/30' :
                            t.priority === 'P1' ? 'bg-orange-500/20 text-orange-400 border border-orange-500/30' :
                            t.priority === 'P2' ? 'bg-amber-500/20 text-amber-400 border border-amber-500/30' :
                            'bg-blue-500/20 text-blue-400 border border-blue-500/30'
                          }`}>
                            {t.priority}
                          </span>
                          <span className="font-mono text-slate-300 font-semibold">{t.skor_risiko || 50}/100</span>
                        </div>
                      </td>

                      {/* Ticket & Incident */}
                      <td className="px-4 py-3">
                        <div className="font-mono font-semibold text-blue-400">{t.triage_id}</div>
                        <div className="text-[11px] text-slate-400 truncate max-w-xs">{t.title}</div>
                        <div className="text-[10px] text-slate-500 font-mono mt-0.5">{t.rule_code}</div>
                      </td>

                      {/* Actor & Target */}
                      <td className="px-4 py-3">
                        <div className="flex items-center gap-1.5 font-mono text-[11px] text-slate-300">
                          <Globe className="w-3 h-3 text-slate-400" />
                          <span>{t.attacker_source_ip || '127.0.0.1'}</span>
                        </div>
                        <div className="flex items-center gap-1.5 font-mono text-[11px] text-slate-400 mt-1">
                          <Server className="w-3 h-3 text-slate-400" />
                          <span>{t.target_host}</span>
                        </div>
                      </td>

                      {/* Verdict */}
                      <td className="px-4 py-3">
                        <div className="flex items-center gap-2">
                          {isTp ? (
                            <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-md text-[11px] font-bold bg-rose-500/20 text-rose-400 border border-rose-500/30">
                              <ShieldAlert className="w-3 h-3" />
                              TRUE POSITIVE
                            </span>
                          ) : (
                            <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-md text-[11px] font-bold bg-emerald-500/20 text-emerald-400 border border-emerald-500/30">
                              <ShieldCheck className="w-3 h-3" />
                              FALSE POSITIVE
                            </span>
                          )}
                        </div>
                        <div className="text-[10px] text-slate-400 mt-1 flex items-center gap-1">
                          <span>Oleh:</span>
                          <span className="font-semibold text-slate-300">{t.assigned_analyst || 'analyst'}</span>
                        </div>
                      </td>

                      {/* Analyst Notes */}
                      <td className="px-4 py-3">
                        <div className="text-[11px] text-slate-300 max-w-sm line-clamp-2 italic">
                          "{t.analyst_notes || 'Tidak ada catatan analis'}"
                        </div>
                      </td>

                      {/* Actions */}
                      <td className="px-4 py-3 text-center">
                        <div className="flex items-center justify-center gap-2">
                          <button
                            onClick={() => handleOpenActionModal(t, 'APPROVE')}
                            className="flex items-center gap-1 px-2.5 py-1 rounded-lg bg-emerald-600/20 hover:bg-emerald-600/30 text-emerald-400 border border-emerald-500/40 text-[11px] font-semibold transition-all cursor-pointer"
                            title="Setujui Ground Truth"
                          >
                            <Check className="w-3.5 h-3.5" />
                            APPROVE
                          </button>
                          <button
                            onClick={() => handleOpenActionModal(t, 'REJECT')}
                            className="flex items-center gap-1 px-2.5 py-1 rounded-lg bg-rose-600/20 hover:bg-rose-600/30 text-rose-400 border border-rose-500/40 text-[11px] font-semibold transition-all cursor-pointer"
                            title="Tolak Ground Truth & Buat Tiket FP Reject"
                          >
                            <X className="w-3.5 h-3.5" />
                            REJECT
                          </button>
                        </div>
                      </td>
                    </tr>
                  );
                })
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* Confirmation & Justification Modal */}
      {selectedTicket && actionType && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/70 backdrop-blur-xs">
          <div className={`w-full max-w-lg rounded-2xl border p-6 shadow-2xl space-y-4 ${
            isDark ? 'bg-slate-900 border-slate-800 text-slate-200' : 'bg-white border-slate-200 text-slate-800'
          }`}>
            <div className="flex items-center justify-between pb-3 border-b border-slate-700/60">
              <div className="flex items-center gap-2">
                {actionType === 'APPROVE' ? (
                  <CheckCircle2 className="w-5 h-5 text-emerald-400" />
                ) : (
                  <AlertTriangle className="w-5 h-5 text-rose-400" />
                )}
                <h3 className="font-bold text-base">
                  {actionType === 'APPROVE' ? 'Setujui Ground Truth (APPROVE)' : 'Tolak Ground Truth (REJECT)'}
                </h3>
              </div>
              <button
                onClick={() => { setSelectedTicket(null); setActionType(null); }}
                className="p-1 rounded-lg hover:bg-slate-800 text-slate-400"
              >
                <X className="w-4 h-4" />
              </button>
            </div>

            <div className="space-y-3 text-xs">
              <div className={`p-3 rounded-xl border ${
                isDark ? 'bg-slate-950/60 border-slate-800' : 'bg-slate-50 border-slate-200'
              }`}>
                <div className="font-mono font-bold text-blue-400 mb-1">{selectedTicket.triage_id} — {selectedTicket.incident_id}</div>
                <div className="text-slate-300 font-medium mb-1">{selectedTicket.title}</div>
                <div className="text-slate-400">
                  Keputusan Analis: <span className="font-bold text-amber-400">{selectedTicket.ground_truth_verdict}</span>
                </div>
              </div>

              {actionType === 'APPROVE' ? (
                <div className="p-3 rounded-xl bg-emerald-500/10 border border-emerald-500/30 text-emerald-300 space-y-1">
                  <div className="font-semibold flex items-center gap-1.5">
                    <Info className="w-4 h-4" /> Dampak Persetujuan:
                  </div>
                  <ul className="list-disc list-inside text-[11px] text-emerald-400/90 space-y-0.5">
                    <li>Tiket bertransisi ke status <strong>APPROVE</strong>.</li>
                    <li>Ditambahkan ke dataset pelatihan ulang (retraining) model ML.</li>
                    <li>{selectedTicket.ground_truth_verdict === 'TRUE_POSITIVE' 
                      ? 'Dieskalasi sebagai Verified True Positive ke DFIR-IRIS dan feed MISP.'
                      : 'Dibuatkan draf usulan supresi Wazuh untuk diverifikasi.'}</li>
                  </ul>
                </div>
              ) : (
                <div className="p-3 rounded-xl bg-rose-500/10 border border-rose-500/30 text-rose-300 space-y-1">
                  <div className="font-semibold flex items-center gap-1.5">
                    <Info className="w-4 h-4" /> Dampak Penolakan:
                  </div>
                  <ul className="list-disc list-inside text-[11px] text-rose-400/90 space-y-0.5">
                    <li>Tiket saat ini berstatus <strong>REJECT</strong>.</li>
                    <li>Sistem otomatis menerbitkan tiket baru di Ticket Queue berstatus <strong>FP Reject</strong>.</li>
                    <li>Analis wajib mengulang investigasi sesuai masukan manajer.</li>
                  </ul>
                </div>
              )}

              <div>
                <label className="block text-[11px] font-semibold text-slate-400 mb-1">
                  Catatan Evaluasi SOC Manager (Wajib):
                </label>
                <textarea
                  value={managerNotes}
                  onChange={(e) => setManagerNotes(e.target.value)}
                  rows="3"
                  className={`w-full p-2.5 rounded-lg border text-xs focus:outline-hidden focus:ring-1 ${
                    isDark 
                      ? 'bg-slate-950 border-slate-700 text-slate-200 focus:border-blue-500' 
                      : 'bg-white border-slate-300 text-slate-800 focus:border-blue-500'
                  }`}
                  placeholder="Masukkan alasan atau instruksi spesifik untuk analis..."
                />
              </div>
            </div>

            <div className="flex items-center justify-end gap-2.5 pt-3 border-t border-slate-700/60">
              <button
                onClick={() => { setSelectedTicket(null); setActionType(null); }}
                disabled={submitting}
                className="px-4 py-2 rounded-xl text-xs font-semibold text-slate-400 hover:text-slate-200"
              >
                Batal
              </button>
              <button
                onClick={handleExecuteAction}
                disabled={submitting || !managerNotes.trim()}
                className={`px-5 py-2 rounded-xl text-xs font-bold text-white shadow-lg transition-all ${
                  actionType === 'APPROVE'
                    ? 'bg-emerald-600 hover:bg-emerald-500 shadow-emerald-900/40'
                    : 'bg-rose-600 hover:bg-rose-500 shadow-rose-900/40'
                } disabled:opacity-50`}
              >
                {submitting ? 'Memproses...' : actionType === 'APPROVE' ? 'Konfirmasi APPROVE' : 'Konfirmasi REJECT'}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
