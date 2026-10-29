import React, { useState, useEffect, useMemo } from 'react';

import {

  Search, RefreshCw, Copy, Check, X, Terminal, Shield,

  ArrowRight, Filter, AlertTriangle, Layers, Globe, Server, FileText, ChevronUp, ChevronDown, ExternalLink

} from 'lucide-react';



export default function RawAlertsQueue({ 

  theme = 'dark', 

  onNavigate, 

  selectedTenant = 'ALL',

  timeRange = 'semua',

  customStartDate = '2026-07-01',

  customEndDate = '2026-09-30'

}) {

  const isDark = theme === 'dark' || (typeof document !== 'undefined' && document.documentElement.classList.contains('dark'));



  const [alerts, setAlerts] = useState([]);

  const [loading, setLoading] = useState(false);

  const [totalRecords, setTotalRecords] = useState(0);

  const [currentPage, setCurrentPage] = useState(1);

  const [pageSize, setPageSize] = useState(25);

  const [levelFilter, setLevelFilter] = useState('ALL');

  const [searchQuery, setSearchQuery] = useState('');

  const [selectedAlert, setSelectedAlert] = useState(null);

  const [copiedId, setCopiedId] = useState(null);

  const [networkError, setNetworkError] = useState(false);

  const [jumpPageInput, setJumpPageInput] = useState('');

  const [levelCounts, setLevelCounts] = useState({

    CRITICAL: 38,

    HIGH: 4448,

    MEDIUM: 925369,

    LOW: 3643243

  });



  const fetchAlerts = async () => {

    setLoading(true);

    try {

      const params = new URLSearchParams({

        page: String(currentPage),

        limit: String(pageSize),

        level_filter: levelFilter

      });

      if (selectedTenant && selectedTenant !== 'ALL') {

        params.append('tenant_id', selectedTenant);

      }

      if (timeRange) {

        params.append('range', timeRange);

        if (timeRange === 'custom') {

          params.append('start', customStartDate);

          params.append('end', customEndDate);

        }

      }

      if (searchQuery.trim()) {

        params.append('search', searchQuery.trim());

      }



      const res = await fetch(`/api/raw-alerts?${params.toString()}`);

      if (res.ok) {

        setNetworkError(false);

        const data = await res.json();

        setAlerts(data.alerts || []);

        if (data.total !== undefined) {

          setTotalRecords(data.total);

        }

        if (data.level_counts) {

          setLevelCounts(data.level_counts);

        }

      } else {

        setNetworkError(true);

      }

    } catch (err) {

      console.error('Failed to fetch raw alerts:', err);

      setNetworkError(true);

    } finally {

      setLoading(false);

    }

  };



  useEffect(() => {

    fetchAlerts();

  }, [currentPage, pageSize, levelFilter, selectedTenant, timeRange, customStartDate, customEndDate]);



  const handleSearchSubmit = (e) => {

    if (e) e.preventDefault();

    setCurrentPage(1);

    fetchAlerts();

  };



  const handleCopyLog = (text, id) => {

    navigator.clipboard.writeText(text);

    setCopiedId(id);

    setTimeout(() => setCopiedId(null), 2500);

  };



  const handleJumpPage = (e) => {

    e.preventDefault();

    const p = parseInt(jumpPageInput, 10);

    const maxPage = Math.max(1, Math.ceil(totalRecords / pageSize));

    if (!isNaN(p) && p >= 1 && p <= maxPage) {

      setCurrentPage(p);

      setJumpPageInput('');

    }

  };



  const levelTabs = [

    { id: 'ALL', label: 'All' },

    { id: 'CRITICAL', label: 'Critical' },

    { id: 'HIGH', label: 'High' },

    { id: 'MEDIUM', label: 'Medium' },

    { id: 'LOW', label: 'Low' },

  ];



  const severityCards = [

    {

      id: 'CRITICAL',

      label: 'Critical',

      range: 'Level 15+',

      count: levelCounts.CRITICAL || 0

    },

    {

      id: 'HIGH',

      label: 'High',

      range: 'Level 12 - 14',

      count: levelCounts.HIGH || 0

    },

    {

      id: 'MEDIUM',

      label: 'Medium',

      range: 'Level 7 - 11',

      count: levelCounts.MEDIUM || 0

    },

    {

      id: 'LOW',

      label: 'Low',

      range: 'Level 0 - 6',

      count: levelCounts.LOW || 0

    }

  ];



  const totalPages = Math.max(1, Math.ceil(totalRecords / pageSize));



  const getLevelBadge = (lvl) => {

    const num = Number(lvl) || 0;

    if (num >= 15) {

      return (

        <span className="font-bold font-mono text-xs text-rose-500">

          {num}

        </span>

      );

    }

    if (num >= 12) {

      return (

        <span className="font-bold font-mono text-xs text-orange-500">

          {num}

        </span>

      );

    }

    if (num >= 7) {

      return (

        <span className="font-bold font-mono text-xs text-amber-500">

          {num}

        </span>

      );

    }

    return (

      <span className="font-bold font-mono text-xs text-emerald-500">

        {num}

      </span>

    );

  };



  return (

    <div className="w-full flex flex-col gap-4">

      {/* 4 Severity Level Metric Summary Cards */}

      <div className="grid grid-cols-2 sm:grid-cols-4 gap-3.5 w-full">

        {severityCards.map(card => {

          const isSelected = levelFilter === card.id;

          return (

            <div

              key={card.id}

              onClick={() => {

                setLevelFilter(prev => prev === card.id ? 'ALL' : card.id);

                setCurrentPage(1);

              }}

              title={`Klik untuk filter ${card.label} (${card.range})`}

              className={`py-4 px-3.5 border rounded-xl transition-all flex flex-col items-center justify-center text-center cursor-pointer select-none group ${

                isDark 

                  ? (isSelected 

                      ? 'bg-blue-950/40 border-blue-500 ring-2 ring-blue-500/40 shadow-md' 

                      : 'bg-[#0a0e1a] border-slate-800 hover:border-slate-700 hover:bg-slate-900/40') 

                  : (isSelected 

                      ? 'bg-blue-50/80 border-blue-600 ring-2 ring-blue-600/30 shadow-md' 

                      : 'bg-white border-slate-200 hover:border-slate-300 hover:bg-slate-50 shadow-xs')

              }`}

            >

              <span className={`text-xs font-bold tracking-wider uppercase ${

                isDark ? 'text-slate-400' : 'text-slate-700'

              }`}>

                {card.label}

              </span>

              <div className={`text-2xl font-bold font-mono tracking-tight my-0.5 ${

                isDark ? 'text-white' : 'text-slate-900'

              }`}>

                {Number(card.count).toLocaleString('id-ID')}

              </div>

              <span className="text-[10px] font-mono text-slate-400 dark:text-slate-500 font-medium">

                {card.range}

              </span>

            </div>

          );

        })}

      </div>



      {/* Main Table + Forensic Log Drawer Container */}

      <div className="w-full flex flex-row gap-4 items-stretch">

        {/* Left: Main Table Container */}

        <div className={`transition-all duration-200 ${

          selectedAlert ? 'flex-1 min-w-0' : 'w-full'

        }`}>

        <div className={`border rounded-xl overflow-hidden ${

          isDark 

            ? 'bg-[#0a0e1a] border-slate-800' 

            : 'bg-white border-slate-200 shadow-xs'

        }`}>

          {/* Header Bar: Title di Kiri, Search Bar di Tengah, Red Flag Icon di Pojok Kanan (Tanpa Lingkaran) */}

          <div className={`px-6 py-3.5 border-b flex items-center justify-between gap-4 transition-colors ${

            isDark ? 'border-slate-800 bg-[#070b14]' : 'border-slate-100 bg-slate-50/50'

          }`}>

            {/* Left Title */}

            <div className="shrink-0 w-24 sm:w-32">

              <h2 className={`text-base font-bold tracking-tight ${

                isDark ? 'text-white' : 'text-slate-900'

              }`}>

                Alert

              </h2>

            </div>



            {/* Center Search Bar */}

            <div className="flex-1 flex items-center justify-center max-w-xl mx-auto">

              <form 

                onSubmit={handleSearchSubmit}

                className="relative w-full"

              >

                <div className="w-full relative flex items-center bg-white dark:bg-[#090d16] border-2 border-[#3B5BFF] rounded-full h-[38px] pl-3.5 pr-1.5 shadow-2xs group focus-within:ring-2 focus-within:ring-[#3B5BFF]/30 transition-all">

                  <Search className="w-4 h-4 text-slate-400 shrink-0 mr-2.5 stroke-[2]" />

                  <input

                    type="text"

                    value={searchQuery}

                    onChange={(e) => {
                      const val = e.target.value;
                      setSearchQuery(val);
                      if (val === '') {
                        setCurrentPage(1);
                        setTimeout(fetchAlerts, 50);
                      }
                    }}

                    placeholder="Search ID, IP, Host, Rule, agg_..., cum_..., TRG-..."

                    className="w-full bg-transparent text-slate-800 dark:text-slate-200 placeholder:text-slate-400 text-xs sm:text-[13px] font-normal focus:outline-none"

                  />

                  {searchQuery && (

                    <button

                      type="button"

                      onClick={() => {

                        setSearchQuery('');

                        setCurrentPage(1);

                        setTimeout(fetchAlerts, 50);

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

                    <Search 

                      className="w-3.5 h-3.5 text-white"

                      strokeWidth={2.5}

                    />

                  </button>

                </div>

              </form>

            </div>



            {/* Right spacer for symmetrical centering */}

            <div className="shrink-0 w-24 sm:w-32" />

          </div>



          {/* High-Density Raw Alerts Table (8 Columns: Timestamp, ID, Tenant, Rule ID, Rule Desc, Level, Actor, Target) */}

          <div className="overflow-x-auto w-full">

            <table className="w-full table-fixed min-w-[760px] text-left text-xs border-collapse">

              <thead className={`border-b text-xs font-semibold ${

                isDark 

                  ? 'bg-[#0b101d] text-slate-300 border-slate-800' 

                  : 'bg-[#F0F5FA] text-slate-700 border-slate-200/80'

              }`}>

                <tr>

                  <th className="w-[13%] px-2.5 py-3 select-none whitespace-nowrap">

                    <span>Timestamp</span>

                  </th>

                  <th className="w-[15%] px-2.5 py-3 select-none whitespace-nowrap">

                    <span>ID</span>

                  </th>

                  <th className="w-[9%] px-2 py-3 select-none whitespace-nowrap">

                    <span>Tenant</span>

                  </th>

                  <th className="w-[6%] px-1.5 py-3 text-center select-none whitespace-nowrap">

                    <span>Rule ID</span>

                  </th>

                  <th className="w-[26%] px-2.5 py-3 select-none whitespace-nowrap">

                    <span>Rule Desc</span>

                  </th>

                  <th className="w-[5%] px-1 py-3 text-center select-none whitespace-nowrap">

                    <span>Level</span>

                  </th>

                  <th className="w-[11%] px-2 py-3 select-none whitespace-nowrap">

                    <span>Actor</span>

                  </th>

                  <th className="w-[15%] px-2 py-3 select-none whitespace-nowrap">

                    <span>Target</span>

                  </th>

                </tr>

              </thead>

              <tbody className={`divide-y font-sans ${

                isDark ? 'divide-slate-800/60 bg-[#0a0e1a]' : 'divide-slate-100 bg-white'

              }`}>

                {loading && alerts.length === 0 ? (

                  <tr>

                    <td colSpan="8" className="px-6 py-20 text-center">

                      <div className="flex flex-col items-center justify-center gap-2.5">

                        <RefreshCw className="w-5 h-5 animate-spin text-blue-500" />

                        <span className={`text-xs font-mono font-medium ${isDark ? 'text-slate-400' : 'text-slate-600'}`}>

                          Memuat data raw alert dari PostgreSQL...

                        </span>

                      </div>

                    </td>

                  </tr>

                ) : networkError && alerts.length === 0 ? (

                  <tr>

                    <td colSpan="8" className="px-6 py-14 text-center">

                      <div className="flex flex-col items-center justify-center gap-2">

                        <AlertTriangle className="w-5 h-5 text-amber-500" />

                        <span className={`text-xs font-mono font-semibold ${isDark ? 'text-amber-400' : 'text-amber-600'}`}>

                          Gagal memuat raw alert dari backend API.

                        </span>

                        <button

                          onClick={fetchAlerts}

                          className="mt-2 px-3 py-1 rounded bg-blue-600 hover:bg-blue-500 text-white text-xs font-medium cursor-pointer"

                        >

                          Coba Lagi

                        </button>

                      </div>

                    </td>

                  </tr>

                ) : alerts.length === 0 ? (

                  <tr>

                    <td colSpan="8" className="px-6 py-14 text-center">

                      <span className={`text-xs font-mono ${isDark ? 'text-slate-500' : 'text-slate-400'}`}>

                        Tidak ada raw alert yang cocok dengan filter atau pencarian ini.

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

                        <td className="px-2.5 py-2 font-mono text-[11px] whitespace-nowrap overflow-hidden">

                          <span className={isDark ? 'text-slate-300' : 'text-slate-600'}>

                            {al.timestamp}

                          </span>

                        </td>



                        {/* Alert ID (ID Wazuh warna biru, clickable, single line) */}

                        <td className="px-2.5 py-2 font-mono whitespace-nowrap overflow-hidden">

                          <span 

                            className="font-bold text-[11px] tracking-tight text-blue-600 dark:text-blue-400 hover:text-blue-700 dark:hover:text-blue-300 hover:underline cursor-pointer select-all truncate block"

                            title={`Buka detail raw alert (${al.id})`}

                            onClick={() => setSelectedAlert(prev => prev?.id === al.id ? null : al)}

                          >

                            {al.id}

                          </span>

                        </td>



                    {/* Tenant */}

                    <td className="px-2 py-2 font-mono whitespace-nowrap overflow-hidden">

                      <span 

                        className={`text-[11px] font-semibold truncate block ${isDark ? 'text-slate-300' : 'text-slate-700'}`}

                        title={al.tenant_id || 'DEFAULT'}

                      >

                        {al.tenant_id || 'DEFAULT'}

                      </span>

                    </td>



                    {/* Rule ID */}

                    <td className="px-1.5 py-2 text-center font-mono whitespace-nowrap overflow-hidden">

                      <span 

                        className={`text-[11px] font-semibold ${

                          isDark ? 'text-slate-300' : 'text-slate-700'

                        }`}

                      >

                        {al.rule_id || '-'}

                      </span>

                    </td>



                    {/* Rule Desc */}

                    <td className="px-2.5 py-2 whitespace-nowrap overflow-hidden">

                      <span 

                        className={`text-[11px] font-medium truncate block ${

                          isDark ? 'text-slate-200' : 'text-slate-800'

                        }`}

                        title={al.rule_description || `Wazuh Rule ${al.rule_id}`}

                      >

                        {al.rule_description || `Wazuh Rule ${al.rule_id}`}

                      </span>

                    </td>



                    {/* Level */}

                    <td className="px-1 py-2 text-center font-mono whitespace-nowrap">

                      {getLevelBadge(al.rule_level)}

                    </td>



                    {/* Actor (Source IP / User) */}

                    <td className="px-2 py-2 font-mono whitespace-nowrap overflow-hidden">

                      <div 

                        className={`text-[11px] font-mono truncate block ${isDark ? 'text-slate-300' : 'text-slate-600'}`}

                        title={al.actor || '-'}

                      >

                        {al.actor || '-'}

                      </div>

                    </td>



                    {/* Target (Agent Name / Destination IP) */}

                    <td className="px-2 py-2 font-mono whitespace-nowrap overflow-hidden">

                      <div 

                        className={`text-[11px] font-semibold truncate block ${isDark ? 'text-slate-200' : 'text-slate-900'}`}

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



        {/* Pagination Footer */}

        <div className={`p-4 border-t flex items-center justify-between text-xs flex-wrap gap-3 ${

          isDark ? 'border-slate-800 text-slate-400 bg-[#0a0e1a]' : 'border-slate-200 text-slate-500 bg-[#F0F5FA]/40'

        }`}>

          <div>

            {loading && alerts.length === 0 ? (

              <span className="font-mono text-xs">Memuat data alert...</span>

            ) : alerts.length === 0 ? (

              <span className="font-mono text-xs">0 alert</span>

            ) : (

              <>

                Showing <span className={`font-mono font-semibold ${isDark ? 'text-slate-200' : 'text-slate-700'}`}>{(currentPage - 1) * pageSize + 1}</span> to <span className={`font-mono font-semibold ${isDark ? 'text-slate-200' : 'text-slate-700'}`}>{Math.min(currentPage * pageSize, totalRecords)}</span> of <span className={`font-mono font-semibold ${isDark ? 'text-slate-200' : 'text-slate-700'}`}>{totalRecords.toLocaleString()}</span> alerts

              </>

            )}

          </div>



          <div className="flex items-center gap-2">

            <button

              onClick={() => setCurrentPage(p => Math.max(1, p - 1))}

              disabled={currentPage === 1 || loading}

              className={`px-3 py-1 rounded-lg border text-xs font-semibold transition-all cursor-pointer disabled:opacity-30 disabled:cursor-not-allowed ${

                isDark 

                  ? 'bg-slate-800 border-slate-700 text-slate-300 hover:bg-slate-700' 

                  : 'bg-white border-slate-200 text-slate-700 hover:bg-slate-50 shadow-2xs'

              }`}

            >

              Prev

            </button>

            <span className={`font-mono text-xs px-2 font-medium ${isDark ? 'text-slate-400' : 'text-slate-600'}`}>

              {currentPage.toLocaleString()} / {totalPages.toLocaleString()}

            </span>

            <button

              onClick={() => setCurrentPage(p => Math.min(totalPages, p + 1))}

              disabled={currentPage === totalPages || loading}

              className={`px-3 py-1 rounded-lg border text-xs font-semibold transition-all cursor-pointer disabled:opacity-30 disabled:cursor-not-allowed ${

                isDark 

                  ? 'bg-slate-800 border-slate-700 text-slate-300 hover:bg-slate-700' 

                  : 'bg-white border-slate-200 text-slate-700 hover:bg-slate-50 shadow-2xs'

              }`}

            >

              Next

            </button>



            {/* Jump to page form */}

            <form onSubmit={handleJumpPage} className="flex items-center gap-1.5 ml-2">

              <input

                type="number"

                min="1"

                max={totalPages}

                value={jumpPageInput}

                onChange={(e) => setJumpPageInput(e.target.value)}

                placeholder="Go to..."

                className={`w-16 px-2 py-1 rounded border text-xs font-mono focus:outline-none ${

                  isDark ? 'bg-slate-900 border-slate-700 text-slate-200' : 'bg-white border-slate-200 text-slate-800'

                }`}

              />

              <button

                type="submit"

                className="px-2 py-1 rounded bg-blue-600 hover:bg-blue-500 text-white text-xs font-medium cursor-pointer"

              >

                Go

              </button>

            </form>

          </div>

        </div>

        </div>

      </div>



      {/* Right: Side Detail Panel (Height matches table via self-stretch) */}

      {selectedAlert && (

        <div className={`w-[360px] md:w-[400px] xl:w-[440px] shrink-0 border rounded-xl p-5 shadow-lg flex flex-col self-stretch animate-in fade-in slide-in-from-right-4 duration-200 ${

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



          <div className="flex-1 flex flex-col space-y-3.5 text-xs">

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

                      <Check className="w-3.5 h-3.5 text-emerald-500" />

                    ) : (

                      <Copy className="w-3.5 h-3.5" />

                    )}

                  </button>

                </div>

              </div>



              <div className="grid grid-cols-2 gap-2 pt-1 border-t border-slate-200 dark:border-slate-800/80">

                <div>

                  <span className={`block text-[10px] uppercase font-semibold ${isDark ? 'text-slate-400' : 'text-slate-500'}`}>Timestamp:</span>

                  <span className={`font-mono font-bold ${isDark ? 'text-white' : 'text-black'}`}>{selectedAlert.timestamp}</span>

                </div>

                <div>

                  <span className={`block text-[10px] uppercase font-semibold ${isDark ? 'text-slate-400' : 'text-slate-500'}`}>Tenant:</span>

                  <span className={`font-mono font-bold ${isDark ? 'text-white' : 'text-black'}`}>{selectedAlert.tenant_id || 'DEFAULT'}</span>

                </div>

              </div>



              <div className="grid grid-cols-2 gap-2 pt-1 border-t border-slate-200 dark:border-slate-800/80">

                <div>

                  <span className={`block text-[10px] uppercase font-semibold ${isDark ? 'text-slate-400' : 'text-slate-500'}`}>Rule & Level:</span>

                  <span className={`font-mono font-bold ${isDark ? 'text-white' : 'text-black'}`}>

                    Rule {selectedAlert.rule_id} · Lv {selectedAlert.rule_level}

                  </span>

                </div>

                <div>

                  <span className={`block text-[10px] uppercase font-semibold ${isDark ? 'text-slate-400' : 'text-slate-500'}`}>Actor (IP):</span>

                  <span className={`font-mono font-bold ${isDark ? 'text-white' : 'text-black'}`}>{selectedAlert.actor || '-'}</span>

                </div>

              </div>



              <div className="pt-1 border-t border-slate-200 dark:border-slate-800/80">

                <span className={`block text-[10px] uppercase font-semibold ${isDark ? 'text-slate-400' : 'text-slate-500'}`}>Target (Agent/Host):</span>

                <span className={`font-mono font-bold ${isDark ? 'text-white' : 'text-black'}`}>{selectedAlert.target || '-'}</span>

              </div>



              <div className="pt-1 border-t border-slate-200 dark:border-slate-800/80">

                <span className={`block text-[10px] uppercase font-semibold ${isDark ? 'text-slate-400' : 'text-slate-500'}`}>Rule Description:</span>

                <span className={`font-medium block mt-0.5 leading-relaxed ${isDark ? 'text-white' : 'text-black'}`}>

                  {selectedAlert.rule_description || '-'}

                </span>

              </div>

            </div>



            {/* Lineage Box */}

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



            {/* Full Log Payload (white box with black text and flex-1 stretch) */}

            <div className="flex-1 flex flex-col min-h-[160px] space-y-1.5 pt-1">

              <div className="flex items-center justify-between text-xs font-semibold">

                <span className={`uppercase font-bold tracking-wider text-[11px] ${

                  isDark ? 'text-slate-300' : 'text-slate-700'

                }`}>

                  FULL LOG PAYLOAD:

                </span>

                <button

                  type="button"

                  onClick={() => handleCopyLog(selectedAlert.full_log, selectedAlert.id)}

                  className="flex items-center gap-1 text-[11px] font-mono text-blue-500 hover:text-blue-400 cursor-pointer"

                >

                  {copiedId === selectedAlert.id ? (

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

              <pre className="raw-log-viewer cluster-raw-log p-3 rounded-lg border border-slate-300 font-mono text-[10.5px] leading-relaxed break-all whitespace-pre-wrap select-all flex-1 min-h-[140px] overflow-y-auto shadow-2xs">

                {selectedAlert.full_log || 'Tidak ada payload log mentah.'}

              </pre>

            </div>

          </div>

        </div>

      )}

      </div>

    </div>

  );

}

