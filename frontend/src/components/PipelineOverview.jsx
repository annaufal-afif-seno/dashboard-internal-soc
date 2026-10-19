import React, { useState, useEffect, useMemo } from 'react';
import { 
  Activity, Filter, Shield, AlertTriangle, Database, Layers, 
  ArrowDownRight, RefreshCw, BarChart2, Inbox, Sliders, ShieldCheck, 
  CheckCircle2, AlertCircle, ArrowRight, ShieldAlert, Clock,
  BellOff, Crosshair 
} from 'lucide-react';
import { AreaChart, Area, XAxis, YAxis, Tooltip, ResponsiveContainer, PieChart, Pie, Cell, CartesianGrid } from 'recharts';

const defaultReductionData = [
  { day: 'Jul 25', ingest: 30458, ingested: 30458, suppressed: 30084, aggregate: 372, aggregated: 372, ticket: 2, ticketing: 2, threat: 1, groundtruth: 1, raw: 30458, visible: 374 },
  { day: 'Jul 26', ingest: 29760, ingested: 29760, suppressed: 29387, aggregate: 371, aggregated: 371, ticket: 2, ticketing: 2, threat: 1, groundtruth: 1, raw: 29760, visible: 373 },
  { day: 'Jul 27', ingest: 29995, ingested: 29995, suppressed: 29617, aggregate: 377, aggregated: 377, ticket: 1, ticketing: 1, threat: 1, groundtruth: 1, raw: 29995, visible: 378 },
  { day: 'Jul 28', ingest: 21344, ingested: 21344, suppressed: 20954, aggregate: 387, aggregated: 387, ticket: 3, ticketing: 3, threat: 1, groundtruth: 1, raw: 21344, visible: 390 },
  { day: 'Jul 29', ingest: 20714, ingested: 20714, suppressed: 20309, aggregate: 399, aggregated: 399, ticket: 6, ticketing: 6, threat: 2, groundtruth: 2, raw: 20714, visible: 405 },
  { day: 'Jul 30', ingest: 22960, ingested: 22960, suppressed: 22670, aggregate: 277, aggregated: 277, ticket: 13, ticketing: 13, threat: 3, groundtruth: 2, raw: 22960, visible: 290 },
  { day: 'Jul 31', ingest: 12768, ingested: 12768, suppressed: 12354, aggregate: 386, aggregated: 386, ticket: 28, ticketing: 28, threat: 5, groundtruth: 4, raw: 12768, visible: 414 },
];

const defaultPriorityData = [
  { name: 'P0', value: 117, color: '#f43f5e' },
  { name: 'P1', value: 239, color: '#f97316' },
  { name: 'P2', value: 14, color: '#eab308' },
  { name: 'P3', value: 0, color: '#10b981' },
  { name: 'P4', value: 0, color: '#64748b' }
];

// SLA Durations for Earliest Deadline First (EDF) Dynamic Scheduling
const SLA_INTERVALS_MS = {
  P0: 15 * 60 * 1000,      // 15 minutes
  P1: 30 * 60 * 1000,      // 30 minutes
  P2: 4 * 60 * 60 * 1000,  // 4 hours
  P3: 24 * 60 * 60 * 1000, // 24 hours
  P4: 7 * 24 * 60 * 60 * 1000 // 7 days
};

const computeSlaDeadlineStr = (createdStr, priority = 'P1') => {
  if (!createdStr) return '';
  const parsed = Date.parse(createdStr.replace(' ', 'T'));
  if (isNaN(parsed)) return createdStr;
  const addMs = SLA_INTERVALS_MS[priority?.toUpperCase()] || SLA_INTERVALS_MS.P1;
  const deadlineDate = new Date(parsed + addMs);
  const pad = (n) => String(n).padStart(2, '0');
  return `${deadlineDate.getFullYear()}-${pad(deadlineDate.getMonth() + 1)}-${pad(deadlineDate.getDate())} ${pad(deadlineDate.getHours())}:${pad(deadlineDate.getMinutes())}:${pad(deadlineDate.getSeconds())}`;
};

const defaultLiveFeed = [
  {
    priority: "P0",
    created_at: "2026-07-31 10:14:00",
    deadline_sla: "2026-07-31 10:29:00",
    time_ago: "2026-07-31 10:29:00",
    title: "Lonjakan koneksi lateral dari 10.0.4.17",
    incident_id: "INC-4412",
    status: "Investigate"
  },
  {
    priority: "P1",
    created_at: "2026-07-31 10:05:00",
    deadline_sla: "2026-07-31 10:35:00",
    time_ago: "2026-07-31 10:35:00",
    title: "Brute-force SSH — 340 percobaan/mnt",
    incident_id: "INC-4410",
    status: "Open"
  },
  {
    priority: "P1",
    created_at: "2026-07-31 10:18:00",
    deadline_sla: "2026-07-31 10:48:00",
    time_ago: "2026-07-31 10:48:00",
    title: "Pola exfiltration DNS terdeteksi",
    incident_id: "INC-4411",
    status: "Investigate"
  },
  {
    priority: "P1",
    created_at: "2026-07-31 10:30:00",
    deadline_sla: "2026-07-31 11:00:00",
    time_ago: "2026-07-31 11:00:00",
    title: "Eksploitasi RCE Web App CVE-2026-218",
    incident_id: "INC-4407",
    status: "Open"
  },
  {
    priority: "P0",
    created_at: "2026-07-31 10:50:00",
    deadline_sla: "2026-07-31 11:05:00",
    time_ago: "2026-07-31 11:05:00",
    title: "Akses root tidak sah pada prod-db-01",
    incident_id: "INC-4406",
    status: "Investigate"
  },
  {
    priority: "P2",
    created_at: "2026-07-31 08:00:00",
    deadline_sla: "2026-07-31 12:00:00",
    time_ago: "2026-07-31 12:00:00",
    title: "Perubahan permission /etc/shadow mendadak",
    incident_id: "INC-4405",
    status: "Open"
  },
  {
    priority: "P3",
    created_at: "2026-07-31 06:00:00",
    deadline_sla: "2026-07-31 14:00:00",
    time_ago: "2026-07-31 14:00:00",
    title: "Anomali volume egress melebihi baseline",
    incident_id: "INC-4404",
    status: "Open"
  },
  {
    priority: "P2",
    created_at: "2026-07-31 08:24:00",
    deadline_sla: "2026-07-31 12:24:00",
    time_ago: "2026-07-31 12:24:00",
    title: "Scanning port 443 dari 185.220.x.x",
    incident_id: "INC-4408",
    status: "Close"
  },
  {
    priority: "P2",
    created_at: "2026-07-31 09:24:05",
    deadline_sla: "2026-07-31 13:24:05",
    time_ago: "2026-07-31 13:24:05",
    title: "Alert supresi FALSE_POS dikonfirmasi",
    incident_id: "INC-4409",
    status: "Close"
  },
  {
    priority: "P3",
    created_at: "2026-07-31 07:15:00",
    deadline_sla: "2026-07-31 15:15:00",
    time_ago: "2026-07-31 15:15:00",
    title: "Akses SMB anomalous antardepartemen",
    incident_id: "INC-4403",
    status: "Close"
  },
  {
    priority: "P4",
    created_at: "2026-07-31 01:00:00",
    deadline_sla: "2026-08-07 01:00:00",
    time_ago: "2026-08-07 01:00:00",
    title: "Audit rotasi kredensial layanan backup",
    incident_id: "INC-4402",
    status: "Investigate"
  },
  {
    priority: "P4",
    created_at: "2026-07-30 18:00:00",
    deadline_sla: "2026-08-06 18:00:00",
    time_ago: "2026-08-06 18:00:00",
    title: "Verifikasi pembaruan patch kernel Ubuntu",
    incident_id: "INC-4401",
    status: "Close"
  }
];

// Custom High-Contrast Tooltip for Area Chart (Adaptive Light & Dark Mode)
const CustomAreaTooltip = ({ active, payload, label, isDark }) => {
  const darkMode = isDark !== undefined 
    ? isDark 
    : (typeof document !== 'undefined' && (document.documentElement.classList.contains('dark') || !document.documentElement.classList.contains('light')));

  if (active && payload && payload.length) {
    return (
      <div style={{
        backgroundColor: darkMode ? '#0f172a' : '#ffffff',
        border: darkMode ? '1px solid #334155' : '1px solid #e2e8f0',
        borderRadius: '8px',
        padding: '10px 14px',
        boxShadow: darkMode 
          ? '0 12px 28px rgba(0, 0, 0, 0.85)' 
          : '0 10px 25px -5px rgba(15, 23, 42, 0.12), 0 8px 10px -6px rgba(15, 23, 42, 0.08)',
        minWidth: '170px'
      }}>
        <div style={{
          color: darkMode ? '#cbd5e1' : '#475569',
          fontSize: '11px',
          fontFamily: 'monospace',
          fontWeight: '600',
          borderBottom: darkMode ? '1px solid #1e293b' : '1px solid #f1f5f9',
          paddingBottom: '4px',
          marginBottom: '6px'
        }}>
          {label}
        </div>
        {payload.map((entry, index) => (
          <div key={`entry-${index}`} style={{
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'space-between',
            gap: '12px',
            marginTop: '3px'
          }}>
            <span style={{ 
              display: 'flex', 
              alignItems: 'center', 
              gap: '6px', 
              color: darkMode ? '#e2e8f0' : '#334155', 
              fontSize: '12px' 
            }}>
              <span style={{ width: '8px', height: '8px', borderRadius: '50%', backgroundColor: entry.color }}></span>
              <span>{entry.name}:</span>
            </span>
            <span style={{ 
              color: darkMode ? '#ffffff' : '#0f172a', 
              fontSize: '12px', 
              fontWeight: 'bold', 
              fontFamily: 'monospace' 
            }}>
              {Number(entry.value).toLocaleString()}
            </span>
          </div>
        ))}
      </div>
    );
  }
  return null;
};

// Custom High-Contrast Tooltip for Priority Donut Chart (Adaptive Light & Dark Mode)
const CustomDonutTooltip = ({ active, payload, isDark }) => {
  const darkMode = isDark !== undefined 
    ? isDark 
    : (typeof document !== 'undefined' && (document.documentElement.classList.contains('dark') || !document.documentElement.classList.contains('light')));

  if (active && payload && payload.length) {
    const item = payload[0];
    return (
      <div style={{
        backgroundColor: darkMode ? '#0f172a' : '#ffffff',
        border: darkMode ? '1px solid #334155' : '1px solid #e2e8f0',
        borderRadius: '8px',
        padding: '8px 12px',
        boxShadow: darkMode 
          ? '0 12px 28px rgba(0, 0, 0, 0.85)' 
          : '0 10px 25px -5px rgba(15, 23, 42, 0.12), 0 8px 10px -6px rgba(15, 23, 42, 0.08)',
        display: 'flex',
        alignItems: 'center',
        gap: '8px'
      }}>
        <span style={{ width: '10px', height: '10px', borderRadius: '50%', backgroundColor: item.payload.color || item.color }}></span>
        <span style={{ 
          color: darkMode ? '#ffffff' : '#0f172a', 
          fontSize: '12px', 
          fontWeight: '600', 
          fontFamily: 'monospace' 
        }}>
          {item.name}:
        </span>
        <span style={{ 
          color: item.payload.color || (darkMode ? '#38bdf8' : '#0284c7'), 
          fontSize: '13px', 
          fontWeight: 'bold', 
          fontFamily: 'monospace' 
        }}>
          {Number(item.value).toLocaleString()}
        </span>
      </div>
    );
  }
  return null;
};

export default function PipelineOverview({ 
  onNavigate, 
  timeRange = 'semua', 
  customStartDate = '2026-07-01', 
  customEndDate = '2026-09-30',
  selectedTenant = 'ALL',
  theme = 'dark'
}) {
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [feedFilter, setFeedFilter] = useState('ALL');

  const fetchOverview = async () => {
    try {
      setLoading(true);
      const params = new URLSearchParams({
        range: timeRange,
        start: customStartDate,
        end: customEndDate
      });
      if (selectedTenant && selectedTenant !== 'ALL') {
        params.append('tenant_id', selectedTenant);
      }
      const res = await fetch(`http://127.0.0.1:8000/api/metrics/overview?${params.toString()}`);
      if (res.ok) {
        const json = await res.json();
        setData(json);
      }
    } catch (err) {
      console.warn("Could not fetch metrics overview:", err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchOverview();
    const interval = setInterval(fetchOverview, 20000);
    return () => clearInterval(interval);
  }, [timeRange, customStartDate, customEndDate, selectedTenant]);

  const totalRaw = data ? data.total_raw_events.toLocaleString() : "-";
  const totalAggs = data ? data.total_aggregated_alerts.toLocaleString() : "-";
  const actionableAggs = data?.actionable_aggregated_alerts !== undefined
    ? Number(data.actionable_aggregated_alerts).toLocaleString()
    : "164";
  const suppressedAggs = data?.suppressed_aggregated_alerts !== undefined
    ? Number(data.suppressed_aggregated_alerts).toLocaleString()
    : "2,405";
  const aggReductionPct = data?.aggregation_reduction_percentage !== undefined
    ? data.aggregation_reduction_percentage
    : 93.6;
  const standaloneAggs = data?.standalone_aggregated_alerts !== undefined
    ? Number(data.standalone_aggregated_alerts).toLocaleString()
    : (data ? (Number(data.actionable_aggregated_alerts || 0) - (data.aggregates_in_correlation || 0)).toLocaleString() : "-");
  const aggsInCorr = data?.aggregates_in_correlation !== undefined
    ? Number(data.aggregates_in_correlation).toLocaleString()
    : "-";
  const totalCorr = data ? data.total_correlated_incidents.toLocaleString() : "-";
  const totalTickets = data ? (data.total_active_tickets || data.total_correlated_incidents).toLocaleString() : (totalCorr || "-");
  const totalThreats = data?.total_threats !== undefined
    ? Number(data.total_threats).toLocaleString()
    : (data?.ticket_overview?.true_positive !== undefined
      ? Number(data.ticket_overview.true_positive).toLocaleString()
      : "0");
  const totalGroundtruth = data
    ? (data.total_groundtruth !== undefined
        ? Number(data.total_groundtruth).toLocaleString()
        : (data.total_ground_truth !== undefined
            ? Number(data.total_ground_truth).toLocaleString()
            : "46.191"))
    : "-";

  const reductionChartData = (data?.reduction_data || defaultReductionData).map(d => {
    const rawVal = d.ingest ?? d.ingested ?? d.raw ?? 0;
    const aggVal = d.aggregate ?? d.aggregated ?? (d.visible ? Math.max(0, d.visible - 2) : 0);
    const tickVal = d.ticket ?? d.ticketing ?? d.correlated ?? 0;
    const thrVal = d.threat ?? Math.round((d.correlated || 0) * 0.12);
    const gtVal = d.groundtruth ?? (d.gt ?? Math.round((d.threat || 0) * 0.8));
    return {
      ...d,
      ingest: rawVal,
      ingested: rawVal,
      aggregate: aggVal,
      aggregated: aggVal,
      ticket: tickVal,
      ticketing: tickVal,
      threat: thrVal,
      groundtruth: gtVal
    };
  });

  const xAxisTicks = useMemo(() => {
    if (!reductionChartData || reductionChartData.length === 0) return [];
    const len = reductionChartData.length;
    if (len <= 10) {
      return reductionChartData.map(d => d.day);
    }
    const maxTicks = 8;
    const step = (len - 1) / (maxTicks - 1);
    const ticks = [];
    for (let i = 0; i < maxTicks; i++) {
      const idx = Math.min(Math.round(i * step), len - 1);
      ticks.push(reductionChartData[idx].day);
    }
    return [...new Set(ticks)];
  }, [reductionChartData]);
  
  // Incident Priority Breakdown (P0-P4: 100% Actionable Incidents & Telemetry, excluding suppressed noise)
  const priorityConfigs = [
    { key: 'P0', label: 'P0', color: '#f43f5e', fallback: 22 },
    { key: 'P1', label: 'P1', color: '#f97316', fallback: 33 },
    { key: 'P2', label: 'P2', color: '#eab308', fallback: 0 },
    { key: 'P3', label: 'P3', color: '#10b981', fallback: 51 },
    { key: 'P4', label: 'P4', color: '#38bdf8', fallback: 110 }
  ];

  const incidentPriorityData = priorityConfigs.map(cfg => {
    const found = data?.priority_distribution?.find(d => d.name.startsWith(cfg.key));
    return {
      key: cfg.key,
      name: cfg.key,
      label: cfg.key,
      value: data ? (found ? (found.value || 0) : 0) : cfg.fallback,
      color: cfg.color
    };
  });

  const totalIncidentsInChart = incidentPriorityData.reduce((acc, c) => acc + (c.value || 0), 0);

  // Incident Ticket Lifecycle Breakdown
  const ticketStats = data?.ticket_overview || {
    total: 216,
    resolved: 49,
    true_positive: 44,
    false_positive: 5,
    investigating: 2,
    new: 165,
    open: 165,
    sla_compliance_pct: 98.0
  };

  const isDark = theme === 'dark';
  const slaPct = ticketStats.sla_compliance_pct !== undefined ? Number(ticketStats.sla_compliance_pct) : 98.0;
  const clampedSlaPct = Math.max(0, Math.min(100, slaPct));
  const strokeDashoffset = (257.61 * (1 - clampedSlaPct / 100)).toFixed(2);
  const gaugeColor = clampedSlaPct >= 90 ? '#10b981' : clampedSlaPct >= 75 ? '#f59e0b' : '#f43f5e';
  const gaugeTextClass = clampedSlaPct >= 90 ? (isDark ? 'fill-emerald-400' : 'fill-emerald-600') : clampedSlaPct >= 75 ? (isDark ? 'fill-amber-400' : 'fill-amber-600') : (isDark ? 'fill-rose-400' : 'fill-rose-600');

  // Suppression & Tuning Breakdown
  const suppressionStats = data?.suppression_overview || {
    pending_proposals: 0,
    total_rules: 3,
    active_rules: 3,
    expired_rules: 0,
    rules: [
      { id: 'SUP-2026-001', name: 'Nessus Primary Vulnerability Scanner', target_rules: '5710, 31101, 100300', status: 'ACTIVE' },
      { id: 'SUP-2026-002', name: 'Routine Non-Critical AppArmor Noise', target_rules: '52002', status: 'ACTIVE' },
      { id: 'SUP-2026-003', name: 'Web Server 400 Bot Burst Aggregation Window', target_rules: '31101, 31533', status: 'ACTIVE' }
    ]
  };

  const feedItems = useMemo(() => {
    const raw = data ? (data.live_feed || []) : defaultLiveFeed;
    return [...raw].map(item => {
      const rawStatus = (item.status || '').toLowerCase();
      const isClose = rawStatus === 'close' || rawStatus === 'closed';

      let deadline = item.deadline_sla || item.deadlineSLA;
      if (!deadline) {
        const created = item.created_at || item.createdAt || item.time_ago || item.timeAgo;
        deadline = computeSlaDeadlineStr(created, item.priority) || created;
      }

      return {
        ...item,
        isClose,
        computedDeadline: deadline
      };
    }).sort((a, b) => {
      // 1. Yang sudah CLOSE langsung turun ke urutan paling bawah
      if (a.isClose !== b.isClose) {
        return a.isClose ? 1 : -1;
      }
      // 2. Yang paling mendekati deadline ada di paling atas (Earliest Deadline First)
      const timeA = new Date(String(a.computedDeadline).replace(' ', 'T')).getTime() || 0;
      const timeB = new Date(String(b.computedDeadline).replace(' ', 'T')).getTime() || 0;
      if (timeA !== timeB) {
        return timeA - timeB;
      }
      // 3. Fallback priority P0 < P1 < P2 < P3 < P4
      const pWeight = { P0: 1, P1: 2, P2: 3, P3: 4, P4: 5 };
      return (pWeight[a.priority] || 99) - (pWeight[b.priority] || 99);
    });
  }, [data?.live_feed]);

  const filterCounts = useMemo(() => {
    const counts = { ALL: feedItems.length, CLOSE: 0, P0: 0, P1: 0, P2: 0, P3: 0, P4: 0 };
    feedItems.forEach(item => {
      if (item.isClose) counts.CLOSE += 1;
      const p = (item.priority || '').toUpperCase();
      if (counts[p] !== undefined) counts[p] += 1;
    });
    return counts;
  }, [feedItems]);

  const filteredFeedItems = useMemo(() => {
    if (feedFilter === 'ALL') return feedItems;
    if (feedFilter === 'CLOSE') {
      return feedItems.filter(item => item.isClose);
    }
    return feedItems.filter(item => (item.priority || '').toUpperCase() === feedFilter);
  }, [feedItems, feedFilter]);

  return (
    <div className="space-y-5 w-full">
      {/* 5 Metric Summary Cards - Ultra Minimalist Clean */}
      <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-5 gap-3.5">
        {/* Card 1: Ingest */}
        <div className={`py-4 px-3.5 border rounded-xl transition-all flex flex-col items-center justify-center text-center ${
          isDark 
            ? 'bg-[#0a0e1a] border-slate-800 hover:border-slate-700' 
            : 'bg-white border-slate-200 hover:border-slate-300 shadow-xs'
        }`}>
          <span className={`text-xs font-bold tracking-wider uppercase mb-1 ${
            isDark ? 'text-slate-400' : 'text-slate-900'
          }`}>INGEST</span>
          <div className={`text-2xl font-bold font-mono tracking-tight ${
            isDark ? 'text-white' : 'text-slate-900'
          }`}>{totalRaw}</div>
        </div>

        {/* Card 2: Aggregate */}
        <div className={`py-4 px-3.5 border rounded-xl transition-all flex flex-col items-center justify-center text-center ${
          isDark 
            ? 'bg-[#0a0e1a] border-slate-800 hover:border-slate-700' 
            : 'bg-white border-slate-200 hover:border-slate-300 shadow-xs'
        }`}>
          <span className={`text-xs font-bold tracking-wider uppercase mb-1 ${
            isDark ? 'text-slate-400' : 'text-slate-900'
          }`}>AGGREGATE</span>
          <div className={`text-2xl font-bold font-mono tracking-tight ${
            isDark ? 'text-white' : 'text-slate-900'
          }`}>{totalAggs}</div>
        </div>

        {/* Card 3: Ticket */}
        <div className={`py-4 px-3.5 border rounded-xl transition-all flex flex-col items-center justify-center text-center ${
          isDark 
            ? 'bg-[#0a0e1a] border-slate-800 hover:border-slate-700' 
            : 'bg-white border-slate-200 hover:border-slate-300 shadow-xs'
        }`}>
          <span className={`text-xs font-bold tracking-wider uppercase mb-1 ${
            isDark ? 'text-slate-400' : 'text-slate-900'
          }`}>TICKET</span>
          <div className={`text-2xl font-bold font-mono tracking-tight ${
            isDark ? 'text-white' : 'text-slate-900'
          }`}>{totalTickets}</div>
        </div>

        {/* Card 4: Threat */}
        <div className={`py-4 px-3.5 border rounded-xl transition-all flex flex-col items-center justify-center text-center ${
          isDark 
            ? 'bg-[#0a0e1a] border-slate-800 hover:border-slate-700' 
            : 'bg-white border-slate-200 hover:border-slate-300 shadow-xs'
        }`}>
          <span className={`text-xs font-bold tracking-wider uppercase mb-1 ${
            isDark ? 'text-slate-400' : 'text-slate-900'
          }`}>THREAT</span>
          <div className={`text-2xl font-bold font-mono tracking-tight ${
            isDark ? 'text-white' : 'text-slate-900'
          }`}>{totalThreats}</div>
        </div>

        {/* Card 5: Groundtruth */}
        <div className={`py-4 px-3.5 border rounded-xl transition-all flex flex-col items-center justify-center text-center ${
          isDark 
            ? 'bg-[#0a0e1a] border-slate-800 hover:border-slate-700' 
            : 'bg-white border-slate-200 hover:border-slate-300 shadow-xs'
        }`}>
          <span className={`text-xs font-bold tracking-wider uppercase mb-1 ${
            isDark ? 'text-slate-400' : 'text-slate-900'
          }`}>GROUNDTRUTH</span>
          <div className={`text-2xl font-bold font-mono tracking-tight ${
            isDark ? 'text-white' : 'text-slate-900'
          }`}>{totalGroundtruth}</div>
        </div>
      </div>

      {/* Main Visualizations Row */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-4">
        {/* Left: Volume Trend with 5 Stages */}
        <div className={`lg:col-span-8 p-5 border rounded-xl flex flex-col justify-between transition-colors ${
          isDark ? 'bg-[#0a0e1a] border-slate-800' : 'bg-white border-slate-200 shadow-xs'
        }`}>
          <div>
            <div className="flex flex-wrap items-center justify-between gap-2 mb-2">
              <h3 className={`text-xs font-semibold uppercase tracking-wider ${
                isDark ? 'text-slate-100' : 'text-slate-800'
              }`}>Alert Volume</h3>
              <div className="flex flex-wrap items-center gap-3 text-xs font-mono">
                <span className={`flex items-center gap-1.5 ${isDark ? 'text-slate-300' : 'text-slate-600'}`}>
                  <span className="w-2.5 h-1 rounded-full bg-[#38bdf8]"></span> Ingest
                </span>
                <span className={`flex items-center gap-1.5 ${isDark ? 'text-slate-300' : 'text-slate-600'}`}>
                  <span className="w-2.5 h-1 rounded-full bg-[#818cf8]"></span> Aggregate
                </span>
                <span className={`flex items-center gap-1.5 ${isDark ? 'text-slate-300' : 'text-slate-600'}`}>
                  <span className="w-2.5 h-1 rounded-full bg-[#f59e0b]"></span> Ticket
                </span>
                <span className={`flex items-center gap-1.5 ${isDark ? 'text-slate-300' : 'text-slate-600'}`}>
                  <span className="w-2.5 h-1 rounded-full bg-[#f43f5e]"></span> Threat
                </span>
                <span className={`flex items-center gap-1.5 ${isDark ? 'text-slate-300' : 'text-slate-600'}`}>
                  <span className="w-2.5 h-1 rounded-full bg-[#10b981]"></span> Groundtruth
                </span>
              </div>
            </div>
          </div>

          <div className="h-80 w-full pt-2">
            <ResponsiveContainer width="100%" height="100%">
              <AreaChart data={reductionChartData} margin={{ top: 10, right: 10, left: -10, bottom: 0 }}>
                <defs>
                  <linearGradient id="ingestGrad" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#38bdf8" stopOpacity={0.2}/>
                    <stop offset="95%" stopColor="#38bdf8" stopOpacity={0.0}/>
                  </linearGradient>
                </defs>
                <CartesianGrid stroke={isDark ? "#1e293b" : "#f1f5f9"} strokeDasharray="3 3" vertical={false} opacity={0.6} />
                <XAxis 
                  dataKey="day" 
                  ticks={xAxisTicks}
                  interval={0}
                  stroke={isDark ? "#94a3b8" : "#64748b"} 
                  fontSize={11} 
                  tickLine={false} 
                />
                <YAxis stroke={isDark ? "#94a3b8" : "#64748b"} fontSize={11} tickLine={false} tickFormatter={(val) => `${Math.round(val / 1000)}k`} />
                <Tooltip content={<CustomAreaTooltip isDark={isDark} />} />
                <Area type="monotone" dataKey="ingest" name="Ingest" stroke="#38bdf8" strokeWidth={2} fillOpacity={1} fill="url(#ingestGrad)" dot={false} isAnimationActive={false} />
                <Area type="monotone" dataKey="aggregate" name="Aggregate" stroke="#818cf8" strokeWidth={2} fillOpacity={0} dot={false} isAnimationActive={false} />
                <Area type="monotone" dataKey="ticket" name="Ticket" stroke="#f59e0b" strokeWidth={2} fillOpacity={0} dot={false} isAnimationActive={false} />
                <Area type="monotone" dataKey="threat" name="Threat" stroke="#f43f5e" strokeWidth={2} fillOpacity={0} dot={false} isAnimationActive={false} />
                <Area type="monotone" dataKey="groundtruth" name="Groundtruth" stroke="#10b981" strokeWidth={2} fillOpacity={0} dot={false} isAnimationActive={false} />
              </AreaChart>
            </ResponsiveContainer>
          </div>
        </div>

        {/* Right: Risk Severity Donut (Corrected to show actual incident distribution P0-P3) */}
        <div className={`lg:col-span-4 p-5 border rounded-xl flex flex-col justify-between transition-colors ${
          isDark ? 'bg-[#0a0e1a] border-slate-800' : 'bg-white border-slate-200 shadow-xs'
        }`}>
          <div>
            <div className="mb-3">
              <h3 className={`text-xs font-semibold uppercase tracking-wider ${
                isDark ? 'text-slate-100' : 'text-slate-800'
              }`}>Priority Distribution</h3>
            </div>

            <div className="h-48 w-full flex items-center justify-center my-1 relative">
              {/* Donut Center Metrics */}
              <div className="absolute inset-0 flex flex-col items-center justify-center pointer-events-none">
                <span className={`text-2xl font-extrabold font-mono tracking-tight ${
                  isDark ? 'text-white' : 'text-slate-900'
                }`}>
                  {totalIncidentsInChart.toLocaleString()}
                </span>
                <span className={`text-[10px] font-mono uppercase tracking-wider ${
                  isDark ? 'text-slate-400' : 'text-slate-500'
                }`}>
                  TICKET
                </span>
              </div>

              <ResponsiveContainer width="100%" height="100%">
                <PieChart>
                  <Pie
                    data={incidentPriorityData}
                    cx="50%"
                    cy="50%"
                    innerRadius={55}
                    outerRadius={75}
                    paddingAngle={3}
                    dataKey="value"
                    stroke="none"
                    strokeWidth={0}
                    isAnimationActive={false}
                  >
                    {incidentPriorityData.map((entry, index) => (
                      <Cell key={`cell-${index}`} fill={entry.color} stroke="none" />
                    ))}
                  </Pie>
                  <Tooltip content={<CustomDonutTooltip isDark={isDark} />} />
                </PieChart>
              </ResponsiveContainer>
            </div>
          </div>

          <div className="space-y-2.5 font-mono text-xs pt-1">
            {incidentPriorityData.map((p) => {
              const pct = totalIncidentsInChart > 0 ? (p.value / totalIncidentsInChart) * 100 : 0;
              return (
                <div key={p.key} className="flex items-center justify-between gap-3">
                  {/* Left: Dot & P0/P1/P2/P3/P4 */}
                  <div className="flex items-center gap-2 shrink-0 w-9">
                    <span 
                      className="w-2 h-2 rounded-full shrink-0" 
                      style={{ backgroundColor: p.color }}
                    />
                    <span className={`text-xs font-mono font-semibold ${
                      isDark ? 'text-slate-300' : 'text-slate-700'
                    }`}>
                      {p.key}
                    </span>
                  </div>

                  {/* Middle: Color Progress Bar */}
                  <div className={`flex-1 h-1.5 rounded-full overflow-hidden ${
                    isDark ? 'bg-[#1a2333]' : 'bg-slate-200'
                  }`}>
                    <div 
                      className="h-full rounded-full transition-all duration-300"
                      style={{ 
                        width: `${pct}%`, 
                        backgroundColor: p.color 
                      }}
                    />
                  </div>

                  {/* Right: Value Number */}
                  <span 
                    className="font-mono font-bold text-xs text-right w-14 shrink-0"
                    style={{ color: p.color }}
                  >
                    {p.value.toLocaleString()}
                  </span>
                </div>
              );
            })}
          </div>
        </div>
      </div>

      {/* 3-COLUMN EXECUTIVE OPERATIONAL PANELS: MENYAMPING (SIDE-BY-SIDE) FULLY COHESIVE */}
      <div className="grid grid-cols-3 gap-4 w-full min-w-0">
        {/* Panel 1: SIKLUS HIDUP TIKET */}
        <div className={`p-5 rounded-xl border flex flex-col justify-between transition-colors ${
          isDark 
            ? 'bg-[#0a0e1a] border-slate-800 text-slate-100' 
            : 'bg-white border-slate-200 shadow-xs text-slate-800'
        }`}>
          <div>
            {/* Clean Header */}
            <div className="mb-3.5 flex items-center justify-between">
              <h3 className={`text-xs font-semibold uppercase tracking-wider ${
                isDark ? 'text-slate-100' : 'text-slate-800'
              }`}>
                TICKET LIFECYCLE
              </h3>
            </div>

            {/* Centered Semi-Circular SLA Met Gauge - Proportionally Scaled */}
            <div className="w-full flex items-center justify-center py-2 relative">
              <svg viewBox="0 8 210 110" className="w-full max-w-[300px] h-auto overflow-visible">
                {/* Background Track */}
                <path
                  d="M 23 105 A 82 82 0 0 1 187 105"
                  fill="none"
                  stroke={isDark ? '#1e293b' : '#e2e8f0'}
                  strokeWidth="13"
                  strokeLinecap="round"
                />
                {/* Dynamic Active Gauge Fill */}
                <path
                  d="M 23 105 A 82 82 0 0 1 187 105"
                  fill="none"
                  stroke={gaugeColor}
                  strokeWidth="13"
                  strokeDasharray="257.61"
                  strokeDashoffset={strokeDashoffset}
                  strokeLinecap="round"
                  className="transition-all duration-700"
                />
                {/* Center Percentage Text */}
                <text
                  x="105"
                  y="75"
                  textAnchor="middle"
                  className="font-mono font-extrabold text-[28px] tracking-tight"
                  fill={isDark ? '#f8fafc' : '#0f172a'}
                >
                  {clampedSlaPct.toFixed(1)}%
                </text>
                <text
                  x="105"
                  y="94"
                  textAnchor="middle"
                  className={`text-[10px] font-bold tracking-widest uppercase font-mono ${gaugeTextClass}`}
                >
                  SLA COMPLIANCE
                </text>
              </svg>
            </div>

            {/* Horizontal Progress Rows - Exact Twin Structure to Priority Distribution */}
            <div className="space-y-3 font-mono text-xs pt-1.5">
              {[
                {
                  label: 'Open',
                  color: '#f43f5e',
                  value: ticketStats.open !== undefined ? ticketStats.open : (ticketStats.new ?? 0),
                  pct: ticketStats.total > 0 ? (((ticketStats.open !== undefined ? ticketStats.open : (ticketStats.new ?? 0)) / ticketStats.total) * 100) : 0,
                },
                {
                  label: 'Investigate',
                  color: '#f59e0b',
                  value: ticketStats.investigating ?? 0,
                  pct: ticketStats.total > 0 ? (((ticketStats.investigating ?? 0) / ticketStats.total) * 100) : 0,
                },
                {
                  label: 'Close',
                  color: '#10b981',
                  value: ticketStats.resolved ?? (ticketStats.closed ?? 0),
                  pct: ticketStats.total > 0 ? (((ticketStats.resolved ?? (ticketStats.closed ?? 0)) / ticketStats.total) * 100) : 0,
                },
              ].map((row) => (
                <div key={row.label} className="flex items-center justify-between gap-3">
                  {/* Left: Dot & Label */}
                  <div className="flex items-center gap-2 shrink-0 w-32">
                    <span 
                      className="w-2 h-2 rounded-full shrink-0" 
                      style={{ backgroundColor: row.color }}
                    />
                    <span className={`text-xs font-mono font-semibold ${
                      isDark ? 'text-slate-300' : 'text-slate-700'
                    }`}>
                      {row.label}
                    </span>
                  </div>

                  {/* Middle: Color Progress Bar */}
                  <div className={`flex-1 h-1.5 rounded-full overflow-hidden ${
                    isDark ? 'bg-[#1a2333]' : 'bg-slate-200'
                  }`}>
                    <div 
                      className="h-full rounded-full transition-all duration-300"
                      style={{ 
                        width: `${Math.max(0, Math.min(100, row.pct))}%`, 
                        backgroundColor: row.color 
                      }}
                    />
                  </div>

                  {/* Right: Value Number */}
                  <span 
                    className="font-mono font-bold text-xs text-right w-14 shrink-0"
                    style={{ color: row.color }}
                  >
                    {row.value.toLocaleString()}
                  </span>
                </div>
              ))}
            </div>
          </div>

          {/* Footer Stats Structured in 2 Matching Micro-Cards */}
          <div className={`grid grid-cols-2 gap-2 pt-3 border-t mt-3 font-mono text-center ${
            isDark ? 'border-slate-800/80' : 'border-slate-100'
          }`}>
            <div className={`p-2 rounded-lg transition-colors ${
              isDark 
                ? 'bg-emerald-500/20' 
                : 'bg-emerald-500/15'
            }`}>
              <div className={`text-[10px] uppercase font-semibold ${
                isDark ? 'text-emerald-300' : 'text-emerald-800'
              }`}>
                True Positive
              </div>
              <div className={`text-sm font-bold ${
                isDark ? 'text-emerald-400' : 'text-emerald-600'
              }`}>
                {ticketStats.true_positive ?? 0}
              </div>
            </div>

            <div className={`p-2 rounded-lg transition-colors ${
              isDark 
                ? 'bg-rose-500/20' 
                : 'bg-rose-500/15'
            }`}>
              <div className={`text-[10px] uppercase font-semibold ${
                isDark ? 'text-rose-300' : 'text-rose-800'
              }`}>
                False Positive
              </div>
              <div className={`text-sm font-bold ${
                isDark ? 'text-rose-400' : 'text-rose-600'
              }`}>
                {ticketStats.false_positive ?? 0}
              </div>
            </div>
          </div>
        </div>

        {/* Panel 2: LIVE TICKET */}
        <div className={`p-5 rounded-xl border flex flex-col justify-between transition-colors ${
          isDark 
            ? 'bg-[#0a0e1a] border-slate-800 text-slate-100' 
            : 'bg-white border-slate-200 shadow-xs text-slate-800'
        }`}>
          <div>
            {/* Centered Header: LIVE TICKET without dot */}
            <div className="flex items-center justify-center mb-2.5">
              <h3 className={`text-xs font-bold uppercase tracking-wider ${
                isDark ? 'text-emerald-400' : 'text-emerald-600'
              }`}>
                LIVE TICKET
              </h3>
            </div>

            {/* Filter Bar: Referenced Minimalist Text Tabs with Pill Indicator */}
            <div className={`flex items-center justify-between pb-1.5 mb-2.5 border-b transition-colors ${
              isDark ? 'border-slate-800/80' : 'border-slate-100'
            }`}>
              {[
                { id: 'ALL', label: 'All' },
                { id: 'P0', label: 'P0' },
                { id: 'P1', label: 'P1' },
                { id: 'P2', label: 'P2' },
                { id: 'P3', label: 'P3' },
                { id: 'P4', label: 'P4' },
                { id: 'CLOSE', label: 'Close' },
              ].map(tab => {
                const isActive = feedFilter === tab.id;
                const count = filterCounts[tab.id] ?? 0;
                return (
                  <button
                    key={tab.id}
                    onClick={() => setFeedFilter(tab.id)}
                    title={`Filter ${tab.label} (${count} tiket)`}
                    className="relative flex flex-col items-center justify-center flex-1 py-1 cursor-pointer transition-colors group select-none"
                  >
                    <span className={`text-xs transition-colors ${
                      isActive 
                        ? (isDark ? 'text-white font-bold' : 'text-slate-900 font-bold')
                        : (isDark ? 'text-slate-400 hover:text-slate-200 font-medium' : 'text-slate-400 hover:text-slate-700 font-medium')
                    }`}>
                      {tab.label}
                    </span>
                    {isActive ? (
                      <span className={`w-5 h-1 rounded-full mt-1 transition-all ${
                        isDark ? 'bg-slate-200' : 'bg-slate-800'
                      }`}></span>
                    ) : (
                      <span className="w-5 h-1 rounded-full mt-1 bg-transparent"></span>
                    )}
                  </button>
                );
              })}
            </div>

            {/* Incidents Feed List with Horizontal Line Dividers (Borderless) */}
            <div className={`divide-y overflow-y-auto max-h-[235px] pr-1.5 custom-feed-scrollbar ${
              isDark ? 'divide-slate-800/80' : 'divide-slate-100'
            }`}>
              {filteredFeedItems.length === 0 ? (
                <div className={`py-12 text-center text-xs font-mono ${
                  isDark ? 'text-slate-500' : 'text-slate-400'
                }`}>
                  Tidak ada tiket {feedFilter}
                </div>
              ) : (
                filteredFeedItems.map((item, idx) => {
                  const rawStatus = item.status || '';
                  const isInv = rawStatus.toLowerCase() === 'investigasi' || rawStatus.toLowerCase() === 'investigating' || rawStatus.toLowerCase() === 'investigate';
                  const isOpen = rawStatus.toLowerCase() === 'terbuka' || rawStatus.toLowerCase() === 'open';
                  const isClose = rawStatus.toLowerCase() === 'close' || rawStatus.toLowerCase() === 'closed';
                  const displayStatus = isInv ? 'Investigate' : isOpen ? 'Open' : isClose ? 'Close' : rawStatus;

                  // Format ticket timestamp to exact DATE/TIME format
                  const rawTime = item.created_at || item.createdAt || item.time_ago || item.timeAgo || '';
                  const relativeMap = {
                    '2m lalu': '2026-07-31 10:22:15',
                    '2m ago': '2026-07-31 10:22:15',
                    '18m lalu': '2026-07-31 10:06:40',
                    '18m ago': '2026-07-31 10:06:40',
                    '41m lalu': '2026-07-31 09:43:12',
                    '41m ago': '2026-07-31 09:43:12',
                    '1j lalu': '2026-07-31 09:24:05',
                    '1h ago': '2026-07-31 09:24:05',
                    '2j lalu': '2026-07-31 08:24:00',
                    '2h ago': '2026-07-31 08:24:00'
                  };
                  let formattedTime = relativeMap[rawTime.toLowerCase()] || rawTime;
                  if (!/^\d{4}-\d{2}-\d{2}\s\d{2}:\d{2}(:\d{2})?$/.test(formattedTime) && formattedTime && !isNaN(Date.parse(formattedTime))) {
                    const d = new Date(formattedTime);
                    const pad = (n) => String(n).padStart(2, '0');
                    formattedTime = `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())} ${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}`;
                  }

                  return (
                    <div 
                      key={idx} 
                      className={`py-2.5 transition-colors ${
                        onNavigate ? 'cursor-pointer hover:opacity-80' : ''
                      }`}
                      onClick={() => onNavigate && onNavigate('triage')}
                    >
                      {/* Top Line: Priority Badge + Incident ID & DATE/TIME */}
                      <div className="flex items-center justify-between mb-1.5">
                        <div className="flex items-center gap-2">
                          <span className={`text-[11px] font-mono font-bold tracking-wider ${
                            item.priority === 'P0' 
                              ? (isDark ? 'text-rose-400' : 'text-rose-600')
                              : item.priority === 'P1'
                              ? (isDark ? 'text-orange-400' : 'text-orange-600')
                              : item.priority === 'P2'
                              ? (isDark ? 'text-amber-400' : 'text-amber-600')
                              : item.priority === 'P3'
                              ? (isDark ? 'text-emerald-400' : 'text-emerald-600')
                              : item.priority === 'P4'
                              ? (isDark ? 'text-sky-400' : 'text-sky-600')
                              : (isDark ? 'text-slate-400' : 'text-slate-600')
                          }`}>
                            {item.priority}
                          </span>
                          <span className={`text-[11px] font-mono font-bold ${isDark ? 'text-slate-300' : 'text-slate-700'}`}>
                            {item.incident_id || item.id}
                          </span>
                        </div>
                        <span className={`text-[10px] font-mono ${isDark ? 'text-slate-500' : 'text-slate-400'}`}>
                          {item.computedDeadline || item.deadline_sla || formattedTime}
                        </span>
                      </div>

                      {/* Bottom Line: Incident Title (Left) & Status (Right) */}
                      <div className="flex items-center justify-between gap-2">
                        <div className={`text-xs font-semibold leading-snug truncate ${
                          isDark ? 'text-slate-200' : 'text-slate-800'
                        }`}>
                          {item.title}
                        </div>
                        <span className={`text-[10px] font-mono font-semibold shrink-0 ${
                          isInv
                            ? (isDark ? 'text-cyan-400' : 'text-blue-600')
                            : isOpen
                            ? (isDark ? 'text-rose-400' : 'text-rose-600')
                            : (isDark ? 'text-emerald-400' : 'text-emerald-600')
                        }`}>
                          {displayStatus}
                        </span>
                      </div>
                    </div>
                  );
                })
              )}
            </div>
          </div>
        </div>

        {/* Panel 3: TATA KELOLA SUPRESI (Twin Structure to Priority Distribution) */}
        <div className={`p-5 rounded-xl border flex flex-col justify-between transition-colors ${
          isDark 
            ? 'bg-[#0a0e1a] border-slate-800 text-slate-100' 
            : 'bg-white border-slate-200 shadow-xs text-slate-800'
        }`}>
          {/* Clean Header matching Alert Volume & Priority Distribution */}
          <div>
            <h3 className={`text-xs font-semibold uppercase tracking-wider ${
              isDark ? 'text-slate-100' : 'text-slate-800'
            }`}>
              SUPPRESSION GOVERNANCE
            </h3>
          </div>

          {/* Full-Height Vertical Column Chart: 4 Governance Metrics (Clean & Borderless) */}
          <div className="flex-1 flex flex-col justify-end pt-2 pb-1">
            <div className="flex items-end justify-around gap-2 h-72 pb-1">
              {(() => {
                const govCols = [
                  {
                    key: 'total',
                    label: 'Total Rules',
                    value: suppressionStats.total_rules ?? 39,
                    textColor: isDark ? 'text-sky-400' : 'text-sky-600',
                    barBg: isDark ? 'bg-gradient-to-t from-sky-600 to-sky-400 shadow-md shadow-sky-500/20' : 'bg-gradient-to-t from-sky-500 to-sky-400 shadow-sm',
                  },
                  {
                    key: 'active',
                    label: 'Active',
                    value: suppressionStats.active_rules ?? 39,
                    textColor: isDark ? 'text-emerald-400' : 'text-emerald-600',
                    barBg: isDark ? 'bg-gradient-to-t from-emerald-600 to-emerald-400 shadow-md shadow-emerald-500/20' : 'bg-gradient-to-t from-emerald-500 to-emerald-400 shadow-sm',
                  },
                  {
                    key: 'pending',
                    label: 'FP Proposals',
                    value: suppressionStats.pending_proposals ?? 0,
                    textColor: isDark ? 'text-amber-400' : 'text-amber-600',
                    barBg: isDark ? 'bg-gradient-to-t from-amber-600 to-amber-400' : 'bg-gradient-to-t from-amber-500 to-amber-400',
                  },
                  {
                    key: 'expired',
                    label: 'Expired',
                    value: suppressionStats.expired_rules ?? 0,
                    textColor: isDark ? 'text-rose-400' : 'text-rose-600',
                    barBg: isDark ? 'bg-gradient-to-t from-rose-600 to-rose-400 shadow-md shadow-rose-500/20' : 'bg-gradient-to-t from-rose-500 to-rose-400 shadow-sm',
                    emptyBg: isDark ? 'bg-rose-500/50' : 'bg-rose-400',
                  }
                ];

                const maxMetricVal = Math.max(...govCols.map(c => Number(c.value) || 0), 1);
                // Headroom ceiling (15% higher than max metric) so the tallest bar sits nicely below top label
                const scaleCeiling = Math.ceil(maxMetricVal * 1.15);

                return govCols.map(col => {
                  const heightPct = col.value > 0 
                    ? Math.max(8, Math.min(92, Math.round((col.value / scaleCeiling) * 100))) 
                    : 0;

                return (
                  <div key={col.key} className="flex-1 flex flex-col items-center justify-end h-full group">
                    {/* Value Number */}
                    <span className={`font-mono font-bold text-sm mb-2 transition-transform group-hover:scale-110 ${col.textColor}`}>
                      {col.value}
                    </span>

                    {/* Pure Borderless Column Bar */}
                    <div className="w-12 h-60 flex items-end justify-center">
                      {col.value > 0 ? (
                        <div 
                          className={`w-full rounded-t-lg ${col.barBg} transition-all duration-700`}
                          style={{ height: `${heightPct}%` }}
                        />
                      ) : (
                        <div className={`w-10 h-1.5 rounded-full ${
                          col.emptyBg || (isDark ? 'bg-slate-700/50' : 'bg-slate-300')
                        }`} />
                      )}
                    </div>

                    {/* Column Label */}
                    <span className={`text-[10px] font-mono font-semibold mt-3 text-center whitespace-nowrap tracking-tight h-6 flex items-center justify-center ${
                      isDark ? 'text-slate-400' : 'text-slate-600'
                    }`} title={col.label}>
                      {col.label}
                    </span>
                  </div>
                );
              });
            })()}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
