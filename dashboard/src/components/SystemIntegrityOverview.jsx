import React, { useState, useMemo } from 'react';
import { ResponsiveContainer, PieChart, Pie, Cell, Tooltip } from 'recharts';
import {
  Search, Shield, AlertTriangle, CheckCircle2, XCircle, 
  Terminal, ExternalLink, Flag, Filter, Building2, Server,
  LayoutGrid, Flame, CheckCircle, Layers, FileCode, Users, WifiOff, Activity, X
} from 'lucide-react';

const PALETTE = ['#f43f5e', '#0284c7', '#f59e0b', '#8b5cf6', '#10b981', '#64748b'];

// Master multi-tenant datasets for System & Host Integrity
const TENANT_SYSTEM_DATASETS = {
  PraditaUniversity: {
    tenantId: 'PraditaUniversity',
    name: 'Pradita University',
    hostsCount: 12,
    fimTotal: 1420,
    privTotal: 4890,
    fileTotal: 34,
    healthTotal: 12,
    healthScore: '83.3%',
    fimData: [
      { name: '/etc/passwd & /shadow', value: 812, pct: '57.2', color: '#f43f5e' },
      { name: '/usr/bin/* Binaries', value: 410, pct: '28.9', color: '#0284c7' },
      { name: '/etc/ssh/sshd_config', value: 198, pct: '13.9', color: '#f59e0b' }
    ],
    privData: [
      { name: 'Unauthorized Sudo (Rule 5402)', value: 2940, pct: '60.1', color: '#f59e0b' },
      { name: 'Failed Root Authentication', value: 1450, pct: '29.7', color: '#f43f5e' },
      { name: 'New User Added (/etc/passwd)', value: 500, pct: '10.2', color: '#8b5cf6' }
    ],
    fileData: [
      { name: 'New Script in /var/www', value: 24, pct: '70.6', color: '#f43f5e' },
      { name: 'Hidden Dotfile (.sh)', value: 8, pct: '23.5', color: '#f59e0b' },
      { name: 'Promiscuous Interface', value: 2, pct: '5.9', color: '#8b5cf6' }
    ],
    healthData: [
      { name: 'Active / Connected', value: 10, pct: '83.3', color: '#10b981' },
      { name: 'Agent Disconnected (501)', value: 2, pct: '16.7', color: '#f43f5e' }
    ]
  },
  InstikiBali: {
    tenantId: 'InstikiBali',
    name: 'Instiki Bali',
    hostsCount: 8,
    fimTotal: 620,
    privTotal: 2140,
    fileTotal: 18,
    healthTotal: 8,
    healthScore: '87.5%',
    fimData: [
      { name: '/usr/bin/* Binaries', value: 280, pct: '45.2', color: '#0284c7' },
      { name: '/etc/shadow Config', value: 215, pct: '34.7', color: '#f43f5e' },
      { name: '/etc/hosts File', value: 125, pct: '20.1', color: '#f59e0b' }
    ],
    privData: [
      { name: 'Unauthorized Sudo (Rule 5402)', value: 1110, pct: '51.9', color: '#f59e0b' },
      { name: 'Failed Root Authentication', value: 1030, pct: '48.1', color: '#f43f5e' }
    ],
    fileData: [
      { name: 'Promiscuous Port (Rootcheck)', value: 11, pct: '61.1', color: '#f43f5e' },
      { name: 'New Script in /tmp', value: 7, pct: '38.9', color: '#f59e0b' }
    ],
    healthData: [
      { name: 'Active / Connected', value: 7, pct: '87.5', color: '#10b981' },
      { name: 'Agent Disconnected (501)', value: 1, pct: '12.5', color: '#f43f5e' }
    ]
  },
  Petra: {
    tenantId: 'Petra',
    name: 'Petra Christian University',
    hostsCount: 10,
    fimTotal: 890,
    privTotal: 1780,
    fileTotal: 12,
    healthTotal: 10,
    healthScore: '100%',
    fimData: [
      { name: '/etc/nginx/conf.d', value: 490, pct: '55.1', color: '#0284c7' },
      { name: '/etc/passwd & /shadow', value: 265, pct: '29.8', color: '#f43f5e' },
      { name: '/bin/bash Integrity', value: 135, pct: '15.1', color: '#f59e0b' }
    ],
    privData: [
      { name: 'Failed Root Authentication', value: 1150, pct: '64.6', color: '#f43f5e' },
      { name: 'Unauthorized Sudo (Rule 5402)', value: 630, pct: '35.4', color: '#f59e0b' }
    ],
    fileData: [
      { name: 'New Script in /var/www', value: 10, pct: '83.3', color: '#f43f5e' },
      { name: 'Hidden Dotfile (.sh)', value: 2, pct: '16.7', color: '#f59e0b' }
    ],
    healthData: [
      { name: 'Active / Connected', value: 10, pct: '100.0', color: '#10b981' }
    ]
  },
  wicida: {
    tenantId: 'wicida',
    name: 'STMIK Widya Cipta Dharma (Wicida)',
    hostsCount: 6,
    fimTotal: 410,
    privTotal: 980,
    fileTotal: 9,
    healthTotal: 6,
    healthScore: '83.3%',
    fimData: [
      { name: '/etc/bind/named.conf', value: 250, pct: '61.0', color: '#0284c7' },
      { name: '/etc/shadow Config', value: 160, pct: '39.0', color: '#f43f5e' }
    ],
    privData: [
      { name: 'Unauthorized Sudo (Rule 5402)', value: 730, pct: '74.5', color: '#f59e0b' },
      { name: 'Failed Root Authentication', value: 250, pct: '25.5', color: '#f43f5e' }
    ],
    fileData: [
      { name: 'Suspicious Script in /tmp', value: 9, pct: '100.0', color: '#f43f5e' }
    ],
    healthData: [
      { name: 'Active / Connected', value: 5, pct: '83.3', color: '#10b981' },
      { name: 'Agent Disconnected (501)', value: 1, pct: '16.7', color: '#f43f5e' }
    ]
  },
  TenantA: {
    tenantId: 'TenantA',
    name: 'Enterprise Tenant A',
    hostsCount: 14,
    fimTotal: 2340,
    privTotal: 6120,
    fileTotal: 45,
    healthTotal: 14,
    healthScore: '92.9%',
    fimData: [
      { name: '/usr/bin/* Binaries', value: 940, pct: '40.2', color: '#0284c7' },
      { name: '/etc/sudoers File', value: 820, pct: '35.0', color: '#f43f5e' },
      { name: '/etc/passwd & /shadow', value: 580, pct: '24.8', color: '#f59e0b' }
    ],
    privData: [
      { name: 'Unauthorized Sudo (Rule 5402)', value: 3370, pct: '55.1', color: '#f59e0b' },
      { name: 'Failed Root Authentication', value: 1830, pct: '29.9', color: '#f43f5e' },
      { name: 'New User Added (/etc/passwd)', value: 920, pct: '15.0', color: '#8b5cf6' }
    ],
    fileData: [
      { name: 'New Script in /var/www', value: 29, pct: '64.4', color: '#f43f5e' },
      { name: 'Hidden Dotfile (.sh)', value: 16, pct: '35.6', color: '#f59e0b' }
    ],
    healthData: [
      { name: 'Active / Connected', value: 13, pct: '92.9', color: '#10b981' },
      { name: 'Agent Disconnected (501)', value: 1, pct: '7.1', color: '#f43f5e' }
    ]
  },
  sgu: {
    tenantId: 'sgu',
    name: 'Swiss German University (SGU)',
    hostsCount: 4,
    fimTotal: 190,
    privTotal: 420,
    fileTotal: 4,
    healthTotal: 4,
    healthScore: '100%',
    fimData: [
      { name: '/etc/ssh/sshd_config', value: 135, pct: '71.1', color: '#f59e0b' },
      { name: '/etc/passwd File', value: 55, pct: '28.9', color: '#f43f5e' }
    ],
    privData: [
      { name: 'Failed Root Authentication', value: 340, pct: '81.0', color: '#f43f5e' },
      { name: 'Unauthorized Sudo (Rule 5402)', value: 80, pct: '19.0', color: '#f59e0b' }
    ],
    fileData: [
      { name: 'Hidden Dotfile (.sh)', value: 4, pct: '100.0', color: '#f59e0b' }
    ],
    healthData: [
      { name: 'Active / Connected', value: 4, pct: '100.0', color: '#10b981' }
    ]
  }
};

// Global aggregate dataset across all tenants for System & Host Integrity
const GLOBAL_SYSTEM_DATA = {
  tenantId: 'ALL',
  name: 'Seluruh Tenant (All Multi-Tenants)',
  hostsCount: 54,
  fimTotal: 5870,
  privTotal: 16330,
  fileTotal: 122,
  healthTotal: 54,
  healthScore: '90.7%',
  fimData: [
    { name: '/etc/passwd & /shadow', value: 2420, pct: '41.2', color: '#f43f5e' },
    { name: '/usr/bin/* Binaries', value: 1850, pct: '31.5', color: '#0284c7' },
    { name: '/etc/ssh/sshd_config', value: 920, pct: '15.7', color: '#f59e0b' },
    { name: '/etc/nginx/conf.d', value: 680, pct: '11.6', color: '#8b5cf6' }
  ],
  privData: [
    { name: 'Unauthorized Sudo (Rule 5402)', value: 9520, pct: '58.3', color: '#f59e0b' },
    { name: 'Failed Root Authentication', value: 5210, pct: '31.9', color: '#f43f5e' },
    { name: 'New User Added (/etc/passwd)', value: 1600, pct: '9.8', color: '#8b5cf6' }
  ],
  fileData: [
    { name: 'New Script in /var/www', value: 78, pct: '63.9', color: '#f43f5e' },
    { name: 'Hidden Dotfile (.sh)', value: 31, pct: '25.4', color: '#f59e0b' },
    { name: 'Promiscuous Port / Interface', value: 13, pct: '10.7', color: '#8b5cf6' }
  ],
  healthData: [
    { name: 'Active / Connected', value: 49, pct: '90.7', color: '#10b981' },
    { name: 'Agent Disconnected (501)', value: 5, pct: '9.3', color: '#f43f5e' }
  ]
};

// Realistic mock audit log samples
const SYSTEM_AUDIT_LOGS = [
  {
    id: 'SYS-2026-8912',
    timestamp: '13:42:10',
    type: 'FIM_MOD',
    typeLabel: 'FIM Checksum',
    rule_id: 550,
    target: '015 (core-pradita)',
    tenant: 'PraditaUniversity',
    affected_item: '/etc/shadow (Integrity Checksum Mismatch)',
    user: 'root',
    severity: 'CRITICAL',
    action: 'Verify diff shadow & investigate audit trail',
    prev_hash: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
    curr_hash: '8f434346648f6b96df89dda901c5176b10a6d83961dd3c1ac88b59b2dc327aa4',
    size_diff: '+48 bytes'
  },
  {
    id: 'SYS-2026-8905',
    timestamp: '13:40:05',
    type: 'BACKDOOR',
    typeLabel: 'Web Shell',
    rule_id: 550,
    target: '015 (core-pradita)',
    tenant: 'PraditaUniversity',
    affected_item: '/var/www/uploads/c99.php (Suspicious Web Shell)',
    user: 'www-data',
    severity: 'CRITICAL',
    action: 'Quarantine file immediately & kill spawned child processes',
    prev_hash: 'None (Newly created file)',
    curr_hash: '4a6b2c9e7821df91a2bc901eef1923419082bcfa781290fecca9012354718290',
    size_diff: '14.2 KB'
  },
  {
    id: 'SYS-2026-8889',
    timestamp: '13:38:22',
    type: 'PRIV_ESC',
    typeLabel: 'Sudo Abuse',
    rule_id: 5402,
    target: '034 (elsa-instiki)',
    tenant: 'InstikiBali',
    affected_item: 'sudo /bin/bash (Unauthorized command attempt)',
    user: 'deploy',
    severity: 'HIGH',
    action: 'Review /etc/sudoers file and revoke unauthorized privileges',
    prev_hash: 'N/A (Process execution event)',
    curr_hash: 'N/A',
    size_diff: 'Command blocked'
  },
  {
    id: 'SYS-2026-8871',
    timestamp: '13:35:11',
    type: 'AGENT',
    typeLabel: 'Heartbeat Lost',
    rule_id: 501,
    target: '020 (proxy-petra)',
    tenant: 'Petra',
    affected_item: 'Wazuh Agent Disconnected (No keep-alive > 10m)',
    user: 'system',
    severity: 'MEDIUM',
    action: 'Ping host network interface & restart wazuh-agent service',
    prev_hash: 'Agent ID: 020',
    curr_hash: 'Status: Disconnected',
    size_diff: 'Last seen: 13:25:00'
  },
  {
    id: 'SYS-2026-8850',
    timestamp: '13:20:00',
    type: 'FIM_OK',
    typeLabel: 'FIM Restored',
    rule_id: 553,
    target: '015 (core-pradita)',
    tenant: 'PraditaUniversity',
    affected_item: '/usr/bin/sudo (Rollback Verified from Gold Image)',
    user: 'sysadmin',
    severity: 'LOW',
    action: 'Compliant. File restored to golden baseline checksum',
    prev_hash: 'Verified matching trusted baseline',
    curr_hash: '5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8',
    size_diff: 'Clean'
  },
  {
    id: 'SYS-2026-8822',
    timestamp: '13:12:44',
    type: 'USER_ADD',
    typeLabel: 'Account Added',
    rule_id: 5902,
    target: '026 (core-wicida)',
    tenant: 'wicida',
    affected_item: 'New User guest_backup added to /etc/passwd',
    user: 'root',
    severity: 'HIGH',
    action: 'Confirm authorization with tenant system administrator',
    prev_hash: 'User count: 24',
    curr_hash: 'User count: 25 (UID: 1004)',
    size_diff: 'Line appended'
  },
  {
    id: 'SYS-2026-8799',
    timestamp: '12:58:30',
    type: 'PROMISC',
    typeLabel: 'Sniffer Indication',
    rule_id: 510,
    target: '034 (elsa-instiki)',
    tenant: 'InstikiBali',
    affected_item: 'Network interface eth0 entered promiscuous mode',
    user: 'kernel',
    severity: 'CRITICAL',
    action: 'Run memory dump via osquery to detect packet sniffing trojans',
    prev_hash: 'Normal (Flag: -PROMISC)',
    curr_hash: 'Abnormal (Flag: +PROMISC)',
    size_diff: 'Hardware flag changed'
  }
];

export default function SystemIntegrityOverview({
  theme = 'dark',
  selectedTenant = 'ALL',
  timeRange = 'All Time'
}) {
  const isDark = theme === 'dark' || (typeof document !== 'undefined' && document.documentElement.classList.contains('dark'));

  // Active tenant data selector: single tenant or global summary
  const activeTenantData = useMemo(() => {
    if (selectedTenant && selectedTenant !== 'ALL' && selectedTenant !== 'all') {
      return TENANT_SYSTEM_DATASETS[selectedTenant] || GLOBAL_SYSTEM_DATA;
    }
    return GLOBAL_SYSTEM_DATA;
  }, [selectedTenant]);

  // Tenant list for multi-tenant rendering
  const tenantList = useMemo(() => {
    if (selectedTenant && selectedTenant !== 'ALL' && selectedTenant !== 'all') {
      const match = TENANT_SYSTEM_DATASETS[selectedTenant];
      return match ? [match] : [TENANT_SYSTEM_DATASETS.PraditaUniversity];
    }
    return Object.values(TENANT_SYSTEM_DATASETS);
  }, [selectedTenant]);

  // Mode: '2x2_charts' (2x2 Matrix of 4 Donut Charts) vs '2x2_tenants' (2x2 Grid of Tenant Boxes)
  const [layoutMode, setLayoutMode] = useState('2x2_charts');

  // Filter state
  const [activeSlice, setActiveSlice] = useState(null);
  const [searchQuery, setSearchQuery] = useState('');
  const [isFlagActive, setIsFlagActive] = useState(false);
  const [selectedLog, setSelectedLog] = useState(null);

  // Filtered logs
  const filteredLogs = useMemo(() => {
    return SYSTEM_AUDIT_LOGS.filter((item) => {
      if (selectedTenant && selectedTenant !== 'ALL' && selectedTenant !== 'all' && item.tenant !== selectedTenant) {
        return false;
      }
      if (isFlagActive && item.severity !== 'CRITICAL') return false;
      if (activeSlice) {
        const desc = (item.affected_item + ' ' + item.type + ' ' + item.typeLabel).toLowerCase();
        const sliceLower = activeSlice.name.toLowerCase().split(' ')[0];
        if (!desc.includes(sliceLower)) return false;
      }
      if (searchQuery.trim()) {
        const q = searchQuery.toLowerCase();
        const full = `${item.id} ${item.affected_item} ${item.user} ${item.tenant} ${item.target} ${item.severity} ${item.typeLabel}`.toLowerCase();
        if (!full.includes(q)) return false;
      }
      return true;
    });
  }, [selectedTenant, isFlagActive, activeSlice, searchQuery]);

  const handleSliceClick = (tenantId, chartName, entry) => {
    if (activeSlice && activeSlice.tenantId === tenantId && activeSlice.name === entry.name) {
      setActiveSlice(null);
    } else {
      setActiveSlice({ tenantId, chartName, name: entry.name, color: entry.color });
    }
  };

  // Helper: Render Recharts Donut Pie Chart Box
  const renderPieChartBox = (tenantId, chartTitle, dataset, totalEvents, unitName, subtitle = '') => {
    return (
      <div className={`p-4 rounded-xl border flex flex-col justify-between transition-colors min-w-0 shadow-xs ${
        isDark ? 'bg-[#060a12] border-slate-800/80 hover:border-slate-700/80' : 'bg-slate-50/70 border-slate-200 hover:border-slate-300'
      }`}>
        {/* Header Kartu: Judul di Kiri, Total di Kanan */}
        <div className="flex items-center justify-between pb-2 border-b border-slate-200 dark:border-slate-800/80 mb-2">
          <div className="min-w-0 pr-2">
            <span className={`text-xs font-bold uppercase tracking-wider block truncate ${
              isDark ? 'text-slate-200' : 'text-slate-800'
            }`}>
              {chartTitle}
            </span>
            {subtitle && (
              <span className="text-[10px] text-slate-400 block truncate">{subtitle}</span>
            )}
          </div>
          <span className="text-[11px] font-mono font-semibold text-blue-500 shrink-0 bg-blue-500/10 px-2 py-0.5 rounded border border-blue-500/20">
            {Number(totalEvents).toLocaleString()} {unitName}
          </span>
        </div>

        {/* Donut Chart di Sisi Kiri, Legend di Sisi Kanan (Side-by-Side) */}
        <div className="flex items-center justify-center gap-3 my-auto py-1.5">
          {/* Donut Ring: Radius 36-52px to fit side-by-side gracefully */}
          <div className="w-28 h-28 shrink-0 relative flex items-center justify-center">
            <ResponsiveContainer width="100%" height="100%">
              <PieChart>
                <Pie
                  data={dataset}
                  cx="50%"
                  cy="50%"
                  innerRadius={36}
                  outerRadius={52}
                  paddingAngle={dataset.length > 1 ? 2.5 : 0}
                  dataKey="value"
                  stroke="none"
                  strokeWidth={0}
                  isAnimationActive={false}
                  cursor="pointer"
                  onClick={(entry) => {
                    if (entry && entry.name) {
                      handleSliceClick(tenantId, chartTitle, entry);
                    }
                  }}
                >
                  {dataset.map((entry, idx) => {
                    const isSelected = activeSlice && activeSlice.tenantId === tenantId && activeSlice.name === entry.name;
                    return (
                      <Cell
                        key={`cell-${tenantId}-${chartTitle}-${idx}`}
                        fill={entry.color || PALETTE[idx % PALETTE.length]}
                        opacity={activeSlice ? (isSelected ? 1 : 0.35) : 1}
                        style={{
                          filter: isSelected ? 'drop-shadow(0 0 6px rgba(59, 130, 246, 0.7))' : 'none',
                          transition: 'all 0.2s ease'
                        }}
                      />
                    );
                  })}
                </Pie>
                <Tooltip
                  formatter={(val, name, props) => [
                    `${Number(val).toLocaleString()} (${props.payload.pct}%)`,
                    props.payload.name
                  ]}
                  contentStyle={{
                    backgroundColor: isDark ? '#0f172a' : '#ffffff',
                    borderColor: isDark ? '#334155' : '#cbd5e1',
                    borderRadius: '8px',
                    fontSize: '11px',
                    color: isDark ? '#f8fafc' : '#0f172a'
                  }}
                />
              </PieChart>
            </ResponsiveContainer>
          </div>

          {/* Legend Items */}
          <div className="flex-1 min-w-0 space-y-1 overflow-hidden">
            {dataset.map((item, idx) => {
              const isSelected = activeSlice && activeSlice.tenantId === tenantId && activeSlice.name === item.name;
              return (
                <div
                  key={`legend-${tenantId}-${chartTitle}-${idx}`}
                  onClick={() => handleSliceClick(tenantId, chartTitle, item)}
                  className={`flex items-center justify-between text-xs cursor-pointer py-0.5 px-1.5 rounded transition-colors ${
                    isSelected
                      ? 'bg-blue-500/15 font-semibold text-blue-500'
                      : isDark
                        ? 'text-slate-300 hover:bg-slate-800/60'
                        : 'text-slate-700 hover:bg-slate-200/60'
                  }`}
                  title={`${item.name}: ${Number(item.value).toLocaleString()} (${item.pct}%)`}
                >
                  <div className="flex items-center gap-1.5 min-w-0 truncate pr-1">
                    <span 
                      className="w-2.5 h-2.5 rounded-full shrink-0" 
                      style={{ backgroundColor: item.color || PALETTE[idx % PALETTE.length] }} 
                    />
                    <span className="truncate text-[11px]">{item.name}</span>
                  </div>
                  <div className="text-[10.5px] font-mono shrink-0 flex items-center gap-1">
                    <span className="font-semibold">{Number(item.value).toLocaleString()}</span>
                    <span className="text-slate-400 text-[9.5px]">({item.pct}%)</span>
                  </div>
                </div>
              );
            })}
          </div>
        </div>
      </div>
    );
  };

  return (
    <div className="space-y-6 w-full">
      {/* ========================================================================= */}
      {/* HEADER & SWITCH VIEW (2x2 Matrix Charts vs 2x2 Host Grid)                 */}
      {/* ========================================================================= */}
      <div className={`p-4 rounded-xl border transition-colors shadow-xs ${
        isDark ? 'bg-[#0a0e1a] border-slate-800' : 'bg-white border-slate-200'
      }`}>
        <div className="flex flex-wrap items-center justify-between gap-3">
          {/* Sisi Kiri: Tenant Info Active */}
          <div className="flex items-center gap-3">
            <div className="p-2.5 rounded-xl bg-sky-500/10 text-sky-500 border border-sky-500/20">
              <Server className="w-5 h-5" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <h2 className={`text-base font-bold tracking-tight ${isDark ? 'text-white' : 'text-slate-900'}`}>
                  {activeTenantData.name}
                </h2>
                <span className="px-2 py-0.5 rounded text-[10.5px] font-mono bg-sky-500/10 text-sky-400 border border-sky-500/20">
                  {activeTenantData.tenantId}
                </span>
              </div>
              <p className="text-xs text-slate-400">
                Memantau Integritas Host & Aktivitas Sistem • {activeTenantData.hostsCount} Server Terdaftar • Rentang waktu: {timeRange}
              </p>
            </div>
          </div>

          {/* Sisi Kanan: Switch View Mode (2x2 Matrix vs 2x2 Tenant Grid) */}
          <div className="flex items-center gap-1.5 p-1 rounded-lg border bg-slate-900/40 border-slate-800 text-xs">
            <button
              onClick={() => setLayoutMode('2x2_charts')}
              className={`flex items-center gap-1.5 px-3 py-1.5 rounded-md font-semibold transition-all cursor-pointer ${
                layoutMode === '2x2_charts'
                  ? 'bg-blue-600 text-white shadow-xs'
                  : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              <LayoutGrid className="w-3.5 h-3.5" />
              <span>2x2 Matrix Charts</span>
            </button>
            <button
              onClick={() => setLayoutMode('2x2_tenants')}
              className={`flex items-center gap-1.5 px-3 py-1.5 rounded-md font-semibold transition-all cursor-pointer ${
                layoutMode === '2x2_tenants'
                  ? 'bg-blue-600 text-white shadow-xs'
                  : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              <Layers className="w-3.5 h-3.5" />
              <span>2x2 Tenant Grid</span>
            </button>
          </div>
        </div>
      </div>

      {/* ========================================================================= */}
      {/* TAMPILAN 1: 2x2 MATRIX CHARTS (4 KUADRAN INTEGRITAS HOST SIDE-BY-SIDE)    */}
      {/* ========================================================================= */}
      {layoutMode === '2x2_charts' && (
        <div className="grid grid-cols-2 gap-4 w-full min-w-0">
          {/* Card 1: Top-Left -> FIM: SYSTEM INTEGRITY */}
          {renderPieChartBox(
            activeTenantData.tenantId,
            'FIM: SYSTEM INTEGRITY',
            activeTenantData.fimData,
            activeTenantData.fimTotal,
            'events',
            'Modifikasi File Biner & Konfigurasi Kritis'
          )}

          {/* Card 2: Top-Right -> PRIVILEGE & ACCOUNT ACTIVITY */}
          {renderPieChartBox(
            activeTenantData.tenantId,
            'PRIVILEGE & ACCOUNT ACTIVITY',
            activeTenantData.privData,
            activeTenantData.privTotal,
            'events',
            'Percobaan Sudo Ilegal & Modifikasi Akun'
          )}

          {/* Card 3: Bottom-Left -> SUSPICIOUS FILES & WEB SHELL */}
          {renderPieChartBox(
            activeTenantData.tenantId,
            'SUSPICIOUS FILES & WEB SHELL',
            activeTenantData.fileData,
            activeTenantData.fileTotal,
            'findings',
            'Potensi Backdoor di Direktori Web & Promiscuous Port'
          )}

          {/* Card 4: Bottom-Right -> AGENT & HOST HEALTH STATE */}
          {renderPieChartBox(
            activeTenantData.tenantId,
            'AGENT & HOST HEALTH STATE',
            activeTenantData.healthData,
            activeTenantData.healthTotal,
            'hosts',
            'Konektivitas Telemetri Agent Wazuh'
          )}
        </div>
      )}

      {/* ========================================================================= */}
      {/* TAMPILAN 2: 2x2 TENANT GRID (KOTAK PER TENANT DENGAN 2 PIE BERDAMPINGAN)   */}
      {/* ========================================================================= */}
      {layoutMode === '2x2_tenants' && (
        <div className="grid grid-cols-2 gap-4 w-full min-w-0">
          {tenantList.map((tenant) => {
            return (
              <div
                key={`tenant-card-sys-${tenant.tenantId}`}
                className={`rounded-xl border p-4 transition-colors shadow-xs flex flex-col justify-between ${
                  isDark ? 'bg-[#0a0e1a] border-slate-800' : 'bg-white border-slate-200'
                }`}
              >
                {/* Header Tenant Box */}
                <div className="flex items-center justify-between gap-2 pb-3 border-b border-slate-200 dark:border-slate-800 mb-3">
                  <div className="flex items-center gap-2 min-w-0">
                    <div className="p-1.5 rounded-lg bg-sky-500/10 text-sky-500 border border-sky-500/20 shrink-0">
                      <Building2 className="w-3.5 h-3.5" />
                    </div>
                    <div className="min-w-0">
                      <h3 className={`text-xs font-bold tracking-tight truncate ${
                        isDark ? 'text-white' : 'text-slate-900'
                      }`}>
                        {tenant.name}
                      </h3>
                      <span className="text-[10px] text-slate-400 block truncate">
                        ID: <span className="font-mono text-sky-400">{tenant.tenantId}</span> • {tenant.hostsCount} Hosts
                      </span>
                    </div>
                  </div>
                  <div className="flex items-center gap-1.5 shrink-0">
                    <span className="px-2 py-0.5 rounded text-[10px] font-mono font-semibold bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
                      Health: {tenant.healthScore}
                    </span>
                  </div>
                </div>

                {/* 2 Pie Chart Samping-Sampingan di Dalam Kotak Tenant */}
                <div className="grid grid-cols-2 gap-3 w-full min-w-0">
                  {renderPieChartBox(
                    tenant.tenantId,
                    'FIM Integrity',
                    tenant.fimData,
                    tenant.fimTotal,
                    'events'
                  )}
                  {renderPieChartBox(
                    tenant.tenantId,
                    'Privilege & Auth',
                    tenant.privData,
                    tenant.privTotal,
                    'events'
                  )}
                </div>
              </div>
            );
          })}
        </div>
      )}

      {/* Filter Active Pill */}
      {activeSlice && (
        <div className={`p-2.5 px-4 rounded-lg flex items-center justify-between border ${
          isDark ? 'bg-sky-950/30 border-sky-800 text-sky-300' : 'bg-sky-50 border-sky-200 text-sky-800'
        }`}>
          <div className="flex items-center gap-2 text-xs">
            <Filter className="w-3.5 h-3.5 text-sky-400" />
            <span>Memfilter audit log <strong>{activeSlice.chartName}</strong> ({activeSlice.tenantId}) slice: <strong>{activeSlice.name}</strong></span>
          </div>
          <button
            onClick={() => setActiveSlice(null)}
            className="text-xs flex items-center gap-1 hover:underline cursor-pointer"
          >
            <X className="w-3.5 h-3.5" /> Hapus Filter
          </button>
        </div>
      )}

      {/* ========================================================================= */}
      {/* TABEL SYSTEM INTEGRITY AUDIT LOG                                         */}
      {/* ========================================================================= */}
      <div className="flex gap-4 items-start w-full min-w-0">
        <div className={`flex-1 min-w-0 rounded-xl border shadow-xs overflow-hidden transition-colors ${
          isDark ? 'bg-[#0a0e1a] border-slate-800' : 'bg-white border-slate-200'
        }`}>
          {/* Table Header: Title di Kiri, Search Bar di Tengah, Red Flag di Pojok Kanan */}
          <div className={`p-4 border-b flex items-center justify-between gap-4 transition-colors ${
            isDark ? 'border-slate-800/80 bg-[#070b14]' : 'border-slate-100 bg-slate-50/50'
          }`}>
            <div className="shrink-0 w-32 sm:w-44">
              <h3 className={`text-base font-bold tracking-tight ${isDark ? 'text-white' : 'text-slate-900'}`}>
                Integrity Audit Log
              </h3>
            </div>

            {/* Center Search Bar */}
            <div className="flex-1 flex items-center justify-center max-w-xl mx-auto">
              <div className="w-full relative flex items-center bg-white dark:bg-[#090d16] border-2 border-[#3B5BFF] rounded-full h-[38px] pl-3.5 pr-1.5 shadow-2xs group focus-within:ring-2 focus-within:ring-[#3B5BFF]/30 transition-all">
                <Search className="w-4 h-4 text-slate-400 shrink-0 mr-2.5 stroke-[2]" />
                <input
                  type="text"
                  value={searchQuery}
                  onChange={(e) => setSearchQuery(e.target.value)}
                  placeholder="Search File Path, User, Host, Action, Rule..."
                  className="w-full bg-transparent text-slate-800 dark:text-slate-200 placeholder:text-slate-400 text-xs sm:text-[13px] font-normal focus:outline-none"
                />
                {searchQuery && (
                  <button
                    type="button"
                    onClick={() => setSearchQuery('')}
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

            {/* Red Flag di Pojok Kanan */}
            <div className="shrink-0 w-28 sm:w-36 flex justify-end items-center">
              <button
                type="button"
                onClick={() => setIsFlagActive(!isFlagActive)}
                className="p-1 cursor-pointer transition-transform hover:scale-125 group flex items-center justify-center"
                title={isFlagActive ? 'Filter Flag Merah Aktif (Critical Events Only)' : 'Filter Flag Merah (Critical Events Only)'}
              >
                <Flag className={`w-5 h-5 transition-all ${
                  isFlagActive
                    ? 'fill-red-600 text-red-600 drop-shadow-[0_0_8px_rgba(239,68,68,0.7)]'
                    : 'fill-red-500 text-red-500 opacity-85 group-hover:opacity-100'
                }`} />
              </button>
            </div>
          </div>

          {/* Table List */}
          <div className="overflow-x-auto w-full">
            <table className="w-full text-left text-xs border-collapse">
              <thead>
                <tr className={`border-b font-mono text-[11px] tracking-wider uppercase ${
                  isDark ? 'border-slate-800/80 bg-slate-900/40 text-slate-400' : 'border-slate-200 bg-slate-50 text-slate-500'
                }`}>
                  <th className="py-2.5 px-3">TIMESTAMP</th>
                  <th className="py-2.5 px-3">EVENT TYPE</th>
                  <th className="py-2.5 px-3">TENANT</th>
                  <th className="py-2.5 px-3">TARGET HOST</th>
                  <th className="py-2.5 px-3">USER</th>
                  <th className="py-2.5 px-3">SEVERITY</th>
                  <th className="py-2.5 px-3">AFFECTED FILE / ACTION</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-200 dark:divide-slate-800/60 font-mono text-[11.5px]">
                {filteredLogs.length === 0 ? (
                  <tr>
                    <td colSpan="7" className="py-12 text-center text-slate-400 font-sans">
                      Tidak ada log integritas yang cocok dengan filter atau pencarian ini.
                    </td>
                  </tr>
                ) : (
                  filteredLogs.map((item) => {
                    const isSelected = selectedLog && selectedLog.id === item.id;
                    return (
                      <tr
                        key={item.id}
                        onClick={() => setSelectedLog(isSelected ? null : item)}
                        className={`cursor-pointer transition-colors ${
                          isSelected
                            ? isDark ? 'bg-sky-950/40' : 'bg-sky-50/70'
                            : isDark ? 'hover:bg-slate-900/60' : 'hover:bg-slate-50'
                        }`}
                      >
                        <td className="py-2.5 px-3 text-slate-400 whitespace-nowrap">
                          {item.timestamp}
                        </td>
                        <td className="py-2.5 px-3">
                          <span className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                            item.type === 'BACKDOOR' ? 'bg-red-500/20 text-red-400 border border-red-500/30' :
                            item.type === 'FIM_MOD' ? 'bg-rose-500/15 text-rose-400 border border-rose-500/30' :
                            item.type === 'PRIV_ESC' ? 'bg-amber-500/15 text-amber-400 border border-amber-500/30' :
                            item.type === 'PROMISC' ? 'bg-purple-500/15 text-purple-400 border border-purple-500/30' :
                            item.type === 'USER_ADD' ? 'bg-blue-500/15 text-blue-400 border border-blue-500/30' :
                            item.type === 'FIM_OK' ? 'bg-emerald-500/15 text-emerald-400 border border-emerald-500/30' :
                            'bg-slate-500/15 text-slate-400 border border-slate-500/30'
                          }`}>
                            {item.typeLabel}
                          </span>
                        </td>
                        <td className="py-2.5 px-3 text-slate-300 truncate max-w-[110px]">
                          {item.tenant}
                        </td>
                        <td className="py-2.5 px-3 text-slate-400 truncate max-w-[120px]">
                          {item.target}
                        </td>
                        <td className="py-2.5 px-3 text-slate-200 font-bold">
                          {item.user}
                        </td>
                        <td className="py-2.5 px-3">
                          <span className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                            item.severity === 'CRITICAL' ? 'bg-red-500/20 text-red-500 border border-red-500/40' :
                            item.severity === 'HIGH' ? 'bg-amber-500/20 text-amber-500 border border-amber-500/40' :
                            item.severity === 'MEDIUM' ? 'bg-blue-500/20 text-blue-500 border border-blue-500/40' :
                            'bg-slate-500/20 text-slate-400 border border-slate-500/30'
                          }`}>
                            {item.severity}
                          </span>
                        </td>
                        <td className="py-2.5 px-3 text-slate-300 font-sans truncate max-w-[280px]">
                          {item.affected_item}
                        </td>
                      </tr>
                    );
                  })
                )}
              </tbody>
            </table>
          </div>
        </div>

        {/* Sisi Kanan: Detail Panel */}
        {selectedLog && (
          <div className={`w-80 sm:w-96 shrink-0 rounded-xl border p-4 shadow-sm space-y-3.5 self-stretch transition-colors ${
            isDark ? 'bg-[#0a0e1a] border-slate-800' : 'bg-white border-slate-200'
          }`}>
            <div className="flex items-center justify-between pb-2 border-b border-slate-200 dark:border-slate-800">
              <span className="text-xs font-bold text-slate-200">Integrity Event Details</span>
              <button
                onClick={() => setSelectedLog(null)}
                className="text-slate-400 hover:text-slate-200 p-0.5 cursor-pointer"
              >
                <X className="w-4 h-4" />
              </button>
            </div>

            <div className="space-y-2 text-xs">
              <div>
                <span className="text-slate-500 block text-[10px]">Event Type:</span>
                <span className="font-mono font-bold text-sky-400">{selectedLog.typeLabel} (Rule {selectedLog.rule_id})</span>
              </div>
              <div>
                <span className="text-slate-500 block text-[10px]">Affected Item / Action:</span>
                <span className="text-slate-200 font-sans font-semibold">{selectedLog.affected_item}</span>
              </div>
              <div className="grid grid-cols-2 gap-2">
                <div>
                  <span className="text-slate-500 block text-[10px]">Target Host:</span>
                  <span className="text-slate-300 font-mono">{selectedLog.target}</span>
                </div>
                <div>
                  <span className="text-slate-500 block text-[10px]">Actor User:</span>
                  <span className="text-slate-300 font-mono font-bold">{selectedLog.user}</span>
                </div>
              </div>
              <div className="p-2 rounded bg-slate-900/60 border border-slate-800 space-y-1 font-mono text-[10.5px]">
                <div className="flex justify-between text-slate-400">
                  <span>Delta / Size:</span>
                  <span className="text-amber-400 font-bold">{selectedLog.size_diff}</span>
                </div>
                <div className="truncate text-slate-400">
                  <span>Prev: </span>
                  <span className="text-slate-300">{selectedLog.prev_hash}</span>
                </div>
                <div className="truncate text-slate-400">
                  <span>Curr: </span>
                  <span className="text-emerald-400">{selectedLog.curr_hash}</span>
                </div>
              </div>
              <div>
                <span className="text-slate-500 block text-[10px]">Recommended Triage Action:</span>
                <div className="mt-1 p-2 rounded bg-sky-500/10 border border-sky-500/20 text-sky-300 text-[11px] font-sans">
                  {selectedLog.action}
                </div>
              </div>
            </div>

            {/* Raw Payload (Pure White Box & Black Text Standard) */}
            <div className="space-y-1">
              <span className="text-slate-500 block text-[10px]">Raw Wazuh Payload:</span>
              <pre className="p-2.5 rounded text-[10.5px] font-mono whitespace-pre-wrap break-all bg-white text-black border border-slate-300 max-h-48 overflow-y-auto">
{JSON.stringify(selectedLog, null, 2)}
              </pre>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
