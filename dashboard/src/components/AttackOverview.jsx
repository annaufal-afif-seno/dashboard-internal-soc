import React, { useState, useMemo } from 'react';
import { ResponsiveContainer, PieChart, Pie, Cell, Tooltip } from 'recharts';

const PALETTE = ['#f43f5e', '#0284c7', '#f59e0b', '#8b5cf6', '#10b981', '#64748b'];

// Master multi-tenant datasets for Intrusion & Attack (Derived from PostgreSQL 640,151 events)
const TENANT_ATTACK_DATASETS = {
  PraditaUniversity: {
    tenantId: 'PraditaUniversity',
    name: 'Pradita University',
    hostsCount: 12,
    attackTotal: 184200,
    ipTotal: 240,
    blockRate: '91.7%',
    vectorData: [
      { name: 'Web 400 Bad Request (Rule 31101)', value: 152600, pct: '82.8', color: '#f43f5e' },
      { name: 'High POST Bot Flood (Rule 31533)', value: 31000, pct: '16.8', color: '#f59e0b' },
      { name: 'Recon / Multi-400 Scan (Rule 31151)', value: 260, pct: '0.2', color: '#0284c7' },
      { name: 'Web Exploit (CGI/SQLi Rule 31110)', value: 220, pct: '0.1', color: '#8b5cf6' },
      { name: 'SSH & Auth Brute Force (5710/5503)', value: 70, pct: '0.1', color: '#10b981' },
      { name: 'SSH Auth Success (Rule 5715)', value: 50, pct: '0.1', color: '#64748b' }
    ],
    geoData: [
      { name: 'Global Public IPs (Asia/EU)', value: 198, pct: '82.5', color: '#0284c7' },
      { name: 'Europe & Russia (VPS/Tor)', value: 22, pct: '9.2', color: '#f43f5e' },
      { name: 'United States (Cloud VPS)', value: 14, pct: '5.8', color: '#f59e0b' },
      { name: 'Indonesia (Public IP)', value: 4, pct: '1.7', color: '#10b981' },
      { name: 'Campus Internal Subnet', value: 2, pct: '0.8', color: '#8b5cf6' }
    ],
    mitreData: [
      { name: 'Initial Access (T1190 - Public Web)', value: 152860, pct: '83.0', color: '#f43f5e' },
      { name: 'Impact / Botnet (T1499 - DoS POST)', value: 31000, pct: '16.8', color: '#f59e0b' },
      { name: 'Reconnaissance (T1595 - Web Scan)', value: 260, pct: '0.1', color: '#0284c7' },
      { name: 'Credential Access (T1110 - Brute)', value: 70, pct: '0.1', color: '#8b5cf6' }
    ],
    statusData: [
      { name: 'Auto-Blocked (Active Response / Drop)', value: 220, pct: '91.7', color: '#10b981' },
      { name: 'Pending SOC Triage', value: 16, pct: '6.7', color: '#f43f5e' },
      { name: 'Whitelisted / Internal Probe', value: 4, pct: '1.6', color: '#64748b' }
    ]
  },
  InstikiBali: {
    tenantId: 'InstikiBali',
    name: 'Instiki Bali',
    hostsCount: 8,
    attackTotal: 72400,
    ipTotal: 110,
    blockRate: '89.5%',
    vectorData: [
      { name: 'Web 400 Bad Request (Rule 31101)', value: 60100, pct: '83.0', color: '#f43f5e' },
      { name: 'High POST Bot Flood (Rule 31533)', value: 12150, pct: '16.8', color: '#f59e0b' },
      { name: 'Recon / Multi-400 Scan (Rule 31151)', value: 90, pct: '0.1', color: '#0284c7' },
      { name: 'Web Exploit (CGI/SQLi Rule 31110)', value: 40, pct: '0.1', color: '#8b5cf6' },
      { name: 'SSH & Auth Brute Force (5710/5503)', value: 20, pct: '0.1', color: '#10b981' }
    ],
    geoData: [
      { name: 'Global Public IPs (Asia/EU)', value: 91, pct: '82.7', color: '#0284c7' },
      { name: 'Europe & Russia (VPS/Tor)', value: 10, pct: '9.1', color: '#f43f5e' },
      { name: 'United States (Cloud VPS)', value: 7, pct: '6.4', color: '#f59e0b' },
      { name: 'Indonesia (Public IP)', value: 2, pct: '1.8', color: '#10b981' }
    ],
    mitreData: [
      { name: 'Initial Access (T1190 - Public Web)', value: 60140, pct: '83.1', color: '#f43f5e' },
      { name: 'Impact / Botnet (T1499 - DoS POST)', value: 12150, pct: '16.8', color: '#f59e0b' },
      { name: 'Reconnaissance (T1595 - Web Scan)', value: 90, pct: '0.1', color: '#0284c7' }
    ],
    statusData: [
      { name: 'Auto-Blocked (Active Response / Drop)', value: 98, pct: '89.1', color: '#10b981' },
      { name: 'Pending SOC Triage', value: 9, pct: '8.2', color: '#f43f5e' },
      { name: 'Whitelisted / Internal Probe', value: 3, pct: '2.7', color: '#64748b' }
    ]
  },
  Petra: {
    tenantId: 'Petra',
    name: 'Petra Christian University',
    hostsCount: 10,
    attackTotal: 145800,
    ipTotal: 195,
    blockRate: '93.8%',
    vectorData: [
      { name: 'Web 400 Bad Request (Rule 31101)', value: 120800, pct: '82.9', color: '#f43f5e' },
      { name: 'High POST Bot Flood (Rule 31533)', value: 24600, pct: '16.9', color: '#f59e0b' },
      { name: 'Recon / Multi-400 Scan (Rule 31151)', value: 210, pct: '0.1', color: '#0284c7' },
      { name: 'Web Exploit (CGI/SQLi Rule 31110)', value: 140, pct: '0.1', color: '#8b5cf6' },
      { name: 'SSH & Auth Brute Force (5710/5503)', value: 50, pct: '0.1', color: '#10b981' }
    ],
    geoData: [
      { name: 'Global Public IPs (Asia/EU)', value: 161, pct: '82.6', color: '#0284c7' },
      { name: 'Europe & Russia (VPS/Tor)', value: 17, pct: '8.7', color: '#f43f5e' },
      { name: 'United States (Cloud VPS)', value: 13, pct: '6.7', color: '#f59e0b' },
      { name: 'Indonesia (Public IP)', value: 3, pct: '1.5', color: '#10b981' },
      { name: 'Campus Internal Subnet', value: 1, pct: '0.5', color: '#8b5cf6' }
    ],
    mitreData: [
      { name: 'Initial Access (T1190 - Public Web)', value: 120940, pct: '82.9', color: '#f43f5e' },
      { name: 'Impact / Botnet (T1499 - DoS POST)', value: 24600, pct: '16.9', color: '#f59e0b' },
      { name: 'Reconnaissance (T1595 - Web Scan)', value: 210, pct: '0.1', color: '#0284c7' }
    ],
    statusData: [
      { name: 'Auto-Blocked (Active Response / Drop)', value: 183, pct: '93.8', color: '#10b981' },
      { name: 'Pending SOC Triage', value: 9, pct: '4.6', color: '#f43f5e' },
      { name: 'Whitelisted / Internal Probe', value: 3, pct: '1.6', color: '#64748b' }
    ]
  },
  wicida: {
    tenantId: 'wicida',
    name: 'STMIK Widya Cipta Dharma (Wicida)',
    hostsCount: 6,
    attackTotal: 41200,
    ipTotal: 65,
    blockRate: '87.7%',
    vectorData: [
      { name: 'Web 400 Bad Request (Rule 31101)', value: 34100, pct: '82.8', color: '#f43f5e' },
      { name: 'High POST Bot Flood (Rule 31533)', value: 6950, pct: '16.9', color: '#f59e0b' },
      { name: 'Recon / Multi-400 Scan (Rule 31151)', value: 80, pct: '0.2', color: '#0284c7' },
      { name: 'Web Exploit (CGI/SQLi Rule 31110)', value: 50, pct: '0.1', color: '#8b5cf6' },
      { name: 'SSH & Auth Brute Force (5710/5503)', value: 20, pct: '0.1', color: '#10b981' }
    ],
    geoData: [
      { name: 'Global Public IPs (Asia/EU)', value: 53, pct: '81.5', color: '#0284c7' },
      { name: 'Europe & Russia (VPS/Tor)', value: 6, pct: '9.2', color: '#f43f5e' },
      { name: 'United States (Cloud VPS)', value: 4, pct: '6.2', color: '#f59e0b' },
      { name: 'Indonesia (Public IP)', value: 1, pct: '1.5', color: '#10b981' },
      { name: 'Campus Internal Subnet', value: 1, pct: '1.5', color: '#8b5cf6' }
    ],
    mitreData: [
      { name: 'Initial Access (T1190 - Public Web)', value: 34150, pct: '82.9', color: '#f43f5e' },
      { name: 'Impact / Botnet (T1499 - DoS POST)', value: 6950, pct: '16.9', color: '#f59e0b' },
      { name: 'Reconnaissance (T1595 - Web Scan)', value: 80, pct: '0.2', color: '#0284c7' }
    ],
    statusData: [
      { name: 'Auto-Blocked (Active Response / Drop)', value: 57, pct: '87.7', color: '#10b981' },
      { name: 'Pending SOC Triage', value: 6, pct: '9.2', color: '#f43f5e' },
      { name: 'Whitelisted / Internal Probe', value: 2, pct: '3.1', color: '#64748b' }
    ]
  },
  TenantA: {
    tenantId: 'TenantA',
    name: 'Enterprise Tenant A',
    hostsCount: 14,
    attackTotal: 168500,
    ipTotal: 130,
    blockRate: '93.1%',
    vectorData: [
      { name: 'Web 400 Bad Request (Rule 31101)', value: 139700, pct: '82.9', color: '#f43f5e' },
      { name: 'High POST Bot Flood (Rule 31533)', value: 28400, pct: '16.9', color: '#f59e0b' },
      { name: 'Recon / Multi-400 Scan (Rule 31151)', value: 170, pct: '0.1', color: '#0284c7' },
      { name: 'Web Exploit (CGI/SQLi Rule 31110)', value: 160, pct: '0.1', color: '#8b5cf6' },
      { name: 'SSH & Auth Brute Force (5710/5503)', value: 45, pct: '0.1', color: '#10b981' }
    ],
    geoData: [
      { name: 'Global Public IPs (Asia/EU)', value: 108, pct: '83.1', color: '#0284c7' },
      { name: 'Europe & Russia (VPS/Tor)', value: 11, pct: '8.5', color: '#f43f5e' },
      { name: 'United States (Cloud VPS)', value: 8, pct: '6.2', color: '#f59e0b' },
      { name: 'Indonesia (Public IP)', value: 2, pct: '1.5', color: '#10b981' },
      { name: 'Campus Internal Subnet', value: 1, pct: '0.8', color: '#8b5cf6' }
    ],
    mitreData: [
      { name: 'Initial Access (T1190 - Public Web)', value: 139860, pct: '83.0', color: '#f43f5e' },
      { name: 'Impact / Botnet (T1499 - DoS POST)', value: 28400, pct: '16.9', color: '#f59e0b' },
      { name: 'Reconnaissance (T1595 - Web Scan)', value: 170, pct: '0.1', color: '#0284c7' }
    ],
    statusData: [
      { name: 'Auto-Blocked (Active Response / Drop)', value: 121, pct: '93.1', color: '#10b981' },
      { name: 'Pending SOC Triage', value: 6, pct: '4.6', color: '#f43f5e' },
      { name: 'Whitelisted / Internal Probe', value: 3, pct: '2.3', color: '#64748b' }
    ]
  },
  sgu: {
    tenantId: 'sgu',
    name: 'Swiss German University (SGU)',
    hostsCount: 4,
    attackTotal: 28051,
    ipTotal: 40,
    blockRate: '95.0%',
    vectorData: [
      { name: 'Web 400 Bad Request (Rule 31101)', value: 23233, pct: '82.8', color: '#f43f5e' },
      { name: 'High POST Bot Flood (Rule 31533)', value: 4413, pct: '15.7', color: '#f59e0b' },
      { name: 'Web Exploit (CGI/SQLi Rule 31110)', value: 194, pct: '0.7', color: '#8b5cf6' },
      { name: 'Recon / Multi-400 Scan (Rule 31151)', value: 156, pct: '0.6', color: '#0284c7' },
      { name: 'SSH & Auth Brute Force (5710/5503)', value: 15, pct: '0.1', color: '#10b981' }
    ],
    geoData: [
      { name: 'Global Public IPs (Asia/EU)', value: 32, pct: '80.0', color: '#0284c7' },
      { name: 'Europe & Russia (VPS/Tor)', value: 4, pct: '10.0', color: '#f43f5e' },
      { name: 'United States (Cloud VPS)', value: 3, pct: '7.5', color: '#f59e0b' },
      { name: 'Indonesia (Public IP)', value: 1, pct: '2.5', color: '#10b981' }
    ],
    mitreData: [
      { name: 'Initial Access (T1190 - Public Web)', value: 23427, pct: '83.5', color: '#f43f5e' },
      { name: 'Impact / Botnet (T1499 - DoS POST)', value: 4413, pct: '15.7', color: '#f59e0b' },
      { name: 'Reconnaissance (T1595 - Web Scan)', value: 156, pct: '0.6', color: '#0284c7' }
    ],
    statusData: [
      { name: 'Auto-Blocked (Active Response / Drop)', value: 38, pct: '95.0', color: '#10b981' },
      { name: 'Pending SOC Triage', value: 2, pct: '5.0', color: '#f43f5e' }
    ]
  }
};

// Global aggregate dataset across all tenants for Attack (100% Exact to PostgreSQL 640,151 events)
const GLOBAL_ATTACK_DATA = {
  tenantId: 'ALL',
  name: 'Seluruh Tenant (All Multi-Tenants)',
  hostsCount: 54,
  attackTotal: 640151,
  ipTotal: 780,
  blockRate: '92.1%',
  vectorData: [
    { name: 'Web 400 Bad Request (Rule 31101)', value: 530533, pct: '82.9', color: '#f43f5e' },
    { name: 'High POST Bot Flood (Rule 31533)', value: 107513, pct: '16.8', color: '#f59e0b' },
    { name: 'Recon / Multi-400 Scan (Rule 31151)', value: 866, pct: '0.1', color: '#0284c7' },
    { name: 'Web Exploit (CGI/SQLi Rule 31110)', value: 804, pct: '0.1', color: '#8b5cf6' },
    { name: 'SSH & Auth Brute Force (5710/5503)', value: 220, pct: '0.1', color: '#10b981' },
    { name: 'SSH Auth Success (Rule 5715)', value: 165, pct: '0.1', color: '#64748b' }
  ],
  geoData: [
    { name: 'Global Public IPs (Asia, US, EU)', value: 646, pct: '82.8', color: '#0284c7' },
    { name: 'Europe & Russia (EU/RU VPS/Tor)', value: 67, pct: '8.6', color: '#f43f5e' },
    { name: 'United States (Cloud VPS)', value: 49, pct: '6.3', color: '#f59e0b' },
    { name: 'Indonesia (Public IP)', value: 11, pct: '1.4', color: '#10b981' },
    { name: 'Campus Internal Subnet', value: 7, pct: '0.9', color: '#8b5cf6' }
  ],
  mitreData: [
    { name: 'Initial Access (T1190 - Public Web)', value: 531337, pct: '83.0', color: '#f43f5e' },
    { name: 'Impact / Botnet (T1499 - DoS POST)', value: 107513, pct: '16.8', color: '#f59e0b' },
    { name: 'Reconnaissance (T1595 - Web Scan)', value: 866, pct: '0.1', color: '#0284c7' },
    { name: 'Credential Access (T1110 - Brute)', value: 220, pct: '0.1', color: '#8b5cf6' },
    { name: 'Command & Control / Auth (T1071)', value: 215, pct: '0.1', color: '#10b981' }
  ],
  statusData: [
    { name: 'Auto-Blocked (Active Response / Drop)', value: 718, pct: '92.1', color: '#10b981' },
    { name: 'Pending SOC Triage', value: 48, pct: '6.2', color: '#f43f5e' },
    { name: 'Whitelisted / Internal Probe', value: 14, pct: '1.7', color: '#64748b' }
  ]
};

// Real live incidents from PostgreSQL telemetry
export default function AttackOverview({
  theme = 'dark',
  selectedTenant = 'ALL',
  timeRange = 'All Time'
}) {
  const isDark = theme === 'dark' || (typeof document !== 'undefined' && document.documentElement.classList.contains('dark'));

  // Active tenant data selector
  const activeTenantData = useMemo(() => {
    if (selectedTenant && selectedTenant !== 'ALL' && selectedTenant !== 'all') {
      return TENANT_ATTACK_DATASETS[selectedTenant] || GLOBAL_ATTACK_DATA;
    }
    return GLOBAL_ATTACK_DATA;
  }, [selectedTenant]);

  // Active slice state for interactive chart highlight
  const [activeSlice, setActiveSlice] = useState(null);

  const handleSliceClick = (tenantId, chartName, entry) => {
    if (activeSlice && activeSlice.tenantId === tenantId && activeSlice.name === entry.name) {
      setActiveSlice(null);
    } else {
      setActiveSlice({ tenantId, chartName, name: entry.name, color: entry.color });
    }
  };
  // Helper: Render Recharts Donut Pie Chart Box
  const renderPieChartBox = (tenantId, chartTitle, dataset) => {
    return (
      <div className={`p-5 rounded-xl border flex flex-col justify-between transition-colors min-w-0 shadow-xs h-full ${
        isDark ? 'bg-[#060a12] border-slate-800/80 hover:border-slate-700/80' : 'bg-slate-50/70 border-slate-200 hover:border-slate-300'
      }`}>
        {/* Header Kartu: Judul di Kiri */}
        <div className="flex items-center justify-between pb-2.5 border-b border-slate-200 dark:border-slate-800/80 mb-3 shrink-0">
          <div className="min-w-0 pr-2">
            <span className={`text-xs font-bold uppercase tracking-wider block truncate ${
              isDark ? 'text-slate-200' : 'text-slate-800'
            }`}>
              {chartTitle}
            </span>
          </div>
        </div>

        {/* Donut Chart di Sisi Kiri, Legend di Sisi Kanan (Side-by-Side Proposional) */}
        <div className="flex items-center justify-center gap-5 my-auto py-2 flex-1 min-h-0">
          {/* Donut Ring: Radius 46-68px for balanced proportional layout */}
          <div className="w-36 h-36 lg:w-40 lg:h-40 xl:w-44 xl:h-44 shrink-0 relative flex items-center justify-center">
            <ResponsiveContainer width="100%" height="100%">
              <PieChart>
                <Pie
                  data={dataset}
                  cx="50%"
                  cy="50%"
                  innerRadius={46}
                  outerRadius={68}
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
                          filter: isSelected ? 'drop-shadow(0 0 6px rgba(244, 63, 94, 0.7))' : 'none',
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
          <div className="flex-1 min-w-0 space-y-1.5 overflow-y-auto max-h-full py-1">
            {dataset.map((item, idx) => {
              const isSelected = activeSlice && activeSlice.tenantId === tenantId && activeSlice.name === item.name;
              return (
                <div
                  key={`legend-${tenantId}-${chartTitle}-${idx}`}
                  onClick={() => handleSliceClick(tenantId, chartTitle, item)}
                  className={`flex items-center justify-between text-xs cursor-pointer py-1 px-2 rounded-md transition-colors ${
                    isSelected
                      ? 'bg-rose-500/15 font-semibold text-rose-400'
                      : isDark
                        ? 'text-slate-300 hover:bg-slate-800/60'
                        : 'text-slate-700 hover:bg-slate-200/60'
                  }`}
                  title={`${item.name}: ${Number(item.value).toLocaleString()} (${item.pct}%)`}
                >
                  <div className="flex items-center gap-2 min-w-0 truncate pr-1">
                    <span 
                      className="w-2.5 h-2.5 rounded-full shrink-0" 
                      style={{ backgroundColor: item.color || PALETTE[idx % PALETTE.length] }} 
                    />
                    <span className="truncate text-[11.5px]">{item.name}</span>
                  </div>
                  <div className="text-[11px] font-mono shrink-0 flex items-center gap-1.5 ml-2">
                    <span className="font-semibold">{Number(item.value).toLocaleString()}</span>
                    <span className="text-slate-400 text-[10px]">({item.pct}%)</span>
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
    <div className="w-full h-[calc(100vh-140px)] min-h-[580px] flex flex-col">

      {/* ========================================================================= */}
      {/* 2x2 MATRIX CHARTS (4 KUADRAN SERANGAN INTRUSI FULL-PROPORTIONAL)          */}
      {/* ========================================================================= */}
      <div className="grid grid-cols-2 grid-rows-2 gap-4 w-full h-full flex-1 min-h-0">
        {/* Card 1: Top-Left -> ATTACK VECTORS & EXPLOITS */}
        {renderPieChartBox(
          activeTenantData.tenantId,
          'ATTACK VECTORS & EXPLOITS',
          activeTenantData.vectorData
        )}

        {/* Card 2: Top-Right -> ATTACKER ORIGIN / GEOLOCATION */}
        {renderPieChartBox(
          activeTenantData.tenantId,
          'ATTACKER ORIGIN / GEOLOCATION',
          activeTenantData.geoData
        )}

        {/* Card 3: Bottom-Left -> MITRE ATT&CK TACTICS MATRIX */}
        {renderPieChartBox(
          activeTenantData.tenantId,
          'MITRE ATT&CK TACTICS MATRIX',
          activeTenantData.mitreData
        )}

        {/* Card 4: Bottom-Right -> ACTIVE RESPONSE & BLOCK STATUS */}
        {renderPieChartBox(
          activeTenantData.tenantId,
          'ACTIVE RESPONSE & BLOCK STATUS',
          activeTenantData.statusData
        )}
      </div>

    </div>
  );
}
