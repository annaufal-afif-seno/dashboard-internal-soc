import React, { useState, useEffect } from 'react';
import { 
  Shield, Activity, RefreshCw, CheckCircle2, AlertTriangle, 
  Layers, Sliders, Database, Cpu, Radio, GitBranch, ArrowRight
} from 'lucide-react';
import { PieChart, Pie, Cell, ResponsiveContainer } from 'recharts';

export default function SocKpiPerformanceView({ initialCategory = 'system', theme = 'light' }) {
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [kpiData, setKpiData] = useState(null);
  const [activeTab, setActiveTab] = useState(initialCategory);
  const [lastRefreshed, setLastRefreshed] = useState(new Date());

  useEffect(() => {
    if (initialCategory) {
      setActiveTab(initialCategory);
    }
  }, [initialCategory]);

  const fetchKpiMetrics = async (isBg = false) => {
    try {
      if (!isBg) setLoading(true);
      else setRefreshing(true);
      const res = await fetch('/api/kpi/metrics');
      if (res.ok) {
        const data = await res.json();
        setKpiData(data);
        setLastRefreshed(new Date());
      }
    } catch (err) {
      console.warn('Failed to load KPI metrics:', err);
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  };

  useEffect(() => {
    fetchKpiMetrics();
    const timer = setInterval(() => fetchKpiMetrics(true), 60000);
    return () => clearInterval(timer);
  }, []);

  const formatSec = (seconds) => {
    if (seconds == null || isNaN(seconds)) return 'N/A';
    const s = Math.abs(Math.round(seconds));
    if (s < 60) return `${s}s`;
    if (s < 3600) return `${Math.floor(s / 60)}m ${s % 60}s`;
    const h = Math.floor(s / 3600);
    const m = Math.floor((s % 3600) / 60);
    return `${h}h ${m}m`;
  };

  const computeSlaGauge = (actualVal, targetMax, isPercentage = false, inverse = false) => {
    let pct = 0;
    if (isPercentage) {
      pct = Math.min(100, Math.max(0, actualVal));
    } else {
      pct = targetMax > 0 ? Math.min(100, Math.round((actualVal / targetMax) * 100)) : 50;
    }

    let color = '#059669'; // Emerald-600
    if (inverse) {
      if (pct < 70) color = '#E11D48';
      else if (pct < 85) color = '#D97706';
      else color = '#059669';
    } else {
      if (pct > 90) color = '#E11D48';
      else if (pct > 75) color = '#D97706';
      else color = '#059669';
    }

    return { pct, color };
  };

  // Metric values from API
  const mttdSec = kpiData?.raw?.mttd_sec ?? 62;
  const mttcSec = kpiData?.raw?.mttc_agg_sec ?? 1036;
  const mttaiSec = kpiData?.raw?.mttai_sec ?? 24;
  const ataPct = kpiData?.raw?.ata_pct ?? 92.4;
  const nrrPct = kpiData?.raw?.nrr_pct ?? 89.4;
  const mttaSec = kpiData?.raw?.mtta_sec ?? 320;
  const mttiSec = kpiData?.raw?.mtti_sec ?? 1140;
  const mttgtSec = kpiData?.raw?.mttgt_sec ?? 4800;
  const mttvSec = kpiData?.raw?.mttv_sec ?? 1800;
  const mttrSec = kpiData?.raw?.mttr_sec ?? 5400;
  const fprPct = kpiData?.raw?.fpr_pct ?? 22.5;
  const rtrPct = kpiData?.raw?.rtr_pct ?? 2.1;
  const mttciSec = kpiData?.raw?.mttci_sec ?? 180;
  const stageVelSec = kpiData?.raw?.stage_vel_sec ?? 720;
  const campDwellSec = kpiData?.raw?.campaign_dwell_sec ?? 1440;
  const mttfSec = kpiData?.raw?.mttf_sec ?? 2700;
  const mttpSec = kpiData?.raw?.mttp_sec ?? 3600;
  const e2eSec = kpiData?.raw?.e2e_tuning_sec ?? 14400;

  // 18 KPIs grouped into 3 core categories
  const featureMetrics = {
    // 1. System Process (6 KPIs: Ingest, Dedup/Clustering, Correlation, Stage Velocity, Campaign Dwell, E2E Tuning)
    system: [
      {
        id: 'MTTD',
        fullName: 'MTTD (Mean Time to Detect)',
        value: formatSec(mttdSec),
        target: '< 2m',
        desc: 'Log transmission latency from agent devices until ingestion into the SOC pipeline.',
        start: 'Suspicious activity initiated on the victim machine or server',
        end: 'Telemetry log successfully received and stored in SOC storage',
        gauge: computeSlaGauge(mttdSec, 120)
      },
      {
        id: 'MTTC',
        fullName: 'MTTC (Mean Time to Cluster)',
        value: formatSec(mttcSec),
        target: '< 20m',
        desc: 'Duration to consolidate hundreds of raw alerts into a single incident cluster.',
        start: 'Raw event first enters the processing pipeline queue',
        end: 'Alert stream aggregated into a consolidated incident package',
        gauge: computeSlaGauge(mttcSec, 1200)
      },
      {
        id: 'MTTCI',
        fullName: 'MTTCI (Mean Time to Correlate Incident)',
        value: formatSec(mttciSec),
        target: '< 5m',
        desc: 'Correlation engine speed in synthesizing discrete events into an attack campaign.',
        start: 'Initial reconnaissance or exploit beacon registered on network',
        end: 'Multi-stage attack pattern correlated into unified incident graph',
        gauge: computeSlaGauge(mttciSec, 300)
      },
      {
        id: 'STAGE-VEL',
        fullName: 'Stage Velocity (Incident Stage Velocity)',
        value: formatSec(stageVelSec),
        target: '< 30m',
        desc: 'Adversary transition speed across progressive MITRE ATT&CK kill-chain stages.',
        start: 'Adversary establishes initial beachhead foothold',
        end: 'Adversary escalates privileges or executes lateral movement',
        gauge: computeSlaGauge(stageVelSec, 1800)
      },
      {
        id: 'CAMP-DWELL',
        fullName: 'Campaign Dwell Time (Campaign Dwell Time)',
        value: formatSec(campDwellSec),
        target: '< 30m',
        desc: 'Time latent threat remains active prior to correlation into an active campaign.',
        start: 'Adversary persistence mechanism planted on enterprise asset',
        end: 'Correlation graph detects synchronized multi-host campaign',
        gauge: computeSlaGauge(campDwellSec, 1800)
      },
      {
        id: 'E2E-TUNING',
        fullName: 'E2E-Tuning (End-to-End Tuning Cycle)',
        value: formatSec(e2eSec),
        target: '< 8h',
        desc: 'Full lifecycle from first noisy alert occurrence to live active enforcement in Wazuh.',
        start: 'Noisy recurring alert first causes triage queue friction',
        end: 'Tuned suppression rule officially enforced in Wazuh engine',
        gauge: computeSlaGauge(e2eSec, 28800)
      }
    ],

    // 2. AI Triage (3 KPIs: MTTAI, ATA, NRR)
    ai: [
      {
        id: 'MTTAI',
        fullName: 'MTTAI (Mean Time to AI Triage)',
        value: formatSec(mttaiSec),
        target: '< 30s',
        desc: 'Evaluation duration for machine learning to score incident threat and impact.',
        start: 'Aggregated incident package produced by clustering pipeline',
        end: 'AI finishes scoring risk, prioritization, and publishes ticket',
        gauge: computeSlaGauge(mttaiSec, 30)
      },
      {
        id: 'ATA',
        fullName: 'ATA (AI Triage Accuracy Rate)',
        value: `${ataPct}%`,
        target: '> 90%',
        desc: 'Accuracy rate of AI severity assessments validated against human analyst findings.',
        start: 'Initial AI risk decision and recommended verdict',
        end: 'Final verdict validation by tier-1 / tier-2 human security analyst',
        gauge: computeSlaGauge(ataPct, 100, true, true)
      },
      {
        id: 'NRR',
        fullName: 'NRR (Noise Reduction Ratio)',
        value: `${nrrPct}%`,
        target: '> 85%',
        desc: 'Percentage of non-actionable alert noise suppressed before reaching analysts.',
        start: 'Total high-volume raw alerts detected across endpoints',
        end: 'Filtered high-fidelity incident tickets routed to triage queues',
        gauge: computeSlaGauge(nrrPct, 100, true, true)
      }
    ],

    // 3. Human Triage (9 KPIs: MTTA, MTTI, MTTGT, MTTV, MTTR, FPR, RTR, MTTF, MTTP)
    human: [
      {
        id: 'MTTA',
        fullName: 'MTTA (Mean Time to Acknowledge)',
        value: formatSec(mttaSec),
        target: '< 15m',
        desc: 'Analyst response speed to claim and acknowledge a pending triage ticket.',
        start: 'New incident ticket appears in active queue awaiting claim',
        end: 'Analyst clicks claim and initiates active ticket handling',
        gauge: computeSlaGauge(mttaSec, 900)
      },
      {
        id: 'MTTI',
        fullName: 'MTTI (Mean Time to Investigate)',
        value: formatSec(mttiSec),
        target: '< 30m',
        desc: 'Time spent by analyst reviewing forensic evidence to reach an investigative verdict.',
        start: 'Analyst starts evaluating process, network, and host telemetry',
        end: 'Analyst concludes assessment and determines True/False positive',
        gauge: computeSlaGauge(mttiSec, 1800)
      },
      {
        id: 'MTTGT',
        fullName: 'MTTGT (Mean Time to Ground Truth Review)',
        value: formatSec(mttgtSec),
        target: '< 4h',
        desc: 'Review turnaround by senior staff on ambiguous incidents for ML model calibration.',
        start: 'Disputed or borderline ticket submitted to senior audit queue',
        end: 'Lead analyst assigns validated ground truth verdict label',
        gauge: computeSlaGauge(mttgtSec, 14400)
      },
      {
        id: 'MTTV',
        fullName: 'MTTV (Mean Time to Verdict Approval)',
        value: formatSec(mttvSec),
        target: '< 1h',
        desc: 'Escalation turnaround for SOC Manager sign-off on remediation actions.',
        start: 'Triage assessment submitted to SOC Manager for verification',
        end: 'SOC Manager formally approves proposed action and playbook',
        gauge: computeSlaGauge(mttvSec, 3600)
      },
      {
        id: 'MTTR',
        fullName: 'MTTR (Mean Time to Resolve)',
        value: formatSec(mttrSec),
        target: '< 2h',
        desc: 'Total elapsed time from threat detection to successful remediation and ticket closure.',
        start: 'Adversary behavior first detected by defense sensors',
        end: 'Threat eradicated, endpoints remediated, and ticket closed',
        gauge: computeSlaGauge(mttrSec, 7200)
      },
      {
        id: 'FPR',
        fullName: 'FPR (False Positive Rate)',
        value: `${fprPct}%`,
        target: '< 10%',
        desc: 'Proportion of escalated tickets attributed to benign administrative activity.',
        start: 'Total investigated and completed security incident alerts',
        end: 'Confirmed benign activity incorrectly triggered as an alert',
        gauge: computeSlaGauge(fprPct, 100, true)
      },
      {
        id: 'RTR',
        fullName: 'RTR (Re-opened Ticket Rate)',
        value: `${rtrPct}%`,
        target: '< 5%',
        desc: 'Percentage of resolved tickets reopened due to recurrence or persistence.',
        start: 'Security incident ticket previously closed as resolved',
        end: 'Ticket reopened due to recurring anomalous execution trace',
        gauge: computeSlaGauge(rtrPct, 10, true)
      },
      {
        id: 'MTTF',
        fullName: 'MTTF (Time to Rule Formulation)',
        value: formatSec(mttfSec),
        target: '< 2h',
        desc: 'Speed in drafting suppression filters once repeated false alarms are identified.',
        start: 'Recurring alert verified as authorized benign behavior',
        end: 'Suppression and whitelist policy draft formulated',
        gauge: computeSlaGauge(mttfSec, 7200)
      },
      {
        id: 'MTTP',
        fullName: 'MTTP (Time to Policy Approval)',
        value: formatSec(mttpSec),
        target: '< 4h',
        desc: 'Governance review latency for management to audit and approve suppression rules.',
        start: 'Filter rule submitted for formal policy review',
        end: 'SOC Lead approves rule deployment into production engine',
        gauge: computeSlaGauge(mttpSec, 14400)
      }
    ]
  };

  const currentMetrics = featureMetrics[activeTab] || featureMetrics.system;

  return (
    <div 
      className="space-y-4 w-full"
      style={{ fontFamily: '"Trebuchet MS", "Lucida Grande", "Lucida Sans Unicode", "Lucida Sans", Tahoma, sans-serif' }}
    >
      {/* 2-Column Grid */}
      <div className="grid grid-cols-2 gap-5 w-full">
        {currentMetrics.map((kpi) => {
          const usedPct = kpi.gauge?.pct ?? 50;
          const remainingPct = Math.max(0, 100 - usedPct);
          const donutColor = kpi.gauge?.color ?? '#059669';

          const pieData = [
            { name: 'Used', value: usedPct, fill: donutColor },
            { name: 'Remaining', value: remainingPct, fill: '#E2E8F0' }
          ];

          return (
            <div 
              key={kpi.id}
              className="bg-white rounded-2xl border border-slate-200/90 shadow-sm p-6 hover:shadow-md transition-all flex flex-col justify-between"
            >
              {/* Header: Metric Title */}
              <div className="border-b border-slate-100 pb-3">
                <div>
                  <h3 className="text-base font-bold text-slate-800 tracking-tight">
                    {kpi.fullName}
                  </h3>
                </div>
              </div>

              {/* Middle Section: Value, SLA Target, Description & Donut Gauge */}
              <div className="my-5 flex items-center justify-between gap-4">
                <div className="space-y-2 flex-1">
                  <div className="flex items-baseline gap-3">
                    <span className="text-3xl font-extrabold text-slate-900 tracking-tight font-sans">
                      {kpi.value}
                    </span>
                    <span className="text-xs font-semibold px-2 py-0.5 rounded-md bg-slate-100 text-slate-600 border border-slate-200/80">
                      Target SLA: {kpi.target}
                    </span>
                  </div>
                  <p className="text-[13px] text-slate-500 leading-relaxed font-normal pr-2">
                    {kpi.desc}
                  </p>
                </div>

                {/* Donut Chart Gauge */}
                <div className="relative w-24 h-24 shrink-0 flex items-center justify-center p-1 bg-slate-50/50 rounded-2xl border border-slate-100">
                  <ResponsiveContainer width="100%" height="100%">
                    <PieChart>
                      <Pie
                        data={pieData}
                        innerRadius={28}
                        outerRadius={40}
                        startAngle={90}
                        endAngle={-270}
                        dataKey="value"
                        stroke="none"
                      >
                        <Cell key="used" fill={donutColor} />
                        <Cell key="remaining" fill="#E2E8F0" />
                      </Pie>
                    </PieChart>
                  </ResponsiveContainer>
                  <div className="absolute flex flex-col items-center justify-center pointer-events-none">
                    <span className="text-xs font-extrabold text-slate-800 leading-none">
                      {usedPct}%
                    </span>
                    <span className="text-[8.5px] font-bold text-slate-400 uppercase tracking-tighter mt-0.5">
                      SLA
                    </span>
                  </div>
                </div>
              </div>

              {/* Bottom Section: Start & Finish Cards */}
              <div className="pt-3 border-t border-slate-100/90 bg-slate-50/70 -mx-6 -mb-6 p-4 rounded-b-2xl">
                <div className="grid grid-cols-2 gap-3 text-xs">
                  <div className="p-2.5 rounded-xl bg-white border border-slate-200/60 shadow-[0_1px_2px_rgba(0,0,0,0.02)]">
                    <span className="text-[10px] font-bold text-slate-400 uppercase tracking-wider block mb-1">
                      Start
                    </span>
                    <p className="text-slate-700 font-medium text-[11.5px] leading-snug">
                      {kpi.start}
                    </p>
                  </div>

                  <div className="p-2.5 rounded-xl bg-white border border-slate-200/60 shadow-[0_1px_2px_rgba(0,0,0,0.02)]">
                    <span className="text-[10px] font-bold text-slate-400 uppercase tracking-wider block mb-1">
                      End
                    </span>
                    <p className="text-slate-700 font-medium text-[11.5px] leading-snug">
                      {kpi.end}
                    </p>
                  </div>
                </div>
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}
