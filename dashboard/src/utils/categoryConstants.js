/**
 * Unified 6 Pure Category & Functional Subcategories Taxonomy Constants (v5.0)
 * Single source of truth for all frontend components.
 * Strictly 6 categories:
 * - Attack
 * - Vulnerability
 * - Configuration / Compliance
 * - Identity / Access
 * - Malware
 * - System / Availability
 */

// ── Primary Categories ────────────────────────────────────────────────────────
export const PRIMARY_CATEGORY = {
  ATTACK:                   'Attack',
  VULNERABILITY:            'Vulnerability',
  CONFIGURATION_COMPLIANCE: 'Configuration / Compliance',
  IDENTITY_ACCESS:          'Identity / Access',
  MALWARE:                  'Malware',
  SYSTEM_AVAILABILITY:      'System / Availability',
};

export const PRIMARY_CATEGORY_ALL = Object.values(PRIMARY_CATEGORY);

// ── UI Display labels ─────────────────────────────────────────────────────────
export const CATEGORY_LABEL = {
  [PRIMARY_CATEGORY.ATTACK]:                   'Attack',
  [PRIMARY_CATEGORY.VULNERABILITY]:            'Vulnerability',
  [PRIMARY_CATEGORY.CONFIGURATION_COMPLIANCE]: 'Configuration / Compliance',
  [PRIMARY_CATEGORY.IDENTITY_ACCESS]:          'Identity / Access',
  [PRIMARY_CATEGORY.MALWARE]:                  'Malware',
  [PRIMARY_CATEGORY.SYSTEM_AVAILABILITY]:      'System / Availability',
};

// ── Colors per category ───────────────────────────────────────────────────────
export const CATEGORY_COLOR = {
  [PRIMARY_CATEGORY.ATTACK]:                   '#f43f5e', // rose-500
  [PRIMARY_CATEGORY.MALWARE]:                  '#e11d48', // red-600
  [PRIMARY_CATEGORY.VULNERABILITY]:            '#f97316', // orange-500
  [PRIMARY_CATEGORY.CONFIGURATION_COMPLIANCE]: '#8b5cf6', // violet-500
  [PRIMARY_CATEGORY.IDENTITY_ACCESS]:          '#3b82f6', // blue-500
  [PRIMARY_CATEGORY.SYSTEM_AVAILABILITY]:      '#10b981', // emerald-500
};

// ── Subcategories per category ────────────────────────────────────────────────
export const SUBCATEGORIES = {
  [PRIMARY_CATEGORY.IDENTITY_ACCESS]: [
    'Auth Success',
    'Auth Failure',
    'Auth Anomaly',
    'Privilege Escalation',
  ],
  [PRIMARY_CATEGORY.ATTACK]: [
    'Web Attack',
    'Exploitation / RCE',
    'Recon / Scan',
    'Command & Control',
    'Lateral Movement',
  ],
  [PRIMARY_CATEGORY.VULNERABILITY]: [
    'CVE Detected',
    'Missing Patch / Outdated',
  ],
  [PRIMARY_CATEGORY.CONFIGURATION_COMPLIANCE]: [
    'SCA / CIS Benchmark',
    'File Integrity (FIM)',
    'Policy Violation',
  ],
  [PRIMARY_CATEGORY.MALWARE]: [
    'Ransomware',
    'Rootkit / Backdoor',
    'Virus / Trojan (YARA)',
  ],
  [PRIMARY_CATEGORY.SYSTEM_AVAILABILITY]: [
    'Web Operational',
    'Service Health / Error',
    'Cloud / Container Event',
  ],
};

// ── Helper functions ──────────────────────────────────────────────────────────
export const getCategoryColor = (category) =>
  CATEGORY_COLOR[category] ?? '#64748b';

export const getCategoryLabel = (category) =>
  CATEGORY_LABEL[category] ?? category ?? 'Unknown';

export const getSubcategoryBadgeClass = (subcat) => {
  const s = (subcat || '').toLowerCase();
  if (s.includes('success')) return 'bg-emerald-500/20 text-emerald-400 border-emerald-500/30';
  if (s.includes('exploit') || s.includes('rce') || s.includes('ransomware') || s.includes('c2')) return 'bg-rose-500/20 text-rose-400 border-rose-500/30';
  if (s.includes('anomaly') || s.includes('attack') || s.includes('cve')) return 'bg-amber-500/20 text-amber-400 border-amber-500/30';
  if (s.includes('fim') || s.includes('benchmark')) return 'bg-violet-500/20 text-violet-400 border-violet-500/30';
  return 'bg-slate-500/20 text-slate-400 border-slate-500/30';
};
