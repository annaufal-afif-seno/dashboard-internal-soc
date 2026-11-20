/**
 * Unified 6 Pure Category & Functional Subcategories Taxonomy Constants (v5.0)
 * Single source of truth for all frontend components.
 * Strictly 6 categories:
 * 1. Attack
 * 2. Vulnerability
 * 3. Configuration / Compliance
 * 4. Identity / Access
 * 5. Malware
 * 6. System / Availability
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

// ── Subcategories per category (Exact 20 OCSF / NIST / MITRE Subcategories) ───
export const SUBCATEGORIES = {
  [PRIMARY_CATEGORY.ATTACK]: [
    'Web Attack',
    'Exploitation / RCE',
    'Recon / Scan',
    'Command & Control (C2)',
    'Lateral Movement',
  ],
  [PRIMARY_CATEGORY.VULNERABILITY]: [
    'CVE Detected',
    'Missing Patch / Outdated Software',
  ],
  [PRIMARY_CATEGORY.CONFIGURATION_COMPLIANCE]: [
    'SCA / CIS Benchmark',
    'File Integrity (FIM)',
    'Policy Violation',
  ],
  [PRIMARY_CATEGORY.IDENTITY_ACCESS]: [
    'Auth Success',
    'Auth Failure',
    'Auth Anomaly',
    'Privilege Escalation',
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

// ── Canonical Normalization Function (Single Source of Truth) ─────────────────
export const mapTo6CategoryTaxonomy = (rawCat, rawSubcat) => {
  const cat = String(rawCat || '').trim();
  const sub = String(rawSubcat || '').trim();
  const catUpper = cat.toUpperCase();
  const subLower = sub.toLowerCase();

  // If already exact match
  if (PRIMARY_CATEGORY_ALL.includes(cat)) {
    // Check if subcategory is valid
    const validSubs = SUBCATEGORIES[cat] || [];
    if (validSubs.includes(sub)) {
      return { category: cat, subcategory: sub };
    }
    // Subcategory tolerance aliases
    if (subLower.includes('command') || subLower.includes('c2')) return { category: cat, subcategory: 'Command & Control (C2)' };
    if (subLower.includes('patch') || subLower.includes('outdated')) return { category: cat, subcategory: 'Missing Patch / Outdated Software' };
    if (validSubs.length > 0) return { category: cat, subcategory: validSubs[0] };
  }

  // 1. Attack
  if (catUpper.includes('WEB_ATTACK') || catUpper.includes('EXPLOIT') || catUpper.includes('RCE') ||
      catUpper.includes('DISCOVERY') || catUpper.includes('C2') || catUpper.includes('COMMAND') ||
      catUpper.includes('LATERAL') || catUpper.includes('EXECUTION') || catUpper.includes('PERSISTENCE') ||
      catUpper.includes('INITIAL_ACCESS') || catUpper.includes('ATTACK')) {
    if (subLower.includes('exploit') || subLower.includes('rce') || catUpper.includes('EXECUTION')) return { category: 'Attack', subcategory: 'Exploitation / RCE' };
    if (subLower.includes('scan') || subLower.includes('recon') || catUpper.includes('DISCOVERY')) return { category: 'Attack', subcategory: 'Recon / Scan' };
    if (subLower.includes('c2') || subLower.includes('command') || subLower.includes('control') || catUpper.includes('COMMAND')) return { category: 'Attack', subcategory: 'Command & Control (C2)' };
    if (subLower.includes('lateral') || subLower.includes('move') || catUpper.includes('LATERAL')) return { category: 'Attack', subcategory: 'Lateral Movement' };
    return { category: 'Attack', subcategory: 'Web Attack' };
  }

  // 2. Vulnerability
  if (catUpper.includes('VULNERABILITY') || catUpper.includes('CVE') || catUpper.includes('PATCH') || catUpper.includes('SOFTWARE_CVE')) {
    if (subLower.includes('patch') || subLower.includes('outdated') || subLower.includes('package') || subLower.includes('mitigated')) {
      return { category: 'Vulnerability', subcategory: 'Missing Patch / Outdated Software' };
    }
    return { category: 'Vulnerability', subcategory: 'CVE Detected' };
  }

  // 3. Configuration / Compliance
  if (catUpper.includes('CONFIGURATION') || catUpper.includes('COMPLIANCE') || catUpper.includes('SCA') ||
      catUpper.includes('CIS') || catUpper.includes('FIM') || catUpper.includes('INTEGRITY') ||
      catUpper.includes('POLICY') || catUpper.includes('SECURITY_POSTURE')) {
    if (subLower.includes('fim') || subLower.includes('integrity') || subLower.includes('checksum') || catUpper.includes('FILE_INTEGRITY')) {
      return { category: 'Configuration / Compliance', subcategory: 'File Integrity (FIM)' };
    }
    if (subLower.includes('policy') || subLower.includes('violation')) {
      return { category: 'Configuration / Compliance', subcategory: 'Policy Violation' };
    }
    return { category: 'Configuration / Compliance', subcategory: 'SCA / CIS Benchmark' };
  }

  // 4. Identity / Access
  if (catUpper.includes('AUTH') || catUpper.includes('IDENTITY') || catUpper.includes('LOGIN') ||
      catUpper.includes('PAM') || catUpper.includes('SSHD') || catUpper.includes('CREDENTIAL') ||
      catUpper.includes('PRIVILEGE') || subLower.includes('auth') || subLower.includes('login')) {
    if (subLower.includes('success') || catUpper.includes('AUTH_SUCCESS') || catUpper.includes('LOGIN_SUCCESS')) {
      return { category: 'Identity / Access', subcategory: 'Auth Success' };
    }
    if (subLower.includes('privilege') || catUpper.includes('PRIVILEGE_ESCALATION')) {
      return { category: 'Identity / Access', subcategory: 'Privilege Escalation' };
    }
    if (subLower.includes('anomaly') || subLower.includes('brute') || subLower.includes('spray')) {
      return { category: 'Identity / Access', subcategory: 'Auth Anomaly' };
    }
    return { category: 'Identity / Access', subcategory: 'Auth Failure' };
  }

  // 5. Malware
  if (catUpper.includes('MALWARE') || catUpper.includes('RANSOMWARE') || catUpper.includes('VIRUS') ||
      catUpper.includes('TROJAN') || catUpper.includes('ROOTKIT') || catUpper.includes('YARA') ||
      catUpper.includes('ENDPOINT_THREAT')) {
    if (subLower.includes('ransom') || catUpper.includes('RANSOMWARE')) return { category: 'Malware', subcategory: 'Ransomware' };
    if (subLower.includes('rootkit') || subLower.includes('backdoor') || subLower.includes('shell')) return { category: 'Malware', subcategory: 'Rootkit / Backdoor' };
    return { category: 'Malware', subcategory: 'Virus / Trojan (YARA)' };
  }

  // 6. System / Availability
  if (catUpper.includes('CLOUD') || catUpper.includes('CONTAINER') || subLower.includes('docker') || subLower.includes('k8s')) {
    return { category: 'System / Availability', subcategory: 'Cloud / Container Event' };
  }
  if (catUpper.includes('WEB_OPERATIONAL') || subLower.includes('404') || subLower.includes('400') || subLower.includes('nginx access')) {
    return { category: 'System / Availability', subcategory: 'Web Operational' };
  }

  return { category: 'System / Availability', subcategory: 'Service Health / Error' };
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
  if (s.includes('anomaly') || s.includes('attack') || s.includes('cve') || s.includes('fail')) return 'bg-amber-500/20 text-amber-400 border-amber-500/30';
  if (s.includes('fim') || s.includes('benchmark')) return 'bg-violet-500/20 text-violet-400 border-violet-500/30';
  return 'bg-slate-500/20 text-slate-400 border-slate-500/30';
};
