// Enterprise Role-Based Access Control (RBAC) & Separation of Duties (SoD) Engine
// Synchronized with Application Sidebar Navigation and Security Operations Governance

export const TAB_TO_FEATURE_MAP = {
  analytics: 'analytics',
  raw_alerts: 'raw_alerts',
  triage: 'ticket_queue',
  verified_tp: 'verified_tp',
  threat_campaigns: 'threat_campaigns',
  groundtruth_queue: 'groundtruth_queue',
  ground_truth_review: 'ground_truth_review',
  suppression_inbox: 'ground_truth_review',
  suppression_rules: 'policy_bundle',
  suppression_groups: 'policy_bundle',
  suppression_audit: 'audit_log_grc',
  system_rbac: 'account_rbac',
  system_database: 'database_health',
  system_api: 'api_threat_intel'
};

export const normalizeRole = (role) => {
  if (!role) return 'SOC_ANALYST';
  const clean = String(role).trim().toUpperCase().replace(/\s+/g, '_');
  if (clean === 'SOC_LEADER') return 'SOC_LEAD';
  return clean;
};

export const syncMatrixWithBlueprint = (savedList, blueprint) => {
  if (!Array.isArray(blueprint) || blueprint.length === 0) return savedList || [];
  const savedRoleMap = {};
  if (Array.isArray(savedList)) {
    savedList.forEach(row => {
      const key = row.id || row.action;
      if (key) savedRoleMap[key] = row.roles;
      // Handle legacy aliases & typo fixes
      if (row.action === 'Verified True Positives' || row.action === 'Verifed Threat' || row.id === 'verified_tp') {
        savedRoleMap['verified_tp'] = row.roles;
      }
      if (row.action === 'Threat Campaigns' || row.id === 'threat_campaigns') {
        savedRoleMap['threat_campaigns'] = row.roles;
      }
      if (row.action === 'Suppression Proposal' || row.id === 'suppression_proposal' || row.id === 'ground_truth_review') {
        savedRoleMap['ground_truth_review'] = row.roles;
      }
      if (row.action === 'Audit Log Supresi (GRC)' || row.id === 'audit_log_grc') {
        savedRoleMap['audit_log_grc'] = row.roles;
      }
    });
  }

  return blueprint.map(def => {
    const savedRoles = savedRoleMap[def.id] || savedRoleMap[def.action];
    return {
      ...def,
      roles: savedRoles ? Object.fromEntries(
        Object.entries({ ...def.roles, ...savedRoles }).map(([r, val]) => [
          r,
          (val === 'READ_WRITE' || val === 'READ_ONLY') ? val : 'NO_ACCESS'
        ])
      ) : def.roles
    };
  });
};

export const getRbacMatrix = (initialFallback = null) => {
  try {
    const saved = localStorage.getItem('wazuh_rbac_permissions_matrix_v3')
      || localStorage.getItem('wazuh_rbac_permissions_matrix_v2')
      || localStorage.getItem('wazuh_rbac_permissions_matrix');
    if (saved) {
      const parsed = JSON.parse(saved);
      if (Array.isArray(parsed) && parsed.length > 0) {
        if (initialFallback && Array.isArray(initialFallback) && initialFallback.length > 0) {
          const synced = syncMatrixWithBlueprint(parsed, initialFallback);
          return synced;
        }
        return parsed;
      }
    }
  } catch (e) {
    console.warn('Failed to read RBAC matrix from storage:', e);
  }
  return initialFallback || [];
};

export const getFeaturePermission = (userRole, featureId, matrixFallback = null) => {
  const normRole = normalizeRole(userRole);
  if (normRole === 'ADMIN') return 'READ_WRITE';

  const matrix = getRbacMatrix(matrixFallback);
  const feature = matrix.find(item => item.id === featureId);
  if (!feature || !feature.roles) {
    // Default safe fallback if matrix not initialized
    if (featureId === 'account_rbac') return 'NO_ACCESS';
    if (featureId === 'policy_bundle' && (normRole === 'SOC_ANALYST' || normRole === 'SOC_DEVELOPER')) return 'NO_ACCESS';
    if (featureId === 'threat_campaigns' && normRole === 'SOC_DEVELOPER') return 'READ_ONLY';
    return 'READ_ONLY';
  }

  return feature.roles[normRole] || 'NO_ACCESS';
};

export const getTabPermission = (userRole, tabId, matrixFallback = null) => {
  const featureId = TAB_TO_FEATURE_MAP[tabId] || tabId;
  return getFeaturePermission(userRole, featureId, matrixFallback);
};

export const canAccessTab = (userRole, tabId, matrixFallback = null) => {
  const perm = getTabPermission(userRole, tabId, matrixFallback);
  return perm === 'READ_WRITE' || perm === 'READ_ONLY';
};

export const isTabReadOnly = (userRole, tabId, matrixFallback = null) => {
  const perm = getTabPermission(userRole, tabId, matrixFallback);
  return perm === 'READ_ONLY';
};
