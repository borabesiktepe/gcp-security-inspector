const { makeGoogleApiRequest } = require('./gcp-api');

async function evaluateGKE({ credentials, projectId }) {
  const results = [];
  // List all clusters in all locations
  let clusters = [];
  try {
    const url = `https://container.googleapis.com/v1/projects/${projectId}/locations/-/clusters`;
    const resp = await makeGoogleApiRequest(credentials, url);
    clusters = resp.clusters || [];
  } catch (e) {}
  // Helper for N/A
  const na = { total: 0, passed: 0, failed: [] };
  if (clusters.length === 0) {
    // If no clusters, mark all as N/A
    const ruleIds = [
      'disable-client-certs','disable-dashboard','disable-legacy-auth','auto-repair','auto-upgrade','binary-auth','cost-allocation','metadata-server','integrity-monitoring','transparent-encryption','intranode-visibility','private-nodes','secure-boot','vpc-native-routing','workload-identity','cluster-logging','cluster-monitoring','security-posture','restrict-network','prevent-default-sa','labels','shielded-nodes'
    ];
    for (const id of ruleIds) {
      results.push({ id, name: id, passed: true, details: 'No clusters found.', resources: na, notApplicable: true });
    }
    return results;
  }
  // 1. Disable Client Certificates
  let clientCertFail = [];
  clusters.forEach(c => {
    if (c.masterAuth && c.masterAuth.clientCertificateConfig && c.masterAuth.clientCertificateConfig.issueClientCertificate) clientCertFail.push(c.name);
  });
  results.push({
    id: 'disable-client-certs',
    name: 'Disable Client Certificates',
    passed: clientCertFail.length === 0,
    details: clientCertFail.length === 0 ? 'Client certificates disabled.' : `Enabled: ${clientCertFail.join(', ')}`,
    resources: { total: clusters.length, passed: clusters.length - clientCertFail.length, failed: clientCertFail },
    notApplicable: false
  });
  // 2. Disable Kubernetes Dashboard
  let dashboardFail = [];
  clusters.forEach(c => {
    if (c.addonsConfig && c.addonsConfig.kubernetesDashboard && c.addonsConfig.kubernetesDashboard.disabled === false) dashboardFail.push(c.name);
  });
  results.push({
    id: 'disable-dashboard',
    name: 'Disable Kubernetes Dashboard for GKE Clusters',
    passed: dashboardFail.length === 0,
    details: dashboardFail.length === 0 ? 'Dashboard disabled.' : `Enabled: ${dashboardFail.join(', ')}`,
    resources: { total: clusters.length, passed: clusters.length - dashboardFail.length, failed: dashboardFail },
    notApplicable: false
  });
  // 3. Disable Legacy Authorization
  let legacyAuthFail = [];
  clusters.forEach(c => {
    if (c.legacyAbac && c.legacyAbac.enabled) legacyAuthFail.push(c.name);
  });
  results.push({
    id: 'disable-legacy-auth',
    name: 'Disable Legacy Authorization',
    passed: legacyAuthFail.length === 0,
    details: legacyAuthFail.length === 0 ? 'Legacy auth disabled.' : `Enabled: ${legacyAuthFail.join(', ')}`,
    resources: { total: clusters.length, passed: clusters.length - legacyAuthFail.length, failed: legacyAuthFail },
    notApplicable: false
  });
  // 4. Enable Auto-Repair
  let autoRepairFail = [];
  clusters.forEach(c => {
    (c.nodePools || []).forEach(np => {
      if (!np.management || !np.management.autoRepair) autoRepairFail.push(`${c.name}/${np.name}`);
    });
  });
  results.push({
    id: 'auto-repair',
    name: 'Enable Auto-Repair for GKE Cluster Nodes',
    passed: autoRepairFail.length === 0,
    details: autoRepairFail.length === 0 ? 'Auto-repair enabled.' : `Disabled: ${autoRepairFail.join(', ')}`,
    resources: { total: clusters.reduce((sum, c) => sum + (c.nodePools ? c.nodePools.length : 0), 0) || 1, passed: clusters.reduce((sum, c) => sum + (c.nodePools ? c.nodePools.filter(np => np.management && np.management.autoRepair).length : 0), 0), failed: autoRepairFail },
    notApplicable: false
  });
  // 5. Enable Auto-Upgrade
  let autoUpgradeFail = [];
  clusters.forEach(c => {
    (c.nodePools || []).forEach(np => {
      if (!np.management || !np.management.autoUpgrade) autoUpgradeFail.push(`${c.name}/${np.name}`);
    });
  });
  results.push({
    id: 'auto-upgrade',
    name: 'Enable Auto-Upgrade for GKE Cluster Nodes',
    passed: autoUpgradeFail.length === 0,
    details: autoUpgradeFail.length === 0 ? 'Auto-upgrade enabled.' : `Disabled: ${autoUpgradeFail.join(', ')}`,
    resources: { total: clusters.reduce((sum, c) => sum + (c.nodePools ? c.nodePools.length : 0), 0) || 1, passed: clusters.reduce((sum, c) => sum + (c.nodePools ? c.nodePools.filter(np => np.management && np.management.autoUpgrade).length : 0), 0), failed: autoUpgradeFail },
    notApplicable: false
  });
  // 6. Enable Binary Authorization
  let binaryAuthFail = [];
  clusters.forEach(c => {
    if (!c.binaryAuthorization || !c.binaryAuthorization.enabled) binaryAuthFail.push(c.name);
  });
  results.push({
    id: 'binary-auth',
    name: 'Enable Binary Authorization',
    passed: binaryAuthFail.length === 0,
    details: binaryAuthFail.length === 0 ? 'Binary Authorization enabled.' : `Disabled: ${binaryAuthFail.join(', ')}`,
    resources: { total: clusters.length, passed: clusters.length - binaryAuthFail.length, failed: binaryAuthFail },
    notApplicable: false
  });
  // 7. Enable Cost Allocation
  let costAllocFail = [];
  clusters.forEach(c => {
    if (!c.costManagementConfig || !c.costManagementConfig.enabled) costAllocFail.push(c.name);
  });
  results.push({
    id: 'cost-allocation',
    name: 'Enable Cost Allocation',
    passed: costAllocFail.length === 0,
    details: costAllocFail.length === 0 ? 'Cost allocation enabled.' : `Disabled: ${costAllocFail.join(', ')}`,
    resources: { total: clusters.length, passed: clusters.length - costAllocFail.length, failed: costAllocFail },
    notApplicable: false
  });
  // 8. Enable GKE Metadata Server
  let metadataFail = [];
  clusters.forEach(c => {
    (c.nodePools || []).forEach(np => {
      if (!np.config || !np.config.workloadMetadataConfig || np.config.workloadMetadataConfig.mode !== 'GKE_METADATA') metadataFail.push(`${c.name}/${np.name}`);
    });
  });
  results.push({
    id: 'metadata-server',
    name: 'Enable GKE Metadata Server',
    passed: metadataFail.length === 0,
    details: metadataFail.length === 0 ? 'GKE Metadata Server enabled.' : `Disabled: ${metadataFail.join(', ')}`,
    resources: { total: clusters.reduce((sum, c) => sum + (c.nodePools ? c.nodePools.length : 0), 0) || 1, passed: clusters.reduce((sum, c) => sum + (c.nodePools ? c.nodePools.filter(np => np.config && np.config.workloadMetadataConfig && np.config.workloadMetadataConfig.mode === 'GKE_METADATA').length : 0), 0), failed: metadataFail },
    notApplicable: false
  });
  // 9. Enable Integrity Monitoring
  let integrityFail = [];
  clusters.forEach(c => {
    (c.nodePools || []).forEach(np => {
      if (!np.config || !np.config.integrityMonitoring || !np.config.integrityMonitoring.enabled) integrityFail.push(`${c.name}/${np.name}`);
    });
  });
  results.push({
    id: 'integrity-monitoring',
    name: 'Enable Integrity Monitoring for Cluster Nodes',
    passed: integrityFail.length === 0,
    details: integrityFail.length === 0 ? 'Integrity monitoring enabled.' : `Disabled: ${integrityFail.join(', ')}`,
    resources: { total: clusters.reduce((sum, c) => sum + (c.nodePools ? c.nodePools.length : 0), 0) || 1, passed: clusters.reduce((sum, c) => sum + (c.nodePools ? c.nodePools.filter(np => np.config && np.config.integrityMonitoring && np.config.integrityMonitoring.enabled).length : 0), 0), failed: integrityFail },
    notApplicable: false
  });
  // 10. Enable Inter-Node Transparent Encryption
  let encryptionFail = [];
  clusters.forEach(c => {
    if (!c.databaseEncryption || c.databaseEncryption.state !== 'ENCRYPTED') encryptionFail.push(c.name);
  });
  results.push({
    id: 'transparent-encryption',
    name: 'Enable Inter-Node Transparent Encryption',
    passed: encryptionFail.length === 0,
    details: encryptionFail.length === 0 ? 'Inter-node encryption enabled.' : `Disabled: ${encryptionFail.join(', ')}`,
    resources: { total: clusters.length, passed: clusters.length - encryptionFail.length, failed: encryptionFail },
    notApplicable: false
  });
  // 11. Enable Intranode Visibility
  let intranodeFail = [];
  clusters.forEach(c => {
    if (!c.intraNodeVisibilityConfig || !c.intraNodeVisibilityConfig.enabled) intranodeFail.push(c.name);
  });
  results.push({
    id: 'intranode-visibility',
    name: 'Enable Intranode Visibility',
    passed: intranodeFail.length === 0,
    details: intranodeFail.length === 0 ? 'Intranode visibility enabled.' : `Disabled: ${intranodeFail.join(', ')}`,
    resources: { total: clusters.length, passed: clusters.length - intranodeFail.length, failed: intranodeFail },
    notApplicable: false
  });
  // 12. Enable Private Nodes
  let privateFail = [];
  clusters.forEach(c => {
    if (!c.privateClusterConfig || !c.privateClusterConfig.enablePrivateNodes) privateFail.push(c.name);
  });
  results.push({
    id: 'private-nodes',
    name: 'Enable Private Nodes',
    passed: privateFail.length === 0,
    details: privateFail.length === 0 ? 'Private nodes enabled.' : `Disabled: ${privateFail.join(', ')}`,
    resources: { total: clusters.length, passed: clusters.length - privateFail.length, failed: privateFail },
    notApplicable: false
  });
  // 13. Enable Secure Boot
  let secureBootFail = [];
  clusters.forEach(c => {
    (c.nodePools || []).forEach(np => {
      if (!np.config || !np.config.shieldedInstanceConfig || !np.config.shieldedInstanceConfig.enableSecureBoot) secureBootFail.push(`${c.name}/${np.name}`);
    });
  });
  results.push({
    id: 'secure-boot',
    name: 'Enable Secure Boot for Cluster Nodes',
    passed: secureBootFail.length === 0,
    details: secureBootFail.length === 0 ? 'Secure boot enabled.' : `Disabled: ${secureBootFail.join(', ')}`,
    resources: { total: clusters.reduce((sum, c) => sum + (c.nodePools ? c.nodePools.length : 0), 0) || 1, passed: clusters.reduce((sum, c) => sum + (c.nodePools ? c.nodePools.filter(np => np.config && np.config.shieldedInstanceConfig && np.config.shieldedInstanceConfig.enableSecureBoot).length : 0), 0), failed: secureBootFail },
    notApplicable: false
  });
  // 14. Enable VPC-Native Traffic Routing
  let vpcNativeFail = [];
  clusters.forEach(c => {
    if (!c.ipAllocationPolicy || !c.ipAllocationPolicy.useIpAliases) vpcNativeFail.push(c.name);
  });
  results.push({
    id: 'vpc-native-routing',
    name: 'Enable VPC-Native Traffic Routing',
    passed: vpcNativeFail.length === 0,
    details: vpcNativeFail.length === 0 ? 'VPC-native routing enabled.' : `Disabled: ${vpcNativeFail.join(', ')}`,
    resources: { total: clusters.length, passed: clusters.length - vpcNativeFail.length, failed: vpcNativeFail },
    notApplicable: false
  });
  // 15. Enable Workload Identity Federation
  let workloadIdFail = [];
  clusters.forEach(c => {
    if (!c.workloadIdentityConfig || !c.workloadIdentityConfig.workloadPool) workloadIdFail.push(c.name);
  });
  results.push({
    id: 'workload-identity',
    name: 'Enable Workload Identity Federation',
    passed: workloadIdFail.length === 0,
    details: workloadIdFail.length === 0 ? 'Workload identity enabled.' : `Disabled: ${workloadIdFail.join(', ')}`,
    resources: { total: clusters.length, passed: clusters.length - workloadIdFail.length, failed: workloadIdFail },
    notApplicable: false
  });
  // 16. Enable and Configure Cluster Logging
  let loggingFail = [];
  clusters.forEach(c => {
    if (!c.loggingService || c.loggingService === 'none') loggingFail.push(c.name);
  });
  results.push({
    id: 'cluster-logging',
    name: 'Enable and Configure Cluster Logging',
    passed: loggingFail.length === 0,
    details: loggingFail.length === 0 ? 'Cluster logging enabled.' : `Disabled: ${loggingFail.join(', ')}`,
    resources: { total: clusters.length, passed: clusters.length - loggingFail.length, failed: loggingFail },
    notApplicable: false
  });
  // 17. Enable and Configure Cluster Monitoring
  let monitoringFail = [];
  clusters.forEach(c => {
    if (!c.monitoringService || c.monitoringService === 'none') monitoringFail.push(c.name);
  });
  results.push({
    id: 'cluster-monitoring',
    name: 'Enable and Configure Cluster Monitoring',
    passed: monitoringFail.length === 0,
    details: monitoringFail.length === 0 ? 'Cluster monitoring enabled.' : `Disabled: ${monitoringFail.join(', ')}`,
    resources: { total: clusters.length, passed: clusters.length - monitoringFail.length, failed: monitoringFail },
    notApplicable: false
  });
  // 18. Restrict Network Access (control plane not public)
  let restrictNetFail = [];
  clusters.forEach(c => {
    if (c.privateClusterConfig && c.privateClusterConfig.enablePrivateEndpoint !== true) restrictNetFail.push(c.name);
  });
  results.push({
    id: 'restrict-network',
    name: 'Restrict Network Access',
    passed: restrictNetFail.length === 0,
    details: restrictNetFail.length === 0 ? 'Control plane not public.' : `Public: ${restrictNetFail.join(', ')}`,
    resources: { total: clusters.length, passed: clusters.length - restrictNetFail.length, failed: restrictNetFail },
    notApplicable: false
  });
  // 19. Prevent Default Service Account Usage
  let defaultSAFail = [];
  clusters.forEach(c => {
    (c.nodePools || []).forEach(np => {
      if (np.config && np.config.serviceAccount === 'default') defaultSAFail.push(`${c.name}/${np.name}`);
    });
  });
  results.push({
    id: 'prevent-default-sa',
    name: 'Prevent Default Service Account Usage',
    passed: defaultSAFail.length === 0,
    details: defaultSAFail.length === 0 ? 'No default service account used.' : `Default SA: ${defaultSAFail.join(', ')}`,
    resources: { total: clusters.reduce((sum, c) => sum + (c.nodePools ? c.nodePools.length : 0), 0) || 1, passed: clusters.reduce((sum, c) => sum + (c.nodePools ? c.nodePools.filter(np => np.config && np.config.serviceAccount !== 'default').length : 0), 0), failed: defaultSAFail },
    notApplicable: false
  });
  // 20. Use Labels for Resource Management
  let labelFail = [];
  clusters.forEach(c => {
    if (!c.resourceLabels || Object.keys(c.resourceLabels).length === 0) labelFail.push(c.name);
  });
  results.push({
    id: 'labels',
    name: 'Use Labels for Resource Management',
    passed: labelFail.length === 0,
    details: labelFail.length === 0 ? 'All clusters labeled.' : `No labels: ${labelFail.join(', ')}`,
    resources: { total: clusters.length, passed: clusters.length - labelFail.length, failed: labelFail },
    notApplicable: false
  });
  // 21. Use Shielded GKE Cluster Nodes
  let shieldedFail = [];
  clusters.forEach(c => {
    (c.nodePools || []).forEach(np => {
      if (!np.config || !np.config.shieldedInstanceConfig || !np.config.shieldedInstanceConfig.enableShieldedNodes) shieldedFail.push(`${c.name}/${np.name}`);
    });
  });
  results.push({
    id: 'shielded-nodes',
    name: 'Use Shielded GKE Cluster Nodes',
    passed: shieldedFail.length === 0,
    details: shieldedFail.length === 0 ? 'Shielded nodes enabled.' : `Not shielded: ${shieldedFail.join(', ')}`,
    resources: { total: clusters.reduce((sum, c) => sum + (c.nodePools ? c.nodePools.length : 0), 0) || 1, passed: clusters.reduce((sum, c) => sum + (c.nodePools ? c.nodePools.filter(np => np.config && np.config.shieldedInstanceConfig && np.config.shieldedInstanceConfig.enableShieldedNodes).length : 0), 0), failed: shieldedFail },
    notApplicable: false
  });
  return results;
}

module.exports = { evaluateGKE }; 