const { makeGoogleApiRequest } = require('./gcp-api');

async function evaluateVPC({ credentials, projectId }) {
  const results = [];
  // 1. Unattached Static External IP Addresses
  let externalIps = [];
  let allExternalIps = [];
  try {
    const url = `https://compute.googleapis.com/compute/v1/projects/${projectId}/aggregated/addresses`;
    const resp = await makeGoogleApiRequest(credentials, url);
    Object.values(resp.items || {}).forEach(region => {
      (region.addresses || []).forEach(addr => {
        if (addr.addressType === 'EXTERNAL') {
          allExternalIps.push(addr.name);
          if (addr.status === 'RESERVED' && !addr.users) {
            externalIps.push(addr.name);
          }
        }
      });
    });
  } catch (e) {}
  const anyFail1 = externalIps.length > 0;
  results.push({
    id: 'unattached-external-ip',
    name: 'Check for Unattached Static External IP Addresses',
    passed: !anyFail1,
    details: !anyFail1 ? 'No unattached static external IPs.' : `Number of assets failed: ${externalIps.length}`,
    resources: { total: 1, passed: anyFail1 ? 0 : 1, failed: externalIps },
    notApplicable: false
  });
  // 2. Unattached Static Internal IP Addresses
  let internalIps = [];
  let allInternalIps = [];
  try {
    const url = `https://compute.googleapis.com/compute/v1/projects/${projectId}/aggregated/addresses`;
    const resp = await makeGoogleApiRequest(credentials, url);
    Object.values(resp.items || {}).forEach(region => {
      (region.addresses || []).forEach(addr => {
        if (addr.addressType === 'INTERNAL') {
          allInternalIps.push(addr.name);
          if (addr.status === 'RESERVED' && !addr.users) {
            internalIps.push(addr.name);
          }
        }
      });
    });
  } catch (e) {}
  const anyFail2 = internalIps.length > 0;
  results.push({
    id: 'unattached-internal-ip',
    name: 'Check for Unattached Static Internal IP Addresses',
    passed: !anyFail2,
    details: !anyFail2 ? 'No unattached static internal IPs.' : `Number of assets failed: ${internalIps.length}`,
    resources: { total: 1, passed: anyFail2 ? 0 : 1, failed: internalIps },
    notApplicable: false
  });
  // 3. Unrestricted Memcached Access (TCP/UDP 11211)
  let memcachedOpen = [];
  try {
    const url = `https://compute.googleapis.com/compute/v1/projects/${projectId}/global/firewalls`;
    const resp = await makeGoogleApiRequest(credentials, url);
    (resp.items || []).forEach(rule => {
      if (rule.allowed && rule.direction === 'INGRESS' && rule.sourceRanges && rule.sourceRanges.includes('0.0.0.0/0')) {
        rule.allowed.forEach(a => {
          if ((a.IPProtocol === 'tcp' || a.IPProtocol === 'udp') && a.ports && a.ports.includes('11211')) {
            memcachedOpen.push(rule.name);
          }
        });
      }
    });
  } catch (e) {}
  const anyFail3 = memcachedOpen.length > 0;
  results.push({
    id: 'unrestricted-memcached',
    name: 'Check for Unrestricted Memcached Access',
    passed: !anyFail3,
    details: !anyFail3 ? 'No unrestricted Memcached firewall rules.' : `Number of assets failed: ${memcachedOpen.length}`,
    resources: { total: 1, passed: anyFail3 ? 0 : 1, failed: memcachedOpen },
    notApplicable: false
  });
  // 4. Unrestricted Redis Access (TCP 6379)
  let redisOpen = [];
  try {
    const url = `https://compute.googleapis.com/compute/v1/projects/${projectId}/global/firewalls`;
    const resp = await makeGoogleApiRequest(credentials, url);
    (resp.items || []).forEach(rule => {
      if (rule.allowed && rule.direction === 'INGRESS' && rule.sourceRanges && rule.sourceRanges.includes('0.0.0.0/0')) {
        rule.allowed.forEach(a => {
          if (a.IPProtocol === 'tcp' && a.ports && a.ports.includes('6379')) {
            redisOpen.push(rule.name);
          }
        });
      }
    });
  } catch (e) {}
  const anyFail4 = redisOpen.length > 0;
  results.push({
    id: 'unrestricted-redis',
    name: 'Check for Unrestricted Redis Access',
    passed: !anyFail4,
    details: !anyFail4 ? 'No unrestricted Redis firewall rules.' : `Number of assets failed: ${redisOpen.length}`,
    resources: { total: 1, passed: anyFail4 ? 0 : 1, failed: redisOpen },
    notApplicable: false
  });
  // 5. Default VPC
  let hasDefaultVPC = false;
  try {
    const url = `https://compute.googleapis.com/compute/v1/projects/${projectId}/global/networks`;
    const resp = await makeGoogleApiRequest(credentials, url);
    const networkNames = (resp.items || []).map(nw => nw.name);
    console.log('VPC network names:', networkNames);
    hasDefaultVPC = networkNames.includes('default');
  } catch (e) {}
  results.push({
    id: 'default-vpc',
    name: 'Check for Default VPC',
    passed: !hasDefaultVPC,
    details: !hasDefaultVPC ? 'No default VPC exists.' : 'Default VPC exists.',
    resources: { total: 1, passed: !hasDefaultVPC ? 1 : 0, failed: hasDefaultVPC ? ['default'] : [] },
    notApplicable: false
  });
  return results;
}

module.exports = { evaluateVPC }; 