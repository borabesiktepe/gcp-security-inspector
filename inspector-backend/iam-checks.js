const { makeGoogleApiRequest } = require('./gcp-api');

async function evaluateIAM({ credentials, projectId }) {
  const results = [];
  const iamUrl = `https://cloudresourcemanager.googleapis.com/v1/projects/${projectId}:getIamPolicy`;
  let policy;
  try {
    policy = await makeGoogleApiRequest(credentials, iamUrl, 'POST', {});
  } catch (error) {
    return [
      {
        id: 'iam-error',
        name: 'IAM Scan Error',
        passed: false,
        details: `Failed to fetch IAM policy: ${error.message}`,
        resources: { total: 1, passed: 0, failed: [] },
        notApplicable: false
      }
    ];
  }
  const bindings = policy.bindings || [];
  // 1. Service Roles at Project Level
  const serviceRoles = ['roles/iam.serviceAccountUser', 'roles/iam.serviceAccountTokenCreator'];
  let failedMembers = [];
  let allMembers = [];
  bindings.forEach(binding => {
    if (serviceRoles.includes(binding.role)) {
      failedMembers = failedMembers.concat(binding.members || []);
      allMembers = allMembers.concat(binding.members || []);
    }
  });
  const anyFail1 = failedMembers.length > 0;
  results.push({
    id: 'service-account-roles',
    name: 'Check for IAM Members with Service Roles at the Project Level',
    passed: !anyFail1,
    details: !anyFail1 ? 'No IAM members with Service Account User/Token Creator roles.' : `Number of assets failed: ${failedMembers.length}`,
    resources: { total: 1, passed: anyFail1 ? 0 : 1, failed: failedMembers },
    notApplicable: false
  });
  // 2. Broad permissions for service accounts
  let broadServiceAccounts = [];
  let allServiceAccounts = [];
  bindings.forEach(binding => {
    if ((binding.role === 'roles/owner' || binding.role === 'roles/editor') && binding.members) {
      const serviceAccounts = binding.members.filter(m => m.startsWith('serviceAccount:'));
      broadServiceAccounts = broadServiceAccounts.concat(serviceAccounts);
      allServiceAccounts = allServiceAccounts.concat(serviceAccounts);
    }
  });
  const anyFail2 = broadServiceAccounts.length > 0;
  results.push({
    id: 'broad-service-account',
    name: 'Check for broad permissions for service accounts',
    passed: !anyFail2,
    details: !anyFail2 ? 'No service accounts with Editor/Owner privileges.' : `Number of assets failed: ${broadServiceAccounts.length}`,
    resources: { total: 1, passed: anyFail2 ? 0 : 1, failed: broadServiceAccounts },
    notApplicable: false
  });
  // 3. Broad permissions for standard accounts
  let broadStandardAccounts = [];
  let allStandardAccounts = [];
  bindings.forEach(binding => {
    if ((binding.role === 'roles/owner' || binding.role === 'roles/editor') && binding.members) {
      const standardAccounts = binding.members.filter(m => m.startsWith('user:'));
      broadStandardAccounts = broadStandardAccounts.concat(standardAccounts);
      allStandardAccounts = allStandardAccounts.concat(standardAccounts);
    }
  });
  const anyFail3 = broadStandardAccounts.length > 0;
  results.push({
    id: 'broad-standard-account',
    name: 'Check for broad permissions for standard accounts',
    passed: !anyFail3,
    details: !anyFail3 ? 'No standard accounts with Editor/Owner privileges.' : `Number of assets failed: ${broadStandardAccounts.length}`,
    resources: { total: 1, passed: anyFail3 ? 0 : 1, failed: broadStandardAccounts },
    notApplicable: false
  });
  return results;
}

module.exports = { evaluateIAM }; 