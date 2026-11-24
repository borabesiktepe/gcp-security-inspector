const express = require('express');
const cors = require('cors');
const bodyParser = require('body-parser');
const { Storage } = require('@google-cloud/storage');
const https = require('https');
const { evaluateComputeEngine } = require('./compute-checks');
const { evaluateCloudStorage } = require('./storage-checks');
const { evaluateIAM } = require('./iam-checks');
const { evaluateVPC } = require('./vpc-checks');
const { evaluateGKE } = require('./gke-checks');
const { google } = require('googleapis');

const app = express();
const port = process.env.PORT || 4000;

// Middleware
app.use(cors({
  origin: ['http://localhost:3000', 'http://localhost:3001'],
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE'],
  allowedHeaders: ['Content-Type', 'Authorization']
}));
app.use(bodyParser.json({limit: '10mb'}));

// Helper function to make authenticated Google Cloud API requests
async function makeGoogleApiRequest(credentials, url) {
  return new Promise((resolve, reject) => {
    // Get access token using the service account credentials
    const { client_email, private_key } = credentials;
    const jwtHeader = {
      alg: 'RS256',
      typ: 'JWT'
    };
    
    const now = Math.floor(Date.now() / 1000);
    const jwtClaimSet = {
      iss: client_email,
      scope: 'https://www.googleapis.com/auth/cloud-platform',
      aud: 'https://www.googleapis.com/oauth2/v4/token',
      exp: now + 3600,
      iat: now
    };

    const headerBase64 = Buffer.from(JSON.stringify(jwtHeader)).toString('base64url');
    const claimSetBase64 = Buffer.from(JSON.stringify(jwtClaimSet)).toString('base64url');
    const crypto = require('crypto');
    
    const signatureInput = `${headerBase64}.${claimSetBase64}`;
    const signer = crypto.createSign('RSA-SHA256');
    signer.update(signatureInput);
    const signature = signer.sign(private_key, 'base64url');
    
    const jwt = `${headerBase64}.${claimSetBase64}.${signature}`;
    
    // Exchange JWT for access token
    const tokenReqOptions = {
      hostname: 'www.googleapis.com',
      path: '/oauth2/v4/token',
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded'
      }
    };
    
    const tokenReq = https.request(tokenReqOptions, (tokenRes) => {
      let tokenData = '';
      
      tokenRes.on('data', (chunk) => {
        tokenData += chunk;
      });
      
      tokenRes.on('end', () => {
        const tokenResponse = JSON.parse(tokenData);
        const accessToken = tokenResponse.access_token;
        
        if (!accessToken) {
          return reject(new Error(`Failed to get access token: ${tokenData}`));
        }
        
        // Make the actual API request with the access token
        const apiReqOptions = new URL(url);
        const apiReq = https.request({
          hostname: apiReqOptions.hostname,
          path: apiReqOptions.pathname + apiReqOptions.search,
          method: 'GET',
          headers: {
            'Authorization': `Bearer ${accessToken}`
          }
        }, (apiRes) => {
          let apiData = '';
          
          apiRes.on('data', (chunk) => {
            apiData += chunk;
          });
          
          apiRes.on('end', () => {
            try {
              const response = JSON.parse(apiData);
              resolve(response);
            } catch (error) {
              reject(new Error(`Failed to parse API response: ${apiData}`));
            }
          });
        });
        
        apiReq.on('error', (error) => {
          reject(new Error(`API request error: ${error.message}`));
        });
        
        apiReq.end();
      });
    });
    
    tokenReq.on('error', (error) => {
      reject(new Error(`Token request error: ${error.message}`));
    });
    
    tokenReq.write(`grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer&assertion=${jwt}`);
    tokenReq.end();
  });
}

// Authentication and scan endpoints
app.post('/api/authenticate', async (req, res) => {
  try {
    const { serviceAccountKey } = req.body;
    
    if (!serviceAccountKey) {
      return res.status(400).json({ 
        success: false, 
        error: 'No service account key provided' 
      });
    }
    
    // Store key in session (for demo purposes only)
    // In production, consider more secure options
    req.session = req.session || {};
    req.session.serviceAccountKey = serviceAccountKey;
    
    // Test connection by making a simple API request
    const projectId = serviceAccountKey.project_id;
    const testUrl = `https://compute.googleapis.com/compute/v1/projects/${projectId}/zones`;
    
    try {
      await makeGoogleApiRequest(serviceAccountKey, testUrl);
      console.log('Authentication successful');
      res.json({ success: true });
    } catch (error) {
      console.error('Authentication API error:', error);
      res.status(401).json({ 
        success: false, 
        error: `Authentication failed: ${error.message}` 
      });
    }
  } catch (error) {
    console.error('Authentication error:', error);
    res.status(401).json({ 
      success: false, 
      error: error.message || 'Failed to authenticate with Google Cloud' 
    });
  }
});

app.post('/api/projects', async (req, res) => {
  try {
    const { serviceAccountKey } = req.body;
    if (!serviceAccountKey) {
      return res.status(400).json({ success: false, error: 'No service account key provided' });
    }
    // Authenticate with service account
    const auth = new google.auth.GoogleAuth({
      credentials: serviceAccountKey,
      scopes: ['https://www.googleapis.com/auth/cloud-platform.read-only']
    });
    const crm = google.cloudresourcemanager({ version: 'v1', auth });
    let projects = [];
    let nextPageToken = undefined;
    do {
      const resp = await crm.projects.list({ pageToken: nextPageToken });
      if (resp.data.projects) projects.push(...resp.data.projects);
      nextPageToken = resp.data.nextPageToken;
    } while (nextPageToken);
    // Only include active projects
    projects = projects.filter(p => p.lifecycleState === 'ACTIVE');
    res.json({ success: true, projects });
  } catch (error) {
    console.error('Error listing projects:', error);
    res.status(500).json({ success: false, error: error.message });
  }
});

app.post('/api/scan', async (req, res) => {
  try {
    const { serviceAccountKey, projectId: overrideProjectId } = req.body;
    if (!serviceAccountKey) {
      return res.status(400).json({ success: false, error: 'No service account key provided' });
    }
    const projectId = overrideProjectId || serviceAccountKey.project_id;
    console.log(`Starting scan for project: ${projectId}`);
    
    // Initialize storage client
    const storage = new Storage({
      projectId: projectId,
      credentials: serviceAccountKey
    });
    
    // For Compute Engine checks, we'll use direct API calls
    // Get list of VMs
    console.log('Getting Compute Engine results...');
    const computeResults = await getComputeEngineResults(serviceAccountKey, projectId);
    console.log(`Compute Engine results: ${computeResults.length} checks`);
    
    // Get Cloud Storage results
    console.log('Getting Cloud Storage results...');
    const storageResults = await getCloudStorageResults(storage, projectId);
    console.log(`Cloud Storage results: ${storageResults.length} checks`);

    // Get GKE results
    console.log('Getting GKE results...');
    const gkeResults = await evaluateGKE({ credentials: serviceAccountKey, projectId });
    console.log(`GKE results: ${gkeResults.length} checks`);

    // Get IAM results
    console.log('Getting IAM results...');
    const iamResults = await evaluateIAM({ credentials: serviceAccountKey, projectId });
    console.log(`IAM results: ${iamResults.length} checks`);

    // Get VPC results
    console.log('Getting VPC results...');
    const vpcResults = await evaluateVPC({ credentials: serviceAccountKey, projectId });
    console.log(`VPC results: ${vpcResults.length} checks`);

    // Calculate scores
    const services = [
      {
        id: 'compute-engine',
        name: 'Compute Engine',
        score: calculateServiceScore(computeResults),
        checks: computeResults
      },
      {
        id: 'cloud-storage',
        name: 'Cloud Storage',
        score: calculateServiceScore(storageResults),
        checks: storageResults
      },
      {
        id: 'gke',
        name: 'Kubernetes Engine',
        score: calculateServiceScore(gkeResults),
        checks: gkeResults.map(check => ({
          ...check,
          remediation: getRemediation(check.id),
          remediationLink: getRemediationLink(check.id)
        }))
      },
      {
        id: 'iam',
        name: 'IAM',
        score: calculateServiceScore(iamResults),
        checks: iamResults.map(check => ({
          ...check,
          remediation: getRemediation(check.id),
          remediationLink: getRemediationLink(check.id)
        }))
      },
      {
        id: 'vpc',
        name: 'VPC',
        score: calculateServiceScore(vpcResults),
        checks: vpcResults.map(check => ({
          ...check,
          remediation: getRemediation(check.id),
          remediationLink: getRemediationLink(check.id)
        }))
      }
    ];
    
    console.log('Services prepared:');
    services.forEach(service => {
      console.log(`${service.name}: ${service.checks.length} checks`);
    });
    
    const overallScore = calculateOverallScore(services);
    
    // Use the first two segments of the projectId as projectName (e.g., 'platform-eng' from 'platform-eng-392007')
    const projectName = projectId.split('-').slice(0,2).join('-');
    const response = {
      projectId: projectId,
      projectName: projectName,
      score: overallScore,
      services
    };
    
    console.log('Sending scan response back to client');
    res.json(response);
  } catch (error) {
    console.error('Scan error:', error);
    res.status(500).json({
      success: false,
      error: error.message || 'Failed to scan Google Cloud resources'
    });
  }
});

// Compute Engine checks
async function getComputeEngineResults(credentials, projectId) {
  try {
    // Get list of VMs in the project
    const vmsUrl = `https://compute.googleapis.com/compute/v1/projects/${projectId}/aggregated/instances`;
    const vmsResponse = await makeGoogleApiRequest(credentials, vmsUrl);
    
    const vms = [];
    if (vmsResponse.items) {
      Object.keys(vmsResponse.items).forEach(zone => {
        if (vmsResponse.items[zone].instances) {
          vmsResponse.items[zone].instances.forEach(vm => {
            vms.push({
              name: vm.name,
              zone: zone.replace('zones/', ''),
              machineType: vm.machineType.split('/').pop(),
              status: vm.status,
              id: vm.id,
              shieldedVmEnabled: vm.shieldedInstanceConfig ? vm.shieldedInstanceConfig.enableSecureBoot : false,
              confidentialComputing: vm.confidentialInstanceConfig ? vm.confidentialInstanceConfig.enableConfidentialCompute : false,
              publicIp: getPublicIp(vm),
              osLogin: vm.metadata && vm.metadata.items ? 
                vm.metadata.items.some(item => item.key === 'enable-oslogin' && item.value === 'TRUE') : false,
              serviceAccount: vm.serviceAccounts ? vm.serviceAccounts[0].email : null,
              deletionProtection: vm.deletionProtection || false,
              bootDiskEncryption: vm.disks && vm.disks.length > 0 ? 
                (vm.disks[0].diskEncryptionKey ? 'CMEK' : 'Google-managed') : 'Unknown',
              canIpForward: vm.canIpForward || false,
              scheduling: vm.scheduling || {},
              metadata: vm,
              labels: vm.labels || {},
              shieldedInstanceConfig: vm.shieldedInstanceConfig || {},
              confidentialInstanceConfig: vm.confidentialInstanceConfig || {},
              credentials // Pass credentials for image deprecation check
            });
          });
        }
      });
    }
    
    // Get project metadata for OS Login setting
    const projectMetadataUrl = `https://compute.googleapis.com/compute/v1/projects/${projectId}`;
    const projectMetadataResponse = await makeGoogleApiRequest(credentials, projectMetadataUrl);
    
    const computeClient = {
      getVMs: () => Promise.resolve([vms]),
      getProjectMetadata: () => Promise.resolve(projectMetadataResponse)
    };
    
    // Use our compute-checks module to evaluate security
    const { evaluateComputeEngine } = require('./compute-checks');
    const results = await evaluateComputeEngine(computeClient);
    
    // Debug output to see what results we're getting
    console.log(`DEBUG: Compute checks found: ${results.length} checks`);
    console.log('DEBUG: Check IDs:', results.map(check => check.id).join(', '));
    
    return results.map(check => ({
      ...check,
      remediation: getRemediation(check.id),
      remediationLink: getRemediationLink(check.id)
    }));
  } catch (error) {
    console.error('Error in getComputeEngineResults:', error);
    return [{
      id: 'compute-error',
      name: 'Compute Engine Scan Error',
      passed: false,
      details: `Failed to scan Compute Engine: ${error.message}`,
      resources: { total: 1, passed: 0, failed: [] },
      remediation: 'Check your service account permissions and network connectivity',
      remediationLink: 'https://cloud.google.com/compute/docs/access/service-accounts'
    }];
  }
}

// Cloud Storage checks
async function getCloudStorageResults(storage, projectId) {
  try {
    // Use our storage-checks module to evaluate security
    const { evaluateCloudStorage } = require('./storage-checks');
    const results = await evaluateCloudStorage(storage);
    
    return results.map(check => ({
      ...check,
      remediation: getRemediation(check.id),
      remediationLink: getRemediationLink(check.id)
    }));
  } catch (error) {
    console.error('Error in getCloudStorageResults:', error);
    return [{
      id: 'storage-error',
      name: 'Cloud Storage Scan Error',
      passed: false,
      details: `Failed to scan Cloud Storage: ${error.message}`,
      resources: { total: 1, passed: 0, failed: [] },
      remediation: 'Check your service account permissions and network connectivity',
      remediationLink: 'https://cloud.google.com/storage/docs/access-control/iam-roles'
    }];
  }
}

// Helper functions
function getRemediation(checkId) {
  const remediationMap = {
    'public-ip': "Remove public IP addresses from VMs that don't need them and use a bastion host or VPN for access.",
    'multiple-nics': 'Simplify network architecture by using a single network interface per VM.',
    'maintenance-behavior': 'Set the maintenance behavior to "Migrate" for all VM instances to ensure availability during host maintenance.',
    'ip-forwarding': 'Disable IP forwarding for all VM instances to improve network security.',
    'auto-restart': 'Enable automatic restart for all VMs to ensure they recover from host maintenance events.',
    'deletion-protection': 'Enable deletion protection for production VMs to prevent accidental deletion.',
    'shielded-vm': 'Enable Shielded VM features to protect VMs against rootkits and bootkits.',
    'integrity-monitoring': 'Enable integrity monitoring for all VMs to detect unauthorized system modifications.',
    'secure-boot': 'Enable secure boot for all VMs to ensure they only run authentic software.',
    'os-login': 'Enable OS Login at the project level to centrally manage SSH access.',
    'confidential-computing': 'Enable confidential computing for VMs processing sensitive data to encrypt data in use.',
    'project-ssh-keys': 'Enable "Block Project-Wide SSH Keys" feature for all VMs to improve access security.',
    'serial-console': 'Disable interactive serial console support unless specifically needed for troubleshooting.',
    'disk-encryption': 'Use Customer-Managed Encryption Keys (CMEK) for boot disks to ensure better security control.',
    'preemptibility': 'Disable preemptibility for production workloads to ensure availability.',
    'public-access': 'Make your Cloud Storage buckets private and use signed URLs for temporary access.',
    'object-versioning': 'Enable object versioning for important buckets to protect against accidental deletions and modifications.',
    'lifecycle-management': 'Configure lifecycle management policies for your buckets to automatically manage object retention.',
    'bucket-level-access': 'Enable uniform bucket-level access to use IAM permissions consistently.',
    'public-access-prevention': 'Enforce public access prevention to provide an additional layer of security.',
    'admin-permissions': 'Review and remove administrative permissions from bucket policies.',
    'website-config': 'Configure both index page suffix and error page for buckets used as websites.',
    'usage-logs': 'Enable usage and storage logs for all buckets for monitoring and auditing.',
    'cors-config': 'Implement secure CORS configurations to control which origins can access your buckets.',
    'default-object-acl': 'Configure default object ACLs to ensure secure access defaults for new objects.',
    'bucket-encryption': 'Use Customer-Managed Encryption Keys for better control and security of bucket content.',
    'retention-policy': 'Configure retention policies for buckets containing sensitive data to prevent unauthorized deletion.',
    'access-logging': 'Enable access logging for sensitive buckets to track all access attempts.',
    'requester-pays': 'Enable requester pays for public datasets to manage costs effectively.',
    'bucket-labels': 'Apply standard labels including environment, owner, and purpose to all buckets.',
    // Cloud Run
    'public-access': 'Restrict public access to Cloud Run services by using IAM policies.',
    'unrestricted-outbound': 'Restrict outbound network access for Cloud Run services.',
    'max-container-instances': 'Set a maximum number of container instances for Cloud Run services.',
    'min-container-instances': 'Set a minimum number of container instances for Cloud Run services as needed.',
    'request-concurrency': 'Configure request concurrency for Cloud Run services.',
    'runtime-version': 'Use the latest supported runtime version for Cloud Run services.',
    'auto-security-updates': 'Enable automatic security updates for Cloud Run services.',
    'binary-authorization': 'Enable Binary Authorization for Cloud Run services.',
    'http2': 'Enable HTTP/2 support for Cloud Run services.',
    'labels': 'Label all Cloud Run services for better management.',
    // GKE
    'disable-client-certs': 'Disable client certificate authentication to reduce risk of credential leakage.',
    'disable-dashboard': 'Disable the Kubernetes Dashboard to minimize attack surface.',
    'disable-legacy-auth': 'Disable legacy ABAC authorization and use RBAC for fine-grained access control.',
    'auto-repair': 'Enable auto-repair for node pools to ensure nodes are automatically fixed if unhealthy.',
    'auto-upgrade': 'Enable auto-upgrade for node pools to keep nodes up to date with security patches.',
    'binary-auth': 'Enable Binary Authorization to enforce image signing and verification.',
    'cluster-backups': 'Regularly back up your GKE clusters and workloads.',
    'cost-allocation': 'Enable cost allocation to track and optimize cluster costs.',
    'critical-notifications': 'Enable critical notifications for cluster events.',
    'metadata-server': 'Enable GKE Metadata Server for secure metadata access.',
    'integrity-monitoring': 'Enable integrity monitoring for all cluster nodes.',
    'transparent-encryption': 'Enable inter-node transparent encryption for data in transit.',
    'intranode-visibility': 'Enable intranode visibility for better network monitoring.',
    'private-nodes': 'Enable private nodes to prevent public IPs on nodes.',
    'secure-boot': 'Enable secure boot for all cluster nodes.',
    'vpc-native-routing': 'Enable VPC-native routing for better network performance and security.',
    'workload-identity': 'Enable Workload Identity Federation for secure service account mapping.',
    'vuln-scanning': 'Enable vulnerability scanning for workloads.',
    'cluster-logging': 'Enable and configure cluster logging for monitoring and auditing.',
    'cluster-monitoring': 'Enable and configure cluster monitoring for health and performance.',
    'security-posture': 'Enable and configure security posture for your clusters.',
    'restrict-network': 'Restrict network access to the control plane.',
    'prevent-default-sa': 'Remove default service account permissions from GKE clusters.',
    'labels': 'Label all GKE clusters for better management.',
    'shielded-nodes': 'Enable shielded nodes for GKE clusters.',
    // IAM
    'service-account-roles': 'Remove unnecessary Service Account User/Token Creator roles from IAM members at the project level.',
    'broad-service-account': 'Restrict Owner/Editor roles for service accounts. Use least privilege principle.',
    'broad-standard-account': 'Restrict Owner/Editor roles for standard user accounts. Assign only required permissions.',
    // VPC
    'unattached-external-ip': 'Release unused static external IP addresses to avoid unnecessary charges and reduce attack surface.',
    'unattached-internal-ip': 'Release unused static internal IP addresses to keep your network clean.',
    'unrestricted-memcached': 'Restrict firewall rules to prevent public access to Memcached (TCP/UDP 11211).',
    'unrestricted-redis': 'Restrict firewall rules to prevent public access to Redis (TCP 6379).',
    'unused-firewall': 'Remove unused firewall rules to reduce potential attack vectors.',
    'default-vpc': 'Delete the default VPC if not needed and use custom VPCs for better security and segmentation.'
  };
  
  return remediationMap[checkId] || 'Follow Google Cloud best practices for this service.';
}

function getRemediationLink(checkId) {
  const remediationLinkMap = {
    'public-ip': 'https://cloud.google.com/compute/docs/ip-addresses',
    'multiple-nics': 'https://cloud.google.com/vpc/docs/multiple-interfaces-concepts',
    'maintenance-behavior': 'https://cloud.google.com/compute/docs/instances/setting-instance-scheduling-options',
    'ip-forwarding': 'https://cloud.google.com/vpc/docs/using-routes#canipforward',
    'auto-restart': 'https://cloud.google.com/compute/docs/instances/setting-instance-scheduling-options',
    'deletion-protection': 'https://cloud.google.com/security-command-center/docs/concepts-vm-threat-detection-overview',
    'shielded-vm': 'https://cloud.google.com/compute/shielded-vm/docs/shielded-vm',
    'integrity-monitoring': 'https://cloud.google.com/compute/shielded-vm/docs/integrity-monitoring',
    'secure-boot': 'https://cloud.google.com/compute/shielded-vm/docs/shielded-vm',
    'os-login': 'https://cloud.google.com/compute/docs/oslogin',
    'confidential-computing': 'https://cloud.google.com/compute/confidential-vm/docs/about-cvm',
    'project-ssh-keys': 'https://cloud.google.com/compute/docs/connect/restrict-ssh-keys',
    'serial-console': 'https://cloud.google.com/compute/docs/instances/interacting-with-serial-console',
    'disk-encryption': 'https://cloud.google.com/compute/docs/disks/customer-managed-encryption',
    'preemptibility': 'https://cloud.google.com/compute/docs/instances/preemptible',
    'public-access': 'https://cloud.google.com/storage/docs/access-control/making-data-public',
    'object-versioning': 'https://cloud.google.com/storage/docs/object-versioning',
    'lifecycle-management': 'https://cloud.google.com/storage/docs/lifecycle',
    'bucket-level-access': 'https://cloud.google.com/storage/docs/uniform-bucket-level-access',
    'public-access-prevention': 'https://cloud.google.com/storage/docs/public-access-prevention',
    'admin-permissions': 'https://cloud.google.com/storage/docs/access-control/iam',
    'website-config': 'https://cloud.google.com/storage/docs/hosting-static-website',
    'usage-logs': 'https://cloud.google.com/storage/docs/access-logs',
    'cors-config': 'https://cloud.google.com/storage/docs/configuring-cors',
    'default-object-acl': 'https://cloud.google.com/storage/docs/access-control/create-manage-lists',
    'bucket-encryption': 'https://cloud.google.com/storage/docs/encryption/customer-managed-keys',
    'retention-policy': 'https://cloud.google.com/storage/docs/bucket-lock',
    'access-logging': 'https://cloud.google.com/storage/docs/access-logs',
    'requester-pays': 'https://cloud.google.com/storage/docs/requester-pays',
    'bucket-labels': 'https://cloud.google.com/storage/docs/creating-buckets#add-bucket-label',
    'vm-image': 'https://cloud.google.com/compute/docs/images',
    'unattached-external-ip': 'https://cloud.google.com/vpc/docs/reserving-external-static-ip-addresses#release',
    'unattached-internal-ip': 'https://cloud.google.com/vpc/docs/using-vpc#deleting-unused-internal-ip',
    'default-vpc': 'https://cloud.google.com/vpc/docs/vpc#default-vpc',
    // Cloud Run
    'public-access': 'https://cloud.google.com/run/docs/securing/public-access',
    'unrestricted-outbound': 'https://cloud.google.com/run/docs/securing/networking',
    'max-container-instances': 'https://cloud.google.com/run/docs/configuring/max-instances',
    'min-container-instances': 'https://cloud.google.com/run/docs/configuring/min-instances',
    'request-concurrency': 'https://cloud.google.com/run/docs/about-instance-concurrency',
    'runtime-version': 'https://cloud.google.com/run/docs/reference/runtimes',
    'auto-security-updates': 'https://cloud.google.com/run/docs/securing/automatic-updates',
    'binary-authorization': 'https://cloud.google.com/binary-authorization/docs/overview',
    'http2': 'https://cloud.google.com/run/docs/configuring/http2',
    'labels': 'https://cloud.google.com/resource-manager/docs/creating-managing-labels',
    // GKE
    'disable-client-certs': 'https://cloud.google.com/kubernetes-engine/docs/how-to/hardening-your-cluster#restrict_client_cert',
    'disable-dashboard': 'https://cloud.google.com/kubernetes-engine/docs/how-to/hardening-your-cluster#disable_dashboard',
    'disable-legacy-auth': 'https://cloud.google.com/kubernetes-engine/docs/how-to/hardening-your-cluster#disable_legacy_abac',
    'auto-repair': 'https://cloud.google.com/kubernetes-engine/docs/how-to/node-auto-repair',
    'auto-upgrade': 'https://cloud.google.com/kubernetes-engine/docs/how-to/node-auto-upgrades',
    'binary-auth': 'https://cloud.google.com/binary-authorization/docs/overview',
    'cluster-backups': 'https://cloud.google.com/kubernetes-engine/docs/how-to/backup-restore',
    'cost-allocation': 'https://cloud.google.com/kubernetes-engine/docs/how-to/cost-allocation',
    'critical-notifications': 'https://cloud.google.com/monitoring/alerts/',
    'metadata-server': 'https://cloud.google.com/kubernetes-engine/docs/how-to/workload-metadata',
    'integrity-monitoring': 'https://cloud.google.com/kubernetes-engine/docs/how-to/shielded-gke-nodes',
    'transparent-encryption': 'https://cloud.google.com/kubernetes-engine/docs/how-to/encrypting-secrets',
    'intranode-visibility': 'https://cloud.google.com/kubernetes-engine/docs/how-to/intranode-visibility',
    'private-nodes': 'https://cloud.google.com/kubernetes-engine/docs/how-to/private-clusters',
    'secure-boot': 'https://cloud.google.com/kubernetes-engine/docs/how-to/shielded-gke-nodes',
    'vpc-native-routing': 'https://cloud.google.com/kubernetes-engine/docs/how-to/alias-ips',
    'workload-identity': 'https://cloud.google.com/kubernetes-engine/docs/how-to/workload-identity',
    'vuln-scanning': 'https://cloud.google.com/kubernetes-engine/docs/how-to/container-analysis',
    'cluster-logging': 'https://cloud.google.com/kubernetes-engine/docs/how-to/logging',
    'cluster-monitoring': 'https://cloud.google.com/kubernetes-engine/docs/how-to/monitoring',
    'security-posture': 'https://cloud.google.com/kubernetes-engine/docs/how-to/security-posture',
    'restrict-network': 'https://cloud.google.com/kubernetes-engine/docs/how-to/network-policy',
    'prevent-default-sa': 'https://cloud.google.com/kubernetes-engine/docs/how-to/hardening-your-cluster#use_least_privilege_service_accounts',
    'labels': 'https://cloud.google.com/resource-manager/docs/creating-managing-labels',
    'shielded-nodes': 'https://cloud.google.com/kubernetes-engine/docs/how-to/shielded-gke-nodes',
    // IAM
    'service-account-roles': 'https://cloud.google.com/iam/docs/understanding-roles#service_account_roles',
    'broad-service-account': 'https://cloud.google.com/iam/docs/understanding-roles#basic',
    'broad-standard-account': 'https://cloud.google.com/iam/docs/understanding-roles#basic',
    // VPC
    'unattached-external-ip': 'https://cloud.google.com/vpc/docs/reserving-external-static-ip-addresses#release',
    'unattached-internal-ip': 'https://cloud.google.com/vpc/docs/using-vpc#deleting-unused-internal-ip',
    'unrestricted-memcached': 'https://cloud.google.com/memorystore/docs/memcached/networking#firewall',
    'unrestricted-redis': 'https://cloud.google.com/memorystore/docs/redis/networking#firewall',
    'unused-firewall': 'https://cloud.google.com/vpc/docs/firewalls#cleaning-up',
    'default-vpc': 'https://cloud.google.com/vpc/docs/vpc#default-vpc'
  };
  
  return remediationLinkMap[checkId] || 'https://cloud.google.com/docs';
}

function calculateServiceScore(checks) {
  if (!checks || checks.length === 0) return 0;
  
  const totalResources = checks.reduce((sum, check) => sum + check.resources.total, 0);
  const passedResources = checks.reduce((sum, check) => sum + check.resources.passed, 0);
  
  return totalResources > 0 ? Math.round((passedResources / totalResources) * 100) : 0;
}

function calculateOverallScore(services) {
  const totalChecks = services.reduce((sum, service) => 
    sum + service.checks.reduce((checksSum, check) => checksSum + check.resources.total, 0), 0);
  
  const passedChecks = services.reduce((sum, service) => 
    sum + service.checks.reduce((checksSum, check) => checksSum + check.resources.passed, 0), 0);
  
  return totalChecks > 0 ? Math.round((passedChecks / totalChecks) * 100) : null;
}

// Helper function to get public IP from VM
function getPublicIp(vm) {
  if (!vm.networkInterfaces || !vm.networkInterfaces.length) return false;
  
  for (const iface of vm.networkInterfaces) {
    if (iface.accessConfigs && iface.accessConfigs.length) {
      for (const config of iface.accessConfigs) {
        if (config.natIP) return true;
      }
    }
  }
  
  return false;
}

// Start server
app.listen(port, () => {
  console.log(`Inspector backend listening on port ${port}`);
}); 