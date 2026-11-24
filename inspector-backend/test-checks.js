// Simple test script to verify compute checks
const { evaluateComputeEngine } = require('./compute-checks');

// Mock compute client with a simple VM
const mockCompute = {
  getVMs: () => Promise.resolve([
    [
      {
        metadata: {
          name: 'test-vm',
          disks: [{ boot: true, initializeParams: { sourceImage: 'projects/debian-cloud/global/images/debian-11' } }],
          networkInterfaces: [{ accessConfigs: [{ natIP: '35.123.45.67' }] }],
          canIpForward: false,
          scheduling: { automaticRestart: true, onHostMaintenance: 'MIGRATE', preemptible: false },
          deletionProtection: false,
          shieldedInstanceConfig: { 
            enableSecureBoot: false, 
            enableVtpm: true, 
            enableIntegrityMonitoring: true 
          },
          confidentialInstanceConfig: { enableConfidentialCompute: false }
        }
      }
    ]
  ]),
  getProjectMetadata: () => Promise.resolve({
    metadata: {
      items: [
        { key: 'enable-oslogin', value: 'TRUE' }
      ]
    }
  })
};

// Run the test
async function runTest() {
  try {
    const results = await evaluateComputeEngine(mockCompute);
    console.log(`COMPUTE CHECKS: Found ${results.length} checks`);
    console.log('CHECK IDs:', results.map(check => check.id).join(', '));
    
    // Print out full details of each check
    results.forEach((check, index) => {
      console.log(`\n--- Check ${index + 1}: ${check.name} ---`);
      console.log(`ID: ${check.id}`);
      console.log(`Passed: ${check.passed}`);
      console.log(`Details: ${check.details}`);
      console.log(`Resources: ${check.resources.passed}/${check.resources.total}`);
      
      if (check.resources.failed && check.resources.failed.length > 0) {
        console.log(`Failed resources: ${check.resources.failed.join(', ')}`);
      }
    });
  } catch (error) {
    console.error('Test failed:', error);
  }
}

runTest(); 