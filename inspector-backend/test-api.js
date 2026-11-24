const axios = require('axios');
const fs = require('fs').promises;

const API_URL = 'http://localhost:4000';

async function loadCredentials() {
  try {
    // Try to load from credentials.json if exists
    const credentialsText = await fs.readFile('credentials.json', 'utf8');
    return JSON.parse(credentialsText);
  } catch (error) {
    console.error('Error loading credentials:', error.message);
    return null;
  }
}

async function testScan() {
  try {
    // Get credentials
    const credentials = await loadCredentials();
    if (!credentials) {
      console.error('No credentials available. Please create a credentials.json file.');
      return;
    }
    
    console.log('Sending scan request...');
    const response = await axios.post(`${API_URL}/api/scan`, {
      serviceAccountKey: credentials
    });
    
    console.log('Scan successful!');
    
    // Find compute engine service
    const computeService = response.data.services.find(s => s.id === 'compute-engine');
    
    if (!computeService) {
      console.error('No compute engine service found in the response');
      return;
    }
    
    console.log(`Found ${computeService.checks.length} compute engine checks:`);
    computeService.checks.forEach((check, i) => {
      console.log(`${i+1}. ${check.id}: ${check.name} - ${check.passed ? 'PASSED' : 'FAILED'}`);
      
      if (check.resources.failed && check.resources.failed.length > 0) {
        console.log(`   Failed resources (${check.resources.failed.length}): ${check.resources.failed.join(', ')}`);
      }
    });
    
    // Find cloud storage service
    const storageService = response.data.services.find(s => s.id === 'cloud-storage');
    
    if (storageService) {
      console.log(`\nFound ${storageService.checks.length} cloud storage checks:`);
      storageService.checks.forEach((check, i) => {
        console.log(`${i+1}. ${check.id}: ${check.name} - ${check.passed ? 'PASSED' : 'FAILED'}`);
        
        if (check.resources.failed && check.resources.failed.length > 0) {
          console.log(`   Failed resources (${check.resources.failed.length}): ${check.resources.failed.join(', ')}`);
        }
      });
    }
    
    return response.data;
  } catch (error) {
    console.error('Test failed:', error.response?.data || error.message);
  }
}

testScan(); 