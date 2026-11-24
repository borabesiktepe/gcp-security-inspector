const axios = require('axios');
const fs = require('fs').promises;
require('dotenv').config();

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

async function testAuthenticate(credentials) {
  try {
    const response = await axios.post(`${API_URL}/api/authenticate`, {
      serviceAccountKey: credentials
    });
    
    console.log('Authentication response:', response.data);
    return response.data.success;
  } catch (error) {
    console.error('Authentication error:', error.response?.data || error.message);
    return false;
  }
}

async function testScan(credentials) {
  try {
    console.log('Sending scan request...');
    const response = await axios.post(`${API_URL}/api/scan`, {
      serviceAccountKey: credentials
    });
    
    console.log('Scan successful!');
    console.log(`Project: ${response.data.projectName}`);
    console.log(`Overall Score: ${response.data.score}%`);
    
    // Check each service
    response.data.services.forEach(service => {
      console.log(`\n${service.name} (${service.score}%):`);
      console.log(`Found ${service.checks.length} checks`);
      
      // Group checks by pass/fail status
      const passedChecks = service.checks.filter(check => check.passed);
      const failedChecks = service.checks.filter(check => !check.passed);
      
      console.log(`Passed: ${passedChecks.length}, Failed: ${failedChecks.length}`);
      
      // Show IDs of all checks
      console.log(`Check IDs: ${service.checks.map(check => check.id).join(', ')}`);
      
      // Print failed checks with details
      if (failedChecks.length > 0) {
        console.log('\nFailed Checks:');
        failedChecks.forEach(check => {
          console.log(`- ${check.name}: ${check.resources.passed}/${check.resources.total}`);
          if (check.resources.failed && check.resources.failed.length > 0) {
            console.log(`  Failed resources: ${check.resources.failed.join(', ')}`);
          }
        });
      }
    });
    
    return true;
  } catch (error) {
    console.error('Scan error:', error.response?.data || error.message);
    return false;
  }
}

async function main() {
  try {
    // Get credentials
    const credentials = await loadCredentials();
    if (!credentials) {
      console.error('No credentials available. Please create a credentials.json file.');
      return;
    }
    
    // Authenticate
    const authSuccess = await testAuthenticate(credentials);
    if (!authSuccess) {
      console.error('Authentication failed. Exiting.');
      return;
    }
    
    // Run scan
    await testScan(credentials);
  } catch (error) {
    console.error('Test failed:', error);
  }
}

main(); 