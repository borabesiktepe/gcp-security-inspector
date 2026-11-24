/**
 * Debug script for troubleshooting compute engine checks
 * Run this in the browser console when on the results page
 */

function debugChecks() {
  // Access the projectData from React DevTools
  // This will only work if you've opened React DevTools and selected the Results component
  try {
    // Try to find compute engine service
    const $r = window.$r; // The currently selected component in React DevTools
    
    if (!$r || !$r.props || !$r.props.projectData) {
      console.error('Please select the Results component in React DevTools first');
      return;
    }
    
    const projectData = $r.props.projectData;
    console.log('Project data found:', projectData);
    
    // Find compute engine service
    const computeService = projectData.services.find(s => s.id === 'compute-engine');
    
    if (!computeService) {
      console.error('No compute engine service found in the response');
      return;
    }
    
    console.log(`Found ${computeService.checks.length} compute engine checks:`);
    computeService.checks.forEach((check, i) => {
      console.log(`${i+1}. ${check.id}: ${check.name} - ${check.passed ? 'PASSED' : 'FAILED'}`);
    });
    
    return computeService.checks;
  } catch (error) {
    console.error('Error in debugChecks:', error);
  }
}

// Alternative method using fetch directly to the API
async function fetchScans(serviceAccountKey) {
  try {
    if (!serviceAccountKey) {
      console.error('Please provide a service account key JSON');
      return;
    }
    
    console.log('Sending scan request to API...');
    const response = await fetch('http://localhost:4000/api/scan', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ serviceAccountKey }),
    });
    
    if (!response.ok) {
      throw new Error(`API error: ${response.status}`);
    }
    
    const data = await response.json();
    console.log('API response:', data);
    
    // Find compute engine service
    const computeService = data.services.find(s => s.id === 'compute-engine');
    
    if (!computeService) {
      console.error('No compute engine service found in the response');
      return;
    }
    
    console.log(`Found ${computeService.checks.length} compute engine checks:`);
    computeService.checks.forEach((check, i) => {
      console.log(`${i+1}. ${check.id}: ${check.name} - ${check.passed ? 'PASSED' : 'FAILED'}`);
    });
    
    return data;
  } catch (error) {
    console.error('Fetch error:', error);
  }
}

// Export functions to the global scope
window.debugChecks = debugChecks;
window.fetchScans = fetchScans;

console.log('Debug functions loaded. Use debugChecks() to view current checks or fetchScans(serviceAccountKey) to make a new request.'); 