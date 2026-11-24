/**
 * Evaluate Compute Engine resources for security compliance
 */
const { makeGoogleApiRequest } = require('./gcp-api');

async function evaluateComputeEngine(compute) {
  try {
    const [vms] = await compute.getVMs();
    const results = [];
    
    if (!vms || vms.length === 0) {
      // No VMs to check
      return [
        {
          id: 'no-vms',
          name: 'No Virtual Machines Found',
          passed: true,
          details: 'No virtual machines were found in this project.',
          resources: { total: 0, passed: 0, failed: [] }
        }
      ];
    }

    // Check 1: Approved Virtual Machine Image in Use
    const approvedImages = ['debian-cloud', 'centos-cloud', 'ubuntu-os-cloud', 'rhel-cloud', 'cos-cloud'];
    const vmImageCheck = {
      id: 'vm-image',
      name: 'Approved Virtual Machine Image in Use',
      passed: true,
      details: 'All VMs use approved and non-deprecated images',
      resources: { total: vms.length, passed: vms.length, failed: [] }
    };

    for (const vm of vms) {
      const disks = vm.metadata.disks || [];
      if (disks.length > 0) {
        const bootDisk = disks.find(disk => disk.boot === true);
        if (bootDisk && bootDisk.initializeParams && bootDisk.initializeParams.sourceImage) {
          const sourceImage = bootDisk.initializeParams.sourceImage.toLowerCase();
          const isApprovedImage = approvedImages.some(approved => sourceImage.includes(approved));
          let isDeprecated = false;
          // Try to fetch image details and check for deprecation
          try {
            // Extract project and image name from sourceImage URL
            // Example: https://www.googleapis.com/compute/v1/projects/centos-cloud/global/images/centos-8-v20230911
            const match = sourceImage.match(/projects\/(.*?)\/global\/images\/(.*)/);
            if (match) {
              const imageProject = match[1];
              const imageName = match[2];
              const imageUrl = `https://compute.googleapis.com/compute/v1/projects/${imageProject}/global/images/${imageName}`;
              const imageDetails = await makeGoogleApiRequest(vm.credentials || {}, imageUrl);
              if (imageDetails && imageDetails.deprecated) {
                isDeprecated = true;
              }
            }
          } catch (e) {
            // If API fails, do not mark as deprecated, but log error
            console.error('Failed to check image deprecation:', e.message);
          }
          if (!isApprovedImage || isDeprecated) {
            vmImageCheck.resources.passed--;
            vmImageCheck.resources.failed.push(vm.metadata.name);
            vmImageCheck.passed = false;
          }
        }
      }
    }

    if (vmImageCheck.resources.passed < vmImageCheck.resources.total) {
      vmImageCheck.details = `Found ${vmImageCheck.resources.total - vmImageCheck.resources.passed} VMs using unapproved or deprecated images`;
    }

    results.push(vmImageCheck);

    // Check 2: Public IP Addresses
    const publicIpCheck = {
      id: 'public-ip',
      name: 'Check for Virtual Machine Instances with Public IP Addresses',
      passed: true,
      details: 'No VMs with public IP addresses found',
      resources: { total: vms.length, passed: vms.length, failed: [] } 
    };

    let publicIpCount = 0;
    for (const vm of vms) {
      const networkInterfaces = vm.metadata.networkInterfaces || [];
      for (const iface of networkInterfaces) {
        if (iface.accessConfigs && iface.accessConfigs.length > 0) {
          for (const config of iface.accessConfigs) {
            if (config.natIP) {
              publicIpCount++;
              publicIpCheck.resources.passed--;
              publicIpCheck.resources.failed.push(vm.metadata.name);
              publicIpCheck.passed = false;
              break;
            }
          }
        }
      }
    }

    if (publicIpCount > 0) {
      publicIpCheck.details = `Found ${publicIpCount} VMs with public IP addresses`;
    }

    results.push(publicIpCheck);
    
    // Check 3: Multiple Network Interfaces
    const multiNicsCheck = {
      id: 'multiple-nics',
      name: 'Compute Instances with Multiple Network Interfaces',
      passed: true,
      details: 'No VMs with multiple network interfaces',
      resources: { total: vms.length, passed: vms.length, failed: [] }
    };
    
    for (const vm of vms) {
      const networkInterfaces = vm.metadata.networkInterfaces || [];
      if (networkInterfaces.length > 1) {
        multiNicsCheck.resources.passed--;
        multiNicsCheck.resources.failed.push(vm.metadata.name);
        multiNicsCheck.passed = false;
      }
    }
    
    if (multiNicsCheck.resources.passed < multiNicsCheck.resources.total) {
      multiNicsCheck.details = `Found ${multiNicsCheck.resources.total - multiNicsCheck.resources.passed} VMs with multiple network interfaces`;
    }
    
    results.push(multiNicsCheck);
    
    // Check 4: Maintenance Behavior
    const maintenanceCheck = {
      id: 'maintenance-behavior',
      name: 'Configure Maintenance Behavior for VM Instances',
      passed: true,
      details: 'All VMs configured for migration during maintenance',
      resources: { total: vms.length, passed: vms.length, failed: [] }
    };
    
    for (const vm of vms) {
      const scheduling = vm.metadata.scheduling || {};
      if (scheduling.onHostMaintenance !== 'MIGRATE') {
        maintenanceCheck.resources.passed--;
        maintenanceCheck.resources.failed.push(vm.metadata.name);
        maintenanceCheck.passed = false;
      }
    }
    
    if (maintenanceCheck.resources.passed < maintenanceCheck.resources.total) {
      maintenanceCheck.details = `Found ${maintenanceCheck.resources.total - maintenanceCheck.resources.passed} VMs not configured for migration during maintenance`;
    }
    
    results.push(maintenanceCheck);
    
    // Check 5: IP Forwarding
    const ipForwardingCheck = {
      id: 'ip-forwarding',
      name: 'Disable IP Forwarding for Virtual Machine Instances',
      passed: true,
      details: 'IP forwarding is disabled on all instances',
      resources: { total: vms.length, passed: vms.length, failed: [] }
    };
    
    for (const vm of vms) {
      if (vm.metadata.canIpForward === true) {
        ipForwardingCheck.resources.passed--;
        ipForwardingCheck.resources.failed.push(vm.metadata.name);
        ipForwardingCheck.passed = false;
      }
    }
    
    if (ipForwardingCheck.resources.passed < ipForwardingCheck.resources.total) {
      ipForwardingCheck.details = `Found ${ipForwardingCheck.resources.total - ipForwardingCheck.resources.passed} VMs with IP forwarding enabled`;
    }
    
    results.push(ipForwardingCheck);
    
    // Check 6: Serial Console
    const serialConsoleCheck = {
      id: 'serial-console',
      name: 'Disable Interactive Serial Console Support',
      passed: true,
      details: 'Interactive serial console is disabled for all instances',
      resources: { total: vms.length, passed: vms.length, failed: [] }
    };
    
    for (const vm of vms) {
      const metadata = vm.metadata.metadata || {};
      const items = metadata.items || [];
      const serialConsoleEnabled = items.some(item => 
        item.key === 'serial-port-enable' && 
        (item.value === 'true' || item.value === 'TRUE')
      );
      
      if (serialConsoleEnabled) {
        serialConsoleCheck.resources.passed--;
        serialConsoleCheck.resources.failed.push(vm.metadata.name);
        serialConsoleCheck.passed = false;
      }
    }
    
    if (serialConsoleCheck.resources.passed < serialConsoleCheck.resources.total) {
      serialConsoleCheck.details = `Found ${serialConsoleCheck.resources.total - serialConsoleCheck.resources.passed} VMs with interactive serial console enabled`;
    }
    
    results.push(serialConsoleCheck);
    
    // Check 7: Project SSH Keys
    const projectSshKeysCheck = {
      id: 'project-ssh-keys',
      name: 'Enable "Block Project-Wide SSH Keys" Security Feature',
      passed: true,
      details: 'All VMs are configured to block project-wide SSH keys',
      resources: { total: vms.length, passed: vms.length, failed: [] }
    };
    
    for (const vm of vms) {
      const metadata = vm.metadata.metadata || {};
      const items = metadata.items || [];
      const blocksProjectSshKeys = items.some(item => 
        item.key === 'block-project-ssh-keys' && 
        (item.value === 'true' || item.value === 'TRUE')
      );
      
      if (!blocksProjectSshKeys) {
        projectSshKeysCheck.resources.passed--;
        projectSshKeysCheck.resources.failed.push(vm.metadata.name);
        projectSshKeysCheck.passed = false;
      }
    }
    
    if (projectSshKeysCheck.resources.passed < projectSshKeysCheck.resources.total) {
      projectSshKeysCheck.details = `Found ${projectSshKeysCheck.resources.total - projectSshKeysCheck.resources.passed} VMs that do not block project-wide SSH keys`;
    }
    
    results.push(projectSshKeysCheck);
    
    // Check 8: Shielded VM
    const shieldedVmCheck = {
      id: 'shielded-vm',
      name: 'Enable "Shielded VM" Security Feature',
      passed: true,
      details: 'Shielded VM feature is enabled for all instances',
      resources: { total: vms.length, passed: vms.length, failed: [] }
    };
    
    for (const vm of vms) {
      const shieldedInstanceConfig = vm.metadata.shieldedInstanceConfig || {};
      if (!shieldedInstanceConfig.enableVtpm || !shieldedInstanceConfig.enableIntegrityMonitoring) {
        shieldedVmCheck.resources.passed--;
        shieldedVmCheck.resources.failed.push(vm.metadata.name);
        shieldedVmCheck.passed = false;
      }
    }
    
    if (shieldedVmCheck.resources.passed < shieldedVmCheck.resources.total) {
      shieldedVmCheck.details = `Found ${shieldedVmCheck.resources.total - shieldedVmCheck.resources.passed} VMs without Shielded VM features enabled`;
    }
    
    results.push(shieldedVmCheck);
    
    // Check 9: Auto-Restart
    const autoRestartCheck = {
      id: 'auto-restart',
      name: 'Enable Automatic Restart for VM Instances',
      passed: true,
      details: 'All VMs have automatic restart enabled',
      resources: { total: vms.length, passed: vms.length, failed: [] }
    };
    
    for (const vm of vms) {
      const scheduling = vm.metadata.scheduling || {};
      if (scheduling.automaticRestart !== true) {
        autoRestartCheck.resources.passed--;
        autoRestartCheck.resources.failed.push(vm.metadata.name);
        autoRestartCheck.passed = false;
      }
    }
    
    if (autoRestartCheck.resources.passed < autoRestartCheck.resources.total) {
      autoRestartCheck.details = `Found ${autoRestartCheck.resources.total - autoRestartCheck.resources.passed} VMs without automatic restart enabled`;
    }
    
    results.push(autoRestartCheck);
    
    // Check 10: Confidential Computing
    const confidentialComputingCheck = {
      id: 'confidential-computing',
      name: 'Enable Confidential Computing for Virtual Machine Instances',
      passed: true,
      details: 'Confidential Computing is enabled for all instances',
      resources: { total: vms.length, passed: vms.length, failed: [] }
    };
    
    for (const vm of vms) {
      const confidentialInstanceConfig = vm.metadata.confidentialInstanceConfig || {};
      if (!confidentialInstanceConfig || !confidentialInstanceConfig.enableConfidentialCompute) {
        confidentialComputingCheck.resources.passed--;
        confidentialComputingCheck.resources.failed.push(vm.metadata.name);
        confidentialComputingCheck.passed = false;
      }
    }
    
    if (confidentialComputingCheck.resources.passed < confidentialComputingCheck.resources.total) {
      confidentialComputingCheck.details = `Found ${confidentialComputingCheck.resources.total - confidentialComputingCheck.resources.passed} VMs without Confidential Computing enabled`;
    }
    
    results.push(confidentialComputingCheck);
    
    // Check 11: Deletion Protection
    const deletionProtectionCheck = {
      id: 'deletion-protection',
      name: 'Enable Deletion Protection for VM Instances',
      passed: true,
      details: 'All VMs have deletion protection enabled',
      resources: { total: vms.length, passed: vms.length, failed: [] }
    };
    
    for (const vm of vms) {
      if (vm.metadata.deletionProtection !== true) {
        deletionProtectionCheck.resources.passed--;
        deletionProtectionCheck.resources.failed.push(vm.metadata.name);
        deletionProtectionCheck.passed = false;
      }
    }
    
    if (deletionProtectionCheck.resources.passed < deletionProtectionCheck.resources.total) {
      deletionProtectionCheck.details = `Found ${deletionProtectionCheck.resources.total - deletionProtectionCheck.resources.passed} VMs without deletion protection enabled`;
    }
    
    results.push(deletionProtectionCheck);
    
    // Check 12: OS Login
    const projectMetadata = await compute.getProjectMetadata();
    const osLoginEnabled = projectMetadata && 
                          projectMetadata.metadata && 
                          projectMetadata.metadata.items && 
                          projectMetadata.metadata.items.some(item => 
                            item.key === 'enable-oslogin' && 
                            item.value === 'TRUE'
                          );
    
    const osLoginCheck = {
      id: 'os-login',
      name: 'Enable OS Login for GCP Projects',
      passed: osLoginEnabled,
      details: osLoginEnabled ? 
        'OS Login is enabled at the project level' : 
        'OS Login is not enabled at the project level',
      resources: { total: vms.length, passed: osLoginEnabled ? vms.length : 0, failed: osLoginEnabled ? [] : vms.map(vm => vm.metadata.name) }
    };
    
    results.push(osLoginCheck);

    // Check 13: Integrity Monitoring
    const integrityMonitoringCheck = {
      id: 'integrity-monitoring',
      name: 'Enable Integrity Monitoring Feature',
      passed: true,
      details: 'Integrity monitoring is enabled for all instances',
      resources: { total: vms.length, passed: vms.length, failed: [] }
    };
    
    for (const vm of vms) {
      const shieldedInstanceConfig = vm.metadata.shieldedInstanceConfig || {};
      if (!shieldedInstanceConfig.enableIntegrityMonitoring) {
        integrityMonitoringCheck.resources.passed--;
        integrityMonitoringCheck.resources.failed.push(vm.metadata.name);
        integrityMonitoringCheck.passed = false;
      }
    }
    
    if (integrityMonitoringCheck.resources.passed < integrityMonitoringCheck.resources.total) {
      integrityMonitoringCheck.details = `Found ${integrityMonitoringCheck.resources.total - integrityMonitoringCheck.resources.passed} VMs without integrity monitoring enabled`;
    }
    
    results.push(integrityMonitoringCheck);
    
    // Check 14: Secure Boot
    const secureBootCheck = {
      id: 'secure-boot',
      name: 'Enable Secure Boot Security Feature',
      passed: true,
      details: 'Secure boot is enabled for all instances',
      resources: { total: vms.length, passed: vms.length, failed: [] }
    };
    
    for (const vm of vms) {
      const shieldedInstanceConfig = vm.metadata.shieldedInstanceConfig || {};
      if (!shieldedInstanceConfig.enableSecureBoot) {
        secureBootCheck.resources.passed--;
        secureBootCheck.resources.failed.push(vm.metadata.name);
        secureBootCheck.passed = false;
      }
    }
    
    if (secureBootCheck.resources.passed < secureBootCheck.resources.total) {
      secureBootCheck.details = `Found ${secureBootCheck.resources.total - secureBootCheck.resources.passed} VMs without secure boot enabled`;
    }
    
    results.push(secureBootCheck);
    
    // Check 15: Preemptibility
    const preemptibilityCheck = {
      id: 'preemptibility',
      name: 'Disable Preemptibility for VM Instances',
      passed: true,
      details: 'No VMs are configured as preemptible',
      resources: { total: vms.length, passed: vms.length, failed: [] }
    };
    
    for (const vm of vms) {
      const scheduling = vm.metadata.scheduling || {};
      if (scheduling.preemptible === true) {
        preemptibilityCheck.resources.passed--;
        preemptibilityCheck.resources.failed.push(vm.metadata.name);
        preemptibilityCheck.passed = false;
      }
    }
    
    if (preemptibilityCheck.resources.passed < preemptibilityCheck.resources.total) {
      preemptibilityCheck.details = `Found ${preemptibilityCheck.resources.total - preemptibilityCheck.resources.passed} preemptible VMs`;
    }
    
    results.push(preemptibilityCheck);
    
    return results;
  } catch (error) {
    console.error('Error evaluating Compute Engine:', error);
    throw error;
  }
}

module.exports = {
  evaluateComputeEngine
}; 