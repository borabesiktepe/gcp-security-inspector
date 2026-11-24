/**
 * Evaluate Cloud Storage resources for security compliance
 */
async function evaluateCloudStorage(storage) {
  try {
    const [buckets] = await storage.getBuckets();
    const results = [];
    
    if (!buckets || buckets.length === 0) {
      // No buckets to check
      return [
        {
          id: 'no-buckets',
          name: 'No Cloud Storage Buckets Found',
          passed: true,
          details: 'No Cloud Storage buckets were found in this project.',
          resources: { total: 0, passed: 0 }
        }
      ];
    }

    // Check 1: Public Access
    const publicAccessCheck = {
      id: 'public-access',
      name: 'Check for Publicly Accessible Cloud Storage Buckets',
      passed: true,
      details: 'No publicly accessible buckets found',
      resources: { total: buckets.length, passed: buckets.length, failed: [] }
    };
    let publicBucketsCount = 0;
    for (const bucket of buckets) {
      try {
        const [policy] = await bucket.iam.getPolicy();
        const hasPublicAccess = policy.bindings?.some(binding => 
          binding.members?.includes('allUsers') || binding.members?.includes('allAuthenticatedUsers')
        );
        if (hasPublicAccess) {
          publicBucketsCount++;
          publicAccessCheck.resources.passed--;
          publicAccessCheck.resources.failed.push(bucket.name);
          publicAccessCheck.passed = false;
        }
      } catch (error) {
        console.error(`Failed to get policy for bucket ${bucket.name}:`, error);
      }
    }
    if (publicBucketsCount > 0) {
      publicAccessCheck.details = `Found ${publicBucketsCount} publicly accessible buckets`;
    }
    results.push(publicAccessCheck);

    // Check 2: Object Versioning
    const objectVersioningCheck = {
      id: 'object-versioning',
      name: 'Enable Object Versioning for Cloud Storage Buckets',
      passed: true,
      details: 'Object versioning is enabled for all buckets',
      resources: { total: buckets.length, passed: buckets.length, failed: [] }
    };
    for (const bucket of buckets) {
      try {
        const [metadata] = await bucket.getMetadata();
        if (!metadata.versioning || !metadata.versioning.enabled) {
          objectVersioningCheck.resources.passed--;
          objectVersioningCheck.resources.failed.push(bucket.name);
          objectVersioningCheck.passed = false;
        }
      } catch (error) {
        console.error(`Failed to get versioning for bucket ${bucket.name}:`, error);
      }
    }
    if (objectVersioningCheck.resources.passed < objectVersioningCheck.resources.total) {
      objectVersioningCheck.details = `Found ${objectVersioningCheck.resources.total - objectVersioningCheck.resources.passed} buckets without object versioning enabled`;
    }
    results.push(objectVersioningCheck);

    // Check 3: Lifecycle Management
    const lifecycleCheck = {
      id: 'lifecycle-management',
      name: 'Enable Lifecycle Management for Cloud Storage Objects',
      passed: true,
      details: 'All buckets have lifecycle management enabled',
      resources: { total: buckets.length, passed: buckets.length, failed: [] }
    };
    for (const bucket of buckets) {
      try {
        const [metadata] = await bucket.getMetadata();
        if (!metadata.lifecycle || !metadata.lifecycle.rule || metadata.lifecycle.rule.length === 0) {
          lifecycleCheck.resources.passed--;
          lifecycleCheck.resources.failed.push(bucket.name);
          lifecycleCheck.passed = false;
        }
      } catch (error) {
        console.error(`Failed to get lifecycle for bucket ${bucket.name}:`, error);
      }
    }
    if (lifecycleCheck.resources.passed < lifecycleCheck.resources.total) {
      lifecycleCheck.details = `Found ${lifecycleCheck.resources.total - lifecycleCheck.resources.passed} buckets without lifecycle management`;
    }
    results.push(lifecycleCheck);

    // Check 4: Bucket-Level Access
    const bucketLevelAccessCheck = {
      id: 'bucket-level-access',
      name: 'Enable Uniform Bucket-Level Access for Cloud Storage Buckets',
      passed: true,
      details: 'Uniform bucket-level access is enabled for all buckets',
      resources: { total: buckets.length, passed: buckets.length, failed: [] }
    };
    for (const bucket of buckets) {
      try {
        const [metadata] = await bucket.getMetadata();
        if (!metadata.iamConfiguration || !metadata.iamConfiguration.uniformBucketLevelAccess || !metadata.iamConfiguration.uniformBucketLevelAccess.enabled) {
          bucketLevelAccessCheck.resources.passed--;
          bucketLevelAccessCheck.resources.failed.push(bucket.name);
          bucketLevelAccessCheck.passed = false;
        }
      } catch (error) {
        console.error(`Failed to get IAM config for bucket ${bucket.name}:`, error);
      }
    }
    if (bucketLevelAccessCheck.resources.passed < bucketLevelAccessCheck.resources.total) {
      bucketLevelAccessCheck.details = `Found ${bucketLevelAccessCheck.resources.total - bucketLevelAccessCheck.resources.passed} buckets without uniform bucket-level access enabled`;
    }
    results.push(bucketLevelAccessCheck);

    // Check 5: Public Access Prevention
    const publicAccessPreventionCheck = {
      id: 'public-access-prevention',
      name: 'Enforce Public Access Prevention',
      passed: true,
      details: 'Public access prevention is enforced for all buckets',
      resources: { total: buckets.length, passed: buckets.length, failed: [] }
    };
    for (const bucket of buckets) {
      try {
        const [metadata] = await bucket.getMetadata();
        if (!metadata.iamConfiguration || !metadata.iamConfiguration.publicAccessPrevention || metadata.iamConfiguration.publicAccessPrevention !== 'enforced') {
          publicAccessPreventionCheck.resources.passed--;
          publicAccessPreventionCheck.resources.failed.push(bucket.name);
          publicAccessPreventionCheck.passed = false;
        }
      } catch (error) {
        console.error(`Failed to get public access prevention config for bucket ${bucket.name}:`, error);
      }
    }
    if (publicAccessPreventionCheck.resources.passed < publicAccessPreventionCheck.resources.total) {
      publicAccessPreventionCheck.details = `Found ${publicAccessPreventionCheck.resources.total - publicAccessPreventionCheck.resources.passed} buckets without public access prevention enforced`;
    }
    results.push(publicAccessPreventionCheck);

    // Check 6: Admin Permissions
    const adminPermissionsCheck = {
      id: 'admin-permissions',
      name: 'Bucket Policies with Administrative Permissions',
      passed: true,
      details: 'No buckets with admin permissions',
      resources: { total: buckets.length, passed: buckets.length, failed: [] }
    };
    const adminRoles = ['roles/storage.admin', 'roles/owner'];
    for (const bucket of buckets) {
      try {
        const [policy] = await bucket.iam.getPolicy();
        const hasAdminPermission = policy.bindings?.some(binding => 
          adminRoles.includes(binding.role) && binding.members?.some(member => 
            member.startsWith('user:') || member.startsWith('serviceAccount:')
          )
        );
        if (hasAdminPermission) {
          adminPermissionsCheck.resources.passed--;
          adminPermissionsCheck.resources.failed.push(bucket.name);
          adminPermissionsCheck.passed = false;
        }
      } catch (error) {
        console.error(`Failed to check admin permissions for bucket ${bucket.name}:`, error);
      }
    }
    if (adminPermissionsCheck.resources.passed < adminPermissionsCheck.resources.total) {
      adminPermissionsCheck.details = `Found ${adminPermissionsCheck.resources.total - adminPermissionsCheck.resources.passed} buckets with admin permissions granted to users or service accounts`;
    }
    results.push(adminPermissionsCheck);

    // Check 7: Website Configuration
    const websiteConfigCheck = {
      id: 'website-config',
      name: 'Define Index page suffix and error page for the bucket website',
      passed: true,
      details: 'All buckets configured as websites have proper error page configuration',
      resources: { total: 0, passed: 0, failed: [] }
    };
    let websiteBucketsCount = 0;
    for (const bucket of buckets) {
      try {
        const [metadata] = await bucket.getMetadata();
        if (metadata.website) {
          websiteBucketsCount++;
          if (!metadata.website.mainPageSuffix || !metadata.website.notFoundPage) {
            websiteConfigCheck.resources.passed--;
            websiteConfigCheck.resources.failed.push(bucket.name);
            websiteConfigCheck.passed = false;
          } else {
            websiteConfigCheck.resources.passed++;
          }
          websiteConfigCheck.resources.total++;
        }
      } catch (error) {
        console.error(`Failed to get website config for bucket ${bucket.name}:`, error);
      }
    }
    if (websiteConfigCheck.resources.total === 0) {
      websiteConfigCheck.details = 'No buckets are configured as websites';
    } else if (websiteConfigCheck.resources.passed < websiteConfigCheck.resources.total) {
      websiteConfigCheck.details = `Found ${websiteConfigCheck.resources.total - websiteConfigCheck.resources.passed} buckets configured as websites missing error page configuration`;
    }
    results.push(websiteConfigCheck);

    // Check 8: Usage and Storage Logs
    const usageLogsCheck = {
      id: 'usage-logs',
      name: 'Enable Usage and Storage Logs',
      passed: true,
      details: 'Usage and storage logs are enabled for all buckets',
      resources: { total: buckets.length, passed: buckets.length, failed: [] }
    };
    for (const bucket of buckets) {
      try {
        const [metadata] = await bucket.getMetadata();
        if (!metadata.logging || !metadata.logging.logBucket) {
          usageLogsCheck.resources.passed--;
          usageLogsCheck.resources.failed.push(bucket.name);
          usageLogsCheck.passed = false;
        }
      } catch (error) {
        console.error(`Failed to get logging config for bucket ${bucket.name}:`, error);
      }
    }
    if (usageLogsCheck.resources.passed < usageLogsCheck.resources.total) {
      usageLogsCheck.details = `Found ${usageLogsCheck.resources.total - usageLogsCheck.resources.passed} buckets without usage logs enabled`;
    }
    results.push(usageLogsCheck);

    // Check 9: CORS Configuration
    const corsConfigCheck = {
      id: 'cors-config',
      name: 'Secure CORS Configuration',
      passed: true,
      details: 'All buckets have secure CORS configuration',
      resources: { total: buckets.length, passed: buckets.length, failed: [] }
    };
    for (const bucket of buckets) {
      try {
        const [metadata] = await bucket.getMetadata();
        if (metadata.cors) {
          const hasWildcardOrigin = metadata.cors.some(corsConfig => 
            corsConfig.origin && corsConfig.origin.includes('*')
          );
          if (hasWildcardOrigin) {
            corsConfigCheck.resources.passed--;
            corsConfigCheck.resources.failed.push(bucket.name);
            corsConfigCheck.passed = false;
          }
        }
      } catch (error) {
        console.error(`Failed to get CORS config for bucket ${bucket.name}:`, error);
      }
    }
    if (corsConfigCheck.resources.passed < corsConfigCheck.resources.total) {
      corsConfigCheck.details = `Found ${corsConfigCheck.resources.total - corsConfigCheck.resources.passed} buckets with wildcard (*) CORS origins`;
    }
    results.push(corsConfigCheck);

    return results;
  } catch (error) {
    console.error('Error evaluating Cloud Storage:', error);
    throw error;
  }
}

module.exports = {
  evaluateCloudStorage
}; 