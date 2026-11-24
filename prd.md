# Google Cloud Inspector PRD

## Overview
A web application that inspects Google Cloud assets from security and architecture perspectives. The application connects to cloud projects via a service account with viewer permissions only.

## Scoring Algorithm
- Simple binary scoring: 1 point if a check passes, 0 if it fails
- Final project score calculated out of 100

## UI/UX
- Interface similar to Google Cloud's native screens
- Focus on simplicity and usability

## To-Do
- [ ] Create service account connection mechanism
- [ ] Implement authentication flow
- [ ] Design API structure for retrieving GCP assets
- [ ] Build binary scoring algorithm
- [ ] Develop checklist implementation for each service
- [ ] Create UI components matching Google Cloud's design
- [ ] Implement project listing view
- [ ] Build detailed project view with compliance scores
- [ ] Add service-specific compliance details views
- [ ] Implement reporting functionality
- [ ] Setup proper error handling
- [ ] Add documentation
- [ ] Write tests
- [ ] Deploy application
- [] Initial project setup
- [] Basic project structure defined
- [] PRD document created
- [] Compute Engine ruleset defined
- [] Cloud Storage ruleset defined
- [] Cloud Run ruleset defined
- [] VPC ruleset defined
- [] Artifact Registry ruleset defined
- [] BigQuery ruleset defined
- [] Vertex AI ruleset defined
- [] Cloud Load Balancer ruleset defined
- [] IAM ruleset defined

## Services to Check

### Compute Engine
| Checklist Name | What to check? | Scoring |
|----------------|----------------|---------|
| Approved Virtual Machine Image in Use | Ensure that all your virtual machine instances are launched from approved images only. | If a VM launched with not approved image 0, else 1 |
| Check for Virtual Machine Instances with Public IP Addresses | Ensure that Google Cloud VM instances are not using public IP addresses. | If a VM is using a public (external) IP 0, else 1 |
| Compute Instances with Multiple Network Interfaces | Ensure that virtual machine (VM) instances are not using multiple network interfaces. | If a VM is using multiple network interface 0, else 1 |
| Configure Maintenance Behavior for VM Instances | Ensure that "On Host Maintenance" configuration setting is set to "Migrate" for all VM instances. | If a VM's on the host maintenance config setting is not migrate 0, else 1 |
| Disable IP Forwarding for Virtual Machine Instances | Ensure that IP Forwarding is not enabled for your Google Cloud virtual machine (VM) instances. | If IP forwarding enabled for a VM 0, else 1 |
| Disable Interactive Serial Console Support | Ensure that interactive serial console support is not enabled for your Google Cloud instances. | If interactive serial console support is enabled 0, else 1 |
| Enable "Block Project-Wide SSH Keys" Security Feature | Ensure that project-wide SSH keys are not used to access your Google Cloud VM instances. | If project-wide ssh key is used to acces to a VM 0, else 1 |
| Enable "Shielded VM" Security Feature | Ensure that Shielded VM feature is enabled for your virtual machine (VM) instances. | If shielded VM feature is not enabled for a VM 0, else 1 |
| Enable Automatic Restart for VM Instances | Ensure that automatic restart is enabled for your Google Cloud virtual machine (VM) instances. | If automatic restart is not enabled for a VM 0, else 1 |
| Enable Confidential Computing for Virtual Machine Instances | Ensure that Confidential Computing is enabled for virtual machine (VM) instances. | If confidential computing is not enabled for a VM 0, else 1 |
| Enable Deletion Protection for VM Instances | Ensure that deletion protection is enabled for your Google Cloud virtual machine (VM) instances. | If deletion protection is not enabled for a VM 0, else 1 |
| Enable OS Login for GCP Projects | Ensure that the OS Login feature is enabled for your Google Cloud projects. | If OS login feature is not enabled for a VM 0, else 1 |
| Enable Integrity Monitoring Feature | Ensure that integrity monitoring feature is enabled for your VM. | If integrity monitoring feature is not enabled for a VM 0, else 1 |
| Enable Secure Boot Security Feature | Ensure that security boot feature is enabled for your VM | If security boot feature is not enabled for a VM 0, else 1 |
| Disable Preemptibility for VM Instances | Ensure that your Google Cloud virtual machine instances are not preemptible. | If the VM instance is preemptible 0, else 1 |

### Cloud Storage
| Checklist Name | What to check? | Scoring |
|----------------|----------------|---------|
| Bucket Policies with Administrative Permissions | Ensure that your Google Cloud Storage buckets are not configured with admin permissions. | If the bucket is configured with administrative permissions 0, else 1 |
| Check for Publicly Accessible Cloud Storage Buckets | Ensure there are no publicly accessible Cloud Storage buckets available within your Google Cloud Platform (GCP) account. | If bucket is publicly accessible 0, else 1 |
| Define Index page suffix and error page for the bucket website | Ensure that bucket website configuration includes main page suffix and error page. | If the bucket website has not a main page suffix and error page 0, else 1 |
| Enable Lifecycle Management for Cloud Storage Objects | Ensure that Google Cloud Storage objects are using a lifecycle configuration for cost management. | For the bucket if there are no lifecycle management rules created and the value is set to Not for object versioning is not enabled for the bucket 0, else 1 |
| Enable Object Versioning for Cloud Storage Buckets | Ensure that object versioning is enabled for your Google Cloud Storage buckets. | If object versioning is not enabled for the bucket 0, else 1 |
| Enable Uniform Bucket-Level Access for Cloud Storage Buckets | Ensure that Google Cloud Storage buckets have uniform bucket-level access enabled. | If bucket has not uniform bucket-level access disabled 0, else 1 |
| Enable Usage and Storage Logs | Ensure that usage and storage logs are enabled for your Google Cloud Storage buckets. | If usage and storage logs are disabled for bucket 0, else 1 |
| Enforce Public Access Prevention | Ensure that Public Access Prevention is enabled for your Google Cloud Storage buckets. | If public access prevention is disabled for bucket 0, else 1 |
| Secure CORS Configuration | Ensure that CORS configuration for your Google Cloud Storage buckets is compliant. | If CORS configuration for bucket is not compliant 0, else 1 |

*Additional services and rules will be added in future updates.* 