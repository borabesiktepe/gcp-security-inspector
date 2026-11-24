# Minimum IAM Roles for Multi-Project GCP Inspector

To scan multiple projects in your organization with this app, your service account needs the following roles:

| Purpose                | Role Name                        |
|------------------------|----------------------------------|
| List all projects      | roles/browser                    |
| Compute Engine         | roles/compute.viewer             |
| Cloud Storage          | roles/storage.viewer             |
| Kubernetes Engine      | roles/container.viewer           |
| IAM                    | roles/iam.viewer                 |
| VPC                    | roles/compute.networkViewer      |

## Notes
- Assign these roles at the organization level for the service account to cover all projects.
- Alternatively, `roles/viewer` at the org level is sufficient for most read-only scans, but the above roles are the minimum for least privilege.
- The service account key you upload must have these permissions in every project you want to scan. 