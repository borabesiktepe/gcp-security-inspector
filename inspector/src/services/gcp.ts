// Real service implementation that calls the backend API
// instead of using browser-based mocks

interface ServiceAccountCredentials {
  projectId: string;
  clientEmail: string;
  privateKey: string;
}

interface CheckResult {
  id: string;
  name: string;
  passed: boolean;
  details: string;
  remediation?: string;
  remediationLink?: string;
  resources: {
    total: number;
    passed: number;
  };
}

interface ServiceCheckResults {
  id: string;
  name: string;
  score: number;
  checks: CheckResult[];
}

interface ScanResults {
  projectId: string;
  projectName: string;
  score: number;
  services: ServiceCheckResults[];
}

interface ConnectionResult {
  success: boolean;
  error?: string;
}

class GCPService {
  private credentials: ServiceAccountCredentials | null = null;
  private apiUrl: string = 'http://localhost:4000/api'; // Update with your backend URL
  private projectId: string = '';

  /**
   * Initialize GCP service connections with credentials via backend API
   */
  public async connect(credentials: ServiceAccountCredentials): Promise<ConnectionResult> {
    try {
      this.credentials = credentials;
      this.projectId = credentials.projectId;
      
      // Convert credentials to the format expected by the backend API
      const serviceAccountKey = {
        project_id: credentials.projectId,
        client_email: credentials.clientEmail,
        private_key: credentials.privateKey
      };
      
      // Authenticate with the backend
      const response = await fetch(`${this.apiUrl}/authenticate`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({ serviceAccountKey })
      });
      
      const result = await response.json();
      
      if (!response.ok || !result.success) {
        throw new Error(result.error || 'Failed to authenticate with Google Cloud');
      }
      
      return { success: true };
    } catch (error) {
      console.error('Failed to connect to GCP:', error);
      return { 
        success: false, 
        error: error instanceof Error ? error.message : 'Unknown error connecting to Google Cloud' 
      };
    }
  }

  /**
   * Scan the project for security checks
   * @param onProgress Optional callback for progress updates: (step: string, percent: number) => void
   * @param projectId Optional projectId to scan (for multi-project scan)
   */
  public async scanProject(onProgress?: (step: string, percent: number) => void, projectId?: string): Promise<ScanResults> {
    if (!this.credentials) {
      throw new Error('GCP service not initialized');
    }
    try {
      const steps = [
        'Compute Engine',
        'Cloud Storage',
        'Kubernetes Engine',
        'IAM',
        'VPC'
      ];
      if (onProgress) onProgress('Starting scan...', 0);
      // Convert credentials to the format expected by the backend API
      const serviceAccountKey = {
        project_id: this.credentials.projectId,
        client_email: this.credentials.clientEmail,
        private_key: this.credentials.privateKey
      };
      // Call the backend scan API
      const body: any = { serviceAccountKey };
      if (projectId) body.projectId = projectId;
      const response = await fetch(`${this.apiUrl}/scan`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify(body)
      });
      if (!response.ok) {
        const errorData = await response.json();
        throw new Error(errorData.error || 'Failed to scan Google Cloud project');
      }
      // Simulate stepwise progress for UI
      const scanResults: ScanResults = await response.json();
      const total = steps.length;
      for (let i = 0; i < steps.length; i++) {
        if (onProgress) onProgress(`Scanning ${steps[i]}...`, Math.round(((i + 1) / total) * 100));
        await new Promise(res => setTimeout(res, 400)); // Simulate delay for effect
      }
      if (onProgress) onProgress('Scan complete!', 100);
      return scanResults;
    } catch (error) {
      console.error('Error scanning project:', error);
      throw new Error('Failed to scan Google Cloud project');
    }
  }

  /**
   * Disconnect and clean up
   */
  public disconnect(): void {
    this.credentials = null;
  }
}

export default new GCPService(); 