import React, { useState, useRef } from 'react';
import { 
  Container, 
  Box, 
  Typography, 
  Button, 
  Paper, 
  TextField,
  Alert,
  CircularProgress,
  LinearProgress
} from '@mui/material';
import CloudUploadIcon from '@mui/icons-material/CloudUpload';
import gcpService from '../services/gcp';

interface LoginProps {
  onLogin: (data: any) => void;
}

const Login: React.FC<LoginProps> = ({ onLogin }) => {
  const [file, setFile] = useState<File | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [progress, setProgress] = useState(0);
  const [progressLabel, setProgressLabel] = useState<string>('');
  const fileInputRef = useRef<HTMLInputElement>(null);
  const [projects, setProjects] = useState<any[]>([]);
  const [selectedProjects, setSelectedProjects] = useState<string[]>([]);
  const [step, setStep] = useState<'upload' | 'select' | 'scan'>('upload');

  const handleFileChange = (event: React.ChangeEvent<HTMLInputElement>) => {
    if (event.target.files && event.target.files[0]) {
      setFile(event.target.files[0]);
      setError(null);
    }
  };

  const handleLogin = async () => {
    if (!file) {
      setError('Please select a service account key file');
      return;
    }
    setLoading(true);
    setProgress(0);
    setProgressLabel('');
    setError(null);
    try {
      // Read the file content
      const fileContent = await readFileAsText(file);
      let keyData;
      // Parse JSON content
      try {
        keyData = JSON.parse(fileContent);
      } catch (err) {
        throw new Error('Invalid JSON format in the key file');
      }
      // Validate key file structure
      if (!keyData.project_id || !keyData.client_email || !keyData.private_key) {
        throw new Error('The file is not a valid Google Cloud service account key');
      }
      // Attempt to connect using the service account
      const connection = await gcpService.connect({
        projectId: keyData.project_id,
        clientEmail: keyData.client_email,
        privateKey: keyData.private_key
      });
      if (!connection.success) {
        throw new Error(connection.error || 'Failed to connect to Google Cloud');
      }
      // Fetch accessible projects
      const resp = await fetch('http://localhost:4000/api/projects', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ serviceAccountKey: keyData })
      });
      const data = await resp.json();
      if (!data.success) throw new Error(data.error || 'Failed to list projects');
      setProjects(data.projects);
      setStep('select');
    } catch (err) {
      console.error('Login error:', err);
      const errorMessage = err instanceof Error ? err.message : 'Failed to authenticate. Please check your key file and try again.';
      setError(errorMessage);
    } finally {
      setLoading(false);
      setProgress(0);
      setProgressLabel('');
    }
  };

  const readFileAsText = (file: File): Promise<string> => {
    return new Promise((resolve, reject) => {
      const reader = new FileReader();
      reader.onload = () => resolve(reader.result as string);
      reader.onerror = () => reject(new Error('Failed to read file'));
      reader.readAsText(file);
    });
  };

  const handleBrowseClick = () => {
    fileInputRef.current?.click();
  };

  const handleProjectSelect = (projectId: string) => {
    setSelectedProjects(prev => prev.includes(projectId)
      ? prev.filter(id => id !== projectId)
      : [...prev, projectId]);
  };

  const handleScanSelected = async () => {
    setStep('scan');
    setLoading(true);
    setProgress(0);
    setProgressLabel('');
    try {
      const allResults = [];
      for (let i = 0; i < selectedProjects.length; i++) {
        const projectId = selectedProjects[i];
        setProgressLabel(`Scanning ${projectId} (${i + 1}/${selectedProjects.length})...`);
        const scanResults = await gcpService.scanProject((step, percent) => {
          setProgress(Math.round((i / selectedProjects.length) * 100 + percent / selectedProjects.length));
          setProgressLabel(`${step} (${i + 1}/${selectedProjects.length})...`);
        }, projectId);
        allResults.push(scanResults);
      }
      onLogin(allResults);
    } catch (err) {
      setError('Scan failed: ' + (err instanceof Error ? err.message : 'Unknown error'));
    } finally {
      setLoading(false);
      setProgress(0);
      setProgressLabel('');
    }
  };

  return (
    <Container maxWidth="sm" sx={{ mt: 8 }}>
      <Paper elevation={3} sx={{ p: 4 }}>
        <Box sx={{ display: 'flex', flexDirection: 'column', alignItems: 'center', mb: 4 }}>
          <img
            src="/images/all-in-cloud-horiz-logo-dark.png"
            alt="All-In-Cloud"
            style={{ width: '260px', maxWidth: '100%', height: 'auto', marginBottom: '20px' }}
          />
          <Typography variant="h4" component="h1" gutterBottom sx={{ color: 'primary.main', fontWeight: 'bold' }}>
            Cloud Inspector
          </Typography>
        </Box>

        {/* Step 1: Upload Key */}
        {step === 'upload' && (
          <>
            <Typography variant="body1" gutterBottom>
              Securely scan your Google Cloud project for security risks, misconfigurations, and best practice violations.
            </Typography>
            
            <Box sx={{ display: 'flex', alignItems: 'center', mt: 1 }}>
              <TextField
                fullWidth
                variant="outlined"
                placeholder="No file selected"
                value={file ? file.name : ''}
                InputProps={{
                  readOnly: true,
                }}
                size="small"
              />
              <Button
                variant="contained"
                component="label"
                onClick={handleBrowseClick}
                sx={{ ml: 1, whiteSpace: 'nowrap' }}
              >
                Browse
              </Button>
              <input
                type="file"
                accept="application/json"
                hidden
                ref={fileInputRef}
                onChange={handleFileChange}
              />
            </Box>

            <Button
              variant="contained"
              color="primary"
              fullWidth
              startIcon={<CloudUploadIcon />}
              sx={{ mt: 3, mb: 2, height: 48, fontWeight: 'bold', fontSize: 18 }}
              disabled={!file || loading}
              onClick={handleLogin}
            >
              CONNECT
            </Button>
          </>
        )}
        {/* Step 2: Select Projects */}
        {step === 'select' && (
          <>
            <Typography variant="h6" gutterBottom>Select Projects to Scan</Typography>
            <Box sx={{ maxHeight: 300, overflowY: 'auto', mb: 2 }}>
              {projects.map((proj: any) => (
                <Box key={proj.projectId} sx={{ display: 'flex', alignItems: 'center', mb: 1 }}>
                  <input
                    type="checkbox"
                    checked={selectedProjects.includes(proj.projectId)}
                    onChange={() => handleProjectSelect(proj.projectId)}
                    id={proj.projectId}
                  />
                  <label htmlFor={proj.projectId} style={{ marginLeft: 8 }}>
                    {proj.name || proj.projectId} <span style={{ color: '#888' }}>({proj.projectId})</span>
                  </label>
                </Box>
              ))}
            </Box>
            <Button
              variant="contained"
              color="primary"
              fullWidth
              sx={{ mt: 2, fontWeight: 'bold', fontSize: 18 }}
              disabled={selectedProjects.length === 0 || loading}
              onClick={handleScanSelected}
            >
              SCAN SELECTED PROJECTS
            </Button>
          </>
        )}
        {/* Step 3: Scan Progress */}
        {step === 'scan' && (
          <Box sx={{ width: '100%', mt: 2 }}>
            <LinearProgress variant="determinate" value={progress} />
            {progressLabel && (
              <Typography variant="body2" align="center" sx={{ mt: 1 }}>{progressLabel}</Typography>
            )}
          </Box>
        )}
        {error && (
          <Alert severity="error" sx={{ mt: 3 }}>
            {error}
          </Alert>
        )}
      </Paper>
    </Container>
  );
};

export default Login; 