import React, { useState, useEffect } from 'react';
import { 
  Box, 
  Typography, 
  Paper, 
  Divider, 
  List, 
  ListItem, 
  ListItemText, 
  ListItemIcon, 
  Chip,
  Card,
  CardContent,
  CardHeader,
  Alert,
  AlertTitle,
  CircularProgress,
  Grid,
  IconButton,
  Link
} from '@mui/material';
import { useParams, useNavigate } from 'react-router-dom';
import ArrowBackIcon from '@mui/icons-material/ArrowBack';
import CheckCircleIcon from '@mui/icons-material/CheckCircle';
import ErrorIcon from '@mui/icons-material/Error';
import WarningIcon from '@mui/icons-material/Warning';

// Mock service specific checks from Compute Engine in the PRD
const mockComputeEngineChecks = [
  { id: 'vm-image', name: 'Approved Virtual Machine Image in Use', passed: true, details: 'All VMs use approved images' },
  { id: 'public-ip', name: 'Check for Virtual Machine Instances with Public IP Addresses', passed: false, details: 'Found 2 VMs with public IP addresses' },
  { id: 'multiple-nics', name: 'Compute Instances with Multiple Network Interfaces', passed: true, details: 'No VMs with multiple network interfaces' },
  { id: 'maintenance-behavior', name: 'Configure Maintenance Behavior for VM Instances', passed: false, details: '3 VMs do not have maintenance behavior set to "Migrate"' },
  { id: 'ip-forwarding', name: 'Disable IP Forwarding for Virtual Machine Instances', passed: true, details: 'IP forwarding is disabled on all instances' }
];

// Mock storage checks from the PRD
const mockStorageChecks = [
  { id: 'admin-permissions', name: 'Bucket Policies with Administrative Permissions', passed: true, details: 'No buckets with admin permissions' },
  { id: 'public-access', name: 'Check for Publicly Accessible Cloud Storage Buckets', passed: false, details: 'Found 1 publicly accessible bucket' },
  { id: 'lifecycle-management', name: 'Enable Lifecycle Management for Cloud Storage Objects', passed: true, details: 'Lifecycle management enabled for all buckets' }
];

const serviceChecksMap: any = {
  'compute-engine': mockComputeEngineChecks,
  'cloud-storage': mockStorageChecks,
};

const serviceNamesMap: any = {
  'compute-engine': 'Compute Engine',
  'cloud-storage': 'Cloud Storage',
  'vpc': 'VPC',
};

const ServiceView: React.FC = () => {
  const { projectId, serviceId } = useParams<{ projectId: string, serviceId: string }>();
  const [loading, setLoading] = useState<boolean>(true);
  const [checks, setChecks] = useState<any[]>([]);
  const [serviceName, setServiceName] = useState<string>('');
  const navigate = useNavigate();

  useEffect(() => {
    const fetchServiceDetails = async () => {
      if (serviceId === 'kubernetes-engine') {
        // Fetch real data from backend for Kubernetes Engine
        try {
          const response = await fetch(`/api/projects/${projectId}/services/${serviceId}`);
          if (response.ok) {
            const data = await response.json();
            setChecks(data.checks || []);
            setServiceName(data.name || 'Kubernetes Engine');
          } else {
            setChecks([]);
            setServiceName('Kubernetes Engine');
          }
        } catch (e) {
          setChecks([]);
          setServiceName('Kubernetes Engine');
        }
      } else if (serviceId && serviceChecksMap[serviceId]) {
        setChecks(serviceChecksMap[serviceId]);
        setServiceName(serviceNamesMap[serviceId] || 'Unknown Service');
      }
      setLoading(false);
    };
    fetchServiceDetails();
  }, [serviceId, projectId]);

  const handleBack = () => {
    navigate(`/projects/${projectId}`);
  };

  const getComplianceScore = () => {
    if (!checks.length) return 0;
    const passedChecks = checks.filter(check => check.passed).length;
    return Math.round((passedChecks / checks.length) * 100);
  };

  if (loading) {
    return (
      <Box sx={{ display: 'flex', justifyContent: 'center', mt: 4 }}>
        <CircularProgress />
      </Box>
    );
  }

  const score = getComplianceScore();

  return (
    <Box>
      <Box sx={{ display: 'flex', alignItems: 'center', mb: 4 }}>
        <IconButton onClick={handleBack} sx={{ mr: 1 }}>
          <ArrowBackIcon />
        </IconButton>
        <Box>
          <Typography variant="h4" component="h1">
            {serviceName}
          </Typography>
          <Typography variant="subtitle1" color="text.secondary">
            Project ID: {projectId}
          </Typography>
        </Box>
      </Box>

      <Grid container spacing={3}>
        <Grid item xs={12} md={4}>
          <Card>
            <CardHeader title="Compliance Score" />
            <CardContent sx={{ textAlign: 'center' }}>
              <Box sx={{ position: 'relative', display: 'inline-flex' }}>
                <CircularProgress
                  variant="determinate"
                  value={score}
                  size={120}
                  sx={{ 
                    color: score >= 90 ? 'success.main' : score >= 70 ? 'warning.main' : 'error.main',
                  }}
                />
                <Box
                  sx={{
                    top: 0,
                    left: 0,
                    bottom: 0,
                    right: 0,
                    position: 'absolute',
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'center',
                  }}
                >
                  <Typography variant="h4" component="div">
                    {score}%
                  </Typography>
                </Box>
              </Box>
              
              <Typography variant="body1" sx={{ mt: 2 }}>
                Passed Checks: {checks.filter(check => check.passed).length}/{checks.length}
              </Typography>
            </CardContent>
          </Card>
        </Grid>
        <Grid item xs={12} md={8}>
          <Card>
            <CardHeader title="Security Checks" />
            <CardContent>
              <List>
                {checks.map((check, index) => (
                  <React.Fragment key={check.id}>
                    {index > 0 && <Divider />}
                    <ListItem sx={{ py: 2 }}>
                      <ListItemIcon>
                        {check.passed ? (
                          <CheckCircleIcon color="success" />
                        ) : (
                          <ErrorIcon color="error" />
                        )}
                      </ListItemIcon>
                      <ListItemText
                        primary={
                          <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                            <Typography variant="subtitle1">{check.name}</Typography>
                            <Chip 
                              label={check.passed ? 'Passed' : 'Failed'} 
                              color={check.passed ? 'success' : 'error'}
                              size="small"
                            />
                          </Box>
                        }
                        secondary={
                          <>
                            <Typography variant="body2" color="textSecondary">{check.details}</Typography>
                            {check.remediation && (
                              <Box mt={1}>
                                <Typography variant="subtitle2">Recommendation</Typography>
                                <Typography variant="body2">{check.remediation}</Typography>
                                {check.remediationLink && check.remediationLink !== '' && (
                                  <Link 
                                    href={check.remediationLink} 
                                    target="_blank" 
                                    rel="noopener"
                                    display="flex"
                                    alignItems="center"
                                    mt={0.5}
                                  >
                                    More information
                                  </Link>
                                )}
                              </Box>
                            )}
                          </>
                        }
                      />
                    </ListItem>
                  </React.Fragment>
                ))}
              </List>
            </CardContent>
          </Card>

          {!checks.every(check => check.passed) && (
            <Alert severity="warning" sx={{ mt: 3 }}>
              <AlertTitle>Remediation Required</AlertTitle>
              There are failed security checks that need to be addressed to improve your compliance score.
            </Alert>
          )}
        </Grid>
      </Grid>
    </Box>
  );
};

export default ServiceView; 