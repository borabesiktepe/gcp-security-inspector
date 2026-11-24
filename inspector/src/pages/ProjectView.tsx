import React, { useState, useEffect } from 'react';
import { 
  Box, 
  Typography, 
  Paper, 
  Grid, 
  CircularProgress, 
  Chip, 
  LinearProgress, 
  Card, 
  CardContent, 
  CardHeader,
  List,
  ListItem,
  ListItemText,
  ListItemIcon,
  Divider
} from '@mui/material';
import { useParams, useNavigate } from 'react-router-dom';
import CheckCircleIcon from '@mui/icons-material/CheckCircle';
import ErrorIcon from '@mui/icons-material/Error';
import WarningIcon from '@mui/icons-material/Warning';

// Mock data
const mockProjectDetails = {
  id: 'project-1',
  name: 'Production',
  score: 85,
  services: [
    { id: 'compute-engine', name: 'Compute Engine', score: 80, violations: 3 },
    { id: 'cloud-storage', name: 'Cloud Storage', score: 90, violations: 1 },
    { id: 'vpc', name: 'VPC', score: 75, violations: 2 },
  ]
};

const ProjectView: React.FC = () => {
  const { projectId } = useParams<{ projectId: string }>();
  const [project, setProject] = useState<any>(null);
  const [loading, setLoading] = useState<boolean>(true);
  const navigate = useNavigate();

  useEffect(() => {
    // In a real app, this would fetch data from an API
    const fetchProjectDetails = async () => {
      // Simulate API call
      await new Promise(resolve => setTimeout(resolve, 1000));
      setProject(mockProjectDetails);
      setLoading(false);
    };

    fetchProjectDetails();
  }, [projectId]);

  const handleServiceClick = (serviceId: string) => {
    navigate(`/projects/${projectId}/${serviceId}`);
  };

  const getScoreColor = (score: number) => {
    if (score >= 90) return 'success.main';
    if (score >= 70) return 'warning.main';
    return 'error.main';
  };

  if (loading) {
    return (
      <Box sx={{ display: 'flex', justifyContent: 'center', mt: 4 }}>
        <CircularProgress />
      </Box>
    );
  }

  return (
    <Box>
      <Box sx={{ mb: 4 }}>
        <Typography variant="h4" component="h1">
          {project.name}
        </Typography>
        <Typography variant="subtitle1" color="text.secondary">
          Project ID: {projectId}
        </Typography>
      </Box>

      <Grid container spacing={3}>
        <Grid item xs={12} md={4}>
          <Card>
            <CardHeader title="Overall Score" />
            <CardContent>
              <Box sx={{ position: 'relative', display: 'inline-flex' }}>
                <CircularProgress
                  variant="determinate"
                  value={project.score}
                  size={100}
                  sx={{ color: getScoreColor(project.score) }}
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
                  <Typography variant="h5" component="div" color="text.secondary">
                    {project.score}%
                  </Typography>
                </Box>
              </Box>
              <Box sx={{ mt: 2 }}>
                <Typography variant="body1" component="div">
                  Services: {project.services.length}
                </Typography>
                <Typography variant="body1" component="div">
                  Violations: {project.services.reduce((acc: number, svc: any) => acc + svc.violations, 0)}
                </Typography>
              </Box>
            </CardContent>
          </Card>
        </Grid>
        <Grid item xs={12} md={8}>
          <Card>
            <CardHeader title="Services" />
            <CardContent>
              <List>
                {project.services.map((service: any, index: number) => (
                  <React.Fragment key={service.id}>
                    {index > 0 && <Divider />}
                    <ListItem 
                      button 
                      onClick={() => handleServiceClick(service.id)}
                      sx={{ py: 2 }}
                    >
                      <ListItemIcon>
                        {service.score === 100 ? (
                          <CheckCircleIcon color="success" />
                        ) : service.score >= 80 ? (
                          <WarningIcon color="warning" />
                        ) : (
                          <ErrorIcon color="error" />
                        )}
                      </ListItemIcon>
                      <ListItemText
                        primary={service.name}
                        secondary={
                          <Box sx={{ mt: 1 }}>
                            <Box sx={{ display: 'flex', alignItems: 'center', mb: 1 }}>
                              <Typography variant="body2" sx={{ minWidth: 60 }}>
                                {service.score}%
                              </Typography>
                              <LinearProgress 
                                variant="determinate" 
                                value={service.score} 
                                sx={{ 
                                  flexGrow: 1, 
                                  ml: 1, 
                                  height: 8, 
                                  borderRadius: 1,
                                  bgcolor: 'grey.200',
                                  '& .MuiLinearProgress-bar': {
                                    bgcolor: getScoreColor(service.score),
                                  }
                                }} 
                              />
                            </Box>
                            <Box sx={{ display: 'flex', justifyContent: 'space-between' }}>
                              <Typography variant="body2" color="text.secondary">
                                Violations: {service.violations}
                              </Typography>
                              {service.violations > 0 ? (
                                <Chip 
                                  label="Issues Found" 
                                  size="small" 
                                  color="error" 
                                  variant="outlined" 
                                />
                              ) : (
                                <Chip 
                                  label="Compliant" 
                                  size="small" 
                                  color="success" 
                                  variant="outlined" 
                                />
                              )}
                            </Box>
                          </Box>
                        }
                      />
                    </ListItem>
                  </React.Fragment>
                ))}
              </List>
            </CardContent>
          </Card>
        </Grid>
      </Grid>
    </Box>
  );
};

export default ProjectView; 