import React, { useState, useEffect } from 'react';
import { 
  Typography, 
  Box, 
  Grid, 
  Paper, 
  Button,
  CircularProgress,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow
} from '@mui/material';
import { useNavigate } from 'react-router-dom';

// Mock data for initial development
const mockProjects = [
  { id: 'project-1', name: 'Production', score: 85, services: 12, violations: 8 },
  { id: 'project-2', name: 'Development', score: 72, services: 10, violations: 15 },
  { id: 'project-3', name: 'Staging', score: 91, services: 8, violations: 3 },
];

const Dashboard: React.FC = () => {
  const [projects, setProjects] = useState<any[]>([]);
  const [loading, setLoading] = useState<boolean>(true);
  const navigate = useNavigate();

  useEffect(() => {
    // In a real app, this would fetch data from an API
    const fetchProjects = async () => {
      // Simulate API call
      await new Promise(resolve => setTimeout(resolve, 1000));
      setProjects(mockProjects);
      setLoading(false);
    };

    fetchProjects();
  }, []);

  const handleProjectClick = (projectId: string) => {
    navigate(`/projects/${projectId}`);
  };

  return (
    <Box>
      <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 4 }}>
        <Typography variant="h4" component="h1">
          Project Overview
        </Typography>
        <Button variant="contained" color="primary">
          Connect to GCP
        </Button>
      </Box>

      {loading ? (
        <Box sx={{ display: 'flex', justifyContent: 'center', mt: 4 }}>
          <CircularProgress />
        </Box>
      ) : (
        <>
          <Grid container spacing={3} sx={{ mb: 4 }}>
            <Grid item xs={12} md={4}>
              <Paper sx={{ p: 3, textAlign: 'center', height: '100%' }}>
                <Typography variant="h4" color="primary">
                  {projects.length}
                </Typography>
                <Typography variant="body1">
                  Projects Monitored
                </Typography>
              </Paper>
            </Grid>
            <Grid item xs={12} md={4}>
              <Paper sx={{ p: 3, textAlign: 'center', height: '100%' }}>
                <Typography variant="h4" color="primary">
                  {projects.reduce((acc, project) => acc + project.score, 0) / projects.length}%
                </Typography>
                <Typography variant="body1">
                  Average Compliance Score
                </Typography>
              </Paper>
            </Grid>
            <Grid item xs={12} md={4}>
              <Paper sx={{ p: 3, textAlign: 'center', height: '100%' }}>
                <Typography variant="h4" color="error">
                  {projects.reduce((acc, project) => acc + project.violations, 0)}
                </Typography>
                <Typography variant="body1">
                  Total Violations
                </Typography>
              </Paper>
            </Grid>
          </Grid>

          <Typography variant="h5" sx={{ mb: 2 }}>
            Projects
          </Typography>
          <TableContainer component={Paper}>
            <Table>
              <TableHead>
                <TableRow>
                  <TableCell>Project Name</TableCell>
                  <TableCell align="right">Compliance Score</TableCell>
                  <TableCell align="right">Services</TableCell>
                  <TableCell align="right">Violations</TableCell>
                  <TableCell align="right">Actions</TableCell>
                </TableRow>
              </TableHead>
              <TableBody>
                {projects.map((project) => (
                  <TableRow key={project.id}>
                    <TableCell component="th" scope="row">
                      {project.name}
                    </TableCell>
                    <TableCell align="right">{project.score}%</TableCell>
                    <TableCell align="right">{project.services}</TableCell>
                    <TableCell align="right">{project.violations}</TableCell>
                    <TableCell align="right">
                      <Button 
                        variant="outlined" 
                        size="small"
                        onClick={() => handleProjectClick(project.id)}
                      >
                        View Details
                      </Button>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </TableContainer>
        </>
      )}
    </Box>
  );
};

export default Dashboard; 