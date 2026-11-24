import React, { useState } from 'react';
import { 
  Container, 
  Box, 
  Typography, 
  Paper, 
  Tabs, 
  Tab, 
  List, 
  ListItem, 
  ListItemIcon, 
  ListItemText, 
  Divider,
  Grid,
  Card,
  CardContent,
  CardHeader,
  Chip,
  AppBar,
  Toolbar,
  CircularProgress,
  Accordion,
  AccordionSummary,
  AccordionDetails,
  Link,
  Button,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow
} from '@mui/material';
import CheckCircleIcon from '@mui/icons-material/CheckCircle';
import ErrorIcon from '@mui/icons-material/Error';
import WarningIcon from '@mui/icons-material/Warning';
import ExpandMoreIcon from '@mui/icons-material/ExpandMore';
import LinkIcon from '@mui/icons-material/Link';
import jsPDF from 'jspdf';

interface CheckItem {
  id: string;
  name: string;
  passed: boolean; // For backward compatibility
  details: string;
  remediation?: string;
  remediationLink?: string;
  resources: {
    total: number;
    passed: number;
    failed?: string[];
  };
  notApplicable: boolean;
}

interface ServiceData {
  id: string;
  name: string;
  score: number;
  checks: CheckItem[];
}

interface ResultsProps {
  projectResults: any[];
}

const CheckCard: React.FC<{check: CheckItem}> = ({ check }) => {
  const statusIcon = check.passed ? <CheckCircleIcon style={{ color: '#4caf50' }} /> : <ErrorIcon style={{ color: '#f44336' }} />;
  const passRate = check.resources.total > 0 ? Math.round((check.resources.passed / check.resources.total) * 100) : 100;
  
  // Always expand checks that have failed for better visibility
  const [expanded, setExpanded] = useState(!check.passed);
  
  return (
    <Accordion 
      expanded={expanded}
      onChange={() => setExpanded(!expanded)}
      sx={{
        mb: 1,
        border: check.passed ? 'none' : '1px solid #ffe0e0',
        backgroundColor: check.passed ? 'inherit' : '#fff8f8'
      }}
    >
      <AccordionSummary
        expandIcon={<ExpandMoreIcon />}
        aria-controls="panel1a-content"
        id="panel1a-header"
      >
        <Box display="flex" alignItems="center" width="100%">
          <Box mr={1}>{statusIcon}</Box>
          <Box flexGrow={1}>
            <Typography variant="subtitle1">{check.name}</Typography>
            <Typography variant="body2" color="textSecondary">{check.details}</Typography>
          </Box>
          <Box>
            <Chip 
              label={`${check.resources.passed}/${check.resources.total}`} 
              color={check.passed ? "success" : "error"}
              size="small"
            />
          </Box>
        </Box>
      </AccordionSummary>
      <AccordionDetails>
        <Box>
          {check.remediation && (
            <Box mb={2}>
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
                  <LinkIcon fontSize="small" style={{marginRight: 4}} />
                  More information
                </Link>
              )}
            </Box>
          )}

          {/* Display table of failed resources with highlighted styling */}
          {check.resources.failed && check.resources.failed.length > 0 && (
            <Box mt={2}>
              <Typography variant="subtitle2" sx={{ color: '#f44336', fontWeight: 'bold' }}>
                Failed Resources ({check.resources.failed.length})
              </Typography>
              <TableContainer 
                component={Paper} 
                variant="outlined" 
                sx={{ 
                  mt: 1, 
                  maxHeight: 200, 
                  overflowY: 'auto',
                  border: '1px solid #ffcccc'
                }}
              >
                <Table size="small">
                  <TableHead sx={{ backgroundColor: '#fff8f8' }}>
                    <TableRow>
                      <TableCell sx={{ fontWeight: 'bold' }}>Resource Name</TableCell>
                    </TableRow>
                  </TableHead>
                  <TableBody>
                    {check.resources.failed.map((resource, index) => (
                      <TableRow key={index}>
                        <TableCell>{resource}</TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </TableContainer>
            </Box>
          )}
        </Box>
      </AccordionDetails>
    </Accordion>
  );
};

const generatePDF = (projectData: any) => {
  const doc = new jsPDF();
  let y = 18;
  // Title
  doc.setFontSize(22);
  doc.setTextColor(40, 76, 189);
  doc.text('Cloud Inspector Report', 10, y);
  doc.setFontSize(11);
  doc.setTextColor(100, 100, 100);
  doc.text('All-In-Cloud', 200, y, { align: 'right' });
  y += 6;
  doc.setDrawColor(40, 76, 189);
  doc.setLineWidth(0.8);
  doc.line(10, y, 200, y);
  y += 8;
  doc.setFontSize(13);
  doc.setTextColor(0,0,0);
  doc.text(`Project: ${projectData.projectName || ''}`, 10, y);
  y += 7;
  doc.text(`Project ID: ${projectData.projectId || ''}`, 10, y);
  y += 10;
  projectData.services.forEach((service: any, sIdx: number) => {
    // Filter out checks with N/A or no assets
    const validChecks = service.checks.filter((check: any) => !(check.notApplicable || check.resources?.total === 0));
    if (validChecks.length === 0) return;
    // Section header
    doc.setFontSize(16);
    doc.setTextColor(40, 76, 189);
    doc.text(service.name, 10, y);
    y += 4;
    doc.setDrawColor(200,200,200);
    doc.setLineWidth(0.5);
    doc.line(10, y, 200, y);
    y += 6;
    validChecks.forEach((check: any) => {
      doc.setFontSize(12);
      doc.setTextColor(0,0,0);
      doc.setFont('helvetica', 'bold');
      const wrappedName = doc.splitTextToSize(`• ${check.name}`, 180);
      if (y + wrappedName.length * 6 > 270) { doc.addPage(); y = 18; }
      doc.text(wrappedName, 12, y);
      y += 6 * wrappedName.length;
      doc.setFont('helvetica', 'normal');
      // Status with color
      let statusColor: [number, number, number] = [76,175,80]; // green
      let statusText = 'Passed';
      if (check.notApplicable) { statusColor = [255,152,0]; statusText = 'N/A'; }
      else if (!check.passed) { statusColor = [244,67,54]; statusText = 'Failed'; }
      doc.setTextColor(...statusColor);
      if (y + 5 > 270) { doc.addPage(); y = 18; }
      doc.text(`Status: ${statusText}`, 16, y);
      y += 5;
      doc.setTextColor(0,0,0);
      const wrappedDetails = doc.splitTextToSize(`Details: ${check.details || ''}`, 180);
      if (y + wrappedDetails.length * 5 > 270) { doc.addPage(); y = 18; }
      doc.text(wrappedDetails, 16, y);
      y += 5 * wrappedDetails.length;
      // Always show recommendation and link if present
      if (check.remediation) {
        doc.setFont('helvetica', 'italic');
        const wrappedRemediation = doc.splitTextToSize(`Recommendation: ${check.remediation}`, 180);
        if (y + wrappedRemediation.length * 5 > 270) { doc.addPage(); y = 18; }
        doc.text(wrappedRemediation, 16, y);
        doc.setFont('helvetica', 'normal');
        y += 5 * wrappedRemediation.length;
      }
      if (check.remediationLink && check.remediationLink !== '') {
        doc.setTextColor(33, 150, 243);
        if (y + 5 > 270) { doc.addPage(); y = 18; }
        doc.textWithLink('More info', 16, y, { url: check.remediationLink });
        doc.setTextColor(0,0,0);
        y += 5;
      }
      if (check.resources?.failed && check.resources.failed.length > 0) {
        if (y + 10 > 270) { doc.addPage(); y = 18; }
        doc.setFont('helvetica', 'bold');
        doc.setTextColor(244,67,54);
        doc.text(`Failed Resources (${check.resources.failed.length})`, 16, y);
        y += 6;
        doc.setFont('helvetica', 'normal');
        doc.setTextColor(0,0,0);
        check.resources.failed.forEach((resource: string) => {
          const wrappedResource = doc.splitTextToSize(resource, 160);
          if (y + wrappedResource.length * 5 > 270) { doc.addPage(); y = 18; }
          doc.text(wrappedResource, 20, y);
          y += 5 * wrappedResource.length;
        });
        y += 2;
      }
      y += 2;
      if (y > 270) { doc.addPage(); y = 18; }
    });
    y += 4;
    if (sIdx < projectData.services.length - 1) {
      doc.setDrawColor(40, 76, 189);
      doc.setLineWidth(0.8);
      doc.line(10, y, 200, y);
      y += 6;
    }
    if (y > 270) { doc.addPage(); y = 18; }
  });
  doc.save('cloud-inspector-report.pdf');
};

const Results: React.FC<ResultsProps> = ({ projectResults }) => {
  const [selectedProject, setSelectedProject] = useState(0);
  const projectData = projectResults[selectedProject];
  if (!projectData) return <Box p={4}><Typography>No results to display.</Typography></Box>;
  
  const handleServiceChange = (_event: React.SyntheticEvent, newValue: number) => {
    setSelectedService(newValue);
  };
  
  const getScoreColor = (score: number) => {
    if (score >= 80) return '#4caf50';
    if (score >= 50) return '#ff9800';
    return '#f44336';
  };
  
  const getCheckStatusColor = (check: CheckItem) => {
    return check.passed ? '#4caf50' : '#f44336';
  };
  
  const calculateServiceStats = (service: ServiceData) => {
    const validChecks = service.checks.filter(check => !check.notApplicable && check.resources.total > 0);
    const totalChecks = validChecks.length;
    const passedChecks = validChecks.filter(check => check.passed).length;
    return {
      passed: passedChecks,
      failed: totalChecks - passedChecks,
      total: totalChecks
    };
  };
  
  const [selectedService, setSelectedService] = useState(0);
  
  return (
    <Container maxWidth="xl" sx={{ py: 4 }}>
      <Paper elevation={3} sx={{ p: 4, borderRadius: 2 }}>
        <Box sx={{ mb: 3 }}>
          <Tabs
            value={selectedProject}
            onChange={(_e, v) => setSelectedProject(v)}
            aria-label="project tabs"
            variant="scrollable"
            scrollButtons="auto"
          >
            {projectResults.map((proj, idx) => (
              <Tab key={proj.projectId} label={proj.projectId} />
            ))}
          </Tabs>
        </Box>
        <Box display="flex" justifyContent="space-between" alignItems="center" mb={4}>
          <Box>
            <Typography variant="h4" gutterBottom>{projectData.projectId}</Typography>
          </Box>
          <Box textAlign="center">
            <Box 
              sx={{ 
                width: 120, 
                height: 120, 
                position: 'relative',
                display: 'inline-flex'
              }}
            >
              <CircularProgress 
                variant="determinate" 
                value={projectData.score} 
                size={120} 
                thickness={5}
                sx={{ color: getScoreColor(projectData.score) }}
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
                <Typography variant="h4" component="div" color="textPrimary">{projectData.score === null || projectData.score === undefined ? 'N/A' : `${projectData.score}%`}</Typography>
              </Box>
            </Box>
            <Typography variant="subtitle1" mt={1}>Overall Score</Typography>
          </Box>
        </Box>
        
        <Box sx={{ borderBottom: 1, borderColor: 'divider', mb: 3 }}>
          <Tabs 
            value={selectedService} 
            onChange={handleServiceChange}
            aria-label="services tabs"
            variant="scrollable"
            scrollButtons="auto"
          >
            {projectData.services.map((service: ServiceData, index: number) => (
              <Tab 
                key={service.id}
                label={
                  <Box display="flex" alignItems="center">
                    <Typography>{service.name}</Typography>
                    <Chip 
                      label={service.score === null || service.score === undefined ? 'N/A' : `${service.score}%`} 
                      size="small" 
                      sx={{ ml: 1 }} 
                      color={service.score >= 80 ? 'success' : service.score >= 50 ? 'warning' : 'error'}
                    />
                  </Box>
                } 
                id={`service-tab-${index}`}
                aria-controls={`service-tabpanel-${index}`}
              />
            ))}
          </Tabs>
        </Box>
        
        {projectData.services.map((service: ServiceData, index: number) => {
          const stats = calculateServiceStats(service);
          
          return (
            <div
              key={service.id}
              role="tabpanel"
              hidden={selectedService !== index}
              id={`service-tabpanel-${index}`}
              aria-labelledby={`service-tab-${index}`}
            >
              {selectedService === index && (
                <Grid container spacing={4}>
                  <Grid item xs={12} md={4}>
                    <Box width="100%">
                      <Card variant="outlined" sx={{ height: '100%' }}>
                        <CardHeader 
                          title={service.name} 
                          subheader={`Security Assessment`}
                        />
                        <CardContent>
                          <Box display="flex" justifyContent="space-around" mb={4}>
                            <Box textAlign="center">
                              <Typography variant="h5" sx={{ color: '#4caf50' }}>{stats.passed}</Typography>
                              <Typography variant="body2" color="textSecondary">Passing</Typography>
                            </Box>
                            <Box textAlign="center">
                              <Typography variant="h5" sx={{ color: '#f44336' }}>{stats.failed}</Typography>
                              <Typography variant="body2" color="textSecondary">Failing</Typography>
                            </Box>
                            <Box textAlign="center">
                              <Typography variant="h5">{stats.total}</Typography>
                              <Typography variant="body2" color="textSecondary">Total</Typography>
                            </Box>
                          </Box>
                          
                          <Box 
                            sx={{ 
                              width: '100%', 
                              height: 8, 
                              bgcolor: 'rgba(0,0,0,0.1)',
                              borderRadius: 4,
                              overflow: 'hidden',
                              mb: 2
                            }}
                          >
                            <Box 
                              sx={{ 
                                width: `${service.score}%`, 
                                height: '100%',
                                bgcolor: getScoreColor(service.score)
                              }}
                            />
                          </Box>
                          <Typography variant="body2" align="center" color="textSecondary">
                            {service.score === null || service.score === undefined ? 'N/A' : `${service.score}%`}
                          </Typography>
                        </CardContent>
                      </Card>
                    </Box>
                  </Grid>
                  <Grid item xs={12} md={8}>
                    <Box width="100%">
                      <Card variant="outlined">
                        <CardHeader title="Security Checks" />
                        <CardContent>
                          <List>
                            {service.checks.map((check: CheckItem, idx: number) => (
                              <React.Fragment key={check.id}>
                                {idx > 0 && <Divider />}
                                <CheckCard check={check} />
                              </React.Fragment>
                            ))}
                          </List>
                        </CardContent>
                      </Card>
                    </Box>
                  </Grid>
                </Grid>
              )}
            </div>
          );
        })}
        <Box sx={{ position: 'fixed', bottom: 32, right: 32, zIndex: 9999 }}>
          <Button
            variant="contained"
            color="primary"
            onClick={() => generatePDF(projectData)}
          >
            Download PDF
          </Button>
        </Box>
      </Paper>
    </Container>
  );
};

export default Results;