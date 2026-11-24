/**
 * Calculates a security score based on passed checks
 */
export const calculateScore = (
  passedChecks: number, 
  totalChecks: number
): number => {
  if (totalChecks === 0) return 100;
  const score = Math.round((passedChecks / totalChecks) * 100);
  return score;
};

/**
 * Gets a color based on score ranges
 */
export const getScoreColor = (score: number): string => {
  if (score >= 90) return 'success';
  if (score >= 70) return 'warning';
  return 'error';
};

/**
 * Gets a severity level based on score
 */
export const getScoreSeverity = (score: number): 'critical' | 'high' | 'medium' | 'low' => {
  if (score >= 90) return 'low';
  if (score >= 75) return 'medium';
  if (score >= 50) return 'high';
  return 'critical';
};

/**
 * Groups check results by service
 */
export const groupResultsByService = (results: any[]): Record<string, any[]> => {
  const grouped: Record<string, any[]> = {};
  
  results.forEach(result => {
    const service = result.service || 'unknown';
    if (!grouped[service]) {
      grouped[service] = [];
    }
    grouped[service].push(result);
  });
  
  return grouped;
};

/**
 * Summarizes project results
 */
export const summarizeProjectResults = (serviceResults: Record<string, any[]>) => {
  const summary = {
    totalChecks: 0,
    passedChecks: 0,
    services: 0,
    serviceScores: {} as Record<string, number>,
    overallScore: 0,
  };
  
  for (const [service, checks] of Object.entries(serviceResults)) {
    const servicePassedChecks = checks.filter(check => check.passed).length;
    const serviceScore = calculateScore(servicePassedChecks, checks.length);
    
    summary.totalChecks += checks.length;
    summary.passedChecks += servicePassedChecks;
    summary.services++;
    summary.serviceScores[service] = serviceScore;
  }
  
  summary.overallScore = calculateScore(summary.passedChecks, summary.totalChecks);
  
  return summary;
}; 