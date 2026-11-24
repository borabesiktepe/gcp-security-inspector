import React, { useState } from 'react';
import { Routes, Route, Navigate } from 'react-router-dom';
import { ThemeProvider, createTheme } from '@mui/material/styles';
import CssBaseline from '@mui/material/CssBaseline';
import Login from './pages/Login';
import Results from './pages/Results';

const theme = createTheme({
  palette: {
    primary: {
      main: '#1D55C4', // All-In-Cloud brand blue
    },
    secondary: {
      main: '#34a853', // Green
    },
    background: {
      default: '#f8f9fa',
    },
  },
  typography: {
    fontFamily: 'Google Sans, Roboto, Arial, sans-serif',
  },
});

const App: React.FC = () => {
  const [isAuthenticated, setIsAuthenticated] = useState(false);
  const [projectResults, setProjectResults] = useState<any[]>([]);
  const [pendingScans, setPendingScans] = useState(0);

  const handleLogin = (results: any[]) => {
    setProjectResults(results);
  };

  React.useEffect(() => {
    if (projectResults.length > 0) setIsAuthenticated(true);
  }, [projectResults]);

  return (
    <ThemeProvider theme={theme}>
      <CssBaseline />
      <Routes>
        <Route 
          path="/" 
          element={
            isAuthenticated ? (
              <Navigate to="/results" replace />
            ) : (
              <Login onLogin={handleLogin} />
            )
          } 
        />
        <Route 
          path="/results" 
          element={
            isAuthenticated ? (
              <Results projectResults={projectResults} />
            ) : (
              <Navigate to="/" replace />
            )
          } 
        />
      </Routes>
    </ThemeProvider>
  );
};

export default App; 