import React from 'react';
import { BrowserRouter, Routes, Route, Navigate, useLocation } from 'react-router-dom';
import { Toaster } from 'react-hot-toast';
import { motion, AnimatePresence } from 'framer-motion';
import { AuthProvider, useAuth } from './context/AuthContext';
import ProtectedRoute from './components/ProtectedRoute';
import NetworkMonitor from './components/NetworkMonitor';
import UnauthorizedBanner from './components/UnauthorizedBanner';
import StartupScreen from './components/StartupScreen';
import LoginPage from './pages/LoginPage';
import RegisterPage from './pages/RegisterPage';
import MFASetupPage from './pages/MFASetupPage';
import ForgotPasswordPage from './pages/ForgotPasswordPage';
import ResetPasswordPage from './pages/ResetPasswordPage';
import MFARecoveryRequestPage from './pages/MFARecoveryRequestPage';
import ContactUsPage from './pages/ContactUsPage';
import HelpPage from './pages/HelpPage';
import PrivacyPolicyPage from './pages/PrivacyPolicyPage';
import './styles/global.css';
import './App.css';
import { ThemeProvider } from './context/ThemeContext';

/**
 * RootRedirect — decides where "/" lands based on auth state.
 * Authenticated users go straight to /dashboard.
 * Unauthenticated users see the cinematic startup only on the first visit
 * of a browser session; subsequent visits go directly to /login.
 */
function RootRedirect() {
  const { isAuthenticated, isLoading } = useAuth();
  if (isLoading) return null; // Wait for token hydration before redirecting.
  if (isAuthenticated) return <Navigate to="/dashboard" replace />;
  // Show startup cinematic only on the first visit (per browser session)
  const startupSeen = sessionStorage.getItem('xdr_startup_seen') === '1';
  return startupSeen
    ? <Navigate to="/login" replace />
    : <Navigate to="/startup" replace />;
}

/** Page transition wrapper — fades in/out on every route change */
const pageVariants = {
  initial: { opacity: 0 },
  animate: { opacity: 1 },
  exit:    { opacity: 0 },
};

const pageTransition = { duration: 0.3, ease: 'easeInOut' as const };

/** Inner app that has access to useLocation (must be inside BrowserRouter) */
function AnimatedRoutes() {
  const location = useLocation();

  return (
    <AnimatePresence mode="wait">
      <motion.div
        key={location.pathname}
        variants={pageVariants}
        initial="initial"
        animate="animate"
        exit="exit"
        transition={pageTransition}
        style={{ display: 'contents' }}
      >
        <Routes location={location}>
          <Route path="/login" element={<LoginPage />} />
          <Route path="/register" element={<RegisterPage />} />
          <Route path="/forgot-password" element={<ForgotPasswordPage />} />
          <Route path="/reset-password" element={<ResetPasswordPage />} />
          <Route path="/mfa-recovery" element={<MFARecoveryRequestPage />} />
          <Route
            path="/dashboard"
            element={
              <ProtectedRoute>
                <div className="App">
                  <NetworkMonitor />
                </div>
              </ProtectedRoute>
            }
          />
          <Route
            path="/setup-2fa"
            element={
              <ProtectedRoute>
                <MFASetupPage />
              </ProtectedRoute>
            }
          />
          {/* Cinematic startup intro — shown once per browser session */}
          <Route path="/startup" element={<StartupScreen />} />
          {/* Public informational pages */}
          <Route path="/contact-us" element={<ContactUsPage />} />
          <Route path="/help" element={<HelpPage />} />
          <Route path="/privacy-policy" element={<PrivacyPolicyPage />} />
          {/* Root redirect — authenticated → /dashboard, guest → /startup or /login */}
          <Route path="/" element={<RootRedirect />} />
          {/* Catch-all */}
          <Route path="*" element={<Navigate to="/dashboard" replace />} />
        </Routes>
      </motion.div>
    </AnimatePresence>
  );
}

function App() {
  return (
    <ThemeProvider>
    <BrowserRouter>
      <AuthProvider>
        {/*
         * UnauthorizedBanner — renders at the very top of the stacking context,
         * above all routes and the Toaster.  Listens to the custom `accessDenied`
         * DOM event dispatched by the axios 403 interceptor in authService.ts.
         */}
        <UnauthorizedBanner />
        <Toaster
          position="top-center"
          toastOptions={{
            duration: 3000,
            style: {
              background: 'rgba(0,20,40,0.95)',
              color: '#e0f4ff',
              border: '1px solid rgba(0,212,255,0.2)',
              backdropFilter: 'blur(12px)',
              fontFamily: "'Fira Code', monospace",
              fontSize: '12px',
            },
          }}
        />
        <AnimatedRoutes />
      </AuthProvider>
    </BrowserRouter>
    </ThemeProvider>
  );
}

export default App;
