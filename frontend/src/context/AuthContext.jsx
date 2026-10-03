import { createContext, useContext, useState, useEffect, useCallback, useMemo } from 'react';
import axios from 'axios';

const rawBackendUrl = process.env.REACT_APP_BACKEND_URL?.trim();

const resolvedBackendUrl = (() => {
  if (!rawBackendUrl || rawBackendUrl === 'undefined' || rawBackendUrl === 'null') {
    return '';
  }

  try {
    const parsed = new URL(rawBackendUrl);
    const isLocalhostTarget = parsed.hostname === 'localhost' || parsed.hostname === '127.0.0.1';
    const isBrowserLocalhost = typeof window !== 'undefined' && (window.location.hostname === 'localhost' || window.location.hostname === '127.0.0.1');

    if (isLocalhostTarget && !isBrowserLocalhost) {
      return '';
    }

    return rawBackendUrl.replace(/\/+$/, '');
  } catch {
    return '';
  }
})();

const API = resolvedBackendUrl ? `${resolvedBackendUrl}/api` : '/api';

const AuthContext = createContext(null);

export const useAuth = () => {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return context;
};

export const AuthProvider = ({ children }) => {
  const [user, setUser] = useState(null);
  const [token, setToken] = useState(localStorage.getItem('token'));
  const [loading, setLoading] = useState(true);

  const applyAuthResponse = useCallback(({ access_token, user: userData }) => {
    localStorage.setItem('token', access_token);
    setToken(access_token);
    setUser(userData);
    return userData;
  }, []);

  useEffect(() => {
    const initAuth = async () => {
      const savedToken = localStorage.getItem('token');
      if (savedToken) {
        try {
          const response = await axios.get(`${API}/auth/me`, {
            headers: { Authorization: `Bearer ${savedToken}` }
          });
          setUser(response.data);
          setToken(savedToken);
        } catch (error) {
          localStorage.removeItem('token');
          setToken(null);
          setUser(null);
        }
      }
      setLoading(false);
    };
    initAuth();
  }, []);

  const login = useCallback(async (email, password) => {
    const response = await axios.post(`${API}/auth/login`, { email, password });
    return applyAuthResponse(response.data);
  }, [applyAuthResponse]);

  const register = useCallback(async (email, password, name) => {
    const response = await axios.post(`${API}/auth/register`, { email, password, name });
    return applyAuthResponse(response.data);
  }, [applyAuthResponse]);

  const setupAdmin = useCallback(async (email, password, name, setupToken = '') => {
    const headers = setupToken ? { 'X-Setup-Token': setupToken } : {};
    const response = await axios.post(
      `${API}/auth/setup`,
      { email, password, name },
      { headers }
    );
    return applyAuthResponse(response.data);
  }, [applyAuthResponse]);

  const getBootstrapStatus = useCallback(async () => {
    const response = await axios.get(`${API}/auth/bootstrap-status`);
    return response.data;
  }, []);

  const logout = useCallback(() => {
    localStorage.removeItem('token');
    setToken(null);
    setUser(null);
  }, []);

  const getAuthHeaders = useCallback(() => ({
    Authorization: `Bearer ${token}`
  }), [token]);

  const value = useMemo(() => ({
    user,
    token,
    loading,
    login,
    register,
    setupAdmin,
    getBootstrapStatus,
    logout,
    getAuthHeaders
  }), [
    user,
    token,
    loading,
    login,
    register,
    setupAdmin,
    getBootstrapStatus,
    logout,
    getAuthHeaders
  ]);

  return (
    <AuthContext.Provider value={value}>
      {children}
    </AuthContext.Provider>
  );
};
