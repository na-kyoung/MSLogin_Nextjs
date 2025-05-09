"use client";

import { useRouter } from 'next/navigation';
import { createContext, useContext, useState, useEffect } from 'react';

const LoginContext = createContext();

export const LoginProvider = ({ children }) => {
  const [Loggedin, setLoggedin] = useState(false);
  const router = useRouter();

  // 예시: 로컬스토리지 기반 상태 복구
  useEffect(() => {
    const token = localStorage.getItem('login_token');
    setLoggedin(!!token);
  }, []);

  const login = (token) => {
    localStorage.setItem('login_token', token);
    setLoggedin(true);
  };

  const logout = () => {
    // localStorage.removeItem('login_token');
    localStorage.clear();
    setLoggedin(false);
    router.push("/");
  };

  const failedLogin = () => {
    localStorage.clear();
    setLoggedin(false);
  };

  return (
    <LoginContext.Provider value={{ Loggedin, login, logout, failedLogin }}>
      {children}
    </LoginContext.Provider>
  );
};

export const useAuth = () => useContext(LoginContext);
