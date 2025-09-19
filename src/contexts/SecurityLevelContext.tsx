import React, { createContext, useContext } from 'react';
import { useSecurityLevel, SecurityLevel } from '../hooks/useSecurityLevel';

interface SecurityLevelContextType {
  securityLevel: SecurityLevel;
  setSecurityLevel: (level: SecurityLevel) => void;
  getSecurityLevelColor: (level: SecurityLevel) => string;
  getSecurityLevelIcon: (level: SecurityLevel) => string;
}

const SecurityLevelContext = createContext<SecurityLevelContextType | undefined>(undefined);

export const SecurityLevelProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const securityLevelHook = useSecurityLevel();

  return (
    <SecurityLevelContext.Provider value={securityLevelHook}>
      {children}
    </SecurityLevelContext.Provider>
  );
};

export const useSecurityLevelContext = () => {
  const context = useContext(SecurityLevelContext);
  if (context === undefined) {
    throw new Error('useSecurityLevelContext must be used within a SecurityLevelProvider');
  }
  return context;
};