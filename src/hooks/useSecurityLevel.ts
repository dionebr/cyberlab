import { useState, useEffect } from "react";

export type SecurityLevel = "low" | "medium" | "high";

export const useSecurityLevel = () => {
  const [securityLevel, setSecurityLevel] = useState<SecurityLevel>("low");

  useEffect(() => {
    const savedLevel = localStorage.getItem("cyberlab-security-level") as SecurityLevel;
    if (savedLevel && ["low", "medium", "high"].includes(savedLevel)) {
      setSecurityLevel(savedLevel);
    }
  }, []);

  const changeSecurityLevel = (level: SecurityLevel) => {
    setSecurityLevel(level);
    localStorage.setItem("cyberlab-security-level", level);
  };

  const getSecurityLevelColor = (level: SecurityLevel) => {
    switch (level) {
      case "low": return "success";
      case "medium": return "warning"; 
      case "high": return "danger";
      default: return "success";
    }
  };

  const getSecurityLevelIcon = (level: SecurityLevel) => {
    switch (level) {
      case "low": return "🟢";
      case "medium": return "🟡";
      case "high": return "🔴";
      default: return "🟢";
    }
  };

  return {
    securityLevel,
    setSecurityLevel: changeSecurityLevel,
    getSecurityLevelColor,
    getSecurityLevelIcon,
  };
};