import { useState, useEffect } from "react";

export type SecurityLevel = "easy" | "medium" | "hard";

export const useSecurityLevel = () => {
  const [securityLevel, setSecurityLevel] = useState<SecurityLevel>("easy");

  useEffect(() => {
    const savedLevel = localStorage.getItem("cyberlab-security-level") as SecurityLevel;
    if (savedLevel && ["easy", "medium", "hard"].includes(savedLevel)) {
      setSecurityLevel(savedLevel);
    }
  }, []);

  const changeSecurityLevel = (level: SecurityLevel) => {
    setSecurityLevel(level);
    localStorage.setItem("cyberlab-security-level", level);
  };

  const getSecurityLevelColor = (level: SecurityLevel) => {
    switch (level) {
      case "easy": return "success";
      case "medium": return "warning"; 
      case "hard": return "danger";
      default: return "success";
    }
  };

  const getSecurityLevelIcon = (level: SecurityLevel) => {
    switch (level) {
      case "easy": return "🟢";
      case "medium": return "🟡";
      case "hard": return "🔴";
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