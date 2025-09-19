import { useState, useEffect } from "react";

export const useTheme = () => {
  const [theme, setTheme] = useState<"light" | "dark">("dark");

  useEffect(() => {
    // Get saved theme or default to dark for cybersecurity aesthetic
    const savedTheme = localStorage.getItem("cyberlab-theme") as "light" | "dark" || "dark";
    setTheme(savedTheme);
  }, []);

  const toggleTheme = () => {
    const newTheme = theme === "light" ? "dark" : "light";
    setTheme(newTheme);
    localStorage.setItem("cyberlab-theme", newTheme);
  };

  return { theme, toggleTheme };
};