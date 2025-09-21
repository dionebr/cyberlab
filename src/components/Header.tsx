import { Moon, Sun, Globe, Menu, Bell, User, Languages, Flag, Shield } from "lucide-react";
import { Button } from "./ui/button";
import { useThemeContext } from "../contexts/ThemeContext";
import { useSecurityLevelContext } from "../contexts/SecurityLevelContext";
import { useLanguageContext } from "../contexts/LanguageContext";
import { SidebarTrigger } from "./ui/sidebar";
import { useLocation } from "react-router-dom";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
  DropdownMenuSeparator,
} from "./ui/dropdown-menu";
import { Badge } from "./ui/badge";
import { Avatar, AvatarFallback, AvatarImage } from "./ui/avatar";

const languageData = {
  "en-US": { name: "English", flag: "🇺🇸" },
  "pt-BR": { name: "Brazil", flag: "🇧🇷" }, 
  "es-ES": { name: "Español", flag: "🇪🇸" }
};

export const Header = () => {
  const { theme, toggleTheme } = useThemeContext();
  const { securityLevel, setSecurityLevel, getSecurityLevelColor, getSecurityLevelIcon } = useSecurityLevelContext();
  const { language, setLanguage, t } = useLanguageContext();
  const location = useLocation();
  
  // Show security level only in challenges
  const isInChallenges = location.pathname.startsWith('/challenges');

  return (
    <header className="sticky top-0 z-50 w-full bg-sidebar/95 backdrop-blur-lg border-b border-sidebar-border shadow-cyber">
      <div className="flex h-12 items-center justify-between px-6 w-full">
        {/* Left side - Sidebar Toggle */}
        <div className="flex items-center gap-4">
          <SidebarTrigger className="h-8 w-8 hover:bg-accent hover:text-accent-foreground" />
          
          {/* Breadcrumb or current section */}
          <div className="hidden md:flex items-center gap-2 text-sm text-muted-foreground">
            <span>CyberLab</span>
            <span>/</span>
            <span className="text-foreground">Dashboard</span>
          </div>
        </div>

        {/* Right side - Controls */}
        <div className="flex items-center gap-3">
          {/* Security Level Toggle - Only show in challenges */}
          {isInChallenges && (
            <DropdownMenu>
            <DropdownMenuTrigger asChild>
              <Button 
                variant="outline" 
                size="sm" 
                className="gap-2 h-9 hover:bg-accent hover:text-accent-foreground transition-colors"
              >
                <Shield className="h-4 w-4" />
                <span className="hidden sm:inline text-sm font-medium capitalize">
                  {securityLevel}
                </span>
                <span className="text-sm">{getSecurityLevelIcon(securityLevel)}</span>
              </Button>
            </DropdownMenuTrigger>
            <DropdownMenuContent align="end" className="w-48">
              {(["easy", "medium", "hard"] as const).map((level) => (
                <DropdownMenuItem 
                  key={level}
                  onClick={() => setSecurityLevel(level)}
                  className={`${securityLevel === level ? "bg-accent text-accent-foreground" : ""} cursor-pointer transition-colors`}
                >
                  <div className="flex items-center gap-3 w-full">
                    <span className="text-base">{getSecurityLevelIcon(level)}</span>
                    <span className="flex-1 capitalize">{level}</span>
                    {securityLevel === level && (
                      <div className="w-2 h-2 rounded-full bg-primary" />
                    )}
                  </div>
                </DropdownMenuItem>
              ))}
            </DropdownMenuContent>
          </DropdownMenu>
          )}

          {/* Language Selector with Flag Only */}
          <DropdownMenu>
            <DropdownMenuTrigger asChild>
              <Button variant="ghost" size="sm" className="gap-2 h-9 w-9 hover:bg-accent hover:text-accent-foreground transition-colors">
                <span className="text-lg">
                  {languageData[language as keyof typeof languageData]?.flag}
                </span>
              </Button>
            </DropdownMenuTrigger>
            <DropdownMenuContent align="end" className="w-48">
              {Object.entries(languageData).map(([code, data]) => (
                <DropdownMenuItem 
                  key={code}
                  onClick={() => setLanguage(code as any)}
                  className={`${language === code ? "bg-primary/10 text-primary" : ""} cursor-pointer transition-colors`}
                >
                  <div className="flex items-center gap-3 w-full">
                    <span className="text-base">{data.flag}</span>
                    <span className="flex-1">{data.name}</span>
                    {language === code && (
                      <div className="w-2 h-2 rounded-full bg-primary" />
                    )}
                  </div>
                </DropdownMenuItem>
              ))}
            </DropdownMenuContent>
          </DropdownMenu>

          {/* Enhanced Notifications */}
          <Button 
            variant="ghost" 
            size="sm" 
            className="relative h-9 w-9 hover:bg-accent hover:text-accent-foreground transition-colors group"
          >
            <Bell className="h-4 w-4 group-hover:animate-pulse" />
            <Badge 
              variant="destructive" 
              className="absolute -top-1 -right-1 w-5 h-5 p-0 flex items-center justify-center text-[10px] font-bold"
            >
              3
            </Badge>
          </Button>

          {/* Theme Toggle */}
          <Button
            variant="ghost"
            size="sm"
            onClick={toggleTheme}
            className="h-9 w-9"
          >
            {theme === "dark" ? (
              <Sun className="h-4 w-4" />
            ) : (
              <Moon className="h-4 w-4" />
            )}
            <span className="sr-only">
              {theme === "dark" ? t("header.light") : t("header.dark")}
            </span>
          </Button>

          {/* User Menu */}
          <DropdownMenu>
            <DropdownMenuTrigger asChild>
              <Button variant="ghost" className="relative h-9 w-9 rounded-full">
                <Avatar className="h-8 w-8">
                  <AvatarImage src="/placeholder.svg" alt="User" />
                  <AvatarFallback>U</AvatarFallback>
                </Avatar>
              </Button>
            </DropdownMenuTrigger>
            <DropdownMenuContent align="end" className="w-56">
              <DropdownMenuItem>
                <User className="mr-2 h-4 w-4" />
                Profile
              </DropdownMenuItem>
              <DropdownMenuItem>
                <Bell className="mr-2 h-4 w-4" />
                Notifications
              </DropdownMenuItem>
              <DropdownMenuSeparator />
              <DropdownMenuItem>
                Settings
              </DropdownMenuItem>
              <DropdownMenuItem>
                Sign out
              </DropdownMenuItem>
            </DropdownMenuContent>
          </DropdownMenu>
        </div>
      </div>
    </header>
  );
};