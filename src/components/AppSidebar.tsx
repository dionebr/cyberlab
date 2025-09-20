import { useState } from "react";
import { NavLink, useLocation } from "react-router-dom";
import {
  Database, Code, Terminal, Shield, Upload, Key, Zap, Home, 
  Target, BookOpen, ChevronRight, Trophy, Star, Users, Flag, FlaskConical
} from "lucide-react";
import {
  Sidebar,
  SidebarContent,
  SidebarGroup,
  SidebarGroupContent,
  SidebarGroupLabel,
  SidebarMenu,
  SidebarMenuButton,
  SidebarMenuItem,
  SidebarMenuSub,
  SidebarMenuSubItem,
  SidebarMenuSubButton,
  useSidebar,
  SidebarHeader,
  SidebarFooter,
  SidebarSeparator,
} from "@/components/ui/sidebar";
import { Badge } from "@/components/ui/badge";
import { Collapsible, CollapsibleContent, CollapsibleTrigger } from "@/components/ui/collapsible";
import { useSecurityLevelContext } from "@/contexts/SecurityLevelContext";

const challengeModules = [
  { 
    id: "sql-injection", 
    icon: Database, 
    color: "danger"
  },
  { 
    id: "sql-blind", 
    icon: Database, 
    color: "accent"
  },
  { 
    id: "xss", 
    icon: Code, 
    color: "warning"
  },
  { 
    id: "command-injection", 
    icon: Terminal, 
    color: "accent"
  },
  { 
    id: "csrf", 
    icon: Shield, 
    color: "info"
  },
  { 
    id: "file-inclusion", 
    icon: Upload, 
    color: "success"
  },
  { 
    id: "file-upload", 
    icon: Upload, 
    color: "info"
  },
  { 
    id: "auth-bypass", 
    icon: Key, 
    color: "danger"
  },
  { 
    id: "brute-force", 
    icon: Zap, 
    color: "warning"
  },
  { 
    id: "insecure-captcha", 
    icon: Shield, 
    color: "accent"
  },
  { 
    id: "weak-session", 
    icon: Users, 
    color: "warning"
  },
];

const learnCategories = [
  {
    id: "fundamentals",
    title: "Security Fundamentals",
    icon: Shield,
    color: "primary",
    topics: [
      { id: "owasp-top10", title: "OWASP Top 10" },
      { id: "secure-coding", title: "Secure Coding Principles" },
      { id: "threat-modeling", title: "Threat Modeling" }
    ]
  },
  {
    id: "web-security",
    title: "Web Security",
    icon: Code,
    color: "info",
    topics: [
      { id: "injection-attacks", title: "Injection Attacks" },
      { id: "authentication", title: "Authentication Security" },
      { id: "session-management", title: "Session Management" }
    ]
  },
  {
    id: "network-security",
    title: "Network Security",
    icon: Target,
    color: "success",
    topics: [
      { id: "network-protocols", title: "Network Protocols" },
      { id: "firewalls", title: "Firewalls & IDS" },
      { id: "encryption", title: "Encryption & PKI" }
    ]
  },
  {
    id: "os-security",
    title: "Operating Systems Security",
    icon: Terminal,
    color: "warning",
    topics: [
      { id: "linux-security", title: "Linux Security" },
      { id: "windows-security", title: "Windows Security" },
      { id: "macos-security", title: "macOS Security" },
      { id: "container-security", title: "Container Security" }
    ]
  },
  {
    id: "programming-security",
    title: "Secure Programming",
    icon: Code,
    color: "accent",
    topics: [
      { id: "python-security", title: "Secure Python" },
      { id: "javascript-security", title: "Secure JavaScript/Node.js" },
      { id: "c-cpp-security", title: "Secure C/C++" },
      { id: "java-security", title: "Secure Java" },
      { id: "assembly-security", title: "Assembly for Security" }
    ]
  }
];

// Static names for vulnerability modules - always in English (technical terms)
const moduleNames = {
  "sql-injection": "SQL Injection",
  "sql-blind": "SQL Injection (Blind)",
  "xss": "Cross-Site Scripting",
  "command-injection": "Command Injection", 
  "csrf": "CSRF Protection",
  "file-inclusion": "File Inclusion",
  "file-upload": "File Upload",
  "auth-bypass": "Auth Bypass",
  "brute-force": "Brute Force",
  "insecure-captcha": "Insecure CAPTCHA",
  "weak-session": "Weak Session IDs",
};

export function AppSidebar() {
  const { state } = useSidebar();
  const location = useLocation();
  const { securityLevel, getSecurityLevelColor, getSecurityLevelIcon } = useSecurityLevelContext();
  const [openGroups, setOpenGroups] = useState<string[]>(["challenges", "learn"]);

  const currentPath = location.pathname;
  const isActive = (path: string) => currentPath === path;
  const collapsed = state === "collapsed";

  const toggleGroup = (groupId: string) => {
    setOpenGroups(prev => 
      prev.includes(groupId) 
        ? prev.filter(id => id !== groupId)
        : [...prev, groupId]
    );
  };

  return (
    <Sidebar collapsible="icon" className="border-r border-sidebar-border h-screen flex flex-col">
      <SidebarHeader className="pb-2 shrink-0">
        <SidebarMenuButton size="lg" asChild>
          <NavLink to="/" className="flex items-center gap-2">
            <div className="p-2 bg-gradient-cyber rounded-xl shadow-cyber">
              <FlaskConical className="h-6 w-6 text-white" />
            </div>
            {!collapsed && (
              <div className="flex flex-col">
                <span className="text-lg font-bold text-sidebar-foreground">
                  CyberLab
                </span>
                <span className="text-xs text-sidebar-accent-foreground">
                  Break'n'Learn
                </span>
              </div>
            )}
          </NavLink>
        </SidebarMenuButton>
      </SidebarHeader>

      <SidebarSeparator className="shrink-0" />

      <SidebarContent className="flex-1 overflow-hidden relative">
        <div className="h-full overflow-y-auto scrollbar-thin scrollbar-thumb-sidebar-border/30 scrollbar-track-transparent hover:scrollbar-thumb-sidebar-border/50 transition-colors">
          <div className="space-y-2 pb-4">{/* Home */}
          <SidebarGroup className="px-2">
            <SidebarMenu>
              <SidebarMenuItem>
                <SidebarMenuButton asChild isActive={isActive("/")}>
                  <NavLink to="/" end>
                    <Home className="h-4 w-4" />
                    <span>Home</span>
                  </NavLink>
                </SidebarMenuButton>
              </SidebarMenuItem>
            </SidebarMenu>
          </SidebarGroup>

          {/* Learn Mode */}
          <SidebarGroup className="px-2">
            <Collapsible 
              open={openGroups.includes("learn")}
              onOpenChange={() => toggleGroup("learn")}
            >
              <SidebarGroupLabel asChild>
                <CollapsibleTrigger className="group/collapsible">
                  <BookOpen className="h-4 w-4" />
                  Learn Mode
                  <ChevronRight className="ml-auto transition-transform group-data-[state=open]/collapsible:rotate-90" />
                </CollapsibleTrigger>
              </SidebarGroupLabel>
              <CollapsibleContent>
                <SidebarGroupContent>
                  <SidebarMenu className="space-y-1">
                    {learnCategories.map((category) => {
                      const Icon = category.icon;
                      const categoryActive = currentPath.startsWith(`/learn/${category.id}`);
                      
                      return (
                        <Collapsible key={category.id} className="group/item">
                          <SidebarMenuItem>
                            <CollapsibleTrigger asChild>
                              <SidebarMenuButton className="group/button">
                                <Icon className="h-4 w-4" />
                                <span>{category.title}</span>
                                <ChevronRight className="ml-auto transition-transform group-data-[state=open]/item:rotate-90" />
                              </SidebarMenuButton>
                            </CollapsibleTrigger>
                            <CollapsibleContent>
                              <SidebarMenuSub className="ml-4 border-l border-sidebar-border/50 pl-2 space-y-1">
                                {category.topics.map((topic) => (
                                  <SidebarMenuSubItem key={topic.id}>
                                    <SidebarMenuSubButton asChild isActive={currentPath === `/learn/${category.id}/${topic.id}`}>
                                      <NavLink to={`/learn/${category.id}/${topic.id}`}>
                                        <Star className="h-3 w-3" />
                                        <span>{topic.title}</span>
                                      </NavLink>
                                    </SidebarMenuSubButton>
                                  </SidebarMenuSubItem>
                                ))}
                              </SidebarMenuSub>
                            </CollapsibleContent>
                          </SidebarMenuItem>
                        </Collapsible>
                      );
                    })}
                  </SidebarMenu>
                </SidebarGroupContent>
              </CollapsibleContent>
            </Collapsible>
          </SidebarGroup>

          {/* Challenge Modules */}
          <SidebarGroup className="px-2">
            <Collapsible 
              open={openGroups.includes("challenges")}
              onOpenChange={() => toggleGroup("challenges")}
            >
              <SidebarGroupLabel asChild>
                <CollapsibleTrigger className="group/collapsible">
                  <Target className="h-4 w-4" />
                  Challenges
                  <ChevronRight className="ml-auto transition-transform group-data-[state=open]/collapsible:rotate-90" />
                </CollapsibleTrigger>
              </SidebarGroupLabel>
              <CollapsibleContent>
                <SidebarGroupContent>
                  <SidebarMenu className="space-y-1">
                    {challengeModules.map((module) => {
                      const Icon = module.icon;
                      const isActive = currentPath.includes(module.id);
                      
                      return (
                        <SidebarMenuItem key={module.id}>
                          <SidebarMenuButton asChild isActive={isActive}>
                            <NavLink to={`/challenges/${module.id}`}>
                              <Icon className="h-4 w-4" />
                              <span>{moduleNames[module.id as keyof typeof moduleNames]}</span>
                            </NavLink>
                          </SidebarMenuButton>
                        </SidebarMenuItem>
                      );
                    })}
                  </SidebarMenu>
                </SidebarGroupContent>
              </CollapsibleContent>
            </Collapsible>
          </SidebarGroup>
          </div>
        </div>
        
        {/* Gradient overlay to indicate more content below */}
        <div className="absolute bottom-0 left-0 right-0 h-8 bg-gradient-to-t from-sidebar/80 to-transparent pointer-events-none" />
      </SidebarContent>

      {/* Quick Stats - Fixed Footer */}
      <SidebarFooter className="border-t border-sidebar-border bg-sidebar/50 shrink-0">
        {!collapsed ? (
          <div className="p-3 space-y-3">
            <div className="text-xs font-medium text-sidebar-foreground/70 uppercase tracking-wide">
              Progress
            </div>
            <div className="space-y-2">
              <div className="flex items-center justify-between text-sm">
                <span className="text-sidebar-foreground/80">Challenges:</span>
                <Badge variant="outline" className="text-xs font-medium">
                  0/{challengeModules.length}
                </Badge>
              </div>
              <div className="flex items-center justify-between text-sm">
                <span className="text-sidebar-foreground/80">Completed:</span>
                <div className="flex items-center gap-1">
                  <span className="text-xs font-medium text-sidebar-foreground/60">0%</span>
                  <Trophy className="h-3 w-3 text-warning" />
                </div>
              </div>
            </div>
          </div>
        ) : (
          <div className="p-2 flex flex-col items-center gap-2">
            <Badge variant="outline" className="text-xs w-8 h-6 flex items-center justify-center">
              0
            </Badge>
            <Trophy className="h-4 w-4 text-warning" />
          </div>
        )}
      </SidebarFooter>
    </Sidebar>
  );
}