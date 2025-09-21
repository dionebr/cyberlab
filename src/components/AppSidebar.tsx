import { useState } from "react";
import { NavLink, useLocation } from "react-router-dom";
import {
  Database, Code, Terminal, Shield, Upload, Key, Zap, Home, 
  Target, BookOpen, ChevronRight, Trophy, Star, Users, Flag, FlaskConical,
  Play, CheckCircle, Lock, Brain, FileText, Video, Gamepad2
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
import { Button } from "@/components/ui/button";
import { Progress } from "@/components/ui/progress";
import { Collapsible, CollapsibleContent, CollapsibleTrigger } from "@/components/ui/collapsible";
import { useSecurityLevelContext } from "@/contexts/SecurityLevelContext";
import { useLearnMode } from "@/hooks/useLearnMode";
import { LearnContent } from "@/components/LearnContent";

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
  { 
    id: "totp-2fa", 
    icon: Key, 
    color: "info"
  },
  { 
    id: "jwt-authentication", 
    icon: Shield, 
    color: "success"
  },
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
  "totp-2fa": "TOTP/2FA Authentication",
  "jwt-authentication": "JWT Authentication",
};

export function AppSidebar() {
  const { state } = useSidebar();
  const location = useLocation();
  const { securityLevel, getSecurityLevelColor, getSecurityLevelIcon } = useSecurityLevelContext();
  const { lessons, stats, startLesson, currentLessonData, roadmapView, toggleRoadmapView } = useLearnMode();
  const [openGroups, setOpenGroups] = useState<string[]>(["challenges"]);
  const [learnMode, setLearnMode] = useState(false);

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

  const toggleLearnMode = () => {
    setLearnMode(!learnMode);
  };

  // If in Learn Mode, show complete content
  if (learnMode && !collapsed) {
    return (
      <div className="fixed inset-0 z-50 bg-background flex">
        {/* Sidebar expandida ocupando tela toda */}
        <div className="w-full h-full border-r border-sidebar-border flex flex-col">
          <SidebarHeader className="pb-2 shrink-0 bg-sidebar border-b">
            <SidebarMenuButton size="lg" onClick={toggleLearnMode} className="cursor-pointer hover:bg-sidebar-accent">
              <div className="flex items-center gap-2">
                <div className="p-2 bg-gradient-cyber rounded-xl shadow-cyber">
                  <BookOpen className="h-6 w-6 text-white" />
                </div>
                <div className="flex flex-col">
                  <span className="text-lg font-bold text-sidebar-foreground">
                    Learn Mode
                  </span>
                  <span className="text-xs text-sidebar-accent-foreground">
                    Modo Imersivo Ativo • Clique para fechar
                  </span>
                </div>
              </div>
            </SidebarMenuButton>
          </SidebarHeader>

          <SidebarSeparator className="shrink-0" />

          <SidebarContent className="flex-1 overflow-hidden">
            <div className="h-full p-6">
              <LearnContent />
            </div>
          </SidebarContent>

          <SidebarFooter className="border-t border-sidebar-border bg-sidebar/50 shrink-0">
            <div className="p-3 space-y-3">
              <div className="flex items-center justify-between text-sm">
                <span className="text-sidebar-foreground/80">Progresso Atual:</span>
                <Badge variant="outline" className="text-xs font-medium">
                  {stats.completedLessons.length}/{lessons.length}
                </Badge>
              </div>
              <div className="flex items-center justify-between text-sm">
                <span className="text-sidebar-foreground/80">Pontos:</span>
                <div className="flex items-center gap-1">
                  <Trophy className="h-3 w-3 text-warning" />
                  <span className="text-xs font-medium">{stats.totalPoints}</span>
                </div>
              </div>
              <Button 
                variant="outline" 
                size="sm" 
                onClick={toggleLearnMode}
                className="mx-auto px-3 py-1 text-xs"
              >
                ✕ Fechar
              </Button>
            </div>
          </SidebarFooter>
        </div>
      </div>
    );
  }

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
            <SidebarGroupLabel asChild>
              <div className="group/collapsible cursor-pointer" onClick={toggleLearnMode}>
                <BookOpen className="h-4 w-4" />
                Learn Mode Imersivo
                <div className="ml-auto flex items-center gap-1">
                  {stats.completedLessons.length > 0 && (
                    <Badge variant="secondary" className="text-xs">
                      {stats.completedLessons.length}
                    </Badge>
                  )}
                  <ChevronRight className="transition-transform" />
                </div>
              </div>
            </SidebarGroupLabel>
            <SidebarGroupContent>
              <SidebarMenu className="space-y-1">
                {/* Roadmap rápido */}
                <SidebarMenuItem>
                  <SidebarMenuButton onClick={toggleLearnMode} className="gap-2">
                    <Target className="h-4 w-4" />
                    <span>Roadmap Interativo</span>
                    <Badge variant="outline" className="ml-auto text-xs">
                      {lessons.length} lessons
                    </Badge>
                  </SidebarMenuButton>
                </SidebarMenuItem>
                
                {/* Lições em destaque */}
                {lessons.slice(0, 3).map((lesson) => {
                  const isCompleted = stats.completedLessons.includes(lesson.id);
                  const isAvailable = lesson.prerequisites.every(prereq => 
                    stats.completedLessons.includes(prereq)
                  );
                  
                  return (
                    <SidebarMenuItem key={lesson.id}>
                      <SidebarMenuButton 
                        onClick={() => {
                          if (isAvailable) {
                            startLesson(lesson.id);
                            toggleLearnMode();
                          }
                        }}
                        className={`gap-2 ${!isAvailable ? 'opacity-50' : ''}`}
                        disabled={!isAvailable}
                      >
                        {isCompleted ? (
                          <CheckCircle className="h-4 w-4 text-green-500" />
                        ) : isAvailable ? (
                          <Play className="h-4 w-4 text-blue-500" />
                        ) : (
                          <Lock className="h-4 w-4 text-gray-400" />
                        )}
                        <span className="text-xs font-medium">{lesson.title}</span>
                      </SidebarMenuButton>
                    </SidebarMenuItem>
                  );
                })}
                
                {/* Estatísticas rápidas */}
                <SidebarMenuItem>
                  <div className="px-2 py-1 space-y-1">
                    <div className="flex items-center justify-between text-xs">
                      <span>Progresso:</span>
                      <span>{Math.round((stats.completedLessons.length / lessons.length) * 100)}%</span>
                    </div>
                    <Progress 
                      value={(stats.completedLessons.length / lessons.length) * 100} 
                      className="h-1"
                    />
                  </div>
                </SidebarMenuItem>
              </SidebarMenu>
            </SidebarGroupContent>
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
                <span className="text-sidebar-foreground/80">Learn Mode:</span>
                <div className="flex items-center gap-1">
                  <Badge variant="secondary" className="text-xs">
                    {stats.completedLessons.length}/{lessons.length}
                  </Badge>
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