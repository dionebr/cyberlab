import { useState, useEffect } from "react";
import { ChevronDown, ChevronRight, Star, Shield, Globe, Network, Lock, Code, Clock, Trophy, Download, Upload } from "lucide-react";
import { Card, CardContent, CardHeader } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Badge } from "@/components/ui/badge";
import { Progress } from "@/components/ui/progress";
import { Separator } from "@/components/ui/separator";
import { useLanguage } from "../hooks/useLanguage";
import { useLearnProgressContext } from "../contexts/LearnProgressContext";
import type { LessonProgress } from "../hooks/useLearnProgress";

interface LearnItem {
  id: string;
  title: string;
  type: 'category' | 'lesson';
  totalSections?: number;
  children?: LearnItem[];
}

// Mapeamento do conteúdo das lições com total de seções
const lessonSectionCount: Record<string, number> = {
  "owasp-top10": 10,
  "secure-coding-principles": 8,
  "threat-modeling": 6,
  "injection-attacks": 8,
  "authentication-security": 7,
  "session-management": 6,
  "network-protocols": 6,
  "firewalls-ids": 8,
  "encryption-pki": 10
};

const learnStructure: LearnItem[] = [
  {
    id: "security-fundamentals",
    title: "Security Fundamentals",
    type: "category",
    children: [
      { id: "owasp-top10", title: "OWASP Top 10", type: "lesson", totalSections: lessonSectionCount["owasp-top10"] },
      { id: "secure-coding-principles", title: "Secure Coding Principles", type: "lesson", totalSections: lessonSectionCount["secure-coding-principles"] },
      { id: "threat-modeling", title: "Threat Modeling", type: "lesson", totalSections: lessonSectionCount["threat-modeling"] }
    ]
  },
  {
    id: "web-security", 
    title: "Web Security",
    type: "category",
    children: [
      { id: "injection-attacks", title: "Injection Attacks", type: "lesson", totalSections: lessonSectionCount["injection-attacks"] },
      { id: "authentication-security", title: "Authentication Security", type: "lesson", totalSections: lessonSectionCount["authentication-security"] },
      { id: "session-management", title: "Session Management", type: "lesson", totalSections: lessonSectionCount["session-management"] }
    ]
  },
  {
    id: "network-security",
    title: "Network Security", 
    type: "category",
    children: [
      { id: "network-protocols", title: "Network Protocols", type: "lesson", totalSections: lessonSectionCount["network-protocols"] },
      { id: "firewalls-ids", title: "Firewalls & IDS", type: "lesson", totalSections: lessonSectionCount["firewalls-ids"] },
      { id: "encryption-pki", title: "Encryption & PKI", type: "lesson", totalSections: lessonSectionCount["encryption-pki"] }
    ]
  }
];

const getCategoryIcon = (id: string) => {
  switch (id) {
    case "security-fundamentals":
      return <Shield className="h-4 w-4" />;
    case "web-security":
      return <Code className="h-4 w-4" />;
    case "network-security":
      return <Network className="h-4 w-4" />;
    default:
      return <Lock className="h-4 w-4" />;
  }
};

interface LearnTreeItemProps {
  item: LearnItem;
  level: number;
  onSelect: (id: string) => void;
  selectedId?: string;
}

const LearnTreeItem = ({ item, level, onSelect, selectedId }: LearnTreeItemProps) => {
  const [isExpanded, setIsExpanded] = useState(true);
  const { t } = useLanguage();
  const { getLessonProgress, toggleFavorite, getCategoryProgress } = useLearnProgressContext();

  const handleClick = () => {
    if (item.type === 'category' && item.children) {
      setIsExpanded(!isExpanded);
    } else {
      onSelect(item.id);
    }
  };

  const handleToggleFavorite = (e: React.MouseEvent) => {
    e.stopPropagation();
    if (item.type === 'lesson' && item.totalSections) {
      // Determinar a categoria pai
      const categoryId = item.id.includes('owasp') || item.id.includes('secure-coding') || item.id.includes('threat') 
        ? 'fundamentals' 
        : item.id.includes('injection') || item.id.includes('auth') || item.id.includes('session')
        ? 'web-security'
        : 'network-security';
      
      toggleFavorite(categoryId, item.id);
    }
  };

  const isSelected = selectedId === item.id;

  // Obter progresso para lições
  let lessonProgress = null;
  let isFavorite = false;
  
  if (item.type === 'lesson') {
    const categoryId = item.id.includes('owasp') || item.id.includes('secure-coding') || item.id.includes('threat') 
      ? 'fundamentals' 
      : item.id.includes('injection') || item.id.includes('auth') || item.id.includes('session')
      ? 'web-security'
      : 'network-security';
    
    lessonProgress = getLessonProgress(categoryId, item.id);
    isFavorite = lessonProgress?.favorite || false;
  }

  // Obter progresso para categorias
  let categoryProgress = null;
  if (item.type === 'category') {
    const categoryMap: Record<string, string> = {
      'security-fundamentals': 'fundamentals',
      'web-security': 'web-security', 
      'network-security': 'network-security'
    };
    categoryProgress = getCategoryProgress(categoryMap[item.id]);
  }

  return (
    <div className="select-none">
      <Button
        variant="ghost"
        size="sm"
        className={`w-full justify-start text-left h-auto p-2 hover:bg-primary/5 ${
          level > 0 ? "ml-4" : ""
        } ${isSelected ? "bg-primary/10 border-l-2 border-l-primary" : ""}`}
        onClick={handleClick}
      >
        <div className="flex items-center gap-2 w-full">
          {item.children ? (
            <>
              {isExpanded ? (
                <ChevronDown className="h-3 w-3 flex-shrink-0" />
              ) : (
                <ChevronRight className="h-3 w-3 flex-shrink-0" />
              )}
              {level === 0 && getCategoryIcon(item.id)}
            </>
          ) : (
            <>
              <div className="w-3" />
              <button onClick={handleToggleFavorite} className="p-0.5 hover:bg-primary/10 rounded">
                {isFavorite && <Star className="h-3 w-3 text-warning fill-warning flex-shrink-0" />}
                {!isFavorite && <Star className="h-3 w-3 text-muted-foreground flex-shrink-0" />}
              </button>
            </>
          )}
          
          <div className="flex-1 min-w-0">
            <div className="flex items-center justify-between">
              <span className={`text-sm ${item.type === 'category' ? 'font-semibold' : 'font-medium'} truncate`}>
                {item.title}
              </span>
              {item.type === 'lesson' && lessonProgress && lessonProgress.progressPercentage > 0 && (
                <Badge variant="secondary" className="text-xs px-1 py-0">
                  {lessonProgress.progressPercentage}%
                </Badge>
              )}
              {item.type === 'category' && categoryProgress && categoryProgress.overallProgress > 0 && (
                <Badge variant="outline" className="text-xs px-1 py-0">
                  {categoryProgress.overallProgress}%
                </Badge>
              )}
            </div>
            
            {/* Progress bar para lições */}
            {item.type === 'lesson' && lessonProgress && (
              <div className="flex items-center gap-1 mt-1">
                <div className="w-16 h-1 bg-muted rounded-full">
                  <div 
                    className={`h-1 rounded-full transition-all duration-300 ${
                      lessonProgress.progressPercentage > 0 ? 'bg-primary' : 'bg-muted'
                    }`}
                    style={{ width: `${lessonProgress.progressPercentage}%` }}
                  />
                </div>
                {lessonProgress.progressPercentage === 100 && (
                  <Trophy className="h-3 w-3 text-warning" />
                )}
              </div>
            )}
            
            {/* Progress bar para categorias */}
            {item.type === 'category' && categoryProgress && (
              <div className="flex items-center gap-1 mt-1">
                <div className="w-20 h-1 bg-muted rounded-full">
                  <div 
                    className={`h-1 rounded-full transition-all duration-300 ${
                      categoryProgress.overallProgress > 0 ? 'bg-success' : 'bg-muted'
                    }`}
                    style={{ width: `${categoryProgress.overallProgress}%` }}
                  />
                </div>
                <span className="text-xs text-muted-foreground">
                  {Object.values(categoryProgress.lessons).filter((l: any) => l.progressPercentage === 100).length}/{Object.keys(categoryProgress.lessons).length}
                </span>
              </div>
            )}
          </div>
        </div>
      </Button>

      {isExpanded && item.children && (
        <div className="mt-1 space-y-0.5">
          {item.children.map((child) => (
            <LearnTreeItem
              key={child.id}
              item={child}
              level={level + 1}
              onSelect={onSelect}
              selectedId={selectedId}
            />
          ))}
        </div>
      )}
    </div>
  );
};

interface LearnSidebarProps {
  selectedLesson?: string;
  onLessonSelect: (lessonId: string) => void;
}

export const LearnSidebar = ({ selectedLesson, onLessonSelect }: LearnSidebarProps) => {
  const { t } = useLanguage();
  const { getOverallStats, exportProgress, importProgress } = useLearnProgressContext();
  const [showStats, setShowStats] = useState(false);

  const overallStats = getOverallStats();

  const handleExport = () => {
    const data = exportProgress();
    const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `cyberlab-progress-${new Date().toISOString().split('T')[0]}.json`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  };

  const handleImport = (event: React.ChangeEvent<HTMLInputElement>) => {
    const file = event.target.files?.[0];
    if (file) {
      const reader = new FileReader();
      reader.onload = (e) => {
        try {
          const data = JSON.parse(e.target?.result as string);
          const success = importProgress(data);
          if (success) {
            // Feedback visual de sucesso seria útil aqui
            console.log('Progresso importado com sucesso');
          }
        } catch (error) {
          console.error('Erro ao importar progresso:', error);
        }
      };
      reader.readAsText(file);
    }
    // Reset input
    event.target.value = '';
  };

  return (
    <Card className="h-full border-r border-border bg-slate-50 dark:bg-slate-900/50">
      <CardContent className="p-0">
        <CardHeader className="p-4 border-b bg-slate-100 dark:bg-slate-800/50">
          <div className="flex items-center justify-between">
            <div>
              <h2 className="font-semibold text-lg text-slate-800 dark:text-slate-200">
                {t("learn.mode")}
              </h2>
              <p className="text-sm text-slate-600 dark:text-slate-400">
                {t("learn.guided")}
              </p>
            </div>
            <Button
              variant="ghost"
              size="sm"
              onClick={() => setShowStats(!showStats)}
              className="p-1"
            >
              <Trophy className="h-4 w-4" />
            </Button>
          </div>
          
          {showStats && (
            <>
              <Separator className="my-3" />
              <div className="space-y-3">
                <div className="grid grid-cols-2 gap-4 text-sm">
                  <div className="text-center">
                    <div className="font-semibold text-lg text-primary">{overallStats.completedLessons}</div>
                    <div className="text-muted-foreground">Concluídas</div>
                  </div>
                  <div className="text-center">
                    <div className="font-semibold text-lg text-muted-foreground">{overallStats.totalLessons}</div>
                    <div className="text-muted-foreground">Total</div>
                  </div>
                </div>
                
                <div className="space-y-2">
                  <div className="flex justify-between text-sm">
                    <span>Progresso Geral</span>
                    <span className="font-medium">{overallStats.overallProgress}%</span>
                  </div>
                  <Progress value={overallStats.overallProgress} className="h-2" />
                </div>

                <div className="grid grid-cols-2 gap-4 text-xs">
                  <div className="flex items-center gap-1">
                    <Clock className="h-3 w-3" />
                    <span>{Math.floor(overallStats.totalTimeSpent / 60)}min</span>
                  </div>
                  <div className="flex items-center gap-1">
                    <Star className="h-3 w-3 text-warning" />
                    <span>{overallStats.favoriteCount}</span>
                  </div>
                </div>

                <div className="flex gap-2">
                  <Button variant="outline" size="sm" onClick={handleExport} className="flex-1">
                    <Download className="h-3 w-3 mr-1" />
                    Export
                  </Button>
                  <label className="flex-1">
                    <Button variant="outline" size="sm" className="w-full">
                      <Upload className="h-3 w-3 mr-1" />
                      Import
                    </Button>
                    <input
                      type="file"
                      accept=".json"
                      onChange={handleImport}
                      className="hidden"
                    />
                  </label>
                </div>
              </div>
            </>
          )}
        </CardHeader>
        
        <ScrollArea className="h-[calc(100vh-180px)]">
          <div className="p-3 space-y-1">
            {learnStructure.map((item) => (
              <LearnTreeItem
                key={item.id}
                item={item}
                level={0}
                onSelect={onLessonSelect}
                selectedId={selectedLesson}
              />
            ))}
          </div>
        </ScrollArea>
      </CardContent>
    </Card>
  );
};