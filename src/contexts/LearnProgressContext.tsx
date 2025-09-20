import { createContext, useContext, ReactNode } from 'react';
import { useLearnProgress, LessonProgress, CategoryProgress } from '../hooks/useLearnProgress';

interface LearnProgressContextType {
  progress: Record<string, CategoryProgress>;
  loading: boolean;
  initializeLesson: (categoryId: string, lessonId: string, totalSections: number) => void;
  markSectionCompleted: (categoryId: string, lessonId: string, sectionId: string) => void;
  updateTimeSpent: (categoryId: string, lessonId: string, additionalSeconds: number) => void;
  toggleFavorite: (categoryId: string, lessonId: string) => void;
  resetLessonProgress: (categoryId: string, lessonId: string) => void;
  getLessonProgress: (categoryId: string, lessonId: string) => LessonProgress | null;
  getCategoryProgress: (categoryId: string) => CategoryProgress | null;
  getOverallStats: () => {
    totalLessons: number;
    completedLessons: number;
    overallProgress: number;
    totalTimeSpent: number;
    favoriteCount: number;
  };
  exportProgress: () => any;
  importProgress: (data: any) => boolean;
}

const LearnProgressContext = createContext<LearnProgressContextType | undefined>(undefined);

export const useLearnProgressContext = (): LearnProgressContextType => {
  const context = useContext(LearnProgressContext);
  if (!context) {
    throw new Error('useLearnProgressContext deve ser usado dentro de LearnProgressProvider');
  }
  return context;
};

interface LearnProgressProviderProps {
  children: ReactNode;
}

export const LearnProgressProvider: React.FC<LearnProgressProviderProps> = ({ children }) => {
  const progressHook = useLearnProgress();

  return (
    <LearnProgressContext.Provider value={progressHook}>
      {children}
    </LearnProgressContext.Provider>
  );
};