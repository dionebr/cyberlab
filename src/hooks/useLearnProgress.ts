import { useState, useEffect, useCallback } from 'react';

export interface LessonProgress {
  lessonId: string;
  sectionsCompleted: string[];
  totalSections: number;
  progressPercentage: number;
  completedAt?: Date;
  timeSpent: number; // em segundos
  lastAccessed: Date;
  favorite: boolean;
}

export interface CategoryProgress {
  categoryId: string;
  lessons: Record<string, LessonProgress>;
  overallProgress: number;
}

const STORAGE_KEY = 'cyberlab-learn-progress';

// Função para calcular progresso geral de uma categoria
const calculateCategoryProgress = (lessons: Record<string, LessonProgress>): number => {
  const lessonKeys = Object.keys(lessons);
  if (lessonKeys.length === 0) return 0;
  
  const totalProgress = lessonKeys.reduce((sum, key) => sum + lessons[key].progressPercentage, 0);
  return Math.round(totalProgress / lessonKeys.length);
};

export const useLearnProgress = () => {
  const [progress, setProgress] = useState<Record<string, CategoryProgress>>({});
  const [loading, setLoading] = useState(true);

  // Carregar progresso do localStorage
  useEffect(() => {
    try {
      const savedProgress = localStorage.getItem(STORAGE_KEY);
      if (savedProgress) {
        const parsed = JSON.parse(savedProgress);
        // Converter strings de data de volta para objetos Date
        Object.keys(parsed).forEach(categoryId => {
          Object.keys(parsed[categoryId].lessons).forEach(lessonId => {
            const lesson = parsed[categoryId].lessons[lessonId];
            if (lesson.completedAt) {
              lesson.completedAt = new Date(lesson.completedAt);
            }
            lesson.lastAccessed = new Date(lesson.lastAccessed);
          });
        });
        setProgress(parsed);
      }
    } catch (error) {
      console.error('Erro ao carregar progresso:', error);
    } finally {
      setLoading(false);
    }
  }, []);

  // Salvar progresso no localStorage
  const saveProgress = useCallback((newProgress: Record<string, CategoryProgress>) => {
    try {
      localStorage.setItem(STORAGE_KEY, JSON.stringify(newProgress));
      setProgress(newProgress);
    } catch (error) {
      console.error('Erro ao salvar progresso:', error);
    }
  }, []);

  // Inicializar lição se não existir
  const initializeLesson = useCallback((categoryId: string, lessonId: string, totalSections: number) => {
    setProgress(currentProgress => {
      const newProgress = { ...currentProgress };
      
      if (!newProgress[categoryId]) {
        newProgress[categoryId] = {
          categoryId,
          lessons: {},
          overallProgress: 0
        };
      }

      if (!newProgress[categoryId].lessons[lessonId]) {
        newProgress[categoryId].lessons[lessonId] = {
          lessonId,
          sectionsCompleted: [],
          totalSections,
          progressPercentage: 0,
          timeSpent: 0,
          lastAccessed: new Date(),
          favorite: false
        };
      }

      // Recalcular progresso da categoria
      newProgress[categoryId].overallProgress = calculateCategoryProgress(newProgress[categoryId].lessons);
      
      saveProgress(newProgress);
      return newProgress;
    });
  }, [saveProgress]);

  // Marcar seção como completada
  const markSectionCompleted = useCallback((categoryId: string, lessonId: string, sectionId: string) => {
    setProgress(currentProgress => {
      const newProgress = { ...currentProgress };
      
      if (!newProgress[categoryId]?.lessons[lessonId]) return currentProgress;

      const lesson = newProgress[categoryId].lessons[lessonId];
      if (!lesson.sectionsCompleted.includes(sectionId)) {
        lesson.sectionsCompleted.push(sectionId);
        lesson.progressPercentage = Math.round((lesson.sectionsCompleted.length / lesson.totalSections) * 100);
        lesson.lastAccessed = new Date();
        
        // Marcar como completada se chegou a 100%
        if (lesson.progressPercentage === 100 && !lesson.completedAt) {
          lesson.completedAt = new Date();
        }
      }

      // Recalcular progresso da categoria
      newProgress[categoryId].overallProgress = calculateCategoryProgress(newProgress[categoryId].lessons);
      
      saveProgress(newProgress);
      return newProgress;
    });
  }, [saveProgress]);

  // Atualizar tempo gasto
  const updateTimeSpent = useCallback((categoryId: string, lessonId: string, additionalSeconds: number) => {
    setProgress(currentProgress => {
      const newProgress = { ...currentProgress };
      
      if (!newProgress[categoryId]?.lessons[lessonId]) return currentProgress;

      const lesson = newProgress[categoryId].lessons[lessonId];
      lesson.timeSpent += additionalSeconds;
      lesson.lastAccessed = new Date();

      saveProgress(newProgress);
      return newProgress;
    });
  }, [saveProgress]);

  // Toggle favorito
  const toggleFavorite = useCallback((categoryId: string, lessonId: string) => {
    setProgress(currentProgress => {
      const newProgress = { ...currentProgress };
      
      if (!newProgress[categoryId]?.lessons[lessonId]) return currentProgress;

      const lesson = newProgress[categoryId].lessons[lessonId];
      lesson.favorite = !lesson.favorite;

      saveProgress(newProgress);
      return newProgress;
    });
  }, [saveProgress]);

  // Resetar progresso de uma lição
  const resetLessonProgress = useCallback((categoryId: string, lessonId: string) => {
    setProgress(currentProgress => {
      const newProgress = { ...currentProgress };
      
      if (!newProgress[categoryId]?.lessons[lessonId]) return currentProgress;

      const lesson = newProgress[categoryId].lessons[lessonId];
      lesson.sectionsCompleted = [];
      lesson.progressPercentage = 0;
      lesson.completedAt = undefined;
      lesson.timeSpent = 0;
      lesson.lastAccessed = new Date();

      // Recalcular progresso da categoria
      newProgress[categoryId].overallProgress = calculateCategoryProgress(newProgress[categoryId].lessons);

      saveProgress(newProgress);
      return newProgress;
    });
  }, [saveProgress]);

  // Obter progresso de uma lição específica
  const getLessonProgress = useCallback((categoryId: string, lessonId: string): LessonProgress | null => {
    return progress[categoryId]?.lessons[lessonId] || null;
  }, [progress]);

  // Obter progresso de uma categoria
  const getCategoryProgress = useCallback((categoryId: string): CategoryProgress | null => {
    return progress[categoryId] || null;
  }, [progress]);

  // Obter estatísticas gerais
  const getOverallStats = useCallback(() => {
    const categories = Object.values(progress);
    const totalLessons = categories.reduce((sum, cat) => sum + Object.keys(cat.lessons).length, 0);
    const completedLessons = categories.reduce((sum, cat) => 
      sum + Object.values(cat.lessons).filter(lesson => lesson.progressPercentage === 100).length, 0
    );
    const totalTimeSpent = categories.reduce((sum, cat) => 
      sum + Object.values(cat.lessons).reduce((timeSum, lesson) => timeSum + lesson.timeSpent, 0), 0
    );
    const favoriteCount = categories.reduce((sum, cat) => 
      sum + Object.values(cat.lessons).filter(lesson => lesson.favorite).length, 0
    );

    return {
      totalLessons,
      completedLessons,
      overallProgress: totalLessons > 0 ? Math.round((completedLessons / totalLessons) * 100) : 0,
      totalTimeSpent,
      favoriteCount
    };
  }, [progress]);

  // Exportar dados de progresso
  const exportProgress = useCallback(() => {
    return {
      exportedAt: new Date().toISOString(),
      version: '1.0',
      progress
    };
  }, [progress]);

  // Importar dados de progresso
  const importProgress = useCallback((importedData: any) => {
    try {
      if (importedData.version === '1.0' && importedData.progress) {
        // Converter strings de data de volta para objetos Date
        Object.keys(importedData.progress).forEach(categoryId => {
          Object.keys(importedData.progress[categoryId].lessons).forEach(lessonId => {
            const lesson = importedData.progress[categoryId].lessons[lessonId];
            if (lesson.completedAt) {
              lesson.completedAt = new Date(lesson.completedAt);
            }
            lesson.lastAccessed = new Date(lesson.lastAccessed);
          });
        });
        
        saveProgress(importedData.progress);
        return true;
      }
      return false;
    } catch (error) {
      console.error('Erro ao importar progresso:', error);
      return false;
    }
  }, [saveProgress]);

  return {
    progress,
    loading,
    initializeLesson,
    markSectionCompleted,
    updateTimeSpent,
    toggleFavorite,
    resetLessonProgress,
    getLessonProgress,
    getCategoryProgress,
    getOverallStats,
    exportProgress,
    importProgress
  };
};