import { useState, useEffect, useCallback } from 'react';
import { lessons as learnLessons, type Lesson, type LessonSection } from '@/data/interactiveContent';

// Use the actual types from interactiveContent
export type LearnLesson = Lesson;
export type LearnSection = LessonSection;

export interface LearningPath {
  id: string;
  title: string;
  description: string;
  lessons: string[];
  totalPoints: number;
  completionBadge: string;
}

export interface Badge {
  id: string;
  name: string;
  description: string;
  icon: string;
  points: number;
  condition: string;
}

// Create basic learning paths and badges from the lesson data
const learningPaths: LearningPath[] = [
  {
    id: 'web-security-basics',
    title: 'Web Security Fundamentals',
    description: 'Complete beginner path for web security',
    lessons: learnLessons.slice(0, 10).map(l => l.id),
    totalPoints: 500,
    completionBadge: 'Web Security Graduate'
  }
];

const badges: Badge[] = [
  {
    id: 'security-rookie',
    name: 'Security Rookie',
    description: 'Started your security journey',
    icon: '🔰',
    points: 25,
    condition: 'Complete first lesson'
  },
  {
    id: 'sql-explorer',
    name: 'SQL Explorer',
    description: 'Discovered SQL injection vulnerabilities',
    icon: '🗃️',
    points: 50,
    condition: 'Complete SQL injection lesson'
  },
  {
    id: 'web-security-graduate',
    name: 'Web Security Graduate',
    description: 'Completed the web security fundamentals path',
    icon: '🎓',
    points: 100,
    condition: 'Complete web security path'
  }
];

export interface LearnProgress {
  lessonId: string;
  sectionId: string;
  completed: boolean;
  timeSpent: number; // in minutes
  quizScore?: number;
  startedAt: Date;
  completedAt?: Date;
}

export interface UserStats {
  totalPoints: number;
  earnedBadges: string[];
  completedLessons: string[];
  currentStreak: number;
  totalTimeSpent: number;
  level: number;
  rank: number;
  achievements: string[];
}

export interface LearnModeState {
  currentLesson: string | null;
  currentSection: string | null;
  progress: LearnProgress[];
  stats: UserStats;
  isLearning: boolean;
  roadmapView: boolean;
}

const STORAGE_KEY = 'cyberlab-learn-progress';

export const useLearnMode = () => {
  const [state, setState] = useState<LearnModeState>({
    currentLesson: null,
    currentSection: null,
    progress: [],
    stats: {
      totalPoints: 0,
      earnedBadges: [],
      completedLessons: [],
      currentStreak: 0,
      totalTimeSpent: 0,
      level: 1,
      rank: 0,
      achievements: []
    },
    isLearning: false,
    roadmapView: false
  });

  // Load progress from localStorage
  useEffect(() => {
    const savedProgress = localStorage.getItem(STORAGE_KEY);
    if (savedProgress) {
      try {
        const parsed = JSON.parse(savedProgress);
        setState(prev => ({
          ...prev,
          ...parsed,
          progress: parsed.progress?.map((p: any) => ({
            ...p,
            startedAt: new Date(p.startedAt),
            completedAt: p.completedAt ? new Date(p.completedAt) : undefined
          })) || []
        }));
      } catch (error) {
        console.error('Error loading learn progress:', error);
      }
    }
  }, []);

  // Save progress to localStorage
  const saveProgress = useCallback((newState: LearnModeState) => {
    try {
      localStorage.setItem(STORAGE_KEY, JSON.stringify(newState));
    } catch (error) {
      console.error('Error saving learn progress:', error);
    }
  }, []);

  // Start a lesson
  const startLesson = useCallback((lessonId: string) => {
    const lesson = learnLessons.find(l => l.id === lessonId);
    if (!lesson) return;

    // Check prerequisites
    const hasPrerequisites = lesson.prerequisites.every(prereqId => 
      state.stats.completedLessons.includes(prereqId)
    );

    if (!hasPrerequisites && lesson.prerequisites.length > 0) {
      console.warn('Prerequisites not met for lesson:', lessonId);
      return;
    }

    const firstSection = lesson.sections[0];
    const newState = {
      ...state,
      currentLesson: lessonId,
      currentSection: firstSection.id,
      isLearning: true,
      roadmapView: false
    };

    // Add progress entry if not exists
    const existingProgress = state.progress.find(p => 
      p.lessonId === lessonId && p.sectionId === firstSection.id
    );

    if (!existingProgress) {
      newState.progress = [
        ...state.progress,
        {
          lessonId,
          sectionId: firstSection.id,
          completed: false,
          timeSpent: 0,
          startedAt: new Date()
        }
      ];
    }

    setState(newState);
    saveProgress(newState);
  }, [state, saveProgress]);

  // Navigate to section
  const goToSection = useCallback((lessonId: string, sectionId: string) => {
    const newState = {
      ...state,
      currentLesson: lessonId,
      currentSection: sectionId,
      isLearning: true
    };

    // Track section start if not exists
    const existingProgress = state.progress.find(p => 
      p.lessonId === lessonId && p.sectionId === sectionId
    );

    if (!existingProgress) {
      newState.progress = [
        ...state.progress,
        {
          lessonId,
          sectionId,
          completed: false,
          timeSpent: 0,
          startedAt: new Date()
        }
      ];
    }

    setState(newState);
    saveProgress(newState);
  }, [state, saveProgress]);

  // Complete section
  const completeSection = useCallback((lessonId: string, sectionId: string, timeSpent: number = 0, quizScore?: number) => {
    const newProgress = state.progress.map(p => {
      if (p.lessonId === lessonId && p.sectionId === sectionId) {
        return {
          ...p,
          completed: true,
          timeSpent: p.timeSpent + timeSpent,
          quizScore,
          completedAt: new Date()
        };
      }
      return p;
    });

    // If section wasn't tracked before, add it as completed
    const existingProgress = state.progress.find(p => 
      p.lessonId === lessonId && p.sectionId === sectionId
    );

    if (!existingProgress) {
      newProgress.push({
        lessonId,
        sectionId,
        completed: true,
        timeSpent,
        quizScore,
        startedAt: new Date(),
        completedAt: new Date()
      });
    }

    // Calculate points earned
    const lesson = learnLessons.find(l => l.id === lessonId);
    const section = lesson?.sections.find(s => s.id === sectionId);
    let pointsEarned = 0;

    if (section?.type === 'quiz' && quizScore) {
      pointsEarned = quizScore;
    } else {
      pointsEarned = Math.floor((lesson?.points || 0) / lesson?.sections.length || 1);
    }

    // Check if lesson is fully completed
    const lessonSections = lesson?.sections.map(s => s.id) || [];
    const completedSections = newProgress
      .filter(p => p.lessonId === lessonId && p.completed)
      .map(p => p.sectionId);
    
    const isLessonComplete = lessonSections.every(sId => completedSections.includes(sId));
    
    // Update stats
    const newStats = {
      ...state.stats,
      totalPoints: state.stats.totalPoints + pointsEarned,
      totalTimeSpent: state.stats.totalTimeSpent + timeSpent
    };

    if (isLessonComplete && !state.stats.completedLessons.includes(lessonId)) {
      newStats.completedLessons = [...state.stats.completedLessons, lessonId];
      newStats.currentStreak = newStats.currentStreak + 1;
      
      // Award achievement badges based on lesson completion
      if (!newStats.earnedBadges.includes('sql-explorer') && lessonId.includes('sql')) {
        newStats.earnedBadges.push('sql-explorer');
        newStats.totalPoints += 50;
      }

      // Check for hidden achievements
      checkHiddenAchievements(newStats, timeSpent, lesson);
    }

    // Calculate level (every 100 points = 1 level)
    newStats.level = Math.floor(newStats.totalPoints / 100) + 1;

    const newState = {
      ...state,
      progress: newProgress,
      stats: newStats
    };

    setState(newState);
    saveProgress(newState);

    return { pointsEarned, isLessonComplete };
  }, [state, saveProgress]);

  // Check hidden achievements
  const checkHiddenAchievements = useCallback((stats: UserStats, timeSpent: number, lesson?: Lesson) => {
    const now = new Date();
    const hour = now.getHours();

    // Night Owl achievement
    if ((hour >= 23 || hour <= 5) && !stats.achievements.includes('night-owl')) {
      stats.achievements.push('night-owl');
    }

    // Speed Learner achievement
    if (lesson && timeSpent < (lesson.estimatedTime * 0.5) && !stats.achievements.includes('speed-learner')) {
      stats.achievements.push('speed-learner');
    }

    // First Root achievement (when completing command injection)
    if (lesson?.id === 'command-injection-basics' && !stats.achievements.includes('first-root')) {
      stats.achievements.push('first-root');
    }
  }, []);

  // Get next section
  const getNextSection = useCallback((lessonId: string, currentSectionId: string) => {
    const lesson = learnLessons.find(l => l.id === lessonId);
    if (!lesson) return null;

    const currentIndex = lesson.sections.findIndex(s => s.id === currentSectionId);
    if (currentIndex === -1 || currentIndex === lesson.sections.length - 1) return null;

    return lesson.sections[currentIndex + 1];
  }, []);

  // Get previous section
  const getPreviousSection = useCallback((lessonId: string, currentSectionId: string) => {
    const lesson = learnLessons.find(l => l.id === lessonId);
    if (!lesson) return null;

    const currentIndex = lesson.sections.findIndex(s => s.id === currentSectionId);
    if (currentIndex <= 0) return null;

    return lesson.sections[currentIndex - 1];
  }, []);

  // Toggle roadmap view
  const toggleRoadmapView = useCallback(() => {
    const newState = {
      ...state,
      roadmapView: !state.roadmapView,
      isLearning: false
    };
    setState(newState);
    saveProgress(newState);
  }, [state, saveProgress]);

  // Get lesson progress percentage
  const getLessonProgress = useCallback((lessonId: string) => {
    const lesson = learnLessons.find(l => l.id === lessonId);
    if (!lesson) return 0;

    const completedSections = state.progress
      .filter(p => p.lessonId === lessonId && p.completed)
      .length;

    return Math.round((completedSections / lesson.sections.length) * 100);
  }, [state.progress]);

  // Get available lessons (considering prerequisites)
  const getAvailableLessons = useCallback(() => {
    return learnLessons.filter(lesson => {
      if (lesson.prerequisites.length === 0) return true;
      return lesson.prerequisites.every(prereqId => 
        state.stats.completedLessons.includes(prereqId)
      );
    });
  }, [state.stats.completedLessons]);

  // Get learning path progress
  const getLearningPathProgress = useCallback((pathId: string) => {
    const path = learningPaths.find(p => p.id === pathId);
    if (!path) return 0;

    const completedLessons = path.lessons.filter(lessonId =>
      state.stats.completedLessons.includes(lessonId)
    ).length;

    return Math.round((completedLessons / path.lessons.length) * 100);
  }, [state.stats.completedLessons]);

  // Exit learn mode
  const exitLearnMode = useCallback(() => {
    setState(prev => ({
      ...prev,
      isLearning: false,
      roadmapView: false
    }));
  }, []);

  return {
    // State
    ...state,
    lessons: learnLessons,
    paths: learningPaths,
    availableBadges: badges,

    // Actions
    startLesson,
    goToSection,
    completeSection,
    getNextSection,
    getPreviousSection,
    toggleRoadmapView,
    getLessonProgress,
    getAvailableLessons,
    getLearningPathProgress,
    exitLearnMode,

    // Computed
    currentLessonData: state.currentLesson ? learnLessons.find(l => l.id === state.currentLesson) : null,
    currentSectionData: state.currentLesson && state.currentSection ? 
      learnLessons.find(l => l.id === state.currentLesson)?.sections.find(s => s.id === state.currentSection) : null
  };
};