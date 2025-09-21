export interface LearnSection {
  id: string;
  title: string;
  type: 'reading' | 'video' | 'example' | 'terminal' | 'code' | 'quiz';
  content: string;
  estimatedTime?: number; // in minutes
  videoUrl?: string;
  codeLanguage?: string;
  terminalCommands?: string[];
  quizQuestions?: QuizQuestion[];
}

export interface QuizQuestion {
  id: string;
  question: string;
  type: 'multiple-choice' | 'true-false' | 'code-completion';
  options: string[];
  correctAnswer: string | number;
  explanation: string;
  points: number;
}

export interface LearnLesson {
  id: string;
  title: string;
  description: string;
  difficulty: 'beginner' | 'intermediate' | 'advanced';
  category: 'web-security' | 'network-security' | 'os-security' | 'programming-security';
  prerequisites: string[]; // lesson IDs
  estimatedTime: number; // total time in minutes
  points: number;
  badges?: string[];
  sections: LearnSection[];
  challengeRecommendation?: string; // challenge ID
}

export interface LearningPath {
  id: string;
  title: string;
  description: string;
  lessons: string[]; // lesson IDs in order
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

// Main learning lessons data (in English)
export const learnLessons: LearnLesson[] = [
  {
    id: 'web-security-intro',
    title: 'Web Security Introduction',
    description: 'Learn the fundamentals of web application security',
    difficulty: 'beginner',
    category: 'web-security',
    prerequisites: [],
    estimatedTime: 30,
    points: 50,
    badges: ['Security Rookie'],
    sections: [
      {
        id: 'intro-reading',
        title: 'What is Web Security?',
        type: 'reading',
        estimatedTime: 15,
        content: 'Web security protects websites and web applications from cyber threats...'
      }
    ]
  },
  {
    id: 'sql-injection-basics',
    title: 'SQL Injection Fundamentals',
    description: 'Learn SQL injection from basics to advanced techniques',
    difficulty: 'beginner',
    category: 'web-security',
    prerequisites: ['web-security-intro'],
    estimatedTime: 45,
    points: 100,
    badges: ['SQL Explorer', 'Database Detective'],
    challengeRecommendation: 'sql-injection',
    sections: [
      {
        id: 'intro-reading',
        title: 'What is SQL Injection?',
        type: 'reading',
        estimatedTime: 15,
        content: 'SQL Injection is one of the most critical web application vulnerabilities...'
      },
      {
        id: 'practical-example',
        title: 'Practical Example: Login Bypass',
        type: 'example',
        estimatedTime: 20,
        content: 'Learn how to identify and exploit SQL injection vulnerabilities...'
      },
      {
        id: 'quiz-section',
        title: 'Test Your Knowledge',
        type: 'quiz',
        estimatedTime: 10,
        content: 'Quiz about SQL injection concepts',
        quizQuestions: [
          {
            id: '1',
            question: 'What is SQL Injection?',
            type: 'multiple-choice',
            options: [
              'A database optimization technique',
              'A vulnerability allowing malicious SQL execution',
              'A data backup method',
              'A database encryption method'
            ],
            correctAnswer: 1,
            explanation: 'SQL Injection allows attackers to execute malicious SQL commands',
            points: 10
          }
        ]
      }
    ]
  },
  {
    id: 'xss-basics',
    title: 'Cross-Site Scripting (XSS)',
    description: 'Understanding XSS attacks and prevention',
    difficulty: 'beginner',
    category: 'web-security',
    prerequisites: ['web-security-intro'],
    estimatedTime: 40,
    points: 100,
    badges: ['XSS Hunter'],
    sections: [
      {
        id: 'intro-reading',
        title: 'Introduction to XSS',
        type: 'reading',
        estimatedTime: 20,
        content: 'Cross-Site Scripting allows injection of malicious scripts...'
      },
      {
        id: 'practical-demo',
        title: 'XSS Demo',
        type: 'terminal',
        estimatedTime: 20,
        content: 'Practice XSS exploitation techniques',
        terminalCommands: [
          'curl -X POST "http://vulnerable-site.com/comment" -d "comment=<script>alert(1)</script>"'
        ]
      }
    ]
  }
];

// Learning paths that group related lessons
export const learningPaths: LearningPath[] = [
  {
    id: 'web-security-basics',
    title: 'Web Security Fundamentals',
    description: 'Complete beginner path for web security',
    lessons: ['web-security-intro', 'sql-injection-basics', 'xss-basics'],
    totalPoints: 250,
    completionBadge: 'Web Security Graduate'
  },
  {
    id: 'injection-specialist',
    title: 'Injection Attack Specialist',
    description: 'Master all types of injection attacks',
    lessons: ['sql-injection-basics'],
    totalPoints: 200,
    completionBadge: 'Injection Master'
  }
];

// Achievement badges
export const badges: Badge[] = [
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
    id: 'database-detective',
    name: 'Database Detective',
    description: 'Expert at finding database vulnerabilities',
    icon: '🕵️',
    points: 75,
    condition: 'Master SQL injection techniques'
  },
  {
    id: 'xss-hunter',
    name: 'XSS Hunter',
    description: 'Found your first XSS vulnerability',
    icon: '🎯',
    points: 50,
    condition: 'Complete XSS lesson'
  },
  {
    id: 'web-security-graduate',
    name: 'Web Security Graduate',
    description: 'Completed the web security fundamentals path',
    icon: '🎓',
    points: 100,
    condition: 'Complete web security path'
  },
  {
    id: 'injection-master',
    name: 'Injection Master',
    description: 'Master of all injection attack types',
    icon: '💉',
    points: 150,
    condition: 'Complete injection specialist path'
  },
  {
    id: 'night-owl',
    name: 'Night Owl',
    description: 'Learning late at night',
    icon: '🦉',
    points: 25,
    condition: 'Complete lesson between 11 PM - 5 AM'
  },
  {
    id: 'speed-learner',
    name: 'Speed Learner',
    description: 'Completed lesson in record time',
    icon: '⚡',
    points: 50,
    condition: 'Complete lesson in less than 50% of estimated time'
  },
  {
    id: 'first-root',
    name: 'First Root',
    description: 'Successfully executed your first command injection',
    icon: '🏁',
    points: 75,
    condition: 'Complete command injection lesson'
  }
];