import type { QuizQuestion } from '../components/QuizComponent';
import type { CodeExercise } from '../components/CodeExerciseComponent';

// Lesson structure
export interface Lesson {
  id: string;
  title: string;
  description: string;
  difficulty: 'beginner' | 'intermediate' | 'advanced';
  estimatedTime: number; // in minutes
  points: number;
  prerequisites: string[];
  sections: LessonSection[];
}

export interface LessonSection {
  id: string;
  type: 'reading' | 'video' | 'code' | 'terminal' | 'quiz';
  title: string;
  content: any;
  estimatedTime: number;
}

// Enhanced lessons with more variety and smaller cards
export const lessons: Lesson[] = [
    // Web Security Fundamentals
  {
    id: 'web-security-intro',
    title: 'Web Security Introduction',
    description: 'Basic concepts of web application security',
    difficulty: 'beginner',
    estimatedTime: 20,
    points: 40,
    prerequisites: [],
    sections: [
      {
        id: 'web-basics',
        type: 'reading',
        title: 'Web Fundamentals',
        content: '# Web Security\n\nFundamental concepts...',
        estimatedTime: 12
      },
      {
        id: 'web-quiz',
        type: 'quiz',
        title: 'Web Security Quiz',
        content: {},
        estimatedTime: 8
      }
    ]
  },
  {
    id: 'owasp-overview',
    title: 'OWASP Top 10 Overview',
    description: 'Overview of the most critical web vulnerabilities',
    difficulty: 'beginner',
    estimatedTime: 20,
    points: 40,
    prerequisites: ['web-security-intro'],
    sections: [
      {
        id: 'owasp-intro',
        type: 'reading',
        title: 'OWASP Top 10',
        content: '# OWASP Top 10\n\nThe most critical vulnerabilities...',
        estimatedTime: 20
      }
    ]
  },

    // SQL Injection Track
  {
    id: 'sql-basics',
    title: 'SQL Injection - Concepts',
    description: 'Understand how SQL injection works',
    difficulty: 'beginner',
    estimatedTime: 23,
    points: 46,
    prerequisites: ['owasp-overview'],
    sections: [
      {
        id: 'sql-theory',
        type: 'reading',
        title: 'SQL Injection Theory',
        content: '# SQL Injection\n\nHow it works...',
        estimatedTime: 15
      },
      {
        id: 'sql-quiz',
        type: 'quiz',
        title: 'SQL Injection Quiz',
        content: {},
        estimatedTime: 8
      }
    ]
  },
  {
    id: 'sql-union-attacks',
    title: 'SQL Union Attacks',
    description: 'Union-based SQL injection techniques',
    difficulty: 'intermediate',
    estimatedTime: 25,
    points: 50,
    prerequisites: ['sql-basics'],
    sections: [
      {
        id: 'union-demo',
        type: 'terminal',
        title: 'Union Attack Demo',
        content: {
          initialCommand: 'sqlmap -u "site.com" --union-test',
          expectedOutput: 'Union attack successful',
          explanation: 'Testando union attacks'
        },
        estimatedTime: 25
      }
    ]
  },
  {
    id: 'sql-blind-injection',
    title: 'Blind SQL Injection',
    description: 'Exploitation without direct output',
    difficulty: 'advanced',
    estimatedTime: 30,
    points: 70,
    prerequisites: ['sql-union-attacks'],
    sections: [
      {
        id: 'blind-theory',
        type: 'reading',
        title: 'Blind Injection',
        content: '# Blind SQL\n\nTécnicas sem output...',
        estimatedTime: 30
      }
    ]
  },

  // XSS Track
  {
    id: 'xss-intro',
    title: 'XSS - Fundamentals',
    description: 'Introduction to Cross-Site Scripting',
    difficulty: 'beginner',
    estimatedTime: 20,
    points: 40,
    prerequisites: ['web-security-intro'],
    sections: [
      {
        id: 'xss-basics',
        type: 'reading',
        title: 'XSS Basics',
        content: '# XSS\n\nMalicious scripts...',
        estimatedTime: 12
      },
      {
        id: 'xss-quiz',
        type: 'quiz',
        title: 'XSS Quiz',
        content: {},
        estimatedTime: 8
      }
    ]
  },
  {
    id: 'xss-reflected',
    title: 'Reflected XSS',
    description: 'Exploitation via URL parameters',
    difficulty: 'beginner',
    estimatedTime: 20,
    points: 40,
    prerequisites: ['xss-intro'],
    sections: [
      {
        id: 'reflected-demo',
        type: 'code',
        title: 'Payload Refletido',
        content: {
          language: 'html',
          code: '<script>alert("XSS")</script>',
          explanation: 'Payload básico XSS'
        },
        estimatedTime: 20
      }
    ]
  },
  {
    id: 'xss-stored',
    title: 'Stored XSS',
    description: 'Persistent XSS in databases',
    difficulty: 'intermediate',
    estimatedTime: 25,
    points: 55,
    prerequisites: ['xss-reflected'],
    sections: [
      {
        id: 'stored-demo',
        type: 'code',
        title: 'Persistent XSS',
        content: {
          language: 'javascript',
          code: 'localStorage.setItem("xss", "payload")',
          explanation: 'XSS that persists'
        },
        estimatedTime: 25
      }
    ]
  },
  {
    id: 'xss-dom',
    title: 'DOM-based XSS',
    description: 'Client-side XSS via DOM',
    difficulty: 'advanced',
    estimatedTime: 28,
    points: 65,
    prerequisites: ['xss-stored'],
    sections: [
      {
        id: 'dom-demo',
        type: 'code',
        title: 'DOM XSS',
        content: {
          language: 'javascript',
          code: 'document.location.hash.substring(1)',
          explanation: 'DOM exploitation'
        },
        estimatedTime: 28
      }
    ]
  },

  // Command Injection Track
  {
    id: 'command-basics',
    title: 'Basic Command Injection',
    description: 'System command injection',
    difficulty: 'beginner',
    estimatedTime: 22,
    points: 44,
    prerequisites: ['web-security-intro'],
    sections: [
      {
        id: 'cmd-intro',
        type: 'reading',
        title: 'Command Injection',
        content: '# Command Injection\n\nCommand execution...',
        estimatedTime: 22
      }
    ]
  },
  {
    id: 'command-concatenation',
    title: 'Command Concatenation',
    description: 'Concatenation techniques',
    difficulty: 'intermediate',
    estimatedTime: 26,
    points: 52,
    prerequisites: ['command-basics'],
    sections: [
      {
        id: 'concat-demo',
        type: 'terminal',
        title: 'Concatenation Demo',
        content: {
          initialCommand: 'ping google.com; whoami',
          expectedOutput: 'www-data',
          explanation: 'Concatenando comandos'
        },
        estimatedTime: 26
      }
    ]
  },

  // Authentication & Authorization
  {
    id: 'auth-basics',
    title: 'Basic Authentication',
    description: 'Authentication fundamentals',
    difficulty: 'beginner',
    estimatedTime: 18,
    points: 36,
    prerequisites: [],
    sections: [
      {
        id: 'auth-theory',
        type: 'reading',
        title: 'Auth Fundamentals',
        content: '# Authentication\n\nLogin systems...',
        estimatedTime: 18
      }
    ]
  },
  {
    id: 'auth-bypass',
    title: 'Login Bypass',
    description: 'Techniques to bypass authentication',
    difficulty: 'intermediate',
    estimatedTime: 24,
    points: 48,
    prerequisites: ['auth-basics', 'sql-basics'],
    sections: [
      {
        id: 'bypass-demo',
        type: 'terminal',
        title: 'Login Bypass',
        content: {
          initialCommand: 'curl -d "user=admin\' OR \'1\'=\'1" site.com',
          expectedOutput: 'Login successful',
          explanation: 'Bypass via SQL injection'
        },
        estimatedTime: 24
      }
    ]
  },
  {
    id: 'session-management',
    title: 'Session Management',
    description: 'Session tokens and cookies',
    difficulty: 'intermediate',
    estimatedTime: 27,
    points: 54,
    prerequisites: ['auth-bypass'],
    sections: [
      {
        id: 'session-theory',
        type: 'reading',
        title: 'Web Sessions',
        content: '# Sessions\n\nState management...',
        estimatedTime: 27
      }
    ]
  },

  // File Security
  {
    id: 'file-upload-basics',
    title: 'File Upload',
    description: 'File upload security',
    difficulty: 'beginner',
    estimatedTime: 20,
    points: 40,
    prerequisites: ['web-security-intro'],
    sections: [
      {
        id: 'upload-theory',
        type: 'reading',
        title: 'File Upload',
        content: '# Secure Upload\n\nFile validation...',
        estimatedTime: 20
      }
    ]
  },
  {
    id: 'lfi-basics',
    title: 'Local File Inclusion',
    description: 'Local file inclusion vulnerabilities',
    difficulty: 'intermediate',
    estimatedTime: 25,
    points: 50,
    prerequisites: ['file-upload-basics'],
    sections: [
      {
        id: 'lfi-demo',
        type: 'terminal',
        title: 'LFI Demo',
        content: {
          initialCommand: 'curl "site.com/page?file=../../../etc/passwd"',
          expectedOutput: 'root:x:0:0',
          explanation: 'Directory traversal'
        },
        estimatedTime: 25
      }
    ]
  },
  {
    id: 'rfi-attacks',
    title: 'Remote File Inclusion',
    description: 'Inclusão de arquivos remotos',
    difficulty: 'advanced',
    estimatedTime: 30,
    points: 60,
    prerequisites: ['lfi-basics'],
    sections: [
      {
        id: 'rfi-demo',
        type: 'code',
        title: 'RFI Payload',
        content: {
          language: 'php',
          code: '<?php system($_GET["cmd"]); ?>',
          explanation: 'Web shell remota'
        },
        estimatedTime: 30
      }
    ]
  },

  // CSRF & Other Attacks
  {
    id: 'csrf-intro',
    title: 'CSRF - Concepts',
    description: 'Cross-Site Request Forgery',
    difficulty: 'beginner',
    estimatedTime: 19,
    points: 38,
    prerequisites: ['web-security-intro'],
    sections: [
      {
        id: 'csrf-theory',
        type: 'reading',
        title: 'CSRF Basics',
        content: '# CSRF\n\nRequest forgery...',
        estimatedTime: 19
      }
    ]
  },
  {
    id: 'csrf-exploitation',
    title: 'CSRF Exploitation',
    description: 'Creating CSRF exploits',
    difficulty: 'intermediate',
    estimatedTime: 26,
    points: 52,
    prerequisites: ['csrf-intro'],
    sections: [
      {
        id: 'csrf-exploit',
        type: 'code',
        title: 'CSRF PoC',
        content: {
          language: 'html',
          code: '<form action="bank.com/transfer" method="POST">',
          explanation: 'Malicious form'
        },
        estimatedTime: 26
      }
    ]
  },

  // Cryptography Basics
  {
    id: 'crypto-intro',
    title: 'Basic Cryptography',
    description: 'Fundamental cryptography concepts',
    difficulty: 'beginner',
    estimatedTime: 25,
    points: 50,
    prerequisites: [],
    sections: [
      {
        id: 'crypto-basics',
        type: 'reading',
        title: 'Crypto Fundamentals',
        content: '# Cryptography\n\nAlgorithms and keys...',
        estimatedTime: 17
      },
      {
        id: 'crypto-quiz',
        type: 'quiz',
        title: 'Cryptography Quiz',
        content: {},
        estimatedTime: 8
      }
    ]
  },
  {
    id: 'hash-functions',
    title: 'Hash Functions',
    description: 'MD5, SHA, bcrypt and applications',
    difficulty: 'intermediate',
    estimatedTime: 24,
    points: 48,
    prerequisites: ['crypto-intro'],
    sections: [
      {
        id: 'hash-demo',
        type: 'terminal',
        title: 'Hash Demo',
        content: {
          initialCommand: 'echo "password" | sha256sum',
          expectedOutput: '5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8',
          explanation: 'Generating SHA-256 hash'
        },
        estimatedTime: 24
      }
    ]
  },

  // Network Security Track
  {
    id: 'network-scanning',
    title: 'Network Scanning',
    description: 'Network reconnaissance techniques',
    difficulty: 'intermediate',
    estimatedTime: 26,
    points: 52,
    prerequisites: ['web-security-intro'],
    sections: [
      {
        id: 'nmap-basics',
        type: 'terminal',
        title: 'Basic Nmap',
        content: {
          initialCommand: 'nmap -sV localhost',
          expectedOutput: 'PORT     STATE SERVICE VERSION\n22/tcp   open  ssh     OpenSSH 8.0',
          explanation: 'Port and service scanning'
        },
        estimatedTime: 26
      }
    ]
  },
  {
    id: 'vulnerability-assessment',
    title: 'Vulnerability Assessment',
    description: 'Identifying and classifying vulnerabilities',
    difficulty: 'advanced',
    estimatedTime: 32,
    points: 64,
    prerequisites: ['network-scanning'],
    sections: [
      {
        id: 'vuln-scanning',
        type: 'reading',
        title: 'Assessment Methodology',
        content: '# Vulnerability Assessment\n\nSystematic identification process...',
        estimatedTime: 32
      }
    ]
  }
];

// Quiz data preserving technical terminology
export const learnQuizzes: Record<string, QuizQuestion[]> = {
  "owasp-top10": [
    {
      id: "owasp-q1",
      question: "Qual das seguintes vulnerabilidades está no topo da OWASP Top 10 2021?",
      options: [
        "SQL Injection",
        "Broken Access Control",
        "Cross-Site Scripting (XSS)",
        "Security Misconfiguration"
      ],
      correctAnswer: 1,
      explanation: "Broken Access Control is #1 in OWASP Top 10 2021, representing access control failures that allow users to access unauthorized resources.",
      difficulty: "easy",
      category: "fundamentals",
      technicalTerms: ["OWASP Top 10", "Broken Access Control"]
    }
  ]
};

// Code exercises preserving technical terminology
export const learnExercises: Record<string, CodeExercise[]> = {
  "secure-coding-principles": [
    {
      id: "secure-input-validation",
      title: "Secure Input Validation",
      description: "Implement a function that validates user input securely.",
      difficulty: "medium",
      language: "python",
      startingCode: `def validate_input(user_input):
    # Seu código aqui
    pass`,
      solution: `def validate_input(user_input):
    import re
    pattern = r'^[a-zA-Z0-9_-]+$'
    return bool(re.match(pattern, user_input))`,
      testCases: [
        {
          input: "valid_input",
          expectedOutput: "True",
          description: "Input válido"
        }
      ],
      hints: ["Use regex for validation"],
      technicalConcepts: ["Input Validation"],
      securityFocus: "Prevention of injection attacks"
    }
  ]
};

// Interactive section types
export type InteractiveSectionType = 'quiz' | 'exercise' | 'theory' | 'practical';

export interface InteractiveSection {
  id: string;
  title: string;
  type: InteractiveSectionType;
  quiz?: QuizQuestion[];
  exercise?: CodeExercise;
  content?: {
    theory?: string;
    keyPoints?: string[];
  };
}

export const interactiveLessons: Record<string, InteractiveSection[]> = {
  "owasp-top10": [
    {
      id: "owasp-quiz",
      title: "OWASP Top 10 Knowledge Check",
      type: "quiz",
      quiz: learnQuizzes["owasp-top10"]
    }
  ]
};