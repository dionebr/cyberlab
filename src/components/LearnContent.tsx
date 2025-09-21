import React from 'react';
import { 
  Star, 
  Trophy, 
  ChevronRight, 
  Play, 
  CheckCircle,
  Lock,
  Book,
  Code,
  Terminal,
  Target,
  FileText,
  Video,
  Brain,
  Sparkles,
  Zap,
  Award,
  Clock
} from 'lucide-react';
import { Card, CardHeader, CardContent } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { useToast } from '@/hooks/use-toast';
import { Badge } from '@/components/ui/badge';
import { Progress } from '@/components/ui/progress';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { useLearnMode } from '@/hooks/useLearnMode';
import { TerminalSandbox } from '@/components/TerminalSandbox';
import { CodeEditor } from '@/components/CodeEditor';
import { InteractiveQuiz } from '@/components/InteractiveQuiz';

export const LearnContent: React.FC = () => {
  const {
    currentLesson,
    currentSection,
    lessons,
    stats,
    progress,
    startLesson,
    goToSection,
    completeSection,
    getLessonProgress,
    currentLessonData,
    currentSectionData,
    availableBadges,
  } = useLearnMode();

  const { toast } = useToast();  const renderRoadmap = () => (
    <div className="space-y-6 p-4">
      <div className="text-center mb-8">
        <h2 className="text-2xl font-bold mb-2">Roadmap de Aprendizagem</h2>
        <p className="text-muted-foreground">Trilha estruturada para dominar cybersecurity</p>
        <div className="flex justify-center gap-6 mt-4">
          <div className="flex items-center gap-2 px-4 py-2 bg-green-50 rounded-lg border border-green-200">
            <div className="w-8 h-8 bg-green-500 rounded-full flex items-center justify-center">
              <span className="text-white text-sm font-bold">✓</span>
            </div>
            <div className="text-center">
              <div className="text-xl font-bold text-green-600">{stats.completedLessons.length}</div>
                            <div className="text-xs text-green-600 font-medium">Completed</div>
            </div>
          </div>
          <div className="flex items-center gap-2 px-4 py-2 bg-blue-50 rounded-lg border border-blue-200">
            <div className="w-8 h-8 bg-blue-500 rounded-full flex items-center justify-center">
              <span className="text-white text-sm font-bold">{lessons.length - stats.completedLessons.length}</span>
            </div>
            <div className="text-center">
              <div className="text-xl font-bold text-blue-600">{lessons.length - stats.completedLessons.length}</div>
              <div className="text-xs text-blue-600 font-medium">Restantes</div>
            </div>
          </div>
          <div className="flex items-center gap-2 px-4 py-2 bg-purple-50 rounded-lg border border-purple-200">
            <div className="w-8 h-8 bg-purple-500 rounded-full flex items-center justify-center">
              <span className="text-white text-sm font-bold">★</span>
            </div>
            <div className="text-center">
              <div className="text-xl font-bold text-purple-600">{stats.totalPoints}</div>
              <div className="text-xs text-purple-600 font-medium">Pontos</div>
            </div>
          </div>
        </div>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4 2xl:grid-cols-5 gap-4 max-w-7xl mx-auto">
        {lessons.map((lesson, index) => {
          const isCompleted = stats.completedLessons.includes(lesson.id);
          const isLocked = lesson.prerequisites.some(req => !stats.completedLessons.includes(req));
          const isAvailable = !isLocked;

          return (
            <Card 
              key={lesson.id} 
              className={`transition-all duration-200 hover:scale-105 max-w-sm w-full ${
                isCompleted ? 'border-green-500 bg-green-50 dark:bg-green-950 dark:border-green-600 shadow-md' : 
                isAvailable ? 'hover:shadow-lg border-blue-200 dark:border-blue-700 cursor-pointer bg-white dark:bg-slate-800' : 'opacity-60 bg-gray-50 dark:bg-gray-900 border-gray-200 dark:border-gray-700'
              }`}
              onClick={() => {
                if (isAvailable) {
                  startLesson(lesson.id);
                  toast({
                    title: "📚 Lesson started!",
                    description: "Go to the 'Current Lesson' tab to start studying.",
                    duration: 5000,
                  });
                }
              }}
            >
              <CardHeader className="pb-3">
                <div className="flex items-center justify-between mb-2">
                  <div className={`p-2 rounded-full ${
                    isCompleted ? 'bg-green-500 text-white' : 
                    isAvailable ? 'bg-blue-500 text-white' : 'bg-gray-300 text-gray-500'
                  }`}>
                    {isCompleted ? <CheckCircle className="w-4 h-4" /> :
                     isLocked ? <Lock className="w-4 h-4" /> :
                     <Target className="w-4 h-4" />}
                  </div>
                  <Badge 
                    variant={
                      lesson.difficulty === 'beginner' ? 'default' : 
                      lesson.difficulty === 'intermediate' ? 'secondary' : 'destructive'
                    }
                    className="text-xs"
                  >
                    {lesson.difficulty === 'beginner' ? '🟢 Básico' : 
                     lesson.difficulty === 'intermediate' ? '🟡 Médio' : '🔴 Avançado'}
                  </Badge>
                </div>
                <h3 className="font-semibold text-sm leading-tight">{lesson.title}</h3>
                <div className="flex items-center gap-3 text-xs text-muted-foreground mt-2">
                  <span className="flex items-center gap-1">
                    <Clock className="w-3 h-3" />
                    {lesson.estimatedTime}min
                  </span>
                  <span className="flex items-center gap-1">
                    <Star className="w-3 h-3" />
                    {lesson.points}
                  </span>
                </div>
              </CardHeader>
              
              <CardContent className="pt-0">
                <p className="text-xs text-muted-foreground mb-3 line-clamp-2">{lesson.description}</p>
                
                {/* Progress for completed lessons */}
                {isCompleted && (
                  <div className="mb-3">
                    <div className="flex items-center justify-between text-xs mb-1">
                                            <span className="text-green-600 font-medium">Completed</span>
                      <span className="text-green-600">100%</span>
                    </div>
                    <Progress value={100} className="h-1 bg-green-100" />
                  </div>
                )}
                
                {/* Action buttons */}
                <div className="flex gap-2">
                  {isAvailable && !isCompleted && (
                    <Button 
                      size="sm" 
                      onClick={(e) => {
                        e.stopPropagation();
                        startLesson(lesson.id);
                        toast({
                          title: "📚 Lesson started!",
                          description: "Go to the 'Current Lesson' tab to start studying.",
                          duration: 5000,
                        });
                      }}
                      className="flex-1 gap-1 text-xs h-8"
                    >
                      <Play className="w-3 h-3" />
                      Iniciar
                    </Button>
                  )}
                  {isCompleted && (
                    <Button 
                      size="sm" 
                      variant="secondary"
                      onClick={(e) => {
                        e.stopPropagation();
                        startLesson(lesson.id);
                      }}
                      className="flex-1 gap-1 text-xs h-8"
                    >
                      <CheckCircle className="w-3 h-3" />
                      Revisar
                    </Button>
                  )}
                  {isLocked && (
                    <div className="flex-1 text-center">
                      <Badge variant="outline" className="text-xs">
                        <Lock className="w-3 h-3 mr-1" />
                        Bloqueado
                      </Badge>
                    </div>
                  )}
                </div>

                {/* Prerequisites indicator */}
                {lesson.prerequisites.length > 0 && (
                  <div className="mt-3 pt-2 border-t border-gray-100">
                    <div className="text-xs text-muted-foreground">
                      Requires: {lesson.prerequisites.length} lesson{lesson.prerequisites.length > 1 ? 's' : ''}
                    </div>
                  </div>
                )}
              </CardContent>
            </Card>
          );
        })}
      </div>
    </div>
  );

  const renderStats = () => (
    <div className="space-y-6 max-w-4xl mx-auto p-4">
      <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
        <Card className="border-2 border-yellow-200 dark:border-yellow-700 bg-gradient-to-br from-yellow-50 to-amber-50 dark:from-yellow-950 dark:to-amber-950">
          <CardHeader className="pb-3">
            <div className="flex items-center gap-3">
              <div className="text-4xl">🏆</div>
              <div>
                <h3 className="font-bold text-lg dark:text-yellow-100">Total Points</h3>
                <div className="text-2xl font-bold text-yellow-600 dark:text-yellow-300">{stats.totalPoints}</div>
              </div>
            </div>
          </CardHeader>
          <CardContent>
            <p className="text-sm text-yellow-700 dark:text-yellow-200">✨ Total earned in lessons</p>
          </CardContent>
        </Card>

        <Card className="border-2 border-green-200 dark:border-green-700 bg-gradient-to-br from-green-50 to-emerald-50 dark:from-green-950 dark:to-emerald-950">
          <CardHeader className="pb-3">
            <div className="flex items-center gap-3">
              <div className="text-4xl">📈</div>
              <div>
                <h3 className="font-bold text-lg dark:text-green-100">Progress</h3>
                <div className="text-2xl font-bold text-green-600 dark:text-green-300">
                  {stats.completedLessons.length}/{lessons.length}
                </div>
              </div>
            </div>
          </CardHeader>
          <CardContent>
            <p className="text-sm text-green-700 dark:text-green-200">🎯 Completed lessons</p>
            <Progress 
              value={(stats.completedLessons.length / lessons.length) * 100} 
              className="mt-2 h-2 bg-green-100 dark:bg-green-800"
            />
          </CardContent>
        </Card>

        <Card className="border-2 border-purple-200 dark:border-purple-700 bg-gradient-to-br from-purple-50 to-violet-50 dark:from-purple-950 dark:to-violet-950">
          <CardHeader className="pb-3">
            <div className="flex items-center gap-3">
              <div className="text-4xl">🏅</div>
              <div>
                <h3 className="font-bold text-lg dark:text-purple-100">Achievements</h3>
                <div className="text-2xl font-bold text-purple-600 dark:text-purple-300">{stats.earnedBadges.length}</div>
              </div>
            </div>
          </CardHeader>
          <CardContent>
            <p className="text-sm text-purple-700 dark:text-purple-200">💎 Earned badges</p>
          </CardContent>
        </Card>
      </div>

      <Card>
        <CardHeader>
          <h3 className="font-semibold">Earned Badges</h3>
        </CardHeader>
        <CardContent>
          <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
            {availableBadges.map((badge) => {
              const isEarned = stats.earnedBadges.includes(badge.id);
              return (
                <div 
                  key={badge.id}
                  className={`p-3 rounded-lg text-center transition-all ${
                    isEarned ? 'bg-yellow-50 border border-yellow-200' : 'bg-gray-50 opacity-50'
                  }`}
                >
                  <div className="text-2xl mb-1">{badge.icon}</div>
                  <div className="text-xs font-medium">{badge.name}</div>
                </div>
              );
            })}
          </div>
        </CardContent>
      </Card>
    </div>
  );

  const renderLesson = () => {
    if (!currentLessonData) {
      return (
        <div className="flex items-center justify-center min-h-[400px]">
          <div className="text-center p-8 rounded-lg border-2 border-dashed border-gray-300 dark:border-gray-700">
            <div className="text-6xl mb-4">📚</div>
            <h3 className="text-xl font-semibold mb-2">No lesson selected</h3>
            <p className="text-muted-foreground mb-4">Choose a lesson from the roadmap to start your studies</p>
            <Button variant="outline" onClick={() => window.location.hash = '#roadmap'}>
              <Target className="w-4 h-4 mr-2" />
              View Roadmap
            </Button>
          </div>
        </div>
      );
    }

    return (
      <div className="max-w-4xl mx-auto p-4">
        {/* Book-style header */}
        <div className="bg-gradient-to-r from-amber-50 to-yellow-50 dark:from-amber-950 dark:to-yellow-950 rounded-t-lg border border-amber-200 dark:border-amber-800 p-6 shadow-lg">
          <div className="flex items-center justify-between mb-4">
            <div className="flex items-center gap-3">
              <div className="text-3xl">📖</div>
              <div>
                <h1 className="text-2xl font-bold text-amber-900 dark:text-amber-100">{currentLessonData.title}</h1>
                <p className="text-amber-700 dark:text-amber-300">{currentLessonData.description}</p>
              </div>
            </div>
            <div className="flex flex-col items-end gap-2">
              <Badge 
                variant="secondary" 
                className="bg-amber-200 text-amber-800 dark:bg-amber-800 dark:text-amber-200"
              >
                {currentLessonData.difficulty === 'beginner' ? '🟢 Basic' : 
                 currentLessonData.difficulty === 'intermediate' ? '🟡 Intermediate' : '🔴 Advanced'}
              </Badge>
              <div className="text-sm text-amber-600 dark:text-amber-400">
                ⏱️ {currentLessonData.estimatedTime} min • ⭐ {currentLessonData.points} pts
              </div>
            </div>
          </div>
          
          <Progress 
            value={getLessonProgress(currentLessonData.id)} 
            className="h-2 bg-amber-100 dark:bg-amber-900"
          />
        </div>

        {/* Book pages */}
        <div className="bg-white dark:bg-gray-900 border-l border-r border-amber-200 dark:border-amber-800 shadow-lg">
          {currentLessonData.sections.map((section, index) => (
            <div key={section.id} className="border-b border-gray-100 dark:border-gray-800 last:border-b-0">
              {/* Page header */}
              <div className="bg-gray-50 dark:bg-gray-800 px-6 py-4 border-b border-gray-200 dark:border-gray-700">
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-3">
                    <div className="flex items-center justify-center w-8 h-8 rounded-full bg-blue-100 dark:bg-blue-900 text-blue-600 dark:text-blue-400 font-semibold text-sm">
                      {index + 1}
                    </div>
                    <div className="flex items-center gap-2">
                      {section.type === 'reading' && <div className="text-lg">📄</div>}
                      {section.type === 'video' && <div className="text-lg">🎥</div>}
                      {section.type === 'code' && <div className="text-lg">💻</div>}
                      {section.type === 'terminal' && <div className="text-lg">⌨️</div>}
                      {section.type === 'quiz' && <div className="text-lg">🧠</div>}
                      <h3 className="font-semibold text-lg">{section.title}</h3>
                    </div>
                  </div>
                  <Badge variant="outline" className="text-xs">
                    📍 {section.estimatedTime} min
                  </Badge>
                </div>
              </div>
              
              {/* Page content */}
              <div className="p-6 space-y-6">
                {/* Rich content based on type */}
                {section.type === 'reading' && (
                  <div className="prose prose-lg max-w-none dark:prose-invert">
                    <div dangerouslySetInnerHTML={{ 
                      __html: getEnrichedContent(section.id, typeof section.content === 'string' ? section.content : '') 
                    }} />
                  </div>
                )}
                
                {section.type === 'terminal' && section.content && (
                  <div className="space-y-4">
                    <div className="prose max-w-none dark:prose-invert">
                      <p className="text-gray-600 dark:text-gray-400 mb-4">
                        In this practical section, you will execute real commands to explore vulnerabilities. 
                        Use the terminal below to follow the examples.
                      </p>
                    </div>
                    <div className="border rounded-lg bg-gray-50 dark:bg-gray-800">
                      <TerminalSandbox
                        title={`🖥️ Practical Terminal: ${section.title}`}
                        initialCommands={getTerminalCommands(section.id)}
                        hints={getTerminalHints(section.id)}
                        environment="linux"
                        onCommandExecuted={(cmd, output) => {
                          console.log(`Command executed: ${cmd}`);
                        }}
                      />
                    </div>
                  </div>
                )}

                {section.type === 'code' && section.content && (
                  <div className="space-y-4">
                    <div className="prose max-w-none dark:prose-invert">
                      <p className="text-gray-600 dark:text-gray-400 mb-4">
                        Analyze the code below and complete the practical exercises. 
                        Identify vulnerabilities and implement fixes.
                      </p>
                    </div>
                    <div className="border rounded-lg bg-gray-50 dark:bg-gray-800">
                      <CodeEditor
                        title={`⚡ Code Editor: ${section.title}`}
                        language={getCodeLanguage(section.id)}
                        initialCode={getInitialCode(section.id)}
                        hints={getCodeHints(section.id)}
                        onCodeExecuted={(code, output, success) => {
                          if (success) {
                            console.log(`Code executed successfully`);
                          }
                        }}
                      />
                    </div>
                  </div>
                )}

                {section.type === 'quiz' && (
                  <div className="space-y-4">
                    <div className="prose max-w-none dark:prose-invert">
                      <p className="text-gray-600 dark:text-gray-400 mb-4">
                        Test your knowledge with this interactive quiz. 
                        You need to score at least 70% to proceed.
                      </p>
                    </div>
                    <div className="border rounded-lg bg-gray-50 dark:bg-gray-800 p-4">
                      <InteractiveQuiz
                        title={`🧠 Quiz: ${section.title}`}
                        questions={getQuizQuestions(section.id)}
                        timeLimit={300}
                        onQuizComplete={(score, answers, passed) => {
                          if (passed) {
                            completeSection(currentLessonData.id, section.id);
                          }
                        }}
                      />
                    </div>
                  </div>
                )}
                
                {/* Section completion */}
                <div className="flex justify-between items-center pt-4 border-t border-gray-200 dark:border-gray-700">
                  <div className="text-sm text-gray-500 dark:text-gray-400">
                    {section.type === 'terminal' && '⌨️ Complete os comandos práticos'}
                    {section.type === 'code' && '💻 Execute o código com sucesso'}
                    {section.type === 'quiz' && '🧠 Acerte pelo menos 70% do quiz'}
                    {section.type === 'reading' && '📖 Read all content'}
                    {section.type === 'video' && '🎥 Assista ao vídeo completo'}
                  </div>
                  
                  <Button 
                    onClick={() => completeSection(currentLessonData.id, section.id)}
                    className="gap-2"
                    variant={progress.some(p => p.lessonId === currentLessonData.id && p.sectionId === section.id && p.completed) ? 'secondary' : 'default'}
                  >
                    {progress.some(p => p.lessonId === currentLessonData.id && p.sectionId === section.id && p.completed) ? (
                      <>
                        <CheckCircle className="w-4 h-4" />
                        ✅ Completed
                      </>
                    ) : (
                      <>
                        <Play className="w-4 h-4" />
                        Mark as Completed
                      </>
                    )}
                  </Button>
                </div>
              </div>
            </div>
          ))}
        </div>

        {/* Book footer */}
        <div className="bg-gradient-to-r from-amber-50 to-yellow-50 dark:from-amber-950 dark:to-yellow-950 rounded-b-lg border border-amber-200 dark:border-amber-800 p-4 shadow-lg">
          <div className="flex justify-center">
            <div className="text-sm text-amber-600 dark:text-amber-400">
              📚 Page {currentLessonData.sections.length} of {currentLessonData.sections.length} • 
              {currentLessonData.title}
            </div>
          </div>
        </div>
      </div>
    );
  };

  // Helper functions for practical content
  const getEnrichedContent = (sectionId: string, originalContent: any): string => {
    // Enhanced content based on section ID
    const enrichedContent: Record<string, string> = {
      'web-basics': `
        <div class="lesson-content">
          <h1 class="text-2xl font-bold mb-4 text-blue-600 dark:text-blue-400">🔒 Web Security - Fundamentals</h1>
          
          <p class="text-base mb-4 leading-relaxed">Web security is a critical field that protects applications and data from digital threats. In this module, you'll learn essential concepts.</p>
          
          <h2 class="text-xl font-semibold mb-3 text-gray-800 dark:text-gray-200">📋 What you'll learn:</h2>
          <ul class="list-disc pl-6 mb-4 space-y-2">
            <li><strong>Types of vulnerabilities</strong> most common</li>
            <li><strong>Security testing methodologies</strong></li>
            <li><strong>Essential tools</strong> for pentesting</li>
            <li><strong>Best practices</strong> for secure development</li>
          </ul>
          
          <h2 class="text-xl font-semibold mb-3 text-gray-800 dark:text-gray-200">⚠️ Main web threats:</h2>
          <div class="bg-blue-50 dark:bg-blue-950 border-l-4 border-blue-500 p-4 mb-4 rounded">
            <h3 class="text-lg font-semibold mb-2 text-blue-800 dark:text-blue-200">🎯 OWASP Top 10</h3>
            <p class="text-blue-700 dark:text-blue-300">OWASP (Open Web Application Security Project) maintains a list of the 10 most critical vulnerabilities in web applications.</p>
          </div>
          
          <p class="text-base bg-yellow-50 dark:bg-yellow-950 border border-yellow-200 dark:border-yellow-700 p-3 rounded">💡 <strong>Important tip:</strong> Always test in controlled environments and with authorization!</p>
        </div>
      `,
      'owasp-intro': `
        <div class="lesson-content">
          <h1 class="text-2xl font-bold mb-4 text-purple-600 dark:text-purple-400">🏆 OWASP Top 10 - Complete Guide</h1>
          
          <p class="text-base mb-4 leading-relaxed">The OWASP Top 10 is the reference standard for web application security, used worldwide by developers and security professionals.</p>
          
          <h2 class="text-xl font-semibold mb-3 text-gray-800 dark:text-gray-200">📊 Top 10 Vulnerabilities (2021):</h2>
          <ol class="list-decimal pl-6 mb-4 space-y-2">
            <li><strong>A01 - Broken Access Control</strong> - Access control failures</li>
            <li><strong>A02 - Cryptographic Failures</strong> - Cryptographic failures</li>
            <li><strong>A03 - Injection</strong> - Injection attacks</li>
            <li><strong>A04 - Insecure Design</strong> - Insecure design</li>
            <li><strong>A05 - Security Misconfiguration</strong> - Security misconfiguration</li>
            <li><strong>A06 - Vulnerable Components</strong> - Vulnerable components</li>
            <li><strong>A07 - Identification & Auth Failures</strong> - Authentication failures</li>
            <li><strong>A08 - Software & Data Integrity</strong> - Integrity failures</li>
            <li><strong>A09 - Security Logging & Monitoring</strong> - Monitoring failures</li>
            <li><strong>A10 - Server-Side Request Forgery</strong> - SSRF</li>
          </ol>
          
          <div class="bg-green-50 dark:bg-green-950 border border-green-200 dark:border-green-700 p-4 rounded">
            <h3 class="text-lg font-semibold mb-2 text-green-800 dark:text-green-200">✅ Why is it important?</h3>
            <ul class="list-disc pl-4 space-y-1">
              <li>Based on real vulnerability data</li>
              <li>Regularly updated by the community</li>
              <li>Reference for compliance and audits</li>
              <li>Guide for developer training</li>
            </ul>
          </div>
        </div>
      `,
      'sql-theory': `
        <div class="lesson-content">
          <h1 class="text-2xl font-bold mb-4 text-red-600 dark:text-red-400">💉 SQL Injection - Fundamental Concepts</h1>
          
          <p class="text-base mb-4 leading-relaxed">SQL Injection is one of the most dangerous and common vulnerabilities in web applications. It allows attackers to execute malicious SQL commands.</p>
          
          <h2 class="text-xl font-semibold mb-3 text-gray-800 dark:text-gray-200">🎯 How does it work?</h2>
          <p class="text-base mb-3">The attack happens when user data is inserted directly into SQL queries without proper validation:</p>
          
          <div class="bg-yellow-50 dark:bg-yellow-950 border-l-4 border-yellow-500 p-4 mb-4 rounded">
            <h3 class="text-lg font-semibold mb-2 text-yellow-800 dark:text-yellow-200">Vulnerable Example:</h3>
            <code class="block bg-gray-100 dark:bg-gray-800 p-3 rounded text-sm font-mono">
              SELECT * FROM users WHERE username = '$username' AND password = '$password'
            </code>
          </div>
          
          <h2 class="text-xl font-semibold mb-3 text-gray-800 dark:text-gray-200">⚡ Types of SQL Injection:</h2>
          <ul class="list-disc pl-6 mb-4 space-y-2">
            <li><strong>Union-based</strong> - Uses UNION to extract data</li>
            <li><strong>Boolean-based</strong> - Based on true/false responses</li>
            <li><strong>Time-based</strong> - Uses delays to infer information</li>
            <li><strong>Error-based</strong> - Exploits error messages</li>
          </ul>
          
          <h2 class="text-xl font-semibold mb-3 text-gray-800 dark:text-gray-200">🛡️ How to prevent:</h2>
          <div class="bg-green-50 dark:bg-green-950 border border-green-200 dark:border-green-700 p-4 rounded">
            <ul class="list-disc pl-4 space-y-2">
              <li><strong>Prepared Statements</strong> - Use placeholders</li>
              <li><strong>Input Validation</strong> - Validate all data</li>
              <li><strong>Principle of Least Privilege</strong> - Limit DB permissions</li>
              <li><strong>WAF</strong> - Web Application Firewall</li>
            </ul>
          </div>
        </div>
      `,
      'xss-basics': `
        <div class="lesson-content">
          <h1 class="text-2xl font-bold mb-4 text-orange-600 dark:text-orange-400">⚡ Cross-Site Scripting (XSS) - Fundamentals</h1>
          
          <p class="text-base mb-4 leading-relaxed">Cross-Site Scripting (XSS) is a vulnerability that allows injection of malicious scripts into trusted web pages, executing code in victims' browsers.</p>
          
          <h2 class="text-xl font-semibold mb-3 text-gray-800 dark:text-gray-200">🎯 How does XSS work?</h2>
          <p class="text-base mb-3">The attacker injects malicious JavaScript code that will be executed in other users' browsers:</p>
          
          <div class="bg-orange-50 dark:bg-orange-950 border-l-4 border-orange-500 p-4 mb-4 rounded">
            <h3 class="text-lg font-semibold mb-2 text-orange-800 dark:text-orange-200">Payload Example:</h3>
            <code class="block bg-gray-100 dark:bg-gray-800 p-3 rounded text-sm font-mono">
              &lt;script&gt;alert('XSS Vulnerability!');&lt;/script&gt;
            </code>
          </div>
          
          <h2 class="text-xl font-semibold mb-3 text-gray-800 dark:text-gray-200">🔍 Types of XSS:</h2>
          <ul class="list-disc pl-6 mb-4 space-y-2">
            <li><strong>Reflected XSS</strong> - Payload immediately reflected in response</li>
            <li><strong>Stored XSS</strong> - Payload stored on server (most dangerous)</li>
            <li><strong>DOM-based XSS</strong> - Client-side exploitation via DOM</li>
          </ul>
          
          <h2 class="text-xl font-semibold mb-3 text-gray-800 dark:text-gray-200">🛡️ How to prevent:</h2>
          <div class="bg-green-50 dark:bg-green-950 border border-green-200 dark:border-green-700 p-4 rounded">
            <ul class="list-disc pl-4 space-y-2">
              <li><strong>Input Validation</strong> - Validate all input data</li>
              <li><strong>Output Encoding</strong> - Escape data before rendering</li>
              <li><strong>Content Security Policy (CSP)</strong> - Control loaded resources</li>
              <li><strong>HttpOnly Cookies</strong> - Protect cookies from JavaScript access</li>
            </ul>
          </div>
        </div>
      `,
      'crypto-basics': `
        <div class="lesson-content">
          <h1 class="text-2xl font-bold mb-4 text-indigo-600 dark:text-indigo-400">🔐 Cryptography - Fundamental Concepts</h1>
          
          <p class="text-base mb-4 leading-relaxed">Cryptography is the science of protecting information by transforming readable data into unreadable formats for unauthorized people.</p>
          
          <h2 class="text-xl font-semibold mb-3 text-gray-800 dark:text-gray-200">🔑 Types of Cryptography:</h2>
          <div class="grid grid-cols-1 md:grid-cols-2 gap-4 mb-4">
            <div class="bg-blue-50 dark:bg-blue-950 border border-blue-200 dark:border-blue-700 p-4 rounded">
              <h3 class="text-lg font-semibold mb-2 text-blue-800 dark:text-blue-200">Symmetric</h3>
              <ul class="text-sm space-y-1">
                <li>• Single key for encryption and decryption</li>
                <li>• Faster for large volumes of data</li>
                <li>• Examples: AES, DES, 3DES</li>
              </ul>
            </div>
            <div class="bg-purple-50 dark:bg-purple-950 border border-purple-200 dark:border-purple-700 p-4 rounded">
              <h3 class="text-lg font-semibold mb-2 text-purple-800 dark:text-purple-200">Asymmetric</h3>
              <ul class="text-sm space-y-1">
                <li>• Key pair: public and private</li>
                <li>• More secure for key exchange</li>
                <li>• Examples: RSA, ECC, DSA</li>
              </ul>
            </div>
          </div>
          
          <h2 class="text-xl font-semibold mb-3 text-gray-800 dark:text-gray-200">🔨 Hash Functions:</h2>
          <p class="text-base mb-3">Transform data of any size into a fixed-size string:</p>
          
          <div class="bg-yellow-50 dark:bg-yellow-950 border-l-4 border-yellow-500 p-4 mb-4 rounded">
            <h3 class="text-lg font-semibold mb-2 text-yellow-800 dark:text-yellow-200">Important characteristics:</h3>
            <ul class="text-sm space-y-1">
              <li>✅ <strong>Deterministic</strong> - Same input, same hash</li>
              <li>✅ <strong>One-way</strong> - Impossible to reverse</li>
              <li>✅ <strong>Collision resistant</strong> - Hard to find two inputs with same hash</li>
              <li>⚠️ <strong>Avoid MD5 and SHA-1</strong> - Use SHA-256 or higher</li>
            </ul>
          </div>
          
          <h2 class="text-xl font-semibold mb-3 text-gray-800 dark:text-gray-200">💡 Practical Applications:</h2>
          <div class="grid grid-cols-1 md:grid-cols-3 gap-3">
            <div class="bg-green-50 dark:bg-green-950 p-3 rounded text-center">
              <div class="text-2xl mb-2">🔒</div>
              <div class="text-sm font-medium">Passwords</div>
            </div>
            <div class="bg-blue-50 dark:bg-blue-950 p-3 rounded text-center">
              <div class="text-2xl mb-2">📡</div>
              <div class="text-sm font-medium">HTTPS/TLS</div>
            </div>
            <div class="bg-purple-50 dark:bg-purple-950 p-3 rounded text-center">
              <div class="text-2xl mb-2">✍️</div>
              <div class="text-sm font-medium">Digital Signatures</div>
            </div>
          </div>
        </div>
      `
    };
    
    return enrichedContent[sectionId] || `
      <div class="lesson-content">
        <p class="text-base leading-relaxed">${originalContent || 'Lesson content will be loaded here.'}</p>
      </div>
    `;
  };

  const getQuizQuestions = (sectionId: string) => {
    const quizzes: Record<string, any[]> = {
      'sql-quiz': [
        {
          id: 1,
          question: "What is SQL Injection?",
          options: [
            "A data encryption method",
            "A vulnerability that allows executing malicious SQL commands",
            "A type of database firewall",
            "A data backup technique"
          ],
          correctAnswer: 1,
          explanation: "SQL Injection is a vulnerability that occurs when untrusted data is inserted into SQL queries, allowing attackers to execute malicious commands.",
          difficulty: "medium",
          points: 10
        },
        {
          id: 2,
          question: "What is the best way to prevent SQL Injection?",
          options: [
            "Using string concatenation",
            "Using prepared statements",
            "Encrypting the database",
            "Using complex passwords"
          ],
          correctAnswer: 1,
          explanation: "Prepared statements are the most effective way to prevent SQL Injection because they separate SQL code from data.",
          difficulty: "medium",
          points: 15
        },
        {
          id: 3,
          question: "What basic payload is used to test SQL Injection?",
          options: [
            "SELECT * FROM users",
            "' OR '1'='1",
            "DROP TABLE users",
            "UPDATE users SET password='123'"
          ],
          correctAnswer: 1,
          explanation: "' OR '1'='1 is a basic payload that always returns true, allowing authentication bypass.",
          difficulty: "easy",
          points: 10
        },
        {
          id: 4,
          question: "In which type of SQL Injection is data extracted using UNION?",
          options: [
            "Blind SQL Injection",
            "Error-based SQL Injection",
            "Union-based SQL Injection",
            "Time-based SQL Injection"
          ],
          correctAnswer: 2,
          explanation: "Union-based SQL Injection uses the UNION command to combine results from different queries and extract data.",
          difficulty: "medium",
          points: 12
        },
        {
          id: 5,
          question: "Which SQL command is most dangerous in a SQL Injection attack?",
          options: [
            "SELECT",
            "INSERT",
            "DROP",
            "UPDATE"
          ],
          correctAnswer: 2,
          explanation: "DROP is extremely dangerous because it can delete entire tables or even the complete database.",
          difficulty: "hard",
          points: 20
        }
      ],
      'web-quiz': [
        {
          id: 1,
          question: "What does OWASP stand for?",
          options: [
            "Open Web Application Security Project",
            "Online Web Application Security Protocol",
            "Open World Application Security Program",
            "Organized Web Application Security Project"
          ],
          correctAnswer: 0,
          explanation: "OWASP stands for Open Web Application Security Project, a community that develops security standards for web applications.",
          difficulty: "easy",
          points: 10
        },
        {
          id: 2,
          question: "What is the #1 vulnerability in OWASP Top 10 2021?",
          options: [
            "SQL Injection",
            "Cross-Site Scripting (XSS)",
            "Broken Access Control",
            "Security Misconfiguration"
          ],
          correctAnswer: 2,
          explanation: "Broken Access Control is the #1 vulnerability in OWASP Top 10 2021, representing access control failures.",
          difficulty: "medium",
          points: 15
        },
        {
          id: 3,
          question: "Why is it important to test security in web applications?",
          options: [
            "To increase website speed",
            "To improve visual design",
            "To protect sensitive data and prevent attacks",
            "To reduce hosting costs"
          ],
          correctAnswer: 2,
          explanation: "Security testing is essential to protect sensitive data, maintain user trust, and prevent malicious attacks.",
          difficulty: "easy",
          points: 10
        },
        {
          id: 4,
          question: "Which protocol should always be used in web applications for encryption?",
          options: [
            "HTTP",
            "FTP",
            "HTTPS",
            "SMTP"
          ],
          correctAnswer: 2,
          explanation: "HTTPS (HTTP Secure) uses SSL/TLS encryption to protect data in transit between client and server.",
          difficulty: "easy",
          points: 8
        },
        {
          id: 5,
          question: "What is a Web Application Firewall (WAF)?",
          options: [
            "A traditional network firewall",
            "A tool that protects web applications by filtering HTTP traffic",
            "An antivirus for web servers",
            "An encryption technique"
          ],
          correctAnswer: 1,
          explanation: "WAF is a security solution that filters, monitors, and blocks malicious HTTP traffic to web applications.",
          difficulty: "medium",
          points: 12
        }
      ],
      'xss-quiz': [
        {
          id: 1,
          question: "What does XSS stand for?",
          options: [
            "XML Server Security",
            "Cross-Site Scripting",
            "eXtended Security System",
            "Cross-Server Synchronization"
          ],
          correctAnswer: 1,
          explanation: "XSS stands for Cross-Site Scripting, a vulnerability that allows injection of malicious scripts into web pages.",
          difficulty: "easy",
          points: 10
        },
        {
          id: 2,
          question: "Which type of XSS is most dangerous?",
          options: [
            "Reflected XSS",
            "Stored XSS",
            "DOM-based XSS",
            "All are equally dangerous"
          ],
          correctAnswer: 1,
          explanation: "Stored XSS is most dangerous because the payload is stored on the server and affects all users who visit the page.",
          difficulty: "medium",
          points: 15
        },
        {
          id: 3,
          question: "How to prevent XSS in web applications?",
          options: [
            "Use only HTTPS",
            "Validate and sanitize user inputs",
            "Encrypt the database",
            "Use strong passwords"
          ],
          correctAnswer: 1,
          explanation: "XSS prevention requires rigorous validation and sanitization of all user inputs, plus output encoding.",
          difficulty: "medium",
          points: 12
        },
        {
          id: 4,
          question: "Which HTML tag is most commonly used in XSS attacks?",
          options: [
            "<div>",
            "<script>",
            "<img>",
            "<p>"
          ],
          correctAnswer: 1,
          explanation: "The <script> tag is most common in XSS as it allows executing JavaScript directly on the page.",
          difficulty: "easy",
          points: 8
        }
      ],
      'crypto-quiz': [
        {
          id: 1,
          question: "Which hash algorithm should NOT be used for passwords?",
          options: [
            "bcrypt",
            "MD5",
            "PBKDF2",
            "Argon2"
          ],
          correctAnswer: 1,
          explanation: "MD5 is considered broken and vulnerable to collision attacks. For passwords, use bcrypt, PBKDF2, or Argon2.",
          difficulty: "easy",
          points: 10
        },
        {
          id: 2,
          question: "What is a Salt in password cryptography?",
          options: [
            "A compression technique",
            "A random value added to the password before hashing",
            "A type of encryption algorithm",
            "An input validation method"
          ],
          correctAnswer: 1,
          explanation: "Salt is a unique random value added to the password before hashing, preventing rainbow table attacks.",
          difficulty: "medium",
          points: 15
        },
        {
          id: 3,
          question: "What is the difference between symmetric and asymmetric cryptography?",
          options: [
            "Symmetric uses one key, asymmetric uses two keys",
            "Symmetric is faster, asymmetric is slower",
            "Symmetric is for data, asymmetric is for communication",
            "All of the above"
          ],
          correctAnswer: 3,
          explanation: "All alternatives are correct: symmetric uses one key vs two in asymmetric, symmetric is faster, and each has specific uses.",
          difficulty: "hard",
          points: 20
        }
      ]
    };
    
    return quizzes[sectionId] || [];
  };

  const getTerminalCommands = (sectionId: string): string[] => {
    const commands: Record<string, string[]> = {
      'sql-injection-practice': ['ls -la', 'cat vulnerable.php', 'sqlmap -u "http://localhost/vulnerable.php?id=1"'],
      'xss-practice': ['curl -X POST "http://localhost/form.php" -d "comment=<script>alert(1)</script>"'],
      'command-injection': ['ping 127.0.0.1; ls', 'nmap -sV localhost'],
    };
    return commands[sectionId] || ['ls', 'pwd', 'whoami'];
  };

  const getTerminalHints = (sectionId: string): string[] => {
    const hints: Record<string, string[]> = {
      'sql-injection-practice': [
        'Use sqlmap to automatically detect SQL injections',
        'Test payloads like \' OR 1=1-- in the parameter',
        'Observe server responses to find vulnerabilities'
      ],
    };
    return hints[sectionId] || ['Explore the system with basic commands'];
  };

  const getCodeLanguage = (sectionId: string): 'javascript' | 'python' | 'php' | 'sql' => {
    if (sectionId.includes('sql')) return 'sql';
    if (sectionId.includes('php')) return 'php';
    if (sectionId.includes('javascript')) return 'javascript';
    return 'python';
  };

  const getInitialCode = (sectionId: string): string => {
    const codeExamples: Record<string, string> = {
      'sql-injection-fix': `// VULNERABLE CODE
const query = "SELECT * FROM users WHERE id = '" + userId + "'";

// TODO: Fix this SQL injection vulnerability
// HINT: Use parameterized queries`,
      
      'xss-prevention': `// VULNERABLE CODE
function displayComment(comment) {
    document.getElementById('comments').innerHTML += '<p>' + comment + '</p>';
}

// TODO: Fix this XSS vulnerability
// HINT: Use textContent or proper escaping`,
    };
    
    return codeExamples[sectionId] || '// Write your code here\nconsole.log("Hello, CyberLab!");';
  };

  const getCodeHints = (sectionId: string): string[] => {
    const hints: Record<string, string[]> = {
      'sql-injection-fix': [
        'Use prepared statements with ? placeholders',
        'Avoid direct string concatenation in SQL',
        'Validate and sanitize all user inputs'
      ],
      'xss-prevention': [
        'Use textContent instead of innerHTML for plain text',
        'Implement Content Security Policy (CSP)',
        'Always escape HTML special characters'
      ],
    };
    return hints[sectionId] || ['Remember security best practices'];
  };  return (
    <div className="w-full h-full flex flex-col">
      <Tabs defaultValue="roadmap" className="w-full h-full flex flex-col">
        <TabsList className="grid w-full grid-cols-3 mb-4">
          <TabsTrigger value="roadmap" className="gap-2">
            <Target className="w-4 h-4" />
            Roadmap
          </TabsTrigger>
          <TabsTrigger value="lesson" className="gap-2">
            <Book className="w-4 h-4" />
            Current Lesson
          </TabsTrigger>
          <TabsTrigger value="stats" className="gap-2">
            <Trophy className="w-4 h-4" />
            Estatísticas
          </TabsTrigger>
        </TabsList>

        <div className="flex-1 overflow-auto">
          <TabsContent value="roadmap" className="mt-0 h-full">
            <div className="h-full overflow-auto">
              {renderRoadmap()}
            </div>
          </TabsContent>

          <TabsContent value="lesson" className="mt-0 h-full">
            <div className="h-full overflow-auto">
              {renderLesson()}
            </div>
          </TabsContent>

          <TabsContent value="stats" className="mt-0 h-full">
            <div className="h-full overflow-auto">
              {renderStats()}
            </div>
          </TabsContent>
        </div>
      </Tabs>
    </div>
  );
};