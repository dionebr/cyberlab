import React, { useState, useEffect } from 'react';
import { 
  Mic, 
  MicOff, 
  Clock, 
  CheckCircle, 
  XCircle, 
  Brain,
  Star,
  Trophy,
  MessageSquare,
  Play,
  Pause,
  RotateCcw,
  FileText,
  Target
} from 'lucide-react';
import { Card, CardContent, CardHeader } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Progress } from '@/components/ui/progress';
import { Alert, AlertDescription } from '@/components/ui/alert';
import { Textarea } from '@/components/ui/textarea';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';

export interface InterviewQuestion {
  id: string;
  category: 'technical' | 'behavioral' | 'scenario' | 'leadership';
  level: 'junior' | 'mid' | 'senior' | 'lead';
  question: string;
  context?: string;
  followUp?: string[];
  keyPoints: string[];
  idealAnswer: string;
  timeLimit: number; // seconds
  difficulty: 'easy' | 'medium' | 'hard';
  tags: string[];
}

export interface InterviewSession {
  id: string;
  questions: InterviewQuestion[];
  currentQuestionIndex: number;
  startTime: Date;
  answers: InterviewAnswer[];
  totalScore: number;
  feedback: string[];
  completed: boolean;
}

export interface InterviewAnswer {
  questionId: string;
  answer: string;
  timeSpent: number;
  score: number; // 0-100
  feedback: string;
  keyPointsCovered: string[];
}

interface InterviewSimulatorProps {
  questions: InterviewQuestion[];
  userLevel: 'junior' | 'mid' | 'senior' | 'lead';
  onSessionComplete: (session: InterviewSession) => void;
  duration?: number; // minutes
}

export const InterviewSimulator: React.FC<InterviewSimulatorProps> = ({
  questions,
  userLevel,
  onSessionComplete,
  duration = 45
}) => {
  const [session, setSession] = useState<InterviewSession | null>(null);
  const [currentAnswer, setCurrentAnswer] = useState('');
  const [timeLeft, setTimeLeft] = useState(0);
  const [isRecording, setIsRecording] = useState(false);
  const [isPaused, setIsPaused] = useState(false);
  const [activeTab, setActiveTab] = useState('interview');
  const [sessionStarted, setSessionStarted] = useState(false);

  // Filter questions by user level
  const levelQuestions = questions.filter(q => 
    q.level === userLevel || 
    (userLevel === 'senior' && ['junior', 'mid'].includes(q.level)) ||
    (userLevel === 'mid' && q.level === 'junior')
  );

  const currentQuestion = session?.questions[session.currentQuestionIndex];

  // Timer effect
  useEffect(() => {
    if (sessionStarted && !isPaused && timeLeft > 0) {
      const timer = setInterval(() => {
        setTimeLeft(prev => {
          if (prev <= 1) {
            handleTimeUp();
            return 0;
          }
          return prev - 1;
        });
      }, 1000);

      return () => clearInterval(timer);
    }
  }, [sessionStarted, isPaused, timeLeft]);

  const startInterview = () => {
    const selectedQuestions = levelQuestions
      .sort(() => Math.random() - 0.5)
      .slice(0, Math.min(8, levelQuestions.length));

    const newSession: InterviewSession = {
      id: Date.now().toString(),
      questions: selectedQuestions,
      currentQuestionIndex: 0,
      startTime: new Date(),
      answers: [],
      totalScore: 0,
      feedback: [],
      completed: false
    };

    setSession(newSession);
    setTimeLeft(selectedQuestions[0]?.timeLimit || 300);
    setSessionStarted(true);
    setActiveTab('interview');
  };

  const handleTimeUp = () => {
    if (currentAnswer.trim()) {
      submitAnswer();
    } else {
      // Auto-submit empty answer if time runs out
      submitAnswer('Tempo esgotado - resposta não fornecida');
    }
  };

  const submitAnswer = (answer: string = currentAnswer) => {
    if (!session || !currentQuestion) return;

    const timeSpent = currentQuestion.timeLimit - timeLeft;
    const score = evaluateAnswer(answer, currentQuestion);
    const feedback = generateFeedback(answer, currentQuestion, score);

    const newAnswer: InterviewAnswer = {
      questionId: currentQuestion.id,
      answer: answer,
      timeSpent,
      score,
      feedback,
      keyPointsCovered: getKeyPointsCovered(answer, currentQuestion.keyPoints)
    };

    const updatedAnswers = [...session.answers, newAnswer];
    const isLastQuestion = session.currentQuestionIndex >= session.questions.length - 1;

    if (isLastQuestion) {
      completeInterview(updatedAnswers);
    } else {
      const nextIndex = session.currentQuestionIndex + 1;
      const nextQuestion = session.questions[nextIndex];
      
      setSession({
        ...session,
        currentQuestionIndex: nextIndex,
        answers: updatedAnswers
      });
      
      setTimeLeft(nextQuestion.timeLimit);
      setCurrentAnswer('');
    }
  };

  const completeInterview = (answers: InterviewAnswer[]) => {
    if (!session) return;

    const totalScore = Math.round(
      answers.reduce((sum, answer) => sum + answer.score, 0) / answers.length
    );

    const completedSession: InterviewSession = {
      ...session,
      answers,
      totalScore,
      feedback: generateOverallFeedback(answers, session.questions),
      completed: true
    };

    setSession(completedSession);
    onSessionComplete(completedSession);
    setSessionStarted(false);
  };

  const evaluateAnswer = (answer: string, question: InterviewQuestion): number => {
    if (!answer.trim()) return 0;

    let score = 30; // Base score for providing an answer
    const answerLower = answer.toLowerCase();
    
    // Check for key points
    const keyPointsFound = question.keyPoints.filter(point =>
      answerLower.includes(point.toLowerCase())
    ).length;
    
    score += (keyPointsFound / question.keyPoints.length) * 50;

    // Length consideration
    const wordCount = answer.split(' ').length;
    if (wordCount >= 50 && wordCount <= 200) {
      score += 10;
    } else if (wordCount < 20) {
      score -= 10;
    }

    // Technical terms bonus for technical questions
    if (question.category === 'technical') {
      const technicalTerms = ['security', 'vulnerability', 'encryption', 'authentication', 'authorization', 'sql injection', 'xss', 'csrf'];
      const termsFound = technicalTerms.filter(term => answerLower.includes(term)).length;
      score += Math.min(termsFound * 5, 20);
    }

    return Math.max(0, Math.min(100, score));
  };

  const generateFeedback = (answer: string, question: InterviewQuestion, score: number): string => {
    const keyPointsCovered = getKeyPointsCovered(answer, question.keyPoints);
    const missingPoints = question.keyPoints.filter(point => 
      !keyPointsCovered.includes(point)
    );

    let feedback = '';

    if (score >= 80) {
      feedback = '🎉 Excelente resposta! ';
    } else if (score >= 60) {
      feedback = '👍 Boa resposta, mas pode melhorar. ';
    } else if (score >= 40) {
      feedback = '🤔 Resposta adequada, mas faltaram pontos importantes. ';
    } else {
      feedback = '📚 Esta resposta precisa de mais desenvolvimento. ';
    }

    if (keyPointsCovered.length > 0) {
      feedback += `Pontos cobertos: ${keyPointsCovered.join(', ')}. `;
    }

    if (missingPoints.length > 0) {
      feedback += `Considere mencionar: ${missingPoints.join(', ')}.`;
    }

    return feedback;
  };

  const getKeyPointsCovered = (answer: string, keyPoints: string[]): string[] => {
    const answerLower = answer.toLowerCase();
    return keyPoints.filter(point => 
      answerLower.includes(point.toLowerCase())
    );
  };

  const generateOverallFeedback = (answers: InterviewAnswer[], questions: InterviewQuestion[]): string[] => {
    const feedback = [];
    const avgScore = answers.reduce((sum, a) => sum + a.score, 0) / answers.length;

    if (avgScore >= 80) {
      feedback.push('🏆 Performance excepcional! Você demonstrou forte conhecimento técnico e habilidades de comunicação.');
    } else if (avgScore >= 60) {
      feedback.push('✅ Boa performance geral. Continue estudando para alcançar a excelência.');
    } else {
      feedback.push('📖 Há espaço para melhorias. Foque nos pontos fracos identificados.');
    }

    // Category analysis
    const categories = ['technical', 'behavioral', 'scenario', 'leadership'];
    categories.forEach(category => {
      const categoryAnswers = answers.filter((_, i) => questions[i].category === category);
      if (categoryAnswers.length > 0) {
        const categoryAvg = categoryAnswers.reduce((sum, a) => sum + a.score, 0) / categoryAnswers.length;
        if (categoryAvg < 50) {
          feedback.push(`⚠️ Área de melhoria: perguntas ${category === 'technical' ? 'técnicas' : category === 'behavioral' ? 'comportamentais' : category === 'scenario' ? 'de cenário' : 'de liderança'}.`);
        }
      }
    });

    return feedback;
  };

  const formatTime = (seconds: number): string => {
    const mins = Math.floor(seconds / 60);
    const secs = seconds % 60;
    return `${mins}:${secs.toString().padStart(2, '0')}`;
  };

  const getScoreColor = (score: number): string => {
    if (score >= 80) return 'text-green-600';
    if (score >= 60) return 'text-blue-600';
    if (score >= 40) return 'text-yellow-600';
    return 'text-red-600';
  };

  if (!sessionStarted && !session?.completed) {
    return (
      <Card className="w-full max-w-4xl mx-auto">
        <CardHeader className="text-center">
          <div className="mb-4">
            <MessageSquare className="w-16 h-16 mx-auto mb-4 text-blue-500" />
            <h2 className="text-2xl font-bold mb-2">Simulador de Entrevista</h2>
            <p className="text-muted-foreground">
              Pratique suas habilidades de entrevista em cybersecurity
            </p>
          </div>
        </CardHeader>
        
        <CardContent className="space-y-6">
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
            <div className="text-center p-4 border rounded-lg">
              <Target className="w-8 h-8 mx-auto mb-2 text-blue-500" />
              <div className="font-semibold">{levelQuestions.length}</div>
              <div className="text-sm text-muted-foreground">Questions</div>
            </div>
            <div className="text-center p-4 border rounded-lg">
              <Clock className="w-8 h-8 mx-auto mb-2 text-green-500" />
              <div className="font-semibold">{duration}min</div>
              <div className="text-sm text-muted-foreground">Duration</div>
            </div>
            <div className="text-center p-4 border rounded-lg">
              <Star className="w-8 h-8 mx-auto mb-2 text-yellow-500" />
              <div className="font-semibold">{userLevel}</div>
              <div className="text-sm text-muted-foreground">Nível</div>
            </div>
            <div className="text-center p-4 border rounded-lg">
              <Brain className="w-8 h-8 mx-auto mb-2 text-purple-500" />
              <div className="font-semibold">AI</div>
              <div className="text-sm text-muted-foreground">Evaluation</div>
            </div>
          </div>

          <Alert>
            <MessageSquare className="h-4 w-4" />
            <AlertDescription>
              <strong>Como funciona:</strong>
              <ul className="mt-2 ml-4 list-disc space-y-1 text-sm">
                <li>Responda 6-8 perguntas típicas de entrevista</li>
                <li>Cada pergunta tem tempo limitado</li>
                <li>Get instant feedback with scoring</li>
                <li>Veja áreas de melhoria personalizadas</li>
              </ul>
            </AlertDescription>
          </Alert>

          <div className="text-center">
            <Button onClick={startInterview} size="lg" className="gap-2">
              <Play className="w-5 h-5" />
              Iniciar Entrevista
            </Button>
          </div>
        </CardContent>
      </Card>
    );
  }

  return (
    <div className="w-full max-w-4xl mx-auto space-y-6">
      <Tabs value={activeTab} onValueChange={setActiveTab} className="w-full">
        <TabsList className="grid w-full grid-cols-2">
          <TabsTrigger value="interview" className="gap-2">
            <MessageSquare className="w-4 h-4" />
            Entrevista
          </TabsTrigger>
          <TabsTrigger value="results" className="gap-2" disabled={!session?.completed}>
            <Trophy className="w-4 h-4" />
            Resultados
          </TabsTrigger>
        </TabsList>

        <TabsContent value="interview" className="space-y-4">
          {session && !session.completed && (
            <>
              {/* Progress and Timer */}
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-4">
                  <Badge variant="outline">
                    Pergunta {session.currentQuestionIndex + 1} de {session.questions.length}
                  </Badge>
                  <Badge variant="secondary">
                    {currentQuestion?.category}
                  </Badge>
                  <Badge variant="outline">
                    {currentQuestion?.level}
                  </Badge>
                </div>
                
                <div className="flex items-center gap-2">
                  <Clock className={`w-4 h-4 ${timeLeft < 30 ? 'text-red-500' : 'text-blue-500'}`} />
                  <span className={`font-mono ${timeLeft < 30 ? 'text-red-500 font-bold' : ''}`}>
                    {formatTime(timeLeft)}
                  </span>
                </div>
              </div>

              <Progress 
                value={((session.currentQuestionIndex) / session.questions.length) * 100}
                className="w-full h-2"
              />

              {/* Question */}
              <Card>
                <CardHeader>
                  <h3 className="text-lg font-semibold">{currentQuestion?.question}</h3>
                  {currentQuestion?.context && (
                    <p className="text-sm text-muted-foreground mt-2">
                      <strong>Contexto:</strong> {currentQuestion.context}
                    </p>
                  )}
                </CardHeader>
                
                <CardContent className="space-y-4">
                  <Textarea
                    value={currentAnswer}
                    onChange={(e) => setCurrentAnswer(e.target.value)}
                    placeholder="Digite sua resposta aqui..."
                    className="min-h-[200px] resize-none"
                    disabled={timeLeft === 0}
                  />
                  
                  <div className="flex items-center justify-between">
                    <div className="text-sm text-muted-foreground">
                      {currentAnswer.split(' ').filter(w => w.length > 0).length} palavras
                    </div>
                    
                    <div className="flex gap-2">
                      <Button
                        variant="outline"
                        size="sm"
                        onClick={() => setIsPaused(!isPaused)}
                      >
                        {isPaused ? <Play className="w-4 h-4" /> : <Pause className="w-4 h-4" />}
                      </Button>
                      
                      <Button 
                        onClick={() => submitAnswer()}
                        disabled={!currentAnswer.trim() || timeLeft === 0}
                      >
                        {session.currentQuestionIndex === session.questions.length - 1 ? 'Finalizar' : 'Próxima'}
                      </Button>
                    </div>
                  </div>
                </CardContent>
              </Card>

              {/* Tips */}
              <Alert>
                <Brain className="h-4 w-4" />
                <AlertDescription>
                  <strong>💡 Dicas:</strong> Seja específico, use exemplos concretos, mencione tecnologias relevantes.
                  {currentQuestion?.keyPoints && (
                    <span> Considere abordar: {currentQuestion.keyPoints.slice(0, 2).join(', ')}.</span>
                  )}
                </AlertDescription>
              </Alert>
            </>
          )}
        </TabsContent>

        <TabsContent value="results" className="space-y-6">
          {session?.completed && (
            <>
              {/* Overall Score */}
              <Card>
                <CardHeader className="text-center">
                  <div className="mb-4">
                    <Trophy className={`w-16 h-16 mx-auto mb-2 ${getScoreColor(session.totalScore)}`} />
                    <div className={`text-4xl font-bold ${getScoreColor(session.totalScore)}`}>
                      {session.totalScore}/100
                    </div>
                    <p className="text-muted-foreground">Final Score</p>
                  </div>
                </CardHeader>
              </Card>

              {/* Detailed Results */}
              <div className="space-y-4">
                {session.answers.map((answer, index) => (
                  <Card key={answer.questionId}>
                    <CardHeader>
                      <div className="flex justify-between items-start">
                        <div className="flex-1">
                          <h4 className="font-semibold">Pergunta {index + 1}</h4>
                          <p className="text-sm text-muted-foreground">
                            {session.questions[index].question}
                          </p>
                        </div>
                        <Badge className={getScoreColor(answer.score)}>
                          {answer.score}/100
                        </Badge>
                      </div>
                    </CardHeader>
                    
                    <CardContent className="space-y-3">
                      <div>
                        <strong>Sua resposta:</strong>
                        <p className="text-sm bg-muted p-3 rounded mt-1">
                          {answer.answer}
                        </p>
                      </div>
                      
                      <div>
                        <strong>Feedback:</strong>
                        <p className="text-sm">{answer.feedback}</p>
                      </div>
                      
                      {answer.keyPointsCovered.length > 0 && (
                        <div>
                          <strong>Pontos-chave cobertos:</strong>
                          <div className="flex flex-wrap gap-1 mt-1">
                            {answer.keyPointsCovered.map((point, i) => (
                              <Badge key={i} variant="outline" className="text-xs">
                                ✓ {point}
                              </Badge>
                            ))}
                          </div>
                        </div>
                      )}
                    </CardContent>
                  </Card>
                ))}
              </div>

              {/* Overall Feedback */}
              <Card>
                <CardHeader>
                  <h3 className="font-semibold">Feedback Geral</h3>
                </CardHeader>
                <CardContent>
                  <ul className="space-y-2">
                    {session.feedback.map((feedback, index) => (
                      <li key={index} className="text-sm">{feedback}</li>
                    ))}
                  </ul>
                </CardContent>
              </Card>

              <div className="text-center">
                <Button onClick={startInterview} className="gap-2">
                  <RotateCcw className="w-4 h-4" />
                  Nova Entrevista
                </Button>
              </div>
            </>
          )}
        </TabsContent>
      </Tabs>
    </div>
  );
};