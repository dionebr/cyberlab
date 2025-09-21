import React, { useState, useEffect } from 'react';
import { 
  CheckCircle2, 
  XCircle, 
  Clock, 
  Trophy, 
  Target,
  RefreshCw,
  ChevronRight,
  ChevronLeft,
  Lightbulb,
  Brain,
  AlertCircle,
  Star
} from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Card, CardHeader, CardContent } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Progress } from '@/components/ui/progress';
import { Alert, AlertDescription } from '@/components/ui/alert';
import { RadioGroup, RadioGroupItem } from '@/components/ui/radio-group';
import { Label } from '@/components/ui/label';

export interface QuizQuestion {
  id: string;
  question: string;
  options: string[];
  correctAnswer: string | number;
  explanation: string;
  difficulty?: 'easy' | 'medium' | 'hard';
  category?: string;
  points: number;
  hints?: string[];
  codeExample?: string;
}

interface QuizAnswer {
  questionId: string;
  selectedAnswer: number;
  isCorrect: boolean;
  timeSpent: number;
  hintsUsed: number;
}

interface QuizProps {
  title?: string;
  questions: QuizQuestion[];
  timeLimit?: number; // em segundos, 0 para sem limite
  showHints?: boolean;
  showExplanations?: boolean;
  allowRetry?: boolean;
  passingScore?: number; // porcentagem para passar
  onQuizComplete?: (score: number, answers: QuizAnswer[], passed: boolean) => void;
  onQuestionAnswered?: (questionId: string, answer: QuizAnswer) => void;
}

export const InteractiveQuiz: React.FC<QuizProps> = ({
  title = 'Quiz Interativo',
  questions,
  timeLimit = 0,
  showHints = true,
  showExplanations = true,
  allowRetry = true,
  passingScore = 70,
  onQuizComplete,
  onQuestionAnswered
}) => {
  const [currentQuestionIndex, setCurrentQuestionIndex] = useState(0);
  const [answers, setAnswers] = useState<QuizAnswer[]>([]);
  const [selectedAnswer, setSelectedAnswer] = useState<number | null>(null);
  const [showAnswer, setShowAnswer] = useState(false);
  const [quizComplete, setQuizComplete] = useState(false);
  const [timeLeft, setTimeLeft] = useState(timeLimit);
  const [showHint, setShowHint] = useState(false);
  const [hintsUsed, setHintsUsed] = useState(0);
  const [questionStartTime, setQuestionStartTime] = useState(Date.now());

  const currentQuestion = questions[currentQuestionIndex];

  // Verificação de segurança
  if (!questions || questions.length === 0) {
    return (
      <Card className="w-full">
        <CardContent className="text-center p-8">
          <Brain className="w-12 h-12 mx-auto mb-4 text-muted-foreground" />
          <h3 className="text-lg font-semibold mb-2">Nenhuma questão disponível</h3>
          <p className="text-muted-foreground">This quiz doesn't have configured questions yet.</p>
        </CardContent>
      </Card>
    );
  }

  if (!currentQuestion) {
    return (
      <Card className="w-full">
        <CardContent className="text-center p-8">
          <Brain className="w-12 h-12 mx-auto mb-4 text-muted-foreground" />
          <h3 className="text-lg font-semibold mb-2">Erro no quiz</h3>
          <p className="text-muted-foreground">Não foi possível carregar a questão atual.</p>
        </CardContent>
      </Card>
    );
  }

  // Timer
  useEffect(() => {
    if (timeLimit > 0 && timeLeft > 0 && !quizComplete && !showAnswer) {
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
  }, [timeLimit, timeLeft, quizComplete, showAnswer]);

  const handleTimeUp = () => {
    if (!showAnswer) {
      submitAnswer(null, true);
    }
  };

  const submitAnswer = (answer: number | null = selectedAnswer, timeUp: boolean = false) => {
    if (showAnswer || quizComplete) return;

    const timeSpent = Math.round((Date.now() - questionStartTime) / 1000);
    const correctAnswerIndex = typeof currentQuestion.correctAnswer === 'number' 
      ? currentQuestion.correctAnswer 
      : parseInt(currentQuestion.correctAnswer as string);
    const isCorrect = answer === correctAnswerIndex;
    
    const answerData: QuizAnswer = {
      questionId: currentQuestion.id,
      selectedAnswer: answer ?? -1,
      isCorrect,
      timeSpent,
      hintsUsed
    };

    const newAnswers = [...answers, answerData];
    setAnswers(newAnswers);
    setShowAnswer(true);

    if (onQuestionAnswered) {
      onQuestionAnswered(currentQuestion.id, answerData);
    }

    // Auto-avançar após mostrar explicação
    setTimeout(() => {
      if (currentQuestionIndex < questions.length - 1) {
        nextQuestion();
      } else {
        completeQuiz(newAnswers);
      }
    }, showExplanations ? 3000 : 1500);
  };

  const nextQuestion = () => {
    if (currentQuestionIndex < questions.length - 1) {
      setCurrentQuestionIndex(prev => prev + 1);
      setSelectedAnswer(null);
      setShowAnswer(false);
      setShowHint(false);
      setHintsUsed(0);
      setQuestionStartTime(Date.now());
    }
  };

  const previousQuestion = () => {
    if (currentQuestionIndex > 0 && !quizComplete) {
      setCurrentQuestionIndex(prev => prev - 1);
      setSelectedAnswer(null);
      setShowAnswer(false);
      setShowHint(false);
      setHintsUsed(0);
      setQuestionStartTime(Date.now());
      
      // Remove last answer
      setAnswers(prev => prev.slice(0, -1));
    }
  };

  const completeQuiz = (finalAnswers: QuizAnswer[]) => {
    setQuizComplete(true);
    
    const correctAnswers = finalAnswers.filter(a => a.isCorrect).length;
    const totalPoints = finalAnswers.reduce((sum, answer, index) => {
      if (answer.isCorrect) {
        // Bonus por velocidade e menos dicas
        const speedBonus = Math.max(0, 10 - answer.timeSpent) * 0.1;
        const hintPenalty = answer.hintsUsed * 0.1;
        return sum + questions[index].points * (1 + speedBonus - hintPenalty);
      }
      return sum;
    }, 0);
    
    const percentage = (correctAnswers / questions.length) * 100;
    const passed = percentage >= passingScore;

    if (onQuizComplete) {
      onQuizComplete(Math.round(totalPoints), finalAnswers, passed);
    }
  };

  const restartQuiz = () => {
    setCurrentQuestionIndex(0);
    setAnswers([]);
    setSelectedAnswer(null);
    setShowAnswer(false);
    setQuizComplete(false);
    setTimeLeft(timeLimit);
    setShowHint(false);
    setHintsUsed(0);
    setQuestionStartTime(Date.now());
  };

  const useHint = () => {
    if (showHints && currentQuestion.hints && currentQuestion.hints.length > hintsUsed) {
      setShowHint(true);
      setHintsUsed(prev => prev + 1);
    }
  };

  const formatTime = (seconds: number) => {
    const mins = Math.floor(seconds / 60);
    const secs = seconds % 60;
    return `${mins}:${secs.toString().padStart(2, '0')}`;
  };

  const getDifficultyColor = (difficulty: string) => {
    const colors = {
      easy: 'bg-green-500',
      medium: 'bg-yellow-500',
      hard: 'bg-red-500'
    };
    return colors[difficulty as keyof typeof colors] || 'bg-gray-500';
  };

  const getScoreColor = (percentage: number) => {
    if (percentage >= 90) return 'text-green-600';
    if (percentage >= 70) return 'text-blue-600';
    if (percentage >= 50) return 'text-yellow-600';
    return 'text-red-600';
  };

  // Função auxiliar para garantir que a questão tenha todas as propriedades necessárias
  const getQuestionWithDefaults = (question: any) => {
    return {
      ...question,
      difficulty: question.difficulty || 'medium',
      points: question.points || 10,
      explanation: question.explanation || 'Explanation not available.'
    };
  };

  if (quizComplete) {
    const correctAnswers = answers.filter(a => a.isCorrect).length;
    const totalPoints = answers.reduce((sum, answer, index) => {
      if (answer.isCorrect) {
        const questionWithDefaults = getQuestionWithDefaults(questions[index]);
        return sum + questionWithDefaults.points;
      }
      return sum;
    }, 0);
    const percentage = (correctAnswers / questions.length) * 100;
    const passed = percentage >= passingScore;

    return (
      <Card className="w-full">
        <CardHeader className="text-center">
          <div className="flex items-center justify-center mb-4">
            {passed ? (
              <Trophy className="w-16 h-16 text-yellow-500" />
            ) : (
              <Target className="w-16 h-16 text-gray-500" />
            )}
          </div>
          <h2 className="text-2xl font-bold mb-2">
            {passed ? 'Parabéns! Quiz Concluído!' : 'Quiz Finalizado'}
          </h2>
          <p className="text-muted-foreground">
            {passed 
              ? 'Você demonstrou excelente conhecimento!' 
              : 'Continue estudando para melhorar!'
            }
          </p>
        </CardHeader>
        
        <CardContent className="space-y-6">
          {/* Resultado geral */}
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
            <div className="text-center p-4 border rounded">
              <div className={`text-2xl font-bold ${getScoreColor(percentage)}`}>
                {correctAnswers}/{questions.length}
              </div>
              <div className="text-sm text-muted-foreground">Acertos</div>
            </div>
            
            <div className="text-center p-4 border rounded">
              <div className={`text-2xl font-bold ${getScoreColor(percentage)}`}>
                {percentage.toFixed(0)}%
              </div>
              <div className="text-sm text-muted-foreground">Score</div>
            </div>
            
            <div className="text-center p-4 border rounded">
              <div className="text-2xl font-bold text-blue-600">{Math.round(totalPoints)}</div>
              <div className="text-sm text-muted-foreground">Pontos</div>
            </div>
            
            <div className="text-center p-4 border rounded">
              <div className="text-2xl font-bold text-purple-600">
                {Math.round(answers.reduce((sum, a) => sum + a.timeSpent, 0) / answers.length)}s
              </div>
              <div className="text-sm text-muted-foreground">Tempo médio</div>
            </div>
          </div>

          {/* Status */}
          <Alert className={passed ? 'border-green-500 bg-green-50' : 'border-red-500 bg-red-50'}>
            <AlertCircle className={`h-4 w-4 ${passed ? 'text-green-600' : 'text-red-600'}`} />
            <AlertDescription className={passed ? 'text-green-700' : 'text-red-700'}>
              <strong>
                {passed ? 'APROVADO!' : 'REPROVADO'}
              </strong>
              {' '}
              {passed 
                ? `Você superou a nota mínima de ${passingScore}%`
                : `Você precisa de pelo menos ${passingScore}% para passar`
              }
            </AlertDescription>
          </Alert>

          {/* Análise por pergunta */}
          <div className="space-y-3">
            <h3 className="font-semibold">Análise detalhada:</h3>
            {answers.map((answer, index) => {
              const question = questions[index];
              return (
                <div 
                  key={answer.questionId}
                  className={`p-3 rounded border ${
                    answer.isCorrect 
                      ? 'border-green-200 bg-green-50' 
                      : 'border-red-200 bg-red-50'
                  }`}
                >
                  <div className="flex items-start justify-between">
                    <div className="flex-1">
                      <div className="flex items-center gap-2 mb-1">
                        {answer.isCorrect ? (
                          <CheckCircle2 className="w-4 h-4 text-green-600" />
                        ) : (
                          <XCircle className="w-4 h-4 text-red-600" />
                        )}
                        <span className="font-medium text-sm">
                          Pergunta {index + 1}
                        </span>
                        <Badge className={getDifficultyColor(question.difficulty)}>
                          {question.difficulty}
                        </Badge>
                      </div>
                      <p className="text-sm text-muted-foreground mb-2">
                        {question.question}
                      </p>
                      {!answer.isCorrect && (
                        <div className="text-xs">
                          <span className="text-red-600">Sua resposta: </span>
                          {question.options[answer.selectedAnswer] || 'Não respondida'}
                          <br />
                          <span className="text-green-600">Resposta correta: </span>
                          {question.options[typeof question.correctAnswer === 'number' 
                            ? question.correctAnswer 
                            : parseInt(question.correctAnswer as string)]}
                        </div>
                      )}
                    </div>
                    <div className="text-right">
                      <div className="text-xs text-muted-foreground">
                        {answer.timeSpent}s
                      </div>
                      <div className="text-xs">
                        +{answer.isCorrect ? getQuestionWithDefaults(question).points : 0} pts
                      </div>
                    </div>
                  </div>
                </div>
              );
            })}
          </div>

          {/* Ações */}
          <div className="flex gap-2 justify-center">
            {allowRetry && (
              <Button onClick={restartQuiz} className="gap-2">
                <RefreshCw className="w-4 h-4" />
                Tentar Novamente
              </Button>
            )}
          </div>
        </CardContent>
      </Card>
    );
  }

  return (
    <Card className="w-full">
      <CardHeader>
        <div className="flex items-center justify-between">
          <div>
            <h2 className="text-xl font-bold">{title}</h2>
            <p className="text-sm text-muted-foreground">
              Pergunta {currentQuestionIndex + 1} de {questions.length}
            </p>
          </div>
          <div className="flex items-center gap-2">
            {timeLimit > 0 && (
              <div className="flex items-center gap-1 text-sm">
                <Clock className="w-4 h-4" />
                <span className={timeLeft < 30 ? 'text-red-600 font-bold' : ''}>
                  {formatTime(timeLeft)}
                </span>
              </div>
            )}
            <Badge className={getDifficultyColor(getQuestionWithDefaults(currentQuestion).difficulty)}>
              {getQuestionWithDefaults(currentQuestion).difficulty}
            </Badge>
            <Badge variant="outline">
              {getQuestionWithDefaults(currentQuestion).points} pts
            </Badge>
          </div>
        </div>
        <Progress 
          value={((currentQuestionIndex + (showAnswer ? 1 : 0)) / questions.length) * 100}
          className="w-full"
        />
      </CardHeader>

      <CardContent className="space-y-6">
        {/* Pergunta */}
        <div className="space-y-4">
          <h3 className="text-lg font-semibold">{currentQuestion.question}</h3>
          
          {/* Código exemplo se houver */}
          {currentQuestion.codeExample && (
            <div className="bg-gray-900 text-green-400 p-4 rounded font-mono text-sm">
              <pre>{currentQuestion.codeExample}</pre>
            </div>
          )}

          {/* Opções */}
          <RadioGroup 
            value={selectedAnswer?.toString()} 
            onValueChange={(value) => setSelectedAnswer(parseInt(value))}
            disabled={showAnswer}
          >
            {currentQuestion.options.map((option, index) => {
              let optionClass = '';
              const correctAnswerIndex = typeof currentQuestion.correctAnswer === 'number' 
                ? currentQuestion.correctAnswer 
                : parseInt(currentQuestion.correctAnswer as string);
                
              if (showAnswer) {
                if (index === correctAnswerIndex) {
                  optionClass = 'border-green-500 bg-green-50';
                } else if (index === selectedAnswer && selectedAnswer !== correctAnswerIndex) {
                  optionClass = 'border-red-500 bg-red-50';
                }
              }
              
              return (
                <div key={index} className={`flex items-center space-x-2 p-3 rounded border ${optionClass}`}>
                  <RadioGroupItem value={index.toString()} id={`option-${index}`} />
                  <Label htmlFor={`option-${index}`} className="flex-1 cursor-pointer">
                    {option}
                  </Label>
                  {showAnswer && index === correctAnswerIndex && (
                    <CheckCircle2 className="w-5 h-5 text-green-600" />
                  )}
                  {showAnswer && index === selectedAnswer && selectedAnswer !== correctAnswerIndex && (
                    <XCircle className="w-5 h-5 text-red-600" />
                  )}
                </div>
              );
            })}
          </RadioGroup>
        </div>

        {/* Dica */}
        {showHints && currentQuestion.hints && !showAnswer && (
          <div className="space-y-2">
            {!showHint ? (
              <Button 
                variant="outline" 
                size="sm" 
                onClick={useHint}
                disabled={hintsUsed >= (currentQuestion.hints?.length || 0)}
                className="gap-2"
              >
                <Lightbulb className="w-4 h-4" />
                Usar Dica ({hintsUsed}/{currentQuestion.hints?.length || 0})
              </Button>
            ) : (
              <Alert>
                <Lightbulb className="h-4 w-4" />
                <AlertDescription>
                  <strong>💡 Dica {hintsUsed}:</strong>
                  {' '}{currentQuestion.hints?.[hintsUsed - 1]}
                </AlertDescription>
              </Alert>
            )}
          </div>
        )}

        {/* Explicação após responder */}
        {showAnswer && showExplanations && (
          <Alert className={selectedAnswer === currentQuestion.correctAnswer ? 'border-green-500 bg-green-50' : 'border-red-500 bg-red-50'}>
            <AlertCircle className={`h-4 w-4 ${selectedAnswer === currentQuestion.correctAnswer ? 'text-green-600' : 'text-red-600'}`} />
            <AlertDescription>
              <strong>
                {selectedAnswer === currentQuestion.correctAnswer ? '✅ Correto!' : '❌ Incorreto'}
              </strong>
              <br />
              {getQuestionWithDefaults(currentQuestion).explanation}
            </AlertDescription>
          </Alert>
        )}

        {/* Controles */}
        <div className="flex justify-between">
          <Button
            variant="outline"
            onClick={previousQuestion}
            disabled={currentQuestionIndex === 0 || showAnswer}
            className="gap-2"
          >
            <ChevronLeft className="w-4 h-4" />
            Anterior
          </Button>

          <div className="flex gap-2">
            {!showAnswer && (
              <Button 
                onClick={() => submitAnswer()}
                disabled={selectedAnswer === null}
                className="gap-2"
              >
                Confirmar Resposta
              </Button>
            )}

            <Button
              variant="outline"
              onClick={nextQuestion}
              disabled={!showAnswer || currentQuestionIndex >= questions.length - 1}
              className="gap-2"
            >
              Próxima
              <ChevronRight className="w-4 h-4" />
            </Button>
          </div>
        </div>
      </CardContent>
    </Card>
  );
};