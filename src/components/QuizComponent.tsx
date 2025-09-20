import { useState, useEffect } from 'react';
import { CheckCircle, XCircle, AlertTriangle, Lightbulb, Clock, Trophy, RotateCcw } from 'lucide-react';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Progress } from '@/components/ui/progress';
import { Alert, AlertDescription } from '@/components/ui/alert';
import { useLanguage } from '../hooks/useLanguage';

export interface QuizQuestion {
  id: string;
  question: string;
  options: string[];
  correctAnswer: number;
  explanation: string;
  difficulty: 'easy' | 'medium' | 'hard';
  category: string;
  technicalTerms?: string[]; // Preserve technical terminology
}

interface QuizComponentProps {
  questions: QuizQuestion[];
  title: string;
  onComplete: (score: number, timeSpent: number) => void;
  allowRetake?: boolean;
}

export const QuizComponent = ({ questions, title, onComplete, allowRetake = true }: QuizComponentProps) => {
  const { t } = useLanguage();
  const [currentQuestion, setCurrentQuestion] = useState(0);
  const [selectedAnswers, setSelectedAnswers] = useState<number[]>([]);
  const [showResults, setShowResults] = useState(false);
  const [startTime] = useState(Date.now());
  const [timeSpent, setTimeSpent] = useState(0);
  const [showExplanation, setShowExplanation] = useState(false);

  const currentQ = questions[currentQuestion];
  const isLastQuestion = currentQuestion === questions.length - 1;
  const hasAnswered = selectedAnswers[currentQuestion] !== undefined;

  // Calculate score
  const score = selectedAnswers.reduce((acc, answer, index) => {
    return acc + (answer === questions[index]?.correctAnswer ? 1 : 0);
  }, 0);

  const scorePercentage = Math.round((score / questions.length) * 100);

  // Handle answer selection
  const handleAnswerSelect = (answerIndex: number) => {
    if (showResults) return;
    
    const newAnswers = [...selectedAnswers];
    newAnswers[currentQuestion] = answerIndex;
    setSelectedAnswers(newAnswers);
    
    // Show explanation after selection
    setShowExplanation(true);
  };

  // Navigate to next question
  const handleNext = () => {
    if (isLastQuestion) {
      // Complete quiz
      const finalTimeSpent = Math.floor((Date.now() - startTime) / 1000);
      setTimeSpent(finalTimeSpent);
      setShowResults(true);
      onComplete(scorePercentage, finalTimeSpent);
    } else {
      setCurrentQuestion(prev => prev + 1);
      setShowExplanation(false);
    }
  };

  // Navigate to previous question
  const handlePrevious = () => {
    if (currentQuestion > 0) {
      setCurrentQuestion(prev => prev - 1);
      setShowExplanation(selectedAnswers[currentQuestion - 1] !== undefined);
    }
  };

  // Restart quiz
  const handleRestart = () => {
    setCurrentQuestion(0);
    setSelectedAnswers([]);
    setShowResults(false);
    setShowExplanation(false);
  };

  // Get difficulty badge color
  const getDifficultyColor = (difficulty: string) => {
    switch (difficulty) {
      case 'easy': return 'bg-green-500';
      case 'medium': return 'bg-yellow-500';
      case 'hard': return 'bg-red-500';
      default: return 'bg-gray-500';
    }
  };

  // Get score badge variant
  const getScoreVariant = (percentage: number) => {
    if (percentage >= 80) return 'default';
    if (percentage >= 60) return 'secondary';
    return 'destructive';
  };

  if (showResults) {
    return (
      <Card className="w-full max-w-4xl mx-auto">
        <CardHeader className="text-center">
          <CardTitle className="flex items-center justify-center gap-2">
            <Trophy className={`h-6 w-6 ${scorePercentage >= 80 ? 'text-yellow-500' : scorePercentage >= 60 ? 'text-blue-500' : 'text-gray-500'}`} />
            Quiz Concluído: {title}
          </CardTitle>
        </CardHeader>
        <CardContent className="space-y-6">
          {/* Score Display */}
          <div className="text-center space-y-4">
            <div className="text-6xl font-bold text-primary">
              {scorePercentage}%
            </div>
            <div className="text-lg text-muted-foreground">
              {score} de {questions.length} questões corretas
            </div>
            <Badge variant={getScoreVariant(scorePercentage)} className="text-sm px-4 py-2">
              {scorePercentage >= 80 ? 'Excelente!' : scorePercentage >= 60 ? 'Bom trabalho!' : 'Continue estudando!'}
            </Badge>
          </div>

          {/* Performance Metrics */}
          <div className="grid md:grid-cols-3 gap-4">
            <div className="text-center p-4 bg-muted/50 rounded-lg">
              <Clock className="h-8 w-8 mx-auto mb-2 text-blue-500" />
              <div className="font-semibold">{Math.floor(timeSpent / 60)}m {timeSpent % 60}s</div>
              <div className="text-sm text-muted-foreground">Tempo total</div>
            </div>
            <div className="text-center p-4 bg-muted/50 rounded-lg">
              <CheckCircle className="h-8 w-8 mx-auto mb-2 text-green-500" />
              <div className="font-semibold">{score}</div>
              <div className="text-sm text-muted-foreground">Acertos</div>
            </div>
            <div className="text-center p-4 bg-muted/50 rounded-lg">
              <XCircle className="h-8 w-8 mx-auto mb-2 text-red-500" />
              <div className="font-semibold">{questions.length - score}</div>
              <div className="text-sm text-muted-foreground">Erros</div>
            </div>
          </div>

          {/* Detailed Results */}
          <div className="space-y-3">
            <h4 className="font-semibold text-lg">Revisão das Respostas</h4>
            {questions.map((question, index) => {
              const userAnswer = selectedAnswers[index];
              const isCorrect = userAnswer === question.correctAnswer;
              
              return (
                <div key={question.id} className={`p-4 rounded-lg border ${isCorrect ? 'border-green-200 bg-green-50 dark:bg-green-900/20' : 'border-red-200 bg-red-50 dark:bg-red-900/20'}`}>
                  <div className="flex items-start gap-3">
                    {isCorrect ? (
                      <CheckCircle className="h-5 w-5 text-green-600 mt-0.5 flex-shrink-0" />
                    ) : (
                      <XCircle className="h-5 w-5 text-red-600 mt-0.5 flex-shrink-0" />
                    )}
                    <div className="flex-1 min-w-0">
                      <p className="font-medium text-sm mb-2">{question.question}</p>
                      <div className="grid grid-cols-1 gap-2 text-sm">
                        <div className={`p-2 rounded ${isCorrect ? 'bg-green-100 dark:bg-green-800/30' : 'bg-red-100 dark:bg-red-800/30'}`}>
                          <strong>Sua resposta:</strong> {question.options[userAnswer]}
                        </div>
                        {!isCorrect && (
                          <div className="p-2 rounded bg-green-100 dark:bg-green-800/30">
                            <strong>Resposta correta:</strong> {question.options[question.correctAnswer]}
                          </div>
                        )}
                      </div>
                    </div>
                  </div>
                </div>
              );
            })}
          </div>

          {/* Action Buttons */}
          <div className="flex justify-center gap-4">
            {allowRetake && (
              <Button onClick={handleRestart} variant="outline" className="flex items-center gap-2">
                <RotateCcw className="h-4 w-4" />
                Tentar Novamente
              </Button>
            )}
          </div>
        </CardContent>
      </Card>
    );
  }

  return (
    <Card className="w-full max-w-4xl mx-auto">
      <CardHeader>
        <div className="flex items-center justify-between">
          <CardTitle className="flex items-center gap-2">
            {title}
            <Badge variant="outline" className={`${getDifficultyColor(currentQ.difficulty)} text-white`}>
              {currentQ.difficulty.toUpperCase()}
            </Badge>
          </CardTitle>
          <Badge variant="secondary">
            {currentQuestion + 1} / {questions.length}
          </Badge>
        </div>
        <Progress value={((currentQuestion + 1) / questions.length) * 100} className="h-2" />
      </CardHeader>

      <CardContent className="space-y-6">
        {/* Question */}
        <div className="space-y-4">
          <h3 className="text-lg font-medium leading-relaxed">
            {currentQ.question}
          </h3>
          
          {/* Technical Terms Highlight */}
          {currentQ.technicalTerms && currentQ.technicalTerms.length > 0 && (
            <Alert>
              <Lightbulb className="h-4 w-4" />
              <AlertDescription>
                <strong>Termos técnicos nesta questão:</strong>{' '}
                {currentQ.technicalTerms.map((term, index) => (
                  <Badge key={index} variant="outline" className="mx-1">
                    {term}
                  </Badge>
                ))}
              </AlertDescription>
            </Alert>
          )}
        </div>

        {/* Answer Options */}
        <div className="space-y-3">
          {currentQ.options.map((option, index) => {
            const isSelected = selectedAnswers[currentQuestion] === index;
            const isCorrect = index === currentQ.correctAnswer;
            const showCorrect = showExplanation && isCorrect;
            const showIncorrect = showExplanation && isSelected && !isCorrect;

            return (
              <Button
                key={index}
                variant={isSelected ? (showCorrect ? "default" : showIncorrect ? "destructive" : "default") : "outline"}
                className={`w-full p-4 h-auto text-left justify-start ${
                  showCorrect ? 'border-green-500 bg-green-50 dark:bg-green-900/20' :
                  showIncorrect ? 'border-red-500 bg-red-50 dark:bg-red-900/20' :
                  isSelected ? 'border-primary' : ''
                }`}
                onClick={() => handleAnswerSelect(index)}
                disabled={showResults}
              >
                <div className="flex items-center gap-3">
                  <div className={`w-6 h-6 rounded-full border-2 flex items-center justify-center text-sm font-bold ${
                    showCorrect ? 'border-green-500 bg-green-500 text-white' :
                    showIncorrect ? 'border-red-500 bg-red-500 text-white' :
                    isSelected ? 'border-primary bg-primary text-primary-foreground' :
                    'border-muted-foreground'
                  }`}>
                    {String.fromCharCode(65 + index)}
                  </div>
                  <span className="flex-1">{option}</span>
                  {showCorrect && <CheckCircle className="h-5 w-5 text-green-600" />}
                  {showIncorrect && <XCircle className="h-5 w-5 text-red-600" />}
                </div>
              </Button>
            );
          })}
        </div>

        {/* Explanation */}
        {showExplanation && (
          <Alert className={selectedAnswers[currentQuestion] === currentQ.correctAnswer ? 'border-green-200 bg-green-50 dark:bg-green-900/20' : 'border-blue-200 bg-blue-50 dark:bg-blue-900/20'}>
            <AlertTriangle className="h-4 w-4" />
            <AlertDescription>
              <strong>Explicação:</strong> {currentQ.explanation}
            </AlertDescription>
          </Alert>
        )}

        {/* Navigation */}
        <div className="flex justify-between items-center pt-4">
          <Button
            variant="outline"
            onClick={handlePrevious}
            disabled={currentQuestion === 0}
          >
            Anterior
          </Button>

          <div className="flex gap-1">
            {questions.map((_, index) => (
              <div
                key={index}
                className={`w-2 h-2 rounded-full ${
                  index === currentQuestion ? 'bg-primary' :
                  selectedAnswers[index] !== undefined ? 'bg-success' : 'bg-muted'
                }`}
              />
            ))}
          </div>

          <Button
            onClick={handleNext}
            disabled={!hasAnswered}
            className="bg-gradient-cyber"
          >
            {isLastQuestion ? 'Finalizar Quiz' : 'Próxima'}
          </Button>
        </div>
      </CardContent>
    </Card>
  );
};