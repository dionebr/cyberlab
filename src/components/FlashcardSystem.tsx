import React, { useState, useEffect } from 'react';
import { 
  RotateCcw, 
  ChevronLeft, 
  ChevronRight, 
  Brain, 
  CheckCircle, 
  XCircle,
  Star,
  Shuffle,
  BarChart3,
  Clock,
  Zap
} from 'lucide-react';
import { Card, CardContent, CardHeader } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Progress } from '@/components/ui/progress';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';

export interface Flashcard {
  id: string;
  category: string;
  difficulty: 'easy' | 'medium' | 'hard';
  front: string;
  back: string;
  hint?: string;
  tags: string[];
  created: Date;
  lastReviewed?: Date;
  nextReview?: Date;
  interval: number; // days until next review
  easeFactor: number; // for spaced repetition algorithm
  reviewCount: number;
  correctStreak: number;
}

export interface FlashcardStats {
  totalCards: number;
  masteredCards: number;
  reviewingCards: number;
  newCards: number;
  todayReviews: number;
  accuracy: number;
  averageTime: number; // seconds per card
  longestStreak: number;
}

interface FlashcardSystemProps {
  cards: Flashcard[];
  onCardReviewed: (cardId: string, correct: boolean, timeSpent: number) => void;
  stats: FlashcardStats;
  autoAdvance?: boolean;
}

export const FlashcardSystem: React.FC<FlashcardSystemProps> = ({
  cards,
  onCardReviewed,
  stats,
  autoAdvance = false
}) => {
  const [currentCardIndex, setCurrentCardIndex] = useState(0);
  const [showAnswer, setShowAnswer] = useState(false);
  const [startTime, setStartTime] = useState(Date.now());
  const [sessionStats, setSessionStats] = useState({
    reviewed: 0,
    correct: 0,
    timeSpent: 0
  });
  const [activeTab, setActiveTab] = useState('study');
  const [shuffled, setShuffled] = useState(false);
  const [studyCards, setStudyCards] = useState<Flashcard[]>([]);

  // Initialize study cards on load
  useEffect(() => {
    const dueTodayCards = cards.filter(card => 
      !card.nextReview || card.nextReview <= new Date()
    );
    setStudyCards(dueTodayCards.length > 0 ? dueTodayCards : cards);
  }, [cards]);

  const currentCard = studyCards[currentCardIndex];

  const flipCard = () => {
    setShowAnswer(!showAnswer);
  };

  const markCard = (correct: boolean) => {
    if (!currentCard) return;

    const timeSpent = Math.round((Date.now() - startTime) / 1000);
    onCardReviewed(currentCard.id, correct, timeSpent);

    setSessionStats(prev => ({
      reviewed: prev.reviewed + 1,
      correct: prev.correct + (correct ? 1 : 0),
      timeSpent: prev.timeSpent + timeSpent
    }));

    if (autoAdvance) {
      setTimeout(() => nextCard(), 1000);
    } else {
      nextCard();
    }
  };

  const nextCard = () => {
    if (currentCardIndex < studyCards.length - 1) {
      setCurrentCardIndex(prev => prev + 1);
    } else {
      setCurrentCardIndex(0); // Loop back to start
    }
    setShowAnswer(false);
    setStartTime(Date.now());
  };

  const previousCard = () => {
    if (currentCardIndex > 0) {
      setCurrentCardIndex(prev => prev - 1);
    } else {
      setCurrentCardIndex(studyCards.length - 1); // Loop to end
    }
    setShowAnswer(false);
    setStartTime(Date.now());
  };

  const shuffleCards = () => {
    const shuffledCards = [...studyCards].sort(() => Math.random() - 0.5);
    setStudyCards(shuffledCards);
    setCurrentCardIndex(0);
    setShuffled(true);
    setShowAnswer(false);
    setStartTime(Date.now());
  };

  const resetSession = () => {
    setCurrentCardIndex(0);
    setShowAnswer(false);
    setSessionStats({ reviewed: 0, correct: 0, timeSpent: 0 });
    setStartTime(Date.now());
  };

  const getDifficultyColor = (difficulty: string) => {
    const colors = {
      easy: 'bg-green-100 text-green-800 border-green-200',
      medium: 'bg-yellow-100 text-yellow-800 border-yellow-200',
      hard: 'bg-red-100 text-red-800 border-red-200'
    };
    return colors[difficulty as keyof typeof colors] || colors.easy;
  };

  const getSessionAccuracy = () => {
    if (sessionStats.reviewed === 0) return 0;
    return Math.round((sessionStats.correct / sessionStats.reviewed) * 100);
  };

  if (studyCards.length === 0) {
    return (
      <Card className="w-full max-w-4xl mx-auto">
        <CardContent className="text-center py-12">
          <Brain className="w-16 h-16 mx-auto mb-4 text-muted-foreground" />
          <h3 className="text-xl font-semibold mb-2">Nenhum flashcard para revisar</h3>
          <p className="text-muted-foreground">Parabéns! Você está em dia com suas revisões.</p>
        </CardContent>
      </Card>
    );
  }

  return (
    <div className="w-full max-w-4xl mx-auto space-y-6">
      <Tabs value={activeTab} onValueChange={setActiveTab} className="w-full">
        <TabsList className="grid w-full grid-cols-2">
          <TabsTrigger value="study" className="gap-2">
            <Brain className="w-4 h-4" />
            Estudar
          </TabsTrigger>
          <TabsTrigger value="stats" className="gap-2">
            <BarChart3 className="w-4 h-4" />
            Estatísticas
          </TabsTrigger>
        </TabsList>

        <TabsContent value="study" className="space-y-4">
          {/* Controls */}
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2">
              <Badge variant="outline">
                {currentCardIndex + 1} de {studyCards.length}
              </Badge>
              <Badge className={getDifficultyColor(currentCard?.difficulty || 'easy')}>
                {currentCard?.difficulty?.toUpperCase()}
              </Badge>
              <Badge variant="secondary">
                {currentCard?.category}
              </Badge>
            </div>
            
            <div className="flex gap-2">
              <Button size="sm" variant="outline" onClick={shuffleCards}>
                <Shuffle className="w-4 h-4" />
              </Button>
              <Button size="sm" variant="outline" onClick={resetSession}>
                <RotateCcw className="w-4 h-4" />
              </Button>
            </div>
          </div>

          {/* Progress */}
          <div className="space-y-2">
            <div className="flex justify-between text-sm text-muted-foreground">
              <span>Progresso da Sessão</span>
              <span>{sessionStats.reviewed} revisados • {getSessionAccuracy()}% acertos</span>
            </div>
            <Progress 
              value={(currentCardIndex / studyCards.length) * 100} 
              className="w-full h-2"
            />
          </div>

          {/* Flashcard */}
          <Card className="min-h-[400px] cursor-pointer" onClick={flipCard}>
            <CardHeader className="text-center">
              <div className="flex items-center justify-center gap-2">
                <div className={`w-4 h-4 rounded-full ${showAnswer ? 'bg-green-500' : 'bg-blue-500'} animate-pulse`} />
                <span className="text-sm font-medium">
                  {showAnswer ? 'Resposta' : 'Pergunta'}
                </span>
                <div className="text-xs text-muted-foreground ml-2">
                  (Clique para virar)
                </div>
              </div>
            </CardHeader>
            
            <CardContent className="flex-1 flex items-center justify-center p-8">
              <div className="text-center space-y-4">
                <div className="text-lg md:text-xl lg:text-2xl font-medium leading-relaxed">
                  {showAnswer ? currentCard?.back : currentCard?.front}
                </div>
                
                {!showAnswer && currentCard?.hint && (
                  <div className="text-sm text-muted-foreground bg-muted p-3 rounded-lg">
                    💡 <strong>Dica:</strong> {currentCard.hint}
                  </div>
                )}
                
                {currentCard?.tags && (
                  <div className="flex flex-wrap gap-1 justify-center mt-4">
                    {currentCard.tags.map((tag, index) => (
                      <Badge key={index} variant="outline" className="text-xs">
                        {tag}
                      </Badge>
                    ))}
                  </div>
                )}
              </div>
            </CardContent>
          </Card>

          {/* Navigation and Rating */}
          <div className="flex items-center justify-between">
            <Button variant="outline" onClick={previousCard}>
              <ChevronLeft className="w-4 h-4 mr-1" />
              Anterior
            </Button>

            {showAnswer && (
              <div className="flex gap-2">
                <Button 
                  variant="destructive" 
                  onClick={() => markCard(false)}
                  className="gap-2"
                >
                  <XCircle className="w-4 h-4" />
                  Difícil
                </Button>
                <Button 
                  variant="default" 
                  onClick={() => markCard(true)}
                  className="gap-2 bg-green-600 hover:bg-green-700"
                >
                  <CheckCircle className="w-4 h-4" />
                  Fácil
                </Button>
              </div>
            )}

            <Button variant="outline" onClick={nextCard}>
              Próximo
              <ChevronRight className="w-4 h-4 ml-1" />
            </Button>
          </div>
        </TabsContent>

        <TabsContent value="stats" className="space-y-6">
          {/* Overall Stats */}
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
            <Card>
              <CardContent className="pt-6">
                <div className="text-center">
                  <div className="text-2xl font-bold text-blue-600">{stats.totalCards}</div>
                  <p className="text-xs text-muted-foreground">Total de Cards</p>
                </div>
              </CardContent>
            </Card>
            
            <Card>
              <CardContent className="pt-6">
                <div className="text-center">
                  <div className="text-2xl font-bold text-green-600">{stats.masteredCards}</div>
                  <p className="text-xs text-muted-foreground">Dominados</p>
                </div>
              </CardContent>
            </Card>
            
            <Card>
              <CardContent className="pt-6">
                <div className="text-center">
                  <div className="text-2xl font-bold text-orange-600">{stats.reviewingCards}</div>
                  <p className="text-xs text-muted-foreground">Em Revisão</p>
                </div>
              </CardContent>
            </Card>
            
            <Card>
              <CardContent className="pt-6">
                <div className="text-center">
                  <div className="text-2xl font-bold text-purple-600">{stats.newCards}</div>
                  <p className="text-xs text-muted-foreground">Novos</p>
                </div>
              </CardContent>
            </Card>
          </div>

          {/* Session Stats */}
          <Card>
            <CardHeader>
              <h3 className="font-semibold">Estatísticas da Sessão</h3>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="grid grid-cols-3 gap-4">
                <div className="text-center">
                  <div className="flex items-center justify-center gap-1 text-lg font-semibold">
                    <Brain className="w-5 h-5 text-blue-500" />
                    {sessionStats.reviewed}
                  </div>
                  <p className="text-sm text-muted-foreground">Revisados</p>
                </div>
                
                <div className="text-center">
                  <div className="flex items-center justify-center gap-1 text-lg font-semibold">
                    <Star className="w-5 h-5 text-yellow-500" />
                    {getSessionAccuracy()}%
                  </div>
                  <p className="text-sm text-muted-foreground">Precisão</p>
                </div>
                
                <div className="text-center">
                  <div className="flex items-center justify-center gap-1 text-lg font-semibold">
                    <Clock className="w-5 h-5 text-green-500" />
                    {Math.round(sessionStats.timeSpent / 60)}m
                  </div>
                  <p className="text-sm text-muted-foreground">Tempo Total</p>
                </div>
              </div>
            </CardContent>
          </Card>

          {/* Performance Metrics */}
          <Card>
            <CardHeader>
              <h3 className="font-semibold">Performance Geral</h3>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="space-y-2">
                <div className="flex justify-between text-sm">
                  <span>Precisão Geral:</span>
                  <span className="font-medium">{stats.accuracy}%</span>
                </div>
                <Progress value={stats.accuracy} className="h-2" />
              </div>
              
              <div className="space-y-2">
                <div className="flex justify-between text-sm">
                  <span>Cards Dominados:</span>
                  <span className="font-medium">{Math.round((stats.masteredCards / stats.totalCards) * 100)}%</span>
                </div>
                <Progress value={(stats.masteredCards / stats.totalCards) * 100} className="h-2" />
              </div>
              
              <div className="flex justify-between items-center pt-2">
                <div className="text-sm">
                  <Zap className="w-4 h-4 inline mr-1 text-yellow-500" />
                  Maior sequência: <span className="font-medium">{stats.longestStreak} acertos</span>
                </div>
                <div className="text-sm">
                  <Clock className="w-4 h-4 inline mr-1 text-blue-500" />
                  Tempo médio: <span className="font-medium">{stats.averageTime}s</span>
                </div>
              </div>
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>
    </div>
  );
};