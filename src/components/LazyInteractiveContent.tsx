import { lazy, Suspense, useState, useEffect } from 'react';
import { Card, CardContent } from '@/components/ui/card';
import { Skeleton } from '@/components/ui/skeleton';
import { Button } from '@/components/ui/button';
import { Loader2 } from 'lucide-react';

// Lazy load heavy components
const QuizComponent = lazy(() => import('../components/QuizComponent').then(module => ({
  default: module.QuizComponent
})));

const CodeExerciseComponent = lazy(() => import('../components/CodeExerciseComponent').then(module => ({
  default: module.CodeExerciseComponent
})));

interface LazyInteractiveContentProps {
  type: 'quiz' | 'exercise';
  children: React.ReactNode;
  onLoad?: () => void;
}

// Loading skeleton for quiz
const QuizSkeleton = () => (
  <Card className="w-full max-w-4xl mx-auto">
    <CardContent className="p-6 space-y-4">
      <div className="flex justify-between items-center">
        <Skeleton className="h-8 w-48" />
        <Skeleton className="h-6 w-20" />
      </div>
      <Skeleton className="h-2 w-full" />
      <Skeleton className="h-20 w-full" />
      <div className="space-y-3">
        {Array.from({length: 4}).map((_, i) => (
          <Skeleton key={i} className="h-12 w-full" />
        ))}
      </div>
      <div className="flex justify-between">
        <Skeleton className="h-10 w-20" />
        <Skeleton className="h-10 w-20" />
      </div>
    </CardContent>
  </Card>
);

// Loading skeleton for code exercise
const ExerciseSkeleton = () => (
  <div className="w-full max-w-6xl mx-auto space-y-6">
    <Card>
      <CardContent className="p-6 space-y-4">
        <div className="flex justify-between items-center">
          <Skeleton className="h-8 w-64" />
          <div className="flex gap-2">
            <Skeleton className="h-6 w-16" />
            <Skeleton className="h-6 w-20" />
          </div>
        </div>
        <Skeleton className="h-16 w-full" />
        <div className="flex flex-wrap gap-2">
          {Array.from({length: 3}).map((_, i) => (
            <Skeleton key={i} className="h-6 w-24" />
          ))}
        </div>
      </CardContent>
    </Card>
    
    <div className="grid lg:grid-cols-2 gap-6">
      <Card>
        <CardContent className="p-6 space-y-4">
          <Skeleton className="h-6 w-32" />
          <Skeleton className="h-[300px] w-full" />
          <div className="flex gap-2">
            <Skeleton className="h-10 w-32" />
            <Skeleton className="h-10 w-20" />
            <Skeleton className="h-10 w-24" />
          </div>
        </CardContent>
      </Card>
      
      <Card>
        <CardContent className="p-6 space-y-4">
          <div className="flex space-x-1">
            {Array.from({length: 3}).map((_, i) => (
              <Skeleton key={i} className="h-10 flex-1" />
            ))}
          </div>
          <Skeleton className="h-64 w-full" />
        </CardContent>
      </Card>
    </div>
  </div>
);

// Lazy loading wrapper with intersection observer
export const LazyInteractiveContent = ({ type, children, onLoad }: LazyInteractiveContentProps) => {
  const [isVisible, setIsVisible] = useState(false);
  const [shouldLoad, setShouldLoad] = useState(false);

  useEffect(() => {
    const observer = new IntersectionObserver(
      ([entry]) => {
        if (entry.isIntersecting) {
          setIsVisible(true);
          // Add small delay to improve UX
          setTimeout(() => setShouldLoad(true), 100);
          observer.disconnect();
        }
      },
      { 
        threshold: 0.1,
        rootMargin: '50px' // Start loading 50px before component enters viewport
      }
    );

    const element = document.getElementById(`lazy-${type}-container`);
    if (element) {
      observer.observe(element);
    }

    return () => observer.disconnect();
  }, [type]);

  useEffect(() => {
    if (shouldLoad && onLoad) {
      onLoad();
    }
  }, [shouldLoad, onLoad]);

  return (
    <div id={`lazy-${type}-container`} className="min-h-[200px]">
      {isVisible ? (
        <Suspense fallback={
          <div className="flex flex-col items-center justify-center p-8 space-y-4">
            <Loader2 className="h-8 w-8 animate-spin text-primary" />
            <p className="text-sm text-muted-foreground">
              Loading interactive content...
            </p>
            {type === 'quiz' ? <QuizSkeleton /> : <ExerciseSkeleton />}
          </div>
        }>
          {shouldLoad ? children : (type === 'quiz' ? <QuizSkeleton /> : <ExerciseSkeleton />)}
        </Suspense>
      ) : (
        <div className="flex flex-col items-center justify-center p-12 border-2 border-dashed border-muted-foreground/20 rounded-lg bg-muted/10">
          <div className="text-center space-y-4">
            <div className="text-4xl">📚</div>
            <h3 className="font-semibold">Interactive Content</h3>
            <p className="text-sm text-muted-foreground max-w-md">
              {type === 'quiz' 
                ? 'Quiz interativo será carregado quando você rolar até aqui'
                : 'Exercício de código será carregado quando você rolar até aqui'
              }
            </p>
            <Button 
              variant="outline" 
              onClick={() => {
                setIsVisible(true);
                setShouldLoad(true);
              }}
            >
              Carregar Agora
            </Button>
          </div>
        </div>
      )}
    </div>
  );
};