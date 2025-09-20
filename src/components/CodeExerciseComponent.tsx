import { useState } from 'react';
import { Play, CheckCircle, XCircle, AlertTriangle, Lightbulb, Terminal, RotateCcw, Eye, EyeOff } from 'lucide-react';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Textarea } from '@/components/ui/textarea';
import { Alert, AlertDescription } from '@/components/ui/alert';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { useLanguage } from '../hooks/useLanguage';

export interface TestCase {
  input: string;
  expectedOutput: string;
  description: string;
}

export interface CodeExercise {
  id: string;
  title: string;
  description: string;
  difficulty: 'easy' | 'medium' | 'hard';
  language: string;
  startingCode: string;
  solution: string;
  testCases: TestCase[];
  hints: string[];
  technicalConcepts: string[];
  securityFocus: string;
}

interface CodeExerciseComponentProps {
  exercise: CodeExercise;
  onComplete: (success: boolean, attempts: number, timeSpent: number) => void;
}

// Simulador simples de execução de código (para demonstração)
const executeCode = (code: string, input: string, language: string): { output: string; error?: string } => {
  try {
    // Esta é uma simulação - em produção seria necessário um sandbox seguro
    if (language === 'python') {
      // Simulação de execução Python
      if (code.includes('sql') && code.includes('prepare') && input.includes("'; DROP")) {
        return { output: "Erro: Tentativa de SQL Injection bloqueada" };
      }
      if (code.includes('hashlib') && code.includes('pbkdf2')) {
        return { output: "Hash seguro gerado com sucesso" };
      }
      if (code.includes('re.match') && code.includes('^[a-zA-Z0-9]')) {
        return { output: "Input validado com sucesso" };
      }
    }
    
    if (language === 'javascript') {
      if (code.includes('textContent') && input.includes('<script>')) {
        return { output: "Texto inserido com segurança (XSS prevenido)" };
      }
      if (code.includes('crypto.randomBytes') && code.includes('pbkdf2')) {
        return { output: "Senha hash criado com segurança" };
      }
    }

    // Simulação padrão
    return { output: `Executado com entrada: ${input}` };
  } catch (error) {
    return { output: "", error: error instanceof Error ? error.message : "Erro desconhecido" };
  }
};

export const CodeExerciseComponent = ({ exercise, onComplete }: CodeExerciseComponentProps) => {
  const { t } = useLanguage();
  const [userCode, setUserCode] = useState(exercise.startingCode);
  const [currentHint, setCurrentHint] = useState(0);
  const [showSolution, setShowSolution] = useState(false);
  const [testResults, setTestResults] = useState<Array<{passed: boolean; output: string; error?: string}>>([]);
  const [attempts, setAttempts] = useState(0);
  const [startTime] = useState(Date.now());
  const [showHints, setShowHints] = useState(false);

  // Execute code against test cases
  const runTests = () => {
    setAttempts(prev => prev + 1);
    
    const results = exercise.testCases.map(testCase => {
      const result = executeCode(userCode, testCase.input, exercise.language);
      const passed = result.output.trim() === testCase.expectedOutput.trim() && !result.error;
      
      return {
        passed,
        output: result.output,
        error: result.error
      };
    });
    
    setTestResults(results);
    
    const allPassed = results.every(r => r.passed);
    if (allPassed) {
      const timeSpent = Math.floor((Date.now() - startTime) / 1000);
      onComplete(true, attempts + 1, timeSpent);
    }
  };

  // Reset exercise
  const resetCode = () => {
    setUserCode(exercise.startingCode);
    setTestResults([]);
    setCurrentHint(0);
    setShowSolution(false);
    setShowHints(false);
  };

  // Get next hint
  const getNextHint = () => {
    if (currentHint < exercise.hints.length - 1) {
      setCurrentHint(prev => prev + 1);
    }
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

  const allTestsPassed = testResults.length > 0 && testResults.every(r => r.passed);

  return (
    <div className="w-full max-w-6xl mx-auto space-y-6">
      {/* Exercise Header */}
      <Card>
        <CardHeader>
          <div className="flex items-center justify-between">
            <CardTitle className="flex items-center gap-2">
              <Terminal className="h-5 w-5" />
              {exercise.title}
            </CardTitle>
            <div className="flex gap-2">
              <Badge variant="outline" className={`${getDifficultyColor(exercise.difficulty)} text-white`}>
                {exercise.difficulty.toUpperCase()}
              </Badge>
              <Badge variant="secondary">{exercise.language}</Badge>
            </div>
          </div>
        </CardHeader>
        <CardContent className="space-y-4">
          <p className="text-muted-foreground">{exercise.description}</p>
          
          <Alert className="border-blue-200 bg-blue-50 dark:bg-blue-900/20">
            <Lightbulb className="h-4 w-4" />
            <AlertDescription>
              <strong>Foco em Segurança:</strong> {exercise.securityFocus}
            </AlertDescription>
          </Alert>

          {/* Technical Concepts */}
          <div>
            <h4 className="font-semibold mb-2">Conceitos Técnicos:</h4>
            <div className="flex flex-wrap gap-2">
              {exercise.technicalConcepts.map((concept, index) => (
                <Badge key={index} variant="outline">
                  {concept}
                </Badge>
              ))}
            </div>
          </div>
        </CardContent>
      </Card>

      <div className="grid lg:grid-cols-2 gap-6">
        {/* Code Editor */}
        <Card>
          <CardHeader>
            <CardTitle className="text-lg">Editor de Código</CardTitle>
          </CardHeader>
          <CardContent className="space-y-4">
            <Textarea
              value={userCode}
              onChange={(e) => setUserCode(e.target.value)}
              className="font-mono text-sm min-h-[300px] bg-muted/50"
              placeholder="Escreva seu código aqui..."
            />
            
            <div className="flex gap-2">
              <Button onClick={runTests} className="flex items-center gap-2">
                <Play className="h-4 w-4" />
                Executar Testes
              </Button>
              <Button variant="outline" onClick={resetCode} className="flex items-center gap-2">
                <RotateCcw className="h-4 w-4" />
                Reset
              </Button>
              <Button 
                variant="outline" 
                onClick={() => setShowHints(!showHints)}
                className="flex items-center gap-2"
              >
                <Lightbulb className="h-4 w-4" />
                {showHints ? 'Ocultar Dicas' : 'Ver Dicas'}
              </Button>
            </div>
          </CardContent>
        </Card>

        {/* Test Results and Help */}
        <Card>
          <CardContent className="p-0">
            <Tabs defaultValue="tests" className="w-full">
              <TabsList className="grid w-full grid-cols-3">
                <TabsTrigger value="tests">Testes</TabsTrigger>
                <TabsTrigger value="hints">Dicas</TabsTrigger>
                <TabsTrigger value="solution">Solução</TabsTrigger>
              </TabsList>

              <TabsContent value="tests" className="p-6 space-y-4">
                <h3 className="font-semibold">Resultados dos Testes</h3>
                
                {testResults.length === 0 ? (
                  <p className="text-muted-foreground">Execute os testes para ver os resultados</p>
                ) : (
                  <div className="space-y-3">
                    {exercise.testCases.map((testCase, index) => {
                      const result = testResults[index];
                      return (
                        <div key={index} className={`p-4 rounded-lg border ${
                          result.passed 
                            ? 'border-green-200 bg-green-50 dark:bg-green-900/20' 
                            : 'border-red-200 bg-red-50 dark:bg-red-900/20'
                        }`}>
                          <div className="flex items-start gap-2">
                            {result.passed ? (
                              <CheckCircle className="h-5 w-5 text-green-600 mt-0.5" />
                            ) : (
                              <XCircle className="h-5 w-5 text-red-600 mt-0.5" />
                            )}
                            <div className="flex-1 min-w-0">
                              <p className="font-medium text-sm">{testCase.description}</p>
                              <div className="mt-2 space-y-1 text-sm">
                                <p><strong>Entrada:</strong> <code className="bg-muted px-1 rounded">{testCase.input}</code></p>
                                <p><strong>Esperado:</strong> <code className="bg-muted px-1 rounded">{testCase.expectedOutput}</code></p>
                                <p><strong>Obtido:</strong> <code className="bg-muted px-1 rounded">{result.output}</code></p>
                                {result.error && (
                                  <p className="text-red-600"><strong>Erro:</strong> {result.error}</p>
                                )}
                              </div>
                            </div>
                          </div>
                        </div>
                      );
                    })}
                  </div>
                )}

                {allTestsPassed && (
                  <Alert className="border-green-200 bg-green-50 dark:bg-green-900/20">
                    <CheckCircle className="h-4 w-4" />
                    <AlertDescription>
                      <strong>Parabéns!</strong> Todos os testes passaram! Você completou o exercício com segurança.
                    </AlertDescription>
                  </Alert>
                )}

                {attempts > 0 && (
                  <div className="text-sm text-muted-foreground">
                    Tentativas: {attempts}
                  </div>
                )}
              </TabsContent>

              <TabsContent value="hints" className="p-6 space-y-4">
                <div className="flex items-center justify-between">
                  <h3 className="font-semibold">Dicas</h3>
                  <Badge variant="secondary">{currentHint + 1} / {exercise.hints.length}</Badge>
                </div>
                
                {exercise.hints.slice(0, currentHint + 1).map((hint, index) => (
                  <Alert key={index} className="border-blue-200 bg-blue-50 dark:bg-blue-900/20">
                    <Lightbulb className="h-4 w-4" />
                    <AlertDescription>
                      <strong>Dica {index + 1}:</strong> {hint}
                    </AlertDescription>
                  </Alert>
                ))}
                
                {currentHint < exercise.hints.length - 1 && (
                  <Button variant="outline" onClick={getNextHint}>
                    Próxima Dica
                  </Button>
                )}
              </TabsContent>

              <TabsContent value="solution" className="p-6 space-y-4">
                <div className="flex items-center justify-between">
                  <h3 className="font-semibold">Solução</h3>
                  <Button
                    variant="outline"
                    size="sm"
                    onClick={() => setShowSolution(!showSolution)}
                    className="flex items-center gap-2"
                  >
                    {showSolution ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
                    {showSolution ? 'Ocultar' : 'Revelar'}
                  </Button>
                </div>

                {showSolution ? (
                  <div className="space-y-4">
                    <Alert className="border-yellow-200 bg-yellow-50 dark:bg-yellow-900/20">
                      <AlertTriangle className="h-4 w-4" />
                      <AlertDescription>
                        Tente resolver por conta própria antes de ver a solução!
                      </AlertDescription>
                    </Alert>
                    
                    <div className="bg-muted/50 p-4 rounded-lg">
                      <pre className="text-sm font-mono whitespace-pre-wrap overflow-x-auto">
                        {exercise.solution}
                      </pre>
                    </div>
                    
                    <Button 
                      variant="outline"
                      onClick={() => setUserCode(exercise.solution)}
                      className="w-full"
                    >
                      Copiar Solução para Editor
                    </Button>
                  </div>
                ) : (
                  <p className="text-muted-foreground">
                    A solução está disponível se você precisar de ajuda, mas tente resolver primeiro!
                  </p>
                )}
              </TabsContent>
            </Tabs>
          </CardContent>
        </Card>
      </div>
    </div>
  );
};