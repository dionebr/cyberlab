import React, { useState, useRef, useEffect } from 'react';
import { 
  Play, 
  Square, 
  Save, 
  Download, 
  Upload, 
  Copy, 
  Check, 
  Code,
  FileText,
  Zap,
  AlertCircle
} from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Card, CardHeader, CardContent } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Alert, AlertDescription } from '@/components/ui/alert';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';

interface CodeEditorProps {
  title?: string;
  language?: 'javascript' | 'python' | 'php' | 'sql' | 'html' | 'css';
  initialCode?: string;
  expectedOutput?: string;
  testCases?: Array<{ input: string; expected: string; description: string }>;
  hints?: string[];
  onCodeExecuted?: (code: string, output: string, success: boolean) => void;
  readOnly?: boolean;
  showLineNumbers?: boolean;
  theme?: 'dark' | 'light';
}

interface ExecutionResult {
  output: string;
  error?: string;
  success: boolean;
  executionTime: number;
}

export const CodeEditor: React.FC<CodeEditorProps> = ({
  title = 'Code Editor',
  language = 'javascript',
  initialCode = '',
  expectedOutput,
  testCases = [],
  hints = [],
  onCodeExecuted,
  readOnly = false,
  showLineNumbers = true,
  theme = 'dark'
}) => {
  const [code, setCode] = useState(initialCode);
  const [output, setOutput] = useState('');
  const [isExecuting, setIsExecuting] = useState(false);
  const [executionHistory, setExecutionHistory] = useState<ExecutionResult[]>([]);
  const [copied, setCopied] = useState(false);
  const [activeTab, setActiveTab] = useState('editor');
  const textareaRef = useRef<HTMLTextAreaElement>(null);

  // Syntax highlighting patterns (simplified)
  const syntaxHighlight = (code: string, lang: string): string => {
    let highlighted = code;
    
    if (lang === 'javascript') {
      // Keywords
      highlighted = highlighted.replace(
        /\b(var|let|const|function|return|if|else|for|while|class|import|export|async|await)\b/g,
        '<span class="text-blue-400">$1</span>'
      );
      // Strings
      highlighted = highlighted.replace(
        /(["'`])((?:(?!\1)[^\\]|\\.)*)(\1)/g,
        '<span class="text-green-400">$1$2$3</span>'
      );
      // Comments
      highlighted = highlighted.replace(
        /(\/\/.*$|\/\*[\s\S]*?\*\/)/gm,
        '<span class="text-gray-500">$1</span>'
      );
    } else if (lang === 'sql') {
      // SQL Keywords
      highlighted = highlighted.replace(
        /\b(SELECT|FROM|WHERE|INSERT|UPDATE|DELETE|CREATE|ALTER|DROP|TABLE|DATABASE|INDEX|UNION|JOIN|INNER|LEFT|RIGHT|ORDER BY|GROUP BY|HAVING)\b/gi,
        '<span class="text-blue-400">$1</span>'
      );
      // Strings
      highlighted = highlighted.replace(
        /(["'])((?:(?!\1)[^\\]|\\.)*)(\1)/g,
        '<span class="text-green-400">$1$2$3</span>'
      );
    } else if (lang === 'php') {
      // PHP tags and keywords
      highlighted = highlighted.replace(
        /(&lt;\?php|\?&gt;)/g,
        '<span class="text-purple-400">$1</span>'
      );
      highlighted = highlighted.replace(
        /\b(echo|print|var_dump|isset|empty|function|class|public|private|protected|static)\b/g,
        '<span class="text-blue-400">$1</span>'
      );
      // Variables
      highlighted = highlighted.replace(
        /\$[a-zA-Z_][a-zA-Z0-9_]*/g,
        '<span class="text-yellow-400">$&</span>'
      );
    }
    
    return highlighted;
  };

  // Simular execução de código
  const executeCode = async (): Promise<ExecutionResult> => {
    const startTime = Date.now();
    
    // Simular diferentes resultados baseados na linguagem e código
    await new Promise(resolve => setTimeout(resolve, 500 + Math.random() * 1000));
    
    const executionTime = Date.now() - startTime;
    
    try {
      let output = '';
      let success = true;
      
      if (language === 'javascript') {
        // Simular execução JavaScript
        if (code.includes('console.log')) {
          const matches = code.match(/console\.log\((.*?)\)/g);
          if (matches) {
            output = matches.map(match => {
              const content = match.match(/console\.log\((.*?)\)/)?.[1] || '';
              return content.replace(/['"]/g, '');
            }).join('\n');
          }
        } else if (code.includes('alert')) {
          output = 'Alert box would be displayed (blocked in sandbox)';
        } else if (code.includes('document.')) {
          output = 'DOM manipulation detected - executed safely in sandbox';
        } else {
          output = 'Code executed successfully';
        }
        
        // Detectar possíveis vulnerabilidades
        if (code.includes('eval(') || code.includes('innerHTML')) {
          output += '\n⚠️ Warning: Potentially dangerous code detected!';
        }
      } else if (language === 'sql') {
        if (code.toLowerCase().includes('select')) {
          if (code.toLowerCase().includes('union') || code.includes('1=1')) {
            output = 'SQL Injection detected!\nid | username | password\n1  | admin    | admin123\n2  | user     | user456';
          } else {
            output = 'Query executed successfully\nRows affected: 1';
          }
        } else if (code.toLowerCase().includes('drop')) {
          output = 'ERROR: DROP statements not allowed in sandbox';
          success = false;
        } else {
          output = 'SQL command executed successfully';
        }
      } else if (language === 'php') {
        if (code.includes('echo')) {
          const matches = code.match(/echo\s+["']([^"']*?)["']/g);
          if (matches) {
            output = matches.map(match => {
              const content = match.match(/echo\s+["']([^"']*?)["']/)?.[1] || '';
              return content;
            }).join('\n');
          }
        } else if (code.includes('$_GET') || code.includes('$_POST')) {
          output = 'User input processing - be careful with XSS!';
          if (!code.includes('htmlspecialchars') && !code.includes('filter_')) {
            output += '\n⚠️ Warning: Input not sanitized!';
          }
        } else {
          output = 'PHP code executed successfully';
        }
      } else {
        output = `${language} code executed successfully`;
      }

      return { output, success, executionTime };
    } catch (error) {
      return {
        output: '',
        error: `Execution error: ${error}`,
        success: false,
        executionTime
      };
    }
  };

  const handleExecute = async () => {
    if (!code.trim()) return;
    
    setIsExecuting(true);
    const result = await executeCode();
    
    setOutput(result.error || result.output);
    setExecutionHistory(prev => [...prev.slice(-4), result]); // Keep last 5 results
    
    if (onCodeExecuted) {
      onCodeExecuted(code, result.output, result.success);
    }
    
    setIsExecuting(false);
  };

  const copyCode = async () => {
    try {
      await navigator.clipboard.writeText(code);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    } catch (err) {
      console.error('Failed to copy code:', err);
    }
  };

  const downloadCode = () => {
    const blob = new Blob([code], { type: 'text/plain' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `code.${language}`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  };

  const handleFileUpload = (event: React.ChangeEvent<HTMLInputElement>) => {
    const file = event.target.files?.[0];
    if (file) {
      const reader = new FileReader();
      reader.onload = (e) => {
        const content = e.target?.result as string;
        setCode(content);
      };
      reader.readAsText(file);
    }
  };

  // Auto-resize textarea
  useEffect(() => {
    if (textareaRef.current) {
      textareaRef.current.style.height = 'auto';
      textareaRef.current.style.height = `${textareaRef.current.scrollHeight}px`;
    }
  }, [code]);

  const getLanguageColor = () => {
    const colors = {
      javascript: 'bg-yellow-500',
      python: 'bg-blue-500',
      php: 'bg-purple-500',
      sql: 'bg-orange-500',
      html: 'bg-red-500',
      css: 'bg-blue-600'
    };
    return colors[language] || 'bg-gray-500';
  };

  return (
    <Card className="w-full">
      <CardHeader className="pb-3">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2">
            <Code className="w-5 h-5" />
            <div>
              <h3 className="font-semibold">{title}</h3>
              <p className="text-sm text-muted-foreground">
                Interactive editor for code practice
              </p>
            </div>
          </div>
          <div className="flex items-center gap-2">
            <Badge className={getLanguageColor()}>
              {language.toUpperCase()}
            </Badge>
            {!readOnly && (
              <div className="flex gap-1">
                <Button
                  size="sm"
                  variant="outline"
                  onClick={copyCode}
                  className="gap-1"
                >
                  {copied ? <Check className="w-3 h-3" /> : <Copy className="w-3 h-3" />}
                </Button>
                <Button
                  size="sm"
                  variant="outline"
                  onClick={downloadCode}
                  className="gap-1"
                >
                  <Download className="w-3 h-3" />
                </Button>
                <label className="cursor-pointer">
                  <Button size="sm" variant="outline" className="gap-1" asChild>
                    <span>
                      <Upload className="w-3 h-3" />
                    </span>
                  </Button>
                  <input
                    type="file"
                    accept=".js,.py,.php,.sql,.html,.css,.txt"
                    onChange={handleFileUpload}
                    className="hidden"
                  />
                </label>
              </div>
            )}
          </div>
        </div>
      </CardHeader>

      <CardContent>
        <Tabs value={activeTab} onValueChange={setActiveTab} className="w-full">
          <TabsList className="grid w-full grid-cols-3">
            <TabsTrigger value="editor" className="gap-2">
              <FileText className="w-4 h-4" />
              Editor
            </TabsTrigger>
            <TabsTrigger value="output" className="gap-2">
              <Zap className="w-4 h-4" />
              Saída
            </TabsTrigger>
            <TabsTrigger value="tests" className="gap-2">
              <AlertCircle className="w-4 h-4" />
              Testes
            </TabsTrigger>
          </TabsList>

          <TabsContent value="editor" className="space-y-4">
            <div className="relative">
              <div 
                className={`font-mono text-sm border rounded p-4 min-h-[300px] ${
                  theme === 'dark' ? 'bg-gray-900 border-gray-700' : 'bg-gray-50 border-gray-300'
                }`}
              >
                {showLineNumbers && (
                  <div className="absolute left-2 top-4 text-gray-500 text-sm font-mono leading-6 pointer-events-none">
                    {code.split('\n').map((_, index) => (
                      <div key={index}>{index + 1}</div>
                    ))}
                  </div>
                )}
                <textarea
                  ref={textareaRef}
                  value={code}
                  onChange={(e) => setCode(e.target.value)}
                  readOnly={readOnly}
                  className={`w-full h-full resize-none outline-none bg-transparent font-mono text-sm ${
                    showLineNumbers ? 'pl-8' : ''
                  } ${theme === 'dark' ? 'text-white' : 'text-black'}`}
                  placeholder={`Digite seu código ${language} aqui...`}
                  spellCheck={false}
                />
              </div>
            </div>

            {!readOnly && (
              <div className="flex gap-2">
                <Button
                  onClick={handleExecute}
                  disabled={isExecuting || !code.trim()}
                  className="gap-2"
                >
                  {isExecuting ? (
                    <Square className="w-4 h-4" />
                  ) : (
                    <Play className="w-4 h-4" />
                  )}
                  {isExecuting ? 'Executando...' : 'Executar Código'}
                </Button>
              </div>
            )}
          </TabsContent>

          <TabsContent value="output" className="space-y-4">
            <div className="space-y-4">
              <div className={`font-mono text-sm border rounded p-4 min-h-[200px] ${
                theme === 'dark' ? 'bg-black border-gray-700 text-green-400' : 'bg-gray-50 border-gray-300'
              }`}>
                {output ? (
                  <pre className="whitespace-pre-wrap">{output}</pre>
                ) : (
                  <div className="text-gray-500 italic">
                    Execute o código para ver a saída aqui...
                  </div>
                )}
              </div>

              {expectedOutput && (
                <Alert>
                  <AlertCircle className="h-4 w-4" />
                  <AlertDescription>
                    <strong>Resultado esperado:</strong>
                    <pre className="mt-2 text-xs bg-muted p-2 rounded font-mono">
                      {expectedOutput}
                    </pre>
                  </AlertDescription>
                </Alert>
              )}

              {executionHistory.length > 0 && (
                <div className="space-y-2">
                  <h4 className="text-sm font-medium">Execution History:</h4>
                  {executionHistory.slice(-3).map((result, index) => (
                    <div key={index} className={`text-xs p-2 rounded border ${
                      result.success ? 'border-green-200 bg-green-50' : 'border-red-200 bg-red-50'
                    }`}>
                      <div className="flex justify-between">
                        <span className={result.success ? 'text-green-700' : 'text-red-700'}>
                          {result.success ? '✓ Sucesso' : '✗ Erro'}
                        </span>
                        <span className="text-gray-500">{result.executionTime}ms</span>
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </div>
          </TabsContent>

          <TabsContent value="tests" className="space-y-4">
            {testCases.length > 0 ? (
              <div className="space-y-4">
                <h4 className="font-medium">Casos de teste:</h4>
                {testCases.map((testCase, index) => (
                  <div key={index} className="border rounded p-3 space-y-2">
                    <div className="font-medium text-sm">{testCase.description}</div>
                    <div className="text-xs text-muted-foreground">
                      <strong>Entrada:</strong> {testCase.input}
                    </div>
                    <div className="text-xs text-muted-foreground">
                      <strong>Esperado:</strong> {testCase.expected}
                    </div>
                  </div>
                ))}
              </div>
            ) : (
              <div className="text-center py-8 text-muted-foreground">
                <AlertCircle className="w-8 h-8 mx-auto mb-2" />
                <p>Nenhum caso de teste definido para este exercício</p>
              </div>
            )}

            {hints.length > 0 && (
              <Alert>
                <AlertDescription>
                  <strong>💡 Dicas:</strong>
                  <ul className="mt-2 ml-4 list-disc">
                    {hints.map((hint, index) => (
                      <li key={index} className="text-sm">{hint}</li>
                    ))}
                  </ul>
                </AlertDescription>
              </Alert>
            )}
          </TabsContent>
        </Tabs>
      </CardContent>
    </Card>
  );
};