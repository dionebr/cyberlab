import React, { useState, useRef, useEffect } from 'react';
import { Terminal, Play, Square, RotateCcw, Copy, Check } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Card, CardHeader, CardContent } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Alert, AlertDescription } from '@/components/ui/alert';

interface TerminalSandboxProps {
  title?: string;
  description?: string;
  initialCommands?: string[];
  expectedOutput?: string;
  hints?: string[];
  onCommandExecuted?: (command: string, output: string) => void;
  allowedCommands?: string[];
  environment?: 'linux' | 'sql' | 'web';
}

interface CommandHistory {
  id: string;
  command: string;
  output: string;
  timestamp: Date;
  isError: boolean;
}

export const TerminalSandbox: React.FC<TerminalSandboxProps> = ({
  title = 'Terminal Sandbox',
  description = 'Execute comandos em ambiente controlado',
  initialCommands = [],
  expectedOutput,
  hints = [],
  onCommandExecuted,
  allowedCommands,
  environment = 'linux'
}) => {
  const [history, setHistory] = useState<CommandHistory[]>([]);
  const [currentCommand, setCurrentCommand] = useState('');
  const [isExecuting, setIsExecuting] = useState(false);
  const [copiedCommand, setCopiedCommand] = useState<string | null>(null);
  const terminalRef = useRef<HTMLDivElement>(null);
  const inputRef = useRef<HTMLInputElement>(null);

  // Simulação de comandos Linux básicos
  const simulateLinuxCommand = (command: string): { output: string; isError: boolean } => {
    const cmd = command.trim().toLowerCase();
    
    if (cmd === 'ls' || cmd === 'ls -la') {
      return {
        output: 'drwxr-xr-x 2 user user 4096 Dec 25 12:00 documents\n-rw-r--r-- 1 user user  156 Dec 25 12:00 vulnerable.php\n-rw-r--r-- 1 user user  89 Dec 25 12:00 test.txt',
        isError: false
      };
    }
    
    if (cmd === 'pwd') {
      return { output: '/home/user/cyberlab', isError: false };
    }
    
    if (cmd === 'whoami') {
      return { output: 'cyberlab-user', isError: false };
    }
    
    if (cmd.startsWith('cat ')) {
      const file = cmd.split(' ')[1];
      if (file === 'vulnerable.php') {
        return {
          output: '<?php\n$user = $_GET[\'user\'];\necho "Hello " . $user;\n// Vulnerable to XSS!\n?>',
          isError: false
        };
      }
      if (file === 'test.txt') {
        return {
          output: 'This is a test file for cybersecurity learning.\nBe careful with user input!',
          isError: false
        };
      }
      return { output: `cat: ${file}: No such file or directory`, isError: true };
    }
    
    if (cmd.startsWith('echo ')) {
      const text = command.slice(5);
      return { output: text, isError: false };
    }
    
    if (cmd === 'ps aux' || cmd === 'ps') {
      return {
        output: 'USER       PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND\nroot         1  0.0  0.1   8892   3456 ?        Ss   12:00   0:01 /sbin/init\nwww-data   123  0.1  2.3  45678  12345 ?        S    12:05   0:02 apache2\nmysql      456  0.2  5.1  78901  23456 ?        Sl   12:05   0:03 mysqld',
        isError: false
      };
    }
    
    if (cmd.startsWith('grep ')) {
      return {
        output: 'vulnerable.php:3:echo "Hello " . $user;',
        isError: false
      };
    }

    // Comandos de segurança
    if (cmd.startsWith('sqlmap') || cmd.includes('sqlmap')) {
      return {
        output: '[*] Starting sqlmap scan...\n[INFO] Testing connection\n[WARNING] Potential SQL injection found!\nParameter: id (GET)\nType: boolean-based blind',
        isError: false
      };
    }

    if (cmd.startsWith('nmap ')) {
      return {
        output: 'Starting Nmap scan...\nNmap scan report for target\nHost is up (0.001s latency)\nPORT     STATE SERVICE\n22/tcp   open  ssh\n80/tcp   open  http\n3306/tcp open  mysql',
        isError: false
      };
    }

    // Comando não reconhecido
    return { 
      output: `bash: ${command}: command not found`, 
      isError: true 
    };
  };

  // Simulação de comandos SQL
  const simulateSQLCommand = (command: string): { output: string; isError: boolean } => {
    const sql = command.trim().toLowerCase();
    
    if (sql.includes('select') && sql.includes('users')) {
      if (sql.includes('or 1=1') || sql.includes('union')) {
        return {
          output: 'id | username | password | email\n1  | admin    | admin123 | admin@test.com\n2  | user     | pass123  | user@test.com\n3  | guest    | guest    | guest@test.com',
          isError: false
        };
      }
      return {
        output: 'id | username | email\n2  | user     | user@test.com',
        isError: false
      };
    }
    
    if (sql.includes('show tables')) {
      return {
        output: 'Tables_in_cyberlab\nusers\nproducts\nsessions\nlogs',
        isError: false
      };
    }
    
    if (sql.includes('describe') || sql.includes('desc')) {
      return {
        output: 'Field     | Type         | Null | Key | Default | Extra\nid        | int(11)      | NO   | PRI | NULL    | auto_increment\nusername  | varchar(50)  | NO   |     | NULL    |\npassword  | varchar(255) | NO   |     | NULL    |\nemail     | varchar(100) | YES  |     | NULL    |',
        isError: false
      };
    }

    return { 
      output: `ERROR 1064: You have an error in your SQL syntax`, 
      isError: true 
    };
  };

  const executeCommand = async (command: string) => {
    if (!command.trim()) return;
    
    setIsExecuting(true);
    
    // Verificar comandos permitidos se especificado
    if (allowedCommands && !allowedCommands.some(allowed => command.startsWith(allowed))) {
      const errorResult = {
        id: Date.now().toString(),
        command,
        output: `Comando não permitido neste exercício. Comandos permitidos: ${allowedCommands.join(', ')}`,
        timestamp: new Date(),
        isError: true
      };
      setHistory(prev => [...prev, errorResult]);
      setIsExecuting(false);
      return;
    }

    // Simular delay de execução
    await new Promise(resolve => setTimeout(resolve, 300 + Math.random() * 700));

    let result: { output: string; isError: boolean };
    
    switch (environment) {
      case 'sql':
        result = simulateSQLCommand(command);
        break;
      case 'linux':
      default:
        result = simulateLinuxCommand(command);
        break;
    }

    const historyEntry: CommandHistory = {
      id: Date.now().toString(),
      command,
      output: result.output,
      timestamp: new Date(),
      isError: result.isError
    };

    setHistory(prev => [...prev, historyEntry]);
    setIsExecuting(false);
    
    if (onCommandExecuted) {
      onCommandExecuted(command, result.output);
    }
  };

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    executeCommand(currentCommand);
    setCurrentCommand('');
  };

  const clearTerminal = () => {
    setHistory([]);
  };

  const copyCommand = async (command: string) => {
    try {
      await navigator.clipboard.writeText(command);
      setCopiedCommand(command);
      setTimeout(() => setCopiedCommand(null), 2000);
    } catch (err) {
      console.error('Failed to copy command:', err);
    }
  };

  const executeInitialCommand = (command: string) => {
    setCurrentCommand(command);
    executeCommand(command);
  };

  // Auto scroll para o final do terminal
  useEffect(() => {
    if (terminalRef.current) {
      terminalRef.current.scrollTop = terminalRef.current.scrollHeight;
    }
  }, [history]);

  const getPrompt = () => {
    switch (environment) {
      case 'sql':
        return 'mysql> ';
      case 'linux':
      default:
        return 'cyberlab@sandbox:~$ ';
    }
  };

  return (
    <Card className="w-full">
      <CardHeader className="pb-3">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2">
            <Terminal className="w-5 h-5" />
            <div>
              <h3 className="font-semibold">{title}</h3>
              {description && (
                <p className="text-sm text-muted-foreground">{description}</p>
              )}
            </div>
          </div>
          <div className="flex items-center gap-2">
            <Badge variant={environment === 'sql' ? 'default' : 'secondary'}>
              {environment.toUpperCase()}
            </Badge>
            <Button
              size="sm"
              variant="outline"
              onClick={clearTerminal}
              className="gap-1"
            >
              <RotateCcw className="w-3 h-3" />
              Clear
            </Button>
          </div>
        </div>
      </CardHeader>

      <CardContent className="space-y-4">
        {/* Comandos iniciais */}
        {initialCommands.length > 0 && (
          <div className="space-y-2">
            <p className="text-sm font-medium">Comandos sugeridos:</p>
            <div className="flex flex-wrap gap-2">
              {initialCommands.map((cmd, index) => (
                <Button
                  key={index}
                  size="sm"
                  variant="outline"
                  onClick={() => executeInitialCommand(cmd)}
                  className="gap-1 font-mono text-xs"
                >
                  <Play className="w-3 h-3" />
                  {cmd}
                </Button>
              ))}
            </div>
          </div>
        )}

        {/* Terminal */}
        <div className="bg-gray-900 rounded-lg overflow-hidden shadow-2xl border border-gray-700">
          {/* macOS Terminal Header */}
          <div className="bg-gray-800 px-4 py-2 flex items-center justify-between border-b border-gray-700">
            <div className="flex items-center gap-2">
              <div className="flex gap-2">
                <div className="w-3 h-3 bg-red-500 rounded-full"></div>
                <div className="w-3 h-3 bg-yellow-500 rounded-full"></div>
                <div className="w-3 h-3 bg-green-500 rounded-full"></div>
              </div>
              <span className="text-gray-300 text-sm font-medium ml-4">
                {title} — Terminal
              </span>
            </div>
            <div className="text-gray-400 text-xs">
              {environment.toUpperCase()}
            </div>
          </div>
          
          {/* Terminal Content */}
          <div 
            ref={terminalRef}
            className="bg-black text-green-400 font-mono text-sm p-4 h-80 overflow-y-auto scrollbar-thin scrollbar-thumb-gray-600 scrollbar-track-gray-800"
          >
            {/* Welcome message */}
            <div className="text-gray-500 text-xs mb-2">
              Last login: {new Date().toDateString()} on ttys000
            </div>
            
            {history.map((entry) => (
              <div key={entry.id} className="mb-3">
                <div className="flex items-center justify-between group">
                  <div className="flex items-center gap-2 flex-1">
                    <span className="text-green-400">cyberlab@security</span>
                    <span className="text-blue-400">:</span>
                    <span className="text-blue-400">~</span>
                    <span className="text-white">$</span>
                    <span className="text-gray-100 flex-1">{entry.command}</span>
                  </div>
                  <Button
                    size="sm"
                    variant="ghost"
                    className="opacity-0 group-hover:opacity-100 h-auto p-1 text-gray-400 hover:text-green-400"
                    onClick={() => copyCommand(entry.command)}
                  >
                    {copiedCommand === entry.command ? (
                      <Check className="w-3 h-3 text-green-400" />
                    ) : (
                      <Copy className="w-3 h-3" />
                    )}
                  </Button>
                </div>
                <pre className={`whitespace-pre-wrap mt-1 ${entry.isError ? 'text-red-400' : 'text-green-300'} pl-4`}>
                  {entry.output}
                </pre>
              </div>
            ))}
            
            {/* Input line */}
            <form onSubmit={handleSubmit} className="flex items-center">
              <div className="flex items-center gap-2 text-sm">
                <span className="text-green-400">cyberlab@security</span>
                <span className="text-blue-400">:</span>
                <span className="text-blue-400">~</span>
                <span className="text-white">$</span>
              </div>
              <input
                ref={inputRef}
                type="text"
                value={currentCommand}
                onChange={(e) => setCurrentCommand(e.target.value)}
                className="flex-1 ml-2 bg-transparent border-none outline-none text-green-400 font-mono placeholder-gray-500"
                placeholder={isExecuting ? 'Executando...' : 'Digite um comando...'}
                disabled={isExecuting}
                autoFocus
              />
            </form>
          </div>
        </div>

        {/* Hints */}
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

        {/* Expected output */}
        {expectedOutput && (
          <Alert>
            <AlertDescription>
              <strong>🎯 Resultado esperado:</strong>
              <pre className="mt-2 text-xs bg-muted p-2 rounded font-mono whitespace-pre-wrap">
                {expectedOutput}
              </pre>
            </AlertDescription>
          </Alert>
        )}
      </CardContent>
    </Card>
  );
};