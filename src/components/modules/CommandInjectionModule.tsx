import { useState } from "react";
import { Terminal, AlertTriangle, CheckCircle, XCircle, Info, Wifi, Server, Shield, Command, Network, AlertCircle } from "lucide-react";
import { Button } from "../ui/button";
import { Input } from "../ui/input";
import { Textarea } from "../ui/textarea";
import { Card, CardContent, CardHeader, CardTitle } from "../ui/card";
import { Alert, AlertDescription } from "../ui/alert";
import { Badge } from "../ui/badge";
import { useLanguage } from "../../hooks/useLanguage";

interface CommandInjectionModuleProps {
  difficulty: string;
}

export const CommandInjectionModule = ({ difficulty }: CommandInjectionModuleProps) => {
  const [userInput, setUserInput] = useState("");
  const [cmdType, setCmdType] = useState("ping"); // ping, network-tools, system-info
  const [toolType, setToolType] = useState("ping"); // para network-tools
  const [infoType, setInfoType] = useState("basic"); // para system-info
  const [targetField, setTargetField] = useState("host"); // host, target, options, custom
  const [results, setResults] = useState<any>(null);
  const [isLoading, setIsLoading] = useState(false);
  const { t } = useLanguage();

  // API base URL
  const API_BASE_URL = import.meta.env.DEV ? 'http://localhost:5001' : '';

  // Get severity-based icon
  const getSeverityIcon = (severity: string) => {
    switch (severity) {
      case 'critical':
        return <XCircle className="h-4 w-4 text-red-500" />;
      case 'high':
        return <AlertTriangle className="h-4 w-4 text-orange-500" />;
      case 'medium':
        return <AlertCircle className="h-4 w-4 text-yellow-500" />;
      case 'low':
        return <Info className="h-4 w-4 text-blue-500" />;
      case 'error':
        return <XCircle className="h-4 w-4 text-red-600" />;
      default:
        return <Info className="h-4 w-4 text-gray-500" />;
    }
  };

  // Command execution with real API
  const executeRealCommand = async (formData: FormData): Promise<any> => {
    setIsLoading(true);
    
    try {
      // Extract form data
      const input = formData.get('input') as string;
      const type = formData.get('type') as string || cmdType;
      const tool = formData.get('tool') as string || toolType;
      const info = formData.get('info') as string || infoType;
      const field = formData.get('field') as string || targetField;
      
      console.log('🚨 Executing Command Injection:', { input, type, tool, info, field, difficulty });

      let url = '';
      let options: RequestInit = {
        headers: {
          'Content-Type': 'application/json',
          'Accept': 'application/json'
        }
      };

      switch (type) {
        case 'ping':
          // Ping command injection
          url = `${API_BASE_URL}/api/cmd/ping`;
          options.method = 'POST';
          options.body = JSON.stringify({
            host: input,
            count: 4,
            timeout: 5,
            difficulty: difficulty
          });
          break;

        case 'network-tools':
          // Network tools command injection
          url = `${API_BASE_URL}/api/cmd/network-tools`;
          options.method = 'POST';
          
          if (tool === 'custom') {
            options.body = JSON.stringify({
              tool: 'custom',
              custom_command: input,
              difficulty: difficulty
            });
          } else {
            let requestData: any = {
              tool: tool,
              difficulty: difficulty
            };
            
            if (field === 'target') {
              requestData.target = input;
            } else if (field === 'options') {
              requestData.options = input;
            }
            
            options.body = JSON.stringify(requestData);
          }
          break;

        case 'system-info':
          // System info command injection
          url = `${API_BASE_URL}/api/cmd/system-info`;
          const params = new URLSearchParams();
          if (info === 'custom') {
            params.set('cmd', input);
          } else {
            params.set('detail', input.includes(';') || input.includes('&&') ? input : info);
          }
          url += `?${params}`;
          options.method = 'GET';
          break;

        default:
          throw new Error(`Unsupported command type: ${type}`);
      }

      console.log('📡 Making API request:', url);
      const response = await fetch(url, options);
      
      if (!response.ok) {
        throw new Error(`HTTP ${response.status}: ${response.statusText}`);
      }
      
      const data = await response.json();
      console.log('📥 API Response:', data);
      
      // Process and format results
      const processedResults = {
        command_type: type,
        tool_used: tool !== 'ping' ? tool : undefined,
        info_type: info !== 'basic' ? info : undefined,
        field_targeted: field,
        command_executed: data.command_executed || data.executed_command || `${type} command with input: ${input}`,
        stdout: data.stdout || data.output,
        stderr: data.stderr || data.error_output,
        success: data.success,
        vulnerable: detectCommandInjection(input, data),
        severity: determineCommandSeverity(input, data),
        exploit_used: detectCommandExploitType(input, data),
        raw_response: data,
        execution_time: data.execution_time || 0,
        system_info: data.system_info,
        educational_note: generateCommandEducationalNote(input, type, difficulty, data),
        prevention_tips: data.debug?.prevention || "Use parameterized commands and strict input validation"
      };

      setResults(processedResults);
      
    } catch (error) {
      console.error('❌ Command Execution Error:', error);
      
      setResults({
        command_type: cmdType,
        input: userInput,
        error: error instanceof Error ? error.message : 'Unknown error',
        educational_note: `Error executing command: ${error instanceof Error ? error.message : 'Unknown error'}. Make sure the backend server is running on port 5001.`,
        severity: 'error',
        vulnerable: false
      });
    } finally {
      setIsLoading(false);
    }
  };

  const detectCommandInjection = (input: string, data: any): boolean => {
    if (data.debug?.command_injection_detected) return true;
    
    const injectionPatterns = [';', '&&', '||', '|', '`', '$', '$(', '${'];
    return injectionPatterns.some(pattern => input.includes(pattern));
  };

  const determineCommandSeverity = (input: string, data: any): string => {
    if (data.error || !data.success) return 'error';
    
    if (detectCommandInjection(input, data)) {
      if (input.includes('/etc/passwd') || input.includes('rm -rf') || 
          input.includes('cat') || input.includes('whoami') || 
          input.includes('id') || input.includes('uname')) {
        return 'critical';
      }
      if (input.includes('&&') || input.includes('||') || input.includes(';')) {
        return 'high';
      }
      return 'medium';
    }
    
    return 'low';
  };

  const detectCommandExploitType = (input: string, data: any): string => {
    if (!detectCommandInjection(input, data)) return 'Normal Command';
    
    if (input.includes(';')) return 'Command Separator (;)';
    if (input.includes('&&')) return 'Logical AND (&&)';
    if (input.includes('||')) return 'Logical OR (||)';
    if (input.includes('|')) return 'Pipe Operator (|)';
    if (input.includes('`') || input.includes('$(')) return 'Command Substitution';
    if (input.includes('&')) return 'Background Execution (&)';
    
    return 'Advanced Injection';
  };

  const generateCommandEducationalNote = (input: string, type: string, difficulty: string, data: any): string => {
    if (data.error) return `Command execution failed: ${data.error}`;
    
    if (detectCommandInjection(input, data)) {
      switch (difficulty) {
        case 'easy':
          return `🚨 Command injection successful! Easy mode has minimal filtering, allowing most injection techniques. Your payload "${input}" was executed.`;
        case 'medium':
          return `⚠️ Command injection detected! Medium difficulty may have basic filtering, but your payload potentially bypassed it. Advanced techniques often work against incomplete filters.`;
        case 'hard':
          return `🔒 Advanced command injection attempt! Hard mode implements strong filtering, but sophisticated techniques might still succeed. This demonstrates the difficulty of perfect input validation.`;
        case 'impossible':
          return `✅ Impossible mode uses allowlist validation and parameterized commands. Command injection should be blocked completely at this level.`;
      }
    }
    
    return `Command executed normally. No injection patterns detected in: "${input}"`;
  };

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (!userInput.trim()) return;
    
    // Create FormData for the API call
    const formData = new FormData();
    formData.set('input', userInput);
    formData.set('type', cmdType);
    formData.set('tool', toolType);
    formData.set('info', infoType);
    formData.set('field', targetField);
    
    executeRealCommand(formData);
  };

  return (
    <div className="max-w-4xl mx-auto space-y-6">
      {/* Header */}
      <div className="flex items-center gap-4 mb-8">
        <div className="p-3 bg-accent/10 rounded-lg">
          <Terminal className="h-8 w-8 text-accent" />
        </div>
        <div>
          <h1 className="text-3xl font-bold">{t("command_injection.title")}</h1>
          <p className="text-muted-foreground">{t("command_injection.description")}</p>
          <Badge variant="outline" className="mt-2">
            Difficulty: {difficulty}
          </Badge>
        </div>
      </div>

      {/* Command Injection Form */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Command className="h-5 w-5" />
            Command Injection Interface
          </CardTitle>
        </CardHeader>
        <CardContent>
          <form onSubmit={handleSubmit} className="space-y-6">
            {/* Command Type Selection */}
            <div className="space-y-2">
              <label htmlFor="cmd-type" className="text-sm font-medium">
                Command Type
              </label>
              <select
                id="cmd-type"
                value={cmdType}
                onChange={(e) => setCmdType(e.target.value)}
                className="w-full p-2 border rounded-md"
              >
                <option value="ping">Ping Command</option>
                <option value="network-tools">Network Tools</option>
                <option value="system-info">System Information</option>
              </select>
            </div>

            {/* Tool Selection for Network Tools */}
            {cmdType === 'network-tools' && (
              <div className="space-y-2">
                <label htmlFor="tool-type" className="text-sm font-medium">
                  Tool Selection
                </label>
                <select
                  id="tool-type"
                  value={toolType}
                  onChange={(e) => setToolType(e.target.value)}
                  className="w-full p-2 border rounded-md"
                >
                  <option value="nmap">Nmap Scanner</option>
                  <option value="netstat">Netstat</option>
                  <option value="traceroute">Traceroute</option>
                  <option value="custom">Custom Command</option>
                </select>
              </div>
            )}

            {/* Info Type Selection for System Info */}
            {cmdType === 'system-info' && (
              <div className="space-y-2">
                <label htmlFor="info-type" className="text-sm font-medium">
                  Information Type
                </label>
                <select
                  id="info-type"
                  value={infoType}
                  onChange={(e) => setInfoType(e.target.value)}
                  className="w-full p-2 border rounded-md"
                >
                  <option value="basic">Basic System Info</option>
                  <option value="processes">Process Information</option>
                  <option value="network">Network Configuration</option>
                  <option value="custom">Custom Query</option>
                </select>
              </div>
            )}

            {/* Field Targeting for Network Tools */}
            {cmdType === 'network-tools' && toolType !== 'custom' && (
              <div className="space-y-2">
                <label htmlFor="target-field" className="text-sm font-medium">
                  Target Field
                </label>
                <select
                  id="target-field"
                  value={targetField}
                  onChange={(e) => setTargetField(e.target.value)}
                  className="w-full p-2 border rounded-md"
                >
                  <option value="target">Target/Host Field</option>
                  <option value="options">Options/Parameters Field</option>
                </select>
              </div>
            )}

            {/* User Input */}
            <div className="space-y-2">
              <label htmlFor="user-input" className="text-sm font-medium">
                {cmdType === 'ping' ? 'Host/IP Address:' : 
                 cmdType === 'network-tools' && toolType === 'custom' ? 'Custom Command:' :
                 cmdType === 'network-tools' ? `${targetField === 'target' ? 'Target' : 'Options'}:` :
                 'System Query:'}
              </label>
              <Input
                id="user-input"
                value={userInput}
                onChange={(e) => setUserInput(e.target.value)}
                placeholder={
                  cmdType === 'ping' ? "e.g., 127.0.0.1 or 127.0.0.1; whoami" :
                  cmdType === 'network-tools' && toolType === 'custom' ? "e.g., nmap -sn 127.0.0.1" :
                  cmdType === 'network-tools' ? "e.g., 192.168.1.1 or 192.168.1.1 && id" :
                  "e.g., basic or /etc/passwd"
                }
                disabled={isLoading}
                className="font-mono text-sm"
              />
            </div>

            {/* Submit Button */}
            <Button type="submit" disabled={isLoading || !userInput.trim()} className="w-full">
              {isLoading ? 'Executing Command...' : `Execute ${cmdType} Command`}
            </Button>
          </form>
        </CardContent>
      </Card>

      {/* Command Injection Results */}
      {results && (
        <div className="space-y-4">
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                {getSeverityIcon(results.severity)}
                Command Execution Results
              </CardTitle>
            </CardHeader>
            <CardContent className="space-y-4">
              {/* Attack Summary */}
              <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
                <div>
                  <h4 className="font-semibold mb-1">Command Type</h4>
                  <Badge variant="outline">{results.command_type}</Badge>
                </div>
                <div>
                  <h4 className="font-semibold mb-1">Tool/Method</h4>
                  <Badge variant="outline">{results.tool_used || results.info_type || 'ping'}</Badge>
                </div>
                <div>
                  <h4 className="font-semibold mb-1">Injection Point</h4>
                  <Badge variant="outline">{results.field_targeted}</Badge>
                </div>
                <div>
                  <h4 className="font-semibold mb-1">Severity</h4>
                  <Badge variant={
                    results.severity === 'critical' ? 'destructive' :
                    results.severity === 'high' ? 'default' : 'secondary'
                  }>
                    {results.severity}
                  </Badge>
                </div>
              </div>

              {/* Executed Command */}
              <div>
                <h4 className="font-semibold mb-2 flex items-center gap-2">
                  <Terminal className="h-4 w-4" />
                  Executed Command(s)
                </h4>
                <code className="block p-3 bg-muted rounded text-sm font-mono break-all whitespace-pre-wrap">
                  {results.command_executed}
                </code>
                {results.execution_time > 0 && (
                  <p className="text-sm text-muted-foreground mt-1">
                    Execution time: {results.execution_time}ms
                  </p>
                )}
              </div>

              {/* Command Output */}
              {results.stdout && (
                <div>
                  <h4 className="font-semibold mb-2 flex items-center gap-2">
                    <CheckCircle className="h-4 w-4 text-success" />
                    Command Output (stdout)
                  </h4>
                  <pre className="p-3 bg-muted rounded text-sm font-mono whitespace-pre-wrap overflow-auto max-h-64">
                    {results.stdout}
                  </pre>
                </div>
              )}

              {/* Error Output */}
              {results.stderr && (
                <div>
                  <h4 className="font-semibold mb-2 flex items-center gap-2">
                    <XCircle className="h-4 w-4 text-danger" />
                    Error Output (stderr)
                  </h4>
                  <pre className="p-3 bg-danger/10 border border-danger/20 rounded text-sm font-mono whitespace-pre-wrap">
                    {results.stderr}
                  </pre>
                </div>
              )}

              {/* System Information */}
              {results.system_info && (
                <div>
                  <h4 className="font-semibold mb-2 flex items-center gap-2">
                    <Server className="h-4 w-4" />
                    System Information Exposed
                  </h4>
                  <div className="p-3 bg-warning/10 border border-warning/20 rounded text-sm">
                    <div className="grid grid-cols-2 md:grid-cols-4 gap-2">
                      <div><strong>Platform:</strong> {results.system_info.platform}</div>
                      <div><strong>Architecture:</strong> {results.system_info.arch}</div>
                      <div><strong>Hostname:</strong> {results.system_info.hostname}</div>
                      <div><strong>Uptime:</strong> {Math.floor((results.system_info.uptime || 0) / 3600)}h</div>
                    </div>
                  </div>
                </div>
              )}

              {/* Educational Note */}
              {results.educational_note && (
                <Alert className={
                  results.severity === 'critical' ? "border-danger bg-danger/10" :
                  results.severity === 'high' ? "border-warning bg-warning/10" :
                  results.severity === 'error' ? "border-destructive bg-destructive/10" :
                  "border-success bg-success/10"
                }>
                  <AlertTriangle className="h-4 w-4" />
                  <AlertDescription>
                    <strong>Analysis:</strong> {results.educational_note}
                  </AlertDescription>
                </Alert>
              )}

              {/* Exploit Information */}
              {results.exploit_used && results.exploit_used !== 'Normal Command' && (
                <Alert className="border-info bg-info/10">
                  <Command className="h-4 w-4" />
                  <AlertDescription>
                    <strong>Exploit Technique:</strong> {results.exploit_used}
                  </AlertDescription>
                </Alert>
              )}

              {/* Prevention Tips */}
              {results.prevention_tips && (
                <Alert className="border-primary bg-primary/10">
                  <Shield className="h-4 w-4" />
                  <AlertDescription>
                    <strong>Prevention:</strong> {results.prevention_tips}
                  </AlertDescription>
                </Alert>
              )}

              {/* Error Display */}
              {results.error && (
                <Alert className="border-destructive bg-destructive/10">
                  <XCircle className="h-4 w-4" />
                  <AlertDescription>
                    <strong>Connection Error:</strong> {results.error}
                  </AlertDescription>
                </Alert>
              )}

              {/* Raw API Response (Debug) */}
              {results.raw_response && import.meta.env.DEV && (
                <details className="mt-4">
                  <summary className="cursor-pointer text-sm text-muted-foreground hover:text-foreground">
                    🐛 Raw API Response (Dev Mode)
                  </summary>
                  <pre className="mt-2 p-3 bg-muted rounded text-xs overflow-auto max-h-40">
                    {JSON.stringify(results.raw_response, null, 2)}
                  </pre>
                </details>
              )}
            </CardContent>
          </Card>
        </div>
      )}

      {/* Educational Examples */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Info className="h-5 w-5" />
            Common Command Injection Techniques
          </CardTitle>
        </CardHeader>
        <CardContent>
          <p className="text-sm text-muted-foreground mb-4">
            Try these common command injection patterns to test different vulnerability scenarios:
          </p>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div className="p-2 bg-background rounded border">
              <strong>Command Separator</strong><br />
              <code>127.0.0.1; cat /etc/passwd</code>
            </div>
            <div className="p-2 bg-background rounded border">
              <strong>Logical AND</strong><br />
              <code>127.0.0.1 && whoami</code>
            </div>
            <div className="p-2 bg-background rounded border">
              <strong>Pipe Operator</strong><br />
              <code>127.0.0.1 | ls -la</code>
            </div>
            <div className="p-2 bg-background rounded border">
              <strong>Background Execution</strong><br />
              <code>127.0.0.1 & ps aux</code>
            </div>
          </div>
        </CardContent>
      </Card>
    </div>
  );
};