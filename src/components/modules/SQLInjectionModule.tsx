import { useState } from "react";
import { Database, AlertTriangle, CheckCircle, XCircle, Info, Terminal } from "lucide-react";
import { Button } from "../ui/button";
import { Input } from "../ui/input";
import { Card, CardContent, CardHeader, CardTitle } from "../ui/card";
import { Alert, AlertDescription } from "../ui/alert";
import { Badge } from "../ui/badge";
import { useLanguage } from "../../hooks/useLanguage";

interface SQLInjectionModuleProps {
  difficulty: string;
}

export const SQLInjectionModule = ({ difficulty }: SQLInjectionModuleProps) => {
  const [userInput, setUserInput] = useState("");
  const [results, setResults] = useState<any>(null);
  const [isLoading, setIsLoading] = useState(false);
  const [endpoint, setEndpoint] = useState("search"); // search, details, reports
  const [searchField, setSearchField] = useState("username"); // username, email, role
  const { t } = useLanguage();

  // Base API URL - configuration for development and production
  const API_BASE_URL = import.meta.env.DEV ? 'http://localhost:5001' : '';

  const executeRealSQLQuery = async (input: string, endpointType: string, field: string) => {
    setIsLoading(true);
    
    try {
      let url = '';
      let options: RequestInit = {
        method: 'GET',
        headers: {
          'Content-Type': 'application/json',
          'Accept': 'application/json'
        }
      };

      // Selecionar endpoint baseado no tipo e dificuldade
      switch (endpointType) {
        case 'search':
          // Endpoint básico de busca - vulnerável
          url = `${API_BASE_URL}/api/vulnerable/users/search?${field}=${encodeURIComponent(input)}`;
          break;
        
        case 'details':
          // Endpoint de detalhes por ID - path parameter injection
          url = `${API_BASE_URL}/api/vulnerable/users/${encodeURIComponent(input)}`;
          break;
        
        case 'reports':
          // Endpoint de relatórios avançados - UNION injection
          url = `${API_BASE_URL}/api/vulnerable/reports/user-stats?${field}=${encodeURIComponent(input)}&order_by=username`;
          break;
        
        case 'logs':
          // Endpoint de logs - Blind SQL injection
          url = `${API_BASE_URL}/api/vulnerable/logs/search?user_id=${encodeURIComponent(input)}&sensitive=true`;
          break;
      }

      // Adicionar parâmetros específicos por dificuldade
      switch (difficulty) {
        case 'easy':
          // Modo mais vulnerável - sem proteções
          url += url.includes('?') ? '&debug=true&bypass_protection=true' : '?debug=true&bypass_protection=true';
          break;
        case 'medium':
          // Alguma proteção mas ainda vulnerável
          url += url.includes('?') ? '&sanitize=basic' : '?sanitize=basic';
          break;
        case 'hard':
          // Proteções avançadas mas ainda vulnerável
          url += url.includes('?') ? '&sanitize=advanced&validate=true' : '?sanitize=advanced&validate=true';
          break;
        case 'impossible':
          // Usar endpoint com prepared statements (se disponível)
          url += url.includes('?') ? '&prepared_statements=true' : '?prepared_statements=true';
          break;
      }

      console.log('🔍 Executing SQL query:', url);

      const response = await fetch(url, options);
      const data = await response.json();

      console.log('📊 API Response:', data);

      // Processar resposta
      const processedResults = {
        query_executed: data.query_executed || data.queries_executed?.select || 'Query hidden',
        data: data.users || data.user ? [data.user] : data.data || data.stats || [],
        success: data.success,
        vulnerable: data.debug?.sql_injection_detected || false,
        severity: determineSeverity(data, input),
        exploit_used: detectExploitType(input, data),
        raw_response: data,
        endpoint_used: endpointType,
        field_targeted: field,
        educational_note: generateEducationalNote(data, input, difficulty),
        prevention_tips: data.debug?.prevention || "Use parameterized queries and input validation",
        execution_time: data.execution_time_ms || 0
      };

      setResults(processedResults);
      
    } catch (error) {
      console.error('❌ SQL Query Error:', error);
      
      setResults({
        query_executed: 'Error executing query',
        data: [],
        success: false,
        vulnerable: true,
        severity: 'error',
        exploit_used: 'Connection Error',
        error: error instanceof Error ? error.message : 'Unknown error',
        educational_note: `Error connecting to vulnerable API: ${error instanceof Error ? error.message : 'Unknown error'}. Make sure the backend server is running on port 5000.`,
        prevention_tips: "Proper error handling should not reveal internal system details.",
        raw_response: null
      });
    } finally {
      setIsLoading(false);
    }
  };

  const determineSeverity = (data: any, input: string): string => {
    if (data.error || !data.success) return 'error';
    
    // Detectar indicators de SQL injection
    const hasInjection = input.includes("'") || input.includes("--") || 
                        input.toLowerCase().includes("union") || 
                        input.toLowerCase().includes("select") ||
                        input.toLowerCase().includes("drop") ||
                        input.toLowerCase().includes("insert") ||
                        input.toLowerCase().includes("update");
    
    if (hasInjection && data.success && (data.users?.length > 1 || data.data?.length > 0)) {
      return 'critical';
    }
    
    if (hasInjection) {
      return 'high';
    }
    
    return 'safe';
  };

  const detectExploitType = (input: string, data: any): string => {
    const lowerInput = input.toLowerCase();
    
    if (lowerInput.includes("union") && lowerInput.includes("select")) {
      return "UNION-based SQL Injection";
    }
    
    if (lowerInput.includes("' or '1'='1") || lowerInput.includes("or 1=1")) {
      return "Boolean-based SQL Injection";
    }
    
    if (lowerInput.includes("--") || lowerInput.includes("#")) {
      return "Comment-based SQL Injection";
    }
    
    if (lowerInput.includes("sleep(") || lowerInput.includes("benchmark(")) {
      return "Time-based Blind SQL Injection";
    }
    
    if (lowerInput.includes("'") && data.success) {
      return "Error-based SQL Injection";
    }
    
    return "Normal Query";
  };

  const generateEducationalNote = (data: any, input: string, difficulty: string): string => {
    if (data.error) {
      return `Connection error occurred. In a real attack, error messages like this could reveal system information.`;
    }

    const hasInjection = input.includes("'") || input.includes("--") || 
                        input.toLowerCase().includes("union") || 
                        input.toLowerCase().includes("select");

    if (hasInjection) {
      switch (difficulty) {
        case 'easy':
          return `🚨 SQL Injection successful! The query was executed without any sanitization. In a real application, this would give an attacker complete access to the database.`;
        case 'medium':
          return `⚠️ Partial protection detected, but the injection might still work. Some sanitization was applied, but it can often be bypassed.`;
        case 'hard':
          return `🔒 Advanced protections are in place, but determined attackers might still find ways to bypass them using sophisticated techniques.`;
        case 'impossible':
          return `✅ Prepared statements are being used. The input is treated as data, not executable code, making SQL injection nearly impossible.`;
      }
    }

    return `Normal query executed. No SQL injection patterns detected in the input.`;
  };

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (!userInput.trim()) return;
    executeRealSQLQuery(userInput, endpoint, searchField);
  };

  const getSeverityIcon = (severity: string) => {
    switch (severity) {
      case 'critical':
        return <XCircle className="h-5 w-5 text-danger" />;
      case 'high':
        return <AlertTriangle className="h-5 w-5 text-warning" />;
      case 'safe':
        return <CheckCircle className="h-5 w-5 text-success" />;
      default:
        return <Info className="h-5 w-5 text-info" />;
    }
  };

  return (
    <div className="max-w-4xl mx-auto space-y-6">
      {/* Header */}
      <div className="flex items-center gap-4 mb-8">
        <div className="p-3 bg-danger/10 rounded-lg">
          <Database className="h-8 w-8 text-danger" />
        </div>
        <div>
          <h1 className="text-3xl font-bold">{t("sql.title")}</h1>
          <p className="text-muted-foreground">{t("sql.description")}</p>
          <Badge variant="outline" className="mt-2">
            Level: {t(`difficulty.${difficulty}`)}
          </Badge>
        </div>
      </div>

      {/* Input Section */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Database className="h-5 w-5" />
            {t("sql_injection.user_lookup")}
          </CardTitle>
        </CardHeader>
        <CardContent>
          <form onSubmit={handleSubmit} className="space-y-4">
            {/* Endpoint Selection */}
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <div>
                <label htmlFor="endpoint" className="block text-sm font-medium mb-2">
                  Target Endpoint
                </label>
                <select 
                  id="endpoint"
                  value={endpoint}
                  onChange={(e) => setEndpoint(e.target.value)}
                  className="w-full p-2 border border-input bg-background rounded-md"
                >
                  <option value="search">User Search (GET)</option>
                  <option value="details">User Details (Path Param)</option>
                  <option value="reports">Reports (UNION)</option>
                  <option value="logs">Logs (Blind SQLi)</option>
                </select>
              </div>
              
              <div>
                <label htmlFor="field" className="block text-sm font-medium mb-2">
                  Search Field
                </label>
                <select 
                  id="field"
                  value={searchField}
                  onChange={(e) => setSearchField(e.target.value)}
                  className="w-full p-2 border border-input bg-background rounded-md"
                  disabled={endpoint === 'details' || endpoint === 'logs'}
                >
                  <option value="username">Username</option>
                  <option value="email">Email</option>
                  <option value="role">Role</option>
                  <option value="department">Department</option>
                </select>
              </div>
            </div>

            <div>
              <label htmlFor="user-input" className="block text-sm font-medium mb-2">
                {endpoint === 'details' ? 'User ID' : 
                 endpoint === 'logs' ? 'User ID (for logs)' :
                 `Search by ${searchField}`}
              </label>
              <Input
                id="user-input"
                type="text"
                value={userInput}
                onChange={(e) => setUserInput(e.target.value)}
                placeholder={
                  endpoint === 'details' ? "Enter user ID (try: 1 OR 1=1)" :
                  endpoint === 'logs' ? "Enter user ID (try: 1; SELECT SLEEP(5))" :
                  `Enter ${searchField} (try: admin' OR '1'='1)`
                }
                className="font-mono"
              />
            </div>
            
            <Button 
              type="submit" 
              disabled={isLoading || !userInput.trim()}
              className="w-full bg-danger hover:bg-danger/90"
            >
              {isLoading ? (
                <div className="flex items-center gap-2">
                  <Terminal className="h-4 w-4 animate-pulse" />
                  Executing SQL Query...
                </div>
              ) : (
                <div className="flex items-center gap-2">
                  <Database className="h-4 w-4" />
                  Execute Query
                </div>
              )}
            </Button>
          </form>
        </CardContent>
      </Card>

      {/* Results Section */}
      {results && (
        <div className="space-y-4">
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                {getSeverityIcon(results.severity)}
                {t("sql.results")}
              </CardTitle>
            </CardHeader>
            <CardContent className="space-y-4">
              {/* Query Display */}
              <div>
                <h4 className="font-semibold mb-2 flex items-center gap-2">
                  <Terminal className="h-4 w-4" />
                  Executed Query
                </h4>
                <code className="block p-3 bg-muted rounded text-sm font-mono whitespace-pre-wrap break-all">
                  {results.query_executed}
                </code>
                {results.endpoint_used && (
                  <div className="mt-2 flex gap-2">
                    <Badge variant="outline">Endpoint: {results.endpoint_used}</Badge>
                    <Badge variant="outline">Field: {results.field_targeted}</Badge>
                    {results.execution_time > 0 && (
                      <Badge variant="outline">Time: {results.execution_time}ms</Badge>
                    )}
                  </div>
                )}
              </div>

              {/* Data Results */}
              {results.data && results.data.length > 0 ? (
                <div>
                  <h4 className="font-semibold mb-2 flex items-center gap-2">
                    <Database className="h-4 w-4" />
                    Retrieved Data ({results.data.length} records)
                  </h4>
                  <div className="overflow-x-auto">
                    <table className="w-full border border-border rounded text-sm">
                      <thead className="bg-muted">
                        <tr>
                          {Object.keys(results.data[0]).map((key) => (
                            <th key={key} className="p-2 text-left font-medium">
                              {key}
                            </th>
                          ))}
                        </tr>
                      </thead>
                      <tbody>
                        {results.data.map((record: any, index: number) => (
                          <tr key={index} className="border-t border-border">
                            {Object.entries(record).map(([key, value]) => (
                              <td key={key} className="p-2">
                                {key === 'role' ? (
                                  <Badge variant={
                                    value === 'admin' || value === 'administrator' ? 'destructive' : 'secondary'
                                  }>
                                    {String(value)}
                                  </Badge>
                                ) : key.includes('password') || key.includes('ssn') || key.includes('credit_card') ? (
                                  <span className="text-danger font-mono">
                                    {String(value)} ⚠️
                                  </span>
                                ) : (
                                  String(value)
                                )}
                              </td>
                            ))}
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                </div>
              ) : results.success ? (
                <Alert>
                  <Info className="h-4 w-4" />
                  <AlertDescription>No records found for the given query.</AlertDescription>
                </Alert>
              ) : (
                <Alert className="border-danger bg-danger/10">
                  <XCircle className="h-4 w-4" />
                  <AlertDescription>
                    <strong>Query Failed:</strong> {results.error || 'Unknown error occurred'}
                  </AlertDescription>
                </Alert>
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
                    <strong>Educational Analysis:</strong> {results.educational_note}
                  </AlertDescription>
                </Alert>
              )}

              {/* Exploit Information */}
              {results.exploit_used && results.exploit_used !== 'Normal Query' && (
                <Alert className="border-info bg-info/10">
                  <Info className="h-4 w-4" />
                  <AlertDescription>
                    <strong>Exploit Detected:</strong> {results.exploit_used}
                  </AlertDescription>
                </Alert>
              )}

              {/* Prevention Tips */}
              {results.prevention_tips && (
                <Alert className="border-primary bg-primary/10">
                  <CheckCircle className="h-4 w-4" />
                  <AlertDescription>
                    <strong>Prevention:</strong> {results.prevention_tips}
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

      {/* Learning Tips */}
      <Card className="border-primary/20 bg-primary/5">
        <CardContent className="p-6">
          <h3 className="text-lg font-semibold mb-3">🎓 SQL Injection Payloads & Techniques</h3>
          
          {/* Basic Payloads */}
          <div className="mb-4">
            <h4 className="font-medium mb-2">Basic Authentication Bypass</h4>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-3 text-sm font-mono">
              <div className="p-2 bg-background rounded border">
                <strong>Boolean-based:</strong><br />
                <code>' OR '1'='1' --</code>
              </div>
              <div className="p-2 bg-background rounded border">
                <strong>Always true:</strong><br />
                <code>' OR 1=1 --</code>
              </div>
            </div>
          </div>

          {/* UNION Attacks */}
          <div className="mb-4">
            <h4 className="font-medium mb-2">UNION-based Attacks</h4>
            <div className="grid grid-cols-1 gap-3 text-sm font-mono">
              <div className="p-2 bg-background rounded border">
                <strong>Basic UNION:</strong><br />
                <code>' UNION SELECT username,password,email,role FROM users --</code>
              </div>
              <div className="p-2 bg-background rounded border">
                <strong>Extract sensitive data:</strong><br />
                <code>' UNION SELECT credit_card,ssn,salary,'admin' FROM users WHERE role='admin' --</code>
              </div>
            </div>
          </div>

          {/* Time-based Blind */}
          <div className="mb-4">
            <h4 className="font-medium mb-2">Time-based Blind SQL Injection</h4>
            <div className="grid grid-cols-1 gap-3 text-sm font-mono">
              <div className="p-2 bg-background rounded border">
                <strong>MySQL Sleep:</strong><br />
                <code>1; SELECT SLEEP(5) --</code>
              </div>
              <div className="p-2 bg-background rounded border">
                <strong>Conditional timing:</strong><br />
                <code>1 AND IF(1=1,SLEEP(3),0) --</code>
              </div>
            </div>
          </div>

          {/* Advanced Techniques */}
          <div className="mb-4">
            <h4 className="font-medium mb-2">Advanced Techniques</h4>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-3 text-sm font-mono">
              <div className="p-2 bg-background rounded border">
                <strong>Stacked Queries:</strong><br />
                <code>1; DROP TABLE users; --</code>
              </div>
              <div className="p-2 bg-background rounded border">
                <strong>Information Schema:</strong><br />
                <code>' UNION SELECT table_name,column_name,'','','' FROM information_schema.columns --</code>
              </div>
            </div>
          </div>

          {/* Endpoint-specific Tips */}
          <Alert className="mt-4">
            <Info className="h-4 w-4" />
            <AlertDescription>
              <strong>💡 Tips:</strong> Different endpoints may have different vulnerabilities. 
              Try the "Reports" endpoint for UNION attacks, or "Logs" for time-based blind injection. 
              The backend will show you the actual SQL queries being executed!
            </AlertDescription>
          </Alert>
        </CardContent>
      </Card>
    </div>
  );
};