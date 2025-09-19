import { useState } from "react";
import { Code, AlertTriangle, CheckCircle, XCircle, Info } from "lucide-react";
import { Button } from "../ui/button";
import { Textarea } from "../ui/textarea";
import { Card, CardContent, CardHeader, CardTitle } from "../ui/card";
import { Alert, AlertDescription } from "../ui/alert";
import { Badge } from "../ui/badge";
import { useLanguage } from "../../hooks/useLanguage";

interface XSSModuleProps {
  difficulty: string;
}

export const XSSModule = ({ difficulty }: XSSModuleProps) => {
  const [userMessage, setUserMessage] = useState("");
  const [displayedMessage, setDisplayedMessage] = useState("");
  const [results, setResults] = useState<any>(null);
  const [isLoading, setIsLoading] = useState(false);
  const { t } = useLanguage();

  const simulateXSS = (message: string) => {
    setIsLoading(true);
    
    setTimeout(() => {
      let sanitizedMessage = message;
      let vulnerabilityDetected = false;
      let educationalNote = "";
      let actualDisplay = message;

      // Apply different security measures based on difficulty
      switch (difficulty) {
        case 'easy':
          // No sanitization - fully vulnerable
          actualDisplay = message; // Raw HTML will be rendered
          if (message.includes("<script>") || message.includes("javascript:") || message.includes("onerror") || message.includes("onload")) {
            vulnerabilityDetected = true;
            educationalNote = "XSS vulnerability detected! The script will execute when displayed. In a real application, this could steal cookies, redirect users, or perform actions on their behalf.";
          } else {
            educationalNote = "No XSS payload detected. Try injecting scripts like: <script>alert('XSS')</script>";
          }
          break;

        case 'medium':
          // Basic HTML encoding - partial protection
          sanitizedMessage = message
            .replace(/</g, "&lt;")
            .replace(/>/g, "&gt;");
          actualDisplay = sanitizedMessage;
          
          if (message.includes("<") || message.includes(">")) {
            educationalNote = "Basic HTML encoding applied. Script tags are escaped, but this protection can sometimes be bypassed with other XSS vectors.";
          } else {
            educationalNote = "Medium level applies basic HTML encoding but may still be vulnerable to attribute-based XSS.";
          }
          break;

        case 'hard':
          // Advanced sanitization
          sanitizedMessage = message
            .replace(/[<>'"&]/g, (match) => {
              const entities: {[key: string]: string} = {
                '<': '&lt;',
                '>': '&gt;',
                '"': '&quot;',
                "'": '&#x27;',
                '&': '&amp;'
              };
              return entities[match];
            })
            .replace(/javascript:/gi, '');
          actualDisplay = sanitizedMessage;
          
          if (message !== sanitizedMessage) {
            educationalNote = "Advanced sanitization applied: HTML entities encoded and javascript: URLs removed. This significantly reduces XSS risk.";
          } else {
            educationalNote = "Hard level uses comprehensive input sanitization, making XSS very difficult.";
          }
          break;

        case 'impossible':
          // Content Security Policy simulation + full sanitization
          sanitizedMessage = message.replace(/[<>'"&]/g, (match) => {
            const entities: {[key: string]: string} = {
              '<': '&lt;',
              '>': '&gt;',
              '"': '&quot;',
              "'": '&#x27;',
              '&': '&amp;'
            };
            return entities[match];
          });
          actualDisplay = sanitizedMessage;
          educationalNote = "Impossible level implements Content Security Policy (CSP) and full input sanitization. XSS attacks are blocked at multiple layers.";
          break;
      }

      setDisplayedMessage(actualDisplay);
      setResults({
        original: message,
        sanitized: sanitizedMessage,
        vulnerable: vulnerabilityDetected,
        severity: vulnerabilityDetected ? "critical" : "safe",
        educationalNote,
        exploitUsed: vulnerabilityDetected ? "Cross-Site Scripting (XSS)" : "None",
        prevention: "Use Content Security Policy (CSP), encode output, and validate/sanitize all user input."
      });
      
      setIsLoading(false);
    }, 1000);
  };

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (!userMessage.trim()) return;
    simulateXSS(userMessage);
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
            Message Board System
          </CardTitle>
        </CardHeader>
        <CardContent>
          <form onSubmit={handleSubmit} className="space-y-4">
            <div>
              <label htmlFor="message" className="block text-sm font-medium mb-2">
                {t("xss.message")}
              </label>
              <Textarea
                id="message"
                value={userMessage}
                onChange={(e) => setUserMessage(e.target.value)}
                placeholder={t("xss.placeholder")}
                className="font-mono min-h-[100px]"
                rows={4}
              />
            </div>
            <Button 
              type="submit" 
              disabled={isLoading || !userMessage.trim()}
              className="w-full bg-warning hover:bg-warning/90"
            >
              {isLoading ? "Processing..." : t("xss.submit")}
            </Button>
          </form>
        </CardContent>
      </Card>

      {/* Message Display Section */}
      {displayedMessage && (
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <Code className="h-5 w-5" />
              {t("xss.results")}
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="p-4 border border-border rounded-lg bg-muted/50">
              <h4 className="font-semibold mb-2">Message Preview:</h4>
              <div 
                className="p-3 bg-background border rounded min-h-[60px]"
                dangerouslySetInnerHTML={{ __html: displayedMessage }}
              />
            </div>
          </CardContent>
        </Card>
      )}

      {/* Results Analysis */}
      {results && (
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              {getSeverityIcon(results.severity)}
              Security Analysis
            </CardTitle>
          </CardHeader>
          <CardContent className="space-y-4">
            {/* Input Comparison */}
            <div className="grid md:grid-cols-2 gap-4">
              <div>
                <h4 className="font-semibold mb-2">Original Input:</h4>
                <code className="block p-3 bg-muted rounded text-sm font-mono break-all">
                  {results.original}
                </code>
              </div>
              <div>
                <h4 className="font-semibold mb-2">Processed Output:</h4>
                <code className="block p-3 bg-muted rounded text-sm font-mono break-all">
                  {results.sanitized}
                </code>
              </div>
            </div>

            {/* Educational Note */}
            {results.educationalNote && (
              <Alert className={results.vulnerable ? "border-danger bg-danger/10" : "border-success bg-success/10"}>
                <AlertTriangle className="h-4 w-4" />
                <AlertDescription>
                  <strong>Educational Note:</strong> {results.educationalNote}
                </AlertDescription>
              </Alert>
            )}

            {/* Prevention Tips */}
            <Alert className="border-info bg-info/10">
              <Info className="h-4 w-4" />
              <AlertDescription>
                <strong>Prevention:</strong> {results.prevention}
              </AlertDescription>
            </Alert>
          </CardContent>
        </Card>
      )}

      {/* Learning Tips */}
      <Card className="border-primary/20 bg-primary/5">
        <CardContent className="p-6">
          <h3 className="text-lg font-semibold mb-3">💡 Try These XSS Payloads:</h3>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-3 text-sm font-mono">
            <div className="p-2 bg-background rounded border">
              <strong>Basic script:</strong><br />
              <code>&lt;script&gt;alert('XSS')&lt;/script&gt;</code>
            </div>
            <div className="p-2 bg-background rounded border">
              <strong>Image onerror:</strong><br />
              <code>&lt;img src=x onerror=alert('XSS')&gt;</code>
            </div>
            <div className="p-2 bg-background rounded border">
              <strong>JavaScript URL:</strong><br />
              <code>&lt;a href="javascript:alert('XSS')"&gt;Click&lt;/a&gt;</code>
            </div>
            <div className="p-2 bg-background rounded border">
              <strong>Event handler:</strong><br />
              <code>&lt;div onmouseover=alert('XSS')&gt;Hover&lt;/div&gt;</code>
            </div>
            <div className="p-2 bg-background rounded border">
              <strong>SVG payload:</strong><br />
              <code>&lt;svg onload=alert('XSS')&gt;</code>
            </div>
            <div className="p-2 bg-background rounded border">
              <strong>Body onload:</strong><br />
              <code>&lt;body onload=alert('XSS')&gt;</code>
            </div>
          </div>
          
          <div className="mt-4 p-3 bg-warning/10 rounded border border-warning/20">
            <p className="text-sm text-warning-foreground">
              ⚠️ <strong>Educational Purpose Only:</strong> These payloads are for learning. Never use them on systems you don't own or without explicit permission.
            </p>
          </div>
        </CardContent>
      </Card>
    </div>
  );
};