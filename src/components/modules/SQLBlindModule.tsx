import { useState } from "react";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Alert, AlertDescription } from "@/components/ui/alert";
import { Database, Eye, Clock, AlertTriangle, CheckCircle, XCircle } from "lucide-react";
import { useLanguage } from "@/hooks/useLanguage";

interface SQLBlindModuleProps {
  difficulty: string;
}

interface BlindResult {
  query: string;
  response: string;
  timing: number;
  vulnerability: boolean;
  severity: string;
  notes: string[];
  prevention: string[];
  technique: string;
}

export const SQLBlindModule = ({ difficulty }: SQLBlindModuleProps) => {
  const { t } = useLanguage();
  const [userId, setUserId] = useState("");
  const [results, setResults] = useState<BlindResult | null>(null);
  const [isLoading, setIsLoading] = useState(false);

  const simulateBlindSQLInjection = (input: string) => {
    setIsLoading(true);
    
    setTimeout(() => {
      let query = "";
      let response = "";
      let timing = 0;
      let vulnerability = false;
      let severity = "info";
      let notes: string[] = [];
      let prevention: string[] = [];
      let technique = "";

      switch (difficulty.toLowerCase()) {
        case 'low':
          // Boolean-based blind SQL injection
          if (input.includes("' AND '1'='1")) {
            vulnerability = true;
            severity = "critical";
            technique = "Boolean-based Blind";
            query = `SELECT * FROM users WHERE id = '${input}'`;
            response = "User found: John Doe";
            timing = 150;
            notes = [
              "Boolean-based blind injection successful!",
              "Application returns different responses for true/false conditions",
              "Data can be extracted bit by bit using binary search",
              "Try: 1' AND (SELECT SUBSTRING(password,1,1) FROM users WHERE username='admin')='a'--"
            ];
          } else if (input.includes("' AND '1'='2")) {
            vulnerability = true;
            severity = "critical";
            technique = "Boolean-based Blind";
            query = `SELECT * FROM users WHERE id = '${input}'`;
            response = "No user found";
            timing = 145;
            notes = [
              "False condition detected - no user found",
              "This confirms boolean-based blind injection vulnerability",
              "Compare responses between true and false conditions"
            ];
          } else {
            query = `SELECT * FROM users WHERE id = '${input}'`;
            response = input.match(/^\d+$/) ? "User found: John Doe" : "No user found";
            timing = 148;
            notes = ["Try boolean payloads: ' AND '1'='1'-- or ' AND '1'='2'--"];
          }
          break;

        case 'medium':
        case 'high':
          // Time-based blind SQL injection
          if (input.includes("SLEEP(") || input.includes("WAITFOR DELAY") || input.includes("pg_sleep(")) {
            vulnerability = true;
            severity = "critical";
            technique = "Time-based Blind";
            query = `SELECT * FROM users WHERE id = '${input}'`;
            response = "Query executed";
            timing = 5000; // 5 second delay
            notes = [
              "Time-based blind injection successful!",
              "Application delays response when condition is true",
              "Data extraction possible through timing analysis",
              "Example: 1' AND IF((SELECT SUBSTRING(password,1,1) FROM users WHERE username='admin')='a',SLEEP(5),0)--"
            ];
          } else if (input.includes("' AND ")) {
            vulnerability = true;
            severity = "high";
            technique = "Boolean-based (Limited)";
            query = `SELECT * FROM users WHERE id = '${input}'`;
            response = "Query executed";
            timing = 152;
            notes = [
              "Boolean conditions work but responses are normalized",
              "Time-based techniques may be more effective",
              "Try: ' AND SLEEP(5)-- or ' WAITFOR DELAY '00:00:05'--"
            ];
          } else {
            query = `SELECT * FROM users WHERE id = '${input}'`;
            response = "Query executed";
            timing = 149;
            notes = ["Try time-based payloads: ' AND SLEEP(5)-- or boolean conditions"];
          }
          break;

        case 'impossible':
          // Prepared statements prevent injection
          vulnerability = false;
          severity = "secure";
          technique = "Parameterized Query";
          query = "SELECT * FROM users WHERE id = ?";
          response = input.match(/^\d+$/) ? "User found: John Doe" : "No user found";
          timing = 45;
          notes = [
            "✓ Parameterized queries prevent SQL injection",
            "✓ Input is safely handled as data, not code", 
            "✓ No way to inject malicious SQL commands"
          ];
          prevention = [
            "✓ Uses prepared statements",
            "✓ Input validation implemented",
            "✓ Proper error handling"
          ];
          break;
      }

      if (vulnerability) {
        prevention = [
          "Use prepared statements (PDO/parameterized queries)",
          "Implement proper input validation",
          "Add query timeouts to prevent time-based attacks",
          "Use stored procedures where appropriate",
          "Implement proper error handling",
          "Apply principle of least privilege for database users"
        ];
      }

      setResults({
        query,
        response,
        timing,
        vulnerability,
        severity,
        notes,
        prevention,
        technique
      });
      
      setIsLoading(false);
    }, results?.timing || 1000);
  };

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (!userId.trim()) return;
    simulateBlindSQLInjection(userId);
  };

  const getSeverityIcon = (severity: string) => {
    switch (severity) {
      case 'critical':
        return <XCircle className="h-5 w-5 text-danger" />;
      case 'high':
        return <AlertTriangle className="h-5 w-5 text-warning" />;
      case 'secure':
        return <CheckCircle className="h-5 w-5 text-success" />;
      default:
        return <Eye className="h-5 w-5 text-info" />;
    }
  };

  return (
    <div className="space-y-6">
      <Card className="border-l-4 border-l-accent">
        <CardHeader>
          <div className="flex items-center gap-2">
            <Database className="h-5 w-5 text-accent" />
            <CardTitle>SQL Injection (Blind)</CardTitle>
            <Badge variant={difficulty === 'impossible' ? 'default' : 'destructive'}>
              {difficulty.charAt(0).toUpperCase() + difficulty.slice(1)}
            </Badge>
          </div>
          <CardDescription>
            {difficulty === 'low' && "Boolean-based blind injection - responses differ for true/false"}
            {difficulty === 'medium' && "Time-based blind injection - extract data through timing"}
            {difficulty === 'high' && "Advanced blind techniques required"}
            {difficulty === 'impossible' && "Prepared statements prevent all injection attempts"}
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <form onSubmit={handleSubmit} className="space-y-4">
            <div>
              <label htmlFor="userId" className="block text-sm font-medium mb-2">
                User ID
              </label>
              <Input
                id="userId"
                value={userId}
                onChange={(e) => setUserId(e.target.value)}
                placeholder="Enter user ID to search..."
                className="font-mono"
              />
            </div>
            <Button 
              type="submit" 
              disabled={isLoading || !userId.trim()}
              className="w-full"
            >
              {isLoading ? "Querying..." : "Search User"}
            </Button>
          </form>

          {results && (
            <div className="space-y-4">
              <Alert className={`border-l-4 ${results.vulnerability ? 'border-l-destructive' : 'border-l-success'}`}>
                <div className="flex items-center gap-2">
                  {getSeverityIcon(results.severity)}
                  <span className="font-semibold">
                    Analysis Results - Technique: {results.technique}
                  </span>
                </div>
                <AlertDescription className="mt-2">
                  <div className="space-y-2">
                    <div>
                      <strong>Query:</strong>
                      <code className="block mt-1 p-2 bg-muted rounded text-sm">{results.query}</code>
                    </div>
                    <div>
                      <strong>Response:</strong>
                      <code className="block mt-1 p-2 bg-muted rounded text-sm">{results.response}</code>
                    </div>
                    <div className="flex items-center gap-2">
                      <Clock className="h-4 w-4" />
                      <strong>Response Time:</strong>
                      <span className={`font-mono ${results.timing > 1000 ? 'text-danger' : 'text-foreground'}`}>
                        {results.timing}ms
                      </span>
                      {results.timing > 1000 && <span className="text-danger">⚠️ Suspicious delay!</span>}
                    </div>
                  </div>
                </AlertDescription>
              </Alert>

              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <Card>
                  <CardHeader>
                    <CardTitle className="text-lg flex items-center gap-2">
                      <AlertTriangle className="h-4 w-4" />
                      Analysis Notes
                    </CardTitle>
                  </CardHeader>
                  <CardContent>
                    <ul className="space-y-1 text-sm">
                      {results.notes.map((note, index) => (
                        <li key={index} className="flex items-start gap-2">
                          <span className={`mt-1 ${results.vulnerability ? 'text-destructive' : 'text-success'}`}>•</span>
                          {note}
                        </li>
                      ))}
                    </ul>
                  </CardContent>
                </Card>

                {results.prevention.length > 0 && (
                  <Card>
                    <CardHeader>
                      <CardTitle className="text-lg flex items-center gap-2">
                        <CheckCircle className="h-4 w-4" />
                        Prevention Measures
                      </CardTitle>
                    </CardHeader>
                    <CardContent>
                      <ul className="space-y-1 text-sm">
                        {results.prevention.map((measure, index) => (
                          <li key={index} className="flex items-start gap-2">
                            <span className="text-success mt-1">•</span>
                            {measure}
                          </li>
                        ))}
                      </ul>
                    </CardContent>
                  </Card>
                )}
              </div>
            </div>
          )}

          {/* Learning Examples */}
          <Card className="border-primary/20 bg-primary/5">
            <CardContent className="p-6">
              <h3 className="text-lg font-semibold mb-3">🎯 Blind SQL Injection Payloads:</h3>
              <div className="grid grid-cols-1 gap-3 text-sm font-mono">
                <div className="p-2 bg-background rounded border">
                  <strong>Boolean-based:</strong><br />
                  <code>1' AND '1'='1'-- (True condition)</code><br />
                  <code>1' AND '1'='2'-- (False condition)</code>
                </div>
                <div className="p-2 bg-background rounded border">
                  <strong>Time-based (MySQL):</strong><br />
                  <code>1' AND SLEEP(5)--</code>
                </div>
                <div className="p-2 bg-background rounded border">
                  <strong>Time-based (SQL Server):</strong><br />
                  <code>1'; WAITFOR DELAY '00:00:05'--</code>
                </div>
                <div className="p-2 bg-background rounded border">
                  <strong>Data extraction:</strong><br />
                  <code>1' AND (SELECT SUBSTRING(password,1,1) FROM users WHERE id=1)='a'--</code>
                </div>
              </div>
            </CardContent>
          </Card>
        </CardContent>
      </Card>
    </div>
  );
};