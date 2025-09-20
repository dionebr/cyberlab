import { useState } from "react";
import { Database, AlertTriangle, CheckCircle, XCircle, Info } from "lucide-react";
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
  const { t } = useLanguage();

  // Mock database for educational purposes
  const mockDatabase = [
    { id: 1, username: 'admin', email: 'admin@example.com', role: 'administrator' },
    { id: 2, username: 'user1', email: 'user1@example.com', role: 'user' },
    { id: 3, username: 'user2', email: 'user2@example.com', role: 'user' },
    { id: 4, username: 'guest', email: 'guest@example.com', role: 'guest' },
  ];

  const simulateSQLQuery = (input: string) => {
    setIsLoading(true);
    
    setTimeout(() => {
      let query = `SELECT * FROM users WHERE id = '${input}'`;
      let sanitizedInput = input;
      let vulnerabilityDetected = false;
      let educationalNote = "";

      // Apply different security measures based on difficulty
      switch (difficulty) {
        case 'easy':
          // No sanitization - fully vulnerable
          if (input.includes("'") || input.includes("--") || input.includes("UNION") || input.includes("SELECT")) {
            vulnerabilityDetected = true;
            // Simulate SQL injection success
            if (input.includes("' OR '1'='1")) {
              setResults({
                query,
                data: mockDatabase,
                vulnerable: true,
                severity: "critical",
                educationalNote: t("sql_injection.sqli_successful"),
                exploitUsed: "Authentication Bypass",
                prevention: "Use parameterized queries or prepared statements to prevent SQL injection."
              });
              setIsLoading(false);
              return;
            }
            if (input.includes("UNION SELECT")) {
              setResults({
                query,
                data: [
                  ...mockDatabase,
                  { id: 999, username: 'injected_data', email: 'hacker@evil.com', role: 'admin' }
                ],
                vulnerable: true,
                severity: "critical",
                educationalNote: t("sql_injection.union_sqli_successful"),
                exploitUsed: "UNION-based injection",
                prevention: "Validate input and use parameterized queries."
              });
              setIsLoading(false);
              return;
            }
          }
          educationalNote = "This level has no input sanitization. Try payloads like: ' OR '1'='1 or ' UNION SELECT * FROM users--";
          break;

        case 'medium':
          // Basic sanitization - some protection
          sanitizedInput = input.replace(/'/g, "\\'");
          query = `SELECT * FROM users WHERE id = '${sanitizedInput}'`;
          if (input.includes("'")) {
            educationalNote = "Basic sanitization applied: single quotes escaped. However, this protection can still be bypassed with other techniques.";
          } else {
            educationalNote = t("sql_injection.medium_sanitization");
          }
          break;

        case 'hard':
          // Advanced sanitization
          sanitizedInput = input.replace(/[^\w\s]/gi, '');
          query = `SELECT * FROM users WHERE id = '${sanitizedInput}'`;
          if (input !== sanitizedInput) {
            educationalNote = "Advanced sanitization applied: special characters removed. This significantly reduces SQL injection risk.";
          } else {
            educationalNote = t("sql_injection.hard_sanitization");
          }
          break;

        case 'impossible':
          // Prepared statements simulation
          query = `SELECT * FROM users WHERE id = ?`;
          educationalNote = "Impossible level uses prepared statements. The input is treated as data, not code, making SQL injection impossible.";
          break;
      }

      // Find user by ID if it's a number
      const userId = parseInt(sanitizedInput);
      const user = mockDatabase.find(u => u.id === userId);
      
      setResults({
        query,
        data: user ? [user] : [],
        vulnerable: vulnerabilityDetected,
        severity: vulnerabilityDetected ? "high" : "safe",
        educationalNote,
        exploitUsed: vulnerabilityDetected ? "SQL Injection" : "None",
        prevention: "Always use parameterized queries and input validation."
      });
      
      setIsLoading(false);
    }, 1000);
  };

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (!userInput.trim()) return;
    simulateSQLQuery(userInput);
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
            <div>
              <label htmlFor="user-id" className="block text-sm font-medium mb-2">
                {t("sql.user_id")}
              </label>
              <Input
                id="user-id"
                type="text"
                value={userInput}
                onChange={(e) => setUserInput(e.target.value)}
                placeholder={t("sql.placeholder")}
                className="font-mono"
              />
            </div>
            <Button 
              type="submit" 
              disabled={isLoading || !userInput.trim()}
              className="w-full bg-danger hover:bg-danger/90"
            >
              {isLoading ? t("sql_injection.querying") : t("sql.submit")}
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
                <h4 className="font-semibold mb-2">{t("sql_injection.executed_query")}</h4>
                <code className="block p-3 bg-muted rounded text-sm font-mono">
                  {results.query}
                </code>
              </div>

              {/* Data Results */}
              {results.data.length > 0 ? (
                <div>
                  <h4 className="font-semibold mb-2">{t("sql_injection.retrieved_data")}</h4>
                  <div className="overflow-x-auto">
                    <table className="w-full border border-border rounded">
                      <thead className="bg-muted">
                        <tr>
                          <th className="p-2 text-left">ID</th>
                          <th className="p-2 text-left">Username</th>
                          <th className="p-2 text-left">Email</th>
                          <th className="p-2 text-left">Role</th>
                        </tr>
                      </thead>
                      <tbody>
                        {results.data.map((user: any, index: number) => (
                          <tr key={index} className="border-t border-border">
                            <td className="p-2">{user.id}</td>
                            <td className="p-2">{user.username}</td>
                            <td className="p-2">{user.email}</td>
                            <td className="p-2">
                              <Badge variant={user.role === 'administrator' ? 'destructive' : 'secondary'}>
                                {user.role}
                              </Badge>
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                </div>
              ) : (
                <Alert>
                  <Info className="h-4 w-4" />
                  <AlertDescription>{t("sql_injection.no_results")}</AlertDescription>
                </Alert>
              )}

              {/* Educational Note */}
              {results.educationalNote && (
                <Alert className={results.vulnerable ? "border-danger bg-danger/10" : "border-success bg-success/10"}>
                  <AlertTriangle className="h-4 w-4" />
                  <AlertDescription>
                    <strong>{t("sql_injection.educational_note")}</strong> {results.educationalNote}
                  </AlertDescription>
                </Alert>
              )}

              {/* Prevention Tips */}
              <Alert className="border-info bg-info/10">
                <Info className="h-4 w-4" />
                <AlertDescription>
                  <strong>{t("sql_injection.prevention")}</strong> {results.prevention}
                </AlertDescription>
              </Alert>
            </CardContent>
          </Card>
        </div>
      )}

      {/* Learning Tips */}
      <Card className="border-primary/20 bg-primary/5">
        <CardContent className="p-6">
          <h3 className="text-lg font-semibold mb-3">{t("sql_injection.payloads_title")}</h3>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-3 text-sm font-mono">
            <div className="p-2 bg-background rounded border">
              <strong>{t("sql_injection.basic_bypass")}</strong><br />
              <code>' OR '1'='1</code>
            </div>
            <div className="p-2 bg-background rounded border">
              <strong>{t("sql_injection.comment_injection")}</strong><br />
              <code>' OR '1'='1' --</code>
            </div>
            <div className="p-2 bg-background rounded border">
              <strong>{t("sql_injection.union_attack")}</strong><br />
              <code>' UNION SELECT * FROM users--</code>
            </div>
            <div className="p-2 bg-background rounded border">
              <strong>{t("sql_injection.boolean_based")}</strong><br />
              <code>' AND '1'='1</code>
            </div>
          </div>
        </CardContent>
      </Card>
    </div>
  );
};