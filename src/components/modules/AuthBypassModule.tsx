import { useState } from "react";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Shield, User, Lock, AlertTriangle, CheckCircle, XCircle, Key } from "lucide-react";
import { useLanguage } from "@/hooks/useLanguage";

interface AuthBypassModuleProps {
  difficulty: string;
}

interface AuthResult {
  username: string;
  password: string;
  authenticated: boolean;
  bypassUsed: string | null;
  severity: string;
  notes: string[];
  prevention: string[];
  sessionData?: any;
}

export const AuthBypassModule = ({ difficulty }: AuthBypassModuleProps) => {
  const { t } = useLanguage();
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [results, setResults] = useState<AuthResult | null>(null);
  const [isLoading, setIsLoading] = useState(false);

  // Mock user database
  const users = [
    { id: 1, username: "admin", password: "admin123", role: "administrator" },
    { id: 2, username: "user", password: "password", role: "user" },
    { id: 3, username: "guest", password: "guest", role: "guest" }
  ];

  const simulateAuthentication = (user: string, pass: string): AuthResult => {
    let authenticated = false;
    let bypassUsed: string | null = null;
    let severity = "info";
    let notes: string[] = [];
    let prevention: string[] = [];
    let sessionData: any = null;

    // Apply different security levels based on difficulty
    switch (difficulty) {
      case "easy":
        // Vulnerable: Basic string comparison, SQL injection possible
        const sqlInjectionPatterns = [
          "' OR '1'='1",
          "' OR 1=1--",
          "admin'--",
          "' UNION SELECT 1,1,1--"
        ];

        // Check for SQL injection in username
        if (sqlInjectionPatterns.some(pattern => user.includes(pattern))) {
          authenticated = true;
          bypassUsed = "SQL Injection";
          severity = "danger";
          sessionData = { username: "admin", role: "administrator" };
          notes.push(t("auth_bypass.sql_injection_successful"));
          notes.push("💀 Authentication bypassed using malicious SQL");
          notes.push("🔓 Admin access granted without valid credentials");
        } else {
          // Normal authentication check
          const foundUser = users.find(u => u.username === user && u.password === pass);
          if (foundUser) {
            authenticated = true;
            sessionData = foundUser;
            notes.push("✅ Valid credentials provided");
          } else {
            notes.push("❌ Invalid username or password");
          }
        }
        break;

      case "medium":
        // Partial protection: Basic input sanitization but logic flaws
        const sanitizedUser = user.replace(/['"]/g, "");
        
        // Check for logic bypass (empty password)
        if (sanitizedUser === "admin" && pass === "") {
          authenticated = true;
          bypassUsed = "Empty Password Bypass";
          severity = "warning";
          sessionData = { username: "admin", role: "administrator" };
          notes.push("🚨 Logic flaw exploited!");
          notes.push("⚠️ Admin login with empty password accepted");
        } else if (user.includes("'") || user.includes('"')) {
          notes.push("🛡️ SQL injection attempt blocked");
          notes.push("❌ Special characters filtered");
        } else {
          const foundUser = users.find(u => u.username === sanitizedUser && u.password === pass);
          if (foundUser) {
            authenticated = true;
            sessionData = foundUser;
            notes.push("✅ Valid credentials provided");
          } else {
            notes.push("❌ Invalid username or password");
          }
        }
        break;

      case "hard":
        // Better protection but still vulnerable to specific attacks
        const cleanUser = user.trim().toLowerCase();
        
        // Check for case sensitivity bypass
        if (cleanUser === "admin" && pass === "admin123") {
          authenticated = true;
          bypassUsed = "Case Sensitivity Bypass";
          severity = "warning";
          sessionData = { username: "admin", role: "administrator" };
          notes.push(t("auth_bypass.case_sensitivity_bypass"));
          notes.push("⚠️ Username validation is case-insensitive");
        } else if (user.includes("\\") || user.includes("%")) {
          notes.push("🛡️ Encoding attack attempt detected");
          notes.push("❌ Special encodings blocked");
        } else {
          const foundUser = users.find(u => u.username === user && u.password === pass);
          if (foundUser) {
            authenticated = true;
            sessionData = foundUser;
            notes.push("✅ Valid credentials provided");
          } else {
            notes.push("❌ Invalid username or password");
          }
        }
        break;

      case "impossible":
        // Secure implementation
        const normalizedUser = user.trim();
        
        // Proper validation and secure password handling
        if (normalizedUser.length > 0 && pass.length > 0) {
          const foundUser = users.find(u => u.username === normalizedUser);
          if (foundUser && foundUser.password === pass) {
            authenticated = true;
            sessionData = foundUser;
            severity = "success";
            notes.push(t("auth_bypass.secure_auth_successful"));
            notes.push("🛡️ All security checks passed");
          } else {
            notes.push("❌ Invalid credentials - secure validation");
          }
        } else {
          notes.push("❌ Username and password required");
        }
        break;
    }

    // Add prevention tips
    prevention = [
      "Use parameterized queries to prevent SQL injection",
      "Implement proper input validation and sanitization",
      "Use secure password hashing (bcrypt, Argon2)",
      "Implement account lockout after failed attempts",
      "Add multi-factor authentication",
      "Use secure session management",
      "Log and monitor authentication attempts"
    ];

    return {
      username: user,
      password: pass,
      authenticated,
      bypassUsed,
      severity,
      notes,
      prevention,
      sessionData
    };
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setIsLoading(true);
    
    // Simulate network delay
    await new Promise(resolve => setTimeout(resolve, 800));
    
    const result = simulateAuthentication(username, password);
    setResults(result);
    setIsLoading(false);
  };

  const getSeverityIcon = (severity: string) => {
    switch (severity) {
      case "danger": return <XCircle className="h-5 w-5 text-danger" />;
      case "warning": return <AlertTriangle className="h-5 w-5 text-warning" />;
      case "success": return <CheckCircle className="h-5 w-5 text-success" />;
      default: return <Shield className="h-5 w-5 text-info" />;
    }
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold text-foreground flex items-center gap-2">
            <Lock className="h-8 w-8 text-primary" />
            {t("auth_bypass.title")}
          </h1>
          <p className="text-lg text-muted-foreground mt-2">
            {t("auth_bypass.description")}
          </p>
        </div>
        <Badge variant="outline" className="text-sm">
          Level: {t(`difficulty.${difficulty}`)}
        </Badge>
      </div>

      {/* Login Form */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <User className="h-5 w-5" />
            {t("auth_bypass.login_system")}
          </CardTitle>
          <CardDescription>
            {t("auth_bypass.login_desc")}
          </CardDescription>
        </CardHeader>
        <CardContent>
          <form onSubmit={handleSubmit} className="space-y-4">
            <div>
              <label htmlFor="username" className="block text-sm font-medium mb-2">
                {t("auth_bypass.username")}:
              </label>
              <Input
                id="username"
                value={username}
                onChange={(e) => setUsername(e.target.value)}
                placeholder={t("auth_bypass.username")}
                className="w-full"
              />
            </div>
            <div>
              <label htmlFor="password" className="block text-sm font-medium mb-2">
                {t("auth_bypass.password")}:
              </label>
              <Input
                id="password"
                type="password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                placeholder={t("auth_bypass.password")}
                className="w-full"
              />
            </div>
            <Button type="submit" disabled={isLoading} className="w-full">
              {isLoading ? t("auth_bypass.logging_in") : t("auth_bypass.login")}
            </Button>
          </form>
        </CardContent>
      </Card>

      {/* Authentication Result */}
      {results && (
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              {getSeverityIcon(results.severity)}
              {t("auth_bypass.auth_analysis")}
            </CardTitle>
          </CardHeader>
          <CardContent className="space-y-4">
            {/* Status */}
            <div className="flex items-center gap-2 p-4 rounded-lg border">
              {results.authenticated ? (
                <>
                  <CheckCircle className="h-6 w-6 text-success" />
                  <span className="font-semibold text-success">{t("auth_bypass.auth_result")} ✅</span>
                </>
              ) : (
                <>
                  <XCircle className="h-6 w-6 text-danger" />
                  <span className="font-semibold text-danger">{t("auth_bypass.auth_result")} ❌</span>
                </>
              )}
            </div>

            {/* Bypass Information */}
            {results.bypassUsed && (
              <div>
                <h4 className="font-semibold text-foreground mb-2">Bypass Method:</h4>
                <Badge variant="destructive" className="text-sm">
                  {results.bypassUsed}
                </Badge>
              </div>
            )}

            {/* Session Data */}
            {results.sessionData && (
              <div>
                <h4 className="font-semibold text-foreground mb-2">{t("auth_bypass.session_info")}</h4>
                <div className="bg-muted p-3 rounded-md">
                  <pre className="text-sm font-mono">
                    {JSON.stringify(results.sessionData, null, 2)}
                  </pre>
                </div>
              </div>
            )}

            {/* Security Analysis */}
            <div>
              <h4 className="font-semibold text-foreground mb-2">{t("auth_bypass.security_analysis")}</h4>
              <div className="space-y-2">
                {results.notes.map((note, index) => (
                  <div key={index} className="flex items-start gap-2">
                    <div className="w-2 h-2 rounded-full bg-primary mt-2 flex-shrink-0" />
                    <span className="text-sm">{note}</span>
                  </div>
                ))}
              </div>
            </div>

            {/* Prevention */}
            <div>
              <h4 className="font-semibold text-foreground mb-2 flex items-center gap-2">
                <Shield className="h-4 w-4 text-success" />
                {t("auth_bypass.prevention_methods")}
              </h4>
              <div className="space-y-2">
                {results.prevention.map((tip, index) => (
                  <div key={index} className="flex items-start gap-2">
                    <CheckCircle className="h-4 w-4 text-success mt-0.5 flex-shrink-0" />
                    <span className="text-sm">{tip}</span>
                  </div>
                ))}
              </div>
            </div>
          </CardContent>
        </Card>
      )}

      {/* Attack Techniques */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Key className="h-5 w-5 text-warning" />
            {t("auth_bypass.common_bypasses")}
          </CardTitle>
        </CardHeader>
        <CardContent>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div>
              <h4 className="font-semibold mb-2">{t("auth_bypass.sql_injection")}</h4>
              <div className="space-y-1 text-sm font-mono bg-muted p-3 rounded-md">
                <div>' OR '1'='1</div>
                <div>' OR 1=1--</div>
                <div>admin'--</div>
                <div>' UNION SELECT 1,1,1--</div>
              </div>
            </div>
            <div>
              <h4 className="font-semibold mb-2">{t("auth_bypass.logic_flaws")}</h4>
              <div className="space-y-1 text-sm bg-muted p-3 rounded-md">
                <div>• Empty password bypass</div>
                <div>• Case sensitivity issues</div>
                <div>• Default credentials</div>
                <div>• Session manipulation</div>
              </div>
            </div>
          </div>
        </CardContent>
      </Card>
    </div>
  );
};