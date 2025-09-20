import { useState, useEffect } from "react";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Progress } from "@/components/ui/progress";
import { Zap, Shield, Clock, AlertTriangle, CheckCircle, XCircle, Eye, EyeOff } from "lucide-react";
import { useLanguage } from "@/hooks/useLanguage";

interface BruteForceModuleProps {
  difficulty: string;
}

interface AttemptResult {
  username: string;
  password: string;
  success: boolean;
  blocked: boolean;
  attempts: number;
  timeDelay: number;
  severity: string;
  notes: string[];
  prevention: string[];
}

export const BruteForceModule = ({ difficulty }: BruteForceModuleProps) => {
  const { t } = useLanguage();
  const [targetUsername, setTargetUsername] = useState("admin");
  const [isAttacking, setIsAttacking] = useState(false);
  const [results, setResults] = useState<AttemptResult | null>(null);
  const [progress, setProgress] = useState(0);
  const [currentPassword, setCurrentPassword] = useState("");
  const [showProgress, setShowProgress] = useState(false);

  // Common passwords for brute force
  const commonPasswords = [
    "password", "123456", "admin", "admin123", "password123",
    "qwerty", "abc123", "letmein", "welcome", "login",
    "root", "toor", "pass", "test", "guest"
  ];

  // Target credentials
  const targetCredentials = {
    username: "admin",
    password: "admin123"
  };

  const simulateBruteForce = async (): Promise<AttemptResult> => {
    let attempts = 0;
    let success = false;
    let blocked = false;
    let timeDelay = 0;
    let severity = "info";
    let notes: string[] = [];
    let prevention: string[] = [];
    let foundPassword = "";

    // Apply different security levels based on difficulty
    switch (difficulty) {
      case "low":
        // No protection - brute force succeeds quickly
        for (const password of commonPasswords) {
          attempts++;
          setCurrentPassword(password);
          setProgress((attempts / commonPasswords.length) * 100);
          
          // Simulate network delay
          await new Promise(resolve => setTimeout(resolve, 200));
          
          if (password === targetCredentials.password) {
            success = true;
            foundPassword = password;
            severity = "danger";
            notes.push(t("brute_force.attack_successful"));
            notes.push(`💀 Password '${password}' cracked in ${attempts} attempts`);
            notes.push("🔓 No rate limiting or account lockout");
            break;
          }
        }
        
        if (!success) {
          notes.push("❌ Password not found in common wordlist");
        }
        break;

      case "medium":
        // Basic rate limiting - small delay between attempts
        timeDelay = 1000; // 1 second delay
        
        for (const password of commonPasswords.slice(0, 5)) { // Limited attempts
          attempts++;
          setCurrentPassword(password);
          setProgress((attempts / 5) * 100);
          
          // Simulate delay
          await new Promise(resolve => setTimeout(resolve, timeDelay));
          
          if (password === targetCredentials.password) {
            success = true;
            foundPassword = password;
            severity = "warning";
            notes.push(t("brute_force.attack_successful_rate_limited"));
            notes.push(`⚠️ Password cracked in ${attempts} attempts with delays`);
            notes.push("🐌 Rate limiting slows but doesn't prevent attack");
            break;
          }
        }
        
        if (!success) {
          notes.push("⏰ Attack slowed by rate limiting");
          notes.push("🛡️ Some protection in place but insufficient");
        }
        break;

      case "high":
        // Account lockout after 3 attempts
        const maxAttempts = 3;
        
        for (const password of commonPasswords.slice(0, maxAttempts)) {
          attempts++;
          setCurrentPassword(password);
          setProgress((attempts / maxAttempts) * 100);
          
          await new Promise(resolve => setTimeout(resolve, 500));
          
          if (password === targetCredentials.password && attempts <= maxAttempts) {
            success = true;
            foundPassword = password;
            severity = "warning";
            notes.push("🚨 Lucky! Password found before lockout");
            break;
          }
        }
        
        if (attempts >= maxAttempts && !success) {
          blocked = true;
          severity = "info";
          notes.push("🛡️ Account locked after 3 failed attempts");
          notes.push("⚠️ Still vulnerable to timing attacks");
          notes.push("💡 Could be bypassed with IP rotation");
        }
        break;

      case "impossible":
        // Secure implementation with strong protection
        blocked = true;
        attempts = 1;
        setProgress(100);
        severity = "success";
        
        await new Promise(resolve => setTimeout(resolve, 1000));
        
        notes.push("🛡️ Account locked after first failed attempt");
        notes.push("🔒 CAPTCHA required after lockout");
        notes.push("📧 Email notification sent to user");
        notes.push("⏰ Progressive delay: 5min → 30min → 24hr");
        notes.push("🔐 Strong password policy enforced");
        break;
    }

    // Add prevention tips
    prevention = [
      "Implement account lockout after failed attempts",
      "Use progressive delays (exponential backoff)",
      "Require CAPTCHA after failed attempts",
      "Implement IP-based rate limiting",
      "Use strong password policies",
      "Enable multi-factor authentication",
      "Monitor and alert on suspicious login patterns",
      "Consider using fail2ban or similar tools"
    ];

    return {
      username: targetUsername,
      password: foundPassword,
      success,
      blocked,
      attempts,
      timeDelay,
      severity,
      notes,
      prevention
    };
  };

  const handleStartAttack = async () => {
    setIsAttacking(true);
    setShowProgress(true);
    setProgress(0);
    setCurrentPassword("");
    
    const result = await simulateBruteForce();
    setResults(result);
    setIsAttacking(false);
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
            <Zap className="h-8 w-8 text-primary" />
            {t("brute_force.title")}
          </h1>
          <p className="text-lg text-muted-foreground mt-2">
            {t("brute_force.description")}
          </p>
        </div>
        <Badge variant="outline" className="text-sm">
          Level: {t(`difficulty.${difficulty}`)}
        </Badge>
      </div>

      {/* Attack Configuration */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Zap className="h-5 w-5" />
            Brute Force Simulator
          </CardTitle>
          <CardDescription>
            Simulate a brute force attack against the login system
          </CardDescription>
        </CardHeader>
        <CardContent>
          <div className="space-y-4">
            <div>
              <label htmlFor="target-username" className="block text-sm font-medium mb-2">
                Target Username:
              </label>
              <Input
                id="target-username"
                value={targetUsername}
                onChange={(e) => setTargetUsername(e.target.value)}
                placeholder="Enter target username"
                className="w-full"
                disabled={isAttacking}
              />
            </div>
            
            <Button 
              onClick={handleStartAttack} 
              disabled={isAttacking}
              className="w-full"
              variant={isAttacking ? "secondary" : "default"}
            >
              {isAttacking ? "Attack in Progress..." : "Start Brute Force Attack"}
            </Button>
          </div>
        </CardContent>
      </Card>

      {/* Attack Progress */}
      {showProgress && (
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <Clock className="h-5 w-5" />
              {t("brute_force.attack_progress")}
            </CardTitle>
          </CardHeader>
          <CardContent className="space-y-4">
            <div>
              <div className="flex justify-between text-sm mb-2">
                <span>Progress</span>
                <span>{Math.round(progress)}%</span>
              </div>
              <Progress value={progress} className="w-full" />
            </div>
            
            {currentPassword && (
              <div>
                <h4 className="font-semibold mb-2">{t("brute_force.current_attempt")}</h4>
                <code className="block bg-muted p-2 rounded font-mono">
                  {currentPassword}
                </code>
              </div>
            )}
          </CardContent>
        </Card>
      )}

      {/* Attack Results */}
      {results && (
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              {getSeverityIcon(results.severity)}
              {t("brute_force.attack_results")}
            </CardTitle>
          </CardHeader>
          <CardContent className="space-y-4">
            {/* Status */}
            <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
              <div className="p-4 rounded-lg border">
                <div className="text-sm text-muted-foreground">{t("brute_force.attack_status")}</div>
                <div className="font-semibold">
                  {results.success ? "✅ Success" : results.blocked ? "🛡️ Blocked" : "❌ Failed"}
                </div>
              </div>
              <div className="p-4 rounded-lg border">
                <div className="text-sm text-muted-foreground">{t("brute_force.total_attempts")}</div>
                <div className="font-semibold">{results.attempts}</div>
              </div>
              <div className="p-4 rounded-lg border">
                <div className="text-sm text-muted-foreground">{t("brute_force.time_taken")}</div>
                <div className="font-semibold">{results.timeDelay}ms</div>
              </div>
            </div>

            {/* Found Credentials */}
            {results.success && (
              <div>
                <h4 className="font-semibold text-foreground mb-2">{t("brute_force.found_password")}</h4>
                <div className="bg-danger/10 border border-danger/20 p-3 rounded-md">
                  <div className="font-mono text-sm">
                    Username: {results.username}<br/>
                    Password: {results.password}
                  </div>
                </div>
              </div>
            )}

            {/* Security Analysis */}
            <div>
              <h4 className="font-semibold text-foreground mb-2">Security Analysis:</h4>
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

      {/* Common Passwords */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Eye className="h-5 w-5 text-warning" />
            {t("brute_force.common_passwords")}
          </CardTitle>
        </CardHeader>
        <CardContent>
          <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-5 gap-2">
            {commonPasswords.map((password, index) => (
              <code key={index} className="block bg-muted p-2 rounded text-sm text-center">
                {password}
              </code>
            ))}
          </div>
          <div className="mt-4 text-sm text-muted-foreground">
            💡 These are some of the most common passwords used in brute force attacks
          </div>
        </CardContent>
      </Card>
    </div>
  );
};