import { useState } from "react";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Shield, RefreshCw, AlertTriangle, CheckCircle, XCircle, Eye, EyeOff } from "lucide-react";
import { useLanguage } from "@/hooks/useLanguage";

interface InsecureCaptchaModuleProps {
  difficulty: string;
}

interface CaptchaResult {
  captchaAnswer: string;
  userInput: string;
  passwordChange: boolean;
  bypassUsed: string | null;
  vulnerability: boolean;
  severity: string;
  notes: string[];
  prevention: string[];
}

export const InsecureCaptchaModule = ({ difficulty }: InsecureCaptchaModuleProps) => {
  const { t } = useLanguage();
  const [newPassword, setNewPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const [captchaInput, setCaptchaInput] = useState("");
  const [captchaCode, setCaptchaCode] = useState("");
  const [showCaptchaAnswer, setShowCaptchaAnswer] = useState(false);
  const [results, setResults] = useState<CaptchaResult | null>(null);
  const [isLoading, setIsLoading] = useState(false);
  const [step, setStep] = useState(1); // 1: Password form, 2: CAPTCHA

  // Generate simple math CAPTCHA
  const generateCaptcha = () => {
    const num1 = Math.floor(Math.random() * 10) + 1;
    const num2 = Math.floor(Math.random() * 10) + 1;
    const operators = ['+', '-', '*'];
    const operator = operators[Math.floor(Math.random() * operators.length)];
    
    let answer;
    switch (operator) {
      case '+': answer = num1 + num2; break;
      case '-': answer = num1 - num2; break;
      case '*': answer = num1 * num2; break;
      default: answer = num1 + num2;
    }
    
    const question = `${num1} ${operator} ${num2} = ?`;
    setCaptchaCode(question);
    return answer.toString();
  };

  // Initialize CAPTCHA on component mount
  useState(() => {
    generateCaptcha();
  });

  const simulateCaptchaBypass = (userAnswer: string, correctAnswer: string): CaptchaResult => {
    let passwordChange = false;
    let bypassUsed: string | null = null;
    let vulnerability = false;
    let severity = "info";
    let notes: string[] = [];
    let prevention: string[] = [];

    // Apply different security levels based on difficulty
    switch (difficulty) {
      case "easy":
        // Completely insecure - CAPTCHA verification is client-side only
        passwordChange = true;
        vulnerability = true;
        severity = "danger";
        bypassUsed = "Client-side Validation Bypass";
        
        notes.push("🚨 CAPTCHA bypassed completely!");
        notes.push("💀 Validation only happens on client-side");
        notes.push("🔓 Password changed without proper verification");
        notes.push("🤖 Automated attacks are trivial");
        break;

      case "medium":
        // Flawed logic - CAPTCHA and password change are separate steps
        if (step === 1) {
          // First step: just move to CAPTCHA without validation
          setStep(2);
          return {
            captchaAnswer: correctAnswer,
            userInput: userAnswer,
            passwordChange: false,
            bypassUsed: null,
            vulnerability: false,
            severity: "info",
            notes: ["Step 1: Password entered, proceed to CAPTCHA"],
            prevention: []
          };
        }
        
        // Second step: Check CAPTCHA but password change happens regardless
        if (userAnswer === correctAnswer) {
          passwordChange = true;
          notes.push("✅ CAPTCHA solved correctly");
        } else {
          // Still allow password change - this is the vulnerability
          passwordChange = true;
          vulnerability = true;
          severity = "warning";
          bypassUsed = "Logic Flaw - State Management";
          notes.push("🚨 Password changed despite wrong CAPTCHA!");
          notes.push("⚠️ Session state not properly validated");
          notes.push("🔄 User can skip CAPTCHA step entirely");
        }
        break;

      case "hard":
        // Better implementation but vulnerable to replay attacks
        if (userAnswer === correctAnswer) {
          passwordChange = true;
          severity = "success";
          notes.push("✅ CAPTCHA solved correctly");
          notes.push("🔒 Password updated successfully");
        } else if (userAnswer === "bypass_token_123") {
          // Hidden bypass for demonstration
          passwordChange = true;
          vulnerability = true;
          severity = "warning";
          bypassUsed = "Token Replay Attack";
          notes.push("🚨 Bypass token accepted!");
          notes.push("⚠️ Old validation tokens still valid");
        } else {
          notes.push("❌ Incorrect CAPTCHA answer");
          notes.push("🛡️ Password change blocked");
        }
        break;

      case "impossible":
        // Secure implementation
        if (userAnswer === correctAnswer) {
          passwordChange = true;
          severity = "success";
          notes.push("✅ CAPTCHA verified successfully");
          notes.push("🛡️ Secure server-side validation");
          notes.push("🔒 Password updated with proper verification");
          notes.push("⏰ CAPTCHA token expires after use");
        } else {
          notes.push("❌ Incorrect CAPTCHA - password change denied");
          notes.push("🛡️ All security checks passed");
        }
        break;
    }

    // Add prevention tips
    prevention = [
      "Always validate CAPTCHA on server-side",
      "Use one-time tokens that expire after use",
      "Implement proper session state management",
      "Validate all steps in multi-step processes",
      "Use established CAPTCHA services (reCAPTCHA)",
      "Add rate limiting for failed attempts",
      "Log and monitor CAPTCHA bypass attempts"
    ];

    return {
      captchaAnswer: correctAnswer,
      userInput: userAnswer,
      passwordChange,
      bypassUsed,
      vulnerability,
      severity,
      notes,
      prevention
    };
  };

  const handlePasswordSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (newPassword !== confirmPassword) {
      alert("Passwords don't match!");
      return;
    }
    if (difficulty === "medium") {
      setStep(2);
    } else {
      // For other difficulties, show CAPTCHA immediately
      const correctAnswer = generateCaptcha();
      handleCaptchaSubmit(correctAnswer);
    }
  };

  const handleCaptchaSubmit = async (correctAnswer?: string) => {
    setIsLoading(true);
    
    // Generate correct answer if not provided
    const answer = correctAnswer || generateCaptcha();
    
    // Simulate network delay
    await new Promise(resolve => setTimeout(resolve, 800));
    
    const result = simulateCaptchaBypass(captchaInput, answer);
    setResults(result);
    setIsLoading(false);
  };

  const refreshCaptcha = () => {
    generateCaptcha();
    setCaptchaInput("");
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
            <Shield className="h-8 w-8 text-primary" />
            Insecure CAPTCHA
          </h1>
          <p className="text-lg text-muted-foreground mt-2">
            Learn about CAPTCHA implementation flaws and bypass techniques
          </p>
        </div>
        <Badge variant="outline" className="text-sm">
          Level: {difficulty}
        </Badge>
      </div>

      {/* Password Change Form */}
      {(step === 1 || difficulty !== "medium") && (
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <Shield className="h-5 w-5" />
              Change Password
            </CardTitle>
            <CardDescription>
              Update your account password with CAPTCHA verification
            </CardDescription>
          </CardHeader>
          <CardContent>
            <form onSubmit={handlePasswordSubmit} className="space-y-4">
              <div>
                <label htmlFor="new-password" className="block text-sm font-medium mb-2">
                  New Password:
                </label>
                <Input
                  id="new-password"
                  type="password"
                  value={newPassword}
                  onChange={(e) => setNewPassword(e.target.value)}
                  placeholder="Enter new password"
                  required
                />
              </div>
              <div>
                <label htmlFor="confirm-password" className="block text-sm font-medium mb-2">
                  Confirm Password:
                </label>
                <Input
                  id="confirm-password"
                  type="password"
                  value={confirmPassword}
                  onChange={(e) => setConfirmPassword(e.target.value)}
                  placeholder="Confirm new password"
                  required
                />
              </div>
              
              {difficulty !== "medium" && (
                <div>
                  <label htmlFor="captcha" className="block text-sm font-medium mb-2">
                    CAPTCHA Verification:
                  </label>
                  <div className="flex items-center gap-2 mb-2">
                    <div className="bg-muted p-3 rounded border font-mono text-lg">
                      {captchaCode}
                    </div>
                    <Button type="button" onClick={refreshCaptcha} variant="outline" size="sm">
                      <RefreshCw className="h-4 w-4" />
                    </Button>
                    <Button
                      type="button"
                      onClick={() => setShowCaptchaAnswer(!showCaptchaAnswer)}
                      variant="ghost"
                      size="sm"
                    >
                      {showCaptchaAnswer ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
                    </Button>
                  </div>
                  {showCaptchaAnswer && (
                    <div className="text-sm text-muted-foreground mb-2">
                      💡 Answer: {generateCaptcha()}
                    </div>
                  )}
                  <Input
                    id="captcha"
                    value={captchaInput}
                    onChange={(e) => setCaptchaInput(e.target.value)}
                    placeholder="Enter the answer"
                    required
                  />
                </div>
              )}

              <Button type="submit" disabled={isLoading} className="w-full">
                {difficulty === "medium" ? "Continue" : (isLoading ? "Updating..." : "Update Password")}
              </Button>
            </form>
          </CardContent>
        </Card>
      )}

      {/* CAPTCHA Step (Medium difficulty only) */}
      {step === 2 && difficulty === "medium" && (
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <Shield className="h-5 w-5" />
              CAPTCHA Verification
            </CardTitle>
            <CardDescription>
              Complete the CAPTCHA to finalize password change
            </CardDescription>
          </CardHeader>
          <CardContent>
            <div className="space-y-4">
              <div>
                <label htmlFor="captcha-step2" className="block text-sm font-medium mb-2">
                  Solve the math problem:
                </label>
                <div className="flex items-center gap-2 mb-2">
                  <div className="bg-muted p-3 rounded border font-mono text-lg">
                    {captchaCode}
                  </div>
                  <Button onClick={refreshCaptcha} variant="outline" size="sm">
                    <RefreshCw className="h-4 w-4" />
                  </Button>
                </div>
                <Input
                  id="captcha-step2"
                  value={captchaInput}
                  onChange={(e) => setCaptchaInput(e.target.value)}
                  placeholder="Enter the answer"
                />
              </div>
              <Button
                onClick={() => handleCaptchaSubmit()}
                disabled={isLoading}
                className="w-full"
              >
                {isLoading ? "Verifying..." : "Complete Password Change"}
              </Button>
            </div>
          </CardContent>
        </Card>
      )}

      {/* Results */}
      {results && (
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              {getSeverityIcon(results.severity)}
              CAPTCHA Analysis
            </CardTitle>
          </CardHeader>
          <CardContent className="space-y-4">
            {/* Status */}
            <div className="flex items-center gap-2 p-4 rounded-lg border">
              {results.passwordChange ? (
                <>
                  <CheckCircle className="h-6 w-6 text-success" />
                  <span className="font-semibold text-success">Password Changed Successfully</span>
                </>
              ) : (
                <>
                  <XCircle className="h-6 w-6 text-danger" />
                  <span className="font-semibold text-danger">Password Change Failed</span>
                </>
              )}
            </div>

            {/* Bypass Method */}
            {results.bypassUsed && (
              <div>
                <h4 className="font-semibold text-foreground mb-2">Bypass Method:</h4>
                <Badge variant="destructive" className="text-sm">
                  {results.bypassUsed}
                </Badge>
              </div>
            )}

            {/* CAPTCHA Details */}
            <div>
              <h4 className="font-semibold text-foreground mb-2">CAPTCHA Details:</h4>
              <div className="bg-muted p-3 rounded-md space-y-1 text-sm">
                <div><strong>Correct Answer:</strong> {results.captchaAnswer}</div>
                <div><strong>User Input:</strong> {results.userInput || "N/A"}</div>
                <div><strong>Match:</strong> {results.userInput === results.captchaAnswer ? "✅ Yes" : "❌ No"}</div>
              </div>
            </div>

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
                Prevention Methods:
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

      {/* Bypass Techniques */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <AlertTriangle className="h-5 w-5 text-warning" />
            CAPTCHA Bypass Techniques
          </CardTitle>
        </CardHeader>
        <CardContent>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div>
              <h4 className="font-semibold mb-2">Implementation Flaws:</h4>
              <div className="space-y-1 text-sm bg-muted p-3 rounded-md">
                <div>• Client-side validation only</div>
                <div>• Session state management issues</div>
                <div>• Token reuse vulnerabilities</div>
                <div>• Logic flow bypasses</div>
              </div>
            </div>
            <div>
              <h4 className="font-semibold mb-2">Attack Methods:</h4>
              <div className="space-y-1 text-sm bg-muted p-3 rounded-md">
                <div>• Direct form submission</div>
                <div>• JavaScript disabled</div>
                <div>• Replay attacks</div>
                <div>• OCR automation</div>
              </div>
            </div>
          </div>
        </CardContent>
      </Card>
    </div>
  );
};