import { useState } from "react";
import { Shield, AlertTriangle, CheckCircle, XCircle, Info, Eye, EyeOff } from "lucide-react";
import { Button } from "../ui/button";
import { Input } from "../ui/input";
import { Card, CardContent, CardHeader, CardTitle } from "../ui/card";
import { Alert, AlertDescription } from "../ui/alert";
import { Badge } from "../ui/badge";
import { Textarea } from "../ui/textarea";
import { useLanguage } from "../../hooks/useLanguage";

interface CSRFModuleProps {
  difficulty: string;
}

export const CSRFModule = ({ difficulty }: CSRFModuleProps) => {
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [results, setResults] = useState<any>(null);
  const [isLoading, setIsLoading] = useState(false);
  const [showToken, setShowToken] = useState(false);
  const { t } = useLanguage();

  // Mock CSRF token
  const csrfToken = "a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6";

  const simulateFormSubmission = () => {
    setIsLoading(true);
    
    setTimeout(() => {
      let vulnerabilityDetected = false;
      let educationalNote = "";
      let hasToken = false;

      // Check for CSRF protection based on difficulty
      switch (difficulty) {
        case 'low':
          // No CSRF protection
          vulnerabilityDetected = true;
          educationalNote = "No CSRF protection! Any malicious site can forge requests on behalf of the user.";
          break;

        case 'medium':
          // Verificação do cabeçalho Referer, contornável
          hasToken = false;
          vulnerabilityDetected = true;
          educationalNote = "Medium level checks Referer header, but this can be bypassed or spoofed by attackers.";
          break;

        case 'high':
          // Token anti-CSRF, difícil de explorar devido à SOP
          hasToken = true;
          vulnerabilityDetected = false;  // Difficult to exploit but not impossible
          educationalNote = "Strong CSRF token protection. Difficult to exploit due to Same-Origin Policy, but XSS could potentially bypass this.";
          break;
          
        case 'impossible':
          // Token anti-CSRF + confirmação de senha do usuário
          hasToken = true;
          vulnerabilityDetected = false;
          educationalNote = "Maximum CSRF protection: anti-CSRF token + user password confirmation required for sensitive operations.";
          break;
      }

      const formHtml = `
<form action="/update-profile" method="POST">
  ${hasToken ? `<input type="hidden" name="csrf_token" value="${csrfToken}" />` : ''}
  <input type="email" name="email" value="${email}" />
  <input type="password" name="password" value="[HIDDEN]" />
  <button type="submit">Update Profile</button>
</form>`;

      const maliciousHtml = `
<!-- Malicious site example -->
<form action="https://vulnerable-site.com/update-profile" method="POST" style="display:none;">
  <input type="email" name="email" value="hacker@evil.com" />
  <input type="password" name="password" value="hacked123" />
  <button type="submit">Hidden Attack</button>
</form>
<script>document.forms[0].submit();</script>`;

      setResults({
        formHtml,
        maliciousHtml,
        vulnerable: vulnerabilityDetected,
        severity: vulnerabilityDetected ? (difficulty === 'low' ? 'critical' : 'high') : 'safe',
        educationalNote,
        hasToken,
        exploitUsed: vulnerabilityDetected ? "CSRF Attack" : "None",
        prevention: "Use anti-CSRF tokens, SameSite cookies, and proper referrer validation."
      });
      
      setIsLoading(false);
    }, 1000);
  };

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (!email.trim() || !password.trim()) return;
    simulateFormSubmission();
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
        <div className="p-3 bg-info/10 rounded-lg">
          <Shield className="h-8 w-8 text-info" />
        </div>
        <div>
          <h1 className="text-3xl font-bold">{t("csrf.title")}</h1>
          <p className="text-muted-foreground">{t("csrf.description")}</p>
          <Badge variant="outline" className="mt-2">
            Level: {t(`difficulty.${difficulty}`)}
          </Badge>
        </div>
      </div>

      {/* Input Section */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Shield className="h-5 w-5" />
            {t("csrf.profile_update")}
          </CardTitle>
        </CardHeader>
        <CardContent>
          <form onSubmit={handleSubmit} className="space-y-4">
            <div>
              <label htmlFor="email" className="block text-sm font-medium mb-2">
                {t("csrf.email_address")}
              </label>
              <Input
                id="email"
                type="email"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                placeholder={t("csrf.email_placeholder")}
                required
              />
            </div>
            <div>
              <label htmlFor="password" className="block text-sm font-medium mb-2">
                {t("csrf.new_password")}
              </label>
              <Input
                id="password"
                type="password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                placeholder={t("csrf.password_placeholder")}
                required
              />
            </div>
            
            {/* CSRF Token Display (when applicable) */}
            {(difficulty === 'medium' || difficulty === 'high') && (
              <div className="p-3 bg-muted rounded border">
                <div className="flex items-center justify-between mb-2">
                  <span className="text-sm font-medium">{t("csrf.csrf_token")}</span>
                  <Button
                    type="button"
                    variant="ghost"
                    size="sm"
                    onClick={() => setShowToken(!showToken)}
                  >
                    {showToken ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
                  </Button>
                </div>
                <code className="text-xs break-all">
                  {showToken ? csrfToken : '•'.repeat(32)}
                </code>
              </div>
            )}

            <Button 
              type="submit" 
              disabled={isLoading || !email.trim() || !password.trim()}
              className="w-full bg-info hover:bg-info/90"
            >
              {isLoading ? t("csrf.updating") : t("csrf.update_profile")}
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
                {t("csrf.form_analysis")}
              </CardTitle>
            </CardHeader>
            <CardContent className="space-y-4">
              {/* Generated Form */}
              <div>
                <h4 className="font-semibold mb-2">{t("csrf.generated_form")}</h4>
                <Textarea
                  value={results.formHtml}
                  readOnly
                  className="font-mono text-sm h-32"
                />
              </div>

              {/* Malicious Example */}
              <div>
                <h4 className="font-semibold mb-2 flex items-center gap-2">
                  <AlertTriangle className="h-4 w-4 text-danger" />
                  {t("csrf.csrf_attack")}
                </h4>
                <Textarea
                  value={results.maliciousHtml}
                  readOnly
                  className="font-mono text-sm h-32 border-danger"
                />
              </div>

              {/* Educational Note */}
              {results.educationalNote && (
                <Alert className={results.vulnerable ? "border-danger bg-danger/10" : "border-success bg-success/10"}>
                  <AlertTriangle className="h-4 w-4" />
                  <AlertDescription>
                    <strong>{t("csrf.security_analysis")}</strong> {results.educationalNote}
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
        </div>
      )}

      {/* Learning Tips */}
      <Card className="border-primary/20 bg-primary/5">
        <CardContent className="p-6">
          <h3 className="text-lg font-semibold mb-3">{t("csrf.protection_methods")}</h3>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-sm">
            <div className="p-3 bg-background rounded border">
              <strong className="text-success">{t("csrf.anti_csrf_tokens")}</strong><br />
              {t("csrf.anti_csrf_desc")}
            </div>
            <div className="p-3 bg-background rounded border">
              <strong className="text-success">{t("csrf.samesite_cookies")}</strong><br />
              {t("csrf.samesite_desc")}
            </div>
            <div className="p-3 bg-background rounded border">
              <strong className="text-success">{t("csrf.referrer_validation")}</strong><br />
              {t("csrf.referrer_desc")}
            </div>
            <div className="p-3 bg-background rounded border">
              <strong className="text-success">{t("csrf.double_submit")}</strong><br />
              {t("csrf.double_submit_desc")}
            </div>
          </div>
        </CardContent>
      </Card>
    </div>
  );
};