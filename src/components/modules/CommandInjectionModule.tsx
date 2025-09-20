import { useState } from "react";
import { Terminal, AlertTriangle, CheckCircle, XCircle, Info } from "lucide-react";
import { Button } from "../ui/button";
import { Input } from "../ui/input";
import { Card, CardContent, CardHeader, CardTitle } from "../ui/card";
import { Alert, AlertDescription } from "../ui/alert";
import { Badge } from "../ui/badge";
import { useLanguage } from "../../hooks/useLanguage";

interface CommandInjectionModuleProps {
  difficulty: string;
}

export const CommandInjectionModule = ({ difficulty }: CommandInjectionModuleProps) => {
  const [userInput, setUserInput] = useState("");
  const [results, setResults] = useState<any>(null);
  const [isLoading, setIsLoading] = useState(false);
  const { t } = useLanguage();

  const simulateCommandExecution = (input: string) => {
    setIsLoading(true);
    
    setTimeout(() => {
      let command = `ping -c 4 ${input}`;
      let sanitizedInput = input;
      let vulnerabilityDetected = false;
      let educationalNote = "";

      // Apply different security measures based on difficulty
      switch (difficulty) {
        case 'low':
          // No sanitization - fully vulnerable
          if (input.includes(";") || input.includes("&&") || input.includes("||") || input.includes("|")) {
            vulnerabilityDetected = true;
            if (input.includes("; cat /etc/passwd")) {
              setResults({
                command,
                output: `PING ${input.split(';')[0]} (127.0.0.1): 56 data bytes\n64 bytes from 127.0.0.1: icmp_seq=1 ttl=64 time=0.123ms\n\n--- Command Injection Detected ---\nroot:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\nbin:x:2:2:bin:/bin:/usr/sbin/nologin\nwww-data:x:33:33:www-data:/var/www:/usr/sbin/nologin`,
                vulnerable: true,
                severity: "critical",
                educationalNote: t("command_injection.semicolon_successful"),
                exploitUsed: "Command Chaining (;)",
                prevention: "Use parameterized commands and input validation."
              });
              setIsLoading(false);
              return;
            }
            if (input.includes("&& whoami")) {
              setResults({
                command,
                output: `PING ${input.split('&&')[0]} (127.0.0.1): 56 data bytes\n64 bytes from 127.0.0.1: icmp_seq=1 ttl=64 time=0.156ms\n\nroot`,
                vulnerable: true,
                severity: "critical",
                educationalNote: t("command_injection.and_operator_successful"),
                exploitUsed: "Logical AND (&&)",
                prevention: "Implement strict input validation and use safe command execution methods."
              });
              setIsLoading(false);
              return;
            }
          }
          educationalNote = "Low level has no input sanitization. Try payloads like: 127.0.0.1; cat /etc/passwd or 127.0.0.1 && whoami";
          break;

        case 'medium':
          // Filtro remove ; e &, exigindo operadores alternativos
          sanitizedInput = input.replace(/[;&]/g, '');
          command = `ping -c 4 ${sanitizedInput}`;
          
          // Check for bypasses using other operators
          if (input.includes('||') && !input.includes(';') && !input.includes('&')) {
            if (input.includes('|| whoami')) {
              setResults({
                command,
                output: `PING ${input.split('||')[0]} (127.0.0.1): 56 data bytes\n--- ping failed ---\n\nroot`,
                vulnerable: true,
                severity: "critical",
                educationalNote: "Medium level filters ; and & but || operator bypassed the filter!",
                exploitUsed: "Logical OR (||) bypass",
                prevention: "Filter ALL command operators, not just specific ones."
              });
              setIsLoading(false);
              return;
            }
          }
          
          if (input !== sanitizedInput) {
            educationalNote = "Medium level filters ; and & characters, but other operators like || may work.";
          } else {
            educationalNote = t("command_injection.medium_filtering");
          }
          break;

        case 'high':
          // Filtro remove espaços e mais operadores, exigindo técnicas avançadas
          sanitizedInput = input.replace(/[^a-zA-Z0-9\.-]/g, '');
          command = `ping -c 4 ${sanitizedInput}`;
          
          // Check for advanced bypasses like command substitution without spaces
          if (input.includes('`') && input.replace(/`.*`/, '').trim()) {
            if (input.includes('`whoami`') || input.includes('$(whoami)')) {
              setResults({
                command,
                output: `PING 127001root (127.0.0.1): 56 data bytes\n--- Advanced injection detected ---\nCommand substitution bypassed space filtering`,
                vulnerable: true,
                severity: "high",
                educationalNote: "High level filters spaces and operators but command substitution without spaces bypassed the filter!",
                exploitUsed: "Command substitution bypass",
                prevention: "Use strict allowlist validation and parameterized commands."
              });
              setIsLoading(false);
              return;
            }
          }
          
          if (input !== sanitizedInput) {
            educationalNote = "High level removes spaces and most special characters. Advanced techniques like ${IFS} or command substitution might work.";
          } else {
            educationalNote = "High level implements advanced filtering. Try space bypasses: ${IFS}, $'\\t', or command substitution.";
          }
          break;
          
        case 'impossible':
          // Validação estrita de entrada (allowlist)
          const allowedHosts = ['127.0.0.1', 'localhost', 'google.com', 'github.com'];
          if (allowedHosts.includes(input.trim())) {
            sanitizedInput = input.trim();
            command = `ping -c 4 ${sanitizedInput}`;
            educationalNote = "Impossible level uses strict allowlist validation. Only predefined safe hosts are allowed.";
          } else {
            setResults({
              command: `ping -c 4 ${input}`,
              output: "Error: Host not in allowlist. Allowed hosts: 127.0.0.1, localhost, google.com, github.com",
              vulnerable: false,
              severity: "safe",
              educationalNote: "Impossible level blocks all inputs not in the predefined allowlist.",
              exploitUsed: "None - Input rejected",
              prevention: "Perfect! Allowlist validation prevents all injection attempts."
            });
            setIsLoading(false);
            return;
          }
          break;
      }

      // Simulate normal ping output
      const cleanInput = sanitizedInput || '127.0.0.1';
      setResults({
        command,
        output: `PING ${cleanInput} (127.0.0.1): 56 data bytes\n64 bytes from 127.0.0.1: icmp_seq=1 ttl=64 time=0.123ms\n64 bytes from 127.0.0.1: icmp_seq=2 ttl=64 time=0.098ms\n64 bytes from 127.0.0.1: icmp_seq=3 ttl=64 time=0.087ms\n64 bytes from 127.0.0.1: icmp_seq=4 ttl=64 time=0.092ms\n\n--- ${cleanInput} ping statistics ---\n4 packets transmitted, 4 received, 0% packet loss`,
        vulnerable: vulnerabilityDetected,
        severity: vulnerabilityDetected ? "high" : "safe",
        educationalNote,
        exploitUsed: vulnerabilityDetected ? "Command Injection" : "None",
        prevention: "Use parameterized commands, input validation, and least privilege principles."
      });
      
      setIsLoading(false);
    }, 1500);
  };

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (!userInput.trim()) return;
    simulateCommandExecution(userInput);
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
        <div className="p-3 bg-accent/10 rounded-lg">
          <Terminal className="h-8 w-8 text-accent" />
        </div>
        <div>
          <h1 className="text-3xl font-bold">{t("command_injection.title")}</h1>
          <p className="text-muted-foreground">{t("command_injection.description")}</p>
          <Badge variant="outline" className="mt-2">
            Level: {t(`difficulty.${difficulty}`)}
          </Badge>
        </div>
      </div>

      {/* Input Section */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Terminal className="h-5 w-5" />
            {t("command_injection.network_ping")}
          </CardTitle>
        </CardHeader>
        <CardContent>
          <form onSubmit={handleSubmit} className="space-y-4">
            <div>
              <label htmlFor="host" className="block text-sm font-medium mb-2">
                {t("command_injection.host_ip")}
              </label>
              <Input
                id="host"
                type="text"
                value={userInput}
                onChange={(e) => setUserInput(e.target.value)}
                placeholder={t("command_injection.host_placeholder")}
                className="font-mono"
              />
            </div>
            <Button 
              type="submit" 
              disabled={isLoading || !userInput.trim()}
              className="w-full bg-accent hover:bg-accent/90"
            >
              {isLoading ? t("command_injection.executing") : t("command_injection.execute_ping")}
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
                {t("command_injection.command_results")}
              </CardTitle>
            </CardHeader>
            <CardContent className="space-y-4">
              {/* Command Display */}
              <div>
                <h4 className="font-semibold mb-2">{t("command_injection.executed_command")}</h4>
                <code className="block p-3 bg-muted rounded text-sm font-mono">
                  {results.command}
                </code>
              </div>

              {/* Output */}
              <div>
                <h4 className="font-semibold mb-2">{t("command_injection.command_output")}</h4>
                <pre className="p-3 bg-muted rounded text-sm font-mono whitespace-pre-wrap">
                  {results.output}
                </pre>
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
        </div>
      )}

      {/* Learning Tips */}
      <Card className="border-primary/20 bg-primary/5">
        <CardContent className="p-6">
          <h3 className="text-lg font-semibold mb-3">{t("command_injection.payloads_title")}</h3>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-3 text-sm font-mono">
            <div className="p-2 bg-background rounded border">
              <strong>{t("command_injection.command_chaining")}</strong><br />
              <code>127.0.0.1; cat /etc/passwd</code>
            </div>
            <div className="p-2 bg-background rounded border">
              <strong>{t("command_injection.logical_and")}</strong><br />
              <code>127.0.0.1 && whoami</code>
            </div>
            <div className="p-2 bg-background rounded border">
              <strong>{t("command_injection.pipe_operator")}</strong><br />
              <code>127.0.0.1 | ls -la</code>
            </div>
            <div className="p-2 bg-background rounded border">
              <strong>{t("command_injection.background_execution")}</strong><br />
              <code>127.0.0.1 & ps aux</code>
            </div>
          </div>
        </CardContent>
      </Card>
    </div>
  );
};