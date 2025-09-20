import { useState, useEffect } from "react";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Alert, AlertDescription } from "@/components/ui/alert";
import { Users, RefreshCw, AlertTriangle, CheckCircle, XCircle, Eye } from "lucide-react";
import { useLanguage } from "@/hooks/useLanguage";

interface WeakSessionModuleProps {
  difficulty: string;
}

interface SessionResult {
  sessionId: string;
  predictedNext: string[];
  actualNext: string;
  vulnerability: boolean;
  severity: string;
  notes: string[];
  prevention: string[];
}

export const WeakSessionModule = ({ difficulty }: WeakSessionModuleProps) => {
  const { t } = useLanguage();
  const [currentSessionId, setCurrentSessionId] = useState("");
  const [predictedSessionId, setPredictedSessionId] = useState("");
  const [sessionHistory, setSessionHistory] = useState<string[]>([]);
  const [results, setResults] = useState<SessionResult | null>(null);
  const [isLoading, setIsLoading] = useState(false);

  // Generate session ID based on difficulty
  const generateSessionId = () => {
    const timestamp = Date.now();
    
    switch (difficulty.toLowerCase()) {
      case 'low':
        // Sequential numbers - extremely predictable
        return (Math.floor(timestamp / 1000) % 10000).toString();
      
      case 'medium':
        // Simple timestamp-based
        return timestamp.toString();
      
      case 'high':
        // MD5 hash of timestamp (still predictable if you know the pattern)
        const hash = btoa(timestamp.toString()).substring(0, 16);
        return hash;
      
      case 'impossible':
        // Cryptographically secure random
        return crypto.getRandomValues(new Uint32Array(4))
          .reduce((acc, val) => acc + val.toString(16), '');
      
      default:
        return Math.random().toString(16).substring(2);
    }
  };

  // Initialize with first session
  useEffect(() => {
    const initialSession = generateSessionId();
    setCurrentSessionId(initialSession);
    setSessionHistory([initialSession]);
  }, [difficulty]);

  const generateNewSession = () => {
    const newSession = generateSessionId();
    setCurrentSessionId(newSession);
    setSessionHistory(prev => [...prev.slice(-4), newSession]); // Keep last 5
  };

  const analyzeSessionVulnerability = () => {
    setIsLoading(true);
    
    setTimeout(() => {
      let vulnerability = false;
      let severity = "Low";
      let notes: string[] = [];
      let prevention: string[] = [];
      let predictedNext: string[] = [];

      switch (difficulty.toLowerCase()) {
        case 'low':
          vulnerability = true;
          severity = "Critical";
          notes = [
            "Session IDs are sequential numbers",
            "Extremely easy to predict next session",
            "Attacker can enumerate all active sessions"
          ];
          prevention = [
            "Use cryptographically secure random number generator",
            "Implement minimum session ID length (128 bits)",
            "Add entropy from multiple sources"
          ];
          // Generate predictable next sessions
          const current = parseInt(currentSessionId);
          predictedNext = [
            (current + 1).toString(),
            (current + 2).toString(),
            (current + 3).toString()
          ];
          break;

        case 'medium':
          vulnerability = true;
          severity = "High";
          notes = [
            "Session IDs based on timestamp",
            "Predictable if attacker knows generation time",
            "Can be brute-forced within time window"
          ];
          prevention = [
            "Add random component to timestamp",
            "Use proper session management library",
            "Implement session rotation"
          ];
          const timestamp = Date.now();
          predictedNext = [
            (timestamp + 1000).toString(),
            (timestamp + 2000).toString(),
            (timestamp + 3000).toString()
          ];
          break;

        case 'high':
          vulnerability = true;
          severity = "Medium";
          notes = [
            "Uses hashed timestamp - still predictable",
            "Pattern can be reverse-engineered",
            "Requires more sophisticated attack"
          ];
          prevention = [
            "Use true random session generation",
            "Implement proper session validation",
            "Add session binding to client characteristics"
          ];
          predictedNext = [t("weak_session.pattern_analysis"), t("weak_session.hash_collision"), t("weak_session.time_prediction")];
          break;

        case 'impossible':
          vulnerability = false;
          severity = "Secure";
          notes = [
            "Uses cryptographically secure random generation",
            "Unpredictable session IDs",
            "Sufficient entropy and length"
          ];
          prevention = [
            "✓ Cryptographically secure random generator",
            "✓ Sufficient session ID length",
            "✓ Regular session rotation"
          ];
          predictedNext = ["Unpredictable", "Secure implementation", "No pattern detected"];
          break;
      }

      const actualNext = generateSessionId();

      setResults({
        sessionId: currentSessionId,
        predictedNext,
        actualNext,
        vulnerability,
        severity,
        notes,
        prevention
      });
      
      setIsLoading(false);
    }, 1000);
  };

  const handleSessionPrediction = () => {
    analyzeSessionVulnerability();
  };

  return (
    <div className="space-y-6">
      <Card className="border-l-4 border-l-warning">
        <CardHeader>
          <div className="flex items-center gap-2">
            <Users className="h-5 w-5 text-warning" />
            <CardTitle>{t("weak_session.title")}</CardTitle>
            <Badge variant={difficulty === 'impossible' ? 'default' : 'destructive'}>
              {t(`difficulty.${difficulty}`)}
            </Badge>
          </div>
          <CardDescription>
            {t("weak_session.description")}
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div>
              <label className="block text-sm font-medium mb-2">{t("weak_session.generated_id")}</label>
              <div className="flex gap-2">
                <Input
                  value={currentSessionId}
                  readOnly
                  className="font-mono text-sm"
                />
                <Button onClick={generateNewSession} variant="outline">
                  <RefreshCw className="h-4 w-4" />
                </Button>
              </div>
            </div>
            
            <div>
              <label className="block text-sm font-medium mb-2">{t("weak_session.generate_session")}</label>
              <div className="flex gap-2">
                <Input
                  value={predictedSessionId}
                  onChange={(e) => setPredictedSessionId(e.target.value)}
                  placeholder={t("weak_session.session_desc")}
                  className="font-mono text-sm"
                />
                <Button onClick={handleSessionPrediction} disabled={isLoading}>
                  {isLoading ? <RefreshCw className="h-4 w-4 animate-spin" /> : <Eye className="h-4 w-4" />}
                  {t("weak_session.session_analysis")}
                </Button>
              </div>
            </div>
          </div>

          {sessionHistory.length > 1 && (
            <div>
              <label className="block text-sm font-medium mb-2">Session History</label>
              <div className="bg-muted/50 rounded-md p-3">
                <div className="grid grid-cols-1 gap-1 text-sm font-mono">
                  {sessionHistory.map((session, index) => (
                    <div key={index} className="flex justify-between">
                      <span>Session {index + 1}:</span>
                      <span>{session}</span>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          )}

          {results && (
            <div className="space-y-4">
              <Alert className={`border-l-4 ${results.vulnerability ? 'border-l-destructive' : 'border-l-success'}`}>
                <div className="flex items-center gap-2">
                  {results.vulnerability ? <XCircle className="h-4 w-4" /> : <CheckCircle className="h-4 w-4" />}
                  <span className="font-semibold">
                    {t("weak_session.session_analysis")} - {t("weak_session.predictability")}: {results.severity}
                  </span>
                </div>
                <AlertDescription className="mt-2">
                  <div className="space-y-2">
                    <div>
                      <strong>Predicted Next Sessions:</strong>
                      <ul className="list-disc list-inside ml-2 text-sm">
                        {results.predictedNext.map((pred, index) => (
                          <li key={index} className="font-mono">{pred}</li>
                        ))}
                      </ul>
                    </div>
                    <div>
                      <strong>Actual Next Session:</strong>
                      <span className="font-mono ml-2">{results.actualNext}</span>
                    </div>
                  </div>
                </AlertDescription>
              </Alert>

              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <Card>
                  <CardHeader>
                    <CardTitle className="text-lg flex items-center gap-2">
                      <AlertTriangle className="h-4 w-4" />
                      {t("weak_session.session_attacks")}
                    </CardTitle>
                  </CardHeader>
                  <CardContent>
                    <ul className="space-y-1 text-sm">
                      {results.notes.map((note, index) => (
                        <li key={index} className="flex items-start gap-2">
                          <span className="text-destructive mt-1">•</span>
                          {note}
                        </li>
                      ))}
                    </ul>
                  </CardContent>
                </Card>

                <Card>
                  <CardHeader>
                    <CardTitle className="text-lg flex items-center gap-2">
                      <CheckCircle className="h-4 w-4" />
                      {t("auth_bypass.prevention_methods")}
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
              </div>
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  );
};