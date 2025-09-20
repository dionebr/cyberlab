import { useState } from "react";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { AlertTriangle, FileText, Shield, AlertCircle, CheckCircle, XCircle } from "lucide-react";
import { useLanguage } from "@/hooks/useLanguage";

interface FileInclusionModuleProps {
  difficulty: string;
}

interface SimulationResult {
  fileRequest: string;
  fileContent: string;
  vulnerability: boolean;
  severity: string;
  notes: string[];
  prevention: string[];
}

export const FileInclusionModule = ({ difficulty }: FileInclusionModuleProps) => {
  const { t } = useLanguage();
  const [userInput, setUserInput] = useState("");
  const [results, setResults] = useState<SimulationResult | null>(null);
  const [isLoading, setIsLoading] = useState(false);

  // Mock file system
  const mockFiles = {
    "home.php": "<?php echo 'Welcome to Break\\'n\\'Learn!'; ?>",
    "about.php": "<?php echo 'About our security platform'; ?>",
    "config.php": "<?php $db_pass = 'admin123'; $api_key = 'secret_key_2024'; ?>",
    "/etc/passwd": "root:x:0:0:root:/root:/bin/bash\nwww-data:x:33:33:www-data:/var/www:/usr/sbin/nologin",
    "/etc/hosts": "127.0.0.1 localhost\n127.0.1.1 vulnerable-server",
  };

  const simulateFileInclusion = (input: string): SimulationResult => {
    let sanitizedInput = input;
    let vulnerability = false;
    let severity = "info";
    let fileContent = "";
    let notes: string[] = [];
    let prevention: string[] = [];

    // Apply different security levels based on difficulty
    switch (difficulty) {
      case "easy":
        // No sanitization - direct file inclusion
        vulnerability = true;
        severity = "danger";
        
        // Check for path traversal attempts
        if (input.includes("../") || input.includes("..\\")) {
          fileContent = mockFiles["/etc/passwd" as keyof typeof mockFiles] || "File not found";
          notes.push(t("file_inclusion.path_traversal_successful"));
          notes.push("💀 System files exposed - /etc/passwd readable");
          notes.push("🔓 No input validation implemented");
        } else if (input.includes("config")) {
          fileContent = mockFiles["config.php" as keyof typeof mockFiles] || "File not found";
          notes.push("🚨 Configuration file exposed!");
          notes.push("💀 Database credentials and API keys leaked");
        } else {
          fileContent = mockFiles[input as keyof typeof mockFiles] || "File not found";
          if (fileContent !== "File not found") {
            notes.push("✅ File included successfully");
          }
        }
        break;

      case "medium":
        // Basic filtering - remove ../ but can be bypassed
        sanitizedInput = input.replace(/\.\.\//g, "");
        
        if (input !== sanitizedInput) {
          notes.push("🛡️ Basic filter detected ../ sequences");
          notes.push("⚠️ But filter can be bypassed!");
        }

        // Check for bypass attempts
        if (input.includes("....//") || input.includes("..\\..\\")) {
          vulnerability = true;
          severity = "warning";
          fileContent = mockFiles["/etc/passwd" as keyof typeof mockFiles] || "File not found";
          notes.push(t("file_inclusion.filter_bypass_successful"));
          notes.push("💡 Used double encoding: ....// → ../");
        } else {
          fileContent = mockFiles[sanitizedInput as keyof typeof mockFiles] || "File not found";
          if (fileContent !== "File not found") {
            notes.push(t("file_inclusion.file_included_successfully"));
          }
        }
        break;

      case "hard":
        // More restrictive - only allow specific files
        const allowedFiles = ["home.php", "about.php"];
        
        if (allowedFiles.includes(input)) {
          fileContent = mockFiles[input as keyof typeof mockFiles] || "File not found";
          notes.push("✅ File allowed by whitelist");
        } else if (input.includes("php://filter") || input.includes("data://")) {
          vulnerability = true;
          severity = "warning";
          fileContent = "<?php system($_GET['cmd']); ?>";
          notes.push("🚨 PHP wrapper attack detected!");
          notes.push("💀 Code execution via php://filter or data:// wrapper");
        } else {
          fileContent = "Access denied - file not in whitelist";
          notes.push("🛡️ File blocked by whitelist");
        }
        break;

      case "impossible":
        // Secure implementation - proper validation
        const secureFiles = ["home.php", "about.php"];
        const basename = input.split("/").pop() || "";
        
        if (secureFiles.includes(basename) && !input.includes("..") && !input.includes("://")) {
          fileContent = mockFiles[basename as keyof typeof mockFiles] || "File not found";
          notes.push("✅ Secure file inclusion");
        } else {
          fileContent = "Access denied - security violation";
          notes.push("🛡️ Secure validation prevents all attacks");
        }
        severity = "success";
        break;
    }

    // Add prevention tips
    prevention = [
      "Use whitelist of allowed files",
      "Validate file paths against allowed patterns",
      "Never trust user input for file paths",
      "Use proper file permissions",
      "Disable dangerous PHP wrappers if not needed",
      "Implement proper error handling"
    ];

    return {
      fileRequest: input,
      fileContent,
      vulnerability,
      severity,
      notes,
      prevention
    };
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setIsLoading(true);
    
    // Simulate network delay
    await new Promise(resolve => setTimeout(resolve, 800));
    
    const result = simulateFileInclusion(userInput);
    setResults(result);
    setIsLoading(false);
  };

  const getSeverityIcon = (severity: string) => {
    switch (severity) {
      case "danger": return <XCircle className="h-5 w-5 text-danger" />;
      case "warning": return <AlertTriangle className="h-5 w-5 text-warning" />;
      case "success": return <CheckCircle className="h-5 w-5 text-success" />;
      default: return <AlertCircle className="h-5 w-5 text-info" />;
    }
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold text-foreground flex items-center gap-2">
            <FileText className="h-8 w-8 text-primary" />
            {t("file_inclusion.title")}
          </h1>
          <p className="text-lg text-muted-foreground mt-2">
            {t("file_inclusion.description")}
          </p>
        </div>
        <Badge variant="outline" className="text-sm">
          Level: {t(`difficulty.${difficulty}`)}
        </Badge>
      </div>

      {/* File Viewer Simulation */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <FileText className="h-5 w-5" />
            {t("file_inclusion.file_viewer")}
          </CardTitle>
          <CardDescription>
            {t("file_inclusion.file_viewer_desc")}
          </CardDescription>
        </CardHeader>
        <CardContent>
          <form onSubmit={handleSubmit} className="space-y-4">
            <div>
              <label htmlFor="file-input" className="block text-sm font-medium mb-2">
                {t("file_inclusion.file_to_include")}
              </label>
              <Input
                id="file-input"
                value={userInput}
                onChange={(e) => setUserInput(e.target.value)}
                placeholder={t("file_inclusion.file_placeholder")}
                className="w-full"
              />
            </div>
            <Button type="submit" disabled={isLoading} className="w-full">
              {isLoading ? t("file_inclusion.loading") : t("file_inclusion.include_file")}
            </Button>
          </form>
        </CardContent>
      </Card>

      {/* Results */}
      {results && (
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              {getSeverityIcon(results.severity)}
              {t("file_inclusion.analysis")}
            </CardTitle>
          </CardHeader>
          <CardContent className="space-y-4">
            {/* File Request */}
            <div>
              <h4 className="font-semibold text-foreground mb-2">{t("file_inclusion.requested_file")}</h4>
              <code className="block bg-muted p-3 rounded-md text-sm font-mono">
                include("{results.fileRequest}")
              </code>
            </div>

            {/* File Content */}
            <div>
              <h4 className="font-semibold text-foreground mb-2">{t("file_inclusion.file_contents")}</h4>
              <pre className="bg-muted p-3 rounded-md text-sm font-mono whitespace-pre-wrap max-h-40 overflow-y-auto">
                {results.fileContent}
              </pre>
            </div>

            {/* Security Analysis */}
            <div>
              <h4 className="font-semibold text-foreground mb-2">{t("file_inclusion.security_analysis")}</h4>
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
                {t("file_inclusion.prevention_methods")}
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

      {/* Common Payloads */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <AlertTriangle className="h-5 w-5 text-warning" />
            {t("file_inclusion.common_payloads")}
          </CardTitle>
        </CardHeader>
        <CardContent>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div>
              <h4 className="font-semibold mb-2">{t("file_inclusion.path_traversal")}</h4>
              <div className="space-y-1 text-sm font-mono bg-muted p-3 rounded-md">
                <div>../../../etc/passwd</div>
                <div>....//....//etc/passwd</div>
                <div>..%2F..%2F..%2Fetc%2Fpasswd</div>
                <div>/etc/passwd%00</div>
              </div>
            </div>
            <div>
              <h4 className="font-semibold mb-2">{t("file_inclusion.php_wrappers")}</h4>
              <div className="space-y-1 text-sm font-mono bg-muted p-3 rounded-md">
                <div>php://filter/read=convert.base64-encode/resource=config</div>
                <div>data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7Pz4=</div>
                <div>expect://id</div>
              </div>
            </div>
          </div>
        </CardContent>
      </Card>
    </div>
  );
};