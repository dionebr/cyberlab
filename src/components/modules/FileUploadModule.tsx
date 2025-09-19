import { useState, useRef } from "react";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Upload, File, AlertTriangle, CheckCircle, XCircle, Shield, Image } from "lucide-react";
import { useLanguage } from "@/hooks/useLanguage";

interface FileUploadModuleProps {
  difficulty: string;
}

interface UploadResult {
  filename: string;
  originalName: string;
  fileType: string;
  fileSize: number;
  uploaded: boolean;
  vulnerability: boolean;
  severity: string;
  notes: string[];
  prevention: string[];
  executionPath?: string;
}

export const FileUploadModule = ({ difficulty }: FileUploadModuleProps) => {
  const { t } = useLanguage();
  const [selectedFile, setSelectedFile] = useState<File | null>(null);
  const [results, setResults] = useState<UploadResult | null>(null);
  const [isUploading, setIsUploading] = useState(false);
  const fileInputRef = useRef<HTMLInputElement>(null);

  const simulateFileUpload = (file: File): UploadResult => {
    let uploaded = false;
    let vulnerability = false;
    let severity = "info";
    let notes: string[] = [];
    let prevention: string[] = [];
    let executionPath: string | undefined;

    const fileName = file.name.toLowerCase();
    const fileExt = fileName.split('.').pop() || '';
    const fileSize = file.size;
    const fileType = file.type;

    // Apply different security levels based on difficulty
    switch (difficulty) {
      case "easy":
        // No validation - accept everything
        uploaded = true;
        
        // Check for malicious files
        const maliciousExtensions = ['php', 'jsp', 'asp', 'aspx', 'sh', 'bat', 'exe'];
        if (maliciousExtensions.includes(fileExt)) {
          vulnerability = true;
          severity = "danger";
          executionPath = `/uploads/${file.name}`;
          notes.push("🚨 Malicious file uploaded successfully!");
          notes.push(`💀 ${fileExt.toUpperCase()} file can be executed on server`);
          notes.push("🔓 No file type validation implemented");
          notes.push(`⚡ Access webshell at: ${executionPath}`);
        } else {
          notes.push("✅ File uploaded successfully");
          notes.push("📁 File stored in uploads directory");
        }
        break;

      case "medium":
        // Basic MIME type checking but can be bypassed
        const allowedMimeTypes = ['image/jpeg', 'image/png', 'image/gif', 'text/plain'];
        
        if (allowedMimeTypes.includes(fileType)) {
          uploaded = true;
          notes.push("✅ File passed MIME type validation");
          
          // But check for bypass attempts
          if (fileName.includes('.php') || fileName.includes('.jsp')) {
            vulnerability = true;
            severity = "warning";
            executionPath = `/uploads/${file.name}`;
            notes.push("🚨 MIME type bypass detected!");
            notes.push("⚠️ File extension suggests executable content");
            notes.push("🔄 Content-Type header was spoofed");
          }
        } else {
          notes.push("🛡️ File rejected due to invalid MIME type");
          notes.push(`❌ ${fileType} not in allowed types`);
        }
        break;

      case "hard":
        // Extension blacklist but vulnerable to bypass
        const blockedExtensions = ['php', 'jsp', 'asp', 'exe', 'bat', 'sh'];
        
        if (blockedExtensions.includes(fileExt)) {
          notes.push("🛡️ Dangerous file extension blocked");
          notes.push(`❌ .${fileExt} files are not allowed`);
        } else if (fileName.includes('.php.') || fileName.includes('.jpg.php')) {
          // Double extension bypass
          vulnerability = true;
          severity = "warning";
          uploaded = true;
          executionPath = `/uploads/${file.name}`;
          notes.push("🚨 Double extension bypass successful!");
          notes.push("⚠️ File.php.jpg bypassed extension filter");
          notes.push("💡 Server may execute as PHP despite .jpg extension");
        } else {
          uploaded = true;
          notes.push("✅ File passed extension validation");
        }
        break;

      case "impossible":
        // Secure implementation
        const safeExtensions = ['jpg', 'jpeg', 'png', 'gif', 'txt', 'pdf'];
        const maxSize = 5 * 1024 * 1024; // 5MB
        
        // Multiple validation layers
        if (fileSize > maxSize) {
          notes.push("❌ File too large (max 5MB)");
        } else if (!safeExtensions.includes(fileExt)) {
          notes.push("❌ File extension not allowed");
        } else if (!fileType.startsWith('image/') && fileType !== 'text/plain' && fileType !== 'application/pdf') {
          notes.push("❌ Invalid MIME type");
        } else {
          uploaded = true;
          severity = "success";
          notes.push("✅ File uploaded securely");
          notes.push("🛡️ Multiple validation layers passed");
          notes.push("🔒 File renamed and stored safely");
          notes.push("🚫 Execution prevented by server configuration");
        }
        break;
    }

    // Add prevention tips
    prevention = [
      "Use whitelist of allowed file extensions",
      "Validate MIME types on server-side",
      "Implement file size limits",
      "Rename uploaded files to prevent execution",
      "Store uploads outside web root",
      "Scan files for malicious content",
      "Use Content-Disposition: attachment headers",
      "Implement virus scanning for uploads"
    ];

    return {
      filename: uploaded ? `upload_${Date.now()}_${file.name}` : file.name,
      originalName: file.name,
      fileType,
      fileSize,
      uploaded,
      vulnerability,
      severity,
      notes,
      prevention,
      executionPath
    };
  };

  const handleFileSelect = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (file) {
      setSelectedFile(file);
      setResults(null);
    }
  };

  const handleUpload = async () => {
    if (!selectedFile) return;
    
    setIsUploading(true);
    
    // Simulate upload delay
    await new Promise(resolve => setTimeout(resolve, 1000));
    
    const result = simulateFileUpload(selectedFile);
    setResults(result);
    setIsUploading(false);
  };

  const getSeverityIcon = (severity: string) => {
    switch (severity) {
      case "danger": return <XCircle className="h-5 w-5 text-danger" />;
      case "warning": return <AlertTriangle className="h-5 w-5 text-warning" />;
      case "success": return <CheckCircle className="h-5 w-5 text-success" />;
      default: return <File className="h-5 w-5 text-info" />;
    }
  };

  const formatFileSize = (bytes: number) => {
    if (bytes === 0) return '0 Bytes';
    const k = 1024;
    const sizes = ['Bytes', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold text-foreground flex items-center gap-2">
            <Upload className="h-8 w-8 text-primary" />
            File Upload Security
          </h1>
          <p className="text-lg text-muted-foreground mt-2">
            Learn about file upload vulnerabilities and security bypass techniques
          </p>
        </div>
        <Badge variant="outline" className="text-sm">
          Level: {difficulty}
        </Badge>
      </div>

      {/* File Upload Form */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Upload className="h-5 w-5" />
            Document Upload System
          </CardTitle>
          <CardDescription>
            Upload your files to the secure document management system
          </CardDescription>
        </CardHeader>
        <CardContent>
          <div className="space-y-4">
            <div>
              <input
                type="file"
                ref={fileInputRef}
                onChange={handleFileSelect}
                className="hidden"
              />
              <Button
                onClick={() => fileInputRef.current?.click()}
                variant="outline"
                className="w-full h-32 border-dashed"
              >
                <div className="text-center">
                  <Upload className="h-8 w-8 mx-auto mb-2 text-muted-foreground" />
                  <div className="text-sm">Click to select file</div>
                </div>
              </Button>
            </div>

            {selectedFile && (
              <div className="p-4 bg-muted rounded-lg">
                <div className="flex items-center gap-3">
                  <File className="h-8 w-8 text-primary" />
                  <div className="flex-1">
                    <div className="font-medium">{selectedFile.name}</div>
                    <div className="text-sm text-muted-foreground">
                      {formatFileSize(selectedFile.size)} • {selectedFile.type || 'Unknown type'}
                    </div>
                  </div>
                </div>
              </div>
            )}

            <Button
              onClick={handleUpload}
              disabled={!selectedFile || isUploading}
              className="w-full"
            >
              {isUploading ? "Uploading..." : "Upload File"}
            </Button>
          </div>
        </CardContent>
      </Card>

      {/* Upload Results */}
      {results && (
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              {getSeverityIcon(results.severity)}
              Upload Analysis
            </CardTitle>
          </CardHeader>
          <CardContent className="space-y-4">
            {/* Upload Status */}
            <div className="flex items-center gap-2 p-4 rounded-lg border">
              {results.uploaded ? (
                <>
                  <CheckCircle className="h-6 w-6 text-success" />
                  <span className="font-semibold text-success">Upload Successful</span>
                </>
              ) : (
                <>
                  <XCircle className="h-6 w-6 text-danger" />
                  <span className="font-semibold text-danger">Upload Rejected</span>
                </>
              )}
            </div>

            {/* File Information */}
            <div>
              <h4 className="font-semibold text-foreground mb-2">File Information:</h4>
              <div className="bg-muted p-3 rounded-md space-y-1 text-sm">
                <div><strong>Original Name:</strong> {results.originalName}</div>
                {results.uploaded && <div><strong>Stored As:</strong> {results.filename}</div>}
                <div><strong>Type:</strong> {results.fileType}</div>
                <div><strong>Size:</strong> {formatFileSize(results.fileSize)}</div>
              </div>
            </div>

            {/* Execution Path */}
            {results.executionPath && (
              <div>
                <h4 className="font-semibold text-foreground mb-2">⚠️ Potential Webshell Access:</h4>
                <code className="block bg-danger/10 border border-danger/20 p-3 rounded text-sm">
                  {results.executionPath}
                </code>
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

      {/* Attack Examples */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <AlertTriangle className="h-5 w-5 text-warning" />
            Common Upload Attack Techniques
          </CardTitle>
        </CardHeader>
        <CardContent>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div>
              <h4 className="font-semibold mb-2">File Extension Bypasses:</h4>
              <div className="space-y-1 text-sm font-mono bg-muted p-3 rounded-md">
                <div>shell.php.jpg</div>
                <div>shell.php%00.jpg</div>
                <div>shell.pHp</div>
                <div>shell.php5</div>
              </div>
            </div>
            <div>
              <h4 className="font-semibold mb-2">MIME Type Spoofing:</h4>
              <div className="space-y-1 text-sm bg-muted p-3 rounded-md">
                <div>• Change Content-Type header</div>
                <div>• Use image headers in PHP files</div>
                <div>• Polyglot files (valid image + code)</div>
                <div>• Magic bytes manipulation</div>
              </div>
            </div>
          </div>
        </CardContent>
      </Card>
    </div>
  );
};