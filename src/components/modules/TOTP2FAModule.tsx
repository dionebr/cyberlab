import React, { useState, useEffect, useRef } from 'react';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Badge } from '@/components/ui/badge';
import { useToast } from '@/hooks/use-toast';
import { useSecurityLevelContext } from '@/contexts/SecurityLevelContext';
import { useLanguage } from '@/hooks/useLanguage';

interface LoginAttempt {
  id: string;
  username: string;
  timestamp: string;
  success: boolean;
  ip: string;
  userAgent: string;
  step: 'password' | '2fa';
}

interface User {
  username: string;
  password: string;
  secret?: string;
  enabled2fa: boolean;
}

export const TOTP2FAModule: React.FC = () => {
  const [users] = useState<User[]>([
    { username: 'admin', password: 'admin123', enabled2fa: false },
    { username: 'user', password: 'password', enabled2fa: false },
    { username: 'test', password: 'test123', enabled2fa: false }
  ]);
  
  const [currentUser, setCurrentUser] = useState<User | null>(null);
  const [loginAttempts, setLoginAttempts] = useState<LoginAttempt[]>([]);
  const [isLoggedIn, setIsLoggedIn] = useState(false);
  const [loginStep, setLoginStep] = useState<'credentials' | '2fa' | 'complete'>('credentials');
  
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [totpCode, setTotpCode] = useState('');
  const [qrCodeUrl, setQrCodeUrl] = useState('');
  const [secret, setSecret] = useState('');
  
  const { securityLevel } = useSecurityLevelContext();
  const { t } = useLanguage();
  const { toast } = useToast();
  const attemptsRef = useRef<number>(0);

  // Generate TOTP secret based on security level
  const generateSecret = (username: string): string => {
    switch (securityLevel) {
      case 'easy':
        // Easy: Weak secret generation
        return btoa(`${username}_secret_123`).substring(0, 16).toUpperCase();
      case 'medium':
        // Medium: Better but still flawed
        return btoa(Math.random().toString() + username + Date.now()).substring(0, 16).toUpperCase();
      case 'hard':
        // Hard: Strong but with implementation flaws
        const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
        let result = '';
        for (let i = 0; i < 32; i++) {
          result += chars.charAt(Math.floor(Math.random() * chars.length));
        }
        return result;
      default:
        return 'JBSWY3DPEHPK3PXP';
    }
  };

  // Generate QR code URL
  const generateQRCode = (username: string, secret: string): string => {
    const issuer = 'CyberLab';
    const label = `${issuer}:${username}`;
    const otpauth = `otpauth://totp/${encodeURIComponent(label)}?secret=${secret}&issuer=${encodeURIComponent(issuer)}`;
    return `https://api.qrserver.com/v1/create-qr-code/?size=200x200&data=${encodeURIComponent(otpauth)}`;
  };

  // Simple TOTP implementation
  const generateTOTP = (secret: string, timestamp?: number): string => {
    const timeStep = securityLevel === 'easy' ? 600 : 30; // 10 minutes for easy, 30 seconds for others
    const currentTime = timestamp || Math.floor(Date.now() / 1000);
    const counter = Math.floor(currentTime / timeStep);
    
    // Simplified TOTP calculation (not cryptographically secure, for demo only)
    const hash = btoa(secret + counter.toString()).replace(/[^0-9]/g, '');
    return hash.substring(0, 6).padStart(6, '0');
  };

  // Validate TOTP code
  const validateTOTP = (userSecret: string, code: string): boolean => {
    const timeStep = securityLevel === 'easy' ? 600 : 30;
    const currentTime = Math.floor(Date.now() / 1000);
    
    // Check current time window and previous/next windows for clock skew
    for (let i = -1; i <= 1; i++) {
      const testTime = currentTime + (i * timeStep);
      const expectedCode = generateTOTP(userSecret, testTime);
      
      // Security flaw in medium: non-constant time comparison
      if (securityLevel === 'medium') {
        if (code === expectedCode) return true;
      } else {
        // Constant time comparison for other levels
        let match = code.length === expectedCode.length;
        for (let j = 0; j < Math.max(code.length, expectedCode.length); j++) {
          match = match && (code[j] === expectedCode[j]);
        }
        if (match) return true;
      }
    }
    return false;
  };

  // Add login attempt
  const addLoginAttempt = (username: string, success: boolean, step: 'password' | '2fa') => {
    const attempt: LoginAttempt = {
      id: Date.now().toString(),
      username,
      timestamp: new Date().toISOString(),
      success,
      ip: '192.168.1.100',
      userAgent: navigator.userAgent,
      step
    };
    setLoginAttempts(prev => [attempt, ...prev].slice(0, 50));
  };

  // Handle credential login
  const handleCredentialLogin = () => {
    const user = users.find(u => u.username === username && u.password === password);
    
    if (!user) {
      addLoginAttempt(username, false, 'password');
      toast({
        title: "Login Failed",
        description: "Invalid credentials",
        variant: "destructive"
      });
      return;
    }

    addLoginAttempt(username, true, 'password');
    setCurrentUser(user);

    if (user.enabled2fa && user.secret) {
      setLoginStep('2fa');
    } else {
      // Security flaw in medium: create pre-authenticated session
      if (securityLevel === 'medium') {
        sessionStorage.setItem('preauth_user', username);
      }
      setIsLoggedIn(true);
      setLoginStep('complete');
    }
  };

  // Handle 2FA verification
  const handle2FAVerification = () => {
    if (!currentUser || !currentUser.secret) return;

    // Security flaw in medium: no rate limiting
    if (securityLevel === 'medium') {
      attemptsRef.current += 1;
    } else if (securityLevel !== 'easy' && attemptsRef.current >= 3) {
      toast({
        title: "Too Many Attempts",
        description: "Account temporarily locked",
        variant: "destructive"
      });
      return;
    }

    const isValid = validateTOTP(currentUser.secret, totpCode);
    
    if (isValid) {
      addLoginAttempt(currentUser.username, true, '2fa');
      setIsLoggedIn(true);
      setLoginStep('complete');
      attemptsRef.current = 0;
      
      // Security flaw in medium: bypass password check with pre-auth session
      if (securityLevel === 'medium' && sessionStorage.getItem('preauth_user')) {
        sessionStorage.removeItem('preauth_user');
      }
    } else {
      addLoginAttempt(currentUser.username, false, '2fa');
      toast({
        title: "Invalid Code",
        description: "Please check your authenticator app",
        variant: "destructive"
      });
    }
  };

  // Enable 2FA for user
  const enable2FA = () => {
    if (!currentUser) return;
    
    const newSecret = generateSecret(currentUser.username);
    const updatedUser = { ...currentUser, secret: newSecret, enabled2fa: true };
    
    setCurrentUser(updatedUser);
    setSecret(newSecret);
    setQrCodeUrl(generateQRCode(currentUser.username, newSecret));
    
    // Security flaw in hard: expose secret in response (check browser dev tools)
    if (securityLevel === 'hard') {
      console.log('DEBUG: TOTP Secret exposed:', newSecret);
      // Simulate API response that leaks secret
      document.getElementById('hidden-secret')?.setAttribute('data-secret', newSecret);
    }
  };

  // Logout
  const logout = () => {
    setIsLoggedIn(false);
    setCurrentUser(null);
    setLoginStep('credentials');
    setUsername('');
    setPassword('');
    setTotpCode('');
    setSecret('');
    setQrCodeUrl('');
    attemptsRef.current = 0;
    sessionStorage.clear();
  };

  const getSecurityLevelInfo = () => {
    switch (securityLevel) {
      case 'easy':
        return {
          title: "Easy - The Predictable Token",
          description: "Weak secret generation and long time window (10 minutes). Secret may be predictable.",
          vulnerabilities: ["Weak secret generation", "10-minute time window", "No replay protection", "Secret exposure"]
        };
      case 'medium':
        return {
          title: "Medium - The Flawed Validation",
          description: "Flawed validation logic and session handling. No rate limiting on 2FA attempts.",
          vulnerabilities: ["Pre-authentication bypass", "No rate limiting", "Timing attack vulnerability", "Session state confusion"]
        };
      case 'hard':
        return {
          title: "Hard - The Cryptographic Leak",
          description: "Strong implementation but with subtle secret leakage. Check browser developer tools.",
          vulnerabilities: ["Secret exposed in responses", "Hidden in HTML/JSON", "Debug information leakage", "Client-side exposure"]
        };
      default:
        return { title: "", description: "", vulnerabilities: [] };
    }
  };

  const levelInfo = getSecurityLevelInfo();

  return (
    <div className="space-y-6">
      {/* Header */}
      <Card>
        <CardHeader>
          <div className="flex justify-between items-center">
            <div>
              <CardTitle className="flex items-center gap-2">
                🔐 TOTP/2FA Authentication
                <Badge variant={securityLevel === 'easy' ? 'destructive' : securityLevel === 'medium' ? 'default' : 'secondary'}>
                  {securityLevel?.toUpperCase()}
                </Badge>
              </CardTitle>
              <p className="text-sm text-muted-foreground mt-2">{levelInfo.description}</p>
            </div>
            <Button variant="outline" onClick={logout}>Logout</Button>
          </div>
        </CardHeader>
      </Card>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Main Interface */}
        <Card>
          <CardHeader>
            <CardTitle>Authentication Interface</CardTitle>
          </CardHeader>
          <CardContent className="space-y-4">
            {!isLoggedIn ? (
              <>
                {loginStep === 'credentials' && (
                  <div className="space-y-4">
                    <div>
                      <Label htmlFor="username">Username</Label>
                      <Input
                        id="username"
                        value={username}
                        onChange={(e) => setUsername(e.target.value)}
                        placeholder="Enter username"
                      />
                    </div>
                    <div>
                      <Label htmlFor="password">Password</Label>
                      <Input
                        id="password"
                        type="password"
                        value={password}
                        onChange={(e) => setPassword(e.target.value)}
                        placeholder="Enter password"
                      />
                    </div>
                    <Button onClick={handleCredentialLogin} className="w-full">
                      Login
                    </Button>
                    <div className="text-sm text-muted-foreground">
                      <p>Try: admin/admin123, user/password, test/test123</p>
                    </div>
                  </div>
                )}

                {loginStep === '2fa' && (
                  <div className="space-y-4">
                    <div className="text-center">
                      <h3 className="font-semibold">Two-Factor Authentication</h3>
                      <p className="text-sm text-muted-foreground">
                        Enter the 6-digit code from your authenticator app
                      </p>
                    </div>
                    <div>
                      <Label htmlFor="totpCode">Authentication Code</Label>
                      <Input
                        id="totpCode"
                        value={totpCode}
                        onChange={(e) => setTotpCode(e.target.value)}
                        placeholder="000000"
                        maxLength={6}
                        className="text-center text-2xl tracking-widest"
                      />
                    </div>
                    <Button onClick={handle2FAVerification} className="w-full">
                      Verify Code
                    </Button>
                    <Button variant="outline" onClick={() => setLoginStep('credentials')} className="w-full">
                      Back to Login
                    </Button>
                  </div>
                )}
              </>
            ) : (
              <div className="text-center space-y-4">
                <div className="p-6 bg-green-50 dark:bg-green-950 rounded-lg">
                  <h3 className="text-xl font-semibold text-green-800 dark:text-green-200">
                    Welcome, {currentUser?.username}!
                  </h3>
                  <p className="text-green-600 dark:text-green-300">
                    You are successfully authenticated
                  </p>
                </div>
                
                {!currentUser?.enabled2fa && (
                  <div className="space-y-4">
                    <Button onClick={enable2FA} className="w-full">
                      Enable Two-Factor Authentication
                    </Button>
                  </div>
                )}

                {qrCodeUrl && (
                  <div className="space-y-4">
                    <h4 className="font-semibold">Setup 2FA</h4>
                    <div className="flex justify-center">
                      <img src={qrCodeUrl} alt="QR Code" className="border rounded" />
                    </div>
                    <div className="text-sm space-y-2">
                      <p>Scan this QR code with your authenticator app</p>
                      <p className="font-mono text-xs bg-muted p-2 rounded">Secret: {secret}</p>
                    </div>
                  </div>
                )}
              </div>
            )}
          </CardContent>
        </Card>

        {/* Login Attempts Dashboard */}
        <Card>
          <CardHeader>
            <CardTitle>Login Attempts Dashboard</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="space-y-2 max-h-96 overflow-y-auto">
              {loginAttempts.length === 0 ? (
                <p className="text-muted-foreground text-sm">No login attempts yet</p>
              ) : (
                loginAttempts.map((attempt) => (
                  <div key={attempt.id} className="flex items-center justify-between p-2 border rounded text-sm">
                    <div>
                      <div className="font-medium">{attempt.username}</div>
                      <div className="text-muted-foreground">
                        {new Date(attempt.timestamp).toLocaleString()} • {attempt.step}
                      </div>
                    </div>
                    <Badge variant={attempt.success ? "default" : "destructive"}>
                      {attempt.success ? "Success" : "Failed"}
                    </Badge>
                  </div>
                ))
              )}
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Vulnerability Information */}
      <Card>
        <CardHeader>
          <CardTitle>{levelInfo.title}</CardTitle>
        </CardHeader>
        <CardContent>
          <div className="space-y-4">
            <div>
              <h4 className="font-semibold mb-2">Vulnerabilities in this level:</h4>
              <ul className="space-y-1">
                {levelInfo.vulnerabilities.map((vuln, index) => (
                  <li key={index} className="flex items-center gap-2">
                    <span className="w-2 h-2 bg-red-500 rounded-full"></span>
                    <span className="text-sm">{vuln}</span>
                  </li>
                ))}
              </ul>
            </div>
            
            {securityLevel === 'easy' && (
              <div className="bg-yellow-50 dark:bg-yellow-950 p-4 rounded border">
                <h5 className="font-semibold text-yellow-800 dark:text-yellow-200">Exploitation Tips:</h5>
                <ul className="text-sm text-yellow-700 dark:text-yellow-300 mt-2 space-y-1">
                  <li>• Try brute-forcing the 6-digit code (10-minute window)</li>
                  <li>• Check if the secret follows a predictable pattern</li>
                  <li>• Test code reuse within the same time window</li>
                </ul>
              </div>
            )}
            
            {securityLevel === 'medium' && (
              <div className="bg-orange-50 dark:bg-orange-950 p-4 rounded border">
                <h5 className="font-semibold text-orange-800 dark:text-orange-200">Exploitation Tips:</h5>
                <ul className="text-sm text-orange-700 dark:text-orange-300 mt-2 space-y-1">
                  <li>• No rate limiting on 2FA attempts - brute force possible</li>
                  <li>• Check session handling for pre-authentication bypass</li>
                  <li>• Try timing attacks on code validation</li>
                </ul>
              </div>
            )}
            
            {securityLevel === 'hard' && (
              <div className="bg-red-50 dark:bg-red-950 p-4 rounded border">
                <h5 className="font-semibold text-red-800 dark:text-red-200">Exploitation Tips:</h5>
                <ul className="text-sm text-red-700 dark:text-red-300 mt-2 space-y-1">
                  <li>• Enable 2FA and check browser Developer Tools</li>
                  <li>• Look for secrets in Network tab responses</li>
                  <li>• Check Console for debug information</li>
                  <li>• Inspect HTML source for hidden data attributes</li>
                </ul>
              </div>
            )}
          </div>
        </CardContent>
      </Card>

      {/* Hidden element for hard level vulnerability */}
      <div id="hidden-secret" style={{ display: 'none' }} data-secret=""></div>
    </div>
  );
};