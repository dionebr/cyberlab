import React, { useState, useEffect } from 'react';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Badge } from '@/components/ui/badge';
import { useToast } from '@/hooks/use-toast';
import { useSecurityLevelContext } from '@/contexts/SecurityLevelContext';
import { useLanguage } from '@/hooks/useLanguage';
import { Textarea } from '@/components/ui/textarea';
import JWTDecoder from '@/components/JWTDecoder';

interface User {
  username: string;
  password: string;
  role: string;
}

interface JWTPayload {
  sub: string;
  username: string;
  role: string;
  iat: number;
  exp: number;
  aud?: string;
  iss?: string;
}

interface JWTHeader {
  alg: string;
  typ: string;
  jku?: string;
}

export const JWTAuthenticationModule: React.FC = () => {
  const [users] = useState<User[]>([
    { username: 'admin', password: 'admin123', role: 'admin' },
    { username: 'user', password: 'password', role: 'user' },
    { username: 'guest', password: 'guest123', role: 'guest' }
  ]);
  
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [token, setToken] = useState('');
  const [decodedToken, setDecodedToken] = useState<any>(null);
  const [isLoggedIn, setIsLoggedIn] = useState(false);
  const [currentUser, setCurrentUser] = useState<User | null>(null);
  const [publicKey, setPublicKey] = useState('');
  const [customToken, setCustomToken] = useState('');
  const [maliciousJKU, setMaliciousJKU] = useState('');
  
  const { securityLevel } = useSecurityLevelContext();
  const { t } = useLanguage();
  const { toast } = useToast();

  // Weak secret for easy level
  const WEAK_SECRET = 'secret';
  const STRONG_SECRET = 'cyberlab_super_secret_key_2024_random_string_very_long_and_secure';
  
  // RSA keys for asymmetric algorithms (simplified for demo)
  const PUBLIC_KEY = `-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA4f5wg5l2hKsTeNem/V41
fGnJm6gOdrj8ym3rFkEjWT2btf1cZjCZwlNyX8J2VuGzXJzEgUVTXexzJqd6C7l5
-----END PUBLIC KEY-----`;

  const PRIVATE_KEY = `-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDh/nCDmXaEqxN4
16b9XjV8acmbqA52uPzKbesWQSNZPZu1/VxmMJnCU3JfwnZW4bNcnMSBRVNd7HMm
-----END PRIVATE KEY-----`;

  useEffect(() => {
    // Expose public key for medium level attack
    if (securityLevel === 'medium') {
      setPublicKey(PUBLIC_KEY);
    }
  }, [securityLevel]);

  // Base64 URL encode/decode functions
  const base64UrlEncode = (str: string): string => {
    return btoa(str).replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
  };

  const base64UrlDecode = (str: string): string => {
    str += new Array(5 - str.length % 4).join('=');
    return atob(str.replace(/-/g, '+').replace(/_/g, '/'));
  };

  // Generate JWT based on security level
  const generateJWT = (user: User): string => {
    const header: JWTHeader = {
      alg: securityLevel === 'easy' ? 'HS256' : securityLevel === 'medium' ? 'RS256' : 'RS256',
      typ: 'JWT'
    };

    // Hard level: Add vulnerable jku header
    if (securityLevel === 'hard') {
      header.jku = 'https://cyberlab.com/.well-known/jwks.json';
    }

    const payload: JWTPayload = {
      sub: user.username,
      username: user.username,
      role: user.role,
      iat: Math.floor(Date.now() / 1000),
      exp: Math.floor(Date.now() / 1000) + (60 * 60), // 1 hour
      aud: 'cyberlab-users',
      iss: 'cyberlab-auth'
    };

    const encodedHeader = base64UrlEncode(JSON.stringify(header));
    const encodedPayload = base64UrlEncode(JSON.stringify(payload));
    
    // Simple signature simulation based on level
    let signature = '';
    if (securityLevel === 'easy') {
      // Weak HMAC with predictable secret
      signature = base64UrlEncode(`hmac_${WEAK_SECRET}_${encodedHeader}_${encodedPayload}`);
    } else {
      // Stronger signature (simulated)
      signature = base64UrlEncode(`rsa_signature_${Math.random().toString(36)}`);
    }

    return `${encodedHeader}.${encodedPayload}.${signature}`;
  };

  // Validate JWT based on security level
  const validateJWT = (token: string): { valid: boolean; payload?: JWTPayload; error?: string } => {
    try {
      const parts = token.split('.');
      if (parts.length !== 3) {
        return { valid: false, error: 'Invalid token format' };
      }

      const [encodedHeader, encodedPayload, signature] = parts;
      const header: JWTHeader = JSON.parse(base64UrlDecode(encodedHeader));
      const payload: JWTPayload = JSON.parse(base64UrlDecode(encodedPayload));

      // Easy level: Accept 'none' algorithm
      if (securityLevel === 'easy' && header.alg === 'none') {
        return { valid: true, payload };
      }

      // Medium level: Algorithm confusion vulnerability
      if (securityLevel === 'medium') {
        // Vulnerable: doesn't enforce specific algorithm
        if (header.alg === 'HS256' && publicKey) {
          // Attacker can sign with public key as HMAC secret
          const expectedSignature = base64UrlEncode(`hmac_${publicKey}_${encodedHeader}_${encodedPayload}`);
          if (signature === expectedSignature) {
            return { valid: true, payload };
          }
        }
      }

      // Hard level: JKU header vulnerability
      if (securityLevel === 'hard' && header.jku) {
        // Vulnerable: trusts user-controlled JKU header
        if (header.jku.startsWith('https://') && header.alg === 'RS256') {
          console.log('Fetching keys from JKU:', header.jku);
          // In real implementation, would fetch from JKU URL
          // For demo, accept if JKU is set
          return { valid: true, payload };
        }
      }

      // Check expiration
      if (payload.exp && payload.exp < Math.floor(Date.now() / 1000)) {
        return { valid: false, error: 'Token expired' };
      }

      // Simple validation for normal cases
      return { valid: true, payload };
    } catch (error) {
      return { valid: false, error: 'Invalid token' };
    }
  };

  // Handle login
  const handleLogin = () => {
    const user = users.find(u => u.username === username && u.password === password);
    
    if (!user) {
      toast({
        title: "Login Failed",
        description: "Invalid credentials",
        variant: "destructive"
      });
      return;
    }

    const jwtToken = generateJWT(user);
    setToken(jwtToken);
    setCurrentUser(user);
    setIsLoggedIn(true);
    
    // Decode token for display
    const validation = validateJWT(jwtToken);
    if (validation.valid) {
      setDecodedToken(validation.payload);
    }

    toast({
      title: "Login Successful",
      description: `Welcome ${user.username}! JWT token generated.`,
    });
  };

  // Handle custom token validation
  const handleCustomToken = () => {
    const validation = validateJWT(customToken);
    
    if (validation.valid && validation.payload) {
      setIsLoggedIn(true);
      setCurrentUser({ username: validation.payload.username, password: '', role: validation.payload.role });
      setDecodedToken(validation.payload);
      setToken(customToken);
      
      toast({
        title: "Token Accepted",
        description: `Authenticated as ${validation.payload.username}`,
      });
    } else {
      toast({
        title: "Invalid Token",
        description: validation.error || "Token validation failed",
        variant: "destructive"
      });
    }
  };

  // Logout
  const logout = () => {
    setIsLoggedIn(false);
    setCurrentUser(null);
    setToken('');
    setDecodedToken(null);
    setUsername('');
    setPassword('');
    setCustomToken('');
  };

  // Generate exploit examples
  const generateExploitExamples = () => {
    switch (securityLevel) {
      case 'easy':
        return {
          title: "None Algorithm Attack",
          description: "Remove signature and set algorithm to 'none'",
          example: generateNoneAlgToken(),
          steps: [
            "1. Decode the JWT header and payload",
            "2. Change the 'alg' field to 'none'",
            "3. Modify the payload (e.g., role: 'admin')",
            "4. Remove the signature part",
            "5. Encode and use the token"
          ]
        };
      case 'medium':
        return {
          title: "Algorithm Confusion Attack",
          description: "Use public key as HMAC secret for HS256",
          example: generateAlgConfusionToken(),
          steps: [
            "1. Obtain the public key from /public-key endpoint",
            "2. Create JWT with HS256 algorithm",
            "3. Sign with public key as HMAC secret",
            "4. Server will verify using public key, which succeeds"
          ]
        };
      case 'hard':
        return {
          title: "JKU Header Injection",
          description: "Control the JKU header to point to malicious key set",
          example: generateJKUToken(),
          steps: [
            "1. Host malicious JWK Set on your domain",
            "2. Create JWT with jku header pointing to your domain",
            "3. Sign with your private key",
            "4. Server fetches your public key and validates successfully"
          ]
        };
      default:
        return { title: "", description: "", example: "", steps: [] };
    }
  };

  // Generate exploit tokens
  const generateNoneAlgToken = (): string => {
    const header = { alg: 'none', typ: 'JWT' };
    const payload = { 
      sub: 'admin', 
      username: 'admin', 
      role: 'admin', 
      iat: Math.floor(Date.now() / 1000), 
      exp: Math.floor(Date.now() / 1000) + 3600 
    };
    
    const encodedHeader = base64UrlEncode(JSON.stringify(header));
    const encodedPayload = base64UrlEncode(JSON.stringify(payload));
    
    return `${encodedHeader}.${encodedPayload}.`;
  };

  const generateAlgConfusionToken = (): string => {
    const header = { alg: 'HS256', typ: 'JWT' };
    const payload = { 
      sub: 'admin', 
      username: 'admin', 
      role: 'admin', 
      iat: Math.floor(Date.now() / 1000), 
      exp: Math.floor(Date.now() / 1000) + 3600 
    };
    
    const encodedHeader = base64UrlEncode(JSON.stringify(header));
    const encodedPayload = base64UrlEncode(JSON.stringify(payload));
    const signature = base64UrlEncode(`hmac_${PUBLIC_KEY}_${encodedHeader}_${encodedPayload}`);
    
    return `${encodedHeader}.${encodedPayload}.${signature}`;
  };

  const generateJKUToken = (): string => {
    const header = { 
      alg: 'RS256', 
      typ: 'JWT',
      jku: maliciousJKU || 'https://attacker.com/.well-known/jwks.json'
    };
    const payload = { 
      sub: 'admin', 
      username: 'admin', 
      role: 'admin', 
      iat: Math.floor(Date.now() / 1000), 
      exp: Math.floor(Date.now() / 1000) + 3600 
    };
    
    const encodedHeader = base64UrlEncode(JSON.stringify(header));
    const encodedPayload = base64UrlEncode(JSON.stringify(payload));
    const signature = base64UrlEncode(`malicious_rsa_signature_${Math.random().toString(36)}`);
    
    return `${encodedHeader}.${encodedPayload}.${signature}`;
  };

  const getSecurityLevelInfo = () => {
    switch (securityLevel) {
      case 'easy':
        return {
          title: "Easy - The None Algorithm",
          description: "Server accepts 'none' algorithm and uses weak secret",
          vulnerabilities: ["Accepts 'none' algorithm", "Weak HMAC secret", "No algorithm validation", "Signature bypass"]
        };
      case 'medium':
        return {
          title: "Medium - Algorithm Confusion",
          description: "Server doesn't validate algorithm type, allowing confusion attacks",
          vulnerabilities: ["Algorithm confusion", "Public key as HMAC secret", "No algorithm enforcement", "Key type confusion"]
        };
      case 'hard':
        return {
          title: "Hard - JKU Header Injection",
          description: "Server trusts user-controlled JKU header for key fetching",
          vulnerabilities: ["JKU header injection", "Untrusted key sources", "URL validation bypass", "Remote key fetching"]
        };
      default:
        return { title: "", description: "", vulnerabilities: [] };
    }
  };

  const levelInfo = getSecurityLevelInfo();
  const exploitInfo = generateExploitExamples();

  return (
    <div className="space-y-6">
      {/* Header */}
      <Card>
        <CardHeader>
          <div className="flex justify-between items-center">
            <div>
              <CardTitle className="flex items-center gap-2">
                🔑 {t('jwt.title')}
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
        {/* Authentication Interface */}
        <Card>
          <CardHeader>
            <CardTitle>{t('jwt.title')}</CardTitle>
          </CardHeader>
          <CardContent className="space-y-4">
            {!isLoggedIn ? (
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
                <Button onClick={handleLogin} className="w-full">
                  {t('jwt.login_generate')}
                </Button>
                <div className="text-sm text-muted-foreground">
                  <p>Try: admin/admin123, user/password, guest/guest123</p>
                </div>
              </div>
            ) : (
              <div className="space-y-4">
                <div className="p-4 bg-green-50 dark:bg-green-950 rounded-lg">
                  <h3 className="font-semibold text-green-800 dark:text-green-200">
                    Authenticated as {currentUser?.username}
                  </h3>
                  <p className="text-sm text-green-600 dark:text-green-300">
                    Role: {currentUser?.role}
                  </p>
                </div>
              </div>
            )}
          </CardContent>
        </Card>

        {/* JWT Token Display */}
        <Card>
          <CardHeader>
            <CardTitle>{t('jwt.current_token')}</CardTitle>
          </CardHeader>
          <CardContent className="space-y-4">
            {token ? (
              <div className="space-y-4">
                <div>
                  <Label>Current Token</Label>
                  <Textarea
                    value={token}
                    readOnly
                    className="font-mono text-xs"
                    rows={4}
                  />
                </div>
                
                {decodedToken && (
                  <div>
                    <Label>Decoded Payload</Label>
                    <Textarea
                      value={JSON.stringify(decodedToken, null, 2)}
                      readOnly
                      className="font-mono text-xs"
                      rows={6}
                    />
                  </div>
                )}
              </div>
            ) : (
              <p className="text-muted-foreground">No token generated yet</p>
            )}
          </CardContent>
        </Card>
      </div>

      {/* Custom Token Testing */}
      <Card>
        <CardHeader>
          <CardTitle>Custom Token Testing</CardTitle>
        </CardHeader>
        <CardContent className="space-y-4">
          <div>
            <Label>Test Custom JWT Token</Label>
            <Textarea
              value={customToken}
              onChange={(e) => setCustomToken(e.target.value)}
              placeholder="Paste your JWT token here..."
              className="font-mono text-xs"
              rows={3}
            />
          </div>
          <Button onClick={handleCustomToken} disabled={!customToken}>
            Validate Token
          </Button>
        </CardContent>
      </Card>

      {/* Public Key Endpoint (Medium Level) */}
      {securityLevel === 'medium' && (
        <Card>
          <CardHeader>
            <CardTitle>🔓 Public Key Endpoint</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="space-y-2">
              <p className="text-sm text-muted-foreground">GET /public-key</p>
              <Textarea
                value={publicKey}
                readOnly
                className="font-mono text-xs"
                rows={4}
              />
            </div>
          </CardContent>
        </Card>
      )}

      {/* JKU Configuration (Hard Level) */}
      {securityLevel === 'hard' && (
        <Card>
          <CardHeader>
            <CardTitle>🌐 JKU Header Configuration</CardTitle>
          </CardHeader>
          <CardContent className="space-y-4">
            <div>
              <Label>Malicious JKU URL</Label>
              <Input
                value={maliciousJKU}
                onChange={(e) => setMaliciousJKU(e.target.value)}
                placeholder="https://attacker.com/.well-known/jwks.json"
              />
            </div>
            <p className="text-sm text-muted-foreground">
              The server will fetch keys from any HTTPS URL specified in the JKU header
            </p>
          </CardContent>
        </Card>
      )}

      {/* Exploit Information */}
      <Card>
        <CardHeader>
          <CardTitle>{levelInfo.title}</CardTitle>
        </CardHeader>
        <CardContent className="space-y-6">
          {/* Vulnerabilities */}
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

          {/* Exploit Example */}
          <div>
            <h4 className="font-semibold mb-2">{exploitInfo.title}</h4>
            <p className="text-sm text-muted-foreground mb-3">{exploitInfo.description}</p>
            
            {exploitInfo.example && (
              <div className="space-y-2">
                <Label>Example Exploit Token:</Label>
                <Textarea
                  value={exploitInfo.example}
                  readOnly
                  className="font-mono text-xs"
                  rows={3}
                />
                <Button 
                  variant="outline" 
                  size="sm"
                  onClick={() => setCustomToken(exploitInfo.example)}
                >
                  Load Example Token
                </Button>
              </div>
            )}

            {securityLevel === 'hard' && maliciousJKU && (
              <div className="mt-4 space-y-2">
                <Label>JKU Exploit Token:</Label>
                <Textarea
                  value={generateJKUToken()}
                  readOnly
                  className="font-mono text-xs"
                  rows={3}
                />
                <Button 
                  variant="outline" 
                  size="sm"
                  onClick={() => setCustomToken(generateJKUToken())}
                >
                  Load JKU Token
                </Button>
              </div>
            )}
          </div>

          {/* Exploitation Steps */}
          <div>
            <h4 className="font-semibold mb-2">Exploitation Steps:</h4>
            <ol className="list-decimal list-inside space-y-1">
              {exploitInfo.steps.map((step, index) => (
                <li key={index} className="text-sm text-muted-foreground">{step}</li>
              ))}
            </ol>
          </div>
        </CardContent>
      </Card>

      {/* JWT Decoder Tool */}
      <Card>
        <CardHeader>
          <CardTitle>{t('jwt.decoder_tool')}</CardTitle>
        </CardHeader>
        <CardContent>
          <JWTDecoder 
            initialToken={token || customToken}
            onTokenChange={(newToken) => {
              setCustomToken(newToken);
              // Auto-validate the token when it changes
              if (newToken) {
                try {
                  const result = validateJWT(newToken);
                  if (result.valid) {
                    setDecodedToken(result.payload);
                  }
                } catch (error) {
                  console.error('Token validation error:', error);
                }
              }
            }}
          />
        </CardContent>
      </Card>
    </div>
  );
};