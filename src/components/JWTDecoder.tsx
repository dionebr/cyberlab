import React, { useState, useEffect } from 'react';
import { Card, CardContent, CardHeader, CardTitle } from './ui/card';
import { Button } from './ui/button';
import { Textarea } from './ui/textarea';
import { Label } from './ui/label';
import { Input } from './ui/input';
import { Badge } from './ui/badge';
import { Copy, Eye, EyeOff, AlertTriangle, CheckCircle } from 'lucide-react';
import { useToast } from '@/hooks/use-toast';
import { useLanguageContext } from '@/contexts/LanguageContext';
import { cn } from '@/lib/utils';

interface JWTDecoderProps {
  className?: string;
  onTokenChange?: (token: string) => void;
  initialToken?: string;
}

interface JWTHeader {
  alg?: string;
  typ?: string;
  kid?: string;
  jku?: string;
  [key: string]: any;
}

interface JWTPayload {
  sub?: string;
  username?: string;
  role?: string;
  iat?: number;
  exp?: number;
  [key: string]: any;
}

interface DecodedJWT {
  header: JWTHeader;
  payload: JWTPayload;
  signature: string;
  isValid: boolean;
  error?: string;
}

const JWTDecoder: React.FC<JWTDecoderProps> = ({ 
  className,
  onTokenChange,
  initialToken = ""
}) => {
  const { t } = useLanguageContext();
  const { toast } = useToast();
  
  const [token, setToken] = useState(initialToken);
  const [decodedJWT, setDecodedJWT] = useState<DecodedJWT | null>(null);
  const [showSignature, setShowSignature] = useState(false);
  const [editedHeader, setEditedHeader] = useState('');
  const [editedPayload, setEditedPayload] = useState('');
  const [customSignature, setCustomSignature] = useState('');

  // Base64 URL decode
  const base64UrlDecode = (str: string): string => {
    try {
      const base64 = str.replace(/-/g, '+').replace(/_/g, '/');
      const pad = base64.length % 4;
      const padded = base64 + '='.repeat(pad === 0 ? 0 : 4 - pad);
      return atob(padded);
    } catch (error) {
      throw new Error('Invalid base64url encoding');
    }
  };

  // Base64 URL encode
  const base64UrlEncode = (str: string): string => {
    return btoa(str)
      .replace(/\+/g, '-')
      .replace(/\//g, '_')
      .replace(/=/g, '');
  };

  // Decode JWT
  const decodeJWT = (jwtToken: string): DecodedJWT => {
    try {
      const parts = jwtToken.split('.');
      
      if (parts.length !== 3) {
        throw new Error('Invalid JWT format. Expected 3 parts separated by dots.');
      }

      const [headerB64, payloadB64, signatureB64] = parts;

      // Decode header
      const headerJson = base64UrlDecode(headerB64);
      const header: JWTHeader = JSON.parse(headerJson);

      // Decode payload
      const payloadJson = base64UrlDecode(payloadB64);
      const payload: JWTPayload = JSON.parse(payloadJson);

      // Signature (keep encoded)
      const signature = signatureB64;

      return {
        header,
        payload,
        signature,
        isValid: true
      };
    } catch (error) {
      return {
        header: {},
        payload: {},
        signature: '',
        isValid: false,
        error: error instanceof Error ? error.message : 'Unknown error'
      };
    }
  };

  // Generate JWT from components
  const generateJWT = (header: JWTHeader, payload: JWTPayload, signature: string): string => {
    try {
      const headerB64 = base64UrlEncode(JSON.stringify(header, null, 0));
      const payloadB64 = base64UrlEncode(JSON.stringify(payload, null, 0));
      return `${headerB64}.${payloadB64}.${signature}`;
    } catch (error) {
      return '';
    }
  };

  // Handle token change
  useEffect(() => {
    if (token.trim()) {
      const decoded = decodeJWT(token);
      setDecodedJWT(decoded);
      
      if (decoded.isValid) {
        setEditedHeader(JSON.stringify(decoded.header, null, 2));
        setEditedPayload(JSON.stringify(decoded.payload, null, 2));
        setCustomSignature(decoded.signature);
      }
    } else {
      setDecodedJWT(null);
      setEditedHeader('');
      setEditedPayload('');
      setCustomSignature('');
    }
    
    onTokenChange?.(token);
  }, [token, onTokenChange]);

  // Copy to clipboard
  const copyToClipboard = async (text: string, label: string) => {
    try {
      await navigator.clipboard.writeText(text);
      toast({
        title: t('jwt_decoder.copied'),
        description: `${label} ${t('jwt_decoder.copied_desc')}`,
      });
    } catch (error) {
      toast({
        title: t('jwt_decoder.copy_failed'),
        description: t('jwt_decoder.copy_failed_desc'),
        variant: "destructive"
      });
    }
  };

  // Generate new token from edited parts
  const generateNewToken = () => {
    try {
      const header = JSON.parse(editedHeader);
      const payload = JSON.parse(editedPayload);
      const newToken = generateJWT(header, payload, customSignature);
      
      if (newToken) {
        setToken(newToken);
        toast({
          title: t('jwt_decoder.token_generated'),
          description: t('jwt_decoder.token_generated_desc'),
        });
      }
    } catch (error) {
      toast({
        title: t('jwt_decoder.generation_failed'),
        description: t('jwt_decoder.invalid_json'),
        variant: "destructive"
      });
    }
  };

  // Format timestamp
  const formatTimestamp = (timestamp: number): string => {
    return new Date(timestamp * 1000).toLocaleString();
  };

  // Check if token is expired
  const isTokenExpired = (exp: number): boolean => {
    return Date.now() / 1000 > exp;
  };

  return (
    <div className={cn("space-y-6", className)}>
      {/* Token Input */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            {t('jwt_decoder.title')}
            {decodedJWT?.isValid && (
              <Badge variant="outline" className="text-green-600">
                <CheckCircle className="w-3 h-3 mr-1" />
                {t('jwt_decoder.valid')}
              </Badge>
            )}
            {decodedJWT && !decodedJWT.isValid && (
              <Badge variant="outline" className="text-red-600">
                <AlertTriangle className="w-3 h-3 mr-1" />
                {t('jwt_decoder.invalid')}
              </Badge>
            )}
          </CardTitle>
        </CardHeader>
        <CardContent className="space-y-4">
          <div>
            <Label htmlFor="jwt-input">{t('jwt_decoder.paste_token')}</Label>
            <Textarea
              id="jwt-input"
              placeholder={t('jwt_decoder.paste_placeholder')}
              value={token}
              onChange={(e) => setToken(e.target.value)}
              className="min-h-[100px] font-mono text-sm"
            />
          </div>
          
          {decodedJWT && !decodedJWT.isValid && (
            <div className="p-4 bg-red-50 dark:bg-red-950/20 border border-red-200 dark:border-red-800 rounded-md">
              <div className="flex items-center gap-2 text-red-800 dark:text-red-200">
                <AlertTriangle className="w-4 h-4" />
                <span className="font-semibold">{t('jwt_decoder.decode_error')}</span>
              </div>
              <p className="text-red-700 dark:text-red-300 text-sm mt-1">
                {decodedJWT.error}
              </p>
            </div>
          )}
        </CardContent>
      </Card>

      {decodedJWT?.isValid && (
        <>
          {/* Header Section */}
          <Card>
            <CardHeader>
              <CardTitle className="text-blue-600 dark:text-blue-400">
                {t('jwt_decoder.header')}
              </CardTitle>
            </CardHeader>
            <CardContent className="space-y-4">
              <div>
                <Label htmlFor="header-json">{t('jwt_decoder.header_json')}</Label>
                <div className="relative">
                  <Textarea
                    id="header-json"
                    value={editedHeader}
                    onChange={(e) => setEditedHeader(e.target.value)}
                    className="font-mono text-sm min-h-[120px]"
                  />
                  <Button
                    size="sm"
                    variant="ghost"
                    className="absolute top-2 right-2"
                    onClick={() => copyToClipboard(editedHeader, 'Header')}
                  >
                    <Copy className="w-4 h-4" />
                  </Button>
                </div>
              </div>
              
              {/* Algorithm Info */}
              {decodedJWT.header.alg && (
                <div className="flex items-center gap-2">
                  <Label>{t('jwt_decoder.algorithm')}:</Label>
                  <Badge variant={decodedJWT.header.alg === 'none' ? 'destructive' : 'secondary'}>
                    {decodedJWT.header.alg}
                  </Badge>
                  {decodedJWT.header.alg === 'none' && (
                    <Badge variant="destructive">
                      <AlertTriangle className="w-3 h-3 mr-1" />
                      {t('jwt_decoder.insecure')}
                    </Badge>
                  )}
                </div>
              )}
            </CardContent>
          </Card>

          {/* Payload Section */}
          <Card>
            <CardHeader>
              <CardTitle className="text-purple-600 dark:text-purple-400">
                {t('jwt_decoder.payload')}
              </CardTitle>
            </CardHeader>
            <CardContent className="space-y-4">
              <div>
                <Label htmlFor="payload-json">{t('jwt_decoder.payload_json')}</Label>
                <div className="relative">
                  <Textarea
                    id="payload-json"
                    value={editedPayload}
                    onChange={(e) => setEditedPayload(e.target.value)}
                    className="font-mono text-sm min-h-[120px]"
                  />
                  <Button
                    size="sm"
                    variant="ghost"
                    className="absolute top-2 right-2"
                    onClick={() => copyToClipboard(editedPayload, 'Payload')}
                  >
                    <Copy className="w-4 h-4" />
                  </Button>
                </div>
              </div>

              {/* Token Claims Info */}
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                {decodedJWT.payload.sub && (
                  <div>
                    <Label>{t('jwt_decoder.subject')}:</Label>
                    <p className="text-sm font-mono bg-gray-100 dark:bg-gray-800 p-2 rounded">
                      {decodedJWT.payload.sub}
                    </p>
                  </div>
                )}
                
                {decodedJWT.payload.username && (
                  <div>
                    <Label>{t('jwt_decoder.username')}:</Label>
                    <p className="text-sm font-mono bg-gray-100 dark:bg-gray-800 p-2 rounded">
                      {decodedJWT.payload.username}
                    </p>
                  </div>
                )}
                
                {decodedJWT.payload.role && (
                  <div>
                    <Label>{t('jwt_decoder.role')}:</Label>
                    <Badge variant={decodedJWT.payload.role === 'admin' ? 'destructive' : 'secondary'}>
                      {decodedJWT.payload.role}
                    </Badge>
                  </div>
                )}

                {decodedJWT.payload.iat && (
                  <div>
                    <Label>{t('jwt_decoder.issued_at')}:</Label>
                    <p className="text-sm bg-gray-100 dark:bg-gray-800 p-2 rounded">
                      {formatTimestamp(decodedJWT.payload.iat)}
                    </p>
                  </div>
                )}

                {decodedJWT.payload.exp && (
                  <div>
                    <Label>{t('jwt_decoder.expires_at')}:</Label>
                    <p className={cn(
                      "text-sm p-2 rounded",
                      isTokenExpired(decodedJWT.payload.exp)
                        ? "bg-red-100 dark:bg-red-900 text-red-800 dark:text-red-200"
                        : "bg-gray-100 dark:bg-gray-800"
                    )}>
                      {formatTimestamp(decodedJWT.payload.exp)}
                      {isTokenExpired(decodedJWT.payload.exp) && (
                        <Badge variant="destructive" className="ml-2">
                          {t('jwt_decoder.expired')}
                        </Badge>
                      )}
                    </p>
                  </div>
                )}
              </div>
            </CardContent>
          </Card>

          {/* Signature Section */}
          <Card>
            <CardHeader>
              <CardTitle className="text-red-600 dark:text-red-400 flex items-center gap-2">
                {t('jwt_decoder.signature')}
                <Button
                  size="sm"
                  variant="ghost"
                  onClick={() => setShowSignature(!showSignature)}
                >
                  {showSignature ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                </Button>
              </CardTitle>
            </CardHeader>
            <CardContent className="space-y-4">
              <div>
                <Label htmlFor="signature-input">{t('jwt_decoder.signature_value')}</Label>
                <div className="relative">
                  <Input
                    id="signature-input"
                    type={showSignature ? "text" : "password"}
                    value={customSignature}
                    onChange={(e) => setCustomSignature(e.target.value)}
                    className="font-mono text-sm"
                    placeholder={t('jwt_decoder.signature_placeholder')}
                  />
                  <Button
                    size="sm"
                    variant="ghost"
                    className="absolute top-0 right-8"
                    onClick={() => copyToClipboard(customSignature, 'Signature')}
                  >
                    <Copy className="w-4 h-4" />
                  </Button>
                </div>
              </div>
              
              <div className="p-4 bg-amber-50 dark:bg-amber-950/20 border border-amber-200 dark:border-amber-800 rounded-md">
                <p className="text-amber-800 dark:text-amber-200 text-sm">
                  <AlertTriangle className="w-4 h-4 inline mr-2" />
                  {t('jwt_decoder.signature_warning')}
                </p>
              </div>
            </CardContent>
          </Card>

          {/* Generate New Token */}
          <Card>
            <CardHeader>
              <CardTitle>{t('jwt_decoder.generate_token')}</CardTitle>
            </CardHeader>
            <CardContent>
              <div className="flex gap-4">
                <Button onClick={generateNewToken} className="flex-1">
                  {t('jwt_decoder.generate_new')}
                </Button>
                <Button 
                  variant="outline" 
                  onClick={() => copyToClipboard(token, 'JWT Token')}
                >
                  <Copy className="w-4 h-4 mr-2" />
                  {t('jwt_decoder.copy_token')}
                </Button>
              </div>
            </CardContent>
          </Card>
        </>
      )}
    </div>
  );
};

export default JWTDecoder;