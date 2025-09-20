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

## References
- [OWASP Cheat Sheets](https://cheatsheetseries.owasp.org/)
- [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings)
- [TryHackMe Walkthroughs](https://tryhackme.com/)

---

This guide is for educational purposes only. Always test in a safe, legal environment.
