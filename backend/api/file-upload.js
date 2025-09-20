/**
 * 🚨 ENDPOINTS VULNERÁVEIS DE FILE UPLOAD
 * 
 * ⚠️ Estes endpoints são INTENCIONALMENTE VULNERÁVEIS
 * 🎓 Para demonstração educacional de File Upload vulnerabilities
 * 🚨 NÃO usar em produção!
 */

const express = require('express');
const multer = require('multer');
const fs = require('fs');
const path = require('path');
const { exec } = require('child_process');
const logger = require('../middleware/logger');
const { vulnerableAuth } = require('../middleware/auth');

const router = express.Router();

// ============================================
// 🚨 CONFIGURAÇÃO VULNERÁVEL DO MULTER
// ============================================

// Diretório de upload vulnerável
const uploadDir = path.join(__dirname, '../uploads');
if (!fs.existsSync(uploadDir)) {
  fs.mkdirSync(uploadDir, { recursive: true, mode: 0o777 }); // Permissões perigosas!
}

// ⚠️ Storage configuration vulnerável
const vulnerableStorage = multer.diskStorage({
  destination: (req, file, cb) => {
    // Permite path traversal através do parâmetro
    const subdir = req.body.directory || req.query.dir || '';
    const finalPath = path.join(uploadDir, subdir);
    
    // Cria diretório se não existir - SEM validação!
    if (!fs.existsSync(finalPath)) {
      fs.mkdirSync(finalPath, { recursive: true, mode: 0o777 });
    }
    
    logger.logSensitive('Upload directory', { 
      requested_subdir: subdir, 
      final_path: finalPath,
      ip: req.ip 
    });
    
    cb(null, finalPath);
  },
  
  filename: (req, file, cb) => {
    // ⚠️ Usar nome original SEM sanitização - MUITO PERIGOSO!
    let filename = file.originalname;
    
    // Se vier parâmetro de rename, usar ele - Path traversal possível!
    if (req.body.filename) {
      filename = req.body.filename;
    }
    
    // "Preservar" extensão dupla - permite bypass de filtros
    if (req.body.preserve_extension === 'true') {
      filename = filename + '.' + (req.body.extension || 'txt');
    }
    
    logger.logSensitive('File upload attempt', {
      original_name: file.originalname,
      final_name: filename,
      mimetype: file.mimetype,
      size: file.size,
      ip: req.ip
    });
    
    cb(null, filename);
  }
});

// ⚠️ Multer sem filtros de segurança
const upload = multer({ 
  storage: vulnerableStorage,
  limits: {
    fileSize: 100 * 1024 * 1024, // 100MB - muito permissivo!
    files: 20 // Muitos arquivos permitidos
  },
  // SEM fileFilter - aceita QUALQUER tipo de arquivo!
});

// ============================================
// 🚨 UPLOAD BÁSICO - SEM VALIDAÇÃO
// ============================================
router.post('/upload', upload.single('file'), (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({
        success: false,
        error: 'No file uploaded',
        debug: {
          hint: 'Try uploading a PHP shell: <?php system($_GET[\"cmd\"]); ?>',
          dangerous_extensions: ['.php', '.jsp', '.asp', '.sh', '.exe', '.bat']
        }
      });
    }
    
    const fileInfo = {
      original_name: req.file.originalname,
      filename: req.file.filename,
      path: req.file.path,
      size: req.file.size,
      mimetype: req.file.mimetype,
      destination: req.file.destination,
      upload_time: new Date()
    };
    
    logger.logSensitive('File uploaded successfully', {
      ...fileInfo,
      body_params: req.body,
      ip: req.ip,
      user_agent: req.get('User-Agent')
    });
    
    // ⚠️ Tentar executar arquivos executáveis automaticamente!
    const ext = path.extname(req.file.filename).toLowerCase();
    if (['.sh', '.py', '.js', '.bat'].includes(ext)) {
      exec(`chmod +x "${req.file.path}"`, (error) => {
        if (error) {
          logger.error('Failed to make file executable:', error);
        } else {
          logger.logSensitive('File made executable', { path: req.file.path });
        }
      });
    }
    
    res.json({
      success: true,
      message: 'File uploaded successfully',
      file_info: fileInfo,
      access_url: `/api/upload/files/${req.file.filename}`,
      direct_path: req.file.path,
      debug: {
        warning: 'File uploaded without any security validation!',
        file_permissions: '777 (world readable/writable)',
        executable_made: ['.sh', '.py', '.js', '.bat'].includes(ext),
        path_traversal_used: req.body.directory ? true : false
      }
    });
    
  } catch (error) {
    logger.error('Upload error:', error);
    
    res.status(500).json({
      success: false,
      error: error.message,
      stack: error.stack
    });
  }
});

// ============================================
// 🚨 MULTIPLE FILE UPLOAD - SEM VALIDAÇÃO
// ============================================
router.post('/upload-multiple', upload.array('files', 20), (req, res) => {
  try {
    if (!req.files || req.files.length === 0) {
      return res.status(400).json({
        success: false,
        error: 'No files uploaded',
        debug: {
          hint: 'Upload multiple malicious files at once',
          max_files: 20
        }
      });
    }
    
    const uploadedFiles = req.files.map(file => ({
      original_name: file.originalname,
      filename: file.filename,
      path: file.path,
      size: file.size,
      mimetype: file.mimetype,
      access_url: `/api/upload/files/${file.filename}`
    }));
    
    // Fazer todos os arquivos executáveis
    req.files.forEach(file => {
      exec(`chmod 777 "${file.path}"`, (error) => {
        if (error) {
          logger.error('Failed to set file permissions:', error);
        }
      });
    });
    
    logger.logSensitive('Multiple files uploaded', {
      files: uploadedFiles,
      total_size: req.files.reduce((sum, f) => sum + f.size, 0),
      ip: req.ip
    });
    
    res.json({
      success: true,
      message: 'Multiple files uploaded successfully',
      files: uploadedFiles,
      total_files: req.files.length,
      total_size: req.files.reduce((sum, f) => sum + f.size, 0),
      debug: {
        warning: 'All files uploaded without validation!',
        permissions_set: '777 for all files'
      }
    });
    
  } catch (error) {
    logger.error('Multiple upload error:', error);
    
    res.status(500).json({
      success: false,
      error: error.message,
      stack: error.stack
    });
  }
});

// ============================================
// 🚨 AVATAR UPLOAD - IMAGE BYPASS
// ============================================
router.post('/avatar', vulnerableAuth, upload.single('avatar'), (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({
        success: false,
        error: 'No avatar file uploaded'
      });
    }
    
    // ⚠️ "Validação" de imagem facilmente contornável
    const allowedTypes = ['image/jpeg', 'image/png', 'image/gif'];
    const fileType = req.file.mimetype;
    
    if (!allowedTypes.includes(fileType)) {
      // ⚠️ Apenas warning, mas ainda permite o upload!
      logger.logSensitive('Avatar upload with non-image type', {
        file: req.file,
        user: req.user,
        warning: 'Non-image type detected but allowed anyway'
      });
    }
    
    // ⚠️ "Renomear" para extensão de imagem independente do conteúdo
    const originalPath = req.file.path;
    const imageExtensions = ['.jpg', '.png', '.gif'];
    const fakeExt = imageExtensions[Math.floor(Math.random() * imageExtensions.length)];
    const newPath = originalPath + fakeExt;
    
    fs.renameSync(originalPath, newPath);
    
    res.json({
      success: true,
      message: 'Avatar uploaded successfully',
      avatar_info: {
        original_name: req.file.originalname,
        stored_name: path.basename(newPath),
        path: newPath,
        size: req.file.size,
        detected_type: fileType,
        fake_extension: fakeExt
      },
      user: req.user,
      avatar_url: `/api/upload/files/${path.basename(newPath)}`,
      debug: {
        warning: 'File renamed with image extension regardless of content!',
        bypass_hint: 'Any file type accepted and renamed to look like image',
        real_mimetype: fileType
      }
    });
    
  } catch (error) {
    logger.error('Avatar upload error:', error);
    
    res.status(500).json({
      success: false,
      error: error.message,
      stack: error.stack
    });
  }
});

// ============================================
// 🚨 DOCUMENT UPLOAD - ZIP BOMB & PATH TRAVERSAL
// ============================================
router.post('/document', vulnerableAuth, upload.single('document'), async (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({
        success: false,
        error: 'No document uploaded'
      });
    }
    
    const fileInfo = {
      name: req.file.filename,
      path: req.file.path,
      size: req.file.size,
      type: req.file.mimetype
    };
    
    // ⚠️ Se for arquivo ZIP, extrair automaticamente - ZIP BOMB POSSÍVEL!
    if (req.file.mimetype === 'application/zip' || req.file.filename.endsWith('.zip')) {
      const extractDir = path.join(req.file.destination, 'extracted_' + Date.now());
      
      // ⚠️ Extração sem validação de tamanho ou path traversal
      const extractCommand = `unzip -o "${req.file.path}" -d "${extractDir}"`;
      
      logger.logVulnerableCommand(extractCommand, { file: req.file }, req.ip, req.user);
      
      exec(extractCommand, { timeout: 30000 }, (error, stdout, stderr) => {
        if (error) {
          logger.error('ZIP extraction error:', error);
        } else {
          logger.logSensitive('ZIP extracted successfully', {
            extract_dir: extractDir,
            stdout: stdout,
            user: req.user
          });
          
          // Listar arquivos extraídos
          exec(`find "${extractDir}" -type f`, (findError, findStdout) => {
            if (!findError) {
              logger.logSensitive('Extracted files list', {
                files: findStdout.split('\n').filter(f => f),
                extract_dir: extractDir
              });
            }
          });
        }
      });
    }
    
    // ⚠️ Análise de arquivo perigosa
    let fileAnalysis = {};
    
    // Tentar executar arquivo se tiver extensão perigosa
    const dangerousExts = ['.sh', '.py', '.php', '.js', '.pl'];
    const ext = path.extname(req.file.filename).toLowerCase();
    
    if (dangerousExts.includes(ext)) {
      const executeCommand = `timeout 5s ${ext === '.sh' ? 'bash' : ext === '.py' ? 'python3' : 'node'} "${req.file.path}"`;
      
      exec(executeCommand, (execError, execStdout, execStderr) => {
        fileAnalysis.execution_attempt = {
          command: executeCommand,
          success: !execError,
          stdout: execStdout,
          stderr: execStderr,
          error: execError ? execError.message : null
        };
        
        logger.logSensitive('Dangerous file execution attempted', fileAnalysis.execution_attempt);
      });
    }
    
    res.json({
      success: true,
      message: 'Document uploaded and processed',
      document_info: fileInfo,
      file_analysis: fileAnalysis,
      access_url: `/api/upload/files/${req.file.filename}`,
      user: req.user,
      debug: {
        warning: 'ZIP files are auto-extracted without validation!',
        zip_bomb_risk: 'No size limits on extraction',
        path_traversal_risk: 'No path validation on extracted files',
        auto_execution: dangerousExts.includes(ext) ? 'File executed automatically' : 'No auto-execution for this type'
      }
    });
    
  } catch (error) {
    logger.error('Document upload error:', error);
    
    res.status(500).json({
      success: false,
      error: error.message,
      stack: error.stack
    });
  }
});

// ============================================
// 🚨 FILE ACCESS - LFI/RFI VULNERÁVEL
// ============================================
router.get('/files/:filename', (req, res) => {
  try {
    let { filename } = req.params;
    const { path: pathParam, type, execute } = req.query;
    
    // ⚠️ Path traversal através de parâmetros
    if (pathParam) {
      filename = path.join(pathParam, filename);
    }
    
    logger.logSensitive('File access attempt', {
      filename: filename,
      path_param: pathParam,
      type: type,
      execute: execute,
      ip: req.ip,
      user_agent: req.get('User-Agent')
    });
    
    // ⚠️ Construir caminho sem sanitização - PATH TRAVERSAL
    const filePath = path.join(uploadDir, filename);
    
    // ⚠️ Permite acesso a qualquer arquivo do sistema!
    if (!fs.existsSync(filePath)) {
      // Se não encontrar, tenta paths alternativos perigosos
      const alternativePaths = [
        `/etc/${filename}`,
        `/var/log/${filename}`,
        `/home/${filename}`,
        path.join(process.cwd(), filename),
        path.resolve(filename) // Resolve path absoluto - MUITO PERIGOSO!
      ];
      
      for (const altPath of alternativePaths) {
        if (fs.existsSync(altPath)) {
          return serveFile(altPath, req, res);
        }
      }
      
      return res.status(404).json({
        success: false,
        error: 'File not found',
        searched_paths: [filePath, ...alternativePaths],
        debug: {
          hint: 'Try path traversal: ../../../etc/passwd',
          lfi_examples: [
            '../../etc/passwd',
            '../../../etc/shadow',
            '../../var/log/auth.log',
            '../../../proc/version'
          ]
        }
      });
    }
    
    serveFile(filePath, req, res);
    
  } catch (error) {
    logger.error('File access error:', error);
    
    res.status(500).json({
      success: false,
      error: error.message,
      stack: error.stack
    });
  }
});

// ============================================
// 🚨 FUNÇÃO AUXILIAR PARA SERVIR ARQUIVOS
// ============================================
function serveFile(filePath, req, res) {
  const { type, execute, download } = req.query;
  
  logger.logSensitive('Serving file', {
    path: filePath,
    type: type,
    execute: execute,
    download: download,
    ip: req.ip
  });
  
  try {
    const stats = fs.statSync(filePath);
    const ext = path.extname(filePath).toLowerCase();
    
    // ⚠️ Se execute=true, executar arquivo ao invés de servir - MUITO PERIGOSO!
    if (execute === 'true') {
      let executeCommand = '';
      
      switch (ext) {
        case '.sh':
        case '.bash':
          executeCommand = `bash "${filePath}"`;
          break;
        case '.py':
          executeCommand = `python3 "${filePath}"`;
          break;
        case '.php':
          executeCommand = `php "${filePath}"`;
          break;
        case '.js':
          executeCommand = `node "${filePath}"`;
          break;
        case '.pl':
          executeCommand = `perl "${filePath}"`;
          break;
        default:
          executeCommand = `"${filePath}"`;
      }
      
      logger.logVulnerableCommand(executeCommand, { file: filePath }, req.ip, null);
      
      exec(executeCommand, { timeout: 10000, maxBuffer: 1024 * 1024 }, (error, stdout, stderr) => {
        res.json({
          success: !error,
          file_executed: filePath,
          command_used: executeCommand,
          stdout: stdout,
          stderr: stderr,
          error: error ? error.message : null,
          debug: {
            warning: 'File executed directly on server!',
            execution_time: Date.now()
          }
        });
      });
      
      return;
    }
    
    // Determinar Content-Type (vulnerável a spoofing)
    let contentType = 'application/octet-stream';
    
    if (type) {
      contentType = type; // Aceita qualquer content-type do query param!
    } else {
      // Mapeamento básico e inseguro
      const mimeTypes = {
        '.html': 'text/html',
        '.htm': 'text/html',
        '.php': 'text/html', // PHP como HTML - PERIGOSO!
        '.js': 'application/javascript',
        '.css': 'text/css',
        '.json': 'application/json',
        '.txt': 'text/plain',
        '.xml': 'application/xml',
        '.pdf': 'application/pdf',
        '.zip': 'application/zip'
      };
      
      contentType = mimeTypes[ext] || contentType;
    }
    
    // Headers de resposta vulneráveis
    res.setHeader('Content-Type', contentType);
    res.setHeader('Content-Length', stats.size);
    res.setHeader('X-File-Path', filePath); // VAZA caminho real!
    res.setHeader('X-File-Size', stats.size);
    res.setHeader('X-File-Modified', stats.mtime);
    
    if (download === 'true') {
      res.setHeader('Content-Disposition', `attachment; filename="${path.basename(filePath)}"`);
    }
    
    // ⚠️ Stream do arquivo sem validação de conteúdo
    const fileStream = fs.createReadStream(filePath);
    
    fileStream.on('error', (error) => {
      logger.error('File stream error:', error);
      res.status(500).json({ error: error.message });
    });
    
    fileStream.pipe(res);
    
  } catch (error) {
    logger.error('File serve error:', error);
    
    res.status(500).json({
      success: false,
      error: error.message,
      file_path: filePath
    });
  }
}

// ============================================
// 🚨 LIST UPLOADED FILES - DIRECTORY TRAVERSAL
// ============================================
router.get('/list', (req, res) => {
  try {
    const { dir = '', recursive = false, show_system = false } = req.query;
    
    let targetDir = uploadDir;
    
    // ⚠️ Directory traversal através do parâmetro dir
    if (dir) {
      targetDir = path.join(uploadDir, dir);
      
      // Se show_system=true, permite listar qualquer diretório do sistema!
      if (show_system === 'true') {
        targetDir = path.resolve(dir);
      }
    }
    
    logger.logSensitive('Directory listing attempt', {
      target_dir: targetDir,
      requested_dir: dir,
      recursive: recursive,
      show_system: show_system,
      ip: req.ip
    });
    
    if (!fs.existsSync(targetDir)) {
      return res.status(404).json({
        success: false,
        error: 'Directory not found',
        target_directory: targetDir,
        debug: {
          hint: 'Try directory traversal: ?dir=../../etc',
          system_access: 'Use ?show_system=true&dir=/etc for system directories'
        }
      });
    }
    
    const listCommand = recursive === 'true' ? 
      `find "${targetDir}" -type f -ls` : 
      `ls -la "${targetDir}"`;
    
    logger.logVulnerableCommand(listCommand, { dir, recursive, show_system }, req.ip, null);
    
    exec(listCommand, { timeout: 10000, maxBuffer: 2 * 1024 * 1024 }, (error, stdout, stderr) => {
      const result = {
        success: !error,
        directory: targetDir,
        listing: stdout,
        stderr: stderr,
        command_used: listCommand,
        debug: {
          directory_traversal: dir ? true : false,
          system_access: show_system === 'true',
          recursive_listing: recursive === 'true',
          dangerous_examples: [
            '?dir=../../etc&show_system=true',
            '?dir=/var/log&show_system=true&recursive=true',
            '?dir=../../home&show_system=true',
            '?dir=/proc&show_system=true'
          ]
        }
      };
      
      if (error) {
        result.error = error.message;
        result.exit_code = error.code;
      }
      
      res.json(result);
    });
    
  } catch (error) {
    logger.error('Directory listing error:', error);
    
    res.status(500).json({
      success: false,
      error: error.message,
      stack: error.stack
    });
  }
});

// ============================================
// 🚨 DELETE FILES - PATH TRAVERSAL
// ============================================
router.delete('/files/:filename', vulnerableAuth, (req, res) => {
  try {
    let { filename } = req.params;
    const { path: pathParam, recursive = false } = req.query;
    
    // ⚠️ Path traversal
    if (pathParam) {
      filename = path.join(pathParam, filename);
    }
    
    const targetPath = path.resolve(uploadDir, filename);
    
    logger.logSensitive('File deletion attempt', {
      filename: filename,
      target_path: targetPath,
      path_param: pathParam,
      recursive: recursive,
      user: req.user,
      ip: req.ip
    });
    
    let deleteCommand = '';
    
    if (recursive === 'true') {
      deleteCommand = `rm -rf "${targetPath}"`;
    } else {
      deleteCommand = `rm "${targetPath}"`;
    }
    
    logger.logVulnerableCommand(deleteCommand, req.params, req.ip, req.user);
    
    exec(deleteCommand, (error, stdout, stderr) => {
      res.json({
        success: !error,
        message: error ? 'Deletion failed' : 'File/directory deleted',
        target: targetPath,
        command_executed: deleteCommand,
        stdout: stdout,
        stderr: stderr,
        error: error ? error.message : null,
        user: req.user,
        debug: {
          warning: 'rm command executed without validation!',
          path_traversal_risk: pathParam ? true : false,
          recursive_deletion: recursive === 'true'
        }
      });
    });
    
  } catch (error) {
    logger.error('File deletion error:', error);
    
    res.status(500).json({
      success: false,
      error: error.message,
      stack: error.stack
    });
  }
});

module.exports = router;