/**
 * VULNERABLE DATABASE CONFIGURATION
 * WARNING: This configuration is INTENTIONALLY INSECURE
 * For educationa      // Insert vulnerable data if file exl purpostsses in cybersecurity
 * DO NOT use in production!
 */

const mysql = require('mysql2');
const fs = require('fs');
const path = require('path');
const { logger } = require('../middleware/logger');

// VULNERABLE CONFIGURATIONS - DO NOT use in production!
const dbConfig = {
  host: process.env.DB_HOST || 'localhost',
  port: process.env.DB_PORT || 3306,
  user: process.env.DB_USER || 'vulnerable_user',
  password: process.env.DB_PASS || 'weak123', // Weak password
  database: process.env.DB_NAME || 'cyberlab_vulnerable',
  charset: 'utf8mb4',
  
  // DANGEROUS CONFIGURATIONS:
  ssl: false, // SSL DISABLED - VULNERABLE
  insecureAuth: true, // Allows insecure authentication
  acquireTimeout: 60000,
  timeout: 60000,
  reconnect: true,
  
  // Multiple statements configuration (SQL Injection)
  multipleStatements: true, // DANGEROUS! Allows multiple queries
  
  // Connection pool with loose configurations
  connectionLimit: 100,
  queueLimit: 0,
  
  // Dangerous flags
  flags: [
    'FOUND_ROWS',
    'LONG_PASSWORD',
    'LONG_FLAG',
    'TRANSACTIONS',
    'PROTOCOL_41',
    'SECURE_CONNECTION'
  ]
};

// Create connection pool (without SSL)
const pool = mysql.createPool(dbConfig);

// Function to execute queries WITHOUT prepared statements - VULNERABLE!
const executeVulnerableQuery = (query, params = []) => {
  return new Promise((resolve, reject) => {
    // VULNERABLE: String concatenation instead of prepared statements
    const finalQuery = typeof params === 'object' && params.length > 0
      ? query.replace(/\?/g, () => `'${params.shift()}'`) // DANGEROUS!
      : query;
    
    logger.warn(`Executing VULNERABLE query: ${finalQuery}`);
    
    pool.execute(finalQuery, (error, results, fields) => {
      if (error) {
        logger.error('Query error:', error);
        reject(error);
      } else {
        resolve({ results, fields });
      }
    });
  });
};

// Function to execute direct queries (very vulnerable)
const executeDirectQuery = (query) => {
  return new Promise((resolve, reject) => {
    logger.warn(`Executing DIRECT query (VERY DANGEROUS): ${query}`);
    
    pool.query(query, (error, results, fields) => {
      if (error) {
        logger.error('Direct query error:', error);
        reject(error);
      } else {
        resolve({ results, fields, query });
      }
    });
  });
};

// Test connection
const testConnection = () => {
  return new Promise((resolve, reject) => {
    pool.getConnection((err, connection) => {
      if (err) {
        logger.error('Database connection failed:', err);
        reject(err);
      } else {
        logger.info('Database connected successfully (WITHOUT SSL)');
        connection.release();
        resolve();
      }
    });
  });
};

// Initialize vulnerable data
const initVulnerableData = async () => {
  try {
    logger.info('Initializing vulnerable database schema and data...');
    
    // Verificar se os arquivos SQL existem
    const initPath = path.join(__dirname, '../database/init.sql');
    const mockPath = path.join(__dirname, '../database/mock-data.sql');
    
    if (!fs.existsSync(initPath)) {
      logger.warn('Init SQL file not found, skipping database initialization');
      return;
    }
    
    // Read and execute initialization script
    const initScript = fs.readFileSync(initPath, 'utf8');
    
    // Execute multiple queries at once - VULNERABLE
    try {
      await executeDirectQuery(initScript);
      logger.info('✅ Database schema initialized');
    } catch (error) {
      logger.warn('Failed to initialize database schema, may already exist:', error.message);
    }
    
    // Inserir dados vulneráveis se o arquivo existir
    if (fs.existsSync(mockPath)) {
      const mockDataScript = fs.readFileSync(mockPath, 'utf8');
      
      try {
        await executeDirectQuery(mockDataScript);
        logger.info('✅ Mock data inserted successfully');
      } catch (error) {
        logger.warn('Failed to insert mock data, may already exist:', error.message);
      }
    }
    
    logger.info('✅ Vulnerable database initialization completed');
    
  } catch (error) {
    logger.error('Failed to initialize vulnerable database:', error);
    // Do NOT throw to avoid server crash
    logger.warn('⚠️ Continuing without database initialization...');
  }
};

// Função para obter informações sensíveis do DB - VULNERÁVEL
const getDatabaseInfo = async () => {
  try {
    const info = await executeDirectQuery(`
      SELECT 
        VERSION() as version,
        USER() as current_user,
        DATABASE() as current_database,
        @@hostname as hostname,
        @@port as port,
        @@basedir as base_directory,
        @@datadir as data_directory,
        @@socket as socket,
        @@ssl_disabled as ssl_status
    `);
    
    return info.results[0];
  } catch (error) {
    logger.error('Failed to get database info:', error);
    return null;
  }
};

// Função para listar todas as tabelas - VULNERÁVEL
const getAllTables = async () => {
  try {
    const tables = await executeDirectQuery('SHOW TABLES');
    return tables.results;
  } catch (error) {
    logger.error('Failed to get tables:', error);
    return [];
  }
};

// Função para descrever estrutura de tabela - VULNERÁVEL  
const describeTable = async (tableName) => {
  try {
    // VULNERÁVEL: Sem validação do nome da tabela
    const structure = await executeDirectQuery(`DESCRIBE ${tableName}`);
    return structure.results;
  } catch (error) {
    logger.error(`Failed to describe table ${tableName}:`, error);
    return [];
  }
};

// Função para fechar conexões
const close = () => {
  pool.end((err) => {
    if (err) {
      logger.error('Error closing database pool:', err);
    } else {
      logger.info('Database pool closed');
    }
  });
};

// Export das funções vulneráveis
module.exports = {
  pool,
  
  // Funções VULNERÁVEIS para educational hacking
  executeVulnerableQuery,
  executeDirectQuery,
  
  // Funções de utilidade
  testConnection,
  initVulnerableData,
  getDatabaseInfo,
  getAllTables,
  describeTable,
  close,
  
  // Configurações expostas (VULNERÁVEL)
  config: dbConfig
};