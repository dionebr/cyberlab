import type { QuizQuestion } from '../components/QuizComponent';
import type { CodeExercise } from '../components/CodeExerciseComponent';

// Quiz data preserving technical terminology
export const learnQuizzes: Record<string, QuizQuestion[]> = {
  "owasp-top10": [
    {
      id: "owasp-q1",
      question: "Qual das seguintes vulnerabilidades está no topo da OWASP Top 10 2021?",
      options: [
        "SQL Injection",
        "Broken Access Control",
        "Cross-Site Scripting (XSS)",
        "Security Misconfiguration"
      ],
      correctAnswer: 1,
      explanation: "Broken Access Control é o #1 na OWASP Top 10 2021, representando falhas no controle de acesso que permitem que usuários acessem recursos não autorizados.",
      difficulty: "easy",
      category: "fundamentals",
      technicalTerms: ["OWASP Top 10", "Broken Access Control"]
    },
    {
      id: "owasp-q2", 
      question: "O que é um ataque de Injection no contexto da OWASP Top 10?",
      options: [
        "Injeção de código malicioso através de inputs não validados",
        "Interceptação de dados em trânsito",
        "Modificação de arquivos de configuração",
        "Acesso físico não autorizado ao servidor"
      ],
      correctAnswer: 0,
      explanation: "Injection attacks (A03) ocorrem quando dados não confiáveis são enviados para um interpretador como parte de um comando ou query, permitindo execução de código malicioso.",
      difficulty: "medium",
      category: "fundamentals", 
      technicalTerms: ["Injection", "SQL Injection", "Command Injection"]
    },
    {
      id: "owasp-q3",
      question: "Qual técnica é mais eficaz para prevenir ataques de Cross-Site Scripting (XSS)?",
      options: [
        "Usar HTTPS em todas as conexões",
        "Implementar autenticação multi-fator",
        "Sanitizar e validar todos os inputs do usuário",
        "Criptografar dados no banco"
      ],
      correctAnswer: 2,
      explanation: "A prevenção de XSS requer sanitização rigorosa de inputs e output encoding. Validação e escape de dados do usuário antes de renderizar no DOM é fundamental.",
      difficulty: "medium",
      category: "fundamentals",
      technicalTerms: ["Cross-Site Scripting", "XSS", "Input Validation", "Output Encoding"]
    }
  ],

  "injection-attacks": [
    {
      id: "inj-q1",
      question: "Em qual situação ocorre uma vulnerabilidade de SQL Injection?",
      options: [
        "Quando senhas são armazenadas em texto plano",
        "Quando queries SQL são construídas concatenando strings de entrada do usuário",
        "Quando conexões com banco não usam SSL/TLS",
        "Quando não há backup do banco de dados"
      ],
      correctAnswer: 1,
      explanation: "SQL Injection ocorre quando queries são construídas dinamicamente concatenando entrada do usuário sem sanitização, permitindo que atacantes modifiquem a lógica SQL.",
      difficulty: "easy",
      category: "web-security",
      technicalTerms: ["SQL Injection", "Prepared Statements", "Parameterized Queries"]
    },
    {
      id: "inj-q2",
      question: "Qual é a melhor defesa contra Command Injection?",
      options: [
        "Usar firewall web application (WAF)",
        "Validar entrada com whitelist e evitar execução direta de comandos",
        "Criptografar comandos antes da execução",
        "Executar aplicação com privilégios de root"
      ],
      correctAnswer: 1,
      explanation: "Command Injection é prevenido através de validação rigorosa de entrada usando whitelists, evitando execução direta de comandos do sistema e usando APIs seguras.",
      difficulty: "medium",
      category: "web-security",
      technicalTerms: ["Command Injection", "Input Validation", "Whitelist", "System Commands"]
    }
  ],

  "encryption-pki": [
    {
      id: "crypto-q1",
      question: "Qual algoritmo de hash não deve mais ser usado para armazenamento seguro de senhas?",
      options: [
        "bcrypt",
        "PBKDF2",
        "MD5",
        "Argon2"
      ],
      correctAnswer: 2,
      explanation: "MD5 é considerado criptograficamente quebrado e vulnerável a ataques de colisão. Para senhas, deve-se usar algoritmos como bcrypt, PBKDF2 ou Argon2 com salt.",
      difficulty: "easy",
      category: "network-security",
      technicalTerms: ["MD5", "bcrypt", "PBKDF2", "Argon2", "Salt", "Hash Functions"]
    },
    {
      id: "crypto-q2",
      question: "O que é Perfect Forward Secrecy (PFS) em TLS?",
      options: [
        "Garantia de que dados criptografados nunca serão quebrados",
        "Capacidade de estabelecer conexões TLS instantaneamente",
        "Propriedade que garante que chaves de sessão comprometidas não afetam sessões passadas ou futuras",
        "Método para validar certificados automaticamente"
      ],
      correctAnswer: 2,
      explanation: "Perfect Forward Secrecy garante que mesmo se a chave privada do servidor for comprometida, as sessões anteriores permanecem seguras pois cada sessão usa chaves efêmeras.",
      difficulty: "hard", 
      category: "network-security",
      technicalTerms: ["Perfect Forward Secrecy", "PFS", "TLS", "ECDHE", "Ephemeral Keys"]
    }
  ]
};

// Code exercises preserving technical terminology
export const learnExercises: Record<string, CodeExercise[]> = {
  "secure-coding-principles": [
    {
      id: "secure-input-validation",
      title: "Validação Segura de Input",
      description: "Implemente uma função que valida entrada de usuário de forma segura, prevenindo ataques de injection.",
      difficulty: "medium",
      language: "python",
      startingCode: `import re

def validate_user_input(user_input):
    """
    Implemente validação segura que aceita apenas:
    - Letras (a-z, A-Z)
    - Números (0-9) 
    - Underscores (_) e hífens (-)
    - Comprimento entre 3 e 20 caracteres
    """
    # Seu código aqui
    pass

def sanitize_html_input(html_input):
    """
    Sanitize HTML input para prevenir XSS
    Remove tags <script> e outros elementos perigosos
    """
    # Seu código aqui
    pass`,
      solution: `import re

def validate_user_input(user_input):
    """
    Validação segura usando whitelist approach
    """
    if not user_input or len(user_input) < 3 or len(user_input) > 20:
        return False
    
    # Whitelist: apenas caracteres seguros
    pattern = r'^[a-zA-Z0-9_-]+$'
    return bool(re.match(pattern, user_input))

def sanitize_html_input(html_input):
    """
    Remove tags perigosas para prevenir XSS
    """
    if not html_input:
        return ""
    
    # Remove tags script e outros elementos perigosos
    dangerous_tags = ['script', 'iframe', 'object', 'embed', 'form']
    sanitized = html_input
    
    for tag in dangerous_tags:
        pattern = f'<{tag}[^>]*>.*?</{tag}>'
        sanitized = re.sub(pattern, '', sanitized, flags=re.IGNORECASE | re.DOTALL)
    
    return sanitized`,
      testCases: [
        {
          input: "valid_user123",
          expectedOutput: "Input validado com sucesso",
          description: "Input válido deve passar na validação"
        },
        {
          input: "'; DROP TABLE users; --",
          expectedOutput: "Erro: Tentativa de SQL Injection bloqueada",
          description: "SQL Injection deve ser bloqueado"
        },
        {
          input: "<script>alert('xss')</script>",
          expectedOutput: "Texto inserido com segurança (XSS prevenido)",
          description: "XSS deve ser prevenido"
        }
      ],
      hints: [
        "Use regex com whitelist approach para validar apenas caracteres seguros",
        "Implemente verificação de tamanho antes da validação de padrão",
        "Para HTML, remova ou escape tags perigosas como <script>, <iframe>",
        "Considere usar bibliotecas especializadas como html.escape() para sanitização"
      ],
      technicalConcepts: [
        "Input Validation",
        "Whitelist Approach", 
        "XSS Prevention",
        "SQL Injection Prevention",
        "Regular Expressions"
      ],
      securityFocus: "Prevenção de ataques de injection através de validação rigorosa de entrada usando whitelist approach."
    }
  ],

  "authentication-security": [
    {
      id: "secure-password-hashing",
      title: "Hash Seguro de Senhas",
      description: "Implemente um sistema seguro de hash de senhas usando bcrypt com salt adequado.",
      difficulty: "medium",
      language: "python", 
      startingCode: `import hashlib
import secrets

def hash_password(password):
    """
    Crie um hash seguro da senha usando técnicas apropriadas
    Deve incluir salt e ser resistente a ataques de força bruta
    """
    # Seu código aqui
    pass

def verify_password(password, stored_hash):
    """
    Verifique se a senha fornecida corresponde ao hash armazenado
    Deve ser resistente a timing attacks
    """
    # Seu código aqui  
    pass`,
      solution: `import hashlib
import secrets
import hmac

def hash_password(password):
    """
    Hash seguro usando PBKDF2 com salt
    """
    salt = secrets.token_hex(32)  # 32 bytes de salt aleatório
    # PBKDF2 com SHA-256, 100000 iterações
    hash_obj = hashlib.pbkdf2_hmac('sha256', password.encode(), salt.encode(), 100000)
    return f"{salt}:{hash_obj.hex()}"

def verify_password(password, stored_hash):
    """
    Verificação usando timing-safe comparison
    """
    try:
        salt, hash_hex = stored_hash.split(':')
        hash_obj = hashlib.pbkdf2_hmac('sha256', password.encode(), salt.encode(), 100000)
        return hmac.compare_digest(hash_obj.hex(), hash_hex)
    except ValueError:
        return False`,
      testCases: [
        {
          input: "strong_password123!",
          expectedOutput: "Hash seguro gerado com sucesso",
          description: "Hash de senha forte deve ser gerado"
        },
        {
          input: "password123",
          expectedOutput: "Senha hash criado com segurança", 
          description: "Sistema deve funcionar com senhas simples também"
        }
      ],
      hints: [
        "Use um salt único e aleatório para cada senha",
        "PBKDF2, bcrypt ou Argon2 são apropriados para hash de senhas",
        "Use pelo menos 100,000 iterações para PBKDF2",
        "Para verificação, use hmac.compare_digest() para evitar timing attacks"
      ],
      technicalConcepts: [
        "Password Hashing",
        "PBKDF2",
        "Salt",
        "Timing Attacks",
        "Cryptographic Security"
      ],
      securityFocus: "Implementação de hash seguro de senhas resistente a ataques de força bruta e timing attacks."
    }
  ],

  "network-protocols": [
    {
      id: "secure-http-client",
      title: "Cliente HTTP Seguro",
      description: "Implemente um cliente HTTP que valida certificados SSL/TLS adequadamente.",
      difficulty: "hard",
      language: "python",
      startingCode: `import requests
import ssl

def make_secure_request(url, data=None):
    """
    Faça uma requisição HTTP segura com validação adequada de certificado
    Deve rejeitar certificados inválidos ou expirados
    """
    # Seu código aqui
    pass

def validate_certificate_chain(hostname):
    """
    Valide a cadeia de certificados de um hostname
    Retorne informações sobre a validade
    """
    # Seu código aqui
    pass`,
      solution: `import requests
import ssl
import socket
from datetime import datetime

def make_secure_request(url, data=None):
    """
    Requisição segura com validação rigorosa
    """
    session = requests.Session()
    
    # Configuração SSL rigorosa
    session.verify = True  # Verificar certificados
    session.headers.update({
        'User-Agent': 'SecureClient/1.0',
        'Connection': 'close'
    })
    
    try:
        if data:
            response = session.post(url, json=data, timeout=30)
        else:
            response = session.get(url, timeout=30)
        
        response.raise_for_status()
        return {"success": True, "data": response.text[:100]}
    except requests.exceptions.SSLError:
        return {"success": False, "error": "Certificado SSL inválido"}
    except requests.exceptions.RequestException as e:
        return {"success": False, "error": str(e)}

def validate_certificate_chain(hostname):
    """
    Validação de certificado
    """
    try:
        context = ssl.create_default_context()
        with socket.create_connection((hostname, 443), timeout=10) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                return {
                    "valid": True,
                    "subject": cert.get('subject'),
                    "issuer": cert.get('issuer'), 
                    "expires": cert.get('notAfter')
                }
    except ssl.SSLError:
        return {"valid": False, "error": "Certificado inválido"}`,
      testCases: [
        {
          input: "https://httpbin.org/get", 
          expectedOutput: "Requisição segura realizada com sucesso",
          description: "Requisição HTTPS válida deve funcionar"
        },
        {
          input: "http://httpbin.org/get",
          expectedOutput: "Erro: Protocolo inseguro detectado", 
          description: "HTTP inseguro deve ser rejeitado"
        }
      ],
      hints: [
        "Use requests.Session() para configurações SSL consistentes",
        "Sempre defina verify=True para validar certificados",
        "Implemente timeout adequado para evitar travamentos",
        "Trate exceções SSL específicas separadamente"
      ],
      technicalConcepts: [
        "HTTPS/TLS",
        "Certificate Validation",
        "SSL/TLS Handshake",
        "Certificate Chain",
        "Secure HTTP Clients"
      ],
      securityFocus: "Implementação de cliente HTTP com validação rigorosa de certificados SSL/TLS."
    }
  ]
};

// Interactive section types
export type InteractiveSectionType = 'quiz' | 'exercise' | 'theory' | 'practical';

export interface InteractiveSection {
  id: string;
  title: string;
  type: InteractiveSectionType;
  quiz?: QuizQuestion[];
  exercise?: CodeExercise;
  content?: {
    theory?: string;
    keyPoints?: string[];
    vulnerability?: {
      code: string;
      explanation: string;
    };
    secure?: {
      code: string;
      explanation: string;
    };
    prevention?: string[];
  };
}

// Enhanced lesson structure with interactive content
export const interactiveLessons: Record<string, InteractiveSection[]> = {
  "owasp-top10": [
    {
      id: "owasp-intro",
      title: "Introduction to OWASP Top 10",
      type: "theory",
      content: {
        theory: "The OWASP Top 10 is a standard awareness document for developers and web application security. It represents a broad consensus about the most critical security risks to web applications.",
        keyPoints: [
          "Updated regularly based on real-world data",
          "Industry standard for web security", 
          "Foundation for secure development practices",
          "Covers 90% of common web vulnerabilities"
        ]
      }
    },
    {
      id: "owasp-quiz",
      title: "OWASP Top 10 Knowledge Check",
      type: "quiz",
      quiz: learnQuizzes["owasp-top10"]
    }
  ],

  "secure-coding-principles": [
    {
      id: "input-validation-exercise", 
      title: "Secure Input Validation Practice",
      type: "exercise",
      exercise: learnExercises["secure-coding-principles"][0]
    }
  ],

  "authentication-security": [
    {
      id: "password-hashing-exercise",
      title: "Secure Password Hashing Implementation", 
      type: "exercise",
      exercise: learnExercises["authentication-security"][0]
    }
  ],

  "injection-attacks": [
    {
      id: "injection-quiz",
      title: "Injection Attack Prevention Quiz",
      type: "quiz", 
      quiz: learnQuizzes["injection-attacks"]
    }
  ],

  "network-protocols": [
    {
      id: "secure-http-exercise",
      title: "Secure HTTP Client Implementation",
      type: "exercise",
      exercise: learnExercises["network-protocols"][0]
    }
  ],

  "encryption-pki": [
    {
      id: "crypto-quiz",
      title: "Cryptography and PKI Quiz",
      type: "quiz",
      quiz: learnQuizzes["encryption-pki"]
    }
  ]
};