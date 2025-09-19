import { createContext, useContext, useState, useEffect, ReactNode } from "react";

type Language = "en-US" | "pt-BR" | "es-ES";

const translations = {
  "en-US": {
    "header.subtitle": "Interactive Web Security Learning Platform",
    "header.light": "Light",
    "header.dark": "Dark",
    "sidebar.difficulty": "Security Level",
    "sidebar.modules": "Learning Modules",
    "sidebar.status": "Session Status",
    "sidebar.current": "Module",
    "sidebar.level": "Level",
    "difficulty.easy": "Easy",
    "difficulty.medium": "Medium", 
    "difficulty.hard": "Hard",
    "difficulty.impossible": "Impossible",
    "security.low": "Low",
    "security.medium": "Medium",
    "security.high": "High",
    "security.level": "Security Level",
    "modules.home": "Home",
    "modules.sql-injection": "SQL Injection",
    "modules.sql-blind": "SQL Injection (Blind)",
    "modules.xss": "Cross-Site Scripting",
    "modules.command-injection": "Command Injection",
    "modules.csrf": "CSRF Protection",
    "modules.file-inclusion": "File Inclusion", 
    "modules.auth-bypass": "Auth Bypass",
    "modules.brute-force": "Brute Force",
    "modules.file-upload": "File Upload",
    "modules.insecure-captcha": "Insecure CAPTCHA",
    "modules.weak-session": "Weak Session IDs",
    "modules.coming_soon": "Module coming soon...",
    "modules.learn": "Learn",
    "learn.mode": "Learn Mode",
    "learn.guided": "Guided Learning",
    "learn.fundamentals": "Security Fundamentals",
    "learn.web_security": "Web Security",
    "learn.network_security": "Network Security",
    "learn.os_security": "Operating Systems Security",
    "learn.programming_security": "Secure Programming",
    "home.title": "Welcome to CyberLab",
    "home.subtitle": "Interactive Web Security Learning Platform",
    "home.description": "CyberLab is an interactive educational platform designed to teach and train web security in a controlled and safe environment. The goal of this platform is to empower students, developers, and security professionals to learn, explore, and understand common web application vulnerabilities through hands-on practice.",
    "home.get_started": "Get Started",
    "home.general_instructions": "General Instructions",
    "home.general_instructions_content": "Users can explore the modules in any order, depending on their knowledge level. Each module includes theory, practical examples, and interactive challenges, allowing users to validate their exploitation attempts. The system also contains hidden and undocumented scenarios to encourage curiosity and promote more creative pentesting approaches. A learning mode is available with hints, tutorials, and additional references.",
    "home.warning": "⚠️ WARNING!",
    "home.warning_content": "CyberLab is a deliberately vulnerable platform, created exclusively for educational purposes. It must NOT be deployed on production servers or exposed to the public internet, as this may compromise the environment's security. It is strongly recommended to run CyberLab in isolated virtual machines or other controlled lab environments.",
    "home.disclaimer": "Disclaimer",
    "home.disclaimer_content": "The developers of CyberLab take no responsibility for any misuse of the platform. This system must be used only for learning purposes and in accordance with ethical and legal practices.",
    "home.features.interactive": "Interactive Learning",
    "home.features.interactive_desc": "Practice with real vulnerabilities",
    "home.features.multilingual": "Multilingual Support",
    "home.features.multilingual_desc": "Available in multiple languages",
    "home.features.difficulty": "Progressive Difficulty",
    "home.features.difficulty_desc": "From beginner to expert levels",
    "sql.title": "SQL Injection",
    "sql.description": "Learn how SQL injection vulnerabilities work and how to exploit them safely.",
    "sql.user_id": "User ID",
    "sql.submit": "Query Database",
    "sql.results": "Query Results",
    "sql.placeholder": "Enter user ID to search...",
    "xss.title": "Cross-Site Scripting (XSS)",
    "xss.description": "Understand XSS vulnerabilities and practice exploiting them.",
    "xss.message": "Message",
    "xss.submit": "Submit Message",
    "xss.results": "Message Display",
    "xss.placeholder": "Enter your message...",
    "command.search": "Search modules...",
    "command.no_results": "No results found.",
    "command.navigation": "Navigation",
    "command.categories": "Learn Categories",
    "command.topics": "Learn Topics",
    
    // 404 Page
    "notfound.title": "Page Not Found",
    "notfound.description": "The page you're looking for doesn't exist or has been moved.",
    "notfound.return_home": "Return to Home",
  },
  "pt-BR": {
    "header.subtitle": "Plataforma Interativa de Aprendizado em Segurança Web",
    "header.light": "Claro",
    "header.dark": "Escuro",
    "sidebar.difficulty": "Nível de Segurança",
    "sidebar.modules": "Módulos de Aprendizado",
    "sidebar.status": "Status da Sessão",
    "sidebar.current": "Módulo",
    "sidebar.level": "Nível",
    "difficulty.easy": "Fácil",
    "difficulty.medium": "Médio",
    "difficulty.hard": "Difícil", 
    "difficulty.impossible": "Impossível",
    "security.low": "Baixo",
    "security.medium": "Médio",
    "security.high": "Alto",
    "security.level": "Nível de Segurança",
    "modules.home": "Início",
    "modules.sql-injection": "Injeção SQL",
    "modules.sql-blind": "Injeção SQL (Blind)",
    "modules.xss": "Cross-Site Scripting",
    "modules.command-injection": "Injeção de Comando",
    "modules.csrf": "Proteção CSRF",
    "modules.file-inclusion": "Inclusão de Arquivo",
    "modules.auth-bypass": "Bypass de Autenticação",
    "modules.brute-force": "Força Bruta",
    "modules.file-upload": "Upload de Arquivo",
    "modules.insecure-captcha": "CAPTCHA Inseguro",
    "modules.weak-session": "IDs de Sessão Fracos",
    "modules.coming_soon": "Módulo em breve...",
    "modules.learn": "Aprender",
    "learn.mode": "Modo Aprendizado",
    "learn.guided": "Aprendizado Guiado",
    "learn.fundamentals": "Fundamentos de Segurança",
    "learn.web_security": "Segurança Web",
    "learn.network_security": "Segurança de Rede",
    "learn.os_security": "Segurança de Sistemas Operacionais",
    "learn.programming_security": "Programação Segura",
    "home.title": "Bem-vindo ao CyberLab",
    "home.subtitle": "Plataforma Interativa de Aprendizado em Segurança Web",
    "home.description": "O CyberLab é uma plataforma educacional interativa projetada para ensinar e treinar segurança web em um ambiente controlado e seguro. O objetivo desta plataforma é capacitar estudantes, desenvolvedores e profissionais de segurança a aprender, explorar e compreender vulnerabilidades comuns de aplicações web através da prática prática.",
    "home.get_started": "Começar",
    "home.general_instructions": "Instruções Gerais",
    "home.general_instructions_content": "Os usuários podem explorar os módulos em qualquer ordem, dependendo do seu nível de conhecimento. Cada módulo inclui teoria, exemplos práticos e desafios interativos, permitindo que os usuários validem suas tentativas de exploração. O sistema também contém cenários ocultos e não documentados para encorajar a curiosidade e promover abordagens de pentesting mais criativas. Um modo de aprendizado está disponível com dicas, tutoriais e referências adicionais.",
    "home.warning": "⚠️ AVISO!",
    "home.warning_content": "O CyberLab é uma plataforma deliberadamente vulnerável, criada exclusivamente para fins educacionais. NÃO deve ser implantada em servidores de produção ou exposta à internet pública, pois isso pode comprometer a segurança do ambiente. É fortemente recomendado executar o CyberLab em máquinas virtuais isoladas ou outros ambientes de laboratório controlados.",
    "home.disclaimer": "Isenção de Responsabilidade",
    "home.disclaimer_content": "Os desenvolvedores do CyberLab não assumem responsabilidade por qualquer uso indevido da plataforma. Este sistema deve ser usado apenas para fins de aprendizado e de acordo com práticas éticas e legais.",
    "home.features.interactive": "Aprendizado Interativo",
    "home.features.interactive_desc": "Pratique com vulnerabilidades reais",
    "home.features.multilingual": "Suporte Multilíngue",
    "home.features.multilingual_desc": "Disponível em múltiplos idiomas",
    "home.features.difficulty": "Dificuldade Progressiva",
    "home.features.difficulty_desc": "Do iniciante ao nível expert",
    "sql.title": "Injeção SQL",
    "sql.description": "Aprenda como funcionam as vulnerabilidades de injeção SQL e como explorá-las com segurança.",
    "sql.user_id": "ID do Usuário",
    "sql.submit": "Consultar Banco",
    "sql.results": "Resultados da Consulta",
    "sql.placeholder": "Digite o ID do usuário para buscar...",
    "xss.title": "Cross-Site Scripting (XSS)",
    "xss.description": "Entenda vulnerabilidades XSS e pratique explorá-las.",
    "xss.message": "Mensagem",
    "xss.submit": "Enviar Mensagem",
    "xss.results": "Exibição da Mensagem",
    "xss.placeholder": "Digite sua mensagem...",
    "command.search": "Pesquisar módulos...",
    "command.no_results": "Nenhum resultado encontrado.",
    "command.navigation": "Navegação",
    "command.categories": "Categorias de Aprendizado",
    "command.topics": "Tópicos de Aprendizado",
    
    // 404 Page
    "notfound.title": "Página Não Encontrada",
    "notfound.description": "A página que você está procurando não existe ou foi movida.",
    "notfound.return_home": "Voltar ao Início",
  },
  "es-ES": {
    "header.subtitle": "Plataforma Interactiva de Aprendizaje de Seguridad Web",
    "header.light": "Claro",
    "header.dark": "Oscuro",
    "sidebar.difficulty": "Nivel de Seguridad",
    "sidebar.modules": "Módulos de Aprendizaje",
    "sidebar.status": "Estado de la Sesión",
    "sidebar.current": "Módulo",
    "sidebar.level": "Nivel",
    "difficulty.easy": "Fácil",
    "difficulty.medium": "Medio",
    "difficulty.hard": "Difícil",
    "difficulty.impossible": "Imposible",
    "security.low": "Bajo",
    "security.medium": "Medio",
    "security.high": "Alto",
    "security.level": "Nivel de Seguridad",
    "modules.home": "Inicio",
    "modules.sql-injection": "Inyección SQL",
    "modules.sql-blind": "Inyección SQL (Blind)",
    "modules.xss": "Cross-Site Scripting",
    "modules.command-injection": "Inyección de Comando",
    "modules.csrf": "Protección CSRF",
    "modules.file-inclusion": "Inclusión de Archivo",
    "modules.auth-bypass": "Bypass de Autenticación",
    "modules.brute-force": "Fuerza Bruta",
    "modules.file-upload": "Subida de Archivo",
    "modules.insecure-captcha": "CAPTCHA Inseguro",
    "modules.weak-session": "IDs de Sesión Débiles",
    "modules.coming_soon": "Módulo próximamente...",
    "modules.learn": "Aprender",
    "learn.mode": "Modo Aprendizaje",
    "learn.guided": "Aprendizaje Guiado",
    "learn.fundamentals": "Fundamentos de Seguridad",
    "learn.web_security": "Seguridad Web",
    "learn.network_security": "Seguridad de Red",
    "learn.os_security": "Seguridad de Sistemas Operativos",
    "learn.programming_security": "Programación Segura",
    "home.title": "Bienvenido a CyberLab ",
    "home.subtitle": "Plataforma Interactiva de Aprendizaje de Seguridad Web",
    "home.description": "CyberLab es una plataforma educativa interactiva diseñada para enseñar y entrenar seguridad web en un entorno controlado y seguro. El objetivo de esta plataforma es empoderar a estudiantes, desarrolladores y profesionales de seguridad para aprender, explorar y comprender vulnerabilidades comunes de aplicaciones web a través de la práctica práctica.",
    "home.get_started": "Comenzar",
    "home.general_instructions": "Instrucciones Generales",
    "home.general_instructions_content": "Los usuarios pueden explorar los módulos en cualquier orden, dependiendo de su nivel de conocimiento. Cada módulo incluye teoría, ejemplos prácticos y desafíos interactivos, permitiendo a los usuarios validar sus intentos de explotación. El sistema también contiene escenarios ocultos y no documentados para fomentar la curiosidad y promover enfoques de pentesting más creativos. Un modo de aprendizaje está disponible con pistas, tutoriales y referencias adicionales.",
    "home.warning": "⚠️ ¡ADVERTENCIA!",
    "home.warning_content": "CyberLab es una plataforma deliberadamente vulnerable, creada exclusivamente para fines educativos. NO debe ser desplegada en servidores de producción o expuesta a internet público, ya que esto puede comprometer la seguridad del entorno. Se recomienda encarecidamente ejecutar CyberLab en máquinas virtuales aisladas u otros entornos de laboratorio controlados.",
    "home.disclaimer": "Descargo de Responsabilidad",
    "home.disclaimer_content": "Los desarrolladores de CyberLab no asumen responsabilidad por cualquier mal uso de la plataforma. Este sistema debe ser usado solo para fines de aprendizaje y de acuerdo con prácticas éticas y legales.",
    "home.features.interactive": "Aprendizaje Interactivo",
    "home.features.interactive_desc": "Practica con vulnerabilidades reales",
    "home.features.multilingual": "Soporte Multilingüe",
    "home.features.multilingual_desc": "Disponible en múltiples idiomas",
    "home.features.difficulty": "Dificultad Progresiva",
    "home.features.difficulty_desc": "Desde principiante hasta niveles expertos",
    "sql.title": "Inyección SQL",
    "sql.description": "Aprende cómo funcionan las vulnerabilidades de inyección SQL y cómo explotarlas de forma segura.",
    "sql.user_id": "ID de Usuario",
    "sql.submit": "Consultar Base de Datos",
    "sql.results": "Resultados de la Consulta",
    "sql.placeholder": "Ingresa ID de usuario para buscar...",
    "xss.title": "Cross-Site Scripting (XSS)",
    "xss.description": "Comprende las vulnerabilidades XSS y practica explotándolas.",
    "xss.message": "Mensaje",
    "xss.submit": "Enviar Mensaje",
    "xss.results": "Visualización del Mensaje",
    "xss.placeholder": "Ingresa tu mensaje...",
    "command.search": "Buscar módulos...",
    "command.no_results": "No se encontraron resultados.",
    "command.navigation": "Navegación",
    "command.categories": "Categorías de Aprendizaje",
    "command.topics": "Tópicos de Aprendizaje",
    
    // 404 Page
    "notfound.title": "Página No Encontrada",
    "notfound.description": "La página que buscas no existe o ha sido movida.",
    "notfound.return_home": "Volver al Inicio",
  },
};

interface LanguageContextType {
  language: Language;
  setLanguage: (language: Language) => void;
  t: (key: string) => string;
}

const LanguageContext = createContext<LanguageContextType | undefined>(undefined);

interface LanguageProviderProps {
  children: ReactNode;
}

export const LanguageProvider = ({ children }: LanguageProviderProps) => {
  const [language, setLanguageState] = useState<Language>("en-US");

  useEffect(() => {
    const savedLanguage = localStorage.getItem("cyberlab-language") as Language;
    if (savedLanguage && translations[savedLanguage]) {
      setLanguageState(savedLanguage);
    }
  }, []);

  const setLanguage = (lang: Language) => {
    setLanguageState(lang);
    localStorage.setItem("cyberlab-language", lang);
  };

  const t = (key: string): string => {
    return translations[language][key as keyof typeof translations[Language]] || key;
  };

  return (
    <LanguageContext.Provider value={{ language, setLanguage, t }}>
      {children}
    </LanguageContext.Provider>
  );
};

export const useLanguageContext = () => {
  const context = useContext(LanguageContext);
  if (context === undefined) {
    throw new Error("useLanguageContext must be used within a LanguageProvider");
  }
  return context;
};