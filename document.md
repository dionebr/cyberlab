# CyberLab - Break'n'Learn

## 📋 Índice
1. [Introdução e Propósito](#introdução-e-propósito)
2. [Características Principais](#características-principais)
3. [Módulos de Vulnerabilidade](#módulos-de-vulnerabilidade)
4. [Sistema de Níveis de Segurança](#sistema-de-níveis-de-segurança)
5. [Modo Aprendizado](#modo-aprendizado)
6. [Tecnologias Utilizadas](#tecnologias-utilizadas)
7. [Estrutura do Projeto](#estrutura-do-projeto)
8. [Objetivos Educacionais](#objetivos-educacionais)
9. [Considerações Éticas](#considerações-éticas)

---

## 🎯 Introdução e Propósito

**CyberLab** é uma plataforma educacional interativa focada no ensino de segurança web através de experiências práticas. A plataforma permite que estudantes, desenvolvedores e profissionais de segurança aprendam sobre vulnerabilidades web comuns em um ambiente controlado e seguro.

### Missão
Democratizar o conhecimento em segurança cibernética através de uma abordagem prática e acessível, preparando profissionais para identificar, compreender e mitigar vulnerabilidades em aplicações web.

---

## ✨ Características Principais

### 🎮 **Aprendizado Interativo**
- Exercícios práticos hands-on
- Simulação de vulnerabilidades reais
- Feedback imediato sobre ações do usuário
- Interface intuitiva e responsiva

### 🌍 **Suporte Multilíngue**
- Interface disponível em múltiplos idiomas
- Conteúdo traduzido para melhor compreensão
- Adaptação cultural dos exemplos

### 📊 **Níveis de Dificuldade Progressivos**
- **Low**: Introdução básica às vulnerabilidades
- **Medium**: Cenários intermediários com proteções básicas
- **High**: Ambientes mais realistas com múltiplas camadas de segurança
- **Impossible**: Demonstração de implementações seguras

### 🎨 **Interface Moderna**
- Design responsivo para todos os dispositivos
- Modo escuro/claro
- Navegação intuitiva via sidebar
- Feedback visual rico

---

## 🔓 Módulos de Vulnerabilidade

A plataforma oferece módulos especializados para diferentes tipos de vulnerabilidades web:

### 1. **SQL Injection**
- **SQL Injection Clássico**: Exploração de consultas SQL vulneráveis
- **Blind SQL Injection**: Técnicas de inferência quando não há output direto

### 2. **Cross-Site Scripting (XSS)**
- Reflected XSS
- Stored XSS
- DOM-based XSS
- Bypass de filtros

### 3. **Cross-Site Request Forgery (CSRF)**
- Ataques de falsificação de requisições
- Proteções com tokens CSRF
- Exploração de sessions vulneráveis

### 4. **Command Injection**
- Execução de comandos no sistema operacional
- Bypass de filtros e sanitização
- Escalação de privilégios

### 5. **File Inclusion**
- Local File Inclusion (LFI)
- Remote File Inclusion (RFI)
- Directory traversal

### 6. **File Upload**
- Upload de arquivos maliciosos
- Bypass de validações
- Webshells e backdoors

### 7. **Autenticação**
- **Auth Bypass**: Contorno de mecanismos de autenticação
- **Brute Force**: Ataques de força bruta
- **Weak Session**: Exploração de sessões fracas

### 8. **Insecure Captcha**
- Exploração de CAPTCHAs mal implementados
- Automação de respostas
- Bypass de proteções

---

## 🛡️ Sistema de Níveis de Segurança

O sistema de níveis proporciona uma progressão natural no aprendizado:

### 🟢 **Low (Baixo)**
- **Cor**: Verde
- **Características**: Aplicações com vulnerabilidades óbvias
- **Objetivo**: Introduzir conceitos básicos
- **Proteções**: Mínimas ou inexistentes

### 🟡 **Medium (Médio)**
- **Cor**: Amarelo
- **Características**: Alguma sanitização básica implementada
- **Objetivo**: Desenvolver técnicas de bypass
- **Proteções**: Filtros simples, validações básicas

### 🔴 **High (Alto)**
- **Cor**: Vermelho
- **Características**: Proteções mais robustas
- **Objetivo**: Simular ambientes reais de produção
- **Proteções**: WAF, validações avançadas, logging

### ⚫ **Impossible (Impossível)**
- **Cor**: Preto
- **Características**: Implementações seguras
- **Objetivo**: Demonstrar boas práticas
- **Proteções**: Código seguro, todas as mitigações aplicadas

---

## 📚 Modo Aprendizado

### Estrutura Educacional
- **Teoria**: Explicações detalhadas sobre cada vulnerabilidade
- **Demonstração**: Exemplos práticos e cases reais
- **Prática**: Exercícios hands-on guiados
- **Avaliação**: Testes de conhecimento

### Categorias Disponíveis
- Fundamentos de Segurança Web
- OWASP Top 10
- Técnicas de Pentesting
- Secure Coding Practices
- Incident Response

---

## 🛠️ Tecnologias Utilizadas

### **Frontend**
- **React 18**: Biblioteca principal para interfaces
- **TypeScript**: Tipagem estática para maior robustez
- **Tailwind CSS**: Framework de estilização utilitária
- **Vite**: Bundler rápido e moderno

### **Roteamento e Estado**
- **React Router**: Navegação SPA
- **TanStack Query**: Gerenciamento de estado servidor
- **Context API**: Estado global da aplicação

### **UI e Componentes**
- **Radix UI**: Componentes acessíveis e customizáveis
- **Shadcn/ui**: Sistema de design consistente
- **Lucide React**: Ícones SVG otimizados

### **Funcionalidades Avançadas**
- **Next Themes**: Sistema de temas
- **React Hook Form**: Gerenciamento de formulários
- **Sonner**: Notificações toast elegantes

---

## 🏗️ Estrutura do Projeto

```
src/
├── components/           # Componentes reutilizáveis
│   ├── ui/              # Componentes de UI base
│   ├── modules/         # Módulos de vulnerabilidade
│   ├── AppSidebar.tsx   # Navegação lateral
│   ├── Header.tsx       # Cabeçalho da aplicação
│   └── ModuleContent.tsx # Roteador de módulos
├── contexts/            # Contextos React
│   ├── ThemeContext.tsx # Gerenciamento de temas
│   └── SecurityLevelContext.tsx # Níveis de segurança
├── hooks/               # Hooks customizados
│   ├── useLanguage.ts   # Internacionalização
│   ├── useTheme.ts      # Controle de temas
│   └── useSecurityLevel.ts # Gerenciamento de níveis
├── pages/               # Páginas da aplicação
│   ├── Index.tsx        # Página inicial
│   ├── Learn.tsx        # Modo aprendizado
│   ├── Challenge.tsx    # Desafios práticos
│   └── NotFound.tsx     # Página 404
└── lib/                 # Utilitários e configurações
    └── utils.ts         # Funções auxiliares
```

### **Organização dos Módulos**
Cada módulo de vulnerabilidade é implementado como um componente independente:
- Interface consistente entre módulos
- Lógica isolada por tipo de vulnerabilidade
- Reutilização de componentes UI
- Facilidade de manutenção e extensão

---

## 🎓 Objetivos Educacionais

### **Público-Alvo**
- **Estudantes** de Ciência da Computação e áreas relacionadas
- **Desenvolvedores** que desejam melhorar conhecimentos em segurança
- **Profissionais de QA** interessados em testes de segurança
- **Pen testers** iniciantes e intermediários
- **Administradores de sistema** focados em segurança

### **Competências Desenvolvidas**
1. **Identificação de Vulnerabilidades**
   - Reconhecimento de padrões inseguros
   - Análise de código vulnerável
   - Uso de ferramentas de scanning

2. **Exploração Ética**
   - Técnicas de exploitation responsável
   - Documentação de vulnerabilidades
   - Proof of Concept (PoC) development

3. **Mitigação e Prevenção**
   - Implementação de controles de segurança
   - Code review focado em segurança
   - Arquitetura de aplicações seguras

4. **Pensamento Crítico**
   - Análise de riscos
   - Priorização de vulnerabilidades
   - Comunicação técnica efetiva

### **Metodologia de Ensino**
- **Learning by Doing**: Aprendizado através da prática
- **Progressão Gradual**: Do simples ao complexo
- **Feedback Imediato**: Correções em tempo real
- **Contextualização**: Cenários realistas de negócio

---

## ⚖️ Considerações Éticas

### **Uso Responsável**
A plataforma CyberLab foi desenvolvida exclusivamente para fins educacionais e deve ser utilizada de forma ética e responsável.

### **Diretrizes de Uso**
1. **Apenas para Aprendizado**: Não utilize conhecimentos adquiridos para atividades maliciosas
2. **Ambiente Controlado**: Pratique apenas em sistemas próprios ou com autorização explícita
3. **Divulgação Responsável**: Se encontrar vulnerabilidades reais, siga práticas de disclosure responsável
4. **Respeito à Privacidade**: Nunca acesse dados pessoais sem autorização

### **Responsabilidade Legal**
- Usuários são responsáveis pelo uso dos conhecimentos adquiridos
- A plataforma não incentiva atividades ilegais
- Sempre respeite leis locais e internacionais sobre segurança cibernética

### **Contribuição Positiva**
Encorajamos o uso dos conhecimentos para:
- Melhorar a segurança de aplicações legítimas
- Educar outros sobre práticas seguras
- Contribuir para a comunidade de segurança
- Desenvolver soluções inovadoras de proteção

---

## 🚀 Começando

Para começar sua jornada de aprendizado:

1. **Explore a Home**: Familiarize-se com a interface
2. **Escolha um Módulo**: Comece com vulnerabilidades mais simples
3. **Selecione o Nível**: Inicie com "Low" e progrida gradualmente
4. **Pratique**: Execute os exercícios práticos
5. **Aprenda**: Consulte o material teórico complementar
6. **Avance**: Progrida para níveis mais desafiadores

---

## 🔌 Integrações e Deploy

### **Integração com Supabase**

O Supabase é a plataforma recomendada para adicionar funcionalidades backend ao CyberLab:

#### **Como Integrar:**
1. **Ativação**: Clique no botão verde "Supabase" no canto superior direito da interface
2. **Conexão**: Conecte-se ao Supabase seguindo o assistente de configuração
3. **Configuração**: Configure as tabelas e políticas RLS necessárias

#### **Funcionalidades Disponíveis:**
- **Autenticação**: Sistema de login/registro com email e senha
- **Banco de Dados**: Armazenamento de progresso e pontuações dos usuários
- **Armazenamento**: Upload de arquivos e imagens de perfil
- **APIs Backend**: Criação de edge functions para lógica personalizada
- **Secrets Management**: Armazenamento seguro de chaves API

#### **Benefícios:**
- Escalabilidade automática
- Segurança integrada com Row Level Security (RLS)
- APIs REST e GraphQL automáticas
- Dashboard administrativo completo

### **Integração com GitHub**

Conecte seu projeto ao GitHub para versionamento e colaboração:

#### **Como Conectar:**
1. **Acesso**: Clique no botão "GitHub" no canto superior direito
2. **Autorização**: Autorize a aplicação GitHub
3. **Repositório**: Selecione a organização e crie um novo repositório
4. **Sincronização**: O código será automaticamente sincronizado

#### **Funcionalidades:**
- **Sync Bidirecional**: Alterações na aplicação são enviadas para GitHub automaticamente
- **Controle de Versão**: Histórico completo de mudanças
- **Colaboração**: Trabalhe em equipe usando branches e pull requests
- **CI/CD**: Integre com GitHub Actions para deployments automáticos

#### **Desenvolvimento Paralelo:**
- Clone o repositório localmente para desenvolvimento offline
- Use seu IDE favorito mantendo sincronização com a aplicação
- Faça push das mudanças - elas serão sincronizadas automaticamente

### **Deploy no Hostinger**

Para hospedar o CyberLab no Hostinger:

#### **Preparação:**
1. **Build do Projeto**: Execute `npm run build` para gerar os arquivos de produção
2. **Arquivos Estáticos**: A pasta `dist/` conterá todos os arquivos necessários

#### **Upload via FTP/File Manager:**
1. **Acesse o Painel**: Entre no painel de controle do Hostinger
2. **File Manager**: Abra o gerenciador de arquivos
3. **Pasta Public**: Navegue até a pasta `public_html/`
4. **Upload**: Faça upload de todos os arquivos da pasta `dist/`

#### **Configuração do Servidor:**
1. **Index.html**: Certifique-se que `index.html` está na raiz
2. **Redirecionamentos**: Configure redirect rules para SPA:
   ```apache
   # .htaccess
   RewriteEngine On
   RewriteBase /
   RewriteRule ^index\.html$ - [L]
   RewriteCond %{REQUEST_FILENAME} !-f
   RewriteCond %{REQUEST_FILENAME} !-d
   RewriteRule . /index.html [L]
   ```

#### **Domínio Personalizado:**
1. **DNS**: Configure os registros DNS para apontar para o Hostinger
2. **SSL**: Ative o certificado SSL gratuito no painel
3. **Teste**: Verifique se o site está funcionando corretamente

#### **Otimizações:**
- **Compressão**: Ative compressão Gzip no servidor
- **Cache**: Configure headers de cache para arquivos estáticos
- **CDN**: Considere usar um CDN para melhor performance global

### **Deploy Alternativo via GitHub Pages**

Se preferir usar GitHub Pages:

1. **GitHub Actions**: Configure workflow para build automático
2. **Branch gh-pages**: Deploy automático para branch de produção
3. **Domínio**: Configure domínio personalizado nas configurações do repositório

### **Monitoramento e Manutenção**

- **Analytics**: Integre Google Analytics ou similar
- **Logs**: Configure logging de erros
- **Backup**: Mantenha backups regulares do banco de dados
- **Updates**: Atualize dependências regularmente para segurança

---

## 📞 Suporte e Comunidade

A plataforma CyberLab é um projeto em constante evolução, com foco no crescimento da comunidade de segurança cibernética através da educação prática e ética.

**Lembre-se**: O conhecimento em segurança é uma ferramenta poderosa. Use-o sempre para o bem, protegendo e educando, nunca para causar danos.

---

*"A segurança não é um destino, é uma jornada contínua de aprendizado e melhoria."*