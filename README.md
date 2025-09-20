# 🚀 CyberLab Professional - Break'n'Learn v2.0

> **Uma plataforma educacional interativa para aprendizado de segurança cibernética através de vulnerabilidades reais em ambiente controlado.**

<div align="center">

[![Docker](https://img.shields.io/badge/Docker-Ready-2496ED?style=for-the-badge&logo=docker&logoColor=white)](https://www.docker.com/)
[![Node.js](https://img.shields.io/badge/Node.js-18+-339933?style=for-the-badge&logo=node.js&logoColor=white)](https://nodejs.org/)
[![React](https://img.shields.io/badge/React-18-61DAFB?style=for-the-badge&logo=react&logoColor=black)](https://reactjs.org/)
[![TypeScript](https://img.shields.io/badge/TypeScript-Ready-3178C6?style=for-the-badge&logo=typescript&logoColor=white)](https://www.typescriptlang.org/)

</div>

## ⚠️ **AVISO IMPORTANTE**
Esta aplicação contém **vulnerabilidades INTENCIONAIS** para fins educacionais. 
**🚨 USE APENAS EM AMBIENTES ISOLADOS E CONTROLADOS 🚨**

---

## 🐳 **INSTALAÇÃO RÁPIDA COM DOCKER (RECOMENDADO)**

### **⚡ Instalação em 3 comandos:**
```bash
# 1. Clonar o repositório
git clone https://github.com/dionebr/cyberlab.git && cd cyberlab

# 2. Iniciar todos os serviços  
docker-compose up -d --build

# 3. Aguardar inicialização (1-2 minutos)
docker-compose logs -f backend
```

### **🌐 Acessar a aplicação:**
- **Frontend**: http://localhost:8080
- **Backend API**: http://localhost:5001  
- **Analytics**: http://localhost:5001/api/analytics/dashboard

### **✅ Verificar instalação:**
```bash
# Verificar status dos serviços
curl http://localhost:5001/api/status

# Ver estatísticas de ataques
curl http://localhost:5001/api/analytics/dashboard
```

---

## 🎯 **O QUE É O CYBERLAB PROFESSIONAL?**

**CyberLab** é uma plataforma educacional completa que permite aprender segurança cibernética através da prática com **vulnerabilidades reais** em um ambiente **totalmente controlado e isolado**.

### **🎓 Para Estudantes:**
- **12+ módulos vulneráveis** com vulnerabilidades reais
- **Sistema educacional** com explicações detalhadas  
- **3 níveis de dificuldade** (Easy/Medium/Hard)
- **Analytics em tempo real** dos seus ataques

### **👨‍🏫 Para Professores:**
- **Ambiente controlado** para demonstrações
- **Material estruturado** para aulas
- **Múltiplos idiomas** (PT/EN/ES)
- **Sistema de progresso** dos alunos

### **👨‍💼 Para Profissionais:**
- **Treinamento prático** em vulnerabilidades web
- **Preparação para certificações** (CEH, OSCP)
- **Desenvolvimento de skills** de pentest ético
- **Ambiente seguro** para testes

---

## 🔴 **MÓDULOS VULNERÁVEIS DISPONÍVEIS**

<table>
<tr>
<td width="50%">

### **🗃️ SQL Injection**
- **Basic, Blind, Union** attacks
- **Database real** com dados sensíveis
- **Bypass de filtros** por nível

### **🕷️ Cross-Site Scripting (XSS)**  
- **Reflected, Stored, DOM-based**
- **Execução real** de scripts
- **Técnicas de bypass** avançadas

### **⚡ Command Injection**
- **Execução real** de comandos do sistema
- **Ferramentas de rede** vulneráveis  
- **Acesso ao file system**

### **📁 File Upload**
- **Bypass de extensão**
- **Path traversal** exploitation
- **Execução** de arquivos maliciosos

### **🔓 Authentication Bypass**
- **SQL injection** em login
- **Manipulação de sessão**
- **Escalação de privilégios**

### **💥 Brute Force**
- **Ataques de força bruta** reais
- **Rate limiting** por dificuldade
- **Análise de timing**

</td>
<td width="50%">

### **🎭 CSRF**
- **Cross-Site Request Forgery**
- **Bypass de token** CSRF
- **Exploração SameSite**

### **📄 File Inclusion**
- **Local File Inclusion (LFI)**
- **Remote File Inclusion (RFI)**  
- **Log poisoning**

### **🔐 Session Management**
- **Session ID** predicável
- **Session fixation**
- **Cookie manipulation**

### **🕵️ Blind SQL Injection**
- **Time-based** blind injection
- **Boolean-based** attacks
- **Enumeração avançada**

### **🤖 Insecure Captcha**
- **Geração predicável**
- **Bypass client-side**
- **Exploração algoritmos**

### **📊 Analytics & Monitoring**
- **Dashboard** em tempo real
- **Logs** de ataques
- **Métricas** educacionais

</td>
</tr>
</table>

---

## 🔧 **TECNOLOGIAS & ARQUITETURA**

### **Frontend:**
- **React 18** + TypeScript + Vite
- **Tailwind CSS** + Shadcn/ui  
- **Context API** para estado global
- **Multi-idioma** (PT/EN/ES)

### **Backend:**
- **Node.js** + Express (vulnerável)
- **MySQL** para persistência
- **Docker** + Docker Compose
- **Analytics** em tempo real

### **Segurança (Intencionalmente Vulnerável):**
- **Zero sanitização** de input (easy mode)
- **Autenticação fraca** 
- **Execução de comandos** sem filtros
- **Information disclosure** extensivo

---

## 📚 **SISTEMA EDUCACIONAL COMPLETO**

### **🎓 Learn Mode:**
```bash
# Acesso: http://localhost:8080/learn
```
- **25+ lições** estruturadas
- **5 categorias** de conteúdo:
  - Security Fundamentals  
  - Web Security
  - Network Security
  - OS Security
  - Secure Programming
- **Sistema de progresso** gamificado
- **Quizzes interativos**

### **⚡ Challenge Mode:**
```bash
# Acesso: http://localhost:8080/challenges  
```
- **12 módulos** práticos
- **Vulnerabilidades reais**
- **Feedback educacional** instantâneo
- **Analytics** de performance

---

## 🚀 **GUIA RÁPIDO DE USO**

### **1️⃣ Primeiro teste - SQL Injection:**
```bash
# 1. Acessar: http://localhost:8080/challenges/sql-injection
# 2. Testar: admin' OR '1'='1' --  
# 3. Resultado: Todos os usuários expostos + explicação educacional
```

### **2️⃣ Segundo teste - XSS:**
```bash  
# 1. Acessar: http://localhost:8080/challenges/xss
# 2. Testar: <script>alert('XSS')</script>
# 3. Resultado: Script executado + análise de impacto
```

### **3️⃣ Terceiro teste - Command Injection:**
```bash
# 1. Acessar: http://localhost:8080/challenges/command-injection  
# 2. Testar: 127.0.0.1; whoami
# 3. Resultado: Comando executado + informações do sistema
```

---

## 📊 **MONITORAMENTO EM TEMPO REAL**

### **Analytics Dashboard:**
```bash
# Dashboard completo
curl http://localhost:5001/api/analytics/dashboard

# Ataques por módulo
curl http://localhost:5001/api/analytics/attacks

# Reset para testes
curl -X DELETE http://localhost:5001/api/analytics/reset
```

### **Métricas Disponíveis:**
- **Taxa de sucesso** por módulo (80%+ típico)
- **Tentativas de ataque** por sessão
- **Vulnerabilidades** mais exploradas  
- **Timeline** de ataques por hora
- **Progression tracking** educacional

### **Logs em Tempo Real:**
```bash
# Docker
docker-compose logs -f backend

# Ou acessar via web
http://localhost:5001/api/analytics/dashboard
```

---

## ⚙️ **INSTALAÇÃO MANUAL (DESENVOLVIMENTO)**

### **Pré-requisitos:**
```bash
# Verificar versões
node --version  # v18+
npm --version   # v8+
```

### **Setup completo:**
```bash
# 1. Clonar repositório
git clone https://github.com/dionebr/cyberlab.git
cd cyberlab

# 2. Frontend (Terminal 1)
npm install
npm run dev
# http://localhost:8080

# 3. Backend (Terminal 2)  
cd backend
npm install
npm run dev
# http://localhost:5001
```

---

## 🛡️ **ISOLAMENTO E SEGURANÇA**

### **⚠️ NUNCA em produção:**

#### **✅ Execute APENAS em:**
- ✅ **Docker containers** isolados
- ✅ **VMs** com rede host-only  
- ✅ **Ambientes de laboratório**
- ✅ **Redes privadas** isoladas

#### **🚫 NUNCA execute em:**
- 🚫 **Servidores de produção**
- 🚫 **Redes corporativas**
- 🚫 **Cloud público** sem isolamento
- 🚫 **Ambientes compartilhados**

### **Configuração Segura:**
```bash
# Network isolada
docker network create --driver bridge cyberlab-isolated

# Limites de recursos
docker-compose up -d --memory="2g" --cpus="2.0"

# Firewall (bloquear acesso externo)
sudo ufw deny from any to any port 5001,8080
sudo ufw allow from 127.0.0.1 to any port 5001,8080
```

---

## 🎯 **CASOS DE USO PRÁTICOS**

### **🎓 Educação:**
- **Universidades**: Disciplinas de segurança cibernética
- **Cursos técnicos**: Treinamento prático
- **Bootcamps**: Preparação para mercado
- **Certificações**: CEH, OSCP, CISSP

### **💼 Corporativo:**
- **Security awareness** para desenvolvedores  
- **Red team training**
- **Incident response** preparation
- **Compliance training** (PCI DSS, SOX)

### **🔬 Pesquisa:**
- **Vulnerability research**
- **Tool development** e testing
- **Academic research** em segurança
- **Proof of concept** development

---

## 📖 **DOCUMENTAÇÃO COMPLETA**

- **📋 Guia Completo**: [`INSTALACAO-COMPLETA.md`](INSTALACAO-COMPLETA.md) (15,000+ palavras)
- **🗺️ Roadmap**: [`CYBERLAB-PROFESSIONAL-ROADMAP.md`](CYBERLAB-PROFESSIONAL-ROADMAP.md)  
- **📚 Documentação Técnica**: [`document.md`](document.md)

---

## 🛠️ **TROUBLESHOOTING RÁPIDO**

### **Backend não inicia:**
```bash
# Verificar porta e reiniciar
sudo kill -9 $(lsof -t -i:5001)
docker-compose restart backend
```

### **Frontend não carrega:**  
```bash
# Limpar cache e rebuild
npm run build && npm run dev
```

### **Reset completo:**
```bash
# Para tudo e reconstrói
docker-compose down -v
docker-compose up -d --build
```

### **Verificar saúde:**
```bash
# Status dos serviços
curl http://localhost:5001/api/status
docker-compose ps
```

---

## 🤝 **SUPORTE E CONTRIBUIÇÃO**

### **🐛 Problemas:**
- **Issues**: https://github.com/dionebr/cyberlab/issues
- **Documentation**: Consulte arquivos `.md` do projeto

### **🔄 Contribuir:**
1. **Fork** do repositório
2. **Criar** feature branch
3. **Enviar** Pull Request

### **💬 Comunidade:**
- **Discussions**: GitHub Discussions
- **Wiki**: Documentação colaborativa

---

## ⚖️ **TERMOS DE USO & RESPONSABILIDADES**

### **✅ Permitido:**
- ✅ **Uso educacional** e pesquisa
- ✅ **Treinamento** em segurança
- ✅ **Preparação** para certificações
- ✅ **Desenvolvimento** de skills éticos

### **🚫 Proibido:**
- 🚫 **Uso em sistemas** de terceiros sem autorização
- 🚫 **Deployment** em produção  
- 🚫 **Atividades maliciosas** ou ilegais
- 🚫 **Violação** de leis locais

**⚖️ Os autores não se responsabilizam por uso inadequado da plataforma.**

---

## 🏆 **ESTATÍSTICAS DO PROJETO**

<div align="center">

| Métrica | Valor |
|---------|-------|
| **🔴 Módulos Vulneráveis** | 12+ |
| **⚡ API Endpoints** | 25+ |
| **🗃️ Vulnerabilidades** | 50+ técnicas |
| **📚 Lições Educacionais** | 25+ |
| **🌐 Idiomas Suportados** | 3 (PT/EN/ES) |
| **🎯 Taxa de Sucesso** | 80%+ ataques |
| **⏱️ Tempo Médio de Setup** | < 5 minutos |

</div>

---

<div align="center">

## 🎉 **CYBERLAB PROFESSIONAL V2.0**
### *"Aprenda atacando, domine defendendo"* 🛡️⚔️

**🚀 A plataforma definitiva para educação em segurança cibernética 🚀**

---

*Desenvolvido com ❤️ pela comunidade de segurança cibernética*

**⭐ Star o projeto no GitHub se ele foi útil para você! ⭐**

</div>

## Como executar o projeto

### Pré-requisitos
- Node.js (versão 18 ou superior)
- npm ou yarn

### Instalação

```bash
# Clone o repositório
git clone <repository-url>
cd CyberLab

# Instale as dependências
npm install

# Execute em modo de desenvolvimento
npm run dev
```

### Scripts disponíveis

- `npm run dev` - Executa o projeto em modo de desenvolvimento
- `npm run build` - Gera build de produção
- `npm run preview` - Visualiza o build de produção localmente

Follow these steps:

```sh
# Step 1: Clone the repository using the project's Git URL.
git clone <YOUR_GIT_URL>

# Step 2: Navigate to the project directory.
cd <YOUR_PROJECT_NAME>

# Step 3: Install the necessary dependencies.
npm i

# Step 4: Start the development server with auto-reloading and an instant preview.
npm run dev
```

**Edit a file directly in GitHub**

- Navigate to the desired file(s).
- Click the "Edit" button (pencil icon) at the top right of the file view.
- Make your changes and commit the changes.

**Use GitHub Codespaces**

- Navigate to the main page of your repository.
- Click on the "Code" button (green button) near the top right.
- Select the "Codespaces" tab.
- Click on "New codespace" to launch a new Codespace environment.
- Edit files directly within the Codespace and commit and push your changes once you're done.

## What technologies are used for this project?

This project is built with:

- Vite
- TypeScript
- React
- shadcn-ui
- Tailwind CSS

## Deploy

### Hostinger
1. Execute `npm run build` para gerar os arquivos de produção
2. Faça upload da pasta `dist/` para o servidor
3. Configure redirects para SPA se necessário

### GitHub Pages
1. Configure GitHub Actions para build automático
2. Deploy para branch gh-pages
3. Configure domínio personalizado se desejado

### Outras plataformas
O projeto é compatível com qualquer serviço de hospedagem que suporte aplicações React/SPA.
