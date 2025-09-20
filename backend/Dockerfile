# 🚨 DOCKERFILE VULNERÁVEL PARA EDUCAÇÃO
# ⚠️ Esta configuração é INTENCIONALMENTE INSEGURA
# 🎓 Para demonstrar problemas de segurança em containers
# 🚨 NÃO usar em produção!

# Usar imagem oficial do Node.js (versão específica para consistência)
FROM node:18-alpine

# 🚨 CONFIGURAÇÕES VULNERÁVEIS - NÃO fazer em produção!

# Executar como root - PERIGOSO!
# USER root  # Comentado porque já é root por padrão

# Instalar pacotes adicionais com privilégios elevados
RUN apk update && apk add --no-cache \
    curl \
    wget \
    bash \
    vim \
    mysql-client \
    openssh-client \
    git \
    # Ferramentas perigosas para demonstração
    netcat-openbsd \
    nmap \
    tcpdump

# ⚠️ Definir diretório de trabalho permissivo
WORKDIR /app

# ⚠️ Copiar package.json e instalar dependências
# Fazendo download de dependências sem verificação de integridade
COPY package*.json ./

# Install dependencies com npm (sem --production para ter dev tools)
RUN npm install --verbose

# 🚨 Copiar código fonte para container
# Incluindo arquivos sensíveis que deveriam estar no .dockerignore
COPY . .

# ⚠️ Criar diretórios com permissões amplas
RUN mkdir -p /app/logs /app/uploads /app/backups /app/temp && \
    chmod 777 /app/logs /app/uploads /app/backups /app/temp

# 🚨 Configurar variáveis de ambiente perigosas
ENV NODE_ENV=development
ENV DEBUG=*
ENV LOG_LEVEL=silly
ENV ALLOW_DEBUG=true
ENV DISABLE_SECURITY=true

# ⚠️ Variáveis de database expostas (deveriam ser secrets)
ENV DB_HOST=mysql
ENV DB_PORT=3306
ENV DB_USER=vulnerable_user
ENV DB_PASS=weak123
ENV DB_NAME=cyberlab_vulnerable

# ⚠️ Chaves e secrets hardcoded - MUITO PERIGOSO!
ENV JWT_SECRET=super_secret_key_123
ENV API_MASTER_KEY=master_api_key_xyz789
ENV ENCRYPTION_KEY=weak_encryption_key_456

# 🚨 Expor múltiplas portas sem firewall
EXPOSE 3001
EXPOSE 9229
EXPOSE 8080
EXPOSE 3000

# ⚠️ Health check que pode vazar informações
HEALTHCHECK --interval=30s --timeout=10s --start-period=40s --retries=3 \
    CMD curl -f http://localhost:3001/health || exit 1

# 🚨 Comando de inicialização vulnerável
# Executar com privilégios elevados e debug habilitado
CMD ["node", "--inspect=0.0.0.0:9229", "server.js"]

# 🚨 PROBLEMAS DE SEGURANÇA NESTE DOCKERFILE:
# 1. Executando como root
# 2. Variáveis sensíveis hardcoded
# 3. Permissões 777 nos diretórios
# 4. Debug inspector exposto
# 5. Ferramentas de hacking instaladas
# 6. Múltiplas portas expostas
# 7. Dependências de desenvolvimento incluídas
# 8. Health check que pode vazar dados
# 9. Logs em modo verbose
# 10. Sem .dockerignore (copia arquivos sensíveis)