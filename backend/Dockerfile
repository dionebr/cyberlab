# 🚨 DOCKERFILE VULNERÁVEL PARA EDUCAÇÃO
# ⚠️ Esta configuração é INTENCIONALMENTE INSEGURA
# 🎓 Para demonstrar problemas de segurança em containers
# 🚨 NÃO usar em produção!

# Usar imagem oficial do Node.js
FROM node:18-alpine

# 🚨 CONFIGURAÇÕES VULNERÁVEIS - NÃO fazer em produção!
# Instalar ferramentas adicionais para demonstrações
RUN apk update && apk add --no-cache \
    curl \
    wget \
    bash \
    vim \
    mysql-client \
    openssh-client \
    git \
    # Ferramentas para command injection demos
    netcat-openbsd \
    bind-tools \
    iputils

# ⚠️ Definir diretório de trabalho
WORKDIR /app

# Copiar package.json e instalar dependências
COPY package*.json ./

# Instalar dependências incluindo dev dependencies para debugging
RUN npm install

# 🚨 Copiar código fonte para container
COPY . .

# ⚠️ Criar diretórios com permissões específicas
RUN mkdir -p /app/logs /app/uploads /app/backups /app/temp && \
    chmod 755 /app/logs /app/uploads /app/backups /app/temp

# 🚨 Configurar variáveis de ambiente para desenvolvimento vulnerável
ENV NODE_ENV=development
ENV DEBUG=cyberlab:*
ENV LOG_LEVEL=debug
ENV PORT=5001

# ⚠️ Variáveis de database (para ambiente educacional)
ENV DB_HOST=mysql
ENV DB_PORT=3306
ENV DB_USER=vulnerable_user
ENV DB_PASS=weak123
ENV DB_NAME=cyberlab_vulnerable

# ⚠️ Secrets para ambiente de laboratório
ENV JWT_SECRET=cyberlab_education_key_123
ENV API_MASTER_KEY=education_master_key
ENV ENCRYPTION_KEY=lab_encryption_key

# Expor porta principal
EXPOSE 5001

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=40s --retries=3 \
    CMD curl -f http://localhost:5001/api/status || exit 1

# Comando de inicialização
CMD ["npm", "run", "dev"]