#!/bin/bash

# 🚀 CyberLab Professional - Script de Inicialização Rápida
# Versão: 2.0
# Uso: ./start.sh [opções]

set -e

# Cores para output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
WHITE='\033[1;37m'
NC='\033[0m' # No Color

# Banner
print_banner() {
    echo -e "${PURPLE}"
    echo "██████╗██╗   ██╗██████╗ ███████╗██████╗ ██╗      █████╗ ██████╗ "
    echo "██╔════╝╚██╗ ██╔╝██╔══██╗██╔════╝██╔══██╗██║     ██╔══██╗██╔══██╗"
    echo "██║      ╚████╔╝ ██████╔╝█████╗  ██████╔╝██║     ███████║██████╔╝"
    echo "██║       ╚██╔╝  ██╔══██╗██╔══╝  ██╔══██╗██║     ██╔══██║██╔══██╗"
    echo "╚██████╗   ██║   ██████╔╝███████╗██║  ██║███████╗██║  ██║██████╔╝"
    echo " ╚═════╝   ╚═╝   ╚═════╝ ╚══════╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝╚═════╝ "
    echo -e "${WHITE}CyberLab Professional v2.0 - Break'n'Learn Platform${NC}"
    echo -e "${YELLOW}⚠️  AMBIENTE EDUCACIONAL VULNERÁVEL - USE APENAS EM LABORATÓRIO ⚠️${NC}"
    echo ""
}

# Verificar dependências
check_dependencies() {
    echo -e "${CYAN}🔍 Verificando dependências...${NC}"
    
    # Verificar Docker
    if ! command -v docker &> /dev/null; then
        echo -e "${RED}❌ Docker não encontrado. Instale o Docker primeiro.${NC}"
        echo -e "${WHITE}Ubuntu/Debian: curl -fsSL https://get.docker.com | sh${NC}"
        exit 1
    fi
    
    # Verificar Docker Compose
    if ! command -v docker-compose &> /dev/null; then
        echo -e "${RED}❌ Docker Compose não encontrado.${NC}"
        echo -e "${WHITE}Instale: sudo curl -L \"https://github.com/docker/compose/releases/latest/download/docker-compose-\$(uname -s)-\$(uname -m)\" -o /usr/local/bin/docker-compose${NC}"
        exit 1
    fi
    
    # Verificar se Docker está rodando
    if ! docker info &> /dev/null; then
        echo -e "${RED}❌ Docker não está rodando. Inicie o Docker primeiro.${NC}"
        echo -e "${WHITE}sudo systemctl start docker${NC}"
        exit 1
    fi
    
    echo -e "${GREEN}✅ Dependências OK${NC}"
}

# Verificar portas
check_ports() {
    echo -e "${CYAN}🔍 Verificando portas disponíveis...${NC}"
    
    PORTS=(5001 8080 3306 8081 8082 6379)
    for port in "${PORTS[@]}"; do
        if lsof -Pi :$port -sTCP:LISTEN -t >/dev/null ; then
            echo -e "${YELLOW}⚠️  Porta $port em uso. Pode haver conflitos.${NC}"
        fi
    done
    
    echo -e "${GREEN}✅ Verificação de portas concluída${NC}"
}

# Inicializar aplicação
start_application() {
    echo -e "${CYAN}🚀 Iniciando CyberLab Professional...${NC}"
    
    # Parar containers existentes
    echo -e "${YELLOW}🛑 Parando containers existentes...${NC}"
    docker-compose down 2>/dev/null || true
    
    # Construir e iniciar serviços
    echo -e "${CYAN}🏗️  Construindo e iniciando serviços...${NC}"
    docker-compose up -d --build
    
    # Aguardar inicialização
    echo -e "${CYAN}⏳ Aguardando inicialização dos serviços...${NC}"
    
    # Função para verificar saúde de um serviço
    wait_for_service() {
        local url=$1
        local name=$2
        local max_attempts=30
        local attempt=1
        
        while [ $attempt -le $max_attempts ]; do
            if curl -s "$url" > /dev/null 2>&1; then
                echo -e "${GREEN}✅ $name está rodando${NC}"
                return 0
            fi
            echo -e "${YELLOW}⏳ Aguardando $name... (tentativa $attempt/$max_attempts)${NC}"
            sleep 2
            ((attempt++))
        done
        
        echo -e "${RED}❌ $name não conseguiu iniciar após $max_attempts tentativas${NC}"
        return 1
    }
    
    # Verificar serviços
    wait_for_service "http://localhost:3001/health" "Backend"
    wait_for_service "http://localhost:8080" "Frontend"
    wait_for_service "http://localhost:8081" "phpMyAdmin"
}

# Mostrar status
show_status() {
    echo ""
    echo -e "${WHITE}🎯 CyberLab Professional está rodando!${NC}"
    echo ""
    echo -e "${BLUE}📱 INTERFACES DISPONÍVEIS:${NC}"
    echo -e "${WHITE}🌐 Frontend:       ${CYAN}http://localhost:8080${NC}"
    echo -e "${WHITE}⚡ Backend API:    ${CYAN}http://localhost:3001${NC}"
    echo -e "${WHITE}🗃️  phpMyAdmin:    ${CYAN}http://localhost:8081${NC}"
    echo -e "${WHITE}💾 Redis Commander: ${CYAN}http://localhost:8082${NC}"
    echo ""
    echo -e "${BLUE}🔗 ENDPOINTS ÚTEIS:${NC}"
    echo -e "${WHITE}📊 Analytics:      ${CYAN}http://localhost:3001/api/analytics/dashboard${NC}"
    echo -e "${WHITE}🩺 Status API:     ${CYAN}http://localhost:3001/health${NC}"
    echo -e "${WHITE}📋 Docs API:       ${CYAN}http://localhost:5001/api${NC}"
    echo ""
    echo -e "${BLUE}🎯 MÓDULOS VULNERÁVEIS:${NC}"
    echo -e "${WHITE}• SQL Injection    • XSS              • Command Injection${NC}"
    echo -e "${WHITE}• File Upload      • Auth Bypass      • Brute Force${NC}" 
    echo -e "${WHITE}• CSRF            • File Inclusion   • Session Mgmt${NC}"
    echo -e "${WHITE}• Blind SQL       • Insecure Captcha • Analytics${NC}"
    echo ""
}

# Mostrar logs
show_logs() {
    echo -e "${CYAN}📋 Logs dos serviços (Ctrl+C para sair):${NC}"
    docker-compose logs -f
}

# Parar aplicação
stop_application() {
    echo -e "${YELLOW}🛑 Parando CyberLab Professional...${NC}"
    docker-compose down
    echo -e "${GREEN}✅ Aplicação parada com sucesso${NC}"
}

# Reset completo
reset_application() {
    echo -e "${RED}🗑️  RESET COMPLETO - Isso irá remover todos os dados!${NC}"
    read -p "Tem certeza? Digite 'RESET' para confirmar: " confirm
    
    if [ "$confirm" = "RESET" ]; then
        echo -e "${YELLOW}🛑 Parando serviços...${NC}"
        docker-compose down -v
        
        echo -e "${YELLOW}🗑️  Removendo imagens...${NC}"
        docker-compose rm -f
        docker system prune -f
        
        echo -e "${YELLOW}🧹 Limpando volumes...${NC}"
        docker volume prune -f
        
        echo -e "${GREEN}✅ Reset completo realizado${NC}"
    else
        echo -e "${BLUE}ℹ️  Reset cancelado${NC}"
    fi
}

# Mostrar uso
show_usage() {
    echo -e "${WHITE}Uso: $0 [comando]${NC}"
    echo ""
    echo -e "${BLUE}Comandos disponíveis:${NC}"
    echo -e "${WHITE}  start     ${NC}Iniciar a aplicação (padrão)"
    echo -e "${WHITE}  stop      ${NC}Parar a aplicação"
    echo -e "${WHITE}  restart   ${NC}Reiniciar a aplicação"  
    echo -e "${WHITE}  logs      ${NC}Mostrar logs em tempo real"
    echo -e "${WHITE}  status    ${NC}Mostrar status dos serviços"
    echo -e "${WHITE}  reset     ${NC}Reset completo (remove todos os dados)"
    echo -e "${WHITE}  help      ${NC}Mostrar esta ajuda"
    echo ""
    echo -e "${BLUE}Exemplos:${NC}"
    echo -e "${WHITE}  $0 start   ${NC}# Inicia a aplicação"
    echo -e "${WHITE}  $0 logs    ${NC}# Mostra logs em tempo real"
    echo -e "${WHITE}  $0 reset   ${NC}# Reset completo"
    echo ""
}

# Menu principal
main() {
    print_banner
    
    case ${1:-start} in
        start)
            check_dependencies
            check_ports
            start_application
            show_status
            ;;
        stop)
            stop_application
            ;;
        restart)
            stop_application
            sleep 2
            start_application
            show_status
            ;;
        logs)
            show_logs
            ;;
        status)
            show_status
            ;;
        reset)
            reset_application
            ;;
        help|--help|-h)
            show_usage
            ;;
        *)
            echo -e "${RED}❌ Comando inválido: $1${NC}"
            show_usage
            exit 1
            ;;
    esac
}

# Verificar se está rodando como root (não recomendado)
if [ "$EUID" -eq 0 ]; then
    echo -e "${YELLOW}⚠️  Rodando como root. Considere criar um usuário não-root para Docker.${NC}"
    sleep 2
fi

# Executar função principal
main "$@"