# CyberLab - Break'n'Learn

Uma plataforma educacional interativa focada no ensino de segurança web através de experiências práticas.

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
