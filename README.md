# VulnScan Pro

Plataforma modular de auditoria de segurança para avaliações autorizadas de sites e análise de código-fonte.

> **Build 0.4.0** — Base FastAPI + React/TypeScript com inspeção segura de ZIP, análise estática heurística, inventário de dependências e workers isolados. Ainda é uma versão de desenvolvimento, não um scanner de segurança pronto para produção.

## Tecnologias
- Frontend: React, TypeScript, Vite e Lucide
- Backend/API: Python, FastAPI e Pydantic Settings
- Persistência: SQLAlchemy, Alembic, SQLite no desenvolvimento e PostgreSQL configurável
- Ferramentas: Bandit, Ruff, Gitleaks e OSV-Scanner (opcional)
- Testes: pytest
- Ambiente: Docker Compose

## Executar localmente

### Docker Compose
```bash
docker compose up --build
```

Painel: http://localhost:5173  
Documentação da API: http://localhost:8000/docs

O ambiente local usa `APP_ENV=development` e aplica as migrações Alembic antes de iniciar a API, criando/atualizando o banco SQLite `vulnscan.db` dentro do backend. O arquivo não contém o ZIP original, apenas metadados e resultados da análise. Para persistência PostgreSQL, configure `DATABASE_URL=postgresql+psycopg://usuario:senha@host:5432/vulnscan` e mantenha as credenciais fora do Git. O Compose recebe `DATABASE_URL` do ambiente. O cadastro inicial é aberto; implemente verificação de e-mail, limitação de tentativas e política de cadastro antes de disponibilizar publicamente. As rotas privadas aceitam o token de sessão no cabeçalho `Authorization: Bearer TOKEN`.

### Contas e proteção da API
- Cadastro e login individuais estão disponíveis em `POST /api/auth/register` e `POST /api/auth/login`.
- Senhas são armazenadas com hash Argon2id; a API nunca retorna o hash.
- As sessões usam tokens aleatórios; somente o hash SHA-256 do token é persistido. A validade padrão é de 12 horas.
- Use `GET /api/auth/me` para consultar a conta atual e `POST /api/auth/logout` para revogar a sessão atual.
- As rotas de análise e histórico exigem uma sessão Bearer válida.
- Cada nova auditoria é associada ao usuário autenticado. Listagem e detalhes só retornam registros pertencentes àquela conta.
- Auditorias criadas antes da migração de contas ficam sem proprietário e não são exibidas no histórico individual.
- O cadastro inicial é aberto. Antes de disponibilizar publicamente, implemente verificação de e-mail, limitação de tentativas, recuperação de senha e política de criação de contas.
- O frontend mantém o token em `sessionStorage`. Isso evita persistência após encerrar a sessão do navegador, mas não protege contra XSS; cookies HttpOnly com proteção CSRF são uma melhoria necessária antes de produção.

### Verificação passiva de sites (opcional)
Somente para alvos próprios ou com autorização explícita:
```bash
ENABLE_WEBSITE_SCAN=true docker compose --profile website-scan up --build
``

A rota `POST /api/analysis/website` recebe `url` e `authorized: true`. O worker valida destinos HTTP(S), fixa o IP público validado, revalida redirecionamentos e faz uma requisição GET passiva limitada. Não executa payloads ou exploração. A rede de saída do Compose não é uma allowlist: antes de uso público, configure firewall/proxy de saída, autenticação de usuários, limites por usuário e auditoria de escopo.

### Verificação de dependências com OSV (opcional)
```bash
ENABLE_OSV_SCAN=true docker compose --profile osv-online up --build
``

O worker OSV tem acesso externo para consultar dados de vulnerabilidades. O worker padrão de scanners continua sem rota externa. Docker Compose não restringe destinos por domínio; use firewall/proxy de saída em implantações reais.

### Executar sem Docker
Instale `backend/requirements.txt`, entre em `backend`, aplique `alembic upgrade head` e execute `uvicorn app.main:app --reload`. Para análise completa, configure os workers separadamente.

### Frontend
Execute `npm install` e `npm run dev` em `frontend`.

## Recursos atuais
- Recebe arquivos ZIP de até 25 MB por padrão.
- Rejeita traversal de caminhos, links simbólicos, arquivos criptografados, expansão suspeita e arquivos excessivamente grandes.
- Detecta marcadores de tecnologias e estrutura do projeto.
- Executa verificações heurísticas limitadas e ferramentas estáticas em worker dedicado.
- Detecta possíveis segredos sem copiar valores sensíveis para as evidências.
- Inventaria manifestos de dependências para npm, Python, Rust, Go, Ruby, PHP, Maven e Gradle.
- Pode consultar vulnerabilidades conhecidas via OSV-Scanner em worker separado e opt-in.
- Oferece auditoria passiva limitada de cabeçalhos HTTP, com validação SSRF e worker separado, opt-in.
- Protege as rotas de análise e histórico com sessões Bearer individuais e isolamento do histórico por usuário.
- Persiste auditorias concluídas e disponibiliza histórico paginado, isolamento por conta e visualização dos detalhes dos relatórios no painel React.

## Isolamento dos workers
Os workers usam usuário sem privilégios, sistema de arquivos somente leitura, diretório temporário limitado com `noexec` e `nosuid`, remoção de capabilities, `no-new-privileges`, limites de CPU/memória/processos e redes dedicadas. Esses controles reduzem riscos, mas não equivalem a uma sandbox completa nem substituem o endurecimento do host.

## Limitações importantes
- Achados heurísticos não provam explorabilidade; falsos positivos e negativos são esperados.
- O conjunto inicial de regras é pequeno e não substitui uma revisão profissional.
- O código enviado não é intencionalmente executado pela API.
- Ainda não há papéis/permissões administrativas, verificação de e-mail, recuperação de senha, rate limiting de login ou proteção CSRF baseada em cookie.
- O esquema do banco é versionado por migrações Alembic; execute `alembic upgrade head` após atualizar a aplicação. O SQLite é o padrão de desenvolvimento; PostgreSQL pode ser informado via `DATABASE_URL`.
- O histórico é isolado por conta para auditorias novas; registros legados sem proprietário não aparecem no histórico individual.
- Ainda faltam rate limiting distribuído, allowlist de saída aplicada por firewall/proxy, explicações por IA e relatórios PDF/JSON.
- O worker de sites executa somente verificações passivas limitadas; não realiza testes ativos.
- Esta base ainda não está pronta para receber tráfego público não confiável.

## Segurança
Avalie somente sistemas próprios ou para os quais exista autorização explícita. Trate arquivos enviados como entrada não confiável.

## Próximas etapas
1. Endurecimento da autenticação: cookies HttpOnly/Secure/SameSite, proteção CSRF, rate limiting e recuperação de conta.
2. Limites de uso por usuário, auditoria de escopo e allowlist de saída por firewall/proxy.
3. PostgreSQL gerenciado e operação de produção com backups e monitoramento.
4. Relatórios exportáveis JSON/PDF e explicações fundamentadas por IA.
