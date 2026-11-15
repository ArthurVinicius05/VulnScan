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

O ambiente local usa `APP_ENV=development` e aplica as migrações Alembic antes de iniciar a API, criando/atualizando o banco SQLite `vulnscan.db` dentro do backend. O arquivo não contém o ZIP original, apenas metadados e resultados da análise. Para persistência PostgreSQL, configure `DATABASE_URL=postgresql+psycopg://usuario:senha@host:5432/vulnscan` e mantenha as credenciais fora do Git. O Compose recebe `DATABASE_URL` do ambiente. O cadastro exige verificação de e-mail quando SMTP está configurado; em desenvolvimento sem SMTP, a conta é ativada automaticamente para facilitar testes. Em produção, o cadastro falha de forma segura se o SMTP não estiver configurado. O Redis é usado pelo Compose para aplicar limites compartilhados entre processos. A sessão é enviada em cookie HttpOnly; em produção, defina `APP_ENV=production` para ativar automaticamente o atributo Secure. O frontend e a API devem usar HTTPS em produção.

### Contas e proteção da API
- Cadastro e login individuais estão disponíveis em `POST /api/auth/register` e `POST /api/auth/login`.
- Verificação de e-mail: `POST /api/auth/verify-email` e reenvio genérico por `POST /api/auth/resend-verification`.
- Recuperação: `POST /api/auth/request-password-reset` e `POST /api/auth/reset-password`. A resposta de solicitação não revela se o e-mail existe.
- Tokens de confirmação e redefinição são aleatórios, armazenados somente como SHA-256, expiram em 30 minutos e são de uso único. Redefinir senha revoga todas as sessões da conta.
- O SMTP é configurado por `SMTP_HOST`, `SMTP_PORT`, `SMTP_USERNAME`, `SMTP_PASSWORD`, `SMTP_STARTTLS`, `MAIL_FROM` e `FRONTEND_URL`; veja `.env.example`.
- Senhas são armazenadas com hash Argon2id; a API nunca retorna o hash.
- As sessões usam tokens aleatórios; somente o hash SHA-256 do token é persistido. A validade padrão é de 12 horas.
- Use `GET /api/auth/me` para consultar a conta atual e `POST /api/auth/logout` para revogar a sessão atual.
- A API entrega a sessão em cookie HttpOnly, SameSite=Lax e Secure em produção. O cookie CSRF é legível pelo frontend e deve ser enviado no cabeçalho `X-CSRF-Token` em operações mutáveis autenticadas.
- As rotas de análise e histórico exigem uma sessão válida; as origens de frontend permitidas devem ser configuradas em `CORS_ORIGINS`.
- Cada nova auditoria é associada ao usuário autenticado. Listagem e detalhes só retornam registros pertencentes àquela conta.
- Auditorias criadas antes da migração de contas ficam sem proprietário e não são exibidas no histórico individual.
- O cadastro continua sem aprovação/invite; em produção, configure SMTP para exigir confirmação do e-mail. A política de convites, MFA e administração de contas ainda não existe.
- A sessão não fica disponível ao JavaScript: o token é mantido em cookie HttpOnly. A proteção CSRF compara o valor do cookie CSRF com o cabeçalho `X-CSRF-Token`; configure corretamente `CORS_ORIGINS` e use HTTPS em produção.
- O middleware limita login/cadastro a 10 requisições por IP em 5 minutos e as rotas de análise a 5 requisições por IP em 10 minutos. No Compose, os contadores são compartilhados pelo Redis em uma rede interna; em desenvolvimento sem Redis, o fallback é local ao processo. Em produção, Redis ausente ou indisponível faz as rotas protegidas falharem com 503 (fail-closed).

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
- Protege as rotas de análise e histórico com sessões individuais em cookies HttpOnly e isolamento do histórico por usuário.
- Aplica rate limiting nas rotas de autenticação e análise, usando Redis compartilhado no Compose.
- Persiste auditorias concluídas e disponibiliza histórico paginado, isolamento por conta e visualização dos detalhes dos relatórios no painel React.

## Isolamento dos workers
Os workers usam usuário sem privilégios, sistema de arquivos somente leitura, diretório temporário limitado com `noexec` e `nosuid`, remoção de capabilities, `no-new-privileges`, limites de CPU/memória/processos e redes dedicadas. Esses controles reduzem riscos, mas não equivalem a uma sandbox completa nem substituem o endurecimento do host.

## Limitações importantes
- Achados heurísticos não provam explorabilidade; falsos positivos e negativos são esperados.
- O conjunto inicial de regras é pequeno e não substitui uma revisão profissional.
- O código enviado não é intencionalmente executado pela API.
- Ainda não há papéis/permissões administrativas, MFA ou política de convites.
- O esquema do banco é versionado por migrações Alembic; execute `alembic upgrade head` após atualizar a aplicação. O SQLite é o padrão de desenvolvimento; PostgreSQL pode ser informado via `DATABASE_URL`.
- O histórico é isolado por conta para auditorias novas; registros legados sem proprietário não aparecem no histórico individual.
- Ainda faltam limites de uso por usuário, allowlist de saída aplicada por firewall/proxy, explicações por IA e relatórios PDF/JSON. O rate limiting atual é por IP e não substitui quotas por conta.
- O worker de sites executa somente verificações passivas limitadas; não realiza testes ativos.
- Esta base ainda não está pronta para receber tráfego público não confiável.

## Segurança
Avalie somente sistemas próprios ou para os quais exista autorização explícita. Trate arquivos enviados como entrada não confiável.

## Próximas etapas
1. Limites de uso por usuário, allowlist de saída aplicada por firewall/proxy e escopo de auditoria.
2. PostgreSQL gerenciado, backups, observabilidade e operação de produção.
3. Relatórios exportáveis JSON/PDF e explicações fundamentadas por IA.
4. MFA, administração de contas e política de convites.
