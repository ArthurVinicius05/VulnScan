# VulnScan Pro

Plataforma de auditoria de segurança para avaliações autorizadas de aplicações web e análise estática de código-fonte. O projeto combina inspeção segura de arquivos, scanners isolados, análise de dependências e relatórios por conta.

> **Build 0.4.0 — hardening em andamento.** O repositório agora possui fila durável, quotas por conta, MFA, locks de dependências, proxy de saída SMTP, backups criptografados e métricas Prometheus. Isso melhora a base operacional, mas não equivale a auditoria independente nem significa que uma implantação pública esteja aprovada.

## Stack

- API: Python 3.12, FastAPI, SQLAlchemy, Alembic e Pydantic Settings.
- Banco: SQLite no desenvolvimento; PostgreSQL no perfil de produção.
- Fila: jobs persistidos no PostgreSQL, worker assíncrono, leases, retries limitados e gravação idempotente do histórico.
- Frontend: React, TypeScript e Vite.
- Scanners: Bandit, Ruff, Gitleaks; OSV-Scanner e verificação de sites são opcionais e permanecem desativados no perfil de produção.
- Rate limiting: Redis compartilhado.
- Operação: Docker Compose, Prometheus e scripts de backup/restore com age.
- Imagens de contêiner: digests multi-plataforma fixados em `images.lock` e verificados no CI.
- Frontend de produção: CSP, Permissions-Policy e cabeçalhos de isolamento no Nginx.
- Logs Docker: rotação local de 10 MB × 5 arquivos por serviço; agregação centralizada permanece tarefa de implantação.
- Dependências: backend/requirements.lock (hashes) e frontend/package-lock.json.

## Desenvolvimento local

~~~bash
cp .env.example .env
docker compose up --build
~~~

- Painel: http://localhost:5173
- API: http://localhost:8000
- OpenAPI/Swagger: disponível somente no ambiente de desenvolvimento.

Sem Docker, instale as dependências Python com pip install -r backend/requirements.txt, aplique alembic upgrade head dentro de backend e execute uvicorn app.main:app --reload. Para o frontend, use npm ci e npm run dev dentro de frontend.

O ambiente local pode ativar contas automaticamente quando SMTP não está configurado. Em produção, o cadastro exige SMTP e confirmação de e-mail.

## Recursos e controles implementados

### Autenticação e conta
- Cadastro, confirmação de e-mail, login, recuperação de senha e logout.
- Senhas com Argon2id; tokens de sessão e de confirmação armazenados somente como hashes.
- Cookies HttpOnly, CSRF, SameSite=Lax e Secure em produção.
- MFA TOTP com segredo criptografado por Fernet, proteção contra replay, desafios de login com expiração/limite de tentativas e códigos de recuperação de uso único.
- Exclusão de conta autenticada por senha e MFA, removendo jobs, relatórios, sessões, tokens e dados MFA do banco ativo; jobs em execução precisam terminar antes.
- A chave MFA_ENCRYPTION_KEY é crítica: guarde-a em gerenciador de segredos e inclua-a em backups seguros. Perdê-la impede a descriptografia dos segredos TOTP existentes.
- Rate limiting compartilhado por Redis; Redis indisponível em produção faz rotas protegidas falharem de forma segura.

### Análise e fila
- Upload ZIP com validação de caminhos, links simbólicos, arquivos criptografados, expansão suspeita e limites de tamanho.
- O endpoint de análise de código-fonte responde HTTP 202 e persiste o job no PostgreSQL.
- O worker usa bloqueio de linha, leases renováveis, propriedade por tentativa, retries limitados e gravação atômica/idempotente do resultado.
- Jobs que esgotam tentativas vão para dead-letter; operadores autenticados podem inspecionar e reprocessar jobs pelo endpoint interno de operações. O token `OPS_ADMIN_TOKEN` deve ser mantido em segredo e nunca colocado no frontend.
- O arquivo original de um job em dead-letter fica disponível por no máximo 72 horas (configurável por `DEAD_LETTER_ARCHIVE_RETENTION_HOURS`); depois disso, só é possível recuperar com novo upload.
- Análises ainda na fila podem ser canceladas pelo usuário; o upload temporário é descartado e a vaga de concorrência liberada. Jobs em execução não podem ser cancelados nesta versão.
- Os arquivos originais são removidos quando a análise termina normalmente; em dead-letter, permanecem apenas durante a janela curta de recuperação e depois são apagados.
- Quotas padrão por conta: 30 análises/mês, 2 análises simultâneas e 50 MB de arquivos pendentes. O limite padrão de upload individual é 25 MB. Ajuste os valores conforme a capacidade real.
- O histórico é isolado por usuário; os resultados heurísticos podem conter falsos positivos e negativos.

### Retenção
- Jobs concluídos, falhos, cancelados e dead-letter: metadados removidos após 30 dias.
- Arquivos originais de jobs dead-letter: apagados após 72 horas por padrão.
- Relatórios de auditoria: retidos por 180 dias.
- Desafios MFA, sessões e tokens expirados: limpeza diária pelo worker.
- Os prazos são configuráveis por ANALYSIS_JOB_RETENTION_DAYS e AUDIT_RETENTION_DAYS. A política pública de privacidade deve refletir os valores reais da implantação.

### Egress e isolamento
- No Compose de produção, a API não possui saída direta para a internet.
- O envio de e-mail passa pelo serviço smtp-proxy, que encaminha somente para SMTP_UPSTREAM_HOST:SMTP_UPSTREAM_PORT, resolve o hostname na inicialização e rejeita IPs não públicos.
- SMTP_TLS_SERVER_NAME deve corresponder exatamente a SMTP_UPSTREAM_HOST. O proxy aceita somente portas STARTTLS 25, 587 ou 2525; TLS implícito na porta 465 não é suportado.
- O proxy SMTP é o único serviço conectado à rede externa de egress. O firewall do host ainda precisa permitir somente os IPs/portas do relay e DNS estritamente necessário.
- Scanner e analysis-worker permanecem em redes internas. Website scanning e OSV online ficam desativados no Compose de produção até existir política de egress específica e testes SSRF/DNS rebinding.

### Monitoramento
- API expõe métricas Prometheus de requisições HTTP, latência, estado da fila e erros de coleta.
- Prometheus coleta métricas e carrega regras para backlog de fila e taxa de erros 5xx.
- Interface Prometheus publicada somente em 127.0.0.1:9090; use túnel SSH para acesso remoto.
- As regras ficam visíveis no Prometheus, mas notificações externas ainda exigem Alertmanager ou integração equivalente.

## Produção experimental

O Compose de desenvolvimento não deve ser publicado na internet. Para preparar o perfil de produção:

1. Copie .env.production.example para .env.production.
2. Gere uma senha PostgreSQL longa e aleatória; mantenha DATABASE_URL consistente com ela.
3. Gere SCANNER_WORKER_TOKEN aleatório e forte.
4. Gere MFA_ENCRYPTION_KEY com:

~~~bash
python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
~~~

5. Configure SMTP_UPSTREAM_HOST, SMTP_UPSTREAM_PORT, SMTP_TLS_SERVER_NAME, credenciais SMTP e BACKUP_RECIPIENT.
6. Para inspecionar a fila morta, use `GET /api/ops/dead-letter` com `X-Operations-Token`. Para reprocessar um job que ainda retenha o arquivo, use `POST /api/ops/jobs/{job_id}/retry` com o mesmo header. A API não disponibiliza uma interface web para esse token.
7. Ajuste CORS_ORIGINS e FRONTEND_URL para o domínio real.
8. Configure o firewall do host para restringir o egress do proxy SMTP ao relay autorizado.
9. Inicie:

~~~bash
docker compose --env-file .env.production -f docker-compose.production.yml up --build -d
~~~

10. Coloque um proxy TLS gerenciado (Caddy, Nginx ou equivalente) na frente de 127.0.0.1:8080. O cookie é Secure; não exponha sem HTTPS.

O perfil de produção mantém API, PostgreSQL, Redis, scanner, worker e Prometheus em redes internas. A interface Prometheus fica em loopback. A API confia em headers forwarded somente do proxy frontend reservado.

## Backup e restauração

Instale age, configure BACKUP_RECIPIENT com a chave pública e execute:

~~~bash
bash scripts/backup_postgres.sh
~~~

O backup PostgreSQL é criptografado, recebe checksum SHA-256 e deve ser enviado para armazenamento externo protegido. Guarde a chave privada age separada do servidor.

Para restaurar, pare backend e analysis-worker, depois execute:

~~~bash
CONFIRM_RESTORE=YES BACKUP_FILE=backups/arquivo.dump.age BACKUP_IDENTITY=/caminho/identity.txt bash scripts/restore_postgres.sh
~~~

O script valida o checksum, descriptografa e executa pg_restore. Faça exercícios periódicos de restauração; um arquivo de backup não testado não comprova recuperabilidade. A agenda e o armazenamento externo precisam ser configurados pelo operador.

## CI e testes

O workflow CI:
- Gera lockfiles Python com hashes e npm lockfile; no push à branch de trabalho, atualiza os lockfiles automaticamente.
- Instala dependências com --require-hashes e npm ci.
- Executa testes backend, testes de integração PostgreSQL e smoke test de backup/restauração criptografados.
- Faz build das imagens backend, frontend, SMTP proxy, website worker e OSV worker.
- Valida o Compose de produção.

Execução local:

~~~bash
cd backend
python -m pytest -q
~~~

## Política de escopo

Use o VulnScan somente em sistemas próprios ou para os quais exista autorização explícita. O projeto não deve executar código enviado. Trate ZIPs, relatórios e evidências como dados potencialmente sensíveis.

Consulte:
- SECURITY.md — divulgação responsável.
- PRIVACY.md — rascunho de privacidade e retenção.
- TERMS.md — termos e escopo de uso.
- docs/ARCHITECTURE.md — arquitetura.
- docs/PRODUCTION_READINESS.md — gates de lançamento.
- docs/DEPENDENCY_MANAGEMENT.md — atualização e validação de dependências.

## Pendências antes de abrir ao público

- Configurar e comprovar firewall/egress allowlist no host real.
- Testar HTTPS, SMTP, backup e restauração em infraestrutura real.
- Configurar Alertmanager, notificações e centralização de logs.
- Fixar imagens Docker por digest e definir política de atualização/rollback.
- Executar testes de carga, abuso, concorrência, SSRF e revisão de escopo.
- Realizar auditoria/pentest independente e corrigir os achados.
- Revisar juridicamente privacidade/termos para LGPD, preencher dados do operador e canal de contato.
- Definir processo de exclusão de conta/dados e atendimento a solicitações dos titulares.

**O VulnScan ainda não deve receber tráfego público não confiável.** A PR pode ser revisada e testada, mas a decisão de produção depende dos gates acima e da validação no ambiente de implantação.
