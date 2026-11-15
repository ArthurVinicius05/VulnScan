# VulnScan Pro

Plataforma modular de auditoria de segurança para avaliações autorizadas de sites e análise de código-fonte.

> **Build 0.4.0** — Base FastAPI + React/TypeScript com inspeção segura de ZIP, análise estática heurística, inventário de dependências e workers isolados. Ainda é uma versão de desenvolvimento, não um scanner de segurança pronto para produção.

## Tecnologias
- Frontend: React, TypeScript, Vite e Lucide
- Backend/API: Python, FastAPI e Pydantic Settings
- Persistência: SQLAlchemy, SQLite no desenvolvimento e PostgreSQL configurável
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

O ambiente local usa `APP_ENV=development` e cria o banco SQLite `vulnscan.db` dentro do backend. O arquivo não contém o ZIP original, apenas metadados e resultados da análise. Para persistência PostgreSQL, configure `DATABASE_URL=postgresql+psycopg://usuario:senha@host:5432/vulnscan` e mantenha as credenciais fora do Git. O Compose recebe `DATABASE_URL` do ambiente. Para exigir uma chave de API também no desenvolvimento, defina `VULNSCAN_API_KEY` antes de iniciar o Compose. As rotas de análise aceitam a chave no cabeçalho `Authorization: Bearer SUA_CHAVE`.

### Proteção da API
- Todas as rotas em `/api/analysis` passam pela dependência de autenticação por chave Bearer.
- Se `API_KEY` estiver configurada, a chave é obrigatória e comparada em tempo constante.
- Em `APP_ENV=production`, a API falha de forma fechada (HTTP 503) se a chave não estiver configurada.
- A rota de saúde permanece pública para healthchecks.
- As rotas `/api/history` também exigem a chave Bearer e permitem listar auditorias com paginação e consultar seus detalhes.
- A chave é um segredo compartilhado de serviço, não um sistema de contas, sessões ou permissões individuais. Não substitui autenticação de usuários, rotação de credenciais, rate limiting ou auditoria.

Para iniciar um ambiente com a proteção habilitada, configure um segredo forte fora do repositório:
```bash
export VULNSCAN_API_KEY="$(python -c 'import secrets; print(secrets.token_urlsafe(48))')"
docker compose up --build
```

Para produção, configure também `APP_ENV=production` no ambiente de implantação e forneça `API_KEY` por um gerenciador de segredos. Não grave chaves no código, no frontend ou no Git.

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
Instale `backend/requirements.txt` e execute `uvicorn app.main:app --reload` dentro de `backend`. Para análise completa, configure os workers separadamente.

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
- Protege as rotas de análise e histórico com chave Bearer configurável.
- Persiste auditorias concluídas e disponibiliza histórico paginado e detalhes por identificador.

## Isolamento dos workers
Os workers usam usuário sem privilégios, sistema de arquivos somente leitura, diretório temporário limitado com `noexec` e `nosuid`, remoção de capabilities, `no-new-privileges`, limites de CPU/memória/processos e redes dedicadas. Esses controles reduzem riscos, mas não equivalem a uma sandbox completa nem substituem o endurecimento do host.

## Limitações importantes
- Achados heurísticos não provam explorabilidade; falsos positivos e negativos são esperados.
- O conjunto inicial de regras é pequeno e não substitui uma revisão profissional.
- O código enviado não é intencionalmente executado pela API.
- A chave Bearer atual é compartilhada e não oferece identidade individual, autorização por papel ou sessões.
- A persistência inicial usa `create_all`; migrações Alembic ainda não foram configuradas. O SQLite é o padrão de desenvolvimento; PostgreSQL pode ser informado via `DATABASE_URL`.
- O histórico atual é compartilhado no workspace, pois ainda não há identidade individual nem isolamento de registros por usuário.
- Ainda faltam autenticação individual, limites por usuário, allowlist de saída, explicações por IA e relatórios PDF/JSON.
- O worker de sites executa somente verificações passivas limitadas; não realiza testes ativos.
- Esta base ainda não está pronta para receber tráfego público não confiável.

## Segurança
Avalie somente sistemas próprios ou para os quais exista autorização explícita. Trate arquivos enviados como entrada não confiável.

## Próximas etapas
1. Autenticação individual, sessões seguras e controle de acesso por usuário.
2. Migrações Alembic, PostgreSQL gerenciado e isolamento do histórico por usuário.
3. Integração do histórico ao painel React.
4. Limites de uso, auditoria de escopo e allowlist de saída por firewall/proxy.
5. Relatórios JSON/PDF e explicações fundamentadas por IA.
