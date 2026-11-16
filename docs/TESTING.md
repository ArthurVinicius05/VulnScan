# Guia de testes do VulnScan

Este guia ajuda a validar o estado integrado do VulnScan localmente. Use a branch `main` para testar a versão integrada mais recente ou uma branch de tarefa específica quando precisar validar uma mudança ainda não promovida. Mantenha o serviço acessível apenas na sua máquina.

## 1. Pré-requisitos

- Git.
- Docker Desktop com Docker Compose habilitado (ou Docker Engine + plugin Compose).
- Pelo menos alguns GB livres para baixar e construir as imagens.
- Navegador atualizado.

Confira as instalações:

```bash
git --version
docker --version
docker compose version
```

## 2. Baixar a versão que será testada

Para testar a versão integrada mais recente:

```bash
git clone https://github.com/ArthurVinicius05/VulnScan.git
cd VulnScan
git switch main
git pull --ff-only origin main
```

Para testar uma alteração ainda não integrada, troque para a branch indicada na respectiva PR:

```bash
git fetch origin
git switch nome-da-branch
git pull --ff-only origin nome-da-branch
```

Confirme o commit exato que está testando:

```bash
git rev-parse HEAD
```

Compare o SHA com o commit exibido na branch ou na PR correspondente. A branch `main` representa o estado integrado; `develop` recebe o trabalho preparado para a próxima integração.

## 3. Iniciar a aplicação

Na raiz do repositório:

```bash
docker compose up --build -d
docker compose ps
```

Aguarde os serviços ficarem saudáveis. Consulte os logs se algum serviço reiniciar ou não ficar pronto:

```bash
docker compose logs --tail=150 backend analysis-worker scanner-worker frontend
```

Endereços locais:

- Frontend: http://localhost:5173
- API: http://localhost:8000
- Documentação interativa da API (somente desenvolvimento): http://localhost:8000/docs
- Health check: http://localhost:8000/api/health

Para encerrar:

```bash
docker compose down
```

Para apagar também os dados locais de desenvolvimento e começar do zero (ação destrutiva):

```bash
docker compose down -v
```

## 4. Roteiro de validação manual

Use um e-mail de teste e um projeto ZIP pequeno, sem credenciais, tokens, dados pessoais ou código de terceiros sem autorização.

- [ ] A página inicial carrega sem erros visíveis no console do navegador.
- [ ] O cadastro de uma conta de teste funciona.
- [ ] Login e logout funcionam; rotas privadas não ficam acessíveis sem sessão.
- [ ] Recuperação de senha e confirmação de e-mail apresentam o comportamento esperado no ambiente local. Sem SMTP configurado, o modo de desenvolvimento pode ativar contas automaticamente; isso não representa o fluxo real de produção.
- [ ] Ative MFA/TOTP, valide um código, saia e entre novamente; teste também um código de recuperação e confirme que ele não pode ser reutilizado.
- [ ] Envie um ZIP pequeno com código-fonte de teste autorizado.
- [ ] A API aceita o envio e cria um job; acompanhe o estado até concluir.
- [ ] O resultado, a cobertura da análise e a contagem de achados aparecem no painel/histórico da conta correta.
- [ ] O menu de perfil mostra o e-mail da conta e o status de verificação corretos; o atalho de segurança leva à seção de MFA e exclusão.
- [ ] Um usuário não consegue consultar o histórico ou os jobs de outra conta.
- [ ] Teste um ZIP inválido, corrompido ou acima do limite e confirme que a aplicação rejeita o envio sem travar.
- [ ] Cancele um job ainda na fila, se conseguir fazê-lo antes de o worker iniciá-lo.
- [ ] Confira que sair e entrar novamente não expõe dados de outra conta.
- [ ] Teste exclusão da conta somente com uma conta descartável, pois a operação remove os dados ativos dessa conta.

Não interprete achados heurísticos como prova definitiva de vulnerabilidade: podem existir falsos positivos e falsos negativos.

## 5. Executar os testes automatizados

Backend (na raiz):

```bash
docker compose exec backend python -m pytest -q
```

Frontend:

```bash
cd frontend
npm ci
npm run build
```

Para parar os serviços antes de remover os contêineres:

```bash
cd ..
docker compose down
```

Os workflows da PR também executam testes de backend, integração PostgreSQL, migrações, concorrência da fila, smoke test de backup/restauração criptografados, auditoria de dependências, varredura de segredos, build das imagens e validação do Compose de produção. A integração PostgreSQL do CI é importante: o Compose local padrão é um ambiente de desenvolvimento simplificado e usa SQLite por padrão, portanto não substitui os testes concorrentes em PostgreSQL.

## 6. Limites importantes do ambiente de teste

- Não exponha as portas locais à internet nem use o Compose de desenvolvimento como implantação pública.
- Não envie código de clientes, credenciais reais, chaves privadas ou arquivos confidenciais.
- SMTP real, HTTPS de domínio, firewall/egress do host, backups externos, alertas externos, logs centralizados e revisão LGPD dependem de infraestrutura e não são simulados por este roteiro.
- Website scanning e consultas online OSV permanecem desativados no perfil de produção até a política de saída de rede ser validada.
- Não habilite esses recursos em produção para “testar” sem uma autorização e uma política de egress revisadas.
- A integração automatizada não substitui o teste manual. Não faça uma implantação pública até o mantenedor concluir os testes locais, revisar os gates de produção e autorizar o lançamento.

## 7. Se encontrar um problema

Abra uma issue ou comente na PR relacionada à mudança que apresentou o problema, informando:

1. Sistema operacional e versão do Docker.
2. SHA retornado por `git rev-parse HEAD` e nome da branch testada.
3. Passos exatos para reproduzir.
4. Resultado esperado e resultado observado.
5. Logs relevantes de `docker compose logs`, removendo e mascarando tokens, cookies, e-mails reais, senhas e outros segredos.
6. Captura de tela, se ajudar a demonstrar o problema.

Não publique arquivos ZIP enviados, relatórios que contenham dados sensíveis ou valores de segredos.
