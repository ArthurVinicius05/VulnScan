# Roadmap VulnScan

## Implementado
- [x] API FastAPI e painel React/TypeScript
- [x] Inspeção segura de ZIP sem extração ou execução do código enviado
- [x] Análise heurística inicial e integrações opcionais Bandit, Ruff e Gitleaks
- [x] Inventário de dependências para múltiplos ecossistemas
- [x] OSV-Scanner opcional em worker separado
- [x] Auditoria passiva de sites com validação SSRF e worker isolado (opt-in)
- [x] Contas individuais, sessões em cookies HttpOnly, CSRF e histórico privado
- [x] Rate limiting Redis compartilhado e fallback local limitado
- [x] Verificação de e-mail via SMTP, tokens de uso único e expiração
- [x] Recuperação de senha com resposta anti-enumeração e revogação de sessões
- [x] Testes automatizados e CI para backend, frontend e imagens de containers

## Próxima fase — Operação segura e produto
1. Limites de uso por conta, quotas, limites de concorrência e escopo de auditoria.
2. Allowlist de saída aplicada por firewall/proxy e hardening de produção.
3. Relatórios exportáveis JSON/PDF e comparação de auditorias.
4. Integração OpenRouter opcional com chave do usuário, contexto mínimo e explicações fundamentadas em evidências.
5. MFA, administração de contas e política de convites.

## Critérios antes de produção
- Configurar HTTPS, APP_ENV=production, CORS_ORIGINS e cookies Secure.
- Configurar Redis monitorado e política noeviction.
- Configurar SMTP e validar entregabilidade, SPF, DKIM e DMARC.
- Usar PostgreSQL gerenciado com backups e restauração testada.
- Aplicar egress allowlist para workers website/OSV por firewall/proxy.
- Adicionar monitoramento, logs sem segredos, alertas, retenção e plano de resposta.
- Executar revisão de segurança independente e testes de integração em ambiente isolado.