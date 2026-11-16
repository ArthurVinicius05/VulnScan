export type Language = 'pt-BR' | 'en'

const messages = {
  en: {
    selectBaseline: 'Use as baseline', baselineSelected: 'Baseline selected', compareWithBaseline: 'Compare', baselineSelectedHint: 'Choose another audit to compare against this baseline.', clearBaseline: 'Clear baseline', comparingAudits: 'Comparing audits…', comparisonTitle: 'Audit comparison', findingsAdded: 'New findings', findingsResolved: 'Resolved findings', findingsUnchanged: 'Unchanged findings', findingDetailsUnavailable: 'Finding-level details are unavailable for one or both audits.', scoreChange: 'Security score', scoreNotComparable: 'Security scores cannot be compared because one is missing or uses a different model version.', severityBreakdown: 'Severity breakdown', comparisonFailed: 'Could not compare audits.',
    unreadable: 'unreadable', language: 'Language', workspace: 'Workspace', overview: 'Overview', websiteScanner: 'Website Scanner',
    soon: 'SOON', settingsDescription: 'Manage account protection and workspace preferences.', preferences: 'Appearance and language', preferencesDescription: 'Choose how VulnScan looks and which language the interface uses.', appearance: 'Color theme', interfaceLanguage: 'Interface language', codeAnalyzer: 'Code Analyzer', auditHistory: 'Audit History', settings: 'Settings',
    account: 'Account', verifiedEmail: 'Verified email', unverifiedEmail: 'Email not verified',
    securitySettings: 'Security and settings', signOut: 'Sign out', securityWorkspace: 'SECURITY WORKSPACE',
    securityOverview: 'Security overview',
    overviewDescription: 'Find weaknesses before attackers do. Audit only codebases and websites you are authorized to test.',
    codeAnalyzerReady: 'CODE ANALYZER READY', auditsPerformed: 'Audits performed',
    savedAudits: 'Saved audits in this workspace', issuesDetected: 'Issues detected',
    currentArchive: 'Current archive', runFirstAudit: 'Run your first audit', securityScore: 'Security score',
    scoringNotImplemented: 'Scoring not implemented', scoreFromCurrentAnalysis: 'From the current analysis', scoreNeedsAnalysis: 'Run an analysis to calculate a score', scoreRating: 'Assessment', scoreStrong: 'Strong', scoreGood: 'Good', scoreNeedsAttention: 'Needs attention', scoreHighRisk: 'High risk', scoreModel: 'Model', scoreConfidence: 'Confidence', scoreLimited: 'Limited', scoreStandard: 'Standard', scoreCoverageCap: 'The score is capped because analysis coverage was incomplete.', scoreDisclaimer: 'This score is a prioritization indicator, not a security certification or proof that no vulnerabilities exist.', accountSecurity: 'Account security',
    accountSecurityDescription: 'Protect your account with an authenticator app and one-time recovery codes.',
    mfaEnabled: 'MFA ENABLED', mfaNotEnabled: 'MFA NOT ENABLED',
    mfaActive: 'Multi-factor authentication is active for this account.',
    mfaActivatedNotice: 'MFA enabled. Save your recovery codes in a secure place.',
    mfaDisabledNotice: 'MFA disabled. All active sessions were signed out.',
    accountDeletedNotice: 'Your account and active audit data were deleted.',
    accountCreatedNotice: 'Account created. Check your email to activate it before signing in.',
    cancelAnalysisFailed: 'Could not cancel the queued analysis.',
    authenticatorOrRecovery: 'Authenticator code or recovery code', codePlaceholder: '6-digit code or recovery code',
    disableMfa: 'Disable MFA and sign out all sessions', setupMfa: 'Set up MFA',
    addSecretManually: 'In your authenticator app, add an account manually with this secret:',
    provisioningUri: 'Provisioning URI', currentSixDigitCode: 'Enter the current 6-digit code',
    confirmEnableMfa: 'Confirm and enable MFA', recoveryCodesSave: 'Recovery codes — save them now',
    recoveryCodesOneTime: 'Each code can be used once. They will not be shown again.',
    deleteAccount: 'Delete account and audit data',
    deleteAccountWarning: 'This permanently removes your account, queued jobs and saved audit reports. Running analyses must finish first. Encrypted backups may retain copies until their configured retention period expires.',
    currentPassword: 'Current password', permanentlyDelete: 'Permanently delete account', cancel: 'Cancel',
    startAssessment: 'Start an assessment', chooseTarget: 'Choose a target type to begin your security review.',
    sourceAnalysis: 'Source code analysis', available: 'AVAILABLE',
    sourceDescription: 'Inspect project structure and run bounded static checks for common insecure coding patterns. Uploaded code is never executed.',
    dropZip: 'Drop your ZIP file here', browseZip: 'or click to browse · max 100 MB',
    fileTooLarge: 'The file exceeds the 100 MB limit.', waitingAnalysis: 'Waiting for analysis…',
    queuedStatus: 'Queued — waiting for an available worker…', runningStatus: 'Analysis running…',
    uploadingStatus: 'Uploading file…', cancelQueued: 'Cancel queued analysis',
    partialAnalysis: 'Analysis partially completed', failedAnalysis: 'Analysis failed',
    completedAnalysis: 'Analysis completed',
    partialCoverage: 'Partial coverage: some files or tools were limited, disabled or unavailable. Review scanner details before interpreting the absence of findings.',
    files: 'files', noStackMarkers: 'No known stack markers detected', potentialFindings: 'potential finding(s)',
    staticTools: 'Static tools', coverage: 'Analysis coverage', heuristics: 'Heuristics',
    overFileLimit: 'above per-file limit', overTotalLimit: 'above total limit', pythonScanners: 'Python scanners',
    dependencyManifests: 'Dependency manifests', dependencies: 'dependencies', inspectedPaths: 'Inspected paths',
    shown: 'shown', confidence: 'confidence', notVerified: 'not verified', verified: 'verified', evidenceLabel: 'Evidence', remediationLabel: 'Recommended remediation', findingsHeading: 'Findings', advisoryReference: 'Advisory reference',
    limitedCoverage: 'coverage limited',
    websiteDescription: 'Review HTTPS configuration, security headers, cookie attributes, and exposed information on authorized targets.',
    websiteNotEnabled: 'Website scanning is not enabled yet',
    websiteSafety: 'Active checks will require explicit authorization and safe scope controls.',
    auditHistoryTitle: 'Audit history', latestAssessments: 'Latest completed assessments saved in this workspace.',
    refresh: 'Refresh', noAudits: 'No saved audits yet.', viewReport: 'View report',
    loadingReport: 'Loading report…', findingsRecorded: 'finding(s) recorded',
    noFindingDetails: 'No finding details were stored in this record.', close: 'Close',
    builtSecurely: 'Built with security in mind.',
    uploadedCodeNotice: 'Uploaded code is treated as untrusted input and is never executed by this service.',
    authorizedTesting: 'FOR AUTHORIZED SECURITY TESTING',
    mfaLoginTitle: 'Two-step verification',
    mfaLoginDescription: 'Enter the code from your authenticator app or a recovery code.',
    mfaCode: 'MFA code', validating: 'Validating…', confirmCode: 'Confirm code', backToLogin: 'Back to login',
    loginDescription: 'Sign in to access your audits.', registerDescription: 'Create an account to keep your history private.',
    email: 'Email', password: 'Password', passwordMin: 'Password must contain at least 12 characters.',
    forgotPassword: 'Forgot password / confirm email', pleaseWait: 'Please wait…', signIn: 'Sign in',
    createAccount: 'Create account', noAccount: "Don't have an account? Sign up",
    haveAccount: 'Already have an account? Sign in', checkingSession: 'Checking session…',
    sessionExpired: 'Your session expired. Sign in again to continue.', unexpectedError: 'Unexpected error.',
    historyLoadFailed: 'Failed to load audit history.', reportLoadFailed: 'Failed to load report.',
    accountLoadFailed: 'Could not load account details.', authFailed: 'Authentication failed.',
    mfaFailed: 'Could not validate MFA.', mfaSetupFailed: 'Could not start MFA setup.',
    mfaEnableFailed: 'Could not enable MFA.', mfaDisableFailed: 'Could not disable MFA.',
    accountDeleteFailed: 'Could not delete account.',
    logoutUnconfirmed: 'The interface was cleared, but the server could not confirm session revocation. Check your connection and try signing in again.',
    queuedCancelled: 'Analysis cancelled; the temporary upload was removed.',
    analysisQueueFailed: 'Could not add the file to the queue.', analysisStatusFailed: 'Could not check analysis status.',
    analysisStillQueued: 'The analysis is still queued. Refresh the history in a moment to check its result.',
    analysisFailed: 'The analysis failed after the allowed attempts.', analysisCancelled: 'Analysis cancelled.',
    back: 'Back',
  },
  'pt-BR': {
    selectBaseline: 'Usar como base', baselineSelected: 'Base selecionada', compareWithBaseline: 'Comparar', baselineSelectedHint: 'Escolha outra auditoria para comparar com esta base.', clearBaseline: 'Limpar base', comparingAudits: 'Comparando auditorias…', comparisonTitle: 'Comparação de auditorias', findingsAdded: 'Novos achados', findingsResolved: 'Achados resolvidos', findingsUnchanged: 'Achados sem alteração', findingDetailsUnavailable: 'Os detalhes dos achados não estão disponíveis em uma ou nas duas auditorias.', scoreChange: 'Pontuação de segurança', scoreNotComparable: 'As pontuações não podem ser comparadas porque falta uma delas ou usam versões diferentes do modelo.', severityBreakdown: 'Detalhamento por severidade', comparisonFailed: 'Não foi possível comparar as auditorias.',
    unreadable: 'ilegíveis', language: 'Idioma', workspace: 'Área de trabalho', overview: 'Visão geral', websiteScanner: 'Scanner de sites',
    soon: 'EM BREVE', settingsDescription: 'Gerencie a proteção da conta e as preferências do ambiente.', preferences: 'Aparência e idioma', preferencesDescription: 'Escolha a aparência do VulnScan e o idioma da interface.', appearance: 'Tema de cores', interfaceLanguage: 'Idioma da interface', codeAnalyzer: 'Analisador de código', auditHistory: 'Histórico de auditorias',
    settings: 'Configurações', account: 'Conta', verifiedEmail: 'E-mail verificado',
    unverifiedEmail: 'E-mail não verificado', securitySettings: 'Segurança e configurações',
    signOut: 'Sair da conta', securityWorkspace: 'ESPAÇO DE SEGURANÇA',
    securityOverview: 'Visão geral de segurança',
    overviewDescription: 'Encontre fragilidades antes dos invasores. Analise apenas projetos e sites que você tem autorização para testar.',
    codeAnalyzerReady: 'ANALISADOR DE CÓDIGO PRONTO', auditsPerformed: 'Auditorias realizadas',
    savedAudits: 'Auditorias salvas nesta área de trabalho', issuesDetected: 'Problemas encontrados',
    currentArchive: 'Arquivo atual', runFirstAudit: 'Faça sua primeira auditoria',
    securityScore: 'Pontuação de segurança', scoringNotImplemented: 'Pontuação ainda não implementada', scoreFromCurrentAnalysis: 'Da análise atual', scoreNeedsAnalysis: 'Execute uma análise para calcular a pontuação', scoreRating: 'Avaliação', scoreStrong: 'Forte', scoreGood: 'Boa', scoreNeedsAttention: 'Precisa de atenção', scoreHighRisk: 'Risco elevado', scoreModel: 'Modelo', scoreConfidence: 'Confiança', scoreLimited: 'Limitada', scoreStandard: 'Padrão', scoreCoverageCap: 'A pontuação tem um limite porque a cobertura da análise foi incompleta.', scoreDisclaimer: 'Esta pontuação é um indicador de prioridade, não uma certificação de segurança nem prova de ausência de vulnerabilidades.',
    accountSecurity: 'Segurança da conta',
    accountSecurityDescription: 'Proteja sua conta com um aplicativo autenticador e códigos de recuperação de uso único.',
    mfaEnabled: 'MFA ATIVADO', mfaNotEnabled: 'MFA NÃO ATIVADO',
    mfaActive: 'A autenticação multifator está ativa nesta conta.',
    mfaActivatedNotice: 'MFA ativado. Salve os códigos de recuperação em local seguro.',
    mfaDisabledNotice: 'MFA desativado. Todas as sessões ativas foram encerradas.',
    accountDeletedNotice: 'Sua conta e os dados ativos de auditoria foram excluídos.',
    accountCreatedNotice: 'Conta criada. Verifique seu e-mail para ativá-la antes de entrar.',
    cancelAnalysisFailed: 'Não foi possível cancelar a análise na fila.',
    authenticatorOrRecovery: 'Código do autenticador ou de recuperação',
    codePlaceholder: 'Código de 6 dígitos ou código de recuperação',
    disableMfa: 'Desativar MFA e encerrar todas as sessões', setupMfa: 'Configurar MFA',
    addSecretManually: 'No aplicativo autenticador, adicione uma conta manualmente usando este segredo:',
    provisioningUri: 'URI de configuração', currentSixDigitCode: 'Digite o código atual de 6 dígitos',
    confirmEnableMfa: 'Confirmar e ativar MFA', recoveryCodesSave: 'Códigos de recuperação — salve agora',
    recoveryCodesOneTime: 'Cada código pode ser usado uma única vez. Eles não serão exibidos novamente.',
    deleteAccount: 'Excluir conta e dados de auditoria',
    deleteAccountWarning: 'Isso remove permanentemente sua conta, análises na fila e relatórios salvos. As análises em execução precisam terminar primeiro. Cópias criptografadas podem permanecer nos backups até o fim do período de retenção configurado.',
    currentPassword: 'Senha atual', permanentlyDelete: 'Excluir conta permanentemente', cancel: 'Cancelar',
    startAssessment: 'Iniciar uma análise', chooseTarget: 'Escolha o tipo de alvo para começar sua avaliação de segurança.',
    sourceAnalysis: 'Análise de código-fonte', available: 'DISPONÍVEL',
    sourceDescription: 'Inspecione a estrutura do projeto e execute verificações estáticas limitadas para padrões inseguros comuns. O código enviado nunca é executado.',
    dropZip: 'Solte seu arquivo ZIP aqui', browseZip: 'ou clique para procurar · máximo de 100 MB',
    fileTooLarge: 'O arquivo excede o limite de 100 MB.', waitingAnalysis: 'Aguardando análise…',
    queuedStatus: 'Na fila — aguardando um worker disponível…', runningStatus: 'Análise em execução…',
    uploadingStatus: 'Enviando arquivo…', cancelQueued: 'Cancelar análise na fila',
    partialAnalysis: 'Análise concluída parcialmente', failedAnalysis: 'Falha na análise',
    completedAnalysis: 'Análise concluída',
    partialCoverage: 'Cobertura parcial: alguns arquivos ou ferramentas foram limitados, desativados ou ficaram indisponíveis. Consulte os detalhes dos scanners antes de interpretar a ausência de achados.',
    files: 'arquivos', noStackMarkers: 'Nenhum marcador de tecnologia conhecido foi detectado',
    potentialFindings: 'achado(s) potencial(is)', staticTools: 'Ferramentas estáticas',
    coverage: 'Cobertura da análise', heuristics: 'Heurísticas', overFileLimit: 'acima do limite por arquivo',
    overTotalLimit: 'acima do limite total', pythonScanners: 'Scanners Python',
    dependencyManifests: 'Manifestos de dependências', dependencies: 'dependências',
    inspectedPaths: 'Caminhos inspecionados', shown: 'exibidos', confidence: 'confiança',
    notVerified: 'não verificado', verified: 'verificado', evidenceLabel: 'Evidência', remediationLabel: 'Correção recomendada', findingsHeading: 'Achados', advisoryReference: 'Referência do aviso', limitedCoverage: 'cobertura limitada',
    websiteDescription: 'Revise a configuração HTTPS, cabeçalhos de segurança, atributos de cookies e informações expostas em alvos autorizados.',
    websiteNotEnabled: 'A verificação de sites ainda não está ativada',
    websiteSafety: 'Verificações ativas exigirão autorização explícita e controles de escopo seguros.',
    auditHistoryTitle: 'Histórico de auditorias',
    latestAssessments: 'Avaliações concluídas mais recentes salvas nesta área de trabalho.',
    refresh: 'Atualizar', noAudits: 'Nenhuma auditoria salva ainda.', viewReport: 'Ver relatório',
    loadingReport: 'Carregando relatório…', findingsRecorded: 'achado(s) registrado(s)',
    noFindingDetails: 'Nenhum detalhe de achado foi armazenado neste registro.', close: 'Fechar',
    builtSecurely: 'Desenvolvido com segurança em mente.',
    uploadedCodeNotice: 'O código enviado é tratado como entrada não confiável e nunca é executado por este serviço.',
    authorizedTesting: 'SOMENTE TESTES AUTORIZADOS', mfaLoginTitle: 'Verificação em duas etapas',
    mfaLoginDescription: 'Digite o código do seu aplicativo autenticador ou um código de recuperação.',
    mfaCode: 'Código MFA', validating: 'Validando…', confirmCode: 'Confirmar código',
    backToLogin: 'Voltar ao login', loginDescription: 'Entre na sua conta para acessar suas auditorias.',
    registerDescription: 'Crie sua conta para manter seu histórico privado.', email: 'E-mail', password: 'Senha',
    passwordMin: 'A senha deve ter pelo menos 12 caracteres.',
    forgotPassword: 'Esqueci minha senha / confirmar e-mail', pleaseWait: 'Aguarde…', signIn: 'Entrar',
    createAccount: 'Criar conta', noAccount: 'Ainda não tem conta? Cadastre-se',
    haveAccount: 'Já tem conta? Entrar', checkingSession: 'Verificando sessão…',
    sessionExpired: 'Sua sessão expirou. Entre novamente para continuar.', unexpectedError: 'Erro inesperado.',
    historyLoadFailed: 'Falha ao carregar histórico.', reportLoadFailed: 'Falha ao carregar relatório.',
    accountLoadFailed: 'Não foi possível consultar os dados da conta.', authFailed: 'Falha na autenticação.',
    mfaFailed: 'Não foi possível validar MFA.', mfaSetupFailed: 'Não foi possível iniciar MFA.',
    mfaEnableFailed: 'Não foi possível ativar MFA.', mfaDisableFailed: 'Não foi possível desativar MFA.',
    accountDeleteFailed: 'Não foi possível excluir a conta.',
    logoutUnconfirmed: 'A interface foi limpa, mas não foi possível confirmar a revogação da sessão no servidor. Verifique sua conexão e tente entrar novamente.',
    queuedCancelled: 'Análise cancelada; o upload temporário foi removido.',
    analysisQueueFailed: 'Falha ao adicionar o arquivo à fila.', analysisStatusFailed: 'Falha ao consultar o status da análise.',
    analysisStillQueued: 'A análise continua na fila. Atualize o histórico em instantes para verificar o resultado.',
    analysisFailed: 'A análise falhou após as tentativas permitidas.', analysisCancelled: 'Análise cancelada.',
    back: 'Voltar',
  },
} as const

export type TranslationKey = keyof typeof messages.en

export function translate(language: Language, key: TranslationKey): string {
  return messages[language][key]
}

export function getInitialLanguage(): Language {
  try {
    const stored = window.localStorage.getItem('vulnscan-language')
    if (stored === 'pt-BR' || stored === 'en') return stored
  } catch {
    // Storage may be unavailable in private or restricted browsing contexts.
  }
  try {
    return navigator.language.toLowerCase().startsWith('pt') ? 'pt-BR' : 'en'
  } catch {
    return 'pt-BR'
  }
}


type FindingTextField = 'title' | 'evidence' | 'recommendation'

const findingTranslations: Record<string, Record<Language, Partial<Record<FindingTextField, string>>>> = {
  SECRET001: {
    en: { title: 'Possible hardcoded credential', recommendation: 'Move the value to a secret manager or environment variable, rotate it if real, and ensure it is not committed.' },
    'pt-BR': { title: 'Possível credencial fixa no código', recommendation: 'Mova o valor para um gerenciador de segredos ou variável de ambiente, faça a rotação se for real e garanta que ele não seja versionado.' },
  },
  PY001: {
    en: { title: 'Dynamic code execution', recommendation: 'Avoid evaluating dynamic input. Replace it with explicit parsing or a strict allowlist of permitted operations.' },
    'pt-BR': { title: 'Execução dinâmica de código', recommendation: 'Evite avaliar entradas dinâmicas. Substitua isso por análise explícita dos dados ou uma lista estrita de operações permitidas.' },
  },
  PY002: {
    en: { title: 'Subprocess with shell enabled', recommendation: 'Prefer argument arrays with shell=False. Validate arguments and never concatenate untrusted input into a command.' },
    'pt-BR': { title: 'Subprocess com execução de shell habilitada', recommendation: 'Prefira listas de argumentos com shell=False. Valide os argumentos e nunca concatene entradas não confiáveis em um comando.' },
  },
  PY003: {
    en: { title: 'Unsafe pickle deserialization', recommendation: 'Do not deserialize pickle data from untrusted sources. Use a non-executable data format such as JSON.' },
    'pt-BR': { title: 'Desserialização insegura de pickle', recommendation: 'Não desserialize dados pickle de fontes não confiáveis. Use um formato de dados não executável, como JSON.' },
  },
  PY004: {
    en: { title: 'Potentially unsafe YAML loading', recommendation: 'Use yaml.safe_load for untrusted YAML, and validate the resulting data against an expected schema.' },
    'pt-BR': { title: 'Carregamento potencialmente inseguro de YAML', recommendation: 'Use yaml.safe_load para YAML não confiável e valide os dados resultantes com um esquema esperado.' },
  },
  WEB001: {
    en: { title: 'Direct HTML injection sink', recommendation: 'Avoid assigning untrusted strings to HTML injection sinks. Prefer textContent or framework-safe rendering; sanitize only when HTML is required.' },
    'pt-BR': { title: 'Ponto de injeção direta de HTML', recommendation: 'Evite atribuir textos não confiáveis a pontos de injeção HTML. Prefira textContent ou a renderização segura do framework; sanitize somente quando HTML for necessário.' },
  },
  SQL001: {
    en: { title: 'Possible SQL built through string formatting', recommendation: 'Use parameterized queries or prepared statements. This pattern is heuristic and requires manual verification.' },
    'pt-BR': { title: 'Possível SQL construído por formatação de texto', recommendation: 'Use consultas parametrizadas ou instruções preparadas. Este padrão é heurístico e exige validação manual.' },
  },
  'WEB-HDR-001': {
    en: { title: 'HSTS header missing', evidence: 'The HTTPS response did not include Strict-Transport-Security.', recommendation: 'Configure the Strict-Transport-Security header on HTTPS responses after confirming all relevant subdomains support HTTPS.' },
    'pt-BR': { title: 'Cabeçalho HSTS ausente', evidence: 'A resposta HTTPS não incluiu Strict-Transport-Security.', recommendation: 'Configure o cabeçalho Strict-Transport-Security nas respostas HTTPS após confirmar que todos os subdomínios relevantes oferecem suporte a HTTPS.' },
  },
  'WEB-HDR-CONTENTSECURITYPOLICY': {
    en: { title: 'Content-Security-Policy header missing', evidence: 'The response did not include the content-security-policy header.', recommendation: 'A Content-Security-Policy header helps mitigate content injection.' },
    'pt-BR': { title: 'Cabeçalho Content-Security-Policy ausente', evidence: 'A resposta não incluiu o cabeçalho content-security-policy.', recommendation: 'O cabeçalho Content-Security-Policy ajuda a reduzir o risco de injeção de conteúdo.' },
  },
  'WEB-HDR-XCONTENTTYPEOPTIONS': {
    en: { title: 'X-Content-Type-Options header missing', evidence: 'The response did not include the x-content-type-options header.', recommendation: 'Set X-Content-Type-Options: nosniff.' },
    'pt-BR': { title: 'Cabeçalho X-Content-Type-Options ausente', evidence: 'A resposta não incluiu o cabeçalho x-content-type-options.', recommendation: 'Configure X-Content-Type-Options: nosniff.' },
  },
  'WEB-HDR-REFERRERPOLICY': {
    en: { title: 'Referrer-Policy header missing', evidence: 'The response did not include the referrer-policy header.', recommendation: 'Set an explicit Referrer-Policy.' },
    'pt-BR': { title: 'Cabeçalho Referrer-Policy ausente', evidence: 'A resposta não incluiu o cabeçalho referrer-policy.', recommendation: 'Defina uma política Referrer-Policy explícita.' },
  },
  'WEB-HDR-PERMISSIONSPOLICY': {
    en: { title: 'Permissions-Policy header missing', evidence: 'The response did not include the permissions-policy header.', recommendation: 'Consider restricting browser features with Permissions-Policy.' },
    'pt-BR': { title: 'Cabeçalho Permissions-Policy ausente', evidence: 'A resposta não incluiu o cabeçalho permissions-policy.', recommendation: 'Considere restringir recursos do navegador com Permissions-Policy.' },
  },
  'WEB-COOKIE-SECURE': {
    en: { title: 'Cookie missing Secure attribute', evidence: 'A response cookie does not declare the Secure attribute.', recommendation: 'Review whether this cookie should include the Secure attribute.' },
    'pt-BR': { title: 'Cookie sem o atributo Secure', evidence: 'Um cookie da resposta não declara o atributo Secure.', recommendation: 'Verifique se este cookie deve incluir o atributo Secure.' },
  },
  'WEB-COOKIE-HTTPONLY': {
    en: { title: 'Cookie missing HttpOnly attribute', evidence: 'A response cookie does not declare the HttpOnly attribute.', recommendation: 'Review whether this cookie should include the HttpOnly attribute.' },
    'pt-BR': { title: 'Cookie sem o atributo HttpOnly', evidence: 'Um cookie da resposta não declara o atributo HttpOnly.', recommendation: 'Verifique se este cookie deve incluir o atributo HttpOnly.' },
  },
  'WEB-COOKIE-SAMESITE': {
    en: { title: 'Cookie missing SameSite attribute', evidence: 'A response cookie does not declare the SameSite attribute.', recommendation: 'Review whether this cookie should include the SameSite attribute.' },
    'pt-BR': { title: 'Cookie sem o atributo SameSite', evidence: 'Um cookie da resposta não declara o atributo SameSite.', recommendation: 'Verifique se este cookie deve incluir o atributo SameSite.' },
  },
}

const backendTextTranslations: Record<string, Record<Language, string>> = {
  'Análise parcial: alguns scanners, arquivos ou achados foram limitados ou ficaram indisponíveis. Consulte coverage e scanner_tools antes de interpretar a ausência de achados. Os resultados não comprovam explorabilidade e exigem validação manual.': {
    en: 'Partial analysis: some scanners, files or findings were limited or unavailable. Review coverage and scanner_tools before interpreting the absence of findings. Results do not prove exploitability and require manual validation.',
    'pt-BR': 'Análise parcial: alguns scanners, arquivos ou achados foram limitados ou ficaram indisponíveis. Consulte a cobertura e os scanners antes de interpretar a ausência de achados. Os resultados não comprovam explorabilidade e exigem validação manual.',
  },
  'Achados heurísticos e resultados de ferramentas estáticas. Eles não comprovam explorabilidade e exigem validação manual.': {
    en: 'Heuristic findings and static-tool results. They do not prove exploitability and require manual validation.',
    'pt-BR': 'Achados heurísticos e resultados de ferramentas estáticas. Eles não comprovam explorabilidade e exigem validação manual.',
  },
  'Manifest inventory only; dependencies were not installed or checked against vulnerability databases.': {
    en: 'Manifest inventory only; dependencies were not installed or checked against vulnerability databases.',
    'pt-BR': 'Apenas inventário de manifestos; as dependências não foram instaladas nem verificadas em bases de dados de vulnerabilidades.',
  },
  'Dependency vulnerability matching is disabled by default; no outbound network access is granted to the scanner worker.': {
    en: 'Dependency vulnerability matching is disabled by default; the scanner worker has no outbound network access.',
    'pt-BR': 'A correlação de vulnerabilidades de dependências vem desativada por padrão; o worker do scanner não possui acesso à rede externa.',
  },
  'No eligible Python files found.': {
    en: 'No eligible Python files found.',
    'pt-BR': 'Nenhum arquivo Python elegível foi encontrado.',
  },
  'No safe Python files to scan.': {
    en: 'No safe Python files to scan.',
    'pt-BR': 'Nenhum arquivo Python seguro para análise foi encontrado.',
  },
  'Ative ENABLE_WEBSITE_SCAN e o perfil website-scan.': {
    en: 'Enable ENABLE_WEBSITE_SCAN and the website-scan profile.',
    'pt-BR': 'Ative ENABLE_WEBSITE_SCAN e o perfil website-scan.',
  },
}

const statusTranslations: Record<string, Record<Language, string>> = {
  completed: { en: 'completed', 'pt-BR': 'concluído' },
  skipped: { en: 'skipped', 'pt-BR': 'ignorado' },
  partial: { en: 'partial', 'pt-BR': 'parcial' },
  unavailable: { en: 'unavailable', 'pt-BR': 'indisponível' },
  disabled: { en: 'disabled', 'pt-BR': 'desativado' },
  timeout: { en: 'timed out', 'pt-BR': 'tempo esgotado' },
  error: { en: 'error', 'pt-BR': 'erro' },
  invalid_output: { en: 'invalid output', 'pt-BR': 'saída inválida' },
  output_limit: { en: 'output limit reached', 'pt-BR': 'limite de saída atingido' },
  inventoried: { en: 'inventoried', 'pt-BR': 'inventariado' },
  skipped_too_large: { en: 'skipped: file too large', 'pt-BR': 'ignorado: arquivo muito grande' },
  unreadable: { en: 'unreadable', 'pt-BR': 'não foi possível ler' },
  invalid_manifest: { en: 'invalid manifest', 'pt-BR': 'manifesto inválido' },
}

export function translateFindingText(language: Language, ruleId: string | undefined, field: FindingTextField, fallback: string | undefined): string {
  if (!fallback) return ''
  const translations = ruleId ? findingTranslations[ruleId] : undefined
  return translations?.[language]?.[field] ?? (ruleId?.startsWith('GITLEAKS_') ? {
    en: {
      title: 'Potential exposed secret',
      evidence: 'Secret value withheld and redacted from the report.',
      recommendation: 'Revoke or rotate the exposed credential and remove it from source history.',
    },
    'pt-BR': {
      title: 'Possível segredo exposto',
      evidence: 'O valor do segredo foi ocultado e removido do relatório.',
      recommendation: 'Revogue ou substitua a credencial exposta e remova-a do histórico do código.',
    },
  }[language][field] : fallback)
}

export function translateBackendText(language: Language, value: string | undefined): string {
  if (!value) return ''
  return backendTextTranslations[value]?.[language] ?? value
}

export function translateStatus(language: Language, value: string | undefined): string {
  if (!value) return ''
  return statusTranslations[value]?.[language] ?? value
}

export function translateSeverity(language: Language, value: string | undefined): string {
  if (!value) return ''
  const labels: Record<string, Record<Language, string>> = {
    critical: { en: 'critical', 'pt-BR': 'crítica' },
    high: { en: 'high', 'pt-BR': 'alta' },
    medium: { en: 'medium', 'pt-BR': 'média' },
    low: { en: 'low', 'pt-BR': 'baixa' },
    informational: { en: 'informational', 'pt-BR': 'informativa' },
    unknown: { en: 'unknown', 'pt-BR': 'desconhecida' },
  }
  return labels[value.toLowerCase()]?.[language] ?? value
}

export function translateAnalysisType(language: Language, value: string): string {
  const labels: Record<string, Record<Language, string>> = {
    static_source_analysis: { en: 'Source code analysis', 'pt-BR': 'Análise de código-fonte' },
    website_security_audit: { en: 'Website security audit', 'pt-BR': 'Auditoria de segurança de site' },
  }
  return labels[value]?.[language] ?? value.replaceAll('_', ' ')
}
