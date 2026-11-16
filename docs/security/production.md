# Controles e operação de segurança — M5

O M5 acrescenta defesa em profundidade ao túnel TLS 1.3/mTLS v3. Este é um
guia dos controles implementados e da revisão interna; não é certificação,
auditoria externa ou promessa de produção sem riscos.

## Autorização HTTP por serviço

Gateway e Agent podem definir `access` em cada serviço. As políticas são
independentes: uma requisição precisa passar pelas duas. A associação de
hostname/serviço à identidade do certificado continua obrigatória.

```yaml
# Dentro de authorized_agents[].services[] (Gateway)
- name: api
  hostname: api.example.com
  access:
    methods: [GET, HEAD, POST]
    path_prefixes: [/api, /health]

# Dentro de services[] (Agent)
- name: api
  hostname: api.example.com
  local_host: 127.0.0.1
  local_port: 8080
  access:
    methods: [GET, HEAD]
    path_prefixes: [/api, /health]
```

Cada lista aceita 1–16 entradas únicas. Métodos são letras ASCII maiúsculas,
até 32 caracteres; CONNECT/TRACE nunca são permitidos. Prefixos têm até
2048 bytes, começam com `/`, não têm query/escape e não terminam com `/`,
exceto a raiz. `/api` permite `/api` e `/api/x`, mas não `/apix`. Comparação
é sensível a maiúsculas. A query é preservada e não participa da autorização.

Na ausência de `access`, o default permite GET, HEAD, POST, PUT, PATCH, DELETE
e OPTIONS sob `/`. Métodos adicionais exigem configuração explícita. A regra
é sobre encaminhamento: OPTIONS com Max-Forwards=0 pode ser respondido pelo
próprio Gateway. Isso não autentica usuários da aplicação nem substitui suas
permissões, tokens, proteção de sessão ou validação de entrada.

O parser rejeita barras duplicadas, backslash, segmentos `.`/`..`, `;`, controles,
escape inválido e percent-encoding de caracteres que não sejam unreserved
ASCII no path (incluindo `/`, `\\`, `%` e Unicode). Escapes unreserved são
decodificados uma vez para comparar a política; o target original segue para
a origem. Reescritas e aliases internos da aplicação devem ser revisados pelo
administrador. Não há promessa de equivalência com normalizações arbitrárias
de todos os frameworks. Caminhos antes aceitos pelo M4 podem retornar 400;
revisar compatibilidade antes de atualizar ambos os binários.

## Revogação e validade

No bloco `security` WSS, `crl_file` opcional aponta para um PEM de CRLs locais.
O caminho é relativo ao YAML, com o mesmo limite de 1 MiB dos demais PEMs
públicos. Quando configurado, OpenSSL exige CRL apropriada e válida em toda
a cadeia; fornecer as CRLs de todos os emissores necessários. Uma CRL estrangeira
ou de assinatura inválida não substitui a lista do emissor correto. O startup
rejeita lista ausente, malformada, sem CRLs ou fora de validade. Assinatura e
pertinência são verificadas durante a validação da cadeia, sem fallback.
O carregador importa somente CRLs: certificados misturados nesse arquivo não
adicionam novas CAs ao trust store. Essa fronteira tem teste com Gateway
forjado por uma CA estrangeira incluída no próprio bundle.

```yaml
security:
  ca_file: certs/agents-ca.crt
  certificate_file: certs/gateway.crt
  private_key_file: certs/gateway.key
  crl_file: certs/agents-ca.crl.pem
```

Sem `crl_file`, continuam obrigatórios mTLS, cadeia estrita, propósito,
hostname do Gateway e pin do Agent; não há consulta de revogação externa.
Nesse modo, revogar acesso requer remover o pin e reiniciar o Gateway.
Escolher conscientemente a política de revogação do deploy; CRL não é baixada
automaticamente e deve ser mantida pelo operador da CA.

Sessões WSS revalidam a cadeia peer com o mesmo trust store, propósito e
parâmetros de identidade a cada segundo, além da validade do leaf local.
Expiração de certificado ou CRL encerra sessões existentes e remove rotas.
HTTPS público revalida o leaf local. A precisão depende do relógio e do
agendamento do SO. Atualizar o arquivo CRL não altera contextos já carregados:
é necessário reiniciar Agent/Gateway conforme o trust store afetado.

A implementação usa [flags oficiais de validação OpenSSL](https://docs.openssl.org/3.0/man3/X509_VERIFY_PARAM_set_flags/),
sem algoritmos criptográficos próprios ou callback que ignore erros.

## Rotação administrativa

1. Emitir um novo leaf com `clientAuth`, CA correta, validade e chave privada
   nova em diretório protegido; manter a chave da CA fora dos hosts do túnel.
2. Validar o material com `shadow config validate`. Calcular SHA-256 do leaf
   DER por `openssl x509 -in novo.crt -noout -fingerprint -sha256` e converter
   para 64 hex minúsculos sem `:`.
3. Adicionar `certificate_sha256_next` à identidade existente no Gateway e
   reiniciar o Gateway. Não criar uma segunda identidade com os mesmos pins.
4. Atualizar certificado/chave no Agent e reiniciá-lo. HELLO/nome e serviços
   permanecem os mesmos; somente uma sessão por identidade é aceita.
5. Promover o novo pin a `certificate_sha256`, remover o pin de sobreposição
   e reiniciar o Gateway. Revogar o certificado anterior na CA e distribuir
   a nova CRL aos validadores, reiniciando os processos afetados.

A sobreposição é temporária e deliberada; os dois certificados têm a mesma
autoridade durante esse intervalo. O procedimento interrompe conexões e não
promete rotação sem downtime. Fazer rollback somente para material ainda
confiável, nunca para certificado comprometido/revogado.

## Chaves e fronteira local

Chaves: arquivo regular de 1 B–64 KiB, sem symlink final e com um único hard
link. Unix rejeita permissões de grupo/outros; Windows consulta proprietário
e DACL usando APIs do SO, permitindo usuário do processo, SYSTEM e grupo de
Administradores. Concessões sensíveis a outros SIDs, DACL nula e tipos de ACE
não suportados falham fechados. ACLs complexas podem ser rejeitadas mesmo
quando uma negação efetiva reduziria o acesso: não são simplificadas pelo runtime.

O software não muda ACL, firewall ou roteador durante sua execução. O gerador
de laboratório restringe apenas suas novas chaves via chmod/icacls ao ser
invocado explicitamente. Diretórios pais, conta de serviço, backups e arquivos
de configuração também precisam ser protegidos. A checagem por caminho e o
carregamento OpenSSL não são um snapshot atômico: um administrador/local
privilegiado ou quem consiga substituir diretórios continua fora dessa proteção.

## Logging e revisão interna

Logs registram motivos fixos como `http_policy_denied`, `tls_handshake_failed`
e `credential_validation_failed`, sem corpo, Authorization, cookies, query,
chaves ou configuração bruta. Campos são sanitizados/truncados a 512 caracteres.
Há limite global de 200 eventos/s com burst de 400; eventos excedentes são
suprimidos e uma emissão posterior informa `events_suppressed count=N`.
O aviso de supressão pode adicionar uma linha à de evento liberado. Não há
persistência, rotação, assinatura ou garantia de registrar todos os acessos.

| Área revisada | Controle e evidência automatizada |
|---|---|
| Identidade e rotação | mTLS + pin atual/próximo + HELLO; rotação não muda identidade |
| Autorização | Políticas independentes, prefixos por segmento, 403 antes de origem |
| Canonicalização | Casos de traversal/encoding e corpus determinístico de 5000 mutações |
| Credenciais | CRL correta/revogada/expirada/estrangeira/malformada e expiração ativa |
| Chave local | Restrição Unix e DACL Windows, com teste negativo de leitura pública |
| Amplificação de logs | Burst de 5000 eventos em teste; ausência de segredos em negativa HTTP |
| Recursos e isolamento | Regressões M1–M4: buffers, timeouts, sessões/IDs, perda e recuperação |

O corpus de mutação é smoke testing, não campanha contínua de fuzzing. O CI
também executa ASan/UBSan e clang-tidy. Revogar aplicação/usuário HTTP continua
sendo responsabilidade da aplicação. Produção exige atualização de dependências,
operação da CA, supervisão, backup seguro e avaliação das limitações do deploy.
