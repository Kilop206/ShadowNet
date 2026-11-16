# Certificados TLS — M2 a M5

O [guia de produção](production.md) descreve políticas, CRL local, pin de
rotação e revalidação durante sessões. O formato do túnel continua v3.

No M3 há contextos separados: WSS v3 mantém mTLS; HTTPS público usa certificado
de servidor e não exige certificado cliente. Ambos requerem TLS 1.3. O leaf
público deve cobrir em SAN cada hostname publicado. Ele pode ser independente
da CA de agentes; compartilhar o leaf de laboratório é apenas conveniência.

As configurações geradas agora publicam API e website via v3. Usar novo
`--output` para preservar uma PKI anterior e atualizar ambos os binários.
O Compose aceita `SHADOW_PKI_DIR` para escolher outra geração.

WSS exige OpenSSL 3.0+, TLS 1.3 como mínimo e máximo e mTLS obrigatório.
O diagnóstico `local_tcp` continua rejeitando campos de credenciais e destinos
externos; não há fallback automático de WSS para esse transporte.

O Agent verifica cadeia X.509 estrita, validade, EKU `serverAuth` e identidade
DNS/IP do Gateway. DNS utiliza SNI; IP literal é verificado contra SAN de IP.
Wildcards parciais não são aceitos. O Gateway verifica cadeia, validade e EKU
`clientAuth`, exige certificado cliente e confere seu fingerprint SHA-256 na
allowlist. O HELLO precisa corresponder ao nome associado ao fingerprint.
Certificados não são autorizados pelo CN autodeclarado. A CA de confiança do
Gateway pode ser diferente da CA que emite seu próprio certificado público.

Sessões TLS não são retomadas; tickets e 0-RTT estão desabilitados. Profundidade
máxima de cadeia: quatro intermediários; lista de certificados TLS: 32 KiB.
Não há opção de ignorar cadeia, hostname, prazo de validade ou certificado cliente.

## Laboratório reproduzível

```sh
python scripts/dev-certificates.py
shadow config validate --type gateway --config build/dev-pki/gateway.wss.yaml
shadow gateway start --config build/dev-pki/gateway.wss.yaml
# Outro terminal:
shadow agent start --config build/dev-pki/agent.wss.yaml
```

O gerador usa OpenSSL CLI, EC P-256, CA descartável de dois dias, certificados
com SAN e EKU e identificadores de chave. Escreve configurações com fingerprint
real, sem editar templates ou trust stores. Recusa sobrescrever um diretório
existente; para outra PKI, usar `--output build/outra-pki`. Seu arquivo de
configuração OpenSSL é local, sem depender da instalação global. A CA privada
é apenas de laboratório, fica em `build/` e nunca é montada no Gateway/Agent
pelo Compose. Nunca versionar seus certificados privados ou chaves.

## Credenciais de deploy

Os caminhos `ca_file`, `certificate_file`, `private_key_file` são relativos ao
YAML. Arquivos precisam ser regulares, legíveis e ter 1 B–1 MiB. O runtime e
`shadow config validate` carregam os PEMs, verificam correspondência da chave,
validade e propósito do certificado local antes de abrir sockets.

Chaves têm teto de 64 KiB, precisam ser arquivos regulares e ter um único link.
No Unix, permissões de grupo/outros são rejeitadas. No Windows, proprietário e
DACL são inspecionados; usuário do processo, SYSTEM e Administradores são
confiados. Concessões de leitura/escrita/controle a outros SIDs são rejeitadas,
mesmo se houver ACE de negação (análise conservadora). ACEs não suportadas e
DACL nula falham fechadas. O runtime não altera ACLs existentes. O gerador,
invocado explicitamente, restringe somente as chaves descartáveis que cria.
PEM criptografado que exige senha interativa
não é suportado: usar arquivos restritos sob uma conta de serviço dedicada.

Calcular o fingerprint do **certificado leaf**, não de sua chave ou do arquivo
PEM, e remover `:`/converter a saída para minúsculas:

```sh
openssl x509 -in agent.crt -noout -fingerprint -sha256
```

O YAML exige exatamente 64 caracteres hexadecimais minúsculos, com nomes e
fingerprints únicos. `certificate_sha256_next` permite sobreposição temporária
de dois pins para a mesma identidade durante uma rotação com reinício controlado.
Nunca armazenar a chave da CA no Gateway ou na origem; manter CA offline ou usar
um emissor apropriado. Não importar a CA de laboratório na confiança do sistema.

## Limitações operacionais

CRL local configurada é obrigatória para a validação daquela cadeia, com
checagem de toda a cadeia. CRL ausente/expirada/inválida não é ignorada.
Sessões WSS revalidam cadeia peer, propósito, identidade e validade a cada
segundo; o leaf local também é revalidado, inclusive em HTTPS público.
Não há OCSP, hot reload, cofre ou rotação automática. Remover um pin/atualizar
CRL requer reinício; interromper o processo encerra sessões antigas. Não há
revogação instantânea a partir da simples alteração de um arquivo em disco.
