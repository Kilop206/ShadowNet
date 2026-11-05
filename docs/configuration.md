# Configuração

## Diagnóstico M1

Exemplos: `config/agent.local.yaml` e `config/gateway.local.yaml`. Um documento
YAML por arquivo, até 64 KiB. Chaves duplicadas, campos desconhecidos,
tipos incorretos e valores ausentes são erros. Não há expansão de ambiente,
leitura de segredos ou defaults implícitos de rede.

| Campo | Regra |
|---|---|
| `transport` | Obrigatório, exatamente `local_tcp` |
| `agent.name` | 1–64 caracteres em `a-z0-9_-` |
| `agent.gateway_host` | Literal `127.0.0.1` ou `::1` |
| `agent.port` | Inteiro decimal, 1–65535 |
| `agent.timeout_ms` | Inteiro, 100–60000; deadline total incluindo conexão |
| `services` | Opcional; sequência de até 32 serviços |
| `services[].name` | Identificador válido e único |
| `services[].hostname` | DNS ASCII minúsculo, até 253 caracteres; labels 1–63, sem `_`, sem wildcard ou ponto final |
| `services[].local_host` | Literal `127.0.0.1` ou `::1` |
| `services[].local_port` | Inteiro decimal, 1–65535 |
| `gateway.bind_host` | Literal `127.0.0.1` ou `::1` |
| `gateway.port` | Inteiro decimal, 1–65535 |
| `gateway.timeout_ms` | Inteiro, 100–60000 |
| `gateway.max_connections` | Inteiro, 1–1024 |

O hostname de serviço também deve ser único. Serviços são apenas validados;
nenhum serviço é publicado ou contatado pelo Agent no M1. Hostnames IDN devem
ser fornecidos em ASCII punycode; não há normalização automática. `localhost`
é rejeitado para eliminar resolução ambígua. Agent e Gateway devem usar a
mesma família de endereços. A disponibilidade de IPv6 depende do sistema.

```sh
shadow config validate --type agent --config config/agent.local.yaml
shadow config validate --type gateway --config config/gateway.local.yaml
```

A validação é offline e não reserva a porta ou prova a existência de um
servidor. Retornos: 0 = validação/handshake concluído ou Gateway encerrado
normalmente; 1 = configuração/rede/runtime falhou; 2 = comando inválido.
No WSS, `shadow config validate` também carrega e valida credenciais TLS antes
de qualquer conexão.

## Túnel WSS do M2

Usar `transport: wss`. Exemplos de schema em `config/*.wss.yaml`; eles contêm
caminhos e fingerprint a substituir. Configurações funcionais de laboratório
são geradas por `python scripts/dev-certificates.py` em `build/dev-pki/`.

| Campo | Regra WSS |
|---|---|
| `agent.gateway_host` | Hostname DNS ASCII minúsculo ou IP literal; verificado contra o certificado |
| `agent.reconnect.enabled` | Obrigatório: `true`/`false`, sem coerções `yes`/`1` |
| `agent.reconnect.initial_ms` | 100–60000 |
| `agent.reconnect.max_ms` | 100–300000, não inferior a `initial_ms` |
| `gateway.bind_host` | IP literal; permite interface pública apenas neste transporte autenticado |
| `gateway.heartbeat_interval_ms` | 100–60000; negociado em WELCOME |
| `gateway.heartbeat_timeout_ms` | 100–60000; negociado em WELCOME |
| `security.ca_file` | CA usada para validar o peer |
| `security.certificate_file` | Cadeia PEM local, leaf primeiro |
| `security.private_key_file` | Chave PEM correspondente; sem senha interativa |
| `authorized_agents` (Gateway) | 1–1024 pares de `name` e `certificate_sha256`, sem duplicação |
| `authorized_agents[].certificate_sha256` | SHA-256 do leaf DER, 64 hex minúsculos sem `:` |

`port`, `timeout_ms` e `max_connections` mantêm os limites do M1. O timeout
cobre conexão/DNS, TLS, upgrade e HELLO/WELCOME. A reconexão tem jitter e não
altera destinos configurados. Chaves precisam de 0600/0400 no Unix; no Windows,
o administrador deve restringir ACLs. Caminhos TLS são relativos ao YAML, não
ao diretório de execução. Ver [TLS](security/tls.md).

Os dois schemas rejeitam chaves desconhecidas, duplicadas e documentos YAML
múltiplos. Opções como `verify: false` e `tls: false` são inválidas. Os serviços
continuam restritos a loopback e apenas validados; registro/publicação é M3.
