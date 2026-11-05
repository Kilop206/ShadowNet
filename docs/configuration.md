# Configuração

## Recursos opcionais do M4 (somente WSS)

| Campo | Default | Intervalo |
|---|---:|---:|
| `agent.buffer_budget_bytes` | 67108864 (64 MiB) | 8 MiB–1 GiB |
| `agent.write_timeout_ms` | 10000 | 100–60000 |
| `gateway.tunnel_buffer_budget_bytes` | 134217728 (128 MiB) | 16 MiB–1 GiB |
| `gateway.write_timeout_ms` | 10000 | 100–60000 |
| `http.buffer_budget_bytes` | 67108864 (64 MiB) | 8 MiB–1 GiB |

São inteiros decimais, validados offline; unidades como `64MB` não são aceitas.
Configurações v3 do M3 continuam válidas com os defaults acima. Reservas,
arredondamento por requisição, espera, deadlines e custos fora do orçamento
estão descritos em [confiabilidade](architecture/reliability.md). Aumentar
`max_connections` ou `max_in_flight` isoladamente não aumenta o orçamento.

## Proxy HTTPS do M3

O protocolo do túnel é v3; atualizar Agent/Gateway juntos. O listener público
é opt-in: sem `http`, o Gateway só recebe túneis mTLS. Cada entrada de
`authorized_agents` pode ter uma lista `services` de até 32 pares `name` e
`hostname`. Nomes são únicos por agente; hostnames são únicos no Gateway.
Uma lista vazia não autoriza publicação. O registro pelo Agent é atômico e
precisa corresponder à política, sem transmitir IPs/portas locais.

```yaml
http:
  bind_host: 0.0.0.0
  port: 8443
  max_connections: 32
  max_in_flight: 16
  requests_per_second: 100
  request_timeout_ms: 5000
  security:
    certificate_file: certs/public-https.crt
    private_key_file: certs/public-https.key
```

Templates completos em `config/*.wss.yaml`; o gerador de laboratório fornece
política e credenciais reais para dois serviços.

| Campo adicional | Regra |
|---|---|
| `http.bind_host` | IP literal; bind público exige configuração explícita |
| `http.port` | 1–65535, diferente da porta WSS |
| `http.security` | Certificado/chave de servidor; sem CA de clientes ou opções de desabilitar TLS |
| `http.max_connections` | 1–256; inclui TLS, leitura, espera e resposta |
| `http.max_in_flight` | 1–64 pendências de origem no Gateway |
| `http.requests_per_second` | 1–10000, token bucket global com burst inicial igual ao valor |
| `http.request_timeout_ms` | 100–60000, prazo por fase: leitura, origem e escrita |
| `agent.max_in_flight` | Opcional, 1–64; padrão 16 conexões HTTP locais |
| `agent.backend_timeout_ms` | Opcional, 100–60000; padrão 3000, total para conexão/escrita/leitura local |

Corpos têm teto fixo de 1 MiB, headers 16 KiB/64 campos e target 8192 B.
Preferir prazo da origem menor que o do Gateway. Timeout envia CANCEL, mas
não desfaz efeitos da aplicação; nenhuma requisição é repetida após reconexão.

As seções abaixo descrevem os schemas herdados; a publicação antes planejada
para M3 agora está implementada com os limites acima.

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
