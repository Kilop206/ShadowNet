# Configuração M1

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
No M2 haverá schema de TLS com validação dos arquivos antes de conectar.
