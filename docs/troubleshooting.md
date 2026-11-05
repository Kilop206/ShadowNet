# Troubleshooting

## Proxy HTTPS M3

| Sintoma/status | Verificação |
|---|---|
| WSS não conecta após upgrade | M3 exige v3 em ambos os binários; caminho/subprotocolo v2 são rejeitados |
| Sem `services_registered` | Conferir pares nome/hostname em Agent e política do certificado no Gateway |
| HTTPS não inicia | Seção `http` explícita, porta distinta, arquivos/validade/EKU da chave/certificado público |
| Certificado falha no navegador/cliente | SAN precisa cobrir cada domínio publicado; nunca usar `-k` para contornar |
| 400 | Host ausente/duplicado, target não origin-form, framing/header inválido ou conexão nomeando framing crítico |
| 404 | Hostname não autorizado; conectar por IP exige enviar o Host público correto |
| 405 / 501 | CONNECT/TRACE e upgrade de aplicações não são suportados |
| 413 / 431 | Corpo acima de 1 MiB ou headers acima dos limites |
| 429 | Token bucket global atingiu `requests_per_second`; aguardar reposição |
| 502 | Origem recusou/fechou conexão, respondeu HTTP inválido ou excedeu limites |
| 503 | Agente desconectado, serviço não registrado, fila ou slots em voo saturados |
| 504 | Prazo na origem/Gateway; CANCEL não desfaz efeitos da aplicação |
| 508 | Via indica retorno ao mesmo intermediário; conferir loops de aplicação/proxy |
| SSE/streaming/keep-alive não funciona | O MVP usa mensagens completas e uma resposta por conexão pública |

Usar `scripts/check-demo.py` para verificar os dois serviços de laboratório.
Heartbeat não prova que uma aplicação local está saudável. Não registrar
corpos, cookies, Authorization ou query strings para investigar falhas.

## Túnel seguro M2

| Evento/sintoma | Verificação |
|---|---|
| OpenSSL não encontrado no CMake | Instalar headers/libs 3.0+ e configurar `OPENSSL_ROOT_DIR`; o bootstrap não baixa OpenSSL |
| DLL OpenSSL ausente no Windows | Adicionar o `bin` da mesma distribuição x64 ao PATH |
| `TLS credentials or context are invalid` | PEMs, validade, EKU e correspondência da chave; não há senha interativa |
| `TLS file is not a readable regular file` | Caminho relativo ao YAML e arquivo disponível |
| `private key permissions...` | Usar 0600/0400, proprietário do processo; não relaxar para contornar |
| `tls_handshake_failed` | CA, cadeia, SAN DNS/IP, validade, EKU e certificado cliente; nunca desabilitar verificação |
| `agent_not_authorized` | SHA-256 do leaf DER, em minúsculas sem `:`, no Gateway |
| `duplicate_agent_session` | A identidade já está conectada; a sessão existente é preservada |
| `invalid_tunnel_message` | Tipo/versão, HELLO divergente ou heartbeat fora de ordem |
| `websocket_upgrade_rejected` | Caminho, subprotocolo, Origin de navegador, tamanho ou corpo inválido |
| `heartbeat_timeout` | Peer sem PING/PONG, interrupção de rede ou prazo insuficiente |
| `reconnect_scheduled` | Esperado com reconexão habilitada; falhas repetidas aumentam o teto até `max_ms` |
| `shutdown_timeout` | Peer não concluiu o fechamento dentro do prazo; socket foi fechado |
| Certificados de laboratório já existem | Gerador recusa sobrescrita; escolher novo `--output` |

## Diagnóstico local M1

| Sintoma | Verificação |
|---|---|
| CMake não encontra Boost/YAML/Catch2 | Usar `bootstrap` ou instalar versões de desenvolvimento compatíveis |
| Download falha | Verificar proxy/HTTPS; preencher `.deps/` e preservar hashes |
| Ninja fica parado na detecção ABI | Usar diretório novo e gerador `MinGW Makefiles` no Windows |
| Executável Windows não inicia | Verificar DLLs/runtime MinGW no PATH e arquitetura x64 |
| `cannot open configuration file` | O caminho é relativo ao diretório de execução, não ao binário |
| `unknown configuration key` | Conferir `transport`: `local_tcp` rejeita campos WSS; todos os schemas rejeitam chaves desconhecidas |
| `connection_failed` | Iniciar Gateway primeiro; conferir porta e família IPv4/IPv6 |
| `handshake_timeout` | Peer ocioso/incompleto ou orçamento pequeno; verificar logs dos dois lados |
| `invalid_header` / `invalid_handshake` | Versão, tipo, comprimento ou identificador inválido |
| `connection_limit_reached` | Sessões simultâneas atingiram o teto; aguardar deadline ou ajustar limite |
| `startup_or_runtime_failure` | Conferir porta ocupada e permissões; diagnósticos externos não são impressos para evitar vazamento |
| Serviço configurado não responde por HTTP | Esperado no M1: só existe handshake, sem proxy |
| Docker `permission denied` no daemon | Executar Compose em uma sessão autorizada a acessar o daemon |

O processo é de primeiro plano. Ctrl+C solicita fechamento das sessões e do
listener. Não desabilitar firewall, validação TLS ou antivírus para
contornar falhas. Logs não incluem configuração bruta, corpos ou credenciais.
