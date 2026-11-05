# Troubleshooting

| Sintoma | Verificação |
|---|---|
| CMake não encontra Boost/YAML/Catch2 | Usar `bootstrap` ou instalar versões de desenvolvimento compatíveis |
| Download falha | Verificar proxy/HTTPS; preencher `.deps/` e preservar hashes |
| Ninja fica parado na detecção ABI | Usar diretório novo e gerador `MinGW Makefiles` no Windows |
| Executável Windows não inicia | Verificar DLLs/runtime MinGW no PATH e arquitetura x64 |
| `cannot open configuration file` | O caminho é relativo ao diretório de execução, não ao binário |
| `unknown configuration key` | Somente schema M1 é aceito; campos TLS e reconexão ainda não existem |
| `connection_failed` | Iniciar Gateway primeiro; conferir porta e família IPv4/IPv6 |
| `handshake_timeout` | Peer ocioso/incompleto ou orçamento pequeno; verificar logs dos dois lados |
| `invalid_header` / `invalid_handshake` | Versão, tipo, comprimento ou identificador inválido |
| `connection_limit_reached` | Sessões simultâneas atingiram o teto; aguardar deadline ou ajustar limite |
| `startup_or_runtime_failure` | Conferir porta ocupada e permissões; diagnósticos externos não são impressos para evitar vazamento |
| Serviço configurado não responde por HTTP | Esperado no M1: só existe handshake, sem proxy |
| Docker `permission denied` no daemon | Executar Compose em uma sessão autorizada a acessar o daemon |

O processo é de primeiro plano. Ctrl+C solicita fechamento das sessões e do
listener. Não desabilitar firewall, validação TLS futura ou antivírus para
contornar falhas. Logs não incluem configuração bruta, corpos ou credenciais.
