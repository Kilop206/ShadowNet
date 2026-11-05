# ShadowNet

Infraestrutura de túnel reverso para publicar serviços privados por um gateway
público. C++20, CMake e bibliotecas independentes. Licença MIT.

**Estado atual: Milestone 2 — Secure Tunnel.** Túnel WSS persistente com TLS 1.3,
mTLS obrigatório, autorização por fingerprint do certificado, validação do
hostname, heartbeat, reconexão com backoff/jitter e encerramento controlado.
O diagnóstico TCP local do M1 permanece separado e restrito a loopback.
**Ainda não há proxy HTTP, publicação ou registro remoto de serviços (M3).**

O objetivo futuro é impedir a exposição direta do IP da origem aos visitantes.
Isso não torna o dispositivo invisível na LAN, para o provedor ou para
administradores da infraestrutura. O gateway e seu operador conhecerão a origem.

## Compilar

Necessários: GCC 11+ ou Clang 14+ com biblioteca padrão C++20, CMake 3.24+,
Ninja, OpenSSL 3.0+ (headers/bibliotecas; CLI para testes) e Python 3.9+ para testes.
Windows usa MinGW-w64; MSVC não é necessário.
O bootstrap baixa Boost 1.90.0, yaml-cpp 0.9.0 e Catch2 3.8.1 com hashes SHA-256.
As versões são fixadas para repetibilidade; não são uma promessa de atualização
automática ou de ausência de vulnerabilidades.

```sh
cmake --preset bootstrap
cmake --build --preset bootstrap --parallel 4
ctest --preset bootstrap
```

Com Boost 1.74+, yaml-cpp 0.7+ e Catch2 3 instalados, usar o preset `dev`.
Para preencher o cache de arquivos previamente: `python scripts/fetch-deps.py`.
O CMake verifica os hashes mesmo quando usa o cache `.deps/`.

Alternativa validada no Windows quando o Ninja local não conclui a detecção:

```powershell
cmake --preset bootstrap -G 'MinGW Makefiles' -B build/mingw
cmake --build build/mingw --parallel 4
ctest --test-dir build/mingw --output-on-failure
```

Mantenha `C:\mingw64\bin` (ou o `bin` do seu MinGW) no PATH, inclusive ao executar
os binários. As DLLs do runtime GCC e OpenSSL não são empacotadas automaticamente.
Se necessário, informar `-DOPENSSL_ROOT_DIR=C:/caminho/openssl` na configuração.

## Demonstrar o túnel seguro

Gerar uma CA descartável e configurações funcionais (não sobrescreve diretórios):

```sh
python scripts/dev-certificates.py
./build/bootstrap/bin/shadow gateway start --config build/dev-pki/gateway.wss.yaml
```

Em outro terminal:

```sh
./build/bootstrap/bin/shadow config validate --type agent --config build/dev-pki/agent.wss.yaml
./build/bootstrap/bin/shadow agent start --config build/dev-pki/agent.wss.yaml
```

O Agent permanece em execução e registra `tunnel_established` e
`heartbeat_confirmed`. Parar e reiniciar o Gateway demonstra reconexão com
um ID de sessão novo. Ctrl+C solicita fechamento WebSocket/TLS limitado a 1 s
por fase de encerramento. No Windows, acrescentar `.exe` e usar o diretório
de build escolhido. Não usar a CA de laboratório em produção.

Configurações TLS são relativas ao arquivo YAML, validam credenciais antes de
conectar e não permitem desabilitar a verificação. Templates de deploy estão
em `config/agent.wss.yaml` e `config/gateway.wss.yaml`; exigem certificados reais
e fingerprint. O gerador mantém chaves em `build/`, fora do versionamento.

## Diagnóstico TCP local do M1

Na raiz do repositório, em um terminal:

```sh
./build/bootstrap/bin/shadow gateway start --config config/gateway.local.yaml
```

Em outro:

```sh
./build/bootstrap/bin/shadow config validate --type agent --config config/agent.local.yaml
./build/bootstrap/bin/shadow agent start --config config/agent.local.yaml
./build/bootstrap/bin/shadow version
```

No Windows, adicionar `.exe`; para o build alternativo, substituir
`build/bootstrap` por `build/mingw`. O Agent retorna zero e registra
`hello_acknowledged` somente após receber um ACK válido com seu nome. O Gateway
permanece em primeiro plano. Ctrl+C solicita encerramento; não há instalação
automática como serviço, daemonização ou persistência.

Os executáveis `shadow-agent --config FILE` e `shadow-gateway --config FILE`
também funcionam. `status`, `stop`, `service list` e `tunnel inspect` ainda não
existem; comandos não implementados retornam erro de uso (código 2).

## Organização

- `apps/`: Agent, Gateway e CLI, com parser de comandos compartilhado.
- `libs/`: core, security, configuration, protocol, networking e observability.
- `tests/`: unitários Catch2, integração com processos e plano de E2E HTTP.
- `config/`: exemplos locais válidos, sem certificados ou segredos.
- `docker/`: laboratório WSS/mTLS; publica 7443 apenas no loopback do host.
- `docs/`: arquitetura, protocolo, ameaças, instalação e roadmap.

O fluxo público planejado é Cliente HTTPS → Gateway → WSS/mTLS iniciado pelo
Agent → serviço autorizado em loopback. Somente o Gateway recebe conexões
do túnel. No M2, os serviços declarados são validados, mas não recebem tráfego.

## Documentação

- [Arquitetura e decisões](docs/architecture/overview.md)
- [Protocolo M1 e evolução](docs/protocols/local-v1.md)
- [Protocolo WSS v2](docs/protocols/wss-v2.md)
- [Modelo de ameaças](docs/security/threat-model.md)
- [Certificados e TLS](docs/security/tls.md)
- [Instalação](docs/deployment/installation.md) e [configuração](docs/configuration.md)
- [Deploy em VPS](docs/deployment/vps.md)
- [Testes e validação](docs/testing.md)
- [Troubleshooting](docs/troubleshooting.md), [limitações](docs/limitations.md) e [roadmap](docs/roadmap.md)
- [Relatório do M1](docs/milestones/m1.md)
- [Relatório do M2](docs/milestones/m2.md)
