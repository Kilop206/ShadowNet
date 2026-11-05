# ShadowNet

Infraestrutura de túnel reverso para publicar serviços privados por um gateway
público. C++20, CMake e bibliotecas independentes. Licença MIT.

**Estado atual: Milestone 4 — Reliability, versão 0.4.0.** O Gateway
recebe HTTPS, autoriza hostnames e encaminha HTTP/1.1 por WSS/TLS 1.3/mTLS até
serviços fixos no Agent. Há registro de serviços, IDs de requisição, isolamento
concorrente, heartbeat, reconexão, deadlines e limites de recursos.
O M4 adiciona admissão por orçamento de buffers, espera FIFO antes de ler
corpos HTTP, respostas adiadas sob backpressure e prazo de escrita no túnel.
O diagnóstico TCP local do M1 permanece separado e restrito a loopback.

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

## Publicar duas aplicações no laboratório

Gerar uma CA descartável e configurações funcionais (não sobrescreve diretórios):

```sh
python scripts/dev-certificates.py --output build/dev-pki-m3
./build/bootstrap/bin/shadow gateway start --config build/dev-pki-m3/gateway.wss.yaml
```

Em outro terminal:

```sh
./build/bootstrap/bin/shadow config validate --type agent --config build/dev-pki-m3/agent.wss.yaml
./build/bootstrap/bin/shadow agent start --config build/dev-pki-m3/agent.wss.yaml
```

Iniciar os serviços locais em outros dois terminais:

```sh
python examples/simple-api/server.py
python examples/website/server.py
```

Verificar o fluxo público completo, sem alterar DNS ou confiança do sistema:

```sh
python scripts/check-demo.py --ca-file build/dev-pki-m3/ca.crt
```

O teste acessa `api.example.test` e `app.example.test` por HTTPS em 8443,
verifica SAN/SNI e conteúdo dos dois serviços. O Agent registra
`tunnel_established`, `services_registered` e `heartbeat_confirmed`.
Parar e reiniciar o Gateway demonstra reconexão e novo registro dos serviços.
Ctrl+C solicita fechamento WebSocket/TLS limitado a 1 s
por fase de encerramento. No Windows, acrescentar `.exe` e usar o diretório
de build escolhido. Não usar a CA de laboratório em produção.

As configurações geradas publicam API em 8080 e website em 3000, ambos em
loopback. O Gateway expõe HTTPS em 8443 e WSS/mTLS em 7443; somente o Gateway
precisa de conexões de entrada no deploy remoto. Configurações TLS são relativas ao YAML e validam credenciais antes de
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
- `tests/`: unitários Catch2, integração, HTTP E2E e carga com falhas reais.
- `config/`: exemplos locais válidos, sem certificados ou segredos.
- `docker/`: Gateway, Agent, API e website; publica 7443/8443 no loopback do host.
- `docs/`: arquitetura, protocolo, ameaças, instalação e roadmap.

O fluxo implementado é Cliente HTTPS → Gateway → WSS/mTLS iniciado pelo Agent
→ serviço autorizado em loopback → resposta ao cliente. Métodos, cabeçalhos,
status e corpos binários são preservados dentro dos limites: corpo de 1 MiB,
headers de 16 KiB e requisições em voo limitadas. Não há streaming, WebSocket
de aplicações, CONNECT/TRACE, HTTP/2 ou keep-alive público nesta versão.
O protocolo do túnel é v3; atualizar Agent e Gateway juntos ao migrar do M2.

## Documentação

- [Arquitetura e decisões](docs/architecture/overview.md)
- [Protocolo M1 e evolução](docs/protocols/local-v1.md)
- [Protocolo WSS v2](docs/protocols/wss-v2.md)
- [Protocolo de proxy v3](docs/protocols/proxy-v3.md)
- [Modelo de ameaças](docs/security/threat-model.md)
- [Certificados e TLS](docs/security/tls.md)
- [Instalação](docs/deployment/installation.md) e [configuração](docs/configuration.md)
- [Deploy em VPS](docs/deployment/vps.md)
- [Testes e validação](docs/testing.md)
- [Troubleshooting](docs/troubleshooting.md), [limitações](docs/limitations.md) e [roadmap](docs/roadmap.md)
- [Relatório do M1](docs/milestones/m1.md)
- [Relatório do M2](docs/milestones/m2.md)
- [Relatório do M3](docs/milestones/m3.md)
- [Controle de recursos e confiabilidade](docs/architecture/reliability.md)
- [Relatório do M4](docs/milestones/m4.md)
