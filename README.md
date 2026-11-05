# ShadowNet

Infraestrutura de túnel reverso para publicar serviços privados por um gateway
público. C++20, CMake e bibliotecas independentes. Licença MIT.

**Estado atual: Milestone 1 — Foundation.** Agent, Gateway e CLI implementados,
com configuração YAML, logging e handshake TCP assíncrono **somente em loopback**.
O Agent conecta, recebe uma confirmação e encerra. Não há TLS, autenticação,
túnel persistente, registro remoto de serviços nem proxy HTTP nesta versão.
Não utilizar o M1 para publicar serviços na internet.

O objetivo futuro é impedir a exposição direta do IP da origem aos visitantes.
Isso não torna o dispositivo invisível na LAN, para o provedor ou para
administradores da infraestrutura. O gateway e seu operador conhecerão a origem.

## Compilar

Necessários: GCC 11+ ou Clang 14+ com biblioteca padrão C++20, CMake 3.24+,
Ninja e Python 3.9+ para testes. Windows usa MinGW-w64; MSVC não é necessário.
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
os binários. As DLLs do runtime GCC não são empacotadas automaticamente.

## Demonstrar a comunicação local

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
- `docker/`: ambiente local preparatório; não publica portas no M1.
- `docs/`: arquitetura, protocolo, ameaças, instalação e roadmap.

O fluxo público planejado é Cliente HTTPS → Gateway → WSS/mTLS iniciado pelo
Agent → serviço autorizado em loopback. Somente o Gateway receberá conexões
públicas. O M1 não encaminha tráfego aos serviços declarados na configuração.

## Documentação

- [Arquitetura e decisões](docs/architecture/overview.md)
- [Protocolo M1 e evolução](docs/protocols/local-v1.md)
- [Modelo de ameaças](docs/security/threat-model.md)
- [Certificados e TLS (planejado)](docs/security/tls.md)
- [Instalação](docs/deployment/installation.md) e [configuração](docs/configuration.md)
- [Deploy em VPS (bloqueado até M2/M3)](docs/deployment/vps.md)
- [Testes e validação](docs/testing.md)
- [Troubleshooting](docs/troubleshooting.md), [limitações](docs/limitations.md) e [roadmap](docs/roadmap.md)
- [Relatório do M1](docs/milestones/m1.md)
