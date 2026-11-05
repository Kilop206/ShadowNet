# Testes

```sh
cmake --preset bootstrap
cmake --build --preset bootstrap --parallel 4
ctest --preset bootstrap
```

`unit.foundation` executa Catch2 com casos de framing v1/v3, versões e tipos
inválidos, limites de tamanho, identificadores, hostnames, YAML inválido,
campos desconhecidos/duplicados, allowlist e logging sem injeção de linhas.

`integration.local_transport` usa Python e processos reais dos três executáveis:
handshake, CLI, fragmentação TCP, 16 agentes simultâneos, mensagens malformadas,
conexões ociosas/truncadas, limite de conexões, recuperação, gateway ausente,
ACK incorreto, desconexão e timeout do Agent. Testa SIGTERM e fechamento de
sessão em POSIX. Esse caso é explicitamente ignorado no Windows, pois
`process.terminate()` não entrega um sinal POSIX.

Para ver cada cenário e contagens: `ctest --test-dir build/mingw -V`.
Os testes não exigem rede externa nem portas fixas; selecionam portas efêmeras
disponíveis e limpam processos e arquivos temporários. As fixtures de integração
ficam no diretório de build e herdam suas permissões, sem conter segredos.
A seleção seguida de bind
tem uma pequena janela de corrida; em caso de conflito o teste falha explicitamente.

## Sanitizers e análise estática

No Linux com GCC/Clang:

```sh
cmake --preset asan -DSHADOW_FETCH_DEPENDENCIES=ON
cmake --build --preset asan --parallel 4
ctest --preset asan
cmake --preset bootstrap -DSHADOW_CLANG_TIDY=ON
cmake --build --preset bootstrap --parallel 4
```

No Windows, o LLVM separado pode não descobrir os includes do MinGW. Para
analisar as dezessete unidades de produção com a toolchain local:

```powershell
./scripts/check-static.ps1 -BuildDir build/mingw -MingwRoot C:/mingw64
```

O script requer `rg` e `clang-tidy` no PATH. A filtragem de headers evita
diagnósticos de dependências vendorizadas; avisos de macros Catch2 nos testes
não fazem parte dessa verificação das unidades de produção.

O CI contém jobs Linux GCC/Clang, sanitizers e Windows MinGW; a definição de
workflow não comprova que esses jobs já rodaram. Resultados locais efetivamente
obtidos estão em `docs/milestones/m1.md`.

## Integração TLS/WSS do M2

`integration.secure_transport` gera CA e certificados descartáveis com o OpenSSL
CLI e executa Agent/Gateway reais, além de peers TLS/WebSocket independentes em
Python. Cobre mTLS, ausência de certificado, CA estrangeira, expiração, EKU,
SAN/hostname, pin negado, nome divergente, identidade duplicada, dois agentes,
TLS 1.2 rejeitado, upgrade inválido, frame inválido/texto/excessivo, heartbeat,
replay, falta de PONG, prazos, fila de conexão e reconexão após reinício.

Também valida backoff/jitter, pares de chaves, arquivos ausentes, autorização
malformada e permissões Unix. Um peer confirma fechamento WebSocket e TLS
`close_notify` em todas as plataformas; SIGTERM de processos permanece POSIX.
As fixtures nunca são versionadas e não alteram a confiança do sistema.
Esse teste não depende de bibliotecas Python externas nem de APIs comerciais.

## HTTP E2E do M3

`e2e.reverse_proxy` executa os binários reais e duas origens HTTP identificáveis.
Valida HTTPS → Gateway → WSS/mTLS → Agent → origem → cliente, com certificados
verificados. A suíte cobre métodos, target/query, headers, cookies repetidos,
corpos binários/gzip de até 1 MiB, HEAD, 204/304, chunked/EOF, 100-continue,
OPTIONS/Max-Forwards e respostas fora de ordem em 16 requisições concorrentes.

Peers independentes também tentam registrar hostname não autorizado, responder
pela sessão de outro agente, reutilizar resposta atrasada e escolher destinos
internos arbitrários. Há testes de framing ambíguo, limites de corpo/headers,
timeouts, CANCEL, perda do túnel, recadastro após reconexão, rate limit e slots.
As fixtures ficam no build, não instalam CA no sistema e limpam seus processos.

O Compose tem Gateway, Agent, API e website. Depois de iniciar as quatro
aplicações, `python scripts/check-demo.py --ca-file build/dev-pki-m3/ca.crt`
verifica os dois serviços por HTTPS com SAN/SNI reais, sem alterar DNS ou
desabilitar certificados. Isso comprova proxy entre contêineres; não comprova
NAT/CGNAT em redes físicas diferentes nem é benchmark de produção.

## Ainda não coberto

Ensaios sustentados de carga, orçamentos globais refinados e backpressure HTTP
são M4. Revogação, rotação automática e auditoria externa são M5. Resultados
realmente executados constam em `docs/milestones/m3.md`.
