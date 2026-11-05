# Testes

```sh
cmake --preset bootstrap
cmake --build --preset bootstrap --parallel 4
ctest --preset bootstrap
```

`unit.foundation` executa Catch2 com casos de framing v1/v2, versões e tipos
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
analisar as treze unidades de produção com a toolchain local:

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

## Ainda não coberto

HTTP, métodos, cabeçalhos, corpos, roteamento
e isolamento de serviços em requisições: M3. Interrupções em carga de proxy e
backpressure HTTP: M4. Não existe teste HTTP E2E aprovado nesta versão; o Compose
valida WSS/mTLS entre contêineres e mantém uma API preparatória para o M3.
