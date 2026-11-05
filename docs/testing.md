# Testes

```sh
cmake --preset bootstrap
cmake --build --preset bootstrap --parallel 4
ctest --preset bootstrap
```

`unit.foundation` executa Catch2 com casos de framing, versões e tipos
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
analisar as nove unidades de produção com a toolchain local:

```powershell
./scripts/check-static.ps1 -BuildDir build/mingw -MingwRoot C:/mingw64
```

O script requer `rg` e `clang-tidy` no PATH. A filtragem de headers evita
diagnósticos de dependências vendorizadas; avisos de macros Catch2 nos testes
não fazem parte dessa verificação das unidades de produção.

O CI contém jobs Linux GCC/Clang, sanitizers e Windows MinGW; a definição de
workflow não comprova que esses jobs já rodaram. Resultados locais efetivamente
obtidos estão em `docs/milestones/m1.md`.

## Não coberto pelo M1

TLS/certificados e autenticação: M2. HTTP, métodos, cabeçalhos, corpos, roteamento
e isolamento de serviços em requisições: M3. Reconexão e interrupções em carga:
M2/M4. Não existe um teste HTTP E2E aprovado nesta versão. O Compose é uma
preparação de ambiente, não prova que o tráfego HTTP já atravessa o túnel.
