# Arquitetura

## Proxy reverso M3

O Gateway tem listeners separados para HTTPS público e WSS/mTLS de agentes.
`HttpsServer` limita e processa conexões TLS/HTTP; `GatewayProxy` autoriza
registros e mantém rotas e pendências por ID/sessão. `SecureSession` transporta
envelopes v3. No Agent, `AgentProxy` aplica a allowlist e limita instâncias de
`LocalHttp`, cada uma conectada a um endpoint fixo de loopback.

```mermaid
sequenceDiagram
    participant C as Cliente HTTPS
    participant G as Gateway
    participant A as Agent privado
    participant S as Serviço local
    A->>G: WSS v3 com TLS 1.3/mTLS
    A->>G: REGISTER com nomes e hostnames
    G->>G: Autorizar política da identidade e publicar atomicamente
    G-->>A: REGISTERED
    C->>G: HTTP/1.1, Host autorizado
    G->>G: Validar framing, limpar headers, reservar ID e prazo
    G->>A: REQUEST com ID e nome de serviço
    A->>A: Conferir allowlist, Host e limite em voo
    A->>S: HTTP/1.1 para IP/porta configurados
    S-->>A: Resposta completa limitada
    A-->>G: RESPONSE com mesmo ID
    G->>G: Conferir sessão responsável e remover pendência
    G-->>C: Status, headers e corpo HTTPS
```

Respostas podem chegar fora de ordem. Só o ID na sessão responsável resolve a
pendência; pedidos de outros agentes permanecem isolados. Perda do túnel remove
rotas e resolve seus pedidos com 503. Timeout envia CANCEL e retorna 504;
respostas antigas são descartadas. Não há replay automático de HTTP.

O MVP usa mensagens completas com até 1 MiB de corpo e conexões públicas de
um request/response. Há simultaneidade entre conexões, sem streaming ou
keep-alive/pipelining público. Tetos cobrem conexões, pendências, frames,
filas, headers e prazos. O M4 refinará orçamento global e backpressure.
As seções de M1/M2 abaixo preservam as decisões anteriores; o fluxo de proxy
nelas planejado já funciona dentro dos limites do M3.

## Túnel seguro M2

O módulo `security` provisiona contextos OpenSSL com TLS 1.3, mTLS, verificação
X.509 estrita e identificação do peer por certificado. `configuration` valida
schema, arquivos e permissões; `protocol/tunnel` serializa mensagens v2.
`networking` separa a sessão SSL/WebSocket de seus controladores de Gateway e
Agent. O Gateway registra identidades ativas e rejeita duplicação; o Agent
controla reconexão com backoff e jitter. Ambos executam callbacks em uma thread
de I/O, com deadlines, filas limitadas e buffers por sessão.

```mermaid
sequenceDiagram
    participant A as Agent privado
    participant G as Gateway
    A->>G: TCP de saída + TLS 1.3/mTLS
    G->>G: Validar cadeia, EKU e fingerprint autorizado
    A->>A: Validar CA e hostname do Gateway
    A->>G: Upgrade /shadow/tunnel/v2, subprotocolo shadownet.v2
    A->>G: HELLO com nome autorizado
    G-->>A: WELCOME com sessão aleatória e prazos
    loop Enquanto conectado
        A->>G: PING com contador
        G-->>A: PONG com mesmo contador
    end
    Note over A,G: Falha provoca fechamento e nova conexão com backoff
```

OpenSSL 3.0+ e Beast já são dependências de runtime/build do M2. O transporte
TCP local abaixo continua sendo um diagnóstico explícito; nunca é fallback.
O proxy público e o registro de serviços permanecem planejados para M3.

## Escopo implementado no M1

O transporte de diagnóstico usa TCP sobre um endereço literal de loopback.
Não faz resolução DNS e não tem caminho para encaminhar requisições externas.
Cada conexão contém apenas HELLO e HELLO_ACK, com memória e tempo limitados.

```mermaid
flowchart LR
    CLI[Shadow CLI] --> Config[configuration: YAML estrito]
    Agent[Shadow Agent] --> Config
    Gateway[Shadow Gateway] --> Config
    CLI --> Network[networking: Boost.Asio]
    Agent --> Network
    Gateway --> Network
    Network --> Protocol[protocol: framing v1]
    Config --> Security[security: validadores]
    Protocol --> Security
    Network --> Logs[observability: logs limitados]
    Security --> Core[core: erro e versão]
    Logs --> Core
```

Cada executável utiliza um único `io_context`, executado em uma única thread.
Leituras, escritas, conexão e timers são assíncronos. Cada sessão possui seus
próprios buffers e estado; não há dados de payload globais. O Gateway limita
sessões ativas, além do backlog do sistema operacional. Sockets, timers e
buffers têm posse RAII; callbacks mantêm a sessão viva até a conclusão.
Cancelamento é idempotente e fecha sockets e timers. Uma falha de sessão
não derruba o listener; uma falha do listener encerra o processo com erro.

Os limites do protocolo precedem a alocação do corpo. O limite de conexões e o
deadline total do handshake limitam memória e retenção por clientes ociosos.
Isso é contenção inicial; não equivale ao controle de fluxo do proxy futuro.

## Decisões de dependências

| Dependência | Uso | Decisão |
|---|---|---|
| Boost.Asio | TCP e timers assíncronos | Portável; permite integrar Beast depois |
| yaml-cpp | Parsing YAML | Schema e autorização continuam no ShadowNet |
| Catch2 3 | Testes unitários | Integração com CMake/CTest, sem framework próprio |
| stdlib C++20 | RAII, erros, logging | Evita outra dependência para logs simples |
| Python 3 | Integração de processos/sockets e API de exemplo | Não é dependência do runtime C++ |
| Boost.Beast | Upgrade HTTP/1.1 e WebSocket | Utilizado no WSS do M2; proxy HTTP no M3 |
| OpenSSL 3.0+ | TLS 1.3 e mTLS | Utilizado no M2; sem criptografia própria |

O bootstrap fixa versões e hashes; o modo de pacotes instalados delega versões
ao operador. O build de produção futuro precisará de inventário/SBOM, política
de atualização e revisão de avisos de segurança. `core` permanece pequeno,
sem uma hierarquia genérica de sockets ou plugins sem consumidores concretos.

## Fluxo do proxy implementado no M3

```mermaid
flowchart LR
    Browser[Cliente externo] -->|HTTPS| GW[Gateway público]
    Agent[Agent na rede privada] -->|WSS TLS 1.3 / mTLS, saída| GW
    Agent -->|HTTP em loopback autorizado| API[API local]
    Agent -->|HTTP em loopback autorizado| Web[Aplicação local]
    GW --> Routes[Registro de agentes e rotas autorizadas]
```

```mermaid
sequenceDiagram
    participant C as Cliente
    participant G as Gateway
    participant A as Agent
    participant S as Serviço local
    A->>G: TLS 1.3 com mTLS, HELLO e registro autorizado
    C->>G: HTTPS Host api.example.com
    G->>G: Autorizar rota e reservar orçamento
    G->>A: Request com request_id e service_id
    A->>A: Verificar service_id na allowlist
    A->>S: HTTP/1.1 para destino fixo
    S-->>A: Status, cabeçalhos e corpo
    A-->>G: Response com o mesmo request_id
    G-->>C: Resposta HTTPS
```

O M3 utiliza mensagens HTTP completas limitadas e tabela de correlação por
sessão, com teto de requisições em voo antes de otimizar multiplexação.
Buffers sem limite, destinos fornecidos pelo cliente e confiança irrestrita em
`Host`, `Forwarded` ou `X-Forwarded-*` não são aceitáveis.
