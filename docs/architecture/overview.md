# Arquitetura

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
| Boost.Beast | HTTP/1.1 e WebSocket | Planejado para M2/M3, ainda não utilizado |
| OpenSSL 3 | TLS 1.3 e mTLS | Planejado para M2; sem criptografia própria |

O bootstrap fixa versões e hashes; o modo de pacotes instalados delega versões
ao operador. O build de produção futuro precisará de inventário/SBOM, política
de atualização e revisão de avisos de segurança. `core` permanece pequeno,
sem uma hierarquia genérica de sockets ou plugins sem consumidores concretos.

## Arquitetura alvo (ainda não implementada)

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

No M3, começar com mensagens HTTP completas limitadas e tabela de correlação
por sessão. Limitar requisições em voo antes de otimizar multiplexação.
Buffers sem limite, destinos fornecidos pelo cliente e confiança irrestrita em
`Host`, `Forwarded` ou `X-Forwarded-*` não são aceitáveis.
