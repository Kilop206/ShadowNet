# Protocolo WSS v3 — Reverse Proxy MVP

Agent e Gateway devem ser atualizados juntos. O caminho é `/shadow/tunnel/v3`,
o subprotocolo é `shadownet.v3` e o byte de versão é 3. Não há downgrade para v2,
v1, TLS inferior ou texto claro. TLS 1.3/mTLS e a autorização por fingerprint
continuam obrigatórios no túnel; o listener HTTPS de visitantes é separado.

## Envelope e limites

Uma mensagem WebSocket binária contém um envelope completo. Cabeçalho de 12 B:
`SHDW` (4 B), versão (1 B), tipo (1 B), reservados zero (2 B), comprimento do
payload (uint32 big endian). Inteiros multi-byte abaixo usam big endian, sem
serializar estruturas nativas C++. Strings não têm terminador.

Antes de HELLO/WELCOME, o teto WebSocket é 268 B. Depois, o teto é 1.081.356 B:
1 MiB de corpo + 32 KiB para metadados/enquadramento + 12 B. Mensagens de
controle 1–5 continuam com payload de até 256 B. Não há compressão WebSocket.
Cada sessão tem no máximo 64 mensagens e 4 vezes o teto de frame em sua fila
de escrita, com apenas uma escrita ativa. Saturação de dados devolve erro ao
chamador; falha ao enfileirar controle crítico fecha a sessão.

| Tipo | Direção | Conteúdo |
|---|---|---|
| 1 HELLO | Agent → Gateway | Nome autorizado pelo certificado |
| 2 WELCOME | Gateway → Agent | ID de sessão aleatório de 128 bits e prazos do heartbeat; formato do M2 |
| 3 PING / 4 PONG | Agent → Gateway / retorno | Contador uint64 em 16 hex; sequência do M2 |
| 5 GOODBYE | Ambos | Literal `shutdown` |
| 6 REGISTER | Agent → Gateway | Lista de pares serviço/hostname |
| 7 REGISTERED | Gateway → Agent | Eco exato da lista aceita |
| 8 REQUEST | Gateway → Agent | ID, serviço e requisição HTTP |
| 9 RESPONSE | Agent → Gateway | Mesmo ID e resposta HTTP |
| 10 CANCEL | Gateway → Agent | ID uint64 não zero |

Registrar serviços é atômico: cada par precisa constar na allowlist do agente
autenticado no Gateway; hostname é globalmente único e uma sessão só registra
uma vez. Nenhuma rota é publicada parcialmente. O Agent só processa REQUEST
depois de confirmar REGISTERED. Agentes sem serviços podem manter heartbeat
sem registrar rotas. Reconectar remove rotas antigas e exige novo registro.

## Codificação dos payloads

`text` = uint16 de comprimento + bytes. `fields` = uint16 de quantidade +
pares `text(nome), text(valor)`, preservando campos repetidos como Set-Cookie.
Nomes de headers no protocolo são ASCII minúsculo e tokens HTTP válidos.
Valores não podem conter controles, CR, LF ou DEL; HTAB/obs-text são permitidos.
No máximo 64 campos, 128 B por nome, 8192 B por valor e 16 KiB agregados.
`body` = uint32 de comprimento + bytes arbitrários, até 1.048.576 B.

| Payload | Campos, em ordem |
|---|---|
| REGISTER / REGISTERED | uint16 quantidade (0–32), seguido de `text(serviço), text(hostname)` por entrada |
| REQUEST | uint64 ID, `text(serviço)`, `text(método)`, `text(target)`, fields, body |
| RESPONSE | uint64 ID, uint16 status, `text(reason)`, fields, body |
| CANCEL | uint64 ID |

Serviço tem 1–64 caracteres `a-z0-9_-`; hostname segue o schema DNS. Método
tem até 32 B; target tem até 8192 B e usa origin-form, ou `*` em OPTIONS.
Não se aceitam destinos absolutos, CONNECT ou TRACE. Responses finais usam
status 200–599 e reason ASCII de até 128 B; 204/304 não carregam corpo.
O parser exige consumo exato: truncamento, dados extras ou limites inválidos
encerram a sessão. Campos de IP/porta do destino local nunca são transmitidos.

## Correlação, cancelamento e falhas

IDs não zero crescem monotonicamente no Gateway e não são reutilizados no
processo. Cada pendência guarda a sessão responsável e um deadline. Uma
RESPONSE de outro agente fecha a sessão infratora e não satisfaz a pendência.
Respostas atrasadas para IDs já removidos são descartadas. O Agent também
exige IDs novos e mantém no máximo `max_in_flight` conexões locais.

Timeout no Gateway retorna 504, remove a pendência e envia CANCEL. O Agent
cancela o socket local e libera o slot. CANCEL atrasado é inofensivo. Isso não
desfaz efeitos que o serviço já produziu: POST e outros métodos nunca são
repetidos automaticamente após reconexão. Perda do túnel remove suas rotas e
resolve suas requisições em voo com 503; outros agentes permanecem isolados.

## Semântica HTTP do MVP

- O Gateway termina HTTPS com certificado de servidor, sem exigir certificado
  de visitante; sua porta WSS separada continua exigindo mTLS de agente.
- Um Host válido e único seleciona uma rota autorizada/registrada. DNS é
  normalizado para comparação; a autoridade original segue para o serviço.
- O Agent escolhe apenas IP literal de loopback/porta da configuração e confere
  que o Host da requisição corresponde ao serviço. Não resolve destinos do cliente.
- Beast interpreta framing HTTP; TE+CL e mensagens malformadas são rejeitados.
  Chunked e EOF de origem são decodificados; Content-Length é reconstruído.
  Transfer-Encoding adicional, como `gzip, chunked`, é rejeitado (400 na
  entrada, 502 na origem). Content-Encoding, inclusive gzip, é preservado.
- Headers hop-by-hop, inclusive os nomeados por Connection, são removidos nos
  dois sentidos. Content-Length só é preservado como metadado em HEAD/304.
  Set-Cookie e demais campos end-to-end repetidos são preservados.
- Forwarded, X-Forwarded-*, X-Real-IP e Via recebidos do visitante não são
  confiados. O Gateway define X-Forwarded-Proto/Host/For e seu Via pseudônimo.
  Detectar seu próprio Via retorna 508, evitando loops simples de proxy.
- HEAD envia somente headers e preserva o comprimento representacional. O
  Gateway atende Expect: 100-continue, rejeita outras expectativas com 417 e
  trata Max-Forwards em OPTIONS. Até quatro respostas 1xx da origem são
  consumidas antes da resposta final; 101/upgrade de aplicações não é suportado.
- Cada conexão pública transporta uma requisição/resposta e fecha. Há
  simultaneidade entre conexões; não há keep-alive/pipelining público nem streaming.

Erros: 400 malformado; 404 hostname desconhecido; 405 CONNECT/TRACE; 413 corpo
de cliente excessivo; 417 expectativa; 429 rate limit global; 431 headers;
501 upgrade; 502 falha/resposta inválida da origem; 503 agente/rota/slot
indisponível; 504 prazo; 505 versão HTTP pública diferente de 1.1; 508 loop.
Não se incluem endereços internos, payloads ou credenciais nos erros.

O limite de conexões inclui TLS e clientes ociosos. Há um prazo para
TLS/leitura, outro para a ida à origem e outro para escrita, além do teto de
1 s para encerramento TLS. Rate limiting usa token bucket global. O M4 tratará
orçamentos globais mais refinados, streaming/backpressure e ensaios de carga.
