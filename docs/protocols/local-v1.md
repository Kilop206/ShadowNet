# Protocolo de diagnóstico local v1 (implementado)

TCP em loopback, sem TLS. Não é protocolo de produção nem autenticação.
Não reutilizar diretamente esse listener em uma interface pública.

| Offset | Tamanho | Campo |
|---|---|---|
| 0 | 4 bytes | ASCII `SHDW` |
| 4 | 1 byte | Versão: `1` |
| 5 | 1 byte | Tipo: `1` HELLO ou `2` HELLO_ACK |
| 6 | 2 bytes | Reservado: ambos zero |
| 8 | 4 bytes | Tamanho do corpo, uint32 big endian |
| 12 | N bytes | Nome ASCII do Agent, sem terminador |

O tamanho estrutural permitido é 1–256 bytes. O corpo precisa ser um identificador
de 1–64 caracteres, contendo apenas `a-z`, `0-9`, `_`, `-`.
Não há compressão, JSON, serialização de estruturas nativas ou alinhamento ABI.

Estados do Agent: conectar → escrever HELLO → ler header/body de HELLO_ACK →
comparar nome com o enviado → fechar → retornar zero. Qualquer falha retorna 1.
Estados do Gateway por sessão: ler HELLO → validar → escrever HELLO_ACK com
o mesmo nome → fechar. Tipos fora de ordem são rejeitados. Um ACK não comprova
identidade, apenas o funcionamento do caminho de comunicação.

`async_read`/`async_write` tratam leituras/escritas parciais. Um único deadline
cobre todo o handshake, incluindo conexão no Agent; receber bytes não reinicia
o prazo. Header inválido ou corpo malformado fecha a conexão sem resposta de
erro. EOF prematuro, timeout e cancelamento também encerram a sessão. Dados
após o único handshake não são processados. Não há retries neste protocolo.

O payload só é alocado após validação do header e é privado de cada sessão.
O teto de conexões limita sessões retidas; conexões excedentes são fechadas.
Não há heartbeat, request_id, serviço remoto, resposta HTTP ou fila de escrita
de múltiplas mensagens no M1.

## Evolução planejada para o túnel seguro

O M2 implementou [WSS v2](wss-v2.md) com TLS 1.3/mTLS e identidade autorizada
pelo fingerprint do certificado. Seus frames são HELLO, WELCOME, PING, PONG e
GOODBYE. Registro de serviços e REQUEST/RESPONSE ficam para M3. O formato v1
desta página permanece somente no diagnóstico local; não é aceito em WSS.

Sessões WSS novas recebem IDs aleatórios e reiniciam contadores. Heartbeat,
backoff/jitter, limites e timeouts têm testes no M2. Autorização de domínios,
janela de requisições e orçamento de corpos HTTP são M3/M4. Nenhuma dessas
funções é inferida do handshake TCP v1.
