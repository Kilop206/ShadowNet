# Modelo de ameaças inicial

## Disponibilidade no M4

Além de limites de conexão/corpo/headers, há admissão global por reservas RAII,
fila FIFO pública antes de ler corpos e teto global para sessões WSS incluindo
handshakes. Agent retém respostas apenas dentro de slots/orçamento, drena a
fila ao recuperar capacidade e aplica prazo de escrita. Controle tem capacidade
reservada, e um peer que acumule mais de 128 trabalhos/rejeições é desconectado.
Esses controles são exercitados com recebedores lentos e interrupção de processos.

São limites de disponibilidade, sem promessa de proteção total contra DoS ou
de teto exato de RSS. Custos de TLS, kernel, allocators e logs precisam de
dimensionamento operacional. Revogação/ciclo de certificados e auditoria
aprofundada continuam no M5. Ver [confiabilidade](../architecture/reliability.md).

## Fronteiras adicionais do M3

Visitantes usam HTTPS sem certificado cliente; a porta de controle WSS mantém
mTLS. O Gateway vincula serviço/hostname ao fingerprint e exige registro
atômico. O Agent confere novamente serviço/Host e abre somente o endpoint de
loopback do YAML. Não há destino de rede selecionado pelo cliente, CONNECT,
TRACE, absolute-form ou upgrade de aplicações; não é proxy aberto.

Beast interpreta framing com limites e rejeita mensagens ambíguas. Campos
hop-by-hop, inclusive os nomeados por Connection, são removidos, Content-Length
é reconstruído e HEAD/204/304 respeitam ausência de corpo. Forwarded e
X-Forwarded recebidos do visitante não são confiados. Via pseudônimo permite
detectar loops simples de encaminhamento.

IDs não são reutilizados; outra sessão não pode responder a uma pendência.
CANCEL libera recursos, mas não faz rollback na aplicação. POST não é repetido
após reconexão. Corpos, headers, conexões, pendências, filas, prazos e RPS têm
limites; isso não substitui defesa de rede contra DDoS ou refinamentos do M4.

Aplicações ainda podem revelar endereços em conteúdo, redirects e headers
próprios. O proxy não reescreve payloads/URLs arbitrariamente. O Gateway conhece
o IP do Agent; LAN, ISP e operadores continuam podendo observar tráfego.

## Controles adicionais implementados no M2

O túnel WSS exige TLS 1.3/mTLS, validação X.509 estrita e autorização de leaf
por SHA-256. Nome autodeclarado precisa corresponder ao pin, e uma segunda
sessão da identidade não substitui a ativa. O Agent confere SAN DNS/IP do
Gateway. Não há 0-RTT, retomada de sessão TLS ou fallback para texto claro.

Cada conexão negocia um ID aleatório e heartbeat com contadores consecutivos.
Frames binários têm limite de 268 B, upgrade 8 KiB, fila quatro mensagens e
deadline de handshake total. Conexões excedentes são fechadas antes de criar
uma sessão SSL. Fechamento WebSocket/TLS tem prazo e reconexão usa backoff/jitter.

Certificados inválidos/expirados, CA errada, EKU incorreto, falta de certificado,
pin não autorizado, nome incorreto, replay de heartbeat, payload excessivo e
upgrade inválido são testados. Configuração valida arquivos e correspondência
da chave antes de conectar. No Unix, chaves acessíveis por grupo/outros são
rejeitadas. ACL Windows, CRL/OCSP, rotação automática e auditoria externa ainda
estão pendentes. Não há revalidação da expiração em conexões já estabelecidas.

A matriz abaixo registra os controles iniciais do M1. Para o comportamento
atual do túnel seguro, consultar também [TLS](tls.md) e [WSS v2](../protocols/wss-v2.md).

## Ativos e fronteiras

Ativos futuros: serviços privados, credenciais dos agentes, chaves do gateway,
conteúdo HTTP e integridade das rotas. Administradores controlam arquivos de
configuração e binários. Visitantes da internet não são confiáveis. Um agente
autenticado também precisa de autorização limitada por serviço/hostname.

O gateway é um ponto de confiança e conhece o endereço da conexão de saída.
Ocultar o IP de origem dos visitantes não torna o dispositivo invisível na LAN,
para o roteador, para o ISP ou para administradores. DNS, conteúdo da aplicação,
redirecionamentos e outros serviços podem revelar o IP independentemente do túnel.

## Controles por ameaça

| Ameaça | Controle M1 | Requisito posterior |
|---|---|---|
| Cliente remoto não autorizado | Listener restrito a loopback | mTLS e política por identidade |
| Processo local malicioso | Limites e parsing estrito; não há autenticação | Autenticação continua necessária |
| Alocação abusiva | Frame 256 B, configuração 64 KiB, máximo 1024 sessões | Orçamento global HTTP e por agente |
| Slowloris no handshake | Deadline total 100–60000 ms | Timeouts separados para TLS/HTTP e filas |
| Injeção em logs | Eventos fixos, controles escapados, limite de texto | Redação de credenciais e auditoria |
| SSRF / proxy aberto | Nenhum encaminhamento; endpoints de configuração em loopback | IDs opacos mapeados a destinos fixos |
| Roubo de hostname | Nenhum registro remoto ainda | Allowlist no gateway vinculada ao certificado |
| Replay / resposta antiga | Sem autorização baseada em handshake local | TLS sem 0-RTT; sessão e IDs novos após reconectar |
| Header smuggling | Não há HTTP no M1 | Beast, rejeição de framing ambíguo e limpeza hop-by-hop |
| Segredos em arquivos | Nenhum segredo necessário; chaves ignoradas no Git | Permissões de arquivo, rotação e revogação |

O M1 não protege o tráfego contra processos locais capazes de interceptá-lo ou
alterar configurações. Não recebe nem armazena credenciais. Um HELLO com nome
correto não autentica um agente. Restrições em `.gitignore` não impedem que
alguém force um commit de chave: revisão de segredos continua necessária.

## Restrições permanentes

Sem alteração automática de firewall, roteador, antivírus ou monitoramento.
Sem ocultação de processos ou persistência furtiva. Sem seleção arbitrária de
destino interno por visitantes. Sem algoritmos criptográficos próprios.
Instalação como serviço exigirá ação explícita do administrador.

Antes de produção: revisar dependências, autorização, chaves, revogação,
timeouts e memória; testes adversariais e auditoria externa. Comprometimento
do host, do serviço local ou do gateway permanece fora da proteção do túnel.
