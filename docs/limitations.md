# Limitações conhecidas

- O M3 publica HTTP/1.1 via HTTPS e WSS/TLS 1.3/mTLS, com mensagens completas limitadas a 1 MiB de corpo.
- O diagnóstico `local_tcp` do M1 é separado e restrito a loopback; encerra após handshake.
- Sem streaming/SSE, WebSocket de aplicações, CONNECT/TRACE, HTTP/2 ou TCP genérico.
- Uma requisição/resposta por conexão pública; sem keep-alive/pipelining público.
- O protocolo WSS é v3, incompatível com M2/v2; atualizar ambos os binários juntos.
- Não há status persistido, comando stop, dashboard administrativo ou serviço de sistema.
- Métricas Prometheus são opt-in e locais, sem TLS/autenticação nesse listener;
  processos locais podem lê-las. O Compose opcional coleta o Gateway, sem coletar
  o exporter do Agent em outro namespace. Não há tracing, alertas configurados,
  medição RSS/CPU ou retenção durável no laboratório Grafana/Prometheus.
- Reiniciar o Gateway no overlay exige reiniciar seu sidecar Prometheus para
  reanexar o namespace; os históricos em tmpfs são descartáveis.
- Um único event loop por processo; não foi feito benchmark de throughput de proxy.
- Limites não são proteção completa contra DoS; logs têm limite global de emissão
  e podem suprimir eventos, sem rotação/persistência internas. Não são trilha de auditoria completa.
- O hostname de serviço aceita apenas DNS ASCII minúsculo; não há normalização IDN.
- Não existe detecção de vazamentos do IP em conteúdo/DNS da própria aplicação.
- Binários Windows dependem dos runtimes MinGW/OpenSSL no PATH; pacotes distribuíveis são M7.
- CRL local é opcional e carregada no início; sem download automático/OCSP,
  hot reload de credenciais/pins, rotação automática ou cofre de segredos.
- Sessões WSS revalidam credenciais a cada segundo; remover pin ou atualizar CRL
  exige reinício controlado. O agendador/relógio do SO limitam a precisão temporal.
- Chaves Unix exigem 0600/0400; DACL Windows é inspecionada conservadoramente.
  Chaves não podem ter symlink final ou mais de um hard link. Diretórios pais
  e a conta do processo precisam de proteção administrativa contra troca de arquivos.
- Políticas de método/caminho não autenticam visitantes. Caminhos ambíguos e
  percent-encoding de caracteres reservados/Unicode no path são rejeitados;
  aplicações que precisam desses formatos exigem adaptação. Queries não são ACLs.
- Sem prompt para PEM criptografado. A CA privada deve permanecer fora dos hosts do túnel.
- Uma identidade aceita uma sessão; múltiplas instâncias da mesma identidade não fazem balanceamento.
- Há E2E HTTPS real com dois serviços e concorrência. Não houve validação física de NAT/CGNAT ou carga de produção.
- Rate limit é global, sem política por cliente ou tenant. O M4 aplica admissão
  por orçamento e backpressure para mensagens completas; streaming continua ausente.
- Reservas de buffers são conservadoras e têm granularidade de mensagem máxima,
  inclusive para GETs pequenos. Não são um teto de RSS: TLS, allocators, buffers
  do kernel, headers pré-admissão e estruturas fixas têm custos adicionais.
  Dimensionamento e limites do SO continuam necessários.
- CANCEL fecha I/O local, mas não desfaz efeitos da aplicação. Requisições nunca são repetidas após reconexão.
- Headers/redirects/conteúdo da aplicação podem revelar IPs; o proxy não reescreve URLs arbitrariamente.
- Resultados efetivamente executados estão nos relatórios de cada milestone;
  configurar CI/Compose não prova aprovação de execuções futuras.

Não há promessa de invisibilidade: LAN, roteador, ISP e operadores continuam
podendo observar dispositivo/tráfego. O gateway conhece o IP de conexão da origem.
