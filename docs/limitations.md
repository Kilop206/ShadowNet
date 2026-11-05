# Limitações conhecidas

- M1 é um diagnóstico TCP em loopback: sem TLS, autenticação, HTTP ou publicação.
- O Agent encerra após um handshake; não há heartbeat, retry ou reconexão.
- Serviços são validados, mas não registrados remotamente e não acessados.
- Não há status persistido, comando stop, dashboard, Prometheus ou serviço de sistema.
- Um único event loop por processo; não foi feito benchmark de throughput.
- Limites iniciais não são proteção completa contra DoS; logs não têm rate limit
  ou rotação interna. Usar supervisão externa apenas quando apropriado.
- O hostname de serviço aceita apenas DNS ASCII minúsculo; não há normalização IDN.
- Não existe detecção de vazamentos do IP em conteúdo/DNS da própria aplicação.
- Binários Windows dependem do runtime MinGW no PATH; pacotes distribuíveis são M7.
- Testes de TLS, HTTP E2E, NAT/CGNAT e carga de produção ainda não existem.
- A matriz CI e o Compose precisam ser executados nos respectivos ambientes.

Não há promessa de invisibilidade: LAN, roteador, ISP e operadores continuam
podendo observar dispositivo/tráfego. O gateway conhece o IP de conexão da origem.
