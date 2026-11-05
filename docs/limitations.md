# Limitações conhecidas

- O M2 estabelece WSS/TLS 1.3/mTLS, mas ainda não oferece proxy HTTP ou publicação.
- O diagnóstico `local_tcp` do M1 é separado e restrito a loopback; encerra após handshake.
- Serviços são validados, mas não registrados remotamente ou acessados (M3).
- Não há status persistido, comando stop, dashboard, Prometheus ou serviço de sistema.
- Um único event loop por processo; não foi feito benchmark de throughput de proxy.
- Limites iniciais não são proteção completa contra DoS; logs não têm rate limit
  ou rotação interna. Usar supervisão externa apenas quando apropriado.
- O hostname de serviço aceita apenas DNS ASCII minúsculo; não há normalização IDN.
- Não existe detecção de vazamentos do IP em conteúdo/DNS da própria aplicação.
- Binários Windows dependem dos runtimes MinGW/OpenSSL no PATH; pacotes distribuíveis são M7.
- Sem CRL/OCSP, hot reload de credenciais/pins, rotação automática ou cofre de segredos.
- Não há revalidação de expiração em sessões existentes; remover pin exige reinício do Gateway.
- Chaves Unix exigem 0600/0400; ACL Windows é responsabilidade do administrador, sem inspeção automática.
- Sem prompt para PEM criptografado. A CA privada deve permanecer fora dos hosts do túnel.
- Uma identidade aceita uma sessão; múltiplas instâncias da mesma identidade não fazem balanceamento.
- Sem HTTP E2E, validação física de NAT/CGNAT ou carga de produção.
- Resultados efetivamente executados estão nos relatórios de cada milestone;
  configurar CI/Compose não prova aprovação de execuções futuras.

Não há promessa de invisibilidade: LAN, roteador, ISP e operadores continuam
podendo observar dispositivo/tráfego. O gateway conhece o IP de conexão da origem.
