# Roadmap

| Milestone | Entrega e aceitação | Estado |
|---|---|---|
| M1 Foundation | Bibliotecas, YAML, logs, CLI real; Agent/Gateway compilam e trocam mensagens locais | Implementado; validação em `milestones/m1.md` |
| M2 Secure Tunnel | OpenSSL TLS 1.3 + mTLS, WSS, identidade autorizada, heartbeat, backoff e testes de certificados | Implementado; validação em `milestones/m2.md` |
| M3 Reverse Proxy MVP | HTTPS público, HTTP/1.1 completo, 2 serviços, Host autorizado, IDs e teste E2E simultâneo | Próximo |
| M4 Reliability | Orçamentos de buffers, backpressure, limites em voo, deadlines, carga e recuperação | Planejado |
| M5 Production Security | Política detalhada, ciclo de certificados, parser hardening, auditoria e testes críticos | Planejado |
| M6 Observability | Conexões, latência, throughput, RPS, erros e exportação Prometheus; Grafana opcional | Planejado |
| M7 Cross-Platform | Validar GCC/Clang/MinGW, shutdown, instalação explícita de serviço e pacotes distribuíveis | Planejado; CI inicial no M1 |
| M8 Advanced | HTTP/2, multiplexação otimizada, failover, balanceamento, dashboard, RBAC e TCP autenticado | Aguardar fundamentos |

O trabalho avança por critérios verificáveis. Produção depende de M2–M5 e
validação operacional; concluir M1 não significa que o produto esteja pronto.
