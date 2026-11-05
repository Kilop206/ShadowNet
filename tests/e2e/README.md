# Teste HTTP ponta a ponta (planejado para M3)

Há túnel WSS/TLS 1.3/mTLS no M2, mas nenhum listener HTTP de visitantes ou
encaminhamento. Nenhum teste HTTP E2E é
declarado aprovado. `integration.local_transport` valida o diagnóstico M1;
`integration.secure_transport` valida certificados, WSS, heartbeat e recuperação M2.

No M3, adicionar a validação Cliente HTTPS → Gateway → túnel autenticado →
Agent → API local → Cliente, com métodos, cabeçalhos, corpos, dois serviços e
requisições simultâneas. A API de exemplo já está em `examples/simple-api/`.
