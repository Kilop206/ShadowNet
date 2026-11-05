# Teste HTTP ponta a ponta (planejado para M3)

Ainda não há listener HTTP, TLS ou encaminhamento. Nenhum teste HTTP E2E é
declarado aprovado. O teste `integration.local_transport` executa processos reais
do Agent, Gateway e CLI, mas valida somente o handshake TCP local do M1.

No M3, adicionar a validação Cliente HTTPS → Gateway → túnel autenticado →
Agent → API local → Cliente, com métodos, cabeçalhos, corpos, dois serviços e
requisições simultâneas. A API de exemplo já está em `examples/simple-api/`.
