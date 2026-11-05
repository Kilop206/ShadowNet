# Deploy em VPS — túnel M2 e preparação do proxy M3

O M2 permite um listener WSS com TLS 1.3/mTLS e autorização por certificado;
**ainda não publica sites ou APIs**. O diagnóstico `local_tcp` nunca deve ser
exposto, e continua impedindo bind público. Não há instalador de serviço.

Para avaliar somente o túnel M2 em infraestrutura administrada:

1. Compilar com OpenSSL 3.0+ e executar sob usuário dedicado.
2. Provisionar CA confiável para agentes, certificado `serverAuth` do Gateway
   com SAN de seu DNS e certificado `clientAuth` do Agent.
3. Copiar templates `config/*.wss.yaml`, apontar os arquivos e substituir o pin
   pelo SHA-256 do leaf DER; restringir chaves a 0600/0400 (ACL no Windows).
4. Validar ambos com `shadow config validate --type ... --config ...`.
5. Configurar explicitamente a entrada TCP escolhida apenas na VPS. O software
   não muda firewall. A origem precisa somente de saída ao DNS/porta do Gateway.
6. Iniciar `shadow gateway start --config ...` e `shadow agent start --config ...`;
   observar estabelecimento, heartbeat e reconexão após interrupção.

Não instalar a CA privada no Gateway/origem, não usar a PKI de laboratório e
não oferecer esse listener como HTTPS de visitantes: ele exige certificado de
agente e só aceita o endpoint interno WSS. Os serviços ainda não são registrados.

O procedimento de publicação HTTP do M3 incluirá:

1. Provisionar VPS Linux com usuário sem privilégios e atualizar o sistema.
2. Apontar registros DNS dos serviços para a VPS, nunca para a origem.
3. Emitir certificado HTTPS e provisionar CA de agentes e certificados mTLS.
4. Vincular identidade do Agent a serviços e hostnames permitidos no Gateway.
5. Abrir explicitamente apenas as portas públicas necessárias no Gateway;
   manter a origem sem regras de entrada e os serviços vinculados a loopback.
6. Configurar saída do Agent ao Gateway, limites, logs e métricas internas.
7. Validar certificados inválidos, falhas, reconexão e HTTP ponta a ponta.
8. Instalar serviço do sistema somente por ação explícita do administrador.

Comandos de publicação e unidade systemd serão fornecidos quando o proxy e a
operação como serviço existirem. Não há comandos fictícios ou mudança de firewall.
Expor o IP de origem em DNS, redirects ou conteúdo da aplicação continuará sendo
um risco mesmo com o túnel funcionando.
