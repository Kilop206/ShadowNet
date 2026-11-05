# Deploy em VPS — preparação para M2/M3

**O M1 não deve ser exposto na internet.** Seu listener é TCP local sem TLS e
rejeita interfaces públicas. O build atual serve apenas para demonstração local.

Após M2/M3, o procedimento incluirá:

1. Provisionar VPS Linux com usuário sem privilégios e atualizar o sistema.
2. Apontar registros DNS dos serviços para a VPS, nunca para a origem.
3. Emitir certificado HTTPS e provisionar CA de agentes e certificados mTLS.
4. Vincular identidade do Agent a serviços e hostnames permitidos no Gateway.
5. Abrir explicitamente apenas as portas públicas necessárias no Gateway;
   manter a origem sem regras de entrada e os serviços vinculados a loopback.
6. Configurar saída do Agent ao Gateway, limites, logs e métricas internas.
7. Validar certificados inválidos, falhas, reconexão e HTTP ponta a ponta.
8. Instalar serviço do sistema somente por ação explícita do administrador.

Comandos de produção e unidade systemd serão fornecidos quando o runtime seguro
existir. Não há comandos de deploy fictícios nem mudança automática de firewall.
Expor o IP de origem em DNS, redirects ou conteúdo da aplicação continuará sendo
um risco mesmo com o túnel funcionando.
