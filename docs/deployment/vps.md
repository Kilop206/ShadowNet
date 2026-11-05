# Deploy em VPS — proxy reverso M3

O M3 publica HTTP/1.1 por HTTPS e encaminha pelo WSS/mTLS iniciado pelo Agent.
A VPS recebe conexões; a origem usa apenas saída e serviços em loopback.
O diagnóstico `local_tcp` nunca deve ser exposto. Não há instalador de serviço
ou alterações automáticas de firewall, DNS ou roteador.

Para configurar o túnel em infraestrutura administrada:

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

Não instalar a CA privada no Gateway/origem nem usar a PKI de laboratório.
A porta WSS exige certificado de agente e só aceita `/shadow/tunnel/v3`.
Visitantes usam outra porta, definida pela seção `http`.

Para publicar HTTP pelo túnel:

1. Provisionar VPS Linux com usuário sem privilégios e atualizar o sistema.
2. Apontar registros DNS dos serviços para a VPS, nunca para a origem.
3. Emitir certificado HTTPS e provisionar CA de agentes e certificados mTLS.
4. Vincular pares de serviço/hostname em `authorized_agents[].services` à
   identidade do Agent; configurar os mesmos pares no Agent com IP literal
   de loopback e porta fixa. O registro precisa corresponder à política.
5. Abrir explicitamente apenas as portas públicas necessárias no Gateway;
   manter a origem sem regras de entrada e os serviços vinculados a loopback.
6. Configurar `http` no Gateway com certificado SAN dos domínios públicos,
   limites de conexões, pendências, RPS e prazos. Sem `http`, não há listener
   de visitantes. Usar porta distinta da WSS; 8443 no laboratório ou 443 com
   permissões de bind concedidas explicitamente pelo administrador.
7. Validar certificados inválidos, falhas, reconexão e HTTP ponta a ponta.
8. Instalar serviço do sistema somente por ação explícita do administrador.

Comandos funcionais após preencher certificados/pins/políticas dos templates:

```sh
shadow config validate --type gateway --config /etc/shadownet/gateway.yaml
shadow gateway start --config /etc/shadownet/gateway.yaml
# Na origem, em outro computador:
shadow config validate --type agent --config agent.yaml
shadow agent start --config agent.yaml
```

Os processos ficam em primeiro plano. Instalação explícita como serviço é M7.
Verificar `services_registered`, requisições HTTPS aos hostnames e recuperação
após interrupção; heartbeat sozinho não comprova funcionamento da aplicação.
O MVP limita corpos a 1 MiB e não oferece streaming, HTTP/2, CONNECT/TRACE,
WebSocket de aplicações ou keep-alive público. CANCEL não desfaz efeitos de
POST; não há replay automático. Uso crítico exige M4/M5 e validação própria.
Expor o IP de origem em DNS, redirects ou conteúdo da aplicação continuará sendo
um risco mesmo com o túnel funcionando.
