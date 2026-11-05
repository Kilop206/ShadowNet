# Túnel seguro do Milestone 2

Na raiz, após compilar e instalar OpenSSL 3.0+:

```sh
python scripts/dev-certificates.py
./build/bootstrap/bin/shadow-gateway --config build/dev-pki/gateway.wss.yaml
# Em outro terminal:
./build/bootstrap/bin/shadow-agent --config build/dev-pki/agent.wss.yaml
```

Observar `tunnel_established` e `heartbeat_confirmed`. Reiniciar o Gateway
demonstra reconexão; cada conexão recebe sessão nova. No Windows, acrescentar
`.exe` e utilizar `build/mingw/bin` quando esse for o diretório de build.
As credenciais de laboratório ficam em `build/` e não devem ir para produção.
Esse túnel ainda não publica serviços: o proxy HTTP entra no M3.

## Diagnóstico local preservado do Milestone 1

Após compilar, iniciar na raiz do projeto:

```sh
./build/bootstrap/bin/shadow-gateway --config config/gateway.local.yaml
```

Em outro terminal:

```sh
./build/bootstrap/bin/shadow-agent --config config/agent.local.yaml
```

No Windows, acrescentar `.exe` e usar o caminho do diretório de build escolhido.
O Agent registra `hello_acknowledged` e retorna 0; o Gateway continua atendendo.
Esse fluxo demonstra comunicação TCP local e não publica os serviços. A API
`python examples/simple-api/server.py` é uma fixture para M3; ainda não é
alcançável por meio do Agent/Gateway.
