# Diagnóstico local do Milestone 1

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
