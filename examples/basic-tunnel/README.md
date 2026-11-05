# Proxy reverso do Milestone 3

Gerar configurações frescas e iniciar quatro processos em terminais separados:

```sh
python scripts/dev-certificates.py --output build/dev-pki-m3
python examples/simple-api/server.py
python examples/website/server.py
./build/bootstrap/bin/shadow-gateway --config build/dev-pki-m3/gateway.wss.yaml
./build/bootstrap/bin/shadow-agent --config build/dev-pki-m3/agent.wss.yaml
```

Em outro terminal, testar os dois hostnames por HTTPS, sem editar DNS:

```sh
python scripts/check-demo.py --ca-file build/dev-pki-m3/ca.crt
```

No Windows, usar `.exe` e o diretório de build escolhido. O protocolo é v3;
atualizar ambos os binários. A PKI é descartável e não serve para produção.

## Diagnóstico de conectividade herdado do M2

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
No M3, os arquivos gerados também publicam API/website; iniciar os dois serviços
locais e utilizar o verificador acima para comprovar o encaminhamento.

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
O transporte `local_tcp` não encaminha HTTP. Usar WSS v3 para publicação.
