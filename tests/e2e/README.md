# Teste HTTP ponta a ponta — M3

`e2e.reverse_proxy` usa Agent/Gateway reais, duas origens HTTP e cliente HTTPS
com certificados verificados. Não usa respostas simuladas no caminho principal.
`backend.py` produz identidades distintas e casos HTTP adversariais;
`tunnel_peer.py` implementa um peer independente para testar autorização,
correlação entre sessões e respostas atrasadas.

Executar: `ctest --test-dir build/mingw -R e2e.reverse_proxy --output-on-failure`.
O CTest fornece caminhos dos executáveis e OpenSSL. Fixtures/chaves efêmeras
ficam no build e são limpas. O teste não altera trust stores, firewall ou DNS.
