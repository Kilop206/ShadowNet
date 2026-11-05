# Certificados TLS — especificação para M2

**Ainda não implementado.** O schema M1 rejeita `security`, `tls`, certificados
e destinos remotos, evitando uma falsa impressão de criptografia habilitada.

O M2 utilizará OpenSSL 3, mínimo e máximo TLS 1.3 no túnel e verificação
obrigatória da cadeia e do hostname do gateway. O gateway exigirá certificado
cliente emitido por uma CA de agentes confiável e verificará autorização por
identidade. Certificados públicos de HTTPS e CA privada de agentes podem ser
separados. Não haverá opção silenciosa de aceitar certificados inválidos.

Para testes, uma CA efêmera gerará certificados com SAN de DNS/IP adequado,
EKU `serverAuth`/`clientAuth`, validade curta e chaves geradas pelo OpenSSL.
Não usar a CA de laboratório em produção. No deploy, guardar chaves fora do
repositório, com acesso apenas ao usuário do processo; a chave da CA deve
permanecer fora do gateway. Permissões Unix e ACLs Windows serão verificadas
conforme a plataforma. Definir rotação e revogação antes de operação pública.

Testes M2: CA errada, SAN incorreto, certificado expirado, ausência de certificado
cliente, identidade sem autorização e protocolo TLS inferior. Nenhum desses
testes existe ou foi declarado aprovado no M1. Não se deve importar uma CA de
testes no trust store do sistema nem desabilitar validação para fazê-los passar.
