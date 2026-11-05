# Instalação e build

Não há release binária ou instalador de serviço de sistema até o M4.

## Linux

Em Debian/Ubuntu, instalar `build-essential`, `cmake`, `ninja-build`, `python3`,
`libssl-dev`, `openssl` e `ca-certificates`. Para Clang, adicionar `clang`;
para análise, `clang-tidy`. OpenSSL 3.0+ é obrigatório mesmo no bootstrap:
não é baixado/compilado implicitamente pelo CMake.

```sh
cmake --preset bootstrap
cmake --build --preset bootstrap --parallel 4
ctest --preset bootstrap
cmake --install build/bootstrap --prefix ./build/install
```

Para usar dependências previamente instaladas: preset `dev`, Boost 1.74+,
yaml-cpp 0.7+ e Catch2 3. Algumas distribuições fornecem apenas Catch2 2;
nesse caso utilizar bootstrap. Sem testes, `-DBUILD_TESTING=OFF` elimina a
necessidade de Python e Catch2. O código C++ não usa Python em execução.

## Windows sem MSVC

Utilizar MinGW-w64 UCRT com GCC, CMake, OpenSSL e Ninja no PATH. MSYS2 UCRT64 é uma
opção; manter compilador e runtime na mesma distribuição. Não misturar
bibliotecas C++ binárias MSVC com MinGW. O preset bootstrap compila as
dependências C++ com a mesma toolchain. A API C do OpenSSL também pode usar
import libraries DLL x64 compatíveis; isso foi validado com OpenSSL 4.0.3 local.
O CI usa OpenSSL do próprio MSYS2. Se o Ninja instalado travar, usar:

```powershell
cmake --preset bootstrap -G 'MinGW Makefiles' -B build/mingw
cmake --build build/mingw --parallel 4
ctest --test-dir build/mingw --output-on-failure
cmake --install build/mingw --prefix build/install
```

Os executáveis estão em `build/mingw/bin`. O runtime GCC precisa estar no PATH;
as DLLs OpenSSL também. Gerar um pacote distribuível com DLLs/licenças é M7.
Se necessário, passar `-DOPENSSL_ROOT_DIR=...`; para layouts fora do padrão,
informar `OPENSSL_INCLUDE_DIR`, `OPENSSL_SSL_LIBRARY`, `OPENSSL_CRYPTO_LIBRARY`.
No MinGW/GCC Debug, a unidade SSL/WebSocket usa `-O1 -g1 -Wa,-mbig-obj` para
limitar o tamanho e o custo dos símbolos; as demais mantêm debug completo.

## Dependências e ambientes offline

O bootstrap usa arquivos com hash fixo em `cmake/Dependencies.cmake`.
`python scripts/fetch-deps.py` preenche `.deps/`. `--direct` permite ignorar
um proxy configurado indisponível mantendo verificação HTTPS. Também é possível
provisionar os três arquivos com os mesmos nomes por um canal confiável.
O CMake sempre verifica os hashes antes de extrair. Nunca alterar fontes das
dependências para fazer o build passar. CMake 4 é tratado para a compatibilidade
com CMake 3.5 declarada pelo yaml-cpp 0.9.0, sem modificar seu código.

## Contêineres

Gerar uma PKI nova fora da imagem. Definir `SHADOW_PKI_DIR` como
`../build/dev-pki-m3`: no Bash, `export SHADOW_PKI_DIR=../build/dev-pki-m3`;
no PowerShell, `$env:SHADOW_PKI_DIR='../build/dev-pki-m3'`.

```sh
python scripts/dev-certificates.py --output build/dev-pki-m3
docker compose -p shadownet-m3 -f docker/compose.yaml up --build -d
python scripts/check-demo.py --ca-file build/dev-pki-m3/ca.crt
docker compose -p shadownet-m3 -f docker/compose.yaml restart gateway
python scripts/check-demo.py --ca-file build/dev-pki-m3/ca.crt
docker compose -p shadownet-m3 -f docker/compose.yaml down
```

No Linux, definir `SHADOW_UID`/`SHADOW_GID` como o proprietário dos arquivos
(padrão 1000:1000), por exemplo exportando as saídas de `id -u`/`id -g`. Não
relaxar as chaves para 0644. Gateway e Agent têm namespaces de rede diferentes;
o Agent resolve o nome `gateway` e verifica seu SAN. Somente o Gateway publica
7443 (controle) e 8443 (HTTPS) no loopback do host. API e website compartilham
o namespace do Agent, em `127.0.0.1:8080` e `127.0.0.1:3000`. Nenhuma porta
de origem é publicada. O verificador acessa ambos pelo Gateway e valida SAN/SNI,
sem mudar DNS ou confiar globalmente na CA descartável.

Cada contêiner recebe apenas seu próprio certificado/chave e a CA pública.
A chave leaf é copiada de um bind somente leitura para tmpfs privado com
umask 077, porque Docker Desktop pode apresentar bind mounts Windows como 0777.
A checagem de permissões do runtime permanece ativa. A chave privada da CA
não é montada em nenhum contêiner. Não há healthcheck que finja validar HTTP;
`tunnel_established`/`heartbeat_confirmed` comprovam a sessão WSS, e
`services_registered` o cadastro. `check-demo.py` comprova tráfego HTTP real.

Esse laboratório não prova NAT/CGNAT em redes físicas distintas e não é um
deploy de produção. A CA descartável não deve ser reutilizada em VPS pública.
