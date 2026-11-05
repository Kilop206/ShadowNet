# Instalação e build

Não há release binária ou serviço de sistema instalável no M1.

## Linux

Em Debian/Ubuntu, instalar `build-essential`, `cmake`, `ninja-build`, `python3`
e `ca-certificates`. Para Clang, adicionar `clang`; para análise, `clang-tidy`.

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

Utilizar MinGW-w64 UCRT com GCC, CMake e Ninja no PATH. MSYS2 UCRT64 é uma
opção; manter compilador e runtime na mesma distribuição. Não misturar
bibliotecas binárias MSVC com MinGW. O preset bootstrap compila dependências
com a mesma toolchain. Se o Ninja instalado travar, usar:

```powershell
cmake --preset bootstrap -G 'MinGW Makefiles' -B build/mingw
cmake --build build/mingw --parallel 4
ctest --test-dir build/mingw --output-on-failure
cmake --install build/mingw --prefix build/install
```

Os executáveis estão em `build/mingw/bin`. O runtime GCC precisa estar no PATH;
gerar um pacote distribuível com suas DLLs e licenças é trabalho do M7.

## Dependências e ambientes offline

O bootstrap usa arquivos com hash fixo em `cmake/Dependencies.cmake`.
`python scripts/fetch-deps.py` preenche `.deps/`. `--direct` permite ignorar
um proxy configurado indisponível mantendo verificação HTTPS. Também é possível
provisionar os três arquivos com os mesmos nomes por um canal confiável.
O CMake sempre verifica os hashes antes de extrair. Nunca alterar fontes das
dependências para fazer o build passar. CMake 4 é tratado para a compatibilidade
com CMake 3.5 declarada pelo yaml-cpp 0.9.0, sem modificar seu código.

## Contêineres

```sh
docker compose -f docker/compose.yaml up --build --abort-on-container-exit agent
```

O Compose compartilha o namespace de rede do Gateway para que o diagnóstico
restrito a loopback funcione. Isso é exclusivo do laboratório M1: não representa
isolamento entre hosts e não valida NAT/CGNAT. Não publica portas. A API está
presente, mas não é acessada pelo túnel até o M3.
