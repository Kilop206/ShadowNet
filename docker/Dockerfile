FROM ubuntu:24.04 AS build
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential cmake ninja-build ca-certificates libssl-dev && rm -rf /var/lib/apt/lists/*
WORKDIR /src
COPY . .
RUN cmake --preset bootstrap -DBUILD_TESTING=OFF -DCMAKE_BUILD_TYPE=Release \
    && cmake --build --preset bootstrap --parallel 2 \
    && cmake --install build/bootstrap --prefix /out

FROM ubuntu:24.04 AS runtime
RUN apt-get update && apt-get install -y --no-install-recommends libstdc++6 libssl3t64 ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --user-group --uid 10001 --create-home shadownet
COPY --from=build /out/ /usr/local/
COPY docker/entrypoint.sh /usr/local/bin/shadow-entrypoint
RUN chmod 755 /usr/local/bin/shadow-entrypoint
USER shadownet
WORKDIR /usr/local/share/shadownet
ENTRYPOINT ["shadow-entrypoint"]
CMD ["shadow-gateway", "--config", "/run/shadow/gateway.yaml"]
