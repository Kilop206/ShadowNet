FROM ubuntu:24.04 AS build
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential cmake ninja-build ca-certificates && rm -rf /var/lib/apt/lists/*
WORKDIR /src
COPY . .
RUN cmake --preset bootstrap -DBUILD_TESTING=OFF -DCMAKE_BUILD_TYPE=Release \
    && cmake --build --preset bootstrap --parallel 2 \
    && cmake --install build/bootstrap --prefix /out

FROM ubuntu:24.04 AS runtime
RUN apt-get update && apt-get install -y --no-install-recommends libstdc++6 ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --uid 10001 --create-home shadow
COPY --from=build /out/ /usr/local/
USER shadow
WORKDIR /usr/local/share/shadownet
CMD ["shadow-gateway", "--config", "config/gateway.local.yaml"]
