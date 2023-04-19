FROM golang:1.18 as builder

COPY . /dud
WORKDIR /dud/mayhem

RUN go install github.com/dvyukov/go-fuzz/go-fuzz@latest github.com/dvyukov/go-fuzz/go-fuzz-build@latest
RUN go get github.com/dvyukov/go-fuzz/go-fuzz-dep
RUN go get github.com/AdaLogics/go-fuzz-headers
RUN apt update && apt install -y clang

RUN go-fuzz-build -libfuzzer -o package fuzzdud.a && \
    clang -fsanitize=fuzzer fuzzdud.a -o fuzzdud.libfuzzer

FROM debian:bookworm-slim
COPY --from=builder /dud/mayhem/fuzzdud.libfuzzer /