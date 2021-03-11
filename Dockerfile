FROM docker.io/library/golang:1.16 AS builder
RUN CGO_ENABLED=0 go get junjie.pro/informer

FROM scratch AS runner
COPY --from=builder /go/bin/informer /informer
VOLUME ["/.config/informer", "/.local/share/informer"]
ENTRYPOINT ["/informer", "--server"]
