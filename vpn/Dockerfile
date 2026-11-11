FROM alpine:3.20
RUN apk add --no-cache wireguard-tools-wg iproute2
COPY entrada.sh /entrada.sh
ENTRYPOINT ["sh", "/entrada.sh"]
