FROM alpine:latest
RUN apk --no-cache add python3
COPY entrypoint.sh /entrypoint.sh
ENTRYPOINT ["/entrypoint.sh"]
