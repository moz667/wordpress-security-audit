FROM alpine:3.24.3

RUN apk update && \
    apk --no-cache add yara coreutils wget

COPY scripts/* /usr/local/bin/
COPY yara-rules /usr/share/yara-rules

VOLUME /var/www/html

CMD [ "yara", "-r", "/usr/share/yara-rules/php.yar", "/var/www/html" ]
