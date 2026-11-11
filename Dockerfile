FROM alpine:3.24.3

RUN apk update && \
    apk --no-cache add yara coreutils wget file binutils php84 php84-tokenizer \
    imagemagick imagemagick-libs imagemagick-jpeg \
    imagemagick-webp imagemagick-tiff imagemagick-heic \
    imagemagick-jp2 imagemagick-pdf imagemagick-raw \
    imagemagick-svg

COPY scripts/ /usr/local/bin/
COPY yara-rules /usr/share/yara-rules

VOLUME /var/www/html

CMD [ "wsa-scan.sh" ]
