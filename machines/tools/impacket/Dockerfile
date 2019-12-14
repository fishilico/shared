# From:
# * https://github.com/razaborg/docker-impacket
# * https://blog.ropnop.com/docker-for-pentesters/

FROM python:3.7-alpine
RUN apk --update --no-cache add \
    zlib-dev \
    musl-dev \
    libc-dev \
    gcc \
    git \
    libffi-dev \
    openssl-dev && \
    rm -rf /var/cache/apk/* && \
    pip install --upgrade pip && \
    mkdir /opt/impacket

COPY impacket /opt/impacket
WORKDIR /opt/impacket
RUN pip install .

WORKDIR /opt/impacket/examples
CMD ["python3"]
