# start from base
FROM ubuntu:20.04
LABEL maintainer="Jesper Mikkelsen"
RUN apt-get update -y && DEBIAN_FRONTEND=noninteractive apt-get install -y python3 python3-pip libssl-dev curl systemd mongodb

COPY requirements.txt /core/requirements.txt

WORKDIR /core

RUN mkdir -p /data/db

COPY base_config.json /core/medallion.conf

RUN pip3 install -r requirements.txt

EXPOSE 80

ENTRYPOINT medallion --host 0.0.0.0 --port 80 /core/medallion.conf