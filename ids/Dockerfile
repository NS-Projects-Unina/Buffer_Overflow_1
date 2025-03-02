FROM ubuntu:latest

RUN apt update && apt install -y snort tshark

RUN  rm -rf /etc/snort/snort.conf
COPY snort.conf /etc/snort/snort.conf

COPY buffer_overflow.rules /etc/snort/rules/buffer_overflow.rules

ENTRYPOINT ["/bin/bash", "-c", "snort -c /etc/snort/snort.conf -i eth0 -A fast -k none >> /var/log/snort/snort.log 2>&1"]

