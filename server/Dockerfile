FROM i386/ubuntu

RUN apt-get update && apt-get install -y gcc gdb

RUN apt update && apt install -y wget git file binutils

RUN wget https://github.com/slimm609/checksec.sh/raw/master/checksec \
    && chmod +x checksec \
    && mv checksec /usr/local/bin/

COPY server_vuln.c /home/server_vuln.c

RUN gcc -g -m32 -no-pie -fno-stack-protector -z execstack -Wl,-z,norelro -o /home/server_vuln /home/server_vuln.c

COPY start_server.sh /start_server.sh
RUN chmod +x /start_server.sh

EXPOSE 4444

# CMD ["./start_server.sh"]

