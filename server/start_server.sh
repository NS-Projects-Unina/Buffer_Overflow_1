#!/bin/bash
echo "Avvio server vulnerabile in ascolto sulla porta 4444...." | tee -a /var/log/server.log  #
while true; do
    echo "Starting.." | tee -a /var/log/server.log 
    /home/server_vuln 4444 | tee -a /var/log/server.log 
    echo "Server crashed! Restarting in 5 seconds..." | tee -a /var/log/server.log 
    sleep 10
done
