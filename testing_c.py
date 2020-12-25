import socket

UDP_IP = "127.0.0.1"
UDP_PORT = 5005
MESSAGE = (b"Hello server")

sock = socket.socket(socket.AF_INET,socket.SOCK_DGRAM) # UDP

sock.sendto(MESSAGE,(UDP_IP,UDP_PORT))
data, addr = sock.recvfrom(4096)
print('server said : ',str(data))
sock.close()

