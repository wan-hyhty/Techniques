# House of Spirit
## Mở đầu
- House of Spirit sẽ free fake chunk vào fastbin hoặc tcache, fastbin sẽ khó hơn vì có các security check.
- House of Spirit sẽ cố gắng tạo fake chunk để free 1 chunk có địa chỉ từ stack và free nó vào bin, sau đó UAF.
## House of Spirit (fastbin)
### Security check
```c
/* Like chunksize, but do not mask SIZE_BITS.  */
#define chunksize_nomask(p)         ((p)->mchunk_size)
/* The chunk header is two SIZE_SZ elements, but this is used widely, so
   we define it here for clarity later.  */
#define CHUNK_HDR_SZ (2 * SIZE_SZ)
#define INTERNAL_SIZE_T size_t      // tuỳ vào cấu trúc 32 hay 64 bit
#define SIZE_SZ (sizeof (INTERNAL_SIZE_T))
av->system_mem = 128kb
...
if (__builtin_expect (chunksize_nomask (chunk_at_offset (p, size))
            <= CHUNK_HDR_SZ, 0)
|| __builtin_expect (chunksize (chunk_at_offset (p, size))
                >= av->system_mem, 0))
    {
bool fail = true;
/* We might not have a lock at this point and concurrent modifications
    of system_mem might result in a false positive.  Redo the test after
    getting the lock.  */
if (!have_lock)
    {
    __libc_lock_lock (av->mutex);
    fail = (chunksize_nomask (chunk_at_offset (p, size)) <= CHUNK_HDR_SZ
        || chunksize (chunk_at_offset (p, size)) >= av->system_mem);
    __libc_lock_unlock (av->mutex);
    }

if (fail)
    malloc_printerr ("free(): invalid next size (fast)");
    }

```
- Ở fastbin, ta cần tạo 2 fake chunk
```
    +-------+---------------------+------+
    | 0x00: | Chunk # 0 prev size | 0x00 |
    +-------+---------------------+------+
    | 0x08: | Chunk # 0 size      | 0x60 |
    +-------+---------------------+------+
    | 0x10: | Chunk # 0 content   | 0x00 |
    +-------+---------------------+------+
    | 0x60: | Chunk # 1 prev size | 0x00 |
    +-------+---------------------+------+
    | 0x68: | Chunk # 1 size      | 0x40 |
    +-------+---------------------+------+
    | 0x70: | Chunk # 1 content   | 0x00 |
    +-------+---------------------+------+
```
- Khi này ta free chunk 1, security check ở trên sẽ kiểm tra next chunk (chunk 2)
- Chỉ cần thoả mãn size chunk 2 > 16 và < 128kb (16 < size < 128kb)

## House of tcache
- Có vẻ khi tcache không kiểm tra next chunk, chỉ cần ta free địa chỉ hợp lệ.

## Ex
- Mình có tạo 1 chall để tập luyện khai thác house of Spirit

### IDA 
```c 
int __cdecl main(int argc, const char **argv, const char **envp)
{
  unsigned int size; // [rsp+0h] [rbp-120h] BYREF
  int size_4; // [rsp+4h] [rbp-11Ch] BYREF
  int v7; // [rsp+8h] [rbp-118h] BYREF
  int v8; // [rsp+Ch] [rbp-114h]
  __int64 *v9; // [rsp+10h] [rbp-110h]
  void *buf; // [rsp+18h] [rbp-108h]
  __int64 s[17]; // [rsp+20h] [rbp-100h] BYREF
  __int64 v12; // [rsp+A8h] [rbp-78h] BYREF
  unsigned __int64 v13; // [rsp+118h] [rbp-8h]

  v13 = __readfsqword(0x28u);
  init(argc, argv, envp);
  v9 = s;
  buf = &v12;
  memset(s, 0, 0xF0uLL);
  while ( 1 )
  {
LABEL_2:
    puts("====================================");
    puts("*** CONG TY TNHH HOUSE OF SPIRIT ***");
    puts("====================================");
    puts("1. Create");
    puts("2. Remove");
    puts("3. Write for fun");
    puts("4. Gift");
    printf("> ");
    __isoc99_scanf("%d", &size_4);
    switch ( size_4 )
    {
      case 1:
        puts("Size: ");
        __isoc99_scanf("%ud", &size);
        v8 = 0;
        break;
      case 2:
        puts("idx: ");
        __isoc99_scanf("%ud", &v7);
        free((void *)s[v7]);
        s[v7] = 0LL;
        continue;
      case 3:
        puts("write for fun");
        read(0, buf, 0x60uLL);
        continue;
      case 4:
        if ( s[6] )
        {
          puts("Gift: ");
          printf("%ld\n", v9);
        }
        continue;
      case 5:
        return v13 - __readfsqword(0x28u);
      default:
        continue;
    }
    while ( v8 <= 7 )
    {
      if ( !s[v8] )
      {
        s[v8] = (__int64)malloc(size);
        puts("Content: ");
        read(0, (void *)s[v8], size);
        puts("Content: ");
        printf("%s\n", (const char *)s[v8]);
        goto LABEL_2;
      }
      ++v8;
    }
  }
}
```
# Ph
