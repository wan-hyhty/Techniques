#include <stdio.h>
#include <stdlib.h>
#include <string.h>
void init()
{
    setbuf(stdin, 0);
    setbuf(stdout, 0);
    setbuf(stderr, 0);
}
void main()
{
    init();
    long int storage[30];
    unsigned int size;
    long int gift = storage;
    long int page = (storage + 17);
    memset(storage, 0, 30 * sizeof(long int));
    while (1)
    {
        int option;
        printf("====================================\n");
        printf("*** CONG TY TNHH HOUSE OF SPIRIT ***\n");
        printf("====================================\n");
        puts("1. Create");
        puts("2. Remove");
        puts("3. Write for fun");
        puts("4. Gift");
        printf("> ");
        scanf("%d", &option);
        switch (option)
        {
        case 1:
            puts("Size: ");
            scanf("%ud", &size);
            for (int i = 0; i < 8; i++)
            {
                if (storage[i] == 0)
                {
                    storage[i] = malloc(size);
                    puts("Content: ");
                    read(0, storage[i], size);
                    puts("Content: ");
                    printf("%s\n", storage[i]);
                    break;
                }
            }
            break;
        case 2:
            unsigned int idx;
            puts("idx: ");
            scanf("%ud", &idx);
            free(storage[idx]);
            storage[idx] = 0;
            break;
        case 3:
            puts("write for fun");
            read(0, page, 12 * 8);
            break;
        case 4:
            if (storage[6] != 0)
            {
                puts("Gift: ");
                printf("%ld\n", gift);
            }
            break;
        case 5:
            return;
        default:
            break;
        }
    }
}
