// winheap.c — run-112: the Win32 heap API backed by the
// kernel-side heap arena. Exercises GetProcessHeap/HeapAlloc/
// HeapReAlloc/HeapSize/HeapFree, the malloc/calloc/realloc/free
// CRT layer rewired onto it, double-free rejection, and reuse of
// a freed block. Exit code 23 = all ok.
#include <windows.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

int main(void)
{
    HANDLE h = GetProcessHeap();
    if (!h)
        return 1;

    BYTE *a = (BYTE *)HeapAlloc(h, HEAP_ZERO_MEMORY, 100);
    if (!a)
        return 2;
    for (int i = 0; i < 100; i++)
        if (a[i] != 0)
            return 3; // HEAP_ZERO_MEMORY must deliver zeros

    BYTE *b = (BYTE *)HeapAlloc(h, 0, 200);
    if (!b)
        return 4;
    memset(b, 0x5a, 200);
    if (HeapSize(h, 0, b) < 200)
        return 5;

    // Grow: content must survive, whether moved or in place.
    memset(a, 0xa5, 100);
    a = (BYTE *)HeapReAlloc(h, 0, a, 1000);
    if (!a)
        return 6;
    for (int i = 0; i < 100; i++)
        if (a[i] != 0xa5)
            return 7;

    // Double free is rejected, not corruption.
    if (!HeapFree(h, 0, b))
        return 8;
    if (HeapFree(h, 0, b))
        return 9;
    if (!HeapFree(h, 0, a))
        return 10;

    // Reuse: a same-size alloc after free should succeed (and
    // typically lands on the freed block — either way is fine).
    BYTE *c = (BYTE *)HeapAlloc(h, 0, 190);
    if (!c)
        return 11;
    HeapFree(h, 0, c);

    // The CRT layer: malloc/calloc/realloc/free ride the heap too.
    char *p = (char *)malloc(64);
    if (!p)
        return 12;
    strcpy(p, "heap");
    char *q = (char *)calloc(8, 32);
    if (!q)
        return 13;
    for (int i = 0; i < 256; i++)
        if (q[i] != 0)
            return 14;
    p = (char *)realloc(p, 512);
    if (!p)
        return 15;
    if (strcmp(p, "heap") != 0)
        return 16;
    free(p);
    free(q);
    free(NULL); // must be a no-op

    puts("winheap: HeapAlloc/ReAlloc/Free/malloc/calloc/realloc all ok");
    return 23;
}
