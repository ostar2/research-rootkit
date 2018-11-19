#ifndef TOOLS
#define TOOLS
#include <linux/types.h>
struct NODE
{
    char *s;
    struct NODE *nex;
    struct NODE *pre;
};
char *get_simpified_path(const char* absolute_path);
int aes_encrypt(u8 *key, u8 *src, u8 *dst, int size);
void aes_decrypt(u8 *key, u8 *src, u8 *dst, int size);

#endif
