#ifndef TOOLS
#define TOOLS
#include <linux/types.h>
struct NODE
{
    char *s;
    struct NODE *nex;
    struct NODE *pre;
};
typedef struct Message
{
    char filename[4096];
    char password[128];
    int type;
} Message;
char *get_simpified_path(const char *absolute_path);
int aes_encrypt(u8 *key, u8 *src, u8 *dst, int size);
void aes_decrypt(u8 *key, u8 *src, u8 *dst, int size);
void single_encrypt(char *key, char *src, char *dst, long length);
void single_decrypt(char *key, char *src, char *dst, long length);

#endif
