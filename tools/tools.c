#include "tools.h"

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/limits.h>
#include <linux/crypto.h>
#include <linux/types.h>
#define AES_BLOCK_SIZE 16
#define N 256

void swap_two_array(unsigned char *a, unsigned char *b)
{
    int tmp = *a;
    *a = *b;
    *b = tmp;
}
int KSA(char *key, unsigned char *S, int n)
{

    int len = strlen(key);
    int j = 0;
    int i;
    for (i = 0; i < n; i++)
        S[i] = i;

    unsigned char tmp;
    for (i = 0; i < n; i++)
    {
        j = (j + S[i] + key[i % len]) % n;
        swap_two_array(&S[i],&S[j]);
    }

    return 0;
}
int get_encrypted(char *key, unsigned char *encrypted)
{
    KSA(key, encrypted, N);
    return 0;
}
int get_decrypted(char *key, unsigned char *decrypted)
{
    unsigned char S[N];
    int i;
    KSA(key, S, N);
    for (i = 0; i < N; i++)
        decrypted[S[i]] = i;
    return 0;
}
int single_encrypt(char *key, char *src, char *dst, long len)
{
    unsigned char encrypted[N];
    long i;
    get_encrypted(key, encrypted);
    for (i = 0; i < len; i++)
        dst[i] = encrypted[((unsigned char)src[i])];
    return 0;
}
int single_decrypt(char *key, char *src, char *dst, long len)
{
    unsigned char decrypted[N];
    long i;
    get_decrypted(key, decrypted);
    for (i = 0; i < len; i++)
        dst[i] = decrypted[((unsigned char)src[i])];
    return 0;
}

int aes_encrypt(unsigned char *key, unsigned char *src, unsigned char *dst, int size)
{
    struct crypto_cipher *tfm;
    tfm = crypto_alloc_cipher("aes", 0, CRYPTO_ALG_ASYNC);
    crypto_cipher_setkey(tfm, key, 32);
    unsigned char *plain = src;
    unsigned char *enc = dst;
    int count = size / AES_BLOCK_SIZE;
    int mod = size % AES_BLOCK_SIZE;
    if (mod > 0)
        count++;
    int i;
    for (i = 0; i < count; i++)
    {
        crypto_cipher_encrypt_one(tfm, enc, plain);
        plain += AES_BLOCK_SIZE;
        enc += AES_BLOCK_SIZE;
    }
    crypto_free_cipher(tfm);

    return count * AES_BLOCK_SIZE;
}
void aes_decrypt(unsigned char *key, unsigned char *src, unsigned char *dst, int size)
{
    struct crypto_cipher *tfm;
    tfm = crypto_alloc_cipher("aes", 0, CRYPTO_ALG_ASYNC);
    crypto_cipher_setkey(tfm, key, 32);
    unsigned char *plain = dst;
    unsigned char *enc = src;
    int count = size / AES_BLOCK_SIZE;
    int i;

    for (i = 0; i < count; i++)
    {
        crypto_cipher_decrypt_one(tfm, plain, enc);
        plain += AES_BLOCK_SIZE;
        enc += AES_BLOCK_SIZE;
    }
    crypto_free_cipher(tfm);
}
char *get_simpified_path(const char *absolute_path)
{
    struct NODE *head = (struct NODE *)kmalloc(sizeof(struct NODE), GFP_KERNEL);
    head->nex = NULL;
    head->pre = NULL;
    struct NODE *tail = head;

    int i = 0;
    while (absolute_path[i++] != '\0')
    {

        //取文件夹名字
        int j = 0;
        char temp[PATH_MAX];
        while ((absolute_path[i] != '/') && (absolute_path[i] != '\0'))
        {
            temp[j++] = absolute_path[i++];
        }
        temp[j] = '\0';

        //赋值
        struct NODE *p = (struct NODE *)kmalloc(sizeof(struct NODE), GFP_KERNEL);
        p->s = (char *)kmalloc(strlen(temp) + 1, GFP_KERNEL);
        strcpy(p->s, temp);

        //尾插
        tail->nex = p;
        p->pre = tail;
        tail = tail->nex;
        p->nex = NULL;
    }

    struct NODE *p = head;
    while (p->nex != NULL)
    {
        if (strcmp(p->nex->s, "..") == 0)
        {
            if (p->pre == NULL)
            {
                struct NODE *q = p->nex;
                p->nex = p->nex->nex;
                if (p->nex->nex != NULL)
                {
                    p->nex->nex->pre = p;
                }
                kfree(q);
            }
            else
            {
                p = p->pre;
                struct NODE *q = p->nex;
                p->nex = q->nex->nex;
                if (q->nex->nex != NULL)
                {
                    q->nex->nex->pre = p;
                }
                struct NODE *k = q->nex;
                kfree(q);
                kfree(k);
            }
        }
        else if (strcmp(p->nex->s, ".") == 0)
        {
            struct NODE *q = p->nex;
            if (q->nex != NULL)
            {
                p->nex = q->nex;
                q->nex->pre = p;
                kfree(q);
            }
            else
            {
                p->nex = NULL;
                kfree(q);
            }
        }

        else
        {
            p = p->nex;
        }
    }
    struct NODE *a = head->nex;
    char out[PATH_MAX];
    out[0] = '\0';
    while (a != NULL)
    {
        strcat(out, "/");
        strcat(out, a->s);
        a = a->nex;
    }
    return out;
}
