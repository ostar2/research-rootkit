// Copyright 2016 Gu Zhengxiong <rectigu@gmail.com>
//
// This file is part of LibZeroEvil.
//
// LibZeroEvil is free software:
// you can redistribute it and/or modify it
// under the terms of the GNU General Public License
// as published by the Free Software Foundation,
// either version 3 of the License,
// or (at your option) any later version.
//
// LibZeroEvil is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with LibZeroEvil.
// If not, see <http://www.gnu.org/licenses/>.

#ifndef CPP
#include <linux/module.h>
#include <linux/kernel.h>


#include <linux/slab.h>

#endif // CPP

#include "zeroevil/zeroevil.h"
#include "tools/tools.h"
#include <linux/random.h>

MODULE_LICENSE("GPL");

int init_module(void) 

{
    fm_alert("%s\n", "Greetings the World!");
    u8 *key = kmalloc(32, GFP_KERNEL);
    u8 *src = kmalloc(65536, GFP_KERNEL);
    u8 *dest = kmalloc(65536, GFP_KERNEL);
    u8 *dest2 = kmalloc(65536, GFP_KERNEL);
    int size = 65536;
    get_random_bytes(src, size);
    get_random_bytes(key, 32);
    fm_alert("Start Encyption\n");
    int size_d = aes_encrypt(key, src, dest, size);
    fm_alert("Encyption finished\n");
    fm_alert("Start Decryption\n");
    aes_decrypt(key, dest, dest2, size_d);
    fm_alert("Decryption finished\n");

    /*
    int i;
    printk("\nplain:");
    for (i = 0; i < size; i++)
        pr_cont("%x", src[i]);

    printk("\nencry:");
    for (i = 0; i < size_d; i++)
        pr_cont("%x", dest[i]);

    printk("\ndecry:");
    for (i = 0; i < size; i++)
        pr_cont("%x", dest2[i]);
    printk("\n");*/

    if (!memcmp(src, dest2, size))
    {
        printk("Success!\n");
    }

    return 0;
}

void cleanup_module(void)
{
    fm_alert("%s\n", "Farewell the World!");

    return;
}
