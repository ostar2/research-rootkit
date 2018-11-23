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
#define N 256
int init_module(void) 

{
    int i;
    char plain[N]="happy";
    char e[N];
    char d[N];
    single_encrypt("te2st", plain,e, N);
    single_decrypt("te2st", e, d, N);
    printk("%s\n",d);
    return 0;
}

void cleanup_module(void)
{
    fm_alert("%s\n", "Farewell the World!");

    return;
}
