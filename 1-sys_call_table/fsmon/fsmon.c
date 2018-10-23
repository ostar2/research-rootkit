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

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/syscalls.h>
#include <linux/fs_struct.h>
#include <linux/path.h>
#include <linux/dcache.h>
#include <linux/fdtable.h>
#include <linux/string.h>

#include "zeroevil/zeroevil.h"

MODULE_LICENSE("GPL");

unsigned long **sct;

asmlinkage long fake_open(const char __user *filename, int flags, umode_t mode);
asmlinkage long fake_unlink(const char __user *pathname);
asmlinkage long fake_unlinkat(int dfd, const char __user *pathname, int flag);
asmlinkage ssize_t fake_read(int __fd, void *__buf, size_t __nbytes);
asmlinkage long (*real_open)(const char __user *filename, int flags, umode_t mode);
asmlinkage long (*real_unlink)(const char __user *pathname);
asmlinkage long (*real_unlinkat)(int dfd, const char __user *pathname, int flag);
asmlinkage ssize_t (*real_read)(int __fd, void *__buf, size_t __nbytes);

int init_module(void)
{
    fm_alert("%s\n", "Greetings the World!");

    /* No consideration on failure. */
    sct = get_sct();

    disable_wp();
    HOOK_SCT(sct, open);
    HOOK_SCT(sct, unlink);
    HOOK_SCT(sct, unlinkat);
    HOOK_SCT(sct, read);
    enable_wp();

    return 0;
}

void cleanup_module(void)
{
    disable_wp();
    UNHOOK_SCT(sct, open);
    UNHOOK_SCT(sct, unlink);
    UNHOOK_SCT(sct, unlinkat);
    UNHOOK_SCT(sct, read);
    enable_wp();

    fm_alert("%s\n", "Farewell the World!");

    return;
}

asmlinkage long fake_open(const char __user *filename, int flags, umode_t mode)
{
    if ((flags & O_CREAT) && strcmp(filename, "/dev/null") != 0)
    {
        //fm_alert("open: %s\n", filename);
    }

    return real_open(filename, flags, mode);
}

asmlinkage long fake_unlink(const char __user *pathname)
{
    //fm_alert("unlink: %s\n", pathname);

    return real_unlink(pathname);
}

asmlinkage long fake_unlinkat(int dfd, const char __user *pathname, int flag)
{
    //fm_alert("unlinkat: %s\n", pathname);

    return real_unlinkat(dfd, pathname, flag);
}
asmlinkage ssize_t fake_read(int __fd, void *__buf, size_t __nbytes)
{

    struct path pwd;
    get_fs_pwd(current->fs, &pwd);
    char x[PATH_MAX];
    char *p = dentry_path_raw(pwd.dentry, x, PATH_MAX - 1);
    //fm_alert("read:%s\n", p);

    char *tmp;
    char *pathname;
    struct file *file;
    struct path *path;
    struct files_struct *files = current->files;
    spin_lock(&files->file_lock);
    file = fcheck_files(files, __fd);
    if (!file)
    {
        spin_unlock(&files->file_lock);
        return -ENOENT;
    }

    path = &file->f_path;
    path_get(path);
    spin_unlock(&files->file_lock);

    tmp = (char *)__get_free_page(GFP_KERNEL);

    if (!tmp)
    {
        path_put(path);
        return -ENOMEM;
    }

    pathname = d_path(path, tmp, PAGE_SIZE);
    path_put(path);
    if (IS_ERR(pathname))
    {
        free_page((unsigned long)tmp);
        return PTR_ERR(pathname);
    }
    ssize_t out=real_read(__fd, __buf, __nbytes);
    if (!strncmp(pathname, "/home/xytao/safe", 15)){
        fm_alert("read:%s:", pathname,__nbytes,strlen(__buf));
        int i;
        for (i=0;i<strlen(__buf);i++)
            printk(KERN_CONT "%c", ((char*)__buf)[i]);
    }
    free_page((unsigned long)tmp);

    return out;
}