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
// linux_dirent64.
#include <linux/dirent.h>
#include <linux/dcache.h>
#include <linux/fdtable.h>
#include <linux/syscalls.h>
#include <linux/fs_struct.h>
#include "zeroevil/zeroevil.h"
#include "tools/tools.h"

MODULE_LICENSE("GPL");

#define SECRET_FILE "safe"
#define SAFE_APP_LOCATION "/home/xytao/linux-safe-desktop/node_modules/electron/dist/electron"
unsigned long **sct;
asmlinkage long fake_open(const char __user *filename, int flags, umode_t mode);
asmlinkage long (*real_open)(const char __user *filename, int flags, umode_t mode);
asmlinkage long fake_mkdir(const char __user *pathname, umode_t mode);
asmlinkage long (*real_mkdir)(const char __user *pathname, umode_t mode);
asmlinkage long fake_rename(const char __user *oldname, const char __user *newname);
asmlinkage long (*real_rename)(const char __user *oldname, const char __user *newname);

asmlinkage long fake_lstat(const char __user *filename,
                           struct __old_kernel_stat __user *statbuf);
asmlinkage long (*real_lstat)(const char __user *filename,
                              struct __old_kernel_stat __user *statbuf);
asmlinkage long (*real_getdents)(unsigned int fd,
                                 struct linux_dirent __user *dirent,
                                 unsigned int count);
asmlinkage long
fake_getdents(unsigned int fd,
              struct linux_dirent __user *dirent,
              unsigned int count);

asmlinkage long (*real_getdents64)(unsigned int fd,
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
char *get_absolute_path(char *filename)
{
    char y[PATH_MAX];
    y[0] = '\0';
    if (!filename)
        return y;
    struct path pwd;
    get_fs_pwd(current->fs, &pwd);
    char x[PATH_MAX];
    char *p = dentry_path_raw(pwd.dentry, x, PATH_MAX - 1);
    if (filename[0] == '/')
        strcpy(y, filename);
    else
    {
        strcpy(y, p);
        if (p[strlen(p) - 1] != '/')
            strcat(y, "/");
        strcat(y, filename);
    }
    return y;
}
bool is_process_valid(void)
{
    struct task_struct *ts = current;
    while (ts->pid != 1)
    {
        if (!strcmp(get_filename(ts->mm->exe_file), SAFE_APP_LOCATION))
            return true;
        ts = ts->parent;
    }
    return false;
}
int init_module(void)
{
    fm_alert("%s\n", "Greetings the World!");

    /* No consideration on failure. */
    sct = get_sct();

    disable_wp();
    HOOK_SCT(sct, getdents);
    HOOK_SCT(sct, stat);
    HOOK_SCT(sct, chdir);
    HOOK_SCT(sct, mkdir);
    HOOK_SCT(sct, rename);
    HOOK_SCT(sct, lstat);
    HOOK_SCT(sct, open);

    //HOOK_SCT(sct, getdents64);
    enable_wp();

    return 0;
}

void cleanup_module(void)
{
    disable_wp();
    UNHOOK_SCT(sct, getdents);
    UNHOOK_SCT(sct, stat);
    UNHOOK_SCT(sct, chdir);
    UNHOOK_SCT(sct, open);
    UNHOOK_SCT(sct, mkdir);
    UNHOOK_SCT(sct, rename);
    UNHOOK_SCT(sct, lstat);

    enable_wp();

    fm_alert("%s\n", "Farewell the World!");

    return;
}
bool isTarget(char *path)
{
    return !strcmp(path, "/home/xytao/safe") ||
           !strncmp(path, "/home/xytao/safe/", 17);
}
char *concat(char *pwd, char *filename)
{
    if (filename[0] == '/')
    {
        return filename;
    }
    strcat(pwd, filename);
    return pwd;
}
asmlinkage long fake_lstat(const char __user *filename, struct __old_kernel_stat __user *statbuf)
{ 
    if ( isTarget(get_simpified_path(get_absolute_path(filename))) && !is_process_valid()) 
    {
        fm_alert("lstat: %s\n", filename);
        return -28;
    }
    return real_lstat(filename, statbuf);
}
asmlinkage long fake_rename(const char __user *oldname, const char __user *newname)
{
    
    if ( (isTarget(get_simpified_path(get_absolute_path(oldname)))||
        isTarget(get_simpified_path(get_absolute_path(newname)))) && 
        !is_process_valid()) 
    {	
        fm_alert("rename: %s,%s\n", oldname,newname);
        return -1;
    }
    return real_rename(oldname, newname);
}

asmlinkage long fake_mkdir(const char __user *pathname, umode_t mode)
{
    
    if ( isTarget(get_simpified_path(get_absolute_path(pathname))) && !is_process_valid())
    {
        fm_alert("mkdir: %s\n", pathname);
        return -25;
    }

    return real_mkdir(pathname, mode);
}

asmlinkage long fake_open(const char __user *filename, int flags, umode_t mode)
{

    if (isTarget(get_simpified_path(get_absolute_path(filename))) && !is_process_valid())
    {
        fm_alert("open: %s\n", filename);
        return -2;
    }

    return real_open(filename, flags, mode);
}
asmlinkage long fake_chdir(const char __user *filename)
{
    if (isTarget(get_simpified_path(get_absolute_path(filename))) && !is_process_valid())
    {
        return -2;
    }
    return real_chdir(filename);
}
asmlinkage long fake_stat(const char __user *filename, struct __old_kernel_stat __user *statbuf)
{
    if (isTarget(get_simpified_path(get_absolute_path(filename))) && !is_process_valid())
    {
        return -2;
    }
    return real_stat(filename, statbuf);
}
long remove(char *name, struct linux_dirent *dirp, long total)
{
    printk("111: %d\n", total);
    struct linux_dirent *cur;
    long index = 0;
    while (index < total)
    {
        cur = (struct linux_dirent *)((unsigned long)dirp + index);
        printk("name:%s", cur->d_name);
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
    char *pathname = get_filename(file);
    //fm_alert("%s\n", pathname);

    long ret;
    ret = real_getdents(fd, dirent, count);
    if (isTarget(pathname) && !is_process_valid())
        return 0;
    if (!strcmp(pathname,"/home/xytao")||!strcmp(pathname,"/home/xytao/"))
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
