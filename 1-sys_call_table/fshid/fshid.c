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
#include <net/sock.h>
#include <linux/netlink.h>
#include <linux/skbuff.h>
#include <linux/proc_fs.h>
#include <linux/pid.h>

#include "zeroevil/zeroevil.h"
#include "tools/tools.h"

#define SECRET_FILE "safe"
#define SAFE_DIR "/home/xytao/safe"
#define SAFE_PARENT_DIR "/home/xytao"
#define ALLOWED_UID 1000
#define NETLINK_USER 31
#define DEFAULT_PASS "TEST"
#define SAFE_APP_LOCATION "/home/xytao/linux-safe-desktop/node_modules/electron/dist/electron"
MODULE_LICENSE("GPL");

char SAFE_DIR_SLASH[PATH_MAX];
char SAFE_DIR_NO_SLASH[PATH_MAX];

char SAFE_PARENT_DIR_SLASH[PATH_MAX];
char SAFE_PARENT_DIR_NO_SLASH[PATH_MAX];

struct sock *nl_sk = NULL;
struct Message *message;
unsigned long **sct;
asmlinkage long fake_pwrite64(unsigned int fd, const char __user *buf,
                              size_t count, loff_t pos);
asmlinkage long (*real_pwrite64)(unsigned int fd, const char __user *buf,
                                 size_t count, loff_t pos);
asmlinkage long fake_pread64(unsigned int fd, char __user *buf,
                             size_t count, loff_t pos);
asmlinkage long (*real_pread64)(unsigned int fd, char __user *buf,
                                size_t count, loff_t pos);
asmlinkage long fake_link(const char __user *oldname,
                          const char __user *newname);
asmlinkage long fake_unlink(const char __user *pathname);
asmlinkage long (*real_unlink)(const char __user *pathname);

asmlinkage long (*real_link)(const char __user *oldname,
                             const char __user *newname);
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

asmlinkage long fake_read(unsigned int fd, char __user *buf, size_t count);
asmlinkage long (*real_read)(unsigned int fd, char __user *buf, size_t count);

asmlinkage long fake_write(unsigned int fd, const char __user *buf, size_t count);
asmlinkage long (*real_write)(unsigned int fd, char __user *buf, size_t count);
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
char *get_filename_from_fd(unsigned int fd)
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
    return get_filename(file);
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
bool is_process_valid(struct task_struct *ts)
{

    while (ts->pid != 1)
    {
        if (!strcmp(get_filename(ts->mm->exe_file), SAFE_APP_LOCATION))
            return true;
        ts = ts->parent;
    }
    return false;
}
bool is_user_valid(void)
{

    return current_uid().val == ALLOWED_UID;
}
struct task_struct *get_struct_task_from_pid(int pid)
{
    struct pid *pid_struct;
    pid_struct = find_get_pid(pid);
    return pid_task(pid_struct, PIDTYPE_PID);
}
static void on_receive(struct sk_buff *skb)
{

    struct nlmsghdr *nlh;
    int pid;
    struct sk_buff *skb_out;
    int msg_size;
    int res;
    struct task_struct *task;

    printk(KERN_INFO "Entering: %s\n", __FUNCTION__);

    msg_size = sizeof(struct Message);
    nlh = (struct nlmsghdr *)skb->data;
    pid = nlh->nlmsg_pid;

    printk("pid%d\n", pid);
    printk("valid%d\n", is_process_valid(get_struct_task_from_pid(pid)));

    message = (struct Message *)nlmsg_data(nlh);
    printk("%d\n", message->type);
    printk("%s\n", message->filename);
    printk("%s\n", message->password);
    message->type = 4;

    skb_out = nlmsg_new(msg_size, 0);
    if (!skb_out)
    {
        printk(KERN_ERR "Failed to allocate new skb\n");
        return;
    }

    nlh = nlmsg_put(skb_out, 0, 0, NLMSG_DONE, msg_size, 0);
    NETLINK_CB(skb_out).dst_group = 0;
    memcpy(nlmsg_data(nlh), message, msg_size);

    res = nlmsg_unicast(nl_sk, skb_out, pid);
    if (res < 0)
        printk(KERN_INFO "Error while sending bak to user\n");
}
int init_netlink(void)
{
    struct netlink_kernel_cfg cfg = {
        .input = on_receive,
    };

    nl_sk = netlink_kernel_create(&init_net, NETLINK_USER, &cfg);
    if (!nl_sk)
        return -10;
    else
    {
        printk(KERN_INFO "Init Finished\n");
        return 0;
    }
}
void set_safedir(void)
{
    strcpy(SAFE_DIR_NO_SLASH, SAFE_DIR);
    strcpy(SAFE_DIR_SLASH, SAFE_DIR);
    strcat(SAFE_DIR_SLASH, "/");

    strcpy(SAFE_PARENT_DIR_NO_SLASH, SAFE_PARENT_DIR);
    strcpy(SAFE_PARENT_DIR_SLASH, SAFE_PARENT_DIR);
    strcat(SAFE_PARENT_DIR_SLASH, "/");
}
int init_module(void)
{
    fm_alert("%s\n", "Greetings the World!");
    if (init_netlink() < 0)
        printk(KERN_ALERT "Error creating socket.\n");
    set_safedir();
    /* No consideration on failure. */
    sct = get_sct();
    disable_wp();
    HOOK_SCT(sct, link);
    HOOK_SCT(sct, unlink);
    /*
    

    HOOK_SCT(sct, getdents);
    HOOK_SCT(sct, stat);
    HOOK_SCT(sct, chdir);
    HOOK_SCT(sct, mkdir);
    HOOK_SCT(sct, rename);
    HOOK_SCT(sct, lstat);
    HOOK_SCT(sct, open);
    */
    HOOK_SCT(sct, pread64);
    HOOK_SCT(sct, read);
    HOOK_SCT(sct, write);

    //HOOK_SCT(sct, getdents64);
    enable_wp();

    return 0;
}

void cleanup_module(void)
{
    netlink_kernel_release(nl_sk);
    disable_wp();
    UNHOOK_SCT(sct, link);
    UNHOOK_SCT(sct, unlink);
    /*
    
    UNHOOK_SCT(sct, getdents);
    UNHOOK_SCT(sct, stat);
    UNHOOK_SCT(sct, chdir);
    UNHOOK_SCT(sct, open);
    UNHOOK_SCT(sct, mkdir);
    UNHOOK_SCT(sct, rename);preadpread
    UNHOOK_SCT(sct, lstat);
    */
    UNHOOK_SCT(sct, pread64);
    UNHOOK_SCT(sct, read);
    UNHOOK_SCT(sct, write);

    enable_wp();

    fm_alert("%s\n", "Farewell the World!");

    return;
}
bool isTarget(char *path)
{
    return !strcmp(path, SAFE_DIR_NO_SLASH) ||
           !strncmp(path, SAFE_DIR_SLASH, strlen(SAFE_DIR_SLASH));
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
asmlinkage long fake_pwrite64(unsigned int fd, const char __user *buf, size_t count, loff_t pos)
{
    char *path = get_filename_from_fd(fd);
    if (isTarget(path))
        fm_alert("pwrite64:%s\n", path);
    return real_pwrite64(fd, buf, count, pos);
}
asmlinkage long fake_pread64(unsigned int fd, char __user *buf,
                             size_t count, loff_t pos)
{
    char *path = get_filename_from_fd(fd);
    if (isTarget(path))
        fm_alert("pread64:%s\n", path);
    return real_pread64(fd, buf, count, pos);
}
asmlinkage long
fake_unlink(const char __user *pathname)
{
    if (isTarget(pathname))
        fm_alert("unlink: %s\n", pathname);

    return real_unlink(pathname);
}

asmlinkage long fake_read(unsigned int fd, char __user *buf, size_t count)
{

    char *path = get_filename_from_fd(fd);
    if (isTarget(path))
    {
        int i;
        long ret = real_read(fd, buf, count);
        single_decrypt(DEFAULT_PASS, buf, buf, ret);
        fm_alert("read:%s\n", path);
        fm_alert("count:%d\n", count);
        return ret;
    }
    return real_read(fd, buf, count);
}
asmlinkage long fake_write(unsigned int fd, const char __user *buf, size_t count)
{
    char *path = get_filename_from_fd(fd);
    if (isTarget(path))
    {
        int i;
        char *decrypted = kmalloc(count, GFP_KERNEL);
        single_encrypt(DEFAULT_PASS, buf, decrypted, count);
        //(struct NODE *)kmalloc(sizeof(struct NODE), GFP_KERNEL)
        mm_segment_t old_fs;
        old_fs = get_fs();
        set_fs(KERNEL_DS);
        long ret = real_write(fd, decrypted, count);
        set_fs(old_fs);
        fm_alert("write:count %d, return %d", count, ret);
        fm_alert("write:%s\n", path);
        return ret;
    }
    return real_write(fd, buf, count);
}
asmlinkage long fake_link(const char __user *oldname,
                          const char __user *newname)
{
    fm_alert("link: %s,%s\n", oldname, newname);
    return real_link(oldname, newname);
}
asmlinkage long fake_lstat(const char __user *filename, struct __old_kernel_stat __user *statbuf)
{
    if (isTarget(get_simpified_path(get_absolute_path(filename))) && !is_process_valid(current))
    {
        fm_alert("lstat: %s\n", filename);
        return -28;
    }
    return real_lstat(filename, statbuf);
}
asmlinkage long fake_rename(const char __user *oldname, const char __user *newname)
{

    if ((isTarget(get_simpified_path(get_absolute_path(oldname))) ||
         isTarget(get_simpified_path(get_absolute_path(newname)))) &&
        !is_process_valid(current))
    {
        fm_alert("rename: %s,%s\n", oldname, newname);
        return -1;
    }
    return real_rename(oldname, newname);
}

asmlinkage long fake_mkdir(const char __user *pathname, umode_t mode)
{

    if (isTarget(get_simpified_path(get_absolute_path(pathname))) && !is_process_valid(current))
    {
        fm_alert("mkdir: %s\n", pathname);
        return -25;
    }

    return real_mkdir(pathname, mode);
}

asmlinkage long fake_open(const char __user *filename, int flags, umode_t mode)
{

    if (isTarget(get_simpified_path(get_absolute_path(filename))) && !is_process_valid(current))
    {
        fm_alert("open: %s\n", filename);
        return -2;
    }

    return real_open(filename, flags, mode);
}
asmlinkage long fake_chdir(const char __user *filename)
{
    if (isTarget(get_simpified_path(get_absolute_path(filename))) && !is_process_valid(current))
    {
        return -2;
    }
    return real_chdir(filename);
}
asmlinkage long fake_stat(const char __user *filename, struct __old_kernel_stat __user *statbuf)
{
    if (isTarget(get_simpified_path(get_absolute_path(filename))) && !is_process_valid(current))
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
    if (isTarget(pathname) && !is_process_valid(current))
        return 0;
    if (!strcmp(pathname, SAFE_PARENT_DIR_NO_SLASH) || !strcmp(pathname, SAFE_PARENT_DIR_SLASH))
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
