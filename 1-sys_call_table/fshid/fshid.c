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

/* open */
asmlinkage long fake_open(const char __user *filename, int flags, umode_t mode);
asmlinkage long (*real_open)(const char __user *filename, int flags, umode_t mode);

/* read & write */
asmlinkage long fake_read(unsigned int fd, char __user *buf, size_t count);
asmlinkage long (*real_read)(unsigned int fd, char __user *buf, size_t count);

asmlinkage long fake_pread64(unsigned int fd, char __user *buf, size_t count, loff_t pos);
asmlinkage long (*real_pread64)(unsigned int fd, char __user *buf, size_t count, loff_t pos);

asmlinkage long fake_write(unsigned int fd, const char __user *buf, size_t count);
asmlinkage long (*real_write)(unsigned int fd, char __user *buf, size_t count);

asmlinkage long fake_pwrite64(unsigned int fd, const char __user *buf, size_t count, loff_t pos);
asmlinkage long (*real_pwrite64)(unsigned int fd, const char __user *buf, size_t count, loff_t pos);

/* link & unlink */
asmlinkage long fake_link(const char __user *oldname, const char __user *newname);
asmlinkage long (*real_link)(const char __user *oldname, const char __user *newname);

asmlinkage long fake_linkat(int olddfd, const char __user *oldname, int newdfd, const char __user *newname, int flags);
asmlinkage long (*real_linkat)(int olddfd, const char __user *oldname, int newdfd, const char __user *newname, int flags);

asmlinkage long fake_symlink(const char __user *old, const char __user *new);
asmlinkage long (*real_symlink)(const char __user *oldname, const char __user *newname);

asmlinkage long fake_symlinkat(const char __user * oldname,int newdfd, const char __user * newname);
asmlinkage long (*real_symlinkat)(const char __user * oldname,int newdfd, const char __user * newname);

asmlinkage long fake_unlink(const char __user *pathname);
asmlinkage long (*real_unlink)(const char __user *pathname);

asmlinkage long fake_unlinkat(int dfd, const char __user * pathname, int flag);
asmlinkage long (*real_unlinkat)(int dfd, const char __user * pathname, int flag);

/* dir */
asmlinkage long fake_chdir(const char __user *filename);
asmlinkage long (*real_chdir)(const char __user *filename);

asmlinkage long fake_mkdir(const char __user *pathname, umode_t mode);
asmlinkage long (*real_mkdir)(const char __user *pathname, umode_t mode);

/* rename */
asmlinkage long fake_rename(const char __user *oldname, const char __user *newname);
asmlinkage long (*real_rename)(const char __user *oldname, const char __user *newname);

/* stat */
asmlinkage long fake_stat(const char __user *filename, struct __old_kernel_stat __user *statbuf);
asmlinkage long (*real_stat)(const char __user *filename, struct __old_kernel_stat __user *statbuf);

asmlinkage long fake_lstat(const char __user *filename, struct __old_kernel_stat __user *statbuf);
asmlinkage long (*real_lstat)(const char __user *filename, struct __old_kernel_stat __user *statbuf);

/* getdents */
asmlinkage long fake_getdents(unsigned int fd, struct linux_dirent __user *dirent, unsigned int count);
asmlinkage long (*real_getdents)(unsigned int fd, struct linux_dirent __user *dirent, unsigned int count);


bool is_process_valid(struct task_struct *ts)
{
    char f[PATH_MAX];
    f[0] = '\0';
    while (ts->pid != 1)
    {
        get_filename_from_struct_file(ts->mm->exe_file, f);
        if (!strcmp(f, SAFE_APP_LOCATION))
            return true;
        ts = ts->parent;
    }
    return false;
}
bool is_user_valid(void)
{

    return current_uid().val == ALLOWED_UID;
}
bool is_target(char *path)
{
    return !strcmp(path, SAFE_DIR_NO_SLASH) ||
           !strncmp(path, SAFE_DIR_SLASH, strlen(SAFE_DIR_SLASH));
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
    sct = get_sct();
    disable_wp();

    HOOK_SCT(sct, link);
    HOOK_SCT(sct, linkat);
    HOOK_SCT(sct, symlink);
    HOOK_SCT(sct, symlinkat);
    HOOK_SCT(sct, unlink);
    HOOK_SCT(sct, unlinkat);

    
    HOOK_SCT(sct, getdents);
    HOOK_SCT(sct, chdir);
    HOOK_SCT(sct, mkdir);
    HOOK_SCT(sct, rename);
    HOOK_SCT(sct, lstat);
    HOOK_SCT(sct, stat);

    HOOK_SCT(sct, open);
    HOOK_SCT(sct, pread64);
    HOOK_SCT(sct, pwrite64);
    HOOK_SCT(sct, read);
    HOOK_SCT(sct, write);

    enable_wp();

    return 0;
}

void cleanup_module(void)
{
    netlink_kernel_release(nl_sk);
    disable_wp();

    UNHOOK_SCT(sct, link);
    UNHOOK_SCT(sct, linkat);
    UNHOOK_SCT(sct, symlink);
    UNHOOK_SCT(sct, symlinkat);
    UNHOOK_SCT(sct, unlink);
    UNHOOK_SCT(sct, unlinkat);

    
    UNHOOK_SCT(sct, getdents);
    UNHOOK_SCT(sct, chdir);
    UNHOOK_SCT(sct, mkdir);
    UNHOOK_SCT(sct, rename);
    UNHOOK_SCT(sct, lstat);
    UNHOOK_SCT(sct, stat);

    UNHOOK_SCT(sct, open);
    UNHOOK_SCT(sct, pread64);
    UNHOOK_SCT(sct, pwrite64);
    UNHOOK_SCT(sct, read);
    UNHOOK_SCT(sct, write);
    enable_wp();

    fm_alert("%s\n", "Farewell the World!");

    return;
}

asmlinkage long fake_link(const char __user *oldname, const char __user *newname)
{      
    char full_new[PATH_MAX];
    char full_old[PATH_MAX];
    get_simplified_path_from_struct_task(current,newname,full_new);
    get_simplified_path_from_struct_task(current,oldname,full_old);
    if ((is_target(full_new)||is_target(full_old))&&!is_process_valid(current)){
        fm_alert("link: from-%s to-%s\n", full_old, full_new);
        return -28;
    }
        
    return real_link(oldname, newname);
} 
asmlinkage long fake_linkat(int olddfd, const char __user *oldname, int newdfd, const char __user *newname, int flags)
{
    char full_new[PATH_MAX];
    char full_old[PATH_MAX];
    get_simplified_path_from_struct_task(current,newname,full_new);
    get_simplified_path_from_struct_task(current,oldname,full_old);
    if ((is_target(full_new)||is_target(full_old))&&!is_process_valid(current)){
        fm_alert("linkat: from-%s to-%s\n", full_old, full_new);
        return -28;
    }
    return real_linkat(olddfd, oldname, newdfd, newname, flags);
}
asmlinkage long fake_symlink(const char __user *old, const char __user *new){
    char full_new[PATH_MAX];
    char full_old[PATH_MAX];
    get_simplified_path_from_struct_task(current, new, full_new);
    get_simplified_path_from_struct_task(current, old, full_old);
    if ((is_target(full_new)||is_target(full_old))&&!is_process_valid(current)){
        fm_alert("symlink: from-%s to-%s\n", full_old, full_new);
        return -28;
    }
    return real_symlink(old,new);
}
asmlinkage long fake_symlinkat(const char __user * oldname,int newdfd, const char __user * newname)
{
    char full_new[PATH_MAX];
    char full_old[PATH_MAX];
    get_simplified_path_from_struct_task(current,newname,full_new);
    get_simplified_path_from_struct_task(current,oldname,full_old);
    if ((is_target(full_new)||is_target(full_old))&&!is_process_valid(current)){
        fm_alert("symlinkat: from-%s to-%s\n", full_old, full_new);
        return -28;
    }
    return real_symlinkat(oldname,newdfd,newname);

}
asmlinkage long fake_unlink(const char __user *pathname)
{   char full[PATH_MAX];
    get_simplified_path_from_struct_task(current,pathname,full);
    if (is_target(full)&&!is_process_valid(current)){
        fm_alert("unlink: %s\n", full);
        return -28;
    }
    return real_unlink(pathname);
}
asmlinkage long fake_unlinkat(int dfd, const char __user * pathname, int flag)
{
    char full[PATH_MAX];
    get_simplified_path_from_struct_task(current,pathname,full);
    if (is_target(full)&&!is_process_valid(current)){
        fm_alert("unlinkat: %s\n", full);
        return -28;
    }
    return real_unlinkat(dfd,pathname,flag);
}

asmlinkage long fake_pwrite64(unsigned int fd, const char __user *buf, size_t count, loff_t pos)
{
    char path[PATH_MAX];
    get_filename_from_fd(current, fd, path);
    if (is_target(path)&&!is_process_valid(current)){
        fm_alert("pwrite64:%s\n", path);
        return -28;
    }
    if (is_target(path)&&is_process_valid(current)){
        char *decrypted = kmalloc(count, GFP_KERNEL);
        single_encrypt(DEFAULT_PASS, buf, decrypted, count);
        mm_segment_t old_fs;
        old_fs = get_fs();
        set_fs(KERNEL_DS);
        long ret = real_pwrite64(fd, decrypted, count,pos);
        set_fs(old_fs);
        fm_alert("pwrite64:%s\n", path);
        return ret;
    }
    return real_pwrite64(fd, buf, count, pos);
}
asmlinkage long fake_pread64(unsigned int fd, char __user *buf, size_t count, loff_t pos)
{
    char path[PATH_MAX];
    get_filename_from_fd(current, fd, path);
    if (is_target(path)&&!is_process_valid(current)){
        fm_alert("pread64:%s\n", path);
        return -28;
    }
    if (is_target(path)&&is_process_valid(current)){
        long ret = real_pread64(fd, buf, count,pos);
        single_decrypt(DEFAULT_PASS, buf, buf, ret);
        fm_alert("pread64:%s\n", path);
        return ret;
    }
    return real_pread64(fd, buf, count, pos);
}

asmlinkage long fake_read(unsigned int fd, char __user *buf, size_t count)
{
    char path[PATH_MAX];
    get_filename_from_fd(current, fd, path);
    if (is_target(path)&&!is_process_valid(current)){
        fm_alert("read:%s\n", path);
        return -28;
    }
    if (is_target(path)&&is_process_valid(current))
    {
        long ret = real_read(fd, buf, count);
        single_decrypt(DEFAULT_PASS, buf, buf, ret);
        fm_alert("read:%s\n", path);
        return ret;
    }
    return real_read(fd, buf, count);
}
asmlinkage long fake_write(unsigned int fd, const char __user *buf, size_t count)
{
    char path[PATH_MAX];
    get_filename_from_fd(current, fd, path);
    if (is_target(path)&&!is_process_valid(current)){
        fm_alert("write:%s\n", path);
        return -28;
    }
    if (is_target(path)&&is_process_valid(current))
    {
        char *decrypted = kmalloc(count, GFP_KERNEL);
        single_encrypt(DEFAULT_PASS, buf, decrypted, count);
        mm_segment_t old_fs;
        old_fs = get_fs();
        set_fs(KERNEL_DS);
        long ret = real_write(fd, decrypted, count);
        set_fs(old_fs);
        fm_alert("write:%s\n", path);
        return ret;
    }
    return real_write(fd, buf, count);
}

asmlinkage long fake_lstat(const char __user *filename, struct __old_kernel_stat __user *statbuf)
{    
    char full[PATH_MAX];
    get_simplified_path_from_struct_task(current,filename,full);
    if (is_target(full) && !is_process_valid(current))
    {
        fm_alert("lstat: %s\n", filename);
        return -28;
    }
    return real_lstat(filename, statbuf);
}
asmlinkage long fake_rename(const char __user *oldname, const char __user *newname)
{
    char full_old[PATH_MAX];
    char full_new[PATH_MAX];
    get_simplified_path_from_struct_task(current,oldname,full_old);
    get_simplified_path_from_struct_task(current,newname,full_new);
    if ((is_target(full_old) ||is_target(full_new)) &&!is_process_valid(current))
    {
        fm_alert("rename: from-%s to-%s\n", full_old, full_new);
        return -1;
    }
    return real_rename(oldname, newname);
}

asmlinkage long fake_mkdir(const char __user *pathname, umode_t mode)
{
    char full[PATH_MAX];
    get_simplified_path_from_struct_task(current,pathname,full);
    if (is_target(full) && !is_process_valid(current))
    {
        fm_alert("mkdir: %s\n", pathname);
        return -25;
    }
    return real_mkdir(pathname, mode);
}

asmlinkage long fake_open(const char __user *filename, int flags, umode_t mode)
{   
    char full[PATH_MAX];
    get_simplified_path_from_struct_task(current,filename,full);
    if (is_target(full) && !is_process_valid(current))
    {
        fm_alert("open: %s\n", filename);
        return -2;
    }
    return real_open(filename, flags, mode);
}
asmlinkage long fake_chdir(const char __user *filename)
{
    char full[PATH_MAX];
    get_simplified_path_from_struct_task(current,filename,full);
    
    if (is_target(full) && !is_process_valid(current))
    {   
        fm_alert("chdir: %s\n", full);
        return -2;
    }
    return real_chdir(filename);
}
asmlinkage long fake_stat(const char __user *filename, struct __old_kernel_stat __user *statbuf)
{
    char full[PATH_MAX];
    get_simplified_path_from_struct_task(current,filename,full);
    if (is_target(full) && !is_process_valid(current))
    {
        return -2;
    }
    return real_stat(filename, statbuf);
}


asmlinkage long
fake_getdents(unsigned int fd,struct linux_dirent __user *dirent,unsigned int count)
{   
    char pathname[PATH_MAX];
    get_filename_from_fd(current,fd,pathname);
    fm_alert("getdents: %s\n", pathname);
    long ret;
    ret = real_getdents(fd, dirent, count);
    if (is_target(pathname) && !is_process_valid(current))
        return 0;
    if (!strcmp(pathname, SAFE_PARENT_DIR_NO_SLASH) || !strcmp(pathname, SAFE_PARENT_DIR_SLASH))
        ret = remove_dent(SECRET_FILE, dirent, ret);

    return ret;
}
