#include <linux/module.h>
#include <net/sock.h> 
#include <linux/netlink.h>
#include <linux/skbuff.h> 
#include <linux/proc_fs.h>
#include <linux/pid.h>

#include "tools/tools.h"

#define NETLINK_USER 31

struct sock *nl_sk = NULL;
typedef struct Message
{
    char filename[4096];
    char password[128];
    int type;
} Message;
struct Message *message;
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
bool is_process_valid(struct task_struct *ts)
{
    while (ts->pid != 1)
    {   printk("%s\n",get_filename(ts->mm->exe_file));
        ts = ts->parent;
    }
    return false;
}
static void hello_nl_recv_msg(struct sk_buff *skb)
{

    struct nlmsghdr *nlh;
    int pid;
    struct sk_buff *skb_out;
    int msg_size;
    int res;
    struct pid *pid_struct;
    struct task_struct *task;
    printk(KERN_INFO "Entering: %s\n", __FUNCTION__);

    msg_size = sizeof(struct Message);
    
    nlh = (struct nlmsghdr *)skb->data;
    message=(struct Message *)nlmsg_data(nlh);
    //printk(KERN_INFO "Netlink received msg payload:%s\n", (char *)nlmsg_data(nlh));
    printk("%d\n",message->type);
    printk("%s\n",message->filename);
    printk("%s\n",message->password);
    message->type=4;
    
    pid = nlh->nlmsg_pid; 
    printk("pid%d\n",pid);
    pid_struct = find_get_pid(pid);
    task = pid_task(pid_struct,PIDTYPE_PID);
    is_process_valid(task);
    skb_out = nlmsg_new(msg_size, 0);
    if (!skb_out) {
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

static int __init hello_init(void)
{

    printk("Entering: %s\n", __FUNCTION__);
    //nl_sk = netlink_kernel_create(&init_net, NETLINK_USER, 0, hello_nl_recv_msg, NULL, THIS_MODULE);
    struct netlink_kernel_cfg cfg = {
        .input = hello_nl_recv_msg,
    };

    nl_sk = netlink_kernel_create(&init_net, NETLINK_USER, &cfg);
    if (!nl_sk) {
        printk(KERN_ALERT "Error creating socket.\n");
        return -10;
    }

    return 0;
}

static void __exit hello_exit(void)
{

    printk(KERN_INFO "exiting hello module\n");
    netlink_kernel_release(nl_sk);
}

module_init(hello_init); module_exit(hello_exit);

MODULE_LICENSE("GPL");
