/**
 * Log messages in the kernel ring buffer
 */
#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/printk.h>
#include <linux/version.h>

static int num = 42;
module_param(num, int, 0664);
MODULE_PARM_DESC(num, "A number");

static int __init hello_world_init(void)
{
	pr_info("Hello, world! The \"num\" param is %d\n", num);
	pr_info("You can change it by writing to /sys/module/"KBUILD_MODNAME"/parameters/num\n");
	pr_info("LINUX_VERSION_CODE is 0x%06x\n", LINUX_VERSION_CODE);
	return 0;
}

static void __exit hello_world_exit(void)
{
	pr_info("Goodbye, world! The \"num\" param was %d\n", num);
}

module_init(hello_world_init);
module_exit(hello_world_exit);
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Nicolas Iooss");
MODULE_DESCRIPTION("Simple kernel module which says hello and bye");
