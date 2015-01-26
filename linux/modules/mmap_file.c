/**
 * Implement the basic operations which are needed to perform a mmap
 */
#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/debugfs.h>
#include <linux/mm.h>
#include <linux/slab.h>
#include <linux/vmalloc.h>

static unsigned long mapsize = PAGE_SIZE << 4;
module_param(mapsize, ulong, S_IRUSR | S_IRGRP | S_IROTH);
MODULE_PARM_DESC(mapsize, "Size of the mmap'ed data");

static char *debugname = "mmap_file";
module_param(debugname, charp, S_IRUSR | S_IRGRP | S_IROTH);
MODULE_PARM_DESC(debugname, "File name in debugfs (/sys/kernel/debug)");

static struct dentry *debugfs_file;

static void mmap_open(struct vm_area_struct *vma)
{
	pr_info("Mmap opening for %pK\n", vma->vm_private_data);
}

static void mmap_close(struct vm_area_struct *vma)
{
	pr_info("Mmap closing for %pK\n", vma->vm_private_data);
}

static int mmap_fault(struct vm_area_struct *vma, struct vm_fault *vmf)
{
	struct page *page;
	off_t offset = vmf->pgoff << PAGE_SHIFT;

	pr_info(
		"Mmap fault occured on page %lu, userspace address %p\n",
		vmf->pgoff, vmf->virtual_address);

	if (!vmf->page) {
		page = vmalloc_to_page((uint8_t *)vma->vm_private_data + offset);
		pr_info(
			"... associating page %pK physical %lx\n",
			page, page_to_pfn(page));
		get_page(page);
		vmf->page = page;
		return 0;
	}
	return VM_FAULT_SIGBUS;
}

static struct vm_operations_struct mmap_vm_ops = {
	.open = mmap_open,
	.close = mmap_close,
	.fault = mmap_fault,
};

static int mmap_file_open(struct inode *inode, struct file *filp)
{
	uint8_t *data;
	unsigned long index;

	/* Forbid call to seek() */
	nonseekable_open(inode, filp);

	/* Allocate memory which will be mapped */
	data = vzalloc(mapsize);
	if (!data)
		return -ENOMEM;

	/* Fill data with some "meaningful" information */
	snprintf(
		data, mapsize,
		"Hello! Here is file %s\npage size is %lu\n",
		filp->f_dentry->d_name.name, PAGE_SIZE);

	for (index = 1; index < (mapsize >> PAGE_SHIFT); index++) {
		off_t offset = index << PAGE_SHIFT;
		snprintf(
			data + offset, mapsize - offset,
			"Page #%lu begins at %pK\n",
			index, data + offset);
	}

	filp->private_data = data;
	pr_info("File opened, %zu bytes at %pK\n", mapsize, data);
	return 0;
}

static int mmap_file_close(struct inode *inode, struct file *filp)
{
	pr_info("File closed, freeing %pK\n", filp->private_data);
	vfree(filp->private_data);
	filp->private_data = NULL;
	return 0;
}

static int mmap_file_mmap(struct file *filp, struct vm_area_struct *vma)
{
	size_t size = vma->vm_end - vma->vm_start;
	unsigned long pfn;
	int ret;

	if (size > mapsize)
		return -EIO;

	/* Map the first page, using the physical page frame number */
	pfn = vmalloc_to_pfn(filp->private_data);
	pr_info(
		"Mapping first page, user %lx kernel %pK physical %lx\n",
		vma->vm_start, filp->private_data, pfn);
	ret = remap_pfn_range(vma, vma->vm_start, pfn, PAGE_SIZE, vma->vm_page_prot);
	if (ret < 0)
		return ret;

	vma->vm_ops = &mmap_vm_ops;
	vma->vm_flags |= VM_DONTEXPAND | VM_DONTDUMP;
	vma->vm_private_data = filp->private_data;
	mmap_open(vma);
	return 0;
}

static const struct file_operations mmap_file_fops = {
	.owner = THIS_MODULE,
	.open = mmap_file_open,
	.release = mmap_file_close,
	.mmap = mmap_file_mmap,
};

static int __init mmap_file_init(void)
{
	debugfs_file = debugfs_create_file(debugname, 0644, NULL, NULL, &mmap_file_fops);
	if (!debugfs_file) {
		pr_err("Unable to create %s in debugfs.\n", debugname);
		return -EINVAL;
	}
	if (debugfs_file->d_inode) {
		debugfs_file->d_inode->i_size = mapsize;
	}
	pr_info("Created file /sys/kernel/debug/%s\n", debugname);
	return 0;
}

static void __exit mmap_file_exit(void)
{
	debugfs_remove(debugfs_file);
	pr_info("Removed file /sys/kernel/debug/%s\n", debugname);
}

module_init(mmap_file_init);
module_exit(mmap_file_exit);
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Nicolas Iooss");
MODULE_DESCRIPTION("Implement the kernel part of mmap operations on a file");
