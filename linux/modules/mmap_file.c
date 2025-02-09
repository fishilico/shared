// SPDX-License-Identifier: GPL-2.0
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
#include <linux/version.h>
#include <linux/vmalloc.h>

/* Linux between 3.2 and 3.6 has VM_NODUMP, and VM_DONTDUMP since 3.7 */
#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 7, 0)
#define VM_DONTDUMP 0
#endif

static unsigned long mapsize = PAGE_SIZE << 4;
module_param(mapsize, ulong, 0444);
MODULE_PARM_DESC(mapsize, "Size of the mmap'ed data");

static char *debugname = "mmap_file";
module_param(debugname, charp, 0444);
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

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 1, 0)
/* Commit 3d3539018d2c ("mm: create the new vm_fault_t type") made vm_fault_t
 * unsigned, which is incompatible with previous versions
 */
static vm_fault_t mmap_fault(struct vm_fault *vmf)
{
	struct vm_area_struct *vma = vmf->vma;
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(4, 11, 0)
/* Commit 11bac8000449 ("mm, fs: reduce fault, page_mkwrite, and pfn_mkwrite to
 * take only vmf") remove vma parameter in Linux 4.11
 */
static int mmap_fault(struct vm_fault *vmf)
{
	struct vm_area_struct *vma = vmf->vma;
#else
static int mmap_fault(struct vm_area_struct *vma, struct vm_fault *vmf)
{
#endif
	struct page *page;
	off_t offset = vmf->pgoff << PAGE_SHIFT;


#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 10, 0)
	/* Commit 1a29d85eb0f1 ("mm: use vmf->address instead of of
	 * vmf->virtual_address") removed virtual_address from struct vm_fault
	 * in favor of address in Linux 4.10
	 */
	pr_info(
		"Mmap fault occurred on page %lu, userspace address %lx\n",
		vmf->pgoff, vmf->address);
#else
	pr_info(
		"Mmap fault occurred on page %lu, userspace address %p\n",
		vmf->pgoff, vmf->virtual_address);
#endif

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

static const struct vm_operations_struct mmap_vm_ops = {
	.open = mmap_open,
	.close = mmap_close,
	.fault = mmap_fault,
};

static int mmap_file_open(struct inode *inode, struct file *filp)
{
	uint8_t *data;
	unsigned long index;
	struct qstr *filename;

	/* Forbid call to seek() */
	nonseekable_open(inode, filp);

	/* Allocate memory which will be mapped */
	data = vzalloc(mapsize);
	if (!data)
		return -ENOMEM;

	/* Fill data with some "meaningful" information */
	filename = &filp->f_path.dentry->d_name;
	snprintf(
		data, mapsize,
		"Hello! Here is file %*s\npage size is %lu\n",
		filename->len, filename->name, PAGE_SIZE);

	for (index = 1; index < (mapsize >> PAGE_SHIFT); index++) {
		off_t offset = index << PAGE_SHIFT;

		snprintf(
			data + offset, mapsize - offset,
			"Page #%lu begins at %pK\n",
			index, data + offset);
	}

	filp->private_data = data;
	pr_info("File opened, %lu bytes at %pK\n", mapsize, data);
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
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)
	/* Commit bc292ab00f6c ("mm: introduce vma->vm_flags wrapper functions")
	 * replaced vma->vm_flags with helpers, to prevent race conditions.
	 */
	vm_flags_set(vma, VM_DONTEXPAND | VM_DONTDUMP);
#else
	vma->vm_flags |= VM_DONTEXPAND | VM_DONTDUMP;
#endif
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
#if LINUX_VERSION_CODE < (IS_ENABLED(CONFIG_DEBUG_FS) ? KERNEL_VERSION(4, 7, 0) : KERNEL_VERSION(4, 14, 0))
	/* Commit 149d200deaa68 ("debugfs: prevent access to removed files'
	 * private data") introduced a file operation proxy which does not
	 * support mmap(). Using an "unsafe" debugfs file is needed to make
	 * mmap() works with Linux 4.7.
	 * Commit 8dc6d81c6b2ac ("debugfs: add small file operations for most files"
	 * introduced a macro named debugfs_create_file, so it is not possible to
	 * just define debugfs_create_file to debugfs_create_file_unsafe, since
	 * Linux 6.13. Instead, define a macro the other way round, to ensure
	 * maximum compatibility.
	 * Unfortunately, the dummy implementation of debugfs_create_file_unsafe
	 * when CONFIG_DEBUG_FS is unset was introduced later, in Linux 4.14, by
	 * commit c2a737eb2ea5 ("debugfs: Add dummy implementation of few helpers").
	 */
#define debugfs_create_file_unsafe debugfs_create_file
#endif
	if (!IS_ENABLED(CONFIG_DEBUG_FS)) {
		pr_err("debugfs support is needed but not enabled.\n");
		return -ENODEV;
	}
	debugfs_file = debugfs_create_file_unsafe(debugname, 0644, NULL, NULL, &mmap_file_fops);
	if (!debugfs_file || IS_ERR(debugfs_file)) {
		pr_err("Unable to create %s in debugfs.\n", debugname);
		return -EINVAL;
	}
	if (debugfs_file->d_inode)
		debugfs_file->d_inode->i_size = mapsize;

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
