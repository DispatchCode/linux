#include <linux/syscalls.h>
#include <linux/mm.h>
#include <linux/kernel.h>
#include <linux/vminfo.h>
#include <linux/pgtable.h>
#include <linux/slab.h>
#include <linux/highmem.h>

#include <asm/processor.h>
#include <asm/io.h>
#include <asm/page.h>


static int bad_address(void *p)
{
	unsigned long dummy;

	return get_kernel_nofault(dummy, (unsigned long *)p);
}

static int get_pte(struct mm_struct *mm, unsigned long address, struct vminfo_struct *vminfo_kern, pte_t *pte_v) {
        pgd_t *pgd;
        p4d_t *p4d;
        pud_t *pud;
        pmd_t *pmd;
        pte_t *pte;

	pgd = pgd_offset(mm, address);

        if(pgd_none(*pgd) || unlikely(pgd_bad(*pgd)))
                return -EINVAL;

        p4d = p4d_offset(pgd, address);
        if(p4d_none(*p4d) || unlikely(p4d_bad(*p4d)))
                return -EINVAL;

        pud = pud_offset(p4d, address);
        if(pud_none(*pud) || unlikely(pud_bad(*pud)))
                return -EINVAL;

        pmd = pmd_offset(pud, address);
        if(pmd_none(*pmd) || unlikely(pmd_bad(*pmd)))
                return -EINVAL;

        pte = pte_offset_kernel(pmd, address);
        if(bad_address(pte))
                return -EINVAL;

        vminfo_kern->pgd = pgd_val(*pgd);
        vminfo_kern->p4d = p4d_val(*p4d);
        vminfo_kern->pud = pud_val(*pud);
        vminfo_kern->pmd = pmd_val(*pmd);
        vminfo_kern->pte = pte_val(*pte);
	
	*pte_v = *pte;

	return 0;
}

static int read_at_page_offset(unsigned long address, unsigned long addr_size, pte_t pte_v, struct vminfo_struct *vminfo_kern) {
	size_t offset;
	void *kaddr;
        
	kaddr = kmap_local_page(pfn_to_page(pte_pfn(pte_v)));

        if(!kaddr) {
                return -ENOMEM;
        }

        offset = address & (PAGE_SIZE - 1);
        memcpy(&vminfo_kern->value, kaddr + offset, addr_size);

        kunmap_local(kaddr);

	return 0;
}

SYSCALL_DEFINE4(vminfo, unsigned long, address, unsigned long, addr_size, pid_t, pid, struct vminfo_struct __user *, vminfo) {
	pr_info("vminfo SYSCALL, pid %d address %lu",pid,address);
	
	struct vminfo_struct vminfo_tmp;
	struct task_struct *task;
	pte_t pte_v;
	int err;

	task = pid_task(find_vpid(pid), PIDTYPE_PID);
	if(!task) {
		err = -ESRCH;
		goto error;
	}

	pr_info("Task status: %lu", task->__state);
	get_task_struct(task);

	if(get_pte(task->mm, address, &vminfo_tmp, &pte_v)) {
		err = -EINVAL;
		goto error;
	}

	if(read_at_page_offset(address, addr_size, pte_v, &vminfo_tmp)) {
		err = -ENOMEM;
		goto error;
	}

	put_task_struct(task);

	pr_info("Read from memory: %lu", vminfo_tmp.value);

	if(copy_to_user(vminfo, &vminfo_tmp, sizeof(vminfo_tmp))) {
		return -EFAULT;
	}	

	pr_info("Copy to user worked successfully");

	return 0;

error:
	pr_err("SYSCALL_VMINFO error: %d", err);
	put_task_struct(task);
	return err;

}
