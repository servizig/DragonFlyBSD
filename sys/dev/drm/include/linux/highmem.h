/*
 * Copyright (c) 2014-2020 François Tigeot <ftigeot@wolfpond.org>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice unmodified, this list of conditions, and the following
 *    disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#ifndef _LINUX_HIGHMEM_H_
#define _LINUX_HIGHMEM_H_

#include <machine/vmparam.h>

#include <linux/kernel.h>
#include <linux/bug.h>
#include <linux/mm.h>
#include <linux/uaccess.h>
#include <linux/hardirq.h>

#include <asm/cacheflush.h>

#include <vm/vm_extern.h>

static inline struct page *
kmap_to_page(void *addr)
{
	if (addr == NULL)
		return NULL;

	return (struct page *)PHYS_TO_VM_PAGE(vtophys(addr));
}

static inline void *kmap(struct page *pg)
{
	vm_page_t ary[1];
	void *kptr;

	ary[0] = &pg->pa_vmpage;
	atomic_add_int(&pg->pa_vmpage.ext_refs, 1);
	while ((kptr = pg->pa_vmpage.ext_kptr) == NULL) {
		kptr = (void *)kmem_alloc_nofault(kernel_map,
						  PAGE_SIZE,
						  VM_SUBSYS_DRM_VMAP,
						  PAGE_SIZE);
		//pmap_qenter((vm_offset_t)kptr, ary, 1);
		pmap_qenter_memattr((vm_offset_t)kptr, ary, 1,
				    VM_MEMATTR_UNCACHEABLE);
		if (atomic_cmpset_ptr(&pg->pa_vmpage.ext_kptr, NULL, kptr))
			break;
		pmap_qremove(kptr, 1);
		kmem_free(kernel_map, kptr, PAGE_SIZE);
	}
	return kptr;
}

static inline void kunmap(struct page *pg)
{
#if 0
	atomic_add_int(&pg->pa_vmpage.ext_refs, -1);
	/* leave kptr cached */
#else
	void *kptr;
	if (atomic_fetchadd_int(&pg->pa_vmpage.ext_refs, -1) == 1) {
		kptr = atomic_swap_ptr((void *)&pg->pa_vmpage.ext_kptr, NULL);
		if (kptr) {
			pmap_qremove(kptr, 1);
			kmem_free(kernel_map, kptr, PAGE_SIZE);
		}
	}
#endif
}

/*
 * kmap_atomic() / kunmap_atomic() maps a page to kernel memory.  Because
 * kunmap_atomic() stupidly takes only a memory pointer, we must allocate
 * custom space for each call.
 *
 * It does not appear that callers expect the returned area to always
 * be in a special cache mode.
 *
 * It doesn't look like we can assume cpu-localized map/unmap here,
 * use a regular qenter.
 */
static inline void *kmap_atomic(struct page *pg)
{
	vm_page_t ary[1];
	void *kptr;

	ary[0] = &pg->pa_vmpage;
	kptr = (void *)kmem_alloc_nofault(kernel_map,
					  PAGE_SIZE,
					  VM_SUBSYS_DRM_VMAP,
					  PAGE_SIZE);
	pmap_qenter/*_quick[_memattr]*/((vm_offset_t)kptr, ary, 1);
	//pmap_qenter_memattr(kptr, ary, 1, VM_MEMATTR_UNCACHEABLE); /* YYY */
	return kptr;
}

/*
 * NOTE: prot is pgflags
 * NOTE: use case is cpu-localized
 */
static inline void *
kmap_atomic_prot(struct page *pg, pgprot_t prot)
{
	vm_page_t ary[1];
	void *kptr;

	ary[0] = &pg->pa_vmpage;
	kptr = (void *)kmem_alloc_nofault(kernel_map,
					  PAGE_SIZE,
					  VM_SUBSYS_DRM_VMAP,
					  PAGE_SIZE);
	pmap_qenter_quick_memattr((vm_offset_t)kptr, ary, 1,
					   pgflags_to_memattr(prot)); 
					   //VM_MEMATTR_UNCACHEABLE); /* YYY */
	return kptr;
}

static inline void
kunmap_atomic(void *vaddr)
{
	pmap_qremove(vaddr, 1);
	kmem_free(kernel_map, vaddr, PAGE_SIZE);
}

/*
 * Quickly map a page for temporary use on the current cpu for a short while,
 * using the given memory attribute.
 *
 * NOTE: This enters a critical section
 */
static inline void *
kmap_atomic_quick(struct page *pg, pgprot_t prot)
{
	vm_page_t m = (vm_page_t)pg;

	return ((void *)pmap_tempmap_enter(VM_PAGE_TO_PHYS(m),
					   pgflags_to_memattr(prot)));
					   //VM_MEMATTR_UNCACHEABLE)); /* YYY */
}

/*
 * Undo the effects of kmap_atomic_quick().
 *
 * NOTE: This exits a critical section.
 */
static inline void
kunmap_atomic_quick(void)
{
	pmap_tempmap_exit();
}

#endif	/* _LINUX_HIGHMEM_H_ */
