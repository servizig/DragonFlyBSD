/*
 * Copyright (c) 2015-2020 François Tigeot <ftigeot@wolfpond.org>
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

#ifndef _LINUX_GFP_H_
#define _LINUX_GFP_H_

#include <linux/mmdebug.h>
#include <linux/mmzone.h>
#include <linux/mm_types.h>
#include <linux/stddef.h>

#include <sys/malloc.h>
#include <vm/vm_page.h>
#include <vm/vm_extern.h>
#include <machine/bus_dma.h>

#define GFP_NOWAIT	(M_NOWAIT | M_CACHEALIGN)
#define GFP_ATOMIC	(M_NOWAIT | M_CACHEALIGN)
#define GFP_KERNEL	(M_WAITOK | M_CACHEALIGN)
#define GFP_TEMPORARY	GFP_KERNEL
#define GFP_USER	GFP_KERNEL
#define GFP_HIGHUSER	GFP_KERNEL

#define __GFP_ZERO		M_ZERO
#define __GFP_NORETRY		M_NULLOK
#define __GFP_RETRY_MAYFAIL	M_NULLOK

#define __GFP_HIGHMEM		0u	/* No particular meaning on DragonFly */
#define __GFP_IO		0u	/* No particular meaning on DragonFly */
#define __GFP_RECLAIM		0u
#define __GFP_RECLAIMABLE	0u
#define __GFP_NOWARN		0u
#define __GFP_NOFAIL		0u

#define __GFP_DMA32	0x10000u	/* XXX: MUST NOT collide with the M_XXX definitions */
#define GFP_DMA32	__GFP_DMA32

static inline void __free_page(struct page *page)
{
	vm_page_t m = (vm_page_t)page;
	void *kptr;

	KKASSERT(m->ext_refs == 0);
	if ((kptr = m->ext_kptr) != NULL) {
		m->ext_kptr = NULL;
		pmap_qremove((vm_offset_t)kptr, 1);
		kmem_free(kernel_map, (vm_offset_t)kptr, PAGE_SIZE);
	}
	vm_page_free_contig((struct vm_page *)page, PAGE_SIZE);
}

static inline struct page *
alloc_page(int flags)
{
	vm_paddr_t high = BUS_SPACE_MAXADDR;

	if (flags & GFP_DMA32)
		high = BUS_SPACE_MAXADDR_32BIT;
//	return (struct page *)vm_page_alloczwq(0, VM_ALLOC_NORMAL | VM_ALLOC_SYSTEM |
//				  VM_ALLOC_INTERRUPT);
	return (struct page *)vm_page_alloc_contig(0LLU, high,
						   PAGE_SIZE, PAGE_SIZE, PAGE_SIZE,
						   VM_MEMATTR_DEFAULT);
}

static inline bool
gfpflags_allow_blocking(const gfp_t flags)
{
	return (flags & M_WAITOK);
}

/*
 * Allocate multiple contiguous pages. The DragonFly code can only do
 * multiple allocations via the free page reserve.  Linux does not appear
 * to restrict the address space, so neither do we.
 */
static inline struct page *
alloc_pages(gfp_t flags, unsigned int order)
{
	size_t bytes = PAGE_SIZE << order;
	struct vm_page *pgs;
	vm_paddr_t high = BUS_SPACE_MAXADDR;

	if (flags & GFP_DMA32)
		high = BUS_SPACE_MAXADDR_32BIT;

	/* lo, hi, align, boundary, size, memattr */
	pgs = vm_page_alloc_contig(0LLU, high, bytes, bytes, bytes,
				   VM_MEMATTR_DEFAULT);

	return (struct page*)pgs;
}

/*
 * Free multiple contiguous pages
 */
static inline void
__free_pages(struct page *pgs, unsigned int order)
{
	size_t pgcount = 1 << order;
	size_t i;
	vm_page_t m;
	void *kptr;

	for (i = 0; i < pgcount; ++i) {
		m = (vm_page_t)&pgs[i];

		KKASSERT(m->ext_refs == 0);
		if ((kptr = m->ext_kptr) != NULL) {
			m->ext_kptr = NULL;
			pmap_qremove((vm_offset_t)kptr, 1);
			kmem_free(kernel_map, (vm_offset_t)kptr, PAGE_SIZE);
		}
	}
	vm_page_free_contig((struct vm_page *)pgs, PAGE_SIZE * pgcount);
}

#endif	/* _LINUX_GFP_H_ */
