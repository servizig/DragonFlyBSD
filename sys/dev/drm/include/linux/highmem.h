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

static inline struct page *
kmap_to_page(void *addr)
{
	if (addr == NULL)
		return NULL;

	return (struct page *)PHYS_TO_VM_PAGE(vtophys(addr));
}

static inline void *kmap(struct page *pg)
{
kprintf("kmap\n");
	return (void *)PHYS_TO_DMAP(VM_PAGE_TO_PHYS( (struct vm_page *)pg ));
}

static inline void kunmap(struct page *pg)
{
	/* Nothing to do on systems with a direct memory map */
}

static inline void *kmap_atomic(struct page *pg)
{
kprintf("kmap_atomic\n");
	return (void *)PHYS_TO_DMAP(VM_PAGE_TO_PHYS( (struct vm_page *)pg ));
}

static inline void *
kmap_atomic_prot(struct page *pg, pgprot_t prot)
{
	return kmap_atomic(pg);
}

static inline void kunmap_atomic(void *vaddr)
{
	/* Nothing to do on systems with a direct memory map */
}

#endif	/* _LINUX_HIGHMEM_H_ */
