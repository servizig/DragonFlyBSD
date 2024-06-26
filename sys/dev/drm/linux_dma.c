/*
 * Copyright (c) 2016 Sascha Wildner <saw@online.de>
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

#include <linux/dma-mapping.h>

#include <vm/vm_extern.h>

void *
dma_alloc_coherent(struct device *dev, size_t size, dma_addr_t *dma_handle,
    gfp_t flag)
{
	vm_paddr_t high;
	size_t align;
	void *mem;

#if 0 /* XXX swildner */
	if (dev->dma_mask)
		high = *dev->dma_mask;
	else
#endif
		high = BUS_SPACE_MAXADDR_32BIT;
	align = PAGE_SIZE << get_order(size);
	mem = (void *)kmem_alloc_contig(size, 0, high, align);
	if (mem)
		*dma_handle = vtophys(mem);
	else
		*dma_handle = 0;
	return (mem);
}

#if 0
#include <linux/radix-tree.h>

struct linux_dma_priv {
	uint64_t	dma_mask;
	bus_dma_tag_t	dmat;
	uint64_t	dma_coherent_mask;
	bus_dma_tag_t	dmat_coherent;
	struct lock	lock;
	struct radix_tree_root	ptree;
};

#define	DMA_PRIV_LOCK(priv) lockmgr(&(priv)->lock, LK_EXCLUSIVE)
#define	DMA_PRIV_UNLOCK(priv) lockmgr(&(priv)->lock, LK_RELEASE)

static dma_addr_t
linux_dma_map_phys_common(struct device *dev, vm_paddr_t phys, size_t len,
    bus_dma_tag_t dmat)
{
	struct linux_dma_priv *priv;
	struct linux_dma_obj *obj;
	int error, nseg;
	bus_dma_segment_t seg;

	priv = dev->dma_priv;

	/*
	 * If the resultant mapping will be entirely 1:1 with the
	 * physical address, short-circuit the remainder of the
	 * bus_dma API.  This avoids tracking collisions in the pctrie
	 * with the additional benefit of reducing overhead.
	 */
	if (bus_dma_id_mapped(dmat, phys, len))
		return (phys);

	obj = uma_zalloc(linux_dma_obj_zone, M_NOWAIT);
	if (obj == NULL) {
		return (0);
	}
	obj->dmat = dmat;

	DMA_PRIV_LOCK(priv);
	if (bus_dmamap_create(obj->dmat, 0, &obj->dmamap) != 0) {
		DMA_PRIV_UNLOCK(priv);
		uma_zfree(linux_dma_obj_zone, obj);
		return (0);
	}

	nseg = -1;
	if (_bus_dmamap_load_phys(obj->dmat, obj->dmamap, phys, len,
	    BUS_DMA_NOWAIT, &seg, &nseg) != 0) {
		bus_dmamap_destroy(obj->dmat, obj->dmamap);
		DMA_PRIV_UNLOCK(priv);
		uma_zfree(linux_dma_obj_zone, obj);
		counter_u64_add(lkpi_pci_nseg1_fail, 1);
#if 0
		if (linuxkpi_debug)
			dump_stack();
#endif
		return (0);
	}

	KASSERT(++nseg == 1, ("More than one segment (nseg=%d)", nseg));
	obj->dma_addr = seg.ds_addr;

	error = radix_tree_insert(&priv->ptree, obj);
	if (error != 0) {
		bus_dmamap_unload(obj->dmat, obj->dmamap);
		bus_dmamap_destroy(obj->dmat, obj->dmamap);
		DMA_PRIV_UNLOCK(priv);
		uma_zfree(linux_dma_obj_zone, obj);
		return (0);
	}
	DMA_PRIV_UNLOCK(priv);
	return (obj->dma_addr);
}

void *
dma_alloc_coherent(struct device *dev, size_t size,
    dma_addr_t *dma_handle, gfp_t flag)
{
	struct linux_dma_priv *priv;
	vm_paddr_t high;
	size_t align;
	void *mem;

	if (dev == NULL || dev->dma_priv == NULL) {
		*dma_handle = 0;
		return (NULL);
	}
	priv = dev->dma_priv;
	if (priv->dma_coherent_mask)
		high = priv->dma_coherent_mask;
	else
		/* Coherent is lower 32bit only by default in Linux. */
		high = BUS_SPACE_MAXADDR_32BIT;
	align = PAGE_SIZE << get_order(size);
	/* Always zero the allocation. */
	flag |= M_ZERO;
	mem = kmem_alloc_contig(size, 0, high, align);
	if (mem != NULL) {
		*dma_handle = linux_dma_map_phys_common(dev, vtophys(mem), size,
		    priv->dmat_coherent);
		if (*dma_handle == 0) {
			kmem_free(mem, 0, size);
			mem = NULL;
		}
	} else {
		*dma_handle = 0;
	}
	return (mem);
}

#endif

void
dma_free_coherent(struct device *dev, size_t size, void *cpu_addr,
    dma_addr_t dma_handle)
{

	kmem_free(kernel_map, (vm_offset_t)cpu_addr, size);
}
