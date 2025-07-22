/*
 * Copyright (c) 2003-2019 The DragonFly Project.  All rights reserved.
 * Copyright (c) 1991 Regents of the University of California.
 * All rights reserved.
 *
 * This code is derived from software contributed to Berkeley by
 * The Mach Operating System project at Carnegie-Mellon University.
 *
 * This code is derived from software contributed to The DragonFly Project
 * by Matthew Dillon <dillon@backplane.com>
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 *	from: @(#)vm_page.c	7.4 (Berkeley) 5/7/91
 * $FreeBSD: src/sys/vm/vm_page.c,v 1.147.2.18 2002/03/10 05:03:19 alc Exp $
 */

/*
 * Copyright (c) 1987, 1990 Carnegie-Mellon University.
 * All rights reserved.
 *
 * Authors: Avadis Tevanian, Jr., Michael Wayne Young
 *
 * Permission to use, copy, modify and distribute this software and
 * its documentation is hereby granted, provided that both the copyright
 * notice and this permission notice appear in all copies of the
 * software, derivative works or modified versions, and any portions
 * thereof, and that both notices appear in supporting documentation.
 *
 * CARNEGIE MELLON ALLOWS FREE USE OF THIS SOFTWARE IN ITS "AS IS"
 * CONDITION.  CARNEGIE MELLON DISCLAIMS ANY LIABILITY OF ANY KIND
 * FOR ANY DAMAGES WHATSOEVER RESULTING FROM THE USE OF THIS SOFTWARE.
 *
 * Carnegie Mellon requests users of this software to return to
 *
 *  Software Distribution Coordinator  or  Software.Distribution@CS.CMU.EDU
 *  School of Computer Science
 *  Carnegie Mellon University
 *  Pittsburgh PA 15213-3890
 *
 * any improvements or extensions that they make and grant Carnegie the
 * rights to redistribute these changes.
 */
/*
 * Resident memory management module.  The module manipulates 'VM pages'.
 * A VM page is the core building block for memory management.
 */

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/malloc.h>
#include <sys/proc.h>
#include <sys/vmmeter.h>
#include <sys/vnode.h>
#include <sys/kernel.h>
#include <sys/alist.h>
#include <sys/sysctl.h>
#include <sys/cpu_topology.h>

#include <vm/vm.h>
#include <vm/vm_param.h>
#include <sys/lock.h>
#include <vm/vm_kern.h>
#include <vm/pmap.h>
#include <vm/vm_map.h>
#include <vm/vm_object.h>
#include <vm/vm_page.h>
#include <vm/vm_pageout.h>
#include <vm/vm_pager.h>
#include <vm/vm_extern.h>
#include <vm/swap_pager.h>

#include <machine/inttypes.h>
#include <machine/md_var.h>
#include <machine/specialreg.h>
#include <machine/bus_dma.h>

#include <vm/vm_page2.h>
#include <sys/spinlock2.h>

/*
 * Cache necessary elements in the hash table itself to avoid indirecting
 * through random vm_page's when doing a lookup.  The hash table is
 * heuristical and it is ok for races to mess up any or all fields.
 */
struct vm_page_hash_elm {
	vm_page_t	m;
	vm_object_t	object;	/* heuristical */
	vm_pindex_t	pindex;	/* heuristical */
	int		ticks;
	int		unused;
};

#define VM_PAGE_HASH_SET	4		    /* power of 2, set-assoc */
#define VM_PAGE_HASH_MAX	(8 * 1024 * 1024)   /* power of 2, max size */

/*
 * SET - Minimum required set associative size, must be a power of 2.  We
 *	 want this to match or exceed the set-associativeness of the cpu,
 *	 up to a reasonable limit (we will use 16).
 */
__read_mostly static int set_assoc_mask = 16 - 1;

static void vm_page_queue_init(void);
static void vm_page_free_wakeup(void);
static vm_page_t vm_page_select_cache(u_short pg_color);
static vm_page_t _vm_page_list_find_wide(int basequeue, int index, int *lastp);
static vm_page_t _vm_page_list_find2_wide(int bq1, int bq2, int index,
			int *lastp1, int *lastp);
static void _vm_page_deactivate_locked(vm_page_t m, int athead);
static void vm_numa_add_topology_mem(cpu_node_t *cpup, int physid, long bytes);

/*
 * Array of tailq lists
 */
struct vpgqueues vm_page_queues[PQ_COUNT];

static volatile int vm_pages_waiting;
static struct alist vm_contig_alist;
static struct almeta vm_contig_ameta[ALIST_RECORDS_1048576];
static struct spinlock vm_contig_spin = SPINLOCK_INITIALIZER(&vm_contig_spin, "vm_contig_spin");

__read_mostly static int vm_page_hash_vnode_only;
__read_mostly static int vm_page_hash_size;
__read_mostly static struct vm_page_hash_elm *vm_page_hash;

static u_long vm_dma_reserved = 0;
TUNABLE_ULONG("vm.dma_reserved", &vm_dma_reserved);
SYSCTL_ULONG(_vm, OID_AUTO, dma_reserved, CTLFLAG_RD, &vm_dma_reserved, 0,
	    "Memory reserved for DMA");
SYSCTL_UINT(_vm, OID_AUTO, dma_free_pages, CTLFLAG_RD,
	    &vm_contig_alist.bl_free, 0, "Memory reserved for DMA");

SYSCTL_INT(_vm, OID_AUTO, page_hash_vnode_only, CTLFLAG_RW,
	    &vm_page_hash_vnode_only, 0, "Only hash vnode pages");
#if 0
static int vm_page_hash_debug;
SYSCTL_INT(_vm, OID_AUTO, page_hash_debug, CTLFLAG_RW,
	    &vm_page_hash_debug, 0, "Only hash vnode pages");
#endif

static int vm_contig_verbose = 0;
TUNABLE_INT("vm.contig_verbose", &vm_contig_verbose);

RB_GENERATE2(vm_page_rb_tree, vm_page, rb_entry, rb_vm_page_compare,
	     vm_pindex_t, pindex);

static void
vm_page_queue_init(void) 
{
	int i;

	for (i = 0; i < PQ_L2_SIZE; i++)
		vm_page_queues[PQ_FREE+i].cnt_offset =
			offsetof(struct vmstats, v_free_count);
	for (i = 0; i < PQ_L2_SIZE; i++)
		vm_page_queues[PQ_CACHE+i].cnt_offset =
			offsetof(struct vmstats, v_cache_count);
	for (i = 0; i < PQ_L2_SIZE; i++)
		vm_page_queues[PQ_INACTIVE+i].cnt_offset =
			offsetof(struct vmstats, v_inactive_count);
	for (i = 0; i < PQ_L2_SIZE; i++)
		vm_page_queues[PQ_ACTIVE+i].cnt_offset =
			offsetof(struct vmstats, v_active_count);
	for (i = 0; i < PQ_L2_SIZE; i++)
		vm_page_queues[PQ_HOLD+i].cnt_offset =
			offsetof(struct vmstats, v_active_count);
	/* PQ_NONE has no queue */

	for (i = 0; i < PQ_COUNT; i++) {
		struct vpgqueues *vpq;

		vpq = &vm_page_queues[i];
		vpq->lastq = -1;
		TAILQ_INIT(&vpq->pl);
		spin_init(&vpq->spin, "vm_page_queue_init");
	}
}

/*
 * note: place in initialized data section?  Is this necessary?
 */
vm_pindex_t first_page = 0;
vm_pindex_t vm_page_array_size = 0;
vm_page_t vm_page_array = NULL;
vm_paddr_t vm_low_phys_reserved;

/*
 * (low level boot)
 *
 * Sets the page size, perhaps based upon the memory size.
 * Must be called before any use of page-size dependent functions.
 */
void
vm_set_page_size(void)
{
	if (vmstats.v_page_size == 0)
		vmstats.v_page_size = PAGE_SIZE;
	if (((vmstats.v_page_size - 1) & vmstats.v_page_size) != 0)
		panic("vm_set_page_size: page size not a power of two");
}

/*
 * (low level boot)
 *
 * Add a new page to the freelist for use by the system.  New pages
 * are added to both the head and tail of the associated free page
 * queue in a bottom-up fashion, so both zero'd and non-zero'd page
 * requests pull 'recent' adds (higher physical addresses) first.
 *
 * Beware that the page zeroing daemon will also be running soon after
 * boot, moving pages from the head to the tail of the PQ_FREE queues.
 *
 * Must be called in a critical section.
 */
static void
vm_add_new_page(vm_paddr_t pa, int *badcountp)
{
	struct vpgqueues *vpq;
	vm_page_t m;

	m = PHYS_TO_VM_PAGE(pa);

	/*
	 * Make sure it isn't a duplicate (due to BIOS page range overlaps,
	 * which we consider bugs... but don't crash).  Note that m->phys_addr
	 * is pre-initialized, so use m->queue as a check.
	 */
	if (m->flags & PG_ADDED) {
		if (*badcountp < 10) {
			kprintf("vm_add_new_page: duplicate pa %016jx\n",
				(intmax_t)pa);
			++*badcountp;
		} else if (*badcountp == 10) {
			kprintf("vm_add_new_page: duplicate pa (many more)\n");
			++*badcountp;
		}
		return;
	}

	m->phys_addr = pa;
	m->flags = PG_ADDED;
	m->pat_mode = PAT_WRITE_BACK;
	m->pc = (pa >> PAGE_SHIFT);

	/*
	 * Twist for cpu localization in addition to page coloring, so
	 * different cpus selecting by m->queue get different page colors.
	 */
	m->pc ^= ((pa >> PAGE_SHIFT) / PQ_L2_SIZE);
	m->pc ^= ((pa >> PAGE_SHIFT) / (PQ_L2_SIZE * PQ_L2_SIZE));
	m->pc &= PQ_L2_MASK;

	/*
	 * Reserve a certain number of contiguous low memory pages for
	 * contigmalloc() to use.
	 *
	 * Even though these pages represent real ram and can be
	 * reverse-mapped, we set PG_FICTITIOUS and PG_UNQUEUED
	 * because their use is special-cased.
	 *
	 * WARNING! Once PG_FICTITIOUS is set, vm_page_wire*()
	 *	    and vm_page_unwire*() calls have no effect.
	 */
	if (pa < vm_low_phys_reserved) {
		atomic_add_long(&vmstats.v_page_count, 1);
		atomic_add_long(&vmstats.v_dma_pages, 1);
		m->flags |= PG_FICTITIOUS | PG_UNQUEUED;
		m->queue = PQ_NONE;
		m->wire_count = 1;
		atomic_add_long(&vmstats.v_wire_count, 1);
		alist_free(&vm_contig_alist, pa >> PAGE_SHIFT, 1);
	} else {
		/*
		 * General page
		 */
		m->queue = m->pc + PQ_FREE;
		KKASSERT(m->dirty == 0);

		atomic_add_long(&vmstats.v_page_count, 1);
		atomic_add_long(&vmstats.v_free_count, 1);
		vpq = &vm_page_queues[m->queue];
		TAILQ_INSERT_HEAD(&vpq->pl, m, pageq);
		++vpq->lcnt;
	}
}

/*
 * (low level boot)
 *
 * Initializes the resident memory module.
 *
 * Preallocates memory for critical VM structures and arrays prior to
 * kernel_map becoming available.
 *
 * Memory is allocated from (virtual2_start, virtual2_end) if available,
 * otherwise memory is allocated from (virtual_start, virtual_end).
 *
 * On x86-64 (virtual_start, virtual_end) is only 2GB and may not be
 * large enough to hold vm_page_array & other structures for machines with
 * large amounts of ram, so we want to use virtual2* when available.
 */
void
vm_page_startup(void)
{
	vm_offset_t vaddr = virtual2_start ? virtual2_start : virtual_start;
	vm_offset_t mapped;
	vm_pindex_t npages;
	vm_paddr_t page_range;
	vm_paddr_t new_end;
	int i;
	vm_paddr_t pa;
	vm_paddr_t last_pa;
	vm_paddr_t end;
	vm_paddr_t biggestone, biggestsize;
	vm_paddr_t total;
	vm_page_t m;
	int badcount;

	total = 0;
	badcount = 0;
	biggestsize = 0;
	biggestone = 0;
	vaddr = round_page(vaddr);

	/*
	 * Make sure ranges are page-aligned.
	 */
	for (i = 0; phys_avail[i].phys_end; ++i) {
		phys_avail[i].phys_beg = round_page64(phys_avail[i].phys_beg);
		phys_avail[i].phys_end = trunc_page64(phys_avail[i].phys_end);
		if (phys_avail[i].phys_end < phys_avail[i].phys_beg)
			phys_avail[i].phys_end = phys_avail[i].phys_beg;
	}

	/*
	 * Locate largest block
	 */
	for (i = 0; phys_avail[i].phys_end; ++i) {
		vm_paddr_t size = phys_avail[i].phys_end -
				  phys_avail[i].phys_beg;

		if (size > biggestsize) {
			biggestone = i;
			biggestsize = size;
		}
		total += size;
	}
	--i;	/* adjust to last entry for use down below */

	end = phys_avail[biggestone].phys_end;
	end = trunc_page(end);

	/*
	 * Initialize the queue headers for the free queue, the active queue
	 * and the inactive queue.
	 */
	vm_page_queue_init();

#if !defined(_KERNEL_VIRTUAL)
	/*
	 * VKERNELs don't support minidumps and as such don't need
	 * vm_page_dump
	 *
	 * Allocate a bitmap to indicate that a random physical page
	 * needs to be included in a minidump.
	 *
	 * The amd64 port needs this to indicate which direct map pages
	 * need to be dumped, via calls to dump_add_page()/dump_drop_page().
	 *
	 * However, x86 still needs this workspace internally within the
	 * minidump code.  In theory, they are not needed on x86, but are
	 * included should the sf_buf code decide to use them.
	 */
	page_range = phys_avail[i].phys_end / PAGE_SIZE;
	vm_page_dump_size = round_page(roundup2(page_range, NBBY) / NBBY);
	end -= vm_page_dump_size;
	vm_page_dump = (void *)pmap_map(&vaddr, end, end + vm_page_dump_size,
					VM_PROT_READ | VM_PROT_WRITE);
	bzero((void *)vm_page_dump, vm_page_dump_size);
#endif
	/*
	 * Compute the number of pages of memory that will be available for
	 * use (taking into account the overhead of a page structure per
	 * page).
	 */
	first_page = phys_avail[0].phys_beg / PAGE_SIZE;
	page_range = phys_avail[i].phys_end / PAGE_SIZE - first_page;
	npages = (total - (page_range * sizeof(struct vm_page))) / PAGE_SIZE;

#ifndef _KERNEL_VIRTUAL
	/*
	 * (only applies to real kernels)
	 *
	 * Reserve a large amount of low memory for potential 32-bit DMA
	 * space allocations.  Once device initialization is complete we
	 * release most of it, but keep (vm_dma_reserved) memory reserved
	 * for later use.  Typically for X / graphics.  Through trial and
	 * error we find that GPUs usually requires ~60-100MB or so.
	 *
	 * By default, 128M is left in reserve on machines with 2G+ of ram.
	 */
	vm_low_phys_reserved = (vm_paddr_t)524288 << PAGE_SHIFT;
	if (vm_low_phys_reserved > total / 4)
		vm_low_phys_reserved = total / 4;
	if (vm_dma_reserved == 0) {
		vm_dma_reserved = 128 * 1024 * 1024;	/* 128MB */
		if (vm_dma_reserved > total / 16)
			vm_dma_reserved = total / 16;
	}
#endif
	alist_init(&vm_contig_alist, 1048576, vm_contig_ameta,
		   ALIST_RECORDS_1048576);

	/*
	 * Initialize the mem entry structures now, and put them in the free
	 * queue.
	 */
	if (bootverbose && ctob(physmem) >= 400LL*1024*1024*1024)
		kprintf("initializing vm_page_array ");
	new_end = trunc_page(end - page_range * sizeof(struct vm_page));
	mapped = pmap_map(&vaddr, new_end, end, VM_PROT_READ | VM_PROT_WRITE);
	vm_page_array = (vm_page_t)mapped;

#if defined(__x86_64__) && !defined(_KERNEL_VIRTUAL)
	/*
	 * since pmap_map on amd64 returns stuff out of a direct-map region,
	 * we have to manually add these pages to the minidump tracking so
	 * that they can be dumped, including the vm_page_array.
	 */
	for (pa = new_end;
	     pa < phys_avail[biggestone].phys_end;
	     pa += PAGE_SIZE) {
		dump_add_page(pa);
	}
#endif

	/*
	 * Clear all of the page structures, run basic initialization so
	 * PHYS_TO_VM_PAGE() operates properly even on pages not in the
	 * map.
	 */
	bzero((caddr_t) vm_page_array, page_range * sizeof(struct vm_page));
	vm_page_array_size = page_range;
	if (bootverbose && ctob(physmem) >= 400LL*1024*1024*1024)
		kprintf("size = 0x%zx\n", vm_page_array_size);

	m = &vm_page_array[0];
	pa = ptoa(first_page);
	for (i = 0; i < page_range; ++i) {
		spin_init(&m->spin, "vm_page");
		m->phys_addr = pa;
		pa += PAGE_SIZE;
		++m;
	}

	/*
	 * Construct the free queue(s) in ascending order (by physical
	 * address) so that the first 16MB of physical memory is allocated
	 * last rather than first.  On large-memory machines, this avoids
	 * the exhaustion of low physical memory before isa_dma_init has run.
	 */
	vmstats.v_page_count = 0;
	vmstats.v_free_count = 0;
	for (i = 0; phys_avail[i].phys_end && npages > 0; ++i) {
		pa = phys_avail[i].phys_beg;
		if (i == biggestone)
			last_pa = new_end;
		else
			last_pa = phys_avail[i].phys_end;
		while (pa < last_pa && npages-- > 0) {
			vm_add_new_page(pa, &badcount);
			pa += PAGE_SIZE;
		}
	}
	if (virtual2_start)
		virtual2_start = vaddr;
	else
		virtual_start = vaddr;
	mycpu->gd_vmstats = vmstats;
}

/*
 * (called from early boot only)
 *
 * Reorganize VM pages based on numa data.  May be called as many times as
 * necessary.  Will reorganize the vm_page_t page color and related queue(s)
 * to allow vm_page_alloc() to choose pages based on socket affinity.
 *
 * NOTE: This function is only called while we are still in UP mode, so
 *	 we only need a critical section to protect the queues (which
 *	 saves a lot of time, there are likely a ton of pages).
 */
void
vm_numa_organize(vm_paddr_t ran_beg, vm_paddr_t bytes, int physid)
{
	vm_paddr_t scan_beg;
	vm_paddr_t scan_end;
	vm_paddr_t ran_end;
	struct vpgqueues *vpq;
	vm_page_t m;
	vm_page_t mend;
	int socket_mod;
	int socket_value;
	int i;

	/*
	 * Check if no physical information, or there was only one socket
	 * (so don't waste time doing nothing!).
	 */
	if (cpu_topology_phys_ids <= 1 ||
	    cpu_topology_core_ids == 0) {
		return;
	}

	/*
	 * Setup for our iteration.  Note that ACPI may iterate CPU
	 * sockets starting at 0 or 1 or some other number.  The
	 * cpu_topology code mod's it against the socket count.
	 */
	ran_end = ran_beg + bytes;

	socket_mod = PQ_L2_SIZE / cpu_topology_phys_ids;
	socket_value = (physid % cpu_topology_phys_ids) * socket_mod;
	mend = &vm_page_array[vm_page_array_size];

	crit_enter();

	/*
	 * Adjust cpu_topology's phys_mem parameter
	 */
	if (root_cpu_node)
		vm_numa_add_topology_mem(root_cpu_node, physid, (long)bytes);

	/*
	 * Adjust vm_page->pc and requeue all affected pages.  The
	 * allocator will then be able to localize memory allocations
	 * to some degree.
	 */
	for (i = 0; phys_avail[i].phys_end; ++i) {
		scan_beg = phys_avail[i].phys_beg;
		scan_end = phys_avail[i].phys_end;
		if (scan_end <= ran_beg)
			continue;
		if (scan_beg >= ran_end)
			continue;
		if (scan_beg < ran_beg)
			scan_beg = ran_beg;
		if (scan_end > ran_end)
			scan_end = ran_end;
		if (atop(scan_end) > first_page + vm_page_array_size)
			scan_end = ptoa(first_page + vm_page_array_size);

		m = PHYS_TO_VM_PAGE(scan_beg);
		while (scan_beg < scan_end) {
			KKASSERT(m < mend);
			if (m->queue != PQ_NONE) {
				vpq = &vm_page_queues[m->queue];
				TAILQ_REMOVE(&vpq->pl, m, pageq);
				--vpq->lcnt;
				/* queue doesn't change, no need to adj cnt */
				m->queue -= m->pc;
				m->pc %= socket_mod;
				m->pc += socket_value;
				m->pc &= PQ_L2_MASK;
				m->queue += m->pc;
				vpq = &vm_page_queues[m->queue];
				TAILQ_INSERT_HEAD(&vpq->pl, m, pageq);
				++vpq->lcnt;
				/* queue doesn't change, no need to adj cnt */
			} else {
				m->pc %= socket_mod;
				m->pc += socket_value;
				m->pc &= PQ_L2_MASK;
			}
			scan_beg += PAGE_SIZE;
			++m;
		}
	}

	crit_exit();
}

/*
 * (called from early boot only)
 *
 * Don't allow the NUMA organization to leave vm_page_queues[] nodes
 * completely empty for a logical cpu.  Doing so would force allocations
 * on that cpu to always borrow from a nearby cpu, create unnecessary
 * contention, and cause vm_page_alloc() to iterate more queues and run more
 * slowly.
 *
 * This situation can occur when memory sticks are not entirely populated,
 * populated at different densities, or in naturally assymetric systems
 * such as the 2990WX.  There could very well be many vm_page_queues[]
 * entries with *NO* pages assigned to them.
 *
 * Fixing this up ensures that each logical CPU has roughly the same
 * sized memory pool, and more importantly ensures that logical CPUs
 * do not wind up with an empty memory pool.
 *
 * At them moment we just iterate the other queues and borrow pages,
 * moving them into the queues for cpus with severe deficits even though
 * the memory might not be local to those cpus.  I am not doing this in
 * a 'smart' way, its effectively UMA style (sorta, since its page-by-page
 * whereas real UMA typically exchanges address bits 8-10 with high address
 * bits).  But it works extremely well and gives us fairly good deterministic
 * results on the cpu cores associated with these secondary nodes.
 */
void
vm_numa_organize_finalize(void)
{
	struct vpgqueues *vpq;
	vm_page_t m;
	long lcnt_lo;
	long lcnt_hi;
	int iter;
	int i;
	int scale_lim;

	crit_enter();

	/*
	 * Machines might not use an exact power of 2 for phys_ids,
	 * core_ids, ht_ids, etc.  This can slightly reduce the actual
	 * range of indices in vm_page_queues[] that are nominally used.
	 */
	if (cpu_topology_ht_ids) {
		scale_lim = PQ_L2_SIZE / cpu_topology_phys_ids;
		scale_lim = scale_lim / cpu_topology_core_ids;
		scale_lim = scale_lim / cpu_topology_ht_ids;
		scale_lim = scale_lim * cpu_topology_ht_ids;
		scale_lim = scale_lim * cpu_topology_core_ids;
		scale_lim = scale_lim * cpu_topology_phys_ids;
	} else {
		scale_lim = PQ_L2_SIZE;
	}

	/*
	 * Calculate an average, set hysteresis for balancing from
	 * 10% below the average to the average.
	 */
	lcnt_hi = 0;
	for (i = 0; i < scale_lim; ++i) {
		lcnt_hi += vm_page_queues[i].lcnt;
	}
	lcnt_hi /= scale_lim;
	lcnt_lo = lcnt_hi - lcnt_hi / 10;

	kprintf("vm_page: avg %ld pages per queue, %d queues\n",
		lcnt_hi, scale_lim);

	iter = 0;
	for (i = 0; i < scale_lim; ++i) {
		vpq = &vm_page_queues[PQ_FREE + i];
		while (vpq->lcnt < lcnt_lo) {
			struct vpgqueues *vptmp;

			iter = (iter + 1) & PQ_L2_MASK;
			vptmp = &vm_page_queues[PQ_FREE + iter];
			if (vptmp->lcnt < lcnt_hi)
				continue;
			m = TAILQ_FIRST(&vptmp->pl);
			KKASSERT(m->queue == PQ_FREE + iter);
			TAILQ_REMOVE(&vptmp->pl, m, pageq);
			--vptmp->lcnt;
			/* queue doesn't change, no need to adj cnt */
			m->queue -= m->pc;
			m->pc = i;
			m->queue += m->pc;
			TAILQ_INSERT_HEAD(&vpq->pl, m, pageq);
			++vpq->lcnt;
		}
	}
	crit_exit();
}

static
void
vm_numa_add_topology_mem(cpu_node_t *cpup, int physid, long bytes)
{
	int cpuid;
	int i;

	switch(cpup->type) {
	case PACKAGE_LEVEL:
		cpup->phys_mem += bytes;
		break;
	case CHIP_LEVEL:
		/*
		 * All members should have the same chipid, so we only need
		 * to pull out one member.
		 */
		if (CPUMASK_TESTNZERO(cpup->members)) {
			cpuid = BSFCPUMASK(cpup->members);
			if (physid ==
			    get_chip_ID_from_APICID(CPUID_TO_APICID(cpuid))) {
				cpup->phys_mem += bytes;
			}
		}
		break;
	case CORE_LEVEL:
	case THREAD_LEVEL:
		/*
		 * Just inherit from the parent node
		 */
		cpup->phys_mem = cpup->parent_node->phys_mem;
		break;
	}
	for (i = 0; i < MAXCPU && cpup->child_node[i]; ++i)
		vm_numa_add_topology_mem(cpup->child_node[i], physid, bytes);
}

/*
 * We tended to reserve a ton of memory for contigmalloc().  Now that most
 * drivers have initialized we want to return most the remaining free
 * reserve back to the VM page queues so they can be used for normal
 * allocations.
 *
 * We leave vm_dma_reserved bytes worth of free pages in the reserve pool.
 */
static void
vm_page_startup_finish(void *dummy __unused)
{
	alist_blk_t blk;
	alist_blk_t rblk;
	alist_blk_t count;
	alist_blk_t xcount;
	alist_blk_t bfree;
	vm_page_t m;
	struct vm_page_hash_elm *mp;
	int mask;

	/*
	 * Set the set_assoc_mask based on the fitted number of CPUs.
	 * This is a mask, so we subject 1.
	 *
	 * w/PQ_L2_SIZE = 1024, Don't let the associativity drop below 8.
	 * So if we have 256 CPUs, two hyper-threads will wind up sharing.
	 *
	 * The maximum is PQ_L2_SIZE.  However, we limit the starting
	 * maximum to 16 (mask = 15) in order to improve the cache locality
	 * of related kernel data structures.
	 */
	mask = PQ_L2_SIZE / ncpus_fit - 1;
	if (mask < 7)		/* minimum is 8-way w/256 CPU threads */
		mask = 7;
	if (mask < 15)
		mask = 15;
	cpu_ccfence();
	set_assoc_mask = mask;

	/*
	 * Return part of the initial reserve back to the system
	 */
	spin_lock(&vm_contig_spin);
	for (;;) {
		bfree = alist_free_info(&vm_contig_alist, &blk, &count);
		if (bfree <= vm_dma_reserved / PAGE_SIZE)
			break;
		if (count == 0)
			break;

		/*
		 * Figure out how much of the initial reserve we have to
		 * free in order to reach our target.
		 */
		bfree -= vm_dma_reserved / PAGE_SIZE;
		if (count > bfree) {
			blk += count - bfree;
			count = bfree;
		}

		/*
		 * Calculate the nearest power of 2 <= count.
		 */
		for (xcount = 1; xcount <= count; xcount <<= 1)
			;
		xcount >>= 1;
		blk += count - xcount;
		count = xcount;

		/*
		 * Allocate the pages from the alist, then free them to
		 * the normal VM page queues.
		 *
		 * Pages allocated from the alist are wired.  We have to
		 * busy, unwire, and free them.  We must also adjust
		 * vm_low_phys_reserved before freeing any pages to prevent
		 * confusion.
		 */
		rblk = alist_alloc(&vm_contig_alist, blk, count);
		if (rblk != blk) {
			kprintf("vm_page_startup_finish: Unable to return "
				"dma space @0x%08x/%d -> 0x%08x\n",
				blk, count, rblk);
			break;
		}
		atomic_add_long(&vmstats.v_dma_pages, -(long)count);
		spin_unlock(&vm_contig_spin);

		m = PHYS_TO_VM_PAGE((vm_paddr_t)blk << PAGE_SHIFT);
		vm_low_phys_reserved = VM_PAGE_TO_PHYS(m);
		while (count) {
			vm_page_flag_clear(m, PG_FICTITIOUS | PG_UNQUEUED);
			vm_page_busy_wait(m, FALSE, "cpgfr");
			vm_page_unwire(m, 0);
			vm_page_free(m);
			--count;
			++m;
		}
		spin_lock(&vm_contig_spin);
	}
	spin_unlock(&vm_contig_spin);

	/*
	 * Print out how much DMA space drivers have already allocated and
	 * how much is left over.
	 */
	kprintf("DMA space used: %jdk, remaining available: %jdk\n",
		(intmax_t)(vmstats.v_dma_pages - vm_contig_alist.bl_free) *
		(PAGE_SIZE / 1024),
		(intmax_t)vm_contig_alist.bl_free * (PAGE_SIZE / 1024));

	/*
	 * Power of 2
	 */
	vm_page_hash_size = 4096;
	while (vm_page_hash_size < (vm_page_array_size / 16))
		vm_page_hash_size <<= 1;
	if (vm_page_hash_size > VM_PAGE_HASH_MAX)
		vm_page_hash_size = VM_PAGE_HASH_MAX;

	/*
	 * hash table for vm_page_lookup_quick()
	 */
	mp = (void *)kmem_alloc3(kernel_map,
				 (vm_page_hash_size + VM_PAGE_HASH_SET) *
				  sizeof(*vm_page_hash),
				 VM_SUBSYS_VMPGHASH, KM_CPU(0));
	bzero(mp, (vm_page_hash_size + VM_PAGE_HASH_SET) * sizeof(*mp));
	cpu_sfence();
	vm_page_hash = mp;
}
SYSINIT(vm_pgend, SI_SUB_PROC0_POST, SI_ORDER_ANY,
	vm_page_startup_finish, NULL);


/*
 * Scan comparison function for Red-Black tree scans.  An inclusive
 * (start,end) is expected.  Other fields are not used.
 */
int
rb_vm_page_scancmp(struct vm_page *p, void *data)
{
	struct rb_vm_page_scan_info *info = data;

	if (p->pindex < info->start_pindex)
		return(-1);
	if (p->pindex > info->end_pindex)
		return(1);
	return(0);
}

int
rb_vm_page_compare(struct vm_page *p1, struct vm_page *p2)
{
	if (p1->pindex < p2->pindex)
		return(-1);
	if (p1->pindex > p2->pindex)
		return(1);
	return(0);
}

void
vm_page_init(vm_page_t m)
{
	/* do nothing for now.  Called from pmap_page_init() */
}

/*
 * Each page queue has its own spin lock, which is fairly optimal for
 * allocating and freeing pages at least.
 *
 * The caller must hold the vm_page_spin_lock() before locking a vm_page's
 * queue spinlock via this function.  Also note that m->queue cannot change
 * unless both the page and queue are locked.
 */
static __inline
void
_vm_page_queue_spin_lock(vm_page_t m)
{
	u_short queue;

	queue = m->queue;
	if (queue != PQ_NONE) {
		spin_lock(&vm_page_queues[queue].spin);
		KKASSERT(queue == m->queue);
	}
}

static __inline
void
_vm_page_queue_spin_unlock(vm_page_t m)
{
	u_short queue;

	queue = m->queue;
	cpu_ccfence();
	if (queue != PQ_NONE)
		spin_unlock(&vm_page_queues[queue].spin);
}

static __inline
void
_vm_page_queues_spin_lock(u_short queue)
{
	cpu_ccfence();
	if (queue != PQ_NONE)
		spin_lock(&vm_page_queues[queue].spin);
}


static __inline
void
_vm_page_queues_spin_unlock(u_short queue)
{
	cpu_ccfence();
	if (queue != PQ_NONE)
		spin_unlock(&vm_page_queues[queue].spin);
}

void
vm_page_queue_spin_lock(vm_page_t m)
{
	_vm_page_queue_spin_lock(m);
}

void
vm_page_queues_spin_lock(u_short queue)
{
	_vm_page_queues_spin_lock(queue);
}

void
vm_page_queue_spin_unlock(vm_page_t m)
{
	_vm_page_queue_spin_unlock(m);
}

void
vm_page_queues_spin_unlock(u_short queue)
{
	_vm_page_queues_spin_unlock(queue);
}

/*
 * This locks the specified vm_page and its queue in the proper order
 * (page first, then queue).  The queue may change so the caller must
 * recheck on return.
 */
static __inline
void
_vm_page_and_queue_spin_lock(vm_page_t m)
{
	vm_page_spin_lock(m);
	_vm_page_queue_spin_lock(m);
}

static __inline
void
_vm_page_and_queue_spin_unlock(vm_page_t m)
{
	_vm_page_queues_spin_unlock(m->queue);
	vm_page_spin_unlock(m);
}

void
vm_page_and_queue_spin_unlock(vm_page_t m)
{
	_vm_page_and_queue_spin_unlock(m);
}

void
vm_page_and_queue_spin_lock(vm_page_t m)
{
	_vm_page_and_queue_spin_lock(m);
}

/*
 * Helper function removes vm_page from its current queue.
 * Returns the base queue the page used to be on.
 *
 * The vm_page and the queue must be spinlocked.
 * This function will unlock the queue but leave the page spinlocked.
 */
static __inline u_short
_vm_page_rem_queue_spinlocked(vm_page_t m)
{
	struct vpgqueues *pq;
	u_short queue;
	u_short oqueue;
	long *cnt_adj;
	long *cnt_gd;

	queue = m->queue;
	if (queue != PQ_NONE) {
		pq = &vm_page_queues[queue];
		TAILQ_REMOVE(&pq->pl, m, pageq);

		/*
		 * Primarily adjust our pcpu stats for rollup, which is
		 * (mycpu->gd_vmstats_adj + offset).  This is normally
		 * synchronized on every hardclock().
		 *
		 * However, in order for the nominal low-memory algorithms
		 * to work properly if the unsynchronized adjustment gets
		 * too negative and might trigger the pageout daemon, we
		 * immediately synchronize with the global structure.
		 *
		 * The idea here is to reduce unnecessary SMP cache mastership
		 * changes in the global vmstats, which can be particularly
		 * bad in multi-socket systems.
		 *
		 * WARNING! In systems with low amounts of memory the
		 *	    vm_paging_needed(-1024 * ncpus) test could
		 *	    wind up testing a value above the paging target,
		 *	    meaning it would almost always return TRUE.  In
		 *	    that situation we synchronize every time the
		 *	    cumulative adjustment falls below -1024.
		 */
		cnt_adj = (long *)((char *)&mycpu->gd_vmstats_adj +
				   pq->cnt_offset);
		cnt_gd = (long *)((char *)&mycpu->gd_vmstats +
				   pq->cnt_offset);
		atomic_add_long(cnt_adj, -1);
		atomic_add_long(cnt_gd, -1);

		if (*cnt_adj < -1024 && vm_paging_start(-1024 * ncpus)) {
			u_long copy = atomic_swap_long(cnt_adj, 0);
			cnt_adj = (long *)((char *)&vmstats + pq->cnt_offset);
			atomic_add_long(cnt_adj, copy);
		}
		pq->lcnt--;
		m->queue = PQ_NONE;
		oqueue = queue;
		queue -= m->pc;
		vm_page_queues_spin_unlock(oqueue);	/* intended */
	}
	return queue;
}

/*
 * Helper function places the vm_page on the specified queue.  Generally
 * speaking only PQ_FREE pages are placed at the head, to allow them to
 * be allocated sooner rather than later on the assumption that they
 * are cache-hot.
 *
 * The vm_page must be spinlocked.
 * The vm_page must NOT be FICTITIOUS (that would be a disaster)
 * This function will return with both the page and the queue locked.
 */
static __inline void
_vm_page_add_queue_spinlocked(vm_page_t m, u_short queue, int athead)
{
	struct vpgqueues *pq;
	u_long *cnt_adj;
	u_long *cnt_gd;

	KKASSERT(m->queue == PQ_NONE &&
		 (m->flags & (PG_FICTITIOUS | PG_UNQUEUED)) == 0);

	if (queue != PQ_NONE) {
		vm_page_queues_spin_lock(queue);
		pq = &vm_page_queues[queue];
		++pq->lcnt;

		/*
		 * Adjust our pcpu stats.  If a system entity really needs
		 * to incorporate the count it will call vmstats_rollup()
		 * to roll it all up into the global vmstats strufture.
		 */
		cnt_adj = (long *)((char *)&mycpu->gd_vmstats_adj +
				   pq->cnt_offset);
		cnt_gd = (long *)((char *)&mycpu->gd_vmstats +
				   pq->cnt_offset);
		atomic_add_long(cnt_adj, 1);
		atomic_add_long(cnt_gd, 1);

		/*
		 * PQ_FREE is always handled LIFO style to try to provide
		 * cache-hot pages to programs.
		 */
		m->queue = queue;
		if (queue - m->pc == PQ_FREE) {
			TAILQ_INSERT_HEAD(&pq->pl, m, pageq);
		} else if (athead) {
			TAILQ_INSERT_HEAD(&pq->pl, m, pageq);
		} else {
			TAILQ_INSERT_TAIL(&pq->pl, m, pageq);
		}
		/* leave the queue spinlocked */
	}
}

/*
 * Wait until page is no longer BUSY.  If also_m_busy is TRUE we wait
 * until the page is no longer BUSY or SBUSY (busy_count field is 0).
 *
 * Returns TRUE if it had to sleep, FALSE if we did not.  Only one sleep
 * call will be made before returning.
 *
 * This function does NOT busy the page and on return the page is not
 * guaranteed to be available.
 */
void
vm_page_sleep_busy(vm_page_t m, int also_m_busy, const char *msg)
{
	u_int32_t busy_count;

	for (;;) {
		busy_count = m->busy_count;
		cpu_ccfence();

		if ((busy_count & PBUSY_LOCKED) == 0 &&
		    (also_m_busy == 0 || (busy_count & PBUSY_MASK) == 0)) {
			break;
		}
		tsleep_interlock(m, 0);
		if (atomic_cmpset_int(&m->busy_count, busy_count,
				      busy_count | PBUSY_WANTED)) {
			atomic_set_int(&m->flags, PG_REFERENCED);
			tsleep(m, PINTERLOCKED, msg, 0);
			break;
		}
	}
}

/*
 * This calculates and returns a page color given an optional VM object and
 * either a pindex or an iterator.  We attempt to return a cpu-localized
 * pg_color that is still roughly 16-way set-associative.  The CPU topology
 * is used if it was probed.
 *
 * The caller may use the returned value to index into e.g. PQ_FREE when
 * allocating a page in order to nominally obtain pages that are hopefully
 * already localized to the requesting cpu.  This function is not able to
 * provide any sort of guarantee of this, but does its best to improve
 * hardware cache management performance.
 *
 * WARNING! The caller must mask the returned value with PQ_L2_MASK.
 */
u_short
vm_get_pg_color(int cpuid, vm_object_t object, vm_pindex_t pindex)
{
	u_short pg_color;
	int object_pg_color;

	/*
	 * WARNING! cpu_topology_core_ids might not be a power of two.
	 *	    We also shouldn't make assumptions about
	 *	    cpu_topology_phys_ids either.
	 *
	 * WARNING! ncpus might not be known at this time (during early
	 *	    boot), and might be set to 1.
	 *
	 * General format: [phys_id][core_id][cpuid][set-associativity]
	 * (but uses modulo, so not necessarily precise bit masks)
	 */
	object_pg_color = object ? object->pg_color : 0;

	if (cpu_topology_ht_ids) {
		int phys_id;
		int core_id;
		int ht_id;
		int physcale;
		int grpscale;
		int cpuscale;

		/*
		 * Translate cpuid to socket, core, and hyperthread id.
		 */
		phys_id = get_cpu_phys_id(cpuid);
		core_id = get_cpu_core_id(cpuid);
		ht_id = get_cpu_ht_id(cpuid);

		/*
		 * Calculate pg_color for our array index.
		 *
		 * physcale - socket multiplier.
		 * grpscale - core multiplier (cores per socket)
		 * cpu*	    - cpus per core
		 *
		 * WARNING! In early boot, ncpus has not yet been
		 *	    initialized and may be set to (1).
		 *
		 * WARNING! physcale must match the organization that
		 *	    vm_numa_organize() creates to ensure that
		 *	    we properly localize allocations to the
		 *	    requested cpuid.
		 */
		physcale = PQ_L2_SIZE / cpu_topology_phys_ids;
		grpscale = physcale / cpu_topology_core_ids;
		cpuscale = grpscale / cpu_topology_ht_ids;

		pg_color = phys_id * physcale;
		pg_color += core_id * grpscale;
		pg_color += ht_id * cpuscale;
		pg_color += (pindex + object_pg_color) % cpuscale;

#if 0
		if (grpsize >= 8) {
			pg_color += (pindex + object_pg_color) % grpsize;
		} else {
			if (grpsize <= 2) {
				grpsize = 8;
			} else {
				/* 3->9, 4->8, 5->10, 6->12, 7->14 */
				grpsize += grpsize;
				if (grpsize < 8)
					grpsize += grpsize;
			}
			pg_color += (pindex + object_pg_color) % grpsize;
		}
#endif
	} else {
		/*
		 * Unknown topology, distribute things evenly.
		 *
		 * WARNING! In early boot, ncpus has not yet been
		 *	    initialized and may be set to (1).
		 */
		int cpuscale;

		cpuscale = PQ_L2_SIZE / ncpus;

		pg_color = cpuid * cpuscale;
		pg_color += (pindex + object_pg_color) % cpuscale;
	}
	return (pg_color & PQ_L2_MASK);
}

/*
 * Wait until BUSY can be set, then set it.  If also_m_busy is TRUE we
 * also wait for m->busy_count to become 0 before setting PBUSY_LOCKED.
 */
void
VM_PAGE_DEBUG_EXT(vm_page_busy_wait)(vm_page_t m,
				     int also_m_busy, const char *msg
				     VM_PAGE_DEBUG_ARGS)
{
	u_int32_t busy_count;

	for (;;) {
		busy_count = m->busy_count;
		cpu_ccfence();
		if (busy_count & PBUSY_LOCKED) {
			tsleep_interlock(m, 0);
			if (atomic_cmpset_int(&m->busy_count, busy_count,
					  busy_count | PBUSY_WANTED)) {
				atomic_set_int(&m->flags, PG_REFERENCED);
				tsleep(m, PINTERLOCKED, msg, 0);
			}
		} else if (also_m_busy && busy_count) {
			tsleep_interlock(m, 0);
			if (atomic_cmpset_int(&m->busy_count, busy_count,
					  busy_count | PBUSY_WANTED)) {
				atomic_set_int(&m->flags, PG_REFERENCED);
				tsleep(m, PINTERLOCKED, msg, 0);
			}
		} else {
			if (atomic_cmpset_int(&m->busy_count, busy_count,
					      busy_count | PBUSY_LOCKED)) {
#ifdef VM_PAGE_DEBUG
				m->busy_func = func;
				m->busy_line = lineno;
#endif
				break;
			}
		}
	}
}

/*
 * Attempt to set BUSY.  If also_m_busy is TRUE we only succeed if
 * m->busy_count is also 0.
 *
 * Returns non-zero on failure.
 */
int
VM_PAGE_DEBUG_EXT(vm_page_busy_try)(vm_page_t m, int also_m_busy
				    VM_PAGE_DEBUG_ARGS)
{
	u_int32_t busy_count;

	for (;;) {
		busy_count = m->busy_count;
		cpu_ccfence();
		if (busy_count & PBUSY_LOCKED)
			return TRUE;
		if (also_m_busy && (busy_count & PBUSY_MASK) != 0)
			return TRUE;
		if (atomic_cmpset_int(&m->busy_count, busy_count,
				      busy_count | PBUSY_LOCKED)) {
#ifdef VM_PAGE_DEBUG
				m->busy_func = func;
				m->busy_line = lineno;
#endif
			return FALSE;
		}
	}
}

/*
 * Clear the BUSY flag and return non-zero to indicate to the caller
 * that a wakeup() should be performed.
 *
 * (inline version)
 */
static __inline
int
_vm_page_wakeup(vm_page_t m)
{
	u_int32_t busy_count;

	busy_count = m->busy_count;
	cpu_ccfence();
	for (;;) {
		if (atomic_fcmpset_int(&m->busy_count, &busy_count,
				      busy_count &
				      ~(PBUSY_LOCKED | PBUSY_WANTED))) {
			return((int)(busy_count & PBUSY_WANTED));
		}
	}
	/* not reached */
}

/*
 * Clear the BUSY flag and wakeup anyone waiting for the page.  This
 * is typically the last call you make on a page before moving onto
 * other things.
 */
void
vm_page_wakeup(vm_page_t m)
{
        KASSERT(m->busy_count & PBUSY_LOCKED,
		("vm_page_wakeup: page not busy!!!"));
	if (_vm_page_wakeup(m))
		wakeup(m);
}

/*
 * Hold a page, preventing reuse.  This is typically only called on pages
 * in a known state (either held busy, special, or interlocked in some
 * manner).  Holding a page does not ensure that it remains valid, it only
 * prevents reuse.  The page must not already be on the FREE queue or in
 * any danger of being moved to the FREE queue concurrent with this call.
 *
 * Other parts of the system can still disassociate the page from its object
 * and attempt to free it, or perform read or write I/O on it and/or otherwise
 * manipulate the page, but if the page is held the VM system will leave the
 * page and its data intact and not cycle it through the FREE queue until
 * the last hold has been released.
 *
 * (see vm_page_wire() if you want to prevent the page from being
 *  disassociated from its object too).
 */
void
vm_page_hold(vm_page_t m)
{
	atomic_add_int(&m->hold_count, 1);
	KKASSERT(m->queue - m->pc != PQ_FREE);
}

/*
 * The opposite of vm_page_hold().  If the page is on the HOLD queue
 * it was freed while held and must be moved back to the FREE queue.
 *
 * To avoid racing against vm_page_free*() we must re-test conditions
 * after obtaining the spin-lock.  The initial test can also race a
 * vm_page_free*() that is in the middle of moving a page to PQ_HOLD,
 * leaving the page on PQ_HOLD with hold_count == 0.  Rather than
 * throw a spin-lock in the critical path, we rely on the pageout
 * daemon to clean-up these loose ends.
 *
 * More critically, the 'easy movement' between queues without busying
 * a vm_page is only allowed for PQ_FREE<->PQ_HOLD.
 */
void
vm_page_unhold(vm_page_t m)
{
	KASSERT(m->hold_count > 0 && m->queue - m->pc != PQ_FREE,
		("vm_page_unhold: pg %p illegal hold_count (%d) or "
		 "on FREE queue (%d)",
		 m, m->hold_count, m->queue - m->pc));

	if (atomic_fetchadd_int(&m->hold_count, -1) == 1 &&
	    m->queue - m->pc == PQ_HOLD) {
		vm_page_spin_lock(m);
		if (m->hold_count == 0 && m->queue - m->pc == PQ_HOLD) {
			_vm_page_queue_spin_lock(m);
			_vm_page_rem_queue_spinlocked(m);
			_vm_page_add_queue_spinlocked(m, PQ_FREE + m->pc, 1);
			_vm_page_queue_spin_unlock(m);
		}
		vm_page_spin_unlock(m);
	}
}

/*
 * Create a fictitious page with the specified physical address and
 * memory attribute.  The memory attribute is the only the machine-
 * dependent aspect of a fictitious page that must be initialized.
 */
void
vm_page_initfake(vm_page_t m, vm_paddr_t paddr, vm_memattr_t memattr)
{
	/*
	 * The page's memattr might have changed since the
	 * previous initialization.  Update the pmap to the
	 * new memattr.
	 */
	if ((m->flags & PG_FICTITIOUS) != 0)
		goto memattr;
	m->phys_addr = paddr;
	m->queue = PQ_NONE;
	/* Fictitious pages don't use "segind". */
	/* Fictitious pages don't use "order" or "pool". */
	m->flags = PG_FICTITIOUS | PG_UNQUEUED;
	m->busy_count = PBUSY_LOCKED;
	m->wire_count = 1;
	spin_init(&m->spin, "fake_page");
	pmap_page_init(m);
memattr:
	pmap_page_set_memattr(m, memattr);
}

/*
 * Inserts the given vm_page into the object and object list.
 *
 * The pagetables are not updated but will presumably fault the page
 * in if necessary, or if a kernel page the caller will at some point
 * enter the page into the kernel's pmap.  We are not allowed to block
 * here so we *can't* do this anyway.
 *
 * This routine may not block.
 * This routine must be called with the vm_object held.
 * This routine must be called with a critical section held.
 *
 * This routine returns TRUE if the page was inserted into the object
 * successfully, and FALSE if the page already exists in the object.
 */
int
vm_page_insert(vm_page_t m, vm_object_t object, vm_pindex_t pindex)
{
	ASSERT_LWKT_TOKEN_HELD_EXCL(vm_object_token(object));
	if (m->object != NULL)
		panic("vm_page_insert: already inserted");

	atomic_add_int(&object->generation, 1);

	/*
	 * Associate the VM page with an (object, offset).
	 *
	 * The vm_page spin lock is required for interactions with the pmap.
	 * XXX vm_page_spin_lock() might not be needed for this any more.
	 */
	vm_page_spin_lock(m);
	m->object = object;
	m->pindex = pindex;
	if (vm_page_rb_tree_RB_INSERT(&object->rb_memq, m)) {
		m->object = NULL;
		m->pindex = 0;
		vm_page_spin_unlock(m);
		return FALSE;
	}
	++object->resident_page_count;
	++mycpu->gd_vmtotal.t_rm;
	vm_page_spin_unlock(m);

	/*
	 * Since we are inserting a new and possibly dirty page,
	 * update the object's OBJ_WRITEABLE and OBJ_MIGHTBEDIRTY flags.
	 */
	if ((m->valid & m->dirty) ||
	    (m->flags & (PG_WRITEABLE | PG_NEED_COMMIT)))
		vm_object_set_writeable_dirty(object);

	/*
	 * Checks for a swap assignment and sets PG_SWAPPED if appropriate.
	 */
	swap_pager_page_inserted(m);
	return TRUE;
}

/*
 * Removes the given vm_page_t from the (object,index) table
 *
 * The page must be BUSY and will remain BUSY on return.
 * No other requirements.
 *
 * NOTE: FreeBSD side effect was to unbusy the page on return.  We leave
 *	 it busy.
 *
 * NOTE: Caller is responsible for any pmap disposition prior to the
 *	 rename (as the pmap code will not be able to find the entries
 *	 once the object has been disassociated).  The caller may choose
 *	 to leave the pmap association intact if this routine is being
 *	 called as part of a rename between shadowed objects.
 *
 * This routine may not block.
 */
void
vm_page_remove(vm_page_t m)
{
	vm_object_t object;

	if (m->object == NULL) {
		return;
	}

	if ((m->busy_count & PBUSY_LOCKED) == 0)
		panic("vm_page_remove: page not busy");

	object = m->object;

	vm_object_hold(object);

	/*
	 * Remove the page from the object and update the object.
	 *
	 * The vm_page spin lock is required for interactions with the pmap.
	 * XXX vm_page_spin_lock() might not be needed for this any more.
	 */
	vm_page_spin_lock(m);
	vm_page_rb_tree_RB_REMOVE(&object->rb_memq, m);
	--object->resident_page_count;
	--mycpu->gd_vmtotal.t_rm;
	m->object = NULL;
	atomic_add_int(&object->generation, 1);
	vm_page_spin_unlock(m);

	vm_object_drop(object);
}

/*
 * Calculate the hash position for the vm_page hash heuristic.  Generally
 * speaking we want to localize sequential lookups to reduce memory stalls.
 *
 * Mask by ~3 to offer 4-way set-assoc
 */
static __inline
struct vm_page_hash_elm *
vm_page_hash_hash(vm_object_t object, vm_pindex_t pindex)
{
	size_t hi;

	hi = iscsi_crc32(&object, sizeof(object)) << 2;
	hi ^= hi >> (23 - 2);
	hi += pindex * VM_PAGE_HASH_SET;
#if 0
	/* mix it up */
	hi = (intptr_t)object ^ object->pg_color ^ pindex;
	hi += object->pg_color * pindex;
	hi = hi ^ (hi >> 20);
#endif
	hi &= vm_page_hash_size - 1;		/* bounds */

	return (&vm_page_hash[hi]);
}

/*
 * Heuristical page lookup that does not require any locks.  Returns
 * a soft-busied page on success, NULL on failure.
 *
 * Caller must lookup the page the slow way if NULL is returned.
 */
vm_page_t
vm_page_hash_get(vm_object_t object, vm_pindex_t pindex)
{
	struct vm_page_hash_elm *mp;
	vm_page_t m;
	int i;

	if (__predict_false(vm_page_hash == NULL))
		return NULL;
	mp = vm_page_hash_hash(object, pindex);
	for (i = 0; i < VM_PAGE_HASH_SET; ++i, ++mp) {
		if (mp->object != object ||
		    mp->pindex != pindex) {
			continue;
		}
		m = mp->m;
		cpu_ccfence();
		if (m == NULL)
			continue;
		if (m->object != object || m->pindex != pindex)
			continue;
		if (vm_page_sbusy_try(m))
			continue;
		if (m->object == object && m->pindex == pindex) {
			/*
			 * On-match optimization - do not update ticks
			 * unless we have to (reduce cache coherency traffic)
			 */
			if (mp->ticks != ticks)
				mp->ticks = ticks;
			return m;
		}
		vm_page_sbusy_drop(m);
	}
	return NULL;
}

/*
 * Enter page onto vm_page_hash[].  This is a heuristic, SMP collisions
 * are allowed.
 */
static __inline
void
vm_page_hash_enter(vm_page_t m)
{
	struct vm_page_hash_elm *mp;
	struct vm_page_hash_elm *best;
	vm_object_t object;
	vm_pindex_t pindex;
	int best_delta;
	int delta;
	int i;

	/*
	 * Only enter type-stable vm_pages with well-shared objects.
	 */
	if ((m->flags & PG_MAPPEDMULTI) == 0)
		return;
	if (__predict_false(vm_page_hash == NULL ||
			    m < &vm_page_array[0] ||
			    m >= &vm_page_array[vm_page_array_size])) {
		return;
	}
	if (__predict_false(m->object == NULL))
		return;
#if 0
	/*
	 * Disabled at the moment, there are some degenerate conditions
	 * with often-exec'd programs that get ignored.  In particular,
	 * the kernel's elf loader does a vn_rdwr() on the first page of
	 * a binary.
	 */
	if (m->object->ref_count <= 2 || (m->object->flags & OBJ_ONEMAPPING))
		return;
#endif
	if (vm_page_hash_vnode_only && m->object->type != OBJT_VNODE)
		return;

	/*
	 * Find best entry
	 */
	object = m->object;
	pindex = m->pindex;

	mp = vm_page_hash_hash(object, pindex);
	best = mp;
	best_delta = ticks - best->ticks;

	for (i = 0; i < VM_PAGE_HASH_SET; ++i, ++mp) {
		if (mp->m == m &&
		    mp->object == object &&
		    mp->pindex == pindex) {
			/*
			 * On-match optimization - do not update ticks
			 * unless we have to (reduce cache coherency traffic)
			 */
			if (mp->ticks != ticks)
				mp->ticks = ticks;
			return;
		}

		/*
		 * The best choice is the oldest entry.
		 *
		 * Also check for a field overflow, using -1 instead of 0
		 * to deal with SMP races on accessing the 'ticks' global.
		 */
		delta = ticks - mp->ticks;
		if (delta < -1)
			best = mp;
		if (best_delta < delta)
			best = mp;
	}

	/*
	 * Load the entry.  Copy a few elements to the hash entry itself
	 * to reduce memory stalls due to memory indirects on lookups.
	 */
	best->m = m;
	best->object = object;
	best->pindex = pindex;
	best->ticks = ticks;
}

/*
 * Locate and return the page at (object, pindex), or NULL if the
 * page could not be found.
 *
 * The caller must hold the vm_object token.
 */
vm_page_t
vm_page_lookup(vm_object_t object, vm_pindex_t pindex)
{
	vm_page_t m;

	/*
	 * Search the hash table for this object/offset pair
	 */
	ASSERT_LWKT_TOKEN_HELD(vm_object_token(object));
	m = vm_page_rb_tree_RB_LOOKUP(&object->rb_memq, pindex);
	if (m) {
		KKASSERT(m->object == object && m->pindex == pindex);
		vm_page_hash_enter(m);
	}
	return(m);
}

vm_page_t
VM_PAGE_DEBUG_EXT(vm_page_lookup_busy_wait)(struct vm_object *object,
					    vm_pindex_t pindex,
					    int also_m_busy, const char *msg
					    VM_PAGE_DEBUG_ARGS)
{
	u_int32_t busy_count;
	vm_page_t m;

	ASSERT_LWKT_TOKEN_HELD(vm_object_token(object));
	m = vm_page_rb_tree_RB_LOOKUP(&object->rb_memq, pindex);
	while (m) {
		KKASSERT(m->object == object && m->pindex == pindex);
		busy_count = m->busy_count;
		cpu_ccfence();
		if (busy_count & PBUSY_LOCKED) {
			tsleep_interlock(m, 0);
			if (atomic_cmpset_int(&m->busy_count, busy_count,
					  busy_count | PBUSY_WANTED)) {
				atomic_set_int(&m->flags, PG_REFERENCED);
				tsleep(m, PINTERLOCKED, msg, 0);
				m = vm_page_rb_tree_RB_LOOKUP(&object->rb_memq,
							      pindex);
			}
		} else if (also_m_busy && busy_count) {
			tsleep_interlock(m, 0);
			if (atomic_cmpset_int(&m->busy_count, busy_count,
					  busy_count | PBUSY_WANTED)) {
				atomic_set_int(&m->flags, PG_REFERENCED);
				tsleep(m, PINTERLOCKED, msg, 0);
				m = vm_page_rb_tree_RB_LOOKUP(&object->rb_memq,
							      pindex);
			}
		} else if (atomic_cmpset_int(&m->busy_count, busy_count,
					     busy_count | PBUSY_LOCKED)) {
#ifdef VM_PAGE_DEBUG
			m->busy_func = func;
			m->busy_line = lineno;
#endif
			vm_page_hash_enter(m);
			break;
		}
	}
	return m;
}

/*
 * Attempt to lookup and busy a page.
 *
 * Returns NULL if the page could not be found
 *
 * Returns a vm_page and error == TRUE if the page exists but could not
 * be busied.
 *
 * Returns a vm_page and error == FALSE on success.
 */
vm_page_t
VM_PAGE_DEBUG_EXT(vm_page_lookup_busy_try)(struct vm_object *object,
					   vm_pindex_t pindex,
					   int also_m_busy, int *errorp
					   VM_PAGE_DEBUG_ARGS)
{
	u_int32_t busy_count;
	vm_page_t m;

	ASSERT_LWKT_TOKEN_HELD(vm_object_token(object));
	m = vm_page_rb_tree_RB_LOOKUP(&object->rb_memq, pindex);
	*errorp = FALSE;
	while (m) {
		KKASSERT(m->object == object && m->pindex == pindex);
		busy_count = m->busy_count;
		cpu_ccfence();
		if (busy_count & PBUSY_LOCKED) {
			*errorp = TRUE;
			break;
		}
		if (also_m_busy && busy_count) {
			*errorp = TRUE;
			break;
		}
		if (atomic_cmpset_int(&m->busy_count, busy_count,
				      busy_count | PBUSY_LOCKED)) {
#ifdef VM_PAGE_DEBUG
			m->busy_func = func;
			m->busy_line = lineno;
#endif
			vm_page_hash_enter(m);
			break;
		}
	}
	return m;
}

/*
 * Returns a page that is only soft-busied for use by the caller in
 * a read-only fashion.  Returns NULL if the page could not be found,
 * the soft busy could not be obtained, or the page data is invalid.
 *
 * XXX Doesn't handle PG_FICTITIOUS pages at the moment, but there is
 *     no reason why we couldn't.
 */
vm_page_t
vm_page_lookup_sbusy_try(struct vm_object *object, vm_pindex_t pindex,
			 int pgoff, int pgbytes)
{
	vm_page_t m;

	ASSERT_LWKT_TOKEN_HELD(vm_object_token(object));
	m = vm_page_rb_tree_RB_LOOKUP(&object->rb_memq, pindex);
	if (m) {
		if ((m->valid != VM_PAGE_BITS_ALL &&
		     !vm_page_is_valid(m, pgoff, pgbytes)) ||
		    (m->flags & PG_FICTITIOUS)) {
			m = NULL;
		} else if (vm_page_sbusy_try(m)) {
			m = NULL;
		} else if ((m->valid != VM_PAGE_BITS_ALL &&
			    !vm_page_is_valid(m, pgoff, pgbytes)) ||
			   (m->flags & PG_FICTITIOUS)) {
			vm_page_sbusy_drop(m);
			m = NULL;
		} else {
			vm_page_hash_enter(m);
		}
	}
	return m;
}

/*
 * Caller must hold the related vm_object
 */
vm_page_t
vm_page_next(vm_page_t m)
{
	vm_page_t next;

	next = vm_page_rb_tree_RB_NEXT(m);
	if (next && next->pindex != m->pindex + 1)
		next = NULL;
	return (next);
}

/*
 * vm_page_rename()
 *
 * Move the given vm_page from its current object to the specified
 * target object/offset.  The page must be busy and will remain so
 * on return.
 *
 * new_object must be held.
 * This routine might block. XXX ?
 *
 * NOTE: Swap associated with the page must be invalidated by the move.  We
 *       have to do this for several reasons:  (1) we aren't freeing the
 *       page, (2) we are dirtying the page, (3) the VM system is probably
 *       moving the page from object A to B, and will then later move
 *       the backing store from A to B and we can't have a conflict.
 *
 * NOTE: We *always* dirty the page.  It is necessary both for the
 *       fact that we moved it, and because we may be invalidating
 *	 swap.  If the page is on the cache, we have to deactivate it
 *	 or vm_page_dirty() will panic.  Dirty pages are not allowed
 *	 on the cache.
 *
 * NOTE: Caller is responsible for any pmap disposition prior to the
 *	 rename (as the pmap code will not be able to find the entries
 *	 once the object has been disassociated or changed).  Nominally
 *	 the caller is moving a page between shadowed objects and so the
 *	 pmap association is retained without having to remove the page
 *	 from it.
 */
void
vm_page_rename(vm_page_t m, vm_object_t new_object, vm_pindex_t new_pindex)
{
	KKASSERT(m->busy_count & PBUSY_LOCKED);
	ASSERT_LWKT_TOKEN_HELD_EXCL(vm_object_token(new_object));
	if (m->object) {
		ASSERT_LWKT_TOKEN_HELD_EXCL(vm_object_token(m->object));
		vm_page_remove(m);
	}
	if (vm_page_insert(m, new_object, new_pindex) == FALSE) {
		panic("vm_page_rename: target exists (%p,%"PRIu64")",
		      new_object, new_pindex);
	}
	if (m->queue - m->pc == PQ_CACHE)
		vm_page_deactivate(m);
	vm_page_dirty(m);
}

/*
 * vm_page_unqueue() without any wakeup.  This routine is used when a page
 * is to remain BUSYied by the caller.
 *
 * This routine may not block.
 */
void
vm_page_unqueue_nowakeup(vm_page_t m)
{
	vm_page_and_queue_spin_lock(m);
	(void)_vm_page_rem_queue_spinlocked(m);
	vm_page_spin_unlock(m);
}

/*
 * vm_page_unqueue() - Remove a page from its queue, wakeup the pagedemon
 * if necessary.
 *
 * This routine may not block.
 */
void
vm_page_unqueue(vm_page_t m)
{
	u_short queue;

	vm_page_and_queue_spin_lock(m);
	queue = _vm_page_rem_queue_spinlocked(m);
	if (queue == PQ_FREE || queue == PQ_CACHE) {
		vm_page_spin_unlock(m);
		pagedaemon_wakeup();
	} else {
		vm_page_spin_unlock(m);
	}
}

/*
 * vm_page_list_find()
 *
 * Find a page on the specified queue with color optimization.
 *
 * The page coloring optimization attempts to locate a page that does
 * not overload other nearby pages in the object in the cpu's L1 or L2
 * caches.  We need this optimization because cpu caches tend to be
 * physical caches, while object spaces tend to be virtual.
 *
 * The page coloring optimization also, very importantly, tries to localize
 * memory to cpus and physical sockets.
 *
 * Each PQ_FREE and PQ_CACHE color queue has its own spinlock and the
 * algorithm is adjusted to localize allocations on a per-core basis.
 * This is done by 'twisting' the colors.
 *
 * The page is returned spinlocked and removed from its queue (it will
 * be on PQ_NONE), or NULL. The page is not BUSY'd.  The caller
 * is responsible for dealing with the busy-page case (usually by
 * deactivating the page and looping).
 *
 * NOTE:  This routine is carefully inlined.  A non-inlined version
 *	  is available for outside callers but the only critical path is
 *	  from within this source file.
 *
 * NOTE:  This routine assumes that the vm_pages found in PQ_CACHE and PQ_FREE
 *	  represent stable storage, allowing us to order our locks vm_page
 *	  first, then queue.
 *
 * WARNING! The returned page is not busied and may race other busying
 *	  operations, callers must check that the page is in the state they
 *	  want after busying.
 */
static __inline
vm_page_t
_vm_page_list_find(int basequeue, int index)
{
	struct vpgqueues *pq;
	vm_page_t m;

	index &= PQ_L2_MASK;
	pq = &vm_page_queues[basequeue + index];

	/*
	 * Try this cpu's colored queue first.  Test for a page unlocked,
	 * then lock the queue and locate a page.  Note that the lock order
	 * is reversed, but we do not want to dwadle on the page spinlock
	 * anyway as it is held significantly longer than the queue spinlock.
	 */
	if (TAILQ_FIRST(&pq->pl)) {
		spin_lock(&pq->spin);
		TAILQ_FOREACH(m, &pq->pl, pageq) {
			if (spin_trylock(&m->spin) == 0)
				continue;
			KKASSERT(m->queue == basequeue + index);
			pq->lastq = -1;
			return(m);
		}
		spin_unlock(&pq->spin);
	}

	m = _vm_page_list_find_wide(basequeue, index, &pq->lastq);

	return(m);
}

/*
 * If we could not find the page in the desired queue try to find it in
 * a nearby (NUMA-aware) queue, spreading out as we go.
 */
static vm_page_t
_vm_page_list_find_wide(int basequeue, int index, int *lastp)
{
	struct vpgqueues *pq;
	vm_page_t m = NULL;
	int pqmask = set_assoc_mask >> 1;
	int pqi;
	int range;
	int skip_start;
	int skip_next;
	int count;

	/*
	 * Avoid re-searching empty queues over and over again skip to
	 * pq->last if appropriate.
	 */
	if (*lastp >= 0)
		index = *lastp;

	index &= PQ_L2_MASK;
	pq = &vm_page_queues[basequeue];
	count = 0;
	skip_start = -1;
	skip_next = -1;

	/*
	 * Run local sets of 16, 32, 64, 128, up to the entire queue if all
	 * else fails (PQ_L2_MASK).
	 *
	 * pqmask is a mask, 15, 31, 63, etc.
	 *
	 * Test each queue unlocked first, then lock the queue and locate
	 * a page.  Note that the lock order is reversed, but we do not want
	 * to dwadle on the page spinlock anyway as it is held significantly
	 * longer than the queue spinlock.
	 */
	do {
		pqmask = (pqmask << 1) | 1;

		pqi = index;
		range = pqmask + 1;

		while (range > 0) {
			if (pqi >= skip_start && pqi < skip_next) {
				range -= skip_next - pqi;
				pqi = (pqi & ~pqmask) | (skip_next & pqmask);
			}
			if (range > 0 && TAILQ_FIRST(&pq[pqi].pl)) {
				spin_lock(&pq[pqi].spin);
				TAILQ_FOREACH(m, &pq[pqi].pl, pageq) {
					if (spin_trylock(&m->spin) == 0)
						continue;
					KKASSERT(m->queue == basequeue + pqi);

					/*
					 * If we had to wander too far, set
					 * *lastp to skip past empty queues.
					 */
					if (count >= 8)
						*lastp = pqi & PQ_L2_MASK;
					return(m);
				}
				spin_unlock(&pq[pqi].spin);
			}
			--range;
			++count;
			pqi = (pqi & ~pqmask) | ((pqi + 1) & pqmask);
		}
		skip_start = pqi & ~pqmask;
		skip_next = (pqi | pqmask) + 1;
	} while (pqmask != PQ_L2_MASK);

	return(m);
}

static __inline
vm_page_t
_vm_page_list_find2(int bq1, int bq2, int index)
{
	struct vpgqueues *pq1;
	struct vpgqueues *pq2;
	vm_page_t m;

	index &= PQ_L2_MASK;
	pq1 = &vm_page_queues[bq1 + index];
	pq2 = &vm_page_queues[bq2 + index];

	/*
	 * Try this cpu's colored queue first.  Test for a page unlocked,
	 * then lock the queue and locate a page.  Note that the lock order
	 * is reversed, but we do not want to dwadle on the page spinlock
	 * anyway as it is held significantly longer than the queue spinlock.
	 */
	if (TAILQ_FIRST(&pq1->pl)) {
		spin_lock(&pq1->spin);
		TAILQ_FOREACH(m, &pq1->pl, pageq) {
			if (spin_trylock(&m->spin) == 0)
				continue;
			KKASSERT(m->queue == bq1 + index);
			pq1->lastq = -1;
			pq2->lastq = -1;
			return(m);
		}
		spin_unlock(&pq1->spin);
	}

	m = _vm_page_list_find2_wide(bq1, bq2, index, &pq1->lastq, &pq2->lastq);

	return(m);
}


/*
 * This version checks two queues at the same time, widening its search
 * as we progress.  prefering basequeue1
 * and starting on basequeue2 after exhausting the first set.  The idea
 * is to try to stay localized to the cpu.
 */
static vm_page_t
_vm_page_list_find2_wide(int basequeue1, int basequeue2, int index,
			 int *lastp1, int *lastp2)
{
	struct vpgqueues *pq1;
	struct vpgqueues *pq2;
	vm_page_t m = NULL;
	int pqmask1, pqmask2;
	int pqi;
	int range;
	int skip_start1, skip_start2;
	int skip_next1, skip_next2;
	int count1, count2;

	/*
	 * Avoid re-searching empty queues over and over again skip to
	 * pq->last if appropriate.
	 */
	if (*lastp1 >= 0)
		index = *lastp1;

	index &= PQ_L2_MASK;

	pqmask1 = set_assoc_mask >> 1;
	pq1 = &vm_page_queues[basequeue1];
	count1 = 0;
	skip_start1 = -1;
	skip_next1 = -1;

	pqmask2 = set_assoc_mask >> 1;
	pq2 = &vm_page_queues[basequeue2];
	count2 = 0;
	skip_start2 = -1;
	skip_next2 = -1;

	/*
	 * Run local sets of 16, 32, 64, 128, up to the entire queue if all
	 * else fails (PQ_L2_MASK).
	 *
	 * pqmask is a mask, 15, 31, 63, etc.
	 *
	 * Test each queue unlocked first, then lock the queue and locate
	 * a page.  Note that the lock order is reversed, but we do not want
	 * to dwadle on the page spinlock anyway as it is held significantly
	 * longer than the queue spinlock.
	 */
	do {
		if (pqmask1 == PQ_L2_MASK)
			goto skip2;

		pqmask1 = (pqmask1 << 1) | 1;
		pqi = index;
		range = pqmask1 + 1;

		while (range > 0) {
			if (pqi >= skip_start1 && pqi < skip_next1) {
				range -= skip_next1 - pqi;
				pqi = (pqi & ~pqmask1) | (skip_next1 & pqmask1);
			}
			if (range > 0 && TAILQ_FIRST(&pq1[pqi].pl)) {
				spin_lock(&pq1[pqi].spin);
				TAILQ_FOREACH(m, &pq1[pqi].pl, pageq) {
					if (spin_trylock(&m->spin) == 0)
						continue;
					KKASSERT(m->queue == basequeue1 + pqi);

					/*
					 * If we had to wander too far, set
					 * *lastp to skip past empty queues.
					 */
					if (count1 >= 8)
						*lastp1 = pqi & PQ_L2_MASK;
					return(m);
				}
				spin_unlock(&pq1[pqi].spin);
			}
			--range;
			++count1;
			pqi = (pqi & ~pqmask1) | ((pqi + 1) & pqmask1);
		}
		skip_start1 = pqi & ~pqmask1;
		skip_next1 = (pqi | pqmask1) + 1;
skip2:
		if (pqmask1 < ((set_assoc_mask << 1) | 1))
			continue;

		pqmask2 = (pqmask2 << 1) | 1;
		pqi = index;
		range = pqmask2 + 1;

		while (range > 0) {
			if (pqi >= skip_start2 && pqi < skip_next2) {
				range -= skip_next2 - pqi;
				pqi = (pqi & ~pqmask2) | (skip_next2 & pqmask2);
			}
			if (range > 0 && TAILQ_FIRST(&pq2[pqi].pl)) {
				spin_lock(&pq2[pqi].spin);
				TAILQ_FOREACH(m, &pq2[pqi].pl, pageq) {
					if (spin_trylock(&m->spin) == 0)
						continue;
					KKASSERT(m->queue == basequeue2 + pqi);

					/*
					 * If we had to wander too far, set
					 * *lastp to skip past empty queues.
					 */
					if (count2 >= 8)
						*lastp2 = pqi & PQ_L2_MASK;
					return(m);
				}
				spin_unlock(&pq2[pqi].spin);
			}
			--range;
			++count2;
			pqi = (pqi & ~pqmask2) | ((pqi + 1) & pqmask2);
		}
		skip_start2 = pqi & ~pqmask2;
		skip_next2 = (pqi | pqmask2) + 1;
	} while (pqmask1 != PQ_L2_MASK && pqmask2 != PQ_L2_MASK);

	return(m);
}

/*
 * Returns a vm_page candidate for allocation.  The page is not busied so
 * it can move around.  The caller must busy the page (and typically
 * deactivate it if it cannot be busied!)
 *
 * Returns a spinlocked vm_page that has been removed from its queue.
 * (note that _vm_page_list_find() does not remove the page from its
 *  queue).
 */
vm_page_t
vm_page_list_find(int basequeue, int index)
{
	vm_page_t m;

	m = _vm_page_list_find(basequeue, index);
	if (m)
		_vm_page_rem_queue_spinlocked(m);
	return m;
}

/*
 * Find a page on the cache queue with color optimization, remove it
 * from the queue, and busy it.  The returned page will not be spinlocked.
 *
 * A candidate failure will be deactivated.  Candidates can fail due to
 * being busied by someone else, in which case they will be deactivated.
 *
 * This routine may not block.
 *
 */
static vm_page_t
vm_page_select_cache(u_short pg_color)
{
	vm_page_t m;

	for (;;) {
		m = _vm_page_list_find(PQ_CACHE, pg_color);
		if (m == NULL)
			break;
		/*
		 * (m) has been spinlocked
		 */
		_vm_page_rem_queue_spinlocked(m);
		if (vm_page_busy_try(m, TRUE)) {
			_vm_page_deactivate_locked(m, 0);
			vm_page_spin_unlock(m);
		} else {
			/*
			 * We successfully busied the page.  This can race
			 * vm_page_lookup() + busy ops so make sure the
			 * page is in the state we want.
			 */
			if ((m->flags & (PG_NEED_COMMIT | PG_MAPPED)) == 0 &&
			    m->hold_count == 0 &&
			    m->wire_count == 0 &&
			    (m->dirty & m->valid) == 0) {
				vm_page_spin_unlock(m);
				KKASSERT((m->flags & PG_UNQUEUED) == 0);
				pagedaemon_wakeup();
				return(m);
			}

			/*
			 * The page cannot be recycled, deactivate it.
			 */
			_vm_page_deactivate_locked(m, 0);
			if (_vm_page_wakeup(m)) {
				vm_page_spin_unlock(m);
				wakeup(m);
			} else {
				vm_page_spin_unlock(m);
			}
		}
	}
	return (m);
}

/*
 * Find a free page.  We attempt to inline the nominal case and fall back
 * to _vm_page_select_free() otherwise.  A busied page is removed from
 * the queue and returned.
 *
 * This routine may not block.
 */
static __inline vm_page_t
vm_page_select_free(u_short pg_color)
{
	vm_page_t m;

	for (;;) {
		m = _vm_page_list_find(PQ_FREE, pg_color);
		if (m == NULL)
			break;
		_vm_page_rem_queue_spinlocked(m);
		if (vm_page_busy_try(m, TRUE)) {
			/*
			 * Various mechanisms such as a pmap_collect can
			 * result in a busy page on the free queue.  We
			 * have to move the page out of the way so we can
			 * retry the allocation.  If the other thread is not
			 * allocating the page then m->valid will remain 0 and
			 * the pageout daemon will free the page later on.
			 *
			 * Since we could not busy the page, however, we
			 * cannot make assumptions as to whether the page
			 * will be allocated by the other thread or not,
			 * so all we can do is deactivate it to move it out
			 * of the way.  In particular, if the other thread
			 * wires the page it may wind up on the inactive
			 * queue and the pageout daemon will have to deal
			 * with that case too.
			 */
			_vm_page_deactivate_locked(m, 0);
			vm_page_spin_unlock(m);
		} else {
			/*
			 * Theoretically if we are able to busy the page
			 * atomic with the queue removal (using the vm_page
			 * lock) nobody else should have been able to mess
			 * with the page before us.
			 *
			 * Assert the page state.  Note that even though
			 * wiring doesn't adjust queues, a page on the free
			 * queue should never be wired at this point.
			 */
			KKASSERT((m->flags & (PG_UNQUEUED |
					      PG_NEED_COMMIT)) == 0);
			KASSERT(m->hold_count == 0,
				("m->hold_count is not zero "
				 "pg %p q=%d flags=%08x hold=%d wire=%d",
				 m, m->queue, m->flags,
				 m->hold_count, m->wire_count));
			KKASSERT(m->wire_count == 0);
			vm_page_spin_unlock(m);
			pagedaemon_wakeup();

			/* return busied and removed page */
			return(m);
		}
	}
	return(m);
}

static __inline vm_page_t
vm_page_select_free_or_cache(u_short pg_color, int *fromcachep)
{
	vm_page_t m;

	*fromcachep = 0;
	for (;;) {
		m = _vm_page_list_find2(PQ_FREE, PQ_CACHE, pg_color);
		if (m == NULL)
			break;
		if (vm_page_busy_try(m, TRUE)) {
			_vm_page_rem_queue_spinlocked(m);
			_vm_page_deactivate_locked(m, 0);
			vm_page_spin_unlock(m);
		} else if (m->queue - m->pc == PQ_FREE) {
			/*
			 * We successfully busied the page, PQ_FREE case
			 */
			_vm_page_rem_queue_spinlocked(m);
			KKASSERT((m->flags & (PG_UNQUEUED |
					      PG_NEED_COMMIT)) == 0);
			KASSERT(m->hold_count == 0,
				("m->hold_count is not zero "
				 "pg %p q=%d flags=%08x hold=%d wire=%d",
				 m, m->queue, m->flags,
				 m->hold_count, m->wire_count));
			KKASSERT(m->wire_count == 0);
			vm_page_spin_unlock(m);
			pagedaemon_wakeup();

			/* return busied and removed page */
			return(m);
		} else {
			/*
			 * We successfully busied the page, PQ_CACHE case
			 *
			 * This can race vm_page_lookup() + busy ops, so make
			 * sure the page is in the state we want.
			 */
			_vm_page_rem_queue_spinlocked(m);
			if ((m->flags & (PG_NEED_COMMIT | PG_MAPPED)) == 0 &&
			    m->hold_count == 0 &&
			    m->wire_count == 0 &&
			    (m->dirty & m->valid) == 0) {
				vm_page_spin_unlock(m);
				KKASSERT((m->flags & PG_UNQUEUED) == 0);
				pagedaemon_wakeup();
				*fromcachep = 1;
				return(m);
			}

			/*
			 * The page cannot be recycled, deactivate it.
			 */
			_vm_page_deactivate_locked(m, 0);
			if (_vm_page_wakeup(m)) {
				vm_page_spin_unlock(m);
				wakeup(m);
			} else {
				vm_page_spin_unlock(m);
			}
		}
	}
	return(m);
}

/*
 * vm_page_alloc()
 *
 * Allocate and return a memory cell associated with this VM object/offset
 * pair.  If object is NULL an unassociated page will be allocated.
 *
 * The returned page will be busied and removed from its queues.  This
 * routine can block and may return NULL if a race occurs and the page
 * is found to already exist at the specified (object, pindex).
 *
 *	VM_ALLOC_NORMAL		- Allow use of cache pages, nominal free drain
 *	VM_ALLOC_QUICK		- Like normal but cannot use cache
 *	VM_ALLOC_SYSTEM		- Greater free drain
 *	VM_ALLOC_INTERRUPT	- Allow free list to be completely drained
 *
 *	VM_ALLOC_CPU(n)		- Allocate using specified cpu localization
 *
 *	VM_ALLOC_ZERO		- Zero the page if we have to allocate it.
 *				  (vm_page_grab() and vm_page_alloczwq() ONLY!)
 *
 *	VM_ALLOC_FORCE_ZERO	- Zero the page unconditionally.
 *				  (vm_page_grab() and vm_page_alloczwq() ONLY!)
 *
 *	VM_ALLOC_NULL_OK	- Return NULL on insertion collision, else
 *				  panic on insertion collisions.
 *				  (vm_page_grab() and vm_page_alloczwq() ONLY!)
 *
 * The object must be held if not NULL
 *
 * This routine may not block
 *
 * Additional special handling is required when called from an interrupt
 * (VM_ALLOC_INTERRUPT).  We are not allowed to mess with the page cache
 * in this case.
 */
vm_page_t
vm_page_alloc(vm_object_t object, vm_pindex_t pindex, int page_req)
{
	globaldata_t gd;
	vm_object_t obj;
	vm_page_t m;
	u_short pg_color;
	int cpuid_local;
	int fromcache;

#if 0
	/*
	 * Special per-cpu free VM page cache.  The pages are pre-busied
	 * and pre-zerod for us.
	 */
	if (gd->gd_vmpg_count && (page_req & VM_ALLOC_USE_GD)) {
		crit_enter_gd(gd);
		if (gd->gd_vmpg_count) {
			m = gd->gd_vmpg_array[--gd->gd_vmpg_count];
			crit_exit_gd(gd);
			goto done;
                }
		crit_exit_gd(gd);
        }
#endif
	m = NULL;

	/*
	 * CPU LOCALIZATION
	 *
	 * CPU localization algorithm.  Break the page queues up by physical
	 * id and core id (note that two cpu threads will have the same core
	 * id, and core_id != gd_cpuid).
	 *
	 * This is nowhere near perfect, for example the last pindex in a
	 * subgroup will overflow into the next cpu or package.  But this
	 * should get us good page reuse locality in heavy mixed loads.
	 *
	 * (may be executed before the APs are started, so other GDs might
	 *  not exist!)
	 */
	if (page_req & VM_ALLOC_CPU_SPEC)
		cpuid_local = VM_ALLOC_GETCPU(page_req);
	else
		cpuid_local = mycpu->gd_cpuid;

	pg_color = vm_get_pg_color(cpuid_local, object, pindex);

	KKASSERT(page_req & (VM_ALLOC_NORMAL | VM_ALLOC_QUICK |
			     VM_ALLOC_INTERRUPT | VM_ALLOC_SYSTEM));

	/*
	 * Certain system threads (pageout daemon, buf_daemon's) are
	 * allowed to eat deeper into the free page list.
	 */
	if (curthread->td_flags & TDF_SYSTHREAD)
		page_req |= VM_ALLOC_SYSTEM;

	/*
	 * To avoid live-locks only compare against v_free_reserved.  The
	 * pageout daemon has extra tests for this.
	 */
loop:
	gd = mycpu;
	if (gd->gd_vmstats.v_free_count >= gd->gd_vmstats.v_free_reserved ||
	    ((page_req & VM_ALLOC_INTERRUPT) &&
	     gd->gd_vmstats.v_free_count > 0) ||
	    ((page_req & VM_ALLOC_SYSTEM) &&
	     gd->gd_vmstats.v_cache_count == 0 &&
	     gd->gd_vmstats.v_free_count >
	     gd->gd_vmstats.v_interrupt_free_min)
	) {
		/*
		 * The free queue has sufficient free pages to take one out.
		 *
		 * However, if the free queue is strained the scan may widen
		 * to the entire queue and cause a great deal of SMP
		 * contention, so we use a double-queue-scan if we can
		 * to avoid this.
		 */
		if (page_req & VM_ALLOC_NORMAL) {
			m = vm_page_select_free_or_cache(pg_color, &fromcache);
			if (m && fromcache)
				goto found_cache;
		} else {
			m = vm_page_select_free(pg_color);
		}
	} else if (page_req & VM_ALLOC_NORMAL) {
		/*
		 * Allocatable from the cache (non-interrupt only).  On
		 * success, we must free the page and try again, thus
		 * ensuring that vmstats.v_*_free_min counters are replenished.
		 */
#ifdef INVARIANTS
		if (curthread->td_preempted) {
			kprintf("vm_page_alloc(): warning, attempt to allocate"
				" cache page from preempting interrupt\n");
			m = NULL;
		} else {
			m = vm_page_select_cache(pg_color);
		}
#else
		m = vm_page_select_cache(pg_color);
#endif
		/*
		 * On success move the page into the free queue and loop.
		 *
		 * Only do this if we can safely acquire the vm_object lock,
		 * because this is effectively a random page and the caller
		 * might be holding the lock shared, we don't want to
		 * deadlock.
		 */
		if (m != NULL) {
found_cache:
			KASSERT(m->dirty == 0,
				("Found dirty cache page %p", m));
			if ((obj = m->object) != NULL) {
				if (vm_object_hold_try(obj)) {
					if (__predict_false((m->flags & (PG_MAPPED|PG_WRITEABLE)) != 0))
						vm_page_protect(m, VM_PROT_NONE);
					vm_page_free(m);
					/* m->object NULL here */
					vm_object_drop(obj);
				} else {
					vm_page_deactivate(m);
					vm_page_wakeup(m);
				}
			} else {
				if (__predict_false((m->flags & (PG_MAPPED|PG_WRITEABLE)) != 0))
					vm_page_protect(m, VM_PROT_NONE);
				vm_page_free(m);
			}
			goto loop;
		}

		/*
		 * On failure return NULL
		 */
		atomic_add_int(&vm_pageout_deficit, 1);
		pagedaemon_wakeup();
		return (NULL);
	} else {
		/*
		 * No pages available, wakeup the pageout daemon and give up.
		 */
		atomic_add_int(&vm_pageout_deficit, 1);
		pagedaemon_wakeup();
		return (NULL);
	}

	/*
	 * v_free_count can race so loop if we don't find the expected
	 * page.
	 */
	if (m == NULL) {
		vmstats_rollup();
		goto loop;
	}

	/*
	 * Good page found.  The page has already been busied for us and
	 * removed from its queues.
	 */
	KASSERT(m->dirty == 0,
		("vm_page_alloc: free/cache page %p was dirty", m));
	KKASSERT(m->queue == PQ_NONE);

#if 0
done:
#endif
	/*
	 * Initialize the structure, inheriting some flags but clearing
	 * all the rest.  The page has already been busied for us.
	 */
	vm_page_flag_clear(m, ~PG_KEEP_NEWPAGE_MASK);

	KKASSERT(m->wire_count == 0);
	KKASSERT((m->busy_count & PBUSY_MASK) == 0);
	m->act_count = 0;
	m->valid = 0;

	/*
	 * Caller must be holding the object lock (asserted by
	 * vm_page_insert()).
	 *
	 * NOTE: Inserting a page here does not insert it into any pmaps
	 *	 (which could cause us to block allocating memory).
	 *
	 * NOTE: If no object an unassociated page is allocated, m->pindex
	 *	 can be used by the caller for any purpose.
	 */
	if (object) {
		if (vm_page_insert(m, object, pindex) == FALSE) {
			vm_page_free(m);
			if ((page_req & VM_ALLOC_NULL_OK) == 0)
				panic("PAGE RACE %p[%ld]/%p",
				      object, (long)pindex, m);
			m = NULL;
		}
	} else {
		m->pindex = pindex;
	}

	/*
	 * Don't wakeup too often - wakeup the pageout daemon when
	 * we would be nearly out of memory.
	 */
	pagedaemon_wakeup();

	/*
	 * A BUSY page is returned.
	 */
	return (m);
}

/*
 * Returns number of pages available in our DMA memory reserve
 * (adjusted with vm.dma_reserved=<value>m in /boot/loader.conf)
 */
vm_size_t
vm_contig_avail_pages(void)
{
	alist_blk_t blk;
	alist_blk_t count;
	alist_blk_t bfree;
	spin_lock(&vm_contig_spin);
	bfree = alist_free_info(&vm_contig_alist, &blk, &count);
	spin_unlock(&vm_contig_spin);

	return bfree;
}

/*
 * Attempt to allocate contiguous physical memory with the specified
 * requirements.
 */
vm_page_t
vm_page_alloc_contig(vm_paddr_t low, vm_paddr_t high,
		     unsigned long alignment, unsigned long boundary,
		     unsigned long size, vm_memattr_t memattr)
{
	alist_blk_t blk;
	vm_page_t m;
	vm_pindex_t i;
#if 0
	static vm_pindex_t contig_rover;
#endif

	alignment >>= PAGE_SHIFT;
	if (alignment == 0)
		alignment = 1;
	boundary >>= PAGE_SHIFT;
	if (boundary == 0)
		boundary = 1;
	size = (size + PAGE_MASK) >> PAGE_SHIFT;

#if 0
	/*
	 * Disabled temporarily until we find a solution for DRM (a flag
	 * to always use the free space reserve, for performance).
	 */
	if (high == BUS_SPACE_MAXADDR && alignment <= PAGE_SIZE &&
	    boundary <= PAGE_SIZE && size == 1 &&
	    memattr == VM_MEMATTR_DEFAULT) {
		/*
		 * Any page will work, use vm_page_alloc()
		 * (e.g. when used from kmem_alloc_attr())
		 */
		m = vm_page_alloc(NULL, (contig_rover++) & 0x7FFFFFFF,
				  VM_ALLOC_NORMAL | VM_ALLOC_SYSTEM |
				  VM_ALLOC_INTERRUPT);
		m->valid = VM_PAGE_BITS_ALL;
		vm_page_wire(m);
		vm_page_wakeup(m);
	} else
#endif
	{
		/*
		 * Use the low-memory dma reserve
		 */
		spin_lock(&vm_contig_spin);
		blk = alist_alloc(&vm_contig_alist, 0, size);
		if (blk == ALIST_BLOCK_NONE) {
			spin_unlock(&vm_contig_spin);
			if (bootverbose) {
				kprintf("vm_page_alloc_contig: %ldk nospace\n",
					(size << PAGE_SHIFT) / 1024);
				print_backtrace(5);
			}
			return(NULL);
		}
		if (high && ((vm_paddr_t)(blk + size) << PAGE_SHIFT) > high) {
			alist_free(&vm_contig_alist, blk, size);
			spin_unlock(&vm_contig_spin);
			if (bootverbose) {
				kprintf("vm_page_alloc_contig: %ldk high "
					"%016jx failed\n",
					(size << PAGE_SHIFT) / 1024,
					(intmax_t)high);
			}
			return(NULL);
		}
		spin_unlock(&vm_contig_spin);

		/*
		 * Base vm_page_t of range
		 */
		m = PHYS_TO_VM_PAGE((vm_paddr_t)blk << PAGE_SHIFT);
	}
	if (vm_contig_verbose) {
		kprintf("vm_page_alloc_contig: %016jx/%ldk "
			"(%016jx-%016jx al=%lu bo=%lu pgs=%lu attr=%d\n",
			(intmax_t)m->phys_addr,
			(size << PAGE_SHIFT) / 1024,
			low, high, alignment, boundary, size, memattr);
	}
	if (memattr != VM_MEMATTR_DEFAULT) {
		for (i = 0; i < size; ++i) {
			KKASSERT(m[i].flags & PG_FICTITIOUS);
			pmap_page_set_memattr(&m[i], memattr);
		}
	}
	return m;
}

/*
 * Free contiguously allocated pages.  The pages will be wired but not busy.
 * When freeing to the alist we leave them wired and not busy.
 */
void
vm_page_free_contig(vm_page_t m, unsigned long size)
{
	vm_paddr_t pa = VM_PAGE_TO_PHYS(m);
	vm_pindex_t start = pa >> PAGE_SHIFT;
	vm_pindex_t pages = (size + PAGE_MASK) >> PAGE_SHIFT;
	vm_pindex_t i;

	if (vm_contig_verbose) {
		kprintf("vm_page_free_contig:  %016jx/%ldk\n",
			(intmax_t)pa, size / 1024);
	}
	if (pa < vm_low_phys_reserved) {
		/*
		 * Just assert check the first page for convenience.
		 */
		KKASSERT(m->wire_count == 1);
		KKASSERT(m->flags & PG_FICTITIOUS);
		KKASSERT(pa + size <= vm_low_phys_reserved);
		for (i = 0; i < pages; ++i) {
			/*
			 * Reset state to invalidate, not dirty, normal
			 * cpu caching
			 */
			vm_page_t p = &m[i];

			p->valid = 0;
			vm_page_undirty(p);
			if (p->pat_mode != PAT_WRITE_BACK) {
				p->pat_mode = PAT_WRITE_BACK;
				pmap_page_set_memattr(p, PAT_WRITE_BACK);
			}
		}
		spin_lock(&vm_contig_spin);
		alist_free(&vm_contig_alist, start, pages);
		spin_unlock(&vm_contig_spin);
	} else {
		while (pages) {
			/* XXX FUTURE, maybe (pair with vm_pg_contig_alloc()) */
			/*vm_page_flag_clear(m, PG_FICTITIOUS | PG_UNQUEUED);*/
			vm_page_busy_wait(m, FALSE, "cpgfr");
			vm_page_unwire(m, 0);
			vm_page_free(m);
			--pages;
			++m;
		}

	}
}


/*
 * Wait for sufficient free memory for nominal heavy memory use kernel
 * operations.
 *
 * WARNING!  Be sure never to call this in any vm_pageout code path, which
 *	     will trivially deadlock the system.
 */
void
vm_wait_nominal(void)
{
	while (vm_paging_min())
		vm_wait(0);
}

/*
 * Test if vm_wait_nominal() would block.
 */
int
vm_test_nominal(void)
{
	if (vm_paging_min())
		return(1);
	return(0);
}

/*
 * Block until free pages are available for allocation, called in various
 * places before memory allocations, and occurs before the minimum is reached.
 * Typically in the I/O path.
 *
 * The caller may loop if vm_paging_min() is TRUE (free pages below minimum),
 * so we cannot be more generous then that.
 */
void
vm_wait(int timo)
{
	/*
	 * never wait forever
	 */
	if (timo == 0)
		timo = hz;
	lwkt_gettoken(&vm_token);

	if (curthread == pagethread ||
	    curthread == emergpager) {
		/*
		 * The pageout daemon itself needs pages, this is bad.
		 */
		if (vm_paging_min()) {
			vm_pageout_pages_needed = 1;
			tsleep(&vm_pageout_pages_needed, 0, "VMWait", timo);
		}
	} else {
		/*
		 * Wakeup the pageout daemon if necessary and wait.
		 *
		 * Do not wait indefinitely for the target to be reached,
		 * as load might prevent it from being reached any time soon.
		 * But wait a little to try to slow down page allocations
		 * and to give more important threads (the pagedaemon)
		 * allocation priority.
		 *
		 * The vm_paging_min() test is a safety.
		 *
		 * I/O waits are given a slightly lower priority (higher nice)
		 * than VM waits.
		 */
		int nice;

		nice = curthread->td_proc ? curthread->td_proc->p_nice : 0;
		/*if (vm_paging_wait() || vm_paging_min())*/
		if (vm_paging_min_nice(nice + 1))
		{
			if (vm_pages_needed <= 1) {
				++vm_pages_needed;
				wakeup(&vm_pages_needed);
			}
			++vm_pages_waiting;	/* SMP race ok */
			tsleep(&vmstats.v_free_count, 0, "vmwait", timo);
		}
	}
	lwkt_reltoken(&vm_token);
}

/*
 * Block until free pages are available for allocation, called in the
 * page-fault code.  We must stall indefinitely (except for certain
 * conditions) when the free page count becomes severe.
 *
 * Called only from vm_fault so that processes page faulting can be
 * easily tracked.
 *
 * The process nice value determines the trip point.  This way niced
 * processes which are heavy memory users do not completely mess the
 * machine up for normal processes.
 */
void
vm_wait_pfault(void)
{
	int nice;

	/*
	 * Wakeup the pageout daemon if necessary and wait.
	 *
	 * Allow VM faults down to the minimum free page count, but only
	 * stall once paging becomes severe.
	 *
	 * Do not wait indefinitely for the target to be reached,
	 * as load might prevent it from being reached any time soon.
	 * But wait a little to try to slow down page allocations
	 * and to give more important threads (the pagedaemon)
	 * allocation priority.
	 */
	nice = curthread->td_proc ? curthread->td_proc->p_nice : 0;

	if (vm_paging_min_nice(nice)) {
		lwkt_gettoken(&vm_token);
		do {
			thread_t td;

			if (vm_pages_needed <= 1) {
				++vm_pages_needed;
				wakeup(&vm_pages_needed);
			}
			++vm_pages_waiting;	/* SMP race ok */
			tsleep(&vmstats.v_free_count, 0, "pfault",
				hz / 10 + 1);

			/*
			 * Do not stay stuck in the loop if the system
			 * is trying to kill the process.
			 */
			td = curthread;
			if (td->td_proc &&
			    (td->td_proc->p_flags & P_LOWMEMKILL))
			{
				break;
			}
		} while (vm_paging_severe());
		lwkt_reltoken(&vm_token);
	}
}

/*
 * Put the specified page on the active list (if appropriate).  Ensure
 * that act_count is at least ACT_INIT but do not otherwise mess with it.
 *
 * The caller should be holding the page busied ? XXX
 * This routine may not block.
 *
 * It is ok if the page is wired (so buffer cache operations don't have
 * to mess with the page queues).
 */
void
vm_page_activate(vm_page_t m)
{
	u_short oqueue;

	/*
	 * If already active or inappropriate, just set act_count and
	 * return.  We don't have to spin-lock the page.
	 */
	if (m->queue - m->pc == PQ_ACTIVE ||
	    (m->flags & (PG_FICTITIOUS | PG_UNQUEUED))) {
		if (m->act_count < ACT_INIT)
			m->act_count = ACT_INIT;
		return;
	}

	vm_page_spin_lock(m);
	if (m->queue - m->pc != PQ_ACTIVE &&
	    (m->flags & (PG_FICTITIOUS | PG_UNQUEUED)) == 0) {
		_vm_page_queue_spin_lock(m);
		oqueue = _vm_page_rem_queue_spinlocked(m);
		/* page is left spinlocked, queue is unlocked */

		if (oqueue == PQ_CACHE)
			mycpu->gd_cnt.v_reactivated++;
		if (m->act_count < ACT_INIT)
			m->act_count = ACT_INIT;
		_vm_page_add_queue_spinlocked(m, PQ_ACTIVE + m->pc, 0);
		_vm_page_and_queue_spin_unlock(m);
		if (oqueue == PQ_CACHE || oqueue == PQ_FREE)
			pagedaemon_wakeup();
	} else {
		if (m->act_count < ACT_INIT)
			m->act_count = ACT_INIT;
		vm_page_spin_unlock(m);
	}
}

void
vm_page_soft_activate(vm_page_t m)
{
	if (m->queue - m->pc == PQ_ACTIVE ||
	    (m->flags & (PG_FICTITIOUS | PG_UNQUEUED))) {
		if (m->act_count < ACT_INIT)
			m->act_count = ACT_INIT;
	} else {
		vm_page_activate(m);
	}
}

/*
 * Helper routine for vm_page_free_toq() and vm_page_cache().  This
 * routine is called when a page has been added to the cache or free
 * queues.
 *
 * This routine may not block.
 */
static __inline void
vm_page_free_wakeup(void)
{
	globaldata_t gd = mycpu;

	/*
	 * If the pageout daemon itself needs pages, then tell it that
	 * there are some free.
	 */
	if (vm_pageout_pages_needed &&
	    gd->gd_vmstats.v_cache_count + gd->gd_vmstats.v_free_count >=
	    gd->gd_vmstats.v_pageout_free_min
	) {
		vm_pageout_pages_needed = 0;
		wakeup(&vm_pageout_pages_needed);
	}

	/*
	 * Wakeup processes that are waiting on memory.
	 *
	 * Generally speaking we want to wakeup stuck processes as soon as
	 * possible.  !vm_page_count_min(0) is the absolute minimum point
	 * where we can do this.  Wait a bit longer to reduce degenerate
	 * re-blocking (vm_page_free_hysteresis).
	 *
	 * The target check is a safety to make sure the min-check
	 * w/hysteresis does not exceed the normal target1.
	 */
	if (vm_pages_waiting) {
		if (!vm_paging_min_dnc(vm_page_free_hysteresis) ||
		    !vm_paging_target1())
		{
			vm_pages_waiting = 0;
			wakeup(&vmstats.v_free_count);
			++mycpu->gd_cnt.v_ppwakeups;
		}
	}
}

/*
 * Returns the given page to the PQ_FREE or PQ_HOLD list and disassociates
 * it from its VM object.
 *
 * The vm_page must be BUSY on entry.  BUSY will be released on
 * return (the page will have been freed).
 */
void
vm_page_free_toq(vm_page_t m)
{
	/*
	 * The page must not be mapped when freed, but we may have to call
	 * pmap_mapped_sync() to validate this.
	 */
	mycpu->gd_cnt.v_tfree++;
	if (m->flags & (PG_MAPPED | PG_WRITEABLE))
		pmap_mapped_sync(m);
	KKASSERT((m->flags & PG_MAPPED) == 0);
	KKASSERT(m->busy_count & PBUSY_LOCKED);

	if ((m->busy_count & PBUSY_MASK) || ((m->queue - m->pc) == PQ_FREE)) {
		kprintf("vm_page_free: pindex(%lu), busy %08x, "
			"hold(%d)\n",
			(u_long)m->pindex, m->busy_count, m->hold_count);
		if ((m->queue - m->pc) == PQ_FREE)
			panic("vm_page_free: freeing free page");
		else
			panic("vm_page_free: freeing busy page");
	}

	/*
	 * Remove from object, spinlock the page and its queues and
	 * remove from any queue.  No queue spinlock will be held
	 * after this section (because the page was removed from any
	 * queue).
	 */
	vm_page_remove(m);

	/*
	 * No further management of fictitious pages occurs beyond object
	 * and queue removal.
	 */
	if ((m->flags & PG_FICTITIOUS) != 0) {
		KKASSERT(m->queue == PQ_NONE);
		vm_page_wakeup(m);
		return;
	}
	vm_page_and_queue_spin_lock(m);
	_vm_page_rem_queue_spinlocked(m);

	/*
	 * Reset state to invalidate, not dirty, normal cpu caching
	 */
	m->valid = 0;
	vm_page_undirty(m);
	if (m->pat_mode != PAT_WRITE_BACK) {
		m->pat_mode = PAT_WRITE_BACK;
		pmap_page_set_memattr(m, PAT_WRITE_BACK);
	}

	if (m->wire_count != 0) {
		if (m->wire_count > 1) {
		    panic(
			"vm_page_free: invalid wire count (%d), pindex: 0x%lx",
			m->wire_count, (long)m->pindex);
		}
		panic("vm_page_free: freeing wired page");
	}

	if (!MD_PAGE_FREEABLE(m))
		panic("vm_page_free: page %p is still mapped!", m);

	/*
	 * Clear the PG_NEED_COMMIT and the PG_UNQUEUED flags.  The
	 * page returns to normal operation and will be placed in
	 * the PQ_HOLD or PQ_FREE queue.
	 */
	vm_page_flag_clear(m, PG_NEED_COMMIT | PG_UNQUEUED);

	if (m->hold_count != 0) {
		_vm_page_add_queue_spinlocked(m, PQ_HOLD + m->pc, 0);
	} else {
		_vm_page_add_queue_spinlocked(m, PQ_FREE + m->pc, 1);
	}

	/*
	 * This sequence allows us to clear BUSY while still holding
	 * its spin lock, which reduces contention vs allocators.  We
	 * must not leave the queue locked or _vm_page_wakeup() may
	 * deadlock.
	 */
	_vm_page_queue_spin_unlock(m);
	if (_vm_page_wakeup(m)) {
		vm_page_spin_unlock(m);
		wakeup(m);
	} else {
		vm_page_spin_unlock(m);
	}
	vm_page_free_wakeup();
}

/*
 * Mark this page as wired down by yet another map.  We do not adjust the
 * queue the page is on, it will be checked for wiring as-needed.
 *
 * This function has no effect on fictitious pages.
 *
 * Caller must be holding the page busy.
 */
void
vm_page_wire(vm_page_t m)
{
	KKASSERT(m->busy_count & PBUSY_LOCKED);
	if ((m->flags & PG_FICTITIOUS) == 0) {
		if (atomic_fetchadd_int(&m->wire_count, 1) == 0) {
			atomic_add_long(&mycpu->gd_vmstats_adj.v_wire_count, 1);
		}
		KASSERT(m->wire_count != 0,
			("vm_page_wire: wire_count overflow m=%p", m));
	}
}

/*
 * Release one wiring of this page, potentially enabling it to be paged again.
 *
 * Note that wired pages are no longer unconditionally removed from the
 * paging queues, so the page may already be on a queue.  Move the page
 * to the desired queue if necessary.
 *
 * Many pages placed on the inactive queue should actually go
 * into the cache, but it is difficult to figure out which.  What
 * we do instead, if the inactive target is well met, is to put
 * clean pages at the head of the inactive queue instead of the tail.
 * This will cause them to be moved to the cache more quickly and
 * if not actively re-referenced, freed more quickly.  If we just
 * stick these pages at the end of the inactive queue, heavy filesystem
 * meta-data accesses can cause an unnecessary paging load on memory bound 
 * processes.  This optimization causes one-time-use metadata to be
 * reused more quickly.
 *
 * Pages marked PG_NEED_COMMIT are always activated and never placed on
 * the inactive queue.  This helps the pageout daemon determine memory
 * pressure and act on out-of-memory situations more quickly.
 *
 * BUT, if we are in a low-memory situation we have no choice but to
 * put clean pages on the cache queue.
 *
 * A number of routines use vm_page_unwire() to guarantee that the page
 * will go into either the inactive or active queues, and will NEVER
 * be placed in the cache - for example, just after dirtying a page.
 * dirty pages in the cache are not allowed.
 *
 * PG_FICTITIOUS or PG_UNQUEUED pages are never moved to any queue, and
 * the wire_count will not be adjusted in any way for a PG_FICTITIOUS
 * page.
 *
 * This routine may not block.
 */
void
vm_page_unwire(vm_page_t m, int activate)
{
	KKASSERT(m->busy_count & PBUSY_LOCKED);
	if (m->flags & PG_FICTITIOUS) {
		/* do nothing */
	} else if ((int)m->wire_count <= 0) {
		panic("vm_page_unwire: invalid wire count: %d", m->wire_count);
	} else {
		if (atomic_fetchadd_int(&m->wire_count, -1) == 1) {
			atomic_add_long(&mycpu->gd_vmstats_adj.v_wire_count,-1);
			if (m->flags & PG_UNQUEUED) {
				;
			} else if (activate || (m->flags & PG_NEED_COMMIT)) {
				vm_page_activate(m);
			} else {
				vm_page_deactivate(m);
			}
		}
	}
}

/*
 * Move the specified page to the inactive queue.
 *
 * Normally athead is 0 resulting in LRU operation.  athead is set
 * to 1 if we want this page to be 'as if it were placed in the cache',
 * except without unmapping it from the process address space.
 *
 * vm_page's spinlock must be held on entry and will remain held on return.
 * This routine may not block.  The caller does not have to hold the page
 * busied but should have some sort of interlock on its validity.
 *
 * It is ok if the page is wired (so buffer cache operations don't have
 * to mess with the page queues).
 */
static void
_vm_page_deactivate_locked(vm_page_t m, int athead)
{
	u_short oqueue;

	/*
	 * Ignore if already inactive.
	 */
	if (m->queue - m->pc == PQ_INACTIVE ||
	    (m->flags & (PG_FICTITIOUS | PG_UNQUEUED))) {
		return;
	}

	_vm_page_queue_spin_lock(m);
	oqueue = _vm_page_rem_queue_spinlocked(m);

	if ((m->flags & (PG_FICTITIOUS | PG_UNQUEUED)) == 0) {
		if (oqueue == PQ_CACHE)
			mycpu->gd_cnt.v_reactivated++;
		vm_page_flag_clear(m, PG_WINATCFLS);
		_vm_page_add_queue_spinlocked(m, PQ_INACTIVE + m->pc, athead);
		if (athead == 0) {
			atomic_add_long(
				&vm_page_queues[PQ_INACTIVE + m->pc].adds, 1);
		}
	}
	/* NOTE: PQ_NONE if condition not taken */
	_vm_page_queue_spin_unlock(m);
	/* leaves vm_page spinlocked */
}

/*
 * Attempt to deactivate a page.
 *
 * No requirements.  We can pre-filter before getting the spinlock.
 *
 * It is ok if the page is wired (so buffer cache operations don't have
 * to mess with the page queues).
 */
void
vm_page_deactivate(vm_page_t m)
{
	if (m->queue - m->pc != PQ_INACTIVE &&
	    (m->flags & (PG_FICTITIOUS | PG_UNQUEUED)) == 0) {
		vm_page_spin_lock(m);
		_vm_page_deactivate_locked(m, 0);
		vm_page_spin_unlock(m);
	}
}

void
vm_page_deactivate_locked(vm_page_t m)
{
	_vm_page_deactivate_locked(m, 0);
}

/*
 * Attempt to move a busied page to PQ_CACHE, then unconditionally unbusy it.
 *
 * This function returns non-zero if it successfully moved the page to
 * PQ_CACHE.
 *
 * This function unconditionally unbusies the page on return.
 */
int
vm_page_try_to_cache(vm_page_t m)
{
	/*
	 * Shortcut if we obviously cannot move the page, or if the
	 * page is already on the cache queue, or it is ficitious.
	 *
	 * Never allow a wired page into the cache.
	 */
	if (m->dirty || m->hold_count || m->wire_count ||
	    m->queue - m->pc == PQ_CACHE ||
	    (m->flags & (PG_UNQUEUED | PG_NEED_COMMIT | PG_FICTITIOUS))) {
		vm_page_wakeup(m);
		return(0);
	}

	/*
	 * Page busied by us and no longer spinlocked.  Dirty pages cannot
	 * be moved to the cache, but can be deactivated.  However, users
	 * of this function want to move pages closer to the cache so we
	 * only deactivate it if it is in PQ_ACTIVE.  We do not re-deactivate.
	 */
	vm_page_test_dirty(m);
	if (m->dirty || (m->flags & PG_NEED_COMMIT)) {
		if (m->queue - m->pc == PQ_ACTIVE)
			vm_page_deactivate(m);
		vm_page_wakeup(m);
		return(0);
	}
	vm_page_cache(m);
	return(1);
}

/*
 * Attempt to free the page.  If we cannot free it, we do nothing.
 * 1 is returned on success, 0 on failure.
 *
 * The page can be in any state, including already being on the free
 * queue.  Check to see if it really can be freed.  Note that we disallow
 * this ad-hoc operation if the page is flagged PG_UNQUEUED.
 *
 * Caller provides an unlocked/non-busied page.
 * No requirements.
 */
int
vm_page_try_to_free(vm_page_t m)
{
	if (vm_page_busy_try(m, TRUE))
		return(0);

	if (m->dirty ||				/* can't free if it is dirty */
	    m->hold_count ||			/* or held (XXX may be wrong) */
	    m->wire_count ||			/* or wired */
	    (m->flags & (PG_UNQUEUED |		/* or unqueued */
			 PG_NEED_COMMIT |	/* or needs a commit */
			 PG_FICTITIOUS)) ||	/* or is fictitious */
	    m->queue - m->pc == PQ_FREE ||	/* already on PQ_FREE */
	    m->queue - m->pc == PQ_HOLD) {	/* already on PQ_HOLD */
		vm_page_wakeup(m);
		return(0);
	}

	/*
	 * We can probably free the page.
	 *
	 * Page busied by us and no longer spinlocked.  Dirty pages will
	 * not be freed by this function.    We have to re-test the
	 * dirty bit after cleaning out the pmaps.
	 */
	vm_page_test_dirty(m);
	if (m->dirty || (m->flags & PG_NEED_COMMIT)) {
		vm_page_wakeup(m);
		return(0);
	}
	vm_page_protect(m, VM_PROT_NONE);
	if (m->dirty || (m->flags & PG_NEED_COMMIT)) {
		vm_page_wakeup(m);
		return(0);
	}
	vm_page_free(m);
	return(1);
}

/*
 * vm_page_cache
 *
 * Put the specified page onto the page cache queue (if appropriate).
 *
 * The page must be busy, and this routine will release the busy and
 * possibly even free the page.
 */
void
vm_page_cache(vm_page_t m)
{
	/*
	 * Not suitable for the cache
	 */
	if ((m->flags & (PG_UNQUEUED | PG_NEED_COMMIT | PG_FICTITIOUS)) ||
	    (m->busy_count & PBUSY_MASK) ||
	    m->wire_count || m->hold_count) {
		vm_page_wakeup(m);
		return;
	}

	/*
	 * Already in the cache (and thus not mapped)
	 */
	if ((m->queue - m->pc) == PQ_CACHE) {
		KKASSERT((m->flags & PG_MAPPED) == 0);
		vm_page_wakeup(m);
		return;
	}

#if 0
	/*
	 * REMOVED - it is possible for dirty to get set at any time as
	 *	     long as the page is still mapped and writeable.
	 *
	 * Caller is required to test m->dirty, but note that the act of
	 * removing the page from its maps can cause it to become dirty
	 * on an SMP system due to another cpu running in usermode.
	 */
	if (m->dirty) {
		panic("vm_page_cache: caching a dirty page, pindex: %ld",
			(long)m->pindex);
	}
#endif

	/*
	 * Remove all pmaps and indicate that the page is not
	 * writeable or mapped.  Our vm_page_protect() call may
	 * have blocked (especially w/ VM_PROT_NONE), so recheck
	 * everything.
	 */
	if (m->flags & (PG_MAPPED | PG_WRITEABLE)) {
		vm_page_protect(m, VM_PROT_NONE);
		pmap_mapped_sync(m);
	}
	if ((m->flags & (PG_UNQUEUED | PG_MAPPED)) ||
	    (m->busy_count & PBUSY_MASK) ||
	    m->wire_count || m->hold_count) {
		vm_page_wakeup(m);
	} else if (m->dirty || (m->flags & PG_NEED_COMMIT)) {
		vm_page_deactivate(m);
		vm_page_wakeup(m);
	} else {
		_vm_page_and_queue_spin_lock(m);
		_vm_page_rem_queue_spinlocked(m);
		_vm_page_add_queue_spinlocked(m, PQ_CACHE + m->pc, 0);
		_vm_page_and_queue_spin_unlock(m);
		vm_page_wakeup(m);
		vm_page_free_wakeup();
	}
}

/*
 * vm_page_dontneed()
 *
 * Cache, deactivate, or do nothing as appropriate.  This routine
 * is typically used by madvise() MADV_DONTNEED.
 *
 * Generally speaking we want to move the page into the cache so
 * it gets reused quickly.  However, this can result in a silly syndrome
 * due to the page recycling too quickly.  Small objects will not be
 * fully cached.  On the otherhand, if we move the page to the inactive
 * queue we wind up with a problem whereby very large objects 
 * unnecessarily blow away our inactive and cache queues.
 *
 * The solution is to move the pages based on a fixed weighting.  We
 * either leave them alone, deactivate them, or move them to the cache,
 * where moving them to the cache has the highest weighting.
 * By forcing some pages into other queues we eventually force the
 * system to balance the queues, potentially recovering other unrelated
 * space from active.  The idea is to not force this to happen too
 * often.
 *
 * The page must be busied.
 */
void
vm_page_dontneed(vm_page_t m)
{
	static int dnweight;
	int dnw;
	int head;

	dnw = ++dnweight;

	/*
	 * occassionally leave the page alone
	 */
	if ((dnw & 0x01F0) == 0 ||
	    m->queue - m->pc == PQ_INACTIVE ||
	    m->queue - m->pc == PQ_CACHE
	) {
		if (m->act_count >= ACT_INIT)
			--m->act_count;
		return;
	}

	/*
	 * If vm_page_dontneed() is inactivating a page, it must clear
	 * the referenced flag; otherwise the pagedaemon will see references
	 * on the page in the inactive queue and reactivate it. Until the 
	 * page can move to the cache queue, madvise's job is not done.
	 */
	vm_page_flag_clear(m, PG_REFERENCED);
	pmap_clear_reference(m);

	if (m->dirty == 0)
		vm_page_test_dirty(m);

	if (m->dirty || (dnw & 0x0070) == 0) {
		/*
		 * Deactivate the page 3 times out of 32.
		 */
		head = 0;
	} else {
		/*
		 * Cache the page 28 times out of every 32.  Note that
		 * the page is deactivated instead of cached, but placed
		 * at the head of the queue instead of the tail.
		 */
		head = 1;
	}
	vm_page_spin_lock(m);
	_vm_page_deactivate_locked(m, head);
	vm_page_spin_unlock(m);
}

/*
 * These routines manipulate the 'soft busy' count for a page.  A soft busy
 * is almost like a hard BUSY except that it allows certain compatible
 * operations to occur on the page while it is busy.  For example, a page
 * undergoing a write can still be mapped read-only.
 *
 * We also use soft-busy to quickly pmap_enter shared read-only pages
 * without having to hold the page locked.
 *
 * The soft-busy count can be > 1 in situations where multiple threads
 * are pmap_enter()ing the same page simultaneously, or when two buffer
 * cache buffers overlap the same page.
 *
 * The caller must hold the page BUSY when making these two calls.
 */
void
vm_page_io_start(vm_page_t m)
{
	uint32_t ocount;

	ocount = atomic_fetchadd_int(&m->busy_count, 1);
	KKASSERT(ocount & PBUSY_LOCKED);
}

void
vm_page_io_finish(vm_page_t m)
{
	uint32_t ocount;

	ocount = atomic_fetchadd_int(&m->busy_count, -1);
	KKASSERT(ocount & PBUSY_MASK);
#if 0
	if (((ocount - 1) & (PBUSY_LOCKED | PBUSY_MASK)) == 0)
		wakeup(m);
#endif
}

/*
 * Attempt to soft-busy a page.  The page must not be PBUSY_LOCKED.
 *
 * We can't use fetchadd here because we might race a hard-busy and the
 * page freeing code asserts on a non-zero soft-busy count (even if only
 * temporary).
 *
 * Returns 0 on success, non-zero on failure.
 */
int
vm_page_sbusy_try(vm_page_t m)
{
	uint32_t ocount;

	for (;;) {
		ocount = m->busy_count;
		cpu_ccfence();
		if (ocount & PBUSY_LOCKED)
			return 1;
		if (atomic_cmpset_int(&m->busy_count, ocount, ocount + 1))
			break;
	}
	return 0;
#if 0
	if (m->busy_count & PBUSY_LOCKED)
		return 1;
	ocount = atomic_fetchadd_int(&m->busy_count, 1);
	if (ocount & PBUSY_LOCKED) {
		vm_page_sbusy_drop(m);
		return 1;
	}
	return 0;
#endif
}

/*
 * Indicate that a clean VM page requires a filesystem commit and cannot
 * be reused.  Used by tmpfs.
 */
void
vm_page_need_commit(vm_page_t m)
{
	vm_page_flag_set(m, PG_NEED_COMMIT);
	vm_object_set_writeable_dirty(m->object);
}

void
vm_page_clear_commit(vm_page_t m)
{
	vm_page_flag_clear(m, PG_NEED_COMMIT);
}

/*
 * Allocate a page without an object.  The returned page will be wired and
 * NOT busy.  The function will block if no page is available, but only loop
 * if VM_ALLOC_RETRY is specified (else returns NULL after blocking).
 *
 * The pindex can be passed as zero, and is typically passed to help the
 * allocator 'color' the page returned.  That is, select pages that are
 * cache-friendly if the caller is allocating multiple pages.
 *
 *	VM_ALLOC_QUICK		- Allocate from free queue only
 *	VM_ALLOC_NORMAL		- Allocate from free + cache
 *	VM_ALLOC_SYSTEM		- Allocation can use system page reserve
 *	VM_ALLOC_INTERRUPT	- Allocation can use emergency page reserve
 *
 *	VM_ALLOC_CPU(n)		- Allocate using specified cpu localization
 *
 *	VM_ALLOC_ZERO		- Zero and set page valid.  If not specified,
 *				  m->valid will be 0 and the page will contain
 *				  prior garbage.
 *
 *	VM_ALLOC_FORCE_ZERO	- (same as VM_ALLOC_ZERO in this case)
 *
 *	VM_ALLOC_RETRY		- Retry until a page is available.  If not
 *				  specified, NULL can be returned.
 *
 *	VM_ALLOC_NULL_OK	- Not applicable since there is no object.
 */
vm_page_t
vm_page_alloczwq(vm_pindex_t pindex, int flags)
{
	vm_page_t m;

	KKASSERT(flags & (VM_ALLOC_NORMAL | VM_ALLOC_QUICK |
			  VM_ALLOC_INTERRUPT | VM_ALLOC_SYSTEM));
	for (;;) {
		m = vm_page_alloc(NULL, pindex, flags & ~VM_ALLOC_RETRY);
		if (m)
			break;
		vm_wait(0);
		if ((flags & VM_ALLOC_RETRY) == 0)
			return NULL;
	}

	if (flags & (VM_ALLOC_ZERO | VM_ALLOC_FORCE_ZERO)) {
		pmap_zero_page(VM_PAGE_TO_PHYS(m));
		m->valid = VM_PAGE_BITS_ALL;
	}

	vm_page_wire(m);
	vm_page_wakeup(m);

	return(m);
}

/*
 * Free a page previously allocated via vm_page_alloczwq().
 *
 * Caller should not busy the page.  This function will busy, unwire,
 * and free the page.
 */
void
vm_page_freezwq(vm_page_t m)
{
	vm_page_busy_wait(m, FALSE, "pgzwq");
	vm_page_unwire(m, 0);
	vm_page_free(m);
}

/*
 * Grab a page, blocking if it is busy and allocating a page if necessary.
 * A busy page is returned or NULL.  The page may or may not be valid and
 * might not be on a queue (the caller is responsible for the disposition of
 * the page).
 *
 *	VM_ALLOC_QUICK		- Allocate from free queue only
 *	VM_ALLOC_NORMAL		- Allocate from free + cache
 *	VM_ALLOC_SYSTEM		- Allocation can use system page reserve
 *	VM_ALLOC_INTERRUPT	- Allocation can use emergency page reserve
 *
 *	VM_ALLOC_CPU(n)		- Allocate using specified cpu localization
 *
 *	VM_ALLOC_ZERO		- If the page does not exist and must be
 *				  allocated, it will be zerod and set valid.
 *
 *	VM_ALLOC_FORCE_ZERO	- The page will be zerod and set valid whether
 *				  it previously existed or had to be allocated.
 *
 *	VM_ALLOC_RETRY		- Routine waits and loops until it can obtain
 *				  the page, never returning NULL.  Also note
 *				  that VM_ALLOC_NORMAL must also be specified
 *				  if you use VM_ALLOC_RETRY.
 *
 *				  Also, VM_ALLOC_NULL_OK is implied when
 *				  VM_ALLOC_RETRY is specified, but will simply
 *				  cause a retry loop and never return NULL.
 *
 *	VM_ALLOC_NULL_OK	- Prevent panic on insertion collision.  This
 *				  flag is implied and need not be set if
 *				  VM_ALLOC_RETRY is specified.
 *
 *				  If VM_ALLOC_RETRY is not specified, the page
 *				  can still be pre-existing and will be
 *				  returned if so, but concurrent creation of
 *				  the same 'new' page can cause one or more
 *				  grabs to return NULL.
 *
 * This routine may block, but if VM_ALLOC_RETRY is not set then NULL is
 * always returned if we had blocked.
 *
 * This routine may not be called from an interrupt.
 *
 * No other requirements.
 */
vm_page_t
vm_page_grab(vm_object_t object, vm_pindex_t pindex, int flags)
{
	vm_page_t m;
	int error;
	int shared = 1;

	KKASSERT(flags & (VM_ALLOC_NORMAL | VM_ALLOC_QUICK |
			  VM_ALLOC_INTERRUPT | VM_ALLOC_SYSTEM));
	vm_object_hold_shared(object);
	for (;;) {
		m = vm_page_lookup_busy_try(object, pindex, TRUE, &error);
		if (error) {
			vm_page_sleep_busy(m, TRUE, "pgrbwt");
			if ((flags & VM_ALLOC_RETRY) == 0) {
				m = NULL;
				break;
			}
			/* retry */
		} else if (m == NULL) {
			if (shared) {
				vm_object_upgrade(object);
				shared = 0;
			}
			if (flags & VM_ALLOC_RETRY)
				flags |= VM_ALLOC_NULL_OK;
			m = vm_page_alloc(object, pindex,
					  flags & ~VM_ALLOC_RETRY);
			if (m)
				break;
			vm_wait(0);
			if ((flags & VM_ALLOC_RETRY) == 0)
				goto failed;
		} else {
			/* m found */
			break;
		}
	}

	/*
	 * If VM_ALLOC_ZERO an invalid page will be zero'd and set valid.
	 *
	 * If VM_ALLOC_FORCE_ZERO the page is unconditionally zero'd and set
	 * valid even if already valid.
	 *
	 * NOTE!  We have removed all of the PG_ZERO optimizations and also
	 *	  removed the idle zeroing code.  These optimizations actually
	 *	  slow things down on modern cpus because the zerod area is
	 *	  likely uncached, placing a memory-access burden on the
	 *	  accesors taking the fault.
	 *
	 *	  By always zeroing the page in-line with the fault, no
	 *	  dynamic ram reads are needed and the caches are hot, ready
	 *	  for userland to access the memory.
	 */
	if (m->valid == 0) {
		if (flags & (VM_ALLOC_ZERO | VM_ALLOC_FORCE_ZERO)) {
			pmap_zero_page(VM_PAGE_TO_PHYS(m));
			m->valid = VM_PAGE_BITS_ALL;
		}
	} else if (flags & VM_ALLOC_FORCE_ZERO) {
		pmap_zero_page(VM_PAGE_TO_PHYS(m));
		m->valid = VM_PAGE_BITS_ALL;
	}
failed:
	vm_object_drop(object);
	return(m);
}

/*
 * Mapping function for valid bits or for dirty bits in
 * a page.  May not block.
 *
 * Inputs are required to range within a page.
 *
 * No requirements.
 * Non blocking.
 */
int
vm_page_bits(int base, int size)
{
	int first_bit;
	int last_bit;

	KASSERT(
	    base + size <= PAGE_SIZE,
	    ("vm_page_bits: illegal base/size %d/%d", base, size)
	);

	if (size == 0)		/* handle degenerate case */
		return(0);

	first_bit = base >> DEV_BSHIFT;
	last_bit = (base + size - 1) >> DEV_BSHIFT;

	return ((2 << last_bit) - (1 << first_bit));
}

/*
 * Sets portions of a page valid and clean.  The arguments are expected
 * to be DEV_BSIZE aligned but if they aren't the bitmap is inclusive
 * of any partial chunks touched by the range.  The invalid portion of
 * such chunks will be zero'd.
 *
 * NOTE: When truncating a buffer vnode_pager_setsize() will automatically
 *	 align base to DEV_BSIZE so as not to mark clean a partially
 *	 truncated device block.  Otherwise the dirty page status might be
 *	 lost.
 *
 * This routine may not block.
 *
 * (base + size) must be less then or equal to PAGE_SIZE.
 */
static void
_vm_page_zero_valid(vm_page_t m, int base, int size)
{
	int frag;
	int endoff;

	if (size == 0)	/* handle degenerate case */
		return;

	/*
	 * If the base is not DEV_BSIZE aligned and the valid
	 * bit is clear, we have to zero out a portion of the
	 * first block.
	 */

	if ((frag = rounddown2(base, DEV_BSIZE)) != base &&
	    (m->valid & (1 << (base >> DEV_BSHIFT))) == 0
	) {
		pmap_zero_page_area(
		    VM_PAGE_TO_PHYS(m),
		    frag,
		    base - frag
		);
	}

	/*
	 * If the ending offset is not DEV_BSIZE aligned and the 
	 * valid bit is clear, we have to zero out a portion of
	 * the last block.
	 */

	endoff = base + size;

	if ((frag = rounddown2(endoff, DEV_BSIZE)) != endoff &&
	    (m->valid & (1 << (endoff >> DEV_BSHIFT))) == 0
	) {
		pmap_zero_page_area(
		    VM_PAGE_TO_PHYS(m),
		    endoff,
		    DEV_BSIZE - (endoff & (DEV_BSIZE - 1))
		);
	}
}

/*
 * Set valid, clear dirty bits.  If validating the entire
 * page we can safely clear the pmap modify bit.  We also
 * use this opportunity to clear the PG_NOSYNC flag.  If a process
 * takes a write fault on a MAP_NOSYNC memory area the flag will
 * be set again.
 *
 * We set valid bits inclusive of any overlap, but we can only
 * clear dirty bits for DEV_BSIZE chunks that are fully within
 * the range.
 *
 * Page must be busied?
 * No other requirements.
 */
void
vm_page_set_valid(vm_page_t m, int base, int size)
{
	_vm_page_zero_valid(m, base, size);
	m->valid |= vm_page_bits(base, size);
}


/*
 * Set valid bits and clear dirty bits.
 *
 * Page must be busied by caller.
 *
 * NOTE: This function does not clear the pmap modified bit.
 *	 Also note that e.g. NFS may use a byte-granular base
 *	 and size.
 *
 * No other requirements.
 */
void
vm_page_set_validclean(vm_page_t m, int base, int size)
{
	int pagebits;

	_vm_page_zero_valid(m, base, size);
	pagebits = vm_page_bits(base, size);
	m->valid |= pagebits;
	m->dirty &= ~pagebits;
	if (base == 0 && size == PAGE_SIZE) {
		/*pmap_clear_modify(m);*/
		vm_page_flag_clear(m, PG_NOSYNC);
	}
}

/*
 * Set valid & dirty.  Used by buwrite()
 *
 * Page must be busied by caller.
 */
void
vm_page_set_validdirty(vm_page_t m, int base, int size)
{
	int pagebits;

	pagebits = vm_page_bits(base, size);
	m->valid |= pagebits;
	m->dirty |= pagebits;
	if (m->object)
	       vm_object_set_writeable_dirty(m->object);
}

/*
 * Clear dirty bits.
 *
 * NOTE: This function does not clear the pmap modified bit.
 *	 Also note that e.g. NFS may use a byte-granular base
 *	 and size.
 *
 * Page must be busied?
 * No other requirements.
 */
void
vm_page_clear_dirty(vm_page_t m, int base, int size)
{
	m->dirty &= ~vm_page_bits(base, size);
	if (base == 0 && size == PAGE_SIZE) {
		/*pmap_clear_modify(m);*/
		vm_page_flag_clear(m, PG_NOSYNC);
	}
}

/*
 * Make the page all-dirty.
 *
 * Also make sure the related object and vnode reflect the fact that the
 * object may now contain a dirty page.
 *
 * Page must be busied?
 * No other requirements.
 */
void
vm_page_dirty(vm_page_t m)
{
#ifdef INVARIANTS
        int pqtype = m->queue - m->pc;
#endif
        KASSERT(pqtype != PQ_CACHE && pqtype != PQ_FREE,
                ("vm_page_dirty: page in free/cache queue!"));
	if (m->dirty != VM_PAGE_BITS_ALL) {
		m->dirty = VM_PAGE_BITS_ALL;
		if (m->object)
			vm_object_set_writeable_dirty(m->object);
	}
}

/*
 * Invalidates DEV_BSIZE'd chunks within a page.  Both the
 * valid and dirty bits for the effected areas are cleared.
 *
 * Page must be busied?
 * Does not block.
 * No other requirements.
 */
void
vm_page_set_invalid(vm_page_t m, int base, int size)
{
	int bits;

	bits = vm_page_bits(base, size);
	m->valid &= ~bits;
	m->dirty &= ~bits;
	atomic_add_int(&m->object->generation, 1);
}

/*
 * The kernel assumes that the invalid portions of a page contain 
 * garbage, but such pages can be mapped into memory by user code.
 * When this occurs, we must zero out the non-valid portions of the
 * page so user code sees what it expects.
 *
 * Pages are most often semi-valid when the end of a file is mapped 
 * into memory and the file's size is not page aligned.
 *
 * Page must be busied?
 * No other requirements.
 */
void
vm_page_zero_invalid(vm_page_t m, boolean_t setvalid)
{
	int b;
	int i;

	/*
	 * Scan the valid bits looking for invalid sections that
	 * must be zerod.  Invalid sub-DEV_BSIZE'd areas ( where the
	 * valid bit may be set ) have already been zerod by
	 * vm_page_set_validclean().
	 */
	for (b = i = 0; i <= PAGE_SIZE / DEV_BSIZE; ++i) {
		if (i == (PAGE_SIZE / DEV_BSIZE) || 
		    (m->valid & (1 << i))
		) {
			if (i > b) {
				pmap_zero_page_area(
				    VM_PAGE_TO_PHYS(m), 
				    b << DEV_BSHIFT,
				    (i - b) << DEV_BSHIFT
				);
			}
			b = i + 1;
		}
	}

	/*
	 * setvalid is TRUE when we can safely set the zero'd areas
	 * as being valid.  We can do this if there are no cache consistency
	 * issues.  e.g. it is ok to do with UFS, but not ok to do with NFS.
	 */
	if (setvalid)
		m->valid = VM_PAGE_BITS_ALL;
}

/*
 * Is a (partial) page valid?  Note that the case where size == 0
 * will return FALSE in the degenerate case where the page is entirely
 * invalid, and TRUE otherwise.
 *
 * Does not block.
 * No other requirements.
 */
int
vm_page_is_valid(vm_page_t m, int base, int size)
{
	int bits = vm_page_bits(base, size);

	if (m->valid && ((m->valid & bits) == bits))
		return 1;
	else
		return 0;
}

/*
 * Update dirty bits from pmap/mmu.  May not block.
 *
 * Caller must hold the page busy
 *
 * WARNING! Unless the page has been unmapped, this function only
 *	    provides a likely dirty status.
 */
void
vm_page_test_dirty(vm_page_t m)
{
	if (m->dirty != VM_PAGE_BITS_ALL && pmap_is_modified(m)) {
		vm_page_dirty(m);
	}
}

#include "opt_ddb.h"
#ifdef DDB
#include <ddb/ddb.h>

DB_SHOW_COMMAND(page, vm_page_print_page_info)
{
	db_printf("vmstats.v_free_count: %ld\n", vmstats.v_free_count);
	db_printf("vmstats.v_cache_count: %ld\n", vmstats.v_cache_count);
	db_printf("vmstats.v_inactive_count: %ld\n", vmstats.v_inactive_count);
	db_printf("vmstats.v_active_count: %ld\n", vmstats.v_active_count);
	db_printf("vmstats.v_wire_count: %ld\n", vmstats.v_wire_count);
	db_printf("vmstats.v_free_reserved: %ld\n", vmstats.v_free_reserved);
	db_printf("vmstats.v_free_min: %ld\n", vmstats.v_free_min);
	db_printf("vmstats.v_free_target: %ld\n", vmstats.v_free_target);
	db_printf("vmstats.v_inactive_target: %ld\n",
		  vmstats.v_inactive_target);
	db_printf("vmstats.v_paging_wait: %ld\n", vmstats.v_paging_wait);
	db_printf("vmstats.v_paging_start: %ld\n", vmstats.v_paging_start);
	db_printf("vmstats.v_paging_target1: %ld\n", vmstats.v_paging_target1);
	db_printf("vmstats.v_paging_target2: %ld\n", vmstats.v_paging_target2);
}

DB_SHOW_COMMAND(pageq, vm_page_print_pageq_info)
{
	int i;
	db_printf("PQ_FREE:");
	for (i = 0; i < PQ_L2_SIZE; i++) {
		db_printf(" %ld", vm_page_queues[PQ_FREE + i].lcnt);
	}
	db_printf("\n");
		
	db_printf("PQ_CACHE:");
	for(i = 0; i < PQ_L2_SIZE; i++) {
		db_printf(" %ld", vm_page_queues[PQ_CACHE + i].lcnt);
	}
	db_printf("\n");

	db_printf("PQ_ACTIVE:");
	for(i = 0; i < PQ_L2_SIZE; i++) {
		db_printf(" %ld", vm_page_queues[PQ_ACTIVE + i].lcnt);
	}
	db_printf("\n");

	db_printf("PQ_INACTIVE:");
	for(i = 0; i < PQ_L2_SIZE; i++) {
		db_printf(" %ld", vm_page_queues[PQ_INACTIVE + i].lcnt);
	}
	db_printf("\n");
}
#endif /* DDB */
