#include <linux/mm_types.h>
#include <vm/vm_page2.h>

void lkpi_mark_page_accessed(struct page *m);

void lkpi_mark_page_accessed(struct page *m)
{
	vm_page_flag_set((struct vm_page *)m, PG_REFERENCED);
}
