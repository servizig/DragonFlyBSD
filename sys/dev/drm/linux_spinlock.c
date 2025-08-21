#include <sys/types.h>
#include <sys/lock.h>

void lkpi_spin_lock(struct lock *lock);
void lkpi_spin_unlock(struct lock *lock);

void
lkpi_spin_lock(struct lock *lock)
{
  lockmgr(lock, LK_EXCLUSIVE | LK_SPIN);
}

void
lkpi_spin_unlock(struct lock *lock)
{
  lockmgr(lock, LK_RELEASE);
}
