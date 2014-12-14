/*
 * RT-Mutexes: simple blocking mutual exclusion locks with PI support
 *
 * started by Ingo Molnar and Thomas Gleixner.
 *
 *  Copyright (C) 2004-2006 Red Hat, Inc., Ingo Molnar <mingo@redhat.com>
 *  Copyright (C) 2005-2006 Timesys Corp., Thomas Gleixner <tglx@timesys.com>
 *  Copyright (C) 2005 Kihon Technologies Inc., Steven Rostedt
 *  Copyright (C) 2006 Esben Nielsen
 *
 *  See Documentation/rt-mutex-design.txt for details.
 */
#include <linux/spinlock.h>
#include <linux/export.h>
#include <linux/sched.h>
#include <linux/timer.h>

#include "rtmutex_common.h"


static void
rt_mutex_set_owner(struct rt_mutex *lock, struct task_struct *owner)
{
	unsigned long val = (unsigned long)owner;

	if (rt_mutex_has_waiters(lock))
		val |= RT_MUTEX_HAS_WAITERS;

	lock->owner = (struct task_struct *)val;
}

static inline void clear_rt_mutex_waiters(struct rt_mutex *lock)
{
	lock->owner = (struct task_struct *)
			((unsigned long)lock->owner & ~RT_MUTEX_HAS_WAITERS);
}

static void fixup_rt_mutex_waiters(struct rt_mutex *lock)
{
	if (!rt_mutex_has_waiters(lock))
		clear_rt_mutex_waiters(lock);
}

#if defined(__HAVE_ARCH_CMPXCHG) && !defined(CONFIG_DEBUG_RT_MUTEXES)
# define rt_mutex_cmpxchg(l,c,n)	(cmpxchg(&l->owner, c, n) == c)
static inline void mark_rt_mutex_waiters(struct rt_mutex *lock)
{
	unsigned long owner, *p = (unsigned long *) &lock->owner;

	do {
		owner = *p;
	} while (cmpxchg(p, owner, owner | RT_MUTEX_HAS_WAITERS) != owner);
}

/*
 * Safe fastpath aware unlock:
 * 1) Clear the waiters bit
 * 2) Drop lock->wait_lock
 * 3) Try to unlock the lock with cmpxchg
 */
static inline bool unlock_rt_mutex_safe(struct rt_mutex *lock)
	__releases(lock->wait_lock)
{
	struct task_struct *owner = rt_mutex_owner(lock);

	clear_rt_mutex_waiters(lock);
	raw_spin_unlock(&lock->wait_lock);
	/*
	 * If a new waiter comes in between the unlock and the cmpxchg
	 * we have two situations:
	 *
	 * unlock(wait_lock);
	 *					lock(wait_lock);
	 * cmpxchg(p, owner, 0) == owner
	 *					mark_rt_mutex_waiters(lock);
	 *					acquire(lock);
	 * or:
	 *
	 * unlock(wait_lock);
	 *					lock(wait_lock);
	 *					mark_rt_mutex_waiters(lock);
	 *
	 * cmpxchg(p, owner, 0) != owner
	 *					enqueue_waiter();
	 *					unlock(wait_lock);
	 * lock(wait_lock);
	 * wake waiter();
	 * unlock(wait_lock);
	 *					lock(wait_lock);
	 *					acquire(lock);
	 */
	return rt_mutex_cmpxchg(lock, owner, NULL);
}

#else
# define rt_mutex_cmpxchg(l,c,n)	(0)
static inline void mark_rt_mutex_waiters(struct rt_mutex *lock)
{
	lock->owner = (struct task_struct *)
			((unsigned long)lock->owner | RT_MUTEX_HAS_WAITERS);
}

/*
 * Simple slow path only version: lock->owner is protected by lock->wait_lock.
 */
static inline bool unlock_rt_mutex_safe(struct rt_mutex *lock)
	__releases(lock->wait_lock)
{
	lock->owner = NULL;
	raw_spin_unlock(&lock->wait_lock);
	return true;
}
#endif

int rt_mutex_getprio(struct task_struct *task)
{
	if (likely(!task_has_pi_waiters(task)))
		return task->normal_prio;

	return min(task_top_pi_waiter(task)->pi_list_entry.prio,
		   task->normal_prio);
}

static void __rt_mutex_adjust_prio(struct task_struct *task)
{
	int prio = rt_mutex_getprio(task);

	if (task->prio != prio)
		rt_mutex_setprio(task, prio);
}

static void rt_mutex_adjust_prio(struct task_struct *task)
{
	unsigned long flags;

	raw_spin_lock_irqsave(&task->pi_lock, flags);
	__rt_mutex_adjust_prio(task);
	raw_spin_unlock_irqrestore(&task->pi_lock, flags);
}

int max_lock_depth = 1024;

static inline struct rt_mutex *task_blocked_on_lock(struct task_struct *p)
{
	return p->pi_blocked_on ? p->pi_blocked_on->lock : NULL;
}

static int rt_mutex_adjust_prio_chain(struct task_struct *task,
				      int deadlock_detect,
				      struct rt_mutex *orig_lock,
				      struct rt_mutex *next_lock,
				      struct rt_mutex_waiter *orig_waiter,
				      struct task_struct *top_task)
{
	struct rt_mutex *lock;
	struct rt_mutex_waiter *waiter, *top_waiter = orig_waiter;
	int detect_deadlock, ret = 0, depth = 0;
	unsigned long flags;

	detect_deadlock = debug_rt_mutex_detect_deadlock(orig_waiter,
							 deadlock_detect);

 again:
	if (++depth > max_lock_depth) {
		static int prev_max;

		if (prev_max != max_lock_depth) {
			prev_max = max_lock_depth;
			printk(KERN_WARNING "Maximum lock depth %d reached "
			       "task: %s (%d)\n", max_lock_depth,
			       top_task->comm, task_pid_nr(top_task));
		}
		put_task_struct(task);

		return -EDEADLK;
	}
 retry:
	raw_spin_lock_irqsave(&task->pi_lock, flags);

	waiter = task->pi_blocked_on;
	if (!waiter)
		goto out_unlock_pi;

	if (orig_waiter && !rt_mutex_owner(orig_lock))
		goto out_unlock_pi;

	/*
	 * We dropped all locks after taking a refcount on @task, so
	 * the task might have moved on in the lock chain or even left
	 * the chain completely and blocks now on an unrelated lock or
	 * on @orig_lock.
	 *
	 * We stored the lock on which @task was blocked in @next_lock,
	 * so we can detect the chain change.
	 */
	if (next_lock != waiter->lock)
		goto out_unlock_pi;

	if (top_waiter) {
		if (!task_has_pi_waiters(task))
			goto out_unlock_pi;
		/*
		 * If deadlock detection is off, we stop here if we
		 * are not the top pi waiter of the task.
		 */
		if (!detect_deadlock && top_waiter != task_top_pi_waiter(task))
			goto out_unlock_pi;
	}

	if (!detect_deadlock && waiter->list_entry.prio == task->prio)
		goto out_unlock_pi;

	lock = waiter->lock;
	if (!raw_spin_trylock(&lock->wait_lock)) {
		raw_spin_unlock_irqrestore(&task->pi_lock, flags);
		cpu_relax();
		goto retry;
	}

	/*
	 * Deadlock detection. If the lock is the same as the original
	 * lock which caused us to walk the lock chain or if the
	 * current lock is owned by the task which initiated the chain
	 * walk, we detected a deadlock.
	 */
	if (lock == orig_lock || rt_mutex_owner(lock) == top_task) {
		debug_rt_mutex_deadlock(deadlock_detect, orig_waiter, lock);
		raw_spin_unlock(&lock->wait_lock);
		ret = -EDEADLK;
		goto out_unlock_pi;
	}

	top_waiter = rt_mutex_top_waiter(lock);

	
	plist_del(&waiter->list_entry, &lock->wait_list);
	waiter->list_entry.prio = task->prio;
	plist_add(&waiter->list_entry, &lock->wait_list);

	
	raw_spin_unlock_irqrestore(&task->pi_lock, flags);
	if (!rt_mutex_owner(lock)) {

		if (top_waiter != rt_mutex_top_waiter(lock))
			wake_up_process(rt_mutex_top_waiter(lock)->task);
		raw_spin_unlock(&lock->wait_lock);
		goto out_put_task;
	}
	put_task_struct(task);

	
	task = rt_mutex_owner(lock);
	get_task_struct(task);
	raw_spin_lock_irqsave(&task->pi_lock, flags);

	if (waiter == rt_mutex_top_waiter(lock)) {
		
		plist_del(&top_waiter->pi_list_entry, &task->pi_waiters);
		waiter->pi_list_entry.prio = waiter->list_entry.prio;
		plist_add(&waiter->pi_list_entry, &task->pi_waiters);
		__rt_mutex_adjust_prio(task);

	} else if (top_waiter == waiter) {
		
		plist_del(&waiter->pi_list_entry, &task->pi_waiters);
		waiter = rt_mutex_top_waiter(lock);
		waiter->pi_list_entry.prio = waiter->list_entry.prio;
		plist_add(&waiter->pi_list_entry, &task->pi_waiters);
		__rt_mutex_adjust_prio(task);
	}

	/*
	 * Check whether the task which owns the current lock is pi
	 * blocked itself. If yes we store a pointer to the lock for
	 * the lock chain change detection above. After we dropped
	 * task->pi_lock next_lock cannot be dereferenced anymore.
	 */
	next_lock = task_blocked_on_lock(task);

	raw_spin_unlock_irqrestore(&task->pi_lock, flags);

	top_waiter = rt_mutex_top_waiter(lock);
	raw_spin_unlock(&lock->wait_lock);

	/*
	 * We reached the end of the lock chain. Stop right here. No
	 * point to go back just to figure that out.
	 */
	if (!next_lock)
		goto out_put_task;

	if (!detect_deadlock && waiter != top_waiter)
		goto out_put_task;

	goto again;

 out_unlock_pi:
	raw_spin_unlock_irqrestore(&task->pi_lock, flags);
 out_put_task:
	put_task_struct(task);

	return ret;
}

static int try_to_take_rt_mutex(struct rt_mutex *lock, struct task_struct *task,
		struct rt_mutex_waiter *waiter)
{
	mark_rt_mutex_waiters(lock);

	if (rt_mutex_owner(lock))
		return 0;

	if (rt_mutex_has_waiters(lock)) {
		if (task->prio >= rt_mutex_top_waiter(lock)->list_entry.prio) {
			if (!waiter || waiter != rt_mutex_top_waiter(lock))
				return 0;
		}
	}

	if (waiter || rt_mutex_has_waiters(lock)) {
		unsigned long flags;
		struct rt_mutex_waiter *top;

		raw_spin_lock_irqsave(&task->pi_lock, flags);

		
		if (waiter) {
			plist_del(&waiter->list_entry, &lock->wait_list);
			task->pi_blocked_on = NULL;
		}

		if (rt_mutex_has_waiters(lock)) {
			top = rt_mutex_top_waiter(lock);
			top->pi_list_entry.prio = top->list_entry.prio;
			plist_add(&top->pi_list_entry, &task->pi_waiters);
		}
		raw_spin_unlock_irqrestore(&task->pi_lock, flags);
	}

	
	debug_rt_mutex_lock(lock);

	rt_mutex_set_owner(lock, task);

	rt_mutex_deadlock_account_lock(lock, task);

	return 1;
}

static int task_blocks_on_rt_mutex(struct rt_mutex *lock,
				   struct rt_mutex_waiter *waiter,
				   struct task_struct *task,
				   int detect_deadlock)
{
	struct task_struct *owner = rt_mutex_owner(lock);
	struct rt_mutex_waiter *top_waiter = waiter;
	struct rt_mutex *next_lock;
	int chain_walk = 0, res;
	unsigned long flags;

	/*
	 * Early deadlock detection. We really don't want the task to
	 * enqueue on itself just to untangle the mess later. It's not
	 * only an optimization. We drop the locks, so another waiter
	 * can come in before the chain walk detects the deadlock. So
	 * the other will detect the deadlock and return -EDEADLOCK,
	 * which is wrong, as the other waiter is not in a deadlock
	 * situation.
	 */
	if (owner == task)
		return -EDEADLK;

	raw_spin_lock_irqsave(&task->pi_lock, flags);
	__rt_mutex_adjust_prio(task);
	waiter->task = task;
	waiter->lock = lock;
	plist_node_init(&waiter->list_entry, task->prio);
	plist_node_init(&waiter->pi_list_entry, task->prio);

	
	if (rt_mutex_has_waiters(lock))
		top_waiter = rt_mutex_top_waiter(lock);
	plist_add(&waiter->list_entry, &lock->wait_list);

	task->pi_blocked_on = waiter;

	raw_spin_unlock_irqrestore(&task->pi_lock, flags);

	if (!owner)
		return 0;

	raw_spin_lock_irqsave(&owner->pi_lock, flags);
	if (waiter == rt_mutex_top_waiter(lock)) {
		plist_del(&top_waiter->pi_list_entry, &owner->pi_waiters);
		plist_add(&waiter->pi_list_entry, &owner->pi_waiters);

		__rt_mutex_adjust_prio(owner);
		if (owner->pi_blocked_on)
			chain_walk = 1;
	} else if (debug_rt_mutex_detect_deadlock(waiter, detect_deadlock)) {
		chain_walk = 1;
	}

	/* Store the lock on which owner is blocked or NULL */
	next_lock = task_blocked_on_lock(owner);

	raw_spin_unlock_irqrestore(&owner->pi_lock, flags);
	/*
	 * Even if full deadlock detection is on, if the owner is not
	 * blocked itself, we can avoid finding this out in the chain
	 * walk.
	 */
	if (!chain_walk || !next_lock)
		return 0;

	get_task_struct(owner);

	raw_spin_unlock(&lock->wait_lock);

	res = rt_mutex_adjust_prio_chain(owner, detect_deadlock, lock,
					 next_lock, waiter, task);

	raw_spin_lock(&lock->wait_lock);

	return res;
}

static void wakeup_next_waiter(struct rt_mutex *lock)
{
	struct rt_mutex_waiter *waiter;
	unsigned long flags;

	raw_spin_lock_irqsave(&current->pi_lock, flags);

	waiter = rt_mutex_top_waiter(lock);

	plist_del(&waiter->pi_list_entry, &current->pi_waiters);

	/*
	 * As we are waking up the top waiter, and the waiter stays
	 * queued on the lock until it gets the lock, this lock
	 * obviously has waiters. Just set the bit here and this has
	 * the added benefit of forcing all new tasks into the
	 * slow path making sure no task of lower priority than
	 * the top waiter can steal this lock.
	 */
	lock->owner = (void *) RT_MUTEX_HAS_WAITERS;

	raw_spin_unlock_irqrestore(&current->pi_lock, flags);

	/*
	 * It's safe to dereference waiter as it cannot go away as
	 * long as we hold lock->wait_lock. The waiter task needs to
	 * acquire it in order to dequeue the waiter.
	 */
	wake_up_process(waiter->task);
}

static void remove_waiter(struct rt_mutex *lock,
			  struct rt_mutex_waiter *waiter)
{
	int first = (waiter == rt_mutex_top_waiter(lock));
	struct task_struct *owner = rt_mutex_owner(lock);
	struct rt_mutex *next_lock = NULL;
	unsigned long flags;

	raw_spin_lock_irqsave(&current->pi_lock, flags);
	plist_del(&waiter->list_entry, &lock->wait_list);
	current->pi_blocked_on = NULL;
	raw_spin_unlock_irqrestore(&current->pi_lock, flags);

	if (!owner)
		return;

	if (first) {

		raw_spin_lock_irqsave(&owner->pi_lock, flags);

		plist_del(&waiter->pi_list_entry, &owner->pi_waiters);

		if (rt_mutex_has_waiters(lock)) {
			struct rt_mutex_waiter *next;

			next = rt_mutex_top_waiter(lock);
			plist_add(&next->pi_list_entry, &owner->pi_waiters);
		}
		__rt_mutex_adjust_prio(owner);

		/* Store the lock on which owner is blocked or NULL */
		next_lock = task_blocked_on_lock(owner);

		raw_spin_unlock_irqrestore(&owner->pi_lock, flags);
	}

	WARN_ON(!plist_node_empty(&waiter->pi_list_entry));

	if (!next_lock)
		return;

	
	get_task_struct(owner);

	raw_spin_unlock(&lock->wait_lock);

	rt_mutex_adjust_prio_chain(owner, 0, lock, next_lock, NULL, current);

	raw_spin_lock(&lock->wait_lock);
}

void rt_mutex_adjust_pi(struct task_struct *task)
{
	struct rt_mutex_waiter *waiter;
	struct rt_mutex *next_lock;
	unsigned long flags;

	raw_spin_lock_irqsave(&task->pi_lock, flags);

	waiter = task->pi_blocked_on;
	if (!waiter || waiter->list_entry.prio == task->prio) {
		raw_spin_unlock_irqrestore(&task->pi_lock, flags);
		return;
	}
	next_lock = waiter->lock;
	raw_spin_unlock_irqrestore(&task->pi_lock, flags);

	/* gets dropped in rt_mutex_adjust_prio_chain()! */
	get_task_struct(task);
	
	rt_mutex_adjust_prio_chain(task, 0, NULL, next_lock, NULL, task);
}

static int __sched
__rt_mutex_slowlock(struct rt_mutex *lock, int state,
		    struct hrtimer_sleeper *timeout,
		    struct rt_mutex_waiter *waiter)
{
	int ret = 0;

	for (;;) {
		
		if (try_to_take_rt_mutex(lock, current, waiter))
			break;

		if (unlikely(state == TASK_INTERRUPTIBLE)) {
			
			if (signal_pending(current))
				ret = -EINTR;
			if (timeout && !timeout->task)
				ret = -ETIMEDOUT;
			if (ret)
				break;
		}

		raw_spin_unlock(&lock->wait_lock);

		debug_rt_mutex_print_deadlock(waiter);

		schedule_rt_mutex(lock);

		raw_spin_lock(&lock->wait_lock);
		set_current_state(state);
	}

	return ret;
}

static void rt_mutex_handle_deadlock(int res, int detect_deadlock,
				     struct rt_mutex_waiter *w)
{
	/*
	 * If the result is not -EDEADLOCK or the caller requested
	 * deadlock detection, nothing to do here.
	 */
	if (res != -EDEADLOCK || detect_deadlock)
		return;

	/*
	 * Yell lowdly and stop the task right here.
	 */
	rt_mutex_print_deadlock(w);
	while (1) {
		set_current_state(TASK_INTERRUPTIBLE);
		schedule();
	}
}

static int __sched
rt_mutex_slowlock(struct rt_mutex *lock, int state,
		  struct hrtimer_sleeper *timeout,
		  int detect_deadlock)
{
	struct rt_mutex_waiter waiter;
	int ret = 0;

	debug_rt_mutex_init_waiter(&waiter);

	raw_spin_lock(&lock->wait_lock);

	
	if (try_to_take_rt_mutex(lock, current, NULL)) {
		raw_spin_unlock(&lock->wait_lock);
		return 0;
	}

	set_current_state(state);

	
	if (unlikely(timeout)) {
		hrtimer_start_expires(&timeout->timer, HRTIMER_MODE_ABS);
		if (!hrtimer_active(&timeout->timer))
			timeout->task = NULL;
	}

	ret = task_blocks_on_rt_mutex(lock, &waiter, current, detect_deadlock);

	if (likely(!ret))
		ret = __rt_mutex_slowlock(lock, state, timeout, &waiter);

	set_current_state(TASK_RUNNING);

	if (unlikely(ret)) {
		remove_waiter(lock, &waiter);
		rt_mutex_handle_deadlock(ret, detect_deadlock, &waiter);
	}

	fixup_rt_mutex_waiters(lock);

	raw_spin_unlock(&lock->wait_lock);

	
	if (unlikely(timeout))
		hrtimer_cancel(&timeout->timer);

	debug_rt_mutex_free_waiter(&waiter);

	return ret;
}

static inline int
rt_mutex_slowtrylock(struct rt_mutex *lock)
{
	int ret = 0;

	raw_spin_lock(&lock->wait_lock);

	if (likely(rt_mutex_owner(lock) != current)) {

		ret = try_to_take_rt_mutex(lock, current, NULL);
		fixup_rt_mutex_waiters(lock);
	}

	raw_spin_unlock(&lock->wait_lock);

	return ret;
}

static void __sched
rt_mutex_slowunlock(struct rt_mutex *lock)
{
	raw_spin_lock(&lock->wait_lock);

	debug_rt_mutex_unlock(lock);

	rt_mutex_deadlock_account_unlock(current);

	/*
	 * We must be careful here if the fast path is enabled. If we
	 * have no waiters queued we cannot set owner to NULL here
	 * because of:
	 *
	 * foo->lock->owner = NULL;
	 *			rtmutex_lock(foo->lock);   <- fast path
	 *			free = atomic_dec_and_test(foo->refcnt);
	 *			rtmutex_unlock(foo->lock); <- fast path
	 *			if (free)
	 *				kfree(foo);
	 * raw_spin_unlock(foo->lock->wait_lock);
	 *
	 * So for the fastpath enabled kernel:
	 *
	 * Nothing can set the waiters bit as long as we hold
	 * lock->wait_lock. So we do the following sequence:
	 *
	 *	owner = rt_mutex_owner(lock);
	 *	clear_rt_mutex_waiters(lock);
	 *	raw_spin_unlock(&lock->wait_lock);
	 *	if (cmpxchg(&lock->owner, owner, 0) == owner)
	 *		return;
	 *	goto retry;
	 *
	 * The fastpath disabled variant is simple as all access to
	 * lock->owner is serialized by lock->wait_lock:
	 *
	 *	lock->owner = NULL;
	 *	raw_spin_unlock(&lock->wait_lock);
	 */
	while (!rt_mutex_has_waiters(lock)) {
		/* Drops lock->wait_lock ! */
		if (unlock_rt_mutex_safe(lock) == true)
			return;
		/* Relock the rtmutex and try again */
		raw_spin_lock(&lock->wait_lock);
	}

	/*
	 * The wakeup next waiter path does not suffer from the above
	 * race. See the comments there.
	 */
	wakeup_next_waiter(lock);

	raw_spin_unlock(&lock->wait_lock);

	
	rt_mutex_adjust_prio(current);
}

static inline int
rt_mutex_fastlock(struct rt_mutex *lock, int state,
		  int detect_deadlock,
		  int (*slowfn)(struct rt_mutex *lock, int state,
				struct hrtimer_sleeper *timeout,
				int detect_deadlock))
{
	if (!detect_deadlock && likely(rt_mutex_cmpxchg(lock, NULL, current))) {
		rt_mutex_deadlock_account_lock(lock, current);
		return 0;
	} else
		return slowfn(lock, state, NULL, detect_deadlock);
}

static inline int
rt_mutex_timed_fastlock(struct rt_mutex *lock, int state,
			struct hrtimer_sleeper *timeout, int detect_deadlock,
			int (*slowfn)(struct rt_mutex *lock, int state,
				      struct hrtimer_sleeper *timeout,
				      int detect_deadlock))
{
	if (!detect_deadlock && likely(rt_mutex_cmpxchg(lock, NULL, current))) {
		rt_mutex_deadlock_account_lock(lock, current);
		return 0;
	} else
		return slowfn(lock, state, timeout, detect_deadlock);
}

static inline int
rt_mutex_fasttrylock(struct rt_mutex *lock,
		     int (*slowfn)(struct rt_mutex *lock))
{
	if (likely(rt_mutex_cmpxchg(lock, NULL, current))) {
		rt_mutex_deadlock_account_lock(lock, current);
		return 1;
	}
	return slowfn(lock);
}

static inline void
rt_mutex_fastunlock(struct rt_mutex *lock,
		    void (*slowfn)(struct rt_mutex *lock))
{
	if (likely(rt_mutex_cmpxchg(lock, current, NULL)))
		rt_mutex_deadlock_account_unlock(current);
	else
		slowfn(lock);
}

void __sched rt_mutex_lock(struct rt_mutex *lock)
{
	might_sleep();

	rt_mutex_fastlock(lock, TASK_UNINTERRUPTIBLE, 0, rt_mutex_slowlock);
}
EXPORT_SYMBOL_GPL(rt_mutex_lock);

int __sched rt_mutex_lock_interruptible(struct rt_mutex *lock,
						 int detect_deadlock)
{
	might_sleep();

	return rt_mutex_fastlock(lock, TASK_INTERRUPTIBLE,
				 detect_deadlock, rt_mutex_slowlock);
}
EXPORT_SYMBOL_GPL(rt_mutex_lock_interruptible);

int
rt_mutex_timed_lock(struct rt_mutex *lock, struct hrtimer_sleeper *timeout,
		    int detect_deadlock)
{
	might_sleep();

	return rt_mutex_timed_fastlock(lock, TASK_INTERRUPTIBLE, timeout,
				       detect_deadlock, rt_mutex_slowlock);
}
EXPORT_SYMBOL_GPL(rt_mutex_timed_lock);

int __sched rt_mutex_trylock(struct rt_mutex *lock)
{
	return rt_mutex_fasttrylock(lock, rt_mutex_slowtrylock);
}
EXPORT_SYMBOL_GPL(rt_mutex_trylock);

void __sched rt_mutex_unlock(struct rt_mutex *lock)
{
	rt_mutex_fastunlock(lock, rt_mutex_slowunlock);
}
EXPORT_SYMBOL_GPL(rt_mutex_unlock);

void rt_mutex_destroy(struct rt_mutex *lock)
{
	WARN_ON(rt_mutex_is_locked(lock));
#ifdef CONFIG_DEBUG_RT_MUTEXES
	lock->magic = NULL;
#endif
}

EXPORT_SYMBOL_GPL(rt_mutex_destroy);

void __rt_mutex_init(struct rt_mutex *lock, const char *name)
{
	lock->owner = NULL;
	raw_spin_lock_init(&lock->wait_lock);
	plist_head_init(&lock->wait_list);

	debug_rt_mutex_init(lock, name);
}
EXPORT_SYMBOL_GPL(__rt_mutex_init);

void rt_mutex_init_proxy_locked(struct rt_mutex *lock,
				struct task_struct *proxy_owner)
{
	__rt_mutex_init(lock, NULL);
	debug_rt_mutex_proxy_lock(lock, proxy_owner);
	rt_mutex_set_owner(lock, proxy_owner);
	rt_mutex_deadlock_account_lock(lock, proxy_owner);
}

void rt_mutex_proxy_unlock(struct rt_mutex *lock,
			   struct task_struct *proxy_owner)
{
	debug_rt_mutex_proxy_unlock(lock);
	rt_mutex_set_owner(lock, NULL);
	rt_mutex_deadlock_account_unlock(proxy_owner);
}

int rt_mutex_start_proxy_lock(struct rt_mutex *lock,
			      struct rt_mutex_waiter *waiter,
			      struct task_struct *task, int detect_deadlock)
{
	int ret;

	raw_spin_lock(&lock->wait_lock);

	if (try_to_take_rt_mutex(lock, task, NULL)) {
		raw_spin_unlock(&lock->wait_lock);
		return 1;
	}

	/* We enforce deadlock detection for futexes */
	ret = task_blocks_on_rt_mutex(lock, waiter, task, 1);

	if (ret && !rt_mutex_owner(lock)) {
		ret = 0;
	}

	if (unlikely(ret))
		remove_waiter(lock, waiter);

	raw_spin_unlock(&lock->wait_lock);

	debug_rt_mutex_print_deadlock(waiter);

	return ret;
}

struct task_struct *rt_mutex_next_owner(struct rt_mutex *lock)
{
	if (!rt_mutex_has_waiters(lock))
		return NULL;

	return rt_mutex_top_waiter(lock)->task;
}

int rt_mutex_finish_proxy_lock(struct rt_mutex *lock,
			       struct hrtimer_sleeper *to,
			       struct rt_mutex_waiter *waiter,
			       int detect_deadlock)
{
	int ret;

	raw_spin_lock(&lock->wait_lock);

	set_current_state(TASK_INTERRUPTIBLE);

	ret = __rt_mutex_slowlock(lock, TASK_INTERRUPTIBLE, to, waiter);

	set_current_state(TASK_RUNNING);

	if (unlikely(ret))
		remove_waiter(lock, waiter);

	fixup_rt_mutex_waiters(lock);

	raw_spin_unlock(&lock->wait_lock);

	return ret;
}
