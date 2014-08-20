#ifndef _LINUX_RATELIMIT_H
#define _LINUX_RATELIMIT_H

#include <linux/param.h>
#include <linux/spinlock.h>

#define DEFAULT_RATELIMIT_INTERVAL	(5 * HZ)
#define DEFAULT_RATELIMIT_BURST		10

struct ratelimit_state {
	raw_spinlock_t	lock;		

	int		interval;
	int		burst;
	int		printed;
	int		missed;
	unsigned long	begin;
};

#define DEFINE_RATELIMIT_STATE(name, interval_init, burst_init)		\
									\
	struct ratelimit_state name = {					\
		.lock		= __RAW_SPIN_LOCK_UNLOCKED(name.lock),	\
		.interval	= interval_init,			\
		.burst		= burst_init,				\
	}

static inline void ratelimit_state_init(struct ratelimit_state *rs,
					int interval, int burst)
{
	raw_spin_lock_init(&rs->lock);
	rs->interval = interval;
	rs->burst = burst;
	rs->printed = 0;
	rs->missed = 0;
	rs->begin = 0;
}

extern struct ratelimit_state printk_ratelimit_state;

extern int ___ratelimit(struct ratelimit_state *rs, const char *func);
#define __ratelimit(state) ___ratelimit(state, __func__)

#ifdef CONFIG_PRINTK

#define WARN_ON_RATELIMIT(condition, state)			\
		WARN_ON((condition) && __ratelimit(state))

#define __WARN_RATELIMIT(condition, state, format...)		\
({								\
	int rtn = 0;						\
	if (unlikely(__ratelimit(state)))			\
		rtn = WARN(condition, format);			\
	rtn;							\
})

#define WARN_RATELIMIT(condition, format...)			\
({								\
	static DEFINE_RATELIMIT_STATE(_rs,			\
				      DEFAULT_RATELIMIT_INTERVAL,	\
				      DEFAULT_RATELIMIT_BURST);	\
	__WARN_RATELIMIT(condition, &_rs, format);		\
})

#else

#define WARN_ON_RATELIMIT(condition, state)			\
	WARN_ON(condition)

#define __WARN_RATELIMIT(condition, state, format...)		\
({								\
	int rtn = WARN(condition, format);			\
	rtn;							\
})

#define WARN_RATELIMIT(condition, format...)			\
({								\
	int rtn = WARN(condition, format);			\
	rtn;							\
})

#endif

/* Lets backport from 3.5.y mainline dev related message printing */
#define IF_DEV_RATELIMITED						\
	static DEFINE_RATELIMIT_STATE(_rs,				\
				      DEFAULT_RATELIMIT_INTERVAL,	\
				      DEFAULT_RATELIMIT_BURST);		\
	if (__ratelimit(&_rs))

#define dev_emerg_ratelimited(dev, fmt, ...)				\
	do { IF_DEV_RATELIMITED dev_printk(KERN_EMERG, dev, fmt, ##__VA_ARGS__); } while (0)
#define dev_alert_ratelimited(dev, fmt, ...)				\
	do { IF_DEV_RATELIMITED dev_printk(KERN_ALERT, dev, fmt, ##__VA_ARGS__); } while (0)
#define dev_crit_ratelimited(dev, fmt, ...)				\
	do { IF_DEV_RATELIMITED dev_printk(KERN_CRIT, dev, fmt, ##__VA_ARGS__); } while (0)
#define dev_err_ratelimited(dev, fmt, ...)				\
	do { IF_DEV_RATELIMITED dev_printk(KERN_ERR, dev, fmt, ##__VA_ARGS__); } while (0)
#define dev_warn_ratelimited(dev, fmt, ...)				\
	do { IF_DEV_RATELIMITED dev_printk(KERN_WARNING, dev, fmt, ##__VA_ARGS__); } while (0)
#define dev_notice_ratelimited(dev, fmt, ...)				\
	do { IF_DEV_RATELIMITED dev_printk(KERN_NOTICE, dev, fmt, ##__VA_ARGS__); } while (0)
#define dev_info_ratelimited(dev, fmt, ...)				\
	do { IF_DEV_RATELIMITED dev_printk(KERN_INFO, dev, fmt, ##__VA_ARGS__); } while (0)

#endif 
