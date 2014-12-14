#ifndef __LINUX_COMPILER_H
#error "Please don't include <linux/compiler-gcc4.h> directly, include <linux/compiler.h> instead."
#endif

#ifdef __KERNEL__
# if __GNUC_MINOR__ == 1 && __GNUC_PATCHLEVEL__ <= 1
#  error Your version of gcc miscompiles the __weak directive
# endif
#endif

#define __used			__attribute__((__used__))
#define __must_check 		__attribute__((warn_unused_result))
#define __compiler_offsetof(a,b) __builtin_offsetof(a,b)

#if __GNUC_MINOR__ >= 3
#define __cold			__attribute__((__cold__))

#define __linktime_error(message) __attribute__((__error__(message)))

/*
 * GCC 'asm goto' miscompiles certain code sequences:
 *
 *   http://gcc.gnu.org/bugzilla/show_bug.cgi?id=58670
 *
 * Work it around via a compiler barrier quirk suggested by Jakub Jelinek.
 * Fixed in GCC 4.8.2 and later versions.
 *
 * (asm goto is automatically volatile - the naming reflects this.)
 */
#if GCC_VERSION <= 40801
# define asm_volatile_goto(x...)	do { asm goto(x); asm (""); } while (0)
#else
# define asm_volatile_goto(x...)	do { asm goto(x); } while (0)
#endif

#if __GNUC_MINOR__ >= 5
#define unreachable() __builtin_unreachable()

#define __noclone	__attribute__((__noclone__))

#endif
#endif

#if __GNUC_MINOR__ > 0
#define __compiletime_object_size(obj) __builtin_object_size(obj, 0)
#endif
#if __GNUC_MINOR__ >= 4 && !defined(__CHECKER__)
#define __compiletime_warning(message) __attribute__((warning(message)))
#define __compiletime_error(message) __attribute__((error(message)))
#endif
