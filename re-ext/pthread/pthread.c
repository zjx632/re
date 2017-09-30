/*
 * pthread.c
 *
 * Description:
 * This translation unit agregates operations on thread attribute objects.
 * It is used for inline optimisation.
 *
 * The included modules are used separately when static executable sizes
 * must be minimised.
 *
 * --------------------------------------------------------------------------
 *
 *      Pthreads-win32 - POSIX Threads Library for Win32
 *      Copyright(C) 1998 John E. Bossom
 *      Copyright(C) 1999,2005 Pthreads-win32 contributors
 *
 *      Contact Email: rpj@callisto.canberra.edu.au
 *
 *      The current list of contributors is contained
 *      in the file CONTRIBUTORS included with the source
 *      code distribution. The list can also be seen at the
 *      following World Wide Web location:
 *      http://sources.redhat.com/pthreads-win32/contributors.html
 *
 *      This library is free software; you can redistribute it and/or
 *      modify it under the terms of the GNU Lesser General Public
 *      License as published by the Free Software Foundation; either
 *      version 2 of the License, or (at your option) any later version.
 *
 *      This library is distributed in the hope that it will be useful,
 *      but WITHOUT ANY WARRANTY; without even the implied warranty of
 *      MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *      Lesser General Public License for more details.
 *
 *      You should have received a copy of the GNU Lesser General Public
 *      License along with this library in the file COPYING.LIB;
 *      if not, write to the Free Software Foundation, Inc.,
 *      59 Temple Place - Suite 330, Boston, MA 02111-1307, USA
 */

#include "pthread.h"

 /*
 * context.h
 *
 * Description:
 * POSIX thread macros related to thread cancellation.
 *
 * --------------------------------------------------------------------------
 *
 *      Pthreads-win32 - POSIX Threads Library for Win32
 *      Copyright(C) 1998 John E. Bossom
 *      Copyright(C) 1999,2005 Pthreads-win32 contributors
 *
 *      Contact Email: rpj@callisto.canberra.edu.au
 *
 *      The current list of contributors is contained
 *      in the file CONTRIBUTORS included with the source
 *      code distribution. The list can also be seen at the
 *      following World Wide Web location:
 *      http://sources.redhat.com/pthreads-win32/contributors.html
 *
 *      This library is free software; you can redistribute it and/or
 *      modify it under the terms of the GNU Lesser General Public
 *      License as published by the Free Software Foundation; either
 *      version 2 of the License, or (at your option) any later version.
 *
 *      This library is distributed in the hope that it will be useful,
 *      but WITHOUT ANY WARRANTY; without even the implied warranty of
 *      MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *      Lesser General Public License for more details.
 *
 *      You should have received a copy of the GNU Lesser General Public
 *      License along with this library in the file COPYING.LIB;
 *      if not, write to the Free Software Foundation, Inc.,
 *      59 Temple Place - Suite 330, Boston, MA 02111-1307, USA
 */

#ifndef PTW32_CONTEXT_H
#define PTW32_CONTEXT_H

#undef PTW32_PROGCTR

#if defined(_M_IX86) || (defined(_X86_) && !defined(__amd64__))
#define PTW32_PROGCTR(Context)  ((Context).Eip)
#endif

#if defined (_M_IA64) || defined(_IA64)
#define PTW32_PROGCTR(Context)  ((Context).StIIP)
#endif

#if defined(_MIPS_) || defined(MIPS)
#define PTW32_PROGCTR(Context)  ((Context).Fir)
#endif

#if defined(_ALPHA_)
#define PTW32_PROGCTR(Context)  ((Context).Fir)
#endif

#if defined(_PPC_)
#define PTW32_PROGCTR(Context)  ((Context).Iar)
#endif

#if defined(_AMD64_) || defined(__amd64__)
#define PTW32_PROGCTR(Context)  ((Context).Rip)
#endif

#if defined(_ARM_) || defined(ARM)
#define PTW32_PROGCTR(Context)  ((Context).Pc)
#endif

#if !defined(PTW32_PROGCTR)
#error Module contains CPU-specific code; modify and recompile.
#endif

#endif


 /*
 * implement.h
 *
 * Definitions that don't need to be public.
 *
 * Keeps all the internals out of pthread.h
 *
 * --------------------------------------------------------------------------
 *
 *      Pthreads-win32 - POSIX Threads Library for Win32
 *      Copyright(C) 1998 John E. Bossom
 *      Copyright(C) 1999,2005 Pthreads-win32 contributors
 *
 *      Contact Email: Ross.Johnson@homemail.com.au
 *
 *      The current list of contributors is contained
 *      in the file CONTRIBUTORS included with the source
 *      code distribution. The list can also be seen at the
 *      following World Wide Web location:
 *      http://sources.redhat.com/pthreads-win32/contributors.html
 *
 *      This library is free software; you can redistribute it and/or
 *      modify it under the terms of the GNU Lesser General Public
 *      License as published by the Free Software Foundation; either
 *      version 2 of the License, or (at your option) any later version.
 *
 *      This library is distributed in the hope that it will be useful,
 *      but WITHOUT ANY WARRANTY; without even the implied warranty of
 *      MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *      Lesser General Public License for more details.
 *
 *      You should have received a copy of the GNU Lesser General Public
 *      License along with this library in the file COPYING.LIB;
 *      if not, write to the Free Software Foundation, Inc.,
 *      59 Temple Place - Suite 330, Boston, MA 02111-1307, USA
 */

#if !defined(_IMPLEMENT_H)
#define _IMPLEMENT_H

#if !defined(_WIN32_WINNT)
#define _WIN32_WINNT 0x0400
#endif

#include <windows.h>

 /*
 * In case windows.h doesn't define it (e.g. WinCE perhaps)
 */
#if defined(WINCE)
typedef VOID(APIENTRY *PAPCFUNC)(DWORD dwParam);
#endif

/*
* note: ETIMEDOUT is correctly defined in winsock.h
*/
#include <winsock.h>

/*
* In case ETIMEDOUT hasn't been defined above somehow.
*/
#if !defined(ETIMEDOUT)
#  define ETIMEDOUT 10060	/* This is the value in winsock.h. */
#endif

#if !defined(malloc)
#include <malloc.h>
#endif

#if defined(__CLEANUP_C)
# include <setjmp.h>
#endif

#if !defined(INT_MAX)
#include <limits.h>
#endif


#if defined(HAVE_C_INLINE) || defined(__cplusplus)
#define INLINE inline
#else
#define INLINE
#endif

#if defined(_MSC_VER) && _MSC_VER < 1300
/*
* MSVC 6 does not use the "volatile" qualifier
*/
#define PTW32_INTERLOCKED_VOLATILE
#else
#define PTW32_INTERLOCKED_VOLATILE volatile
#endif
#define PTW32_INTERLOCKED_LONG long
#define PTW32_INTERLOCKED_SIZE size_t
#define PTW32_INTERLOCKED_PVOID PVOID
#define PTW32_INTERLOCKED_LONGPTR PTW32_INTERLOCKED_VOLATILE long*
#define PTW32_INTERLOCKED_SIZEPTR PTW32_INTERLOCKED_VOLATILE size_t*
#define PTW32_INTERLOCKED_PVOID_PTR PTW32_INTERLOCKED_VOLATILE PVOID*

#if defined(__MINGW64__) || defined(__MINGW32__)
#  include <stdint.h>
#elif defined(__BORLANDC__)
#  define int64_t ULONGLONG
#else
#  define int64_t _int64
#  if defined(_MSC_VER) && _MSC_VER < 1300
typedef long intptr_t;
#  endif
#endif

typedef enum
{
	/*
	* This enumeration represents the state of the thread;
	* The thread is still "alive" if the numeric value of the
	* state is greater or equal "PThreadStateRunning".
	*/
	PThreadStateInitial = 0,	/* Thread not running                   */
	PThreadStateRunning,		/* Thread alive & kicking               */
	PThreadStateSuspended,	/* Thread alive but suspended           */
	PThreadStateCancelPending,	/* Thread alive but                     */
								/* has cancelation pending.             */
								PThreadStateCanceling,	/* Thread alive but is                  */
														/* in the process of terminating        */
														/* due to a cancellation request        */
														PThreadStateExiting,		/* Thread alive but exiting             */
																					/* due to an exception                  */
																					PThreadStateLast,             /* All handlers have been run and now   */
																												  /* final cleanup can be done.           */
																												  PThreadStateReuse             /* In reuse pool.                       */
}
PThreadState;

typedef struct ptw32_mcs_node_t_     ptw32_mcs_local_node_t;
typedef struct ptw32_mcs_node_t_*    ptw32_mcs_lock_t;
typedef struct ptw32_robust_node_t_  ptw32_robust_node_t;
typedef struct ptw32_thread_t_       ptw32_thread_t;


struct ptw32_thread_t_
{
	unsigned __int64 seqNumber;	/* Process-unique thread sequence number */
	HANDLE threadH;		/* Win32 thread handle - POSIX thread is invalid if threadH == 0 */
	pthread_t ptHandle;		/* This thread's permanent pthread_t handle */
	ptw32_thread_t * prevReuse;	/* Links threads on reuse stack */
	volatile PThreadState state;
	ptw32_mcs_lock_t threadLock;	/* Used for serialised access to public thread state */
	ptw32_mcs_lock_t stateLock;	/* Used for async-cancel safety */
	HANDLE cancelEvent;
	void *exitStatus;
	void *parms;
	void *keys;
	void *nextAssoc;
#if defined(__CLEANUP_C)
	jmp_buf start_mark;		/* Jump buffer follows void* so should be aligned */
#endif				/* __CLEANUP_C */
#if defined(HAVE_SIGSET_T)
	sigset_t sigmask;
#endif				/* HAVE_SIGSET_T */
	ptw32_mcs_lock_t
		robustMxListLock; /* robustMxList lock */
	ptw32_robust_node_t*
		robustMxList; /* List of currenty held robust mutexes */
	int ptErrno;
	int detachState;
	int sched_priority;		/* As set, not as currently is */
	int cancelState;
	int cancelType;
	int implicit : 1;
	DWORD thread;			/* Win32 thread ID */
#if defined(_UWIN)
	DWORD dummy[5];
#endif
	size_t align;			/* Force alignment if this struct is packed */
};


/*
* Special value to mark attribute objects as valid.
*/
#define PTW32_ATTR_VALID ((unsigned long) 0xC4C0FFEE)

struct pthread_attr_t_
{
	unsigned long valid;
	void *stackaddr;
	size_t stacksize;
	int detachstate;
	struct sched_param param;
	int inheritsched;
	int contentionscope;
#if defined(HAVE_SIGSET_T)
	sigset_t sigmask;
#endif				/* HAVE_SIGSET_T */
};


/*
* ====================
* ====================
* Semaphores, Mutexes and Condition Variables
* ====================
* ====================
*/

struct sem_t_
{
	int value;
	pthread_mutex_t lock;
	HANDLE sem;
#if defined(NEED_SEM)
	int leftToUnblock;
#endif
};

#define PTW32_OBJECT_AUTO_INIT ((void *)(size_t) -1)
#define PTW32_OBJECT_INVALID   NULL

struct pthread_mutex_t_
{
	LONG lock_idx;		/* Provides exclusive access to mutex state
						via the Interlocked* mechanism.
						0: unlocked/free.
						1: locked - no other waiters.
						-1: locked - with possible other waiters.
						*/
	int recursive_count;		/* Number of unlocks a thread needs to perform
								before the lock is released (recursive
								mutexes only). */
	int kind;			/* Mutex type. */
	pthread_t ownerThread;
	HANDLE event;			/* Mutex release notification to waiting
							threads. */
	ptw32_robust_node_t*
		robustNode; /* Extra state for robust mutexes  */
};

enum ptw32_robust_state_t_
{
	PTW32_ROBUST_CONSISTENT,
	PTW32_ROBUST_INCONSISTENT,
	PTW32_ROBUST_NOTRECOVERABLE
};

typedef enum ptw32_robust_state_t_   ptw32_robust_state_t;

/*
* Node used to manage per-thread lists of currently-held robust mutexes.
*/
struct ptw32_robust_node_t_
{
	pthread_mutex_t mx;
	ptw32_robust_state_t stateInconsistent;
	ptw32_robust_node_t* prev;
	ptw32_robust_node_t* next;
};

struct pthread_mutexattr_t_
{
	int pshared;
	int kind;
	int robustness;
};

/*
* Possible values, other than PTW32_OBJECT_INVALID,
* for the "interlock" element in a spinlock.
*
* In this implementation, when a spinlock is initialised,
* the number of cpus available to the process is checked.
* If there is only one cpu then "interlock" is set equal to
* PTW32_SPIN_USE_MUTEX and u.mutex is an initialised mutex.
* If the number of cpus is greater than 1 then "interlock"
* is set equal to PTW32_SPIN_UNLOCKED and the number is
* stored in u.cpus. This arrangement allows the spinlock
* routines to attempt an InterlockedCompareExchange on "interlock"
* immediately and, if that fails, to try the inferior mutex.
*
* "u.cpus" isn't used for anything yet, but could be used at
* some point to optimise spinlock behaviour.
*/
#define PTW32_SPIN_INVALID     (0)
#define PTW32_SPIN_UNLOCKED    (1)
#define PTW32_SPIN_LOCKED      (2)
#define PTW32_SPIN_USE_MUTEX   (3)

struct pthread_spinlock_t_
{
	long interlock;		/* Locking element for multi-cpus. */
	union
	{
		int cpus;			/* No. of cpus if multi cpus, or   */
		pthread_mutex_t mutex;	/* mutex if single cpu.            */
	} u;
};

/*
* MCS lock queue node - see ptw32_MCS_lock.c
*/
struct ptw32_mcs_node_t_
{
	struct ptw32_mcs_node_t_ **lock;        /* ptr to tail of queue */
	struct ptw32_mcs_node_t_  *next;        /* ptr to successor in queue */
	HANDLE                     readyFlag;   /* set after lock is released by
											predecessor */
	HANDLE                     nextFlag;    /* set after 'next' ptr is set by
											successor */
};


struct pthread_barrier_t_
{
	unsigned int nCurrentBarrierHeight;
	unsigned int nInitialBarrierHeight;
	int pshared;
	sem_t semBarrierBreeched;
	ptw32_mcs_lock_t lock;
	ptw32_mcs_local_node_t proxynode;
};

struct pthread_barrierattr_t_
{
	int pshared;
};

struct pthread_key_t_
{
	DWORD key;
	void (PTW32_CDECL *destructor) (void *);
	ptw32_mcs_lock_t keyLock;
	void *threads;
};


typedef struct ThreadParms ThreadParms;

struct ThreadParms
{
	pthread_t tid;
	void *(PTW32_CDECL *start) (void *);
	void *arg;
};


struct pthread_cond_t_
{
	long nWaitersBlocked;		/* Number of threads blocked            */
	long nWaitersGone;		/* Number of threads timed out          */
	long nWaitersToUnblock;	/* Number of threads to unblock         */
	sem_t semBlockQueue;		/* Queue up threads waiting for the     */
								/*   condition to become signalled      */
	sem_t semBlockLock;		/* Semaphore that guards access to      */
							/* | waiters blocked count/block queue  */
							/* +-> Mandatory Sync.LEVEL-1           */
	pthread_mutex_t mtxUnblockLock;	/* Mutex that guards access to          */
									/* | waiters (to)unblock(ed) counts     */
									/* +-> Optional* Sync.LEVEL-2           */
	pthread_cond_t next;		/* Doubly linked list                   */
	pthread_cond_t prev;
};


struct pthread_condattr_t_
{
	int pshared;
};

#define PTW32_RWLOCK_MAGIC 0xfacade2

struct pthread_rwlock_t_
{
	pthread_mutex_t mtxExclusiveAccess;
	pthread_mutex_t mtxSharedAccessCompleted;
	pthread_cond_t cndSharedAccessCompleted;
	int nSharedAccessCount;
	int nExclusiveAccessCount;
	int nCompletedSharedAccessCount;
	int nMagic;
};

struct pthread_rwlockattr_t_
{
	int pshared;
};

typedef struct ThreadKeyAssoc ThreadKeyAssoc;

struct ThreadKeyAssoc
{
	/*
	* Purpose:
	*      This structure creates an association between a thread and a key.
	*      It is used to implement the implicit invocation of a user defined
	*      destroy routine for thread specific data registered by a user upon
	*      exiting a thread.
	*
	*      Graphically, the arrangement is as follows, where:
	*
	*         K - Key with destructor
	*            (head of chain is key->threads)
	*         T - Thread that has called pthread_setspecific(Kn)
	*            (head of chain is thread->keys)
	*         A - Association. Each association is a node at the
	*             intersection of two doubly-linked lists.
	*
	*                 T1    T2    T3
	*                 |     |     |
	*                 |     |     |
	*         K1 -----+-----A-----A----->
	*                 |     |     |
	*                 |     |     |
	*         K2 -----A-----A-----+----->
	*                 |     |     |
	*                 |     |     |
	*         K3 -----A-----+-----A----->
	*                 |     |     |
	*                 |     |     |
	*                 V     V     V
	*
	*      Access to the association is guarded by two locks: the key's
	*      general lock (guarding the row) and the thread's general
	*      lock (guarding the column). This avoids the need for a
	*      dedicated lock for each association, which not only consumes
	*      more handles but requires that the lock resources persist
	*      until both the key is deleted and the thread has called the
	*      destructor. The two-lock arrangement allows those resources
	*      to be freed as soon as either thread or key is concluded.
	*
	*      To avoid deadlock, whenever both locks are required both the
	*      key and thread locks are acquired consistently in the order
	*      "key lock then thread lock". An exception to this exists
	*      when a thread calls the destructors, however, this is done
	*      carefully (but inelegantly) to avoid deadlock.
	*
	*      An association is created when a thread first calls
	*      pthread_setspecific() on a key that has a specified
	*      destructor.
	*
	*      An association is destroyed either immediately after the
	*      thread calls the key destructor function on thread exit, or
	*      when the key is deleted.
	*
	* Attributes:
	*      thread
	*              reference to the thread that owns the
	*              association. This is actually the pointer to the
	*              thread struct itself. Since the association is
	*              destroyed before the thread exits, this can never
	*              point to a different logical thread to the one that
	*              created the assoc, i.e. after thread struct reuse.
	*
	*      key
	*              reference to the key that owns the association.
	*
	*      nextKey
	*              The pthread_t->keys attribute is the head of a
	*              chain of associations that runs through the nextKey
	*              link. This chain provides the 1 to many relationship
	*              between a pthread_t and all pthread_key_t on which
	*              it called pthread_setspecific.
	*
	*      prevKey
	*              Similarly.
	*
	*      nextThread
	*              The pthread_key_t->threads attribute is the head of
	*              a chain of associations that runs through the
	*              nextThreads link. This chain provides the 1 to many
	*              relationship between a pthread_key_t and all the
	*              PThreads that have called pthread_setspecific for
	*              this pthread_key_t.
	*
	*      prevThread
	*              Similarly.
	*
	* Notes:
	*      1)      As soon as either the key or the thread is no longer
	*              referencing the association, it can be destroyed. The
	*              association will be removed from both chains.
	*
	*      2)      Under WIN32, an association is only created by
	*              pthread_setspecific if the user provided a
	*              destroyRoutine when they created the key.
	*
	*
	*/
	ptw32_thread_t * thread;
	pthread_key_t key;
	ThreadKeyAssoc *nextKey;
	ThreadKeyAssoc *nextThread;
	ThreadKeyAssoc *prevKey;
	ThreadKeyAssoc *prevThread;
};


#if defined(__CLEANUP_SEH)
/*
* --------------------------------------------------------------
* MAKE_SOFTWARE_EXCEPTION
*      This macro constructs a software exception code following
*      the same format as the standard Win32 error codes as defined
*      in WINERROR.H
*  Values are 32 bit values laid out as follows:
*
*   1 0 9 8 7 6 5 4 3 2 1 0 9 8 7 6 5 4 3 2 1 0 9 8 7 6 5 4 3 2 1 0
*  +---+-+-+-----------------------+-------------------------------+
*  |Sev|C|R|     Facility          |               Code            |
*  +---+-+-+-----------------------+-------------------------------+
*
* Severity Values:
*/
#define SE_SUCCESS              0x00
#define SE_INFORMATION          0x01
#define SE_WARNING              0x02
#define SE_ERROR                0x03

#define MAKE_SOFTWARE_EXCEPTION( _severity, _facility, _exception ) \
( (DWORD) ( ( (_severity) << 30 ) |     /* Severity code        */ \
            ( 1 << 29 ) |               /* MS=0, User=1         */ \
            ( 0 << 28 ) |               /* Reserved             */ \
            ( (_facility) << 16 ) |     /* Facility Code        */ \
            ( (_exception) <<  0 )      /* Exception Code       */ \
            ) )

/*
* We choose one specific Facility/Error code combination to
* identify our software exceptions vs. WIN32 exceptions.
* We store our actual component and error code within
* the optional information array.
*/
#define EXCEPTION_PTW32_SERVICES        \
     MAKE_SOFTWARE_EXCEPTION( SE_ERROR, \
                              PTW32_SERVICES_FACILITY, \
                              PTW32_SERVICES_ERROR )

#define PTW32_SERVICES_FACILITY         0xBAD
#define PTW32_SERVICES_ERROR            0xDEED

#endif /* __CLEANUP_SEH */

/*
* Services available through EXCEPTION_PTW32_SERVICES
* and also used [as parameters to ptw32_throw()] as
* generic exception selectors.
*/

#define PTW32_EPS_EXIT                  (1)
#define PTW32_EPS_CANCEL                (2)


/* Useful macros */
#define PTW32_MAX(a,b)  ((a)<(b)?(b):(a))
#define PTW32_MIN(a,b)  ((a)>(b)?(b):(a))


/* Declared in pthread_cancel.c */
extern DWORD(*ptw32_register_cancelation) (PAPCFUNC, HANDLE, DWORD);

/* Thread Reuse stack bottom marker. Must not be NULL or any valid pointer to memory. */
#define PTW32_THREAD_REUSE_EMPTY ((ptw32_thread_t *)(size_t) 1)

extern int ptw32_processInitialized;
extern ptw32_thread_t * ptw32_threadReuseTop;
extern ptw32_thread_t * ptw32_threadReuseBottom;
extern pthread_key_t ptw32_selfThreadKey;
extern pthread_key_t ptw32_cleanupKey;
extern pthread_cond_t ptw32_cond_list_head;
extern pthread_cond_t ptw32_cond_list_tail;

extern int ptw32_mutex_default_kind;

extern unsigned __int64 ptw32_threadSeqNumber;

extern int ptw32_concurrency;

extern int ptw32_features;

extern ptw32_mcs_lock_t ptw32_thread_reuse_lock;
extern ptw32_mcs_lock_t ptw32_mutex_test_init_lock;
extern ptw32_mcs_lock_t ptw32_cond_list_lock;
extern ptw32_mcs_lock_t ptw32_cond_test_init_lock;
extern ptw32_mcs_lock_t ptw32_rwlock_test_init_lock;
extern ptw32_mcs_lock_t ptw32_spinlock_test_init_lock;

#if defined(_UWIN)
extern int pthread_count;
#endif

#if defined(__cplusplus)
extern "C"
{
#endif				/* __cplusplus */

	/*
	* =====================
	* =====================
	* Forward Declarations
	* =====================
	* =====================
	*/

	int ptw32_is_attr(const pthread_attr_t * attr);

	int ptw32_cond_check_need_init(pthread_cond_t * cond);
	int ptw32_mutex_check_need_init(pthread_mutex_t * mutex);
	int ptw32_rwlock_check_need_init(pthread_rwlock_t * rwlock);

	int ptw32_robust_mutex_inherit(pthread_mutex_t * mutex);
	void ptw32_robust_mutex_add(pthread_mutex_t* mutex, pthread_t self);
	void ptw32_robust_mutex_remove(pthread_mutex_t* mutex, ptw32_thread_t* otp);

	DWORD
		ptw32_RegisterCancelation(PAPCFUNC callback,
			HANDLE threadH, DWORD callback_arg);

	int ptw32_processInitialize(void);

	void ptw32_processTerminate(void);

	void ptw32_threadDestroy(pthread_t tid);

	void ptw32_pop_cleanup_all(int execute);

	pthread_t ptw32_new(void);

	pthread_t ptw32_threadReusePop(void);

	void ptw32_threadReusePush(pthread_t thread);

	int ptw32_getprocessors(int *count);

	int ptw32_setthreadpriority(pthread_t thread, int policy, int priority);

	void ptw32_rwlock_cancelwrwait(void *arg);

#if ! (defined (__MINGW64__) || defined(__MINGW32__)) || (defined(__MSVCRT__) && ! defined(__DMC__))
	unsigned __stdcall
#else
	void
#endif
		ptw32_threadStart(void *vthreadParms);

	void ptw32_callUserDestroyRoutines(pthread_t thread);

	int ptw32_tkAssocCreate(ptw32_thread_t * thread, pthread_key_t key);

	void ptw32_tkAssocDestroy(ThreadKeyAssoc * assoc);

	int ptw32_semwait(sem_t * sem);

	DWORD ptw32_relmillisecs(const struct timespec * abstime);

	void ptw32_mcs_lock_acquire(ptw32_mcs_lock_t * lock, ptw32_mcs_local_node_t * node);

	int ptw32_mcs_lock_try_acquire(ptw32_mcs_lock_t * lock, ptw32_mcs_local_node_t * node);

	void ptw32_mcs_lock_release(ptw32_mcs_local_node_t * node);

	void ptw32_mcs_node_transfer(ptw32_mcs_local_node_t * new_node, ptw32_mcs_local_node_t * old_node);

#if defined(NEED_FTIME)
	void ptw32_timespec_to_filetime(const struct timespec *ts, FILETIME * ft);
	void ptw32_filetime_to_timespec(const FILETIME * ft, struct timespec *ts);
#endif

	/* Declared in misc.c */
#if defined(NEED_CALLOC)
#define calloc(n, s) ptw32_calloc(n, s)
	void *ptw32_calloc(size_t n, size_t s);
#endif

	/* Declared in private.c */
#if defined(_MSC_VER)
	/*
	* Ignore the warning:
	* "C++ exception specification ignored except to indicate that
	* the function is not __declspec(nothrow)."
	*/
#pragma warning(disable:4290)
#endif
	void ptw32_throw(DWORD exception)
#if defined(__CLEANUP_CXX)
		throw(ptw32_exception_cancel, ptw32_exception_exit)
#endif
		;

#if defined(__cplusplus)
}
#endif				/* __cplusplus */


#if defined(_UWIN_)
#   if defined(_MT)
#       if defined(__cplusplus)
extern "C"
{
#       endif
	_CRTIMP unsigned long __cdecl _beginthread(void(__cdecl *) (void *),
		unsigned, void *);
	_CRTIMP void __cdecl _endthread(void);
	_CRTIMP unsigned long __cdecl _beginthreadex(void *, unsigned,
		unsigned(__stdcall *) (void *),
		void *, unsigned, unsigned *);
	_CRTIMP void __cdecl _endthreadex(unsigned);
#       if defined(__cplusplus)
}
#       endif
#   endif
#else
#       include <process.h>
#   endif


/*
* Use intrinsic versions wherever possible. VC will do this
* automatically where possible and GCC define these if available:
* __GCC_HAVE_SYNC_COMPARE_AND_SWAP_1
* __GCC_HAVE_SYNC_COMPARE_AND_SWAP_2
* __GCC_HAVE_SYNC_COMPARE_AND_SWAP_4
* __GCC_HAVE_SYNC_COMPARE_AND_SWAP_8
* __GCC_HAVE_SYNC_COMPARE_AND_SWAP_16
*
* The full set of Interlocked intrinsics in GCC are (check versions):
* type __sync_fetch_and_add (type *ptr, type value, ...)
* type __sync_fetch_and_sub (type *ptr, type value, ...)
* type __sync_fetch_and_or (type *ptr, type value, ...)
* type __sync_fetch_and_and (type *ptr, type value, ...)
* type __sync_fetch_and_xor (type *ptr, type value, ...)
* type __sync_fetch_and_nand (type *ptr, type value, ...)
* type __sync_add_and_fetch (type *ptr, type value, ...)
* type __sync_sub_and_fetch (type *ptr, type value, ...)
* type __sync_or_and_fetch (type *ptr, type value, ...)
* type __sync_and_and_fetch (type *ptr, type value, ...)
* type __sync_xor_and_fetch (type *ptr, type value, ...)
* type __sync_nand_and_fetch (type *ptr, type value, ...)
* bool __sync_bool_compare_and_swap (type *ptr, type oldval type newval, ...)
* type __sync_val_compare_and_swap (type *ptr, type oldval type newval, ...)
* __sync_synchronize (...) // Full memory barrier
* type __sync_lock_test_and_set (type *ptr, type value, ...) // Acquire barrier
* void __sync_lock_release (type *ptr, ...) // Release barrier
*
* These are all overloaded and take 1,2,4,8 byte scalar or pointer types.
*
* The above aren't available in Mingw32 as of gcc 4.5.2 so define our own.
*/
#if defined(__GNUC__)
# if defined(_WIN64)
# define PTW32_INTERLOCKED_COMPARE_EXCHANGE_64(location, value, comparand)    \
    ({                                                                     \
      __typeof (value) _result;                                            \
      __asm__ __volatile__                                                 \
      (                                                                    \
        "lock\n\t"                                                         \
        "cmpxchgq      %2,(%1)"                                            \
        :"=a" (_result)                                                    \
        :"r"  (location), "r" (value), "a" (comparand)                     \
        :"memory", "cc");                                                  \
      _result;                                                             \
    })
# define PTW32_INTERLOCKED_EXCHANGE_64(location, value)                    \
    ({                                                                     \
      __typeof (value) _result;                                            \
      __asm__ __volatile__                                                 \
      (                                                                    \
        "xchgq	 %0,(%1)"                                                  \
        :"=r" (_result)                                                    \
        :"r" (location), "0" (value)                                       \
        :"memory", "cc");                                                  \
      _result;                                                             \
    })
# define PTW32_INTERLOCKED_EXCHANGE_ADD_64(location, value)                \
    ({                                                                     \
      __typeof (value) _result;                                            \
      __asm__ __volatile__                                                 \
      (                                                                    \
        "lock\n\t"                                                         \
        "xaddq	 %0,(%1)"                                                  \
        :"=r" (_result)                                                    \
        :"r" (location), "0" (value)                                       \
        :"memory", "cc");                                                  \
      _result;                                                             \
    })
# define PTW32_INTERLOCKED_INCREMENT_64(location)                          \
    ({                                                                     \
      PTW32_INTERLOCKED_LONG _temp = 1;                                   \
      __asm__ __volatile__                                                 \
      (                                                                    \
        "lock\n\t"                                                         \
        "xaddq	 %0,(%1)"                                                  \
        :"+r" (_temp)                                                      \
        :"r" (location)                                                    \
        :"memory", "cc");                                                  \
      ++_temp;                                                             \
    })
# define PTW32_INTERLOCKED_DECREMENT_64(location)                          \
    ({                                                                     \
      PTW32_INTERLOCKED_LONG _temp = -1;                                  \
      __asm__ __volatile__                                                 \
      (                                                                    \
        "lock\n\t"                                                         \
        "xaddq	 %2,(%1)"                                                  \
        :"+r" (_temp)                                                      \
        :"r" (location)                                                    \
        :"memory", "cc");                                                  \
      --_temp;                                                             \
    })
#endif
# define PTW32_INTERLOCKED_COMPARE_EXCHANGE_LONG(location, value, comparand)    \
    ({                                                                     \
      __typeof (value) _result;                                            \
      __asm__ __volatile__                                                 \
      (                                                                    \
        "lock\n\t"                                                         \
        "cmpxchgl       %2,(%1)"                                           \
        :"=a" (_result)                                                    \
        :"r"  (location), "r" (value), "a" (comparand)                     \
        :"memory", "cc");                                                  \
      _result;                                                             \
    })
# define PTW32_INTERLOCKED_EXCHANGE_LONG(location, value)                  \
    ({                                                                     \
      __typeof (value) _result;                                            \
      __asm__ __volatile__                                                 \
      (                                                                    \
        "xchgl	 %0,(%1)"                                                  \
        :"=r" (_result)                                                    \
        :"r" (location), "0" (value)                                       \
        :"memory", "cc");                                                  \
      _result;                                                             \
    })
# define PTW32_INTERLOCKED_EXCHANGE_ADD_LONG(location, value)              \
    ({                                                                     \
      __typeof (value) _result;                                            \
      __asm__ __volatile__                                                 \
      (                                                                    \
        "lock\n\t"                                                         \
        "xaddl	 %0,(%1)"                                                  \
        :"=r" (_result)                                                    \
        :"r" (location), "0" (value)                                       \
        :"memory", "cc");                                                  \
      _result;                                                             \
    })
# define PTW32_INTERLOCKED_INCREMENT_LONG(location)                        \
    ({                                                                     \
      PTW32_INTERLOCKED_LONG _temp = 1;                                   \
      __asm__ __volatile__                                                 \
      (                                                                    \
        "lock\n\t"                                                         \
        "xaddl	 %0,(%1)"                                                  \
        :"+r" (_temp)                                                      \
        :"r" (location)                                                    \
        :"memory", "cc");                                                  \
      ++_temp;                                                             \
    })
# define PTW32_INTERLOCKED_DECREMENT_LONG(location)                        \
    ({                                                                     \
      PTW32_INTERLOCKED_LONG _temp = -1;                                  \
      __asm__ __volatile__                                                 \
      (                                                                    \
        "lock\n\t"                                                         \
        "xaddl	 %0,(%1)"                                                  \
        :"+r" (_temp)                                                      \
        :"r" (location)                                                    \
        :"memory", "cc");                                                  \
      --_temp;                                                             \
    })
# define PTW32_INTERLOCKED_COMPARE_EXCHANGE_PTR(location, value, comparand) \
    PTW32_INTERLOCKED_COMPARE_EXCHANGE_SIZE((PTW32_INTERLOCKED_SIZEPTR)location, \
                                            (PTW32_INTERLOCKED_SIZE)value, \
                                            (PTW32_INTERLOCKED_SIZE)comparand)
# define PTW32_INTERLOCKED_EXCHANGE_PTR(location, value) \
    PTW32_INTERLOCKED_EXCHANGE_SIZE((PTW32_INTERLOCKED_SIZEPTR)location, \
                                    (PTW32_INTERLOCKED_SIZE)value)
#else
# if defined(_WIN64)
#   define PTW32_INTERLOCKED_COMPARE_EXCHANGE_64 InterlockedCompareExchange64
#   define PTW32_INTERLOCKED_EXCHANGE_64 InterlockedExchange64
#   define PTW32_INTERLOCKED_EXCHANGE_ADD_64 InterlockedExchangeAdd64
#   define PTW32_INTERLOCKED_INCREMENT_64 InterlockedIncrement64
#   define PTW32_INTERLOCKED_DECREMENT_64 InterlockedDecrement64
# endif
# if defined(_MSC_VER) && _MSC_VER < 1300 && !defined(_WIN64) /* MSVC 6 */
#  define PTW32_INTERLOCKED_COMPARE_EXCHANGE_LONG(location, value, comparand) \
      ((LONG)InterlockedCompareExchange((PVOID *)(location), (PVOID)(value), (PVOID)(comparand)))
# else
#  define PTW32_INTERLOCKED_COMPARE_EXCHANGE_LONG InterlockedCompareExchange
# endif
# define PTW32_INTERLOCKED_EXCHANGE_LONG InterlockedExchange
# define PTW32_INTERLOCKED_EXCHANGE_ADD_LONG InterlockedExchangeAdd
# define PTW32_INTERLOCKED_INCREMENT_LONG InterlockedIncrement
# define PTW32_INTERLOCKED_DECREMENT_LONG InterlockedDecrement
# if defined(_MSC_VER) && _MSC_VER < 1300 && !defined(_WIN64) /* MSVC 6 */
#  define PTW32_INTERLOCKED_COMPARE_EXCHANGE_PTR InterlockedCompareExchange
#  define PTW32_INTERLOCKED_EXCHANGE_PTR(location, value) \
    ((PVOID)InterlockedExchange((LPLONG)(location), (LONG)(value)))
# else
#  define PTW32_INTERLOCKED_COMPARE_EXCHANGE_PTR InterlockedCompareExchangePointer
#  define PTW32_INTERLOCKED_EXCHANGE_PTR InterlockedExchangePointer
# endif
#endif
#if defined(_WIN64)
#   define PTW32_INTERLOCKED_COMPARE_EXCHANGE_SIZE PTW32_INTERLOCKED_COMPARE_EXCHANGE_64
#   define PTW32_INTERLOCKED_EXCHANGE_SIZE PTW32_INTERLOCKED_EXCHANGE_64
#   define PTW32_INTERLOCKED_EXCHANGE_ADD_SIZE PTW32_INTERLOCKED_EXCHANGE_ADD_64
#   define PTW32_INTERLOCKED_INCREMENT_SIZE PTW32_INTERLOCKED_INCREMENT_64
#   define PTW32_INTERLOCKED_DECREMENT_SIZE PTW32_INTERLOCKED_DECREMENT_64
#else
#   define PTW32_INTERLOCKED_COMPARE_EXCHANGE_SIZE PTW32_INTERLOCKED_COMPARE_EXCHANGE_LONG
#   define PTW32_INTERLOCKED_EXCHANGE_SIZE PTW32_INTERLOCKED_EXCHANGE_LONG
#   define PTW32_INTERLOCKED_EXCHANGE_ADD_SIZE PTW32_INTERLOCKED_EXCHANGE_ADD_LONG
#   define PTW32_INTERLOCKED_INCREMENT_SIZE PTW32_INTERLOCKED_INCREMENT_LONG
#   define PTW32_INTERLOCKED_DECREMENT_SIZE PTW32_INTERLOCKED_DECREMENT_LONG
#endif

#if defined(NEED_CREATETHREAD)

/*
* Macro uses args so we can cast start_proc to LPTHREAD_START_ROUTINE
* in order to avoid warnings because of return type
*/

#define _beginthreadex(security, \
                       stack_size, \
                       start_proc, \
                       arg, \
                       flags, \
                       pid) \
        CreateThread(security, \
                     stack_size, \
                     (LPTHREAD_START_ROUTINE) start_proc, \
                     arg, \
                     flags, \
                     pid)

#define _endthreadex ExitThread

#endif				/* NEED_CREATETHREAD */


#endif				/* _IMPLEMENT_H */



#if defined(PTW32_STATIC_LIB)

#if defined(__MINGW64__) || defined(__MINGW32__) || defined(_MSC_VER)


static void on_process_init(void)
{
	pthread_win32_process_attach_np();
}

static void on_process_exit(void)
{
	pthread_win32_thread_detach_np();
	pthread_win32_process_detach_np();
}

#if defined(__MINGW64__) || defined(__MINGW32__)
# define attribute_section(a) __attribute__((section(a)))
#elif defined(_MSC_VER)
# define attribute_section(a) __pragma(section(a,long,read)); __declspec(allocate(a))
#endif

attribute_section(".ctors") void *gcc_ctor = on_process_init;
attribute_section(".dtors") void *gcc_dtor = on_process_exit;

attribute_section(".CRT$XCU") void *msc_ctor = on_process_init;
attribute_section(".CRT$XPU") void *msc_dtor = on_process_exit;

#endif /* defined(__MINGW64__) || defined(__MINGW32__) || defined(_MSC_VER) */

#endif /* PTW32_STATIC_LIB */
/*
 * barrier.c
 *
 * Description:
 * This translation unit implements barrier primitives.
 *
 * --------------------------------------------------------------------------
 *
 *      Pthreads-win32 - POSIX Threads Library for Win32
 *      Copyright(C) 1998 John E. Bossom
 *      Copyright(C) 1999,2005 Pthreads-win32 contributors
 *
 *      Contact Email: rpj@callisto.canberra.edu.au
 *
 *      The current list of contributors is contained
 *      in the file CONTRIBUTORS included with the source
 *      code distribution. The list can also be seen at the
 *      following World Wide Web location:
 *      http://sources.redhat.com/pthreads-win32/contributors.html
 *
 *      This library is free software; you can redistribute it and/or
 *      modify it under the terms of the GNU Lesser General Public
 *      License as published by the Free Software Foundation; either
 *      version 2 of the License, or (at your option) any later version.
 *
 *      This library is distributed in the hope that it will be useful,
 *      but WITHOUT ANY WARRANTY; without even the implied warranty of
 *      MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *      Lesser General Public License for more details.
 *
 *      You should have received a copy of the GNU Lesser General Public
 *      License along with this library in the file COPYING.LIB;
 *      if not, write to the Free Software Foundation, Inc.,
 *      59 Temple Place - Suite 330, Boston, MA 02111-1307, USA
 */



 /*
  * cancel.c
  *
  * Description:
  * POSIX thread functions related to thread cancellation.
  *
  * --------------------------------------------------------------------------
  *
  *      Pthreads-win32 - POSIX Threads Library for Win32
  *      Copyright(C) 1998 John E. Bossom
  *      Copyright(C) 1999,2005 Pthreads-win32 contributors
  *
  *      Contact Email: rpj@callisto.canberra.edu.au
  *
  *      The current list of contributors is contained
  *      in the file CONTRIBUTORS included with the source
  *      code distribution. The list can also be seen at the
  *      following World Wide Web location:
  *      http://sources.redhat.com/pthreads-win32/contributors.html
  *
  *      This library is free software; you can redistribute it and/or
  *      modify it under the terms of the GNU Lesser General Public
  *      License as published by the Free Software Foundation; either
  *      version 2 of the License, or (at your option) any later version.
  *
  *      This library is distributed in the hope that it will be useful,
  *      but WITHOUT ANY WARRANTY; without even the implied warranty of
  *      MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
  *      Lesser General Public License for more details.
  *
  *      You should have received a copy of the GNU Lesser General Public
  *      License along with this library in the file COPYING.LIB;
  *      if not, write to the Free Software Foundation, Inc.,
  *      59 Temple Place - Suite 330, Boston, MA 02111-1307, USA
  */



  /*
   * cleanup.c
   *
   * Description:
   * This translation unit implements routines associated
   * with cleaning up threads.
   *
   *
   * --------------------------------------------------------------------------
   *
   *      Pthreads-win32 - POSIX Threads Library for Win32
   *      Copyright(C) 1998 John E. Bossom
   *      Copyright(C) 1999,2005 Pthreads-win32 contributors
   *
   *      Contact Email: rpj@callisto.canberra.edu.au
   *
   *      The current list of contributors is contained
   *      in the file CONTRIBUTORS included with the source
   *      code distribution. The list can also be seen at the
   *      following World Wide Web location:
   *      http://sources.redhat.com/pthreads-win32/contributors.html
   *
   *      This library is free software; you can redistribute it and/or
   *      modify it under the terms of the GNU Lesser General Public
   *      License as published by the Free Software Foundation; either
   *      version 2 of the License, or (at your option) any later version.
   *
   *      This library is distributed in the hope that it will be useful,
   *      but WITHOUT ANY WARRANTY; without even the implied warranty of
   *      MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   *      Lesser General Public License for more details.
   *
   *      You should have received a copy of the GNU Lesser General Public
   *      License along with this library in the file COPYING.LIB;
   *      if not, write to the Free Software Foundation, Inc.,
   *      59 Temple Place - Suite 330, Boston, MA 02111-1307, USA
   */



   /*
	* The functions ptw32_pop_cleanup and ptw32_push_cleanup
	* are implemented here for applications written in C with no
	* SEH or C++ destructor support.
	*/

ptw32_cleanup_t *
ptw32_pop_cleanup(int execute)
/*
 * ------------------------------------------------------
 * DOCPUBLIC
 *      This function pops the most recently pushed cleanup
 *      handler. If execute is nonzero, then the cleanup handler
 *      is executed if non-null.
 *
 * PARAMETERS
 *      execute
 *              if nonzero, execute the cleanup handler
 *
 *
 * DESCRIPTION
 *      This function pops the most recently pushed cleanup
 *      handler. If execute is nonzero, then the cleanup handler
 *      is executed if non-null.
 *      NOTE: specify 'execute' as nonzero to avoid duplication
 *                of common cleanup code.
 *
 * RESULTS
 *              N/A
 *
 * ------------------------------------------------------
 */
{
	ptw32_cleanup_t *cleanup;

	cleanup = (ptw32_cleanup_t *)pthread_getspecific(ptw32_cleanupKey);

	if (cleanup != NULL)
	{
		if (execute && (cleanup->routine != NULL))
		{

			(*cleanup->routine) (cleanup->arg);

		}

		pthread_setspecific(ptw32_cleanupKey, (void *)cleanup->prev);

	}

	return (cleanup);

}				/* ptw32_pop_cleanup */


void
ptw32_push_cleanup(ptw32_cleanup_t * cleanup,
	ptw32_cleanup_callback_t routine, void *arg)
	/*
	 * ------------------------------------------------------
	 * DOCPUBLIC
	 *      This function pushes a new cleanup handler onto the thread's stack
	 *      of cleanup handlers. Each cleanup handler pushed onto the stack is
	 *      popped and invoked with the argument 'arg' when
	 *              a) the thread exits by calling 'pthread_exit',
	 *              b) when the thread acts on a cancellation request,
	 *              c) or when the thread calls pthread_cleanup_pop with a nonzero
	 *                 'execute' argument
	 *
	 * PARAMETERS
	 *      cleanup
	 *              a pointer to an instance of pthread_cleanup_t,
	 *
	 *      routine
	 *              pointer to a cleanup handler,
	 *
	 *      arg
	 *              parameter to be passed to the cleanup handler
	 *
	 *
	 * DESCRIPTION
	 *      This function pushes a new cleanup handler onto the thread's stack
	 *      of cleanup handlers. Each cleanup handler pushed onto the stack is
	 *      popped and invoked with the argument 'arg' when
	 *              a) the thread exits by calling 'pthread_exit',
	 *              b) when the thread acts on a cancellation request,
	 *              c) or when the thrad calls pthread_cleanup_pop with a nonzero
	 *                 'execute' argument
	 *      NOTE: pthread_push_cleanup, ptw32_pop_cleanup must be paired
	 *                in the same lexical scope.
	 *
	 * RESULTS
	 *              pthread_cleanup_t *
	 *                              pointer to the previous cleanup
	 *
	 * ------------------------------------------------------
	 */
{
	cleanup->routine = routine;
	cleanup->arg = arg;

	cleanup->prev = (ptw32_cleanup_t *)pthread_getspecific(ptw32_cleanupKey);

	pthread_setspecific(ptw32_cleanupKey, (void *)cleanup);

}				/* ptw32_push_cleanup */
/*
 * condvar.c
 *
 * Description:
 * This translation unit implements condition variables and their primitives.
 *
 *
 * --------------------------------------------------------------------------
 *
 *      Pthreads-win32 - POSIX Threads Library for Win32
 *      Copyright(C) 1998 John E. Bossom
 *      Copyright(C) 1999,2005 Pthreads-win32 contributors
 *
 *      Contact Email: rpj@callisto.canberra.edu.au
 *
 *      The current list of contributors is contained
 *      in the file CONTRIBUTORS included with the source
 *      code distribution. The list can also be seen at the
 *      following World Wide Web location:
 *      http://sources.redhat.com/pthreads-win32/contributors.html
 *
 *      This library is free software; you can redistribute it and/or
 *      modify it under the terms of the GNU Lesser General Public
 *      License as published by the Free Software Foundation; either
 *      version 2 of the License, or (at your option) any later version.
 *
 *      This library is distributed in the hope that it will be useful,
 *      but WITHOUT ANY WARRANTY; without even the implied warranty of
 *      MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *      Lesser General Public License for more details.
 *
 *      You should have received a copy of the GNU Lesser General Public
 *      License along with this library in the file COPYING.LIB;
 *      if not, write to the Free Software Foundation, Inc.,
 *      59 Temple Place - Suite 330, Boston, MA 02111-1307, USA
 *
 */


 /*
  * create.c
  *
  * Description:
  * This translation unit implements routines associated with spawning a new
  * thread.
  *
  * --------------------------------------------------------------------------
  *
  *      Pthreads-win32 - POSIX Threads Library for Win32
  *      Copyright(C) 1998 John E. Bossom
  *      Copyright(C) 1999,2005 Pthreads-win32 contributors
  *
  *      Contact Email: rpj@callisto.canberra.edu.au
  *
  *      The current list of contributors is contained
  *      in the file CONTRIBUTORS included with the source
  *      code distribution. The list can also be seen at the
  *      following World Wide Web location:
  *      http://sources.redhat.com/pthreads-win32/contributors.html
  *
  *      This library is free software; you can redistribute it and/or
  *      modify it under the terms of the GNU Lesser General Public
  *      License as published by the Free Software Foundation; either
  *      version 2 of the License, or (at your option) any later version.
  *
  *      This library is distributed in the hope that it will be useful,
  *      but WITHOUT ANY WARRANTY; without even the implied warranty of
  *      MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
  *      Lesser General Public License for more details.
  *
  *      You should have received a copy of the GNU Lesser General Public
  *      License along with this library in the file COPYING.LIB;
  *      if not, write to the Free Software Foundation, Inc.,
  *      59 Temple Place - Suite 330, Boston, MA 02111-1307, USA
  */

#if ! defined(_UWIN) && ! defined(WINCE)
#endif

int
pthread_create(pthread_t * tid,
	const pthread_attr_t * attr,
	void *(PTW32_CDECL *start) (void *), void *arg)
	/*
	 * ------------------------------------------------------
	 * DOCPUBLIC
	 *      This function creates a thread running the start function,
	 *      passing it the parameter value, 'arg'. The 'attr'
	 *      argument specifies optional creation attributes.
	 *      The identity of the new thread is returned
	 *      via 'tid', which should not be NULL.
	 *
	 * PARAMETERS
	 *      tid
	 *              pointer to an instance of pthread_t
	 *
	 *      attr
	 *              optional pointer to an instance of pthread_attr_t
	 *
	 *      start
	 *              pointer to the starting routine for the new thread
	 *
	 *      arg
	 *              optional parameter passed to 'start'
	 *
	 *
	 * DESCRIPTION
	 *      This function creates a thread running the start function,
	 *      passing it the parameter value, 'arg'. The 'attr'
	 *      argument specifies optional creation attributes.
	 *      The identity of the new thread is returned
	 *      via 'tid', which should not be the NULL pointer.
	 *
	 * RESULTS
	 *              0               successfully created thread,
	 *              EINVAL          attr invalid,
	 *              EAGAIN          insufficient resources.
	 *
	 * ------------------------------------------------------
	 */
{
	pthread_t thread;
	ptw32_thread_t * tp;
	register pthread_attr_t a;
	HANDLE threadH = 0;
	int result = EAGAIN;
	int run = PTW32_TRUE;
	ThreadParms *parms = NULL;
	unsigned int stackSize;
	int priority;
	pthread_t self;

	/*
	 * Before doing anything, check that tid can be stored through
	 * without invoking a memory protection error (segfault).
	 * Make sure that the assignment below can't be optimised out by the compiler.
	 * This is assured by conditionally assigning *tid again at the end.
	 */
	tid->x = 0;

	if (attr != NULL)
	{
		a = *attr;
	}
	else
	{
		a = NULL;
	}

	if ((thread = ptw32_new()).p == NULL)
	{
		goto FAIL0;
	}

	tp = (ptw32_thread_t *)thread.p;

	priority = tp->sched_priority;

	if ((parms = (ThreadParms *)malloc(sizeof(*parms))) == NULL)
	{
		goto FAIL0;
	}

	parms->tid = thread;
	parms->start = start;
	parms->arg = arg;

#if defined(HAVE_SIGSET_T)

	/*
	 * Threads inherit their initial sigmask from their creator thread.
	 */
	self = pthread_self();
	tp->sigmask = ((ptw32_thread_t *)self.p)->sigmask;

#endif /* HAVE_SIGSET_T */


	if (a != NULL)
	{
		stackSize = (unsigned int)a->stacksize;
		tp->detachState = a->detachstate;
		priority = a->param.sched_priority;

#if (THREAD_PRIORITY_LOWEST > THREAD_PRIORITY_NORMAL)
		/* WinCE */
#else
		/* Everything else */

		/*
		 * Thread priority must be set to a valid system level
		 * without altering the value set by pthread_attr_setschedparam().
		 */

		 /*
		  * PTHREAD_EXPLICIT_SCHED is the default because Win32 threads
		  * don't inherit their creator's priority. They are started with
		  * THREAD_PRIORITY_NORMAL (win32 value). The result of not supplying
		  * an 'attr' arg to pthread_create() is equivalent to defaulting to
		  * PTHREAD_EXPLICIT_SCHED and priority THREAD_PRIORITY_NORMAL.
		  */
		if (PTHREAD_INHERIT_SCHED == a->inheritsched)
		{
			/*
			 * If the thread that called pthread_create() is a Win32 thread
			 * then the inherited priority could be the result of a temporary
			 * system adjustment. This is not the case for POSIX threads.
			 */
#if ! defined(HAVE_SIGSET_T)
			self = pthread_self();
#endif
			priority = ((ptw32_thread_t *)self.p)->sched_priority;
		}

#endif

	}
	else
	{
		/*
		 * Default stackSize
		 */
		stackSize = PTHREAD_STACK_MIN;
	}

	tp->state = run ? PThreadStateInitial : PThreadStateSuspended;

	tp->keys = NULL;

	/*
	 * Threads must be started in suspended mode and resumed if necessary
	 * after _beginthreadex returns us the handle. Otherwise we set up a
	 * race condition between the creating and the created threads.
	 * Note that we also retain a local copy of the handle for use
	 * by us in case thread.p->threadH gets NULLed later but before we've
	 * finished with it here.
	 */

#if ! (defined (__MINGW64__) || defined(__MINGW32__)) || defined (__MSVCRT__) || defined (__DMC__) 

	tp->threadH =
		threadH =
		(HANDLE)_beginthreadex((void *)NULL,	/* No security info             */
			stackSize,		/* default stack size   */
			ptw32_threadStart,
			parms,
			(unsigned)
			CREATE_SUSPENDED,
			(unsigned *) &(tp->thread));

	if (threadH != 0)
	{
		if (a != NULL)
		{
			(void)ptw32_setthreadpriority(thread, SCHED_OTHER, priority);
		}

		if (run)
		{
			ResumeThread(threadH);
		}
	}

#else

	{
		ptw32_mcs_local_node_t stateLock;

		/*
		 * This lock will force pthread_threadStart() to wait until we have
		 * the thread handle and have set the priority.
		 */
		ptw32_mcs_lock_acquire(&tp->stateLock, &stateLock);

		tp->threadH =
			threadH =
			(HANDLE)_beginthread(ptw32_threadStart, stackSize,	/* default stack size   */
				parms);

		/*
		 * Make the return code match _beginthreadex's.
		 */
		if (threadH == (HANDLE)-1L)
		{
			tp->threadH = threadH = 0;
		}
		else
		{
			if (!run)
			{
				/*
				 * beginthread does not allow for create flags, so we do it now.
				 * Note that beginthread itself creates the thread in SUSPENDED
				 * mode, and then calls ResumeThread to start it.
				 */
				SuspendThread(threadH);
			}

			if (a != NULL)
			{
				(void)ptw32_setthreadpriority(thread, SCHED_OTHER, priority);
			}
		}

		ptw32_mcs_lock_release(&stateLock);
	}
#endif

	result = (threadH != 0) ? 0 : EAGAIN;

	/*
	 * Fall Through Intentionally
	 */

	 /*
	  * ------------
	  * Failure Code
	  * ------------
	  */

FAIL0:
	if (result != 0)
	{

		ptw32_threadDestroy(thread);
		tp = NULL;

		if (parms != NULL)
		{
			free(parms);
		}
	}
	else
	{
		*tid = thread;
	}

#if defined(_UWIN)
	if (result == 0)
		pthread_count++;
#endif
	return (result);

}				/* pthread_create */
/*
 * dll.c
 *
 * Description:
 * This translation unit implements DLL initialisation.
 *
 * --------------------------------------------------------------------------
 *
 *      Pthreads-win32 - POSIX Threads Library for Win32
 *      Copyright(C) 1998 John E. Bossom
 *      Copyright(C) 1999,2005 Pthreads-win32 contributors
 *
 *      Contact Email: rpj@callisto.canberra.edu.au
 *
 *      The current list of contributors is contained
 *      in the file CONTRIBUTORS included with the source
 *      code distribution. The list can also be seen at the
 *      following World Wide Web location:
 *      http://sources.redhat.com/pthreads-win32/contributors.html
 *
 *      This library is free software; you can redistribute it and/or
 *      modify it under the terms of the GNU Lesser General Public
 *      License as published by the Free Software Foundation; either
 *      version 2 of the License, or (at your option) any later version.
 *
 *      This library is distributed in the hope that it will be useful,
 *      but WITHOUT ANY WARRANTY; without even the implied warranty of
 *      MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *      Lesser General Public License for more details.
 *
 *      You should have received a copy of the GNU Lesser General Public
 *      License along with this library in the file COPYING.LIB;
 *      if not, write to the Free Software Foundation, Inc.,
 *      59 Temple Place - Suite 330, Boston, MA 02111-1307, USA
 */

#if !defined(PTW32_STATIC_LIB)


#if defined(_MSC_VER)
 /*
  * lpvReserved yields an unreferenced formal parameter;
  * ignore it
  */
#pragma warning( disable : 4100 )
#endif

#if defined(__cplusplus)
  /*
   * Dear c++: Please don't mangle this name. -thanks
   */
extern "C"
#endif				/* __cplusplus */
BOOL WINAPI
DllMain(HINSTANCE hinstDll, DWORD fdwReason, LPVOID lpvReserved)
{
	BOOL result = PTW32_TRUE;

	switch (fdwReason)
	{

	case DLL_PROCESS_ATTACH:
		result = pthread_win32_process_attach_np();
		break;

	case DLL_THREAD_ATTACH:
		/*
		 * A thread is being created
		 */
		result = pthread_win32_thread_attach_np();
		break;

	case DLL_THREAD_DETACH:
		/*
		 * A thread is exiting cleanly
		 */
		result = pthread_win32_thread_detach_np();
		break;

	case DLL_PROCESS_DETACH:
		(void)pthread_win32_thread_detach_np();
		result = pthread_win32_process_detach_np();
		break;
	}

	return (result);

}				/* DllMain */

#endif /* PTW32_STATIC_LIB */
/*
 * errno.c
 *
 * Description:
 * This translation unit implements routines associated with spawning a new
 * thread.
 *
 * --------------------------------------------------------------------------
 *
 *      Pthreads-win32 - POSIX Threads Library for Win32
 *      Copyright(C) 1998 John E. Bossom
 *      Copyright(C) 1999,2005 Pthreads-win32 contributors
 *
 *      Contact Email: rpj@callisto.canberra.edu.au
 *
 *      The current list of contributors is contained
 *      in the file CONTRIBUTORS included with the source
 *      code distribution. The list can also be seen at the
 *      following World Wide Web location:
 *      http://sources.redhat.com/pthreads-win32/contributors.html
 *
 *      This library is free software; you can redistribute it and/or
 *      modify it under the terms of the GNU Lesser General Public
 *      License as published by the Free Software Foundation; either
 *      version 2 of the License, or (at your option) any later version.
 *
 *      This library is distributed in the hope that it will be useful,
 *      but WITHOUT ANY WARRANTY; without even the implied warranty of
 *      MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *      Lesser General Public License for more details.
 *
 *      You should have received a copy of the GNU Lesser General Public
 *      License along with this library in the file COPYING.LIB;
 *      if not, write to the Free Software Foundation, Inc.,
 *      59 Temple Place - Suite 330, Boston, MA 02111-1307, USA
 */

#if defined(NEED_ERRNO)


static int reallyBad = ENOMEM;

/*
 * Re-entrant errno.
 *
 * Each thread has it's own errno variable in pthread_t.
 *
 * The benefit of using the pthread_t structure
 * instead of another TSD key is TSD keys are limited
 * on Win32 to 64 per process. Secondly, to implement
 * it properly without using pthread_t you'd need
 * to dynamically allocate an int on starting the thread
 * and store it manually into TLS and then ensure that you free
 * it on thread termination. We get all that for free
 * by simply storing the errno on the pthread_t structure.
 *
 * MSVC and Mingw32 already have their own thread-safe errno.
 *
 * #if defined( _REENTRANT ) || defined( _MT )
 * #define errno *_errno()
 *
 * int *_errno( void );
 * #else
 * extern int errno;
 * #endif
 *
 */

int *
_errno(void)
{
	pthread_t self;
	int *result;

	if ((self = pthread_self()).p == NULL)
	{
		/*
		 * Yikes! unable to allocate a thread!
		 * Throw an exception? return an error?
		 */
		result = &reallyBad;
	}
	else
	{
		result = (int *)(&self.p->exitStatus);
	}

	return (result);

}				/* _errno */

#endif /* (NEED_ERRNO) */
/*
 * exit.c
 *
 * Description:
 * This translation unit implements routines associated with exiting from
 * a thread.
 *
 * --------------------------------------------------------------------------
 *
 *      Pthreads-win32 - POSIX Threads Library for Win32
 *      Copyright(C) 1998 John E. Bossom
 *      Copyright(C) 1999,2005 Pthreads-win32 contributors
 *
 *      Contact Email: rpj@callisto.canberra.edu.au
 *
 *      The current list of contributors is contained
 *      in the file CONTRIBUTORS included with the source
 *      code distribution. The list can also be seen at the
 *      following World Wide Web location:
 *      http://sources.redhat.com/pthreads-win32/contributors.html
 *
 *      This library is free software; you can redistribute it and/or
 *      modify it under the terms of the GNU Lesser General Public
 *      License as published by the Free Software Foundation; either
 *      version 2 of the License, or (at your option) any later version.
 *
 *      This library is distributed in the hope that it will be useful,
 *      but WITHOUT ANY WARRANTY; without even the implied warranty of
 *      MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *      Lesser General Public License for more details.
 *
 *      You should have received a copy of the GNU Lesser General Public
 *      License along with this library in the file COPYING.LIB;
 *      if not, write to the Free Software Foundation, Inc.,
 *      59 Temple Place - Suite 330, Boston, MA 02111-1307, USA
 */

#if ! defined(_UWIN) && ! defined(WINCE)
#   include <process.h>
#endif

 /*
  * fork.c
  *
  * Description:
  * Implementation of fork() for POSIX threads.
  *
  * --------------------------------------------------------------------------
  *
  *      Pthreads-win32 - POSIX Threads Library for Win32
  *      Copyright(C) 1998 John E. Bossom
  *      Copyright(C) 1999,2005 Pthreads-win32 contributors
  *
  *      Contact Email: rpj@callisto.canberra.edu.au
  *
  *      The current list of contributors is contained
  *      in the file CONTRIBUTORS included with the source
  *      code distribution. The list can also be seen at the
  *      following World Wide Web location:
  *      http://sources.redhat.com/pthreads-win32/contributors.html
  *
  *      This library is free software; you can redistribute it and/or
  *      modify it under the terms of the GNU Lesser General Public
  *      License as published by the Free Software Foundation; either
  *      version 2 of the License, or (at your option) any later version.
  *
  *      This library is distributed in the hope that it will be useful,
  *      but WITHOUT ANY WARRANTY; without even the implied warranty of
  *      MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
  *      Lesser General Public License for more details.
  *
  *      You should have received a copy of the GNU Lesser General Public
  *      License along with this library in the file COPYING.LIB;
  *      if not, write to the Free Software Foundation, Inc.,
  *      59 Temple Place - Suite 330, Boston, MA 02111-1307, USA
  */


  /*
   * global.c
   *
   * Description:
   * This translation unit instantiates data associated with the implementation
   * as a whole.
   *
   * --------------------------------------------------------------------------
   *
   *      Pthreads-win32 - POSIX Threads Library for Win32
   *      Copyright(C) 1998 John E. Bossom
   *      Copyright(C) 1999,2005 Pthreads-win32 contributors
   *
   *      Contact Email: rpj@callisto.canberra.edu.au
   *
   *      The current list of contributors is contained
   *      in the file CONTRIBUTORS included with the source
   *      code distribution. The list can also be seen at the
   *      following World Wide Web location:
   *      http://sources.redhat.com/pthreads-win32/contributors.html
   *
   *      This library is free software; you can redistribute it and/or
   *      modify it under the terms of the GNU Lesser General Public
   *      License as published by the Free Software Foundation; either
   *      version 2 of the License, or (at your option) any later version.
   *
   *      This library is distributed in the hope that it will be useful,
   *      but WITHOUT ANY WARRANTY; without even the implied warranty of
   *      MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   *      Lesser General Public License for more details.
   *
   *      You should have received a copy of the GNU Lesser General Public
   *      License along with this library in the file COPYING.LIB;
   *      if not, write to the Free Software Foundation, Inc.,
   *      59 Temple Place - Suite 330, Boston, MA 02111-1307, USA
   */



int ptw32_processInitialized = PTW32_FALSE;
ptw32_thread_t * ptw32_threadReuseTop = PTW32_THREAD_REUSE_EMPTY;
ptw32_thread_t * ptw32_threadReuseBottom = PTW32_THREAD_REUSE_EMPTY;
pthread_key_t ptw32_selfThreadKey = NULL;
pthread_key_t ptw32_cleanupKey = NULL;
pthread_cond_t ptw32_cond_list_head = NULL;
pthread_cond_t ptw32_cond_list_tail = NULL;

int ptw32_concurrency = 0;

/* What features have been auto-detected */
int ptw32_features = 0;

/*
 * Global [process wide] thread sequence Number
 */
unsigned __int64 ptw32_threadSeqNumber = 0;

/*
 * Function pointer to QueueUserAPCEx if it exists, otherwise
 * it will be set at runtime to a substitute routine which cannot unblock
 * blocked threads.
 */
DWORD(*ptw32_register_cancelation) (PAPCFUNC, HANDLE, DWORD) = NULL;

/*
 * Global lock for managing pthread_t struct reuse.
 */
ptw32_mcs_lock_t ptw32_thread_reuse_lock = 0;

/*
 * Global lock for testing internal state of statically declared mutexes.
 */
ptw32_mcs_lock_t ptw32_mutex_test_init_lock = 0;

/*
 * Global lock for testing internal state of PTHREAD_COND_INITIALIZER
 * created condition variables.
 */
ptw32_mcs_lock_t ptw32_cond_test_init_lock = 0;

/*
 * Global lock for testing internal state of PTHREAD_RWLOCK_INITIALIZER
 * created read/write locks.
 */
ptw32_mcs_lock_t ptw32_rwlock_test_init_lock = 0;

/*
 * Global lock for testing internal state of PTHREAD_SPINLOCK_INITIALIZER
 * created spin locks.
 */
ptw32_mcs_lock_t ptw32_spinlock_test_init_lock = 0;

/*
 * Global lock for condition variable linked list. The list exists
 * to wake up CVs when a WM_TIMECHANGE message arrives. See
 * w32_TimeChangeHandler.c.
 */
ptw32_mcs_lock_t ptw32_cond_list_lock = 0;

#if defined(_UWIN)
/*
 * Keep a count of the number of threads.
 */
int pthread_count = 0;
#endif
/*
 * misc.c
 *
 * Description:
 * This translation unit implements miscellaneous thread functions.
 *
 * --------------------------------------------------------------------------
 *
 *      Pthreads-win32 - POSIX Threads Library for Win32
 *      Copyright(C) 1998 John E. Bossom
 *      Copyright(C) 1999,2005 Pthreads-win32 contributors
 *
 *      Contact Email: rpj@callisto.canberra.edu.au
 *
 *      The current list of contributors is contained
 *      in the file CONTRIBUTORS included with the source
 *      code distribution. The list can also be seen at the
 *      following World Wide Web location:
 *      http://sources.redhat.com/pthreads-win32/contributors.html
 *
 *      This library is free software; you can redistribute it and/or
 *      modify it under the terms of the GNU Lesser General Public
 *      License as published by the Free Software Foundation; either
 *      version 2 of the License, or (at your option) any later version.
 *
 *      This library is distributed in the hope that it will be useful,
 *      but WITHOUT ANY WARRANTY; without even the implied warranty of
 *      MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *      Lesser General Public License for more details.
 *
 *      You should have received a copy of the GNU Lesser General Public
 *      License along with this library in the file COPYING.LIB;
 *      if not, write to the Free Software Foundation, Inc.,
 *      59 Temple Place - Suite 330, Boston, MA 02111-1307, USA
 */



 /*
  * mutex.c
  *
  * Description:
  * This translation unit implements mutual exclusion (mutex) primitives.
  *
  * --------------------------------------------------------------------------
  *
  *      Pthreads-win32 - POSIX Threads Library for Win32
  *      Copyright(C) 1998 John E. Bossom
  *      Copyright(C) 1999,2005 Pthreads-win32 contributors
  *
  *      Contact Email: rpj@callisto.canberra.edu.au
  *
  *      The current list of contributors is contained
  *      in the file CONTRIBUTORS included with the source
  *      code distribution. The list can also be seen at the
  *      following World Wide Web location:
  *      http://sources.redhat.com/pthreads-win32/contributors.html
  *
  *      This library is free software; you can redistribute it and/or
  *      modify it under the terms of the GNU Lesser General Public
  *      License as published by the Free Software Foundation; either
  *      version 2 of the License, or (at your option) any later version.
  *
  *      This library is distributed in the hope that it will be useful,
  *      but WITHOUT ANY WARRANTY; without even the implied warranty of
  *      MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
  *      Lesser General Public License for more details.
  *
  *      You should have received a copy of the GNU Lesser General Public
  *      License along with this library in the file COPYING.LIB;
  *      if not, write to the Free Software Foundation, Inc.,
  *      59 Temple Place - Suite 330, Boston, MA 02111-1307, USA
  */

#if ! defined(_UWIN) && ! defined(WINCE)
#   include <process.h>
#endif
#if !defined(NEED_FTIME)
#endif


  /*
   * nonportable.c
   *
   * Description:
   * This translation unit implements non-portable thread functions.
   *
   * --------------------------------------------------------------------------
   *
   *      Pthreads-win32 - POSIX Threads Library for Win32
   *      Copyright(C) 1998 John E. Bossom
   *      Copyright(C) 1999,2005 Pthreads-win32 contributors
   *
   *      Contact Email: rpj@callisto.canberra.edu.au
   *
   *      The current list of contributors is contained
   *      in the file CONTRIBUTORS included with the source
   *      code distribution. The list can also be seen at the
   *      following World Wide Web location:
   *      http://sources.redhat.com/pthreads-win32/contributors.html
   *
   *      This library is free software; you can redistribute it and/or
   *      modify it under the terms of the GNU Lesser General Public
   *      License as published by the Free Software Foundation; either
   *      version 2 of the License, or (at your option) any later version.
   *
   *      This library is distributed in the hope that it will be useful,
   *      but WITHOUT ANY WARRANTY; without even the implied warranty of
   *      MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   *      Lesser General Public License for more details.
   *
   *      You should have received a copy of the GNU Lesser General Public
   *      License along with this library in the file COPYING.LIB;
   *      if not, write to the Free Software Foundation, Inc.,
   *      59 Temple Place - Suite 330, Boston, MA 02111-1307, USA
   */


   /*
	* private.c
	*
	* Description:
	* This translation unit implements routines which are private to
	* the implementation and may be used throughout it.
	*
	* --------------------------------------------------------------------------
	*
	*      Pthreads-win32 - POSIX Threads Library for Win32
	*      Copyright(C) 1998 John E. Bossom
	*      Copyright(C) 1999,2005 Pthreads-win32 contributors
	*
	*      Contact Email: rpj@callisto.canberra.edu.au
	*
	*      The current list of contributors is contained
	*      in the file CONTRIBUTORS included with the source
	*      code distribution. The list can also be seen at the
	*      following World Wide Web location:
	*      http://sources.redhat.com/pthreads-win32/contributors.html
	*
	*      This library is free software; you can redistribute it and/or
	*      modify it under the terms of the GNU Lesser General Public
	*      License as published by the Free Software Foundation; either
	*      version 2 of the License, or (at your option) any later version.
	*
	*      This library is distributed in the hope that it will be useful,
	*      but WITHOUT ANY WARRANTY; without even the implied warranty of
	*      MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
	*      Lesser General Public License for more details.
	*
	*      You should have received a copy of the GNU Lesser General Public
	*      License along with this library in the file COPYING.LIB;
	*      if not, write to the Free Software Foundation, Inc.,
	*      59 Temple Place - Suite 330, Boston, MA 02111-1307, USA
	*/


	/*
	 * pthread.c
	 *
	 * Description:
	 * This translation unit agregates pthreads-win32 translation units.
	 * It is used for inline optimisation of the library,
	 * maximising for speed at the expense of size.
	 *
	 * --------------------------------------------------------------------------
	 *
	 *      Pthreads-win32 - POSIX Threads Library for Win32
	 *      Copyright(C) 1998 John E. Bossom
	 *      Copyright(C) 1999,2005 Pthreads-win32 contributors
	 *
	 *      Contact Email: rpj@callisto.canberra.edu.au
	 *
	 *      The current list of contributors is contained
	 *      in the file CONTRIBUTORS included with the source
	 *      code distribution. The list can also be seen at the
	 *      following World Wide Web location:
	 *      http://sources.redhat.com/pthreads-win32/contributors.html
	 *
	 *      This library is free software; you can redistribute it and/or
	 *      modify it under the terms of the GNU Lesser General Public
	 *      License as published by the Free Software Foundation; either
	 *      version 2 of the License, or (at your option) any later version.
	 *
	 *      This library is distributed in the hope that it will be useful,
	 *      but WITHOUT ANY WARRANTY; without even the implied warranty of
	 *      MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
	 *      Lesser General Public License for more details.
	 *
	 *      You should have received a copy of the GNU Lesser General Public
	 *      License along with this library in the file COPYING.LIB;
	 *      if not, write to the Free Software Foundation, Inc.,
	 *      59 Temple Place - Suite 330, Boston, MA 02111-1307, USA
	 */


	 /* The following are ordered for inlining */

	 /*
	  * pthread_attr_destroy.c
	  *
	  * Description:
	  * This translation unit implements operations on thread attribute objects.
	  *
	  * --------------------------------------------------------------------------
	  *
	  *      Pthreads-win32 - POSIX Threads Library for Win32
	  *      Copyright(C) 1998 John E. Bossom
	  *      Copyright(C) 1999,2005 Pthreads-win32 contributors
	  *
	  *      Contact Email: rpj@callisto.canberra.edu.au
	  *
	  *      The current list of contributors is contained
	  *      in the file CONTRIBUTORS included with the source
	  *      code distribution. The list can also be seen at the
	  *      following World Wide Web location:
	  *      http://sources.redhat.com/pthreads-win32/contributors.html
	  *
	  *      This library is free software; you can redistribute it and/or
	  *      modify it under the terms of the GNU Lesser General Public
	  *      License as published by the Free Software Foundation; either
	  *      version 2 of the License, or (at your option) any later version.
	  *
	  *      This library is distributed in the hope that it will be useful,
	  *      but WITHOUT ANY WARRANTY; without even the implied warranty of
	  *      MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
	  *      Lesser General Public License for more details.
	  *
	  *      You should have received a copy of the GNU Lesser General Public
	  *      License along with this library in the file COPYING.LIB;
	  *      if not, write to the Free Software Foundation, Inc.,
	  *      59 Temple Place - Suite 330, Boston, MA 02111-1307, USA
	  */



int
pthread_attr_destroy(pthread_attr_t * attr)
/*
 * ------------------------------------------------------
 * DOCPUBLIC
 *      Destroys a thread attributes object.
 *
 * PARAMETERS
 *      attr
 *              pointer to an instance of pthread_attr_t
 *
 *
 * DESCRIPTION
 *      Destroys a thread attributes object.
 *
 *      NOTES:
 *              1)      Does not affect threads created with 'attr'.
 *
 * RESULTS
 *              0               successfully destroyed attr,
 *              EINVAL          'attr' is invalid.
 *
 * ------------------------------------------------------
 */
{
	if (ptw32_is_attr(attr) != 0)
	{
		return EINVAL;
	}

	/*
	 * Set the attribute object to a specific invalid value.
	 */
	(*attr)->valid = 0;
	free(*attr);
	*attr = NULL;

	return 0;
}
/*
 * pthread_attr_getdetachstate.c
 *
 * Description:
 * This translation unit implements operations on thread attribute objects.
 *
 * --------------------------------------------------------------------------
 *
 *      Pthreads-win32 - POSIX Threads Library for Win32
 *      Copyright(C) 1998 John E. Bossom
 *      Copyright(C) 1999,2005 Pthreads-win32 contributors
 *
 *      Contact Email: rpj@callisto.canberra.edu.au
 *
 *      The current list of contributors is contained
 *      in the file CONTRIBUTORS included with the source
 *      code distribution. The list can also be seen at the
 *      following World Wide Web location:
 *      http://sources.redhat.com/pthreads-win32/contributors.html
 *
 *      This library is free software; you can redistribute it and/or
 *      modify it under the terms of the GNU Lesser General Public
 *      License as published by the Free Software Foundation; either
 *      version 2 of the License, or (at your option) any later version.
 *
 *      This library is distributed in the hope that it will be useful,
 *      but WITHOUT ANY WARRANTY; without even the implied warranty of
 *      MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *      Lesser General Public License for more details.
 *
 *      You should have received a copy of the GNU Lesser General Public
 *      License along with this library in the file COPYING.LIB;
 *      if not, write to the Free Software Foundation, Inc.,
 *      59 Temple Place - Suite 330, Boston, MA 02111-1307, USA
 */



int
pthread_attr_getdetachstate(const pthread_attr_t * attr, int *detachstate)
/*
 * ------------------------------------------------------
 * DOCPUBLIC
 *      This function determines whether threads created with
 *      'attr' will run detached.
 *
 * PARAMETERS
 *      attr
 *              pointer to an instance of pthread_attr_t
 *
 *      detachstate
 *              pointer to an integer into which is returned one
 *              of:
 *
 *              PTHREAD_CREATE_JOINABLE
 *                              Thread ID is valid, must be joined
 *
 *              PTHREAD_CREATE_DETACHED
 *                              Thread ID is invalid, cannot be joined,
 *                              canceled, or modified
 *
 *
 * DESCRIPTION
 *      This function determines whether threads created with
 *      'attr' will run detached.
 *
 *      NOTES:
 *              1)      You cannot join or cancel detached threads.
 *
 * RESULTS
 *              0               successfully retrieved detach state,
 *              EINVAL          'attr' is invalid
 *
 * ------------------------------------------------------
 */
{
	if (ptw32_is_attr(attr) != 0 || detachstate == NULL)
	{
		return EINVAL;
	}

	*detachstate = (*attr)->detachstate;
	return 0;
}
/*
 * pthread_attr_getinheritsched.c
 *
 * Description:
 * POSIX thread functions that deal with thread scheduling.
 *
 * --------------------------------------------------------------------------
 *
 *      Pthreads-win32 - POSIX Threads Library for Win32
 *      Copyright(C) 1998 John E. Bossom
 *      Copyright(C) 1999,2005 Pthreads-win32 contributors
 *
 *      Contact Email: rpj@callisto.canberra.edu.au
 *
 *      The current list of contributors is contained
 *      in the file CONTRIBUTORS included with the source
 *      code distribution. The list can also be seen at the
 *      following World Wide Web location:
 *      http://sources.redhat.com/pthreads-win32/contributors.html
 *
 *      This library is free software; you can redistribute it and/or
 *      modify it under the terms of the GNU Lesser General Public
 *      License as published by the Free Software Foundation; either
 *      version 2 of the License, or (at your option) any later version.
 *
 *      This library is distributed in the hope that it will be useful,
 *      but WITHOUT ANY WARRANTY; without even the implied warranty of
 *      MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *      Lesser General Public License for more details.
 *
 *      You should have received a copy of the GNU Lesser General Public
 *      License along with this library in the file COPYING.LIB;
 *      if not, write to the Free Software Foundation, Inc.,
 *      59 Temple Place - Suite 330, Boston, MA 02111-1307, USA
 */


int
pthread_attr_getinheritsched(const pthread_attr_t * attr, int *inheritsched)
{
	if (ptw32_is_attr(attr) != 0 || inheritsched == NULL)
	{
		return EINVAL;
	}

	*inheritsched = (*attr)->inheritsched;
	return 0;
}
/*
 * pthread_attr_getschedparam.c
 *
 * Description:
 * POSIX thread functions that deal with thread scheduling.
 *
 * --------------------------------------------------------------------------
 *
 *      Pthreads-win32 - POSIX Threads Library for Win32
 *      Copyright(C) 1998 John E. Bossom
 *      Copyright(C) 1999,2005 Pthreads-win32 contributors
 *
 *      Contact Email: rpj@callisto.canberra.edu.au
 *
 *      The current list of contributors is contained
 *      in the file CONTRIBUTORS included with the source
 *      code distribution. The list can also be seen at the
 *      following World Wide Web location:
 *      http://sources.redhat.com/pthreads-win32/contributors.html
 *
 *      This library is free software; you can redistribute it and/or
 *      modify it under the terms of the GNU Lesser General Public
 *      License as published by the Free Software Foundation; either
 *      version 2 of the License, or (at your option) any later version.
 *
 *      This library is distributed in the hope that it will be useful,
 *      but WITHOUT ANY WARRANTY; without even the implied warranty of
 *      MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *      Lesser General Public License for more details.
 *
 *      You should have received a copy of the GNU Lesser General Public
 *      License along with this library in the file COPYING.LIB;
 *      if not, write to the Free Software Foundation, Inc.,
 *      59 Temple Place - Suite 330, Boston, MA 02111-1307, USA
 */


int
pthread_attr_getschedparam(const pthread_attr_t * attr,
	struct sched_param *param)
{
	if (ptw32_is_attr(attr) != 0 || param == NULL)
	{
		return EINVAL;
	}

	memcpy(param, &(*attr)->param, sizeof(*param));
	return 0;
}
/*
 * pthread_attr_getschedpolicy.c
 *
 * Description:
 * POSIX thread functions that deal with thread scheduling.
 *
 * --------------------------------------------------------------------------
 *
 *      Pthreads-win32 - POSIX Threads Library for Win32
 *      Copyright(C) 1998 John E. Bossom
 *      Copyright(C) 1999,2005 Pthreads-win32 contributors
 *
 *      Contact Email: rpj@callisto.canberra.edu.au
 *
 *      The current list of contributors is contained
 *      in the file CONTRIBUTORS included with the source
 *      code distribution. The list can also be seen at the
 *      following World Wide Web location:
 *      http://sources.redhat.com/pthreads-win32/contributors.html
 *
 *      This library is free software; you can redistribute it and/or
 *      modify it under the terms of the GNU Lesser General Public
 *      License as published by the Free Software Foundation; either
 *      version 2 of the License, or (at your option) any later version.
 *
 *      This library is distributed in the hope that it will be useful,
 *      but WITHOUT ANY WARRANTY; without even the implied warranty of
 *      MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *      Lesser General Public License for more details.
 *
 *      You should have received a copy of the GNU Lesser General Public
 *      License along with this library in the file COPYING.LIB;
 *      if not, write to the Free Software Foundation, Inc.,
 *      59 Temple Place - Suite 330, Boston, MA 02111-1307, USA
 */


int
pthread_attr_getschedpolicy(const pthread_attr_t * attr, int *policy)
{
	if (ptw32_is_attr(attr) != 0 || policy == NULL)
	{
		return EINVAL;
	}

	/*
	 * Validate the policy arg.
	 * Check that a policy constant wasn't passed rather than &policy.
	 */
	if (policy <= (int *)SCHED_MAX)
	{
		return EINVAL;
	}

	*policy = SCHED_OTHER;

	return 0;
}
/*
 * pthread_attr_getscope.c
 *
 * Description:
 * This translation unit implements operations on thread attribute objects.
 *
 * --------------------------------------------------------------------------
 *
 *      Pthreads-win32 - POSIX Threads Library for Win32
 *      Copyright(C) 1998 John E. Bossom
 *      Copyright(C) 1999,2005 Pthreads-win32 contributors
 *
 *      Contact Email: rpj@callisto.canberra.edu.au
 *
 *      The current list of contributors is contained
 *      in the file CONTRIBUTORS included with the source
 *      code distribution. The list can also be seen at the
 *      following World Wide Web location:
 *      http://sources.redhat.com/pthreads-win32/contributors.html
 *
 *      This library is free software; you can redistribute it and/or
 *      modify it under the terms of the GNU Lesser General Public
 *      License as published by the Free Software Foundation; either
 *      version 2 of the License, or (at your option) any later version.
 *
 *      This library is distributed in the hope that it will be useful,
 *      but WITHOUT ANY WARRANTY; without even the implied warranty of
 *      MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *      Lesser General Public License for more details.
 *
 *      You should have received a copy of the GNU Lesser General Public
 *      License along with this library in the file COPYING.LIB;
 *      if not, write to the Free Software Foundation, Inc.,
 *      59 Temple Place - Suite 330, Boston, MA 02111-1307, USA
 */


 /* ignore warning "unreferenced formal parameter" */
#if defined(_MSC_VER)
#pragma warning( disable : 4100 )
#endif

int
pthread_attr_getscope(const pthread_attr_t * attr, int *contentionscope)
{
#if defined(_POSIX_THREAD_PRIORITY_SCHEDULING)
	*contentionscope = (*attr)->contentionscope;
	return 0;
#else
	return ENOSYS;
#endif
}
/*
 * pthread_attr_getstackaddr.c
 *
 * Description:
 * This translation unit implements operations on thread attribute objects.
 *
 * --------------------------------------------------------------------------
 *
 *      Pthreads-win32 - POSIX Threads Library for Win32
 *      Copyright(C) 1998 John E. Bossom
 *      Copyright(C) 1999,2005 Pthreads-win32 contributors
 *
 *      Contact Email: rpj@callisto.canberra.edu.au
 *
 *      The current list of contributors is contained
 *      in the file CONTRIBUTORS included with the source
 *      code distribution. The list can also be seen at the
 *      following World Wide Web location:
 *      http://sources.redhat.com/pthreads-win32/contributors.html
 *
 *      This library is free software; you can redistribute it and/or
 *      modify it under the terms of the GNU Lesser General Public
 *      License as published by the Free Software Foundation; either
 *      version 2 of the License, or (at your option) any later version.
 *
 *      This library is distributed in the hope that it will be useful,
 *      but WITHOUT ANY WARRANTY; without even the implied warranty of
 *      MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *      Lesser General Public License for more details.
 *
 *      You should have received a copy of the GNU Lesser General Public
 *      License along with this library in the file COPYING.LIB;
 *      if not, write to the Free Software Foundation, Inc.,
 *      59 Temple Place - Suite 330, Boston, MA 02111-1307, USA
 */


 /* ignore warning "unreferenced formal parameter" */
#if defined(_MSC_VER)
#pragma warning( disable : 4100 )
#endif

int
pthread_attr_getstackaddr(const pthread_attr_t * attr, void **stackaddr)
/*
 * ------------------------------------------------------
 * DOCPUBLIC
 *      This function determines the address of the stack
 *      on which threads created with 'attr' will run.
 *
 * PARAMETERS
 *      attr
 *              pointer to an instance of pthread_attr_t
 *
 *      stackaddr
 *              pointer into which is returned the stack address.
 *
 *
 * DESCRIPTION
 *      This function determines the address of the stack
 *      on which threads created with 'attr' will run.
 *
 *      NOTES:
 *              1)      Function supported only if this macro is
 *                      defined:
 *
 *                              _POSIX_THREAD_ATTR_STACKADDR
 *
 *              2)      Create only one thread for each stack
 *                      address..
 *
 * RESULTS
 *              0               successfully retreived stack address,
 *              EINVAL          'attr' is invalid
 *              ENOSYS          function not supported
 *
 * ------------------------------------------------------
 */
{
#if defined( _POSIX_THREAD_ATTR_STACKADDR )

	if (ptw32_is_attr(attr) != 0)
	{
		return EINVAL;
	}

	*stackaddr = (*attr)->stackaddr;
	return 0;

#else

	return ENOSYS;

#endif /* _POSIX_THREAD_ATTR_STACKADDR */
}
/*
 * pthread_attr_getstacksize.c
 *
 * Description:
 * This translation unit implements operations on thread attribute objects.
 *
 * --------------------------------------------------------------------------
 *
 *      Pthreads-win32 - POSIX Threads Library for Win32
 *      Copyright(C) 1998 John E. Bossom
 *      Copyright(C) 1999,2005 Pthreads-win32 contributors
 *
 *      Contact Email: rpj@callisto.canberra.edu.au
 *
 *      The current list of contributors is contained
 *      in the file CONTRIBUTORS included with the source
 *      code distribution. The list can also be seen at the
 *      following World Wide Web location:
 *      http://sources.redhat.com/pthreads-win32/contributors.html
 *
 *      This library is free software; you can redistribute it and/or
 *      modify it under the terms of the GNU Lesser General Public
 *      License as published by the Free Software Foundation; either
 *      version 2 of the License, or (at your option) any later version.
 *
 *      This library is distributed in the hope that it will be useful,
 *      but WITHOUT ANY WARRANTY; without even the implied warranty of
 *      MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *      Lesser General Public License for more details.
 *
 *      You should have received a copy of the GNU Lesser General Public
 *      License along with this library in the file COPYING.LIB;
 *      if not, write to the Free Software Foundation, Inc.,
 *      59 Temple Place - Suite 330, Boston, MA 02111-1307, USA
 */


 /* ignore warning "unreferenced formal parameter" */
#if defined(_MSC_VER)
#pragma warning( disable : 4100 )
#endif

int
pthread_attr_getstacksize(const pthread_attr_t * attr, size_t * stacksize)
/*
 * ------------------------------------------------------
 * DOCPUBLIC
 *      This function determines the size of the stack on
 *      which threads created with 'attr' will run.
 *
 * PARAMETERS
 *      attr
 *              pointer to an instance of pthread_attr_t
 *
 *      stacksize
 *              pointer to size_t into which is returned the
 *              stack size, in bytes.
 *
 *
 * DESCRIPTION
 *      This function determines the size of the stack on
 *      which threads created with 'attr' will run.
 *
 *      NOTES:
 *              1)      Function supported only if this macro is
 *                      defined:
 *
 *                              _POSIX_THREAD_ATTR_STACKSIZE
 *
 *              2)      Use on newly created attributes object to
 *                      find the default stack size.
 *
 * RESULTS
 *              0               successfully retrieved stack size,
 *              EINVAL          'attr' is invalid
 *              ENOSYS          function not supported
 *
 * ------------------------------------------------------
 */
{
#if defined(_POSIX_THREAD_ATTR_STACKSIZE)

	if (ptw32_is_attr(attr) != 0)
	{
		return EINVAL;
	}

	/* Everything is okay. */
	*stacksize = (*attr)->stacksize;
	return 0;

#else

	return ENOSYS;

#endif /* _POSIX_THREAD_ATTR_STACKSIZE */

}
/*
 * pthread_attr_init.c
 *
 * Description:
 * This translation unit implements operations on thread attribute objects.
 *
 * --------------------------------------------------------------------------
 *
 *      Pthreads-win32 - POSIX Threads Library for Win32
 *      Copyright(C) 1998 John E. Bossom
 *      Copyright(C) 1999,2005 Pthreads-win32 contributors
 *
 *      Contact Email: rpj@callisto.canberra.edu.au
 *
 *      The current list of contributors is contained
 *      in the file CONTRIBUTORS included with the source
 *      code distribution. The list can also be seen at the
 *      following World Wide Web location:
 *      http://sources.redhat.com/pthreads-win32/contributors.html
 *
 *      This library is free software; you can redistribute it and/or
 *      modify it under the terms of the GNU Lesser General Public
 *      License as published by the Free Software Foundation; either
 *      version 2 of the License, or (at your option) any later version.
 *
 *      This library is distributed in the hope that it will be useful,
 *      but WITHOUT ANY WARRANTY; without even the implied warranty of
 *      MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *      Lesser General Public License for more details.
 *
 *      You should have received a copy of the GNU Lesser General Public
 *      License along with this library in the file COPYING.LIB;
 *      if not, write to the Free Software Foundation, Inc.,
 *      59 Temple Place - Suite 330, Boston, MA 02111-1307, USA
 */



int
pthread_attr_init(pthread_attr_t * attr)
/*
 * ------------------------------------------------------
 * DOCPUBLIC
 *      Initializes a thread attributes object with default
 *      attributes.
 *
 * PARAMETERS
 *      attr
 *              pointer to an instance of pthread_attr_t
 *
 *
 * DESCRIPTION
 *      Initializes a thread attributes object with default
 *      attributes.
 *
 *      NOTES:
 *              1)      Used to define thread attributes
 *
 * RESULTS
 *              0               successfully initialized attr,
 *              ENOMEM          insufficient memory for attr.
 *
 * ------------------------------------------------------
 */
{
	pthread_attr_t attr_result;

	if (attr == NULL)
	{
		/* This is disallowed. */
		return EINVAL;
	}

	attr_result = (pthread_attr_t)malloc(sizeof(*attr_result));

	if (attr_result == NULL)
	{
		return ENOMEM;
	}

#if defined(_POSIX_THREAD_ATTR_STACKSIZE)
	/*
	 * Default to zero size. Unless changed explicitly this
	 * will allow Win32 to set the size to that of the
	 * main thread.
	 */
	attr_result->stacksize = 0;
#endif

#if defined(_POSIX_THREAD_ATTR_STACKADDR)
	/* FIXME: Set this to something sensible when we support it. */
	attr_result->stackaddr = NULL;
#endif

	attr_result->detachstate = PTHREAD_CREATE_JOINABLE;

#if defined(HAVE_SIGSET_T)
	memset(&(attr_result->sigmask), 0, sizeof(sigset_t));
#endif /* HAVE_SIGSET_T */

	/*
	 * Win32 sets new threads to THREAD_PRIORITY_NORMAL and
	 * not to that of the parent thread. We choose to default to
	 * this arrangement.
	 */
	attr_result->param.sched_priority = THREAD_PRIORITY_NORMAL;
	attr_result->inheritsched = PTHREAD_EXPLICIT_SCHED;
	attr_result->contentionscope = PTHREAD_SCOPE_SYSTEM;

	attr_result->valid = PTW32_ATTR_VALID;

	*attr = attr_result;

	return 0;
}
/*
 * pthread_attr_setdetachstate.c
 *
 * Description:
 * This translation unit implements operations on thread attribute objects.
 *
 * --------------------------------------------------------------------------
 *
 *      Pthreads-win32 - POSIX Threads Library for Win32
 *      Copyright(C) 1998 John E. Bossom
 *      Copyright(C) 1999,2005 Pthreads-win32 contributors
 *
 *      Contact Email: rpj@callisto.canberra.edu.au
 *
 *      The current list of contributors is contained
 *      in the file CONTRIBUTORS included with the source
 *      code distribution. The list can also be seen at the
 *      following World Wide Web location:
 *      http://sources.redhat.com/pthreads-win32/contributors.html
 *
 *      This library is free software; you can redistribute it and/or
 *      modify it under the terms of the GNU Lesser General Public
 *      License as published by the Free Software Foundation; either
 *      version 2 of the License, or (at your option) any later version.
 *
 *      This library is distributed in the hope that it will be useful,
 *      but WITHOUT ANY WARRANTY; without even the implied warranty of
 *      MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *      Lesser General Public License for more details.
 *
 *      You should have received a copy of the GNU Lesser General Public
 *      License along with this library in the file COPYING.LIB;
 *      if not, write to the Free Software Foundation, Inc.,
 *      59 Temple Place - Suite 330, Boston, MA 02111-1307, USA
 */



int
pthread_attr_setdetachstate(pthread_attr_t * attr, int detachstate)
/*
 * ------------------------------------------------------
 * DOCPUBLIC
 *      This function specifies whether threads created with
 *      'attr' will run detached.
 *
 * PARAMETERS
 *      attr
 *              pointer to an instance of pthread_attr_t
 *
 *      detachstate
 *              an integer containing one of:
 *
 *              PTHREAD_CREATE_JOINABLE
 *                              Thread ID is valid, must be joined
 *
 *              PTHREAD_CREATE_DETACHED
 *                              Thread ID is invalid, cannot be joined,
 *                              canceled, or modified
 *
 *
 * DESCRIPTION
 *      This function specifies whether threads created with
 *      'attr' will run detached.
 *
 *      NOTES:
 *              1)      You cannot join or cancel detached threads.
 *
 * RESULTS
 *              0               successfully set detach state,
 *              EINVAL          'attr' or 'detachstate' is invalid
 *
 * ------------------------------------------------------
 */
{
	if (ptw32_is_attr(attr) != 0)
	{
		return EINVAL;
	}

	if (detachstate != PTHREAD_CREATE_JOINABLE &&
		detachstate != PTHREAD_CREATE_DETACHED)
	{
		return EINVAL;
	}

	(*attr)->detachstate = detachstate;
	return 0;
}
/*
 * pthread_attr_setinheritsched.c
 *
 * Description:
 * POSIX thread functions that deal with thread scheduling.
 *
 * --------------------------------------------------------------------------
 *
 *      Pthreads-win32 - POSIX Threads Library for Win32
 *      Copyright(C) 1998 John E. Bossom
 *      Copyright(C) 1999,2005 Pthreads-win32 contributors
 *
 *      Contact Email: rpj@callisto.canberra.edu.au
 *
 *      The current list of contributors is contained
 *      in the file CONTRIBUTORS included with the source
 *      code distribution. The list can also be seen at the
 *      following World Wide Web location:
 *      http://sources.redhat.com/pthreads-win32/contributors.html
 *
 *      This library is free software; you can redistribute it and/or
 *      modify it under the terms of the GNU Lesser General Public
 *      License as published by the Free Software Foundation; either
 *      version 2 of the License, or (at your option) any later version.
 *
 *      This library is distributed in the hope that it will be useful,
 *      but WITHOUT ANY WARRANTY; without even the implied warranty of
 *      MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *      Lesser General Public License for more details.
 *
 *      You should have received a copy of the GNU Lesser General Public
 *      License along with this library in the file COPYING.LIB;
 *      if not, write to the Free Software Foundation, Inc.,
 *      59 Temple Place - Suite 330, Boston, MA 02111-1307, USA
 */


int
pthread_attr_setinheritsched(pthread_attr_t * attr, int inheritsched)
{
	if (ptw32_is_attr(attr) != 0)
	{
		return EINVAL;
	}

	if (PTHREAD_INHERIT_SCHED != inheritsched
		&& PTHREAD_EXPLICIT_SCHED != inheritsched)
	{
		return EINVAL;
	}

	(*attr)->inheritsched = inheritsched;
	return 0;
}
/*
 * pthread_attr_setschedparam.c
 *
 * Description:
 * POSIX thread functions that deal with thread scheduling.
 *
 * --------------------------------------------------------------------------
 *
 *      Pthreads-win32 - POSIX Threads Library for Win32
 *      Copyright(C) 1998 John E. Bossom
 *      Copyright(C) 1999,2005 Pthreads-win32 contributors
 *
 *      Contact Email: rpj@callisto.canberra.edu.au
 *
 *      The current list of contributors is contained
 *      in the file CONTRIBUTORS included with the source
 *      code distribution. The list can also be seen at the
 *      following World Wide Web location:
 *      http://sources.redhat.com/pthreads-win32/contributors.html
 *
 *      This library is free software; you can redistribute it and/or
 *      modify it under the terms of the GNU Lesser General Public
 *      License as published by the Free Software Foundation; either
 *      version 2 of the License, or (at your option) any later version.
 *
 *      This library is distributed in the hope that it will be useful,
 *      but WITHOUT ANY WARRANTY; without even the implied warranty of
 *      MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *      Lesser General Public License for more details.
 *
 *      You should have received a copy of the GNU Lesser General Public
 *      License along with this library in the file COPYING.LIB;
 *      if not, write to the Free Software Foundation, Inc.,
 *      59 Temple Place - Suite 330, Boston, MA 02111-1307, USA
 */


int
pthread_attr_setschedparam(pthread_attr_t * attr,
	const struct sched_param *param)
{
	int priority;

	if (ptw32_is_attr(attr) != 0 || param == NULL)
	{
		return EINVAL;
	}

	priority = param->sched_priority;

	/* Validate priority level. */
	if (priority < sched_get_priority_min(SCHED_OTHER) ||
		priority > sched_get_priority_max(SCHED_OTHER))
	{
		return EINVAL;
	}

	memcpy(&(*attr)->param, param, sizeof(*param));
	return 0;
}
/*
 * pthread_attr_setschedpolicy.c
 *
 * Description:
 * POSIX thread functions that deal with thread scheduling.
 *
 * --------------------------------------------------------------------------
 *
 *      Pthreads-win32 - POSIX Threads Library for Win32
 *      Copyright(C) 1998 John E. Bossom
 *      Copyright(C) 1999,2005 Pthreads-win32 contributors
 *
 *      Contact Email: rpj@callisto.canberra.edu.au
 *
 *      The current list of contributors is contained
 *      in the file CONTRIBUTORS included with the source
 *      code distribution. The list can also be seen at the
 *      following World Wide Web location:
 *      http://sources.redhat.com/pthreads-win32/contributors.html
 *
 *      This library is free software; you can redistribute it and/or
 *      modify it under the terms of the GNU Lesser General Public
 *      License as published by the Free Software Foundation; either
 *      version 2 of the License, or (at your option) any later version.
 *
 *      This library is distributed in the hope that it will be useful,
 *      but WITHOUT ANY WARRANTY; without even the implied warranty of
 *      MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *      Lesser General Public License for more details.
 *
 *      You should have received a copy of the GNU Lesser General Public
 *      License along with this library in the file COPYING.LIB;
 *      if not, write to the Free Software Foundation, Inc.,
 *      59 Temple Place - Suite 330, Boston, MA 02111-1307, USA
 */


int
pthread_attr_setschedpolicy(pthread_attr_t * attr, int policy)
{
	if (ptw32_is_attr(attr) != 0)
	{
		return EINVAL;
	}

	if (policy != SCHED_OTHER)
	{
		return ENOTSUP;
	}

	return 0;
}
/*
 * pthread_attr_setscope.c
 *
 * Description:
 * This translation unit implements operations on thread attribute objects.
 *
 * --------------------------------------------------------------------------
 *
 *      Pthreads-win32 - POSIX Threads Library for Win32
 *      Copyright(C) 1998 John E. Bossom
 *      Copyright(C) 1999,2005 Pthreads-win32 contributors
 *
 *      Contact Email: rpj@callisto.canberra.edu.au
 *
 *      The current list of contributors is contained
 *      in the file CONTRIBUTORS included with the source
 *      code distribution. The list can also be seen at the
 *      following World Wide Web location:
 *      http://sources.redhat.com/pthreads-win32/contributors.html
 *
 *      This library is free software; you can redistribute it and/or
 *      modify it under the terms of the GNU Lesser General Public
 *      License as published by the Free Software Foundation; either
 *      version 2 of the License, or (at your option) any later version.
 *
 *      This library is distributed in the hope that it will be useful,
 *      but WITHOUT ANY WARRANTY; without even the implied warranty of
 *      MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *      Lesser General Public License for more details.
 *
 *      You should have received a copy of the GNU Lesser General Public
 *      License along with this library in the file COPYING.LIB;
 *      if not, write to the Free Software Foundation, Inc.,
 *      59 Temple Place - Suite 330, Boston, MA 02111-1307, USA
 */


 /* ignore warning "unreferenced formal parameter" */
#if defined(_MSC_VER)
#pragma warning( disable : 4100 )
#endif

int
pthread_attr_setscope(pthread_attr_t * attr, int contentionscope)
{
#if defined(_POSIX_THREAD_PRIORITY_SCHEDULING)
	switch (contentionscope)
	{
	case PTHREAD_SCOPE_SYSTEM:
		(*attr)->contentionscope = contentionscope;
		return 0;
	case PTHREAD_SCOPE_PROCESS:
		return ENOTSUP;
	default:
		return EINVAL;
	}
#else
	return ENOSYS;
#endif
}
/*
 * pthread_attr_setstackaddr.c
 *
 * Description:
 * This translation unit implements operations on thread attribute objects.
 *
 * --------------------------------------------------------------------------
 *
 *      Pthreads-win32 - POSIX Threads Library for Win32
 *      Copyright(C) 1998 John E. Bossom
 *      Copyright(C) 1999,2005 Pthreads-win32 contributors
 *
 *      Contact Email: rpj@callisto.canberra.edu.au
 *
 *      The current list of contributors is contained
 *      in the file CONTRIBUTORS included with the source
 *      code distribution. The list can also be seen at the
 *      following World Wide Web location:
 *      http://sources.redhat.com/pthreads-win32/contributors.html
 *
 *      This library is free software; you can redistribute it and/or
 *      modify it under the terms of the GNU Lesser General Public
 *      License as published by the Free Software Foundation; either
 *      version 2 of the License, or (at your option) any later version.
 *
 *      This library is distributed in the hope that it will be useful,
 *      but WITHOUT ANY WARRANTY; without even the implied warranty of
 *      MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *      Lesser General Public License for more details.
 *
 *      You should have received a copy of the GNU Lesser General Public
 *      License along with this library in the file COPYING.LIB;
 *      if not, write to the Free Software Foundation, Inc.,
 *      59 Temple Place - Suite 330, Boston, MA 02111-1307, USA
 */



int
pthread_attr_setstackaddr(pthread_attr_t * attr, void *stackaddr)
/*
 * ------------------------------------------------------
 * DOCPUBLIC
 *      Threads created with 'attr' will run on the stack
 *      starting at 'stackaddr'.
 *      Stack must be at least PTHREAD_STACK_MIN bytes.
 *
 * PARAMETERS
 *      attr
 *              pointer to an instance of pthread_attr_t
 *
 *      stackaddr
 *              the address of the stack to use
 *
 *
 * DESCRIPTION
 *      Threads created with 'attr' will run on the stack
 *      starting at 'stackaddr'.
 *      Stack must be at least PTHREAD_STACK_MIN bytes.
 *
 *      NOTES:
 *              1)      Function supported only if this macro is
 *                      defined:
 *
 *                              _POSIX_THREAD_ATTR_STACKADDR
 *
 *              2)      Create only one thread for each stack
 *                      address..
 *
 *              3)      Ensure that stackaddr is aligned.
 *
 * RESULTS
 *              0               successfully set stack address,
 *              EINVAL          'attr' is invalid
 *              ENOSYS          function not supported
 *
 * ------------------------------------------------------
 */
{
#if defined( _POSIX_THREAD_ATTR_STACKADDR )

	if (ptw32_is_attr(attr) != 0)
	{
		return EINVAL;
	}

	(*attr)->stackaddr = stackaddr;
	return 0;

#else

	return ENOSYS;

#endif /* _POSIX_THREAD_ATTR_STACKADDR */
}
/*
 * pthread_attr_setstacksize.c
 *
 * Description:
 * This translation unit implements operations on thread attribute objects.
 *
 * --------------------------------------------------------------------------
 *
 *      Pthreads-win32 - POSIX Threads Library for Win32
 *      Copyright(C) 1998 John E. Bossom
 *      Copyright(C) 1999,2005 Pthreads-win32 contributors
 *
 *      Contact Email: rpj@callisto.canberra.edu.au
 *
 *      The current list of contributors is contained
 *      in the file CONTRIBUTORS included with the source
 *      code distribution. The list can also be seen at the
 *      following World Wide Web location:
 *      http://sources.redhat.com/pthreads-win32/contributors.html
 *
 *      This library is free software; you can redistribute it and/or
 *      modify it under the terms of the GNU Lesser General Public
 *      License as published by the Free Software Foundation; either
 *      version 2 of the License, or (at your option) any later version.
 *
 *      This library is distributed in the hope that it will be useful,
 *      but WITHOUT ANY WARRANTY; without even the implied warranty of
 *      MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *      Lesser General Public License for more details.
 *
 *      You should have received a copy of the GNU Lesser General Public
 *      License along with this library in the file COPYING.LIB;
 *      if not, write to the Free Software Foundation, Inc.,
 *      59 Temple Place - Suite 330, Boston, MA 02111-1307, USA
 */



int
pthread_attr_setstacksize(pthread_attr_t * attr, size_t stacksize)
/*
 * ------------------------------------------------------
 * DOCPUBLIC
 *      This function specifies the size of the stack on
 *      which threads created with 'attr' will run.
 *
 * PARAMETERS
 *      attr
 *              pointer to an instance of pthread_attr_t
 *
 *      stacksize
 *              stack size, in bytes.
 *
 *
 * DESCRIPTION
 *      This function specifies the size of the stack on
 *      which threads created with 'attr' will run.
 *
 *      NOTES:
 *              1)      Function supported only if this macro is
 *                      defined:
 *
 *                              _POSIX_THREAD_ATTR_STACKSIZE
 *
 *              2)      Find the default first (using
 *                      pthread_attr_getstacksize), then increase
 *                      by multiplying.
 *
 *              3)      Only use if thread needs more than the
 *                      default.
 *
 * RESULTS
 *              0               successfully set stack size,
 *              EINVAL          'attr' is invalid or stacksize too
 *                              small or too big.
 *              ENOSYS          function not supported
 *
 * ------------------------------------------------------
 */
{
#if defined(_POSIX_THREAD_ATTR_STACKSIZE)

#if PTHREAD_STACK_MIN > 0

	/*  Verify that the stack size is within range. */
	if (stacksize < PTHREAD_STACK_MIN)
	{
		return EINVAL;
	}

#endif

	if (ptw32_is_attr(attr) != 0)
	{
		return EINVAL;
	}

	/* Everything is okay. */
	(*attr)->stacksize = stacksize;
	return 0;

#else

	return ENOSYS;

#endif /* _POSIX_THREAD_ATTR_STACKSIZE */

}
/*
 * pthread_barrier_attr_destroy.c
 *
 * Description:
 * This translation unit implements barrier primitives.
 *
 * --------------------------------------------------------------------------
 *
 *      Pthreads-win32 - POSIX Threads Library for Win32
 *      Copyright(C) 1998 John E. Bossom
 *      Copyright(C) 1999,2005 Pthreads-win32 contributors
 *
 *      Contact Email: rpj@callisto.canberra.edu.au
 *
 *      The current list of contributors is contained
 *      in the file CONTRIBUTORS included with the source
 *      code distribution. The list can also be seen at the
 *      following World Wide Web location:
 *      http://sources.redhat.com/pthreads-win32/contributors.html
 *
 *      This library is free software; you can redistribute it and/or
 *      modify it under the terms of the GNU Lesser General Public
 *      License as published by the Free Software Foundation; either
 *      version 2 of the License, or (at your option) any later version.
 *
 *      This library is distributed in the hope that it will be useful,
 *      but WITHOUT ANY WARRANTY; without even the implied warranty of
 *      MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *      Lesser General Public License for more details.
 *
 *      You should have received a copy of the GNU Lesser General Public
 *      License along with this library in the file COPYING.LIB;
 *      if not, write to the Free Software Foundation, Inc.,
 *      59 Temple Place - Suite 330, Boston, MA 02111-1307, USA
 */



int
pthread_barrierattr_destroy(pthread_barrierattr_t * attr)
/*
 * ------------------------------------------------------
 * DOCPUBLIC
 *      Destroys a barrier attributes object. The object can
 *      no longer be used.
 *
 * PARAMETERS
 *      attr
 *              pointer to an instance of pthread_barrierattr_t
 *
 *
 * DESCRIPTION
 *      Destroys a barrier attributes object. The object can
 *      no longer be used.
 *
 *      NOTES:
 *              1)      Does not affect barrieres created using 'attr'
 *
 * RESULTS
 *              0               successfully released attr,
 *              EINVAL          'attr' is invalid.
 *
 * ------------------------------------------------------
 */
{
	int result = 0;

	if (attr == NULL || *attr == NULL)
	{
		result = EINVAL;
	}
	else
	{
		pthread_barrierattr_t ba = *attr;

		*attr = NULL;
		free(ba);
	}

	return (result);
}				/* pthread_barrierattr_destroy */
/*
 * pthread_barrier_attr_getpshared.c
 *
 * Description:
 * This translation unit implements barrier primitives.
 *
 * --------------------------------------------------------------------------
 *
 *      Pthreads-win32 - POSIX Threads Library for Win32
 *      Copyright(C) 1998 John E. Bossom
 *      Copyright(C) 1999,2005 Pthreads-win32 contributors
 *
 *      Contact Email: rpj@callisto.canberra.edu.au
 *
 *      The current list of contributors is contained
 *      in the file CONTRIBUTORS included with the source
 *      code distribution. The list can also be seen at the
 *      following World Wide Web location:
 *      http://sources.redhat.com/pthreads-win32/contributors.html
 *
 *      This library is free software; you can redistribute it and/or
 *      modify it under the terms of the GNU Lesser General Public
 *      License as published by the Free Software Foundation; either
 *      version 2 of the License, or (at your option) any later version.
 *
 *      This library is distributed in the hope that it will be useful,
 *      but WITHOUT ANY WARRANTY; without even the implied warranty of
 *      MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *      Lesser General Public License for more details.
 *
 *      You should have received a copy of the GNU Lesser General Public
 *      License along with this library in the file COPYING.LIB;
 *      if not, write to the Free Software Foundation, Inc.,
 *      59 Temple Place - Suite 330, Boston, MA 02111-1307, USA
 */



int
pthread_barrierattr_getpshared(const pthread_barrierattr_t * attr,
	int *pshared)
	/*
	 * ------------------------------------------------------
	 * DOCPUBLIC
	 *      Determine whether barriers created with 'attr' can be
	 *      shared between processes.
	 *
	 * PARAMETERS
	 *      attr
	 *              pointer to an instance of pthread_barrierattr_t
	 *
	 *      pshared
	 *              will be set to one of:
	 *
	 *                      PTHREAD_PROCESS_SHARED
	 *                              May be shared if in shared memory
	 *
	 *                      PTHREAD_PROCESS_PRIVATE
	 *                              Cannot be shared.
	 *
	 *
	 * DESCRIPTION
	 *      Mutexes creatd with 'attr' can be shared between
	 *      processes if pthread_barrier_t variable is allocated
	 *      in memory shared by these processes.
	 *      NOTES:
	 *              1)      pshared barriers MUST be allocated in shared
	 *                      memory.
	 *              2)      The following macro is defined if shared barriers
	 *                      are supported:
	 *                              _POSIX_THREAD_PROCESS_SHARED
	 *
	 * RESULTS
	 *              0               successfully retrieved attribute,
	 *              EINVAL          'attr' is invalid,
	 *
	 * ------------------------------------------------------
	 */
{
	int result;

	if ((attr != NULL && *attr != NULL) && (pshared != NULL))
	{
		*pshared = (*attr)->pshared;
		result = 0;
	}
	else
	{
		result = EINVAL;
	}

	return (result);
}				/* pthread_barrierattr_getpshared */
/*
 * pthread_barrier_attr_init.c
 *
 * Description:
 * This translation unit implements barrier primitives.
 *
 * --------------------------------------------------------------------------
 *
 *      Pthreads-win32 - POSIX Threads Library for Win32
 *      Copyright(C) 1998 John E. Bossom
 *      Copyright(C) 1999,2005 Pthreads-win32 contributors
 *
 *      Contact Email: rpj@callisto.canberra.edu.au
 *
 *      The current list of contributors is contained
 *      in the file CONTRIBUTORS included with the source
 *      code distribution. The list can also be seen at the
 *      following World Wide Web location:
 *      http://sources.redhat.com/pthreads-win32/contributors.html
 *
 *      This library is free software; you can redistribute it and/or
 *      modify it under the terms of the GNU Lesser General Public
 *      License as published by the Free Software Foundation; either
 *      version 2 of the License, or (at your option) any later version.
 *
 *      This library is distributed in the hope that it will be useful,
 *      but WITHOUT ANY WARRANTY; without even the implied warranty of
 *      MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *      Lesser General Public License for more details.
 *
 *      You should have received a copy of the GNU Lesser General Public
 *      License along with this library in the file COPYING.LIB;
 *      if not, write to the Free Software Foundation, Inc.,
 *      59 Temple Place - Suite 330, Boston, MA 02111-1307, USA
 */



int
pthread_barrierattr_init(pthread_barrierattr_t * attr)
/*
 * ------------------------------------------------------
 * DOCPUBLIC
 *      Initializes a barrier attributes object with default
 *      attributes.
 *
 * PARAMETERS
 *      attr
 *              pointer to an instance of pthread_barrierattr_t
 *
 *
 * DESCRIPTION
 *      Initializes a barrier attributes object with default
 *      attributes.
 *
 *      NOTES:
 *              1)      Used to define barrier types
 *
 * RESULTS
 *              0               successfully initialized attr,
 *              ENOMEM          insufficient memory for attr.
 *
 * ------------------------------------------------------
 */
{
	pthread_barrierattr_t ba;
	int result = 0;

	ba = (pthread_barrierattr_t)calloc(1, sizeof(*ba));

	if (ba == NULL)
	{
		result = ENOMEM;
	}
	else
	{
		ba->pshared = PTHREAD_PROCESS_PRIVATE;
	}

	*attr = ba;

	return (result);
}				/* pthread_barrierattr_init */
/*
 * pthread_barrier_attr_setpshared.c
 *
 * Description:
 * This translation unit implements barrier primitives.
 *
 * --------------------------------------------------------------------------
 *
 *      Pthreads-win32 - POSIX Threads Library for Win32
 *      Copyright(C) 1998 John E. Bossom
 *      Copyright(C) 1999,2005 Pthreads-win32 contributors
 *
 *      Contact Email: rpj@callisto.canberra.edu.au
 *
 *      The current list of contributors is contained
 *      in the file CONTRIBUTORS included with the source
 *      code distribution. The list can also be seen at the
 *      following World Wide Web location:
 *      http://sources.redhat.com/pthreads-win32/contributors.html
 *
 *      This library is free software; you can redistribute it and/or
 *      modify it under the terms of the GNU Lesser General Public
 *      License as published by the Free Software Foundation; either
 *      version 2 of the License, or (at your option) any later version.
 *
 *      This library is distributed in the hope that it will be useful,
 *      but WITHOUT ANY WARRANTY; without even the implied warranty of
 *      MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *      Lesser General Public License for more details.
 *
 *      You should have received a copy of the GNU Lesser General Public
 *      License along with this library in the file COPYING.LIB;
 *      if not, write to the Free Software Foundation, Inc.,
 *      59 Temple Place - Suite 330, Boston, MA 02111-1307, USA
 */



int
pthread_barrierattr_setpshared(pthread_barrierattr_t * attr, int pshared)
/*
 * ------------------------------------------------------
 * DOCPUBLIC
 *      Barriers created with 'attr' can be shared between
 *      processes if pthread_barrier_t variable is allocated
 *      in memory shared by these processes.
 *
 * PARAMETERS
 *      attr
 *              pointer to an instance of pthread_barrierattr_t
 *
 *      pshared
 *              must be one of:
 *
 *                      PTHREAD_PROCESS_SHARED
 *                              May be shared if in shared memory
 *
 *                      PTHREAD_PROCESS_PRIVATE
 *                              Cannot be shared.
 *
 * DESCRIPTION
 *      Mutexes creatd with 'attr' can be shared between
 *      processes if pthread_barrier_t variable is allocated
 *      in memory shared by these processes.
 *
 *      NOTES:
 *              1)      pshared barriers MUST be allocated in shared
 *                      memory.
 *
 *              2)      The following macro is defined if shared barriers
 *                      are supported:
 *                              _POSIX_THREAD_PROCESS_SHARED
 *
 * RESULTS
 *              0               successfully set attribute,
 *              EINVAL          'attr' or pshared is invalid,
 *              ENOSYS          PTHREAD_PROCESS_SHARED not supported,
 *
 * ------------------------------------------------------
 */
{
	int result;

	if ((attr != NULL && *attr != NULL) &&
		((pshared == PTHREAD_PROCESS_SHARED) ||
		(pshared == PTHREAD_PROCESS_PRIVATE)))
	{
		if (pshared == PTHREAD_PROCESS_SHARED)
		{

#if !defined( _POSIX_THREAD_PROCESS_SHARED )

			result = ENOSYS;
			pshared = PTHREAD_PROCESS_PRIVATE;

#else

			result = 0;

#endif /* _POSIX_THREAD_PROCESS_SHARED */

		}
		else
		{
			result = 0;
		}

		(*attr)->pshared = pshared;
	}
	else
	{
		result = EINVAL;
	}

	return (result);

}				/* pthread_barrierattr_setpshared */
/*
 * pthread_barrier_destroy.c
 *
 * Description:
 * This translation unit implements barrier primitives.
 *
 * --------------------------------------------------------------------------
 *
 *      Pthreads-win32 - POSIX Threads Library for Win32
 *      Copyright(C) 1998 John E. Bossom
 *      Copyright(C) 1999,2005 Pthreads-win32 contributors
 *
 *      Contact Email: rpj@callisto.canberra.edu.au
 *
 *      The current list of contributors is contained
 *      in the file CONTRIBUTORS included with the source
 *      code distribution. The list can also be seen at the
 *      following World Wide Web location:
 *      http://sources.redhat.com/pthreads-win32/contributors.html
 *
 *      This library is free software; you can redistribute it and/or
 *      modify it under the terms of the GNU Lesser General Public
 *      License as published by the Free Software Foundation; either
 *      version 2 of the License, or (at your option) any later version.
 *
 *      This library is distributed in the hope that it will be useful,
 *      but WITHOUT ANY WARRANTY; without even the implied warranty of
 *      MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *      Lesser General Public License for more details.
 *
 *      You should have received a copy of the GNU Lesser General Public
 *      License along with this library in the file COPYING.LIB;
 *      if not, write to the Free Software Foundation, Inc.,
 *      59 Temple Place - Suite 330, Boston, MA 02111-1307, USA
 */


int
pthread_barrier_destroy(pthread_barrier_t * barrier)
{
	int result = 0;
	pthread_barrier_t b;
	ptw32_mcs_local_node_t node;

	if (barrier == NULL || *barrier == (pthread_barrier_t)PTW32_OBJECT_INVALID)
	{
		return EINVAL;
	}

	if (0 != ptw32_mcs_lock_try_acquire(&(*barrier)->lock, &node))
	{
		return EBUSY;
	}

	b = *barrier;

	if (b->nCurrentBarrierHeight < b->nInitialBarrierHeight)
	{
		result = EBUSY;
	}
	else
	{
		if (0 == (result = sem_destroy(&(b->semBarrierBreeched))))
		{
			*barrier = (pthread_barrier_t)PTW32_OBJECT_INVALID;
			/*
			 * Release the lock before freeing b.
			 *
			 * FIXME: There may be successors which, when we release the lock,
			 * will be linked into b->lock, which will be corrupted at some
			 * point with undefined results for the application. To fix this
			 * will require changing pthread_barrier_t from a pointer to
			 * pthread_barrier_t_ to an instance. This is a change to the ABI
			 * and will require a major version number increment.
			 */
			ptw32_mcs_lock_release(&node);
			(void)free(b);
			return 0;
		}
		else
		{
			/*
			 * This should not ever be reached.
			 * Restore the barrier to working condition before returning.
			 */
			(void)sem_init(&(b->semBarrierBreeched), b->pshared, 0);
		}

		if (result != 0)
		{
			/*
			 * The barrier still exists and is valid
			 * in the event of any error above.
			 */
			result = EBUSY;
		}
	}

	ptw32_mcs_lock_release(&node);
	return (result);
}
/*
 * pthread_barrier_init.c
 *
 * Description:
 * This translation unit implements barrier primitives.
 *
 * --------------------------------------------------------------------------
 *
 *      Pthreads-win32 - POSIX Threads Library for Win32
 *      Copyright(C) 1998 John E. Bossom
 *      Copyright(C) 1999,2005 Pthreads-win32 contributors
 *
 *      Contact Email: rpj@callisto.canberra.edu.au
 *
 *      The current list of contributors is contained
 *      in the file CONTRIBUTORS included with the source
 *      code distribution. The list can also be seen at the
 *      following World Wide Web location:
 *      http://sources.redhat.com/pthreads-win32/contributors.html
 *
 *      This library is free software; you can redistribute it and/or
 *      modify it under the terms of the GNU Lesser General Public
 *      License as published by the Free Software Foundation; either
 *      version 2 of the License, or (at your option) any later version.
 *
 *      This library is distributed in the hope that it will be useful,
 *      but WITHOUT ANY WARRANTY; without even the implied warranty of
 *      MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *      Lesser General Public License for more details.
 *
 *      You should have received a copy of the GNU Lesser General Public
 *      License along with this library in the file COPYING.LIB;
 *      if not, write to the Free Software Foundation, Inc.,
 *      59 Temple Place - Suite 330, Boston, MA 02111-1307, USA
 */



int
pthread_barrier_init(pthread_barrier_t * barrier,
	const pthread_barrierattr_t * attr, unsigned int count)
{
	pthread_barrier_t b;

	if (barrier == NULL || count == 0)
	{
		return EINVAL;
	}

	if (NULL != (b = (pthread_barrier_t)calloc(1, sizeof(*b))))
	{
		b->pshared = (attr != NULL && *attr != NULL
			? (*attr)->pshared : PTHREAD_PROCESS_PRIVATE);

		b->nCurrentBarrierHeight = b->nInitialBarrierHeight = count;
		b->lock = 0;

		if (0 == sem_init(&(b->semBarrierBreeched), b->pshared, 0))
		{
			*barrier = b;
			return 0;
		}
		(void)free(b);
	}

	return ENOMEM;
}
/*
 * pthread_barrier_wait.c
 *
 * Description:
 * This translation unit implements barrier primitives.
 *
 * --------------------------------------------------------------------------
 *
 *      Pthreads-win32 - POSIX Threads Library for Win32
 *      Copyright(C) 1998 John E. Bossom
 *      Copyright(C) 1999,2005 Pthreads-win32 contributors
 *
 *      Contact Email: rpj@callisto.canberra.edu.au
 *
 *      The current list of contributors is contained
 *      in the file CONTRIBUTORS included with the source
 *      code distribution. The list can also be seen at the
 *      following World Wide Web location:
 *      http://sources.redhat.com/pthreads-win32/contributors.html
 *
 *      This library is free software; you can redistribute it and/or
 *      modify it under the terms of the GNU Lesser General Public
 *      License as published by the Free Software Foundation; either
 *      version 2 of the License, or (at your option) any later version.
 *
 *      This library is distributed in the hope that it will be useful,
 *      but WITHOUT ANY WARRANTY; without even the implied warranty of
 *      MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *      Lesser General Public License for more details.
 *
 *      You should have received a copy of the GNU Lesser General Public
 *      License along with this library in the file COPYING.LIB;
 *      if not, write to the Free Software Foundation, Inc.,
 *      59 Temple Place - Suite 330, Boston, MA 02111-1307, USA
 */



int
pthread_barrier_wait(pthread_barrier_t * barrier)
{
	int result;
	pthread_barrier_t b;

	ptw32_mcs_local_node_t node;

	if (barrier == NULL || *barrier == (pthread_barrier_t)PTW32_OBJECT_INVALID)
	{
		return EINVAL;
	}

	ptw32_mcs_lock_acquire(&(*barrier)->lock, &node);

	b = *barrier;
	if (--b->nCurrentBarrierHeight == 0)
	{
		/*
		 * We are the last thread to arrive at the barrier before it releases us.
		 * Move our MCS local node to the global scope barrier handle so that the
		 * last thread out (not necessarily us) can release the lock.
		 */
		ptw32_mcs_node_transfer(&b->proxynode, &node);

		/*
		 * Any threads that have not quite entered sem_wait below when the
		 * multiple_post has completed will nevertheless continue through
		 * the semaphore (barrier).
		 */
		result = (b->nInitialBarrierHeight > 1
			? sem_post_multiple(&(b->semBarrierBreeched),
				b->nInitialBarrierHeight - 1) : 0);
	}
	else
	{
		ptw32_mcs_lock_release(&node);
		/*
		 * Use the non-cancelable version of sem_wait().
		 *
		 * It is possible that all nInitialBarrierHeight-1 threads are
		 * at this point when the last thread enters the barrier, resets
		 * nCurrentBarrierHeight = nInitialBarrierHeight and leaves.
		 * If pthread_barrier_destroy is called at that moment then the
		 * barrier will be destroyed along with the semas.
		 */
		result = ptw32_semwait(&(b->semBarrierBreeched));
	}

	if ((PTW32_INTERLOCKED_LONG)PTW32_INTERLOCKED_INCREMENT_LONG((PTW32_INTERLOCKED_LONGPTR)&b->nCurrentBarrierHeight)
		== (PTW32_INTERLOCKED_LONG)b->nInitialBarrierHeight)
	{
		/*
		 * We are the last thread to cross this barrier
		 */
		ptw32_mcs_lock_release(&b->proxynode);
		if (0 == result)
		{
			result = PTHREAD_BARRIER_SERIAL_THREAD;
		}
	}

	return (result);
}
/*
 * pthread_cancel.c
 *
 * Description:
 * POSIX thread functions related to thread cancellation.
 *
 * --------------------------------------------------------------------------
 *
 *      Pthreads-win32 - POSIX Threads Library for Win32
 *      Copyright(C) 1998 John E. Bossom
 *      Copyright(C) 1999,2005 Pthreads-win32 contributors
 *
 *      Contact Email: rpj@callisto.canberra.edu.au
 *
 *      The current list of contributors is contained
 *      in the file CONTRIBUTORS included with the source
 *      code distribution. The list can also be seen at the
 *      following World Wide Web location:
 *      http://sources.redhat.com/pthreads-win32/contributors.html
 *
 *      This library is free software; you can redistribute it and/or
 *      modify it under the terms of the GNU Lesser General Public
 *      License as published by the Free Software Foundation; either
 *      version 2 of the License, or (at your option) any later version.
 *
 *      This library is distributed in the hope that it will be useful,
 *      but WITHOUT ANY WARRANTY; without even the implied warranty of
 *      MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *      Lesser General Public License for more details.
 *
 *      You should have received a copy of the GNU Lesser General Public
 *      License along with this library in the file COPYING.LIB;
 *      if not, write to the Free Software Foundation, Inc.,
 *      59 Temple Place - Suite 330, Boston, MA 02111-1307, USA
 */


static void
ptw32_cancel_self(void)
{
	ptw32_throw(PTW32_EPS_CANCEL);

	/* Never reached */
}

static void CALLBACK
ptw32_cancel_callback(ULONG_PTR unused)
{
	ptw32_throw(PTW32_EPS_CANCEL);

	/* Never reached */
}

/*
 * ptw32_RegisterCancelation() -
 * Must have args of same type as QueueUserAPCEx because this function
 * is a substitute for QueueUserAPCEx if it's not available.
 */
DWORD
ptw32_RegisterCancelation(PAPCFUNC unused1, HANDLE threadH, DWORD unused2)
{
	CONTEXT context;

	context.ContextFlags = CONTEXT_CONTROL;
	GetThreadContext(threadH, &context);
	PTW32_PROGCTR(context) = (DWORD_PTR)ptw32_cancel_self;
	SetThreadContext(threadH, &context);
	return 0;
}

int
pthread_cancel(pthread_t thread)
/*
 * ------------------------------------------------------
 * DOCPUBLIC
 *      This function requests cancellation of 'thread'.
 *
 * PARAMETERS
 *      thread
 *              reference to an instance of pthread_t
 *
 *
 * DESCRIPTION
 *      This function requests cancellation of 'thread'.
 *      NOTE: cancellation is asynchronous; use pthread_join to
 *                wait for termination of 'thread' if necessary.
 *
 * RESULTS
 *              0               successfully requested cancellation,
 *              ESRCH           no thread found corresponding to 'thread',
 *              ENOMEM          implicit self thread create failed.
 * ------------------------------------------------------
 */
{
	int result;
	int cancel_self;
	pthread_t self;
	ptw32_thread_t * tp;
	ptw32_mcs_local_node_t stateLock;

	result = pthread_kill(thread, 0);

	if (0 != result)
	{
		return result;
	}

	if ((self = pthread_self()).p == NULL)
	{
		return ENOMEM;
	};

	/*
	 * For self cancellation we need to ensure that a thread can't
	 * deadlock itself trying to cancel itself asynchronously
	 * (pthread_cancel is required to be an async-cancel
	 * safe function).
	 */
	cancel_self = pthread_equal(thread, self);

	tp = (ptw32_thread_t *)thread.p;

	/*
	 * Lock for async-cancel safety.
	 */
	ptw32_mcs_lock_acquire(&tp->stateLock, &stateLock);

	if (tp->cancelType == PTHREAD_CANCEL_ASYNCHRONOUS
		&& tp->cancelState == PTHREAD_CANCEL_ENABLE
		&& tp->state < PThreadStateCanceling)
	{
		if (cancel_self)
		{
			tp->state = PThreadStateCanceling;
			tp->cancelState = PTHREAD_CANCEL_DISABLE;

			ptw32_mcs_lock_release(&stateLock);
			ptw32_throw(PTW32_EPS_CANCEL);

			/* Never reached */
		}
		else
		{
			HANDLE threadH = tp->threadH;

			SuspendThread(threadH);

			if (WaitForSingleObject(threadH, 0) == WAIT_TIMEOUT)
			{
				tp->state = PThreadStateCanceling;
				tp->cancelState = PTHREAD_CANCEL_DISABLE;
				/*
				 * If alertdrv and QueueUserAPCEx is available then the following
				 * will result in a call to QueueUserAPCEx with the args given, otherwise
				 * this will result in a call to ptw32_RegisterCancelation and only
				 * the threadH arg will be used.
				 */
				ptw32_register_cancelation((PAPCFUNC)ptw32_cancel_callback, threadH, 0);
				ptw32_mcs_lock_release(&stateLock);
				ResumeThread(threadH);
			}
		}
	}
	else
	{
		/*
		 * Set for deferred cancellation.
		 */
		if (tp->state < PThreadStateCancelPending)
		{
			tp->state = PThreadStateCancelPending;
			if (!SetEvent(tp->cancelEvent))
			{
				result = ESRCH;
			}
		}
		else if (tp->state >= PThreadStateCanceling)
		{
			result = ESRCH;
		}

		ptw32_mcs_lock_release(&stateLock);
	}

	return (result);
}
/*
 * condvar_attr_destroy.c
 *
 * Description:
 * This translation unit implements condition variables and their primitives.
 *
 *
 * --------------------------------------------------------------------------
 *
 *      Pthreads-win32 - POSIX Threads Library for Win32
 *      Copyright(C) 1998 John E. Bossom
 *      Copyright(C) 1999,2005 Pthreads-win32 contributors
 *
 *      Contact Email: rpj@callisto.canberra.edu.au
 *
 *      The current list of contributors is contained
 *      in the file CONTRIBUTORS included with the source
 *      code distribution. The list can also be seen at the
 *      following World Wide Web location:
 *      http://sources.redhat.com/pthreads-win32/contributors.html
 *
 *      This library is free software; you can redistribute it and/or
 *      modify it under the terms of the GNU Lesser General Public
 *      License as published by the Free Software Foundation; either
 *      version 2 of the License, or (at your option) any later version.
 *
 *      This library is distributed in the hope that it will be useful,
 *      but WITHOUT ANY WARRANTY; without even the implied warranty of
 *      MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *      Lesser General Public License for more details.
 *
 *      You should have received a copy of the GNU Lesser General Public
 *      License along with this library in the file COPYING.LIB;
 *      if not, write to the Free Software Foundation, Inc.,
 *      59 Temple Place - Suite 330, Boston, MA 02111-1307, USA
 */



int
pthread_condattr_destroy(pthread_condattr_t * attr)
/*
 * ------------------------------------------------------
 * DOCPUBLIC
 *      Destroys a condition variable attributes object.
 *      The object can no longer be used.
 *
 * PARAMETERS
 *      attr
 *              pointer to an instance of pthread_condattr_t
 *
 *
 * DESCRIPTION
 *      Destroys a condition variable attributes object.
 *      The object can no longer be used.
 *
 *      NOTES:
 *      1)      Does not affect condition variables created
 *              using 'attr'
 *
 * RESULTS
 *              0               successfully released attr,
 *              EINVAL          'attr' is invalid.
 *
 * ------------------------------------------------------
 */
{
	int result = 0;

	if (attr == NULL || *attr == NULL)
	{
		result = EINVAL;
	}
	else
	{
		(void)free(*attr);

		*attr = NULL;
		result = 0;
	}

	return result;

}				/* pthread_condattr_destroy */
/*
 * pthread_condattr_getpshared.c
 *
 * Description:
 * This translation unit implements condition variables and their primitives.
 *
 *
 * --------------------------------------------------------------------------
 *
 *      Pthreads-win32 - POSIX Threads Library for Win32
 *      Copyright(C) 1998 John E. Bossom
 *      Copyright(C) 1999,2005 Pthreads-win32 contributors
 *
 *      Contact Email: rpj@callisto.canberra.edu.au
 *
 *      The current list of contributors is contained
 *      in the file CONTRIBUTORS included with the source
 *      code distribution. The list can also be seen at the
 *      following World Wide Web location:
 *      http://sources.redhat.com/pthreads-win32/contributors.html
 *
 *      This library is free software; you can redistribute it and/or
 *      modify it under the terms of the GNU Lesser General Public
 *      License as published by the Free Software Foundation; either
 *      version 2 of the License, or (at your option) any later version.
 *
 *      This library is distributed in the hope that it will be useful,
 *      but WITHOUT ANY WARRANTY; without even the implied warranty of
 *      MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *      Lesser General Public License for more details.
 *
 *      You should have received a copy of the GNU Lesser General Public
 *      License along with this library in the file COPYING.LIB;
 *      if not, write to the Free Software Foundation, Inc.,
 *      59 Temple Place - Suite 330, Boston, MA 02111-1307, USA
 */



int
pthread_condattr_getpshared(const pthread_condattr_t * attr, int *pshared)
/*
 * ------------------------------------------------------
 * DOCPUBLIC
 *      Determine whether condition variables created with 'attr'
 *      can be shared between processes.
 *
 * PARAMETERS
 *      attr
 *              pointer to an instance of pthread_condattr_t
 *
 *      pshared
 *              will be set to one of:
 *
 *                      PTHREAD_PROCESS_SHARED
 *                              May be shared if in shared memory
 *
 *                      PTHREAD_PROCESS_PRIVATE
 *                              Cannot be shared.
 *
 *
 * DESCRIPTION
 *      Condition Variables created with 'attr' can be shared
 *      between processes if pthread_cond_t variable is allocated
 *      in memory shared by these processes.
 *      NOTES:
 *      1)      pshared condition variables MUST be allocated in
 *              shared memory.
 *
 *      2)      The following macro is defined if shared mutexes
 *              are supported:
 *                      _POSIX_THREAD_PROCESS_SHARED
 *
 * RESULTS
 *              0               successfully retrieved attribute,
 *              EINVAL          'attr' or 'pshared' is invalid,
 *
 * ------------------------------------------------------
 */
{
	int result;

	if ((attr != NULL && *attr != NULL) && (pshared != NULL))
	{
		*pshared = (*attr)->pshared;
		result = 0;
	}
	else
	{
		result = EINVAL;
	}

	return result;

}				/* pthread_condattr_getpshared */
/*
 * pthread_condattr_init.c
 *
 * Description:
 * This translation unit implements condition variables and their primitives.
 *
 *
 * --------------------------------------------------------------------------
 *
 *      Pthreads-win32 - POSIX Threads Library for Win32
 *      Copyright(C) 1998 John E. Bossom
 *      Copyright(C) 1999,2005 Pthreads-win32 contributors
 *
 *      Contact Email: rpj@callisto.canberra.edu.au
 *
 *      The current list of contributors is contained
 *      in the file CONTRIBUTORS included with the source
 *      code distribution. The list can also be seen at the
 *      following World Wide Web location:
 *      http://sources.redhat.com/pthreads-win32/contributors.html
 *
 *      This library is free software; you can redistribute it and/or
 *      modify it under the terms of the GNU Lesser General Public
 *      License as published by the Free Software Foundation; either
 *      version 2 of the License, or (at your option) any later version.
 *
 *      This library is distributed in the hope that it will be useful,
 *      but WITHOUT ANY WARRANTY; without even the implied warranty of
 *      MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *      Lesser General Public License for more details.
 *
 *      You should have received a copy of the GNU Lesser General Public
 *      License along with this library in the file COPYING.LIB;
 *      if not, write to the Free Software Foundation, Inc.,
 *      59 Temple Place - Suite 330, Boston, MA 02111-1307, USA
 */



int
pthread_condattr_init(pthread_condattr_t * attr)
/*
 * ------------------------------------------------------
 * DOCPUBLIC
 *      Initializes a condition variable attributes object
 *      with default attributes.
 *
 * PARAMETERS
 *      attr
 *              pointer to an instance of pthread_condattr_t
 *
 *
 * DESCRIPTION
 *      Initializes a condition variable attributes object
 *      with default attributes.
 *
 *      NOTES:
 *              1)      Use to define condition variable types
 *              2)      It is up to the application to ensure
 *                      that it doesn't re-init an attribute
 *                      without destroying it first. Otherwise
 *                      a memory leak is created.
 *
 * RESULTS
 *              0               successfully initialized attr,
 *              ENOMEM          insufficient memory for attr.
 *
 * ------------------------------------------------------
 */
{
	pthread_condattr_t attr_result;
	int result = 0;

	attr_result = (pthread_condattr_t)calloc(1, sizeof(*attr_result));

	if (attr_result == NULL)
	{
		result = ENOMEM;
	}

	*attr = attr_result;

	return result;

}				/* pthread_condattr_init */
/*
 * pthread_condattr_setpshared.c
 *
 * Description:
 * This translation unit implements condition variables and their primitives.
 *
 *
 * --------------------------------------------------------------------------
 *
 *      Pthreads-win32 - POSIX Threads Library for Win32
 *      Copyright(C) 1998 John E. Bossom
 *      Copyright(C) 1999,2005 Pthreads-win32 contributors
 *
 *      Contact Email: rpj@callisto.canberra.edu.au
 *
 *      The current list of contributors is contained
 *      in the file CONTRIBUTORS included with the source
 *      code distribution. The list can also be seen at the
 *      following World Wide Web location:
 *      http://sources.redhat.com/pthreads-win32/contributors.html
 *
 *      This library is free software; you can redistribute it and/or
 *      modify it under the terms of the GNU Lesser General Public
 *      License as published by the Free Software Foundation; either
 *      version 2 of the License, or (at your option) any later version.
 *
 *      This library is distributed in the hope that it will be useful,
 *      but WITHOUT ANY WARRANTY; without even the implied warranty of
 *      MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *      Lesser General Public License for more details.
 *
 *      You should have received a copy of the GNU Lesser General Public
 *      License along with this library in the file COPYING.LIB;
 *      if not, write to the Free Software Foundation, Inc.,
 *      59 Temple Place - Suite 330, Boston, MA 02111-1307, USA
 */



int
pthread_condattr_setpshared(pthread_condattr_t * attr, int pshared)
/*
 * ------------------------------------------------------
 * DOCPUBLIC
 *      Mutexes created with 'attr' can be shared between
 *      processes if pthread_mutex_t variable is allocated
 *      in memory shared by these processes.
 *
 * PARAMETERS
 *      attr
 *              pointer to an instance of pthread_mutexattr_t
 *
 *      pshared
 *              must be one of:
 *
 *                      PTHREAD_PROCESS_SHARED
 *                              May be shared if in shared memory
 *
 *                      PTHREAD_PROCESS_PRIVATE
 *                              Cannot be shared.
 *
 * DESCRIPTION
 *      Mutexes creatd with 'attr' can be shared between
 *      processes if pthread_mutex_t variable is allocated
 *      in memory shared by these processes.
 *
 *      NOTES:
 *              1)      pshared mutexes MUST be allocated in shared
 *                      memory.
 *
 *              2)      The following macro is defined if shared mutexes
 *                      are supported:
 *                              _POSIX_THREAD_PROCESS_SHARED
 *
 * RESULTS
 *              0               successfully set attribute,
 *              EINVAL          'attr' or pshared is invalid,
 *              ENOSYS          PTHREAD_PROCESS_SHARED not supported,
 *
 * ------------------------------------------------------
 */
{
	int result;

	if ((attr != NULL && *attr != NULL)
		&& ((pshared == PTHREAD_PROCESS_SHARED)
			|| (pshared == PTHREAD_PROCESS_PRIVATE)))
	{
		if (pshared == PTHREAD_PROCESS_SHARED)
		{

#if !defined( _POSIX_THREAD_PROCESS_SHARED )
			result = ENOSYS;
			pshared = PTHREAD_PROCESS_PRIVATE;
#else
			result = 0;

#endif /* _POSIX_THREAD_PROCESS_SHARED */

		}
		else
		{
			result = 0;
		}

		(*attr)->pshared = pshared;
	}
	else
	{
		result = EINVAL;
	}

	return result;

}				/* pthread_condattr_setpshared */
/*
 * pthread_cond_destroy.c
 *
 * Description:
 * This translation unit implements condition variables and their primitives.
 *
 *
 * --------------------------------------------------------------------------
 *
 *      Pthreads-win32 - POSIX Threads Library for Win32
 *      Copyright(C) 1998 John E. Bossom
 *      Copyright(C) 1999,2005 Pthreads-win32 contributors
 *
 *      Contact Email: rpj@callisto.canberra.edu.au
 *
 *      The current list of contributors is contained
 *      in the file CONTRIBUTORS included with the source
 *      code distribution. The list can also be seen at the
 *      following World Wide Web location:
 *      http://sources.redhat.com/pthreads-win32/contributors.html
 *
 *      This library is free software; you can redistribute it and/or
 *      modify it under the terms of the GNU Lesser General Public
 *      License as published by the Free Software Foundation; either
 *      version 2 of the License, or (at your option) any later version.
 *
 *      This library is distributed in the hope that it will be useful,
 *      but WITHOUT ANY WARRANTY; without even the implied warranty of
 *      MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *      Lesser General Public License for more details.
 *
 *      You should have received a copy of the GNU Lesser General Public
 *      License along with this library in the file COPYING.LIB;
 *      if not, write to the Free Software Foundation, Inc.,
 *      59 Temple Place - Suite 330, Boston, MA 02111-1307, USA
 */


int
pthread_cond_destroy(pthread_cond_t * cond)
/*
 * ------------------------------------------------------
 * DOCPUBLIC
 *      This function destroys a condition variable
 *
 *
 * PARAMETERS
 *      cond
 *              pointer to an instance of pthread_cond_t
 *
 *
 * DESCRIPTION
 *      This function destroys a condition variable.
 *
 *      NOTES:
 *              1)      A condition variable can be destroyed
 *                      immediately after all the threads that
 *                      are blocked on it are awakened. e.g.
 *
 *                      struct list {
 *                        pthread_mutex_t lm;
 *                        ...
 *                      }
 *
 *                      struct elt {
 *                        key k;
 *                        int busy;
 *                        pthread_cond_t notbusy;
 *                        ...
 *                      }
 *
 *
 *                      struct elt *
 *                      list_find(struct list *lp, key k)
 *                      {
 *                        struct elt *ep;
 *
 *                        pthread_mutex_lock(&lp->lm);
 *                        while ((ep = find_elt(l,k) != NULL) && ep->busy)
 *                          pthread_cond_wait(&ep->notbusy, &lp->lm);
 *                        if (ep != NULL)
 *                          ep->busy = 1;
 *                        pthread_mutex_unlock(&lp->lm);
 *                        return(ep);
 *                      }
 *
 *                      delete_elt(struct list *lp, struct elt *ep)
 *                      {
 *                        pthread_mutex_lock(&lp->lm);
 *                        assert(ep->busy);
 *                        ... remove ep from list ...
 *                        ep->busy = 0;
 *                    (A) pthread_cond_broadcast(&ep->notbusy);
 *                        pthread_mutex_unlock(&lp->lm);
 *                    (B) pthread_cond_destroy(&rp->notbusy);
 *                        free(ep);
 *                      }
 *
 *                      In this example, the condition variable
 *                      and its list element may be freed (line B)
 *                      immediately after all threads waiting for
 *                      it are awakened (line A), since the mutex
 *                      and the code ensure that no other thread
 *                      can touch the element to be deleted.
 *
 * RESULTS
 *              0               successfully released condition variable,
 *              EINVAL          'cond' is invalid,
 *              EBUSY           'cond' is in use,
 *
 * ------------------------------------------------------
 */
{
	pthread_cond_t cv;
	int result = 0, result1 = 0, result2 = 0;

	/*
	 * Assuming any race condition here is harmless.
	 */
	if (cond == NULL || *cond == NULL)
	{
		return EINVAL;
	}

	if (*cond != PTHREAD_COND_INITIALIZER)
	{
		ptw32_mcs_local_node_t node;
		ptw32_mcs_lock_acquire(&ptw32_cond_list_lock, &node);

		cv = *cond;

		/*
		 * Close the gate; this will synchronize this thread with
		 * all already signaled waiters to let them retract their
		 * waiter status - SEE NOTE 1 ABOVE!!!
		 */
		if (ptw32_semwait(&(cv->semBlockLock)) != 0) /* Non-cancelable */
		{
			result = errno;
		}
		else
		{
			/*
			 * !TRY! lock mtxUnblockLock; try will detect busy condition
			 * and will not cause a deadlock with respect to concurrent
			 * signal/broadcast.
			 */
			if ((result = pthread_mutex_trylock(&(cv->mtxUnblockLock))) != 0)
			{
				(void)sem_post(&(cv->semBlockLock));
			}
		}

		if (result != 0)
		{
			ptw32_mcs_lock_release(&node);
			return result;
		}

		/*
		 * Check whether cv is still busy (still has waiters)
		 */
		if (cv->nWaitersBlocked > cv->nWaitersGone)
		{
			if (sem_post(&(cv->semBlockLock)) != 0)
			{
				result = errno;
			}
			result1 = pthread_mutex_unlock(&(cv->mtxUnblockLock));
			result2 = EBUSY;
		}
		else
		{
			/*
			 * Now it is safe to destroy
			 */
			*cond = NULL;

			if (sem_destroy(&(cv->semBlockLock)) != 0)
			{
				result = errno;
			}
			if (sem_destroy(&(cv->semBlockQueue)) != 0)
			{
				result1 = errno;
			}
			if ((result2 = pthread_mutex_unlock(&(cv->mtxUnblockLock))) == 0)
			{
				result2 = pthread_mutex_destroy(&(cv->mtxUnblockLock));
			}

			/* Unlink the CV from the list */

			if (ptw32_cond_list_head == cv)
			{
				ptw32_cond_list_head = cv->next;
			}
			else
			{
				cv->prev->next = cv->next;
			}

			if (ptw32_cond_list_tail == cv)
			{
				ptw32_cond_list_tail = cv->prev;
			}
			else
			{
				cv->next->prev = cv->prev;
			}

			(void)free(cv);
		}

		ptw32_mcs_lock_release(&node);
	}
	else
	{
		ptw32_mcs_local_node_t node;
		/*
		 * See notes in ptw32_cond_check_need_init() above also.
		 */
		ptw32_mcs_lock_acquire(&ptw32_cond_test_init_lock, &node);

		/*
		 * Check again.
		 */
		if (*cond == PTHREAD_COND_INITIALIZER)
		{
			/*
			 * This is all we need to do to destroy a statically
			 * initialised cond that has not yet been used (initialised).
			 * If we get to here, another thread waiting to initialise
			 * this cond will get an EINVAL. That's OK.
			 */
			*cond = NULL;
		}
		else
		{
			/*
			 * The cv has been initialised while we were waiting
			 * so assume it's in use.
			 */
			result = EBUSY;
		}

		ptw32_mcs_lock_release(&node);
	}

	return ((result != 0) ? result : ((result1 != 0) ? result1 : result2));
}
/*
 * pthread_cond_init.c
 *
 * Description:
 * This translation unit implements condition variables and their primitives.
 *
 *
 * --------------------------------------------------------------------------
 *
 *      Pthreads-win32 - POSIX Threads Library for Win32
 *      Copyright(C) 1998 John E. Bossom
 *      Copyright(C) 1999,2005 Pthreads-win32 contributors
 *
 *      Contact Email: rpj@callisto.canberra.edu.au
 *
 *      The current list of contributors is contained
 *      in the file CONTRIBUTORS included with the source
 *      code distribution. The list can also be seen at the
 *      following World Wide Web location:
 *      http://sources.redhat.com/pthreads-win32/contributors.html
 *
 *      This library is free software; you can redistribute it and/or
 *      modify it under the terms of the GNU Lesser General Public
 *      License as published by the Free Software Foundation; either
 *      version 2 of the License, or (at your option) any later version.
 *
 *      This library is distributed in the hope that it will be useful,
 *      but WITHOUT ANY WARRANTY; without even the implied warranty of
 *      MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *      Lesser General Public License for more details.
 *
 *      You should have received a copy of the GNU Lesser General Public
 *      License along with this library in the file COPYING.LIB;
 *      if not, write to the Free Software Foundation, Inc.,
 *      59 Temple Place - Suite 330, Boston, MA 02111-1307, USA
 */



int
pthread_cond_init(pthread_cond_t * cond, const pthread_condattr_t * attr)
/*
 * ------------------------------------------------------
 * DOCPUBLIC
 *      This function initializes a condition variable.
 *
 * PARAMETERS
 *      cond
 *              pointer to an instance of pthread_cond_t
 *
 *      attr
 *              specifies optional creation attributes.
 *
 *
 * DESCRIPTION
 *      This function initializes a condition variable.
 *
 * RESULTS
 *              0               successfully created condition variable,
 *              EINVAL          'attr' is invalid,
 *              EAGAIN          insufficient resources (other than
 *                              memory,
 *              ENOMEM          insufficient memory,
 *              EBUSY           'cond' is already initialized,
 *
 * ------------------------------------------------------
 */
{
	int result;
	pthread_cond_t cv = NULL;

	if (cond == NULL)
	{
		return EINVAL;
	}

	if ((attr != NULL && *attr != NULL) &&
		((*attr)->pshared == PTHREAD_PROCESS_SHARED))
	{
		/*
		 * Creating condition variable that can be shared between
		 * processes.
		 */
		result = ENOSYS;
		goto DONE;
	}

	cv = (pthread_cond_t)calloc(1, sizeof(*cv));

	if (cv == NULL)
	{
		result = ENOMEM;
		goto DONE;
	}

	cv->nWaitersBlocked = 0;
	cv->nWaitersToUnblock = 0;
	cv->nWaitersGone = 0;

	if (sem_init(&(cv->semBlockLock), 0, 1) != 0)
	{
		result = errno;
		goto FAIL0;
	}

	if (sem_init(&(cv->semBlockQueue), 0, 0) != 0)
	{
		result = errno;
		goto FAIL1;
	}

	if ((result = pthread_mutex_init(&(cv->mtxUnblockLock), 0)) != 0)
	{
		goto FAIL2;
	}

	result = 0;

	goto DONE;

	/*
	 * -------------
	 * Failed...
	 * -------------
	 */
FAIL2:
	(void)sem_destroy(&(cv->semBlockQueue));

FAIL1:
	(void)sem_destroy(&(cv->semBlockLock));

FAIL0:
	(void)free(cv);
	cv = NULL;

DONE:
	if (0 == result)
	{
		ptw32_mcs_local_node_t node;

		ptw32_mcs_lock_acquire(&ptw32_cond_list_lock, &node);

		cv->next = NULL;
		cv->prev = ptw32_cond_list_tail;

		if (ptw32_cond_list_tail != NULL)
		{
			ptw32_cond_list_tail->next = cv;
		}

		ptw32_cond_list_tail = cv;

		if (ptw32_cond_list_head == NULL)
		{
			ptw32_cond_list_head = cv;
		}

		ptw32_mcs_lock_release(&node);
	}

	*cond = cv;

	return result;

}				/* pthread_cond_init */
/*
 * pthread_cond_signal.c
 *
 * Description:
 * This translation unit implements condition variables and their primitives.
 *
 *
 * --------------------------------------------------------------------------
 *
 *      Pthreads-win32 - POSIX Threads Library for Win32
 *      Copyright(C) 1998 John E. Bossom
 *      Copyright(C) 1999,2005 Pthreads-win32 contributors
 *
 *      Contact Email: rpj@callisto.canberra.edu.au
 *
 *      The current list of contributors is contained
 *      in the file CONTRIBUTORS included with the source
 *      code distribution. The list can also be seen at the
 *      following World Wide Web location:
 *      http://sources.redhat.com/pthreads-win32/contributors.html
 *
 *      This library is free software; you can redistribute it and/or
 *      modify it under the terms of the GNU Lesser General Public
 *      License as published by the Free Software Foundation; either
 *      version 2 of the License, or (at your option) any later version.
 *
 *      This library is distributed in the hope that it will be useful,
 *      but WITHOUT ANY WARRANTY; without even the implied warranty of
 *      MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *      Lesser General Public License for more details.
 *
 *      You should have received a copy of the GNU Lesser General Public
 *      License along with this library in the file COPYING.LIB;
 *      if not, write to the Free Software Foundation, Inc.,
 *      59 Temple Place - Suite 330, Boston, MA 02111-1307, USA
 *
 * -------------------------------------------------------------
 * Algorithm:
 * See the comments at the top of pthread_cond_wait.c.
 */


static INLINE int
ptw32_cond_unblock(pthread_cond_t * cond, int unblockAll)
/*
 * Notes.
 *
 * Does not use the external mutex for synchronisation,
 * therefore semBlockLock is needed.
 * mtxUnblockLock is for LEVEL-2 synch. LEVEL-2 is the
 * state where the external mutex is not necessarily locked by
 * any thread, ie. between cond_wait unlocking and re-acquiring
 * the lock after having been signaled or a timeout or
 * cancellation.
 *
 * Uses the following CV elements:
 *   nWaitersBlocked
 *   nWaitersToUnblock
 *   nWaitersGone
 *   mtxUnblockLock
 *   semBlockLock
 *   semBlockQueue
 */
{
	int result;
	pthread_cond_t cv;
	int nSignalsToIssue;

	if (cond == NULL || *cond == NULL)
	{
		return EINVAL;
	}

	cv = *cond;

	/*
	 * No-op if the CV is static and hasn't been initialised yet.
	 * Assuming that any race condition is harmless.
	 */
	if (cv == PTHREAD_COND_INITIALIZER)
	{
		return 0;
	}

	if ((result = pthread_mutex_lock(&(cv->mtxUnblockLock))) != 0)
	{
		return result;
	}

	if (0 != cv->nWaitersToUnblock)
	{
		if (0 == cv->nWaitersBlocked)
		{
			return pthread_mutex_unlock(&(cv->mtxUnblockLock));
		}
		if (unblockAll)
		{
			cv->nWaitersToUnblock += (nSignalsToIssue = cv->nWaitersBlocked);
			cv->nWaitersBlocked = 0;
		}
		else
		{
			nSignalsToIssue = 1;
			cv->nWaitersToUnblock++;
			cv->nWaitersBlocked--;
		}
	}
	else if (cv->nWaitersBlocked > cv->nWaitersGone)
	{
		/* Use the non-cancellable version of sem_wait() */
		if (ptw32_semwait(&(cv->semBlockLock)) != 0)
		{
			result = errno;
			(void)pthread_mutex_unlock(&(cv->mtxUnblockLock));
			return result;
		}
		if (0 != cv->nWaitersGone)
		{
			cv->nWaitersBlocked -= cv->nWaitersGone;
			cv->nWaitersGone = 0;
		}
		if (unblockAll)
		{
			nSignalsToIssue = cv->nWaitersToUnblock = cv->nWaitersBlocked;
			cv->nWaitersBlocked = 0;
		}
		else
		{
			nSignalsToIssue = cv->nWaitersToUnblock = 1;
			cv->nWaitersBlocked--;
		}
	}
	else
	{
		return pthread_mutex_unlock(&(cv->mtxUnblockLock));
	}

	if ((result = pthread_mutex_unlock(&(cv->mtxUnblockLock))) == 0)
	{
		if (sem_post_multiple(&(cv->semBlockQueue), nSignalsToIssue) != 0)
		{
			result = errno;
		}
	}

	return result;

}				/* ptw32_cond_unblock */

int
pthread_cond_signal(pthread_cond_t * cond)
/*
 * ------------------------------------------------------
 * DOCPUBLIC
 *      This function signals a condition variable, waking
 *      one waiting thread.
 *      If SCHED_FIFO or SCHED_RR policy threads are waiting
 *      the highest priority waiter is awakened; otherwise,
 *      an unspecified waiter is awakened.
 *
 * PARAMETERS
 *      cond
 *              pointer to an instance of pthread_cond_t
 *
 *
 * DESCRIPTION
 *      This function signals a condition variable, waking
 *      one waiting thread.
 *      If SCHED_FIFO or SCHED_RR policy threads are waiting
 *      the highest priority waiter is awakened; otherwise,
 *      an unspecified waiter is awakened.
 *
 *      NOTES:
 *
 *      1)      Use when any waiter can respond and only one need
 *              respond (all waiters being equal).
 *
 * RESULTS
 *              0               successfully signaled condition,
 *              EINVAL          'cond' is invalid,
 *
 * ------------------------------------------------------
 */
{
	/*
	 * The '0'(FALSE) unblockAll arg means unblock ONE waiter.
	 */
	return (ptw32_cond_unblock(cond, 0));

}				/* pthread_cond_signal */

int
pthread_cond_broadcast(pthread_cond_t * cond)
/*
 * ------------------------------------------------------
 * DOCPUBLIC
 *      This function broadcasts the condition variable,
 *      waking all current waiters.
 *
 * PARAMETERS
 *      cond
 *              pointer to an instance of pthread_cond_t
 *
 *
 * DESCRIPTION
 *      This function signals a condition variable, waking
 *      all waiting threads.
 *
 *      NOTES:
 *
 *      1)      Use when more than one waiter may respond to
 *              predicate change or if any waiting thread may
 *              not be able to respond
 *
 * RESULTS
 *              0               successfully signalled condition to all
 *                              waiting threads,
 *              EINVAL          'cond' is invalid
 *              ENOSPC          a required resource has been exhausted,
 *
 * ------------------------------------------------------
 */
{
	/*
	 * The TRUE unblockAll arg means unblock ALL waiters.
	 */
	return (ptw32_cond_unblock(cond, PTW32_TRUE));

}				/* pthread_cond_broadcast */
/*
 * pthread_cond_wait.c
 *
 * Description:
 * This translation unit implements condition variables and their primitives.
 *
 *
 * --------------------------------------------------------------------------
 *
 *      Pthreads-win32 - POSIX Threads Library for Win32
 *      Copyright(C) 1998 John E. Bossom
 *      Copyright(C) 1999,2005 Pthreads-win32 contributors
 *
 *      Contact Email: rpj@callisto.canberra.edu.au
 *
 *      The current list of contributors is contained
 *      in the file CONTRIBUTORS included with the source
 *      code distribution. The list can also be seen at the
 *      following World Wide Web location:
 *      http://sources.redhat.com/pthreads-win32/contributors.html
 *
 *      This library is free software; you can redistribute it and/or
 *      modify it under the terms of the GNU Lesser General Public
 *      License as published by the Free Software Foundation; either
 *      version 2 of the License, or (at your option) any later version.
 *
 *      This library is distributed in the hope that it will be useful,
 *      but WITHOUT ANY WARRANTY; without even the implied warranty of
 *      MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *      Lesser General Public License for more details.
 *
 *      You should have received a copy of the GNU Lesser General Public
 *      License along with this library in the file COPYING.LIB;
 *      if not, write to the Free Software Foundation, Inc.,
 *      59 Temple Place - Suite 330, Boston, MA 02111-1307, USA
 *
 * -------------------------------------------------------------
 * Algorithm:
 * The algorithm used in this implementation is that developed by
 * Alexander Terekhov in colaboration with Louis Thomas. The bulk
 * of the discussion is recorded in the file README.CV, which contains
 * several generations of both colaborators original algorithms. The final
 * algorithm used here is the one referred to as
 *
 *     Algorithm 8a / IMPL_SEM,UNBLOCK_STRATEGY == UNBLOCK_ALL
 *
 * presented below in pseudo-code as it appeared:
 *
 *
 * given:
 * semBlockLock - bin.semaphore
 * semBlockQueue - semaphore
 * mtxExternal - mutex or CS
 * mtxUnblockLock - mutex or CS
 * nWaitersGone - int
 * nWaitersBlocked - int
 * nWaitersToUnblock - int
 *
 * wait( timeout ) {
 *
 *   [auto: register int result          ]     // error checking omitted
 *   [auto: register int nSignalsWasLeft ]
 *   [auto: register int nWaitersWasGone ]
 *
 *   sem_wait( semBlockLock );
 *   nWaitersBlocked++;
 *   sem_post( semBlockLock );
 *
 *   unlock( mtxExternal );
 *   bTimedOut = sem_wait( semBlockQueue,timeout );
 *
 *   lock( mtxUnblockLock );
 *   if ( 0 != (nSignalsWasLeft = nWaitersToUnblock) ) {
 *     if ( bTimeout ) {                       // timeout (or canceled)
 *       if ( 0 != nWaitersBlocked ) {
 *         nWaitersBlocked--;
 *       }
 *       else {
 *         nWaitersGone++;                     // count spurious wakeups.
 *       }
 *     }
 *     if ( 0 == --nWaitersToUnblock ) {
 *       if ( 0 != nWaitersBlocked ) {
 *         sem_post( semBlockLock );           // open the gate.
 *         nSignalsWasLeft = 0;                // do not open the gate
 *                                             // below again.
 *       }
 *       else if ( 0 != (nWaitersWasGone = nWaitersGone) ) {
 *         nWaitersGone = 0;
 *       }
 *     }
 *   }
 *   else if ( INT_MAX/2 == ++nWaitersGone ) { // timeout/canceled or
 *                                             // spurious semaphore :-)
 *     sem_wait( semBlockLock );
 *     nWaitersBlocked -= nWaitersGone;     // something is going on here
 *                                          //  - test of timeouts? :-)
 *     sem_post( semBlockLock );
 *     nWaitersGone = 0;
 *   }
 *   unlock( mtxUnblockLock );
 *
 *   if ( 1 == nSignalsWasLeft ) {
 *     if ( 0 != nWaitersWasGone ) {
 *       // sem_adjust( semBlockQueue,-nWaitersWasGone );
 *       while ( nWaitersWasGone-- ) {
 *         sem_wait( semBlockQueue );       // better now than spurious later
 *       }
 *     } sem_post( semBlockLock );          // open the gate
 *   }
 *
 *   lock( mtxExternal );
 *
 *   return ( bTimedOut ) ? ETIMEOUT : 0;
 * }
 *
 * signal(bAll) {
 *
 *   [auto: register int result         ]
 *   [auto: register int nSignalsToIssue]
 *
 *   lock( mtxUnblockLock );
 *
 *   if ( 0 != nWaitersToUnblock ) {        // the gate is closed!!!
 *     if ( 0 == nWaitersBlocked ) {        // NO-OP
 *       return unlock( mtxUnblockLock );
 *     }
 *     if (bAll) {
 *       nWaitersToUnblock += nSignalsToIssue=nWaitersBlocked;
 *       nWaitersBlocked = 0;
 *     }
 *     else {
 *       nSignalsToIssue = 1;
 *       nWaitersToUnblock++;
 *       nWaitersBlocked--;
 *     }
 *   }
 *   else if ( nWaitersBlocked > nWaitersGone ) { // HARMLESS RACE CONDITION!
 *     sem_wait( semBlockLock );                  // close the gate
 *     if ( 0 != nWaitersGone ) {
 *       nWaitersBlocked -= nWaitersGone;
 *       nWaitersGone = 0;
 *     }
 *     if (bAll) {
 *       nSignalsToIssue = nWaitersToUnblock = nWaitersBlocked;
 *       nWaitersBlocked = 0;
 *     }
 *     else {
 *       nSignalsToIssue = nWaitersToUnblock = 1;
 *       nWaitersBlocked--;
 *     }
 *   }
 *   else { // NO-OP
 *     return unlock( mtxUnblockLock );
 *   }
 *
 *   unlock( mtxUnblockLock );
 *   sem_post( semBlockQueue,nSignalsToIssue );
 *   return result;
 * }
 * -------------------------------------------------------------
 *
 *     Algorithm 9 / IMPL_SEM,UNBLOCK_STRATEGY == UNBLOCK_ALL
 *
 * presented below in pseudo-code; basically 8a...
 *                                      ...BUT W/O "spurious wakes" prevention:
 *
 *
 * given:
 * semBlockLock - bin.semaphore
 * semBlockQueue - semaphore
 * mtxExternal - mutex or CS
 * mtxUnblockLock - mutex or CS
 * nWaitersGone - int
 * nWaitersBlocked - int
 * nWaitersToUnblock - int
 *
 * wait( timeout ) {
 *
 *   [auto: register int result          ]     // error checking omitted
 *   [auto: register int nSignalsWasLeft ]
 *
 *   sem_wait( semBlockLock );
 *   ++nWaitersBlocked;
 *   sem_post( semBlockLock );
 *
 *   unlock( mtxExternal );
 *   bTimedOut = sem_wait( semBlockQueue,timeout );
 *
 *   lock( mtxUnblockLock );
 *   if ( 0 != (nSignalsWasLeft = nWaitersToUnblock) ) {
 *     --nWaitersToUnblock;
 *   }
 *   else if ( INT_MAX/2 == ++nWaitersGone ) { // timeout/canceled or
 *                                             // spurious semaphore :-)
 *     sem_wait( semBlockLock );
 *     nWaitersBlocked -= nWaitersGone;        // something is going on here
 *                                             //  - test of timeouts? :-)
 *     sem_post( semBlockLock );
 *     nWaitersGone = 0;
 *   }
 *   unlock( mtxUnblockLock );
 *
 *   if ( 1 == nSignalsWasLeft ) {
 *     sem_post( semBlockLock );               // open the gate
 *   }
 *
 *   lock( mtxExternal );
 *
 *   return ( bTimedOut ) ? ETIMEOUT : 0;
 * }
 *
 * signal(bAll) {
 *
 *   [auto: register int result         ]
 *   [auto: register int nSignalsToIssue]
 *
 *   lock( mtxUnblockLock );
 *
 *   if ( 0 != nWaitersToUnblock ) {        // the gate is closed!!!
 *     if ( 0 == nWaitersBlocked ) {        // NO-OP
 *       return unlock( mtxUnblockLock );
 *     }
 *     if (bAll) {
 *       nWaitersToUnblock += nSignalsToIssue=nWaitersBlocked;
 *       nWaitersBlocked = 0;
 *     }
 *     else {
 *       nSignalsToIssue = 1;
 *       ++nWaitersToUnblock;
 *       --nWaitersBlocked;
 *     }
 *   }
 *   else if ( nWaitersBlocked > nWaitersGone ) { // HARMLESS RACE CONDITION!
 *     sem_wait( semBlockLock );                  // close the gate
 *     if ( 0 != nWaitersGone ) {
 *       nWaitersBlocked -= nWaitersGone;
 *       nWaitersGone = 0;
 *     }
 *     if (bAll) {
 *       nSignalsToIssue = nWaitersToUnblock = nWaitersBlocked;
 *       nWaitersBlocked = 0;
 *     }
 *     else {
 *       nSignalsToIssue = nWaitersToUnblock = 1;
 *       --nWaitersBlocked;
 *     }
 *   }
 *   else { // NO-OP
 *     return unlock( mtxUnblockLock );
 *   }
 *
 *   unlock( mtxUnblockLock );
 *   sem_post( semBlockQueue,nSignalsToIssue );
 *   return result;
 * }
 * -------------------------------------------------------------
 *
 */


 /*
  * Arguments for cond_wait_cleanup, since we can only pass a
  * single void * to it.
  */
typedef struct
{
	pthread_mutex_t *mutexPtr;
	pthread_cond_t cv;
	int *resultPtr;
} ptw32_cond_wait_cleanup_args_t;

static void PTW32_CDECL
ptw32_cond_wait_cleanup(void *args)
{
	ptw32_cond_wait_cleanup_args_t *cleanup_args =
		(ptw32_cond_wait_cleanup_args_t *)args;
	pthread_cond_t cv = cleanup_args->cv;
	int *resultPtr = cleanup_args->resultPtr;
	int nSignalsWasLeft;
	int result;

	/*
	 * Whether we got here as a result of signal/broadcast or because of
	 * timeout on wait or thread cancellation we indicate that we are no
	 * longer waiting. The waiter is responsible for adjusting waiters
	 * (to)unblock(ed) counts (protected by unblock lock).
	 */
	if ((result = pthread_mutex_lock(&(cv->mtxUnblockLock))) != 0)
	{
		*resultPtr = result;
		return;
	}

	if (0 != (nSignalsWasLeft = cv->nWaitersToUnblock))
	{
		--(cv->nWaitersToUnblock);
	}
	else if (INT_MAX / 2 == ++(cv->nWaitersGone))
	{
		/* Use the non-cancellable version of sem_wait() */
		if (ptw32_semwait(&(cv->semBlockLock)) != 0)
		{
			*resultPtr = errno;
			/*
			 * This is a fatal error for this CV,
			 * so we deliberately don't unlock
			 * cv->mtxUnblockLock before returning.
			 */
			return;
		}
		cv->nWaitersBlocked -= cv->nWaitersGone;
		if (sem_post(&(cv->semBlockLock)) != 0)
		{
			*resultPtr = errno;
			/*
			 * This is a fatal error for this CV,
			 * so we deliberately don't unlock
			 * cv->mtxUnblockLock before returning.
			 */
			return;
		}
		cv->nWaitersGone = 0;
	}

	if ((result = pthread_mutex_unlock(&(cv->mtxUnblockLock))) != 0)
	{
		*resultPtr = result;
		return;
	}

	if (1 == nSignalsWasLeft)
	{
		if (sem_post(&(cv->semBlockLock)) != 0)
		{
			*resultPtr = errno;
			return;
		}
	}

	/*
	 * XSH: Upon successful return, the mutex has been locked and is owned
	 * by the calling thread.
	 */
	if ((result = pthread_mutex_lock(cleanup_args->mutexPtr)) != 0)
	{
		*resultPtr = result;
	}
}				/* ptw32_cond_wait_cleanup */

static INLINE int
ptw32_cond_timedwait(pthread_cond_t * cond,
	pthread_mutex_t * mutex, const struct timespec *abstime)
{
	int result = 0;
	pthread_cond_t cv;
	ptw32_cond_wait_cleanup_args_t cleanup_args;

	if (cond == NULL || *cond == NULL)
	{
		return EINVAL;
	}

	/*
	 * We do a quick check to see if we need to do more work
	 * to initialise a static condition variable. We check
	 * again inside the guarded section of ptw32_cond_check_need_init()
	 * to avoid race conditions.
	 */
	if (*cond == PTHREAD_COND_INITIALIZER)
	{
		result = ptw32_cond_check_need_init(cond);
	}

	if (result != 0 && result != EBUSY)
	{
		return result;
	}

	cv = *cond;

	/* Thread can be cancelled in sem_wait() but this is OK */
	if (sem_wait(&(cv->semBlockLock)) != 0)
	{
		return errno;
	}

	++(cv->nWaitersBlocked);

	if (sem_post(&(cv->semBlockLock)) != 0)
	{
		return errno;
	}

	/*
	 * Setup this waiter cleanup handler
	 */
	cleanup_args.mutexPtr = mutex;
	cleanup_args.cv = cv;
	cleanup_args.resultPtr = &result;

#if defined(_MSC_VER) && _MSC_VER < 1400
#pragma inline_depth(0)
#endif
	pthread_cleanup_push(ptw32_cond_wait_cleanup, (void *)&cleanup_args);

	/*
	 * Now we can release 'mutex' and...
	 */
	if ((result = pthread_mutex_unlock(mutex)) == 0)
	{

		/*
		 * ...wait to be awakened by
		 *              pthread_cond_signal, or
		 *              pthread_cond_broadcast, or
		 *              timeout, or
		 *              thread cancellation
		 *
		 * Note:
		 *
		 *      sem_timedwait is a cancellation point,
		 *      hence providing the mechanism for making
		 *      pthread_cond_wait a cancellation point.
		 *      We use the cleanup mechanism to ensure we
		 *      re-lock the mutex and adjust (to)unblock(ed) waiters
		 *      counts if we are cancelled, timed out or signalled.
		 */
		if (sem_timedwait(&(cv->semBlockQueue), abstime) != 0)
		{
			result = errno;
		}
	}

	/*
	 * Always cleanup
	 */
	pthread_cleanup_pop(1);
#if defined(_MSC_VER) && _MSC_VER < 1400
#pragma inline_depth()
#endif

	/*
	 * "result" can be modified by the cleanup handler.
	 */
	return result;

}				/* ptw32_cond_timedwait */


int
pthread_cond_wait(pthread_cond_t * cond, pthread_mutex_t * mutex)
/*
 * ------------------------------------------------------
 * DOCPUBLIC
 *      This function waits on a condition variable until
 *      awakened by a signal or broadcast.
 *
 *      Caller MUST be holding the mutex lock; the
 *      lock is released and the caller is blocked waiting
 *      on 'cond'. When 'cond' is signaled, the mutex
 *      is re-acquired before returning to the caller.
 *
 * PARAMETERS
 *      cond
 *              pointer to an instance of pthread_cond_t
 *
 *      mutex
 *              pointer to an instance of pthread_mutex_t
 *
 *
 * DESCRIPTION
 *      This function waits on a condition variable until
 *      awakened by a signal or broadcast.
 *
 *      NOTES:
 *
 *      1)      The function must be called with 'mutex' LOCKED
 *              by the calling thread, or undefined behaviour
 *              will result.
 *
 *      2)      This routine atomically releases 'mutex' and causes
 *              the calling thread to block on the condition variable.
 *              The blocked thread may be awakened by
 *                      pthread_cond_signal or
 *                      pthread_cond_broadcast.
 *
 * Upon successful completion, the 'mutex' has been locked and
 * is owned by the calling thread.
 *
 *
 * RESULTS
 *              0               caught condition; mutex released,
 *              EINVAL          'cond' or 'mutex' is invalid,
 *              EINVAL          different mutexes for concurrent waits,
 *              EINVAL          mutex is not held by the calling thread,
 *
 * ------------------------------------------------------
 */
{
	/*
	 * The NULL abstime arg means INFINITE waiting.
	 */
	return (ptw32_cond_timedwait(cond, mutex, NULL));

}				/* pthread_cond_wait */


int
pthread_cond_timedwait(pthread_cond_t * cond,
	pthread_mutex_t * mutex,
	const struct timespec *abstime)
	/*
	 * ------------------------------------------------------
	 * DOCPUBLIC
	 *      This function waits on a condition variable either until
	 *      awakened by a signal or broadcast; or until the time
	 *      specified by abstime passes.
	 *
	 * PARAMETERS
	 *      cond
	 *              pointer to an instance of pthread_cond_t
	 *
	 *      mutex
	 *              pointer to an instance of pthread_mutex_t
	 *
	 *      abstime
	 *              pointer to an instance of (const struct timespec)
	 *
	 *
	 * DESCRIPTION
	 *      This function waits on a condition variable either until
	 *      awakened by a signal or broadcast; or until the time
	 *      specified by abstime passes.
	 *
	 *      NOTES:
	 *      1)      The function must be called with 'mutex' LOCKED
	 *              by the calling thread, or undefined behaviour
	 *              will result.
	 *
	 *      2)      This routine atomically releases 'mutex' and causes
	 *              the calling thread to block on the condition variable.
	 *              The blocked thread may be awakened by
	 *                      pthread_cond_signal or
	 *                      pthread_cond_broadcast.
	 *
	 *
	 * RESULTS
	 *              0               caught condition; mutex released,
	 *              EINVAL          'cond', 'mutex', or abstime is invalid,
	 *              EINVAL          different mutexes for concurrent waits,
	 *              EINVAL          mutex is not held by the calling thread,
	 *              ETIMEDOUT       abstime ellapsed before cond was signaled.
	 *
	 * ------------------------------------------------------
	 */
{
	if (abstime == NULL)
	{
		return EINVAL;
	}

	return (ptw32_cond_timedwait(cond, mutex, abstime));

}				/* pthread_cond_timedwait */
/*
 * pthreads_delay_np.c
 *
 * Description:
 * This translation unit implements non-portable thread functions.
 *
 * --------------------------------------------------------------------------
 *
 *      Pthreads-win32 - POSIX Threads Library for Win32
 *      Copyright(C) 1998 John E. Bossom
 *      Copyright(C) 1999,2005 Pthreads-win32 contributors
 *
 *      Contact Email: rpj@callisto.canberra.edu.au
 *
 *      The current list of contributors is contained
 *      in the file CONTRIBUTORS included with the source
 *      code distribution. The list can also be seen at the
 *      following World Wide Web location:
 *      http://sources.redhat.com/pthreads-win32/contributors.html
 *
 *      This library is free software; you can redistribute it and/or
 *      modify it under the terms of the GNU Lesser General Public
 *      License as published by the Free Software Foundation; either
 *      version 2 of the License, or (at your option) any later version.
 *
 *      This library is distributed in the hope that it will be useful,
 *      but WITHOUT ANY WARRANTY; without even the implied warranty of
 *      MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *      Lesser General Public License for more details.
 *
 *      You should have received a copy of the GNU Lesser General Public
 *      License along with this library in the file COPYING.LIB;
 *      if not, write to the Free Software Foundation, Inc.,
 *      59 Temple Place - Suite 330, Boston, MA 02111-1307, USA
 */


 /*
  * pthread_delay_np
  *
  * DESCRIPTION
  *
  *       This routine causes a thread to delay execution for a specific period of time.
  *       This period ends at the current time plus the specified interval. The routine
  *       will not return before the end of the period is reached, but may return an
  *       arbitrary amount of time after the period has gone by. This can be due to
  *       system load, thread priorities, and system timer granularity.
  *
  *       Specifying an interval of zero (0) seconds and zero (0) nanoseconds is
  *       allowed and can be used to force the thread to give up the processor or to
  *       deliver a pending cancelation request.
  *
  *       The timespec structure contains the following two fields:
  *
  *            tv_sec is an integer number of seconds.
  *            tv_nsec is an integer number of nanoseconds.
  *
  *  Return Values
  *
  *  If an error condition occurs, this routine returns an integer value indicating
  *  the type of error. Possible return values are as follows:
  *
  *  0
  *           Successful completion.
  *  [EINVAL]
  *           The value specified by interval is invalid.
  *
  * Example
  *
  * The following code segment would wait for 5 and 1/2 seconds
  *
  *  struct timespec tsWait;
  *  int      intRC;
  *
  *  tsWait.tv_sec  = 5;
  *  tsWait.tv_nsec = 500000000L;
  *  intRC = pthread_delay_np(&tsWait);
  */
int
pthread_delay_np(struct timespec *interval)
{
	DWORD wait_time;
	DWORD secs_in_millisecs;
	DWORD millisecs;
	DWORD status;
	pthread_t self;
	ptw32_thread_t * sp;

	if (interval == NULL)
	{
		return EINVAL;
	}

	if (interval->tv_sec == 0L && interval->tv_nsec == 0L)
	{
		pthread_testcancel();
		Sleep(0);
		pthread_testcancel();
		return (0);
	}

	/* convert secs to millisecs */
	secs_in_millisecs = (DWORD)interval->tv_sec * 1000L;

	/* convert nanosecs to millisecs (rounding up) */
	millisecs = (interval->tv_nsec + 999999L) / 1000000L;

#if defined(__WATCOMC__)
#pragma disable_message (124)
#endif

	/*
	 * Most compilers will issue a warning 'comparison always 0'
	 * because the variable type is unsigned, but we need to keep this
	 * for some reason I can't recall now.
	 */
	if (0 > (wait_time = secs_in_millisecs + millisecs))
	{
		return EINVAL;
	}

#if defined(__WATCOMC__)
#pragma enable_message (124)
#endif

	if (NULL == (self = pthread_self()).p)
	{
		return ENOMEM;
	}

	sp = (ptw32_thread_t *)self.p;

	if (sp->cancelState == PTHREAD_CANCEL_ENABLE)
	{
		/*
		 * Async cancelation won't catch us until wait_time is up.
		 * Deferred cancelation will cancel us immediately.
		 */
		if (WAIT_OBJECT_0 ==
			(status = WaitForSingleObject(sp->cancelEvent, wait_time)))
		{
			ptw32_mcs_local_node_t stateLock;
			/*
			 * Canceling!
			 */
			ptw32_mcs_lock_acquire(&sp->stateLock, &stateLock);
			if (sp->state < PThreadStateCanceling)
			{
				sp->state = PThreadStateCanceling;
				sp->cancelState = PTHREAD_CANCEL_DISABLE;
				ptw32_mcs_lock_release(&stateLock);

				ptw32_throw(PTW32_EPS_CANCEL);
			}

			ptw32_mcs_lock_release(&stateLock);
			return ESRCH;
		}
		else if (status != WAIT_TIMEOUT)
		{
			return EINVAL;
		}
	}
	else
	{
		Sleep(wait_time);
	}

	return (0);
}
/*
 * pthread_detach.c
 *
 * Description:
 * This translation unit implements functions related to thread
 * synchronisation.
 *
 * --------------------------------------------------------------------------
 *
 *      Pthreads-win32 - POSIX Threads Library for Win32
 *      Copyright(C) 1998 John E. Bossom
 *      Copyright(C) 1999,2005 Pthreads-win32 contributors
 *
 *      Contact Email: rpj@callisto.canberra.edu.au
 *
 *      The current list of contributors is contained
 *      in the file CONTRIBUTORS included with the source
 *      code distribution. The list can also be seen at the
 *      following World Wide Web location:
 *      http://sources.redhat.com/pthreads-win32/contributors.html
 *
 *      This library is free software; you can redistribute it and/or
 *      modify it under the terms of the GNU Lesser General Public
 *      License as published by the Free Software Foundation; either
 *      version 2 of the License, or (at your option) any later version.
 *
 *      This library is distributed in the hope that it will be useful,
 *      but WITHOUT ANY WARRANTY; without even the implied warranty of
 *      MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *      Lesser General Public License for more details.
 *
 *      You should have received a copy of the GNU Lesser General Public
 *      License along with this library in the file COPYING.LIB;
 *      if not, write to the Free Software Foundation, Inc.,
 *      59 Temple Place - Suite 330, Boston, MA 02111-1307, USA
 */


 /*
  * Not needed yet, but defining it should indicate clashes with build target
  * environment that should be fixed.
  */
#if !defined(WINCE)
#  include <signal.h>
#endif


int
pthread_detach(pthread_t thread)
/*
 * ------------------------------------------------------
 * DOCPUBLIC
 *      This function detaches the given thread.
 *
 * PARAMETERS
 *      thread
 *              an instance of a pthread_t
 *
 *
 * DESCRIPTION
 *      This function detaches the given thread. You may use it to
 *      detach the main thread or to detach a joinable thread.
 *      NOTE:   detached threads cannot be joined;
 *              storage is freed immediately on termination.
 *
 * RESULTS
 *              0               successfully detached the thread,
 *              EINVAL          thread is not a joinable thread,
 *              ENOSPC          a required resource has been exhausted,
 *              ESRCH           no thread could be found for 'thread',
 *
 * ------------------------------------------------------
 */
{
	int result;
	BOOL destroyIt = PTW32_FALSE;
	ptw32_thread_t * tp = (ptw32_thread_t *)thread.p;
	ptw32_mcs_local_node_t node;

	ptw32_mcs_lock_acquire(&ptw32_thread_reuse_lock, &node);

	if (NULL == tp
		|| thread.x != tp->ptHandle.x)
	{
		result = ESRCH;
	}
	else if (PTHREAD_CREATE_DETACHED == tp->detachState)
	{
		result = EINVAL;
	}
	else
	{
		ptw32_mcs_local_node_t stateLock;
		/*
		 * Joinable ptw32_thread_t structs are not scavenged until
		 * a join or detach is done. The thread may have exited already,
		 * but all of the state and locks etc are still there.
		 */
		result = 0;

		ptw32_mcs_lock_acquire(&tp->stateLock, &stateLock);
		if (tp->state != PThreadStateLast)
		{
			tp->detachState = PTHREAD_CREATE_DETACHED;
		}
		else if (tp->detachState != PTHREAD_CREATE_DETACHED)
		{
			/*
			 * Thread is joinable and has exited or is exiting.
			 */
			destroyIt = PTW32_TRUE;
		}
		ptw32_mcs_lock_release(&stateLock);
	}

	ptw32_mcs_lock_release(&node);

	if (result == 0)
	{
		/* Thread is joinable */

		if (destroyIt)
		{
			/* The thread has exited or is exiting but has not been joined or
			 * detached. Need to wait in case it's still exiting.
			 */
			(void)WaitForSingleObject(tp->threadH, INFINITE);
			ptw32_threadDestroy(thread);
		}
	}

	return (result);

}				/* pthread_detach */
/*
 * pthread_equal.c
 *
 * Description:
 * This translation unit implements miscellaneous thread functions.
 *
 * --------------------------------------------------------------------------
 *
 *      Pthreads-win32 - POSIX Threads Library for Win32
 *      Copyright(C) 1998 John E. Bossom
 *      Copyright(C) 1999,2005 Pthreads-win32 contributors
 *
 *      Contact Email: rpj@callisto.canberra.edu.au
 *
 *      The current list of contributors is contained
 *      in the file CONTRIBUTORS included with the source
 *      code distribution. The list can also be seen at the
 *      following World Wide Web location:
 *      http://sources.redhat.com/pthreads-win32/contributors.html
 *
 *      This library is free software; you can redistribute it and/or
 *      modify it under the terms of the GNU Lesser General Public
 *      License as published by the Free Software Foundation; either
 *      version 2 of the License, or (at your option) any later version.
 *
 *      This library is distributed in the hope that it will be useful,
 *      but WITHOUT ANY WARRANTY; without even the implied warranty of
 *      MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *      Lesser General Public License for more details.
 *
 *      You should have received a copy of the GNU Lesser General Public
 *      License along with this library in the file COPYING.LIB;
 *      if not, write to the Free Software Foundation, Inc.,
 *      59 Temple Place - Suite 330, Boston, MA 02111-1307, USA
 */



int
pthread_equal(pthread_t t1, pthread_t t2)
/*
 * ------------------------------------------------------
 * DOCPUBLIC
 *      This function returns nonzero if t1 and t2 are equal, else
 *      returns zero
 *
 * PARAMETERS
 *      t1,
 *      t2
 *              thread IDs
 *
 *
 * DESCRIPTION
 *      This function returns nonzero if t1 and t2 are equal, else
 *      returns zero.
 *
 * RESULTS
 *              non-zero        if t1 and t2 refer to the same thread,
 *              0               t1 and t2 do not refer to the same thread
 *
 * ------------------------------------------------------
 */
{
	int result;

	/*
	 * We also accept NULL == NULL - treating NULL as a thread
	 * for this special case, because there is no error that we can return.
	 */
	result = (t1.p == t2.p && t1.x == t2.x);

	return (result);

}				/* pthread_equal */
/*
 * pthread_exit.c
 *
 * Description:
 * This translation unit implements routines associated with exiting from
 * a thread.
 *
 * --------------------------------------------------------------------------
 *
 *      Pthreads-win32 - POSIX Threads Library for Win32
 *      Copyright(C) 1998 John E. Bossom
 *      Copyright(C) 1999,2005 Pthreads-win32 contributors
 *
 *      Contact Email: rpj@callisto.canberra.edu.au
 *
 *      The current list of contributors is contained
 *      in the file CONTRIBUTORS included with the source
 *      code distribution. The list can also be seen at the
 *      following World Wide Web location:
 *      http://sources.redhat.com/pthreads-win32/contributors.html
 *
 *      This library is free software; you can redistribute it and/or
 *      modify it under the terms of the GNU Lesser General Public
 *      License as published by the Free Software Foundation; either
 *      version 2 of the License, or (at your option) any later version.
 *
 *      This library is distributed in the hope that it will be useful,
 *      but WITHOUT ANY WARRANTY; without even the implied warranty of
 *      MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *      Lesser General Public License for more details.
 *
 *      You should have received a copy of the GNU Lesser General Public
 *      License along with this library in the file COPYING.LIB;
 *      if not, write to the Free Software Foundation, Inc.,
 *      59 Temple Place - Suite 330, Boston, MA 02111-1307, USA
 */

#if !defined(_UWIN)
 /*#   include <process.h> */
#endif

void
pthread_exit(void *value_ptr)
/*
 * ------------------------------------------------------
 * DOCPUBLIC
 *      This function terminates the calling thread, returning
 *      the value 'value_ptr' to any joining thread.
 *
 * PARAMETERS
 *      value_ptr
 *              a generic data value (i.e. not the address of a value)
 *
 *
 * DESCRIPTION
 *      This function terminates the calling thread, returning
 *      the value 'value_ptr' to any joining thread.
 *      NOTE: thread should be joinable.
 *
 * RESULTS
 *              N/A
 *
 * ------------------------------------------------------
 */
{
	ptw32_thread_t * sp;

	/*
	 * Don't use pthread_self() to avoid creating an implicit POSIX thread handle
	 * unnecessarily.
	 */
	sp = (ptw32_thread_t *)pthread_getspecific(ptw32_selfThreadKey);

#if defined(_UWIN)
	if (--pthread_count <= 0)
		exit((int)value_ptr);
#endif

	if (NULL == sp)
	{
		/*
		 * A POSIX thread handle was never created. I.e. this is a
		 * Win32 thread that has never called a pthreads-win32 routine that
		 * required a POSIX handle.
		 *
		 * Implicit POSIX handles are cleaned up in ptw32_throw() now.
		 */

#if ! (defined (__MINGW64__) || defined(__MINGW32__)) || defined (__MSVCRT__)  || defined (__DMC__)
		_endthreadex((unsigned)(size_t)value_ptr);
#else
		_endthread();
#endif

		/* Never reached */
	}

	sp->exitStatus = value_ptr;

	ptw32_throw(PTW32_EPS_EXIT);

	/* Never reached. */

}
/*
 * pthread_getconcurrency.c
 *
 * Description:
 * This translation unit implements miscellaneous thread functions.
 *
 * --------------------------------------------------------------------------
 *
 *      Pthreads-win32 - POSIX Threads Library for Win32
 *      Copyright(C) 1998 John E. Bossom
 *      Copyright(C) 1999,2005 Pthreads-win32 contributors
 *
 *      Contact Email: rpj@callisto.canberra.edu.au
 *
 *      The current list of contributors is contained
 *      in the file CONTRIBUTORS included with the source
 *      code distribution. The list can also be seen at the
 *      following World Wide Web location:
 *      http://sources.redhat.com/pthreads-win32/contributors.html
 *
 *      This library is free software; you can redistribute it and/or
 *      modify it under the terms of the GNU Lesser General Public
 *      License as published by the Free Software Foundation; either
 *      version 2 of the License, or (at your option) any later version.
 *
 *      This library is distributed in the hope that it will be useful,
 *      but WITHOUT ANY WARRANTY; without even the implied warranty of
 *      MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *      Lesser General Public License for more details.
 *
 *      You should have received a copy of the GNU Lesser General Public
 *      License along with this library in the file COPYING.LIB;
 *      if not, write to the Free Software Foundation, Inc.,
 *      59 Temple Place - Suite 330, Boston, MA 02111-1307, USA
 */



int
pthread_getconcurrency(void)
{
	return ptw32_concurrency;
}
/*
 * sched_getschedparam.c
 *
 * Description:
 * POSIX thread functions that deal with thread scheduling.
 *
 * --------------------------------------------------------------------------
 *
 *      Pthreads-win32 - POSIX Threads Library for Win32
 *      Copyright(C) 1998 John E. Bossom
 *      Copyright(C) 1999,2005 Pthreads-win32 contributors
 *
 *      Contact Email: rpj@callisto.canberra.edu.au
 *
 *      The current list of contributors is contained
 *      in the file CONTRIBUTORS included with the source
 *      code distribution. The list can also be seen at the
 *      following World Wide Web location:
 *      http://sources.redhat.com/pthreads-win32/contributors.html
 *
 *      This library is free software; you can redistribute it and/or
 *      modify it under the terms of the GNU Lesser General Public
 *      License as published by the Free Software Foundation; either
 *      version 2 of the License, or (at your option) any later version.
 *
 *      This library is distributed in the hope that it will be useful,
 *      but WITHOUT ANY WARRANTY; without even the implied warranty of
 *      MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *      Lesser General Public License for more details.
 *
 *      You should have received a copy of the GNU Lesser General Public
 *      License along with this library in the file COPYING.LIB;
 *      if not, write to the Free Software Foundation, Inc.,
 *      59 Temple Place - Suite 330, Boston, MA 02111-1307, USA
 */


int
pthread_getschedparam(pthread_t thread, int *policy,
	struct sched_param *param)
{
	int result;

	/* Validate the thread id. */
	result = pthread_kill(thread, 0);
	if (0 != result)
	{
		return result;
	}

	/*
	 * Validate the policy and param args.
	 * Check that a policy constant wasn't passed rather than &policy.
	 */
	if (policy <= (int *)SCHED_MAX || param == NULL)
	{
		return EINVAL;
	}

	/* Fill out the policy. */
	*policy = SCHED_OTHER;

	/*
	 * This function must return the priority value set by
	 * the most recent pthread_setschedparam() or pthread_create()
	 * for the target thread. It must not return the actual thread
	 * priority as altered by any system priority adjustments etc.
	 */
	param->sched_priority = ((ptw32_thread_t *)thread.p)->sched_priority;

	return 0;
}
/*
 * pthread_getspecific.c
 *
 * Description:
 * POSIX thread functions which implement thread-specific data (TSD).
 *
 * --------------------------------------------------------------------------
 *
 *      Pthreads-win32 - POSIX Threads Library for Win32
 *      Copyright(C) 1998 John E. Bossom
 *      Copyright(C) 1999,2005 Pthreads-win32 contributors
 *
 *      Contact Email: rpj@callisto.canberra.edu.au
 *
 *      The current list of contributors is contained
 *      in the file CONTRIBUTORS included with the source
 *      code distribution. The list can also be seen at the
 *      following World Wide Web location:
 *      http://sources.redhat.com/pthreads-win32/contributors.html
 *
 *      This library is free software; you can redistribute it and/or
 *      modify it under the terms of the GNU Lesser General Public
 *      License as published by the Free Software Foundation; either
 *      version 2 of the License, or (at your option) any later version.
 *
 *      This library is distributed in the hope that it will be useful,
 *      but WITHOUT ANY WARRANTY; without even the implied warranty of
 *      MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *      Lesser General Public License for more details.
 *
 *      You should have received a copy of the GNU Lesser General Public
 *      License along with this library in the file COPYING.LIB;
 *      if not, write to the Free Software Foundation, Inc.,
 *      59 Temple Place - Suite 330, Boston, MA 02111-1307, USA
 */



void *
pthread_getspecific(pthread_key_t key)
/*
 * ------------------------------------------------------
 * DOCPUBLIC
 *      This function returns the current value of key in the
 *      calling thread. If no value has been set for 'key' in
 *      the thread, NULL is returned.
 *
 * PARAMETERS
 *      key
 *              an instance of pthread_key_t
 *
 *
 * DESCRIPTION
 *      This function returns the current value of key in the
 *      calling thread. If no value has been set for 'key' in
 *      the thread, NULL is returned.
 *
 * RESULTS
 *              key value or NULL on failure
 *
 * ------------------------------------------------------
 */
{
	void * ptr;

	if (key == NULL)
	{
		ptr = NULL;
	}
	else
	{
		int lasterror = GetLastError();
#if defined(RETAIN_WSALASTERROR)
		int lastWSAerror = WSAGetLastError();
#endif
		ptr = TlsGetValue(key->key);

		SetLastError(lasterror);
#if defined(RETAIN_WSALASTERROR)
		WSASetLastError(lastWSAerror);
#endif
	}

	return ptr;
}
/*
 * pthread_getunique_np.c
 *
 * Description:
 * This translation unit implements non-portable thread functions.
 *
 * --------------------------------------------------------------------------
 *
 *      Pthreads-win32 - POSIX Threads Library for Win32
 *      Copyright(C) 1998 John E. Bossom
 *      Copyright(C) 1999,2005 Pthreads-win32 contributors
 *
 *      Contact Email: rpj@callisto.canberra.edu.au
 *
 *      The current list of contributors is contained
 *      in the file CONTRIBUTORS included with the source
 *      code distribution. The list can also be seen at the
 *      following World Wide Web location:
 *      http://sources.redhat.com/pthreads-win32/contributors.html
 *
 *      This library is free software; you can redistribute it and/or
 *      modify it under the terms of the GNU Lesser General Public
 *      License as published by the Free Software Foundation; either
 *      version 2 of the License, or (at your option) any later version.
 *
 *      This library is distributed in the hope that it will be useful,
 *      but WITHOUT ANY WARRANTY; without even the implied warranty of
 *      MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *      Lesser General Public License for more details.
 *
 *      You should have received a copy of the GNU Lesser General Public
 *      License along with this library in the file COPYING.LIB;
 *      if not, write to the Free Software Foundation, Inc.,
 *      59 Temple Place - Suite 330, Boston, MA 02111-1307, USA
 */


 /*
  *
  */
unsigned __int64
pthread_getunique_np(pthread_t thread)
{
	return ((ptw32_thread_t*)thread.p)->seqNumber;
}
/*
 * pthread_getw32threadhandle_np.c
 *
 * Description:
 * This translation unit implements non-portable thread functions.
 *
 * --------------------------------------------------------------------------
 *
 *      Pthreads-win32 - POSIX Threads Library for Win32
 *      Copyright(C) 1998 John E. Bossom
 *      Copyright(C) 1999,2005 Pthreads-win32 contributors
 *
 *      Contact Email: rpj@callisto.canberra.edu.au
 *
 *      The current list of contributors is contained
 *      in the file CONTRIBUTORS included with the source
 *      code distribution. The list can also be seen at the
 *      following World Wide Web location:
 *      http://sources.redhat.com/pthreads-win32/contributors.html
 *
 *      This library is free software; you can redistribute it and/or
 *      modify it under the terms of the GNU Lesser General Public
 *      License as published by the Free Software Foundation; either
 *      version 2 of the License, or (at your option) any later version.
 *
 *      This library is distributed in the hope that it will be useful,
 *      but WITHOUT ANY WARRANTY; without even the implied warranty of
 *      MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *      Lesser General Public License for more details.
 *
 *      You should have received a copy of the GNU Lesser General Public
 *      License along with this library in the file COPYING.LIB;
 *      if not, write to the Free Software Foundation, Inc.,
 *      59 Temple Place - Suite 330, Boston, MA 02111-1307, USA
 */


 /*
  * pthread_getw32threadhandle_np()
  *
  * Returns the win32 thread handle that the POSIX
  * thread "thread" is running as.
  *
  * Applications can use the win32 handle to set
  * win32 specific attributes of the thread.
  */
HANDLE
pthread_getw32threadhandle_np(pthread_t thread)
{
	return ((ptw32_thread_t *)thread.p)->threadH;
}

/*
 * pthread_getw32threadid_np()
 *
 * Returns the win32 thread id that the POSIX
 * thread "thread" is running as.
 */
DWORD
pthread_getw32threadid_np(pthread_t thread)
{
	return ((ptw32_thread_t *)thread.p)->thread;
}
/*
 * pthread_join.c
 *
 * Description:
 * This translation unit implements functions related to thread
 * synchronisation.
 *
 * --------------------------------------------------------------------------
 *
 *      Pthreads-win32 - POSIX Threads Library for Win32
 *      Copyright(C) 1998 John E. Bossom
 *      Copyright(C) 1999,2005 Pthreads-win32 contributors
 *
 *      Contact Email: rpj@callisto.canberra.edu.au
 *
 *      The current list of contributors is contained
 *      in the file CONTRIBUTORS included with the source
 *      code distribution. The list can also be seen at the
 *      following World Wide Web location:
 *      http://sources.redhat.com/pthreads-win32/contributors.html
 *
 *      This library is free software; you can redistribute it and/or
 *      modify it under the terms of the GNU Lesser General Public
 *      License as published by the Free Software Foundation; either
 *      version 2 of the License, or (at your option) any later version.
 *
 *      This library is distributed in the hope that it will be useful,
 *      but WITHOUT ANY WARRANTY; without even the implied warranty of
 *      MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *      Lesser General Public License for more details.
 *
 *      You should have received a copy of the GNU Lesser General Public
 *      License along with this library in the file COPYING.LIB;
 *      if not, write to the Free Software Foundation, Inc.,
 *      59 Temple Place - Suite 330, Boston, MA 02111-1307, USA
 */


 /*
  * Not needed yet, but defining it should indicate clashes with build target
  * environment that should be fixed.
  */
#if !defined(WINCE)
#  include <signal.h>
#endif


int
pthread_join(pthread_t thread, void **value_ptr)
/*
 * ------------------------------------------------------
 * DOCPUBLIC
 *      This function waits for 'thread' to terminate and
 *      returns the thread's exit value if 'value_ptr' is not
 *      NULL. This also detaches the thread on successful
 *      completion.
 *
 * PARAMETERS
 *      thread
 *              an instance of pthread_t
 *
 *      value_ptr
 *              pointer to an instance of pointer to void
 *
 *
 * DESCRIPTION
 *      This function waits for 'thread' to terminate and
 *      returns the thread's exit value if 'value_ptr' is not
 *      NULL. This also detaches the thread on successful
 *      completion.
 *      NOTE:   detached threads cannot be joined or canceled
 *
 * RESULTS
 *              0               'thread' has completed
 *              EINVAL          thread is not a joinable thread,
 *              ESRCH           no thread could be found with ID 'thread',
 *              ENOENT          thread couldn't find it's own valid handle,
 *              EDEADLK         attempt to join thread with self
 *
 * ------------------------------------------------------
 */
{
	int result;
	pthread_t self;
	ptw32_thread_t * tp = (ptw32_thread_t *)thread.p;
	ptw32_mcs_local_node_t node;

	ptw32_mcs_lock_acquire(&ptw32_thread_reuse_lock, &node);

	if (NULL == tp
		|| thread.x != tp->ptHandle.x)
	{
		result = ESRCH;
	}
	else if (PTHREAD_CREATE_DETACHED == tp->detachState)
	{
		result = EINVAL;
	}
	else
	{
		result = 0;
	}

	ptw32_mcs_lock_release(&node);

	if (result == 0)
	{
		/*
		 * The target thread is joinable and can't be reused before we join it.
		 */
		self = pthread_self();

		if (NULL == self.p)
		{
			result = ENOENT;
		}
		else if (pthread_equal(self, thread))
		{
			result = EDEADLK;
		}
		else
		{
			/*
			 * Pthread_join is a cancelation point.
			 * If we are canceled then our target thread must not be
			 * detached (destroyed). This is guarranteed because
			 * pthreadCancelableWait will not return if we
			 * are canceled.
			 */
			result = pthreadCancelableWait(tp->threadH);

			if (0 == result)
			{
				if (value_ptr != NULL)
				{
					*value_ptr = tp->exitStatus;
				}

				/*
				 * The result of making multiple simultaneous calls to
				 * pthread_join() or pthread_detach() specifying the same
				 * target is undefined.
				 */
				result = pthread_detach(thread);
			}
			else
			{
				result = ESRCH;
			}
		}
	}

	return (result);

}				/* pthread_join */
/*
 * pthread_key_create.c
 *
 * Description:
 * POSIX thread functions which implement thread-specific data (TSD).
 *
 * --------------------------------------------------------------------------
 *
 *      Pthreads-win32 - POSIX Threads Library for Win32
 *      Copyright(C) 1998 John E. Bossom
 *      Copyright(C) 1999,2005 Pthreads-win32 contributors
 *
 *      Contact Email: rpj@callisto.canberra.edu.au
 *
 *      The current list of contributors is contained
 *      in the file CONTRIBUTORS included with the source
 *      code distribution. The list can also be seen at the
 *      following World Wide Web location:
 *      http://sources.redhat.com/pthreads-win32/contributors.html
 *
 *      This library is free software; you can redistribute it and/or
 *      modify it under the terms of the GNU Lesser General Public
 *      License as published by the Free Software Foundation; either
 *      version 2 of the License, or (at your option) any later version.
 *
 *      This library is distributed in the hope that it will be useful,
 *      but WITHOUT ANY WARRANTY; without even the implied warranty of
 *      MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *      Lesser General Public License for more details.
 *
 *      You should have received a copy of the GNU Lesser General Public
 *      License along with this library in the file COPYING.LIB;
 *      if not, write to the Free Software Foundation, Inc.,
 *      59 Temple Place - Suite 330, Boston, MA 02111-1307, USA
 */



 /* TLS_OUT_OF_INDEXES not defined on WinCE */
#if !defined(TLS_OUT_OF_INDEXES)
#define TLS_OUT_OF_INDEXES 0xffffffff
#endif

int
pthread_key_create(pthread_key_t * key, void (PTW32_CDECL *destructor) (void *))
/*
 * ------------------------------------------------------
 * DOCPUBLIC
 *      This function creates a thread-specific data key visible
 *      to all threads. All existing and new threads have a value
 *      NULL for key until set using pthread_setspecific. When any
 *      thread with a non-NULL value for key terminates, 'destructor'
 *      is called with key's current value for that thread.
 *
 * PARAMETERS
 *      key
 *              pointer to an instance of pthread_key_t
 *
 *
 * DESCRIPTION
 *      This function creates a thread-specific data key visible
 *      to all threads. All existing and new threads have a value
 *      NULL for key until set using pthread_setspecific. When any
 *      thread with a non-NULL value for key terminates, 'destructor'
 *      is called with key's current value for that thread.
 *
 * RESULTS
 *              0               successfully created semaphore,
 *              EAGAIN          insufficient resources or PTHREAD_KEYS_MAX
 *                              exceeded,
 *              ENOMEM          insufficient memory to create the key,
 *
 * ------------------------------------------------------
 */
{
	int result = 0;
	pthread_key_t newkey;

	if ((newkey = (pthread_key_t)calloc(1, sizeof(*newkey))) == NULL)
	{
		result = ENOMEM;
	}
	else if ((newkey->key = TlsAlloc()) == TLS_OUT_OF_INDEXES)
	{
		result = EAGAIN;

		free(newkey);
		newkey = NULL;
	}
	else if (destructor != NULL)
	{
		/*
		 * Have to manage associations between thread and key;
		 * Therefore, need a lock that allows competing threads
		 * to gain exclusive access to the key->threads list.
		 *
		 * The mutex will only be created when it is first locked.
		 */
		newkey->keyLock = 0;
		newkey->destructor = destructor;
	}

	*key = newkey;

	return (result);
}
/*
 * pthread_key_delete.c
 *
 * Description:
 * POSIX thread functions which implement thread-specific data (TSD).
 *
 * --------------------------------------------------------------------------
 *
 *      Pthreads-win32 - POSIX Threads Library for Win32
 *      Copyright(C) 1998 John E. Bossom
 *      Copyright(C) 1999,2005 Pthreads-win32 contributors
 *
 *      Contact Email: rpj@callisto.canberra.edu.au
 *
 *      The current list of contributors is contained
 *      in the file CONTRIBUTORS included with the source
 *      code distribution. The list can also be seen at the
 *      following World Wide Web location:
 *      http://sources.redhat.com/pthreads-win32/contributors.html
 *
 *      This library is free software; you can redistribute it and/or
 *      modify it under the terms of the GNU Lesser General Public
 *      License as published by the Free Software Foundation; either
 *      version 2 of the License, or (at your option) any later version.
 *
 *      This library is distributed in the hope that it will be useful,
 *      but WITHOUT ANY WARRANTY; without even the implied warranty of
 *      MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *      Lesser General Public License for more details.
 *
 *      You should have received a copy of the GNU Lesser General Public
 *      License along with this library in the file COPYING.LIB;
 *      if not, write to the Free Software Foundation, Inc.,
 *      59 Temple Place - Suite 330, Boston, MA 02111-1307, USA
 */



int
pthread_key_delete(pthread_key_t key)
/*
 * ------------------------------------------------------
 * DOCPUBLIC
 *      This function deletes a thread-specific data key. This
 *      does not change the value of the thread specific data key
 *      for any thread and does not run the key's destructor
 *      in any thread so it should be used with caution.
 *
 * PARAMETERS
 *      key
 *              pointer to an instance of pthread_key_t
 *
 *
 * DESCRIPTION
 *      This function deletes a thread-specific data key. This
 *      does not change the value of the thread specific data key
 *      for any thread and does not run the key's destructor
 *      in any thread so it should be used with caution.
 *
 * RESULTS
 *              0               successfully deleted the key,
 *              EINVAL          key is invalid,
 *
 * ------------------------------------------------------
 */
{
	ptw32_mcs_local_node_t keyLock;
	int result = 0;

	if (key != NULL)
	{
		if (key->threads != NULL && key->destructor != NULL)
		{
			ThreadKeyAssoc *assoc;
			ptw32_mcs_lock_acquire(&(key->keyLock), &keyLock);
			/*
			 * Run through all Thread<-->Key associations
			 * for this key.
			 *
			 * While we hold at least one of the locks guarding
			 * the assoc, we know that the assoc pointed to by
			 * key->threads is valid.
			 */
			while ((assoc = (ThreadKeyAssoc *)key->threads) != NULL)
			{
				ptw32_mcs_local_node_t threadLock;
				ptw32_thread_t * thread = assoc->thread;

				if (assoc == NULL)
				{
					/* Finished */
					break;
				}

				ptw32_mcs_lock_acquire(&(thread->threadLock), &threadLock);
				/*
				 * Since we are starting at the head of the key's threads
				 * chain, this will also point key->threads at the next assoc.
				 * While we hold key->keyLock, no other thread can insert
				 * a new assoc via pthread_setspecific.
				 */
				ptw32_tkAssocDestroy(assoc);
				ptw32_mcs_lock_release(&threadLock);
				ptw32_mcs_lock_release(&keyLock);
			}
		}

		void* arg = pthread_getspecific(key);
		TlsFree(key->key);
		if (key->destructor != NULL)
		{
			key->destructor(arg);

			/* A thread could be holding the keyLock */
			ptw32_mcs_lock_acquire(&(key->keyLock), &keyLock);
			ptw32_mcs_lock_release(&keyLock);
		}

#if defined( _DEBUG )
		memset((char *)key, 0, sizeof(*key));
#endif
		free(key);
	}

	return (result);
}
/*
 * pthread_kill.c
 *
 * Description:
 * This translation unit implements the pthread_kill routine.
 *
 * --------------------------------------------------------------------------
 *
 *      Pthreads-win32 - POSIX Threads Library for Win32
 *      Copyright(C) 1998 John E. Bossom
 *      Copyright(C) 1999,2005 Pthreads-win32 contributors
 *
 *      Contact Email: rpj@callisto.canberra.edu.au
 *
 *      The current list of contributors is contained
 *      in the file CONTRIBUTORS included with the source
 *      code distribution. The list can also be seen at the
 *      following World Wide Web location:
 *      http://sources.redhat.com/pthreads-win32/contributors.html
 *
 *      This library is free software; you can redistribute it and/or
 *      modify it under the terms of the GNU Lesser General Public
 *      License as published by the Free Software Foundation; either
 *      version 2 of the License, or (at your option) any later version.
 *
 *      This library is distributed in the hope that it will be useful,
 *      but WITHOUT ANY WARRANTY; without even the implied warranty of
 *      MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *      Lesser General Public License for more details.
 *
 *      You should have received a copy of the GNU Lesser General Public
 *      License along with this library in the file COPYING.LIB;
 *      if not, write to the Free Software Foundation, Inc.,
 *      59 Temple Place - Suite 330, Boston, MA 02111-1307, USA
 */


 /*
  * Not needed yet, but defining it should indicate clashes with build target
  * environment that should be fixed.
  */
#if !defined(WINCE)
#  include <signal.h>
#endif

int
pthread_kill(pthread_t thread, int sig)
/*
 * ------------------------------------------------------
 * DOCPUBLIC
 *      This function requests that a signal be delivered to the
 *      specified thread. If sig is zero, error checking is
 *      performed but no signal is actually sent such that this
 *      function can be used to check for a valid thread ID.
 *
 * PARAMETERS
 *      thread  reference to an instances of pthread_t
 *      sig     signal. Currently only a value of 0 is supported.
 *
 *
 * DESCRIPTION
 *      This function requests that a signal be delivered to the
 *      specified thread. If sig is zero, error checking is
 *      performed but no signal is actually sent such that this
 *      function can be used to check for a valid thread ID.
 *
 * RESULTS
 *              ESRCH           the thread is not a valid thread ID,
 *              EINVAL          the value of the signal is invalid
 *                              or unsupported.
 *              0               the signal was successfully sent.
 *
 * ------------------------------------------------------
 */
{
	int result = 0;
	ptw32_thread_t * tp;
	ptw32_mcs_local_node_t node;

	ptw32_mcs_lock_acquire(&ptw32_thread_reuse_lock, &node);

	tp = (ptw32_thread_t *)thread.p;

	if (NULL == tp
		|| thread.x != tp->ptHandle.x
		|| NULL == tp->threadH)
	{
		result = ESRCH;
	}

	ptw32_mcs_lock_release(&node);

	if (0 == result && 0 != sig)
	{
		/*
		 * Currently does not support any signals.
		 */
		result = EINVAL;
	}

	return result;

}				/* pthread_kill */
/*
 * pthread_mutexattr_destroy.c
 *
 * Description:
 * This translation unit implements mutual exclusion (mutex) primitives.
 *
 * --------------------------------------------------------------------------
 *
 *      Pthreads-win32 - POSIX Threads Library for Win32
 *      Copyright(C) 1998 John E. Bossom
 *      Copyright(C) 1999,2005 Pthreads-win32 contributors
 *
 *      Contact Email: rpj@callisto.canberra.edu.au
 *
 *      The current list of contributors is contained
 *      in the file CONTRIBUTORS included with the source
 *      code distribution. The list can also be seen at the
 *      following World Wide Web location:
 *      http://sources.redhat.com/pthreads-win32/contributors.html
 *
 *      This library is free software; you can redistribute it and/or
 *      modify it under the terms of the GNU Lesser General Public
 *      License as published by the Free Software Foundation; either
 *      version 2 of the License, or (at your option) any later version.
 *
 *      This library is distributed in the hope that it will be useful,
 *      but WITHOUT ANY WARRANTY; without even the implied warranty of
 *      MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *      Lesser General Public License for more details.
 *
 *      You should have received a copy of the GNU Lesser General Public
 *      License along with this library in the file COPYING.LIB;
 *      if not, write to the Free Software Foundation, Inc.,
 *      59 Temple Place - Suite 330, Boston, MA 02111-1307, USA
 */



int
pthread_mutexattr_destroy(pthread_mutexattr_t * attr)
/*
 * ------------------------------------------------------
 * DOCPUBLIC
 *      Destroys a mutex attributes object. The object can
 *      no longer be used.
 *
 * PARAMETERS
 *      attr
 *              pointer to an instance of pthread_mutexattr_t
 *
 *
 * DESCRIPTION
 *      Destroys a mutex attributes object. The object can
 *      no longer be used.
 *
 *      NOTES:
 *              1)      Does not affect mutexes created using 'attr'
 *
 * RESULTS
 *              0               successfully released attr,
 *              EINVAL          'attr' is invalid.
 *
 * ------------------------------------------------------
 */
{
	int result = 0;

	if (attr == NULL || *attr == NULL)
	{
		result = EINVAL;
	}
	else
	{
		pthread_mutexattr_t ma = *attr;

		*attr = NULL;
		free(ma);
	}

	return (result);
}				/* pthread_mutexattr_destroy */
/*
 * pthread_mutexattr_getkind_np.c
 *
 * Description:
 * This translation unit implements non-portable thread functions.
 *
 * --------------------------------------------------------------------------
 *
 *      Pthreads-win32 - POSIX Threads Library for Win32
 *      Copyright(C) 1998 John E. Bossom
 *      Copyright(C) 1999,2005 Pthreads-win32 contributors
 *
 *      Contact Email: rpj@callisto.canberra.edu.au
 *
 *      The current list of contributors is contained
 *      in the file CONTRIBUTORS included with the source
 *      code distribution. The list can also be seen at the
 *      following World Wide Web location:
 *      http://sources.redhat.com/pthreads-win32/contributors.html
 *
 *      This library is free software; you can redistribute it and/or
 *      modify it under the terms of the GNU Lesser General Public
 *      License as published by the Free Software Foundation; either
 *      version 2 of the License, or (at your option) any later version.
 *
 *      This library is distributed in the hope that it will be useful,
 *      but WITHOUT ANY WARRANTY; without even the implied warranty of
 *      MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *      Lesser General Public License for more details.
 *
 *      You should have received a copy of the GNU Lesser General Public
 *      License along with this library in the file COPYING.LIB;
 *      if not, write to the Free Software Foundation, Inc.,
 *      59 Temple Place - Suite 330, Boston, MA 02111-1307, USA
 */


int
pthread_mutexattr_getkind_np(pthread_mutexattr_t * attr, int *kind)
{
	return pthread_mutexattr_gettype(attr, kind);
}
/*
 * pthread_mutexattr_getpshared.c
 *
 * Description:
 * This translation unit implements mutual exclusion (mutex) primitives.
 *
 * --------------------------------------------------------------------------
 *
 *      Pthreads-win32 - POSIX Threads Library for Win32
 *      Copyright(C) 1998 John E. Bossom
 *      Copyright(C) 1999,2005 Pthreads-win32 contributors
 *
 *      Contact Email: rpj@callisto.canberra.edu.au
 *
 *      The current list of contributors is contained
 *      in the file CONTRIBUTORS included with the source
 *      code distribution. The list can also be seen at the
 *      following World Wide Web location:
 *      http://sources.redhat.com/pthreads-win32/contributors.html
 *
 *      This library is free software; you can redistribute it and/or
 *      modify it under the terms of the GNU Lesser General Public
 *      License as published by the Free Software Foundation; either
 *      version 2 of the License, or (at your option) any later version.
 *
 *      This library is distributed in the hope that it will be useful,
 *      but WITHOUT ANY WARRANTY; without even the implied warranty of
 *      MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *      Lesser General Public License for more details.
 *
 *      You should have received a copy of the GNU Lesser General Public
 *      License along with this library in the file COPYING.LIB;
 *      if not, write to the Free Software Foundation, Inc.,
 *      59 Temple Place - Suite 330, Boston, MA 02111-1307, USA
 */



int
pthread_mutexattr_getpshared(const pthread_mutexattr_t * attr, int *pshared)
/*
 * ------------------------------------------------------
 * DOCPUBLIC
 *      Determine whether mutexes created with 'attr' can be
 *      shared between processes.
 *
 * PARAMETERS
 *      attr
 *              pointer to an instance of pthread_mutexattr_t
 *
 *      pshared
 *              will be set to one of:
 *
 *                      PTHREAD_PROCESS_SHARED
 *                              May be shared if in shared memory
 *
 *                      PTHREAD_PROCESS_PRIVATE
 *                              Cannot be shared.
 *
 *
 * DESCRIPTION
 *      Mutexes creatd with 'attr' can be shared between
 *      processes if pthread_mutex_t variable is allocated
 *      in memory shared by these processes.
 *      NOTES:
 *              1)      pshared mutexes MUST be allocated in shared
 *                      memory.
 *              2)      The following macro is defined if shared mutexes
 *                      are supported:
 *                              _POSIX_THREAD_PROCESS_SHARED
 *
 * RESULTS
 *              0               successfully retrieved attribute,
 *              EINVAL          'attr' is invalid,
 *
 * ------------------------------------------------------
 */
{
	int result;

	if ((attr != NULL && *attr != NULL) && (pshared != NULL))
	{
		*pshared = (*attr)->pshared;
		result = 0;
	}
	else
	{
		result = EINVAL;
	}

	return (result);

}				/* pthread_mutexattr_getpshared */
/*
 * pthread_mutexattr_getrobust.c
 *
 * Description:
 * This translation unit implements mutual exclusion (mutex) primitives.
 *
 * --------------------------------------------------------------------------
 *
 *      Pthreads-win32 - POSIX Threads Library for Win32
 *      Copyright(C) 1998 John E. Bossom
 *      Copyright(C) 1999,2005 Pthreads-win32 contributors
 *
 *      Contact Email: rpj@callisto.canberra.edu.au
 *
 *      The current list of contributors is contained
 *      in the file CONTRIBUTORS included with the source
 *      code distribution. The list can also be seen at the
 *      following World Wide Web location:
 *      http://sources.redhat.com/pthreads-win32/contributors.html
 *
 *      This library is free software; you can redistribute it and/or
 *      modify it under the terms of the GNU Lesser General Public
 *      License as published by the Free Software Foundation; either
 *      version 2 of the License, or (at your option) any later version.
 *
 *      This library is distributed in the hope that it will be useful,
 *      but WITHOUT ANY WARRANTY; without even the implied warranty of
 *      MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *      Lesser General Public License for more details.
 *
 *      You should have received a copy of the GNU Lesser General Public
 *      License along with this library in the file COPYING.LIB;
 *      if not, write to the Free Software Foundation, Inc.,
 *      59 Temple Place - Suite 330, Boston, MA 02111-1307, USA
 */



int
pthread_mutexattr_getrobust(const pthread_mutexattr_t * attr, int * robust)
/*
 * ------------------------------------------------------
 *
 * DOCPUBLIC
 * The pthread_mutexattr_setrobust() and
 * pthread_mutexattr_getrobust() functions  respectively set and
 * get the mutex robust  attribute. This attribute is set in  the
 * robust parameter to these functions.
 *
 * PARAMETERS
 *      attr
 *              pointer to an instance of pthread_mutexattr_t
 *
 *     robust
 *              must be one of:
 *
 *                      PTHREAD_MUTEX_STALLED
 *
 *                      PTHREAD_MUTEX_ROBUST
 *
 * DESCRIPTION
 * The pthread_mutexattr_setrobust() and
 * pthread_mutexattr_getrobust() functions  respectively set and
 * get the mutex robust  attribute. This attribute is set in  the
 * robust  parameter to these functions. The default value of the
 * robust  attribute is  PTHREAD_MUTEX_STALLED.
 *
 * The robustness of mutex is contained in the robustness attribute
 * of the mutex attributes. Valid mutex robustness values are:
 *
 * PTHREAD_MUTEX_STALLED
 * No special actions are taken if the owner of the mutex is
 * terminated while holding the mutex lock. This can lead to
 * deadlocks if no other thread can unlock the mutex.
 * This is the default value.
 *
 * PTHREAD_MUTEX_ROBUST
 * If the process containing the owning thread of a robust mutex
 * terminates while holding the mutex lock, the next thread that
 * acquires the mutex shall be notified about the termination by
 * the return value [EOWNERDEAD] from the locking function. If the
 * owning thread of a robust mutex terminates while holding the mutex
 * lock, the next thread that acquires the mutex may be notified
 * about the termination by the return value [EOWNERDEAD]. The
 * notified thread can then attempt to mark the state protected by
 * the mutex as consistent again by a call to
 * pthread_mutex_consistent(). After a subsequent successful call to
 * pthread_mutex_unlock(), the mutex lock shall be released and can
 * be used normally by other threads. If the mutex is unlocked without
 * a call to pthread_mutex_consistent(), it shall be in a permanently
 * unusable state and all attempts to lock the mutex shall fail with
 * the error [ENOTRECOVERABLE]. The only permissible operation on such
 * a mutex is pthread_mutex_destroy().
 *
 * RESULTS
 *              0               successfully set attribute,
 *              EINVAL          'attr' or 'robust' is invalid,
 *
 * ------------------------------------------------------
 */
{
	int result = EINVAL;

	if ((attr != NULL && *attr != NULL && robust != NULL))
	{
		*robust = (*attr)->robustness;
		result = 0;
	}

	return (result);
}				/* pthread_mutexattr_getrobust */
/*
 * pthread_mutexattr_gettype.c
 *
 * Description:
 * This translation unit implements mutual exclusion (mutex) primitives.
 *
 * --------------------------------------------------------------------------
 *
 *      Pthreads-win32 - POSIX Threads Library for Win32
 *      Copyright(C) 1998 John E. Bossom
 *      Copyright(C) 1999,2005 Pthreads-win32 contributors
 *
 *      Contact Email: rpj@callisto.canberra.edu.au
 *
 *      The current list of contributors is contained
 *      in the file CONTRIBUTORS included with the source
 *      code distribution. The list can also be seen at the
 *      following World Wide Web location:
 *      http://sources.redhat.com/pthreads-win32/contributors.html
 *
 *      This library is free software; you can redistribute it and/or
 *      modify it under the terms of the GNU Lesser General Public
 *      License as published by the Free Software Foundation; either
 *      version 2 of the License, or (at your option) any later version.
 *
 *      This library is distributed in the hope that it will be useful,
 *      but WITHOUT ANY WARRANTY; without even the implied warranty of
 *      MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *      Lesser General Public License for more details.
 *
 *      You should have received a copy of the GNU Lesser General Public
 *      License along with this library in the file COPYING.LIB;
 *      if not, write to the Free Software Foundation, Inc.,
 *      59 Temple Place - Suite 330, Boston, MA 02111-1307, USA
 */



int
pthread_mutexattr_gettype(const pthread_mutexattr_t * attr, int *kind)
{
	int result = 0;

	if (attr != NULL && *attr != NULL && kind != NULL)
	{
		*kind = (*attr)->kind;
	}
	else
	{
		result = EINVAL;
	}

	return (result);
}
/*
 * pthread_mutexattr_init.c
 *
 * Description:
 * This translation unit implements mutual exclusion (mutex) primitives.
 *
 * --------------------------------------------------------------------------
 *
 *      Pthreads-win32 - POSIX Threads Library for Win32
 *      Copyright(C) 1998 John E. Bossom
 *      Copyright(C) 1999,2005 Pthreads-win32 contributors
 *
 *      Contact Email: rpj@callisto.canberra.edu.au
 *
 *      The current list of contributors is contained
 *      in the file CONTRIBUTORS included with the source
 *      code distribution. The list can also be seen at the
 *      following World Wide Web location:
 *      http://sources.redhat.com/pthreads-win32/contributors.html
 *
 *      This library is free software; you can redistribute it and/or
 *      modify it under the terms of the GNU Lesser General Public
 *      License as published by the Free Software Foundation; either
 *      version 2 of the License, or (at your option) any later version.
 *
 *      This library is distributed in the hope that it will be useful,
 *      but WITHOUT ANY WARRANTY; without even the implied warranty of
 *      MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *      Lesser General Public License for more details.
 *
 *      You should have received a copy of the GNU Lesser General Public
 *      License along with this library in the file COPYING.LIB;
 *      if not, write to the Free Software Foundation, Inc.,
 *      59 Temple Place - Suite 330, Boston, MA 02111-1307, USA
 */



int
pthread_mutexattr_init(pthread_mutexattr_t * attr)
/*
 * ------------------------------------------------------
 * DOCPUBLIC
 *      Initializes a mutex attributes object with default
 *      attributes.
 *
 * PARAMETERS
 *      attr
 *              pointer to an instance of pthread_mutexattr_t
 *
 *
 * DESCRIPTION
 *      Initializes a mutex attributes object with default
 *      attributes.
 *
 *      NOTES:
 *              1)      Used to define mutex types
 *
 * RESULTS
 *              0               successfully initialized attr,
 *              ENOMEM          insufficient memory for attr.
 *
 * ------------------------------------------------------
 */
{
	int result = 0;
	pthread_mutexattr_t ma;

	ma = (pthread_mutexattr_t)calloc(1, sizeof(*ma));

	if (ma == NULL)
	{
		result = ENOMEM;
	}
	else
	{
		ma->pshared = PTHREAD_PROCESS_PRIVATE;
		ma->kind = PTHREAD_MUTEX_DEFAULT;
	}

	*attr = ma;

	return (result);
}				/* pthread_mutexattr_init */
/*
 * pthread_mutexattr_setkind_np.c
 *
 * Description:
 * This translation unit implements non-portable thread functions.
 *
 * --------------------------------------------------------------------------
 *
 *      Pthreads-win32 - POSIX Threads Library for Win32
 *      Copyright(C) 1998 John E. Bossom
 *      Copyright(C) 1999,2005 Pthreads-win32 contributors
 *
 *      Contact Email: rpj@callisto.canberra.edu.au
 *
 *      The current list of contributors is contained
 *      in the file CONTRIBUTORS included with the source
 *      code distribution. The list can also be seen at the
 *      following World Wide Web location:
 *      http://sources.redhat.com/pthreads-win32/contributors.html
 *
 *      This library is free software; you can redistribute it and/or
 *      modify it under the terms of the GNU Lesser General Public
 *      License as published by the Free Software Foundation; either
 *      version 2 of the License, or (at your option) any later version.
 *
 *      This library is distributed in the hope that it will be useful,
 *      but WITHOUT ANY WARRANTY; without even the implied warranty of
 *      MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *      Lesser General Public License for more details.
 *
 *      You should have received a copy of the GNU Lesser General Public
 *      License along with this library in the file COPYING.LIB;
 *      if not, write to the Free Software Foundation, Inc.,
 *      59 Temple Place - Suite 330, Boston, MA 02111-1307, USA
 */


int
pthread_mutexattr_setkind_np(pthread_mutexattr_t * attr, int kind)
{
	return pthread_mutexattr_settype(attr, kind);
}
/*
 * pthread_mutexattr_setpshared.c
 *
 * Description:
 * This translation unit implements mutual exclusion (mutex) primitives.
 *
 * --------------------------------------------------------------------------
 *
 *      Pthreads-win32 - POSIX Threads Library for Win32
 *      Copyright(C) 1998 John E. Bossom
 *      Copyright(C) 1999,2005 Pthreads-win32 contributors
 *
 *      Contact Email: rpj@callisto.canberra.edu.au
 *
 *      The current list of contributors is contained
 *      in the file CONTRIBUTORS included with the source
 *      code distribution. The list can also be seen at the
 *      following World Wide Web location:
 *      http://sources.redhat.com/pthreads-win32/contributors.html
 *
 *      This library is free software; you can redistribute it and/or
 *      modify it under the terms of the GNU Lesser General Public
 *      License as published by the Free Software Foundation; either
 *      version 2 of the License, or (at your option) any later version.
 *
 *      This library is distributed in the hope that it will be useful,
 *      but WITHOUT ANY WARRANTY; without even the implied warranty of
 *      MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *      Lesser General Public License for more details.
 *
 *      You should have received a copy of the GNU Lesser General Public
 *      License along with this library in the file COPYING.LIB;
 *      if not, write to the Free Software Foundation, Inc.,
 *      59 Temple Place - Suite 330, Boston, MA 02111-1307, USA
 */



int
pthread_mutexattr_setpshared(pthread_mutexattr_t * attr, int pshared)
/*
 * ------------------------------------------------------
 * DOCPUBLIC
 *      Mutexes created with 'attr' can be shared between
 *      processes if pthread_mutex_t variable is allocated
 *      in memory shared by these processes.
 *
 * PARAMETERS
 *      attr
 *              pointer to an instance of pthread_mutexattr_t
 *
 *      pshared
 *              must be one of:
 *
 *                      PTHREAD_PROCESS_SHARED
 *                              May be shared if in shared memory
 *
 *                      PTHREAD_PROCESS_PRIVATE
 *                              Cannot be shared.
 *
 * DESCRIPTION
 *      Mutexes creatd with 'attr' can be shared between
 *      processes if pthread_mutex_t variable is allocated
 *      in memory shared by these processes.
 *
 *      NOTES:
 *              1)      pshared mutexes MUST be allocated in shared
 *                      memory.
 *
 *              2)      The following macro is defined if shared mutexes
 *                      are supported:
 *                              _POSIX_THREAD_PROCESS_SHARED
 *
 * RESULTS
 *              0               successfully set attribute,
 *              EINVAL          'attr' or pshared is invalid,
 *              ENOSYS          PTHREAD_PROCESS_SHARED not supported,
 *
 * ------------------------------------------------------
 */
{
	int result;

	if ((attr != NULL && *attr != NULL) &&
		((pshared == PTHREAD_PROCESS_SHARED) ||
		(pshared == PTHREAD_PROCESS_PRIVATE)))
	{
		if (pshared == PTHREAD_PROCESS_SHARED)
		{

#if !defined( _POSIX_THREAD_PROCESS_SHARED )

			result = ENOSYS;
			pshared = PTHREAD_PROCESS_PRIVATE;

#else

			result = 0;

#endif /* _POSIX_THREAD_PROCESS_SHARED */

		}
		else
		{
			result = 0;
		}

		(*attr)->pshared = pshared;
	}
	else
	{
		result = EINVAL;
	}

	return (result);

}				/* pthread_mutexattr_setpshared */
/*
 * pthread_mutexattr_setrobust.c
 *
 * Description:
 * This translation unit implements mutual exclusion (mutex) primitives.
 *
 * --------------------------------------------------------------------------
 *
 *      Pthreads-win32 - POSIX Threads Library for Win32
 *      Copyright(C) 1998 John E. Bossom
 *      Copyright(C) 1999,2005 Pthreads-win32 contributors
 *
 *      Contact Email: rpj@callisto.canberra.edu.au
 *
 *      The current list of contributors is contained
 *      in the file CONTRIBUTORS included with the source
 *      code distribution. The list can also be seen at the
 *      following World Wide Web location:
 *      http://sources.redhat.com/pthreads-win32/contributors.html
 *
 *      This library is free software; you can redistribute it and/or
 *      modify it under the terms of the GNU Lesser General Public
 *      License as published by the Free Software Foundation; either
 *      version 2 of the License, or (at your option) any later version.
 *
 *      This library is distributed in the hope that it will be useful,
 *      but WITHOUT ANY WARRANTY; without even the implied warranty of
 *      MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *      Lesser General Public License for more details.
 *
 *      You should have received a copy of the GNU Lesser General Public
 *      License along with this library in the file COPYING.LIB;
 *      if not, write to the Free Software Foundation, Inc.,
 *      59 Temple Place - Suite 330, Boston, MA 02111-1307, USA
 */



int
pthread_mutexattr_setrobust(pthread_mutexattr_t * attr, int robust)
/*
 * ------------------------------------------------------
 *
 * DOCPUBLIC
 * The pthread_mutexattr_setrobust() and
 * pthread_mutexattr_getrobust() functions  respectively set and
 * get the mutex robust  attribute. This attribute is set in  the
 * robust parameter to these functions.
 *
 * PARAMETERS
 *      attr
 *              pointer to an instance of pthread_mutexattr_t
 *
 *     robust
 *              must be one of:
 *
 *                      PTHREAD_MUTEX_STALLED
 *
 *                      PTHREAD_MUTEX_ROBUST
 *
 * DESCRIPTION
 * The pthread_mutexattr_setrobust() and
 * pthread_mutexattr_getrobust() functions  respectively set and
 * get the mutex robust  attribute. This attribute is set in  the
 * robust  parameter to these functions. The default value of the
 * robust  attribute is  PTHREAD_MUTEX_STALLED.
 *
 * The robustness of mutex is contained in the robustness attribute
 * of the mutex attributes. Valid mutex robustness values are:
 *
 * PTHREAD_MUTEX_STALLED
 * No special actions are taken if the owner of the mutex is
 * terminated while holding the mutex lock. This can lead to
 * deadlocks if no other thread can unlock the mutex.
 * This is the default value.
 *
 * PTHREAD_MUTEX_ROBUST
 * If the process containing the owning thread of a robust mutex
 * terminates while holding the mutex lock, the next thread that
 * acquires the mutex shall be notified about the termination by
 * the return value [EOWNERDEAD] from the locking function. If the
 * owning thread of a robust mutex terminates while holding the mutex
 * lock, the next thread that acquires the mutex may be notified
 * about the termination by the return value [EOWNERDEAD]. The
 * notified thread can then attempt to mark the state protected by
 * the mutex as consistent again by a call to
 * pthread_mutex_consistent(). After a subsequent successful call to
 * pthread_mutex_unlock(), the mutex lock shall be released and can
 * be used normally by other threads. If the mutex is unlocked without
 * a call to pthread_mutex_consistent(), it shall be in a permanently
 * unusable state and all attempts to lock the mutex shall fail with
 * the error [ENOTRECOVERABLE]. The only permissible operation on such
 * a mutex is pthread_mutex_destroy().
 *
 * RESULTS
 *              0               successfully set attribute,
 *              EINVAL          'attr' or 'robust' is invalid,
 *
 * ------------------------------------------------------
 */
{
	int result = EINVAL;

	if ((attr != NULL && *attr != NULL))
	{
		switch (robust)
		{
		case PTHREAD_MUTEX_STALLED:
		case PTHREAD_MUTEX_ROBUST:
			(*attr)->robustness = robust;
			result = 0;
			break;
		}
	}

	return (result);
}				/* pthread_mutexattr_setrobust */
/*
 * pthread_mutexattr_settype.c
 *
 * Description:
 * This translation unit implements mutual exclusion (mutex) primitives.
 *
 * --------------------------------------------------------------------------
 *
 *      Pthreads-win32 - POSIX Threads Library for Win32
 *      Copyright(C) 1998 John E. Bossom
 *      Copyright(C) 1999,2005 Pthreads-win32 contributors
 *
 *      Contact Email: rpj@callisto.canberra.edu.au
 *
 *      The current list of contributors is contained
 *      in the file CONTRIBUTORS included with the source
 *      code distribution. The list can also be seen at the
 *      following World Wide Web location:
 *      http://sources.redhat.com/pthreads-win32/contributors.html
 *
 *      This library is free software; you can redistribute it and/or
 *      modify it under the terms of the GNU Lesser General Public
 *      License as published by the Free Software Foundation; either
 *      version 2 of the License, or (at your option) any later version.
 *
 *      This library is distributed in the hope that it will be useful,
 *      but WITHOUT ANY WARRANTY; without even the implied warranty of
 *      MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *      Lesser General Public License for more details.
 *
 *      You should have received a copy of the GNU Lesser General Public
 *      License along with this library in the file COPYING.LIB;
 *      if not, write to the Free Software Foundation, Inc.,
 *      59 Temple Place - Suite 330, Boston, MA 02111-1307, USA
 */



int
pthread_mutexattr_settype(pthread_mutexattr_t * attr, int kind)
/*
 * ------------------------------------------------------
 *
 * DOCPUBLIC
 * The pthread_mutexattr_settype() and
 * pthread_mutexattr_gettype() functions  respectively set and
 * get the mutex type  attribute. This attribute is set in  the
 * type parameter to these functions.
 *
 * PARAMETERS
 *      attr
 *              pointer to an instance of pthread_mutexattr_t
 *
 *      type
 *              must be one of:
 *
 *                      PTHREAD_MUTEX_DEFAULT
 *
 *                      PTHREAD_MUTEX_NORMAL
 *
 *                      PTHREAD_MUTEX_ERRORCHECK
 *
 *                      PTHREAD_MUTEX_RECURSIVE
 *
 * DESCRIPTION
 * The pthread_mutexattr_settype() and
 * pthread_mutexattr_gettype() functions  respectively set and
 * get the mutex type  attribute. This attribute is set in  the
 * type  parameter to these functions. The default value of the
 * type  attribute is  PTHREAD_MUTEX_DEFAULT.
 *
 * The type of mutex is contained in the type  attribute of the
 * mutex attributes. Valid mutex types include:
 *
 * PTHREAD_MUTEX_NORMAL
 *          This type of mutex does  not  detect  deadlock.  A
 *          thread  attempting  to  relock  this mutex without
 *          first unlocking it will  deadlock.  Attempting  to
 *          unlock  a  mutex  locked  by  a  different  thread
 *          results  in  undefined  behavior.  Attempting   to
 *          unlock  an  unlocked  mutex  results  in undefined
 *          behavior.
 *
 * PTHREAD_MUTEX_ERRORCHECK
 *          This type of  mutex  provides  error  checking.  A
 *          thread  attempting  to  relock  this mutex without
 *          first unlocking it will return with  an  error.  A
 *          thread  attempting to unlock a mutex which another
 *          thread has locked will return  with  an  error.  A
 *          thread attempting to unlock an unlocked mutex will
 *          return with an error.
 *
 * PTHREAD_MUTEX_DEFAULT
 *          Same as PTHREAD_MUTEX_NORMAL.
 *
 * PTHREAD_MUTEX_RECURSIVE
 *          A thread attempting to relock this  mutex  without
 *          first  unlocking  it  will  succeed in locking the
 *          mutex. The relocking deadlock which can occur with
 *          mutexes of type  PTHREAD_MUTEX_NORMAL cannot occur
 *          with this type of mutex. Multiple  locks  of  this
 *          mutex  require  the  same  number  of  unlocks  to
 *          release  the  mutex  before  another  thread   can
 *          acquire the mutex. A thread attempting to unlock a
 *          mutex which another thread has locked will  return
 *          with  an  error. A thread attempting to  unlock an
 *          unlocked mutex will return  with  an  error.  This
 *          type  of mutex is only supported for mutexes whose
 *          process        shared         attribute         is
 *          PTHREAD_PROCESS_PRIVATE.
 *
 * RESULTS
 *              0               successfully set attribute,
 *              EINVAL          'attr' or 'type' is invalid,
 *
 * ------------------------------------------------------
 */
{
	int result = 0;

	if ((attr != NULL && *attr != NULL))
	{
		switch (kind)
		{
		case PTHREAD_MUTEX_FAST_NP:
		case PTHREAD_MUTEX_RECURSIVE_NP:
		case PTHREAD_MUTEX_ERRORCHECK_NP:
			(*attr)->kind = kind;
			break;
		default:
			result = EINVAL;
			break;
		}
	}
	else
	{
		result = EINVAL;
	}

	return (result);
}				/* pthread_mutexattr_settype */
/*
 * pthread_mutex_consistent.c
 *
 * Description:
 * This translation unit implements mutual exclusion (mutex) primitives.
 *
 * --------------------------------------------------------------------------
 *
 *      Pthreads-win32 - POSIX Threads Library for Win32
 *      Copyright(C) 1998 John E. Bossom
 *      Copyright(C) 1999,2005 Pthreads-win32 contributors
 *
 *      Contact Email: rpj@callisto.canberra.edu.au
 *
 *      The current list of contributors is contained
 *      in the file CONTRIBUTORS included with the source
 *      code distribution. The list can also be seen at the
 *      following World Wide Web location:
 *      http://sources.redhat.com/pthreads-win32/contributors.html
 *
 *      This library is free software; you can redistribute it and/or
 *      modify it under the terms of the GNU Lesser General Public
 *      License as published by the Free Software Foundation; either
 *      version 2 of the License, or (at your option) any later version.
 *
 *      This library is distributed in the hope that it will be useful,
 *      but WITHOUT ANY WARRANTY; without even the implied warranty of
 *      MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *      Lesser General Public License for more details.
 *
 *      You should have received a copy of the GNU Lesser General Public
 *      License along with this library in the file COPYING.LIB;
 *      if not, write to the Free Software Foundation, Inc.,
 *      59 Temple Place - Suite 330, Boston, MA 02111-1307, USA
 */

 /*
  * From the Sun Multi-threaded Programming Guide
  *
  * robustness defines the behavior when the owner of the mutex terminates without unlocking the
  * mutex, usually because its process terminated abnormally. The value of robustness that is
  * defined in pthread.h is PTHREAD_MUTEX_ROBUST or PTHREAD_MUTEX_STALLED. The
  * default value is PTHREAD_MUTEX_STALLED .
  * ■ PTHREAD_MUTEX_STALLED
  * When the owner of the mutex terminates without unlocking the mutex, all subsequent calls
  * to pthread_mutex_lock() are blocked from progress in an unspecified manner.
  * ■ PTHREAD_MUTEX_ROBUST
  * When the owner of the mutex terminates without unlocking the mutex, the mutex is
  * unlocked. The next owner of this mutex acquires the mutex with an error return of
  * EOWNERDEAD.
  * Note – Your application must always check the return code from pthread_mutex_lock() for
  * a mutex initialized with the PTHREAD_MUTEX_ROBUST attribute.
  * ■ The new owner of this mutex should make the state protected by the mutex consistent.
  * This state might have been left inconsistent when the previous owner terminated.
  * ■ If the new owner is able to make the state consistent, call
  * pthread_mutex_consistent() for the mutex before unlocking the mutex. This
  * marks the mutex as consistent and subsequent calls to pthread_mutex_lock() and
  * pthread_mutex_unlock() will behave in the normal manner.
  * ■ If the new owner is not able to make the state consistent, do not call
  * pthread_mutex_consistent() for the mutex, but unlock the mutex.
  * All waiters are woken up and all subsequent calls to pthread_mutex_lock() fail to
  * acquire the mutex. The return code is ENOTRECOVERABLE. The mutex can be made
  * consistent by calling pthread_mutex_destroy() to uninitialize the mutex, and calling
  * pthread_mutex_int() to reinitialize the mutex.However, the state that was protected
  * by the mutex remains inconsistent and some form of application recovery is required.
  * ■ If the thread that acquires the lock with EOWNERDEAD terminates without unlocking the
  * mutex, the next owner acquires the lock with an EOWNERDEAD return code.
  */
#if !defined(_UWIN)
  /*#   include <process.h> */
#endif

INLINE
int
ptw32_robust_mutex_inherit(pthread_mutex_t * mutex)
{
	int result;
	pthread_mutex_t mx = *mutex;
	ptw32_robust_node_t* robust = mx->robustNode;

	switch ((LONG)PTW32_INTERLOCKED_COMPARE_EXCHANGE_LONG(
		(PTW32_INTERLOCKED_LONGPTR)&robust->stateInconsistent,
		(PTW32_INTERLOCKED_LONG)PTW32_ROBUST_INCONSISTENT,
		(PTW32_INTERLOCKED_LONG)-1 /* The terminating thread sets this */))
	{
	case -1L:
		result = EOWNERDEAD;
		break;
	case (LONG)PTW32_ROBUST_NOTRECOVERABLE:
		result = ENOTRECOVERABLE;
		break;
	default:
		result = 0;
		break;
	}

	return result;
}

/*
 * The next two internal support functions depend on only being
 * called by the thread that owns the robust mutex. This enables
 * us to avoid additional locks.
 * Any mutex currently in the thread's robust mutex list is held
 * by the thread, again eliminating the need for locks.
 * The forward/backward links allow the thread to unlock mutexes
 * in any order, not necessarily the reverse locking order.
 * This is all possible because it is an error if a thread that
 * does not own the [robust] mutex attempts to unlock it.
 */

INLINE
void
ptw32_robust_mutex_add(pthread_mutex_t* mutex, pthread_t self)
{
	ptw32_robust_node_t** list;
	pthread_mutex_t mx = *mutex;
	ptw32_thread_t* tp = (ptw32_thread_t*)self.p;
	ptw32_robust_node_t* robust = mx->robustNode;

	list = &tp->robustMxList;
	mx->ownerThread = self;
	if (NULL == *list)
	{
		robust->prev = NULL;
		robust->next = NULL;
		*list = robust;
	}
	else
	{
		robust->prev = NULL;
		robust->next = *list;
		(*list)->prev = robust;
		*list = robust;
	}
}

INLINE
void
ptw32_robust_mutex_remove(pthread_mutex_t* mutex, ptw32_thread_t* otp)
{
	ptw32_robust_node_t** list;
	pthread_mutex_t mx = *mutex;
	ptw32_robust_node_t* robust = mx->robustNode;

	list = &(((ptw32_thread_t*)mx->ownerThread.p)->robustMxList);
	mx->ownerThread.p = otp;
	if (robust->next != NULL)
	{
		robust->next->prev = robust->prev;
	}
	if (robust->prev != NULL)
	{
		robust->prev->next = robust->next;
	}
	if (*list == robust)
	{
		*list = robust->next;
	}
}


int
pthread_mutex_consistent(pthread_mutex_t* mutex)
{
	pthread_mutex_t mx = *mutex;
	int result = 0;

	/*
	 * Let the system deal with invalid pointers.
	 */
	if (mx == NULL)
	{
		return EINVAL;
	}

	if (mx->kind >= 0
		|| (PTW32_INTERLOCKED_LONG)PTW32_ROBUST_INCONSISTENT != PTW32_INTERLOCKED_COMPARE_EXCHANGE_LONG(
		(PTW32_INTERLOCKED_LONGPTR)&mx->robustNode->stateInconsistent,
			(PTW32_INTERLOCKED_LONG)PTW32_ROBUST_CONSISTENT,
			(PTW32_INTERLOCKED_LONG)PTW32_ROBUST_INCONSISTENT))
	{
		result = EINVAL;
	}

	return (result);
}

/*
 * pthread_mutex_destroy.c
 *
 * Description:
 * This translation unit implements mutual exclusion (mutex) primitives.
 *
 * --------------------------------------------------------------------------
 *
 *      Pthreads-win32 - POSIX Threads Library for Win32
 *      Copyright(C) 1998 John E. Bossom
 *      Copyright(C) 1999,2005 Pthreads-win32 contributors
 *
 *      Contact Email: rpj@callisto.canberra.edu.au
 *
 *      The current list of contributors is contained
 *      in the file CONTRIBUTORS included with the source
 *      code distribution. The list can also be seen at the
 *      following World Wide Web location:
 *      http://sources.redhat.com/pthreads-win32/contributors.html
 *
 *      This library is free software; you can redistribute it and/or
 *      modify it under the terms of the GNU Lesser General Public
 *      License as published by the Free Software Foundation; either
 *      version 2 of the License, or (at your option) any later version.
 *
 *      This library is distributed in the hope that it will be useful,
 *      but WITHOUT ANY WARRANTY; without even the implied warranty of
 *      MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *      Lesser General Public License for more details.
 *
 *      You should have received a copy of the GNU Lesser General Public
 *      License along with this library in the file COPYING.LIB;
 *      if not, write to the Free Software Foundation, Inc.,
 *      59 Temple Place - Suite 330, Boston, MA 02111-1307, USA
 */



int
pthread_mutex_destroy(pthread_mutex_t * mutex)
{
	int result = 0;
	pthread_mutex_t mx;

	/*
	 * Let the system deal with invalid pointers.
	 */

	 /*
	  * Check to see if we have something to delete.
	  */
	if (*mutex < PTHREAD_ERRORCHECK_MUTEX_INITIALIZER)
	{
		mx = *mutex;

		result = pthread_mutex_trylock(&mx);

		/*
		 * If trylock succeeded and the mutex is not recursively locked it
		 * can be destroyed.
		 */
		if (0 == result || ENOTRECOVERABLE == result)
		{
			if (mx->kind != PTHREAD_MUTEX_RECURSIVE || 1 == mx->recursive_count)
			{
				/*
				 * FIXME!!!
				 * The mutex isn't held by another thread but we could still
				 * be too late invalidating the mutex below since another thread
				 * may already have entered mutex_lock and the check for a valid
				 * *mutex != NULL.
				 */
				*mutex = NULL;

				result = (0 == result) ? pthread_mutex_unlock(&mx) : 0;

				if (0 == result)
				{
					if (mx->robustNode != NULL)
					{
						free(mx->robustNode);
					}
					if (!CloseHandle(mx->event))
					{
						*mutex = mx;
						result = EINVAL;
					}
					else
					{
						free(mx);
					}
				}
				else
				{
					/*
					 * Restore the mutex before we return the error.
					 */
					*mutex = mx;
				}
			}
			else			/* mx->recursive_count > 1 */
			{
				/*
				 * The mutex must be recursive and already locked by us (this thread).
				 */
				mx->recursive_count--;	/* Undo effect of pthread_mutex_trylock() above */
				result = EBUSY;
			}
		}
	}
	else
	{
		ptw32_mcs_local_node_t node;

		/*
		 * See notes in ptw32_mutex_check_need_init() above also.
		 */

		ptw32_mcs_lock_acquire(&ptw32_mutex_test_init_lock, &node);

		/*
		 * Check again.
		 */
		if (*mutex >= PTHREAD_ERRORCHECK_MUTEX_INITIALIZER)
		{
			/*
			 * This is all we need to do to destroy a statically
			 * initialised mutex that has not yet been used (initialised).
			 * If we get to here, another thread
			 * waiting to initialise this mutex will get an EINVAL.
			 */
			*mutex = NULL;
		}
		else
		{
			/*
			 * The mutex has been initialised while we were waiting
			 * so assume it's in use.
			 */
			result = EBUSY;
		}
		ptw32_mcs_lock_release(&node);
	}

	return (result);
}
/*
 * pthread_mutex_init.c
 *
 * Description:
 * This translation unit implements mutual exclusion (mutex) primitives.
 *
 * --------------------------------------------------------------------------
 *
 *      Pthreads-win32 - POSIX Threads Library for Win32
 *      Copyright(C) 1998 John E. Bossom
 *      Copyright(C) 1999,2005 Pthreads-win32 contributors
 *
 *      Contact Email: rpj@callisto.canberra.edu.au
 *
 *      The current list of contributors is contained
 *      in the file CONTRIBUTORS included with the source
 *      code distribution. The list can also be seen at the
 *      following World Wide Web location:
 *      http://sources.redhat.com/pthreads-win32/contributors.html
 *
 *      This library is free software; you can redistribute it and/or
 *      modify it under the terms of the GNU Lesser General Public
 *      License as published by the Free Software Foundation; either
 *      version 2 of the License, or (at your option) any later version.
 *
 *      This library is distributed in the hope that it will be useful,
 *      but WITHOUT ANY WARRANTY; without even the implied warranty of
 *      MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *      Lesser General Public License for more details.
 *
 *      You should have received a copy of the GNU Lesser General Public
 *      License along with this library in the file COPYING.LIB;
 *      if not, write to the Free Software Foundation, Inc.,
 *      59 Temple Place - Suite 330, Boston, MA 02111-1307, USA
 */



int
pthread_mutex_init(pthread_mutex_t * mutex, const pthread_mutexattr_t * attr)
{
	int result = 0;
	pthread_mutex_t mx;

	if (mutex == NULL)
	{
		return EINVAL;
	}

	if (attr != NULL && *attr != NULL)
	{
		if ((*attr)->pshared == PTHREAD_PROCESS_SHARED)
		{
			/*
			 * Creating mutex that can be shared between
			 * processes.
			 */
#if _POSIX_THREAD_PROCESS_SHARED >= 0

			 /*
			  * Not implemented yet.
			  */

#error ERROR [__FILE__, line __LINE__]: Process shared mutexes are not supported yet.

#else

			return ENOSYS;

#endif /* _POSIX_THREAD_PROCESS_SHARED */
		}
	}

	mx = (pthread_mutex_t)calloc(1, sizeof(*mx));

	if (mx == NULL)
	{
		result = ENOMEM;
	}
	else
	{
		mx->lock_idx = 0;
		mx->recursive_count = 0;
		mx->robustNode = NULL;
		if (attr == NULL || *attr == NULL)
		{
			mx->kind = PTHREAD_MUTEX_DEFAULT;
		}
		else
		{
			mx->kind = (*attr)->kind;
			if ((*attr)->robustness == PTHREAD_MUTEX_ROBUST)
			{
				/*
				 * Use the negative range to represent robust types.
				 * Replaces a memory fetch with a register negate and incr
				 * in pthread_mutex_lock etc.
				 *
				 * Map 0,1,..,n to -1,-2,..,(-n)-1
				 */
				mx->kind = -mx->kind - 1;

				mx->robustNode = (ptw32_robust_node_t*)malloc(sizeof(ptw32_robust_node_t));
				mx->robustNode->stateInconsistent = PTW32_ROBUST_CONSISTENT;
				mx->robustNode->mx = mx;
				mx->robustNode->next = NULL;
				mx->robustNode->prev = NULL;
			}
		}

		mx->ownerThread.p = NULL;

		mx->event = CreateEvent(NULL, PTW32_FALSE,    /* manual reset = No */
			PTW32_FALSE,           /* initial state = not signaled */
			NULL);                 /* event name */

		if (0 == mx->event)
		{
			result = ENOSPC;
			free(mx);
			mx = NULL;
		}
	}

	*mutex = mx;

	return (result);
}
/*
 * pthread_mutex_lock.c
 *
 * Description:
 * This translation unit implements mutual exclusion (mutex) primitives.
 *
 * --------------------------------------------------------------------------
 *
 *      Pthreads-win32 - POSIX Threads Library for Win32
 *      Copyright(C) 1998 John E. Bossom
 *      Copyright(C) 1999,2005 Pthreads-win32 contributors
 *
 *      Contact Email: rpj@callisto.canberra.edu.au
 *
 *      The current list of contributors is contained
 *      in the file CONTRIBUTORS included with the source
 *      code distribution. The list can also be seen at the
 *      following World Wide Web location:
 *      http://sources.redhat.com/pthreads-win32/contributors.html
 *
 *      This library is free software; you can redistribute it and/or
 *      modify it under the terms of the GNU Lesser General Public
 *      License as published by the Free Software Foundation; either
 *      version 2 of the License, or (at your option) any later version.
 *
 *      This library is distributed in the hope that it will be useful,
 *      but WITHOUT ANY WARRANTY; without even the implied warranty of
 *      MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *      Lesser General Public License for more details.
 *
 *      You should have received a copy of the GNU Lesser General Public
 *      License along with this library in the file COPYING.LIB;
 *      if not, write to the Free Software Foundation, Inc.,
 *      59 Temple Place - Suite 330, Boston, MA 02111-1307, USA
 */

#if !defined(_UWIN)
 /*#   include <process.h> */
#endif

int
pthread_mutex_lock(pthread_mutex_t * mutex)
{
	int kind;
	pthread_mutex_t mx;
	int result = 0;

	/*
	 * Let the system deal with invalid pointers.
	 */
	if (*mutex == NULL)
	{
		return EINVAL;
	}

	/*
	 * We do a quick check to see if we need to do more work
	 * to initialise a static mutex. We check
	 * again inside the guarded section of ptw32_mutex_check_need_init()
	 * to avoid race conditions.
	 */
	if (*mutex >= PTHREAD_ERRORCHECK_MUTEX_INITIALIZER)
	{
		if ((result = ptw32_mutex_check_need_init(mutex)) != 0)
		{
			return (result);
		}
	}

	mx = *mutex;
	kind = mx->kind;

	if (kind >= 0)
	{
		/* Non-robust */
		if (PTHREAD_MUTEX_NORMAL == kind)
		{
			if ((PTW32_INTERLOCKED_LONG)PTW32_INTERLOCKED_EXCHANGE_LONG(
				(PTW32_INTERLOCKED_LONGPTR)&mx->lock_idx,
				(PTW32_INTERLOCKED_LONG)1) != 0)
			{
				while ((PTW32_INTERLOCKED_LONG)PTW32_INTERLOCKED_EXCHANGE_LONG(
					(PTW32_INTERLOCKED_LONGPTR)&mx->lock_idx,
					(PTW32_INTERLOCKED_LONG)-1) != 0)
				{
					if (WAIT_OBJECT_0 != WaitForSingleObject(mx->event, INFINITE))
					{
						result = EINVAL;
						break;
					}
				}
			}
		}
		else
		{
			pthread_t self = pthread_self();

			if ((PTW32_INTERLOCKED_LONG)PTW32_INTERLOCKED_COMPARE_EXCHANGE_LONG(
				(PTW32_INTERLOCKED_LONGPTR)&mx->lock_idx,
				(PTW32_INTERLOCKED_LONG)1,
				(PTW32_INTERLOCKED_LONG)0) == 0)
			{
				mx->recursive_count = 1;
				mx->ownerThread = self;
			}
			else
			{
				if (pthread_equal(mx->ownerThread, self))
				{
					if (kind == PTHREAD_MUTEX_RECURSIVE)
					{
						mx->recursive_count++;
					}
					else
					{
						result = EDEADLK;
					}
				}
				else
				{
					while ((PTW32_INTERLOCKED_LONG)PTW32_INTERLOCKED_EXCHANGE_LONG(
						(PTW32_INTERLOCKED_LONGPTR)&mx->lock_idx,
						(PTW32_INTERLOCKED_LONG)-1) != 0)
					{
						if (WAIT_OBJECT_0 != WaitForSingleObject(mx->event, INFINITE))
						{
							result = EINVAL;
							break;
						}
					}

					if (0 == result)
					{
						mx->recursive_count = 1;
						mx->ownerThread = self;
					}
				}
			}
		}
	}
	else
	{
		/*
		 * Robust types
		 * All types record the current owner thread.
		 * The mutex is added to a per thread list when ownership is acquired.
		 */
		ptw32_robust_state_t* statePtr = &mx->robustNode->stateInconsistent;

		if ((PTW32_INTERLOCKED_LONG)PTW32_ROBUST_NOTRECOVERABLE == PTW32_INTERLOCKED_EXCHANGE_ADD_LONG(
			(PTW32_INTERLOCKED_LONGPTR)statePtr,
			(PTW32_INTERLOCKED_LONG)0))
		{
			result = ENOTRECOVERABLE;
		}
		else
		{
			pthread_t self = pthread_self();

			kind = -kind - 1; /* Convert to non-robust range */

			if (PTHREAD_MUTEX_NORMAL == kind)
			{
				if ((PTW32_INTERLOCKED_LONG)PTW32_INTERLOCKED_EXCHANGE_LONG(
					(PTW32_INTERLOCKED_LONGPTR)&mx->lock_idx,
					(PTW32_INTERLOCKED_LONG)1) != 0)
				{
					while (0 == (result = ptw32_robust_mutex_inherit(mutex))
						&& (PTW32_INTERLOCKED_LONG)PTW32_INTERLOCKED_EXCHANGE_LONG(
						(PTW32_INTERLOCKED_LONGPTR)&mx->lock_idx,
							(PTW32_INTERLOCKED_LONG)-1) != 0)
					{
						if (WAIT_OBJECT_0 != WaitForSingleObject(mx->event, INFINITE))
						{
							result = EINVAL;
							break;
						}
						if ((PTW32_INTERLOCKED_LONG)PTW32_ROBUST_NOTRECOVERABLE ==
							PTW32_INTERLOCKED_EXCHANGE_ADD_LONG(
							(PTW32_INTERLOCKED_LONGPTR)statePtr,
								(PTW32_INTERLOCKED_LONG)0))
						{
							/* Unblock the next thread */
							SetEvent(mx->event);
							result = ENOTRECOVERABLE;
							break;
						}
					}
				}
				if (0 == result || EOWNERDEAD == result)
				{
					/*
					 * Add mutex to the per-thread robust mutex currently-held list.
					 * If the thread terminates, all mutexes in this list will be unlocked.
					 */
					ptw32_robust_mutex_add(mutex, self);
				}
			}
			else
			{
				if ((PTW32_INTERLOCKED_LONG)PTW32_INTERLOCKED_COMPARE_EXCHANGE_LONG(
					(PTW32_INTERLOCKED_LONGPTR)&mx->lock_idx,
					(PTW32_INTERLOCKED_LONG)1,
					(PTW32_INTERLOCKED_LONG)0) == 0)
				{
					mx->recursive_count = 1;
					/*
					 * Add mutex to the per-thread robust mutex currently-held list.
					 * If the thread terminates, all mutexes in this list will be unlocked.
					 */
					ptw32_robust_mutex_add(mutex, self);
				}
				else
				{
					if (pthread_equal(mx->ownerThread, self))
					{
						if (PTHREAD_MUTEX_RECURSIVE == kind)
						{
							mx->recursive_count++;
						}
						else
						{
							result = EDEADLK;
						}
					}
					else
					{
						while (0 == (result = ptw32_robust_mutex_inherit(mutex))
							&& (PTW32_INTERLOCKED_LONG)PTW32_INTERLOCKED_EXCHANGE_LONG(
							(PTW32_INTERLOCKED_LONGPTR)&mx->lock_idx,
								(PTW32_INTERLOCKED_LONG)-1) != 0)
						{
							if (WAIT_OBJECT_0 != WaitForSingleObject(mx->event, INFINITE))
							{
								result = EINVAL;
								break;
							}
							if ((PTW32_INTERLOCKED_LONG)PTW32_ROBUST_NOTRECOVERABLE ==
								PTW32_INTERLOCKED_EXCHANGE_ADD_LONG(
								(PTW32_INTERLOCKED_LONGPTR)statePtr,
									(PTW32_INTERLOCKED_LONG)0))
							{
								/* Unblock the next thread */
								SetEvent(mx->event);
								result = ENOTRECOVERABLE;
								break;
							}
						}

						if (0 == result || EOWNERDEAD == result)
						{
							mx->recursive_count = 1;
							/*
							 * Add mutex to the per-thread robust mutex currently-held list.
							 * If the thread terminates, all mutexes in this list will be unlocked.
							 */
							ptw32_robust_mutex_add(mutex, self);
						}
					}
				}
			}
		}
	}

	return (result);
}

/*
 * pthread_mutex_timedlock.c
 *
 * Description:
 * This translation unit implements mutual exclusion (mutex) primitives.
 *
 * --------------------------------------------------------------------------
 *
 *      Pthreads-win32 - POSIX Threads Library for Win32
 *      Copyright(C) 1998 John E. Bossom
 *      Copyright(C) 1999,2005 Pthreads-win32 contributors
 *
 *      Contact Email: rpj@callisto.canberra.edu.au
 *
 *      The current list of contributors is contained
 *      in the file CONTRIBUTORS included with the source
 *      code distribution. The list can also be seen at the
 *      following World Wide Web location:
 *      http://sources.redhat.com/pthreads-win32/contributors.html
 *
 *      This library is free software; you can redistribute it and/or
 *      modify it under the terms of the GNU Lesser General Public
 *      License as published by the Free Software Foundation; either
 *      version 2 of the License, or (at your option) any later version.
 *
 *      This library is distributed in the hope that it will be useful,
 *      but WITHOUT ANY WARRANTY; without even the implied warranty of
 *      MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *      Lesser General Public License for more details.
 *
 *      You should have received a copy of the GNU Lesser General Public
 *      License along with this library in the file COPYING.LIB;
 *      if not, write to the Free Software Foundation, Inc.,
 *      59 Temple Place - Suite 330, Boston, MA 02111-1307, USA
 */



static INLINE int
ptw32_timed_eventwait(HANDLE event, const struct timespec *abstime)
/*
 * ------------------------------------------------------
 * DESCRIPTION
 *      This function waits on an event until signaled or until
 *      abstime passes.
 *      If abstime has passed when this routine is called then
 *      it returns a result to indicate this.
 *
 *      If 'abstime' is a NULL pointer then this function will
 *      block until it can successfully decrease the value or
 *      until interrupted by a signal.
 *
 *      This routine is not a cancelation point.
 *
 * RESULTS
 *              0               successfully signaled,
 *              ETIMEDOUT       abstime passed
 *              EINVAL          'event' is not a valid event,
 *
 * ------------------------------------------------------
 */
{

	DWORD milliseconds;
	DWORD status;

	if (event == NULL)
	{
		return EINVAL;
	}
	else
	{
		if (abstime == NULL)
		{
			milliseconds = INFINITE;
		}
		else
		{
			/*
			 * Calculate timeout as milliseconds from current system time.
			 */
			milliseconds = ptw32_relmillisecs(abstime);
		}

		status = WaitForSingleObject(event, milliseconds);

		if (status == WAIT_OBJECT_0)
		{
			return 0;
		}
		else if (status == WAIT_TIMEOUT)
		{
			return ETIMEDOUT;
		}
		else
		{
			return EINVAL;
		}
	}

	return 0;

}				/* ptw32_timed_semwait */


int
pthread_mutex_timedlock(pthread_mutex_t * mutex,
	const struct timespec *abstime)
{
	pthread_mutex_t mx;
	int kind;
	int result = 0;

	/*
	 * Let the system deal with invalid pointers.
	 */

	 /*
	  * We do a quick check to see if we need to do more work
	  * to initialise a static mutex. We check
	  * again inside the guarded section of ptw32_mutex_check_need_init()
	  * to avoid race conditions.
	  */
	if (*mutex >= PTHREAD_ERRORCHECK_MUTEX_INITIALIZER)
	{
		if ((result = ptw32_mutex_check_need_init(mutex)) != 0)
		{
			return (result);
		}
	}

	mx = *mutex;
	kind = mx->kind;

	if (kind >= 0)
	{
		if (mx->kind == PTHREAD_MUTEX_NORMAL)
		{
			if ((PTW32_INTERLOCKED_LONG)PTW32_INTERLOCKED_EXCHANGE_LONG(
				(PTW32_INTERLOCKED_LONGPTR)&mx->lock_idx,
				(PTW32_INTERLOCKED_LONG)1) != 0)
			{
				while ((PTW32_INTERLOCKED_LONG)PTW32_INTERLOCKED_EXCHANGE_LONG(
					(PTW32_INTERLOCKED_LONGPTR)&mx->lock_idx,
					(PTW32_INTERLOCKED_LONG)-1) != 0)
				{
					if (0 != (result = ptw32_timed_eventwait(mx->event, abstime)))
					{
						return result;
					}
				}
			}
		}
		else
		{
			pthread_t self = pthread_self();

			if ((PTW32_INTERLOCKED_LONG)PTW32_INTERLOCKED_COMPARE_EXCHANGE_LONG(
				(PTW32_INTERLOCKED_LONGPTR)&mx->lock_idx,
				(PTW32_INTERLOCKED_LONG)1,
				(PTW32_INTERLOCKED_LONG)0) == 0)
			{
				mx->recursive_count = 1;
				mx->ownerThread = self;
			}
			else
			{
				if (pthread_equal(mx->ownerThread, self))
				{
					if (mx->kind == PTHREAD_MUTEX_RECURSIVE)
					{
						mx->recursive_count++;
					}
					else
					{
						return EDEADLK;
					}
				}
				else
				{
					while ((PTW32_INTERLOCKED_LONG)PTW32_INTERLOCKED_EXCHANGE_LONG(
						(PTW32_INTERLOCKED_LONGPTR)&mx->lock_idx,
						(PTW32_INTERLOCKED_LONG)-1) != 0)
					{
						if (0 != (result = ptw32_timed_eventwait(mx->event, abstime)))
						{
							return result;
						}
					}

					mx->recursive_count = 1;
					mx->ownerThread = self;
				}
			}
		}
	}
	else
	{
		/*
		 * Robust types
		 * All types record the current owner thread.
		 * The mutex is added to a per thread list when ownership is acquired.
		 */
		ptw32_robust_state_t* statePtr = &mx->robustNode->stateInconsistent;

		if ((PTW32_INTERLOCKED_LONG)PTW32_ROBUST_NOTRECOVERABLE == PTW32_INTERLOCKED_EXCHANGE_ADD_LONG(
			(PTW32_INTERLOCKED_LONGPTR)statePtr,
			(PTW32_INTERLOCKED_LONG)0))
		{
			result = ENOTRECOVERABLE;
		}
		else
		{
			pthread_t self = pthread_self();

			kind = -kind - 1; /* Convert to non-robust range */

			if (PTHREAD_MUTEX_NORMAL == kind)
			{
				if ((PTW32_INTERLOCKED_LONG)PTW32_INTERLOCKED_EXCHANGE_LONG(
					(PTW32_INTERLOCKED_LONGPTR)&mx->lock_idx,
					(PTW32_INTERLOCKED_LONG)1) != 0)
				{
					while (0 == (result = ptw32_robust_mutex_inherit(mutex))
						&& (PTW32_INTERLOCKED_LONG)PTW32_INTERLOCKED_EXCHANGE_LONG(
						(PTW32_INTERLOCKED_LONGPTR)&mx->lock_idx,
							(PTW32_INTERLOCKED_LONG)-1) != 0)
					{
						if (0 != (result = ptw32_timed_eventwait(mx->event, abstime)))
						{
							return result;
						}
						if ((PTW32_INTERLOCKED_LONG)PTW32_ROBUST_NOTRECOVERABLE ==
							PTW32_INTERLOCKED_EXCHANGE_ADD_LONG(
							(PTW32_INTERLOCKED_LONGPTR)statePtr,
								(PTW32_INTERLOCKED_LONG)0))
						{
							/* Unblock the next thread */
							SetEvent(mx->event);
							result = ENOTRECOVERABLE;
							break;
						}
					}

					if (0 == result || EOWNERDEAD == result)
					{
						/*
						 * Add mutex to the per-thread robust mutex currently-held list.
						 * If the thread terminates, all mutexes in this list will be unlocked.
						 */
						ptw32_robust_mutex_add(mutex, self);
					}
				}
			}
			else
			{
				pthread_t self = pthread_self();

				if (0 == (PTW32_INTERLOCKED_LONG)PTW32_INTERLOCKED_COMPARE_EXCHANGE_LONG(
					(PTW32_INTERLOCKED_LONGPTR)&mx->lock_idx,
					(PTW32_INTERLOCKED_LONG)1,
					(PTW32_INTERLOCKED_LONG)0))
				{
					mx->recursive_count = 1;
					/*
					 * Add mutex to the per-thread robust mutex currently-held list.
					 * If the thread terminates, all mutexes in this list will be unlocked.
					 */
					ptw32_robust_mutex_add(mutex, self);
				}
				else
				{
					if (pthread_equal(mx->ownerThread, self))
					{
						if (PTHREAD_MUTEX_RECURSIVE == kind)
						{
							mx->recursive_count++;
						}
						else
						{
							return EDEADLK;
						}
					}
					else
					{
						while (0 == (result = ptw32_robust_mutex_inherit(mutex))
							&& (PTW32_INTERLOCKED_LONG)PTW32_INTERLOCKED_EXCHANGE_LONG(
							(PTW32_INTERLOCKED_LONGPTR)&mx->lock_idx,
								(PTW32_INTERLOCKED_LONG)-1) != 0)
						{
							if (0 != (result = ptw32_timed_eventwait(mx->event, abstime)))
							{
								return result;
							}
						}

						if ((PTW32_INTERLOCKED_LONG)PTW32_ROBUST_NOTRECOVERABLE ==
							PTW32_INTERLOCKED_EXCHANGE_ADD_LONG(
							(PTW32_INTERLOCKED_LONGPTR)statePtr,
								(PTW32_INTERLOCKED_LONG)0))
						{
							/* Unblock the next thread */
							SetEvent(mx->event);
							result = ENOTRECOVERABLE;
						}
						else if (0 == result || EOWNERDEAD == result)
						{
							mx->recursive_count = 1;
							/*
							 * Add mutex to the per-thread robust mutex currently-held list.
							 * If the thread terminates, all mutexes in this list will be unlocked.
							 */
							ptw32_robust_mutex_add(mutex, self);
						}
					}
				}
			}
		}
	}

	return result;
}
/*
 * pthread_mutex_trylock.c
 *
 * Description:
 * This translation unit implements mutual exclusion (mutex) primitives.
 *
 * --------------------------------------------------------------------------
 *
 *      Pthreads-win32 - POSIX Threads Library for Win32
 *      Copyright(C) 1998 John E. Bossom
 *      Copyright(C) 1999,2005 Pthreads-win32 contributors
 *
 *      Contact Email: rpj@callisto.canberra.edu.au
 *
 *      The current list of contributors is contained
 *      in the file CONTRIBUTORS included with the source
 *      code distribution. The list can also be seen at the
 *      following World Wide Web location:
 *      http://sources.redhat.com/pthreads-win32/contributors.html
 *
 *      This library is free software; you can redistribute it and/or
 *      modify it under the terms of the GNU Lesser General Public
 *      License as published by the Free Software Foundation; either
 *      version 2 of the License, or (at your option) any later version.
 *
 *      This library is distributed in the hope that it will be useful,
 *      but WITHOUT ANY WARRANTY; without even the implied warranty of
 *      MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *      Lesser General Public License for more details.
 *
 *      You should have received a copy of the GNU Lesser General Public
 *      License along with this library in the file COPYING.LIB;
 *      if not, write to the Free Software Foundation, Inc.,
 *      59 Temple Place - Suite 330, Boston, MA 02111-1307, USA
 */



int
pthread_mutex_trylock(pthread_mutex_t * mutex)
{
	pthread_mutex_t mx;
	int kind;
	int result = 0;

	/*
	 * Let the system deal with invalid pointers.
	 */

	 /*
	  * We do a quick check to see if we need to do more work
	  * to initialise a static mutex. We check
	  * again inside the guarded section of ptw32_mutex_check_need_init()
	  * to avoid race conditions.
	  */
	if (*mutex >= PTHREAD_ERRORCHECK_MUTEX_INITIALIZER)
	{
		if ((result = ptw32_mutex_check_need_init(mutex)) != 0)
		{
			return (result);
		}
	}

	mx = *mutex;
	kind = mx->kind;

	if (kind >= 0)
	{
		/* Non-robust */
		if (0 == (PTW32_INTERLOCKED_LONG)PTW32_INTERLOCKED_COMPARE_EXCHANGE_LONG(
			(PTW32_INTERLOCKED_LONGPTR)&mx->lock_idx,
			(PTW32_INTERLOCKED_LONG)1,
			(PTW32_INTERLOCKED_LONG)0))
		{
			if (kind != PTHREAD_MUTEX_NORMAL)
			{
				mx->recursive_count = 1;
				mx->ownerThread = pthread_self();
			}
		}
		else
		{
			if (kind == PTHREAD_MUTEX_RECURSIVE &&
				pthread_equal(mx->ownerThread, pthread_self()))
			{
				mx->recursive_count++;
			}
			else
			{
				result = EBUSY;
			}
		}
	}
	else
	{
		/*
		 * Robust types
		 * All types record the current owner thread.
		 * The mutex is added to a per thread list when ownership is acquired.
		 */
		pthread_t self;
		ptw32_robust_state_t* statePtr = &mx->robustNode->stateInconsistent;

		if ((PTW32_INTERLOCKED_LONG)PTW32_ROBUST_NOTRECOVERABLE ==
			PTW32_INTERLOCKED_EXCHANGE_ADD_LONG(
			(PTW32_INTERLOCKED_LONGPTR)statePtr,
				(PTW32_INTERLOCKED_LONG)0))
		{
			return ENOTRECOVERABLE;
		}

		self = pthread_self();
		kind = -kind - 1; /* Convert to non-robust range */

		if (0 == (PTW32_INTERLOCKED_LONG)PTW32_INTERLOCKED_COMPARE_EXCHANGE_LONG(
			(PTW32_INTERLOCKED_LONGPTR)&mx->lock_idx,
			(PTW32_INTERLOCKED_LONG)1,
			(PTW32_INTERLOCKED_LONG)0))
		{
			if (kind != PTHREAD_MUTEX_NORMAL)
			{
				mx->recursive_count = 1;
			}
			ptw32_robust_mutex_add(mutex, self);
		}
		else
		{
			if (PTHREAD_MUTEX_RECURSIVE == kind &&
				pthread_equal(mx->ownerThread, pthread_self()))
			{
				mx->recursive_count++;
			}
			else
			{
				if (EOWNERDEAD == (result = ptw32_robust_mutex_inherit(mutex)))
				{
					mx->recursive_count = 1;
					ptw32_robust_mutex_add(mutex, self);
				}
				else
				{
					if (0 == result)
					{
						result = EBUSY;
					}
				}
			}
		}
	}

	return (result);
}
/*
 * pthread_mutex_unlock.c
 *
 * Description:
 * This translation unit implements mutual exclusion (mutex) primitives.
 *
 * --------------------------------------------------------------------------
 *
 *      Pthreads-win32 - POSIX Threads Library for Win32
 *      Copyright(C) 1998 John E. Bossom
 *      Copyright(C) 1999,2005 Pthreads-win32 contributors
 *
 *      Contact Email: rpj@callisto.canberra.edu.au
 *
 *      The current list of contributors is contained
 *      in the file CONTRIBUTORS included with the source
 *      code distribution. The list can also be seen at the
 *      following World Wide Web location:
 *      http://sources.redhat.com/pthreads-win32/contributors.html
 *
 *      This library is free software; you can redistribute it and/or
 *      modify it under the terms of the GNU Lesser General Public
 *      License as published by the Free Software Foundation; either
 *      version 2 of the License, or (at your option) any later version.
 *
 *      This library is distributed in the hope that it will be useful,
 *      but WITHOUT ANY WARRANTY; without even the implied warranty of
 *      MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *      Lesser General Public License for more details.
 *
 *      You should have received a copy of the GNU Lesser General Public
 *      License along with this library in the file COPYING.LIB;
 *      if not, write to the Free Software Foundation, Inc.,
 *      59 Temple Place - Suite 330, Boston, MA 02111-1307, USA
 */



int
pthread_mutex_unlock(pthread_mutex_t * mutex)
{
	int result = 0;
	int kind;
	pthread_mutex_t mx;

	/*
	 * Let the system deal with invalid pointers.
	 */

	mx = *mutex;

	/*
	 * If the thread calling us holds the mutex then there is no
	 * race condition. If another thread holds the
	 * lock then we shouldn't be in here.
	 */
	if (mx < PTHREAD_ERRORCHECK_MUTEX_INITIALIZER)
	{
		kind = mx->kind;

		if (kind >= 0)
		{
			if (kind == PTHREAD_MUTEX_NORMAL)
			{
				LONG idx;

				idx = (LONG)PTW32_INTERLOCKED_EXCHANGE_LONG((PTW32_INTERLOCKED_LONGPTR)&mx->lock_idx,
					(PTW32_INTERLOCKED_LONG)0);
				if (idx != 0)
				{
					if (idx < 0)
					{
						/*
						 * Someone may be waiting on that mutex.
						 */
						if (SetEvent(mx->event) == 0)
						{
							result = EINVAL;
						}
					}
				}
			}
			else
			{
				if (pthread_equal(mx->ownerThread, pthread_self()))
				{
					if (kind != PTHREAD_MUTEX_RECURSIVE
						|| 0 == --mx->recursive_count)
					{
						mx->ownerThread.p = NULL;

						if ((LONG)PTW32_INTERLOCKED_EXCHANGE_LONG((PTW32_INTERLOCKED_LONGPTR)&mx->lock_idx,
							(PTW32_INTERLOCKED_LONG)0) < 0L)
						{
							/* Someone may be waiting on that mutex */
							if (SetEvent(mx->event) == 0)
							{
								result = EINVAL;
							}
						}
					}
				}
				else
				{
					result = EPERM;
				}
			}
		}
		else
		{
			/* Robust types */
			pthread_t self = pthread_self();
			kind = -kind - 1; /* Convert to non-robust range */

			/*
			 * The thread must own the lock regardless of type if the mutex
			 * is robust.
			 */
			if (pthread_equal(mx->ownerThread, self))
			{
				PTW32_INTERLOCKED_COMPARE_EXCHANGE_LONG((PTW32_INTERLOCKED_LONGPTR)&mx->robustNode->stateInconsistent,
					(PTW32_INTERLOCKED_LONG)PTW32_ROBUST_NOTRECOVERABLE,
					(PTW32_INTERLOCKED_LONG)PTW32_ROBUST_INCONSISTENT);
				if (PTHREAD_MUTEX_NORMAL == kind)
				{
					ptw32_robust_mutex_remove(mutex, NULL);

					if ((LONG)PTW32_INTERLOCKED_EXCHANGE_LONG((PTW32_INTERLOCKED_LONGPTR)&mx->lock_idx,
						(PTW32_INTERLOCKED_LONG)0) < 0)
					{
						/*
						 * Someone may be waiting on that mutex.
						 */
						if (SetEvent(mx->event) == 0)
						{
							result = EINVAL;
						}
					}
				}
				else
				{
					if (kind != PTHREAD_MUTEX_RECURSIVE
						|| 0 == --mx->recursive_count)
					{
						ptw32_robust_mutex_remove(mutex, NULL);

						if ((LONG)PTW32_INTERLOCKED_EXCHANGE_LONG((PTW32_INTERLOCKED_LONGPTR)&mx->lock_idx,
							(PTW32_INTERLOCKED_LONG)0) < 0)
						{
							/*
							 * Someone may be waiting on that mutex.
							 */
							if (SetEvent(mx->event) == 0)
							{
								result = EINVAL;
							}
						}
					}
				}
			}
			else
			{
				result = EPERM;
			}
		}
	}
	else if (mx != PTHREAD_MUTEX_INITIALIZER)
	{
		result = EINVAL;
	}

	return (result);
}
/*
 * pthread_num_processors_np.c
 *
 * Description:
 * This translation unit implements non-portable thread functions.
 *
 * --------------------------------------------------------------------------
 *
 *      Pthreads-win32 - POSIX Threads Library for Win32
 *      Copyright(C) 1998 John E. Bossom
 *      Copyright(C) 1999,2005 Pthreads-win32 contributors
 *
 *      Contact Email: rpj@callisto.canberra.edu.au
 *
 *      The current list of contributors is contained
 *      in the file CONTRIBUTORS included with the source
 *      code distribution. The list can also be seen at the
 *      following World Wide Web location:
 *      http://sources.redhat.com/pthreads-win32/contributors.html
 *
 *      This library is free software; you can redistribute it and/or
 *      modify it under the terms of the GNU Lesser General Public
 *      License as published by the Free Software Foundation; either
 *      version 2 of the License, or (at your option) any later version.
 *
 *      This library is distributed in the hope that it will be useful,
 *      but WITHOUT ANY WARRANTY; without even the implied warranty of
 *      MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *      Lesser General Public License for more details.
 *
 *      You should have received a copy of the GNU Lesser General Public
 *      License along with this library in the file COPYING.LIB;
 *      if not, write to the Free Software Foundation, Inc.,
 *      59 Temple Place - Suite 330, Boston, MA 02111-1307, USA
 */


 /*
  * pthread_num_processors_np()
  *
  * Get the number of CPUs available to the process.
  */
int
pthread_num_processors_np(void)
{
	int count;

	if (ptw32_getprocessors(&count) != 0)
	{
		count = 1;
	}

	return (count);
}
/*
 * pthread_once.c
 *
 * Description:
 * This translation unit implements miscellaneous thread functions.
 *
 * --------------------------------------------------------------------------
 *
 *      Pthreads-win32 - POSIX Threads Library for Win32
 *      Copyright(C) 1998 John E. Bossom
 *      Copyright(C) 1999,2005 Pthreads-win32 contributors
 *
 *      Contact Email: rpj@callisto.canberra.edu.au
 *
 *      The current list of contributors is contained
 *      in the file CONTRIBUTORS included with the source
 *      code distribution. The list can also be seen at the
 *      following World Wide Web location:
 *      http://sources.redhat.com/pthreads-win32/contributors.html
 *
 *      This library is free software; you can redistribute it and/or
 *      modify it under the terms of the GNU Lesser General Public
 *      License as published by the Free Software Foundation; either
 *      version 2 of the License, or (at your option) any later version.
 *
 *      This library is distributed in the hope that it will be useful,
 *      but WITHOUT ANY WARRANTY; without even the implied warranty of
 *      MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *      Lesser General Public License for more details.
 *
 *      You should have received a copy of the GNU Lesser General Public
 *      License along with this library in the file COPYING.LIB;
 *      if not, write to the Free Software Foundation, Inc.,
 *      59 Temple Place - Suite 330, Boston, MA 02111-1307, USA
 */


int
pthread_once(pthread_once_t * once_control, void (PTW32_CDECL *init_routine) (void))
{
	if (once_control == NULL || init_routine == NULL)
	{
		return EINVAL;
	}

	if ((PTW32_INTERLOCKED_LONG)PTW32_FALSE ==
		(PTW32_INTERLOCKED_LONG)PTW32_INTERLOCKED_EXCHANGE_ADD_LONG((PTW32_INTERLOCKED_LONGPTR)&once_control->done,
		(PTW32_INTERLOCKED_LONG)0)) /* MBR fence */
	{
		ptw32_mcs_local_node_t node;

		ptw32_mcs_lock_acquire((ptw32_mcs_lock_t *)&once_control->lock, &node);

		if (!once_control->done)
		{

#if defined(_MSC_VER) && _MSC_VER < 1400
#pragma inline_depth(0)
#endif

			pthread_cleanup_push(ptw32_mcs_lock_release, &node);
			(*init_routine)();
			pthread_cleanup_pop(0);

#if defined(_MSC_VER) && _MSC_VER < 1400
#pragma inline_depth()
#endif

			once_control->done = PTW32_TRUE;
		}

		ptw32_mcs_lock_release(&node);
	}

	return 0;

}				/* pthread_once */
/*
 * pthread_rwlockattr_destroy.c
 *
 * Description:
 * This translation unit implements read/write lock primitives.
 *
 * --------------------------------------------------------------------------
 *
 *      Pthreads-win32 - POSIX Threads Library for Win32
 *      Copyright(C) 1998 John E. Bossom
 *      Copyright(C) 1999,2005 Pthreads-win32 contributors
 *
 *      Contact Email: rpj@callisto.canberra.edu.au
 *
 *      The current list of contributors is contained
 *      in the file CONTRIBUTORS included with the source
 *      code distribution. The list can also be seen at the
 *      following World Wide Web location:
 *      http://sources.redhat.com/pthreads-win32/contributors.html
 *
 *      This library is free software; you can redistribute it and/or
 *      modify it under the terms of the GNU Lesser General Public
 *      License as published by the Free Software Foundation; either
 *      version 2 of the License, or (at your option) any later version.
 *
 *      This library is distributed in the hope that it will be useful,
 *      but WITHOUT ANY WARRANTY; without even the implied warranty of
 *      MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *      Lesser General Public License for more details.
 *
 *      You should have received a copy of the GNU Lesser General Public
 *      License along with this library in the file COPYING.LIB;
 *      if not, write to the Free Software Foundation, Inc.,
 *      59 Temple Place - Suite 330, Boston, MA 02111-1307, USA
 */



int
pthread_rwlockattr_destroy(pthread_rwlockattr_t * attr)
/*
 * ------------------------------------------------------
 * DOCPUBLIC
 *      Destroys a rwlock attributes object. The object can
 *      no longer be used.
 *
 * PARAMETERS
 *      attr
 *              pointer to an instance of pthread_rwlockattr_t
 *
 *
 * DESCRIPTION
 *      Destroys a rwlock attributes object. The object can
 *      no longer be used.
 *
 *      NOTES:
 *              1)      Does not affect rwlockss created using 'attr'
 *
 * RESULTS
 *              0               successfully released attr,
 *              EINVAL          'attr' is invalid.
 *
 * ------------------------------------------------------
 */
{
	int result = 0;

	if (attr == NULL || *attr == NULL)
	{
		result = EINVAL;
	}
	else
	{
		pthread_rwlockattr_t rwa = *attr;

		*attr = NULL;
		free(rwa);
	}

	return (result);
}				/* pthread_rwlockattr_destroy */
/*
 * pthread_rwlockattr_getpshared.c
 *
 * Description:
 * This translation unit implements read/write lock primitives.
 *
 * --------------------------------------------------------------------------
 *
 *      Pthreads-win32 - POSIX Threads Library for Win32
 *      Copyright(C) 1998 John E. Bossom
 *      Copyright(C) 1999,2005 Pthreads-win32 contributors
 *
 *      Contact Email: rpj@callisto.canberra.edu.au
 *
 *      The current list of contributors is contained
 *      in the file CONTRIBUTORS included with the source
 *      code distribution. The list can also be seen at the
 *      following World Wide Web location:
 *      http://sources.redhat.com/pthreads-win32/contributors.html
 *
 *      This library is free software; you can redistribute it and/or
 *      modify it under the terms of the GNU Lesser General Public
 *      License as published by the Free Software Foundation; either
 *      version 2 of the License, or (at your option) any later version.
 *
 *      This library is distributed in the hope that it will be useful,
 *      but WITHOUT ANY WARRANTY; without even the implied warranty of
 *      MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *      Lesser General Public License for more details.
 *
 *      You should have received a copy of the GNU Lesser General Public
 *      License along with this library in the file COPYING.LIB;
 *      if not, write to the Free Software Foundation, Inc.,
 *      59 Temple Place - Suite 330, Boston, MA 02111-1307, USA
 */



int
pthread_rwlockattr_getpshared(const pthread_rwlockattr_t * attr,
	int *pshared)
	/*
	 * ------------------------------------------------------
	 * DOCPUBLIC
	 *      Determine whether rwlocks created with 'attr' can be
	 *      shared between processes.
	 *
	 * PARAMETERS
	 *      attr
	 *              pointer to an instance of pthread_rwlockattr_t
	 *
	 *      pshared
	 *              will be set to one of:
	 *
	 *                      PTHREAD_PROCESS_SHARED
	 *                              May be shared if in shared memory
	 *
	 *                      PTHREAD_PROCESS_PRIVATE
	 *                              Cannot be shared.
	 *
	 *
	 * DESCRIPTION
	 *      Rwlocks creatd with 'attr' can be shared between
	 *      processes if pthread_rwlock_t variable is allocated
	 *      in memory shared by these processes.
	 *      NOTES:
	 *              1)      pshared rwlocks MUST be allocated in shared
	 *                      memory.
	 *              2)      The following macro is defined if shared rwlocks
	 *                      are supported:
	 *                              _POSIX_THREAD_PROCESS_SHARED
	 *
	 * RESULTS
	 *              0               successfully retrieved attribute,
	 *              EINVAL          'attr' is invalid,
	 *
	 * ------------------------------------------------------
	 */
{
	int result;

	if ((attr != NULL && *attr != NULL) && (pshared != NULL))
	{
		*pshared = (*attr)->pshared;
		result = 0;
	}
	else
	{
		result = EINVAL;
	}

	return (result);

}				/* pthread_rwlockattr_getpshared */
/*
 * pthread_rwlockattr_init.c
 *
 * Description:
 * This translation unit implements read/write lock primitives.
 *
 * --------------------------------------------------------------------------
 *
 *      Pthreads-win32 - POSIX Threads Library for Win32
 *      Copyright(C) 1998 John E. Bossom
 *      Copyright(C) 1999,2005 Pthreads-win32 contributors
 *
 *      Contact Email: rpj@callisto.canberra.edu.au
 *
 *      The current list of contributors is contained
 *      in the file CONTRIBUTORS included with the source
 *      code distribution. The list can also be seen at the
 *      following World Wide Web location:
 *      http://sources.redhat.com/pthreads-win32/contributors.html
 *
 *      This library is free software; you can redistribute it and/or
 *      modify it under the terms of the GNU Lesser General Public
 *      License as published by the Free Software Foundation; either
 *      version 2 of the License, or (at your option) any later version.
 *
 *      This library is distributed in the hope that it will be useful,
 *      but WITHOUT ANY WARRANTY; without even the implied warranty of
 *      MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *      Lesser General Public License for more details.
 *
 *      You should have received a copy of the GNU Lesser General Public
 *      License along with this library in the file COPYING.LIB;
 *      if not, write to the Free Software Foundation, Inc.,
 *      59 Temple Place - Suite 330, Boston, MA 02111-1307, USA
 */



int
pthread_rwlockattr_init(pthread_rwlockattr_t * attr)
/*
 * ------------------------------------------------------
 * DOCPUBLIC
 *      Initializes a rwlock attributes object with default
 *      attributes.
 *
 * PARAMETERS
 *      attr
 *              pointer to an instance of pthread_rwlockattr_t
 *
 *
 * DESCRIPTION
 *      Initializes a rwlock attributes object with default
 *      attributes.
 *
 * RESULTS
 *              0               successfully initialized attr,
 *              ENOMEM          insufficient memory for attr.
 *
 * ------------------------------------------------------
 */
{
	int result = 0;
	pthread_rwlockattr_t rwa;

	rwa = (pthread_rwlockattr_t)calloc(1, sizeof(*rwa));

	if (rwa == NULL)
	{
		result = ENOMEM;
	}
	else
	{
		rwa->pshared = PTHREAD_PROCESS_PRIVATE;
	}

	*attr = rwa;

	return (result);
}				/* pthread_rwlockattr_init */
/*
 * pthread_rwlockattr_setpshared.c
 *
 * Description:
 * This translation unit implements read/write lock primitives.
 *
 * --------------------------------------------------------------------------
 *
 *      Pthreads-win32 - POSIX Threads Library for Win32
 *      Copyright(C) 1998 John E. Bossom
 *      Copyright(C) 1999,2005 Pthreads-win32 contributors
 *
 *      Contact Email: rpj@callisto.canberra.edu.au
 *
 *      The current list of contributors is contained
 *      in the file CONTRIBUTORS included with the source
 *      code distribution. The list can also be seen at the
 *      following World Wide Web location:
 *      http://sources.redhat.com/pthreads-win32/contributors.html
 *
 *      This library is free software; you can redistribute it and/or
 *      modify it under the terms of the GNU Lesser General Public
 *      License as published by the Free Software Foundation; either
 *      version 2 of the License, or (at your option) any later version.
 *
 *      This library is distributed in the hope that it will be useful,
 *      but WITHOUT ANY WARRANTY; without even the implied warranty of
 *      MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *      Lesser General Public License for more details.
 *
 *      You should have received a copy of the GNU Lesser General Public
 *      License along with this library in the file COPYING.LIB;
 *      if not, write to the Free Software Foundation, Inc.,
 *      59 Temple Place - Suite 330, Boston, MA 02111-1307, USA
 */



int
pthread_rwlockattr_setpshared(pthread_rwlockattr_t * attr, int pshared)
/*
 * ------------------------------------------------------
 * DOCPUBLIC
 *      Rwlocks created with 'attr' can be shared between
 *      processes if pthread_rwlock_t variable is allocated
 *      in memory shared by these processes.
 *
 * PARAMETERS
 *      attr
 *              pointer to an instance of pthread_rwlockattr_t
 *
 *      pshared
 *              must be one of:
 *
 *                      PTHREAD_PROCESS_SHARED
 *                              May be shared if in shared memory
 *
 *                      PTHREAD_PROCESS_PRIVATE
 *                              Cannot be shared.
 *
 * DESCRIPTION
 *      Rwlocks creatd with 'attr' can be shared between
 *      processes if pthread_rwlock_t variable is allocated
 *      in memory shared by these processes.
 *
 *      NOTES:
 *              1)      pshared rwlocks MUST be allocated in shared
 *                      memory.
 *
 *              2)      The following macro is defined if shared rwlocks
 *                      are supported:
 *                              _POSIX_THREAD_PROCESS_SHARED
 *
 * RESULTS
 *              0               successfully set attribute,
 *              EINVAL          'attr' or pshared is invalid,
 *              ENOSYS          PTHREAD_PROCESS_SHARED not supported,
 *
 * ------------------------------------------------------
 */
{
	int result;

	if ((attr != NULL && *attr != NULL) &&
		((pshared == PTHREAD_PROCESS_SHARED) ||
		(pshared == PTHREAD_PROCESS_PRIVATE)))
	{
		if (pshared == PTHREAD_PROCESS_SHARED)
		{

#if !defined( _POSIX_THREAD_PROCESS_SHARED )

			result = ENOSYS;
			pshared = PTHREAD_PROCESS_PRIVATE;

#else

			result = 0;

#endif /* _POSIX_THREAD_PROCESS_SHARED */

		}
		else
		{
			result = 0;
		}

		(*attr)->pshared = pshared;
	}
	else
	{
		result = EINVAL;
	}

	return (result);

}				/* pthread_rwlockattr_setpshared */
/*
 * pthread_rwlock_destroy.c
 *
 * Description:
 * This translation unit implements read/write lock primitives.
 *
 * --------------------------------------------------------------------------
 *
 *      Pthreads-win32 - POSIX Threads Library for Win32
 *      Copyright(C) 1998 John E. Bossom
 *      Copyright(C) 1999,2005 Pthreads-win32 contributors
 *
 *      Contact Email: rpj@callisto.canberra.edu.au
 *
 *      The current list of contributors is contained
 *      in the file CONTRIBUTORS included with the source
 *      code distribution. The list can also be seen at the
 *      following World Wide Web location:
 *      http://sources.redhat.com/pthreads-win32/contributors.html
 *
 *      This library is free software; you can redistribute it and/or
 *      modify it under the terms of the GNU Lesser General Public
 *      License as published by the Free Software Foundation; either
 *      version 2 of the License, or (at your option) any later version.
 *
 *      This library is distributed in the hope that it will be useful,
 *      but WITHOUT ANY WARRANTY; without even the implied warranty of
 *      MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *      Lesser General Public License for more details.
 *
 *      You should have received a copy of the GNU Lesser General Public
 *      License along with this library in the file COPYING.LIB;
 *      if not, write to the Free Software Foundation, Inc.,
 *      59 Temple Place - Suite 330, Boston, MA 02111-1307, USA
 */



int
pthread_rwlock_destroy(pthread_rwlock_t * rwlock)
{
	pthread_rwlock_t rwl;
	int result = 0, result1 = 0, result2 = 0;

	if (rwlock == NULL || *rwlock == NULL)
	{
		return EINVAL;
	}

	if (*rwlock != PTHREAD_RWLOCK_INITIALIZER)
	{
		rwl = *rwlock;

		if (rwl->nMagic != PTW32_RWLOCK_MAGIC)
		{
			return EINVAL;
		}

		if ((result = pthread_mutex_lock(&(rwl->mtxExclusiveAccess))) != 0)
		{
			return result;
		}

		if ((result =
			pthread_mutex_lock(&(rwl->mtxSharedAccessCompleted))) != 0)
		{
			(void)pthread_mutex_unlock(&(rwl->mtxExclusiveAccess));
			return result;
		}

		/*
		 * Check whether any threads own/wait for the lock (wait for ex.access);
		 * report "BUSY" if so.
		 */
		if (rwl->nExclusiveAccessCount > 0
			|| rwl->nSharedAccessCount > rwl->nCompletedSharedAccessCount)
		{
			result = pthread_mutex_unlock(&(rwl->mtxSharedAccessCompleted));
			result1 = pthread_mutex_unlock(&(rwl->mtxExclusiveAccess));
			result2 = EBUSY;
		}
		else
		{
			rwl->nMagic = 0;

			if ((result =
				pthread_mutex_unlock(&(rwl->mtxSharedAccessCompleted))) != 0)
			{
				pthread_mutex_unlock(&rwl->mtxExclusiveAccess);
				return result;
			}

			if ((result =
				pthread_mutex_unlock(&(rwl->mtxExclusiveAccess))) != 0)
			{
				return result;
			}

			*rwlock = NULL;	/* Invalidate rwlock before anything else */
			result = pthread_cond_destroy(&(rwl->cndSharedAccessCompleted));
			result1 = pthread_mutex_destroy(&(rwl->mtxSharedAccessCompleted));
			result2 = pthread_mutex_destroy(&(rwl->mtxExclusiveAccess));
			(void)free(rwl);
		}
	}
	else
	{
		ptw32_mcs_local_node_t node;
		/*
		 * See notes in ptw32_rwlock_check_need_init() above also.
		 */
		ptw32_mcs_lock_acquire(&ptw32_rwlock_test_init_lock, &node);

		/*
		 * Check again.
		 */
		if (*rwlock == PTHREAD_RWLOCK_INITIALIZER)
		{
			/*
			 * This is all we need to do to destroy a statically
			 * initialised rwlock that has not yet been used (initialised).
			 * If we get to here, another thread
			 * waiting to initialise this rwlock will get an EINVAL.
			 */
			*rwlock = NULL;
		}
		else
		{
			/*
			 * The rwlock has been initialised while we were waiting
			 * so assume it's in use.
			 */
			result = EBUSY;
		}

		ptw32_mcs_lock_release(&node);
	}

	return ((result != 0) ? result : ((result1 != 0) ? result1 : result2));
}
/*
 * pthread_rwlock_init.c
 *
 * Description:
 * This translation unit implements read/write lock primitives.
 *
 * --------------------------------------------------------------------------
 *
 *      Pthreads-win32 - POSIX Threads Library for Win32
 *      Copyright(C) 1998 John E. Bossom
 *      Copyright(C) 1999,2005 Pthreads-win32 contributors
 *
 *      Contact Email: rpj@callisto.canberra.edu.au
 *
 *      The current list of contributors is contained
 *      in the file CONTRIBUTORS included with the source
 *      code distribution. The list can also be seen at the
 *      following World Wide Web location:
 *      http://sources.redhat.com/pthreads-win32/contributors.html
 *
 *      This library is free software; you can redistribute it and/or
 *      modify it under the terms of the GNU Lesser General Public
 *      License as published by the Free Software Foundation; either
 *      version 2 of the License, or (at your option) any later version.
 *
 *      This library is distributed in the hope that it will be useful,
 *      but WITHOUT ANY WARRANTY; without even the implied warranty of
 *      MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *      Lesser General Public License for more details.
 *
 *      You should have received a copy of the GNU Lesser General Public
 *      License along with this library in the file COPYING.LIB;
 *      if not, write to the Free Software Foundation, Inc.,
 *      59 Temple Place - Suite 330, Boston, MA 02111-1307, USA
 */



int
pthread_rwlock_init(pthread_rwlock_t * rwlock,
	const pthread_rwlockattr_t * attr)
{
	int result;
	pthread_rwlock_t rwl = 0;

	if (rwlock == NULL)
	{
		return EINVAL;
	}

	if (attr != NULL && *attr != NULL)
	{
		result = EINVAL;		/* Not supported */
		goto DONE;
	}

	rwl = (pthread_rwlock_t)calloc(1, sizeof(*rwl));

	if (rwl == NULL)
	{
		result = ENOMEM;
		goto DONE;
	}

	rwl->nSharedAccessCount = 0;
	rwl->nExclusiveAccessCount = 0;
	rwl->nCompletedSharedAccessCount = 0;

	result = pthread_mutex_init(&rwl->mtxExclusiveAccess, NULL);
	if (result != 0)
	{
		goto FAIL0;
	}

	result = pthread_mutex_init(&rwl->mtxSharedAccessCompleted, NULL);
	if (result != 0)
	{
		goto FAIL1;
	}

	result = pthread_cond_init(&rwl->cndSharedAccessCompleted, NULL);
	if (result != 0)
	{
		goto FAIL2;
	}

	rwl->nMagic = PTW32_RWLOCK_MAGIC;

	result = 0;
	goto DONE;

FAIL2:
	(void)pthread_mutex_destroy(&(rwl->mtxSharedAccessCompleted));

FAIL1:
	(void)pthread_mutex_destroy(&(rwl->mtxExclusiveAccess));

FAIL0:
	(void)free(rwl);
	rwl = NULL;

DONE:
	*rwlock = rwl;

	return result;
}
/*
 * pthread_rwlock_rdlock.c
 *
 * Description:
 * This translation unit implements read/write lock primitives.
 *
 * --------------------------------------------------------------------------
 *
 *      Pthreads-win32 - POSIX Threads Library for Win32
 *      Copyright(C) 1998 John E. Bossom
 *      Copyright(C) 1999,2005 Pthreads-win32 contributors
 *
 *      Contact Email: rpj@callisto.canberra.edu.au
 *
 *      The current list of contributors is contained
 *      in the file CONTRIBUTORS included with the source
 *      code distribution. The list can also be seen at the
 *      following World Wide Web location:
 *      http://sources.redhat.com/pthreads-win32/contributors.html
 *
 *      This library is free software; you can redistribute it and/or
 *      modify it under the terms of the GNU Lesser General Public
 *      License as published by the Free Software Foundation; either
 *      version 2 of the License, or (at your option) any later version.
 *
 *      This library is distributed in the hope that it will be useful,
 *      but WITHOUT ANY WARRANTY; without even the implied warranty of
 *      MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *      Lesser General Public License for more details.
 *
 *      You should have received a copy of the GNU Lesser General Public
 *      License along with this library in the file COPYING.LIB;
 *      if not, write to the Free Software Foundation, Inc.,
 *      59 Temple Place - Suite 330, Boston, MA 02111-1307, USA
 */



int
pthread_rwlock_rdlock(pthread_rwlock_t * rwlock)
{
	int result;
	pthread_rwlock_t rwl;

	if (rwlock == NULL || *rwlock == NULL)
	{
		return EINVAL;
	}

	/*
	 * We do a quick check to see if we need to do more work
	 * to initialise a static rwlock. We check
	 * again inside the guarded section of ptw32_rwlock_check_need_init()
	 * to avoid race conditions.
	 */
	if (*rwlock == PTHREAD_RWLOCK_INITIALIZER)
	{
		result = ptw32_rwlock_check_need_init(rwlock);

		if (result != 0 && result != EBUSY)
		{
			return result;
		}
	}

	rwl = *rwlock;

	if (rwl->nMagic != PTW32_RWLOCK_MAGIC)
	{
		return EINVAL;
	}

	if ((result = pthread_mutex_lock(&(rwl->mtxExclusiveAccess))) != 0)
	{
		return result;
	}

	if (++rwl->nSharedAccessCount == INT_MAX)
	{
		if ((result =
			pthread_mutex_lock(&(rwl->mtxSharedAccessCompleted))) != 0)
		{
			(void)pthread_mutex_unlock(&(rwl->mtxExclusiveAccess));
			return result;
		}

		rwl->nSharedAccessCount -= rwl->nCompletedSharedAccessCount;
		rwl->nCompletedSharedAccessCount = 0;

		if ((result =
			pthread_mutex_unlock(&(rwl->mtxSharedAccessCompleted))) != 0)
		{
			(void)pthread_mutex_unlock(&(rwl->mtxExclusiveAccess));
			return result;
		}
	}

	return (pthread_mutex_unlock(&(rwl->mtxExclusiveAccess)));
}
/*
 * pthread_rwlock_timedrdlock.c
 *
 * Description:
 * This translation unit implements read/write lock primitives.
 *
 * --------------------------------------------------------------------------
 *
 *      Pthreads-win32 - POSIX Threads Library for Win32
 *      Copyright(C) 1998 John E. Bossom
 *      Copyright(C) 1999,2005 Pthreads-win32 contributors
 *
 *      Contact Email: rpj@callisto.canberra.edu.au
 *
 *      The current list of contributors is contained
 *      in the file CONTRIBUTORS included with the source
 *      code distribution. The list can also be seen at the
 *      following World Wide Web location:
 *      http://sources.redhat.com/pthreads-win32/contributors.html
 *
 *      This library is free software; you can redistribute it and/or
 *      modify it under the terms of the GNU Lesser General Public
 *      License as published by the Free Software Foundation; either
 *      version 2 of the License, or (at your option) any later version.
 *
 *      This library is distributed in the hope that it will be useful,
 *      but WITHOUT ANY WARRANTY; without even the implied warranty of
 *      MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *      Lesser General Public License for more details.
 *
 *      You should have received a copy of the GNU Lesser General Public
 *      License along with this library in the file COPYING.LIB;
 *      if not, write to the Free Software Foundation, Inc.,
 *      59 Temple Place - Suite 330, Boston, MA 02111-1307, USA
 */



int
pthread_rwlock_timedrdlock(pthread_rwlock_t * rwlock,
	const struct timespec *abstime)
{
	int result;
	pthread_rwlock_t rwl;

	if (rwlock == NULL || *rwlock == NULL)
	{
		return EINVAL;
	}

	/*
	 * We do a quick check to see if we need to do more work
	 * to initialise a static rwlock. We check
	 * again inside the guarded section of ptw32_rwlock_check_need_init()
	 * to avoid race conditions.
	 */
	if (*rwlock == PTHREAD_RWLOCK_INITIALIZER)
	{
		result = ptw32_rwlock_check_need_init(rwlock);

		if (result != 0 && result != EBUSY)
		{
			return result;
		}
	}

	rwl = *rwlock;

	if (rwl->nMagic != PTW32_RWLOCK_MAGIC)
	{
		return EINVAL;
	}

	if ((result =
		pthread_mutex_timedlock(&(rwl->mtxExclusiveAccess), abstime)) != 0)
	{
		return result;
	}

	if (++rwl->nSharedAccessCount == INT_MAX)
	{
		if ((result =
			pthread_mutex_timedlock(&(rwl->mtxSharedAccessCompleted),
				abstime)) != 0)
		{
			if (result == ETIMEDOUT)
			{
				++rwl->nCompletedSharedAccessCount;
			}
			(void)pthread_mutex_unlock(&(rwl->mtxExclusiveAccess));
			return result;
		}

		rwl->nSharedAccessCount -= rwl->nCompletedSharedAccessCount;
		rwl->nCompletedSharedAccessCount = 0;

		if ((result =
			pthread_mutex_unlock(&(rwl->mtxSharedAccessCompleted))) != 0)
		{
			(void)pthread_mutex_unlock(&(rwl->mtxExclusiveAccess));
			return result;
		}
	}

	return (pthread_mutex_unlock(&(rwl->mtxExclusiveAccess)));
}
/*
 * pthread_rwlock_timedwrlock.c
 *
 * Description:
 * This translation unit implements read/write lock primitives.
 *
 * --------------------------------------------------------------------------
 *
 *      Pthreads-win32 - POSIX Threads Library for Win32
 *      Copyright(C) 1998 John E. Bossom
 *      Copyright(C) 1999,2005 Pthreads-win32 contributors
 *
 *      Contact Email: rpj@callisto.canberra.edu.au
 *
 *      The current list of contributors is contained
 *      in the file CONTRIBUTORS included with the source
 *      code distribution. The list can also be seen at the
 *      following World Wide Web location:
 *      http://sources.redhat.com/pthreads-win32/contributors.html
 *
 *      This library is free software; you can redistribute it and/or
 *      modify it under the terms of the GNU Lesser General Public
 *      License as published by the Free Software Foundation; either
 *      version 2 of the License, or (at your option) any later version.
 *
 *      This library is distributed in the hope that it will be useful,
 *      but WITHOUT ANY WARRANTY; without even the implied warranty of
 *      MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *      Lesser General Public License for more details.
 *
 *      You should have received a copy of the GNU Lesser General Public
 *      License along with this library in the file COPYING.LIB;
 *      if not, write to the Free Software Foundation, Inc.,
 *      59 Temple Place - Suite 330, Boston, MA 02111-1307, USA
 */



int
pthread_rwlock_timedwrlock(pthread_rwlock_t * rwlock,
	const struct timespec *abstime)
{
	int result;
	pthread_rwlock_t rwl;

	if (rwlock == NULL || *rwlock == NULL)
	{
		return EINVAL;
	}

	/*
	 * We do a quick check to see if we need to do more work
	 * to initialise a static rwlock. We check
	 * again inside the guarded section of ptw32_rwlock_check_need_init()
	 * to avoid race conditions.
	 */
	if (*rwlock == PTHREAD_RWLOCK_INITIALIZER)
	{
		result = ptw32_rwlock_check_need_init(rwlock);

		if (result != 0 && result != EBUSY)
		{
			return result;
		}
	}

	rwl = *rwlock;

	if (rwl->nMagic != PTW32_RWLOCK_MAGIC)
	{
		return EINVAL;
	}

	if ((result =
		pthread_mutex_timedlock(&(rwl->mtxExclusiveAccess), abstime)) != 0)
	{
		return result;
	}

	if ((result =
		pthread_mutex_timedlock(&(rwl->mtxSharedAccessCompleted),
			abstime)) != 0)
	{
		(void)pthread_mutex_unlock(&(rwl->mtxExclusiveAccess));
		return result;
	}

	if (rwl->nExclusiveAccessCount == 0)
	{
		if (rwl->nCompletedSharedAccessCount > 0)
		{
			rwl->nSharedAccessCount -= rwl->nCompletedSharedAccessCount;
			rwl->nCompletedSharedAccessCount = 0;
		}

		if (rwl->nSharedAccessCount > 0)
		{
			rwl->nCompletedSharedAccessCount = -rwl->nSharedAccessCount;

			/*
			 * This routine may be a cancelation point
			 * according to POSIX 1003.1j section 18.1.2.
			 */
#if defined(_MSC_VER) && _MSC_VER < 1400
#pragma inline_depth(0)
#endif
			pthread_cleanup_push(ptw32_rwlock_cancelwrwait, (void *)rwl);

			do
			{
				result =
					pthread_cond_timedwait(&(rwl->cndSharedAccessCompleted),
						&(rwl->mtxSharedAccessCompleted),
						abstime);
			} while (result == 0 && rwl->nCompletedSharedAccessCount < 0);

			pthread_cleanup_pop((result != 0) ? 1 : 0);
#if defined(_MSC_VER) && _MSC_VER < 1400
#pragma inline_depth()
#endif

			if (result == 0)
			{
				rwl->nSharedAccessCount = 0;
			}
		}
	}

	if (result == 0)
	{
		rwl->nExclusiveAccessCount++;
	}

	return result;
}
/*
 * pthread_rwlock_tryrdlock.c
 *
 * Description:
 * This translation unit implements read/write lock primitives.
 *
 * --------------------------------------------------------------------------
 *
 *      Pthreads-win32 - POSIX Threads Library for Win32
 *      Copyright(C) 1998 John E. Bossom
 *      Copyright(C) 1999,2005 Pthreads-win32 contributors
 *
 *      Contact Email: rpj@callisto.canberra.edu.au
 *
 *      The current list of contributors is contained
 *      in the file CONTRIBUTORS included with the source
 *      code distribution. The list can also be seen at the
 *      following World Wide Web location:
 *      http://sources.redhat.com/pthreads-win32/contributors.html
 *
 *      This library is free software; you can redistribute it and/or
 *      modify it under the terms of the GNU Lesser General Public
 *      License as published by the Free Software Foundation; either
 *      version 2 of the License, or (at your option) any later version.
 *
 *      This library is distributed in the hope that it will be useful,
 *      but WITHOUT ANY WARRANTY; without even the implied warranty of
 *      MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *      Lesser General Public License for more details.
 *
 *      You should have received a copy of the GNU Lesser General Public
 *      License along with this library in the file COPYING.LIB;
 *      if not, write to the Free Software Foundation, Inc.,
 *      59 Temple Place - Suite 330, Boston, MA 02111-1307, USA
 */



int
pthread_rwlock_tryrdlock(pthread_rwlock_t * rwlock)
{
	int result;
	pthread_rwlock_t rwl;

	if (rwlock == NULL || *rwlock == NULL)
	{
		return EINVAL;
	}

	/*
	 * We do a quick check to see if we need to do more work
	 * to initialise a static rwlock. We check
	 * again inside the guarded section of ptw32_rwlock_check_need_init()
	 * to avoid race conditions.
	 */
	if (*rwlock == PTHREAD_RWLOCK_INITIALIZER)
	{
		result = ptw32_rwlock_check_need_init(rwlock);

		if (result != 0 && result != EBUSY)
		{
			return result;
		}
	}

	rwl = *rwlock;

	if (rwl->nMagic != PTW32_RWLOCK_MAGIC)
	{
		return EINVAL;
	}

	if ((result = pthread_mutex_trylock(&(rwl->mtxExclusiveAccess))) != 0)
	{
		return result;
	}

	if (++rwl->nSharedAccessCount == INT_MAX)
	{
		if ((result =
			pthread_mutex_lock(&(rwl->mtxSharedAccessCompleted))) != 0)
		{
			(void)pthread_mutex_unlock(&(rwl->mtxExclusiveAccess));
			return result;
		}

		rwl->nSharedAccessCount -= rwl->nCompletedSharedAccessCount;
		rwl->nCompletedSharedAccessCount = 0;

		if ((result =
			pthread_mutex_unlock(&(rwl->mtxSharedAccessCompleted))) != 0)
		{
			(void)pthread_mutex_unlock(&(rwl->mtxExclusiveAccess));
			return result;
		}
	}

	return (pthread_mutex_unlock(&rwl->mtxExclusiveAccess));
}
/*
 * pthread_rwlock_trywrlock.c
 *
 * Description:
 * This translation unit implements read/write lock primitives.
 *
 * --------------------------------------------------------------------------
 *
 *      Pthreads-win32 - POSIX Threads Library for Win32
 *      Copyright(C) 1998 John E. Bossom
 *      Copyright(C) 1999,2005 Pthreads-win32 contributors
 *
 *      Contact Email: rpj@callisto.canberra.edu.au
 *
 *      The current list of contributors is contained
 *      in the file CONTRIBUTORS included with the source
 *      code distribution. The list can also be seen at the
 *      following World Wide Web location:
 *      http://sources.redhat.com/pthreads-win32/contributors.html
 *
 *      This library is free software; you can redistribute it and/or
 *      modify it under the terms of the GNU Lesser General Public
 *      License as published by the Free Software Foundation; either
 *      version 2 of the License, or (at your option) any later version.
 *
 *      This library is distributed in the hope that it will be useful,
 *      but WITHOUT ANY WARRANTY; without even the implied warranty of
 *      MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *      Lesser General Public License for more details.
 *
 *      You should have received a copy of the GNU Lesser General Public
 *      License along with this library in the file COPYING.LIB;
 *      if not, write to the Free Software Foundation, Inc.,
 *      59 Temple Place - Suite 330, Boston, MA 02111-1307, USA
 */



int
pthread_rwlock_trywrlock(pthread_rwlock_t * rwlock)
{
	int result, result1;
	pthread_rwlock_t rwl;

	if (rwlock == NULL || *rwlock == NULL)
	{
		return EINVAL;
	}

	/*
	 * We do a quick check to see if we need to do more work
	 * to initialise a static rwlock. We check
	 * again inside the guarded section of ptw32_rwlock_check_need_init()
	 * to avoid race conditions.
	 */
	if (*rwlock == PTHREAD_RWLOCK_INITIALIZER)
	{
		result = ptw32_rwlock_check_need_init(rwlock);

		if (result != 0 && result != EBUSY)
		{
			return result;
		}
	}

	rwl = *rwlock;

	if (rwl->nMagic != PTW32_RWLOCK_MAGIC)
	{
		return EINVAL;
	}

	if ((result = pthread_mutex_trylock(&(rwl->mtxExclusiveAccess))) != 0)
	{
		return result;
	}

	if ((result =
		pthread_mutex_trylock(&(rwl->mtxSharedAccessCompleted))) != 0)
	{
		result1 = pthread_mutex_unlock(&(rwl->mtxExclusiveAccess));
		return ((result1 != 0) ? result1 : result);
	}

	if (rwl->nExclusiveAccessCount == 0)
	{
		if (rwl->nCompletedSharedAccessCount > 0)
		{
			rwl->nSharedAccessCount -= rwl->nCompletedSharedAccessCount;
			rwl->nCompletedSharedAccessCount = 0;
		}

		if (rwl->nSharedAccessCount > 0)
		{
			if ((result =
				pthread_mutex_unlock(&(rwl->mtxSharedAccessCompleted))) != 0)
			{
				(void)pthread_mutex_unlock(&(rwl->mtxExclusiveAccess));
				return result;
			}

			if ((result =
				pthread_mutex_unlock(&(rwl->mtxExclusiveAccess))) == 0)
			{
				result = EBUSY;
			}
		}
		else
		{
			rwl->nExclusiveAccessCount = 1;
		}
	}
	else
	{
		result = EBUSY;
	}

	return result;
}
/*
 * pthread_rwlock_unlock.c
 *
 * Description:
 * This translation unit implements read/write lock primitives.
 *
 * --------------------------------------------------------------------------
 *
 *      Pthreads-win32 - POSIX Threads Library for Win32
 *      Copyright(C) 1998 John E. Bossom
 *      Copyright(C) 1999,2005 Pthreads-win32 contributors
 *
 *      Contact Email: rpj@callisto.canberra.edu.au
 *
 *      The current list of contributors is contained
 *      in the file CONTRIBUTORS included with the source
 *      code distribution. The list can also be seen at the
 *      following World Wide Web location:
 *      http://sources.redhat.com/pthreads-win32/contributors.html
 *
 *      This library is free software; you can redistribute it and/or
 *      modify it under the terms of the GNU Lesser General Public
 *      License as published by the Free Software Foundation; either
 *      version 2 of the License, or (at your option) any later version.
 *
 *      This library is distributed in the hope that it will be useful,
 *      but WITHOUT ANY WARRANTY; without even the implied warranty of
 *      MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *      Lesser General Public License for more details.
 *
 *      You should have received a copy of the GNU Lesser General Public
 *      License along with this library in the file COPYING.LIB;
 *      if not, write to the Free Software Foundation, Inc.,
 *      59 Temple Place - Suite 330, Boston, MA 02111-1307, USA
 */



int
pthread_rwlock_unlock(pthread_rwlock_t * rwlock)
{
	int result, result1;
	pthread_rwlock_t rwl;

	if (rwlock == NULL || *rwlock == NULL)
	{
		return (EINVAL);
	}

	if (*rwlock == PTHREAD_RWLOCK_INITIALIZER)
	{
		/*
		 * Assume any race condition here is harmless.
		 */
		return 0;
	}

	rwl = *rwlock;

	if (rwl->nMagic != PTW32_RWLOCK_MAGIC)
	{
		return EINVAL;
	}

	if (rwl->nExclusiveAccessCount == 0)
	{
		if ((result =
			pthread_mutex_lock(&(rwl->mtxSharedAccessCompleted))) != 0)
		{
			return result;
		}

		if (++rwl->nCompletedSharedAccessCount == 0)
		{
			result = pthread_cond_signal(&(rwl->cndSharedAccessCompleted));
		}

		result1 = pthread_mutex_unlock(&(rwl->mtxSharedAccessCompleted));
	}
	else
	{
		rwl->nExclusiveAccessCount--;

		result = pthread_mutex_unlock(&(rwl->mtxSharedAccessCompleted));
		result1 = pthread_mutex_unlock(&(rwl->mtxExclusiveAccess));

	}

	return ((result != 0) ? result : result1);
}
/*
 * pthread_rwlock_wrlock.c
 *
 * Description:
 * This translation unit implements read/write lock primitives.
 *
 * --------------------------------------------------------------------------
 *
 *      Pthreads-win32 - POSIX Threads Library for Win32
 *      Copyright(C) 1998 John E. Bossom
 *      Copyright(C) 1999,2005 Pthreads-win32 contributors
 *
 *      Contact Email: rpj@callisto.canberra.edu.au
 *
 *      The current list of contributors is contained
 *      in the file CONTRIBUTORS included with the source
 *      code distribution. The list can also be seen at the
 *      following World Wide Web location:
 *      http://sources.redhat.com/pthreads-win32/contributors.html
 *
 *      This library is free software; you can redistribute it and/or
 *      modify it under the terms of the GNU Lesser General Public
 *      License as published by the Free Software Foundation; either
 *      version 2 of the License, or (at your option) any later version.
 *
 *      This library is distributed in the hope that it will be useful,
 *      but WITHOUT ANY WARRANTY; without even the implied warranty of
 *      MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *      Lesser General Public License for more details.
 *
 *      You should have received a copy of the GNU Lesser General Public
 *      License along with this library in the file COPYING.LIB;
 *      if not, write to the Free Software Foundation, Inc.,
 *      59 Temple Place - Suite 330, Boston, MA 02111-1307, USA
 */



int
pthread_rwlock_wrlock(pthread_rwlock_t * rwlock)
{
	int result;
	pthread_rwlock_t rwl;

	if (rwlock == NULL || *rwlock == NULL)
	{
		return EINVAL;
	}

	/*
	 * We do a quick check to see if we need to do more work
	 * to initialise a static rwlock. We check
	 * again inside the guarded section of ptw32_rwlock_check_need_init()
	 * to avoid race conditions.
	 */
	if (*rwlock == PTHREAD_RWLOCK_INITIALIZER)
	{
		result = ptw32_rwlock_check_need_init(rwlock);

		if (result != 0 && result != EBUSY)
		{
			return result;
		}
	}

	rwl = *rwlock;

	if (rwl->nMagic != PTW32_RWLOCK_MAGIC)
	{
		return EINVAL;
	}

	if ((result = pthread_mutex_lock(&(rwl->mtxExclusiveAccess))) != 0)
	{
		return result;
	}

	if ((result = pthread_mutex_lock(&(rwl->mtxSharedAccessCompleted))) != 0)
	{
		(void)pthread_mutex_unlock(&(rwl->mtxExclusiveAccess));
		return result;
	}

	if (rwl->nExclusiveAccessCount == 0)
	{
		if (rwl->nCompletedSharedAccessCount > 0)
		{
			rwl->nSharedAccessCount -= rwl->nCompletedSharedAccessCount;
			rwl->nCompletedSharedAccessCount = 0;
		}

		if (rwl->nSharedAccessCount > 0)
		{
			rwl->nCompletedSharedAccessCount = -rwl->nSharedAccessCount;

			/*
			 * This routine may be a cancelation point
			 * according to POSIX 1003.1j section 18.1.2.
			 */
#if defined(_MSC_VER) && _MSC_VER < 1400
#pragma inline_depth(0)
#endif
			pthread_cleanup_push(ptw32_rwlock_cancelwrwait, (void *)rwl);

			do
			{
				result = pthread_cond_wait(&(rwl->cndSharedAccessCompleted),
					&(rwl->mtxSharedAccessCompleted));
			} while (result == 0 && rwl->nCompletedSharedAccessCount < 0);

			pthread_cleanup_pop((result != 0) ? 1 : 0);
#if defined(_MSC_VER) && _MSC_VER < 1400
#pragma inline_depth()
#endif

			if (result == 0)
			{
				rwl->nSharedAccessCount = 0;
			}
		}
	}

	if (result == 0)
	{
		rwl->nExclusiveAccessCount++;
	}

	return result;
}
/*
 * pthread_self.c
 *
 * Description:
 * This translation unit implements miscellaneous thread functions.
 *
 * --------------------------------------------------------------------------
 *
 *      Pthreads-win32 - POSIX Threads Library for Win32
 *      Copyright(C) 1998 John E. Bossom
 *      Copyright(C) 1999,2005 Pthreads-win32 contributors
 *
 *      Contact Email: rpj@callisto.canberra.edu.au
 *
 *      The current list of contributors is contained
 *      in the file CONTRIBUTORS included with the source
 *      code distribution. The list can also be seen at the
 *      following World Wide Web location:
 *      http://sources.redhat.com/pthreads-win32/contributors.html
 *
 *      This library is free software; you can redistribute it and/or
 *      modify it under the terms of the GNU Lesser General Public
 *      License as published by the Free Software Foundation; either
 *      version 2 of the License, or (at your option) any later version.
 *
 *      This library is distributed in the hope that it will be useful,
 *      but WITHOUT ANY WARRANTY; without even the implied warranty of
 *      MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *      Lesser General Public License for more details.
 *
 *      You should have received a copy of the GNU Lesser General Public
 *      License along with this library in the file COPYING.LIB;
 *      if not, write to the Free Software Foundation, Inc.,
 *      59 Temple Place - Suite 330, Boston, MA 02111-1307, USA
 */


pthread_t
pthread_self(void)
/*
 * ------------------------------------------------------
 * DOCPUBLIC
 *      This function returns a reference to the current running
 *      thread.
 *
 * PARAMETERS
 *      N/A
 *
 *
 * DESCRIPTION
 *      This function returns a reference to the current running
 *      thread.
 *
 * RESULTS
 *              pthread_t       reference to the current thread
 *
 * ------------------------------------------------------
 */
{
	pthread_t self;
	pthread_t nil = { NULL, 0 };
	ptw32_thread_t * sp;

#if defined(_UWIN)
	if (!ptw32_selfThreadKey)
		return nil;
#endif

	sp = (ptw32_thread_t *)pthread_getspecific(ptw32_selfThreadKey);

	if (sp != NULL)
	{
		self = sp->ptHandle;
	}
	else
	{
		/*
		 * Need to create an implicit 'self' for the currently
		 * executing thread.
		 */
		self = ptw32_new();
		sp = (ptw32_thread_t *)self.p;

		if (sp != NULL)
		{
			/*
			 * This is a non-POSIX thread which has chosen to call
			 * a POSIX threads function for some reason. We assume that
			 * it isn't joinable, but we do assume that it's
			 * (deferred) cancelable.
			 */
			sp->implicit = 1;
			sp->detachState = PTHREAD_CREATE_DETACHED;
			sp->thread = GetCurrentThreadId();

#if defined(NEED_DUPLICATEHANDLE)
			/*
			 * DuplicateHandle does not exist on WinCE.
			 *
			 * NOTE:
			 * GetCurrentThread only returns a pseudo-handle
			 * which is only valid in the current thread context.
			 * Therefore, you should not pass the handle to
			 * other threads for whatever purpose.
			 */
			sp->threadH = GetCurrentThread();
#else
			if (!DuplicateHandle(GetCurrentProcess(),
				GetCurrentThread(),
				GetCurrentProcess(),
				&sp->threadH,
				0, FALSE, DUPLICATE_SAME_ACCESS))
			{
				/*
				 * Should not do this, but we have no alternative if
				 * we can't get a Win32 thread handle.
				 * Thread structs are never freed.
				 */
				ptw32_threadReusePush(self);
				/*
				 * As this is a win32 thread calling us and we have failed,
				 * return a value that makes sense to win32.
				 */
				return nil;
			}
#endif

			/*
			 * No need to explicitly serialise access to sched_priority
			 * because the new handle is not yet public.
			 */
			sp->sched_priority = GetThreadPriority(sp->threadH);
			pthread_setspecific(ptw32_selfThreadKey, (void *)sp);
		}
	}

	return (self);

}				/* pthread_self */
/*
 * pthread_setcancelstate.c
 *
 * Description:
 * POSIX thread functions related to thread cancellation.
 *
 * --------------------------------------------------------------------------
 *
 *      Pthreads-win32 - POSIX Threads Library for Win32
 *      Copyright(C) 1998 John E. Bossom
 *      Copyright(C) 1999,2005 Pthreads-win32 contributors
 *
 *      Contact Email: rpj@callisto.canberra.edu.au
 *
 *      The current list of contributors is contained
 *      in the file CONTRIBUTORS included with the source
 *      code distribution. The list can also be seen at the
 *      following World Wide Web location:
 *      http://sources.redhat.com/pthreads-win32/contributors.html
 *
 *      This library is free software; you can redistribute it and/or
 *      modify it under the terms of the GNU Lesser General Public
 *      License as published by the Free Software Foundation; either
 *      version 2 of the License, or (at your option) any later version.
 *
 *      This library is distributed in the hope that it will be useful,
 *      but WITHOUT ANY WARRANTY; without even the implied warranty of
 *      MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *      Lesser General Public License for more details.
 *
 *      You should have received a copy of the GNU Lesser General Public
 *      License along with this library in the file COPYING.LIB;
 *      if not, write to the Free Software Foundation, Inc.,
 *      59 Temple Place - Suite 330, Boston, MA 02111-1307, USA
 */



int
pthread_setcancelstate(int state, int *oldstate)
/*
 * ------------------------------------------------------
 * DOCPUBLIC
 *      This function atomically sets the calling thread's
 *      cancelability state to 'state' and returns the previous
 *      cancelability state at the location referenced by
 *      'oldstate'
 *
 * PARAMETERS
 *      state,
 *      oldstate
 *              PTHREAD_CANCEL_ENABLE
 *                      cancellation is enabled,
 *
 *              PTHREAD_CANCEL_DISABLE
 *                      cancellation is disabled
 *
 *
 * DESCRIPTION
 *      This function atomically sets the calling thread's
 *      cancelability state to 'state' and returns the previous
 *      cancelability state at the location referenced by
 *      'oldstate'.
 *
 *      NOTES:
 *      1)      Use to disable cancellation around 'atomic' code that
 *              includes cancellation points
 *
 * COMPATIBILITY ADDITIONS
 *      If 'oldstate' is NULL then the previous state is not returned
 *      but the function still succeeds. (Solaris)
 *
 * RESULTS
 *              0               successfully set cancelability type,
 *              EINVAL          'state' is invalid
 *
 * ------------------------------------------------------
 */
{
	ptw32_mcs_local_node_t stateLock;
	int result = 0;
	pthread_t self = pthread_self();
	ptw32_thread_t * sp = (ptw32_thread_t *)self.p;

	if (sp == NULL
		|| (state != PTHREAD_CANCEL_ENABLE && state != PTHREAD_CANCEL_DISABLE))
	{
		return EINVAL;
	}

	/*
	 * Lock for async-cancel safety.
	 */
	ptw32_mcs_lock_acquire(&sp->stateLock, &stateLock);

	if (oldstate != NULL)
	{
		*oldstate = sp->cancelState;
	}

	sp->cancelState = state;

	/*
	 * Check if there is a pending asynchronous cancel
	 */
	if (state == PTHREAD_CANCEL_ENABLE
		&& sp->cancelType == PTHREAD_CANCEL_ASYNCHRONOUS
		&& WaitForSingleObject(sp->cancelEvent, 0) == WAIT_OBJECT_0)
	{
		sp->state = PThreadStateCanceling;
		sp->cancelState = PTHREAD_CANCEL_DISABLE;
		ResetEvent(sp->cancelEvent);
		ptw32_mcs_lock_release(&stateLock);
		ptw32_throw(PTW32_EPS_CANCEL);

		/* Never reached */
	}

	ptw32_mcs_lock_release(&stateLock);

	return (result);

}				/* pthread_setcancelstate */
/*
 * pthread_setcanceltype.c
 *
 * Description:
 * POSIX thread functions related to thread cancellation.
 *
 * --------------------------------------------------------------------------
 *
 *      Pthreads-win32 - POSIX Threads Library for Win32
 *      Copyright(C) 1998 John E. Bossom
 *      Copyright(C) 1999,2005 Pthreads-win32 contributors
 *
 *      Contact Email: rpj@callisto.canberra.edu.au
 *
 *      The current list of contributors is contained
 *      in the file CONTRIBUTORS included with the source
 *      code distribution. The list can also be seen at the
 *      following World Wide Web location:
 *      http://sources.redhat.com/pthreads-win32/contributors.html
 *
 *      This library is free software; you can redistribute it and/or
 *      modify it under the terms of the GNU Lesser General Public
 *      License as published by the Free Software Foundation; either
 *      version 2 of the License, or (at your option) any later version.
 *
 *      This library is distributed in the hope that it will be useful,
 *      but WITHOUT ANY WARRANTY; without even the implied warranty of
 *      MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *      Lesser General Public License for more details.
 *
 *      You should have received a copy of the GNU Lesser General Public
 *      License along with this library in the file COPYING.LIB;
 *      if not, write to the Free Software Foundation, Inc.,
 *      59 Temple Place - Suite 330, Boston, MA 02111-1307, USA
 */



int
pthread_setcanceltype(int type, int *oldtype)
/*
 * ------------------------------------------------------
 * DOCPUBLIC
 *      This function atomically sets the calling thread's
 *      cancelability type to 'type' and returns the previous
 *      cancelability type at the location referenced by
 *      'oldtype'
 *
 * PARAMETERS
 *      type,
 *      oldtype
 *              PTHREAD_CANCEL_DEFERRED
 *                      only deferred cancelation is allowed,
 *
 *              PTHREAD_CANCEL_ASYNCHRONOUS
 *                      Asynchronous cancellation is allowed
 *
 *
 * DESCRIPTION
 *      This function atomically sets the calling thread's
 *      cancelability type to 'type' and returns the previous
 *      cancelability type at the location referenced by
 *      'oldtype'
 *
 *      NOTES:
 *      1)      Use with caution; most code is not safe for use
 *              with asynchronous cancelability.
 *
 * COMPATIBILITY ADDITIONS
 *      If 'oldtype' is NULL then the previous type is not returned
 *      but the function still succeeds. (Solaris)
 *
 * RESULTS
 *              0               successfully set cancelability type,
 *              EINVAL          'type' is invalid
 *
 * ------------------------------------------------------
 */
{
	ptw32_mcs_local_node_t stateLock;
	int result = 0;
	pthread_t self = pthread_self();
	ptw32_thread_t * sp = (ptw32_thread_t *)self.p;

	if (sp == NULL
		|| (type != PTHREAD_CANCEL_DEFERRED
			&& type != PTHREAD_CANCEL_ASYNCHRONOUS))
	{
		return EINVAL;
	}

	/*
	 * Lock for async-cancel safety.
	 */
	ptw32_mcs_lock_acquire(&sp->stateLock, &stateLock);

	if (oldtype != NULL)
	{
		*oldtype = sp->cancelType;
	}

	sp->cancelType = type;

	/*
	 * Check if there is a pending asynchronous cancel
	 */
	if (sp->cancelState == PTHREAD_CANCEL_ENABLE
		&& type == PTHREAD_CANCEL_ASYNCHRONOUS
		&& WaitForSingleObject(sp->cancelEvent, 0) == WAIT_OBJECT_0)
	{
		sp->state = PThreadStateCanceling;
		sp->cancelState = PTHREAD_CANCEL_DISABLE;
		ResetEvent(sp->cancelEvent);
		ptw32_mcs_lock_release(&stateLock);
		ptw32_throw(PTW32_EPS_CANCEL);

		/* Never reached */
	}

	ptw32_mcs_lock_release(&stateLock);

	return (result);

}				/* pthread_setcanceltype */
/*
 * pthread_setconcurrency.c
 *
 * Description:
 * This translation unit implements miscellaneous thread functions.
 *
 * --------------------------------------------------------------------------
 *
 *      Pthreads-win32 - POSIX Threads Library for Win32
 *      Copyright(C) 1998 John E. Bossom
 *      Copyright(C) 1999,2005 Pthreads-win32 contributors
 *
 *      Contact Email: rpj@callisto.canberra.edu.au
 *
 *      The current list of contributors is contained
 *      in the file CONTRIBUTORS included with the source
 *      code distribution. The list can also be seen at the
 *      following World Wide Web location:
 *      http://sources.redhat.com/pthreads-win32/contributors.html
 *
 *      This library is free software; you can redistribute it and/or
 *      modify it under the terms of the GNU Lesser General Public
 *      License as published by the Free Software Foundation; either
 *      version 2 of the License, or (at your option) any later version.
 *
 *      This library is distributed in the hope that it will be useful,
 *      but WITHOUT ANY WARRANTY; without even the implied warranty of
 *      MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *      Lesser General Public License for more details.
 *
 *      You should have received a copy of the GNU Lesser General Public
 *      License along with this library in the file COPYING.LIB;
 *      if not, write to the Free Software Foundation, Inc.,
 *      59 Temple Place - Suite 330, Boston, MA 02111-1307, USA
 */



int
pthread_setconcurrency(int level)
{
	if (level < 0)
	{
		return EINVAL;
	}
	else
	{
		ptw32_concurrency = level;
		return 0;
	}
}
/*
 * sched_setschedparam.c
 *
 * Description:
 * POSIX thread functions that deal with thread scheduling.
 *
 * --------------------------------------------------------------------------
 *
 *      Pthreads-win32 - POSIX Threads Library for Win32
 *      Copyright(C) 1998 John E. Bossom
 *      Copyright(C) 1999,2005 Pthreads-win32 contributors
 *
 *      Contact Email: rpj@callisto.canberra.edu.au
 *
 *      The current list of contributors is contained
 *      in the file CONTRIBUTORS included with the source
 *      code distribution. The list can also be seen at the
 *      following World Wide Web location:
 *      http://sources.redhat.com/pthreads-win32/contributors.html
 *
 *      This library is free software; you can redistribute it and/or
 *      modify it under the terms of the GNU Lesser General Public
 *      License as published by the Free Software Foundation; either
 *      version 2 of the License, or (at your option) any later version.
 *
 *      This library is distributed in the hope that it will be useful,
 *      but WITHOUT ANY WARRANTY; without even the implied warranty of
 *      MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *      Lesser General Public License for more details.
 *
 *      You should have received a copy of the GNU Lesser General Public
 *      License along with this library in the file COPYING.LIB;
 *      if not, write to the Free Software Foundation, Inc.,
 *      59 Temple Place - Suite 330, Boston, MA 02111-1307, USA
 */


int
pthread_setschedparam(pthread_t thread, int policy,
	const struct sched_param *param)
{
	int result;

	/* Validate the thread id. */
	result = pthread_kill(thread, 0);
	if (0 != result)
	{
		return result;
	}

	/* Validate the scheduling policy. */
	if (policy < SCHED_MIN || policy > SCHED_MAX)
	{
		return EINVAL;
	}

	/* Ensure the policy is SCHED_OTHER. */
	if (policy != SCHED_OTHER)
	{
		return ENOTSUP;
	}

	return (ptw32_setthreadpriority(thread, policy, param->sched_priority));
}


int
ptw32_setthreadpriority(pthread_t thread, int policy, int priority)
{
	int prio;
	ptw32_mcs_local_node_t threadLock;
	int result = 0;
	ptw32_thread_t * tp = (ptw32_thread_t *)thread.p;

	prio = priority;

	/* Validate priority level. */
	if (prio < sched_get_priority_min(policy) ||
		prio > sched_get_priority_max(policy))
	{
		return EINVAL;
	}

#if (THREAD_PRIORITY_LOWEST > THREAD_PRIORITY_NORMAL)
	/* WinCE */
#else
	/* Everything else */

	if (THREAD_PRIORITY_IDLE < prio && THREAD_PRIORITY_LOWEST > prio)
	{
		prio = THREAD_PRIORITY_LOWEST;
	}
	else if (THREAD_PRIORITY_TIME_CRITICAL > prio
		&& THREAD_PRIORITY_HIGHEST < prio)
	{
		prio = THREAD_PRIORITY_HIGHEST;
	}

#endif

	ptw32_mcs_lock_acquire(&tp->threadLock, &threadLock);

	/* If this fails, the current priority is unchanged. */
	if (0 == SetThreadPriority(tp->threadH, prio))
	{
		result = EINVAL;
	}
	else
	{
		/*
		 * Must record the thread's sched_priority as given,
		 * not as finally adjusted.
		 */
		tp->sched_priority = priority;
	}

	ptw32_mcs_lock_release(&threadLock);

	return result;
}
/*
 * pthread_setspecific.c
 *
 * Description:
 * POSIX thread functions which implement thread-specific data (TSD).
 *
 * --------------------------------------------------------------------------
 *
 *      Pthreads-win32 - POSIX Threads Library for Win32
 *      Copyright(C) 1998 John E. Bossom
 *      Copyright(C) 1999,2005 Pthreads-win32 contributors
 *
 *      Contact Email: rpj@callisto.canberra.edu.au
 *
 *      The current list of contributors is contained
 *      in the file CONTRIBUTORS included with the source
 *      code distribution. The list can also be seen at the
 *      following World Wide Web location:
 *      http://sources.redhat.com/pthreads-win32/contributors.html
 *
 *      This library is free software; you can redistribute it and/or
 *      modify it under the terms of the GNU Lesser General Public
 *      License as published by the Free Software Foundation; either
 *      version 2 of the License, or (at your option) any later version.
 *
 *      This library is distributed in the hope that it will be useful,
 *      but WITHOUT ANY WARRANTY; without even the implied warranty of
 *      MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *      Lesser General Public License for more details.
 *
 *      You should have received a copy of the GNU Lesser General Public
 *      License along with this library in the file COPYING.LIB;
 *      if not, write to the Free Software Foundation, Inc.,
 *      59 Temple Place - Suite 330, Boston, MA 02111-1307, USA
 */



int
pthread_setspecific(pthread_key_t key, const void *value)
/*
 * ------------------------------------------------------
 * DOCPUBLIC
 *      This function sets the value of the thread specific
 *      key in the calling thread.
 *
 * PARAMETERS
 *      key
 *              an instance of pthread_key_t
 *      value
 *              the value to set key to
 *
 *
 * DESCRIPTION
 *      This function sets the value of the thread specific
 *      key in the calling thread.
 *
 * RESULTS
 *              0               successfully set value
 *              EAGAIN          could not set value
 *              ENOENT          SERIOUS!!
 *
 * ------------------------------------------------------
 */
{
	pthread_t self;
	int result = 0;

	if (key != ptw32_selfThreadKey)
	{
		/*
		 * Using pthread_self will implicitly create
		 * an instance of pthread_t for the current
		 * thread if one wasn't explicitly created
		 */
		self = pthread_self();
		if (self.p == NULL)
		{
			return ENOENT;
		}
	}
	else
	{
		/*
		 * Resolve catch-22 of registering thread with selfThread
		 * key
		 */
		ptw32_thread_t * sp = (ptw32_thread_t *)pthread_getspecific(ptw32_selfThreadKey);

		if (sp == NULL)
		{
			if (value == NULL)
			{
				return ENOENT;
			}
			self = *((pthread_t *)value);
		}
		else
		{
			self = sp->ptHandle;
		}
	}

	result = 0;

	if (key != NULL)
	{
		if (self.p != NULL && key->destructor != NULL && value != NULL)
		{
			ptw32_mcs_local_node_t keyLock;
			ptw32_mcs_local_node_t threadLock;
			ptw32_thread_t * sp = (ptw32_thread_t *)self.p;
			/*
			 * Only require associations if we have to
			 * call user destroy routine.
			 * Don't need to locate an existing association
			 * when setting data to NULL for WIN32 since the
			 * data is stored with the operating system; not
			 * on the association; setting assoc to NULL short
			 * circuits the search.
			 */
			ThreadKeyAssoc *assoc;

			ptw32_mcs_lock_acquire(&(key->keyLock), &keyLock);
			ptw32_mcs_lock_acquire(&(sp->threadLock), &threadLock);

			assoc = (ThreadKeyAssoc *)sp->keys;
			/*
			 * Locate existing association
			 */
			while (assoc != NULL)
			{
				if (assoc->key == key)
				{
					/*
					 * Association already exists
					 */
					break;
				}
				assoc = assoc->nextKey;
			}

			/*
			 * create an association if not found
			 */
			if (assoc == NULL)
			{
				result = ptw32_tkAssocCreate(sp, key);
			}

			ptw32_mcs_lock_release(&threadLock);
			ptw32_mcs_lock_release(&keyLock);
		}

		if (result == 0)
		{
			if (!TlsSetValue(key->key, (LPVOID)value))
			{
				result = EAGAIN;
			}
		}
	}

	return (result);
}				/* pthread_setspecific */
/*
 * pthread_spin_destroy.c
 *
 * Description:
 * This translation unit implements spin lock primitives.
 *
 * --------------------------------------------------------------------------
 *
 *      Pthreads-win32 - POSIX Threads Library for Win32
 *      Copyright(C) 1998 John E. Bossom
 *      Copyright(C) 1999,2005 Pthreads-win32 contributors
 *
 *      Contact Email: rpj@callisto.canberra.edu.au
 *
 *      The current list of contributors is contained
 *      in the file CONTRIBUTORS included with the source
 *      code distribution. The list can also be seen at the
 *      following World Wide Web location:
 *      http://sources.redhat.com/pthreads-win32/contributors.html
 *
 *      This library is free software; you can redistribute it and/or
 *      modify it under the terms of the GNU Lesser General Public
 *      License as published by the Free Software Foundation; either
 *      version 2 of the License, or (at your option) any later version.
 *
 *      This library is distributed in the hope that it will be useful,
 *      but WITHOUT ANY WARRANTY; without even the implied warranty of
 *      MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *      Lesser General Public License for more details.
 *
 *      You should have received a copy of the GNU Lesser General Public
 *      License along with this library in the file COPYING.LIB;
 *      if not, write to the Free Software Foundation, Inc.,
 *      59 Temple Place - Suite 330, Boston, MA 02111-1307, USA
 */



int
pthread_spin_destroy(pthread_spinlock_t * lock)
{
	register pthread_spinlock_t s;
	int result = 0;

	if (lock == NULL || *lock == NULL)
	{
		return EINVAL;
	}

	if ((s = *lock) != PTHREAD_SPINLOCK_INITIALIZER)
	{
		if (s->interlock == PTW32_SPIN_USE_MUTEX)
		{
			result = pthread_mutex_destroy(&(s->u.mutex));
		}
		else if ((PTW32_INTERLOCKED_LONG)PTW32_SPIN_UNLOCKED !=
			PTW32_INTERLOCKED_COMPARE_EXCHANGE_LONG((PTW32_INTERLOCKED_LONGPTR)&s->interlock,
			(PTW32_INTERLOCKED_LONG)PTW32_SPIN_INVALID,
				(PTW32_INTERLOCKED_LONG)PTW32_SPIN_UNLOCKED))
		{
			result = EINVAL;
		}

		if (0 == result)
		{
			/*
			 * We are relying on the application to ensure that all other threads
			 * have finished with the spinlock before destroying it.
			 */
			*lock = NULL;
			(void)free(s);
		}
	}
	else
	{
		/*
		 * See notes in ptw32_spinlock_check_need_init() above also.
		 */
		ptw32_mcs_local_node_t node;

		ptw32_mcs_lock_acquire(&ptw32_spinlock_test_init_lock, &node);

		/*
		 * Check again.
		 */
		if (*lock == PTHREAD_SPINLOCK_INITIALIZER)
		{
			/*
			 * This is all we need to do to destroy a statically
			 * initialised spinlock that has not yet been used (initialised).
			 * If we get to here, another thread
			 * waiting to initialise this mutex will get an EINVAL.
			 */
			*lock = NULL;
		}
		else
		{
			/*
			 * The spinlock has been initialised while we were waiting
			 * so assume it's in use.
			 */
			result = EBUSY;
		}

		ptw32_mcs_lock_release(&node);
	}

	return (result);
}
/*
 * pthread_spin_init.c
 *
 * Description:
 * This translation unit implements spin lock primitives.
 *
 * --------------------------------------------------------------------------
 *
 *      Pthreads-win32 - POSIX Threads Library for Win32
 *      Copyright(C) 1998 John E. Bossom
 *      Copyright(C) 1999,2005 Pthreads-win32 contributors
 *
 *      Contact Email: rpj@callisto.canberra.edu.au
 *
 *      The current list of contributors is contained
 *      in the file CONTRIBUTORS included with the source
 *      code distribution. The list can also be seen at the
 *      following World Wide Web location:
 *      http://sources.redhat.com/pthreads-win32/contributors.html
 *
 *      This library is free software; you can redistribute it and/or
 *      modify it under the terms of the GNU Lesser General Public
 *      License as published by the Free Software Foundation; either
 *      version 2 of the License, or (at your option) any later version.
 *
 *      This library is distributed in the hope that it will be useful,
 *      but WITHOUT ANY WARRANTY; without even the implied warranty of
 *      MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *      Lesser General Public License for more details.
 *
 *      You should have received a copy of the GNU Lesser General Public
 *      License along with this library in the file COPYING.LIB;
 *      if not, write to the Free Software Foundation, Inc.,
 *      59 Temple Place - Suite 330, Boston, MA 02111-1307, USA
 */



int
pthread_spin_init(pthread_spinlock_t * lock, int pshared)
{
	pthread_spinlock_t s;
	int cpus = 0;
	int result = 0;

	if (lock == NULL)
	{
		return EINVAL;
	}

	if (0 != ptw32_getprocessors(&cpus))
	{
		cpus = 1;
	}

	if (cpus > 1)
	{
		if (pshared == PTHREAD_PROCESS_SHARED)
		{
			/*
			 * Creating spinlock that can be shared between
			 * processes.
			 */
#if _POSIX_THREAD_PROCESS_SHARED >= 0

			 /*
			  * Not implemented yet.
			  */

#error ERROR [__FILE__, line __LINE__]: Process shared spin locks are not supported yet.

#else

			return ENOSYS;

#endif /* _POSIX_THREAD_PROCESS_SHARED */

		}
	}

	s = (pthread_spinlock_t)calloc(1, sizeof(*s));

	if (s == NULL)
	{
		return ENOMEM;
	}

	if (cpus > 1)
	{
		s->u.cpus = cpus;
		s->interlock = PTW32_SPIN_UNLOCKED;
	}
	else
	{
		pthread_mutexattr_t ma;
		result = pthread_mutexattr_init(&ma);

		if (0 == result)
		{
			ma->pshared = pshared;
			result = pthread_mutex_init(&(s->u.mutex), &ma);
			if (0 == result)
			{
				s->interlock = PTW32_SPIN_USE_MUTEX;
			}
		}
		(void)pthread_mutexattr_destroy(&ma);
	}

	if (0 == result)
	{
		*lock = s;
	}
	else
	{
		(void)free(s);
		*lock = NULL;
	}

	return (result);
}
/*
 * pthread_spin_lock.c
 *
 * Description:
 * This translation unit implements spin lock primitives.
 *
 * --------------------------------------------------------------------------
 *
 *      Pthreads-win32 - POSIX Threads Library for Win32
 *      Copyright(C) 1998 John E. Bossom
 *      Copyright(C) 1999,2005 Pthreads-win32 contributors
 *
 *      Contact Email: rpj@callisto.canberra.edu.au
 *
 *      The current list of contributors is contained
 *      in the file CONTRIBUTORS included with the source
 *      code distribution. The list can also be seen at the
 *      following World Wide Web location:
 *      http://sources.redhat.com/pthreads-win32/contributors.html
 *
 *      This library is free software; you can redistribute it and/or
 *      modify it under the terms of the GNU Lesser General Public
 *      License as published by the Free Software Foundation; either
 *      version 2 of the License, or (at your option) any later version.
 *
 *      This library is distributed in the hope that it will be useful,
 *      but WITHOUT ANY WARRANTY; without even the implied warranty of
 *      MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *      Lesser General Public License for more details.
 *
 *      You should have received a copy of the GNU Lesser General Public
 *      License along with this library in the file COPYING.LIB;
 *      if not, write to the Free Software Foundation, Inc.,
 *      59 Temple Place - Suite 330, Boston, MA 02111-1307, USA
 */



int
pthread_spin_lock(pthread_spinlock_t * lock)
{
	register pthread_spinlock_t s;

	if (NULL == lock || NULL == *lock)
	{
		return (EINVAL);
	}

	if (*lock == PTHREAD_SPINLOCK_INITIALIZER)
	{
		int result;

		if ((result = ptw32_spinlock_check_need_init(lock)) != 0)
		{
			return (result);
		}
	}

	s = *lock;

	while ((PTW32_INTERLOCKED_LONG)PTW32_SPIN_LOCKED ==
		PTW32_INTERLOCKED_COMPARE_EXCHANGE_LONG((PTW32_INTERLOCKED_LONGPTR)&s->interlock,
		(PTW32_INTERLOCKED_LONG)PTW32_SPIN_LOCKED,
			(PTW32_INTERLOCKED_LONG)PTW32_SPIN_UNLOCKED))
	{
	}

	if (s->interlock == PTW32_SPIN_LOCKED)
	{
		return 0;
	}
	else if (s->interlock == PTW32_SPIN_USE_MUTEX)
	{
		return pthread_mutex_lock(&(s->u.mutex));
	}

	return EINVAL;
}
/*
 * pthread_spin_trylock.c
 *
 * Description:
 * This translation unit implements spin lock primitives.
 *
 * --------------------------------------------------------------------------
 *
 *      Pthreads-win32 - POSIX Threads Library for Win32
 *      Copyright(C) 1998 John E. Bossom
 *      Copyright(C) 1999,2005 Pthreads-win32 contributors
 *
 *      Contact Email: rpj@callisto.canberra.edu.au
 *
 *      The current list of contributors is contained
 *      in the file CONTRIBUTORS included with the source
 *      code distribution. The list can also be seen at the
 *      following World Wide Web location:
 *      http://sources.redhat.com/pthreads-win32/contributors.html
 *
 *      This library is free software; you can redistribute it and/or
 *      modify it under the terms of the GNU Lesser General Public
 *      License as published by the Free Software Foundation; either
 *      version 2 of the License, or (at your option) any later version.
 *
 *      This library is distributed in the hope that it will be useful,
 *      but WITHOUT ANY WARRANTY; without even the implied warranty of
 *      MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *      Lesser General Public License for more details.
 *
 *      You should have received a copy of the GNU Lesser General Public
 *      License along with this library in the file COPYING.LIB;
 *      if not, write to the Free Software Foundation, Inc.,
 *      59 Temple Place - Suite 330, Boston, MA 02111-1307, USA
 */



int
pthread_spin_trylock(pthread_spinlock_t * lock)
{
	register pthread_spinlock_t s;

	if (NULL == lock || NULL == *lock)
	{
		return (EINVAL);
	}

	if (*lock == PTHREAD_SPINLOCK_INITIALIZER)
	{
		int result;

		if ((result = ptw32_spinlock_check_need_init(lock)) != 0)
		{
			return (result);
		}
	}

	s = *lock;

	switch ((long)
		PTW32_INTERLOCKED_COMPARE_EXCHANGE_LONG((PTW32_INTERLOCKED_LONGPTR)&s->interlock,
		(PTW32_INTERLOCKED_LONG)PTW32_SPIN_LOCKED,
			(PTW32_INTERLOCKED_LONG)PTW32_SPIN_UNLOCKED))
	{
	case PTW32_SPIN_UNLOCKED:
		return 0;
	case PTW32_SPIN_LOCKED:
		return EBUSY;
	case PTW32_SPIN_USE_MUTEX:
		return pthread_mutex_trylock(&(s->u.mutex));
	}

	return EINVAL;
}
/*
 * pthread_spin_unlock.c
 *
 * Description:
 * This translation unit implements spin lock primitives.
 *
 * --------------------------------------------------------------------------
 *
 *      Pthreads-win32 - POSIX Threads Library for Win32
 *      Copyright(C) 1998 John E. Bossom
 *      Copyright(C) 1999,2005 Pthreads-win32 contributors
 *
 *      Contact Email: rpj@callisto.canberra.edu.au
 *
 *      The current list of contributors is contained
 *      in the file CONTRIBUTORS included with the source
 *      code distribution. The list can also be seen at the
 *      following World Wide Web location:
 *      http://sources.redhat.com/pthreads-win32/contributors.html
 *
 *      This library is free software; you can redistribute it and/or
 *      modify it under the terms of the GNU Lesser General Public
 *      License as published by the Free Software Foundation; either
 *      version 2 of the License, or (at your option) any later version.
 *
 *      This library is distributed in the hope that it will be useful,
 *      but WITHOUT ANY WARRANTY; without even the implied warranty of
 *      MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *      Lesser General Public License for more details.
 *
 *      You should have received a copy of the GNU Lesser General Public
 *      License along with this library in the file COPYING.LIB;
 *      if not, write to the Free Software Foundation, Inc.,
 *      59 Temple Place - Suite 330, Boston, MA 02111-1307, USA
 */



int
pthread_spin_unlock(pthread_spinlock_t * lock)
{
	register pthread_spinlock_t s;

	if (NULL == lock || NULL == *lock)
	{
		return (EINVAL);
	}

	s = *lock;

	if (s == PTHREAD_SPINLOCK_INITIALIZER)
	{
		return EPERM;
	}

	switch ((long)
		PTW32_INTERLOCKED_COMPARE_EXCHANGE_LONG((PTW32_INTERLOCKED_LONGPTR)&s->interlock,
		(PTW32_INTERLOCKED_LONG)PTW32_SPIN_UNLOCKED,
			(PTW32_INTERLOCKED_LONG)PTW32_SPIN_LOCKED))
	{
	case PTW32_SPIN_LOCKED:
	case PTW32_SPIN_UNLOCKED:
		return 0;
	case PTW32_SPIN_USE_MUTEX:
		return pthread_mutex_unlock(&(s->u.mutex));
	}

	return EINVAL;
}
/*
 * pthread_testcancel.c
 *
 * Description:
 * POSIX thread functions related to thread cancellation.
 *
 * --------------------------------------------------------------------------
 *
 *      Pthreads-win32 - POSIX Threads Library for Win32
 *      Copyright(C) 1998 John E. Bossom
 *      Copyright(C) 1999,2005 Pthreads-win32 contributors
 *
 *      Contact Email: rpj@callisto.canberra.edu.au
 *
 *      The current list of contributors is contained
 *      in the file CONTRIBUTORS included with the source
 *      code distribution. The list can also be seen at the
 *      following World Wide Web location:
 *      http://sources.redhat.com/pthreads-win32/contributors.html
 *
 *      This library is free software; you can redistribute it and/or
 *      modify it under the terms of the GNU Lesser General Public
 *      License as published by the Free Software Foundation; either
 *      version 2 of the License, or (at your option) any later version.
 *
 *      This library is distributed in the hope that it will be useful,
 *      but WITHOUT ANY WARRANTY; without even the implied warranty of
 *      MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *      Lesser General Public License for more details.
 *
 *      You should have received a copy of the GNU Lesser General Public
 *      License along with this library in the file COPYING.LIB;
 *      if not, write to the Free Software Foundation, Inc.,
 *      59 Temple Place - Suite 330, Boston, MA 02111-1307, USA
 */

 /*
  * context.h
  *
  * Description:
  * POSIX thread macros related to thread cancellation.
  *
  * --------------------------------------------------------------------------
  *
  *      Pthreads-win32 - POSIX Threads Library for Win32
  *      Copyright(C) 1998 John E. Bossom
  *      Copyright(C) 1999,2005 Pthreads-win32 contributors
  *
  *      Contact Email: rpj@callisto.canberra.edu.au
  *
  *      The current list of contributors is contained
  *      in the file CONTRIBUTORS included with the source
  *      code distribution. The list can also be seen at the
  *      following World Wide Web location:
  *      http://sources.redhat.com/pthreads-win32/contributors.html
  *
  *      This library is free software; you can redistribute it and/or
  *      modify it under the terms of the GNU Lesser General Public
  *      License as published by the Free Software Foundation; either
  *      version 2 of the License, or (at your option) any later version.
  *
  *      This library is distributed in the hope that it will be useful,
  *      but WITHOUT ANY WARRANTY; without even the implied warranty of
  *      MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
  *      Lesser General Public License for more details.
  *
  *      You should have received a copy of the GNU Lesser General Public
  *      License along with this library in the file COPYING.LIB;
  *      if not, write to the Free Software Foundation, Inc.,
  *      59 Temple Place - Suite 330, Boston, MA 02111-1307, USA
  */

#ifndef PTW32_CONTEXT_H
#define PTW32_CONTEXT_H

#undef PTW32_PROGCTR

#if defined(_M_IX86) || (defined(_X86_) && !defined(__amd64__))
#define PTW32_PROGCTR(Context)  ((Context).Eip)
#endif

#if defined (_M_IA64) || defined(_IA64)
#define PTW32_PROGCTR(Context)  ((Context).StIIP)
#endif

#if defined(_MIPS_) || defined(MIPS)
#define PTW32_PROGCTR(Context)  ((Context).Fir)
#endif

#if defined(_ALPHA_)
#define PTW32_PROGCTR(Context)  ((Context).Fir)
#endif

#if defined(_PPC_)
#define PTW32_PROGCTR(Context)  ((Context).Iar)
#endif

#if defined(_AMD64_) || defined(__amd64__)
#define PTW32_PROGCTR(Context)  ((Context).Rip)
#endif

#if defined(_ARM_) || defined(ARM)
#define PTW32_PROGCTR(Context)  ((Context).Pc)
#endif

#if !defined(PTW32_PROGCTR)
#error Module contains CPU-specific code; modify and recompile.
#endif

#endif


void
pthread_testcancel(void)
/*
 * ------------------------------------------------------
 * DOCPUBLIC
 *      This function creates a deferred cancellation point
 *      in the calling thread. The call has no effect if the
 *      current cancelability state is
 *              PTHREAD_CANCEL_DISABLE
 *
 * PARAMETERS
 *      N/A
 *
 *
 * DESCRIPTION
 *      This function creates a deferred cancellation point
 *      in the calling thread. The call has no effect if the
 *      current cancelability state is
 *              PTHREAD_CANCEL_DISABLE
 *
 *      NOTES:
 *      1)      Cancellation is asynchronous. Use pthread_join
 *              to wait for termination of thread if necessary
 *
 * RESULTS
 *              N/A
 *
 * ------------------------------------------------------
 */
{
	ptw32_mcs_local_node_t stateLock;
	pthread_t self = pthread_self();
	ptw32_thread_t * sp = (ptw32_thread_t *)self.p;

	if (sp == NULL)
	{
		return;
	}

	/*
	 * Pthread_cancel() will have set sp->state to PThreadStateCancelPending
	 * and set an event, so no need to enter kernel space if
	 * sp->state != PThreadStateCancelPending - that only slows us down.
	 */
	if (sp->state != PThreadStateCancelPending)
	{
		return;
	}

	ptw32_mcs_lock_acquire(&sp->stateLock, &stateLock);

	if (sp->cancelState != PTHREAD_CANCEL_DISABLE)
	{
		ResetEvent(sp->cancelEvent);
		sp->state = PThreadStateCanceling;
		sp->cancelState = PTHREAD_CANCEL_DISABLE;
		ptw32_mcs_lock_release(&stateLock);
		ptw32_throw(PTW32_EPS_CANCEL);
		/* Never returns here */
	}

	ptw32_mcs_lock_release(&stateLock);
}				/* pthread_testcancel */
/*
 * pthread_timechange_handler_np.c
 *
 * Description:
 * This translation unit implements miscellaneous thread functions.
 *
 * --------------------------------------------------------------------------
 *
 *      Pthreads-win32 - POSIX Threads Library for Win32
 *      Copyright(C) 1998 John E. Bossom
 *      Copyright(C) 1999,2005 Pthreads-win32 contributors
 *
 *      Contact Email: rpj@callisto.canberra.edu.au
 *
 *      The current list of contributors is contained
 *      in the file CONTRIBUTORS included with the source
 *      code distribution. The list can also be seen at the
 *      following World Wide Web location:
 *      http://sources.redhat.com/pthreads-win32/contributors.html
 *
 *      This library is free software; you can redistribute it and/or
 *      modify it under the terms of the GNU Lesser General Public
 *      License as published by the Free Software Foundation; either
 *      version 2 of the License, or (at your option) any later version.
 *
 *      This library is distributed in the hope that it will be useful,
 *      but WITHOUT ANY WARRANTY; without even the implied warranty of
 *      MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *      Lesser General Public License for more details.
 *
 *      You should have received a copy of the GNU Lesser General Public
 *      License along with this library in the file COPYING.LIB;
 *      if not, write to the Free Software Foundation, Inc.,
 *      59 Temple Place - Suite 330, Boston, MA 02111-1307, USA
 */


 /*
  * Notes on handling system time adjustments (especially negative ones).
  * ---------------------------------------------------------------------
  *
  * This solution was suggested by Alexander Terekhov, but any errors
  * in the implementation are mine - [Ross Johnson]
  *
  * 1) The problem: threads doing a timedwait on a CV may expect to timeout
  *    at a specific absolute time according to a system timer. If the
  *    system clock is adjusted backwards then those threads sleep longer than
  *    expected. Also, pthreads-win32 converts absolute times to intervals in
  *    order to make use of the underlying Win32, and so waiting threads may
  *    awake before their proper abstimes.
  *
  * 2) We aren't able to distinquish between threads on timed or untimed waits,
  *    so we wake them all at the time of the adjustment so that they can
  *    re-evaluate their conditions and re-compute their timeouts.
  *
  * 3) We rely on correctly written applications for this to work. Specifically,
  *    they must be able to deal properly with spurious wakeups. That is,
  *    they must re-test their condition upon wakeup and wait again if
  *    the condition is not satisfied.
  */

void *
pthread_timechange_handler_np(void *arg)
/*
 * ------------------------------------------------------
 * DOCPUBLIC
 *      Broadcasts all CVs to force re-evaluation and
 *      new timeouts if required.
 *
 * PARAMETERS
 *      NONE
 *
 *
 * DESCRIPTION
 *      Broadcasts all CVs to force re-evaluation and
 *      new timeouts if required.
 *
 *      This routine may be passed directly to pthread_create()
 *      as a new thread in order to run asynchronously.
 *
 *
 * RESULTS
 *              0               successfully broadcast all CVs
 *              EAGAIN          Not all CVs were broadcast
 *
 * ------------------------------------------------------
 */
{
	int result = 0;
	pthread_cond_t cv;
	ptw32_mcs_local_node_t node;

	ptw32_mcs_lock_acquire(&ptw32_cond_list_lock, &node);

	cv = ptw32_cond_list_head;

	while (cv != NULL && 0 == result)
	{
		result = pthread_cond_broadcast(&cv);
		cv = cv->next;
	}

	ptw32_mcs_lock_release(&node);

	return (void *)(size_t)(result != 0 ? EAGAIN : 0);
}
/*
 * pthread_win32_attach_detach_np.c
 *
 * Description:
 * This translation unit implements non-portable thread functions.
 *
 * --------------------------------------------------------------------------
 *
 *      Pthreads-win32 - POSIX Threads Library for Win32
 *      Copyright(C) 1998 John E. Bossom
 *      Copyright(C) 1999,2005 Pthreads-win32 contributors
 *
 *      Contact Email: rpj@callisto.canberra.edu.au
 *
 *      The current list of contributors is contained
 *      in the file CONTRIBUTORS included with the source
 *      code distribution. The list can also be seen at the
 *      following World Wide Web location:
 *      http://sources.redhat.com/pthreads-win32/contributors.html
 *
 *      This library is free software; you can redistribute it and/or
 *      modify it under the terms of the GNU Lesser General Public
 *      License as published by the Free Software Foundation; either
 *      version 2 of the License, or (at your option) any later version.
 *
 *      This library is distributed in the hope that it will be useful,
 *      but WITHOUT ANY WARRANTY; without even the implied warranty of
 *      MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *      Lesser General Public License for more details.
 *
 *      You should have received a copy of the GNU Lesser General Public
 *      License along with this library in the file COPYING.LIB;
 *      if not, write to the Free Software Foundation, Inc.,
 *      59 Temple Place - Suite 330, Boston, MA 02111-1307, USA
 */


 /*
  * Handle to quserex.dll
  */
static HINSTANCE ptw32_h_quserex;

BOOL
pthread_win32_process_attach_np()
{
	TCHAR QuserExDLLPathBuf[1024];
	BOOL result = TRUE;

	result = ptw32_processInitialize();

#if defined(_UWIN)
	pthread_count++;
#endif

#if defined(__GNUC__)
	ptw32_features = 0;
#else
	/*
	 * This is obsolete now.
	 */
	ptw32_features = PTW32_SYSTEM_INTERLOCKED_COMPARE_EXCHANGE;
#endif

	/*
	 * Load QUSEREX.DLL and try to get address of QueueUserAPCEx.
	 * Because QUSEREX.DLL requires a driver to be installed we will
	 * assume the DLL is in the system directory.
	 *
	 * This should take care of any security issues.
	 */
#if defined(__GNUC__) || _MSC_VER < 1400
	if (GetSystemDirectory(QuserExDLLPathBuf, sizeof(QuserExDLLPathBuf)))
	{
		(void)strncat(QuserExDLLPathBuf,
			"\\QUSEREX.DLL",
			sizeof(QuserExDLLPathBuf) - strlen(QuserExDLLPathBuf) - 1);
		ptw32_h_quserex = LoadLibrary(QuserExDLLPathBuf);
	}
#else
	 /* strncat is secure - this is just to avoid a warning */
	if (GetSystemDirectory(QuserExDLLPathBuf, sizeof(QuserExDLLPathBuf)) &&
		0 == strncat_s(QuserExDLLPathBuf, sizeof(QuserExDLLPathBuf), "\\QUSEREX.DLL", 12))
	{
		ptw32_h_quserex = LoadLibrary(QuserExDLLPathBuf);
	}
#endif

	if (ptw32_h_quserex != NULL)
	{
		ptw32_register_cancelation = (DWORD(*)(PAPCFUNC, HANDLE, DWORD))
#if defined(NEED_UNICODE_CONSTS)
			GetProcAddress(ptw32_h_quserex,
			(const TCHAR *)TEXT("QueueUserAPCEx"));
#else
			GetProcAddress(ptw32_h_quserex, (LPCSTR) "QueueUserAPCEx");
#endif
	}

	if (NULL == ptw32_register_cancelation)
	{
		ptw32_register_cancelation = ptw32_RegisterCancelation;

		if (ptw32_h_quserex != NULL)
		{
			(void)FreeLibrary(ptw32_h_quserex);
		}
		ptw32_h_quserex = 0;
	}
	else
	{
		/* Initialise QueueUserAPCEx */
		BOOL(*queue_user_apc_ex_init) (VOID);

		queue_user_apc_ex_init = (BOOL(*)(VOID))
#if defined(NEED_UNICODE_CONSTS)
			GetProcAddress(ptw32_h_quserex,
			(const TCHAR *)TEXT("QueueUserAPCEx_Init"));
#else
			GetProcAddress(ptw32_h_quserex, (LPCSTR) "QueueUserAPCEx_Init");
#endif

		if (queue_user_apc_ex_init == NULL || !queue_user_apc_ex_init())
		{
			ptw32_register_cancelation = ptw32_RegisterCancelation;

			(void)FreeLibrary(ptw32_h_quserex);
			ptw32_h_quserex = 0;
		}
	}

	if (ptw32_h_quserex)
	{
		ptw32_features |= PTW32_ALERTABLE_ASYNC_CANCEL;
	}

	return result;
}


BOOL
pthread_win32_process_detach_np()
{
	if (ptw32_processInitialized)
	{
		ptw32_thread_t * sp = (ptw32_thread_t *)pthread_getspecific(ptw32_selfThreadKey);

		if (sp != NULL)
		{
			/*
			 * Detached threads have their resources automatically
			 * cleaned up upon exit (others must be 'joined').
			 */
			if (sp->detachState == PTHREAD_CREATE_DETACHED)
			{
				ptw32_threadDestroy(sp->ptHandle);
				TlsSetValue(ptw32_selfThreadKey->key, NULL);
			}
		}

		/*
		 * The DLL is being unmapped from the process's address space
		 */
		ptw32_processTerminate();

		if (ptw32_h_quserex)
		{
			/* Close QueueUserAPCEx */
			BOOL(*queue_user_apc_ex_fini) (VOID);

			queue_user_apc_ex_fini = (BOOL(*)(VOID))
#if defined(NEED_UNICODE_CONSTS)
				GetProcAddress(ptw32_h_quserex,
				(const TCHAR *)TEXT("QueueUserAPCEx_Fini"));
#else
				GetProcAddress(ptw32_h_quserex, (LPCSTR) "QueueUserAPCEx_Fini");
#endif

			if (queue_user_apc_ex_fini != NULL)
			{
				(void)queue_user_apc_ex_fini();
			}
			(void)FreeLibrary(ptw32_h_quserex);
		}
	}

	return TRUE;
}

BOOL
pthread_win32_thread_attach_np()
{
	return TRUE;
}

BOOL
pthread_win32_thread_detach_np()
{
	if (ptw32_processInitialized)
	{
		/*
		 * Don't use pthread_self() - to avoid creating an implicit POSIX thread handle
		 * unnecessarily.
		 */
		ptw32_thread_t * sp = (ptw32_thread_t *)pthread_getspecific(ptw32_selfThreadKey);

		if (sp != NULL) // otherwise Win32 thread with no implicit POSIX handle.
		{
			ptw32_mcs_local_node_t stateLock;
			ptw32_callUserDestroyRoutines(sp->ptHandle);

			ptw32_mcs_lock_acquire(&sp->stateLock, &stateLock);
			sp->state = PThreadStateLast;
			/*
			 * If the thread is joinable at this point then it MUST be joined
			 * or detached explicitly by the application.
			 */
			ptw32_mcs_lock_release(&stateLock);

			/*
			 * Robust Mutexes
			 */
			while (sp->robustMxList != NULL)
			{
				pthread_mutex_t mx = sp->robustMxList->mx;
				ptw32_robust_mutex_remove(&mx, sp);
				(void)PTW32_INTERLOCKED_EXCHANGE_LONG(
					(PTW32_INTERLOCKED_LONGPTR)&mx->robustNode->stateInconsistent,
					(PTW32_INTERLOCKED_LONG)-1);
				/*
				 * If there are no waiters then the next thread to block will
				 * sleep, wakeup immediately and then go back to sleep.
				 * See pthread_mutex_lock.c.
				 */
				SetEvent(mx->event);
			}


			if (sp->detachState == PTHREAD_CREATE_DETACHED)
			{
				ptw32_threadDestroy(sp->ptHandle);

				TlsSetValue(ptw32_selfThreadKey->key, NULL);
			}
		}
	}

	return TRUE;
}

BOOL
pthread_win32_test_features_np(int feature_mask)
{
	return ((ptw32_features & feature_mask) == feature_mask);
}
/*
 * ptw32_calloc.c
 *
 * Description:
 * This translation unit implements miscellaneous thread functions.
 *
 * --------------------------------------------------------------------------
 *
 *      Pthreads-win32 - POSIX Threads Library for Win32
 *      Copyright(C) 1998 John E. Bossom
 *      Copyright(C) 1999,2005 Pthreads-win32 contributors
 *
 *      Contact Email: rpj@callisto.canberra.edu.au
 *
 *      The current list of contributors is contained
 *      in the file CONTRIBUTORS included with the source
 *      code distribution. The list can also be seen at the
 *      following World Wide Web location:
 *      http://sources.redhat.com/pthreads-win32/contributors.html
 *
 *      This library is free software; you can redistribute it and/or
 *      modify it under the terms of the GNU Lesser General Public
 *      License as published by the Free Software Foundation; either
 *      version 2 of the License, or (at your option) any later version.
 *
 *      This library is distributed in the hope that it will be useful,
 *      but WITHOUT ANY WARRANTY; without even the implied warranty of
 *      MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *      Lesser General Public License for more details.
 *
 *      You should have received a copy of the GNU Lesser General Public
 *      License along with this library in the file COPYING.LIB;
 *      if not, write to the Free Software Foundation, Inc.,
 *      59 Temple Place - Suite 330, Boston, MA 02111-1307, USA
 */



#if defined(NEED_CALLOC)
void *
ptw32_calloc(size_t n, size_t s)
{
	unsigned int m = n * s;
	void *p;

	p = malloc(m);
	if (p == NULL)
		return NULL;

	memset(p, 0, m);

	return p;
}
#endif
/*
 * ptw32_callUserDestroyRoutines.c
 *
 * Description:
 * This translation unit implements routines which are private to
 * the implementation and may be used throughout it.
 *
 * --------------------------------------------------------------------------
 *
 *      Pthreads-win32 - POSIX Threads Library for Win32
 *      Copyright(C) 1998 John E. Bossom
 *      Copyright(C) 1999,2005 Pthreads-win32 contributors
 *
 *      Contact Email: rpj@callisto.canberra.edu.au
 *
 *      The current list of contributors is contained
 *      in the file CONTRIBUTORS included with the source
 *      code distribution. The list can also be seen at the
 *      following World Wide Web location:
 *      http://sources.redhat.com/pthreads-win32/contributors.html
 *
 *      This library is free software; you can redistribute it and/or
 *      modify it under the terms of the GNU Lesser General Public
 *      License as published by the Free Software Foundation; either
 *      version 2 of the License, or (at your option) any later version.
 *
 *      This library is distributed in the hope that it will be useful,
 *      but WITHOUT ANY WARRANTY; without even the implied warranty of
 *      MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *      Lesser General Public License for more details.
 *
 *      You should have received a copy of the GNU Lesser General Public
 *      License along with this library in the file COPYING.LIB;
 *      if not, write to the Free Software Foundation, Inc.,
 *      59 Temple Place - Suite 330, Boston, MA 02111-1307, USA
 */


#if defined(__CLEANUP_CXX)
# if defined(_MSC_VER)
#  include <eh.h>
# elif defined(__WATCOMC__)
#  include <eh.h>
#  include <exceptio.h>
# else
#  if defined(__GNUC__) && __GNUC__ < 3
#    include <new.h>
#  else
#    include <new>
using
std::terminate;
#  endif
# endif
#endif

void
ptw32_callUserDestroyRoutines(pthread_t thread)
/*
 * -------------------------------------------------------------------
 * DOCPRIVATE
 *
 * This the routine runs through all thread keys and calls
 * the destroy routines on the user's data for the current thread.
 * It simulates the behaviour of POSIX Threads.
 *
 * PARAMETERS
 *              thread
 *                      an instance of pthread_t
 *
 * RETURNS
 *              N/A
 * -------------------------------------------------------------------
 */
{
	ThreadKeyAssoc * assoc;

	if (thread.p != NULL)
	{
		ptw32_mcs_local_node_t threadLock;
		ptw32_mcs_local_node_t keyLock;
		int assocsRemaining;
		int iterations = 0;
		ptw32_thread_t * sp = (ptw32_thread_t *)thread.p;

		/*
		 * Run through all Thread<-->Key associations
		 * for the current thread.
		 *
		 * Do this process at most PTHREAD_DESTRUCTOR_ITERATIONS times.
		 */
		do
		{
			assocsRemaining = 0;
			iterations++;

			ptw32_mcs_lock_acquire(&(sp->threadLock), &threadLock);
			/*
			 * The pointer to the next assoc is stored in the thread struct so that
			 * the assoc destructor in pthread_key_delete can adjust it
			 * if it deletes this assoc. This can happen if we fail to acquire
			 * both locks below, and are forced to release all of our locks,
			 * leaving open the opportunity for pthread_key_delete to get in
			 * before us.
			 */
			sp->nextAssoc = sp->keys;
			ptw32_mcs_lock_release(&threadLock);

			for (;;)
			{
				void * value;
				pthread_key_t k;
				void(*destructor) (void *);

				/*
				 * First we need to serialise with pthread_key_delete by locking
				 * both assoc guards, but in the reverse order to our convention,
				 * so we must be careful to avoid deadlock.
				 */
				ptw32_mcs_lock_acquire(&(sp->threadLock), &threadLock);

				if ((assoc = (ThreadKeyAssoc *)sp->nextAssoc) == NULL)
				{
					/* Finished */
					ptw32_mcs_lock_release(&threadLock);
					break;
				}
				else
				{
					/*
					 * assoc->key must be valid because assoc can't change or be
					 * removed from our chain while we hold at least one lock. If
					 * the assoc was on our key chain then the key has not been
					 * deleted yet.
					 *
					 * Now try to acquire the second lock without deadlocking.
					 * If we fail, we need to relinquish the first lock and the
					 * processor and then try to acquire them all again.
					 */
					if (ptw32_mcs_lock_try_acquire(&(assoc->key->keyLock), &keyLock) == EBUSY)
					{
						ptw32_mcs_lock_release(&threadLock);
						Sleep(0);
						/*
						 * Go around again.
						 * If pthread_key_delete has removed this assoc in the meantime,
						 * sp->nextAssoc will point to a new assoc.
						 */
						continue;
					}
				}

				/* We now hold both locks */

				sp->nextAssoc = assoc->nextKey;

				/*
				 * Key still active; pthread_key_delete
				 * will block on these same mutexes before
				 * it can release actual key; therefore,
				 * key is valid and we can call the destroy
				 * routine;
				 */
				k = assoc->key;
				destructor = k->destructor;
				value = TlsGetValue(k->key);
				TlsSetValue(k->key, NULL);

				// Every assoc->key exists and has a destructor
				if (value != NULL && iterations <= PTHREAD_DESTRUCTOR_ITERATIONS)
				{
					/*
					 * Unlock both locks before the destructor runs.
					 * POSIX says pthread_key_delete can be run from destructors,
					 * and that probably includes with this key as target.
					 * pthread_setspecific can also be run from destructors and
					 * also needs to be able to access the assocs.
					 */
					ptw32_mcs_lock_release(&threadLock);
					ptw32_mcs_lock_release(&keyLock);

					assocsRemaining++;

#if defined(__cplusplus)

					try
					{
						/*
						 * Run the caller's cleanup routine.
						 */
						destructor(value);
					}
					catch (...)
					{
						/*
						 * A system unexpected exception has occurred
						 * running the user's destructor.
						 * We get control back within this block in case
						 * the application has set up it's own terminate
						 * handler. Since we are leaving the thread we
						 * should not get any internal pthreads
						 * exceptions.
						 */
						terminate();
					}

#else /* __cplusplus */

					/*
					 * Run the caller's cleanup routine.
					 */
					destructor(value);

#endif /* __cplusplus */

				}
				else
				{
					/*
					 * Remove association from both the key and thread chains
					 * and reclaim it's memory resources.
					 */
					ptw32_tkAssocDestroy(assoc);
					ptw32_mcs_lock_release(&threadLock);
					ptw32_mcs_lock_release(&keyLock);
				}
			}
		} while (assocsRemaining);
	}
}				/* ptw32_callUserDestroyRoutines */
/*
 * ptw32_cond_check_need_init.c
 *
 * Description:
 * This translation unit implements condition variables and their primitives.
 *
 *
 * --------------------------------------------------------------------------
 *
 *      Pthreads-win32 - POSIX Threads Library for Win32
 *      Copyright(C) 1998 John E. Bossom
 *      Copyright(C) 1999,2005 Pthreads-win32 contributors
 *
 *      Contact Email: rpj@callisto.canberra.edu.au
 *
 *      The current list of contributors is contained
 *      in the file CONTRIBUTORS included with the source
 *      code distribution. The list can also be seen at the
 *      following World Wide Web location:
 *      http://sources.redhat.com/pthreads-win32/contributors.html
 *
 *      This library is free software; you can redistribute it and/or
 *      modify it under the terms of the GNU Lesser General Public
 *      License as published by the Free Software Foundation; either
 *      version 2 of the License, or (at your option) any later version.
 *
 *      This library is distributed in the hope that it will be useful,
 *      but WITHOUT ANY WARRANTY; without even the implied warranty of
 *      MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *      Lesser General Public License for more details.
 *
 *      You should have received a copy of the GNU Lesser General Public
 *      License along with this library in the file COPYING.LIB;
 *      if not, write to the Free Software Foundation, Inc.,
 *      59 Temple Place - Suite 330, Boston, MA 02111-1307, USA
 */



INLINE int
ptw32_cond_check_need_init(pthread_cond_t * cond)
{
	int result = 0;
	ptw32_mcs_local_node_t node;

	/*
	 * The following guarded test is specifically for statically
	 * initialised condition variables (via PTHREAD_OBJECT_INITIALIZER).
	 */
	ptw32_mcs_lock_acquire(&ptw32_cond_test_init_lock, &node);

	/*
	 * We got here possibly under race
	 * conditions. Check again inside the critical section.
	 * If a static cv has been destroyed, the application can
	 * re-initialise it only by calling pthread_cond_init()
	 * explicitly.
	 */
	if (*cond == PTHREAD_COND_INITIALIZER)
	{
		result = pthread_cond_init(cond, NULL);
	}
	else if (*cond == NULL)
	{
		/*
		 * The cv has been destroyed while we were waiting to
		 * initialise it, so the operation that caused the
		 * auto-initialisation should fail.
		 */
		result = EINVAL;
	}

	ptw32_mcs_lock_release(&node);

	return result;
}
/*
 * ptw32_getprocessors.c
 *
 * Description:
 * This translation unit implements routines which are private to
 * the implementation and may be used throughout it.
 *
 * --------------------------------------------------------------------------
 *
 *      Pthreads-win32 - POSIX Threads Library for Win32
 *      Copyright(C) 1998 John E. Bossom
 *      Copyright(C) 1999,2005 Pthreads-win32 contributors
 *
 *      Contact Email: rpj@callisto.canberra.edu.au
 *
 *      The current list of contributors is contained
 *      in the file CONTRIBUTORS included with the source
 *      code distribution. The list can also be seen at the
 *      following World Wide Web location:
 *      http://sources.redhat.com/pthreads-win32/contributors.html
 *
 *      This library is free software; you can redistribute it and/or
 *      modify it under the terms of the GNU Lesser General Public
 *      License as published by the Free Software Foundation; either
 *      version 2 of the License, or (at your option) any later version.
 *
 *      This library is distributed in the hope that it will be useful,
 *      but WITHOUT ANY WARRANTY; without even the implied warranty of
 *      MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *      Lesser General Public License for more details.
 *
 *      You should have received a copy of the GNU Lesser General Public
 *      License along with this library in the file COPYING.LIB;
 *      if not, write to the Free Software Foundation, Inc.,
 *      59 Temple Place - Suite 330, Boston, MA 02111-1307, USA
 */



 /*
  * ptw32_getprocessors()
  *
  * Get the number of CPUs available to the process.
  *
  * If the available number of CPUs is 1 then pthread_spin_lock()
  * will block rather than spin if the lock is already owned.
  *
  * pthread_spin_init() calls this routine when initialising
  * a spinlock. If the number of available processors changes
  * (after a call to SetProcessAffinityMask()) then only
  * newly initialised spinlocks will notice.
  */
int
ptw32_getprocessors(int *count)
{
	DWORD_PTR vProcessCPUs;
	DWORD_PTR vSystemCPUs;
	int result = 0;

#if defined(NEED_PROCESS_AFFINITY_MASK)

	*count = 1;

#else

	if (GetProcessAffinityMask(GetCurrentProcess(),
		&vProcessCPUs, &vSystemCPUs))
	{
		DWORD_PTR bit;
		int CPUs = 0;

		for (bit = 1; bit != 0; bit <<= 1)
		{
			if (vProcessCPUs & bit)
			{
				CPUs++;
			}
		}
		*count = CPUs;
	}
	else
	{
		result = EAGAIN;
	}

#endif

	return (result);
}
/*
 * ptw32_is_attr.c
 *
 * Description:
 * This translation unit implements operations on thread attribute objects.
 *
 * --------------------------------------------------------------------------
 *
 *      Pthreads-win32 - POSIX Threads Library for Win32
 *      Copyright(C) 1998 John E. Bossom
 *      Copyright(C) 1999,2005 Pthreads-win32 contributors
 *
 *      Contact Email: rpj@callisto.canberra.edu.au
 *
 *      The current list of contributors is contained
 *      in the file CONTRIBUTORS included with the source
 *      code distribution. The list can also be seen at the
 *      following World Wide Web location:
 *      http://sources.redhat.com/pthreads-win32/contributors.html
 *
 *      This library is free software; you can redistribute it and/or
 *      modify it under the terms of the GNU Lesser General Public
 *      License as published by the Free Software Foundation; either
 *      version 2 of the License, or (at your option) any later version.
 *
 *      This library is distributed in the hope that it will be useful,
 *      but WITHOUT ANY WARRANTY; without even the implied warranty of
 *      MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *      Lesser General Public License for more details.
 *
 *      You should have received a copy of the GNU Lesser General Public
 *      License along with this library in the file COPYING.LIB;
 *      if not, write to the Free Software Foundation, Inc.,
 *      59 Temple Place - Suite 330, Boston, MA 02111-1307, USA
 */


int
ptw32_is_attr(const pthread_attr_t * attr)
{
	/* Return 0 if the attr object is valid, non-zero otherwise. */

	return (attr == NULL ||
		*attr == NULL || (*attr)->valid != PTW32_ATTR_VALID);
}
/*
 * ptw32_MCS_lock.c
 *
 * Description:
 * This translation unit implements queue-based locks.
 *
 * --------------------------------------------------------------------------
 *
 *      Pthreads-win32 - POSIX Threads Library for Win32
 *      Copyright(C) 1998 John E. Bossom
 *      Copyright(C) 1999,2005 Pthreads-win32 contributors
 *
 *      Contact Email: rpj@callisto.canberra.edu.au
 *
 *      The current list of contributors is contained
 *      in the file CONTRIBUTORS included with the source
 *      code distribution. The list can also be seen at the
 *      following World Wide Web location:
 *      http://sources.redhat.com/pthreads-win32/contributors.html
 *
 *      This library is free software; you can redistribute it and/or
 *      modify it under the terms of the GNU Lesser General Public
 *      License as published by the Free Software Foundation; either
 *      version 2 of the License, or (at your option) any later version.
 *
 *      This library is distributed in the hope that it will be useful,
 *      but WITHOUT ANY WARRANTY; without even the implied warranty of
 *      MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *      Lesser General Public License for more details.
 *
 *      You should have received a copy of the GNU Lesser General Public
 *      License along with this library in the file COPYING.LIB;
 *      if not, write to the Free Software Foundation, Inc.,
 *      59 Temple Place - Suite 330, Boston, MA 02111-1307, USA
 */

 /*
  * About MCS locks:
  *
  * MCS locks are queue-based locks, where the queue nodes are local to the
  * thread. The 'lock' is nothing more than a global pointer that points to
  * the last node in the queue, or is NULL if the queue is empty.
  *
  * Originally designed for use as spin locks requiring no kernel resources
  * for synchronisation or blocking, the implementation below has adapted
  * the MCS spin lock for use as a general mutex that will suspend threads
  * when there is lock contention.
  *
  * Because the queue nodes are thread-local, most of the memory read/write
  * operations required to add or remove nodes from the queue do not trigger
  * cache-coherence updates.
  *
  * Like 'named' mutexes, MCS locks consume system resources transiently -
  * they are able to acquire and free resources automatically - but MCS
  * locks do not require any unique 'name' to identify the lock to all
  * threads using it.
  *
  * Usage of MCS locks:
  *
  * - you need a global ptw32_mcs_lock_t instance initialised to 0 or NULL.
  * - you need a local thread-scope ptw32_mcs_local_node_t instance, which
  *   may serve several different locks but you need at least one node for
  *   every lock held concurrently by a thread.
  *
  * E.g.:
  *
  * ptw32_mcs_lock_t lock1 = 0;
  * ptw32_mcs_lock_t lock2 = 0;
  *
  * void *mythread(void *arg)
  * {
  *   ptw32_mcs_local_node_t node;
  *
  *   ptw32_mcs_acquire (&lock1, &node);
  *   ptw32_mcs_lock_release (&node);
  *
  *   ptw32_mcs_lock_acquire (&lock2, &node);
  *   ptw32_mcs_lock_release (&node);
  *   {
  *      ptw32_mcs_local_node_t nodex;
  *
  *      ptw32_mcs_lock_acquire (&lock1, &node);
  *      ptw32_mcs_lock_acquire (&lock2, &nodex);
  *
  *      ptw32_mcs_lock_release (&nodex);
  *      ptw32_mcs_lock_release (&node);
  *   }
  *   return (void *)0;
  * }
  */


  /*
   * ptw32_mcs_flag_set -- notify another thread about an event.
   *
   * Set event if an event handle has been stored in the flag, and
   * set flag to -1 otherwise. Note that -1 cannot be a valid handle value.
   */
INLINE void
ptw32_mcs_flag_set(HANDLE * flag)
{
	HANDLE e = (HANDLE)(PTW32_INTERLOCKED_SIZE)PTW32_INTERLOCKED_COMPARE_EXCHANGE_SIZE(
		(PTW32_INTERLOCKED_SIZEPTR)flag,
		(PTW32_INTERLOCKED_SIZE)-1,
		(PTW32_INTERLOCKED_SIZE)0);
	if ((HANDLE)0 != e)
	{
		/* another thread has already stored an event handle in the flag */
		SetEvent(e);
	}
}

/*
 * ptw32_mcs_flag_set -- wait for notification from another.
 *
 * Store an event handle in the flag and wait on it if the flag has not been
 * set, and proceed without creating an event otherwise.
 */
INLINE void
ptw32_mcs_flag_wait(HANDLE * flag)
{
	if ((PTW32_INTERLOCKED_LONG)0 ==
		PTW32_INTERLOCKED_EXCHANGE_ADD_SIZE((PTW32_INTERLOCKED_SIZEPTR)flag,
		(PTW32_INTERLOCKED_SIZE)0)) /* MBR fence */
	{
		/* the flag is not set. create event. */

		HANDLE e = CreateEvent(NULL, PTW32_FALSE, PTW32_FALSE, NULL);

		if ((PTW32_INTERLOCKED_SIZE)0 == PTW32_INTERLOCKED_COMPARE_EXCHANGE_SIZE(
			(PTW32_INTERLOCKED_SIZEPTR)flag,
			(PTW32_INTERLOCKED_SIZE)e,
			(PTW32_INTERLOCKED_SIZE)0))
		{
			/* stored handle in the flag. wait on it now. */
			WaitForSingleObject(e, INFINITE);
		}

		CloseHandle(e);
	}
}

/*
 * ptw32_mcs_lock_acquire -- acquire an MCS lock.
 *
 * See:
 * J. M. Mellor-Crummey and M. L. Scott.
 * Algorithms for Scalable Synchronization on Shared-Memory Multiprocessors.
 * ACM Transactions on Computer Systems, 9(1):21-65, Feb. 1991.
 */
#if defined(PTW32_BUILD_INLINED)
INLINE
#endif /* PTW32_BUILD_INLINED */
void
ptw32_mcs_lock_acquire(ptw32_mcs_lock_t * lock, ptw32_mcs_local_node_t * node)
{
	ptw32_mcs_local_node_t  *pred;

	node->lock = lock;
	node->nextFlag = 0;
	node->readyFlag = 0;
	node->next = 0; /* initially, no successor */

	/* queue for the lock */
	pred = (ptw32_mcs_local_node_t *)PTW32_INTERLOCKED_EXCHANGE_PTR((PTW32_INTERLOCKED_PVOID_PTR)lock,
		(PTW32_INTERLOCKED_PVOID)node);

	if (0 != pred)
	{
		/* the lock was not free. link behind predecessor. */
		pred->next = node;
		ptw32_mcs_flag_set(&pred->nextFlag);
		ptw32_mcs_flag_wait(&node->readyFlag);
	}
}

/*
 * ptw32_mcs_lock_release -- release an MCS lock.
 *
 * See:
 * J. M. Mellor-Crummey and M. L. Scott.
 * Algorithms for Scalable Synchronization on Shared-Memory Multiprocessors.
 * ACM Transactions on Computer Systems, 9(1):21-65, Feb. 1991.
 */
#if defined(PTW32_BUILD_INLINED)
INLINE
#endif /* PTW32_BUILD_INLINED */
void
ptw32_mcs_lock_release(ptw32_mcs_local_node_t * node)
{
	ptw32_mcs_lock_t *lock = node->lock;
	ptw32_mcs_local_node_t *next =
		(ptw32_mcs_local_node_t *)
		PTW32_INTERLOCKED_EXCHANGE_ADD_SIZE((PTW32_INTERLOCKED_SIZEPTR)&node->next, (PTW32_INTERLOCKED_SIZE)0); /* MBR fence */

	if (0 == next)
	{
		/* no known successor */

		if (node == (ptw32_mcs_local_node_t *)
			PTW32_INTERLOCKED_COMPARE_EXCHANGE_PTR((PTW32_INTERLOCKED_PVOID_PTR)lock,
			(PTW32_INTERLOCKED_PVOID)0,
				(PTW32_INTERLOCKED_PVOID)node))
		{
			/* no successor, lock is free now */
			return;
		}

		/* A successor has started enqueueing behind us so wait for them to link to us */
		ptw32_mcs_flag_wait(&node->nextFlag);
		next = (ptw32_mcs_local_node_t *)
			PTW32_INTERLOCKED_EXCHANGE_ADD_SIZE((PTW32_INTERLOCKED_SIZEPTR)&node->next, (PTW32_INTERLOCKED_SIZE)0); /* MBR fence */
	}

	/* pass the lock */
	ptw32_mcs_flag_set(&next->readyFlag);
}

/*
  * ptw32_mcs_lock_try_acquire
 */
#if defined(PTW32_BUILD_INLINED)
INLINE
#endif /* PTW32_BUILD_INLINED */
int
ptw32_mcs_lock_try_acquire(ptw32_mcs_lock_t * lock, ptw32_mcs_local_node_t * node)
{
	node->lock = lock;
	node->nextFlag = 0;
	node->readyFlag = 0;
	node->next = 0; /* initially, no successor */

	return ((PTW32_INTERLOCKED_PVOID)PTW32_INTERLOCKED_COMPARE_EXCHANGE_PTR((PTW32_INTERLOCKED_PVOID_PTR)lock,
		(PTW32_INTERLOCKED_PVOID)node,
		(PTW32_INTERLOCKED_PVOID)0)
		== (PTW32_INTERLOCKED_PVOID)0) ? 0 : EBUSY;
}

/*
 * ptw32_mcs_node_transfer -- move an MCS lock local node, usually from thread
 * space to, for example, global space so that another thread can release
 * the lock on behalf of the current lock owner.
 *
 * Example: used in pthread_barrier_wait where we want the last thread out of
 * the barrier to release the lock owned by the last thread to enter the barrier
 * (the one that releases all threads but not necessarily the last to leave).
 *
 * Should only be called by the thread that has the lock.
 */
#if defined(PTW32_BUILD_INLINED)
INLINE
#endif /* PTW32_BUILD_INLINED */
void
ptw32_mcs_node_transfer(ptw32_mcs_local_node_t * new_node, ptw32_mcs_local_node_t * old_node)
{
	new_node->lock = old_node->lock;
	new_node->nextFlag = 0; /* Not needed - used only in initial Acquire */
	new_node->readyFlag = 0; /* Not needed - we were waiting on this */
	new_node->next = 0;

	if ((ptw32_mcs_local_node_t *)PTW32_INTERLOCKED_COMPARE_EXCHANGE_PTR((PTW32_INTERLOCKED_PVOID_PTR)new_node->lock,
		(PTW32_INTERLOCKED_PVOID)new_node,
		(PTW32_INTERLOCKED_PVOID)old_node)
		!= old_node)
	{
		/*
		 * A successor has queued after us, so wait for them to link to us
		 */
		while (old_node->next == 0)
		{
			sched_yield();
		}
		new_node->next = old_node->next;
	}
}
/*
 * ptw32_mutex_check_need_init.c
 *
 * Description:
 * This translation unit implements mutual exclusion (mutex) primitives.
 *
 * --------------------------------------------------------------------------
 *
 *      Pthreads-win32 - POSIX Threads Library for Win32
 *      Copyright(C) 1998 John E. Bossom
 *      Copyright(C) 1999,2005 Pthreads-win32 contributors
 *
 *      Contact Email: rpj@callisto.canberra.edu.au
 *
 *      The current list of contributors is contained
 *      in the file CONTRIBUTORS included with the source
 *      code distribution. The list can also be seen at the
 *      following World Wide Web location:
 *      http://sources.redhat.com/pthreads-win32/contributors.html
 *
 *      This library is free software; you can redistribute it and/or
 *      modify it under the terms of the GNU Lesser General Public
 *      License as published by the Free Software Foundation; either
 *      version 2 of the License, or (at your option) any later version.
 *
 *      This library is distributed in the hope that it will be useful,
 *      but WITHOUT ANY WARRANTY; without even the implied warranty of
 *      MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *      Lesser General Public License for more details.
 *
 *      You should have received a copy of the GNU Lesser General Public
 *      License along with this library in the file COPYING.LIB;
 *      if not, write to the Free Software Foundation, Inc.,
 *      59 Temple Place - Suite 330, Boston, MA 02111-1307, USA
 */


static struct pthread_mutexattr_t_ ptw32_recursive_mutexattr_s =
{ PTHREAD_PROCESS_PRIVATE, PTHREAD_MUTEX_RECURSIVE };
static struct pthread_mutexattr_t_ ptw32_errorcheck_mutexattr_s =
{ PTHREAD_PROCESS_PRIVATE, PTHREAD_MUTEX_ERRORCHECK };
static pthread_mutexattr_t ptw32_recursive_mutexattr = &ptw32_recursive_mutexattr_s;
static pthread_mutexattr_t ptw32_errorcheck_mutexattr = &ptw32_errorcheck_mutexattr_s;


INLINE int
ptw32_mutex_check_need_init(pthread_mutex_t * mutex)
{
	register int result = 0;
	register pthread_mutex_t mtx;
	ptw32_mcs_local_node_t node;

	ptw32_mcs_lock_acquire(&ptw32_mutex_test_init_lock, &node);

	/*
	 * We got here possibly under race
	 * conditions. Check again inside the critical section
	 * and only initialise if the mutex is valid (not been destroyed).
	 * If a static mutex has been destroyed, the application can
	 * re-initialise it only by calling pthread_mutex_init()
	 * explicitly.
	 */
	mtx = *mutex;

	if (mtx == PTHREAD_MUTEX_INITIALIZER)
	{
		result = pthread_mutex_init(mutex, NULL);
	}
	else if (mtx == PTHREAD_RECURSIVE_MUTEX_INITIALIZER)
	{
		result = pthread_mutex_init(mutex, &ptw32_recursive_mutexattr);
	}
	else if (mtx == PTHREAD_ERRORCHECK_MUTEX_INITIALIZER)
	{
		result = pthread_mutex_init(mutex, &ptw32_errorcheck_mutexattr);
	}
	else if (mtx == NULL)
	{
		/*
		 * The mutex has been destroyed while we were waiting to
		 * initialise it, so the operation that caused the
		 * auto-initialisation should fail.
		 */
		result = EINVAL;
	}

	ptw32_mcs_lock_release(&node);

	return (result);
}
/*
 * ptw32_new.c
 *
 * Description:
 * This translation unit implements miscellaneous thread functions.
 *
 * --------------------------------------------------------------------------
 *
 *      Pthreads-win32 - POSIX Threads Library for Win32
 *      Copyright(C) 1998 John E. Bossom
 *      Copyright(C) 1999,2005 Pthreads-win32 contributors
 *
 *      Contact Email: rpj@callisto.canberra.edu.au
 *
 *      The current list of contributors is contained
 *      in the file CONTRIBUTORS included with the source
 *      code distribution. The list can also be seen at the
 *      following World Wide Web location:
 *      http://sources.redhat.com/pthreads-win32/contributors.html
 *
 *      This library is free software; you can redistribute it and/or
 *      modify it under the terms of the GNU Lesser General Public
 *      License as published by the Free Software Foundation; either
 *      version 2 of the License, or (at your option) any later version.
 *
 *      This library is distributed in the hope that it will be useful,
 *      but WITHOUT ANY WARRANTY; without even the implied warranty of
 *      MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *      Lesser General Public License for more details.
 *
 *      You should have received a copy of the GNU Lesser General Public
 *      License along with this library in the file COPYING.LIB;
 *      if not, write to the Free Software Foundation, Inc.,
 *      59 Temple Place - Suite 330, Boston, MA 02111-1307, USA
 */



pthread_t
ptw32_new(void)
{
	pthread_t t;
	pthread_t nil = { NULL, 0 };
	ptw32_thread_t * tp;

	/*
	 * If there's a reusable pthread_t then use it.
	 */
	t = ptw32_threadReusePop();

	if (NULL != t.p)
	{
		tp = (ptw32_thread_t *)t.p;
	}
	else
	{
		/* No reuse threads available */
		tp = (ptw32_thread_t *)calloc(1, sizeof(ptw32_thread_t));

		if (tp == NULL)
		{
			return nil;
		}

		/* ptHandle.p needs to point to it's parent ptw32_thread_t. */
		t.p = tp->ptHandle.p = tp;
		t.x = tp->ptHandle.x = 0;
	}

	/* Set default state. */
	tp->seqNumber = ++ptw32_threadSeqNumber;
	tp->sched_priority = THREAD_PRIORITY_NORMAL;
	tp->detachState = PTHREAD_CREATE_JOINABLE;
	tp->cancelState = PTHREAD_CANCEL_ENABLE;
	tp->cancelType = PTHREAD_CANCEL_DEFERRED;
	tp->stateLock = 0;
	tp->threadLock = 0;
	tp->robustMxListLock = 0;
	tp->robustMxList = NULL;
	tp->cancelEvent = CreateEvent(0, (int)PTW32_TRUE,	/* manualReset  */
		(int)PTW32_FALSE,	/* setSignaled  */
		NULL);

	if (tp->cancelEvent == NULL)
	{
		ptw32_threadReusePush(tp->ptHandle);
		return nil;
	}

	return t;

}

/*
 * ptw32_processInitialize.c
 *
 * Description:
 * This translation unit implements routines which are private to
 * the implementation and may be used throughout it.
 *
 * --------------------------------------------------------------------------
 *
 *      Pthreads-win32 - POSIX Threads Library for Win32
 *      Copyright(C) 1998 John E. Bossom
 *      Copyright(C) 1999,2005 Pthreads-win32 contributors
 *
 *      Contact Email: rpj@callisto.canberra.edu.au
 *
 *      The current list of contributors is contained
 *      in the file CONTRIBUTORS included with the source
 *      code distribution. The list can also be seen at the
 *      following World Wide Web location:
 *      http://sources.redhat.com/pthreads-win32/contributors.html
 *
 *      This library is free software; you can redistribute it and/or
 *      modify it under the terms of the GNU Lesser General Public
 *      License as published by the Free Software Foundation; either
 *      version 2 of the License, or (at your option) any later version.
 *
 *      This library is distributed in the hope that it will be useful,
 *      but WITHOUT ANY WARRANTY; without even the implied warranty of
 *      MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *      Lesser General Public License for more details.
 *
 *      You should have received a copy of the GNU Lesser General Public
 *      License along with this library in the file COPYING.LIB;
 *      if not, write to the Free Software Foundation, Inc.,
 *      59 Temple Place - Suite 330, Boston, MA 02111-1307, USA
 */



int
ptw32_processInitialize(void)
/*
 * ------------------------------------------------------
 * DOCPRIVATE
 *      This function performs process wide initialization for
 *      the pthread library.
 *
 * PARAMETERS
 *      N/A
 *
 * DESCRIPTION
 *      This function performs process wide initialization for
 *      the pthread library.
 *      If successful, this routine sets the global variable
 *      ptw32_processInitialized to TRUE.
 *
 * RESULTS
 *              TRUE    if successful,
 *              FALSE   otherwise
 *
 * ------------------------------------------------------
 */
{
	if (ptw32_processInitialized)
	{
		/*
		 * Ignore if already initialized. this is useful for
		 * programs that uses a non-dll pthread
		 * library. Such programs must call ptw32_processInitialize() explicitly,
		 * since this initialization routine is automatically called only when
		 * the dll is loaded.
		 */
		return PTW32_TRUE;
	}

	ptw32_processInitialized = PTW32_TRUE;

	/*
	 * Initialize Keys
	 */
	if ((pthread_key_create(&ptw32_selfThreadKey, NULL) != 0) ||
		(pthread_key_create(&ptw32_cleanupKey, NULL) != 0))
	{

		ptw32_processTerminate();
	}

	return (ptw32_processInitialized);

}				/* processInitialize */
/*
 * ptw32_processTerminate.c
 *
 * Description:
 * This translation unit implements routines which are private to
 * the implementation and may be used throughout it.
 *
 * --------------------------------------------------------------------------
 *
 *      Pthreads-win32 - POSIX Threads Library for Win32
 *      Copyright(C) 1998 John E. Bossom
 *      Copyright(C) 1999,2005 Pthreads-win32 contributors
 *
 *      Contact Email: rpj@callisto.canberra.edu.au
 *
 *      The current list of contributors is contained
 *      in the file CONTRIBUTORS included with the source
 *      code distribution. The list can also be seen at the
 *      following World Wide Web location:
 *      http://sources.redhat.com/pthreads-win32/contributors.html
 *
 *      This library is free software; you can redistribute it and/or
 *      modify it under the terms of the GNU Lesser General Public
 *      License as published by the Free Software Foundation; either
 *      version 2 of the License, or (at your option) any later version.
 *
 *      This library is distributed in the hope that it will be useful,
 *      but WITHOUT ANY WARRANTY; without even the implied warranty of
 *      MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *      Lesser General Public License for more details.
 *
 *      You should have received a copy of the GNU Lesser General Public
 *      License along with this library in the file COPYING.LIB;
 *      if not, write to the Free Software Foundation, Inc.,
 *      59 Temple Place - Suite 330, Boston, MA 02111-1307, USA
 */



void
ptw32_processTerminate(void)
/*
 * ------------------------------------------------------
 * DOCPRIVATE
 *      This function performs process wide termination for
 *      the pthread library.
 *
 * PARAMETERS
 *      N/A
 *
 * DESCRIPTION
 *      This function performs process wide termination for
 *      the pthread library.
 *      This routine sets the global variable
 *      ptw32_processInitialized to FALSE
 *
 * RESULTS
 *              N/A
 *
 * ------------------------------------------------------
 */
{
	if (ptw32_processInitialized)
	{
		ptw32_thread_t * tp, *tpNext;
		ptw32_mcs_local_node_t node;

		if (ptw32_selfThreadKey != NULL)
		{
			/*
			 * Release ptw32_selfThreadKey
			 */
			pthread_key_delete(ptw32_selfThreadKey);

			ptw32_selfThreadKey = NULL;
		}

		if (ptw32_cleanupKey != NULL)
		{
			/*
			 * Release ptw32_cleanupKey
			 */
			pthread_key_delete(ptw32_cleanupKey);

			ptw32_cleanupKey = NULL;
		}

		ptw32_mcs_lock_acquire(&ptw32_thread_reuse_lock, &node);

		tp = ptw32_threadReuseTop;
		while (tp != PTW32_THREAD_REUSE_EMPTY)
		{
			tpNext = tp->prevReuse;
			free(tp);
			tp = tpNext;
		}

		ptw32_mcs_lock_release(&node);

		ptw32_processInitialized = PTW32_FALSE;
	}

}				/* processTerminate */
/*
 * ptw32_relmillisecs.c
 *
 * Description:
 * This translation unit implements miscellaneous thread functions.
 *
 * --------------------------------------------------------------------------
 *
 *      Pthreads-win32 - POSIX Threads Library for Win32
 *      Copyright(C) 1998 John E. Bossom
 *      Copyright(C) 1999,2005 Pthreads-win32 contributors
 *
 *      Contact Email: rpj@callisto.canberra.edu.au
 *
 *      The current list of contributors is contained
 *      in the file CONTRIBUTORS included with the source
 *      code distribution. The list can also be seen at the
 *      following World Wide Web location:
 *      http://sources.redhat.com/pthreads-win32/contributors.html
 *
 *      This library is free software; you can redistribute it and/or
 *      modify it under the terms of the GNU Lesser General Public
 *      License as published by the Free Software Foundation; either
 *      version 2 of the License, or (at your option) any later version.
 *
 *      This library is distributed in the hope that it will be useful,
 *      but WITHOUT ANY WARRANTY; without even the implied warranty of
 *      MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *      Lesser General Public License for more details.
 *
 *      You should have received a copy of the GNU Lesser General Public
 *      License along with this library in the file COPYING.LIB;
 *      if not, write to the Free Software Foundation, Inc.,
 *      59 Temple Place - Suite 330, Boston, MA 02111-1307, USA
 */

#if !defined(NEED_FTIME)
#include <sys/timeb.h>
#endif


#if defined(PTW32_BUILD_INLINED)
INLINE
#endif /* PTW32_BUILD_INLINED */
DWORD
ptw32_relmillisecs(const struct timespec * abstime)
{
	const int64_t NANOSEC_PER_MILLISEC = 1000000;
	const int64_t MILLISEC_PER_SEC = 1000;
	DWORD milliseconds;
	int64_t tmpAbsMilliseconds;
	int64_t tmpCurrMilliseconds;
#if defined(NEED_FTIME)
	struct timespec currSysTime;
	FILETIME ft;
	SYSTEMTIME st;
#else /* ! NEED_FTIME */
#if ( defined(_MSC_VER) && _MSC_VER >= 1300 ) || \
    ( (defined(__MINGW64__) || defined(__MINGW32__)) && __MSVCRT_VERSION__ >= 0x0601 )
	struct __timeb64 currSysTime;
#else
	struct _timeb currSysTime;
#endif
#endif /* NEED_FTIME */


	/*
	 * Calculate timeout as milliseconds from current system time.
	 */

	 /*
	  * subtract current system time from abstime in a way that checks
	  * that abstime is never in the past, or is never equivalent to the
	  * defined INFINITE value (0xFFFFFFFF).
	  *
	  * Assume all integers are unsigned, i.e. cannot test if less than 0.
	  */
	tmpAbsMilliseconds = (int64_t)abstime->tv_sec * MILLISEC_PER_SEC;
	tmpAbsMilliseconds += ((int64_t)abstime->tv_nsec + (NANOSEC_PER_MILLISEC / 2)) / NANOSEC_PER_MILLISEC;

	/* get current system time */

#if defined(NEED_FTIME)

	GetSystemTime(&st);
	SystemTimeToFileTime(&st, &ft);
	/*
	 * GetSystemTimeAsFileTime(&ft); would be faster,
	 * but it does not exist on WinCE
	 */

	ptw32_filetime_to_timespec(&ft, &currSysTime);

	tmpCurrMilliseconds = (int64_t)currSysTime.tv_sec * MILLISEC_PER_SEC;
	tmpCurrMilliseconds += ((int64_t)currSysTime.tv_nsec + (NANOSEC_PER_MILLISEC / 2))
		/ NANOSEC_PER_MILLISEC;

#else /* ! NEED_FTIME */

#if defined(_MSC_VER) && _MSC_VER >= 1400
	_ftime64_s(&currSysTime);
#elif ( defined(_MSC_VER) && _MSC_VER >= 1300 ) || \
      ( (defined(__MINGW64__) || defined(__MINGW32__)) && __MSVCRT_VERSION__ >= 0x0601 )
	_ftime64(&currSysTime);
#else
	_ftime(&currSysTime);
#endif

	tmpCurrMilliseconds = (int64_t)currSysTime.time * MILLISEC_PER_SEC;
	tmpCurrMilliseconds += (int64_t)currSysTime.millitm;

#endif /* NEED_FTIME */

	if (tmpAbsMilliseconds > tmpCurrMilliseconds)
	{
		milliseconds = (DWORD)(tmpAbsMilliseconds - tmpCurrMilliseconds);
		if (milliseconds == INFINITE)
		{
			/* Timeouts must be finite */
			milliseconds--;
		}
	}
	else
	{
		/* The abstime given is in the past */
		milliseconds = 0;
	}

	return milliseconds;
}
/*
 * ptw32_threadReuse.c
 *
 * Description:
 * This translation unit implements miscellaneous thread functions.
 *
 * --------------------------------------------------------------------------
 *
 *      Pthreads-win32 - POSIX Threads Library for Win32
 *      Copyright(C) 1998 John E. Bossom
 *      Copyright(C) 1999,2005 Pthreads-win32 contributors
 *
 *      Contact Email: rpj@callisto.canberra.edu.au
 *
 *      The current list of contributors is contained
 *      in the file CONTRIBUTORS included with the source
 *      code distribution. The list can also be seen at the
 *      following World Wide Web location:
 *      http://sources.redhat.com/pthreads-win32/contributors.html
 *
 *      This library is free software; you can redistribute it and/or
 *      modify it under the terms of the GNU Lesser General Public
 *      License as published by the Free Software Foundation; either
 *      version 2 of the License, or (at your option) any later version.
 *
 *      This library is distributed in the hope that it will be useful,
 *      but WITHOUT ANY WARRANTY; without even the implied warranty of
 *      MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *      Lesser General Public License for more details.
 *
 *      You should have received a copy of the GNU Lesser General Public
 *      License along with this library in the file COPYING.LIB;
 *      if not, write to the Free Software Foundation, Inc.,
 *      59 Temple Place - Suite 330, Boston, MA 02111-1307, USA
 */



 /*
  * How it works:
  * A pthread_t is a struct (2x32 bit scalar types on IA-32, 2x64 bit on IA-64)
  * which is normally passed/returned by value to/from pthreads routines.
  * Applications are therefore storing a copy of the struct as it is at that
  * time.
  *
  * The original pthread_t struct plus all copies of it contain the address of
  * the thread state struct ptw32_thread_t_ (p), plus a reuse counter (x). Each
  * ptw32_thread_t contains the original copy of it's pthread_t.
  * Once malloced, a ptw32_thread_t_ struct is not freed until the process exits.
  *
  * The thread reuse stack is a simple LILO stack managed through a singly
  * linked list element in the ptw32_thread_t.
  *
  * Each time a thread is destroyed, the ptw32_thread_t address is pushed onto the
  * reuse stack after it's ptHandle's reuse counter has been incremented.
  *
  * The following can now be said from this:
  * - two pthread_t's are identical if their ptw32_thread_t reference pointers
  * are equal and their reuse counters are equal. That is,
  *
  *   equal = (a.p == b.p && a.x == b.x)
  *
  * - a pthread_t copy refers to a destroyed thread if the reuse counter in
  * the copy is not equal to the reuse counter in the original.
  *
  *   threadDestroyed = (copy.x != ((ptw32_thread_t *)copy.p)->ptHandle.x)
  *
  */

  /*
   * Pop a clean pthread_t struct off the reuse stack.
   */
pthread_t
ptw32_threadReusePop(void)
{
	pthread_t t = { NULL, 0 };
	ptw32_mcs_local_node_t node;

	ptw32_mcs_lock_acquire(&ptw32_thread_reuse_lock, &node);

	if (PTW32_THREAD_REUSE_EMPTY != ptw32_threadReuseTop)
	{
		ptw32_thread_t * tp;

		tp = ptw32_threadReuseTop;

		ptw32_threadReuseTop = tp->prevReuse;

		if (PTW32_THREAD_REUSE_EMPTY == ptw32_threadReuseTop)
		{
			ptw32_threadReuseBottom = PTW32_THREAD_REUSE_EMPTY;
		}

		tp->prevReuse = NULL;

		t = tp->ptHandle;
	}

	ptw32_mcs_lock_release(&node);

	return t;

}

/*
 * Push a clean pthread_t struct onto the reuse stack.
 * Must be re-initialised when reused.
 * All object elements (mutexes, events etc) must have been either
 * detroyed before this, or never initialised.
 */
void
ptw32_threadReusePush(pthread_t thread)
{
	ptw32_thread_t * tp = (ptw32_thread_t *)thread.p;
	pthread_t t;
	ptw32_mcs_local_node_t node;

	ptw32_mcs_lock_acquire(&ptw32_thread_reuse_lock, &node);

	t = tp->ptHandle;
	memset(tp, 0, sizeof(ptw32_thread_t));

	/* Must restore the original POSIX handle that we just wiped. */
	tp->ptHandle = t;

	/* Bump the reuse counter now */
#if defined(PTW32_THREAD_ID_REUSE_INCREMENT)
	tp->ptHandle.x += PTW32_THREAD_ID_REUSE_INCREMENT;
#else
	tp->ptHandle.x++;
#endif

	tp->state = PThreadStateReuse;

	tp->prevReuse = PTW32_THREAD_REUSE_EMPTY;

	if (PTW32_THREAD_REUSE_EMPTY != ptw32_threadReuseBottom)
	{
		ptw32_threadReuseBottom->prevReuse = tp;
	}
	else
	{
		ptw32_threadReuseTop = tp;
	}

	ptw32_threadReuseBottom = tp;

	ptw32_mcs_lock_release(&node);
}
/*
 * ptw32_rwlock_cancelwrwait.c
 *
 * Description:
 * This translation unit implements read/write lock primitives.
 *
 * --------------------------------------------------------------------------
 *
 *      Pthreads-win32 - POSIX Threads Library for Win32
 *      Copyright(C) 1998 John E. Bossom
 *      Copyright(C) 1999,2005 Pthreads-win32 contributors
 *
 *      Contact Email: rpj@callisto.canberra.edu.au
 *
 *      The current list of contributors is contained
 *      in the file CONTRIBUTORS included with the source
 *      code distribution. The list can also be seen at the
 *      following World Wide Web location:
 *      http://sources.redhat.com/pthreads-win32/contributors.html
 *
 *      This library is free software; you can redistribute it and/or
 *      modify it under the terms of the GNU Lesser General Public
 *      License as published by the Free Software Foundation; either
 *      version 2 of the License, or (at your option) any later version.
 *
 *      This library is distributed in the hope that it will be useful,
 *      but WITHOUT ANY WARRANTY; without even the implied warranty of
 *      MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *      Lesser General Public License for more details.
 *
 *      You should have received a copy of the GNU Lesser General Public
 *      License along with this library in the file COPYING.LIB;
 *      if not, write to the Free Software Foundation, Inc.,
 *      59 Temple Place - Suite 330, Boston, MA 02111-1307, USA
 */


void
ptw32_rwlock_cancelwrwait(void *arg)
{
	pthread_rwlock_t rwl = (pthread_rwlock_t)arg;

	rwl->nSharedAccessCount = -rwl->nCompletedSharedAccessCount;
	rwl->nCompletedSharedAccessCount = 0;

	(void)pthread_mutex_unlock(&(rwl->mtxSharedAccessCompleted));
	(void)pthread_mutex_unlock(&(rwl->mtxExclusiveAccess));
}
/*
 * pthread_rwlock_check_need_init.c
 *
 * Description:
 * This translation unit implements read/write lock primitives.
 *
 * --------------------------------------------------------------------------
 *
 *      Pthreads-win32 - POSIX Threads Library for Win32
 *      Copyright(C) 1998 John E. Bossom
 *      Copyright(C) 1999,2005 Pthreads-win32 contributors
 *
 *      Contact Email: rpj@callisto.canberra.edu.au
 *
 *      The current list of contributors is contained
 *      in the file CONTRIBUTORS included with the source
 *      code distribution. The list can also be seen at the
 *      following World Wide Web location:
 *      http://sources.redhat.com/pthreads-win32/contributors.html
 *
 *      This library is free software; you can redistribute it and/or
 *      modify it under the terms of the GNU Lesser General Public
 *      License as published by the Free Software Foundation; either
 *      version 2 of the License, or (at your option) any later version.
 *
 *      This library is distributed in the hope that it will be useful,
 *      but WITHOUT ANY WARRANTY; without even the implied warranty of
 *      MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *      Lesser General Public License for more details.
 *
 *      You should have received a copy of the GNU Lesser General Public
 *      License along with this library in the file COPYING.LIB;
 *      if not, write to the Free Software Foundation, Inc.,
 *      59 Temple Place - Suite 330, Boston, MA 02111-1307, USA
 */


INLINE int
ptw32_rwlock_check_need_init(pthread_rwlock_t * rwlock)
{
	int result = 0;
	ptw32_mcs_local_node_t node;

	/*
	 * The following guarded test is specifically for statically
	 * initialised rwlocks (via PTHREAD_RWLOCK_INITIALIZER).
	 */
	ptw32_mcs_lock_acquire(&ptw32_rwlock_test_init_lock, &node);

	/*
	 * We got here possibly under race
	 * conditions. Check again inside the critical section
	 * and only initialise if the rwlock is valid (not been destroyed).
	 * If a static rwlock has been destroyed, the application can
	 * re-initialise it only by calling pthread_rwlock_init()
	 * explicitly.
	 */
	if (*rwlock == PTHREAD_RWLOCK_INITIALIZER)
	{
		result = pthread_rwlock_init(rwlock, NULL);
	}
	else if (*rwlock == NULL)
	{
		/*
		 * The rwlock has been destroyed while we were waiting to
		 * initialise it, so the operation that caused the
		 * auto-initialisation should fail.
		 */
		result = EINVAL;
	}

	ptw32_mcs_lock_release(&node);

	return result;
}
/*
 * ptw32_semwait.c
 *
 * Description:
 * This translation unit implements mutual exclusion (mutex) primitives.
 *
 * --------------------------------------------------------------------------
 *
 *      Pthreads-win32 - POSIX Threads Library for Win32
 *      Copyright(C) 1998 John E. Bossom
 *      Copyright(C) 1999,2005 Pthreads-win32 contributors
 *
 *      Contact Email: rpj@callisto.canberra.edu.au
 *
 *      The current list of contributors is contained
 *      in the file CONTRIBUTORS included with the source
 *      code distribution. The list can also be seen at the
 *      following World Wide Web location:
 *      http://sources.redhat.com/pthreads-win32/contributors.html
 *
 *      This library is free software; you can redistribute it and/or
 *      modify it under the terms of the GNU Lesser General Public
 *      License as published by the Free Software Foundation; either
 *      version 2 of the License, or (at your option) any later version.
 *
 *      This library is distributed in the hope that it will be useful,
 *      but WITHOUT ANY WARRANTY; without even the implied warranty of
 *      MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *      Lesser General Public License for more details.
 *
 *      You should have received a copy of the GNU Lesser General Public
 *      License along with this library in the file COPYING.LIB;
 *      if not, write to the Free Software Foundation, Inc.,
 *      59 Temple Place - Suite 330, Boston, MA 02111-1307, USA
 */

#if !defined(_UWIN)
 /*#   include <process.h> */
#endif


int
ptw32_semwait(sem_t * sem)
/*
 * ------------------------------------------------------
 * DESCRIPTION
 *      This function waits on a POSIX semaphore. If the
 *      semaphore value is greater than zero, it decreases
 *      its value by one. If the semaphore value is zero, then
 *      the calling thread (or process) is blocked until it can
 *      successfully decrease the value.
 *
 *      Unlike sem_wait(), this routine is non-cancelable.
 *
 * RESULTS
 *              0               successfully decreased semaphore,
 *              -1              failed, error in errno.
 * ERRNO
 *              EINVAL          'sem' is not a valid semaphore,
 *              ENOSYS          semaphores are not supported,
 *              EINTR           the function was interrupted by a signal,
 *              EDEADLK         a deadlock condition was detected.
 *
 * ------------------------------------------------------
 */
{
	int result = 0;
	sem_t s = *sem;

	if (s == NULL)
	{
		result = EINVAL;
	}
	else
	{
		if ((result = pthread_mutex_lock(&s->lock)) == 0)
		{
			int v;

			/* See sem_destroy.c
			 */
			if (*sem == NULL)
			{
				(void)pthread_mutex_unlock(&s->lock);
				errno = EINVAL;
				return -1;
			}

			v = --s->value;
			(void)pthread_mutex_unlock(&s->lock);

			if (v < 0)
			{
				/* Must wait */
				if (WaitForSingleObject(s->sem, INFINITE) == WAIT_OBJECT_0)
				{
#if defined(NEED_SEM)
					if (pthread_mutex_lock(&s->lock) == 0)
					{
						if (*sem == NULL)
						{
							(void)pthread_mutex_unlock(&s->lock);
							errno = EINVAL;
							return -1;
						}

						if (s->leftToUnblock > 0)
						{
							--s->leftToUnblock;
							SetEvent(s->sem);
						}
						(void)pthread_mutex_unlock(&s->lock);
					}
#endif
					return 0;
				}
			}
			else
			{
				return 0;
			}
		}
	}

	if (result != 0)
	{
		errno = result;
		return -1;
	}

	return 0;

}				/* ptw32_semwait */
/*
 * ptw32_spinlock_check_need_init.c
 *
 * Description:
 * This translation unit implements spin lock primitives.
 *
 * --------------------------------------------------------------------------
 *
 *      Pthreads-win32 - POSIX Threads Library for Win32
 *      Copyright(C) 1998 John E. Bossom
 *      Copyright(C) 1999,2005 Pthreads-win32 contributors
 *
 *      Contact Email: rpj@callisto.canberra.edu.au
 *
 *      The current list of contributors is contained
 *      in the file CONTRIBUTORS included with the source
 *      code distribution. The list can also be seen at the
 *      following World Wide Web location:
 *      http://sources.redhat.com/pthreads-win32/contributors.html
 *
 *      This library is free software; you can redistribute it and/or
 *      modify it under the terms of the GNU Lesser General Public
 *      License as published by the Free Software Foundation; either
 *      version 2 of the License, or (at your option) any later version.
 *
 *      This library is distributed in the hope that it will be useful,
 *      but WITHOUT ANY WARRANTY; without even the implied warranty of
 *      MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *      Lesser General Public License for more details.
 *
 *      You should have received a copy of the GNU Lesser General Public
 *      License along with this library in the file COPYING.LIB;
 *      if not, write to the Free Software Foundation, Inc.,
 *      59 Temple Place - Suite 330, Boston, MA 02111-1307, USA
 */



INLINE int
ptw32_spinlock_check_need_init(pthread_spinlock_t * lock)
{
	int result = 0;
	ptw32_mcs_local_node_t node;

	/*
	 * The following guarded test is specifically for statically
	 * initialised spinlocks (via PTHREAD_SPINLOCK_INITIALIZER).
	 */
	ptw32_mcs_lock_acquire(&ptw32_spinlock_test_init_lock, &node);

	/*
	 * We got here possibly under race
	 * conditions. Check again inside the critical section
	 * and only initialise if the spinlock is valid (not been destroyed).
	 * If a static spinlock has been destroyed, the application can
	 * re-initialise it only by calling pthread_spin_init()
	 * explicitly.
	 */
	if (*lock == PTHREAD_SPINLOCK_INITIALIZER)
	{
		result = pthread_spin_init(lock, PTHREAD_PROCESS_PRIVATE);
	}
	else if (*lock == NULL)
	{
		/*
		 * The spinlock has been destroyed while we were waiting to
		 * initialise it, so the operation that caused the
		 * auto-initialisation should fail.
		 */
		result = EINVAL;
	}

	ptw32_mcs_lock_release(&node);

	return (result);
}
/*
 * ptw32_threadDestroy.c
 *
 * Description:
 * This translation unit implements routines which are private to
 * the implementation and may be used throughout it.
 *
 * --------------------------------------------------------------------------
 *
 *      Pthreads-win32 - POSIX Threads Library for Win32
 *      Copyright(C) 1998 John E. Bossom
 *      Copyright(C) 1999,2005 Pthreads-win32 contributors
 *
 *      Contact Email: rpj@callisto.canberra.edu.au
 *
 *      The current list of contributors is contained
 *      in the file CONTRIBUTORS included with the source
 *      code distribution. The list can also be seen at the
 *      following World Wide Web location:
 *      http://sources.redhat.com/pthreads-win32/contributors.html
 *
 *      This library is free software; you can redistribute it and/or
 *      modify it under the terms of the GNU Lesser General Public
 *      License as published by the Free Software Foundation; either
 *      version 2 of the License, or (at your option) any later version.
 *
 *      This library is distributed in the hope that it will be useful,
 *      but WITHOUT ANY WARRANTY; without even the implied warranty of
 *      MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *      Lesser General Public License for more details.
 *
 *      You should have received a copy of the GNU Lesser General Public
 *      License along with this library in the file COPYING.LIB;
 *      if not, write to the Free Software Foundation, Inc.,
 *      59 Temple Place - Suite 330, Boston, MA 02111-1307, USA
 */



void
ptw32_threadDestroy(pthread_t thread)
{
	ptw32_thread_t * tp = (ptw32_thread_t *)thread.p;
	ptw32_thread_t threadCopy;

	if (tp != NULL)
	{
		/*
		 * Copy thread state so that the thread can be atomically NULLed.
		 */
		memcpy(&threadCopy, tp, sizeof(threadCopy));

		/*
		 * Thread ID structs are never freed. They're NULLed and reused.
		 * This also sets the thread to PThreadStateInitial (invalid).
		 */
		ptw32_threadReusePush(thread);

		/* Now work on the copy. */
		if (threadCopy.cancelEvent != NULL)
		{
			CloseHandle(threadCopy.cancelEvent);
		}

#if ! (defined(__MINGW64__) || defined(__MINGW32__)) || defined (__MSVCRT__) || defined (__DMC__)
		/*
		 * See documentation for endthread vs endthreadex.
		 */
		if (threadCopy.threadH != 0)
		{
			CloseHandle(threadCopy.threadH);
		}
#endif

	}
}				/* ptw32_threadDestroy */

/*
 * ptw32_threadStart.c
 *
 * Description:
 * This translation unit implements routines which are private to
 * the implementation and may be used throughout it.
 *
 * --------------------------------------------------------------------------
 *
 *      Pthreads-win32 - POSIX Threads Library for Win32
 *      Copyright(C) 1998 John E. Bossom
 *      Copyright(C) 1999,2005 Pthreads-win32 contributors
 *
 *      Contact Email: rpj@callisto.canberra.edu.au
 *
 *      The current list of contributors is contained
 *      in the file CONTRIBUTORS included with the source
 *      code distribution. The list can also be seen at the
 *      following World Wide Web location:
 *      http://sources.redhat.com/pthreads-win32/contributors.html
 *
 *      This library is free software; you can redistribute it and/or
 *      modify it under the terms of the GNU Lesser General Public
 *      License as published by the Free Software Foundation; either
 *      version 2 of the License, or (at your option) any later version.
 *
 *      This library is distributed in the hope that it will be useful,
 *      but WITHOUT ANY WARRANTY; without even the implied warranty of
 *      MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *      Lesser General Public License for more details.
 *
 *      You should have received a copy of the GNU Lesser General Public
 *      License along with this library in the file COPYING.LIB;
 *      if not, write to the Free Software Foundation, Inc.,
 *      59 Temple Place - Suite 330, Boston, MA 02111-1307, USA
 */


#if defined(__CLEANUP_C)
# include <setjmp.h>
#endif

#if defined(__CLEANUP_SEH)

static DWORD
ExceptionFilter(EXCEPTION_POINTERS * ep, DWORD * ei)
{
	switch (ep->ExceptionRecord->ExceptionCode)
	{
	case EXCEPTION_PTW32_SERVICES:
	{
		DWORD param;
		DWORD numParams = ep->ExceptionRecord->NumberParameters;

		numParams = (numParams > 3) ? 3 : numParams;

		for (param = 0; param < numParams; param++)
		{
			ei[param] = ep->ExceptionRecord->ExceptionInformation[param];
		}

		return EXCEPTION_EXECUTE_HANDLER;
		break;
	}
	default:
	{
		/*
		 * A system unexpected exception has occurred running the user's
		 * routine. We need to cleanup before letting the exception
		 * out of thread scope.
		 */
		pthread_t self = pthread_self();

		ptw32_callUserDestroyRoutines(self);

		return EXCEPTION_CONTINUE_SEARCH;
		break;
	}
	}
}

#elif defined(__CLEANUP_CXX)

#if defined(_MSC_VER)
# include <eh.h>
#elif defined(__WATCOMC__)
# include <eh.h>
# include <exceptio.h>
typedef terminate_handler
terminate_function;
#else
# if defined(__GNUC__) && __GNUC__ < 3
#   include <new.h>
# else
#   include <new>
using
std::terminate_handler;
using
std::terminate;
using
std::set_terminate;
# endif
typedef terminate_handler
terminate_function;
#endif

static terminate_function
ptw32_oldTerminate;

void
ptw32_terminate()
{
	set_terminate(ptw32_oldTerminate);
	(void)pthread_win32_thread_detach_np();
	terminate();
}

#endif

#if ! (defined(__MINGW64__) || defined(__MINGW32__)) || (defined (__MSVCRT__) && ! defined (__DMC__))
unsigned
__stdcall
#else
void
#endif
ptw32_threadStart(void *vthreadParms)
{
	ThreadParms * threadParms = (ThreadParms *)vthreadParms;
	pthread_t self;
	ptw32_thread_t * sp;
	void * (PTW32_CDECL *start) (void *);
	void * arg;

#if defined(__CLEANUP_SEH)
	DWORD
		ei[] = { 0, 0, 0 };
#endif

#if defined(__CLEANUP_C)
	int setjmp_rc;
#endif

	ptw32_mcs_local_node_t stateLock;
	void * status = (void *)0;

	self = threadParms->tid;
	sp = (ptw32_thread_t *)self.p;
	start = threadParms->start;
	arg = threadParms->arg;

	free(threadParms);

#if (defined(__MINGW64__) || defined(__MINGW32__)) && ! defined (__MSVCRT__)
	/*
	 * beginthread does not return the thread id and is running
	 * before it returns us the thread handle, and so we do it here.
	 */
	sp->thread = GetCurrentThreadId();
	/*
	 * Here we're using stateLock as a general-purpose lock
	 * to make the new thread wait until the creating thread
	 * has the new handle.
	 */
	ptw32_mcs_lock_acquire(&sp->stateLock, &stateLock);
	pthread_setspecific(ptw32_selfThreadKey, sp);
#else
	pthread_setspecific(ptw32_selfThreadKey, sp);
	ptw32_mcs_lock_acquire(&sp->stateLock, &stateLock);
#endif

	sp->state = PThreadStateRunning;
	ptw32_mcs_lock_release(&stateLock);

#if defined(__CLEANUP_SEH)

	__try
	{
		/*
		 * Run the caller's routine;
		 */
		status = sp->exitStatus = (*start) (arg);
		sp->state = PThreadStateExiting;

#if defined(_UWIN)
		if (--pthread_count <= 0)
			exit(0);
#endif

	}
	__except (ExceptionFilter(GetExceptionInformation(), ei))
	{
		switch (ei[0])
		{
		case PTW32_EPS_CANCEL:
			status = sp->exitStatus = PTHREAD_CANCELED;
#if defined(_UWIN)
			if (--pthread_count <= 0)
				exit(0);
#endif
			break;
		case PTW32_EPS_EXIT:
			status = sp->exitStatus;
			break;
		default:
			status = sp->exitStatus = PTHREAD_CANCELED;
			break;
		}
	}

#else /* __CLEANUP_SEH */

#if defined(__CLEANUP_C)

	setjmp_rc = setjmp(sp->start_mark);

	if (0 == setjmp_rc)
	{

		/*
		 * Run the caller's routine;
		 */
		status = sp->exitStatus = (*start) (arg);
		sp->state = PThreadStateExiting;
	}
	else
	{
		switch (setjmp_rc)
		{
		case PTW32_EPS_CANCEL:
			status = sp->exitStatus = PTHREAD_CANCELED;
			break;
		case PTW32_EPS_EXIT:
			status = sp->exitStatus;
			break;
		default:
			status = sp->exitStatus = PTHREAD_CANCELED;
			break;
		}
	}

#else /* __CLEANUP_C */

#if defined(__CLEANUP_CXX)

	ptw32_oldTerminate = set_terminate(&ptw32_terminate);

	try
	{
		/*
		 * Run the caller's routine in a nested try block so that we
		 * can run the user's terminate function, which may call
		 * pthread_exit() or be canceled.
		 */
		try
		{
			status = sp->exitStatus = (*start) (arg);
			sp->state = PThreadStateExiting;
		}
		catch (ptw32_exception &)
		{
			/*
			 * Pass these through to the outer block.
			 */
			throw;
		}
		catch (...)
		{
			/*
			 * We want to run the user's terminate function if supplied.
			 * That function may call pthread_exit() or be canceled, which will
			 * be handled by the outer try block.
			 *
			 * ptw32_terminate() will be called if there is no user
			 * supplied function.
			 */
			terminate_function
				term_func = set_terminate(0);
			set_terminate(term_func);

			if (term_func != 0)
			{
				term_func();
			}
			throw;
		}
	}
	catch (ptw32_exception_cancel &)
	{
		/*
		 * Thread was canceled.
		 */
		status = sp->exitStatus = PTHREAD_CANCELED;
	}
	catch (ptw32_exception_exit &)
	{
		/*
		 * Thread was exited via pthread_exit().
		 */
		status = sp->exitStatus;
	}
	catch (...)
	{
		/*
		 * A system unexpected exception has occurred running the user's
		 * terminate routine. We get control back within this block
		 * and exit with a substitute status. If the thread was not
		 * cancelled then this indicates the unhandled exception.
		 */
		status = sp->exitStatus = PTHREAD_CANCELED;
	}

	(void)set_terminate(ptw32_oldTerminate);

#else

#error ERROR [__FILE__, line __LINE__]: Cleanup type undefined.

#endif /* __CLEANUP_CXX */
#endif /* __CLEANUP_C */
#endif /* __CLEANUP_SEH */

#if defined(PTW32_STATIC_LIB)
	/*
	 * We need to cleanup the pthread now if we have
	 * been statically linked, in which case the cleanup
	 * in dllMain won't get done. Joinable threads will
	 * only be partially cleaned up and must be fully cleaned
	 * up by pthread_join() or pthread_detach().
	 *
	 * Note: if this library has been statically linked,
	 * implicitly created pthreads (those created
	 * for Win32 threads which have called pthreads routines)
	 * must be cleaned up explicitly by the application
	 * (by calling pthread_win32_thread_detach_np()).
	 * For the dll, dllMain will do the cleanup automatically.
	 */
	(void)pthread_win32_thread_detach_np();
#endif

#if ! (defined(__MINGW64__) || defined(__MINGW32__)) || defined (__MSVCRT__) || defined (__DMC__)
	_endthreadex((unsigned)(size_t)status);
#else
	_endthread();
#endif

	/*
	 * Never reached.
	 */

#if ! (defined(__MINGW64__) || defined(__MINGW32__)) || defined (__MSVCRT__) || defined (__DMC__)
	return (unsigned)(size_t)status;
#endif

}				/* ptw32_threadStart */
/*
 * ptw32_throw.c
 *
 * Description:
 * This translation unit implements routines which are private to
 * the implementation and may be used throughout it.
 *
 * --------------------------------------------------------------------------
 *
 *      Pthreads-win32 - POSIX Threads Library for Win32
 *      Copyright(C) 1998 John E. Bossom
 *      Copyright(C) 1999,2005 Pthreads-win32 contributors
 *
 *      Contact Email: rpj@callisto.canberra.edu.au
 *
 *      The current list of contributors is contained
 *      in the file CONTRIBUTORS included with the source
 *      code distribution. The list can also be seen at the
 *      following World Wide Web location:
 *      http://sources.redhat.com/pthreads-win32/contributors.html
 *
 *      This library is free software; you can redistribute it and/or
 *      modify it under the terms of the GNU Lesser General Public
 *      License as published by the Free Software Foundation; either
 *      version 2 of the License, or (at your option) any later version.
 *
 *      This library is distributed in the hope that it will be useful,
 *      but WITHOUT ANY WARRANTY; without even the implied warranty of
 *      MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *      Lesser General Public License for more details.
 *
 *      You should have received a copy of the GNU Lesser General Public
 *      License along with this library in the file COPYING.LIB;
 *      if not, write to the Free Software Foundation, Inc.,
 *      59 Temple Place - Suite 330, Boston, MA 02111-1307, USA
 */


#if defined(__CLEANUP_C)
# include <setjmp.h>
#endif

 /*
  * ptw32_throw
  *
  * All canceled and explicitly exited POSIX threads go through
  * here. This routine knows how to exit both POSIX initiated threads and
  * 'implicit' POSIX threads for each of the possible language modes (C,
  * C++, and SEH).
  */
#if defined(_MSC_VER)
  /*
   * Ignore the warning:
   * "C++ exception specification ignored except to indicate that
   * the function is not __declspec(nothrow)."
   */
#pragma warning(disable:4290)
#endif
void
ptw32_throw(DWORD exception)
#if defined(__CLEANUP_CXX)
throw(ptw32_exception_cancel, ptw32_exception_exit)
#endif
{
	/*
	 * Don't use pthread_self() to avoid creating an implicit POSIX thread handle
	 * unnecessarily.
	 */
	ptw32_thread_t * sp = (ptw32_thread_t *)pthread_getspecific(ptw32_selfThreadKey);

#if defined(__CLEANUP_SEH)
	DWORD exceptionInformation[3];
#endif

	sp->state = PThreadStateExiting;

	if (exception != PTW32_EPS_CANCEL && exception != PTW32_EPS_EXIT)
	{
		/* Should never enter here */
		exit(1);
	}

	if (NULL == sp || sp->implicit)
	{
		/*
		 * We're inside a non-POSIX initialised Win32 thread
		 * so there is no point to jump or throw back to. Just do an
		 * explicit thread exit here after cleaning up POSIX
		 * residue (i.e. cleanup handlers, POSIX thread handle etc).
		 */
#if ! (defined(__MINGW64__) || defined(__MINGW32__)) || defined (__MSVCRT__) || defined (__DMC__)
		unsigned exitCode = 0;

		switch (exception)
		{
		case PTW32_EPS_CANCEL:
			exitCode = (unsigned)(size_t)PTHREAD_CANCELED;
			break;
		case PTW32_EPS_EXIT:
			if (NULL != sp)
			{
				exitCode = (unsigned)(size_t)sp->exitStatus;
			}
			break;
		}
#endif

#if defined(PTW32_STATIC_LIB)

		pthread_win32_thread_detach_np();

#endif

#if ! (defined(__MINGW64__) || defined(__MINGW32__)) || defined (__MSVCRT__) || defined (__DMC__)
		_endthreadex(exitCode);
#else
		_endthread();
#endif

	}

#if defined(__CLEANUP_SEH)


	exceptionInformation[0] = (DWORD)(exception);
	exceptionInformation[1] = (DWORD)(0);
	exceptionInformation[2] = (DWORD)(0);

	RaiseException(EXCEPTION_PTW32_SERVICES, 0, 3, exceptionInformation);

#else /* __CLEANUP_SEH */

#if defined(__CLEANUP_C)

	ptw32_pop_cleanup_all(1);
	longjmp(sp->start_mark, exception);

#else /* __CLEANUP_C */

#if defined(__CLEANUP_CXX)

	switch (exception)
	{
	case PTW32_EPS_CANCEL:
		throw ptw32_exception_cancel();
		break;
	case PTW32_EPS_EXIT:
		throw ptw32_exception_exit();
		break;
	}

#else

#error ERROR [__FILE__, line __LINE__]: Cleanup type undefined.

#endif /* __CLEANUP_CXX */

#endif /* __CLEANUP_C */

#endif /* __CLEANUP_SEH */

	/* Never reached */
}


void
ptw32_pop_cleanup_all(int execute)
{
	while (NULL != ptw32_pop_cleanup(execute))
	{
	}
}


DWORD
ptw32_get_exception_services_code(void)
{
#if defined(__CLEANUP_SEH)

	return EXCEPTION_PTW32_SERVICES;

#else

	return (DWORD)0;

#endif
}
/*
 * ptw32_timespec.c
 *
 * Description:
 * This translation unit implements routines which are private to
 * the implementation and may be used throughout it.
 *
 * --------------------------------------------------------------------------
 *
 *      Pthreads-win32 - POSIX Threads Library for Win32
 *      Copyright(C) 1998 John E. Bossom
 *      Copyright(C) 1999,2005 Pthreads-win32 contributors
 *
 *      Contact Email: rpj@callisto.canberra.edu.au
 *
 *      The current list of contributors is contained
 *      in the file CONTRIBUTORS included with the source
 *      code distribution. The list can also be seen at the
 *      following World Wide Web location:
 *      http://sources.redhat.com/pthreads-win32/contributors.html
 *
 *      This library is free software; you can redistribute it and/or
 *      modify it under the terms of the GNU Lesser General Public
 *      License as published by the Free Software Foundation; either
 *      version 2 of the License, or (at your option) any later version.
 *
 *      This library is distributed in the hope that it will be useful,
 *      but WITHOUT ANY WARRANTY; without even the implied warranty of
 *      MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *      Lesser General Public License for more details.
 *
 *      You should have received a copy of the GNU Lesser General Public
 *      License along with this library in the file COPYING.LIB;
 *      if not, write to the Free Software Foundation, Inc.,
 *      59 Temple Place - Suite 330, Boston, MA 02111-1307, USA
 */



#if defined(NEED_FTIME)

 /*
  * time between jan 1, 1601 and jan 1, 1970 in units of 100 nanoseconds
  */
#define PTW32_TIMESPEC_TO_FILETIME_OFFSET \
	  ( ((int64_t) 27111902 << 32) + (int64_t) 3577643008 )

INLINE void
ptw32_timespec_to_filetime(const struct timespec *ts, FILETIME * ft)
/*
 * -------------------------------------------------------------------
 * converts struct timespec
 * where the time is expressed in seconds and nanoseconds from Jan 1, 1970.
 * into FILETIME (as set by GetSystemTimeAsFileTime), where the time is
 * expressed in 100 nanoseconds from Jan 1, 1601,
 * -------------------------------------------------------------------
 */
{
	*(int64_t *)ft = ts->tv_sec * 10000000
		+ (ts->tv_nsec + 50) / 100 + PTW32_TIMESPEC_TO_FILETIME_OFFSET;
}

INLINE void
ptw32_filetime_to_timespec(const FILETIME * ft, struct timespec *ts)
/*
 * -------------------------------------------------------------------
 * converts FILETIME (as set by GetSystemTimeAsFileTime), where the time is
 * expressed in 100 nanoseconds from Jan 1, 1601,
 * into struct timespec
 * where the time is expressed in seconds and nanoseconds from Jan 1, 1970.
 * -------------------------------------------------------------------
 */
{
	ts->tv_sec =
		(int)((*(int64_t *)ft - PTW32_TIMESPEC_TO_FILETIME_OFFSET) / 10000000);
	ts->tv_nsec =
		(int)((*(int64_t *)ft - PTW32_TIMESPEC_TO_FILETIME_OFFSET -
		((int64_t)ts->tv_sec * (int64_t)10000000)) * 100);
}

#endif /* NEED_FTIME */
/*
 * ptw32_tkAssocCreate.c
 *
 * Description:
 * This translation unit implements routines which are private to
 * the implementation and may be used throughout it.
 *
 * --------------------------------------------------------------------------
 *
 *      Pthreads-win32 - POSIX Threads Library for Win32
 *      Copyright(C) 1998 John E. Bossom
 *      Copyright(C) 1999,2005 Pthreads-win32 contributors
 *
 *      Contact Email: rpj@callisto.canberra.edu.au
 *
 *      The current list of contributors is contained
 *      in the file CONTRIBUTORS included with the source
 *      code distribution. The list can also be seen at the
 *      following World Wide Web location:
 *      http://sources.redhat.com/pthreads-win32/contributors.html
 *
 *      This library is free software; you can redistribute it and/or
 *      modify it under the terms of the GNU Lesser General Public
 *      License as published by the Free Software Foundation; either
 *      version 2 of the License, or (at your option) any later version.
 *
 *      This library is distributed in the hope that it will be useful,
 *      but WITHOUT ANY WARRANTY; without even the implied warranty of
 *      MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *      Lesser General Public License for more details.
 *
 *      You should have received a copy of the GNU Lesser General Public
 *      License along with this library in the file COPYING.LIB;
 *      if not, write to the Free Software Foundation, Inc.,
 *      59 Temple Place - Suite 330, Boston, MA 02111-1307, USA
 */



int
ptw32_tkAssocCreate(ptw32_thread_t * sp, pthread_key_t key)
/*
 * -------------------------------------------------------------------
 * This routine creates an association that
 * is unique for the given (thread,key) combination.The association
 * is referenced by both the thread and the key.
 * This association allows us to determine what keys the
 * current thread references and what threads a given key
 * references.
 * See the detailed description
 * at the beginning of this file for further details.
 *
 * Notes:
 *      1)      New associations are pushed to the beginning of the
 *              chain so that the internal ptw32_selfThreadKey association
 *              is always last, thus allowing selfThreadExit to
 *              be implicitly called last by pthread_exit.
 *      2)
 *
 * Parameters:
 *              thread
 *                      current running thread.
 *              key
 *                      key on which to create an association.
 * Returns:
 *       0              - if successful,
 *       ENOMEM         - not enough memory to create assoc or other object
 *       EINVAL         - an internal error occurred
 *       ENOSYS         - an internal error occurred
 * -------------------------------------------------------------------
 */
{
	ThreadKeyAssoc *assoc;

	/*
	 * Have to create an association and add it
	 * to both the key and the thread.
	 *
	 * Both key->keyLock and thread->threadLock are locked before
	 * entry to this routine.
	 */
	assoc = (ThreadKeyAssoc *)calloc(1, sizeof(*assoc));

	if (assoc == NULL)
	{
		return ENOMEM;
	}

	assoc->thread = sp;
	assoc->key = key;

	/*
	 * Register assoc with key
	 */
	assoc->prevThread = NULL;
	assoc->nextThread = (ThreadKeyAssoc *)key->threads;
	if (assoc->nextThread != NULL)
	{
		assoc->nextThread->prevThread = assoc;
	}
	key->threads = (void *)assoc;

	/*
	 * Register assoc with thread
	 */
	assoc->prevKey = NULL;
	assoc->nextKey = (ThreadKeyAssoc *)sp->keys;
	if (assoc->nextKey != NULL)
	{
		assoc->nextKey->prevKey = assoc;
	}
	sp->keys = (void *)assoc;

	return (0);

}				/* ptw32_tkAssocCreate */
/*
 * ptw32_tkAssocDestroy.c
 *
 * Description:
 * This translation unit implements routines which are private to
 * the implementation and may be used throughout it.
 *
 * --------------------------------------------------------------------------
 *
 *      Pthreads-win32 - POSIX Threads Library for Win32
 *      Copyright(C) 1998 John E. Bossom
 *      Copyright(C) 1999,2005 Pthreads-win32 contributors
 *
 *      Contact Email: rpj@callisto.canberra.edu.au
 *
 *      The current list of contributors is contained
 *      in the file CONTRIBUTORS included with the source
 *      code distribution. The list can also be seen at the
 *      following World Wide Web location:
 *      http://sources.redhat.com/pthreads-win32/contributors.html
 *
 *      This library is free software; you can redistribute it and/or
 *      modify it under the terms of the GNU Lesser General Public
 *      License as published by the Free Software Foundation; either
 *      version 2 of the License, or (at your option) any later version.
 *
 *      This library is distributed in the hope that it will be useful,
 *      but WITHOUT ANY WARRANTY; without even the implied warranty of
 *      MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *      Lesser General Public License for more details.
 *
 *      You should have received a copy of the GNU Lesser General Public
 *      License along with this library in the file COPYING.LIB;
 *      if not, write to the Free Software Foundation, Inc.,
 *      59 Temple Place - Suite 330, Boston, MA 02111-1307, USA
 */



void
ptw32_tkAssocDestroy(ThreadKeyAssoc * assoc)
/*
 * -------------------------------------------------------------------
 * This routine releases all resources for the given ThreadKeyAssoc
 * once it is no longer being referenced
 * ie) either the key or thread has stopped referencing it.
 *
 * Parameters:
 *              assoc
 *                      an instance of ThreadKeyAssoc.
 * Returns:
 *      N/A
 * -------------------------------------------------------------------
 */
{

	/*
	 * Both key->keyLock and thread->threadLock are locked before
	 * entry to this routine.
	 */
	if (assoc != NULL)
	{
		ThreadKeyAssoc * prev, *next;

		/* Remove assoc from thread's keys chain */
		prev = assoc->prevKey;
		next = assoc->nextKey;
		if (prev != NULL)
		{
			prev->nextKey = next;
		}
		if (next != NULL)
		{
			next->prevKey = prev;
		}

		if (assoc->thread->keys == assoc)
		{
			/* We're at the head of the thread's keys chain */
			assoc->thread->keys = next;
		}
		if (assoc->thread->nextAssoc == assoc)
		{
			/*
			 * Thread is exiting and we're deleting the assoc to be processed next.
			 * Hand thread the assoc after this one.
			 */
			assoc->thread->nextAssoc = next;
		}

		/* Remove assoc from key's threads chain */
		prev = assoc->prevThread;
		next = assoc->nextThread;
		if (prev != NULL)
		{
			prev->nextThread = next;
		}
		if (next != NULL)
		{
			next->prevThread = prev;
		}

		if (assoc->key->threads == assoc)
		{
			/* We're at the head of the key's threads chain */
			assoc->key->threads = next;
		}

		free(assoc);
	}

}				/* ptw32_tkAssocDestroy */
/*
 * rwlock.c
 *
 * Description:
 * This translation unit implements read/write lock primitives.
 *
 * --------------------------------------------------------------------------
 *
 *      Pthreads-win32 - POSIX Threads Library for Win32
 *      Copyright(C) 1998 John E. Bossom
 *      Copyright(C) 1999,2005 Pthreads-win32 contributors
 *
 *      Contact Email: rpj@callisto.canberra.edu.au
 *
 *      The current list of contributors is contained
 *      in the file CONTRIBUTORS included with the source
 *      code distribution. The list can also be seen at the
 *      following World Wide Web location:
 *      http://sources.redhat.com/pthreads-win32/contributors.html
 *
 *      This library is free software; you can redistribute it and/or
 *      modify it under the terms of the GNU Lesser General Public
 *      License as published by the Free Software Foundation; either
 *      version 2 of the License, or (at your option) any later version.
 *
 *      This library is distributed in the hope that it will be useful,
 *      but WITHOUT ANY WARRANTY; without even the implied warranty of
 *      MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *      Lesser General Public License for more details.
 *
 *      You should have received a copy of the GNU Lesser General Public
 *      License along with this library in the file COPYING.LIB;
 *      if not, write to the Free Software Foundation, Inc.,
 *      59 Temple Place - Suite 330, Boston, MA 02111-1307, USA
 */

 /*
  * sched.c
  *
  * Description:
  * POSIX thread functions that deal with thread scheduling.
  *
  * --------------------------------------------------------------------------
  *
  *      Pthreads-win32 - POSIX Threads Library for Win32
  *      Copyright(C) 1998 John E. Bossom
  *      Copyright(C) 1999,2005 Pthreads-win32 contributors
  *
  *      Contact Email: rpj@callisto.canberra.edu.au
  *
  *      The current list of contributors is contained
  *      in the file CONTRIBUTORS included with the source
  *      code distribution. The list can also be seen at the
  *      following World Wide Web location:
  *      http://sources.redhat.com/pthreads-win32/contributors.html
  *
  *      This library is free software; you can redistribute it and/or
  *      modify it under the terms of the GNU Lesser General Public
  *      License as published by the Free Software Foundation; either
  *      version 2 of the License, or (at your option) any later version.
  *
  *      This library is distributed in the hope that it will be useful,
  *      but WITHOUT ANY WARRANTY; without even the implied warranty of
  *      MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
  *      Lesser General Public License for more details.
  *
  *      You should have received a copy of the GNU Lesser General Public
  *      License along with this library in the file COPYING.LIB;
  *      if not, write to the Free Software Foundation, Inc.,
  *      59 Temple Place - Suite 330, Boston, MA 02111-1307, USA
  */


  /*
   * sched_getscheduler.c
   *
   * Description:
   * POSIX thread functions that deal with thread scheduling.
   *
   * --------------------------------------------------------------------------
   *
   *      Pthreads-win32 - POSIX Threads Library for Win32
   *      Copyright(C) 1998 John E. Bossom
   *      Copyright(C) 1999,2005 Pthreads-win32 contributors
   *
   *      Contact Email: rpj@callisto.canberra.edu.au
   *
   *      The current list of contributors is contained
   *      in the file CONTRIBUTORS included with the source
   *      code distribution. The list can also be seen at the
   *      following World Wide Web location:
   *      http://sources.redhat.com/pthreads-win32/contributors.html
   *
   *      This library is free software; you can redistribute it and/or
   *      modify it under the terms of the GNU Lesser General Public
   *      License as published by the Free Software Foundation; either
   *      version 2 of the License, or (at your option) any later version.
   *
   *      This library is distributed in the hope that it will be useful,
   *      but WITHOUT ANY WARRANTY; without even the implied warranty of
   *      MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   *      Lesser General Public License for more details.
   *
   *      You should have received a copy of the GNU Lesser General Public
   *      License along with this library in the file COPYING.LIB;
   *      if not, write to the Free Software Foundation, Inc.,
   *      59 Temple Place - Suite 330, Boston, MA 02111-1307, USA
   */


int
sched_getscheduler(pid_t pid)
{
	/*
	 * Win32 only has one policy which we call SCHED_OTHER.
	 * However, we try to provide other valid side-effects
	 * such as EPERM and ESRCH errors.
	 */
	if (0 != pid)
	{
		int selfPid = (int)GetCurrentProcessId();

		if (pid != selfPid)
		{
			HANDLE h =
				OpenProcess(PROCESS_QUERY_INFORMATION, PTW32_FALSE, (DWORD)pid);

			if (NULL == h)
			{
				errno =
					(GetLastError() ==
					(0xFF & ERROR_ACCESS_DENIED)) ? EPERM : ESRCH;
				return -1;
			}
			else
				CloseHandle(h);
		}
	}

	return SCHED_OTHER;
}
/*
 * sched_get_priority_max.c
 *
 * Description:
 * POSIX thread functions that deal with thread scheduling.
 *
 * --------------------------------------------------------------------------
 *
 *      Pthreads-win32 - POSIX Threads Library for Win32
 *      Copyright(C) 1998 John E. Bossom
 *      Copyright(C) 1999,2005 Pthreads-win32 contributors
 *
 *      Contact Email: rpj@callisto.canberra.edu.au
 *
 *      The current list of contributors is contained
 *      in the file CONTRIBUTORS included with the source
 *      code distribution. The list can also be seen at the
 *      following World Wide Web location:
 *      http://sources.redhat.com/pthreads-win32/contributors.html
 *
 *      This library is free software; you can redistribute it and/or
 *      modify it under the terms of the GNU Lesser General Public
 *      License as published by the Free Software Foundation; either
 *      version 2 of the License, or (at your option) any later version.
 *
 *      This library is distributed in the hope that it will be useful,
 *      but WITHOUT ANY WARRANTY; without even the implied warranty of
 *      MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *      Lesser General Public License for more details.
 *
 *      You should have received a copy of the GNU Lesser General Public
 *      License along with this library in the file COPYING.LIB;
 *      if not, write to the Free Software Foundation, Inc.,
 *      59 Temple Place - Suite 330, Boston, MA 02111-1307, USA
 */


 /*
  * On Windows98, THREAD_PRIORITY_LOWEST is (-2) and
  * THREAD_PRIORITY_HIGHEST is 2, and everything works just fine.
  *
  * On WinCE 3.0, it so happen that THREAD_PRIORITY_LOWEST is 5
  * and THREAD_PRIORITY_HIGHEST is 1 (yes, I know, it is funny:
  * highest priority use smaller numbers) and the following happens:
  *
  * sched_get_priority_min() returns 5
  * sched_get_priority_max() returns 1
  *
  * The following table shows the base priority levels for combinations
  * of priority class and priority value in Win32.
  *
  *   Process Priority Class               Thread Priority Level
  *   -----------------------------------------------------------------
  *   1 IDLE_PRIORITY_CLASS                THREAD_PRIORITY_IDLE
  *   1 BELOW_NORMAL_PRIORITY_CLASS        THREAD_PRIORITY_IDLE
  *   1 NORMAL_PRIORITY_CLASS              THREAD_PRIORITY_IDLE
  *   1 ABOVE_NORMAL_PRIORITY_CLASS        THREAD_PRIORITY_IDLE
  *   1 HIGH_PRIORITY_CLASS                THREAD_PRIORITY_IDLE
  *   2 IDLE_PRIORITY_CLASS                THREAD_PRIORITY_LOWEST
  *   3 IDLE_PRIORITY_CLASS                THREAD_PRIORITY_BELOW_NORMAL
  *   4 IDLE_PRIORITY_CLASS                THREAD_PRIORITY_NORMAL
  *   4 BELOW_NORMAL_PRIORITY_CLASS        THREAD_PRIORITY_LOWEST
  *   5 IDLE_PRIORITY_CLASS                THREAD_PRIORITY_ABOVE_NORMAL
  *   5 BELOW_NORMAL_PRIORITY_CLASS        THREAD_PRIORITY_BELOW_NORMAL
  *   5 Background NORMAL_PRIORITY_CLASS   THREAD_PRIORITY_LOWEST
  *   6 IDLE_PRIORITY_CLASS                THREAD_PRIORITY_HIGHEST
  *   6 BELOW_NORMAL_PRIORITY_CLASS        THREAD_PRIORITY_NORMAL
  *   6 Background NORMAL_PRIORITY_CLASS   THREAD_PRIORITY_BELOW_NORMAL
  *   7 BELOW_NORMAL_PRIORITY_CLASS        THREAD_PRIORITY_ABOVE_NORMAL
  *   7 Background NORMAL_PRIORITY_CLASS   THREAD_PRIORITY_NORMAL
  *   7 Foreground NORMAL_PRIORITY_CLASS   THREAD_PRIORITY_LOWEST
  *   8 BELOW_NORMAL_PRIORITY_CLASS        THREAD_PRIORITY_HIGHEST
  *   8 NORMAL_PRIORITY_CLASS              THREAD_PRIORITY_ABOVE_NORMAL
  *   8 Foreground NORMAL_PRIORITY_CLASS   THREAD_PRIORITY_BELOW_NORMAL
  *   8 ABOVE_NORMAL_PRIORITY_CLASS        THREAD_PRIORITY_LOWEST
  *   9 NORMAL_PRIORITY_CLASS              THREAD_PRIORITY_HIGHEST
  *   9 Foreground NORMAL_PRIORITY_CLASS   THREAD_PRIORITY_NORMAL
  *   9 ABOVE_NORMAL_PRIORITY_CLASS        THREAD_PRIORITY_BELOW_NORMAL
  *  10 Foreground NORMAL_PRIORITY_CLASS   THREAD_PRIORITY_ABOVE_NORMAL
  *  10 ABOVE_NORMAL_PRIORITY_CLASS        THREAD_PRIORITY_NORMAL
  *  11 Foreground NORMAL_PRIORITY_CLASS   THREAD_PRIORITY_HIGHEST
  *  11 ABOVE_NORMAL_PRIORITY_CLASS        THREAD_PRIORITY_ABOVE_NORMAL
  *  11 HIGH_PRIORITY_CLASS                THREAD_PRIORITY_LOWEST
  *  12 ABOVE_NORMAL_PRIORITY_CLASS        THREAD_PRIORITY_HIGHEST
  *  12 HIGH_PRIORITY_CLASS                THREAD_PRIORITY_BELOW_NORMAL
  *  13 HIGH_PRIORITY_CLASS                THREAD_PRIORITY_NORMAL
  *  14 HIGH_PRIORITY_CLASS                THREAD_PRIORITY_ABOVE_NORMAL
  *  15 HIGH_PRIORITY_CLASS                THREAD_PRIORITY_HIGHEST
  *  15 HIGH_PRIORITY_CLASS                THREAD_PRIORITY_TIME_CRITICAL
  *  15 IDLE_PRIORITY_CLASS                THREAD_PRIORITY_TIME_CRITICAL
  *  15 BELOW_NORMAL_PRIORITY_CLASS        THREAD_PRIORITY_TIME_CRITICAL
  *  15 NORMAL_PRIORITY_CLASS              THREAD_PRIORITY_TIME_CRITICAL
  *  15 ABOVE_NORMAL_PRIORITY_CLASS        THREAD_PRIORITY_TIME_CRITICAL
  *  16 REALTIME_PRIORITY_CLASS            THREAD_PRIORITY_IDLE
  *  17 REALTIME_PRIORITY_CLASS            -7
  *  18 REALTIME_PRIORITY_CLASS            -6
  *  19 REALTIME_PRIORITY_CLASS            -5
  *  20 REALTIME_PRIORITY_CLASS            -4
  *  21 REALTIME_PRIORITY_CLASS            -3
  *  22 REALTIME_PRIORITY_CLASS            THREAD_PRIORITY_LOWEST
  *  23 REALTIME_PRIORITY_CLASS            THREAD_PRIORITY_BELOW_NORMAL
  *  24 REALTIME_PRIORITY_CLASS            THREAD_PRIORITY_NORMAL
  *  25 REALTIME_PRIORITY_CLASS            THREAD_PRIORITY_ABOVE_NORMAL
  *  26 REALTIME_PRIORITY_CLASS            THREAD_PRIORITY_HIGHEST
  *  27 REALTIME_PRIORITY_CLASS             3
  *  28 REALTIME_PRIORITY_CLASS             4
  *  29 REALTIME_PRIORITY_CLASS             5
  *  30 REALTIME_PRIORITY_CLASS             6
  *  31 REALTIME_PRIORITY_CLASS            THREAD_PRIORITY_TIME_CRITICAL
  *
  * Windows NT:  Values -7, -6, -5, -4, -3, 3, 4, 5, and 6 are not supported.
  */


int
sched_get_priority_max(int policy)
{
	if (policy < SCHED_MIN || policy > SCHED_MAX)
	{
		errno = EINVAL;
		return -1;
	}

#if (THREAD_PRIORITY_LOWEST > THREAD_PRIORITY_NORMAL)
	/* WinCE? */
	return PTW32_MAX(THREAD_PRIORITY_IDLE, THREAD_PRIORITY_TIME_CRITICAL);
#else
	/* This is independent of scheduling policy in Win32. */
	return PTW32_MAX(THREAD_PRIORITY_IDLE, THREAD_PRIORITY_TIME_CRITICAL);
#endif
}
/*
 * sched_get_priority_min.c
 *
 * Description:
 * POSIX thread functions that deal with thread scheduling.
 *
 * --------------------------------------------------------------------------
 *
 *      Pthreads-win32 - POSIX Threads Library for Win32
 *      Copyright(C) 1998 John E. Bossom
 *      Copyright(C) 1999,2005 Pthreads-win32 contributors
 *
 *      Contact Email: rpj@callisto.canberra.edu.au
 *
 *      The current list of contributors is contained
 *      in the file CONTRIBUTORS included with the source
 *      code distribution. The list can also be seen at the
 *      following World Wide Web location:
 *      http://sources.redhat.com/pthreads-win32/contributors.html
 *
 *      This library is free software; you can redistribute it and/or
 *      modify it under the terms of the GNU Lesser General Public
 *      License as published by the Free Software Foundation; either
 *      version 2 of the License, or (at your option) any later version.
 *
 *      This library is distributed in the hope that it will be useful,
 *      but WITHOUT ANY WARRANTY; without even the implied warranty of
 *      MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *      Lesser General Public License for more details.
 *
 *      You should have received a copy of the GNU Lesser General Public
 *      License along with this library in the file COPYING.LIB;
 *      if not, write to the Free Software Foundation, Inc.,
 *      59 Temple Place - Suite 330, Boston, MA 02111-1307, USA
 */


 /*
  * On Windows98, THREAD_PRIORITY_LOWEST is (-2) and
  * THREAD_PRIORITY_HIGHEST is 2, and everything works just fine.
  *
  * On WinCE 3.0, it so happen that THREAD_PRIORITY_LOWEST is 5
  * and THREAD_PRIORITY_HIGHEST is 1 (yes, I know, it is funny:
  * highest priority use smaller numbers) and the following happens:
  *
  * sched_get_priority_min() returns 5
  * sched_get_priority_max() returns 1
  *
  * The following table shows the base priority levels for combinations
  * of priority class and priority value in Win32.
  *
  *   Process Priority Class               Thread Priority Level
  *   -----------------------------------------------------------------
  *   1 IDLE_PRIORITY_CLASS                THREAD_PRIORITY_IDLE
  *   1 BELOW_NORMAL_PRIORITY_CLASS        THREAD_PRIORITY_IDLE
  *   1 NORMAL_PRIORITY_CLASS              THREAD_PRIORITY_IDLE
  *   1 ABOVE_NORMAL_PRIORITY_CLASS        THREAD_PRIORITY_IDLE
  *   1 HIGH_PRIORITY_CLASS                THREAD_PRIORITY_IDLE
  *   2 IDLE_PRIORITY_CLASS                THREAD_PRIORITY_LOWEST
  *   3 IDLE_PRIORITY_CLASS                THREAD_PRIORITY_BELOW_NORMAL
  *   4 IDLE_PRIORITY_CLASS                THREAD_PRIORITY_NORMAL
  *   4 BELOW_NORMAL_PRIORITY_CLASS        THREAD_PRIORITY_LOWEST
  *   5 IDLE_PRIORITY_CLASS                THREAD_PRIORITY_ABOVE_NORMAL
  *   5 BELOW_NORMAL_PRIORITY_CLASS        THREAD_PRIORITY_BELOW_NORMAL
  *   5 Background NORMAL_PRIORITY_CLASS   THREAD_PRIORITY_LOWEST
  *   6 IDLE_PRIORITY_CLASS                THREAD_PRIORITY_HIGHEST
  *   6 BELOW_NORMAL_PRIORITY_CLASS        THREAD_PRIORITY_NORMAL
  *   6 Background NORMAL_PRIORITY_CLASS   THREAD_PRIORITY_BELOW_NORMAL
  *   7 BELOW_NORMAL_PRIORITY_CLASS        THREAD_PRIORITY_ABOVE_NORMAL
  *   7 Background NORMAL_PRIORITY_CLASS   THREAD_PRIORITY_NORMAL
  *   7 Foreground NORMAL_PRIORITY_CLASS   THREAD_PRIORITY_LOWEST
  *   8 BELOW_NORMAL_PRIORITY_CLASS        THREAD_PRIORITY_HIGHEST
  *   8 NORMAL_PRIORITY_CLASS              THREAD_PRIORITY_ABOVE_NORMAL
  *   8 Foreground NORMAL_PRIORITY_CLASS   THREAD_PRIORITY_BELOW_NORMAL
  *   8 ABOVE_NORMAL_PRIORITY_CLASS        THREAD_PRIORITY_LOWEST
  *   9 NORMAL_PRIORITY_CLASS              THREAD_PRIORITY_HIGHEST
  *   9 Foreground NORMAL_PRIORITY_CLASS   THREAD_PRIORITY_NORMAL
  *   9 ABOVE_NORMAL_PRIORITY_CLASS        THREAD_PRIORITY_BELOW_NORMAL
  *  10 Foreground NORMAL_PRIORITY_CLASS   THREAD_PRIORITY_ABOVE_NORMAL
  *  10 ABOVE_NORMAL_PRIORITY_CLASS        THREAD_PRIORITY_NORMAL
  *  11 Foreground NORMAL_PRIORITY_CLASS   THREAD_PRIORITY_HIGHEST
  *  11 ABOVE_NORMAL_PRIORITY_CLASS        THREAD_PRIORITY_ABOVE_NORMAL
  *  11 HIGH_PRIORITY_CLASS                THREAD_PRIORITY_LOWEST
  *  12 ABOVE_NORMAL_PRIORITY_CLASS        THREAD_PRIORITY_HIGHEST
  *  12 HIGH_PRIORITY_CLASS                THREAD_PRIORITY_BELOW_NORMAL
  *  13 HIGH_PRIORITY_CLASS                THREAD_PRIORITY_NORMAL
  *  14 HIGH_PRIORITY_CLASS                THREAD_PRIORITY_ABOVE_NORMAL
  *  15 HIGH_PRIORITY_CLASS                THREAD_PRIORITY_HIGHEST
  *  15 HIGH_PRIORITY_CLASS                THREAD_PRIORITY_TIME_CRITICAL
  *  15 IDLE_PRIORITY_CLASS                THREAD_PRIORITY_TIME_CRITICAL
  *  15 BELOW_NORMAL_PRIORITY_CLASS        THREAD_PRIORITY_TIME_CRITICAL
  *  15 NORMAL_PRIORITY_CLASS              THREAD_PRIORITY_TIME_CRITICAL
  *  15 ABOVE_NORMAL_PRIORITY_CLASS        THREAD_PRIORITY_TIME_CRITICAL
  *  16 REALTIME_PRIORITY_CLASS            THREAD_PRIORITY_IDLE
  *  17 REALTIME_PRIORITY_CLASS            -7
  *  18 REALTIME_PRIORITY_CLASS            -6
  *  19 REALTIME_PRIORITY_CLASS            -5
  *  20 REALTIME_PRIORITY_CLASS            -4
  *  21 REALTIME_PRIORITY_CLASS            -3
  *  22 REALTIME_PRIORITY_CLASS            THREAD_PRIORITY_LOWEST
  *  23 REALTIME_PRIORITY_CLASS            THREAD_PRIORITY_BELOW_NORMAL
  *  24 REALTIME_PRIORITY_CLASS            THREAD_PRIORITY_NORMAL
  *  25 REALTIME_PRIORITY_CLASS            THREAD_PRIORITY_ABOVE_NORMAL
  *  26 REALTIME_PRIORITY_CLASS            THREAD_PRIORITY_HIGHEST
  *  27 REALTIME_PRIORITY_CLASS             3
  *  28 REALTIME_PRIORITY_CLASS             4
  *  29 REALTIME_PRIORITY_CLASS             5
  *  30 REALTIME_PRIORITY_CLASS             6
  *  31 REALTIME_PRIORITY_CLASS            THREAD_PRIORITY_TIME_CRITICAL
  *
  * Windows NT:  Values -7, -6, -5, -4, -3, 3, 4, 5, and 6 are not supported.
  *
  */


int
sched_get_priority_min(int policy)
{
	if (policy < SCHED_MIN || policy > SCHED_MAX)
	{
		errno = EINVAL;
		return -1;
	}

#if (THREAD_PRIORITY_LOWEST > THREAD_PRIORITY_NORMAL)
	/* WinCE? */
	return PTW32_MIN(THREAD_PRIORITY_IDLE, THREAD_PRIORITY_TIME_CRITICAL);
#else
	/* This is independent of scheduling policy in Win32. */
	return PTW32_MIN(THREAD_PRIORITY_IDLE, THREAD_PRIORITY_TIME_CRITICAL);
#endif
}
/*
 * sched_setscheduler.c
 *
 * Description:
 * POSIX thread functions that deal with thread scheduling.
 *
 * --------------------------------------------------------------------------
 *
 *      Pthreads-win32 - POSIX Threads Library for Win32
 *      Copyright(C) 1998 John E. Bossom
 *      Copyright(C) 1999,2005 Pthreads-win32 contributors
 *
 *      Contact Email: rpj@callisto.canberra.edu.au
 *
 *      The current list of contributors is contained
 *      in the file CONTRIBUTORS included with the source
 *      code distribution. The list can also be seen at the
 *      following World Wide Web location:
 *      http://sources.redhat.com/pthreads-win32/contributors.html
 *
 *      This library is free software; you can redistribute it and/or
 *      modify it under the terms of the GNU Lesser General Public
 *      License as published by the Free Software Foundation; either
 *      version 2 of the License, or (at your option) any later version.
 *
 *      This library is distributed in the hope that it will be useful,
 *      but WITHOUT ANY WARRANTY; without even the implied warranty of
 *      MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *      Lesser General Public License for more details.
 *
 *      You should have received a copy of the GNU Lesser General Public
 *      License along with this library in the file COPYING.LIB;
 *      if not, write to the Free Software Foundation, Inc.,
 *      59 Temple Place - Suite 330, Boston, MA 02111-1307, USA
 */


int
sched_setscheduler(pid_t pid, int policy)
{
	/*
	 * Win32 only has one policy which we call SCHED_OTHER.
	 * However, we try to provide other valid side-effects
	 * such as EPERM and ESRCH errors. Choosing to check
	 * for a valid policy last allows us to get the most value out
	 * of this function.
	 */
	if (0 != pid)
	{
		int selfPid = (int)GetCurrentProcessId();

		if (pid != selfPid)
		{
			HANDLE h =
				OpenProcess(PROCESS_SET_INFORMATION, PTW32_FALSE, (DWORD)pid);

			if (NULL == h)
			{
				errno =
					(GetLastError() ==
					(0xFF & ERROR_ACCESS_DENIED)) ? EPERM : ESRCH;
				return -1;
			}
			else
				CloseHandle(h);
		}
	}

	if (SCHED_OTHER != policy)
	{
		errno = ENOSYS;
		return -1;
	}

	/*
	 * Don't set anything because there is nothing to set.
	 * Just return the current (the only possible) value.
	 */
	return SCHED_OTHER;
}
/*
 * sched_yield.c
 *
 * Description:
 * POSIX thread functions that deal with thread scheduling.
 *
 * --------------------------------------------------------------------------
 *
 *      Pthreads-win32 - POSIX Threads Library for Win32
 *      Copyright(C) 1998 John E. Bossom
 *      Copyright(C) 1999,2005 Pthreads-win32 contributors
 *
 *      Contact Email: rpj@callisto.canberra.edu.au
 *
 *      The current list of contributors is contained
 *      in the file CONTRIBUTORS included with the source
 *      code distribution. The list can also be seen at the
 *      following World Wide Web location:
 *      http://sources.redhat.com/pthreads-win32/contributors.html
 *
 *      This library is free software; you can redistribute it and/or
 *      modify it under the terms of the GNU Lesser General Public
 *      License as published by the Free Software Foundation; either
 *      version 2 of the License, or (at your option) any later version.
 *
 *      This library is distributed in the hope that it will be useful,
 *      but WITHOUT ANY WARRANTY; without even the implied warranty of
 *      MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *      Lesser General Public License for more details.
 *
 *      You should have received a copy of the GNU Lesser General Public
 *      License along with this library in the file COPYING.LIB;
 *      if not, write to the Free Software Foundation, Inc.,
 *      59 Temple Place - Suite 330, Boston, MA 02111-1307, USA
 */


int
sched_yield(void)
/*
 * ------------------------------------------------------
 * DOCPUBLIC
 *      This function indicates that the calling thread is
 *      willing to give up some time slices to other threads.
 *
 * PARAMETERS
 *      N/A
 *
 *
 * DESCRIPTION
 *      This function indicates that the calling thread is
 *      willing to give up some time slices to other threads.
 *      NOTE: Since this is part of POSIX 1003.1b
 *                (realtime extensions), it is defined as returning
 *                -1 if an error occurs and sets errno to the actual
 *                error.
 *
 * RESULTS
 *              0               successfully created semaphore,
 *              ENOSYS          sched_yield not supported,
 *
 * ------------------------------------------------------
 */
{
	Sleep(0);

	return 0;
}
/*
 * -------------------------------------------------------------
 *
 * Module: semaphore.c
 *
 * Purpose:
 *	Concatenated version of separate modules to allow
 *	inlining optimisation, which it is assumed can only
 *	be effective within a single module.
 *
 *	Semaphores aren't actually part of the PThreads standard.
 *	They are defined by the POSIX Standard:
 *
 *		POSIX 1003.1b-1993	(POSIX.1b)
 *
 * -------------------------------------------------------------
 *
 * --------------------------------------------------------------------------
 *
 *      Pthreads-win32 - POSIX Threads Library for Win32
 *      Copyright(C) 1998 John E. Bossom
 *      Copyright(C) 1999,2005 Pthreads-win32 contributors
 *
 *      Contact Email: rpj@callisto.canberra.edu.au
 *
 *      The current list of contributors is contained
 *      in the file CONTRIBUTORS included with the source
 *      code distribution. The list can also be seen at the
 *      following World Wide Web location:
 *      http://sources.redhat.com/pthreads-win32/contributors.html
 *
 *      This library is free software; you can redistribute it and/or
 *      modify it under the terms of the GNU Lesser General Public
 *      License as published by the Free Software Foundation; either
 *      version 2 of the License, or (at your option) any later version.
 *
 *      This library is distributed in the hope that it will be useful,
 *      but WITHOUT ANY WARRANTY; without even the implied warranty of
 *      MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *      Lesser General Public License for more details.
 *
 *      You should have received a copy of the GNU Lesser General Public
 *      License along with this library in the file COPYING.LIB;
 *      if not, write to the Free Software Foundation, Inc.,
 *      59 Temple Place - Suite 330, Boston, MA 02111-1307, USA
 */

#if !defined(NEED_FTIME)
#  include <sys/timeb.h>
#endif




 /*
  * -------------------------------------------------------------
  *
  * Module: sem_close.c
  *
  * Purpose:
  *	Semaphores aren't actually part of the PThreads standard.
  *	They are defined by the POSIX Standard:
  *
  *		POSIX 1003.1b-1993	(POSIX.1b)
  *
  * -------------------------------------------------------------
  *
  * --------------------------------------------------------------------------
  *
  *      Pthreads-win32 - POSIX Threads Library for Win32
  *      Copyright(C) 1998 John E. Bossom
  *      Copyright(C) 1999,2005 Pthreads-win32 contributors
  *
  *      Contact Email: rpj@callisto.canberra.edu.au
  *
  *      The current list of contributors is contained
  *      in the file CONTRIBUTORS included with the source
  *      code distribution. The list can also be seen at the
  *      following World Wide Web location:
  *      http://sources.redhat.com/pthreads-win32/contributors.html
  *
  *      This library is free software; you can redistribute it and/or
  *      modify it under the terms of the GNU Lesser General Public
  *      License as published by the Free Software Foundation; either
  *      version 2 of the License, or (at your option) any later version.
  *
  *      This library is distributed in the hope that it will be useful,
  *      but WITHOUT ANY WARRANTY; without even the implied warranty of
  *      MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
  *      Lesser General Public License for more details.
  *
  *      You should have received a copy of the GNU Lesser General Public
  *      License along with this library in the file COPYING.LIB;
  *      if not, write to the Free Software Foundation, Inc.,
  *      59 Temple Place - Suite 330, Boston, MA 02111-1307, USA
  */


  /* ignore warning "unreferenced formal parameter" */
#if defined(_MSC_VER)
#pragma warning( disable : 4100 )
#endif

int
sem_close(sem_t * sem)
{
	errno = ENOSYS;
	return -1;
}				/* sem_close */
/*
 * -------------------------------------------------------------
 *
 * Module: sem_destroy.c
 *
 * Purpose:
 *	Semaphores aren't actually part of the PThreads standard.
 *	They are defined by the POSIX Standard:
 *
 *		POSIX 1003.1b-1993	(POSIX.1b)
 *
 * -------------------------------------------------------------
 *
 * --------------------------------------------------------------------------
 *
 *      Pthreads-win32 - POSIX Threads Library for Win32
 *      Copyright(C) 1998 John E. Bossom
 *      Copyright(C) 1999,2005 Pthreads-win32 contributors
 *
 *      Contact Email: rpj@callisto.canberra.edu.au
 *
 *      The current list of contributors is contained
 *      in the file CONTRIBUTORS included with the source
 *      code distribution. The list can also be seen at the
 *      following World Wide Web location:
 *      http://sources.redhat.com/pthreads-win32/contributors.html
 *
 *      This library is free software; you can redistribute it and/or
 *      modify it under the terms of the GNU Lesser General Public
 *      License as published by the Free Software Foundation; either
 *      version 2 of the License, or (at your option) any later version.
 *
 *      This library is distributed in the hope that it will be useful,
 *      but WITHOUT ANY WARRANTY; without even the implied warranty of
 *      MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *      Lesser General Public License for more details.
 *
 *      You should have received a copy of the GNU Lesser General Public
 *      License along with this library in the file COPYING.LIB;
 *      if not, write to the Free Software Foundation, Inc.,
 *      59 Temple Place - Suite 330, Boston, MA 02111-1307, USA
 */



int
sem_destroy(sem_t * sem)
/*
 * ------------------------------------------------------
 * DOCPUBLIC
 *      This function destroys an unnamed semaphore.
 *
 * PARAMETERS
 *      sem
 *              pointer to an instance of sem_t
 *
 * DESCRIPTION
 *      This function destroys an unnamed semaphore.
 *
 * RESULTS
 *              0               successfully destroyed semaphore,
 *              -1              failed, error in errno
 * ERRNO
 *              EINVAL          'sem' is not a valid semaphore,
 *              ENOSYS          semaphores are not supported,
 *              EBUSY           threads (or processes) are currently
 *                                      blocked on 'sem'
 *
 * ------------------------------------------------------
 */
{
	int result = 0;
	sem_t s = NULL;

	if (sem == NULL || *sem == NULL)
	{
		result = EINVAL;
	}
	else
	{
		s = *sem;

		if ((result = pthread_mutex_lock(&s->lock)) == 0)
		{
			if (s->value < 0)
			{
				(void)pthread_mutex_unlock(&s->lock);
				result = EBUSY;
			}
			else
			{
				/* There are no threads currently blocked on this semaphore. */

				if (!CloseHandle(s->sem))
				{
					(void)pthread_mutex_unlock(&s->lock);
					result = EINVAL;
				}
				else
				{
					/*
					 * Invalidate the semaphore handle when we have the lock.
					 * Other sema operations should test this after acquiring the lock
					 * to check that the sema is still valid, i.e. before performing any
					 * operations. This may only be necessary before the sema op routine
					 * returns so that the routine can return EINVAL - e.g. if setting
					 * s->value to SEM_VALUE_MAX below does force a fall-through.
					 */
					*sem = NULL;

					/* Prevent anyone else actually waiting on or posting this sema.
					 */
					s->value = SEM_VALUE_MAX;

					(void)pthread_mutex_unlock(&s->lock);

					do
					{
						/* Give other threads a chance to run and exit any sema op
						 * routines. Due to the SEM_VALUE_MAX value, if sem_post or
						 * sem_wait were blocked by us they should fall through.
						 */
						Sleep(0);
					} while (pthread_mutex_destroy(&s->lock) == EBUSY);
				}
			}
		}
	}

	if (result != 0)
	{
		errno = result;
		return -1;
	}

	free(s);

	return 0;

}				/* sem_destroy */
/*
 * -------------------------------------------------------------
 *
 * Module: sem_getvalue.c
 *
 * Purpose:
 *	Semaphores aren't actually part of PThreads.
 *	They are defined by the POSIX Standard:
 *
 *		POSIX 1003.1-2001
 *
 * -------------------------------------------------------------
 *
 * --------------------------------------------------------------------------
 *
 *      Pthreads-win32 - POSIX Threads Library for Win32
 *      Copyright(C) 1998 John E. Bossom
 *      Copyright(C) 1999,2005 Pthreads-win32 contributors
 *
 *      Contact Email: rpj@callisto.canberra.edu.au
 *
 *      The current list of contributors is contained
 *      in the file CONTRIBUTORS included with the source
 *      code distribution. The list can also be seen at the
 *      following World Wide Web location:
 *      http://sources.redhat.com/pthreads-win32/contributors.html
 *
 *      This library is free software; you can redistribute it and/or
 *      modify it under the terms of the GNU Lesser General Public
 *      License as published by the Free Software Foundation; either
 *      version 2 of the License, or (at your option) any later version.
 *
 *      This library is distributed in the hope that it will be useful,
 *      but WITHOUT ANY WARRANTY; without even the implied warranty of
 *      MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *      Lesser General Public License for more details.
 *
 *      You should have received a copy of the GNU Lesser General Public
 *      License along with this library in the file COPYING.LIB;
 *      if not, write to the Free Software Foundation, Inc.,
 *      59 Temple Place - Suite 330, Boston, MA 02111-1307, USA
 */



int
sem_getvalue(sem_t * sem, int *sval)
/*
 * ------------------------------------------------------
 * DOCPUBLIC
 *      This function stores the current count value of the
 *      semaphore.
 * RESULTS
 *
 * Return value
 *
 *       0                  sval has been set.
 *      -1                  failed, error in errno
 *
 *  in global errno
 *
 *      EINVAL              'sem' is not a valid semaphore,
 *      ENOSYS              this function is not supported,
 *
 *
 * PARAMETERS
 *
 *      sem                 pointer to an instance of sem_t
 *
 *      sval                pointer to int.
 *
 * DESCRIPTION
 *      This function stores the current count value of the semaphore
 *      pointed to by sem in the int pointed to by sval.
 */
{
	if (sem == NULL || *sem == NULL || sval == NULL)
	{
		errno = EINVAL;
		return -1;
	}
	else
	{
		long value;
		register sem_t s = *sem;
		int result = 0;

		if ((result = pthread_mutex_lock(&s->lock)) == 0)
		{
			/* See sem_destroy.c
			 */
			if (*sem == NULL)
			{
				(void)pthread_mutex_unlock(&s->lock);
				errno = EINVAL;
				return -1;
			}

			value = s->value;
			(void)pthread_mutex_unlock(&s->lock);
			*sval = value;
		}

		return result;
	}

}				/* sem_getvalue */
/*
 * -------------------------------------------------------------
 *
 * Module: sem_init.c
 *
 * Purpose:
 *	Semaphores aren't actually part of PThreads.
 *	They are defined by the POSIX Standard:
 *
 *		POSIX 1003.1-2001
 *
 * -------------------------------------------------------------
 *
 *      Pthreads-win32 - POSIX Threads Library for Win32
 *      Copyright(C) 1998 John E. Bossom
 *      Copyright(C) 1999,2005 Pthreads-win32 contributors
 *
 *      Contact Email: rpj@callisto.canberra.edu.au
 *
 *      The current list of contributors is contained
 *      in the file CONTRIBUTORS included with the source
 *      code distribution. The list can also be seen at the
 *      following World Wide Web location:
 *      http://sources.redhat.com/pthreads-win32/contributors.html
 *
 *      This library is free software; you can redistribute it and/or
 *      modify it under the terms of the GNU Lesser General Public
 *      License as published by the Free Software Foundation; either
 *      version 2 of the License, or (at your option) any later version.
 *
 *      This library is distributed in the hope that it will be useful,
 *      but WITHOUT ANY WARRANTY; without even the implied warranty of
 *      MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *      Lesser General Public License for more details.
 *
 *      You should have received a copy of the GNU Lesser General Public
 *      License along with this library in the file COPYING.LIB;
 *      if not, write to the Free Software Foundation, Inc.,
 *      59 Temple Place - Suite 330, Boston, MA 02111-1307, USA
 */


int
sem_init(sem_t * sem, int pshared, unsigned int value)
/*
 * ------------------------------------------------------
 * DOCPUBLIC
 *      This function initializes a semaphore. The
 *      initial value of the semaphore is 'value'
 *
 * PARAMETERS
 *      sem
 *              pointer to an instance of sem_t
 *
 *      pshared
 *              if zero, this semaphore may only be shared between
 *              threads in the same process.
 *              if nonzero, the semaphore can be shared between
 *              processes
 *
 *      value
 *              initial value of the semaphore counter
 *
 * DESCRIPTION
 *      This function initializes a semaphore. The
 *      initial value of the semaphore is set to 'value'.
 *
 * RESULTS
 *              0               successfully created semaphore,
 *              -1              failed, error in errno
 * ERRNO
 *              EINVAL          'sem' is not a valid semaphore, or
 *                              'value' >= SEM_VALUE_MAX
 *              ENOMEM          out of memory,
 *              ENOSPC          a required resource has been exhausted,
 *              ENOSYS          semaphores are not supported,
 *              EPERM           the process lacks appropriate privilege
 *
 * ------------------------------------------------------
 */
{
	int result = 0;
	sem_t s = NULL;

	if (pshared != 0)
	{
		/*
		 * Creating a semaphore that can be shared between
		 * processes
		 */
		result = EPERM;
	}
	else if (value > (unsigned int)SEM_VALUE_MAX)
	{
		result = EINVAL;
	}
	else
	{
		s = (sem_t)calloc(1, sizeof(*s));

		if (NULL == s)
		{
			result = ENOMEM;
		}
		else
		{

			s->value = value;
			if (pthread_mutex_init(&s->lock, NULL) == 0)
			{

#if defined(NEED_SEM)

				s->sem = CreateEvent(NULL,
					PTW32_FALSE,	/* auto (not manual) reset */
					PTW32_FALSE,	/* initial state is unset */
					NULL);

				if (0 == s->sem)
				{
					free(s);
					(void)pthread_mutex_destroy(&s->lock);
					result = ENOSPC;
				}
				else
				{
					s->leftToUnblock = 0;
				}

#else /* NEED_SEM */

				if ((s->sem = CreateSemaphore(NULL,	/* Always NULL */
					(long)0,	/* Force threads to wait */
					(long)SEM_VALUE_MAX,	/* Maximum value */
					NULL)) == 0)	/* Name */
				{
					(void)pthread_mutex_destroy(&s->lock);
					result = ENOSPC;
				}

#endif /* NEED_SEM */

			}
			else
			{
				result = ENOSPC;
			}

			if (result != 0)
			{
				free(s);
			}
		}
	}

	if (result != 0)
	{
		errno = result;
		return -1;
	}

	*sem = s;

	return 0;

}				/* sem_init */
/*
 * -------------------------------------------------------------
 *
 * Module: sem_open.c
 *
 * Purpose:
 *	Semaphores aren't actually part of the PThreads standard.
 *	They are defined by the POSIX Standard:
 *
 *		POSIX 1003.1b-1993	(POSIX.1b)
 *
 * -------------------------------------------------------------
 *
 * --------------------------------------------------------------------------
 *
 *      Pthreads-win32 - POSIX Threads Library for Win32
 *      Copyright(C) 1998 John E. Bossom
 *      Copyright(C) 1999,2005 Pthreads-win32 contributors
 *
 *      Contact Email: rpj@callisto.canberra.edu.au
 *
 *      The current list of contributors is contained
 *      in the file CONTRIBUTORS included with the source
 *      code distribution. The list can also be seen at the
 *      following World Wide Web location:
 *      http://sources.redhat.com/pthreads-win32/contributors.html
 *
 *      This library is free software; you can redistribute it and/or
 *      modify it under the terms of the GNU Lesser General Public
 *      License as published by the Free Software Foundation; either
 *      version 2 of the License, or (at your option) any later version.
 *
 *      This library is distributed in the hope that it will be useful,
 *      but WITHOUT ANY WARRANTY; without even the implied warranty of
 *      MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *      Lesser General Public License for more details.
 *
 *      You should have received a copy of the GNU Lesser General Public
 *      License along with this library in the file COPYING.LIB;
 *      if not, write to the Free Software Foundation, Inc.,
 *      59 Temple Place - Suite 330, Boston, MA 02111-1307, USA
 */


 /* ignore warning "unreferenced formal parameter" */
#if defined(_MSC_VER)
#pragma warning( disable : 4100 )
#endif

int
sem_open(const char *name, int oflag, mode_t mode, unsigned int value)
{
	errno = ENOSYS;
	return -1;
}				/* sem_open */
/*
 * -------------------------------------------------------------
 *
 * Module: sem_post.c
 *
 * Purpose:
 *	Semaphores aren't actually part of the PThreads standard.
 *	They are defined by the POSIX Standard:
 *
 *		POSIX 1003.1b-1993	(POSIX.1b)
 *
 * -------------------------------------------------------------
 *
 * --------------------------------------------------------------------------
 *
 *      Pthreads-win32 - POSIX Threads Library for Win32
 *      Copyright(C) 1998 John E. Bossom
 *      Copyright(C) 1999,2005 Pthreads-win32 contributors
 *
 *      Contact Email: rpj@callisto.canberra.edu.au
 *
 *      The current list of contributors is contained
 *      in the file CONTRIBUTORS included with the source
 *      code distribution. The list can also be seen at the
 *      following World Wide Web location:
 *      http://sources.redhat.com/pthreads-win32/contributors.html
 *
 *      This library is free software; you can redistribute it and/or
 *      modify it under the terms of the GNU Lesser General Public
 *      License as published by the Free Software Foundation; either
 *      version 2 of the License, or (at your option) any later version.
 *
 *      This library is distributed in the hope that it will be useful,
 *      but WITHOUT ANY WARRANTY; without even the implied warranty of
 *      MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *      Lesser General Public License for more details.
 *
 *      You should have received a copy of the GNU Lesser General Public
 *      License along with this library in the file COPYING.LIB;
 *      if not, write to the Free Software Foundation, Inc.,
 *      59 Temple Place - Suite 330, Boston, MA 02111-1307, USA
 */



int
sem_post(sem_t * sem)
/*
 * ------------------------------------------------------
 * DOCPUBLIC
 *      This function posts a wakeup to a semaphore.
 *
 * PARAMETERS
 *      sem
 *              pointer to an instance of sem_t
 *
 * DESCRIPTION
 *      This function posts a wakeup to a semaphore. If there
 *      are waiting threads (or processes), one is awakened;
 *      otherwise, the semaphore value is incremented by one.
 *
 * RESULTS
 *              0               successfully posted semaphore,
 *              -1              failed, error in errno
 * ERRNO
 *              EINVAL          'sem' is not a valid semaphore,
 *              ENOSYS          semaphores are not supported,
 *              ERANGE          semaphore count is too big
 *
 * ------------------------------------------------------
 */
{
	int result = 0;
	sem_t s = *sem;

	if (s == NULL)
	{
		result = EINVAL;
	}
	else if ((result = pthread_mutex_lock(&s->lock)) == 0)
	{
		/* See sem_destroy.c
		 */
		if (*sem == NULL)
		{
			(void)pthread_mutex_unlock(&s->lock);
			result = EINVAL;
			return -1;
		}

		if (s->value < SEM_VALUE_MAX)
		{
#if defined(NEED_SEM)
			if (++s->value <= 0
				&& !SetEvent(s->sem))
			{
				s->value--;
				result = EINVAL;
			}
#else
			if (++s->value <= 0
				&& !ReleaseSemaphore(s->sem, 1, NULL))
			{
				s->value--;
				result = EINVAL;
			}
#endif /* NEED_SEM */
		}
		else
		{
			result = ERANGE;
		}

		(void)pthread_mutex_unlock(&s->lock);
	}

	if (result != 0)
	{
		errno = result;
		return -1;
	}

	return 0;

}				/* sem_post */
/*
 * -------------------------------------------------------------
 *
 * Module: sem_post_multiple.c
 *
 * Purpose:
 *	Semaphores aren't actually part of the PThreads standard.
 *	They are defined by the POSIX Standard:
 *
 *		POSIX 1003.1b-1993	(POSIX.1b)
 *
 * -------------------------------------------------------------
 *
 * --------------------------------------------------------------------------
 *
 *      Pthreads-win32 - POSIX Threads Library for Win32
 *      Copyright(C) 1998 John E. Bossom
 *      Copyright(C) 1999,2005 Pthreads-win32 contributors
 *
 *      Contact Email: rpj@callisto.canberra.edu.au
 *
 *      The current list of contributors is contained
 *      in the file CONTRIBUTORS included with the source
 *      code distribution. The list can also be seen at the
 *      following World Wide Web location:
 *      http://sources.redhat.com/pthreads-win32/contributors.html
 *
 *      This library is free software; you can redistribute it and/or
 *      modify it under the terms of the GNU Lesser General Public
 *      License as published by the Free Software Foundation; either
 *      version 2 of the License, or (at your option) any later version.
 *
 *      This library is distributed in the hope that it will be useful,
 *      but WITHOUT ANY WARRANTY; without even the implied warranty of
 *      MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *      Lesser General Public License for more details.
 *
 *      You should have received a copy of the GNU Lesser General Public
 *      License along with this library in the file COPYING.LIB;
 *      if not, write to the Free Software Foundation, Inc.,
 *      59 Temple Place - Suite 330, Boston, MA 02111-1307, USA
 */



int
sem_post_multiple(sem_t * sem, int count)
/*
 * ------------------------------------------------------
 * DOCPUBLIC
 *      This function posts multiple wakeups to a semaphore.
 *
 * PARAMETERS
 *      sem
 *              pointer to an instance of sem_t
 *
 *      count
 *              counter, must be greater than zero.
 *
 * DESCRIPTION
 *      This function posts multiple wakeups to a semaphore. If there
 *      are waiting threads (or processes), n <= count are awakened;
 *      the semaphore value is incremented by count - n.
 *
 * RESULTS
 *              0               successfully posted semaphore,
 *              -1              failed, error in errno
 * ERRNO
 *              EINVAL          'sem' is not a valid semaphore
 *                              or count is less than or equal to zero.
 *              ERANGE          semaphore count is too big
 *
 * ------------------------------------------------------
 */
{
	int result = 0;
	long waiters;
	sem_t s = *sem;

	if (s == NULL || count <= 0)
	{
		result = EINVAL;
	}
	else if ((result = pthread_mutex_lock(&s->lock)) == 0)
	{
		/* See sem_destroy.c
		 */
		if (*sem == NULL)
		{
			(void)pthread_mutex_unlock(&s->lock);
			result = EINVAL;
			return -1;
		}

		if (s->value <= (SEM_VALUE_MAX - count))
		{
			waiters = -s->value;
			s->value += count;
			if (waiters > 0)
			{
#if defined(NEED_SEM)
				if (SetEvent(s->sem))
				{
					waiters--;
					s->leftToUnblock += count - 1;
					if (s->leftToUnblock > waiters)
					{
						s->leftToUnblock = waiters;
					}
				}
#else
				if (ReleaseSemaphore(s->sem, (waiters <= count) ? waiters : count, 0))
				{
					/* No action */
				}
#endif
				else
				{
					s->value -= count;
					result = EINVAL;
				}
			}
		}
		else
		{
			result = ERANGE;
		}
		(void)pthread_mutex_unlock(&s->lock);
	}

	if (result != 0)
	{
		errno = result;
		return -1;
	}

	return 0;

}				/* sem_post_multiple */
/*
 * -------------------------------------------------------------
 *
 * Module: sem_timedwait.c
 *
 * Purpose:
 *	Semaphores aren't actually part of the PThreads standard.
 *	They are defined by the POSIX Standard:
 *
 *		POSIX 1003.1b-1993	(POSIX.1b)
 *
 * -------------------------------------------------------------
 *
 * --------------------------------------------------------------------------
 *
 *      Pthreads-win32 - POSIX Threads Library for Win32
 *      Copyright(C) 1998 John E. Bossom
 *      Copyright(C) 1999,2005 Pthreads-win32 contributors
 *
 *      Contact Email: rpj@callisto.canberra.edu.au
 *
 *      The current list of contributors is contained
 *      in the file CONTRIBUTORS included with the source
 *      code distribution. The list can also be seen at the
 *      following World Wide Web location:
 *      http://sources.redhat.com/pthreads-win32/contributors.html
 *
 *      This library is free software; you can redistribute it and/or
 *      modify it under the terms of the GNU Lesser General Public
 *      License as published by the Free Software Foundation; either
 *      version 2 of the License, or (at your option) any later version.
 *
 *      This library is distributed in the hope that it will be useful,
 *      but WITHOUT ANY WARRANTY; without even the implied warranty of
 *      MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *      Lesser General Public License for more details.
 *
 *      You should have received a copy of the GNU Lesser General Public
 *      License along with this library in the file COPYING.LIB;
 *      if not, write to the Free Software Foundation, Inc.,
 *      59 Temple Place - Suite 330, Boston, MA 02111-1307, USA
 */



typedef struct {
	sem_t sem;
	int * resultPtr;
} sem_timedwait_cleanup_args_t;


static void PTW32_CDECL
ptw32_sem_timedwait_cleanup(void * args)
{
	sem_timedwait_cleanup_args_t * a = (sem_timedwait_cleanup_args_t *)args;
	sem_t s = a->sem;

	if (pthread_mutex_lock(&s->lock) == 0)
	{
		/*
		 * We either timed out or were cancelled.
		 * If someone has posted between then and now we try to take the semaphore.
		 * Otherwise the semaphore count may be wrong after we
		 * return. In the case of a cancellation, it is as if we
		 * were cancelled just before we return (after taking the semaphore)
		 * which is ok.
		 */
		if (WaitForSingleObject(s->sem, 0) == WAIT_OBJECT_0)
		{
			/* We got the semaphore on the second attempt */
			*(a->resultPtr) = 0;
		}
		else
		{
			/* Indicate we're no longer waiting */
			s->value++;
#if defined(NEED_SEM)
			if (s->value > 0)
			{
				s->leftToUnblock = 0;
			}
#else
			/*
			 * Don't release the W32 sema, it doesn't need adjustment
			 * because it doesn't record the number of waiters.
			 */
#endif
		}
		(void)pthread_mutex_unlock(&s->lock);
	}
}


int
sem_timedwait(sem_t * sem, const struct timespec *abstime)
/*
 * ------------------------------------------------------
 * DOCPUBLIC
 *      This function waits on a semaphore possibly until
 *      'abstime' time.
 *
 * PARAMETERS
 *      sem
 *              pointer to an instance of sem_t
 *
 *      abstime
 *              pointer to an instance of struct timespec
 *
 * DESCRIPTION
 *      This function waits on a semaphore. If the
 *      semaphore value is greater than zero, it decreases
 *      its value by one. If the semaphore value is zero, then
 *      the calling thread (or process) is blocked until it can
 *      successfully decrease the value or until interrupted by
 *      a signal.
 *
 *      If 'abstime' is a NULL pointer then this function will
 *      block until it can successfully decrease the value or
 *      until interrupted by a signal.
 *
 * RESULTS
 *              0               successfully decreased semaphore,
 *              -1              failed, error in errno
 * ERRNO
 *              EINVAL          'sem' is not a valid semaphore,
 *              ENOSYS          semaphores are not supported,
 *              EINTR           the function was interrupted by a signal,
 *              EDEADLK         a deadlock condition was detected.
 *              ETIMEDOUT       abstime elapsed before success.
 *
 * ------------------------------------------------------
 */
{
	int result = 0;
	sem_t s = *sem;

	pthread_testcancel();

	if (sem == NULL)
	{
		result = EINVAL;
	}
	else
	{
		DWORD milliseconds;

		if (abstime == NULL)
		{
			milliseconds = INFINITE;
		}
		else
		{
			/*
			 * Calculate timeout as milliseconds from current system time.
			 */
			milliseconds = ptw32_relmillisecs(abstime);
		}

		if ((result = pthread_mutex_lock(&s->lock)) == 0)
		{
			int v;

			/* See sem_destroy.c
			 */
			if (*sem == NULL)
			{
				(void)pthread_mutex_unlock(&s->lock);
				errno = EINVAL;
				return -1;
			}

			v = --s->value;
			(void)pthread_mutex_unlock(&s->lock);

			if (v < 0)
			{
#if defined(NEED_SEM)
				int timedout;
#endif
				sem_timedwait_cleanup_args_t cleanup_args;

				cleanup_args.sem = s;
				cleanup_args.resultPtr = &result;

#if defined(_MSC_VER) && _MSC_VER < 1400
#pragma inline_depth(0)
#endif
				/* Must wait */
				pthread_cleanup_push(ptw32_sem_timedwait_cleanup, (void *)&cleanup_args);
#if defined(NEED_SEM)
				timedout =
#endif
					result = pthreadCancelableTimedWait(s->sem, milliseconds);
				pthread_cleanup_pop(result);
#if defined(_MSC_VER) && _MSC_VER < 1400
#pragma inline_depth()
#endif

#if defined(NEED_SEM)

				if (!timedout && pthread_mutex_lock(&s->lock) == 0)
				{
					if (*sem == NULL)
					{
						(void)pthread_mutex_unlock(&s->lock);
						errno = EINVAL;
						return -1;
					}

					if (s->leftToUnblock > 0)
					{
						--s->leftToUnblock;
						SetEvent(s->sem);
					}
					(void)pthread_mutex_unlock(&s->lock);
				}

#endif /* NEED_SEM */

			}
		}

	}

	if (result != 0)
	{

		errno = result;
		return -1;

	}

	return 0;

}				/* sem_timedwait */
/*
 * -------------------------------------------------------------
 *
 * Module: sem_trywait.c
 *
 * Purpose:
 *	Semaphores aren't actually part of the PThreads standard.
 *	They are defined by the POSIX Standard:
 *
 *		POSIX 1003.1b-1993	(POSIX.1b)
 *
 * -------------------------------------------------------------
 *
 * --------------------------------------------------------------------------
 *
 *      Pthreads-win32 - POSIX Threads Library for Win32
 *      Copyright(C) 1998 John E. Bossom
 *      Copyright(C) 1999,2005 Pthreads-win32 contributors
 *
 *      Contact Email: rpj@callisto.canberra.edu.au
 *
 *      The current list of contributors is contained
 *      in the file CONTRIBUTORS included with the source
 *      code distribution. The list can also be seen at the
 *      following World Wide Web location:
 *      http://sources.redhat.com/pthreads-win32/contributors.html
 *
 *      This library is free software; you can redistribute it and/or
 *      modify it under the terms of the GNU Lesser General Public
 *      License as published by the Free Software Foundation; either
 *      version 2 of the License, or (at your option) any later version.
 *
 *      This library is distributed in the hope that it will be useful,
 *      but WITHOUT ANY WARRANTY; without even the implied warranty of
 *      MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *      Lesser General Public License for more details.
 *
 *      You should have received a copy of the GNU Lesser General Public
 *      License along with this library in the file COPYING.LIB;
 *      if not, write to the Free Software Foundation, Inc.,
 *      59 Temple Place - Suite 330, Boston, MA 02111-1307, USA
 */



int
sem_trywait(sem_t * sem)
/*
 * ------------------------------------------------------
 * DOCPUBLIC
 *      This function tries to wait on a semaphore.
 *
 * PARAMETERS
 *      sem
 *              pointer to an instance of sem_t
 *
 * DESCRIPTION
 *      This function tries to wait on a semaphore. If the
 *      semaphore value is greater than zero, it decreases
 *      its value by one. If the semaphore value is zero, then
 *      this function returns immediately with the error EAGAIN
 *
 * RESULTS
 *              0               successfully decreased semaphore,
 *              -1              failed, error in errno
 * ERRNO
 *              EAGAIN          the semaphore was already locked,
 *              EINVAL          'sem' is not a valid semaphore,
 *              ENOTSUP         sem_trywait is not supported,
 *              EINTR           the function was interrupted by a signal,
 *              EDEADLK         a deadlock condition was detected.
 *
 * ------------------------------------------------------
 */
{
	int result = 0;
	sem_t s = *sem;

	if (s == NULL)
	{
		result = EINVAL;
	}
	else if ((result = pthread_mutex_lock(&s->lock)) == 0)
	{
		/* See sem_destroy.c
		 */
		if (*sem == NULL)
		{
			(void)pthread_mutex_unlock(&s->lock);
			errno = EINVAL;
			return -1;
		}

		if (s->value > 0)
		{
			s->value--;
		}
		else
		{
			result = EAGAIN;
		}

		(void)pthread_mutex_unlock(&s->lock);
	}

	if (result != 0)
	{
		errno = result;
		return -1;
	}

	return 0;

}				/* sem_trywait */
/*
 * -------------------------------------------------------------
 *
 * Module: sem_unlink.c
 *
 * Purpose:
 *	Semaphores aren't actually part of the PThreads standard.
 *	They are defined by the POSIX Standard:
 *
 *		POSIX 1003.1b-1993	(POSIX.1b)
 *
 * -------------------------------------------------------------
 *
 * --------------------------------------------------------------------------
 *
 *      Pthreads-win32 - POSIX Threads Library for Win32
 *      Copyright(C) 1998 John E. Bossom
 *      Copyright(C) 1999,2005 Pthreads-win32 contributors
 *
 *      Contact Email: rpj@callisto.canberra.edu.au
 *
 *      The current list of contributors is contained
 *      in the file CONTRIBUTORS included with the source
 *      code distribution. The list can also be seen at the
 *      following World Wide Web location:
 *      http://sources.redhat.com/pthreads-win32/contributors.html
 *
 *      This library is free software; you can redistribute it and/or
 *      modify it under the terms of the GNU Lesser General Public
 *      License as published by the Free Software Foundation; either
 *      version 2 of the License, or (at your option) any later version.
 *
 *      This library is distributed in the hope that it will be useful,
 *      but WITHOUT ANY WARRANTY; without even the implied warranty of
 *      MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *      Lesser General Public License for more details.
 *
 *      You should have received a copy of the GNU Lesser General Public
 *      License along with this library in the file COPYING.LIB;
 *      if not, write to the Free Software Foundation, Inc.,
 *      59 Temple Place - Suite 330, Boston, MA 02111-1307, USA
 */


 /* ignore warning "unreferenced formal parameter" */
#if defined(_MSC_VER)
#pragma warning( disable : 4100 )
#endif

int
sem_unlink(const char *name)
{
	errno = ENOSYS;
	return -1;
}				/* sem_unlink */
/*
 * -------------------------------------------------------------
 *
 * Module: sem_wait.c
 *
 * Purpose:
 *	Semaphores aren't actually part of the PThreads standard.
 *	They are defined by the POSIX Standard:
 *
 *		POSIX 1003.1b-1993	(POSIX.1b)
 *
 * -------------------------------------------------------------
 *
 * --------------------------------------------------------------------------
 *
 *      Pthreads-win32 - POSIX Threads Library for Win32
 *      Copyright(C) 1998 John E. Bossom
 *      Copyright(C) 1999,2005 Pthreads-win32 contributors
 *
 *      Contact Email: rpj@callisto.canberra.edu.au
 *
 *      The current list of contributors is contained
 *      in the file CONTRIBUTORS included with the source
 *      code distribution. The list can also be seen at the
 *      following World Wide Web location:
 *      http://sources.redhat.com/pthreads-win32/contributors.html
 *
 *      This library is free software; you can redistribute it and/or
 *      modify it under the terms of the GNU Lesser General Public
 *      License as published by the Free Software Foundation; either
 *      version 2 of the License, or (at your option) any later version.
 *
 *      This library is distributed in the hope that it will be useful,
 *      but WITHOUT ANY WARRANTY; without even the implied warranty of
 *      MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *      Lesser General Public License for more details.
 *
 *      You should have received a copy of the GNU Lesser General Public
 *      License along with this library in the file COPYING.LIB;
 *      if not, write to the Free Software Foundation, Inc.,
 *      59 Temple Place - Suite 330, Boston, MA 02111-1307, USA
 */



static void PTW32_CDECL
ptw32_sem_wait_cleanup(void * sem)
{
	sem_t s = (sem_t)sem;

	if (pthread_mutex_lock(&s->lock) == 0)
	{
		/*
		 * If sema is destroyed do nothing, otherwise:-
		 * If the sema is posted between us being cancelled and us locking
		 * the sema again above then we need to consume that post but cancel
		 * anyway. If we don't get the semaphore we indicate that we're no
		 * longer waiting.
		 */
		if (*((sem_t *)sem) != NULL && !(WaitForSingleObject(s->sem, 0) == WAIT_OBJECT_0))
		{
			++s->value;
#if defined(NEED_SEM)
			if (s->value > 0)
			{
				s->leftToUnblock = 0;
			}
#else
			/*
			 * Don't release the W32 sema, it doesn't need adjustment
			 * because it doesn't record the number of waiters.
			 */
#endif /* NEED_SEM */
		}
		(void)pthread_mutex_unlock(&s->lock);
	}
}

int
sem_wait(sem_t * sem)
/*
 * ------------------------------------------------------
 * DOCPUBLIC
 *      This function  waits on a semaphore.
 *
 * PARAMETERS
 *      sem
 *              pointer to an instance of sem_t
 *
 * DESCRIPTION
 *      This function waits on a semaphore. If the
 *      semaphore value is greater than zero, it decreases
 *      its value by one. If the semaphore value is zero, then
 *      the calling thread (or process) is blocked until it can
 *      successfully decrease the value or until interrupted by
 *      a signal.
 *
 * RESULTS
 *              0               successfully decreased semaphore,
 *              -1              failed, error in errno
 * ERRNO
 *              EINVAL          'sem' is not a valid semaphore,
 *              ENOSYS          semaphores are not supported,
 *              EINTR           the function was interrupted by a signal,
 *              EDEADLK         a deadlock condition was detected.
 *
 * ------------------------------------------------------
 */
{
	int result = 0;
	sem_t s = *sem;

	pthread_testcancel();

	if (s == NULL)
	{
		result = EINVAL;
	}
	else
	{
		if ((result = pthread_mutex_lock(&s->lock)) == 0)
		{
			int v;

			/* See sem_destroy.c
			 */
			if (*sem == NULL)
			{
				(void)pthread_mutex_unlock(&s->lock);
				errno = EINVAL;
				return -1;
			}

			v = --s->value;
			(void)pthread_mutex_unlock(&s->lock);

			if (v < 0)
			{
#if defined(_MSC_VER) && _MSC_VER < 1400
#pragma inline_depth(0)
#endif
				/* Must wait */
				pthread_cleanup_push(ptw32_sem_wait_cleanup, (void *)s);
				result = pthreadCancelableWait(s->sem);
				/* Cleanup if we're canceled or on any other error */
				pthread_cleanup_pop(result);
#if defined(_MSC_VER) && _MSC_VER < 1400
#pragma inline_depth()
#endif
			}
#if defined(NEED_SEM)

			if (!result && pthread_mutex_lock(&s->lock) == 0)
			{
				if (*sem == NULL)
				{
					(void)pthread_mutex_unlock(&s->lock);
					errno = EINVAL;
					return -1;
				}

				if (s->leftToUnblock > 0)
				{
					--s->leftToUnblock;
					SetEvent(s->sem);
				}
				(void)pthread_mutex_unlock(&s->lock);
			}

#endif /* NEED_SEM */

		}

	}

	if (result != 0)
	{
		errno = result;
		return -1;
	}

	return 0;

}				/* sem_wait */
/*
 * signal.c
 *
 * Description:
 * Thread-aware signal functions.
 *
 * --------------------------------------------------------------------------
 *
 *      Pthreads-win32 - POSIX Threads Library for Win32
 *      Copyright(C) 1998 John E. Bossom
 *      Copyright(C) 1999,2005 Pthreads-win32 contributors
 *
 *      Contact Email: rpj@callisto.canberra.edu.au
 *
 *      The current list of contributors is contained
 *      in the file CONTRIBUTORS included with the source
 *      code distribution. The list can also be seen at the
 *      following World Wide Web location:
 *      http://sources.redhat.com/pthreads-win32/contributors.html
 *
 *      This library is free software; you can redistribute it and/or
 *      modify it under the terms of the GNU Lesser General Public
 *      License as published by the Free Software Foundation; either
 *      version 2 of the License, or (at your option) any later version.
 *
 *      This library is distributed in the hope that it will be useful,
 *      but WITHOUT ANY WARRANTY; without even the implied warranty of
 *      MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *      Lesser General Public License for more details.
 *
 *      You should have received a copy of the GNU Lesser General Public
 *      License along with this library in the file COPYING.LIB;
 *      if not, write to the Free Software Foundation, Inc.,
 *      59 Temple Place - Suite 330, Boston, MA 02111-1307, USA
 */

 /*
  * Possible future strategy for implementing pthread_kill()
  * ========================================================
  *
  * Win32 does not implement signals.
  * Signals are simply software interrupts.
  * pthread_kill() asks the system to deliver a specified
  * signal (interrupt) to a specified thread in the same
  * process.
  * Signals are always asynchronous (no deferred signals).
  * Pthread-win32 has an async cancelation mechanism.
  * A similar system can be written to deliver signals
  * within the same process (on ix86 processors at least).
  *
  * Each thread maintains information about which
  * signals it will respond to. Handler routines
  * are set on a per-process basis - not per-thread.
  * When signalled, a thread will check it's sigmask
  * and, if the signal is not being ignored, call the
  * handler routine associated with the signal. The
  * thread must then (except for some signals) return to
  * the point where it was interrupted.
  *
  * Ideally the system itself would check the target thread's
  * mask before possibly needlessly bothering the thread
  * itself. This could be done by pthread_kill(), that is,
  * in the signaling thread since it has access to
  * all pthread_t structures. It could also retrieve
  * the handler routine address to minimise the target
  * threads response overhead. This may also simplify
  * serialisation of the access to the per-thread signal
  * structures.
  *
  * pthread_kill() eventually calls a routine similar to
  * ptw32_cancel_thread() which manipulates the target
  * threads processor context to cause the thread to
  * run the handler launcher routine. pthread_kill() must
  * save the target threads current context so that the
  * handler launcher routine can restore the context after
  * the signal handler has returned. Some handlers will not
  * return, eg. the default SIGKILL handler may simply
  * call pthread_exit().
  *
  * The current context is saved in the target threads
  * pthread_t structure.
  */


#if defined(HAVE_SIGSET_T)

static void
ptw32_signal_thread()
{
}

static void
ptw32_signal_callhandler()
{
}

int
pthread_sigmask(int how, sigset_t const *set, sigset_t * oset)
{
	pthread_t thread = pthread_self();

	if (thread.p == NULL)
	{
		return ENOENT;
	}

	/* Validate the `how' argument. */
	if (set != NULL)
	{
		switch (how)
		{
		case SIG_BLOCK:
			break;
		case SIG_UNBLOCK:
			break;
		case SIG_SETMASK:
			break;
		default:
			/* Invalid `how' argument. */
			return EINVAL;
		}
	}

	/* Copy the old mask before modifying it. */
	if (oset != NULL)
	{
		memcpy(oset, &(thread.p->sigmask), sizeof(sigset_t));
	}

	if (set != NULL)
	{
		unsigned int i;

		/* FIXME: this code assumes that sigmask is an even multiple of
		   the size of a long integer. */

		unsigned long *src = (unsigned long const *)set;
		unsigned long *dest = (unsigned long *) &(thread.p->sigmask);

		switch (how)
		{
		case SIG_BLOCK:
			for (i = 0; i < (sizeof(sigset_t) / sizeof(unsigned long)); i++)
			{
				/* OR the bit field longword-wise. */
				*dest++ |= *src++;
			}
			break;
		case SIG_UNBLOCK:
			for (i = 0; i < (sizeof(sigset_t) / sizeof(unsigned long)); i++)
			{
				/* XOR the bitfield longword-wise. */
				*dest++ ^= *src++;
			}
		case SIG_SETMASK:
			/* Replace the whole sigmask. */
			memcpy(&(thread.p->sigmask), set, sizeof(sigset_t));
			break;
		}
	}

	return 0;
}

int
sigwait(const sigset_t * set, int *sig)
{
	/* This routine is a cancellation point */
	pthread_test_cancel();
}

int
sigaction(int signum, const struct sigaction *act, struct sigaction *oldact)
{
}

#endif /* HAVE_SIGSET_T */
/*
 * spin.c
 *
 * Description:
 * This translation unit implements spin lock primitives.
 *
 * --------------------------------------------------------------------------
 *
 *      Pthreads-win32 - POSIX Threads Library for Win32
 *      Copyright(C) 1998 John E. Bossom
 *      Copyright(C) 1999,2005 Pthreads-win32 contributors
 *
 *      Contact Email: rpj@callisto.canberra.edu.au
 *
 *      The current list of contributors is contained
 *      in the file CONTRIBUTORS included with the source
 *      code distribution. The list can also be seen at the
 *      following World Wide Web location:
 *      http://sources.redhat.com/pthreads-win32/contributors.html
 *
 *      This library is free software; you can redistribute it and/or
 *      modify it under the terms of the GNU Lesser General Public
 *      License as published by the Free Software Foundation; either
 *      version 2 of the License, or (at your option) any later version.
 *
 *      This library is distributed in the hope that it will be useful,
 *      but WITHOUT ANY WARRANTY; without even the implied warranty of
 *      MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *      Lesser General Public License for more details.
 *
 *      You should have received a copy of the GNU Lesser General Public
 *      License along with this library in the file COPYING.LIB;
 *      if not, write to the Free Software Foundation, Inc.,
 *      59 Temple Place - Suite 330, Boston, MA 02111-1307, USA
 */



 /*
  * sync.c
  *
  * Description:
  * This translation unit implements functions related to thread
  * synchronisation.
  *
  * --------------------------------------------------------------------------
  *
  *      Pthreads-win32 - POSIX Threads Library for Win32
  *      Copyright(C) 1998 John E. Bossom
  *      Copyright(C) 1999,2005 Pthreads-win32 contributors
  *
  *      Contact Email: rpj@callisto.canberra.edu.au
  *
  *      The current list of contributors is contained
  *      in the file CONTRIBUTORS included with the source
  *      code distribution. The list can also be seen at the
  *      following World Wide Web location:
  *      http://sources.redhat.com/pthreads-win32/contributors.html
  *
  *      This library is free software; you can redistribute it and/or
  *      modify it under the terms of the GNU Lesser General Public
  *      License as published by the Free Software Foundation; either
  *      version 2 of the License, or (at your option) any later version.
  *
  *      This library is distributed in the hope that it will be useful,
  *      but WITHOUT ANY WARRANTY; without even the implied warranty of
  *      MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
  *      Lesser General Public License for more details.
  *
  *      You should have received a copy of the GNU Lesser General Public
  *      License along with this library in the file COPYING.LIB;
  *      if not, write to the Free Software Foundation, Inc.,
  *      59 Temple Place - Suite 330, Boston, MA 02111-1307, USA
  */



  /*
   * tsd.c
   *
   * Description:
   * POSIX thread functions which implement thread-specific data (TSD).
   *
   * --------------------------------------------------------------------------
   *
   *      Pthreads-win32 - POSIX Threads Library for Win32
   *      Copyright(C) 1998 John E. Bossom
   *      Copyright(C) 1999,2005 Pthreads-win32 contributors
   *
   *      Contact Email: rpj@callisto.canberra.edu.au
   *
   *      The current list of contributors is contained
   *      in the file CONTRIBUTORS included with the source
   *      code distribution. The list can also be seen at the
   *      following World Wide Web location:
   *      http://sources.redhat.com/pthreads-win32/contributors.html
   *
   *      This library is free software; you can redistribute it and/or
   *      modify it under the terms of the GNU Lesser General Public
   *      License as published by the Free Software Foundation; either
   *      version 2 of the License, or (at your option) any later version.
   *
   *      This library is distributed in the hope that it will be useful,
   *      but WITHOUT ANY WARRANTY; without even the implied warranty of
   *      MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   *      Lesser General Public License for more details.
   *
   *      You should have received a copy of the GNU Lesser General Public
   *      License along with this library in the file COPYING.LIB;
   *      if not, write to the Free Software Foundation, Inc.,
   *      59 Temple Place - Suite 330, Boston, MA 02111-1307, USA
   */



   /*
	* w32_CancelableWait.c
	*
	* Description:
	* This translation unit implements miscellaneous thread functions.
	*
	* --------------------------------------------------------------------------
	*
	*      Pthreads-win32 - POSIX Threads Library for Win32
	*      Copyright(C) 1998 John E. Bossom
	*      Copyright(C) 1999,2005 Pthreads-win32 contributors
	*
	*      Contact Email: rpj@callisto.canberra.edu.au
	*
	*      The current list of contributors is contained
	*      in the file CONTRIBUTORS included with the source
	*      code distribution. The list can also be seen at the
	*      following World Wide Web location:
	*      http://sources.redhat.com/pthreads-win32/contributors.html
	*
	*      This library is free software; you can redistribute it and/or
	*      modify it under the terms of the GNU Lesser General Public
	*      License as published by the Free Software Foundation; either
	*      version 2 of the License, or (at your option) any later version.
	*
	*      This library is distributed in the hope that it will be useful,
	*      but WITHOUT ANY WARRANTY; without even the implied warranty of
	*      MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
	*      Lesser General Public License for more details.
	*
	*      You should have received a copy of the GNU Lesser General Public
	*      License along with this library in the file COPYING.LIB;
	*      if not, write to the Free Software Foundation, Inc.,
	*      59 Temple Place - Suite 330, Boston, MA 02111-1307, USA
	*/



static INLINE int
ptw32_cancelable_wait(HANDLE waitHandle, DWORD timeout)
/*
 * -------------------------------------------------------------------
 * This provides an extra hook into the pthread_cancel
 * mechanism that will allow you to wait on a Windows handle and make it a
 * cancellation point. This function blocks until the given WIN32 handle is
 * signaled or pthread_cancel has been called. It is implemented using
 * WaitForMultipleObjects on 'waitHandle' and a manually reset WIN32
 * event used to implement pthread_cancel.
 *
 * Given this hook it would be possible to implement more of the cancellation
 * points.
 * -------------------------------------------------------------------
 */
{
	int result;
	pthread_t self;
	ptw32_thread_t * sp;
	HANDLE handles[2];
	DWORD nHandles = 1;
	DWORD status;

	handles[0] = waitHandle;

	self = pthread_self();
	sp = (ptw32_thread_t *)self.p;

	if (sp != NULL)
	{
		/*
		 * Get cancelEvent handle
		 */
		if (sp->cancelState == PTHREAD_CANCEL_ENABLE)
		{

			if ((handles[1] = sp->cancelEvent) != NULL)
			{
				nHandles++;
			}
		}
	}
	else
	{
		handles[1] = NULL;
	}

	status = WaitForMultipleObjects(nHandles, handles, PTW32_FALSE, timeout);

	switch (status - WAIT_OBJECT_0)
	{
	case 0:
		/*
		 * Got the handle.
		 * In the event that both handles are signalled, the smallest index
		 * value (us) is returned. As it has been arranged, this ensures that
		 * we don't drop a signal that we should act on (i.e. semaphore,
		 * mutex, or condition variable etc).
		 */
		result = 0;
		break;

	case 1:
		/*
		 * Got cancel request.
		 * In the event that both handles are signaled, the cancel will
		 * be ignored (see case 0 comment).
		 */
		ResetEvent(handles[1]);

		if (sp != NULL)
		{
			ptw32_mcs_local_node_t stateLock;
			/*
			 * Should handle POSIX and implicit POSIX threads..
			 * Make sure we haven't been async-canceled in the meantime.
			 */
			ptw32_mcs_lock_acquire(&sp->stateLock, &stateLock);
			if (sp->state < PThreadStateCanceling)
			{
				sp->state = PThreadStateCanceling;
				sp->cancelState = PTHREAD_CANCEL_DISABLE;
				ptw32_mcs_lock_release(&stateLock);
				ptw32_throw(PTW32_EPS_CANCEL);

				/* Never reached */
			}
			ptw32_mcs_lock_release(&stateLock);
		}

		/* Should never get to here. */
		result = EINVAL;
		break;

	default:
		if (status == WAIT_TIMEOUT)
		{
			result = ETIMEDOUT;
		}
		else
		{
			result = EINVAL;
		}
		break;
	}

	return (result);

}				/* CancelableWait */

int
pthreadCancelableWait(HANDLE waitHandle)
{
	return (ptw32_cancelable_wait(waitHandle, INFINITE));
}

int
pthreadCancelableTimedWait(HANDLE waitHandle, DWORD timeout)
{
	return (ptw32_cancelable_wait(waitHandle, timeout));
}
