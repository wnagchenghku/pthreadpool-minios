/* Standard C headers */
#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

/* POSIX headers */
#include <pthread.h>
#include <unistd.h>

/* Platform-specific headers */
#if defined(__linux__)
	#define PTHREADPOOL_USE_FUTEX 1
	#include <sys/syscall.h>
	#include <linux/futex.h>

	/* Old Android NDKs do not define SYS_futex and FUTEX_PRIVATE_FLAG */
	#ifndef SYS_futex
		#define SYS_futex __NR_futex
	#endif
	#ifndef FUTEX_PRIVATE_FLAG
		#define FUTEX_PRIVATE_FLAG 128
	#endif
#elif defined(__native_client__)
	#define PTHREADPOOL_USE_FUTEX 1
	#include <irt.h>
#else
	#define PTHREADPOOL_USE_FUTEX 0
#endif

/* Dependencies */
#include <fxdiv.h>

/* Library header */
#include <pthreadpool.h>

#define PTHREADPOOL_CACHELINE_SIZE 64
#define PTHREADPOOL_CACHELINE_ALIGNED __attribute__((__aligned__(PTHREADPOOL_CACHELINE_SIZE)))

#if defined(__clang__)
	#if __has_extension(c_static_assert) || __has_feature(c_static_assert)
		#define PTHREADPOOL_STATIC_ASSERT(predicate, message) _Static_assert((predicate), message)
	#else
		#define PTHREADPOOL_STATIC_ASSERT(predicate, message)
	#endif
#elif defined(__GNUC__) && ((__GNUC__ > 4) || (__GNUC__ == 4) && (__GNUC_MINOR__ >= 6))
	/* Static assert is supported by gcc >= 4.6 */
	#define PTHREADPOOL_STATIC_ASSERT(predicate, message) _Static_assert((predicate), message)
#else
	#define PTHREADPOOL_STATIC_ASSERT(predicate, message)
#endif

static inline size_t multiply_divide(size_t a, size_t b, size_t d) {
	#if defined(__SIZEOF_SIZE_T__) && (__SIZEOF_SIZE_T__ == 4)
		return (size_t) (((uint64_t) a) * ((uint64_t) b)) / ((uint64_t) d);
	#elif defined(__SIZEOF_SIZE_T__) && (__SIZEOF_SIZE_T__ == 8)
		return (size_t) (((__uint128_t) a) * ((__uint128_t) b)) / ((__uint128_t) d);
	#else
		#error "Unsupported platform"
	#endif
}

static inline size_t divide_round_up(size_t dividend, size_t divisor) {
	if (dividend % divisor == 0) {
		return dividend / divisor;
	} else {
		return dividend / divisor + 1;
	}
}

static inline size_t min(size_t a, size_t b) {
	return a < b ? a : b;
}

#if PTHREADPOOL_USE_FUTEX
	#if defined(__linux__)
		static int futex_wait(volatile uint32_t* address, uint32_t value) {
			return syscall(SYS_futex, address, FUTEX_WAIT | FUTEX_PRIVATE_FLAG, value,
				NULL, NULL, 0);
		}

		static int futex_wake_all(volatile uint32_t* address) {
			return syscall(SYS_futex, address, FUTEX_WAKE | FUTEX_PRIVATE_FLAG, INT_MAX,
				NULL, NULL, 0);
		}
	#elif defined(__native_client__)
		static struct nacl_irt_futex nacl_irt_futex = { 0 };
		static pthread_once_t nacl_init_guard = PTHREAD_ONCE_INIT;
		static void nacl_init(void) {
			nacl_interface_query(NACL_IRT_FUTEX_v0_1, &nacl_irt_futex, sizeof(nacl_irt_futex));
		}

		static int futex_wait(volatile uint32_t* address, uint32_t value) {
			return nacl_irt_futex.futex_wait_abs((volatile int*) address, (int) value, NULL);
		}

		static int futex_wake_all(volatile uint32_t* address) {
			int count;
			return nacl_irt_futex.futex_wake((volatile int*) address, INT_MAX, &count);
		}
	#else
		#error "Platform-specific implementation of futex_wait and futex_wake_all required"
	#endif
#endif

#define THREADPOOL_COMMAND_MASK UINT32_C(0x7FFFFFFF)

enum threadpool_command {
	threadpool_command_init,
	threadpool_command_compute_1d,
	threadpool_command_shutdown,
};

struct PTHREADPOOL_CACHELINE_ALIGNED thread_info {
	/**
	 * Index of the first element in the work range.
	 * Before processing a new element the owning worker thread increments this value.
	 */
	volatile size_t range_start;
	/**
	 * Index of the element after the last element of the work range.
	 * Before processing a new element the stealing worker thread decrements this value.
	 */
	volatile size_t range_end;
	/**
	 * The number of elements in the work range.
	 * Due to race conditions range_length <= range_end - range_start.
	 * The owning worker thread must decrement this value before incrementing @a range_start.
	 * The stealing worker thread must decrement this value before decrementing @a range_end.
	 */
	volatile size_t range_length;
	/**
	 * Thread number in the 0..threads_count-1 range.
	 */
	size_t thread_number;
	/**
	 * The pthread object corresponding to the thread.
	 */
	// pthread_t thread_object;
	/**
	 * Condition variable used to wake up the thread.
	 * When the thread is idle, it waits on this condition variable.
	 */
	// pthread_cond_t wakeup_condvar;
};

PTHREADPOOL_STATIC_ASSERT(sizeof(struct thread_info) % PTHREADPOOL_CACHELINE_SIZE == 0, "thread_info structure must occupy an integer number of cache lines (64 bytes)");

struct PTHREADPOOL_CACHELINE_ALIGNED pthreadpool {
	/**
	 * The number of threads that are processing an operation.
	 */
	volatile size_t active_threads;
#if PTHREADPOOL_USE_FUTEX
	/**
	 * Indicates if there are active threads.
	 * Only two values are possible:
	 * - has_active_threads == 0 if active_threads == 0
	 * - has_active_threads == 1 if active_threads != 0
	 */
	volatile uint32_t has_active_threads;
#endif
	/**
	 * The last command submitted to the thread pool.
	 */
	volatile uint32_t command;
	/**
	 * The function to call for each item.
	 */
	volatile void* function;
	/**
	 * The first argument to the item processing function.
	 */
	void *volatile argument;
	/**
	 * Serializes concurrent calls to @a pthreadpool_compute_* from different threads.
	 */
	pthread_mutex_t execution_mutex;
#if !PTHREADPOOL_USE_FUTEX
	/**
	 * Guards access to the @a active_threads variable.
	 */
	pthread_mutex_t completion_mutex;
	/**
	 * Condition variable to wait until all threads complete an operation (until @a active_threads is zero).
	 */
	// pthread_cond_t completion_condvar;
	/**
	 * Guards access to the @a command variable.
	 */
	pthread_mutex_t command_mutex;
	/**
	 * Condition variable to wait for change of the @a command variable.
	 */
	// pthread_cond_t command_condvar;
#endif
	/**
	 * The number of threads in the thread pool. Never changes after initialization.
	 */
	size_t threads_count;
	/**
	 * Thread information structures that immediately follow this structure.
	 */
	struct thread_info threads[];
};

size_t pthreadpool_get_threads_count(struct pthreadpool* threadpool) {
	if (threadpool == NULL) {
		return 1;
	} else {
		return threadpool->threads_count;
	}
}

void pthreadpool_compute_1d(
	struct pthreadpool* threadpool,
	pthreadpool_function_1d_t function,
	void* argument,
	size_t range)
{
	if (threadpool == NULL) {
		/* No thread pool provided: execute function sequentially on the calling thread */
		for (size_t i = 0; i < range; i++) {
			function(argument, i);
		}
	}
}

struct compute_1d_tiled_context {
	pthreadpool_function_1d_tiled_t function;
	void* argument;
	size_t range;
	size_t tile;
};

static void compute_1d_tiled(const struct compute_1d_tiled_context* context, size_t linear_index) {
	const size_t tile_index = linear_index;
	const size_t index = tile_index * context->tile;
	const size_t tile = min(context->tile, context->range - index);
	context->function(context->argument, index, tile);
}

void pthreadpool_compute_1d_tiled(
	pthreadpool_t threadpool,
	pthreadpool_function_1d_tiled_t function,
	void* argument,
	size_t range,
	size_t tile)
{
	if (threadpool == NULL) {
		/* No thread pool provided: execute function sequentially on the calling thread */
		for (size_t i = 0; i < range; i += tile) {
			function(argument, i, min(range - i, tile));
		}
	}
}

struct compute_2d_context {
	pthreadpool_function_2d_t function;
	void* argument;
	struct fxdiv_divisor_size_t range_j;
};

static void compute_2d(const struct compute_2d_context* context, size_t linear_index) {
	const struct fxdiv_divisor_size_t range_j = context->range_j;
	const struct fxdiv_result_size_t index = fxdiv_divide_size_t(linear_index, range_j);
	context->function(context->argument, index.quotient, index.remainder);
}

void pthreadpool_compute_2d(
	struct pthreadpool* threadpool,
	pthreadpool_function_2d_t function,
	void* argument,
	size_t range_i,
	size_t range_j)
{
	if (threadpool == NULL) {
		/* No thread pool provided: execute function sequentially on the calling thread */
		for (size_t i = 0; i < range_i; i++) {
			for (size_t j = 0; j < range_j; j++) {
				function(argument, i, j);
			}
		}
	}
}

struct compute_2d_tiled_context {
	pthreadpool_function_2d_tiled_t function;
	void* argument;
	struct fxdiv_divisor_size_t tile_range_j;
	size_t range_i;
	size_t range_j;
	size_t tile_i;
	size_t tile_j;
};

static void compute_2d_tiled(const struct compute_2d_tiled_context* context, size_t linear_index) {
	const struct fxdiv_divisor_size_t tile_range_j = context->tile_range_j;
	const struct fxdiv_result_size_t tile_index = fxdiv_divide_size_t(linear_index, tile_range_j);
	const size_t max_tile_i = context->tile_i;
	const size_t max_tile_j = context->tile_j;
	const size_t index_i = tile_index.quotient * max_tile_i;
	const size_t index_j = tile_index.remainder * max_tile_j;
	const size_t tile_i = min(max_tile_i, context->range_i - index_i);
	const size_t tile_j = min(max_tile_j, context->range_j - index_j);
	context->function(context->argument, index_i, index_j, tile_i, tile_j);
}

void pthreadpool_compute_2d_tiled(
	pthreadpool_t threadpool,
	pthreadpool_function_2d_tiled_t function,
	void* argument,
	size_t range_i,
	size_t range_j,
	size_t tile_i,
	size_t tile_j)
{
	if (threadpool == NULL) {
		/* No thread pool provided: execute function sequentially on the calling thread */
		for (size_t i = 0; i < range_i; i += tile_i) {
			for (size_t j = 0; j < range_j; j += tile_j) {
				function(argument, i, j, min(range_i - i, tile_i), min(range_j - j, tile_j));
			}
		}
	}
}
