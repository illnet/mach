#ifndef LURE_SOCK_EPOLL_H
#define LURE_SOCK_EPOLL_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct LureEpollConnection LureEpollConnection;

typedef struct {
    int fd_a;
    int fd_b;
    uint64_t c2s_bytes;
    uint64_t s2c_bytes;
    uint64_t c2s_chunks;
    uint64_t s2c_chunks;
    int32_t result;
    uint32_t state_flags;
} LureEpollShared;

enum {
    LURE_EPOLL_RUNNING = 1u << 0,
    LURE_EPOLL_DONE = 1u << 1,
    LURE_EPOLL_FAILED = 1u << 2,
};

typedef void (*LureEpollStartupFailCb)(void* user_data, int err);

int lure_epoll_connection_main(
    LureEpollShared* shared,
    LureEpollStartupFailCb on_startup_fail,
    void* user_data,
    LureEpollConnection** out_conn
);

int lure_epoll_connection_join(LureEpollConnection* conn);
void lure_epoll_connection_free(LureEpollConnection* conn);

/* ── N-worker pool ─────────────────────────────────────────────────────────── */

/*
 * Completion frame written to the shared done-pipe after each connection
 * finishes.  sizeof(LureEpollDone) == 48, which fits inside PIPE_BUF, so
 * every write is atomic even with multiple workers sharing one pipe.
 */
typedef struct {
    uint64_t conn_id;
    uint64_t c2s_bytes;
    uint64_t s2c_bytes;
    uint64_t c2s_chunks;
    uint64_t s2c_chunks;
    int32_t  result;
    uint32_t _pad;
} LureEpollDone;

/*
 * Live byte/chunk counters shared with Rust for mid-session polling.
 * Allocated and owned by Rust; passed to C at submit time.
 * C writes plain (non-atomic) u64 values; Rust reads via read_volatile.
 * Cache-line aligned (64 bytes) to avoid false sharing with other slot data.
 */
typedef struct __attribute__((aligned(64))) {
    uint64_t c2s_bytes;
    uint64_t s2c_bytes;
    uint64_t c2s_chunks;
    uint64_t s2c_chunks;
} LureEpollLiveBytes;

typedef struct LureEpollWorker LureEpollWorker;

/*
 * Create a new worker thread.  done_pipe_write_fd is the write end of a pipe
 * shared with the Rust drain task; the worker writes LureEpollDone frames to
 * it.  The caller retains ownership of the fd (worker does NOT close it).
 * Returns NULL on failure.
 */
LureEpollWorker* lure_epoll_worker_new(int done_pipe_write_fd);

/*
 * Submit a connection pair to the worker.  The worker takes ownership of
 * fd_a and fd_b (it will close them when done, including on error).
 * live points to Rust-allocated LureEpollLiveBytes for mid-session polling.
 * Returns 0 on success or -ENOMEM if the submit node cannot be allocated
 * (in which case fd_a/fd_b are closed by this function before returning).
 */
int lure_epoll_worker_submit(LureEpollWorker* w, int fd_a, int fd_b,
                             uint64_t conn_id, LureEpollLiveBytes* live);

/* Request abort of the connection identified by conn_id. No-op if not found. */
void lure_epoll_worker_abort(LureEpollWorker* w, uint64_t conn_id);

/*
 * Signal the worker to drain remaining connections and exit cleanly.
 * Blocks until the worker thread has exited.
 */
void lure_epoll_worker_shutdown(LureEpollWorker* w);

/* Free all resources.  Must be called after lure_epoll_worker_shutdown. */
void lure_epoll_worker_free(LureEpollWorker* w);

#ifdef __cplusplus
}
#endif

#endif
