#ifndef _GNU_SOURCE
#define _GNU_SOURCE 1
#endif

#include "epoll.h"

#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <pthread.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/eventfd.h>
#include <sys/socket.h>
#include <unistd.h>

enum {
    SIDE_A = 0,
    SIDE_B = 1,
    MAX_EVENTS = 4,
    BUF_CAP = 64 * 1024,
    PIPE_CAP = 512 * 1024,  // Increased for sustained streaming
};

struct LureEpollConnection {
    LureEpollShared* shared;
    LureEpollStartupFailCb fail_cb;
    void* fail_cb_user;

    pthread_t io_thread;
    pthread_t cleanup_thread;
    int io_started;
    int cleanup_started;

    int epoll_fd;
    int result;
    uint32_t abort_flag;  // Moved from LureEpollShared (cache line 0)

    int eof_a;
    int eof_b;
    int hup_a;
    int hup_b;
    int shut_wr_a;
    int shut_wr_b;
    uint32_t prev_ev_a;  // Track previous interest mask to avoid unnecessary epoll_ctl
    uint32_t prev_ev_b;

    // Pipe pairs for splice (kernel-space forwarding, zero-copy)
    int a2b_pipe[2];     // [0] = read end, [1] = write end
    int b2a_pipe[2];
    size_t a2b_pipe_len; // Bytes currently buffered in pipe
    size_t b2a_pipe_len;
};

static inline void shared_set_flag(LureEpollShared* shared, uint32_t flag) {
    __atomic_fetch_or(&shared->state_flags, flag, __ATOMIC_RELEASE);
}

static inline void shared_clear_flag(LureEpollShared* shared, uint32_t flag) {
    __atomic_fetch_and(&shared->state_flags, ~flag, __ATOMIC_RELEASE);
}

static inline int conn_abort_requested(const struct LureEpollConnection* conn) {
    return __atomic_load_n(&conn->abort_flag, __ATOMIC_ACQUIRE) != 0;
}

static inline uint64_t live_progress_bytes(const LureEpollLiveBytes *live) {
    return live ? (live->c2s_bytes + live->s2c_bytes) : 0;
}

static inline int set_nonblocking(int fd) {
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0) {
        return -1;
    }
    return fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}

static void set_tcp_opts(int fd) {
    int one = 1;
    (void)setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
    (void)setsockopt(fd, IPPROTO_TCP, TCP_QUICKACK, &one, sizeof(one));
}

static inline uint32_t side_events(const struct LureEpollConnection* conn, int side) {
    uint32_t ev = EPOLLET | EPOLLERR | EPOLLHUP | EPOLLRDHUP;  // Always include EPOLLET for edge-triggered

    if (side == SIDE_A) {
        // EPOLLIN: read from A if pipe has room and no EOF
        if (!conn->eof_a && conn->a2b_pipe_len < PIPE_CAP) {
            ev |= EPOLLIN;
        }
        // EPOLLOUT: write to A if B→A pipe has data
        if (conn->b2a_pipe_len > 0) {
            ev |= EPOLLOUT;
        }
    } else {
        // EPOLLIN: read from B if pipe has room and no EOF
        if (!conn->eof_b && conn->b2a_pipe_len < PIPE_CAP) {
            ev |= EPOLLIN;
        }
        // EPOLLOUT: write to B if A→B pipe has data
        if (conn->a2b_pipe_len > 0) {
            ev |= EPOLLOUT;
        }
    }

    return ev;
}

static int epoll_mod(int epoll_fd, int fd, uint64_t key, uint32_t events) {
    struct epoll_event ev;
    memset(&ev, 0, sizeof(ev));
    ev.events = events;
    ev.data.u64 = key;
    return epoll_ctl(epoll_fd, EPOLL_CTL_MOD, fd, &ev);
}

// Drain buffered pipe data to dst_fd.
// Updates *pipe_len with residual bytes in pipe and records delivered bytes.
// Returns 0 on success or -errno on error.
static int splice_drain_pipe(int pipe_read, int dst_fd,
                             size_t *pipe_len, uint64_t *bytes_counter)
{
    while (*pipe_len > 0) {
        ssize_t n = splice(pipe_read, NULL, dst_fd, NULL,
                           *pipe_len,
                           SPLICE_F_NONBLOCK | SPLICE_F_MOVE);
        if (n > 0) {
            *pipe_len -= (size_t)n;
            if (bytes_counter) {
                *bytes_counter += (uint64_t)n;
            }
        } else if (errno == EAGAIN || errno == EWOULDBLOCK) {
            break;  // dst backpressure
        } else {
            return -errno;
        }
    }
    return 0;
}

// Splice data from src_fd into pipe, then drain pipe to dst_fd.
// Updates *pipe_len with residual bytes in pipe and records logical chunk
// ingress plus delivered bytes.
// Returns 0 on success, -errno on error, sets *eof if src closed.
static int splice_forward(int src_fd, int pipe_write, int pipe_read, int dst_fd,
                          size_t *pipe_len, int *eof,
                          uint64_t *bytes_counter, uint64_t *chunks_counter)
{
    // Fill the pipe from src (only if pipe has room)
    if (*pipe_len < PIPE_CAP && !*eof) {
        ssize_t n = splice(src_fd, NULL, pipe_write, NULL,
                           PIPE_CAP - *pipe_len,
                           SPLICE_F_NONBLOCK | SPLICE_F_MOVE);
        if (n > 0) {
            *pipe_len += (size_t)n;
            if (chunks_counter) {
                *chunks_counter += 1;
            }
        } else if (n == 0) {
            *eof = 1;
        } else if (errno != EAGAIN && errno != EWOULDBLOCK) {
            return -errno;
        }
    }

    return splice_drain_pipe(pipe_read, dst_fd, pipe_len, bytes_counter);
}

static int refresh_interest(struct LureEpollConnection* conn) {
    uint32_t new_ev_a = side_events(conn, SIDE_A);
    uint32_t new_ev_b = side_events(conn, SIDE_B);

    // Only call epoll_ctl if the mask actually changed (reduces syscalls in steady state)
    if (new_ev_a != conn->prev_ev_a) {
        if (epoll_mod(conn->epoll_fd, conn->shared->fd_a, SIDE_A, new_ev_a) < 0) {
            return -errno;
        }
        conn->prev_ev_a = new_ev_a;
    }

    if (new_ev_b != conn->prev_ev_b) {
        if (epoll_mod(conn->epoll_fd, conn->shared->fd_b, SIDE_B, new_ev_b) < 0) {
            return -errno;
        }
        conn->prev_ev_b = new_ev_b;
    }

    return 0;
}

static inline int is_complete(const struct LureEpollConnection* conn) {
    // Complete when both sides closed and pipes are empty
    return conn->eof_a && conn->eof_b &&
           conn->a2b_pipe_len == 0 &&
           conn->b2a_pipe_len == 0;
}

static int probe_hup_side_conn(struct LureEpollConnection *conn, int side) {
    if (side == SIDE_A) {
        if (!conn->hup_a || conn->eof_a || conn->a2b_pipe_len >= PIPE_CAP) {
            return 0;
        }
        return splice_forward(
            conn->shared->fd_a, conn->a2b_pipe[1], conn->a2b_pipe[0],
            conn->shared->fd_b, &conn->a2b_pipe_len, &conn->eof_a,
            &conn->shared->c2s_bytes, &conn->shared->c2s_chunks
        );
    }

    if (!conn->hup_b || conn->eof_b || conn->b2a_pipe_len >= PIPE_CAP) {
        return 0;
    }
    return splice_forward(
        conn->shared->fd_b, conn->b2a_pipe[1], conn->b2a_pipe[0],
        conn->shared->fd_a, &conn->b2a_pipe_len, &conn->eof_b,
        &conn->shared->s2c_bytes, &conn->shared->s2c_chunks
    );
}

static void* io_main(void* arg) {
    struct LureEpollConnection* conn = (struct LureEpollConnection*)arg;
    struct epoll_event events[MAX_EVENTS];

    for (;;) {
        if (conn_abort_requested(conn)) {
            conn->result = -ECANCELED;
            break;
        }

        int n = epoll_wait(conn->epoll_fd, events, MAX_EVENTS, 1000);
        if (n < 0) {
            if (errno == EINTR) {
                continue;
            }
            conn->result = -errno;
            break;
        }

        for (int i = 0; i < n; i++) {
            uint32_t ev = events[i].events;
            uint64_t side = events[i].data.u64;
            int want_read = (ev & (EPOLLIN | EPOLLERR | EPOLLHUP | EPOLLRDHUP)) != 0;

            if (ev & (EPOLLHUP | EPOLLRDHUP)) {
                if (side == SIDE_A) conn->hup_a = 1;
                else                conn->hup_b = 1;
            }

            if (side == SIDE_A) {
                if (want_read) {
                    // Splice from A into a2b pipe, then drain a2b pipe to B
                    int rc = splice_forward(
                        conn->shared->fd_a, conn->a2b_pipe[1], conn->a2b_pipe[0],
                        conn->shared->fd_b, &conn->a2b_pipe_len, &conn->eof_a,
                        &conn->shared->c2s_bytes, &conn->shared->c2s_chunks
                    );
                    if (rc < 0) {
                        conn->result = rc;
                        goto done;
                    }
                }
                if (ev & EPOLLOUT) {
                    // Drain remaining b2a pipe data to A
                    int rc = splice_drain_pipe(
                        conn->b2a_pipe[0],
                        conn->shared->fd_a,
                        &conn->b2a_pipe_len,
                        &conn->shared->s2c_bytes
                    );
                    if (rc < 0) {
                        conn->result = rc;
                        goto done;
                    }
                }
            } else {
                if (want_read) {
                    // Splice from B into b2a pipe, then drain b2a pipe to A
                    int rc = splice_forward(
                        conn->shared->fd_b, conn->b2a_pipe[1], conn->b2a_pipe[0],
                        conn->shared->fd_a, &conn->b2a_pipe_len, &conn->eof_b,
                        &conn->shared->s2c_bytes, &conn->shared->s2c_chunks
                    );
                    if (rc < 0) {
                        conn->result = rc;
                        goto done;
                    }
                }
                if (ev & EPOLLOUT) {
                    // Drain remaining a2b pipe data to B
                    int rc = splice_drain_pipe(
                        conn->a2b_pipe[0],
                        conn->shared->fd_b,
                        &conn->a2b_pipe_len,
                        &conn->shared->c2s_bytes
                    );
                    if (rc < 0) {
                        conn->result = rc;
                        goto done;
                    }
                }
            }

            {
                int rc = probe_hup_side_conn(conn, SIDE_A);
                if (rc < 0) {
                    conn->result = rc;
                    goto done;
                }
                rc = probe_hup_side_conn(conn, SIDE_B);
                if (rc < 0) {
                    conn->result = rc;
                    goto done;
                }
            }
        }

        // Shutdown when one side closes and its outgoing pipe is empty
        if (conn->eof_a && !conn->shut_wr_b && conn->a2b_pipe_len == 0) {
            (void)shutdown(conn->shared->fd_b, SHUT_WR);
            conn->shut_wr_b = 1;
        }
        if (conn->eof_b && !conn->shut_wr_a && conn->b2a_pipe_len == 0) {
            (void)shutdown(conn->shared->fd_a, SHUT_WR);
            conn->shut_wr_a = 1;
        }

        int rc = refresh_interest(conn);
        if (rc < 0) {
            conn->result = rc;
            break;
        }

        if (is_complete(conn)) {
            conn->result = 0;
            break;
        }
    }

done:
    return NULL;
}

static void close_owned_fds(LureEpollShared* shared) {
    if (!shared) {
        return;
    }
    if (shared->fd_a >= 0) {
        close(shared->fd_a);
        shared->fd_a = -1;
    }
    if (shared->fd_b >= 0) {
        close(shared->fd_b);
        shared->fd_b = -1;
    }
}

static void* cleanup_main(void* arg) {
    struct LureEpollConnection* conn = (struct LureEpollConnection*)arg;

    if (conn->io_started) {
        (void)pthread_join(conn->io_thread, NULL);
        conn->io_started = 0;
    }

    if (conn->epoll_fd >= 0) {
        close(conn->epoll_fd);
        conn->epoll_fd = -1;
    }

    close_owned_fds(conn->shared);

    conn->shared->result = conn->result;
    shared_clear_flag(conn->shared, LURE_EPOLL_RUNNING);
    shared_set_flag(conn->shared, LURE_EPOLL_DONE);
    if (conn->result < 0) {
        shared_set_flag(conn->shared, LURE_EPOLL_FAILED);
    }

    return NULL;
}

static int startup_fail(
    LureEpollShared* shared,
    LureEpollStartupFailCb cb,
    void* cb_user,
    int err,
    struct LureEpollConnection* conn
) {
    if (shared) {
        shared->result = -err;
        shared_clear_flag(shared, LURE_EPOLL_RUNNING);
        shared_set_flag(shared, LURE_EPOLL_DONE | LURE_EPOLL_FAILED);
        close_owned_fds(shared);
    }

    if (conn) {
        if (conn->io_started) {
            __atomic_store_n(&conn->abort_flag, 1u, __ATOMIC_RELEASE);
            (void)pthread_join(conn->io_thread, NULL);
            conn->io_started = 0;
        }
        if (conn->epoll_fd >= 0) {
            close(conn->epoll_fd);
            conn->epoll_fd = -1;
        }
        free(conn);
    }

    if (cb) {
        cb(cb_user, err);
    }
    return -err;
}

int lure_epoll_connection_main(
    LureEpollShared* shared,
    LureEpollStartupFailCb on_startup_fail,
    void* user_data,
    LureEpollConnection** out_conn
) {
    if (!shared || !out_conn || shared->fd_a < 0 || shared->fd_b < 0) {
        return -EINVAL;
    }

    shared->c2s_bytes = 0;
    shared->s2c_bytes = 0;
    shared->c2s_chunks = 0;
    shared->s2c_chunks = 0;
    shared->result = 0;
    shared->state_flags = LURE_EPOLL_RUNNING;

    struct LureEpollConnection* conn =
        (struct LureEpollConnection*)calloc(1, sizeof(struct LureEpollConnection));
    if (!conn) {
        return startup_fail(shared, on_startup_fail, user_data, ENOMEM, NULL);
    }

    conn->shared = shared;
    conn->fail_cb = on_startup_fail;
    conn->fail_cb_user = user_data;
    conn->epoll_fd = -1;
    conn->a2b_pipe[0] = conn->a2b_pipe[1] = -1;
    conn->b2a_pipe[0] = conn->b2a_pipe[1] = -1;

    // Create pipes for zero-copy splice forwarding
    if (pipe2(conn->a2b_pipe, O_NONBLOCK | O_CLOEXEC) < 0) {
        return startup_fail(shared, on_startup_fail, user_data, errno, conn);
    }
    if (pipe2(conn->b2a_pipe, O_NONBLOCK | O_CLOEXEC) < 0) {
        return startup_fail(shared, on_startup_fail, user_data, errno, conn);
    }

    // Increase pipe capacity for sustained streaming (512KB per direction)
    (void)fcntl(conn->a2b_pipe[1], F_SETPIPE_SZ, PIPE_CAP);
    (void)fcntl(conn->b2a_pipe[1], F_SETPIPE_SZ, PIPE_CAP);

    if (set_nonblocking(shared->fd_a) < 0 || set_nonblocking(shared->fd_b) < 0) {
        return startup_fail(shared, on_startup_fail, user_data, errno, conn);
    }

    set_tcp_opts(shared->fd_a);
    set_tcp_opts(shared->fd_b);

    conn->epoll_fd = epoll_create1(EPOLL_CLOEXEC);
    if (conn->epoll_fd < 0) {
        return startup_fail(shared, on_startup_fail, user_data, errno, conn);
    }

    struct epoll_event ev;
    memset(&ev, 0, sizeof(ev));

    ev.events = EPOLLIN | EPOLLERR | EPOLLHUP | EPOLLRDHUP;
    ev.data.u64 = SIDE_A;
    if (epoll_ctl(conn->epoll_fd, EPOLL_CTL_ADD, shared->fd_a, &ev) < 0) {
        return startup_fail(shared, on_startup_fail, user_data, errno, conn);
    }

    ev.events = EPOLLIN | EPOLLERR | EPOLLHUP | EPOLLRDHUP;
    ev.data.u64 = SIDE_B;
    if (epoll_ctl(conn->epoll_fd, EPOLL_CTL_ADD, shared->fd_b, &ev) < 0) {
        return startup_fail(shared, on_startup_fail, user_data, errno, conn);
    }

    // Initialize previous interest masks so refresh_interest() can detect changes (note: EPOLLET is always on)
    conn->prev_ev_a = EPOLLET | EPOLLIN | EPOLLERR | EPOLLHUP | EPOLLRDHUP;
    conn->prev_ev_b = EPOLLET | EPOLLIN | EPOLLERR | EPOLLHUP | EPOLLRDHUP;

    int rc = pthread_create(&conn->io_thread, NULL, io_main, conn);
    if (rc != 0) {
        return startup_fail(shared, on_startup_fail, user_data, rc, conn);
    }
    conn->io_started = 1;

    rc = pthread_create(&conn->cleanup_thread, NULL, cleanup_main, conn);
    if (rc != 0) {
        return startup_fail(shared, on_startup_fail, user_data, rc, conn);
    }
    conn->cleanup_started = 1;

    *out_conn = conn;
    return 0;
}

int lure_epoll_connection_join(LureEpollConnection* conn) {
    if (!conn) {
        return -EINVAL;
    }

    if (conn->cleanup_started) {
        int rc = pthread_join(conn->cleanup_thread, NULL);
        conn->cleanup_started = 0;
        if (rc != 0) {
            return -rc;
        }
    }

    return conn->result;
}

void lure_epoll_connection_free(LureEpollConnection* conn) {
    if (!conn) {
        return;
    }

    if (conn->cleanup_started) {
        (void)pthread_join(conn->cleanup_thread, NULL);
        conn->cleanup_started = 0;
    }

    if (conn->io_started) {
        __atomic_store_n(&conn->abort_flag, 1u, __ATOMIC_RELEASE);
        (void)pthread_join(conn->io_thread, NULL);
        conn->io_started = 0;
    }

    if (conn->epoll_fd >= 0) {
        close(conn->epoll_fd);
        conn->epoll_fd = -1;
    }

    // Close pipes
    if (conn->a2b_pipe[0] >= 0) {
        close(conn->a2b_pipe[0]);
        conn->a2b_pipe[0] = -1;
    }
    if (conn->a2b_pipe[1] >= 0) {
        close(conn->a2b_pipe[1]);
        conn->a2b_pipe[1] = -1;
    }
    if (conn->b2a_pipe[0] >= 0) {
        close(conn->b2a_pipe[0]);
        conn->b2a_pipe[0] = -1;
    }
    if (conn->b2a_pipe[1] >= 0) {
        close(conn->b2a_pipe[1]);
        conn->b2a_pipe[1] = -1;
    }

    free(conn);
}

/* ════════════════════════════════════════════════════════════════════════════
 * N-WORKER POOL
 *
 * One LureEpollWorker owns a single epoll_fd that monitors all connection FDs
 * assigned to it.  A flat slot array (WORKER_MAX_SLOTS entries, FAM) holds
 * per-connection state.  Connections are submitted from Rust via a
 * mutex-guarded queue and an eventfd wakeup; completions are reported by
 * writing a 48-byte LureEpollDone frame to a shared done-pipe.
 * ════════════════════════════════════════════════════════════════════════════ */

enum {
    WORKER_MAX_SLOTS        = 4096,
    WORKER_EPOLL_BATCH      = 64,
    WORKER_STALL_TICKS_MAX  = 12,   /* 12 × 5 s ≈ 60 s stall timeout */
};

/* Slot key encoding in epoll_event.data.u64:
 *   key = ((uint64_t)slot_idx << 1) | side
 * The eventfd uses WORKER_EVENTFD_KEY, which cannot be a valid slot key. */
#define WORKER_EVENTFD_KEY  UINT64_MAX

/* ---- per-connection slot -------------------------------------------------- */

typedef struct {
    int      fd_a, fd_b;
    uint64_t conn_id;

    int eof_a, eof_b;
    int hup_a, hup_b;
    int shut_wr_a, shut_wr_b;
    uint32_t prev_ev_a, prev_ev_b;

    int    a2b_pipe[2];     /* [0]=read [1]=write */
    int    b2a_pipe[2];
    size_t a2b_pipe_len;
    size_t b2a_pipe_len;

    LureEpollLiveBytes *live;  /* Rust-allocated live counter region (may be NULL) */

    uint32_t abort_flag;   /* set atomically from other threads */
    uint32_t stall_ticks;  /* watchdog: ticks with no delivered-byte progress */
    uint64_t prev_progress;  /* byte-progress snapshot at last watchdog pass */

    int32_t next_free;     /* free-list linkage; -1 == end of list */
    int     active;        /* 1 while slot is occupied */
} LureEpollSlot;

/* ---- pending queue nodes -------------------------------------------------- */

typedef struct PendingSubmit {
    int fd_a, fd_b;
    uint64_t conn_id;
    LureEpollLiveBytes *live;
    struct PendingSubmit *next;
} PendingSubmit;

typedef struct PendingAbort {
    uint64_t conn_id;
    struct PendingAbort *next;
} PendingAbort;

/* ---- worker --------------------------------------------------------------- */

struct LureEpollWorker {
    int epoll_fd;
    int event_fd;           /* eventfd: written to wake the worker thread */
    int done_pipe_write;    /* NOT owned; 48-byte completion frames written here */

    pthread_t       thread;
    pthread_mutex_t queue_lock;

    PendingSubmit *submit_head;
    PendingAbort  *abort_head;

    uint32_t active_count;
    int32_t  free_head;     /* index of first free slot; -1 == full */
    uint32_t shutdown;      /* atomic flag */

    uint32_t      n_slots;
    LureEpollSlot slots[];  /* FAM — n_slots elements */
};

/* ---- slot-level side_events and refresh_interest -------------------------- */

static uint32_t wslot_side_events(const LureEpollSlot *s, int side) {
    uint32_t ev = EPOLLET | EPOLLERR | EPOLLHUP | EPOLLRDHUP;
    if (side == SIDE_A) {
        if (!s->eof_a && s->a2b_pipe_len < PIPE_CAP) ev |= EPOLLIN;
        if (s->b2a_pipe_len > 0)                      ev |= EPOLLOUT;
    } else {
        if (!s->eof_b && s->b2a_pipe_len < PIPE_CAP)  ev |= EPOLLIN;
        if (s->a2b_pipe_len > 0)                       ev |= EPOLLOUT;
    }
    return ev;
}

static void wslot_refresh_interest(LureEpollWorker *w, uint32_t idx) {
    LureEpollSlot *s = &w->slots[idx];
    uint64_t key_a = ((uint64_t)idx << 1) | SIDE_A;
    uint64_t key_b = ((uint64_t)idx << 1) | SIDE_B;
    uint32_t ea = wslot_side_events(s, SIDE_A);
    uint32_t eb = wslot_side_events(s, SIDE_B);
    if (ea != s->prev_ev_a) {
        if (s->fd_a >= 0) epoll_mod(w->epoll_fd, s->fd_a, key_a, ea);
        s->prev_ev_a = ea;
    }
    if (eb != s->prev_ev_b) {
        if (s->fd_b >= 0) epoll_mod(w->epoll_fd, s->fd_b, key_b, eb);
        s->prev_ev_b = eb;
    }
}

/* ---- wslot_release: complete or error a slot and return it to free list --- */

static void wslot_release(LureEpollWorker *w, uint32_t idx, int32_t result) {
    LureEpollSlot *s = &w->slots[idx];

    /* Write 48-byte completion frame atomically (fits inside PIPE_BUF). */
    LureEpollDone done;
    memset(&done, 0, sizeof(done));
    done.conn_id    = s->conn_id;
    done.c2s_bytes  = s->live ? s->live->c2s_bytes  : 0;
    done.s2c_bytes  = s->live ? s->live->s2c_bytes  : 0;
    done.c2s_chunks = s->live ? s->live->c2s_chunks : 0;
    done.s2c_chunks = s->live ? s->live->s2c_chunks : 0;
    done.result     = result;
    (void)write(w->done_pipe_write, &done, sizeof(done));

    /* Remove FDs from epoll and close. */
    if (s->fd_a >= 0) {
        epoll_ctl(w->epoll_fd, EPOLL_CTL_DEL, s->fd_a, NULL);
        close(s->fd_a);
        s->fd_a = -1;
    }
    if (s->fd_b >= 0) {
        epoll_ctl(w->epoll_fd, EPOLL_CTL_DEL, s->fd_b, NULL);
        close(s->fd_b);
        s->fd_b = -1;
    }
    for (int i = 0; i < 2; i++) {
        if (s->a2b_pipe[i] >= 0) { close(s->a2b_pipe[i]); s->a2b_pipe[i] = -1; }
        if (s->b2a_pipe[i] >= 0) { close(s->b2a_pipe[i]); s->b2a_pipe[i] = -1; }
    }

    s->active    = 0;
    s->next_free = w->free_head;
    w->free_head = (int32_t)idx;
    w->active_count--;
}

/* ---- wsubmit_now: allocate slot and register with epoll ------------------- */

static void wsubmit_now(LureEpollWorker *w, int fd_a, int fd_b, uint64_t conn_id,
                        LureEpollLiveBytes *live) {
    /* No free slots — signal error and close fds. */
    if (w->free_head < 0) {
        LureEpollDone done;
        memset(&done, 0, sizeof(done));
        done.conn_id = conn_id;
        done.result  = -ENOSPC;
        (void)write(w->done_pipe_write, &done, sizeof(done));
        close(fd_a);
        close(fd_b);
        return;
    }

    uint32_t idx = (uint32_t)w->free_head;
    LureEpollSlot *s = &w->slots[idx];
    w->free_head = s->next_free;
    w->active_count++;  /* increment before any failure path */

    memset(s, 0, sizeof(*s));
    s->fd_a      = fd_a;
    s->fd_b      = fd_b;
    s->conn_id   = conn_id;
    s->live      = live;
    s->active    = 1;
    s->next_free = -1;
    s->a2b_pipe[0] = s->a2b_pipe[1] = -1;
    s->b2a_pipe[0] = s->b2a_pipe[1] = -1;

    int err;

    if (pipe2(s->a2b_pipe, O_NONBLOCK | O_CLOEXEC) < 0) { err = errno; goto fail; }
    if (pipe2(s->b2a_pipe, O_NONBLOCK | O_CLOEXEC) < 0) { err = errno; goto fail; }

    (void)fcntl(s->a2b_pipe[1], F_SETPIPE_SZ, PIPE_CAP);
    (void)fcntl(s->b2a_pipe[1], F_SETPIPE_SZ, PIPE_CAP);

    (void)set_nonblocking(fd_a);
    (void)set_nonblocking(fd_b);
    set_tcp_opts(fd_a);
    set_tcp_opts(fd_b);

    {
        uint64_t key_a   = ((uint64_t)idx << 1) | SIDE_A;
        uint64_t key_b   = ((uint64_t)idx << 1) | SIDE_B;
        uint32_t init_ev = EPOLLIN | EPOLLOUT | EPOLLERR | EPOLLHUP | EPOLLRDHUP | EPOLLET;
        struct epoll_event ev;
        memset(&ev, 0, sizeof(ev));

        ev.events = init_ev; ev.data.u64 = key_a;
        if (epoll_ctl(w->epoll_fd, EPOLL_CTL_ADD, fd_a, &ev) < 0) {
            err = errno;
            /* fd_a was never added, so no DEL needed */
            goto fail;
        }

        ev.events = init_ev; ev.data.u64 = key_b;
        if (epoll_ctl(w->epoll_fd, EPOLL_CTL_ADD, fd_b, &ev) < 0) {
            err = errno;
            epoll_ctl(w->epoll_fd, EPOLL_CTL_DEL, fd_a, NULL);
            goto fail;
        }

        s->prev_ev_a = init_ev;
        s->prev_ev_b = init_ev;
    }
    return;

fail:
    {
        LureEpollDone done;
        memset(&done, 0, sizeof(done));
        done.conn_id = conn_id;
        done.result  = -err;
        (void)write(w->done_pipe_write, &done, sizeof(done));
        for (int i = 0; i < 2; i++) {
            if (s->a2b_pipe[i] >= 0) { close(s->a2b_pipe[i]); s->a2b_pipe[i] = -1; }
            if (s->b2a_pipe[i] >= 0) { close(s->b2a_pipe[i]); s->b2a_pipe[i] = -1; }
        }
        if (s->fd_a >= 0) { close(s->fd_a); s->fd_a = -1; }
        if (s->fd_b >= 0) { close(s->fd_b); s->fd_b = -1; }
        s->active    = 0;
        s->next_free = w->free_head;
        w->free_head = (int32_t)idx;
        w->active_count--;
    }
}

/* ---- process one epoll event for a slot ---------------------------------- */

static void wslot_process_event(LureEpollWorker *w, uint32_t idx,
                                int side, uint32_t ev) {
    LureEpollSlot *s = &w->slots[idx];
    int want_read = (ev & (EPOLLIN | EPOLLERR | EPOLLHUP | EPOLLRDHUP)) != 0;
    if (!s->active) return;

    /* Check for externally requested abort. */
    if (__atomic_load_n(&s->abort_flag, __ATOMIC_ACQUIRE)) {
        wslot_release(w, idx, -ECANCELED);
        return;
    }

    if (ev & (EPOLLHUP | EPOLLRDHUP)) {
        if (side == SIDE_A) s->hup_a = 1;
        else                s->hup_b = 1;
    }

    if (want_read) {
        int rc;
        if (side == SIDE_A) {
            rc = splice_forward(s->fd_a, s->a2b_pipe[1], s->a2b_pipe[0],
                                s->fd_b, &s->a2b_pipe_len, &s->eof_a,
                                s->live ? &s->live->c2s_bytes : NULL,
                                s->live ? &s->live->c2s_chunks : NULL);
        } else {
            rc = splice_forward(s->fd_b, s->b2a_pipe[1], s->b2a_pipe[0],
                                s->fd_a, &s->b2a_pipe_len, &s->eof_b,
                                s->live ? &s->live->s2c_bytes : NULL,
                                s->live ? &s->live->s2c_chunks : NULL);
        }
        if (rc < 0) {
            wslot_release(w, idx, rc);
            return;
        }
    }

    if (ev & EPOLLOUT) {
        if (side == SIDE_A) {
            /* Drain b2a pipe to A (s2c direction). */
            int rc = splice_drain_pipe(
                s->b2a_pipe[0],
                s->fd_a,
                &s->b2a_pipe_len,
                s->live ? &s->live->s2c_bytes : NULL
            );
            if (rc < 0) {
                wslot_release(w, idx, rc);
                return;
            }
        } else {
            /* Drain a2b pipe to B (c2s direction). */
            int rc = splice_drain_pipe(
                s->a2b_pipe[0],
                s->fd_b,
                &s->a2b_pipe_len,
                s->live ? &s->live->c2s_bytes : NULL
            );
            if (rc < 0) {
                wslot_release(w, idx, rc);
                return;
            }
        }
    }

    if (s->hup_a && !s->eof_a && s->a2b_pipe_len < PIPE_CAP) {
        int rc = splice_forward(
            s->fd_a, s->a2b_pipe[1], s->a2b_pipe[0],
            s->fd_b, &s->a2b_pipe_len, &s->eof_a,
            s->live ? &s->live->c2s_bytes : NULL,
            s->live ? &s->live->c2s_chunks : NULL
        );
        if (rc < 0) {
            wslot_release(w, idx, rc);
            return;
        }
    }
    if (s->hup_b && !s->eof_b && s->b2a_pipe_len < PIPE_CAP) {
        int rc = splice_forward(
            s->fd_b, s->b2a_pipe[1], s->b2a_pipe[0],
            s->fd_a, &s->b2a_pipe_len, &s->eof_b,
            s->live ? &s->live->s2c_bytes : NULL,
            s->live ? &s->live->s2c_chunks : NULL
        );
        if (rc < 0) {
            wslot_release(w, idx, rc);
            return;
        }
    }

    /* Shutdown the write-side once EOF is received and its pipe is drained. */
    if (s->eof_a && !s->shut_wr_b && s->a2b_pipe_len == 0) {
        (void)shutdown(s->fd_b, SHUT_WR);
        s->shut_wr_b = 1;
    }
    if (s->eof_b && !s->shut_wr_a && s->b2a_pipe_len == 0) {
        (void)shutdown(s->fd_a, SHUT_WR);
        s->shut_wr_a = 1;
    }

    if (s->eof_a && s->eof_b && s->a2b_pipe_len == 0 && s->b2a_pipe_len == 0) {
        wslot_release(w, idx, 0);
    } else {
        wslot_refresh_interest(w, idx);
    }
}

/* ---- drain pending submit / abort queues ---------------------------------- */

static void process_submits(LureEpollWorker *w) {
    PendingSubmit *head;
    pthread_mutex_lock(&w->queue_lock);
    head           = w->submit_head;
    w->submit_head = NULL;
    pthread_mutex_unlock(&w->queue_lock);

    while (head) {
        PendingSubmit *cur = head;
        head = head->next;
        wsubmit_now(w, cur->fd_a, cur->fd_b, cur->conn_id, cur->live);
        free(cur);
    }
}

static void process_aborts(LureEpollWorker *w) {
    PendingAbort *head;
    pthread_mutex_lock(&w->queue_lock);
    head          = w->abort_head;
    w->abort_head = NULL;
    pthread_mutex_unlock(&w->queue_lock);

    while (head) {
        PendingAbort *cur = head;
        head = head->next;
        for (uint32_t i = 0; i < w->n_slots; i++) {
            if (w->slots[i].active && w->slots[i].conn_id == cur->conn_id) {
                __atomic_store_n(&w->slots[i].abort_flag, 1u, __ATOMIC_RELEASE);
                break;
            }
        }
        free(cur);
    }
}

/* ---- watchdog: abort connections stalled for ~60 s ----------------------- */

static void scan_stale_slots(LureEpollWorker *w) {
    for (uint32_t i = 0; i < w->n_slots; i++) {
        LureEpollSlot *s = &w->slots[i];
        if (!s->active) continue;

        /* Check externally-requested abort first. */
        if (__atomic_load_n(&s->abort_flag, __ATOMIC_ACQUIRE)) {
            wslot_release(w, i, -ECANCELED);
            continue;
        }

        uint64_t progress = live_progress_bytes(s->live);
        if (progress == s->prev_progress) {
            s->stall_ticks++;
            if (s->stall_ticks >= WORKER_STALL_TICKS_MAX) {
                wslot_release(w, i, -ETIMEDOUT);
                continue;
            }
        } else {
            s->stall_ticks = 0;
            s->prev_progress = progress;
        }
    }
}

/* ---- worker thread main --------------------------------------------------- */

static void *worker_thread_main(void *arg) {
    LureEpollWorker *w = (LureEpollWorker *)arg;
    struct epoll_event events[WORKER_EPOLL_BATCH];

    for (;;) {
        if (__atomic_load_n(&w->shutdown, __ATOMIC_ACQUIRE) &&
            w->active_count == 0) {
            break;
        }

        int n = epoll_wait(w->epoll_fd, events, WORKER_EPOLL_BATCH, 5000);
        if (n < 0) {
            if (errno == EINTR) continue;
            break;
        }

        for (int i = 0; i < n; i++) {
            uint64_t key = events[i].data.u64;
            uint32_t ev  = events[i].events;

            if (key == WORKER_EVENTFD_KEY) {
                /* Drain the eventfd counter, then process queued work. */
                uint64_t val;
                (void)read(w->event_fd, &val, sizeof(val));
                process_submits(w);
                process_aborts(w);
            } else {
                uint32_t slot_idx = (uint32_t)(key >> 1);
                int      side     = (int)(key & 1);
                if (slot_idx < w->n_slots) {
                    wslot_process_event(w, slot_idx, side, ev);
                }
            }
        }

        /* On timeout (n==0) run the stale-connection watchdog. */
        if (n == 0) {
            scan_stale_slots(w);
        }
    }

    return NULL;
}

/* ── Public API ─────────────────────────────────────────────────────────────── */

LureEpollWorker *lure_epoll_worker_new(int done_pipe_write_fd) {
    uint32_t n  = WORKER_MAX_SLOTS;
    size_t   sz = sizeof(LureEpollWorker) + n * sizeof(LureEpollSlot);

    LureEpollWorker *w = (LureEpollWorker *)calloc(1, sz);
    if (!w) return NULL;

    w->done_pipe_write = done_pipe_write_fd;
    w->n_slots         = n;
    w->free_head       = 0;

    /* Build the free list and initialize sentinel fd values. */
    for (uint32_t i = 0; i < n; i++) {
        w->slots[i].next_free    = (i + 1 < n) ? (int32_t)(i + 1) : -1;
        w->slots[i].fd_a         = -1;
        w->slots[i].fd_b         = -1;
        w->slots[i].a2b_pipe[0]  = w->slots[i].a2b_pipe[1] = -1;
        w->slots[i].b2a_pipe[0]  = w->slots[i].b2a_pipe[1] = -1;
    }

    if (pthread_mutex_init(&w->queue_lock, NULL) != 0) {
        free(w);
        return NULL;
    }

    w->epoll_fd = epoll_create1(EPOLL_CLOEXEC);
    if (w->epoll_fd < 0) {
        pthread_mutex_destroy(&w->queue_lock);
        free(w);
        return NULL;
    }

    w->event_fd = eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC);
    if (w->event_fd < 0) {
        close(w->epoll_fd);
        pthread_mutex_destroy(&w->queue_lock);
        free(w);
        return NULL;
    }

    struct epoll_event ev;
    memset(&ev, 0, sizeof(ev));
    ev.events   = EPOLLIN;
    ev.data.u64 = WORKER_EVENTFD_KEY;
    if (epoll_ctl(w->epoll_fd, EPOLL_CTL_ADD, w->event_fd, &ev) < 0) {
        close(w->event_fd);
        close(w->epoll_fd);
        pthread_mutex_destroy(&w->queue_lock);
        free(w);
        return NULL;
    }

    if (pthread_create(&w->thread, NULL, worker_thread_main, w) != 0) {
        close(w->event_fd);
        close(w->epoll_fd);
        pthread_mutex_destroy(&w->queue_lock);
        free(w);
        return NULL;
    }

    return w;
}

int lure_epoll_worker_submit(LureEpollWorker *w, int fd_a, int fd_b,
                             uint64_t conn_id, LureEpollLiveBytes *live) {
    PendingSubmit *node = (PendingSubmit *)malloc(sizeof(PendingSubmit));
    if (!node) {
        /* C closes the fds since caller relinquished ownership. */
        close(fd_a);
        close(fd_b);
        return -ENOMEM;
    }
    node->fd_a    = fd_a;
    node->fd_b    = fd_b;
    node->conn_id = conn_id;
    node->live    = live;
    node->next    = NULL;

    pthread_mutex_lock(&w->queue_lock);
    node->next     = w->submit_head;
    w->submit_head = node;
    pthread_mutex_unlock(&w->queue_lock);

    uint64_t val = 1;
    (void)write(w->event_fd, &val, sizeof(val));
    return 0;
}

void lure_epoll_worker_abort(LureEpollWorker *w, uint64_t conn_id) {
    PendingAbort *node = (PendingAbort *)malloc(sizeof(PendingAbort));
    if (!node) return;  /* best-effort; watchdog will catch it eventually */
    node->conn_id = conn_id;
    node->next    = NULL;

    pthread_mutex_lock(&w->queue_lock);
    node->next    = w->abort_head;
    w->abort_head = node;
    pthread_mutex_unlock(&w->queue_lock);

    uint64_t val = 1;
    (void)write(w->event_fd, &val, sizeof(val));
}

void lure_epoll_worker_shutdown(LureEpollWorker *w) {
    __atomic_store_n(&w->shutdown, 1u, __ATOMIC_RELEASE);
    uint64_t val = 1;
    (void)write(w->event_fd, &val, sizeof(val));
    pthread_join(w->thread, NULL);
}

void lure_epoll_worker_free(LureEpollWorker *w) {
    if (!w) return;
    close(w->event_fd);
    close(w->epoll_fd);
    pthread_mutex_destroy(&w->queue_lock);
    free(w);
}
