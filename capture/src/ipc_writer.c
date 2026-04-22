/*
    ipc_writer.c - Unix domain socket IPC (Inter-Process Communication), ring buffer,
    background sender

    The packet callback thread enqueues via ipc_writer_enqueue(); lock-free
    write to the ring with an atomic index update. The sender thread drains
    the ring and writes to the socket; it reconnects if the socket drops

    A doubly linked list could potentially block on the heap lock due to
    malloc(), and so a ring buffer is the preferred option.

    Ring buffer layout: head = next write position (producer), tail = next
    read position (consumer). Full condition: (head - tail) == capacity.
    Empty condition: head == tail. Single producer, single consumer - no CAS
    needed, only compiler barriers to prevent reordering
*/
#include "ipc_writer.h"
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <pthread.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <stdatomic.h>
#include <time.h>

/*
    Returns current wall-clock time in nanoseconds
    CLOCK_REALTIME is the Unix epoch clock (matches Python time.time_ns())
    tv_sec = whole seconds since epoch, tv_nsec = fractional nanoseconds
*/
static uint64_t _enqueue_ns(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

// Ring buffer

static flow_record_t ring[IPC_RING_CAPACITY];

// head: written by producer (packet callback), read by consumer (sender thread)
// tail: written by consumer, read by producer
static _Atomic uint32_t ring_head = 0;
static _Atomic uint32_t ring_tail = 0;

static _Atomic int running = 1; // set to 0 by ipc_writer_shutdown()

static uint64_t drops = 0; // flows dropped due to full ring

// Socket

static int sock_fd = -1;

static int connect_socket(void)
{
    /*
        Close any previously open socket before creating a new one
        A file descriptor is a kernel resource; leaking it would exhaust the
        process fd table after enough reconnect cycles
    */
    if (sock_fd >= 0)
    {
        close(sock_fd);
        sock_fd = -1;
    }

    /*
        AF_UNIX - Unix domain socket (local filesystem, not network)
        SOCK_STREAM - reliable, ordered, connection-oriented
        0 - default protocol for socket type
        Returns a file descriptor that represents the socket
    */
    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0)
    {
        perror("[ipc] socket()");
        return -1;
    }

    /*
        sockaddr_un is the address structure for Unix sockets
        sun_path holds the filesystem path to the socket file
        The Python server creates this file when it calls bind() +
        listen()
    */
    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, IPC_SOCKET_PATH, sizeof(addr.sun_path) - 1);

    /*
        connect() initiates the TCP-style handshake to the listening server.
        Fails immediately (ECONNREFUSED) if Python has not called listen() yet
        The sender thread calls again after 100ms backoff until it succeeds
        Cast to sockaddr* because connect() predates AF_UNIX and takes the
        generic base struct; the kernel dispatches on sun_family internally
    */
    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0)
    {
        close(fd);
        return -1;
    }

    sock_fd = fd;
    fprintf(stderr, "[ipc] connected to %s\n", IPC_SOCKET_PATH);
    return 0;
}

/*
    Write exactly n bytes; returns 0 on success, -1 on error/disconnect
    MSG_NOSIGNAL converts SIGPIPE (broken socket) to EPIPE return value so
    the sender thread can reconnect rather than killing the whole process
*/
static int write_all(int fd, const void *buf, size_t n)
{
    const uint_8 *p = buf;
    while (n > 0)
    {
        /*
            send() is like write() but for sockets and supports flags
            It may return fewer bytes than requested if the kernel socket
            buffer is nearly full - the loop retries the remainder.
            MSG_NOSIGNAL: if the peer closed the connection, return EPIPE as
            an error code instead of raising SIGPIPE, which would kill the process
        */
        ssize_t w = send(fd, p, n, MSG_NOSIGNAL);
        if (w <= 0)
            return -1; // 0 - peer closed cleanly, <0 - error
        p += w;
        n -= (size_t)w;
    }
    return 0;
}

/*
    sender_thread is the background thread that drains the ring buffer to the socket.
    Signature is void *(*)(void *) because that is what pthread_create() requires;
    the void* argument and return value are unused here
*/
static void *sender_thread(void *arg)
{
    (void)arg; // suppress unused parameter warning
    uint32_t payload_len = sizeof(flow_record_t);

    /*
        Keep running while the engine is active OR there are unsent flows
        in the ring.
        The second condition drains any remaining flows after ipc_writer_shutdown()
        sets running=0 so we don't lose the last flows on clean exit
    */
    while (atomic_load(&running) || atomic_load(&ring_head) != atomic_load(&ring_tail))
    {
        /*
            Retry every 100ms until Python server is up
            connect_socket() fails immediately if the socket file does not exist yet
        */
        while (sock_fd < 0 && atomic_load(&running))
        {
            if (connect_socket() < 0)
                usleep(100000); // usleep supresses this thread only
        }

        /*
            Snapshot head and tail. head is written by the producer (enqueue),
            tail is written here. Reading both atomically gives a consistent view
        */
        uint32_t head = atomic_load(&ring_head);
        uint32_t tail = atomic_load(&ring_tail);

        if (head == tail)
        {
            // ring is empty. Sleep 1ms. usleep() gives up the CPU usage. OS wakes up after 1ms
            usleep(1000);
            continue;
        }

        /*
           Bitmask (capacity - 1) maps the ever-increasing tail counter to a slot
           Index within [0, IPC_RING_CAPACITY]. WOrks because capacity is a power of 2
        */
        uint32_t slot = tail & (IPC_RING_CAPACITY - 1);
        const flow_record_t *flow = &ring[slot];

        /*
            Wire format: [uint32_t length][flow_record_t bytes]
            Python reads the 4-byte length first to know how many bytes follow
        */
        int err = write_all(sock_fd, &payload_len, sizeof(payload_len));
        if (err < 0)
        {
            /*
                Socket broke (Python restarted, container stopped, etc.)
                close() releases the fd; connect_socket() will reopen it next iteration
            */
            fprintf(stderr, "[ipc] send error, reconnecting...\n");
            close(sock_fd);
            sock_fd = -1;
            // Do not advance tail - retry sending this same flow after reconnect
            continue;
        }

        /*
            Advance tail only after a confirmed successful send.
            This is safe without a mutex because only this thread writes ring_tail
        */
        atomic_store(&ring_tail, tail + 1);
    }
    // Drain complete. Close the socket cleanly so Python sees EOF, not a reset.
    if (sock_fd >= 0)
    {
        close(sock_fd);
        sock_fd = -1;
    }
    return NULL;
}

// Public API

void ipc_writer_init(void)
{
    atomic_store(&ring_head, 0);
    atomic_store(&ring_tail, 0);
    atomic_store(&running, 1);

    pthread_t tid;
    pthread_attr_t attr;
    pthread_attr_init(&attr);
    /*
        PTHREAD_CREATE_DETACHED means it will never call pthread_join() on this thread.
        The OS reclaims its resources automatically when it exits, so we don't need
        to hold a reference to tid after pthread_create(). Without this, not joining
        would leak a zombie thread entry in the thread table until process exit
    */
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
    /*
        Spawn the sender thread. It starts executing sender_thread(NULL) immediately.
        The NULL is the void* argument passed to the sender thread - unused here.
    */
    pthread_create(&tid, &attr, sender_thread, NULL);
    pthread_attr_destroy(&attr);
}

void ipc_writer_enqueue(const flow_record_t *flow)
{
    /*
        Called from the packet callback thread - must return immediately
        No mutex, no malloc, no blocking calls
    */
    uint32_t head = atomic_load(&ring_head);
    uint32_t tail = atomic_load(&ring_tail);

    if (head - tail >= IPC_RING_CAPACITY)
    {
        /*
            Ring is full. Overwrite the oldest unread slot by bumping tail forward,
            effectively evicting it. This keeps the ring always accepting new flows
            at the cost of losing the oldest one. The alternative - blocking the
            packet callback - would stall pcap and drop packets at the NIC level,
            which is worse than losing one completed flow record
        */
        atomic_store(&ring_tail, tail + 1);
        drops++;
        if (drops % 100 == 0)
            fprintf(stderr, "[ipc] WARNING: ring buffer full, %llu flows dropped\n",
                    (unsigned long long)drops);
    }

    // Bitmask maps head to a slot index. Same power of 2 trick as in sender_thread.
    uint32_t slot = head & (IPC_RING_CAPACITY - 1);
    /*
        Copy before updating head so the sender sees a complete record.
        If we incremented head first, the sender could read a half-written struct
    */
    ring[slot] = *flow;
    /*
        Stamp enqueue time on the ring slot copy. This is the correct IPC-start
        timestamp: t_socket_ns - t_enqueue_ns = actual wire + decode latency
        Using first_pkt_ns instead would include the full flow lifetime.
    */
    ring[slot].t_enqueue_ns = _enqueue_ns();
    /*
        memory_order_release pairs with the sender's atomic_load (acquire)
        It guarantees that all writes above (the memcpy and timestamp) are visible
        to the sender thread before it sees the incremented head value.
        Without this, the CPU or compiler could reorder the head increment before
        the copy, and the sender would read garbage from an incomplete slot.
    */
    atomic_store_explicit(&ring_head, head + 1, memory_order_release);
}

void ipc_writer_shutdown(void)
{
    atomic_store(&running, 0);
}