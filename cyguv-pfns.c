/* Copyright mybots.org. and other Node contributors. All rights reserved.
 *
 */

/* See https://github.com/libuv/libuv#documentation for documentation. */

#ifdef __cplusplus
extern "C" {
#endif

#ifdef _WIN32
  /* Windows - set up dll import/export decorators. */
# if defined(BUILDING_UV_SHARED)
    /* Building shared library. */
#   define UV_EXTERN __declspec(dllexport)
# elif defined(USING_UV_SHARED)
    /* Using shared library. */
#   define UV_EXTERN __declspec(dllimport)
# else
    /* Building static library. */
#   define UV_EXTERN /* nothing */
# endif
#elif __GNUC__ >= 4
# define UV_EXTERN __attribute__((visibility("default")))
#else
# define UV_EXTERN /* nothing */
#endif

#include "uv-errno.h"
#include "uv-version.h"
#include <stddef.h>
#include <stdio.h>

#if defined(_MSC_VER) && _MSC_VER < 1600
# include "stdint-msvc2008.h"
#else
# include <stdint.h>
#endif

#if defined(_WIN32)
# include "uv-win.h"
#else
# include "uv-unix.h"
#endif

#include "cyguv-pfns.h"
#include <stdarg.h>

extern void cyguv_init(int force);

#define CYGUV_API_CALL(api)          (cyguv_init(0), pfn_ ## api)


UV_EXTERN unsigned int uv_version(void)
{
	return CYGUV_API_CALL(uv_version)
		();
}
UV_EXTERN const char* uv_version_string(void)
{
	return CYGUV_API_CALL(uv_version_string)
		();
}

typedef void* (*uv_malloc_func)(size_t size);
typedef void* (*uv_realloc_func)(void* ptr, size_t size);
typedef void* (*uv_calloc_func)(size_t count, size_t size);
typedef void (*uv_free_func)(void* ptr);

UV_EXTERN int uv_replace_allocator(uv_malloc_func malloc_func,
                                   uv_realloc_func realloc_func,
                                   uv_calloc_func calloc_func,
                                   uv_free_func free_func)
{
	return CYGUV_API_CALL(uv_replace_allocator)
		(malloc_func, realloc_func, calloc_func, free_func);
}

UV_EXTERN uv_loop_t* uv_default_loop(void)
{
	return CYGUV_API_CALL(uv_default_loop)
		();
}
UV_EXTERN int uv_loop_init(uv_loop_t* loop)
{
	return CYGUV_API_CALL(uv_loop_init)
		(loop);
}
UV_EXTERN int uv_loop_close(uv_loop_t* loop)
{
	return CYGUV_API_CALL(uv_loop_close)
		(loop);
}
/*
 * NOTE:
 *  This function is DEPRECATED (to be removed after 0.12), users should
 *  allocate the loop manually and use uv_loop_init instead.
 */
UV_EXTERN uv_loop_t* uv_loop_new(void)
{
	return CYGUV_API_CALL(uv_loop_new)
		();
}
/*
 * NOTE:
 *  This function is DEPRECATED (to be removed after 0.12). Users should use
 *  uv_loop_close and free the memory manually instead.
 */
UV_EXTERN void uv_loop_delete(uv_loop_t* loop)
{
	return CYGUV_API_CALL(uv_loop_delete)
		(loop);
}
UV_EXTERN size_t uv_loop_size(void)
{
	return CYGUV_API_CALL(uv_loop_size)
		();
}
UV_EXTERN int uv_loop_alive(const uv_loop_t* loop)
{
	return CYGUV_API_CALL(uv_loop_alive)
		(loop);
}
UV_EXTERN int uv_loop_configure(uv_loop_t* loop, uv_loop_option option, ...)
{
	return CYGUV_API_CALL(uv_loop_configure)
		(loop, option);
}

UV_EXTERN int uv_run(uv_loop_t* loop, uv_run_mode mode)
{
	return CYGUV_API_CALL(uv_run)
		(loop, mode);
}
UV_EXTERN void uv_stop(uv_loop_t* loop)
{
	return CYGUV_API_CALL(uv_stop)
		(loop);
}

UV_EXTERN void uv_ref(uv_handle_t* handle)
{
	return CYGUV_API_CALL(uv_ref)
		(handle);
}
UV_EXTERN void uv_unref(uv_handle_t* handle)
{
	return CYGUV_API_CALL(uv_unref)
		(handle);
}
UV_EXTERN int uv_has_ref(const uv_handle_t* handle)
{
	return CYGUV_API_CALL(uv_has_ref)
		(handle);
}

UV_EXTERN void uv_update_time(uv_loop_t* loop)
{
	return CYGUV_API_CALL(uv_update_time)
		(loop);
}
UV_EXTERN uint64_t uv_now(const uv_loop_t* loop)
{
	return CYGUV_API_CALL(uv_now)
		(loop);
}

UV_EXTERN int uv_backend_fd(const uv_loop_t* loop)
{
	return CYGUV_API_CALL(uv_backend_fd)
		(loop);
}
UV_EXTERN int uv_backend_timeout(const uv_loop_t* loop)
{
	return CYGUV_API_CALL(uv_backend_timeout)
		(loop);
}

typedef void (*uv_alloc_cb)(uv_handle_t* handle,
                            size_t suggested_size,
                            uv_buf_t* buf);
typedef void (*uv_read_cb)(uv_stream_t* stream,
                           ssize_t nread,
                           const uv_buf_t* buf);
typedef void (*uv_write_cb)(uv_write_t* req, int status);
typedef void (*uv_connect_cb)(uv_connect_t* req, int status);
typedef void (*uv_shutdown_cb)(uv_shutdown_t* req, int status);
typedef void (*uv_connection_cb)(uv_stream_t* server, int status);
typedef void (*uv_close_cb)(uv_handle_t* handle);
typedef void (*uv_poll_cb)(uv_poll_t* handle, int status, int events);
typedef void (*uv_timer_cb)(uv_timer_t* handle);
typedef void (*uv_async_cb)(uv_async_t* handle);
typedef void (*uv_prepare_cb)(uv_prepare_t* handle);
typedef void (*uv_check_cb)(uv_check_t* handle);
typedef void (*uv_idle_cb)(uv_idle_t* handle);
typedef void (*uv_exit_cb)(uv_process_t*, int64_t exit_status, int term_signal);
typedef void (*uv_walk_cb)(uv_handle_t* handle, void* arg);
typedef void (*uv_fs_cb)(uv_fs_t* req);
typedef void (*uv_work_cb)(uv_work_t* req);
typedef void (*uv_after_work_cb)(uv_work_t* req, int status);
typedef void (*uv_getaddrinfo_cb)(uv_getaddrinfo_t* req,
                                  int status,
                                  struct addrinfo* res);
typedef void (*uv_getnameinfo_cb)(uv_getnameinfo_t* req,
                                  int status,
                                  const char* hostname,
                                  const char* service);


typedef void (*uv_fs_event_cb)(uv_fs_event_t* handle,
                               const char* filename,
                               int events,
                               int status);

typedef void (*uv_fs_poll_cb)(uv_fs_poll_t* handle,
                              int status,
                              const uv_stat_t* prev,
                              const uv_stat_t* curr);

typedef void (*uv_signal_cb)(uv_signal_t* handle, int signum);


UV_EXTERN const char* uv_strerror(int err)
{
	return CYGUV_API_CALL(uv_strerror)
		(err);
}
UV_EXTERN const char* uv_err_name(int err)
{
	return CYGUV_API_CALL(uv_err_name)
		(err);
}

UV_EXTERN int uv_shutdown(uv_shutdown_t* req,
                          uv_stream_t* handle,
                          uv_shutdown_cb cb)
{
	return CYGUV_API_CALL(uv_shutdown)
		(req, handle, cb);
}

UV_EXTERN size_t uv_handle_size(uv_handle_type type)
{
	return CYGUV_API_CALL(uv_handle_size)
		(type);
}
UV_EXTERN size_t uv_req_size(uv_req_type type)
{
	return CYGUV_API_CALL(uv_req_size)
		(type);
}

UV_EXTERN int uv_is_active(const uv_handle_t* handle)
{
	return CYGUV_API_CALL(uv_is_active)
		(handle);
}

UV_EXTERN void uv_walk(uv_loop_t* loop, uv_walk_cb walk_cb, void* arg)
{
	return CYGUV_API_CALL(uv_walk)
		(loop, walk_cb, arg);
}

/* Helpers for ad hoc debugging, no API/ABI stability guaranteed. */
UV_EXTERN void uv_print_all_handles(uv_loop_t* loop, FILE* stream)
{
	return CYGUV_API_CALL(uv_print_all_handles)
		(loop, stream);
}
UV_EXTERN void uv_print_active_handles(uv_loop_t* loop, FILE* stream)
{
	return CYGUV_API_CALL(uv_print_active_handles)
		(loop, stream);
}

UV_EXTERN void uv_close(uv_handle_t* handle, uv_close_cb close_cb)
{
	return CYGUV_API_CALL(uv_close)
		(handle, close_cb);
}

UV_EXTERN int uv_send_buffer_size(uv_handle_t* handle, int* value)
{
	return CYGUV_API_CALL(uv_send_buffer_size)
		(handle, value);
}
UV_EXTERN int uv_recv_buffer_size(uv_handle_t* handle, int* value)
{
	return CYGUV_API_CALL(uv_recv_buffer_size)
		(handle, value);
}

UV_EXTERN int uv_fileno(const uv_handle_t* handle, uv_os_fd_t* fd)
{
	return CYGUV_API_CALL(uv_fileno)
		(handle, fd);
}

UV_EXTERN uv_buf_t uv_buf_init(char* base, unsigned int len)
{
	return CYGUV_API_CALL(uv_buf_init)
		(base, len);
}

UV_EXTERN int uv_listen(uv_stream_t* stream, int backlog, uv_connection_cb cb)
{
	return CYGUV_API_CALL(uv_listen)
		(stream, backlog, cb);
}
UV_EXTERN int uv_accept(uv_stream_t* server, uv_stream_t* client)
{
	return CYGUV_API_CALL(uv_accept)
		(server, client);
}

UV_EXTERN int uv_read_start(uv_stream_t* stream,
                            uv_alloc_cb alloc_cb,
                            uv_read_cb read_cb)
{
	return CYGUV_API_CALL(uv_read_start)
		(stream, alloc_cb, read_cb);
}
UV_EXTERN int uv_read_stop(uv_stream_t* stream)
{
	return CYGUV_API_CALL(uv_read_stop)
		(stream);
}

UV_EXTERN int uv_write(uv_write_t* req,
                       uv_stream_t* handle,
                       const uv_buf_t bufs[],
                       unsigned int nbufs,
                       uv_write_cb cb)
{
	return CYGUV_API_CALL(uv_write)
		(req, handle, bufs, nbufs, cb);
}
UV_EXTERN int uv_write2(uv_write_t* req,
                        uv_stream_t* handle,
                        const uv_buf_t bufs[],
                        unsigned int nbufs,
                        uv_stream_t* send_handle,
                        uv_write_cb cb)
{
	return CYGUV_API_CALL(uv_write2)
		(req, handle, bufs, nbufs, send_handle, cb);
}
UV_EXTERN int uv_try_write(uv_stream_t* handle,
                           const uv_buf_t bufs[],
                           unsigned int nbufs)
{
	return CYGUV_API_CALL(uv_try_write)
		(handle, bufs, nbufs);
}

UV_EXTERN int uv_is_readable(const uv_stream_t* handle)
{
	return CYGUV_API_CALL(uv_is_readable)
		(handle);
}
UV_EXTERN int uv_is_writable(const uv_stream_t* handle)
{
	return CYGUV_API_CALL(uv_is_writable)
		(handle);
}

UV_EXTERN int uv_stream_set_blocking(uv_stream_t* handle, int blocking)
{
	return CYGUV_API_CALL(uv_stream_set_blocking)
		(handle, blocking);
}

UV_EXTERN int uv_is_closing(const uv_handle_t* handle)
{
	return CYGUV_API_CALL(uv_is_closing)
		(handle);
}

UV_EXTERN int uv_tcp_init(uv_loop_t* loop, uv_tcp_t* handle)
{
	return CYGUV_API_CALL(uv_tcp_init)
		(loop, handle);
}
UV_EXTERN int uv_tcp_init_ex(uv_loop_t* loop, uv_tcp_t* handle, unsigned int flags)
{
	return CYGUV_API_CALL(uv_tcp_init_ex)
		(loop, handle, flags);
}
UV_EXTERN int uv_tcp_open(uv_tcp_t* handle, uv_os_sock_t sock)
{
	return CYGUV_API_CALL(uv_tcp_open)
		(handle, sock);
}
UV_EXTERN int uv_tcp_nodelay(uv_tcp_t* handle, int enable)
{
	return CYGUV_API_CALL(uv_tcp_nodelay)
		(handle, enable);
}
UV_EXTERN int uv_tcp_keepalive(uv_tcp_t* handle,
                               int enable,
                               unsigned int delay)
{
	return CYGUV_API_CALL(uv_tcp_keepalive)
		(handle, enable, delay);
}
UV_EXTERN int uv_tcp_simultaneous_accepts(uv_tcp_t* handle, int enable)
{
	return CYGUV_API_CALL(uv_tcp_simultaneous_accepts)
		(handle, enable);
}

UV_EXTERN int uv_tcp_bind(uv_tcp_t* handle,
                          const struct sockaddr* addr,
                          unsigned int flags)
{
	return CYGUV_API_CALL(uv_tcp_bind)
		(handle, addr, flags);
}
UV_EXTERN int uv_tcp_getsockname(const uv_tcp_t* handle,
                                 struct sockaddr* name,
                                 int* namelen)
{
	return CYGUV_API_CALL(uv_tcp_getsockname)
		(handle, name, namelen);
}
UV_EXTERN int uv_tcp_getpeername(const uv_tcp_t* handle,
                                 struct sockaddr* name,
                                 int* namelen)
{
	return CYGUV_API_CALL(uv_tcp_getpeername)
		(handle, name, namelen);
}
UV_EXTERN int uv_tcp_connect(uv_connect_t* req,
                             uv_tcp_t* handle,
                             const struct sockaddr* addr,
                             uv_connect_cb cb)
{
	return CYGUV_API_CALL(uv_tcp_connect)
		(req, handle, addr, cb);
}

UV_EXTERN int uv_udp_init(uv_loop_t* loop, uv_udp_t* handle)
{
	return CYGUV_API_CALL(uv_udp_init)
		(loop, handle);
}
UV_EXTERN int uv_udp_init_ex(uv_loop_t* loop, uv_udp_t* handle, unsigned int flags)
{
	return CYGUV_API_CALL(uv_udp_init_ex)
		(loop, handle, flags);
}
UV_EXTERN int uv_udp_open(uv_udp_t* handle, uv_os_sock_t sock)
{
	return CYGUV_API_CALL(uv_udp_open)
		(handle, sock);
}
UV_EXTERN int uv_udp_bind(uv_udp_t* handle,
                          const struct sockaddr* addr,
                          unsigned int flags)
{
	return CYGUV_API_CALL(uv_udp_bind)
		(handle, addr, flags);
}

UV_EXTERN int uv_udp_getsockname(const uv_udp_t* handle,
                                 struct sockaddr* name,
                                 int* namelen)
{
	return CYGUV_API_CALL(uv_udp_getsockname)
		(handle, name, namelen);
}
UV_EXTERN int uv_udp_set_membership(uv_udp_t* handle,
                                    const char* multicast_addr,
                                    const char* interface_addr,
                                    uv_membership membership)
{
	return CYGUV_API_CALL(uv_udp_set_membership)
		(handle, multicast_addr, interface_addr, membership);
}
UV_EXTERN int uv_udp_set_multicast_ttl(uv_udp_t* handle, int ttl)
{
	return CYGUV_API_CALL(uv_udp_set_multicast_ttl)
		(handle, ttl);
}
UV_EXTERN int uv_udp_set_multicast_interface(uv_udp_t* handle,
                                             const char* interface_addr)
{
	return CYGUV_API_CALL(uv_udp_set_multicast_interface)
		(handle, interface_addr);
}
UV_EXTERN int uv_udp_set_broadcast(uv_udp_t* handle, int on)
{
	return CYGUV_API_CALL(uv_udp_set_broadcast)
		(handle, on);
}
UV_EXTERN int uv_udp_set_ttl(uv_udp_t* handle, int ttl)
{
	return CYGUV_API_CALL(uv_udp_set_ttl)
		(handle, ttl);
}
UV_EXTERN int uv_udp_send(uv_udp_send_t* req,
                          uv_udp_t* handle,
                          const uv_buf_t bufs[],
                          unsigned int nbufs,
                          const struct sockaddr* addr,
                          uv_udp_send_cb send_cb)
{
	return CYGUV_API_CALL(uv_udp_send)
		(req, handle, bufs, nbufs, addr, send_cb);
}
UV_EXTERN int uv_udp_try_send(uv_udp_t* handle,
                              const uv_buf_t bufs[],
                              unsigned int nbufs,
                              const struct sockaddr* addr)
{
	return CYGUV_API_CALL(uv_udp_try_send)
		(handle, bufs, nbufs, addr);
}
UV_EXTERN int uv_udp_recv_start(uv_udp_t* handle,
                                uv_alloc_cb alloc_cb,
                                uv_udp_recv_cb recv_cb)
{
	return CYGUV_API_CALL(uv_udp_recv_start)
		(handle, alloc_cb, recv_cb);
}
UV_EXTERN int uv_udp_recv_stop(uv_udp_t* handle)
{
	return CYGUV_API_CALL(uv_udp_recv_stop)
		(handle);
}

UV_EXTERN int uv_tty_init(uv_loop_t* loop, uv_tty_t* tty, uv_file fd, int readable)
{
	return CYGUV_API_CALL(uv_tty_init)
		(loop, tty, fd, readable);
}
UV_EXTERN int uv_tty_set_mode(uv_tty_t* tty, uv_tty_mode_t mode)
{
	return CYGUV_API_CALL(uv_tty_set_mode)
		(tty, mode);
}
UV_EXTERN int uv_tty_reset_mode(void)
{
	return CYGUV_API_CALL(uv_tty_reset_mode)
		();
}
UV_EXTERN int uv_tty_get_winsize(uv_tty_t* tty, int* width, int* height)
{
	return CYGUV_API_CALL(uv_tty_get_winsize)
		(tty, width, height);
}

#ifdef __cplusplus
extern "C++" {

inline int uv_tty_set_mode(uv_tty_t* handle, int mode) {
  return uv_tty_set_mode(handle, static_cast<uv_tty_mode_t>(mode));
}

}
#endif

UV_EXTERN uv_handle_type uv_guess_handle(uv_file file)
{
	return CYGUV_API_CALL(uv_guess_handle)
		(file);
}

UV_EXTERN int uv_pipe_init(uv_loop_t* loop, uv_pipe_t* handle, int ipc)
{
	return CYGUV_API_CALL(uv_pipe_init)
		(loop, handle, ipc);
}
UV_EXTERN int uv_pipe_open(uv_pipe_t* pipe, uv_file file)
{
	return CYGUV_API_CALL(uv_pipe_open)
		(pipe, file);
}
UV_EXTERN int uv_pipe_bind(uv_pipe_t* handle, const char* name)
{
	return CYGUV_API_CALL(uv_pipe_bind)
		(handle, name);
}
UV_EXTERN void uv_pipe_connect(uv_connect_t* req,
                               uv_pipe_t* handle,
                               const char* name,
                               uv_connect_cb cb)
{
	return CYGUV_API_CALL(uv_pipe_connect)
		(req, handle, name, cb);
}
UV_EXTERN int uv_pipe_getsockname(const uv_pipe_t* handle,
                                  char* buffer,
                                  size_t* size)
{
	return CYGUV_API_CALL(uv_pipe_getsockname)
		(handle, buffer, size);
}
UV_EXTERN int uv_pipe_getpeername(const uv_pipe_t* handle,
                                  char* buffer,
                                  size_t* size)
{
	return CYGUV_API_CALL(uv_pipe_getpeername)
		(handle, buffer, size);
}
UV_EXTERN void uv_pipe_pending_instances(uv_pipe_t* handle, int count)
{
	return CYGUV_API_CALL(uv_pipe_pending_instances)
		(handle, count);
}
UV_EXTERN int uv_pipe_pending_count(uv_pipe_t* handle)
{
	return CYGUV_API_CALL(uv_pipe_pending_count)
		(handle);
}
UV_EXTERN uv_handle_type uv_pipe_pending_type(uv_pipe_t* handle)
{
	return CYGUV_API_CALL(uv_pipe_pending_type)
		(handle);
}

UV_EXTERN int uv_poll_init(uv_loop_t* loop, uv_poll_t* handle, int fd)
{
	return CYGUV_API_CALL(uv_poll_init)
		(loop, handle, fd);
}
UV_EXTERN int uv_poll_init_socket(uv_loop_t* loop,
                                  uv_poll_t* handle,
                                  uv_os_sock_t socket)
{
	return CYGUV_API_CALL(uv_poll_init_socket)
		(loop, handle, socket);
}
UV_EXTERN int uv_poll_start(uv_poll_t* handle, int events, uv_poll_cb cb)
{
	return CYGUV_API_CALL(uv_poll_start)
		(handle, events, cb);
}
UV_EXTERN int uv_poll_stop(uv_poll_t* handle)
{
	return CYGUV_API_CALL(uv_poll_stop)
		(handle);
}

UV_EXTERN int uv_prepare_init(uv_loop_t* loop, uv_prepare_t* prepare)
{
	return CYGUV_API_CALL(uv_prepare_init)
		(loop, prepare);
}
UV_EXTERN int uv_prepare_start(uv_prepare_t* prepare, uv_prepare_cb cb)
{
	return CYGUV_API_CALL(uv_prepare_start)
		(prepare, cb);
}
UV_EXTERN int uv_prepare_stop(uv_prepare_t* prepare)
{
	return CYGUV_API_CALL(uv_prepare_stop)
		(prepare);
}

UV_EXTERN int uv_check_init(uv_loop_t* loop, uv_check_t* check)
{
	return CYGUV_API_CALL(uv_check_init)
		(loop, check);
}
UV_EXTERN int uv_check_start(uv_check_t* check, uv_check_cb cb)
{
	return CYGUV_API_CALL(uv_check_start)
		(check, cb);
}
UV_EXTERN int uv_check_stop(uv_check_t* check)
{
	return CYGUV_API_CALL(uv_check_stop)
		(check);
}

UV_EXTERN int uv_idle_init(uv_loop_t* loop, uv_idle_t* idle)
{
	return CYGUV_API_CALL(uv_idle_init)
		(loop, idle);
}
UV_EXTERN int uv_idle_start(uv_idle_t* idle, uv_idle_cb cb)
{
	return CYGUV_API_CALL(uv_idle_start)
		(idle, cb);
}
UV_EXTERN int uv_idle_stop(uv_idle_t* idle)
{
	return CYGUV_API_CALL(uv_idle_stop)
		(idle);
}

UV_EXTERN int uv_async_init(uv_loop_t* loop,
                            uv_async_t* async,
                            uv_async_cb async_cb)
{
	return CYGUV_API_CALL(uv_async_init)
		(loop, async, async_cb);
}
UV_EXTERN int uv_async_send(uv_async_t* async)
{
	return CYGUV_API_CALL(uv_async_send)
		(async);
}

UV_EXTERN int uv_timer_init(uv_loop_t* loop, uv_timer_t* handle)
{
	return CYGUV_API_CALL(uv_timer_init)
		(loop, handle);
}
UV_EXTERN int uv_timer_start(uv_timer_t* handle,
                             uv_timer_cb cb,
                             uint64_t timeout,
                             uint64_t repeat)
{
	return CYGUV_API_CALL(uv_timer_start)
		(handle, cb, timeout, repeat);
}
UV_EXTERN int uv_timer_stop(uv_timer_t* handle)
{
	return CYGUV_API_CALL(uv_timer_stop)
		(handle);
}
UV_EXTERN int uv_timer_again(uv_timer_t* handle)
{
	return CYGUV_API_CALL(uv_timer_again)
		(handle);
}
UV_EXTERN void uv_timer_set_repeat(uv_timer_t* handle, uint64_t repeat)
{
	return CYGUV_API_CALL(uv_timer_set_repeat)
		(handle, repeat);
}
UV_EXTERN uint64_t uv_timer_get_repeat(const uv_timer_t* handle)
{
	return CYGUV_API_CALL(uv_timer_get_repeat)
		(handle);
}

UV_EXTERN int uv_getaddrinfo(uv_loop_t* loop,
                             uv_getaddrinfo_t* req,
                             uv_getaddrinfo_cb getaddrinfo_cb,
                             const char* node,
                             const char* service,
                             const struct addrinfo* hints)
{
	return CYGUV_API_CALL(uv_getaddrinfo)
		(loop, req, getaddrinfo_cb, node, service, hints);
}
UV_EXTERN void uv_freeaddrinfo(struct addrinfo* ai)
{
	return CYGUV_API_CALL(uv_freeaddrinfo)
		(ai);
}

UV_EXTERN int uv_getnameinfo(uv_loop_t* loop,
                             uv_getnameinfo_t* req,
                             uv_getnameinfo_cb getnameinfo_cb,
                             const struct sockaddr* addr,
                             int flags)
{
	return CYGUV_API_CALL(uv_getnameinfo)
		(loop, req, getnameinfo_cb, addr, flags);
}

UV_EXTERN int uv_spawn(uv_loop_t* loop,
                       uv_process_t* handle,
                       const uv_process_options_t* options)
{
	return CYGUV_API_CALL(uv_spawn)
		(loop, handle, options);
}
UV_EXTERN int uv_process_kill(uv_process_t* process, int signum)
{
	return CYGUV_API_CALL(uv_process_kill)
		(process, signum);
}
UV_EXTERN int uv_kill(int pid, int signum)
{
	return CYGUV_API_CALL(uv_kill)
		(pid, signum);
}

UV_EXTERN int uv_queue_work(uv_loop_t* loop,
                            uv_work_t* req,
                            uv_work_cb work_cb,
                            uv_after_work_cb after_work_cb)
{
	return CYGUV_API_CALL(uv_queue_work)
		(loop, req, work_cb, after_work_cb);
}

UV_EXTERN int uv_cancel(uv_req_t* req)
{
	return CYGUV_API_CALL(uv_cancel)
		(req);
}

UV_EXTERN char** uv_setup_args(int argc, char** argv)
{
	return CYGUV_API_CALL(uv_setup_args)
		(argc, argv);
}
UV_EXTERN int uv_get_process_title(char* buffer, size_t size)
{
	return CYGUV_API_CALL(uv_get_process_title)
		(buffer, size);
}
UV_EXTERN int uv_set_process_title(const char* title)
{
	return CYGUV_API_CALL(uv_set_process_title)
		(title);
}
UV_EXTERN int uv_resident_set_memory(size_t* rss)
{
	return CYGUV_API_CALL(uv_resident_set_memory)
		(rss);
}
UV_EXTERN int uv_uptime(double* uptime)
{
	return CYGUV_API_CALL(uv_uptime)
		(uptime);
}

UV_EXTERN int uv_getrusage(uv_rusage_t* rusage)
{
	return CYGUV_API_CALL(uv_getrusage)
		(rusage);
}

UV_EXTERN int uv_os_homedir(char* buffer, size_t* size)
{
	return CYGUV_API_CALL(uv_os_homedir)
		(buffer, size);
}
UV_EXTERN int uv_os_tmpdir(char* buffer, size_t* size)
{
	return CYGUV_API_CALL(uv_os_tmpdir)
		(buffer, size);
}
UV_EXTERN int uv_os_get_passwd(uv_passwd_t* pwd)
{
	return CYGUV_API_CALL(uv_os_get_passwd)
		(pwd);
}
UV_EXTERN void uv_os_free_passwd(uv_passwd_t* pwd)
{
	return CYGUV_API_CALL(uv_os_free_passwd)
		(pwd);
}

UV_EXTERN int uv_cpu_info(uv_cpu_info_t** cpu_infos, int* count)
{
	return CYGUV_API_CALL(uv_cpu_info)
		(cpu_infos, count);
}
UV_EXTERN void uv_free_cpu_info(uv_cpu_info_t* cpu_infos, int count)
{
	return CYGUV_API_CALL(uv_free_cpu_info)
		(cpu_infos, count);
}

UV_EXTERN int uv_interface_addresses(uv_interface_address_t** addresses,
                                     int* count)
{
	return CYGUV_API_CALL(uv_interface_addresses)
		(addresses, count);
}
UV_EXTERN void uv_free_interface_addresses(uv_interface_address_t* addresses,
                                           int count)
{
	return CYGUV_API_CALL(uv_free_interface_addresses)
		(addresses, count);
}

UV_EXTERN void uv_fs_req_cleanup(uv_fs_t* req)
{
	return CYGUV_API_CALL(uv_fs_req_cleanup)
		(req);
}
UV_EXTERN int uv_fs_close(uv_loop_t* loop,
                          uv_fs_t* req,
                          uv_file file,
                          uv_fs_cb cb)
{
	return CYGUV_API_CALL(uv_fs_close)
		(loop, req, file, cb);
}
UV_EXTERN int uv_fs_open(uv_loop_t* loop,
                         uv_fs_t* req,
                         const char* path,
                         int flags,
                         int mode,
                         uv_fs_cb cb)
{
	return CYGUV_API_CALL(uv_fs_open)
		(loop, req, path, flags, mode, cb);
}
UV_EXTERN int uv_fs_read(uv_loop_t* loop,
                         uv_fs_t* req,
                         uv_file file,
                         const uv_buf_t bufs[],
                         unsigned int nbufs,
                         int64_t offset,
                         uv_fs_cb cb)
{
	return CYGUV_API_CALL(uv_fs_read)
		(loop, req, file, bufs, nbufs, offset, cb);
}
UV_EXTERN int uv_fs_unlink(uv_loop_t* loop,
                           uv_fs_t* req,
                           const char* path,
                           uv_fs_cb cb)
{
	return CYGUV_API_CALL(uv_fs_unlink)
		(loop, req, path, cb);
}
UV_EXTERN int uv_fs_write(uv_loop_t* loop,
                          uv_fs_t* req,
                          uv_file file,
                          const uv_buf_t bufs[],
                          unsigned int nbufs,
                          int64_t offset,
                          uv_fs_cb cb)
{
	return CYGUV_API_CALL(uv_fs_write)
		(loop, req, file, bufs, nbufs, offset, cb);
}
UV_EXTERN int uv_fs_mkdir(uv_loop_t* loop,
                          uv_fs_t* req,
                          const char* path,
                          int mode,
                          uv_fs_cb cb)
{
	return CYGUV_API_CALL(uv_fs_mkdir)
		(loop, req, path, mode, cb);
}
UV_EXTERN int uv_fs_mkdtemp(uv_loop_t* loop,
                            uv_fs_t* req,
                            const char* tpl,
                            uv_fs_cb cb)
{
	return CYGUV_API_CALL(uv_fs_mkdtemp)
		(loop, req, tpl, cb);
}
UV_EXTERN int uv_fs_rmdir(uv_loop_t* loop,
                          uv_fs_t* req,
                          const char* path,
                          uv_fs_cb cb)
{
	return CYGUV_API_CALL(uv_fs_rmdir)
		(loop, req, path, cb);
}
UV_EXTERN int uv_fs_scandir(uv_loop_t* loop,
                            uv_fs_t* req,
                            const char* path,
                            int flags,
                            uv_fs_cb cb)
{
	return CYGUV_API_CALL(uv_fs_scandir)
		(loop, req, path, flags, cb);
}
UV_EXTERN int uv_fs_scandir_next(uv_fs_t* req,
                                 uv_dirent_t* ent)
{
	return CYGUV_API_CALL(uv_fs_scandir_next)
		(req, ent);
}
UV_EXTERN int uv_fs_stat(uv_loop_t* loop,
                         uv_fs_t* req,
                         const char* path,
                         uv_fs_cb cb)
{
	return CYGUV_API_CALL(uv_fs_stat)
		(loop, req, path, cb);
}
UV_EXTERN int uv_fs_fstat(uv_loop_t* loop,
                          uv_fs_t* req,
                          uv_file file,
                          uv_fs_cb cb)
{
	return CYGUV_API_CALL(uv_fs_fstat)
		(loop, req, file, cb);
}
UV_EXTERN int uv_fs_rename(uv_loop_t* loop,
                           uv_fs_t* req,
                           const char* path,
                           const char* new_path,
                           uv_fs_cb cb)
{
	return CYGUV_API_CALL(uv_fs_rename)
		(loop, req, path, new_path, cb);
}
UV_EXTERN int uv_fs_fsync(uv_loop_t* loop,
                          uv_fs_t* req,
                          uv_file file,
                          uv_fs_cb cb)
{
	return CYGUV_API_CALL(uv_fs_fsync)
		(loop, req, file, cb);
}
UV_EXTERN int uv_fs_fdatasync(uv_loop_t* loop,
                              uv_fs_t* req,
                              uv_file file,
                              uv_fs_cb cb)
{
	return CYGUV_API_CALL(uv_fs_fdatasync)
		(loop, req, file, cb);
}
UV_EXTERN int uv_fs_ftruncate(uv_loop_t* loop,
                              uv_fs_t* req,
                              uv_file file,
                              int64_t offset,
                              uv_fs_cb cb)
{
	return CYGUV_API_CALL(uv_fs_ftruncate)
		(loop, req, file, offset, cb);
}
UV_EXTERN int uv_fs_sendfile(uv_loop_t* loop,
                             uv_fs_t* req,
                             uv_file out_fd,
                             uv_file in_fd,
                             int64_t in_offset,
                             size_t length,
                             uv_fs_cb cb)
{
	return CYGUV_API_CALL(uv_fs_sendfile)
		(loop, req, out_fd, in_fd, in_offset, length, cb);
}
UV_EXTERN int uv_fs_access(uv_loop_t* loop,
                           uv_fs_t* req,
                           const char* path,
                           int mode,
                           uv_fs_cb cb)
{
	return CYGUV_API_CALL(uv_fs_access)
		(loop, req, path, mode, cb);
}
UV_EXTERN int uv_fs_chmod(uv_loop_t* loop,
                          uv_fs_t* req,
                          const char* path,
                          int mode,
                          uv_fs_cb cb)
{
	return CYGUV_API_CALL(uv_fs_chmod)
		(loop, req, path, mode, cb);
}
UV_EXTERN int uv_fs_utime(uv_loop_t* loop,
                          uv_fs_t* req,
                          const char* path,
                          double atime,
                          double mtime,
                          uv_fs_cb cb)
{
	return CYGUV_API_CALL(uv_fs_utime)
		(loop, req, path, atime, mtime, cb);
}
UV_EXTERN int uv_fs_futime(uv_loop_t* loop,
                           uv_fs_t* req,
                           uv_file file,
                           double atime,
                           double mtime,
                           uv_fs_cb cb)
{
	return CYGUV_API_CALL(uv_fs_futime)
		(loop, req, file, atime, mtime, cb);
}
UV_EXTERN int uv_fs_lstat(uv_loop_t* loop,
                          uv_fs_t* req,
                          const char* path,
                          uv_fs_cb cb)
{
	return CYGUV_API_CALL(uv_fs_lstat)
		(loop, req, path, cb);
}
UV_EXTERN int uv_fs_link(uv_loop_t* loop,
                         uv_fs_t* req,
                         const char* path,
                         const char* new_path,
                         uv_fs_cb cb)
{
	return CYGUV_API_CALL(uv_fs_link)
		(loop, req, path, new_path, cb);
}

UV_EXTERN int uv_fs_symlink(uv_loop_t* loop,
                            uv_fs_t* req,
                            const char* path,
                            const char* new_path,
                            int flags,
                            uv_fs_cb cb)
{
	return CYGUV_API_CALL(uv_fs_symlink)
		(loop, req, path, new_path, flags, cb);
}
UV_EXTERN int uv_fs_readlink(uv_loop_t* loop,
                             uv_fs_t* req,
                             const char* path,
                             uv_fs_cb cb)
{
	return CYGUV_API_CALL(uv_fs_readlink)
		(loop, req, path, cb);
}
UV_EXTERN int uv_fs_realpath(uv_loop_t* loop,
                             uv_fs_t* req,
                             const char* path,
                             uv_fs_cb cb)
{
	return CYGUV_API_CALL(uv_fs_realpath)
		(loop, req, path, cb);
}
UV_EXTERN int uv_fs_fchmod(uv_loop_t* loop,
                           uv_fs_t* req,
                           uv_file file,
                           int mode,
                           uv_fs_cb cb)
{
	return CYGUV_API_CALL(uv_fs_fchmod)
		(loop, req, file, mode, cb);
}
UV_EXTERN int uv_fs_chown(uv_loop_t* loop,
                          uv_fs_t* req,
                          const char* path,
                          uv_uid_t uid,
                          uv_gid_t gid,
                          uv_fs_cb cb)
{
	return CYGUV_API_CALL(uv_fs_chown)
		(loop, req, path, uid, gid, cb);
}
UV_EXTERN int uv_fs_fchown(uv_loop_t* loop,
                           uv_fs_t* req,
                           uv_file file,
                           uv_uid_t uid,
                           uv_gid_t gid,
                           uv_fs_cb cb)
{
	return CYGUV_API_CALL(uv_fs_fchown)
		(loop, req, file, uid, gid, cb);
}

UV_EXTERN int uv_fs_poll_init(uv_loop_t* loop, uv_fs_poll_t* handle)
{
	return CYGUV_API_CALL(uv_fs_poll_init)
		(loop, handle);
}
UV_EXTERN int uv_fs_poll_start(uv_fs_poll_t* handle,
                               uv_fs_poll_cb poll_cb,
                               const char* path,
                               unsigned int interval)
{
	return CYGUV_API_CALL(uv_fs_poll_start)
		(handle, poll_cb, path, interval);
}
UV_EXTERN int uv_fs_poll_stop(uv_fs_poll_t* handle)
{
	return CYGUV_API_CALL(uv_fs_poll_stop)
		(handle);
}
UV_EXTERN int uv_fs_poll_getpath(uv_fs_poll_t* handle,
                                 char* buffer,
                                 size_t* size)
{
	return CYGUV_API_CALL(uv_fs_poll_getpath)
		(handle, buffer, size);
}

UV_EXTERN int uv_signal_init(uv_loop_t* loop, uv_signal_t* handle)
{
	return CYGUV_API_CALL(uv_signal_init)
		(loop, handle);
}
UV_EXTERN int uv_signal_start(uv_signal_t* handle,
                              uv_signal_cb signal_cb,
                              int signum)
{
	return CYGUV_API_CALL(uv_signal_start)
		(handle, signal_cb, signum);
}
UV_EXTERN int uv_signal_stop(uv_signal_t* handle)
{
	return CYGUV_API_CALL(uv_signal_stop)
		(handle);
}

UV_EXTERN void uv_loadavg(double avg[3])
{
	return CYGUV_API_CALL(uv_loadavg)
		(avg);
}

UV_EXTERN int uv_fs_event_init(uv_loop_t* loop, uv_fs_event_t* handle)
{
	return CYGUV_API_CALL(uv_fs_event_init)
		(loop, handle);
}
UV_EXTERN int uv_fs_event_start(uv_fs_event_t* handle,
                                uv_fs_event_cb cb,
                                const char* path,
                                unsigned int flags)
{
	return CYGUV_API_CALL(uv_fs_event_start)
		(handle, cb, path, flags);
}
UV_EXTERN int uv_fs_event_stop(uv_fs_event_t* handle)
{
	return CYGUV_API_CALL(uv_fs_event_stop)
		(handle);
}
UV_EXTERN int uv_fs_event_getpath(uv_fs_event_t* handle,
                                  char* buffer,
                                  size_t* size)
{
	return CYGUV_API_CALL(uv_fs_event_getpath)
		(handle, buffer, size);
}

UV_EXTERN int uv_ip4_addr(const char* ip, int port, struct sockaddr_in* addr)
{
	return CYGUV_API_CALL(uv_ip4_addr)
		(ip, port, addr);
}
UV_EXTERN int uv_ip6_addr(const char* ip, int port, struct sockaddr_in6* addr)
{
	return CYGUV_API_CALL(uv_ip6_addr)
		(ip, port, addr);
}

UV_EXTERN int uv_ip4_name(const struct sockaddr_in* src, char* dst, size_t size)
{
	return CYGUV_API_CALL(uv_ip4_name)
		(src, dst, size);
}
UV_EXTERN int uv_ip6_name(const struct sockaddr_in6* src, char* dst, size_t size)
{
	return CYGUV_API_CALL(uv_ip6_name)
		(src, dst, size);
}

UV_EXTERN int uv_inet_ntop(int af, const void* src, char* dst, size_t size)
{
	return CYGUV_API_CALL(uv_inet_ntop)
		(af, src, dst, size);
}
UV_EXTERN int uv_inet_pton(int af, const char* src, void* dst)
{
	return CYGUV_API_CALL(uv_inet_pton)
		(af, src, dst);
}

UV_EXTERN int uv_exepath(char* buffer, size_t* size)
{
	return CYGUV_API_CALL(uv_exepath)
		(buffer, size);
}

UV_EXTERN int uv_cwd(char* buffer, size_t* size)
{
	return CYGUV_API_CALL(uv_cwd)
		(buffer, size);
}

UV_EXTERN int uv_chdir(const char* dir)
{
	return CYGUV_API_CALL(uv_chdir)
		(dir);
}

UV_EXTERN uint64_t uv_get_free_memory(void)
{
	return CYGUV_API_CALL(uv_get_free_memory)
		();
}
UV_EXTERN uint64_t uv_get_total_memory(void)
{
	return CYGUV_API_CALL(uv_get_total_memory)
		();
}

UV_EXTERN uint64_t uv_hrtime(void)
{
	return CYGUV_API_CALL(uv_hrtime)
		();
}

UV_EXTERN void uv_disable_stdio_inheritance(void)
{
	return CYGUV_API_CALL(uv_disable_stdio_inheritance)
		();
}

UV_EXTERN int uv_dlopen(const char* filename, uv_lib_t* lib)
{
	return CYGUV_API_CALL(uv_dlopen)
		(filename, lib);
}
UV_EXTERN void uv_dlclose(uv_lib_t* lib)
{
	return CYGUV_API_CALL(uv_dlclose)
		(lib);
}
UV_EXTERN int uv_dlsym(uv_lib_t* lib, const char* name, void** ptr)
{
	return CYGUV_API_CALL(uv_dlsym)
		(lib, name, ptr);
}
UV_EXTERN const char* uv_dlerror(const uv_lib_t* lib)
{
	return CYGUV_API_CALL(uv_dlerror)
		(lib);
}

UV_EXTERN int uv_mutex_init(uv_mutex_t* handle)
{
	return CYGUV_API_CALL(uv_mutex_init)
		(handle);
}
UV_EXTERN void uv_mutex_destroy(uv_mutex_t* handle)
{
	return CYGUV_API_CALL(uv_mutex_destroy)
		(handle);
}
UV_EXTERN void uv_mutex_lock(uv_mutex_t* handle)
{
	return CYGUV_API_CALL(uv_mutex_lock)
		(handle);
}
UV_EXTERN int uv_mutex_trylock(uv_mutex_t* handle)
{
	return CYGUV_API_CALL(uv_mutex_trylock)
		(handle);
}
UV_EXTERN void uv_mutex_unlock(uv_mutex_t* handle)
{
	return CYGUV_API_CALL(uv_mutex_unlock)
		(handle);
}

UV_EXTERN int uv_rwlock_init(uv_rwlock_t* rwlock)
{
	return CYGUV_API_CALL(uv_rwlock_init)
		(rwlock);
}
UV_EXTERN void uv_rwlock_destroy(uv_rwlock_t* rwlock)
{
	return CYGUV_API_CALL(uv_rwlock_destroy)
		(rwlock);
}
UV_EXTERN void uv_rwlock_rdlock(uv_rwlock_t* rwlock)
{
	return CYGUV_API_CALL(uv_rwlock_rdlock)
		(rwlock);
}
UV_EXTERN int uv_rwlock_tryrdlock(uv_rwlock_t* rwlock)
{
	return CYGUV_API_CALL(uv_rwlock_tryrdlock)
		(rwlock);
}
UV_EXTERN void uv_rwlock_rdunlock(uv_rwlock_t* rwlock)
{
	return CYGUV_API_CALL(uv_rwlock_rdunlock)
		(rwlock);
}
UV_EXTERN void uv_rwlock_wrlock(uv_rwlock_t* rwlock)
{
	return CYGUV_API_CALL(uv_rwlock_wrlock)
		(rwlock);
}
UV_EXTERN int uv_rwlock_trywrlock(uv_rwlock_t* rwlock)
{
	return CYGUV_API_CALL(uv_rwlock_trywrlock)
		(rwlock);
}
UV_EXTERN void uv_rwlock_wrunlock(uv_rwlock_t* rwlock)
{
	return CYGUV_API_CALL(uv_rwlock_wrunlock)
		(rwlock);
}

UV_EXTERN int uv_sem_init(uv_sem_t* sem, unsigned int value)
{
	return CYGUV_API_CALL(uv_sem_init)
		(sem, value);
}
UV_EXTERN void uv_sem_destroy(uv_sem_t* sem)
{
	return CYGUV_API_CALL(uv_sem_destroy)
		(sem);
}
UV_EXTERN void uv_sem_post(uv_sem_t* sem)
{
	return CYGUV_API_CALL(uv_sem_post)
		(sem);
}
UV_EXTERN void uv_sem_wait(uv_sem_t* sem)
{
	return CYGUV_API_CALL(uv_sem_wait)
		(sem);
}
UV_EXTERN int uv_sem_trywait(uv_sem_t* sem)
{
	return CYGUV_API_CALL(uv_sem_trywait)
		(sem);
}

UV_EXTERN int uv_cond_init(uv_cond_t* cond)
{
	return CYGUV_API_CALL(uv_cond_init)
		(cond);
}
UV_EXTERN void uv_cond_destroy(uv_cond_t* cond)
{
	return CYGUV_API_CALL(uv_cond_destroy)
		(cond);
}
UV_EXTERN void uv_cond_signal(uv_cond_t* cond)
{
	return CYGUV_API_CALL(uv_cond_signal)
		(cond);
}
UV_EXTERN void uv_cond_broadcast(uv_cond_t* cond)
{
	return CYGUV_API_CALL(uv_cond_broadcast)
		(cond);
}

UV_EXTERN int uv_barrier_init(uv_barrier_t* barrier, unsigned int count)
{
	return CYGUV_API_CALL(uv_barrier_init)
		(barrier, count);
}
UV_EXTERN void uv_barrier_destroy(uv_barrier_t* barrier)
{
	return CYGUV_API_CALL(uv_barrier_destroy)
		(barrier);
}
UV_EXTERN int uv_barrier_wait(uv_barrier_t* barrier)
{
	return CYGUV_API_CALL(uv_barrier_wait)
		(barrier);
}

UV_EXTERN void uv_cond_wait(uv_cond_t* cond, uv_mutex_t* mutex)
{
	return CYGUV_API_CALL(uv_cond_wait)
		(cond, mutex);
}
UV_EXTERN int uv_cond_timedwait(uv_cond_t* cond,
                                uv_mutex_t* mutex,
                                uint64_t timeout)
{
	return CYGUV_API_CALL(uv_cond_timedwait)
		(cond, mutex, timeout);
}

UV_EXTERN void uv_once(uv_once_t* guard, void (*callback)(void))
{
	return CYGUV_API_CALL(uv_once)
		(guard, callback);
}

UV_EXTERN int uv_key_create(uv_key_t* key)
{
	return CYGUV_API_CALL(uv_key_create)
		(key);
}
UV_EXTERN void uv_key_delete(uv_key_t* key)
{
	return CYGUV_API_CALL(uv_key_delete)
		(key);
}
UV_EXTERN void* uv_key_get(uv_key_t* key)
{
	return CYGUV_API_CALL(uv_key_get)
		(key);
}
UV_EXTERN void uv_key_set(uv_key_t* key, void* value)
{
	return CYGUV_API_CALL(uv_key_set)
		(key, value);
}

UV_EXTERN int uv_thread_create(uv_thread_t* tid, uv_thread_cb entry, void* arg)
{
	return CYGUV_API_CALL(uv_thread_create)
		(tid, entry, arg);
}
UV_EXTERN uv_thread_t uv_thread_self(void)
{
	return CYGUV_API_CALL(uv_thread_self)
		();
}
UV_EXTERN int uv_thread_join(uv_thread_t *tid)
{
	return CYGUV_API_CALL(uv_thread_join)
		(tid);
}
UV_EXTERN int uv_thread_equal(const uv_thread_t* t1, const uv_thread_t* t2)
{
	return CYGUV_API_CALL(uv_thread_equal)
		(t1, t2);
}

#ifdef __cplusplus
}
#endif
