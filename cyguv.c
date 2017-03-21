
#include <stdlib.h>
#include <dlfcn.h>
#include <pthread.h>
#include <string.h>
#include <unistd.h>
#include <sys/cygwin.h>

#include "cyguv-pfns.h"
#include "cyguv-pfns.c"

static void *cyguv_init_internal();
static void *cyguv_init_fail();

static pthread_mutex_t cyguv_mutex = PTHREAD_MUTEX_INITIALIZER;
static void *cyguv_handle = 0;

void __attribute__((constructor))
cyguv_init(int force)
{
    pthread_mutex_lock(&cyguv_mutex);
    if (force || 0 == cyguv_handle)
        cyguv_handle = cyguv_init_internal();
    pthread_mutex_unlock(&cyguv_mutex);
}

#define CYGUV_GET_API(h, n)           \
    if (0 == (*(void **)&(pfn_ ## n) = dlsym(h, #n)))\
        return cyguv_init_fail();

static void *cyguv_init_internal()
{
    void *h;

    h = dlopen("libuv.dll", RTLD_NOW);
    if (0 == h)
    {
        h = dlopen("/bin/libuv.dll", RTLD_NOW);
        if (0 == h)
            return cyguv_init_fail();
    }

    /* uv.h */
	CYGUV_GET_API(h, uv_accept);
	//CYGUV_GET_API(h, uv_async_close);
	//CYGUV_GET_API(h, uv_async_endgame);
	CYGUV_GET_API(h, uv_async_init);
	CYGUV_GET_API(h, uv_async_send);
	CYGUV_GET_API(h, uv_backend_fd);
	CYGUV_GET_API(h, uv_backend_timeout);
	CYGUV_GET_API(h, uv_barrier_destroy);
	CYGUV_GET_API(h, uv_barrier_init);
	CYGUV_GET_API(h, uv_barrier_wait);
	CYGUV_GET_API(h, uv_buf_init);
	CYGUV_GET_API(h, uv_cancel);
	CYGUV_GET_API(h, uv_chdir);
	CYGUV_GET_API(h, uv_check_init);
	//CYGUV_GET_API(h, uv_check_invoke);
	CYGUV_GET_API(h, uv_check_start);
	CYGUV_GET_API(h, uv_check_stop);
	CYGUV_GET_API(h, uv_close);
	CYGUV_GET_API(h, uv_cond_broadcast);
	CYGUV_GET_API(h, uv_cond_destroy);
	CYGUV_GET_API(h, uv_cond_init);
	CYGUV_GET_API(h, uv_cond_signal);
	CYGUV_GET_API(h, uv_cond_timedwait);
	CYGUV_GET_API(h, uv_cond_wait);
	//CYGUV_GET_API(h, uv_console_init);
	CYGUV_GET_API(h, uv_cpu_info);
	//CYGUV_GET_API(h, uv_current_pid);
	CYGUV_GET_API(h, uv_cwd);
	CYGUV_GET_API(h, uv_default_loop);
	CYGUV_GET_API(h, uv_disable_stdio_inheritance);
	CYGUV_GET_API(h, uv_dlclose);
	CYGUV_GET_API(h, uv_dlerror);
	CYGUV_GET_API(h, uv_dlopen);
	CYGUV_GET_API(h, uv_dlsym);
	CYGUV_GET_API(h, uv_err_name);
	CYGUV_GET_API(h, uv_exepath);
	//CYGUV_GET_API(h, uv_fatal_error);
	CYGUV_GET_API(h, uv_fileno);
	CYGUV_GET_API(h, uv_free_cpu_info);
	CYGUV_GET_API(h, uv_free_interface_addresses);
	CYGUV_GET_API(h, uv_freeaddrinfo);
	CYGUV_GET_API(h, uv_fs_access);
	CYGUV_GET_API(h, uv_fs_chmod);
	CYGUV_GET_API(h, uv_fs_chown);
	CYGUV_GET_API(h, uv_fs_close);
	//CYGUV_GET_API(h, uv_fs_event_close);
	//CYGUV_GET_API(h, uv_fs_event_endgame);
	CYGUV_GET_API(h, uv_fs_event_getpath);
	CYGUV_GET_API(h, uv_fs_event_init);
	CYGUV_GET_API(h, uv_fs_event_start);
	CYGUV_GET_API(h, uv_fs_event_stop);
	CYGUV_GET_API(h, uv_fs_fchmod);
	CYGUV_GET_API(h, uv_fs_fchown);
	CYGUV_GET_API(h, uv_fs_fdatasync);
	CYGUV_GET_API(h, uv_fs_fstat);
	CYGUV_GET_API(h, uv_fs_fsync);
	CYGUV_GET_API(h, uv_fs_ftruncate);
	CYGUV_GET_API(h, uv_fs_futime);
	//CYGUV_GET_API(h, uv_fs_init);
	CYGUV_GET_API(h, uv_fs_link);
	CYGUV_GET_API(h, uv_fs_lstat);
	CYGUV_GET_API(h, uv_fs_mkdir);
	CYGUV_GET_API(h, uv_fs_mkdtemp);
	CYGUV_GET_API(h, uv_fs_open);
	CYGUV_GET_API(h, uv_fs_poll_getpath);
	CYGUV_GET_API(h, uv_fs_poll_init);
	CYGUV_GET_API(h, uv_fs_poll_start);
	CYGUV_GET_API(h, uv_fs_poll_stop);
	CYGUV_GET_API(h, uv_fs_read);
	CYGUV_GET_API(h, uv_fs_readlink);
	CYGUV_GET_API(h, uv_fs_realpath);
	CYGUV_GET_API(h, uv_fs_rename);
	CYGUV_GET_API(h, uv_fs_req_cleanup);
	CYGUV_GET_API(h, uv_fs_rmdir);
	CYGUV_GET_API(h, uv_fs_scandir);
	CYGUV_GET_API(h, uv_fs_scandir_next);
	CYGUV_GET_API(h, uv_fs_sendfile);
	CYGUV_GET_API(h, uv_fs_stat);
	CYGUV_GET_API(h, uv_fs_symlink);
	CYGUV_GET_API(h, uv_fs_unlink);
	CYGUV_GET_API(h, uv_fs_utime);
	CYGUV_GET_API(h, uv_fs_write);
	//CYGUV_GET_API(h, uv_get_acceptex_function);
	//CYGUV_GET_API(h, uv_get_connectex_function);
	CYGUV_GET_API(h, uv_get_free_memory);
	CYGUV_GET_API(h, uv_get_process_title);
	CYGUV_GET_API(h, uv_get_total_memory);
	CYGUV_GET_API(h, uv_getaddrinfo);
	CYGUV_GET_API(h, uv_getnameinfo);
	CYGUV_GET_API(h, uv_getrusage);
	CYGUV_GET_API(h, uv_guess_handle);
	CYGUV_GET_API(h, uv_handle_size);
	CYGUV_GET_API(h, uv_has_ref);
	CYGUV_GET_API(h, uv_hrtime);
	CYGUV_GET_API(h, uv_idle_init);
	//CYGUV_GET_API(h, uv_idle_invoke);
	CYGUV_GET_API(h, uv_idle_start);
	CYGUV_GET_API(h, uv_idle_stop);
	CYGUV_GET_API(h, uv_inet_ntop);
	CYGUV_GET_API(h, uv_inet_pton);
	CYGUV_GET_API(h, uv_interface_addresses);
	CYGUV_GET_API(h, uv_ip4_addr);
	CYGUV_GET_API(h, uv_ip4_name);
	CYGUV_GET_API(h, uv_ip6_addr);
	CYGUV_GET_API(h, uv_ip6_name);
	CYGUV_GET_API(h, uv_is_active);
	CYGUV_GET_API(h, uv_is_closing);
	CYGUV_GET_API(h, uv_is_readable);
	//CYGUV_GET_API(h, uv_is_tty);
	CYGUV_GET_API(h, uv_is_writable);
	CYGUV_GET_API(h, uv_key_create);
	CYGUV_GET_API(h, uv_key_delete);
	CYGUV_GET_API(h, uv_key_get);
	CYGUV_GET_API(h, uv_key_set);
	CYGUV_GET_API(h, uv_kill);
	CYGUV_GET_API(h, uv_listen);
	CYGUV_GET_API(h, uv_loadavg);
	CYGUV_GET_API(h, uv_loop_alive);
	CYGUV_GET_API(h, uv_loop_close);
	CYGUV_GET_API(h, uv_loop_configure);
	CYGUV_GET_API(h, uv_loop_delete);
	CYGUV_GET_API(h, uv_loop_init);
	CYGUV_GET_API(h, uv_loop_new);
	CYGUV_GET_API(h, uv_loop_size);
	//CYGUV_GET_API(h, uv_loop_watcher_endgame);
	//CYGUV_GET_API(h, uv_msafd_poll@16);
	CYGUV_GET_API(h, uv_mutex_destroy);
	CYGUV_GET_API(h, uv_mutex_init);
	CYGUV_GET_API(h, uv_mutex_lock);
	CYGUV_GET_API(h, uv_mutex_trylock);
	CYGUV_GET_API(h, uv_mutex_unlock);
	CYGUV_GET_API(h, uv_now);
	//CYGUV_GET_API(h, uv_ntstatus_to_winsock_error);
	CYGUV_GET_API(h, uv_once);
	//CYGUV_GET_API(h, uv_os_free_passwd);
	CYGUV_GET_API(h, uv_os_get_passwd);
	CYGUV_GET_API(h, uv_os_homedir);
	CYGUV_GET_API(h, uv_os_tmpdir);
	//CYGUV_GET_API(h, uv_parent_pid);
	//CYGUV_GET_API(h, uv_pipe_accept);
	CYGUV_GET_API(h, uv_pipe_bind);
	//CYGUV_GET_API(h, uv_pipe_cleanup);
	//CYGUV_GET_API(h, uv_pipe_close);
	CYGUV_GET_API(h, uv_pipe_connect);
	//CYGUV_GET_API(h, uv_pipe_endgame);
	CYGUV_GET_API(h, uv_pipe_getpeername);
	CYGUV_GET_API(h, uv_pipe_getsockname);
	CYGUV_GET_API(h, uv_pipe_init);
	//CYGUV_GET_API(h, uv_pipe_listen);
	CYGUV_GET_API(h, uv_pipe_open);
	CYGUV_GET_API(h, uv_pipe_pending_count);
	CYGUV_GET_API(h, uv_pipe_pending_instances);
	CYGUV_GET_API(h, uv_pipe_pending_type);
	//CYGUV_GET_API(h, uv_pipe_read_start);
	//CYGUV_GET_API(h, uv_pipe_write);
	//CYGUV_GET_API(h, uv_pipe_write2);
	//CYGUV_GET_API(h, uv_poll_close);
	//CYGUV_GET_API(h, uv_poll_endgame);
	CYGUV_GET_API(h, uv_poll_init);
	CYGUV_GET_API(h, uv_poll_init_socket);
	CYGUV_GET_API(h, uv_poll_start);
	CYGUV_GET_API(h, uv_poll_stop);
	CYGUV_GET_API(h, uv_prepare_init);
	//CYGUV_GET_API(h, uv_prepare_invoke);
	CYGUV_GET_API(h, uv_prepare_start);
	CYGUV_GET_API(h, uv_prepare_stop);
	CYGUV_GET_API(h, uv_print_active_handles);
	CYGUV_GET_API(h, uv_print_all_handles);
	//CYGUV_GET_API(h, uv_process_async_wakeup_req);
	//CYGUV_GET_API(h, uv_process_close);
	//CYGUV_GET_API(h, uv_process_endgame);
	//CYGUV_GET_API(h, uv_process_fs_event_req);
	CYGUV_GET_API(h, uv_process_kill);
	//CYGUV_GET_API(h, uv_process_pipe_accept_req);
	//CYGUV_GET_API(h, uv_process_pipe_connect_req);
	//CYGUV_GET_API(h, uv_process_pipe_read_req);
	//CYGUV_GET_API(h, uv_process_pipe_shutdown_req);
	//CYGUV_GET_API(h, uv_process_pipe_write_req);
	//CYGUV_GET_API(h, uv_process_poll_req);
	//CYGUV_GET_API(h, uv_process_proc_exit);
	//CYGUV_GET_API(h, uv_process_signal_req);
	//CYGUV_GET_API(h, uv_process_tcp_accept_req);
	//CYGUV_GET_API(h, uv_process_tcp_connect_req);
	//CYGUV_GET_API(h, uv_process_tcp_read_req);
	//CYGUV_GET_API(h, uv_process_tcp_write_req);
	//CYGUV_GET_API(h, uv_process_timers);
	//CYGUV_GET_API(h, uv_process_tty_accept_req);
	//CYGUV_GET_API(h, uv_process_tty_connect_req);
	//CYGUV_GET_API(h, uv_process_tty_read_line_req);
	//CYGUV_GET_API(h, uv_process_tty_read_raw_req);
	//CYGUV_GET_API(h, uv_process_tty_read_req);
	//CYGUV_GET_API(h, uv_process_tty_write_req);
	//CYGUV_GET_API(h, uv_process_udp_recv_req);
	//CYGUV_GET_API(h, uv_process_udp_send_req);
	CYGUV_GET_API(h, uv_queue_work);
	CYGUV_GET_API(h, uv_read_start);
	CYGUV_GET_API(h, uv_read_stop);
	CYGUV_GET_API(h, uv_recv_buffer_size);
	CYGUV_GET_API(h, uv_ref);
	CYGUV_GET_API(h, uv_replace_allocator);
	CYGUV_GET_API(h, uv_req_size);
	CYGUV_GET_API(h, uv_resident_set_memory);
	CYGUV_GET_API(h, uv_run);
	CYGUV_GET_API(h, uv_rwlock_destroy);
	CYGUV_GET_API(h, uv_rwlock_init);
	CYGUV_GET_API(h, uv_rwlock_rdlock);
	CYGUV_GET_API(h, uv_rwlock_rdunlock);
	CYGUV_GET_API(h, uv_rwlock_tryrdlock);
	CYGUV_GET_API(h, uv_rwlock_trywrlock);
	CYGUV_GET_API(h, uv_rwlock_wrlock);
	CYGUV_GET_API(h, uv_rwlock_wrunlock);
	CYGUV_GET_API(h, uv_sem_destroy);
	CYGUV_GET_API(h, uv_sem_init);
	CYGUV_GET_API(h, uv_sem_post);
	CYGUV_GET_API(h, uv_sem_trywait);
	CYGUV_GET_API(h, uv_sem_wait);
	CYGUV_GET_API(h, uv_send_buffer_size);
	CYGUV_GET_API(h, uv_set_process_title);
	CYGUV_GET_API(h, uv_setup_args);
	CYGUV_GET_API(h, uv_shutdown);
	//CYGUV_GET_API(h, uv_signal_close);
	//CYGUV_GET_API(h, uv_signal_endgame);
	CYGUV_GET_API(h, uv_signal_init);
	CYGUV_GET_API(h, uv_signal_start);
	CYGUV_GET_API(h, uv_signal_stop);
	//CYGUV_GET_API(h, uv_signals_init);
	CYGUV_GET_API(h, uv_spawn);
	//CYGUV_GET_API(h, uv_stdio_pipe_server);
	CYGUV_GET_API(h, uv_stop);
	CYGUV_GET_API(h, uv_stream_set_blocking);
	CYGUV_GET_API(h, uv_strerror);
	//CYGUV_GET_API(h, uv_tcp_accept);
	CYGUV_GET_API(h, uv_tcp_bind);
	//CYGUV_GET_API(h, uv_tcp_close);
	CYGUV_GET_API(h, uv_tcp_connect);
	//CYGUV_GET_API(h, uv_tcp_duplicate_socket);
	//CYGUV_GET_API(h, uv_tcp_endgame);
	CYGUV_GET_API(h, uv_tcp_getpeername);
	CYGUV_GET_API(h, uv_tcp_getsockname);
	//CYGUV_GET_API(h, uv_tcp_import);
	CYGUV_GET_API(h, uv_tcp_init);
	CYGUV_GET_API(h, uv_tcp_init_ex);
	CYGUV_GET_API(h, uv_tcp_keepalive);
	//CYGUV_GET_API(h, uv_tcp_listen);
	CYGUV_GET_API(h, uv_tcp_nodelay);
	CYGUV_GET_API(h, uv_tcp_open);
	//CYGUV_GET_API(h, uv_tcp_read_start);
	CYGUV_GET_API(h, uv_tcp_simultaneous_accepts);
	//CYGUV_GET_API(h, uv_tcp_write);
	CYGUV_GET_API(h, uv_thread_create);
	CYGUV_GET_API(h, uv_thread_equal);
	CYGUV_GET_API(h, uv_thread_join);
	CYGUV_GET_API(h, uv_thread_self);
	CYGUV_GET_API(h, uv_timer_again);
	//CYGUV_GET_API(h, uv_timer_endgame);
	CYGUV_GET_API(h, uv_timer_get_repeat);
	CYGUV_GET_API(h, uv_timer_init);
	CYGUV_GET_API(h, uv_timer_set_repeat);
	CYGUV_GET_API(h, uv_timer_start);
	CYGUV_GET_API(h, uv_timer_stop);
	//CYGUV_GET_API(h, uv_translate_sys_error);
	CYGUV_GET_API(h, uv_try_write);
	//CYGUV_GET_API(h, uv_tty_close);
	//CYGUV_GET_API(h, uv_tty_endgame);
	CYGUV_GET_API(h, uv_tty_get_winsize);
	CYGUV_GET_API(h, uv_tty_init);
	//CYGUV_GET_API(h, uv_tty_read_start);
	//CYGUV_GET_API(h, uv_tty_read_stop);
	CYGUV_GET_API(h, uv_tty_reset_mode);
	CYGUV_GET_API(h, uv_tty_set_mode);
	//CYGUV_GET_API(h, uv_tty_write);
	CYGUV_GET_API(h, uv_udp_bind);
	//CYGUV_GET_API(h, uv_udp_close);
	//CYGUV_GET_API(h, uv_udp_endgame);
	CYGUV_GET_API(h, uv_udp_getsockname);
	CYGUV_GET_API(h, uv_udp_init);
	CYGUV_GET_API(h, uv_udp_init_ex);
	CYGUV_GET_API(h, uv_udp_open);
	CYGUV_GET_API(h, uv_udp_recv_start);
	CYGUV_GET_API(h, uv_udp_recv_stop);
	CYGUV_GET_API(h, uv_udp_send);
	CYGUV_GET_API(h, uv_udp_set_broadcast);
	CYGUV_GET_API(h, uv_udp_set_membership);
	CYGUV_GET_API(h, uv_udp_set_multicast_interface);
	CYGUV_GET_API(h, uv_udp_set_multicast_loop);
	CYGUV_GET_API(h, uv_udp_set_multicast_ttl);
	CYGUV_GET_API(h, uv_udp_set_ttl);
	CYGUV_GET_API(h, uv_udp_try_send);
	CYGUV_GET_API(h, uv_unref);
	CYGUV_GET_API(h, uv_update_time);
	CYGUV_GET_API(h, uv_uptime);
	CYGUV_GET_API(h, uv_version);
	CYGUV_GET_API(h, uv_version_string);
	CYGUV_GET_API(h, uv_walk);
	//CYGUV_GET_API(h, uv_winapi_init);
	//CYGUV_GET_API(h, uv_winsock_init);
	CYGUV_GET_API(h, uv_write);
	CYGUV_GET_API(h, uv_write2);
	//CYGUV_GET_API(h, uv_wsarecv_workaround@28);
	//CYGUV_GET_API(h, uv_wsarecvfrom_workaround@36);

    return h;
}

static void *cyguv_init_fail()
{
    abort();
    return 0;
}
