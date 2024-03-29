#! /usr/bin/env python

syscallmap32 = [
	"RESTART_SYSCALL", # __NR_restart_syscall
	"EXIT", # __NR_exit
	"FORK", # __NR_fork
	"READ", # __NR_read
	"WRITE", # __NR_write
	"OPEN", # __NR_open
	"CLOSE", # __NR_close
	"WAITPID", # __NR_waitpid
	"CREAT", # __NR_creat
	"LINK", # __NR_link
	"UNLINK", # __NR_unlink
	"EXECVE", # __NR_execve
	"CHDIR", # __NR_chdir
	"TIME", # __NR_time
	"MKNOD", # __NR_mknod
	"CHMOD", # __NR_chmod
	"LCHOWN", # __NR_lchown
	"BREAK", # __NR_break
	"OLDSTAT", # __NR_oldstat
	"LSEEK", # __NR_lseek
	"GETPID", # __NR_getpid
	"MOUNT", # __NR_mount
	"UMOUNT", # __NR_umount
	"SETUID", # __NR_setuid
	"GETUID", # __NR_getuid
	"STIME", # __NR_stime
	"PTRACE", # __NR_ptrace
	"ALARM", # __NR_alarm
	"OLDFSTAT", # __NR_oldfstat
	"PAUSE", # __NR_pause
	"UTIME", # __NR_utime
	"STTY", # __NR_stty
	"GTTY", # __NR_gtty
	"ACCESS", # __NR_access
	"NICE", # __NR_nice
	"FTIME", # __NR_ftime
	"SYNC", # __NR_sync
	"KILL", # __NR_kill
	"RENAME", # __NR_rename
	"MKDIR", # __NR_mkdir
	"RMDIR", # __NR_rmdir
	"DUP", # __NR_dup
	"PIPE", # __NR_pipe
	"TIMES", # __NR_times
	"PROF", # __NR_prof
	"BRK", # __NR_brk
	"SETGID", # __NR_setgid
	"GETGID", # __NR_getgid
	"SIGNAL", # __NR_signal
	"GETEUID", # __NR_geteuid
	"GETEGID", # __NR_getegid
	"ACCT", # __NR_acct
	"UMOUNT2", # __NR_umount2
	"LOCK", # __NR_lock
	"IOCTL", # __NR_ioctl
	"FCNTL", # __NR_fcntl
	"MPX", # __NR_mpx
	"SETPGID", # __NR_setpgid
	"ULIMIT", # __NR_ulimit
	"OLDOLDUNAME", # __NR_oldolduname
	"UMASK", # __NR_umask
	"CHROOT", # __NR_chroot
	"USTAT", # __NR_ustat
	"DUP2", # __NR_dup2
	"GETPPID", # __NR_getppid
	"GETPGRP", # __NR_getpgrp
	"SETSID", # __NR_setsid
	"SIGACTION", # __NR_sigaction
	"SGETMASK", # __NR_sgetmask
	"SSETMASK", # __NR_ssetmask
	"SETREUID", # __NR_setreuid
	"SETREGID", # __NR_setregid
	"SIGSUSPEND", # __NR_sigsuspend
	"SIGPENDING", # __NR_sigpending
	"SETHOSTNAME", # __NR_sethostname
	"SETRLIMIT", # __NR_setrlimit
	"GETRLIMIT", # __NR_getrlimit
	"GETRUSAGE", # __NR_getrusage
	"GETTIMEOFDAY", # __NR_gettimeofday
	"SETTIMEOFDAY", # __NR_settimeofday
	"GETGROUPS", # __NR_getgroups
	"SETGROUPS", # __NR_setgroups
	"SELECT", # __NR_select
	"SYMLINK", # __NR_symlink
	"OLDLSTAT", # __NR_oldlstat
	"READLINK", # __NR_readlink
	"USELIB", # __NR_uselib
	"SWAPON", # __NR_swapon
	"REBOOT", # __NR_reboot
	"READDIR", # __NR_readdir
	"MMAP", # __NR_mmap
	"MUNMAP", # __NR_munmap
	"TRUNCATE", # __NR_truncate
	"FTRUNCATE", # __NR_ftruncate
	"FCHMOD", # __NR_fchmod
	"FCHOWN", # __NR_fchown
	"GETPRIORITY", # __NR_getpriority
	"SETPRIORITY", # __NR_setpriority
	"PROFIL", # __NR_profil
	"STATFS", # __NR_statfs
	"FSTATFS", # __NR_fstatfs
	"IOPERM", # __NR_ioperm
	"SOCKETCALL", # __NR_socketcall
	"SYSLOG", # __NR_syslog
	"SETITIMER", # __NR_setitimer
	"GETITIMER", # __NR_getitimer
	"STAT", # __NR_stat
	"LSTAT", # __NR_lstat
	"FSTAT", # __NR_fstat
	"OLDUNAME", # __NR_olduname
	"IOPL", # __NR_iopl
	"VHANGUP", # __NR_vhangup
	"IDLE", # __NR_idle
	"VM86OLD", # __NR_vm86old
	"WAIT4", # __NR_wait4
	"SWAPOFF", # __NR_swapoff
	"SYSINFO", # __NR_sysinfo
	"IPC", # __NR_ipc
	"FSYNC", # __NR_fsync
	"SIGRETURN", # __NR_sigreturn
	"CLONE", # __NR_clone
	"SETDOMAINNAME", # __NR_setdomainname
	"UNAME", # __NR_uname
	"MODIFY_LDT", # __NR_modify_ldt
	"ADJTIMEX", # __NR_adjtimex
	"MPROTECT", # __NR_mprotect
	"SIGPROCMASK", # __NR_sigprocmask
	"CREATE_MODULE", # __NR_create_module
	"INIT_MODULE", # __NR_init_module
	"DELETE_MODULE", # __NR_delete_module
	"GET_KERNEL_SYMS", # __NR_get_kernel_syms
	"QUOTACTL", # __NR_quotactl
	"GETPGID", # __NR_getpgid
	"FCHDIR", # __NR_fchdir
	"BDFLUSH", # __NR_bdflush
	"SYSFS", # __NR_sysfs
	"PERSONALITY", # __NR_personality
	"AFS_SYSCALL", # __NR_afs_syscall
	"SETFSUID", # __NR_setfsuid
	"SETFSGID", # __NR_setfsgid
	"_LLSEEK", # __NR__llseek
	"GETDENTS", # __NR_getdents
	"_NEWSELECT", # __NR__newselect
	"FLOCK", # __NR_flock
	"MSYNC", # __NR_msync
	"READV", # __NR_readv
	"WRITEV", # __NR_writev
	"GETSID", # __NR_getsid
	"FDATASYNC", # __NR_fdatasync
	"_SYSCTL", # __NR__sysctl
	"MLOCK", # __NR_mlock
	"MUNLOCK", # __NR_munlock
	"MLOCKALL", # __NR_mlockall
	"MUNLOCKALL", # __NR_munlockall
	"SCHED_SETPARAM", # __NR_sched_setparam
	"SCHED_GETPARAM", # __NR_sched_getparam
	"SCHED_SETSCHEDULER", # __NR_sched_setscheduler
	"SCHED_GETSCHEDULER", # __NR_sched_getscheduler
	"SCHED_YIELD", # __NR_sched_yield
	"SCHED_GET_PRIORITY_MAX", # __NR_sched_get_priority_max
	"SCHED_GET_PRIORITY_MIN", # __NR_sched_get_priority_min
	"SCHED_RR_GET_INTERVAL", # __NR_sched_rr_get_interval
	"NANOSLEEP", # __NR_nanosleep
	"MREMAP", # __NR_mremap
	"SETRESUID", # __NR_setresuid
	"GETRESUID", # __NR_getresuid
	"VM86", # __NR_vm86
	"QUERY_MODULE", # __NR_query_module
	"POLL", # __NR_poll
	"NFSSERVCTL", # __NR_nfsservctl
	"SETRESGID", # __NR_setresgid
	"GETRESGID", # __NR_getresgid
	"PRCTL", # __NR_prctl
	"RT_SIGRETURN", # __NR_rt_sigreturn
	"RT_SIGACTION", # __NR_rt_sigaction
	"RT_SIGPROCMASK", # __NR_rt_sigprocmask
	"RT_SIGPENDING", # __NR_rt_sigpending
	"RT_SIGTIMEDWAIT", # __NR_rt_sigtimedwait
	"RT_SIGQUEUEINFO", # __NR_rt_sigqueueinfo
	"RT_SIGSUSPEND", # __NR_rt_sigsuspend
	"PREAD64", # __NR_pread64
	"PWRITE64", # __NR_pwrite64
	"CHOWN", # __NR_chown
	"GETCWD", # __NR_getcwd
	"CAPGET", # __NR_capget
	"CAPSET", # __NR_capset
	"SIGALTSTACK", # __NR_sigaltstack
	"SENDFILE", # __NR_sendfile
	"GETPMSG", # __NR_getpmsg
	"PUTPMSG", # __NR_putpmsg
	"VFORK", # __NR_vfork
	"UGETRLIMIT", # __NR_ugetrlimit
	"MMAP2", # __NR_mmap2
	"TRUNCATE64", # __NR_truncate64
	"FTRUNCATE64", # __NR_ftruncate64
	"STAT64", # __NR_stat64
	"LSTAT64", # __NR_lstat64
	"FSTAT64", # __NR_fstat64
	"LCHOWN32", # __NR_lchown32
	"GETUID32", # __NR_getuid32
	"GETGID32", # __NR_getgid32
	"GETEUID32", # __NR_geteuid32
	"GETEGID32", # __NR_getegid32
	"SETREUID32", # __NR_setreuid32
	"SETREGID32", # __NR_setregid32
	"GETGROUPS32", # __NR_getgroups32
	"SETGROUPS32", # __NR_setgroups32
	"FCHOWN32", # __NR_fchown32
	"SETRESUID32", # __NR_setresuid32
	"GETRESUID32", # __NR_getresuid32
	"SETRESGID32", # __NR_setresgid32
	"GETRESGID32", # __NR_getresgid32
	"CHOWN32", # __NR_chown32
	"SETUID32", # __NR_setuid32
	"SETGID32", # __NR_setgid32
	"SETFSUID32", # __NR_setfsuid32
	"SETFSGID32", # __NR_setfsgid32
	"PIVOT_ROOT", # __NR_pivot_root
	"MINCORE", # __NR_mincore
	"MADVISE", # __NR_madvise
	"GETDENTS64", # __NR_getdents64
	"FCNTL64", # __NR_fcntl64
	"UNDEF", # undefined
	"UNDEF", # undefined
	"GETTID", # __NR_gettid
	"READAHEAD", # __NR_readahead
	"SETXATTR", # __NR_setxattr
	"LSETXATTR", # __NR_lsetxattr
	"FSETXATTR", # __NR_fsetxattr
	"GETXATTR", # __NR_getxattr
	"LGETXATTR", # __NR_lgetxattr
	"FGETXATTR", # __NR_fgetxattr
	"LISTXATTR", # __NR_listxattr
	"LLISTXATTR", # __NR_llistxattr
	"FLISTXATTR", # __NR_flistxattr
	"REMOVEXATTR", # __NR_removexattr
	"LREMOVEXATTR", # __NR_lremovexattr
	"FREMOVEXATTR", # __NR_fremovexattr
	"TKILL", # __NR_tkill
	"SENDFILE64", # __NR_sendfile64
	"FUTEX", # __NR_futex
	"SCHED_SETAFFINITY", # __NR_sched_setaffinity
	"SCHED_GETAFFINITY", # __NR_sched_getaffinity
	"SET_THREAD_AREA", # __NR_set_thread_area
	"GET_THREAD_AREA", # __NR_get_thread_area
	"IO_SETUP", # __NR_io_setup
	"IO_DESTROY", # __NR_io_destroy
	"IO_GETEVENTS", # __NR_io_getevents
	"IO_SUBMIT", # __NR_io_submit
	"IO_CANCEL", # __NR_io_cancel
	"FADVISE64", # __NR_fadvise64
	"UNDEF", # undefined
	"EXIT_GROUP", # __NR_exit_group
	"LOOKUP_DCOOKIE", # __NR_lookup_dcookie
	"EPOLL_CREATE", # __NR_epoll_create
	"EPOLL_CTL", # __NR_epoll_ctl
	"EPOLL_WAIT", # __NR_epoll_wait
	"REMAP_FILE_PAGES", # __NR_remap_file_pages
	"SET_TID_ADDRESS", # __NR_set_tid_address
	"TIMER_CREATE", # __NR_timer_create
	"TIMER_SETTIME", # __NR_timer_settime
	"TIMER_GETTIME", # __NR_timer_gettime
	"TIMER_GETOVERRUN", # __NR_timer_getoverrun
	"TIMER_DELETE", # __NR_timer_delete
	"CLOCK_SETTIME", # __NR_clock_settime
	"CLOCK_GETTIME", # __NR_clock_gettime
	"CLOCK_GETRES", # __NR_clock_getres
	"CLOCK_NANOSLEEP", # __NR_clock_nanosleep
	"STATFS64", # __NR_statfs64
	"FSTATFS64", # __NR_fstatfs64
	"TGKILL", # __NR_tgkill
	"UTIMES", # __NR_utimes
	"FADVISE64_64", # __NR_fadvise64_64
	"VSERVER", # __NR_vserver
	"MBIND", # __NR_mbind
	"GET_MEMPOLICY", # __NR_get_mempolicy
	"SET_MEMPOLICY", # __NR_set_mempolicy
	"MQ_OPEN", # __NR_mq_open
	"MQ_UNLINK", # __NR_mq_unlink
	"MQ_TIMEDSEND", # __NR_mq_timedsend
	"MQ_TIMEDRECEIVE", # __NR_mq_timedreceive
	"MQ_NOTIFY", # __NR_mq_notify
	"MQ_GETSETATTR", # __NR_mq_getsetattr
	"KEXEC_LOAD", # __NR_kexec_load
	"WAITID", # __NR_waitid
	"UNDEF", # undefined
	"ADD_KEY", # __NR_add_key
	"REQUEST_KEY", # __NR_request_key
	"KEYCTL", # __NR_keyctl
	"IOPRIO_SET", # __NR_ioprio_set
	"IOPRIO_GET", # __NR_ioprio_get
	"INOTIFY_INIT", # __NR_inotify_init
	"INOTIFY_ADD_WATCH", # __NR_inotify_add_watch
	"INOTIFY_RM_WATCH", # __NR_inotify_rm_watch
	"MIGRATE_PAGES", # __NR_migrate_pages
	"OPENAT", # __NR_openat
	"MKDIRAT", # __NR_mkdirat
	"MKNODAT", # __NR_mknodat
	"FCHOWNAT", # __NR_fchownat
	"FUTIMESAT", # __NR_futimesat
	"FSTATAT64", # __NR_fstatat64
	"UNLINKAT", # __NR_unlinkat
	"RENAMEAT", # __NR_renameat
	"LINKAT", # __NR_linkat
	"SYMLINKAT", # __NR_symlinkat
	"READLINKAT", # __NR_readlinkat
	"FCHMODAT", # __NR_fchmodat
	"FACCESSAT", # __NR_faccessat
	"PSELECT6", # __NR_pselect6
	"PPOLL", # __NR_ppoll
	"UNSHARE", # __NR_unshare
	"SET_ROBUST_LIST", # __NR_set_robust_list
	"GET_ROBUST_LIST", # __NR_get_robust_list
	"SPLICE", # __NR_splice
	"SYNC_FILE_RANGE", # __NR_sync_file_range
	"TEE", # __NR_tee
	"VMSPLICE", # __NR_vmsplice
	"MOVE_PAGES", # __NR_move_pages
	"GETCPU", # __NR_getcpu
	"EPOLL_PWAIT", # __NR_epoll_pwait
	"UTIMENSAT", # __NR_utimensat
	"SIGNALFD", # __NR_signalfd
	"TIMERFD_CREATE", # __NR_timerfd_create
	"EVENTFD", # __NR_eventfd
	"FALLOCATE", # __NR_fallocate
	"TIMERFD_SETTIME", # __NR_timerfd_settime
	"TIMERFD_GETTIME", # __NR_timerfd_gettime
	"SIGNALFD4", # __NR_signalfd4
	"EVENTFD2", # __NR_eventfd2
	"EPOLL_CREATE1", # __NR_epoll_create1
	"DUP3", # __NR_dup3
	"PIPE2", # __NR_pipe2
	"INOTIFY_INIT1", # __NR_inotify_init1
	"PREADV", # __NR_preadv
	"PWRITEV", # __NR_pwritev
	"RT_TGSIGQUEUEINFO", # __NR_rt_tgsigqueueinfo
	"PERF_EVENT_OPEN", # __NR_perf_event_open
	"RECVMMSG", # __NR_recvmmsg
	"FANOTIFY_INIT", # __NR_fanotify_init
	"FANOTIFY_MARK", # __NR_fanotify_mark
	"PRLIMIT64", # __NR_prlimit64
	"NAME_TO_HANDLE_AT", # __NR_name_to_handle_at
	"OPEN_BY_HANDLE_AT", # __NR_open_by_handle_at
	"CLOCK_ADJTIME", # __NR_clock_adjtime
	"SYNCFS", # __NR_syncfs
	"SENDMMSG", # __NR_sendmmsg
	"SETNS", # __NR_setns
	"PROCESS_VM_READV", # __NR_process_vm_readv
	"PROCESS_VM_WRITEV", # __NR_process_vm_writev
	"KCMP", # __NR_kcmp
	"FINIT_MODULE", # __NR_finit_module
	"SCHED_SETATTR", # __NR_sched_setattr
	"SCHED_GETATTR", # __NR_sched_getattr
	"RENAMEAT2", # __NR_renameat2
	"SECCOMP", # __NR_seccomp	
]