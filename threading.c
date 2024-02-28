#ifdef WINDOWS
#include <windows.h>

int get_processor_count() {
    SYSTEM_INFO sysinfo;
    GetSystemInfo(&sysinfo);
    return sysinfo.dwNumberOfProcessors;
}

#else
#include <pthread.h>
#include <sys/sysinfo.h>

#define THREAD_EXIT pthread_exit(NULL)
#define THREAD_CANCEL(ref) pthread_cancel((pthread_t)ref)
#define THREAD_KILL(ref) pthread_kill((pthread_t)ref, 0)
#define THREAD_JOIN(ref) pthread_join((pthread_t)ref, NULL)
#define THREAD_ID_TYPE pthread_t

int get_processor_count() {
    return get_nprocs();
}

int create_thread(pthread_t *ref, void *func, void *arg) {
    pthread_t thread;
    int ret = pthread_create(&thread, NULL, func, arg);
    *ref = thread;
    return ret;
}

#endif

