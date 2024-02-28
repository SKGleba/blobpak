#ifdef WINDOWS
#include <windows.h>
#include <wincrypt.h>

#define THREAD_EXIT ExitThread(0)
#define THREAD_CANCEL(ref) TerminateThread(ref, 0)
#define THREAD_KILL(ref) TerminateThread(ref, 0)
#define THREAD_JOIN(ref) WaitForSingleObject(ref, INFINITE)
#define THREAD_INVALIDATE(ref) CloseHandle(ref)
#define THREAD_ID_TYPE HANDLE
//#define THREAD_FETCH_ARG(arg) (*(void *)arg)

int get_processor_count() {
    SYSTEM_INFO sysinfo;
    GetSystemInfo(&sysinfo);
    return sysinfo.dwNumberOfProcessors;
}

int create_thread(HANDLE *ref, void *func, void *arg) {
    HANDLE thread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)func, arg, 0, NULL);
    *ref = thread;
    return thread == NULL;
}

void get_randoms(uint8_t *buffer, int length) {
    HCRYPTPROV hCryptProv = 0;
    CryptAcquireContext(&hCryptProv, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT);
    CryptGenRandom(hCryptProv, length, buffer);
    CryptReleaseContext(hCryptProv, 0);
}

#else
#include <pthread.h>
#include <sys/sysinfo.h>

#define THREAD_EXIT pthread_exit(NULL)
#define THREAD_CANCEL(ref) pthread_cancel((pthread_t)ref)
#define THREAD_KILL(ref) pthread_kill((pthread_t)ref, 0)
#define THREAD_JOIN(ref) pthread_join((pthread_t)ref, NULL)
#define THREAD_INVALIDATE(ref)
#define THREAD_ID_TYPE pthread_t
//#define THREAD_FETCH_ARG(arg) (arg)

int get_processor_count() {
    return get_nprocs();
}

int create_thread(pthread_t *ref, void *func, void *arg) {
    pthread_t thread;
    int ret = pthread_create(&thread, NULL, func, arg);
    *ref = thread;
    return ret;
}

void get_randoms(uint8_t *buffer, int length) {
    FILE *fp = fopen("/dev/urandom", "r");
    if (fp) {
        fread(buffer, 1, length, fp);
        fclose(fp);
    }
}

#endif

