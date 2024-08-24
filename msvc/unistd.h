#ifndef UNISTD_H
#define UNISTD_H

#include <time.h>
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <process.h>

typedef int pid_t;
#define getpid _getpid
#define fileno _fileno

#ifndef CLOCK_REALTIME
# define CLOCK_REALTIME 1
#endif
#ifndef CLOCK_BOOTTIME
# define CLOCK_BOOTTIME 2
#endif

inline int clock_gettime(int clk_id, struct timespec* tv)
{
    if (CLOCK_REALTIME == clk_id)
        return timespec_get(tv, TIME_UTC);
    const ULONGLONG ms = GetTickCount64();
    tv->tv_sec = ms / 1000L;
    tv->tv_nsec = (ms % 1000L) * 1000L;
    return TIME_UTC;
}

#endif
