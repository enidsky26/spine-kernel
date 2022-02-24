#ifndef SPINE_PRIV_H
#define SPINE_PRIV_H

#ifdef __KERNEL__
#include <linux/kernel.h>
#else
#include <stdio.h>
#endif

#define log_fmt(level, fmt, args...)                                  \
    {                                                                 \
        char msg[80];                                                 \
        int __ok = snprintf((char *)&msg, 80, fmt, ##args);           \
        if (__ok >= 0)                                                \
        {                                                             \
            datapath->log(datapath, level, (const char *)&msg, __ok); \
        }                                                             \
    }

// __LOG_INFO__ is default
#define spine_trace(fmt, args...)
#define spine_debug(fmt, args...)
#define spine_info(fmt, args...) log_fmt(INFO, fmt, ##args)
#define spine_warn(fmt, args...) log_fmt(WARN, fmt, ##args)
#define spine_error(fmt, args...) log_fmt(ERROR, fmt, ##args)

#ifdef __LOG_TRACE__
#undef spine_trace
#define spine_trace(fmt, args...) log_fmt(TRACE, fmt, ##args)
#undef spine_debug
#define spine_debug(fmt, args...) log_fmt(DEBUG, fmt, ##args)
#endif

#ifdef __LOG_DEBUG__
#undef spine_debug
#define spine_debug(fmt, args...) log_fmt(DEBUG, fmt, ##args)
#endif

#ifdef __LOG_WARN__
#undef spine_info
#define spine_info(fmt, args...)
#endif
#ifdef __LOG_ERROR__
#undef spine_info
#define spine_info(fmt, args...)
#undef spine_warn
#define spine_warn(fmt, args...)
#endif

#endif