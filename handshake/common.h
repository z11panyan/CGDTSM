#ifndef __COMMON_H__
#define __COMMON_H__

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <sys/stat.h>
#include <assert.h>

// Generic interface to packages
typedef int (*fp_t)(const uint8_t *, uint32_t);


/**
 * Default CApath
 */



/**
 * Since we are verifying a certificate chain, a wealth of information (such as
 * the depth where error occurs, raw error code, and whether the chain validates
 * successfully) is available.
 *
 * We combine these values together into a composite return value.
 *  - [0]:      1 if chain validates successfully
 *  - [3:1]:    Set to 0
 *  - [11:4]:   depth (leaf cert is always at depth 0)
 *  - [32:12]:  err code of the most recent error
 */
#define compositize_ret_val(response) \
            ( (response[0] << 4) )

#ifdef CONFIG_SUMMARY
#define DBG_S(...) do {printf(__VA_ARGS__); fflush(stdout);} while (0)
#else
#define DBG_S(...) do {} while (0)
#endif

#ifdef CONFIG_DEBUG
#define DBG(...) do {printf(__VA_ARGS__); fflush(stdout);} while (0)
#else
#define DBG(...) do {} while (0)
#endif


// Directives to enable desired functions to be exported
#if __GNUC__ >= 4
    #define LIB_EXPORT      __attribute__ ((visibility("default")))
#else
    #define LIB_EXPORT
#endif



// Normalized error codes
#define RET_CERT_OK             0
#define RET_CERT_ERR            1
#define RET_CERT_CANT_PARSE     0xFFFFFFF0
#define FAILURE_INTERNAL        0xFFFFFFFF

#define FN_DO_HANDSHAKE          "do_handshake_mem"


#define FREE_PTR(ptr) \
    if (ptr) { \
        free(ptr);\
        ptr = NULL;\
    }
#endif  //__COMMON_H__
