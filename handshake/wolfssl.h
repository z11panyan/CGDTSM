#ifndef __WOLFSSL_H__
#define __WOLFSSL_H__

#include "common.h"


#ifdef CONFIG_USE_DER
const static char *LIB_WOLFSSL = "lib/libwolfssl.so";
#else
const static char *LIB_WOLFSSL = "lib/libwolfssl.so";
#endif

extern "C"
int do_handshake_mem(const uint8_t *Data, uint32_t Size);
extern "C"
int do_handshake_mem_wolfssl(const uint8_t *Data, uint32_t Size);

#endif  //__WOLFSSL_H__
