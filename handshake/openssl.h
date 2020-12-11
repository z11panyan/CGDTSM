#ifndef __OPENSSL_H__
#define __OPENSSL_H__

#include "common.h"


#ifdef CONFIG_USE_DER
const static char *LIB_OPENSSL = "lib/libopenssl.so";
#else
const static char *LIB_OPENSSL = "lib/libopenssl.so";
#endif

extern "C"
int do_handshake_mem(const uint8_t *Data, uint32_t Size);
extern "C"
int do_handshake_mem_openssl(const uint8_t *Data, uint32_t Size);

#endif  //__OPENSSL_H__
