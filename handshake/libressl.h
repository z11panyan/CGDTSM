#ifndef __LIBRESSL_H__
#define __LIBRESSL_H__

#include "common.h"


#ifdef CONFIG_USE_DER
const static char *LIB_LIBRESSL = "lib/liblibressl.so";
#else
const static char *LIB_LIBRESSL = "lib/liblibressl.so";
#endif

extern "C"
int do_handshake_mem(const uint8_t *Data, uint32_t Size);
extern "C"
int do_handshake_mem_libressl(const uint8_t *Data, uint32_t Size);

#endif  //__LIBRESSL_H__
