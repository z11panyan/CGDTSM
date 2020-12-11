#ifndef __BORINGSSL_H__
#define __BORINGSSL_H__

#include "common.h"

#ifdef CONFIG_USE_DER
const static char *LIB_BORINGSSL = "lib/libboringssl.so";
#else
const static char *LIB_BORINGSSL = "lib/libboringssl.so";
#endif

extern "C"
int do_handshake_mem(const uint8_t *Data, uint32_t Size);
extern "C"
int do_handshake_mem_boringssl(const uint8_t *Data, uint32_t Size);

#endif  //__BORINGSSL_H__
