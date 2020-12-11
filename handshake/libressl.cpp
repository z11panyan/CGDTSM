#include "libressl.h"

#include <assert.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <assert.h>
#include <stdint.h>
#include <stddef.h>

SSL_CTX *Init() {
    SSL_library_init();
    SSL_load_error_strings();
    ERR_load_BIO_strings();
    OpenSSL_add_all_algorithms();
    SSL_CTX *sctx;
    assert (sctx = SSL_CTX_new(TLSv1_method()));
    //SSL_CTX_set_security_level(sctx, 0);
    //assert(SSL_CTX_use_certificate_file(sctx, "runtime/server.pem",SSL_FILETYPE_PEM));
    if (0 == SSL_CTX_use_certificate_file(sctx, "runtime/server.pem",SSL_FILETYPE_PEM))
    {
        printf("Cannot use Certificate File:%s", ERR_error_string( ERR_get_error(), NULL ));
        exit(1);
    }

    assert(SSL_CTX_use_PrivateKey_file(sctx, "runtime/server.key",
                                      SSL_FILETYPE_PEM));
    return sctx;
}

extern "C"
LIB_EXPORT
int do_handshake_mem(const uint8_t *Data, uint32_t Size)
{
    static SSL_CTX *sctx = Init();
    uint8_t *response = new uint8_t[8];
    int composite_ret;
    memset(response,0,8*sizeof(uint8_t));
    SSL *server = SSL_new(sctx);
    BIO *sinbio = BIO_new(BIO_s_mem());
    BIO *soutbio = BIO_new(BIO_s_mem());
    
    SSL_set_bio(server, sinbio, soutbio);
    SSL_set_accept_state(server);
    //SSL_accept(server);
    BIO_write(sinbio, Data, Size);
    int r = SSL_do_handshake(server);

    BIO_read(soutbio,response,8*sizeof(uint8_t));
    
    if(response[0]==0x16)
    {        
        DBG("[libressl] [handshake: HS/%02x/%02x%02x]\n",response[5],response[1],response[2]);	        
	//composite_ret = 0;
    }
    else if(response[0]==0x15)
    {
        DBG("[libressl] [Alert: AL/%02x/%02x%02x]\n",response[6],response[1],response[2]);
	//composite_ret = response[6];
    }
    else
    {
	DBG("[libressl] [No output: %02x%02x%02x]\n",response[0],response[1],response[2]);
	//composite_ret = 1;
    }
    SSL_free(server);    
    //SSL_CTX_free(sctx);
    composite_ret = response[0];

    
    if(composite_ret==0)
	composite_ret = 21;
    else if(composite_ret==22)
	composite_ret = 0;
    delete [] response;
    return composite_ret;
}

extern "C"
LIB_EXPORT
int do_handshake_mem_libressl(const uint8_t *Data, uint32_t Size)
{
    return do_handshake_mem(Data, Size);
}
