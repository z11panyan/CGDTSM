#include "wolfssl.h"

#include <assert.h>
#include <wolfssl/options.h>
#include <wolfssl/ssl.h>
//#include <wolfssl/openssl/ssl.h>
//#include <wolfssl/openssl/err.h>
#include <assert.h>
#include <stdint.h>
#include <stddef.h>

WOLFSSL_CTX *Init() {
    wolfSSL_Init(); 
    //wolfSSL_library_init ();
    WOLFSSL_CTX *sctx;
    assert (sctx  = wolfSSL_CTX_new(wolfTLSv1_2_server_method()));
    wolfSSL_CTX_set_verify(sctx, SSL_VERIFY_NONE,0);
    //assert(SSL_CTX_use_certificate_file(sctx, "runtime/server.pem",SSL_FILETYPE_PEM));
    
    int ret = wolfSSL_CTX_use_certificate_file(sctx, "./runtime/server.pem",SSL_FILETYPE_PEM);
    if (WOLFSSL_SUCCESS != ret)
    {
	char buffer[80];
	wolfSSL_ERR_error_string( ret, buffer );
        printf("Cannot use Certificate File:%d", ret);
        exit(1);
    }
    ret = wolfSSL_CTX_use_PrivateKey_file(sctx, "./runtime/rsa_private_key.pem",WOLFSSL_FILETYPE_PEM);
    if(ret !=WOLFSSL_SUCCESS)
    {
	char buffer[80];
	ERR_error_string( wolfSSL_get_error(NULL,ret), buffer );
	printf("Cannot use Certificate File:%s",buffer);
        exit(1);
    }
    return sctx;
}

extern "C"
LIB_EXPORT
int do_handshake_mem(const uint8_t *Data, uint32_t Size)
{
    static WOLFSSL_CTX *sctx = Init();
    uint8_t *response = new uint8_t[8];
    int composite_ret;
    memset(response,0,8*sizeof(uint8_t));
    WOLFSSL *server = wolfSSL_new(sctx);
    WOLFSSL_BIO *sinbio;
    sinbio = wolfSSL_BIO_new(wolfSSL_BIO_s_mem());
    WOLFSSL_BIO *soutbio = wolfSSL_BIO_new(wolfSSL_BIO_s_mem());
    
    wolfSSL_set_bio(server, sinbio, soutbio);
    wolfSSL_set_accept_state(server);
    //SSL_accept(server);
    wolfSSL_BIO_write(sinbio, Data, Size);
    int r = wolfSSL_SSL_do_handshake(server);

    wolfSSL_BIO_read(soutbio,response,8*sizeof(uint8_t));
    
    if(response[0]==0x16)
    {        
        DBG("[wolfssl] [handshake: HS/%02x/%02x%02x]\n",response[5],response[1],response[2]);	        
	//composite_ret = 0;
    }
    else if(response[0]==0x15)
    {
        DBG("[wolfssl] [Alert: AL/%02x/%02x%02x]\n",response[6],response[1],response[2]);
	//composite_ret = response[6];
    }
    else
    {
	DBG("[wolfssl] [No output: %02x%02x%02x]\n",response[0],response[1],response[2]);
	//composite_ret = 1;
    }
    wolfSSL_free(server);    
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
int do_handshake_mem_wolfssl(const uint8_t *Data, uint32_t Size)
{
    return do_handshake_mem(Data, Size);
}
