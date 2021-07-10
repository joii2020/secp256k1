#ifndef _SRCBENCH_SCHNORRSIG_RISCV_H_
#define _SRCBENCH_SCHNORRSIG_RISCV_H_

#include <string.h>
#include <stdlib.h>

#include "../include/secp256k1.h"
#include "../include/secp256k1_schnorrsig.h"
#include "util.h"
#include "bench.h"

unsigned char hex_char_to_num(char c)
{
    unsigned char ref = 0;
    if (c >= '0' && c <= '9')
        ref = c - '0';
    else if (c >= 'A' && c <= 'F')
        ref = c - 'A' + 0xa;
    else
        CHECK(0);
    return ref;
}

void num_to_hex_str(unsigned char c, char *str)
{
    unsigned char c1 = c >> 4;
    if (c1 <= 9)
        str[0] = c1 + '0';
    else
        str[0] = c1 + 'A' - 0xa;

    c = c & 0xf;

    if (c <= 9)
        str[1] = c + '0';
    else
        str[1] = c + 'A' - 0xa;
}

int str_to_bin_size(const char *str)
{
    return strlen(str) / 2;
}

void str_to_bin(const char *in_str, unsigned char *out_bin)
{
    int size = str_to_bin_size(in_str);

    int i = 0;
    while (i < size)
    {
        out_bin[i] = (hex_char_to_num(in_str[0]) << 4) + hex_char_to_num(in_str[1]);
        in_str += 2;
        i++;
    }
}

const char *bin_to_str(unsigned char *bin, int size)
{
    char *ref = (char *)malloc(size * 2 + 1);

    int i = 0;
    while (i < size)
    {
        num_to_hex_str(bin[i], ref + i * 2);
        i++;
    }
    ref[size * 2] = '\0';
    return ref;
}

unsigned char test_data_sk[32] = "1234567890abcdef1234567890abcdef";
unsigned char test_data_msg[32] = "12345678123456781234567812345678";

const char test_data_sig[] =
    "788406A358F2C4D6633739DB485C2EADE8731CCE21C5CDD22ED71429DA143D45AEA7B324F309892E29CFCEB46E409BBB60FDADD919856C73D4D6AF5F1D2F6352";
const char test_data_pubkey[] =
    "1F107428609C2FA59A0E035A6B275FBE99B1D72D9A052A3FD05F53E27B71FDABFE56ECD16FE1445365F0F52A549DC6F8F88291443C2F0F1BD9449F9A3BB33CB7";

int run(void)
{
#ifdef USE_RISC_V
    secp256k1_context_verify ctx_verify;
    secp256k1_context *ctx = (secp256k1_context*)&ctx_verify;
#else
    secp256k1_context *ctx = NULL;
#endif

/*
#ifdef USE_RISC_V
    secp256k1_keypair keypair, *p_keypair = &keypair;
#else
    secp256k1_keypair *p_keypair = malloc(sizeof(secp256k1_keypair));
#endif
*/

    secp256k1_xonly_pubkey pubkey;
    unsigned char sig[64];
    /*const char *str_sig, *str_pubkey;*/

    int ref = 1;
    int loop = 0;

#ifdef USE_RISC_V
    memset(&ctx_verify, 0, sizeof(ctx_verify));
    ref = secp256k1_context_create_noalloc(
        SECP256K1_CONTEXT_VERIFY /*| SECP256K1_CONTEXT_SIGN*/, ctx);
#else
    ctx = secp256k1_context_create(SECP256K1_CONTEXT_VERIFY);
    if (ctx == NULL)
        ref = 0;
#endif
    if (ref != 1)
        return -1;

    /*
    if (secp256k1_keypair_create(ctx, p_keypair, test_data_sk) != 1)
        return -2;

    if (secp256k1_schnorrsig_sign(ctx, sig, test_data_msg, &keypair, NULL, NULL) != 1)
    {
        CHECK(0);
    }

    if (secp256k1_keypair_xonly_pub(ctx, &pubkey, NULL, &keypair) != 1)
    {
        CHECK(0);
    }
    */

    str_to_bin(test_data_pubkey, (unsigned char *)&pubkey);
    str_to_bin(test_data_sig, sig);

    loop = 100;
    while (loop) {
        if (secp256k1_schnorrsig_verify(ctx, sig, test_data_msg, &pubkey) == 1)
        {
            ref = 0;
    #ifndef USE_RISC_V
            printf("verify success\n");
    #endif
        }
        else
        {
            ref = 1;
    #ifndef USE_RISC_V
            printf("verify failed\n");
    #endif
        }
        loop--;
    }
    /*
    {
        str_sig = bin_to_str(sig, sizeof(sig));
        printf("sign is :%s\n", str_sig);
        free(str_sig);

        str_pubkey = bin_to_str(&pubkey, sizeof(pubkey));
        printf("pubkey :%s\n", str_pubkey);
        free(str_pubkey);
    }
    */
#ifdef USE_RISC_V
    secp256k1_context_destroy_noalloc(ctx);
#else
    secp256k1_context_destroy(ctx);
#endif

    return ref;
}

#endif /*_SRCBENCH_SCHNORRSIG_RISCV_H_*/
