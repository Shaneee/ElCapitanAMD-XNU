/*
 * Copyright (c) 2012 Apple Computer, Inc. All rights reserved.
 *
 * @APPLE_OSREFERENCE_LICENSE_HEADER_START@
 * 
 * This file contains Original Code and/or Modifications of Original Code
 * as defined in and that are subject to the Apple Public Source License
 * Version 2.0 (the 'License'). You may not use this file except in
 * compliance with the License. The rights granted to you under the License
 * may not be used to create, or enable the creation or redistribution of,
 * unlawful or unlicensed copies of an Apple operating system, or to
 * circumvent, violate, or enable the circumvention or violation of, any
 * terms of an Apple operating system software license agreement.
 * 
 * Please obtain a copy of the License at
 * http://www.opensource.apple.com/apsl/ and read it before using this file.
 * 
 * The Original Code and all software distributed under the License are
 * distributed on an 'AS IS' basis, WITHOUT WARRANTY OF ANY KIND, EITHER
 * EXPRESS OR IMPLIED, AND APPLE HEREBY DISCLAIMS ALL SUCH WARRANTIES,
 * INCLUDING WITHOUT LIMITATION, ANY WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE, QUIET ENJOYMENT OR NON-INFRINGEMENT.
 * Please see the License for the specific language governing rights and
 * limitations under the License.
 * 
 * @APPLE_OSREFERENCE_LICENSE_HEADER_END@
 */

#ifndef _BLOWFISH_H
#define _BLOWFISH_H

#if defined(__cplusplus)
extern "C"
{
#endif

#include <corecrypto/ccmode.h>
#include <corecrypto/ccn.h>

#define BLOWFISH_BLOCK_SIZE  16  /* the Blowfish block size in bytes          */

//Unholy HACK: this works because we know the size of the context for every
//possible corecrypto implementation is less than this.
#define BLOWFISH_ECB_CTX_MAX_SIZE (ccn_sizeof_size(sizeof(void *)) + ccn_sizeof_size(BLOWFISH_BLOCK_SIZE) + ccn_sizeof_size(8192*4))

typedef struct{
	ccecb_ctx_decl(BLOWFISH_ECB_CTX_MAX_SIZE, ctx);
} blowfish_decrypt_ctx;

typedef struct{
	ccecb_ctx_decl(BLOWFISH_ECB_CTX_MAX_SIZE, ctx);
} blowfish_encrypt_ctx;

typedef struct
{
	blowfish_decrypt_ctx decrypt;
	blowfish_encrypt_ctx encrypt;
} blowfish_ctx;

/* for compatibility with old apis*/
#define blowfish_ret     int
#define blowfish_good    0
#define blowfish_error  -1
#define blowfish_rval    blowfish_ret

/* Key lengths in the range 16 <= key_len <= 32 are given in bytes, */
/* those in the range 128 <= key_len <= 256 are given in bits       */

blowfish_rval blowfish_encrypt_key(const unsigned char *key, int key_len, blowfish_encrypt_ctx cx[1]);
blowfish_rval blowfish_encrypt_key128(const unsigned char *key, blowfish_encrypt_ctx cx[1]);
blowfish_rval blowfish_encrypt_key256(const unsigned char *key, blowfish_encrypt_ctx cx[1]);
blowfish_rval blowfish_encrypt_key512(const unsigned char *key, blowfish_encrypt_ctx cx[1]);

#if defined (__i386__) || defined (__x86_64__) || defined (__arm64__)
blowfish_rval blowfish_encrypt(const unsigned char *in, unsigned char *out, blowfish_encrypt_ctx cx[1]);
#endif

blowfish_rval blowfish_encrypt_ecb(const unsigned char *in_blk, unsigned int num_blk,
					 unsigned char *out_blk, blowfish_encrypt_ctx cx[1]);
blowfish_rval blowfish_encrypt_cbc(const unsigned char *in_blk, const unsigned char *in_iv, unsigned int num_blk,
                     unsigned char *out_blk, blowfish_encrypt_ctx cx[1]);

blowfish_rval blowfish_decrypt_key(const unsigned char *key, int key_len, blowfish_decrypt_ctx cx[1]);
blowfish_rval blowfish_decrypt_key128(const unsigned char *key, blowfish_decrypt_ctx cx[1]);
blowfish_rval blowfish_decrypt_key256(const unsigned char *key, blowfish_decrypt_ctx cx[1]);
blowfish_rval blowfish_decrypt_key512(const unsigned char *key, blowfish_decrypt_ctx cx[1]);

#if defined (__i386__) || defined (__x86_64__) || defined (__arm64__)
blowfish_rval blowfish_decrypt(const unsigned char *in, unsigned char *out, blowfish_decrypt_ctx cx[1]);
#endif

blowfish_rval blowfish_decrypt_ecb(const unsigned char *in_blk, unsigned int num_blk,
					 unsigned char *out_blk, blowfish_decrypt_ctx cx[1]);
blowfish_rval blowfish_decrypt_cbc(const unsigned char *in_blk, const unsigned char *in_iv, unsigned int num_blk,
                     unsigned char *out_blk, blowfish_decrypt_ctx cx[1]);

#if defined(__cplusplus)
}
#endif

#endif
