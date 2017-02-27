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

#include <libkern/crypto/crypto_internal.h>
#include <libkern/crypto/blowfish.h>
#include <corecrypto/ccmode.h>
#include <corecrypto/ccblowfish.h>
#include <kern/debug.h>

blowfish_rval blowfish_encrypt_key(const unsigned char *key, int key_len, blowfish_encrypt_ctx cx[1])
{
	const struct ccmode_ecb *ecb = g_crypto_funcs->ccblowfish_ecb_encrypt;

    /* Make sure the context size for the mode fits in the one we have */
    if(ecb->size>sizeof(blowfish_encrypt_ctx))
        panic("%s: inconsistent size (should be bigger than %d, is %d) for Blowfish encrypt context", __FUNCTION__, (int)ecb->size, (int)sizeof(blowfish_encrypt_ctx));

	ccecb_init(ecb, cx[0].ctx, key_len, key);

	return blowfish_good;
}

blowfish_rval blowfish_encrypt_ecb(const unsigned char *in_blk, unsigned int num_blk,
					 unsigned char *out_blk, blowfish_encrypt_ctx cx[1])
{
	const struct ccmode_ecb *ecb = g_crypto_funcs->ccblowfish_ecb_encrypt;

    ccecb_update(ecb, cx[0].ctx, num_blk, in_blk, out_blk);	//Actually ecb encrypt.

	return blowfish_good;
}

#if defined (__i386__) || defined (__x86_64__) || defined (__arm64__)
/* This does one block of ECB, using the ECB implementation */
blowfish_rval blowfish_encrypt(const unsigned char *in_blk, unsigned char *out_blk, blowfish_encrypt_ctx cx[1])
{
       return blowfish_encrypt_ecb(in_blk, 1, out_blk, cx);
}
#endif

#if defined(OPENSSL_SYS_WIN16) || defined(__LP32__) || defined(OPENSSL_SYS_CRAY) || defined(__ILP64__)
#define BF_LONG unsigned long
#else
#define BF_LONG unsigned int
#endif

#define n2l(c,l)	(l =((unsigned long)(*((c)++)))<<24, \
l|=((unsigned long)(*((c)++)))<<16, \
l|=((unsigned long)(*((c)++)))<< 8, \
l|=((unsigned long)(*((c)++))))

#define l2n(l,c)	(*((c)++)=(unsigned char)(((l)>>24)&0xff), \
*((c)++)=(unsigned char)(((l)>>16)&0xff), \
*((c)++)=(unsigned char)(((l)>> 8)&0xff), \
*((c)++)=(unsigned char)(((l)    )&0xff))

#define l2nn(l1,l2,l3,l4,c,n)	{ \
c+=n; \
switch (n) { \
case 16: *(--(c))=(unsigned char)(((l4)    )&0xff); \
case 15: *(--(c))=(unsigned char)(((l4)>> 8)&0xff); \
case 14: *(--(c))=(unsigned char)(((l4)>>16)&0xff); \
case 13: *(--(c))=(unsigned char)(((l4)>>24)&0xff); \
case 12: *(--(c))=(unsigned char)(((l3)    )&0xff); \
case 11: *(--(c))=(unsigned char)(((l3)>> 8)&0xff); \
case 10: *(--(c))=(unsigned char)(((l3)>>16)&0xff); \
case  9: *(--(c))=(unsigned char)(((l3)>>24)&0xff); \
case  8: *(--(c))=(unsigned char)(((l2)    )&0xff); \
case  7: *(--(c))=(unsigned char)(((l2)>> 8)&0xff); \
case  6: *(--(c))=(unsigned char)(((l2)>>16)&0xff); \
case  5: *(--(c))=(unsigned char)(((l2)>>24)&0xff); \
case  4: *(--(c))=(unsigned char)(((l1)    )&0xff); \
case  3: *(--(c))=(unsigned char)(((l1)>> 8)&0xff); \
case  2: *(--(c))=(unsigned char)(((l1)>>16)&0xff); \
case  1: *(--(c))=(unsigned char)(((l1)>>24)&0xff); \
} \
}

#define n2ln(c,l1,l2,l3,l4,n)	{ \
c+=n; \
l1=l2=0; \
switch (n) { \
case 16: l4 =((unsigned long)(*(--(c))))    ; \
case 15: l4|=((unsigned long)(*(--(c))))<< 8; \
case 14: l4|=((unsigned long)(*(--(c))))<<16; \
case 13: l4|=((unsigned long)(*(--(c))))<<24; \
case 12: l3 =((unsigned long)(*(--(c))))    ; \
case 11: l3|=((unsigned long)(*(--(c))))<< 8; \
case 10: l3|=((unsigned long)(*(--(c))))<<16; \
case  9: l3|=((unsigned long)(*(--(c))))<<24; \
case  8: l2 =((unsigned long)(*(--(c))))    ; \
case  7: l2|=((unsigned long)(*(--(c))))<< 8; \
case  6: l2|=((unsigned long)(*(--(c))))<<16; \
case  5: l2|=((unsigned long)(*(--(c))))<<24; \
case  4: l1 =((unsigned long)(*(--(c))))    ; \
case  3: l1|=((unsigned long)(*(--(c))))<< 8; \
case  2: l1|=((unsigned long)(*(--(c))))<<16; \
case  1: l1|=((unsigned long)(*(--(c))))<<24; \
} \
}

blowfish_rval blowfish_encrypt_cbc(const unsigned char *in_blk, const unsigned char *in_iv, unsigned int num_blk,
                                   unsigned char *out_blk, blowfish_encrypt_ctx cx[1])
{
    BF_LONG tin0,tin1,tin2,tin3;
    BF_LONG tout0,tout1,tout2,tout3;
    BF_LONG tin[4];
    BF_LONG tout[4];
    long l = (long)(num_blk * BLOWFISH_BLOCK_SIZE);
    unsigned char *ivec = (unsigned char *)in_iv;

    n2l(ivec,tout0);
    n2l(ivec,tout1);
    n2l(ivec,tout2);
    n2l(ivec,tout3);
    ivec-=BLOWFISH_BLOCK_SIZE;
    for (l-=BLOWFISH_BLOCK_SIZE; l>=0; l-=BLOWFISH_BLOCK_SIZE)
    {
        n2l(in_blk,tin0);
        n2l(in_blk,tin1);
        n2l(in_blk,tin2);
        n2l(in_blk,tin3);
        tin0^=tout0;
        tin1^=tout1;
        tin2^=tout2;
        tin3^=tout3;
        tin[0]=tin0;
        tin[1]=tin1;
        tin[2]=tin2;
        tin[3]=tin3;
        blowfish_encrypt_ecb((const unsigned char *)tin, 1, (unsigned char *)tout, cx);
        tout0=tout[0];
        tout1=tout[1];
        tout2=tout[2];
        tout3=tout[3];
        l2n(tout0,out_blk);
        l2n(tout1,out_blk);
        l2n(tout2,out_blk);
        l2n(tout3,out_blk);
    }
    if (l != -BLOWFISH_BLOCK_SIZE)
    {
        n2ln(in_blk,tin0,tin1,tin2,tin3,l+BLOWFISH_BLOCK_SIZE);
        tin0^=tout0;
        tin1^=tout1;
        tin2^=tout2;
        tin3^=tout3;
        tin[0]=tin0;
        tin[1]=tin1;
        tin[2]=tin2;
        tin[3]=tin3;
        blowfish_encrypt_ecb((const unsigned char *)tin, 1, (unsigned char *)tout, cx);
        tout0=tout[0];
        tout1=tout[1];
        tout2=tout[2];
        tout3=tout[3];
        l2n(tout0,out_blk);
        l2n(tout1,out_blk);
        l2n(tout2,out_blk);
        l2n(tout3,out_blk);
    }
    l2n(tout0,ivec);
    l2n(tout1,ivec);
    l2n(tout2,ivec);
    l2n(tout3,ivec);

    return blowfish_good;
}

blowfish_rval blowfish_decrypt_key(const unsigned char *key, int key_len, blowfish_decrypt_ctx cx[1])
{
	const struct ccmode_ecb *ecb = g_crypto_funcs->ccblowfish_ecb_decrypt;

    /* Make sure the context size for the mode fits in the one we have */
    if(ecb->size>sizeof(blowfish_decrypt_ctx))
        panic("%s: inconsistent size (should be bigger than %d, is %d) for Blowfish decrypt context", __FUNCTION__, (int)ecb->size, (int)sizeof(blowfish_decrypt_ctx));

	ccecb_init(ecb, cx[0].ctx, key_len, key);

	return blowfish_good;
}

blowfish_rval blowfish_decrypt_ecb(const unsigned char *in_blk, unsigned int num_blk,
					 	 unsigned char *out_blk, blowfish_decrypt_ctx cx[1])
{
	const struct ccmode_ecb *ecb = g_crypto_funcs->ccblowfish_ecb_decrypt;

    ccecb_update(ecb, cx[0].ctx, num_blk, in_blk, out_blk);	//Actually ecb decrypt.

	return blowfish_good;
}

#if defined (__i386__) || defined (__x86_64__) || defined (__arm64__)
/* This does one block of ECB, using the ECB implementation */
blowfish_rval blowfish_decrypt(const unsigned char *in_blk, unsigned char *out_blk, blowfish_decrypt_ctx cx[1])
{
	return blowfish_decrypt_ecb(in_blk, 1, out_blk, cx);
}
#endif

blowfish_rval blowfish_decrypt_cbc(const unsigned char *in_blk, const unsigned char *in_iv, unsigned int num_blk,
                                   unsigned char *out_blk, blowfish_decrypt_ctx cx[1])
{
    BF_LONG tin0,tin1,tin2,tin3;
    BF_LONG tout0,tout1,tout2,tout3,xor0,xor1,xor2,xor3;
    BF_LONG tin[4];
    BF_LONG tout[4];
    long l = (long)(num_blk * BLOWFISH_BLOCK_SIZE);
    unsigned char *ivec = (unsigned char *)in_iv;
    
    n2l(ivec,xor0);
    n2l(ivec,xor1);
    n2l(ivec,xor2);
    n2l(ivec,xor3);
    ivec-=BLOWFISH_BLOCK_SIZE;
    for (l-=BLOWFISH_BLOCK_SIZE; l>=0; l-=BLOWFISH_BLOCK_SIZE)
    {
        n2l(in_blk,tin0);
        n2l(in_blk,tin1);
        n2l(in_blk,tin2);
        n2l(in_blk,tin3);
        tin[0]=tin0;
        tin[1]=tin1;
        tin[2]=tin2;
        tin[3]=tin3;
        blowfish_decrypt_ecb((const unsigned char *)tin, 1, (unsigned char *)tout, cx);
        tout0=tout[0]^xor0;
        tout1=tout[1]^xor1;
        tout2=tout[2]^xor2;
        tout3=tout[3]^xor3;
        l2n(tout0,out_blk);
        l2n(tout1,out_blk);
        l2n(tout2,out_blk);
        l2n(tout3,out_blk);
        xor0=tin0;
        xor1=tin1;
        xor2=tin2;
        xor3=tin3;
    }
    if (l != -16)
    {
        n2l(in_blk,tin0);
        n2l(in_blk,tin1);
        n2l(in_blk,tin2);
        n2l(in_blk,tin3);
        tin[0]=tin0;
        tin[1]=tin1;
        tin[2]=tin2;
        tin[3]=tin3;
        blowfish_decrypt_ecb((const unsigned char *)tin, 1, (unsigned char *)tout, cx);
        tout0=tout[0]^xor0;
        tout1=tout[1]^xor1;
        tout2=tout[2]^xor2;
        tout3=tout[3]^xor3;
        l2nn(tout0,tout1,tout2,tout3,out_blk,l+BLOWFISH_BLOCK_SIZE);
        xor0=tin0;
        xor1=tin1;
        xor2=tin2;
        xor3=tin3;
    }
    l2n(xor0,ivec);
    l2n(xor1,ivec);
    l2n(xor2,ivec);
    l2n(xor3,ivec);
    
    return blowfish_good;
}

blowfish_rval blowfish_encrypt_key128(const unsigned char *key, blowfish_encrypt_ctx cx[1])
{
	return blowfish_encrypt_key(key, 16, cx);
}

blowfish_rval blowfish_decrypt_key128(const unsigned char *key, blowfish_decrypt_ctx cx[1])
{
	return blowfish_decrypt_key(key, 16, cx);
}

blowfish_rval blowfish_encrypt_key256(const unsigned char *key, blowfish_encrypt_ctx cx[1])
{
	return blowfish_encrypt_key(key, 32, cx);
}

blowfish_rval blowfish_decrypt_key256(const unsigned char *key, blowfish_decrypt_ctx cx[1])
{
	return blowfish_decrypt_key(key, 32, cx);
}

blowfish_rval blowfish_encrypt_key512(const unsigned char *key, blowfish_encrypt_ctx cx[1])
{
    return blowfish_encrypt_key(key, 64, cx);
}

blowfish_rval blowfish_decrypt_key512(const unsigned char *key, blowfish_decrypt_ctx cx[1])
{
    return blowfish_decrypt_key(key, 64, cx);
}
