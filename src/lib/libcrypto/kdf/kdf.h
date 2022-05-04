/*
 * Copyright 2016-2018 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef HEADER_KDF_H
# define HEADER_KDF_H

# include <openssl/kdferr.h>
#ifdef __cplusplus
extern "C" {
#endif

# define EVP_PKEY_CTRL_TLS_MD                   (EVP_PKEY_ALG_CTRL)
# define EVP_PKEY_CTRL_TLS_SECRET               (EVP_PKEY_ALG_CTRL + 1)
# define EVP_PKEY_CTRL_TLS_SEED                 (EVP_PKEY_ALG_CTRL + 2)
# define EVP_PKEY_CTRL_HKDF_MD                  (EVP_PKEY_ALG_CTRL + 3)
# define EVP_PKEY_CTRL_HKDF_SALT                (EVP_PKEY_ALG_CTRL + 4)
# define EVP_PKEY_CTRL_HKDF_KEY                 (EVP_PKEY_ALG_CTRL + 5)
# define EVP_PKEY_CTRL_HKDF_INFO                (EVP_PKEY_ALG_CTRL + 6)
# define EVP_PKEY_CTRL_HKDF_MODE                (EVP_PKEY_ALG_CTRL + 7)
# define EVP_PKEY_CTRL_PASS                     (EVP_PKEY_ALG_CTRL + 8)
# define EVP_PKEY_CTRL_SCRYPT_SALT              (EVP_PKEY_ALG_CTRL + 9)
# define EVP_PKEY_CTRL_SCRYPT_N                 (EVP_PKEY_ALG_CTRL + 10)
# define EVP_PKEY_CTRL_SCRYPT_R                 (EVP_PKEY_ALG_CTRL + 11)
# define EVP_PKEY_CTRL_SCRYPT_P                 (EVP_PKEY_ALG_CTRL + 12)
# define EVP_PKEY_CTRL_SCRYPT_MAXMEM_BYTES      (EVP_PKEY_ALG_CTRL + 13)

# define EVP_PKEY_HKDEF_MODE_EXTRACT_AND_EXPAND 0
# define EVP_PKEY_HKDEF_MODE_EXTRACT_ONLY       1
# define EVP_PKEY_HKDEF_MODE_EXPAND_ONLY        2

# define EVP_PKEY_CTX_set_tls1_prf_md(pctx, md) \
            EVP_PKEY_CTX_ctrl(pctx, -1, EVP_PKEY_OP_DERIVE, \
                              EVP_PKEY_CTRL_TLS_MD, 0, (void *)(md))

# define EVP_PKEY_CTX_set1_tls1_prf_secret(pctx, sec, seclen) \
            EVP_PKEY_CTX_ctrl(pctx, -1, EVP_PKEY_OP_DERIVE, \
                              EVP_PKEY_CTRL_TLS_SECRET, seclen, (void *)(sec))

# define EVP_PKEY_CTX_add1_tls1_prf_seed(pctx, seed, seedlen) \
            EVP_PKEY_CTX_ctrl(pctx, -1, EVP_PKEY_OP_DERIVE, \
                              EVP_PKEY_CTRL_TLS_SEED, seedlen, (void *)(seed))

# define EVP_PKEY_CTX_set_hkdf_md(pctx, md) \
            EVP_PKEY_CTX_ctrl(pctx, -1, EVP_PKEY_OP_DERIVE, \
                              EVP_PKEY_CTRL_HKDF_MD, 0, (void *)(md))

# define EVP_PKEY_CTX_set1_hkdf_salt(pctx, salt, saltlen) \
            EVP_PKEY_CTX_ctrl(pctx, -1, EVP_PKEY_OP_DERIVE, \
                              EVP_PKEY_CTRL_HKDF_SALT, saltlen, (void *)(salt))

# define EVP_PKEY_CTX_set1_hkdf_key(pctx, key, keylen) \
            EVP_PKEY_CTX_ctrl(pctx, -1, EVP_PKEY_OP_DERIVE, \
                              EVP_PKEY_CTRL_HKDF_KEY, keylen, (void *)(key))

# define EVP_PKEY_CTX_add1_hkdf_info(pctx, info, infolen) \
            EVP_PKEY_CTX_ctrl(pctx, -1, EVP_PKEY_OP_DERIVE, \
                              EVP_PKEY_CTRL_HKDF_INFO, infolen, (void *)(info))

# define EVP_PKEY_CTX_hkdf_mode(pctx, mode) \
            EVP_PKEY_CTX_ctrl(pctx, -1, EVP_PKEY_OP_DERIVE, \
                              EVP_PKEY_CTRL_HKDF_MODE, mode, NULL)

# define EVP_PKEY_CTX_set1_pbe_pass(pctx, pass, passlen) \
            EVP_PKEY_CTX_ctrl(pctx, -1, EVP_PKEY_OP_DERIVE, \
                            EVP_PKEY_CTRL_PASS, passlen, (void *)(pass))

# define EVP_PKEY_CTX_set1_scrypt_salt(pctx, salt, saltlen) \
            EVP_PKEY_CTX_ctrl(pctx, -1, EVP_PKEY_OP_DERIVE, \
                            EVP_PKEY_CTRL_SCRYPT_SALT, saltlen, (void *)(salt))

# define EVP_PKEY_CTX_set_scrypt_N(pctx, n) \
            EVP_PKEY_CTX_ctrl_uint64(pctx, -1, EVP_PKEY_OP_DERIVE, \
                            EVP_PKEY_CTRL_SCRYPT_N, n)

# define EVP_PKEY_CTX_set_scrypt_r(pctx, r) \
            EVP_PKEY_CTX_ctrl_uint64(pctx, -1, EVP_PKEY_OP_DERIVE, \
                            EVP_PKEY_CTRL_SCRYPT_R, r)

# define EVP_PKEY_CTX_set_scrypt_p(pctx, p) \
            EVP_PKEY_CTX_ctrl_uint64(pctx, -1, EVP_PKEY_OP_DERIVE, \
                            EVP_PKEY_CTRL_SCRYPT_P, p)

# define EVP_PKEY_CTX_set_scrypt_maxmem_bytes(pctx, maxmem_bytes) \
            EVP_PKEY_CTX_ctrl_uint64(pctx, -1, EVP_PKEY_OP_DERIVE, \
                            EVP_PKEY_CTRL_SCRYPT_MAXMEM_BYTES, maxmem_bytes)

/*
 * Generated by util/mkerr.pl DO NOT EDIT
 */

int ERR_load_KDF_strings(void);

/*
 * KDF function codes.
 */
# define KDF_F_PKEY_HKDF_CTRL_STR                         103
# define KDF_F_PKEY_HKDF_DERIVE                           102
# define KDF_F_PKEY_HKDF_INIT                             108
# define KDF_F_PKEY_SCRYPT_CTRL_STR                       104
# define KDF_F_PKEY_SCRYPT_CTRL_UINT64                    105
# define KDF_F_PKEY_SCRYPT_DERIVE                         109
# define KDF_F_PKEY_SCRYPT_INIT                           106
# define KDF_F_PKEY_SCRYPT_SET_MEMBUF                     107
# define KDF_F_PKEY_TLS1_PRF_CTRL_STR                     100
# define KDF_F_PKEY_TLS1_PRF_DERIVE                       101
# define KDF_F_PKEY_TLS1_PRF_INIT                         110
# define KDF_F_TLS1_PRF_ALG                               111

/*
 * KDF reason codes.
 */
# define KDF_R_INVALID_DIGEST                             100
# define KDF_R_MISSING_ITERATION_COUNT                    109
# define KDF_R_MISSING_KEY                                104
# define KDF_R_MISSING_MESSAGE_DIGEST                     105
# define KDF_R_MISSING_PARAMETER                          101
# define KDF_R_MISSING_PASS                               110
# define KDF_R_MISSING_SALT                               111
# define KDF_R_MISSING_SECRET                             107
# define KDF_R_MISSING_SEED                               106
# define KDF_R_UNKNOWN_PARAMETER_TYPE                     103
# define KDF_R_VALUE_ERROR                                108
# define KDF_R_VALUE_MISSING                              102

# ifdef  __cplusplus
}
# endif
#endif
