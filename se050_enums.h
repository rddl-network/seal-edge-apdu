/**
 * Copyright (c) 2020, Michael Grand
 * SPDX-License-Identifier: Apache-2.0
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef SE050_ENUMS_H
#define SE050_ENUMS_H

typedef enum
{ /** Invalid */
    SW_NA = 0,
    /** No Error */
    SW_NO_ERROR = 0x9000,
    /** Conditions not satisfied */
    SW_CONDITIONS_NOT_SATISFIED = 0x6985,
    /** Security status not satisfied. */
    SW_SECURITY_STATUS = 0x6982,
    /** Wrong data provided. */
    SW_WRONG_DATA = 0x6A80,
    /** Data invalid - policy set invalid for the given object */
    SW_DATA_INVALID = 0x6984,
    /** Command not allowed - access denied based on object policy */
   SW_COMMAND_NOT_ALLOWED = 0x6986,
} SE050_SW_t;

typedef enum
{
    /** Mask for getting attestation data. */
    SE050_INS_ATTEST = 0x20,
    /** Perform Security Operation */
    SE050_INS_WRITE  = 0x01,
    SE050_INS_READ   = 0x02,
    SE050_INS_CRYPTO = 0x03,
    SE050_INS_MGMT   = 0x04,
    SE050_INS_PROCESS = 0x05,
    SE050_INS_IMPORT_EXTRNL   = 0x06
} SE050_INS_t;

typedef enum
{
	SE050_P1_DEFAULT = 0x00,
    SE050_P1_EC      = 0x01,
    SE050_P1_BINARY  = 0x06,
    SE050_P1_CURVE      = 0x0B,
    SE050_P1_SIGNATURE  = 0x0C,
    SE050_P1_CRYPTO_OBJ = 0x10
} SE050_P1_t;

typedef enum
{
    SE050_P2_DEFAULT        = 0x00,
    SE050_P2_SIGN           = 0x09,
    SE050_P2_VERIFY         = 0x0A,
    SE050_P2_ONESHOT        = 0x0E,
    SE050_P2_SESSION_CLOSE  = 0x1C,
    SE050_P2_VERSION        = 0x20,
    SE050_P2_LIST           = 0x25,
    SE050_P2_TYPE           = 0x26,
    SE050_P2_EXIST          = 0x27,
    SE050_P2_DELETE_OBJ     = 0x28,
    SE050_P2_DELETEALL      = 0x2A,
    SE050_P2_I2CM           = 0x30,
    SE050_P2_ID             = 0x36,
    SE050_P2_RANDOM         = 0x49
} SE050_P2_t;

typedef enum
{
    SE050_TAG_1 = 0x41,
    SE050_TAG_2 = 0x42,
    SE050_TAG_3 = 0x43,
    SE050_TAG_4 = 0x44,
    SE050_TAG_5 = 0x45,
    SE050_TAG_6 = 0x46,
    SE050_TAG_7 = 0x47
} SE050_TAG_t;

typedef enum
{ /** Invalid */
    SE050_ECSignatureAlgo_NA = 0,
    /** NOT SUPPORTED */
    SE050_ECSignatureAlgo_PLAIN = 0x09,
    SE050_ECSignatureAlgo_SHA = 0x11,
    SE050_ECSignatureAlgo_SHA_224 = 0x25,
    SE050_ECSignatureAlgo_SHA_256 = 0x21,
    SE050_ECSignatureAlgo_SHA_384 = 0x22,
    SE050_ECSignatureAlgo_SHA_512 = 0x26,
} SE050_ECSignatureAlgo_t;

typedef enum
{ /** Invalid */
    SE050_EDSignatureAlgo_NA = 0,
    /** Message input must be prehashed (using SHA512). */
    SE050_EDSignatureAlgo_ED25519PH_SHA_512 = 0xA3,
} SE050_EDSignatureAlgo_t;

typedef enum
{ /** Invalid */
    SE050_ECDAASignatureAlgo_NA = 0,
    /** Message input must be prehashed (using SHA256) */
    SE050_ECDAASignatureAlgo_ECDAA = 0xF4,
} SE050_ECDAASignatureAlgo_t;

typedef enum
{ /** Invalid */
    SE050_RSASignatureAlgo_NA = 0,
    /** RFC8017: RSASSA-PSS */
    SE050_RSASignatureAlgo_SHA1_PKCS1_PSS = 0x15,
    /** RFC8017: RSASSA-PSS */
    SE050_RSASignatureAlgo_SHA224_PKCS1_PSS = 0x2B,
    /** RFC8017: RSASSA-PSS */
    SE050_RSASignatureAlgo_SHA256_PKCS1_PSS = 0x2C,
    /** RFC8017: RSASSA-PSS */
    SE050_RSASignatureAlgo_SHA384_PKCS1_PSS = 0x2D,
    /** RFC8017: RSASSA-PSS */
    SE050_RSASignatureAlgo_SHA512_PKCS1_PSS = 0x2E,
    /** RFC8017: RSASSA-PKCS1-v1_5 */
    SE050_RSASignatureAlgo_SHA1_PKCS1 = 0x0A,
    /** RFC8017: RSASSA-PKCS1-v1_5 */
    SE050_RSASignatureAlgo_SHA_224_PKCS1 = 0x27,
    /** RFC8017: RSASSA-PKCS1-v1_5 */
    SE050_RSASignatureAlgo_SHA_256_PKCS1 = 0x28,
    /** RFC8017: RSASSA-PKCS1-v1_5 */
    SE050_RSASignatureAlgo_SHA_384_PKCS1 = 0x29,
    /** RFC8017: RSASSA-PKCS1-v1_5 */
    SE050_RSASignatureAlgo_SHA_512_PKCS1 = 0x2A,
} SE050_RSASignatureAlgo_t;

typedef enum
{
    SE050_TAG_I2CM_Config = 0x01,
    SE050_TAG_I2CM_Write = 0x03,
    SE050_TAG_I2CM_Read = 0x04,
} SE050_I2CM_TAG_t;

typedef enum
{
    SE050_AttestationAlgo_EC_PLAIN = SE050_ECSignatureAlgo_PLAIN,
    SE050_AttestationAlgo_EC_SHA = SE050_ECSignatureAlgo_SHA,
    SE050_AttestationAlgo_EC_SHA_224 = SE050_ECSignatureAlgo_SHA_224,
    SE050_AttestationAlgo_EC_SHA_256 = SE050_ECSignatureAlgo_SHA_256,
    SE050_AttestationAlgo_EC_SHA_384 = SE050_ECSignatureAlgo_SHA_384,
    SE050_AttestationAlgo_EC_SHA_512 = SE050_ECSignatureAlgo_SHA_512,
    SE050_AttestationAlgo_ED25519PH_SHA_512 = SE050_EDSignatureAlgo_ED25519PH_SHA_512,
    SE050_AttestationAlgo_ECDAA = SE050_ECDAASignatureAlgo_ECDAA,
    SE050_AttestationAlgo_RSA_SHA1_PKCS1_PSS = SE050_RSASignatureAlgo_SHA1_PKCS1_PSS,
    SE050_AttestationAlgo_RSA_SHA224_PKCS1_PSS = SE050_RSASignatureAlgo_SHA224_PKCS1_PSS,
    SE050_AttestationAlgo_RSA_SHA256_PKCS1_PSS = SE050_RSASignatureAlgo_SHA256_PKCS1_PSS,
    SE050_AttestationAlgo_RSA_SHA384_PKCS1_PSS = SE050_RSASignatureAlgo_SHA384_PKCS1_PSS,
    SE050_AttestationAlgo_RSA_SHA512_PKCS1_PSS = SE050_RSASignatureAlgo_SHA512_PKCS1_PSS,
    SE050_AttestationAlgo_RSA_SHA_224_PKCS1 = SE050_RSASignatureAlgo_SHA_224_PKCS1,
    SE050_AttestationAlgo_RSA_SHA_256_PKCS1 = SE050_RSASignatureAlgo_SHA_256_PKCS1,
    SE050_AttestationAlgo_RSA_SHA_384_PKCS1 = SE050_RSASignatureAlgo_SHA_384_PKCS1,
    SE050_AttestationAlgo_RSA_SHA_512_PKCS1 = SE050_RSASignatureAlgo_SHA_512_PKCS1,

} SE050_AttestationAlgo_t;

typedef enum
{
    SE050_UNUSED 		 = 0x00, 
    SE050_NIST_P192 	 = 0x01, 
    SE050_NIST_P224 	 = 0x02, 
    SE050_NIST_P256 	 = 0x03, 
    SE050_NIST_P384 	 = 0x04, 
    SE050_NIST_P521 	 = 0x05, 
    SE050_Brainpool160   = 0x06, 
    SE050_Brainpool192   = 0x07, 
    SE050_Brainpool224   = 0x08, 
    SE050_Brainpool256   = 0x09, 
    SE050_Brainpool320   = 0x0A, 
    SE050_Brainpool384   = 0x0B, 
    SE050_Brainpool512   = 0x0C, 
    SE050_Secp160k1 	 = 0x0D, 
    SE050_Secp192k1 	 = 0x0E, 
    SE050_Secp224k1 	 = 0x0F, 
    SE050_Secp256k1 	 = 0x10, 
    SE050_TPM_ECC_BN_P256 = 0x11, 
    SE050_ID_ECC_ED_25519 = 0x40, 
    SE050_ID_ECC_MONT_DH_25519 = 0x41 
}SE050_ECCurve_t;

typedef enum
{
    SE050_DIGEST_NO_HASH    = 0x00,
    SE050_DIGEST_SHA        = 0x01,
    SE050_DIGEST_SHA224     = 0x07,
    SE050_DIGEST_SHA256     = 0x04,
    SE050_DIGEST_SHA384     = 0x05,
    SE050_DIGEST_SHA512     = 0x06
}SE050_Digest_Mode_t;

typedef enum
{
    SE050_RESULT_SUCCESS = 0x01,
    SE050_RESULT_FAIL    = 0x02
}SE050_Result_t;

typedef enum
{
    SE050_NO_MORE = 0x01,
    SE050_MORE    = 0x02
}SE050_More_Indicator_t;

#endif /* SE050_ENUMS_H */
