/*
 * @copyright Copyright (c) 2020, Michael Grand
 * @license SPDX-License-Identifier: Apache-2.0
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

#ifndef SE050_DRV_APDU_H_
#define SE050_DRV_APDU_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include "T1oI2C/phNxpEse_Api.h"
#include <stdbool.h>
#include "se050_enums.h"

/**
 * @file apdu.h
 * @author Michael Grand
 */

/**
 * Status returned by function used to pass APDU command to the SE050.
 * To status value are defined : APDU_OK (0) and APDU_ERROR (1).
 */
typedef enum {
	APDU_OK,		///< Proper execution of the fuction
	APDU_ERROR		///< An error has occured
} apdu_status_t;

/**
 * This structure allows to store command/response to/from the I2C
 * slave device connected to the SE050 chip.
 */
typedef struct {
	/// Used to store the type of a command either CONFIG, WRITE or READ
	SE050_I2CM_TAG_t tag;
	/// Structure containing a pointer to the cmd buffer and the length of the command
	phNxpEse_data cmd;
	/// Structure containing a point to the rsp buffer and the length of the obtained response
	phNxpEse_data rsp;
	/// Status word related to the command response
	uint8_t sw;
} i2cm_tlv_t;

/**
 * This structure contains pointers to attestation data fields. Currently, actual data
 * are stored in a single buffer.
 */
typedef struct {
	/// Structure containing a pointer to attested data and its length
	phNxpEse_data data;
	/// 16-byte Random returned by SE050
	uint8_t *outrandom;
	/// 18-byte ChipId returned by the SE050
	uint8_t *chipId;
	/// Structure containing a pointer to the attestation signature and its length
	phNxpEse_data signature;
	/// 12-byte time stamp returned by the SE050
	uint8_t *timeStamp;
} attestation_t;

/**
 * This structure is used to store the version of the SE050 firmware.
 */
typedef struct {
	/// Major version
	uint8_t major;
	/// Minor version
	uint8_t minor;
	/// Patch version
	uint8_t patch;
	/// AppletConfig version
	uint16_t appletConfig;
	/// SecureBox versin
	uint16_t secureBox;
} versionInfo_t;

/**
 * @biref Size of the APDU buffer
 */
#define APDU_BUFF_SZ 900
/**
 * @brief Structure storing the context of the connection.
 */
typedef struct {
	/// ATR value
	uint8_t atr[64];
	/// Length of the ATR
	uint8_t atrLen;
	/// Version of the SE050 firmware
	versionInfo_t version;
	/// APDU buffer which is used by this driver
	uint8_t buff[APDU_BUFF_SZ];
	/// Structure pointing to the APDU buffer and containing its length
	phNxpEse_data payload;
	/// Structure pointing to the APDU buffer and containing the length of the current command
	phNxpEse_data in;
	/// Structure pointing to the APDU buffer and containing the length of the current response
	phNxpEse_data out;
	/// Status word related to the current command response.
	uint16_t sw;
} apdu_ctx_t;

/**
 * @brief Structure storing the context of the object policy.
 */
typedef struct __attribute__((packed)){
	unsigned int polr_allow_decryption : 1;
	unsigned int polr_allow_encryption : 1;
	unsigned int polr_allow_key_agreement : 1;
	unsigned int polr_allow_verify : 1;
	unsigned int polr_allow_sign : 1;
	unsigned int polr_forbid_all : 1;
	unsigned int polr_reserved_1 : 2;
	unsigned int polr_require_pcr_val : 1;
	unsigned int polr_require_sm : 1;
	unsigned int polr_allow_delete : 1;
	unsigned int polr_allow_gen : 1;
	unsigned int polr_allow_write : 1;
	unsigned int polr_allow_read : 1;
	unsigned int polr_allow_wrap : 1;
	unsigned int polr_allow_key_derivation : 1;
	unsigned int polr_reserved_2 : 4;
	unsigned int polr_allow_import_export : 1;
	unsigned int polr_allow_desfire_dump_sess : 1;
	unsigned int polr_allow_desfire_auth : 1;
	unsigned int polr_allow_attestation : 1;
	unsigned int polr_reserved_3 : 8;
} apdu_obj_policy_rules_t;

typedef struct __attribute__((packed)){
	uint8_t					op_policy_length;
	uint32_t				op_auth_obj_id;
	apdu_obj_policy_rules_t	op_pol_rules;
}apdu_obj_policy_t;


/**
 * This command is used to initialize the APDU context structure.
 * @param ctx Pointer to an APDU context structure
 */
void apduSe050InitApduCtx(apdu_ctx_t *ctx);

/**
 * Allows connection to a SE050 chip (fixed I2C address 0x48).
 * This command trigger a chip reset followed by a select command.
 * ATR buffer and firmware version will be filled by this command.
 * @param ctx Pointer to an initialized APDU context structure
 * @returns status indicating if connect is successful
 */
apdu_status_t apduSe050Connect(apdu_ctx_t *apdu_ctx);

/**
 * Disconnect from SE050 chip.
 * @param ctx Pointer to an initialized APDU context structure
 * @returns status indicating if disconnection is successful
 */
apdu_status_t apduSe050Disconnect(apdu_ctx_t *ctx);

/**
 * Allows select the applet programmed in the SE050 chip.
 * This command fills the firmware version filed of the APDU context.
 * @param ctx Pointer to an initialized APDU context structure
 * @returns status indicating SE050 applet is properly selected
 */
apdu_status_t apduSe050Select(apdu_ctx_t *apdu_ctx);
apdu_status_t apduSe050Select2(apdu_ctx_t *apdu_ctx);

apdu_status_t se050_i2cm_attestedCmds(i2cm_tlv_t *tlv, uint8_t sz_tlv, SE050_AttestationAlgo_t algo,
		uint8_t *random, attestation_t *attestation, apdu_ctx_t *ctx);

/********************************************************************************************************************************/
/********************************************************************************************************************************/
/********************************************************************************************************************************/

typedef enum {
	APDU_CMD_CLOSE_SESSION, 
	APDU_CMD_READ_VERSION,
	APDU_CMD_DELETE_ALL,
	APDU_CMD_GET_RANDOM,
	APDU_CMD_INITUPDT,
	APDU_CMD_READIDLISTALL,
	APDU_CMD_READIDLISTCRY,
	APDU_CMD_READTYPE,
	APDU_CMD_READIDLISTCRV,
	APDU_CMD_READOBJCRV,
	APDU_CMD_DELETE_OBJ,
	APDU_CMD_CHECK_OBJ,
	APDU_CMD_WRITE_OBJ,
	APDU_CMD_SIGN,
	APDU_CMD_WRITE_PUB,
	APDU_CMD_READ_PUB,
	APDU_CMD_VERIFY,
	APDU_CMD_DIGESTONESHOT,
	APDU_CMD_BINARYWRITE,
	APDU_CMD_CREATE_CURVE,
	APDU_CMD_SET_CURVE,
	NUMBER_OF_APDU_CMD     
}APDU_HEADER_CMD_LIST;

typedef enum{
	P1_KEY_PAIR = 0x60,		// Key pair (private key + public key)
	P1_PRIVATE 	= 0x40, 	// Private key
	P1_PUBLIC 	= 0x20, 	// Public key
}APDU_KEY_TYPE_CONST;

typedef struct{
	uint8_t		aht_apdu_cli;
	uint8_t		aht_apdu_ins;
	uint8_t		aht_apdu_p1;
	uint8_t		aht_apdu_p2;
	uint32_t	aht_apdu_resp_len;
} apdu_header_table_t;

apdu_status_t se050_get_version_info( apdu_ctx_t *ctx, phNxpEse_data* resp);
apdu_status_t se050_nopayload_transceive( apdu_ctx_t *ctx, phNxpEse_data* resp, apdu_header_table_t* apt_cmd); 
apdu_status_t se050_apdu_readidlist(i2cm_tlv_t *tlv, apdu_ctx_t *ctx, phNxpEse_data* resp, apdu_header_table_t* apt_cmd);
apdu_status_t se050_apdu_delete_object(uint32_t obj_id, apdu_ctx_t *ctx, phNxpEse_data* resp, apdu_header_table_t* apt_cmd);
apdu_status_t se050_apdu_check_object(uint32_t obj_id, apdu_ctx_t *ctx, phNxpEse_data* resp, apdu_header_table_t* apt_cmd);
apdu_status_t se050_apdu_send_cmd(i2cm_tlv_t *tlv, uint8_t tlv_num, apdu_ctx_t *ctx, apdu_header_table_t* apt_cmd);

apdu_status_t apduInitInterface();
apdu_status_t apduCloseInterface();
apdu_status_t apduGenerateECCKeyPair_NISTP256(uint32_t keyID, bool deletable);
apdu_status_t apduSignSha256DigestECDSA_NISTP256(const uint32_t keyID, const uint8_t * digest, uint8_t *signature[], int32_t * signatureLen );
bool apduVerifySha256DigestECDSA_NISTP256(const uint8_t *pubKey, int32_t pubKeyLen, const uint8_t *digest, const uint8_t *signature, int32_t signatureLen);
bool apduIDExists(uint32_t keyID);
apdu_status_t apduGetECCPubKey_NISTP256(uint32_t keyID, uint8_t *pubkey[], int32_t * pubkeyLen);
apdu_status_t apduDeleteObj(uint32_t keyID);
uint8_t apduReadObjType(uint32_t keyID);
apdu_status_t apduReadCurve(phNxpEse_data  *resp);
uint8_t apduGetECCurveID(uint32_t keyID);
apdu_status_t apduReadIDList(phNxpEse_data  *resp);
apdu_status_t apduReadCryptoObjectList(phNxpEse_data  *resp);
apdu_status_t apduCalculateSHA256(uint8_t *input, size_t inputLen, uint8_t *output[]);
apdu_status_t apduGenerateRandom(size_t size , uint8_t *output[]);
apdu_status_t apduBinaryWriteData(uint32_t objId, const uint8_t *input, size_t inputLen, bool deletable);
apdu_status_t apduBinaryReadData(uint32_t objId, size_t dataLen , uint8_t* data[]);
apdu_status_t apduGenerateECCKeyPair_SECP256K1(uint32_t keyID, bool deletable);
apdu_status_t apduInjectECCKeyPair_SECP256K1(uint32_t keyID, uint8_t* privKey, uint32_t privKeyLen, uint8_t* pubKey, uint32_t pubKeyLen, bool deletable);

#define MAKE_TEST_ID(x) (0xEF | x<<24) 

#ifdef __cplusplus
}
#endif
#endif /* SE050_DRV_APDU_H_ */
