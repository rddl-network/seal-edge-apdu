/*
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
#include <stdio.h>
#include "apdu.h"
#include <string.h>

static apdu_ctx_t ctx;
static i2cm_tlv_t apduTlvBuff[5];

static apdu_header_table_t     apdu_header_table[NUMBER_OF_APDU_CMD] = {
                                /* CLI */   /* INS */           /* P1 */            /*  P2 */                   /* RES_PLEN */
/* APDU_CMD_CLOSE_SESSION */    {0x80,      SE050_INS_MGMT,     SE050_P1_DEFAULT,   SE050_P2_SESSION_CLOSE,      0},
/* APDU_CMD_READ_VERSION */     {0x80,      SE050_INS_MGMT,     SE050_P1_DEFAULT,   SE050_P2_VERSION,           0x0B},
/* APDU_CMD_DELETE_ALL*/        {0x80,      SE050_INS_MGMT,     SE050_P1_DEFAULT,   SE050_P2_DELETEALL,          0},
/* APDU_CMD_GET_RANDOM*/        {0x80,      SE050_INS_MGMT,     SE050_P1_DEFAULT,   SE050_P2_RANDOM,             0},
/* APDU_CMD_INITUPDT*/          {0x80,      0x50,               SE050_P1_DEFAULT,   SE050_P2_DEFAULT,            0},
/* APDU_CMD_READIDLISTALL*/     {0x80,      SE050_INS_READ,     SE050_P1_DEFAULT,   SE050_P2_LIST,               0},
/* APDU_CMD_READIDLISTCRY*/     {0x80,      SE050_INS_READ,     SE050_P1_CRYPTO_OBJ,SE050_P2_LIST,               0},
/* APDU_CMD_READTYPE*/			{0x80,      SE050_INS_READ,     SE050_P1_DEFAULT,	SE050_P2_TYPE,               0},
/* APDU_CMD_READIDLISTCRV*/     {0x80,      SE050_INS_READ,     SE050_P1_CURVE,     SE050_P2_LIST,               0},
/* APDU_CMD_READOBJCRV*/		{0x80,      SE050_INS_READ,     SE050_P1_DEFAULT,	SE050_P2_ID,               	-1},
/* APDU_CMD_DELETE_OBJ*/        {0x80,      SE050_INS_MGMT,     SE050_P1_DEFAULT,   SE050_P2_DELETE_OBJ,        -1},
/* APDU_CMD_CHECK_OBJ*/         {0x80,      SE050_INS_MGMT,     SE050_P1_DEFAULT,   SE050_P2_EXIST,             -1},
/* APDU_CMD_WRITE_OBJ*/         {0x80,      SE050_INS_WRITE,    P1_KEY_PAIR | SE050_P1_EC, SE050_P2_DEFAULT,    -1},
/* APDU_CMD_SIGN*/              {0x80,      SE050_INS_CRYPTO,   SE050_P1_SIGNATURE, SE050_P2_SIGN,              -1},
/* APDU_CMD_WRITE_PUB*/         {0x80,      SE050_INS_WRITE,    P1_PUBLIC | SE050_P1_EC, SE050_P2_DEFAULT,      -1},
/* APDU_CMD_READ_PUB*/          {0x80,      SE050_INS_READ,     SE050_P1_DEFAULT, 	SE050_P2_DEFAULT,      		-2},
/* APDU_CMD_VERIFY*/            {0x80,      SE050_INS_CRYPTO,   SE050_P1_SIGNATURE, SE050_P2_VERIFY,            -1},
/* APDU_CMD_DIGESTONESHOT*/     {0x80,      SE050_INS_CRYPTO,   SE050_P1_DEFAULT, 	SE050_P2_ONESHOT,           -1},
/* APDU_CMD_BINARYWRITE*/		{0x80,      SE050_INS_WRITE,   	SE050_P1_BINARY, 	SE050_P2_DEFAULT,           -1}
};

#define CHECK_IF_ERROR_AND_ACCUMULATE(tmp, acc) if(tmp > 0) {\
													acc += tmp;\
												} else {\
													return APDU_ERROR;\
												}

#define CHECK_IF_ERROR(a)	if(a != APDU_OK) {\
								return APDU_ERROR;\
							}

static uint32_t getTLVarray(SE050_TAG_t tag, uint8_t *buff, uint8_t *array[],
		int32_t *len, bool extended) {

	if (tag != buff[0])
		return 0;

	if (buff[1] == 0x82) { //extended
		*len = buff[2] << 8 | buff[3];
		*array = &buff[4];
		return *len + 4;
	} else {
		*len = buff[1];
		*array = &buff[2];
		return *len + 2;
	}
}

//TODO: extended array 0x82?
static uint32_t setTLVarray(SE050_TAG_t tag, uint8_t *buff, const uint8_t *array,
		uint32_t len) {

	uint32_t i = 0;

	buff[i++] = tag;

	if(len > 0xFFFF){
		buff[i++] = 0x83;
		buff[i++] = ((len >> 16) & 0xFF);
		buff[i++] = ((len >> 8) & 0xFF);
		buff[i++] = (len & 0xFF);
	}else if(len > 0xFF){
		buff[i++] = 0x82;
		buff[i++] = ((len >> 8) & 0xFF);
		buff[i++] = (len & 0xFF);
	}else if(len > 0x7F){
		buff[i++] = 0x81;
		buff[i++] = (len & 0xFF);
	}else
		buff[i++] = (len & 0x7F);

	memmove(&buff[i], &array[0], len);

	return (i + len);
}

void apduSe050InitApduCtx(apdu_ctx_t *ctx) {
	memset(ctx, 0, sizeof(apdu_ctx_t));
	ctx->in.len = APDU_BUFF_SZ;
	ctx->in.p_data = &ctx->buff[0];
	ctx->out.len = 0;
	ctx->out.p_data = &ctx->buff[0];
	ctx->sw = 0x0000;
}

apdu_status_t apduSe050Connect(apdu_ctx_t *ctx) {
	ESESTATUS ret;
	phNxpEse_initParams initParams = {.initMode = ESE_MODE_NORMAL};

	ret = phNxpEse_open(initParams);
	if (ret != ESESTATUS_SUCCESS) {
		return APDU_ERROR;
	}

	ret = phNxpEse_init(initParams, &ctx->out);
	if (ret != ESESTATUS_SUCCESS) {
		ctx->payload.len = 0;
		return APDU_ERROR;
	}
	ctx->atrLen = ctx->out.len;
	memcpy(ctx->atr, ctx->out.p_data, ctx->atrLen);
	return APDU_OK;
}

apdu_status_t apduSe050Disconnect(apdu_ctx_t *ctx) {
	if(ESESTATUS_SUCCESS != phNxpEse_close())
		return APDU_ERROR;
	return APDU_OK;
}

// does not support extend command
static apdu_status_t APDU_case4(const uint8_t *header, apdu_ctx_t *ctx, uint8_t lenSize) {
	ESESTATUS status = ESESTATUS_OK;
	static int cnt=1;

	if((ctx->in.len > 127) || (ctx->out.len == -2)){
		memmove(&ctx->in.p_data[6+lenSize], &ctx->in.p_data[0], ctx->in.len);
		memcpy(&ctx->in.p_data[0], &header[0], 4);

		ctx->in.p_data[4] = (ctx->in.len >> 16) & 0xFF;
		ctx->in.p_data[5] = (ctx->in.len >> 8) 	& 0xFF;	
		ctx->in.p_data[6] = (ctx->in.len) 		& 0xFF;
		ctx->in.len += 6+1;
	}else if(ctx->in.len){
		memmove(&ctx->in.p_data[4+lenSize], &ctx->in.p_data[0], ctx->in.len);
		memcpy(&ctx->in.p_data[0], &header[0], 4);

		ctx->in.p_data[4] = ctx->in.len & 0xFF;
		ctx->in.len += 4+1;
	}else{
		memmove(&ctx->in.p_data[4+lenSize], &ctx->in.p_data[0], ctx->in.len);
		memcpy(&ctx->in.p_data[0], &header[0], 4);
		ctx->in.len += 4;
	}

	if(ctx->out.len != -1)
		ctx->in.p_data[ctx->in.len++] = ctx->out.len & 0xFF;

	if(ctx->out.len == -2){
		ctx->in.p_data[ctx->in.len - 1]	= 0x00;
		ctx->in.p_data[ctx->in.len++] 	= 0x00;
	}

	if(ctx->out.len == 0 || ctx->out.len == -1 || ctx->out.len == -2)
		ctx->out.len = APDU_BUFF_SZ;
	ctx->out.len += 2; 

	// printf("\n*****APDUCASE4 TX %d: ", cnt++);
	// for(int i=0; i<ctx->in.len; i++)
	// 	printf("%02X ", ctx->in.p_data[i]);
	// printf("\n");
	
	status = phNxpEse_Transceive(&ctx->in, &ctx->out);
	
	// printf("\n*****APDUCASE4 RX: ");
	// for(int i=0; i<ctx->out.len; i++)
	// 	printf("%02X ", ctx->out.p_data[i]);
	// printf("\n");
	
	if (status == ESESTATUS_OK) {
		ctx->sw = ctx->out.p_data[ctx->out.len - 2] << 8
				| ctx->out.p_data[ctx->out.len - 1];
		ctx->out.len -= 2;
		return APDU_OK;
	} else {
		ctx->out.len = 0;
		ctx->sw = 0;
		return APDU_ERROR;
	}
}

apdu_status_t apduSe050Select(apdu_ctx_t *ctx) {

	apdu_status_t status;
	const uint8_t select_header[] = { 0x00, 0xA4, 0x04, 0x00, 0x00};
	const uint8_t applet_aid[] = { 0xA0, 0x00, 0x00, 0x03, 0x96, 0x54, 0x53,
			0x00, 0x00, 0x00, 0x01, 0x03, 0x00, 0x00, 0x00, 0x00 };

	ctx->in.len = 0;
	//ctx->in.p_data[0] = 0x00;
	//memcpy(&ctx->in.p_data[0], &applet_aid[0], ctx->in.len);
	ctx->out.len = 0;

	status = APDU_case4(&select_header[0], ctx, 0);
	if(status != APDU_OK || ctx->sw != 0x9000)
		return APDU_ERROR;

	ctx->version.major = ctx->out.p_data[0];
	ctx->version.minor = ctx->out.p_data[1];
	ctx->version.patch = ctx->out.p_data[2];
	ctx->version.appletConfig = ctx->out.p_data[3] << 8 | ctx->out.p_data[4];
	ctx->version.secureBox = ctx->out.p_data[5] << 8 | ctx->out.p_data[6];
	return APDU_OK;
}

apdu_status_t apduSe050Select2(apdu_ctx_t *ctx) {

	apdu_status_t status;
	const uint8_t select_header[] = { 0x00, 0xA4, 0x04, 0x00};
	const uint8_t applet_aid[] = { 0xA0, 0x00, 0x00, 0x03, 0x96, 0x54, 0x53,
			0x00, 0x00, 0x00, 0x01, 0x03, 0x00, 0x00 ,0x00};

	ctx->in.len = sizeof(applet_aid);
	memcpy(&ctx->in.p_data[0], &applet_aid[0], ctx->in.len);
	ctx->out.len = 0;

	status = APDU_case4(&select_header[0], ctx, 1);
	if(status != APDU_OK || ctx->sw != 0x9000)
		return APDU_ERROR;

	ctx->version.major = ctx->out.p_data[0];
	ctx->version.minor = ctx->out.p_data[1];
	ctx->version.patch = ctx->out.p_data[2];
	ctx->version.appletConfig = ctx->out.p_data[3] << 8 | ctx->out.p_data[4];
	ctx->version.secureBox = ctx->out.p_data[5] << 8 | ctx->out.p_data[6];
	return APDU_OK;
}


apdu_status_t se050_apdu_send_cmd(i2cm_tlv_t *tlv, uint8_t tlv_num, apdu_ctx_t *ctx, apdu_header_table_t* apt_cmd) {
	const uint8_t select_header[] = { apt_cmd->aht_apdu_cli, apt_cmd->aht_apdu_ins, apt_cmd->aht_apdu_p1, apt_cmd->aht_apdu_p2};

	uint32_t lc = 0;

	for(int i=0; i<tlv_num; i++)
		lc += setTLVarray(tlv[i].tag, &ctx->in.p_data[lc], tlv[i].cmd.p_data, tlv[i].cmd.len);

	ctx->in.len  = lc;
	ctx->out.len = apt_cmd->aht_apdu_resp_len;

	apdu_status_t status = APDU_case4(&select_header[0], ctx, 1);

	if (ctx->sw != 0x9000)
		return APDU_ERROR;

	return APDU_OK;
}

void apduSysExit(const char* msg){
    printf("ERROR! %s\n", msg);
    //exit(EXIT_FAILURE);
}

uint8_t apduReadObjType(uint32_t keyID){
	phNxpEse_data  response;

	if(apduIDExists(keyID) == false)
		return APDU_ERROR;

	if(se050_apdu_send_cmd(NULL, 0, &ctx, &apdu_header_table[APDU_CMD_READTYPE]) == APDU_ERROR)
        apduSysExit("APDU_CMD_READTYPE");

	uint32_t le 	= 0;
	uint32_t tmp_le = 0;
	tmp_le = getTLVarray(SE050_TAG_1, &ctx.out.p_data[le], &response.p_data, &response.len, false);
	CHECK_IF_ERROR_AND_ACCUMULATE(tmp_le, le);
	
	return *response.p_data;
}


apdu_status_t apduReadCurve(phNxpEse_data  *resp){
	if(se050_apdu_send_cmd(NULL, 0, &ctx, &apdu_header_table[APDU_CMD_READIDLISTCRV]) == APDU_ERROR)
        apduSysExit("APDU_CMD_READIDLISTCRV");

	uint32_t le 	= 0;
	uint32_t tmp_le = 0;
	tmp_le = getTLVarray(SE050_TAG_1, &ctx.out.p_data[le], &resp->p_data, &resp->len, true);
	CHECK_IF_ERROR_AND_ACCUMULATE(tmp_le, le);
	
	return APDU_OK;
}


uint8_t apduGetECCurveID(uint32_t keyID){
	phNxpEse_data  response;

	if(apduIDExists(keyID) == false)
		return APDU_ERROR;

	if(se050_apdu_send_cmd(NULL, 0, &ctx, &apdu_header_table[APDU_CMD_READOBJCRV]) == APDU_ERROR)
        apduSysExit("APDU_CMD_READOBJCRV");

	uint32_t le 	= 0;
	uint32_t tmp_le = 0;
	tmp_le = getTLVarray(SE050_TAG_1, &ctx.out.p_data[le], &response.p_data, &response.len, false);
	CHECK_IF_ERROR_AND_ACCUMULATE(tmp_le, le);
	
	return *response.p_data;
}

apdu_status_t apduReadIDList(phNxpEse_data  *resp){
	uint8_t data1[4]   			= {0x00, 0x00};
    apduTlvBuff[0].tag          = SE050_TAG_1;
    apduTlvBuff[0].cmd.len      = 2;
    apduTlvBuff[0].cmd.p_data   = &data1[0];
    uint8_t data2[1]   			= {0xFF};
    apduTlvBuff[1].tag          = SE050_TAG_2;
    apduTlvBuff[1].cmd.len      = 1;
    apduTlvBuff[1].cmd.p_data   = &data2[0];

	if(se050_apdu_send_cmd(apduTlvBuff, 2, &ctx, &apdu_header_table[APDU_CMD_READIDLISTALL]) == APDU_ERROR)
        apduSysExit("APDU_CMD_READIDLISTALL");

	uint32_t le 	= 0;
	uint32_t tmp_le = 0;
	tmp_le = getTLVarray(SE050_TAG_1, &ctx.out.p_data[le], &resp->p_data, &resp->len, false);
	CHECK_IF_ERROR_AND_ACCUMULATE(tmp_le, le);

	// TODO: Check More Indicator

	tmp_le = getTLVarray(SE050_TAG_2, &ctx.out.p_data[le], &resp->p_data, &resp->len, true);
	CHECK_IF_ERROR_AND_ACCUMULATE(tmp_le, le);
	
	return APDU_OK;
}


apdu_status_t apduReadCryptoObjectList(phNxpEse_data  *resp){
	if(se050_apdu_send_cmd(NULL, 0, &ctx, &apdu_header_table[APDU_CMD_READIDLISTCRY]) == APDU_ERROR)
        apduSysExit("APDU_CMD_READIDLISTCRY");

	uint32_t le 	= 0;
	uint32_t tmp_le = 0;
	tmp_le = getTLVarray(SE050_TAG_1, &ctx.out.p_data[le], &resp->p_data, &resp->len, true);
	CHECK_IF_ERROR_AND_ACCUMULATE(tmp_le, le);
	
	return APDU_OK;
}

apdu_status_t apduInitInterface(){
	apduSe050InitApduCtx(&ctx);

    if(apduSe050Connect(&ctx) == APDU_ERROR) apduSysExit("apduSe050Connect");

    if(apduSe050Select(&ctx) == APDU_ERROR) apduSysExit("apduSe050Select");

	if(apduSe050Select2(&ctx) == APDU_ERROR) apduSysExit("apduSe050Select2");

	return APDU_OK;
}

apdu_status_t apduGenerateECCKeyPair_NISTP256(uint32_t keyID){
	phNxpEse_data	resp;
	
	if(apduReadIDList(&resp) == APDU_ERROR)
		apduSysExit("apduReadIDList");

	if(apduReadCryptoObjectList(&resp) == APDU_ERROR)
		apduSysExit("apduReadCryptoObjectList");

	if(apduIDExists(keyID) == true){
		//printf("Obj Exist\n");
		//return APDU_OK;
	}

	if(apduReadCurve(&resp) == APDU_ERROR)
		apduSysExit("apduReadCurve");

	if(apduIDExists(keyID) == true){
		//printf("Obj Exist\n");
		//return APDU_OK;
	}
	
	uint32_t data1    			= keyID;
    apduTlvBuff[0].tag          = SE050_TAG_1;
    apduTlvBuff[0].cmd.len      = 4;
    apduTlvBuff[0].cmd.p_data   = (uint8_t *)&data1;
    uint8_t data2[1]    		= {SE050_NIST_P256};
    apduTlvBuff[1].tag          = SE050_TAG_2;
    apduTlvBuff[1].cmd.len      = 1;
    apduTlvBuff[1].cmd.p_data   = &data2[0]; 

    if(se050_apdu_send_cmd(apduTlvBuff, 2, &ctx, &apdu_header_table[APDU_CMD_WRITE_OBJ]) == APDU_ERROR) apduSysExit("APDU_CMD_WRITE_OBJ");

	return APDU_OK;
}

apdu_status_t apduSignSha256DigestECDSA_NISTP256(const uint32_t keyID, const uint8_t *digest, uint8_t *signature[], size_t * signatureLen ){

	// if(apduIDExists(keyID) == true){
	// 	printf("Obj Exist\n");
	// }
	
	uint32_t data1				= keyID;
    apduTlvBuff[0].tag          = SE050_TAG_1;
    apduTlvBuff[0].cmd.len      = 4;
    apduTlvBuff[0].cmd.p_data   = (uint8_t *)&data1;
    uint8_t data2[1]   			= {SE050_ECSignatureAlgo_SHA_256};
    apduTlvBuff[1].tag          = SE050_TAG_2;
    apduTlvBuff[1].cmd.len      = 1;
    apduTlvBuff[1].cmd.p_data   = &data2[0];

    apduTlvBuff[2].tag          = SE050_TAG_3;
    apduTlvBuff[2].cmd.len      = 32;
    apduTlvBuff[2].cmd.p_data   = digest;

    if(se050_apdu_send_cmd(apduTlvBuff, 3, &ctx, &apdu_header_table[APDU_CMD_SIGN]) == APDU_ERROR) apduSysExit("APDU_CMD_SIGN");

	uint32_t le = 0;
	uint32_t tmp_le = 0;
	uint32_t fieldLen = 0;
	tmp_le = getTLVarray(SE050_TAG_1, &ctx.out.p_data[le], signature, signatureLen, false);
	CHECK_IF_ERROR_AND_ACCUMULATE(tmp_le, le);
	
	return APDU_OK;
}

bool apduIDExists(uint32_t keyID){
	phNxpEse_data  response;

	uint32_t data	   			= keyID;
    apduTlvBuff[0].tag          = SE050_TAG_1;
    apduTlvBuff[0].cmd.len      = 4;
    apduTlvBuff[0].cmd.p_data   = (uint8_t *)&data;

	if(se050_apdu_send_cmd(apduTlvBuff, 1, &ctx, &apdu_header_table[APDU_CMD_CHECK_OBJ]) == APDU_ERROR)
        apduSysExit("APDU_CMD_CHECK_OBJ");
	else{
		uint32_t le = 0;
		uint32_t tmp_le = 0;
		tmp_le = getTLVarray(SE050_TAG_1, &ctx.out.p_data[le], &response.p_data, &response.len, false);
		CHECK_IF_ERROR_AND_ACCUMULATE(tmp_le, le);
	}

	return (*response.p_data != SE050_RESULT_SUCCESS);
}

apdu_status_t apduGetECCPubKey_NISTP256(uint32_t keyID, uint8_t *pubkey[], size_t * pubkeyLen){
	if(apduIDExists(keyID) == false)
		return APDU_ERROR;

	uint32_t data	   			= keyID;
    apduTlvBuff[0].tag          = SE050_TAG_1;
    apduTlvBuff[0].cmd.len      = 4;
    apduTlvBuff[0].cmd.p_data   = (uint8_t *)&data;

	if(se050_apdu_send_cmd(apduTlvBuff, 1, &ctx, &apdu_header_table[APDU_CMD_READ_PUB]) == APDU_ERROR)
        apduSysExit("APDU_CMD_READ_PUB");
	else{
		uint32_t le = 0;
		uint32_t tmp_le = 0;
		tmp_le = getTLVarray(SE050_TAG_1, &ctx.out.p_data[le], pubkey, pubkeyLen, true);
		CHECK_IF_ERROR_AND_ACCUMULATE(tmp_le, le);
	}

	return APDU_OK;
}

apdu_status_t apduDeleteObj(uint32_t keyID){
	apdu_status_t status = APDU_OK;
	if(apduIDExists(keyID) == false)
		return APDU_OK;

	uint8_t data[]	   			= {(uint8_t)((keyID>>24) & 0xFF), (uint8_t)((keyID>>16) & 0xFF) , (uint8_t)((keyID>>8) & 0xFF), (uint8_t)(keyID & 0xFF)};
    apduTlvBuff[0].tag          = SE050_TAG_1;
    apduTlvBuff[0].cmd.len      = 4;
    apduTlvBuff[0].cmd.p_data   = data;

	if((status = se050_apdu_send_cmd(apduTlvBuff, 1, &ctx, &apdu_header_table[APDU_CMD_DELETE_OBJ])) == APDU_ERROR)
        apduSysExit("APDU_CMD_DELETE_OBJ");

	return status;
}	


apdu_status_t apduCalculateSHA256(uint8_t *input, size_t inputLen, uint8_t *output[]){
	apdu_status_t status = APDU_OK;
	uint8_t data1				= SE050_DIGEST_SHA256;
    apduTlvBuff[0].tag          = SE050_TAG_1;
    apduTlvBuff[0].cmd.len      = 1;
    apduTlvBuff[0].cmd.p_data   = (uint8_t *)&data1;

    apduTlvBuff[1].tag          = SE050_TAG_2;
    apduTlvBuff[1].cmd.len      = inputLen;
    apduTlvBuff[1].cmd.p_data   = input;

	if((status = se050_apdu_send_cmd(apduTlvBuff, 2, &ctx, &apdu_header_table[APDU_CMD_DIGESTONESHOT])) == APDU_ERROR)
        apduSysExit("APDU_CMD_DIGESTONESHOT");
	else{
		uint32_t le = 0;
		uint32_t tmp_le = 0;
		int32_t outSize = 0;
		tmp_le = getTLVarray(SE050_TAG_1, &ctx.out.p_data[le], output, &outSize, true);
		CHECK_IF_ERROR_AND_ACCUMULATE(tmp_le, le);
	}

	return status;
}


apdu_status_t apduGenerateRandom(size_t size , uint8_t *output[]){
	apdu_status_t status = APDU_OK;
	uint8_t data1[2]			;
    apduTlvBuff[0].tag          = SE050_TAG_1;
    apduTlvBuff[0].cmd.len      = 2;
    apduTlvBuff[0].cmd.p_data   = (uint8_t *)&data1;
	data1[0]					= 0;
	data1[1]					= (uint8_t)size;	

	if((status = se050_apdu_send_cmd(apduTlvBuff, 1, &ctx, &apdu_header_table[APDU_CMD_GET_RANDOM])) == APDU_ERROR)
        apduSysExit("APDU_CMD_GET_RANDOM");
	else{
		uint32_t le = 0;
		uint32_t tmp_le = 0;
		int32_t outSize = 0;
		tmp_le = getTLVarray(SE050_TAG_1, &ctx.out.p_data[le], output, &outSize, true);
		CHECK_IF_ERROR_AND_ACCUMULATE(tmp_le, le);
	}

	return status;
}


apdu_status_t apduBinaryWriteData(uint32_t objId, const uint8_t *input, size_t inputLen){
	apdu_status_t status = APDU_OK;
	uint8_t data1[4]			= {(uint8_t)((objId>>24 )& 0xFF), (uint8_t)((objId>>16 )& 0xFF) , (uint8_t)((objId>>8 )& 0xFF), (uint8_t)(objId & 0xFF)};
    apduTlvBuff[0].tag          = SE050_TAG_1;
    apduTlvBuff[0].cmd.len      = 4;
    apduTlvBuff[0].cmd.p_data   = (uint8_t *)&data1;

	uint8_t fileLen[2]			= {(uint8_t)(inputLen>>8), (uint8_t)(inputLen & 0xFF)};
    apduTlvBuff[1].tag          = SE050_TAG_3;
    apduTlvBuff[1].cmd.len      = 2;
    apduTlvBuff[1].cmd.p_data   = (uint8_t *)&fileLen;

	uint8_t* data_ptr			= (uint8_t*)malloc(inputLen + 1);
	//data_ptr[0]					= (uint8_t)inputLen;
	memcpy(&data_ptr[0], input, inputLen);
	apduTlvBuff[2].tag          = SE050_TAG_4;
    apduTlvBuff[2].cmd.len      = inputLen;
    apduTlvBuff[2].cmd.p_data   = data_ptr;

	if((status = se050_apdu_send_cmd(apduTlvBuff, 3, &ctx, &apdu_header_table[APDU_CMD_BINARYWRITE])) == APDU_ERROR)
        apduSysExit("APDU_CMD_BINARYWRITE");

	return status;
}


apdu_status_t apduBinaryReadData(uint32_t objId, size_t dataLen , uint8_t* data[]){
	apdu_status_t status = APDU_OK;
	uint8_t data1[4]			= {(uint8_t)((objId>>24 )& 0xFF), (uint8_t)((objId>>16 )& 0xFF) , (uint8_t)((objId>>8 )& 0xFF), (uint8_t)(objId & 0xFF)};
    apduTlvBuff[0].tag          = SE050_TAG_1;
    apduTlvBuff[0].cmd.len      = 4;
    apduTlvBuff[0].cmd.p_data   = (uint8_t *)&data1;

	uint8_t fileLen[2]			= {(uint8_t)(dataLen>>8), (uint8_t)(dataLen & 0xFF)};
    apduTlvBuff[1].tag          = SE050_TAG_3;
    apduTlvBuff[1].cmd.len      = 2;
    apduTlvBuff[1].cmd.p_data   = (uint8_t *)&fileLen;

	if((status = se050_apdu_send_cmd(apduTlvBuff, 2, &ctx, &apdu_header_table[APDU_CMD_READ_PUB])) == APDU_ERROR)
        apduSysExit("apduBinaryReadData");
	else{
		uint32_t le = 0;
		uint32_t tmp_le = 0;
		uint32_t data_len = dataLen;
		tmp_le = getTLVarray(SE050_TAG_1, &ctx.out.p_data[le], data, &data_len, true);
		CHECK_IF_ERROR_AND_ACCUMULATE(tmp_le, le);
	}

	return status;
}