#include <iostream>
#include <iomanip>
#include "se050_middleware.h"
#include "apdu.h"

extern "C"{
    #include "platform/i2c.h"
}

Se050Middleware se050_obj; 

void Se050Middleware::init_interface(){
    if(apduInitInterface() == APDU_ERROR)
        std::cout << "ERROR! se050 init_interface" << "\n";

    return;
}


void Se050Middleware::init_interface(int sda, int scl){
    if(apduInitInterface() == APDU_ERROR)
        std::cout << "ERROR! se050 init_interface" << "\n";

    set_sda_scl_pins(sda, scl);
    return;
}


void Se050Middleware::generate_key_pair_nistp256(){
    if(apduGenerateECCKeyPair_NISTP256(mkey_id) == APDU_ERROR)
        std::cout << "ERROR! se050 generate_key_pair_nistp256" << "\n";

    return;
}


std::vector<uint8_t> Se050Middleware::sign_sha256_digest(const std::vector<uint8_t>& digest){
    int32_t  sign_len = 256;
    uint8_t* resp_ptr = nullptr;
    std::vector<uint8_t> signature;

    if(apduSignSha256DigestECDSA_NISTP256(mkey_id, digest.data(), &resp_ptr, &sign_len) == APDU_ERROR)
        std::cout << "ERROR! se050 sign_sha256_digest" << "\n";
    else
        signature.insert(signature.begin(), resp_ptr, resp_ptr + SHA256_HASH_BUFF_SIZE);
    
    return signature;
}


std::vector<uint8_t> Se050Middleware::calculate_sha256(std::vector<uint8_t>& payload){
    uint8_t* resp_ptr = nullptr;
    std::vector<uint8_t> hashBuff;

    if(apduCalculateSHA256(payload.data(), payload.size(), &resp_ptr) == APDU_ERROR)
        std::cout << "ERROR! se050 calculate_sha256" << "\n";
    else
        hashBuff.insert(hashBuff.begin(), resp_ptr, resp_ptr + SHA256_HASH_BUFF_SIZE);

    return hashBuff;
}


std::vector<uint8_t> Se050Middleware::generate_random_number(size_t size){
    uint8_t* resp_ptr = nullptr;
    std::vector<uint8_t> randNum;

    if(apduGenerateRandom(size, &resp_ptr) == APDU_ERROR)
        std::cout << "ERROR! se050 generate_random_number" << "\n";
    else
        randNum.insert(randNum.begin(), resp_ptr, resp_ptr + size);

    return randNum;
}



void Se050Middleware::delete_obj(size_t objId){
    if(apduDeleteObj(objId) == APDU_ERROR)
        std::cout << "ERROR! se050 delete_obj" << "\n";

    return;
}


void Se050Middleware::print_hex_buffer(const std::vector<uint8_t>& hexBuff){
    for(auto x : hexBuff)
        std::cout << std::setw(2) << std::setfill('0') << std::hex << (int)x << " ";
    std::cout << std::endl;
}


int Se050Middleware::write_binary_data(size_t objId, const std::vector<uint8_t>& payload){
    uint8_t* resp_ptr = nullptr;
    int      ret_val = 0;

    if(apduBinaryWriteData(objId, payload.data(), payload.size()) == APDU_ERROR)
        std::cout << "ERROR! se050 write_binary_data" << "\n";
    else
        ret_val = payload.size();
    
    return ret_val;
}


std::vector<uint8_t> Se050Middleware::read_binary_data(size_t objId, size_t dataLen){
    uint8_t* resp_ptr = nullptr;
    std::vector<uint8_t> signature;

    if(apduBinaryReadData(objId, dataLen, &resp_ptr) == APDU_ERROR)
        std::cout << "ERROR! se050 read_binary_data" << "\n";    
    else
        signature.insert(signature.begin(), resp_ptr, resp_ptr + dataLen);

    return signature;
}