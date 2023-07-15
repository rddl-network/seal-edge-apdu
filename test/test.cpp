#include <iostream>
#include "../se050_middleware.h"

int main(){
    se050_obj.init_interface();

    se050_obj.generate_key_pair_nistp256();

    std::vector<uint8_t> digest = {0x48, 0x65, 0x6C, 0x6C, 0x6F, 0x20, 0x57, 0x6F, 0x72, 0x6C, 0x64, 0x00, 0x00, 0x00, 0x00, 0x00,
                                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

    std::vector<uint8_t> signBuff = se050_obj.sign_sha256_digest(digest); 
    std::cout << "Signed buff: ";
    se050_obj.print_hex_buffer(signBuff);

    std::vector<uint8_t> hashInput = {'H', 'E', 'L', 'L', 'O', 'W', 'O', 'R', 'L', 'D'};

    auto hashBuff = se050_obj.calculate_sha256(hashInput);
    std::cout << "Hash buff: ";
    se050_obj.print_hex_buffer(hashBuff);

    return 0;
}