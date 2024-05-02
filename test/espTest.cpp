#include <iostream>
#include <Arduino.h>
#include <Wire.h>
#include <se050_middleware.h>


constexpr int BINARY_RW_SLOT = 225;
constexpr int BINARY_TEST_SIZE = 64; 

void se050ErrorCheck(Se050Middleware& se050_obj, const char* msg){
  char errMsg[100];
  se050_obj.read_error_msg(errMsg);
  if(strlen(errMsg) != 0){ 
    Serial.print(msg); Serial.println(errMsg);
  }
}


void setup() {
  /* Init Serial Bus */ 
  Serial.begin(115200);
  Serial.println("\nTest Begin\n");

  int keyId = MAKE_TEST_ID(__LINE__) - 4;
  Se050Middleware se050_obj(keyId); 

  se050_obj.init_interface(5, 6);
  se050_obj.generate_key_pair_nistp256();
  se050ErrorCheck(se050_obj, "generate_key_pair_nistp256 err: ");

  std::vector<uint8_t> hashInput = {'H', 'E', 'L', 'L', 'O', 'W', 'O', 'R', 'L', 'D'};

  auto hashBuff = se050_obj.calculate_sha256(hashInput);
  se050ErrorCheck(se050_obj, "calculate_sha256 err: ");
  std::cout << "Hash buff: ";
  se050_obj.print_hex_buffer(hashBuff);


  std::vector<uint8_t> signBuff = se050_obj.sign_sha256_digest(hashBuff); 
  se050ErrorCheck(se050_obj, "sign_sha256_digest err: ");
  std::cout << "Signed buff: ";
  se050_obj.print_hex_buffer(signBuff);

  auto pubKey = se050_obj.get_public_key();
  se050ErrorCheck(se050_obj, "get_public_key err: ");
  std::cout << "PubKey buff: ";
  se050_obj.print_hex_buffer(pubKey);

  auto verifyRes = se050_obj.verify_sha256_digest(hashBuff, signBuff, pubKey);
  se050ErrorCheck(se050_obj, "verify_sha256_digest err: ");
  std::cout << "verifyRes: ";
  std::cout << std::boolalpha << verifyRes << "\n";

  se050_obj.delete_obj(keyId);
  se050ErrorCheck(se050_obj, "delete_obj err: ");

  std::vector<uint8_t> writtenData(BINARY_TEST_SIZE);
  std::generate(writtenData.begin(), writtenData.end(), std::rand);
  if(se050_obj.write_binary_data(BINARY_RW_SLOT, writtenData) != writtenData.size()){
    se050ErrorCheck(se050_obj, "write_binary_data err: ");
  }else{
    auto readData = se050_obj.read_binary_data(BINARY_RW_SLOT, BINARY_TEST_SIZE);
    se050ErrorCheck(se050_obj, "read_binary_data err: ");

    (writtenData == readData) ? std::cout << "Binary READ-WRITE TEST Success!\n" : std::cout << "Binary READ-WRITE TEST Fail!\n";
  }
  se050_obj.delete_obj(BINARY_RW_SLOT);
  se050ErrorCheck(se050_obj, "delete_obj err: ");

}
 
void loop() {
    printf("Test Continue...\n");
    delay(10000);
}