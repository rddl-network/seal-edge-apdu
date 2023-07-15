#include <iostream>
#include <Arduino.h>
#include <Wire.h>
#include <se050_middleware.h>

#define I2C_MASTER_SCL_IO           6                  
#define I2C_MASTER_SDA_IO           5
#define I2C_MASTER_FREQ_HZ          400000
 
void setup() {
  /* Init Serial Bus */ 
  Serial.begin(115200);
  Serial.println("\nTest Begin\n");

  /* Init I2C Bus */ 
  Wire.begin(I2C_MASTER_SDA_IO, I2C_MASTER_SCL_IO, I2C_MASTER_FREQ_HZ);

  int keyId = MAKE_TEST_ID(__LINE__);
  Se050Middleware se050_obj(keyId); 

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

  se050_obj.delete_obj();
}
 
void loop() {
    printf("Test Continue...\n");
    delay(10000);
}