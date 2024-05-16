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
#include <stdio.h>
#include <string.h>
#include <unistd.h>				//Needed for I2C port
#include "../i2c.h"				//Needed for I2C port
#include "esp_log.h"
#include "driver/i2c.h"
#include <Wire.h>

#define I2C_MASTER_FREQ_HZ          100000                     /*!< I2C master clock frequency */
#define SE050_SENSOR_ADDR           0x48        /*!< Slave address of the SE050 sensor */

int i2c_master_scl_pin = 6;     /*!< GPIO number used for I2C master clock */
int i2c_master_sda_pin = 5;     /*!< GPIO number used for I2C master data  */


void set_sda_scl_pins(int sda, int scl){
    i2c_master_sda_pin = sda;
    i2c_master_scl_pin = scl;
}


// Function to fully reset the Wire (I2C) module
void resetWireModule() {
    Wire.end(); // End I2C communication
    delay(100); // Delay for stability
    Wire.begin(); // Restart I2C communication
    delay(100); // Delay for stability
}

i2c_error_t axI2CInit(void)
{
    resetWireModule(); // Reset Wire module before initialization
    Wire.begin(i2c_master_sda_pin, i2c_master_scl_pin, I2C_MASTER_FREQ_HZ);
    return I2C_OK;
}


i2c_error_t axI2CWrite(unsigned char bus_unused_param, 
                       unsigned char addr, 
                       unsigned char *pTx, 
                       unsigned short txLen)
{
    uint16_t ack = 0;

    Wire.beginTransmission(SE050_SENSOR_ADDR);
    Wire.write(pTx, txLen);
    ack = Wire.endTransmission(true);

    // printf("\nI2C bus TX DATA: ");
	// for(int i=0; i<txLen; i++)
	// 	printf("%02x ", pTx[i]);
	// printf("\n");

    return (ack == ESP_OK) ? I2C_OK : I2C_FAILED;;
}


i2c_error_t axI2CRead(unsigned char bus, 
                      unsigned char addr, 
                      unsigned char *pRx, 
                      unsigned short rxLen)
{
    usleep(200000);

    int bytes = rxLen;
    uint16_t rx_len = 0;

    bytes = Wire.requestFrom(SE050_SENSOR_ADDR, bytes);

    if (bytes == 0){
        return I2C_FAILED;
    }

    while (Wire.available() && (rx_len < rxLen))
    {
        pRx[rx_len] = Wire.read();
        rx_len++;
    }

    // printf("\nI2C bus RX DATA: ");
	// for(int i=0; i<rxLen; i++)
	// 	printf("%02x ", pRx[i]);
	// printf("\n");

    return (rx_len == rxLen) ? I2C_OK : I2C_FAILED;
}

i2c_error_t axI2CClose(void)
{
    delay(100);
    Wire.end();
    delay(100);
    return I2C_OK;
}
