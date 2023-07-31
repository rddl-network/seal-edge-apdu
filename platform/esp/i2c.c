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

static const char *TAG = "i2c-simple-example";

#define I2C_MASTER_NUM              0                   /*!< I2C master i2c port number, the number of i2c peripheral interfaces available will depend on the chip */
#define I2C_MASTER_FREQ_HZ          400000                     /*!< I2C master clock frequency */
#define I2C_MASTER_TX_BUF_DISABLE   0                          /*!< I2C master doesn't need buffer */
#define I2C_MASTER_RX_BUF_DISABLE   0                          /*!< I2C master doesn't need buffer */
#define I2C_MASTER_TIMEOUT_MS       1000000

#define SE050_SENSOR_ADDR           0x48        /*!< Slave address of the SE050 sensor */

int i2c_addr = 0;

int i2c_master_scl_pin = 6;     /*!< GPIO number used for I2C master clock */
int i2c_master_sda_pin = 5;     /*!< GPIO number used for I2C master data  */


void set_sda_scl_pins(int sda, int scl){
    i2c_master_sda_pin = sda;
    i2c_master_scl_pin = scl;
}

/**
 * @brief i2c master initialization
 */
static esp_err_t i2c_master_init(void)
{
    int i2c_master_port = I2C_MASTER_NUM;

    i2c_config_t conf = {
        .mode = I2C_MODE_MASTER,
        .sda_io_num = i2c_master_sda_pin,
        .scl_io_num = i2c_master_scl_pin,
        .sda_pullup_en = GPIO_PULLUP_ENABLE,
        .scl_pullup_en = GPIO_PULLUP_ENABLE,
        .master.clk_speed = I2C_MASTER_FREQ_HZ,
        .clk_flags = 0,  
    };

    i2c_param_config(i2c_master_port, &conf);

    return i2c_driver_install(i2c_master_port, conf.mode, I2C_MASTER_RX_BUF_DISABLE, I2C_MASTER_TX_BUF_DISABLE, 0);
}


i2c_error_t axI2CInit(void)
{
    uint8_t data[2];
    ESP_ERROR_CHECK(i2c_master_init());
    ESP_LOGI(TAG, "I2C initialized successfully");

    int a = (I2C_MASTER_TIMEOUT_MS / portTICK_PERIOD_MS);
    ESP_LOGI(TAG, "A %d ", a);
    return I2C_OK;
}

i2c_error_t axI2CWrite(unsigned char bus_unused_param, 
                       unsigned char addr, 
                       unsigned char *pTx, 
                       unsigned short txLen)
{

    i2c_master_write_to_device(I2C_MASTER_NUM, SE050_SENSOR_ADDR, (uint8_t*)pTx, txLen, I2C_MASTER_TIMEOUT_MS / portTICK_PERIOD_MS);  
   
    // printf("I2C bus TX DATA: ");
	// for(int i=0; i<txLen; i++)
	// 	printf("%02x ", pTx[i]);
	// printf("\n");

    return I2C_OK;
}

i2c_error_t axI2CRead(unsigned char bus, 
                      unsigned char addr, 
                      unsigned char *pRx, 
                      unsigned short rxLen)
{
    usleep(200000);

    i2c_master_read_from_device(I2C_MASTER_NUM, SE050_SENSOR_ADDR, pRx, rxLen, I2C_MASTER_TIMEOUT_MS / portTICK_PERIOD_MS);
        
    // printf("\nI2C bus RX DATA: ");
	// for(int i=0; i<rxLen; i++)
	// 	printf("%02x ", pRx[i]);
	// printf("\n");

    return I2C_OK;
}

i2c_error_t axI2CClose(void)
{

    return I2C_OK;
}
