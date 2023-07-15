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
#include <unistd.h>				//Needed for I2C port
#include <fcntl.h>				//Needed for I2C port
#include <sys/ioctl.h>			//Needed for I2C port
#include <linux/i2c-dev.h>		//Needed for I2C port
#include <i2c.h>				//Needed for I2C port

static  int file_i2c;
static  int length;
static	unsigned char buffer[60] = {0};

int i2c_master_scl_pin = 6;     /*!< GPIO number used for I2C master clock */
int i2c_master_sda_pin = 5;     /*!< GPIO number used for I2C master data  */

void set_sda_scl_pins(int sda, int scl){
    i2c_master_sda_pin = sda;
    i2c_master_scl_pin = scl;
}

i2c_error_t axI2CInit(void)
{
    char *filename = (char*)"/dev/i2c-1";
	if ((file_i2c = open(filename, O_RDWR)) < 0)
	{
		//ERROR HANDLING: you can check errno to see what went wrong
		printf("Failed to open the i2c bus");
		return I2C_FAILED;
	}
	
	int addr = I2C_DEVICE_ADDRESS;          //<<<<<The I2C address of the slave
	if (ioctl(file_i2c, I2C_SLAVE, addr) < 0)
	{
		printf("Failed to acquire bus access and/or talk to slave.\n");
		//ERROR HANDLING; you can check errno to see what went wrong
		return I2C_FAILED;
	}

	printf("\nOpen the i2c bus \n");
    return I2C_OK;
}

i2c_error_t axI2CWrite(unsigned char bus_unused_param, 
                       unsigned char addr, 
                       unsigned char *pTx, 
                       unsigned short txLen)
{
	if (write(file_i2c, (char*)pTx, txLen) != txLen)		//write() returns the number of bytes actually written, if it doesn't match then an error occurred (e.g. no response from the device)
	{
		/* ERROR HANDLING: i2c transaction failed */
		printf("Failed to write to the i2c bus.\n");
        return I2C_FAILED;
    }

	printf("I2C bus TX DATA: ");
	for(int i=0; i<txLen; i++)
		printf("%02x ", pTx[i]);
	printf("\n");
	
    return I2C_OK;
}

i2c_error_t axI2CRead(unsigned char bus, 
                      unsigned char addr, 
                      unsigned char *pRx, 
                      unsigned short rxLen)
{
	sleep(1);

	if (read(file_i2c, (char*)pRx, rxLen) != rxLen)		//read() returns the number of bytes actually read, if it doesn't match then an error occurred (e.g. no response from the device)
	{
		//ERROR HANDLING: i2c transaction failed
		printf("Failed to read from the i2c bus.\n");
        return I2C_FAILED;
	}

	printf("\nI2C bus RX DATA: ");
	for(int i=0; i<rxLen; i++)
		printf("%02x ", pRx[i]);
	printf("\n");

    return I2C_OK;
}

i2c_error_t axI2CClose(void)
{
    close(file_i2c);

    return I2C_OK;
}