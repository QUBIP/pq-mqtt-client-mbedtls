//#include <stdio.h>
//#include <stdint.h>
//#include <stdlib.h>
//#include <string.h>
//#include <sys/ioctl.h>
//#include <unistd.h>
//#include <fcntl.h>
//#include <linux/i2c-dev.h>
//#include <sys/time.h>
//#include <sys/mman.h>

#include "extra_func.h"

//-- Create new type for the I2C File Descriptor
typedef int I2C_FD;

//-- Check I2C Port is available
void checkI2CBus();
FILE * doCommand(char *cmd);

//-- Open and Close I2C Port
void open_I2C(I2C_FD* i2c_fd);
void close_I2C(I2C_FD i2c_fd);

//-- Set I2C Slave Device Address
void set_address_I2C(I2C_FD i2c_fd, uint8_t slave_addr);

//-- Read & Write I2C Slave Registers
void read_I2C(I2C_FD i2c_fd, void* data, size_t offset, size_t size_data);
void write_I2C(I2C_FD i2c_fd, void* data, size_t offset, size_t size_data);
void read_I2C_ull(I2C_FD i2c_fd, void* data, size_t offset, size_t size_data);
void write_I2C_ull(I2C_FD i2c_fd, void* data, size_t offset, size_t size_data);

/*
//-- Read & Write SAFE I2C Slave Registers
void read_I2C_safe(I2C_FD i2c_fd, void* data, size_t offset, size_t size_data);
void write_I2C_safe(I2C_FD i2c_fd, void* data, size_t offset, size_t size_data);
void read_I2C_ull_safe(I2C_FD i2c_fd, unsigned long long* data, size_t offset, size_t size_data);
void write_I2C_ull_safe(I2C_FD i2c_fd, unsigned long long* data, size_t offset, size_t size_data);
*/
