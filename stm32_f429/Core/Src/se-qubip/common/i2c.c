#include "../../../Inc/main.h"
#include "../../se-qubip/common/i2c.h"

//------------------------------------------------------------------
//-- Check I2C Port is available
//------------------------------------------------------------------

extern I2C_HandleTypeDef hi2c1;

#define I2C_SLAVE_ADDRESS (0x1A << 1)
#define I2C_TIMEOUT (1000)

void checkI2CBus() {
    FILE *fd = doCommand("sudo dtparam -l");
    char output[1024];
    int txfound = 0;
    while (fgets(output, sizeof (output), fd) != NULL) {
        printf("%s\n\r", output);
        fflush(stdout);
        if (strstr(output, "i2c_arm=on") != NULL) {
            txfound = 1;
        }
        if (strstr(output, "i2c_arm=off") != NULL) {
            txfound = 0;
        }
    }
    pclose(fd);
    if (txfound == 0) {
        fd = doCommand("sudo dtparam i2c_arm=on");
        pclose(fd);
    }
}

FILE * doCommand(char *cmd) {
    FILE *fp = popen(cmd, "r");
    if (fp == NULL) {
        printf("Failed to run command %s \n\r", cmd);
        exit(1);
    }
    return fp;
}


//------------------------------------------------------------------
//-- Open and Close I2C Port
//------------------------------------------------------------------

void open_I2C(I2C_FD* i2c_fd)  {
	//*i2c_fd = open("/dev/i2c-1", O_RDWR);
}
void close_I2C(I2C_FD i2c_fd) {
	//close(i2c_fd);
}


//------------------------------------------------------------------
//-- Set I2C Slave Device Address
//------------------------------------------------------------------

void set_address_I2C(I2C_FD i2c_fd, uint8_t i2c_addr){
	//ioctl(i2c_fd, I2C_SLAVE, i2c_addr);
}


//------------------------------------------------------------------
//-- Read & Write I2C Slave Registers
//------------------------------------------------------------------

//void read_I2C(I2C_FD i2c_fd, void* data, size_t offset, size_t size_data)
//{
//    //-- Pointer Index
//    unsigned char ptr_idx = (unsigned char) offset;
//    //-- Write Pointer Index
//    write(i2c_fd, &ptr_idx, 1);
//    //-- Read from I2C Port
//    read(i2c_fd, data, size_data);
//}

void write_I2C(I2C_FD i2c_fd, void* data, size_t offset, size_t size_data)
{
    //-- Buffer -> {Pointer_index, data_char}
    unsigned char buf[1 + size_data];
    //-- Pointer Index
    unsigned char ptr_idx[1] = {offset};
    //-- Copy to buffer
    memcpy(buf, ptr_idx, 1);
    memcpy(buf + 1, data, size_data);
    //-- Send through I2C Port 
    //write(i2c_fd, buf, 1 + size_data);
    HAL_I2C_Master_Transmit(&hi2c1, I2C_SLAVE_ADDRESS, buf, 1 + size_data, I2C_TIMEOUT);

}

void read_I2C_ull(I2C_FD i2c_fd, void* data, size_t offset, size_t size_data)
{
    //-- Pointer Index
    unsigned char ptr_idx = (unsigned char) offset;
    //-- Write Pointer Index
    //write(i2c_fd, &ptr_idx, 1);
    HAL_I2C_Master_Transmit(&hi2c1, I2C_SLAVE_ADDRESS,  &ptr_idx, 1, I2C_TIMEOUT);
    //-- Read from I2C Port
    unsigned char data_char[size_data];
    //read(i2c_fd, data_char, size_data);
    HAL_I2C_Master_Receive(&hi2c1, I2C_SLAVE_ADDRESS, data_char, size_data, I2C_TIMEOUT);
    //-- Cast char to unsigned long long
    size_t size_data_ull = (size_data % 8 == 0) ? (size_data / 8) : (size_data / 8 + 1);
    for (int i = 0; i < size_data_ull; i++)
    {
        swapEndianness(data_char + 8 * i, 8);
    }
    memcpy(data, data_char, size_data);
}

void write_I2C_ull(I2C_FD i2c_fd, void* data, size_t offset, size_t size_data)
{
    //-- Cast unsigned long long to char
    unsigned char data_char[size_data];
    size_t size_data_ull = (size_data % 8 == 0) ? (size_data / 8) : (size_data / 8 + 1);
    memcpy(data_char, data, size_data);
    for (int i = 0; i < size_data_ull; i++)
    {
        swapEndianness(data_char + 8 * i, 8);
    }
    //-- Buffer -> {Pointer_index, data_char}
    unsigned char buf[1 + size_data];
    //-- Pointer Index
    unsigned char ptr_idx[1] = {offset};
    //-- Copy to buffer
    memcpy(buf, ptr_idx, 1);
    memcpy(buf + 1, data_char, size_data);
    //-- Send through I2C Port 
    //write(i2c_fd, buf, 1 + size_data);
    HAL_I2C_Master_Transmit(&hi2c1, I2C_SLAVE_ADDRESS, buf, 1 + size_data, I2C_TIMEOUT);
}

