//-- Include Interfaces
#include "i2c.h"


//-- Interface Definition

typedef I2C_FD INTF;


//-- Open and Close Interface
void open_INTF(INTF* interface, size_t address, size_t length);
void close_INTF(INTF interface);

//-- Read & Write
void read_INTF(INTF interface, void* data, size_t offset, size_t size_data);
void write_INTF(INTF interface, void* data, size_t offset, size_t size_data);
