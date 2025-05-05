#include "../../se-qubip/common/intf.h"

//------------------------------------------------------------------
//-- Open and Close Interface
//------------------------------------------------------------------

void open_INTF(INTF* interface, size_t address, size_t length)
{
    open_I2C(interface);
    set_address_I2C(*interface, address);
}

void close_INTF(INTF interface)
{
    close_I2C(interface);
}

//------------------------------------------------------------------
//--Read & Write
//------------------------------------------------------------------

void read_INTF(INTF interface, void* data, size_t offset, size_t size_data)
{
    read_I2C_ull(interface, data, offset, size_data);

}

void write_INTF(INTF interface, void* data, size_t offset, size_t size_data)
{
    write_I2C_ull(interface, data, offset, size_data);

}

