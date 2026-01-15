#include "intf.h"
#include "scp03/scp03.h"
#include "qubip.h"

//------------------------------------------------------------------
//-- Open and Close Interface
//------------------------------------------------------------------

#if SCP03 == 1
    //-- Create Context for SCP03
    scp03_session_t scp03_session;
#endif

void open_INTF(INTF *interface, size_t address, size_t length) {

#if SCP03 == 0
	open_I2C(interface);
	set_address_I2C(*interface, address);
#else
	open_I2C(interface);
	set_address_I2C(*interface, address);
	scp03_init(*interface, &scp03_session);
#endif

}

void close_INTF(INTF interface) {
	close_I2C(interface);
}

//------------------------------------------------------------------
//--Read & Write
//------------------------------------------------------------------

void read_INTF(INTF interface, void *data, size_t offset, size_t size_data) {
#if SCP03 == 0
	read_I2C_ull(interface, data, offset, size_data);
#else
    scp03_read(interface, &scp03_session, offset >> 3, data);
#endif

}

void write_INTF(INTF interface, void *data, size_t offset, size_t size_data) {
#if SCP03 == 0
	write_I2C_ull(interface, data, offset, size_data);
#else
    scp03_write(interface, &scp03_session, offset >> 3, data);
#endif

}

