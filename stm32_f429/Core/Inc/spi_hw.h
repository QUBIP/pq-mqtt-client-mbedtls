#ifndef SPI_HW_H
#define SPI_HW_H

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include "intf.h"
#include "conf.h"
#include "picorv32.h"
#include "extra_func.h"

/************************ MS2XL Function Definitions **********************/
#define SPI_PAGE_SIZE_DWORDS        32
#define AXI_BYTES                   8

//-- SPI Flash Operations
#define SPI_OP_SAVE_SECMEM          (1 << 0)
#define SPI_OP_RECOVER_SECMEM       (1 << 1)
#define SPI_OP_SAVE_DATA            (1 << 2)
#define SPI_OP_RECOVER_DATA    	     (1 << 3)

//-- SPI Flash Functions
void save_secmem_flash(INTF interface);
void recover_secmem_flash(INTF interface);
void save_data_flash(unsigned int addr, unsigned int data_len,
		unsigned char *data_in, INTF interface);
void recover_data_flash(unsigned int addr, unsigned int data_len,
		unsigned char *data_out, INTF interface);

#endif // SPI_HW_H
