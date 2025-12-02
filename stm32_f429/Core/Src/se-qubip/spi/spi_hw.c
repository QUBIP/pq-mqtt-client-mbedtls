#include "spi_hw.h"

void save_secmem_flash(INTF interface) {
	//-- se_code = { {32'b0}, {12'b0}, {RECOVER_DATA, SAVE_DATA, RECOVER_SECMEM, SAVE_SECMEM}, {(16'b)SPI} }
	uint64_t next_block = 0;
	uint64_t control = 0;
	while (control != CMD_SE_CODE) {
		picorv32_control(interface, &control);
	}
	uint64_t se_code = ((uint64_t) SPI_OP_SAVE_SECMEM << 16) | SPI_SE_CODE;
	write_INTF(interface, &se_code, PICORV32_DATA_IN, AXI_BYTES);

	control = 0;
	while (control != CMD_SE_CODE) {
		picorv32_control(interface, &control);
	}
}

void recover_secmem_flash(INTF interface) {
	//-- se_code = { {32'b0}, {12'b0}, {RECOVER_DATA, SAVE_DATA, RECOVER_SECMEM, SAVE_SECMEM}, {(16'b)SPI} }
	uint64_t next_block = 0;
	uint64_t control = 0;
	while (control != CMD_SE_CODE) {
		picorv32_control(interface, &control);
	}
	uint64_t se_code = ((uint64_t) SPI_OP_RECOVER_SECMEM << 16) | SPI_SE_CODE;
	write_INTF(interface, &se_code, PICORV32_DATA_IN, AXI_BYTES);

	control = 0;
	while (control != CMD_SE_CODE) {
		picorv32_control(interface, &control);
	}
}

void save_data_flash(unsigned int addr, unsigned int data_len,
		unsigned char *data_in, INTF interface) {
	//-- se_code = { {32'b0}, {12'b0}, {RECOVER_DATA, SAVE_DATA, RECOVER_SECMEM, SAVE_SECMEM}, {(16'b)SPI} }
	uint64_t next_block = 0;
	uint64_t control = 0;
	while (control != CMD_SE_CODE) {
		picorv32_control(interface, &control);
	}
	uint64_t se_code = ((uint64_t) SPI_OP_SAVE_DATA << 16) | SPI_SE_CODE;
	write_INTF(interface, &se_code, PICORV32_DATA_IN, AXI_BYTES);

	uint32_t data_packages = (data_len + AXI_BYTES - 1) / AXI_BYTES;
	uint32_t data_pages = data_packages / SPI_PAGE_SIZE_DWORDS;
	uint32_t data_rem = data_packages % SPI_PAGE_SIZE_DWORDS;

	uint64_t addr_data_len = (((uint64_t) addr) << 32) | data_len;

	while (control != CMD_SE_WAIT) {
		picorv32_control(interface, &control);
	}
	write_INTF(interface, &addr_data_len, PICORV32_DATA_IN, AXI_BYTES);

	//-- Write Data
	uint32_t packages_write = 0;
	for (uint32_t i = 0; i < data_pages; i++) {
		while (control != CMD_SE_WRITE) {
			picorv32_control(interface, &control);
		}

		for (uint32_t j = 0; j < SPI_PAGE_SIZE_DWORDS; j++) {
			write_INTF(interface, data_in + (j + packages_write) * AXI_BYTES,
					PICORV32_DATA_IN, AXI_BYTES);
		}
		packages_write += SPI_PAGE_SIZE_DWORDS;

		while (control != CMD_SE_WAIT) {
			picorv32_control(interface, &control);
			if (control == CMD_SE_WAIT)
				read_INTF(interface, &next_block, PICORV32_DATA_OUT, AXI_BYTES); // Send a read signal to continue
		}
	}

	while (control != CMD_SE_WRITE) {
		picorv32_control(interface, &control);
	}

	for (uint32_t i = 0; i < data_rem; i++) {
		write_INTF(interface, data_in + (i + packages_write) * AXI_BYTES,
				PICORV32_DATA_IN, AXI_BYTES);
	}

	while (control != CMD_SE_CODE) {
		picorv32_control(interface, &control);
	}
}

void recover_data_flash(unsigned int addr, unsigned int data_len,
		unsigned char *data_out, INTF interface) {
	//-- se_code = { {32'b0}, {12'b0}, {RECOVER_DATA, SAVE_DATA, RECOVER_SECMEM, SAVE_SECMEM}, {(16'b)SPI} }
	uint64_t next_block = 0;
	uint64_t control = 0;
	while (control != CMD_SE_CODE) {
		picorv32_control(interface, &control);
	}
	uint64_t se_code = ((uint64_t) SPI_OP_RECOVER_DATA << 16) | SPI_SE_CODE;
	write_INTF(interface, &se_code, PICORV32_DATA_IN, AXI_BYTES);

	uint32_t data_packages = (data_len + AXI_BYTES - 1) / AXI_BYTES;
	uint32_t data_blocks = data_packages / (FIFO_OUT_DEPTH - 2);
	uint32_t data_rem = data_packages % (FIFO_OUT_DEPTH - 2);

	uint64_t addr_data_len = (((uint64_t) addr) << 32) | data_len;

	while (control != CMD_SE_WRITE) {
		picorv32_control(interface, &control);
	}
	write_INTF(interface, &addr_data_len, PICORV32_DATA_IN, AXI_BYTES);

	//-- Read Data
	uint32_t packages_read = 0;
	for (uint32_t i = 0; i < data_blocks; i++) {
		while (control != CMD_SE_READ) {
			picorv32_control(interface, &control);
		}

		for (uint32_t j = 0; j < FIFO_IN_DEPTH - 2; j++) {
			read_INTF(interface, data_out + (j + packages_read) * AXI_BYTES,
					PICORV32_DATA_OUT, AXI_BYTES);
		}
		packages_read += FIFO_OUT_DEPTH - 2;

		while (control != CMD_SE_WAIT) {
			picorv32_control(interface, &control);
			if (control == CMD_SE_WAIT)
				read_INTF(interface, &next_block, PICORV32_DATA_OUT, AXI_BYTES); // Send a read signal to continue
		}
	}

	while (control != CMD_SE_READ) {
		picorv32_control(interface, &control);
	}

	for (uint32_t i = 0; i < data_rem; i++) {
		read_INTF(interface, data_out + (i + packages_read) * AXI_BYTES,
				PICORV32_DATA_OUT, AXI_BYTES);
	}

	while (control != CMD_SE_CODE) {
		picorv32_control(interface, &control);
	}
}
