////////////////////////////////////////////////////////////////////////////////////
// Company: IMSE-CNM CSIC
// Engineer: Pablo Navarro Torrero
//
// Create Date: 14/05/2024
// File Name: picorv32.c
// Project Name: SE-QUBIP
// Target Devices: PYNQ-Z2
// Description:
//
//		picorv32 Driver File
//
// Additional Comment:
//
////////////////////////////////////////////////////////////////////////////////////

#include "picorv32.h"
#include "se-qubip.h"

//------------------------------------------------------------------
//-- Picorv32 Error Information
//------------------------------------------------------------------

void generate_features_string(uint32_t features_word, char *imp_string,
		char *not_imp_string) {
	// --- Implemented Features ---
	strcpy(imp_string, "");

	// Check each bit and append the name if it's set
	if (features_word & OP_SHA2)
		strcat(imp_string, "SHA-2 ");
	if (features_word & OP_SHA3)
		strcat(imp_string, "SHA-3 ");
	if (features_word & OP_ECDSA)
		strcat(imp_string, "EdDSA ");
	if (features_word & OP_ECDH)
		strcat(imp_string, "X25519 ");
	if (features_word & OP_TRNG)
		strcat(imp_string, "TRNG ");
	if (features_word & OP_AES)
		strcat(imp_string, "AES ");
	if (features_word & OP_MLKEM)
		strcat(imp_string, "ML-KEM ");
	if (features_word & OP_MLDSA)
		strcat(imp_string, "ML-DSA ");
	if (features_word & OP_SLHDSA)
		strcat(imp_string, "SLH-DSA ");

	// Check if nothing was implemented
	if (features_word == 0) {
		strcat(imp_string, "None ");
	}

	// --- Not Implemented Features ---
	strcpy(not_imp_string, "");

	// Check each bit and append the name if it's NOT set
	if (!(features_word & OP_SHA2))
		strcat(not_imp_string, "SHA-2 ");
	if (!(features_word & OP_SHA3))
		strcat(not_imp_string, "SHA-3 ");
	if (!(features_word & OP_ECDSA))
		strcat(not_imp_string, "EdDSA ");
	if (!(features_word & OP_ECDH))
		strcat(not_imp_string, "X25519 ");
	if (!(features_word & OP_TRNG))
		strcat(not_imp_string, "TRNG ");
	if (!(features_word & OP_AES))
		strcat(not_imp_string, "AES ");
	if (!(features_word & OP_MLKEM))
		strcat(not_imp_string, "ML-KEM ");
	if (!(features_word & OP_MLDSA))
		strcat(not_imp_string, "ML-DSA ");
	if (!(features_word & OP_SLHDSA))
		strcat(not_imp_string, "SLH-DSA ");

	// Check if everything was implemented
	uint32_t all_features = OP_SHA2 | OP_SHA3 | OP_ECDSA | OP_ECDH | OP_TRNG
			| OP_AES | OP_MLKEM | OP_MLDSA | OP_SLHDSA;
	if ((features_word & all_features) == all_features) {
		strcat(not_imp_string, "None ");
	}
}

// --- Helper function to print a formatted line with color ---
static void print_error_line(const char *label, uint32_t value,
		const char *value_color) {
	printf(
			"     " CYAN "> %-22s" RESET ": %s0x%08X" RESET "                                       \n",
			label, value_color, value);
}

// --- Main error printing function with color ---
static void print_fatal_error_screen(uint64_t error_loc_id_irqs,
		uint64_t error_code, uint64_t error_debug_0_1, uint64_t error_debug_2_3,
		uint64_t error_debug_4) {

	// --- Extract all info first for clarity ---
	uint32_t error_type = error_loc_id_irqs >> 32;
	uint32_t error_info = error_loc_id_irqs & 0xFFFFFFFF;
	uint32_t faulting_pc = (error_code >> 32) & 0xFFFFFFFE;
	uint32_t dbg_reg_0 = error_debug_0_1 & 0xFFFFFFFF;
	uint32_t dbg_reg_1 = error_debug_0_1 >> 32;
	uint32_t dbg_reg_2 = error_debug_2_3 & 0xFFFFFFFF;
	uint32_t dbg_reg_3 = error_debug_2_3 >> 32;
	uint32_t dbg_reg_4 = error_debug_4 & 0xFFFFFFFF;

	// --- Print Header ---
	printf(
			"\n\n" "+==============================================================================+\n");
	printf(
			"|                           >> FATAL SYSTEM ERROR <<                           |\n");
	printf(
			"+==============================================================================+" "\n");
	printf(
			"                                                                                \n");

	// --- Print Primary Error Type ---
	printf("   " BOLD WHITE "ERROR TYPE: " RESET);
	switch (error_type) {
	case ERROR_SE_CODE:
		printf(
				RED "CRYPTOGRAPHIC OPERATION NOT AVAILABLE OR CODE NOT RECOGNIZED" RESET "     \n");
		break;
	case ERROR_ILLEGAL_INSTR:
		printf(
				RED "ILLEGAL INSTRUCTION" RESET "                                              \n");
		break;
	case ERROR_MISALIGNED:
		printf(
				RED "MISALIGNED MEMORY ACCESS" RESET "                                         \n");
		break;
	case ERROR_TIMEOUT:
		printf(
				RED "WATCHDOG TIMEOUT" RESET "                                                 \n");
		break;
	case ERROR_DMA:
		printf(
				RED "MISALIGNED DMA" RESET "                                                   \n");
		break;
	case ERROR_ILLEGAL_ADDR:
		printf(
				RED "ILLEGAL MEMORY ADDRESS" RESET "                                           \n");
		break;
	case ERROR_SECMEM_STORE:
		printf(
				RED "SECURE MEMORY ERROR" RESET "                                              \n");
		break;
	case ERROR_SECMEM_DELETE:
		printf(
				RED "SECURE MEMORY ERROR" RESET "                                              \n");
		break;
	case ERROR_SECMEM_GET:
		printf(
				RED "SECURE MEMORY ERROR" RESET "                                              \n");
		break;
	default:
		printf(
				RED "UNKNOWN (CODE: 0x%08X)" RESET "                                       \n",
				error_type);
		break;
	}
	printf(
			"                                                                                \n");

	// --- Print Context-Specific Details ---
	printf(
			"   " BOLD WHITE "DETAILS:" RESET "                                                                     \n");
	switch (error_type) {
	case ERROR_SE_CODE:
		char imp_string[256];
		char not_imp_string[256];
		generate_features_string(error_code >> 32, imp_string, not_imp_string);
		printf(
				"     " CYAN "> Available Op.         " RESET ":" GREEN " %s" RESET "                                       \n",
				imp_string);
		printf(
				"     " CYAN "> Not Available         " RESET ":" RED " %s" RESET "                                       \n",
				not_imp_string);
		break;
	case ERROR_TIMEOUT:
		printf(
				"     " CYAN "> Timeout Location ID   " RESET ":" GREEN " 0x%08x" RESET "                                       \n",
				error_info);
		break;
	case ERROR_DMA:
		if (error_info == (1 << 0))
			printf(
					"     " CYAN "> Reason                " RESET ": DMA UNALIGNED LENGTH                             \n");
		if (error_info == (1 << 1))
			printf(
					"     " CYAN "> Reason                " RESET ": DMA UNALIGNED SRC ADDR                           \n");
		if (error_info == (1 << 2))
			printf(
					"     " CYAN "> Reason                " RESET ": DMA UNALIGNED DST ADDR                           \n");
		break;
	case ERROR_ILLEGAL_ADDR:
		print_error_line("Faulting Address", error_info, GREEN);
		break;
	case ERROR_SECMEM_STORE:
		printf(
				"     " CYAN "> Reason                " RESET ": NO FREE SLOTS AVAILABLE TO STORE A NEW KEY       \n");
		break;
	case ERROR_SECMEM_DELETE:
		printf(
				"     " CYAN "> Reason                " RESET ": INVALID KEY ID OR SLOT IS EMPTY TO DELETE        \n");
		break;
	case ERROR_SECMEM_GET:
		printf(
				"     " CYAN "> Reason                " RESET ": INVALID KEY ID TO GET                            \n");
		break;
	}
	print_error_line("Program Counter (PC)", faulting_pc, GREEN);
	printf(
			"                                                                                \n");

	// --- Print Generic Debug Registers ---
	printf(
			"   " BOLD WHITE "DEBUG CONTEXT:" RESET "                                                               \n");
	print_error_line("DEBUG REG 0", dbg_reg_0, GREEN);
	print_error_line("DEBUG REG 1", dbg_reg_1, GREEN);
	print_error_line("DEBUG REG 2", dbg_reg_2, GREEN);
	print_error_line("DEBUG REG 3", dbg_reg_3, GREEN);
	print_error_line("DEBUG REG 4", dbg_reg_4, GREEN);
	printf(
			"                                                                                \n");

	// --- Print Footer ---
	printf(
			"+------------------------------------------------------------------------------+\n");
	printf(
			"|                              SYSTEM HALTED                                   |\n");
	printf(
			"+------------------------------------------------------------------------------+\n\n\n");
}

static void picorv32_error(INTF interface) {
	uint64_t error_code;
	uint64_t error_loc_id_irqs;
	uint64_t error_debug_0_1;
	uint64_t error_debug_2_3;
	uint64_t error_debug_4;

	read_INTF(interface, &error_code, PICORV32_CONTROL, AXI_BYTES);
	read_INTF(interface, &error_loc_id_irqs, PICORV32_DATA_OUT, AXI_BYTES);
	HAL_Delay(100);
	read_INTF(interface, &error_debug_0_1, PICORV32_DATA_OUT, AXI_BYTES);
	HAL_Delay(100);
	read_INTF(interface, &error_debug_2_3, PICORV32_DATA_OUT, AXI_BYTES);
	HAL_Delay(100);
	read_INTF(interface, &error_debug_4, PICORV32_DATA_OUT, AXI_BYTES);

	// Call the single, clean printing function
	print_fatal_error_screen(error_loc_id_irqs, error_code, error_debug_0_1,
			error_debug_2_3, error_debug_4);
}

//------------------------------------------------------------------
//-- Picorv32 Communication
//------------------------------------------------------------------

void picorv32_control(INTF interface, uint64_t *control) {
	uint64_t data_out = 0;
	uint64_t data_in = 0;

	read_INTF(interface, control, PICORV32_CONTROL, AXI_BYTES);
	*control = 0xFFFFFFFF & *control;

	// printf("control = %lld\n", *control);
	// fflush(stdout);

	if (*control == CMD_PUTCHAR) {
		read_INTF(interface, &data_out, PICORV32_DATA_OUT, AXI_BYTES);
		printf("%c", (char) data_out);
		fflush(stdout);
	} else if ((int) *control == CMD_ERROR) {
		// Error Message
		picorv32_error(interface);
#ifdef AXI
            //-- Return to default frequency
            unsigned int clk_index = 0;
	        float clk_frequency;
            float set_clk_frequency = FREQ_TYPICAL;
            Set_Clk_Freq(clk_index, &clk_frequency, &set_clk_frequency, 0);
        #endif
		// --- Close Interface --- //
		close_INTF(interface);

		exit(0);
	} else if (*control == CMD_END) {
		//-- Return to default frequency
#ifdef AXI
            unsigned int clk_index = 0;
	        float clk_frequency;
            float set_clk_frequency = FREQ_TYPICAL;
            Set_Clk_Freq(clk_index, &clk_frequency, &set_clk_frequency, 0);
        #endif
		// --- Close Interface --- //
		close_INTF(interface);

		exit(0);
	}
}

//----------------------------------------------------------------------------------------------------
// READ & WRITE PICORV PROGRAM MEMORY
//----------------------------------------------------------------------------------------------------

void READ_PICORV_PROGRAM(INTF interface) {
	uint64_t AXI_RAM = 0;
	uint64_t AXI_RAM_WEN_ADDR = 5ULL << 29;      //-- 0b101 << 29
	uint64_t AXI_RAM_RDATA = 0;

	for (int i = 0; i < PICORV32_PROGRAM_SIZE; i += 4) {
#ifdef AXI
            AXI_RAM = AXI_RAM_WEN_ADDR;
            write_INTF(interface, &AXI_RAM, PICORV32_PROGRAM, AXI_BYTES);
            read_INTF(interface, &AXI_RAM_RDATA, PICORV32_PROGRAM, AXI_BYTES);
        #elif I2C
            AXI_RAM = AXI_RAM_WEN_ADDR << 32;

            write_INTF(interface, &AXI_RAM, PICORV32_PROGRAM, AXI_BYTES);
            // printf("\nAXI_RAM = 0x%016llx", AXI_RAM);
            // getchar();
            
            read_INTF(interface, &AXI_RAM_RDATA, PICORV32_PROGRAM + 8, AXI_BYTES);
            printf("\n%05d: 0x%08x", i / 4 + 1, (uint32_t) AXI_RAM_RDATA);
            // getchar();
        #endif
		AXI_RAM_WEN_ADDR += 4;
	}

	getchar();

	AXI_RAM = 0;
	write_INTF(interface, &AXI_RAM, PICORV32_PROGRAM, AXI_BYTES);
}

void WRITE_PICORV_PROGRAM(INTF interface) {
	//-- Open the file
	FILE *fp = fopen("../se-qubip/fw/firmware.hex", "r");
	if (fp == NULL) {
		perror("\nError opening firmware.hex at /se-qubip/fw/\n");
		exit(1);
	}

	// Count total number of lines (instructions).
	int total_lines = 0;
	char buffer[256];
	while (fgets(buffer, sizeof(buffer), fp) != NULL) {
		total_lines++;
	}

	// Total number of lines MUST not exceed the available memory
	if (total_lines * 4 > PICORV32_PROGRAM_SIZE) {
		printf(
				"\nError program size (%i bytes) is bigger than the available space (%i bytes)\n",
				total_lines * 4, PICORV32_PROGRAM_SIZE);
		return;
	}

	// Rewind the file pointer to the beginning of the file.
	rewind(fp);

	//-- Declare AXI variables
	uint64_t AXI_RAM = 0;
	uint32_t AXI_RAM_WEN_ADDR = 3ULL << 30;      //-- 0'b11 << 30
	uint32_t AXI_RAM_WDATA = 0;

	printf("\n");

	//-- 1st Pass is for Cleaning the Memory
	for (int i = 0; i < PICORV32_PROGRAM_SIZE; i += 4) {
#ifdef AXI
            AXI_RAM = AXI_RAM_WEN_ADDR;
        #elif I2C
            printf("%d\r", i);
            fflush(stdout); 
            AXI_RAM = (((uint64_t) AXI_RAM_WEN_ADDR) << 32);
        #endif
		write_INTF(interface, &AXI_RAM, PICORV32_PROGRAM, AXI_BYTES);
		AXI_RAM_WEN_ADDR += 4;
	}

#ifdef I2C
        printf("            \r");
        fflush(stdout); 
    #endif

	//-- Return address to 0
	AXI_RAM_WEN_ADDR = 3 << 30;

	//-- Read firmware.hex and write in Memory
	char line[128];
	int idx = 0;
	// Loop: read the file line by line using fgets()
	while (fgets(line, sizeof(line), fp) != NULL) {
		// Optional: Remove newline character if present.
		size_t len = strlen(line);
		if (len > 0 && (line[len - 1] == '\n' || line[len - 1] == '\r'))
			line[len - 1] = '\0';

		// Convert the hex ASCII string to an unsigned 32-bit integer.
		// strtoul converts the string using base 16.
		AXI_RAM_WDATA = (uint32_t) strtoul(line, NULL, 16);
#ifdef AXI
            AXI_RAM = ((uint64_t) AXI_RAM_WDATA << 32) + AXI_RAM_WEN_ADDR;
        #elif I2C
            AXI_RAM = ((uint64_t) AXI_RAM_WEN_ADDR << 32) + AXI_RAM_WDATA;
            printf("%d\r", idx);
            fflush(stdout);
        #endif
		write_INTF(interface, &AXI_RAM, PICORV32_PROGRAM, AXI_BYTES);

		// printf("\nAXI_RAM = 0x%08x_%08x", AXI_RAM_WDATA, AXI_RAM_WEN_ADDR);
		// getchar();

		idx += 4;
		AXI_RAM_WEN_ADDR += 4;
	}

#ifdef I2C
        printf("            \r");
        fflush(stdout); 
    #endif

	//-- End Writing the Program Memory
	AXI_RAM = 0;
	write_INTF(interface, &AXI_RAM, PICORV32_PROGRAM, AXI_BYTES);

	// Close the file.
	fclose(fp);
	return;
}
