
#include "mldsa_hw.h"

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>

//==============================================================================
// KEY GENERATION
//==============================================================================

void mldsa44_genkeys_hw(unsigned char d[32], unsigned char* pk, unsigned char* sk, bool ext_key, uint8_t* key_id, INTF interface) {

	mldsa_genkeys_hw(44, d, pk, sk, ext_key, key_id, interface);

}

void mldsa65_genkeys_hw(unsigned char d[32], unsigned char* pk, unsigned char* sk, bool ext_key, uint8_t* key_id, INTF interface) {

	mldsa_genkeys_hw(65, d, pk, sk, ext_key, key_id, interface);

}

void mldsa87_genkeys_hw(unsigned char d[32], unsigned char* pk, unsigned char* sk, bool ext_key, uint8_t* key_id, INTF interface) {

	mldsa_genkeys_hw(87, d, pk, sk, ext_key, key_id, interface);

}

void mldsa_genkeys_hw(int mode, unsigned char d[32], unsigned char* pk, unsigned char* sk, bool ext_key, uint8_t* key_id, INTF interface) 
{
	//-- se_code = { {(32'b) 64-bit data_packages}, {10'b0}, {k = 4, k = 3, k = 2, DEC, ENC, KEY_GEN}, {(16'b)MLKEM} }
	uint64_t next_block = 0;
	uint64_t control = 0;
    while (control != CMD_SE_CODE)
    {
        picorv32_control(interface, &control);
    }

	int k; 
	if (mode == 44) k = 2;
	else if (mode == 65) k = 3;
	else if (mode == 87) k = 4;
	else k = 2; // Default to 44

    const uint8_t mldsa_code  = MLDSA_SE_CODE;
    uint16_t mldsa_op_sel     = ((uint16_t) !ext_key << 15) | ((uint16_t) (*key_id << 9)) | (1 << (k + 1)) | (1 << 0); 
    
    uint64_t se_code = ((uint32_t) mldsa_op_sel << 16) + mldsa_code;
    write_INTF(interface, &se_code, PICORV32_DATA_IN, AXI_BYTES);

	uint32_t LEN_PK;					// Bytes
	uint32_t LEN_SK;					// Bytes
	uint32_t LEN_PK_packages;			// Packages of 64-bit
	uint32_t LEN_SK_packages;			// Packages of 64-bit
	uint32_t LEN_PK_blocks;				// Blocks of #FIFO_DEPTH-1 * 64-bit
	uint32_t LEN_SK_blocks;				// Blocks of #FIFO_DEPTH-1 * 64-bit
	uint32_t LEN_PK_rem;				// Remaining packages of 64-bit
	uint32_t LEN_SK_rem;				// Remaining packages of 64-bit
	
	//-- ML-DSA-44
	if (mode == 44)							
	{
		LEN_PK 	= 1312;
		LEN_SK 	= 2560;
	}
	//-- ML-DSA-65
	else if (mode == 65)						
	{
		LEN_PK 	= 1952;
		LEN_SK 	= 4032;
	}
	//-- ML-DSA-87
	else if (mode == 87)						
	{
		LEN_PK 	= 2592;
		LEN_SK 	= 4896;
	}
	else
	{
		LEN_PK 	= 1312;
		LEN_SK 	= 2560;
	}

    volatile uint8_t PK[2592];
    volatile uint8_t SK[4896];
    volatile uint8_t seed[32];

	LEN_PK_packages = LEN_PK >> 3;
	LEN_SK_packages = LEN_SK >> 3;
	LEN_PK_blocks 	= LEN_PK_packages / (FIFO_OUT_DEPTH - 2);
	LEN_SK_blocks 	= LEN_SK_packages / (FIFO_OUT_DEPTH - 2);
	LEN_PK_rem 		= LEN_PK_packages % (FIFO_OUT_DEPTH - 2);
	LEN_SK_rem 		= LEN_SK_packages % (FIFO_OUT_DEPTH - 2);
	
	uint64_t d64[4];
	memcpy(d64, d, 32);

	if (ext_key)
	{
		while (control != CMD_SE_WRITE)
    	{
    	    picorv32_control(interface, &control);
    	}
	
		//-- Send seed (d)
		for (int i = 0; i < 4; i++)
		{
			write_INTF(interface, d64 + i, PICORV32_DATA_IN, AXI_BYTES);
		}
	}
	

	//-- Read pk
	uint32_t packages_read = 0;
	for (int i = 0; i < LEN_PK_blocks; i++)
	{
		while (control != CMD_SE_READ)
    	{
    	    picorv32_control(interface, &control);
    	}

		for (int j = 0; j < FIFO_OUT_DEPTH - 2; j++)
		{
			read_INTF(interface, pk + (j + packages_read) * AXI_BYTES, PICORV32_DATA_OUT, AXI_BYTES);
		}
		packages_read += FIFO_OUT_DEPTH - 2;

		while (control != CMD_SE_WAIT)
    	{
    	    picorv32_control(interface, &control);
			if (control == CMD_SE_WAIT) read_INTF(interface, &next_block, PICORV32_DATA_OUT, AXI_BYTES); // Send a read signal to continue
    	}
	}

	if(LEN_PK_rem) {
		while (control != CMD_SE_READ)
		{
			picorv32_control(interface, &control);
		}
		
		for (int i = 0; i < LEN_PK_rem; i++)
		{
			read_INTF(interface, pk + (i + packages_read) * AXI_BYTES, PICORV32_DATA_OUT, AXI_BYTES);
		}

			
		packages_read = 0;

		while (control != CMD_SE_WAIT)
		{
			picorv32_control(interface, &control);
			if (control == CMD_SE_WAIT) read_INTF(interface, &next_block, PICORV32_DATA_OUT, AXI_BYTES); // Send a read signal to continue
		}
	}


	//-- Read sk
	packages_read = 0;
	for (int i = 0; i < LEN_SK_blocks; i++)
	{
		while (control != CMD_SE_READ)
    	{
    	    picorv32_control(interface, &control);
    	}

		for (int j = 0; j < FIFO_OUT_DEPTH - 2; j++)
		{
			read_INTF(interface, sk + (j + packages_read) * AXI_BYTES, PICORV32_DATA_OUT, AXI_BYTES);
		}
		packages_read += FIFO_OUT_DEPTH - 2;

		while (control != CMD_SE_WAIT)
    	{
    	    picorv32_control(interface, &control);
			if (control == CMD_SE_WAIT) read_INTF(interface, &next_block, PICORV32_DATA_OUT, AXI_BYTES); // Send a read signal to continue
    	}
	}

	if(LEN_SK_rem) {
		while (control != CMD_SE_READ)
		{
			picorv32_control(interface, &control);
		}

		for (int i = 0; i < LEN_SK_rem; i++)
		{
			read_INTF(interface, sk + (i + packages_read) * AXI_BYTES, PICORV32_DATA_OUT, AXI_BYTES);
		}

		packages_read = 0;

		while (control != CMD_SE_WAIT)
		{
			picorv32_control(interface, &control);
			if (control == CMD_SE_WAIT) read_INTF(interface, &next_block, PICORV32_DATA_OUT, AXI_BYTES); // Send a read signal to continue
		}
	}

	while (control != CMD_SE_CODE) 
    {
        picorv32_control(interface, &control);
    }
}

//==============================================================================
// SIGNATURE
//==============================================================================

void mldsa44_sign_hw(
  	unsigned char* msg, unsigned int msg_len, 
  	unsigned char* sk, 
  	unsigned char* sig, unsigned int* sig_len, 
  	unsigned char* ctx, unsigned int ctx_len, bool ext_key, uint8_t* key_id, INTF interface) {
		
		mldsa_sign_hw(44, msg, msg_len, sk, sig, sig_len, ctx, ctx_len, ext_key, key_id, interface);

}

void mldsa65_sign_hw(
  	unsigned char* msg, unsigned int msg_len, 
  	unsigned char* sk, 
  	unsigned char* sig, unsigned int* sig_len, 
  	unsigned char* ctx, unsigned int ctx_len, bool ext_key, uint8_t* key_id, INTF interface) {
		
		mldsa_sign_hw(65, msg, msg_len, sk, sig, sig_len, ctx, ctx_len, ext_key, key_id, interface);

}

void mldsa87_sign_hw(
  	unsigned char* msg, unsigned int msg_len, 
  	unsigned char* sk, 
  	unsigned char* sig, unsigned int* sig_len, 
  	unsigned char* ctx, unsigned int ctx_len, bool ext_key, uint8_t* key_id, INTF interface) {
		
		mldsa_sign_hw(87, msg, msg_len, sk, sig, sig_len, ctx, ctx_len, ext_key, key_id, interface);

}

void mldsa_sign_hw(
	int mode, 
  	unsigned char* msg, unsigned int msg_len, 
  	unsigned char* sk, 
  	unsigned char* sig, unsigned int* sig_len, 
  	unsigned char* ctx, unsigned int ctx_len, bool ext_key, uint8_t* key_id, INTF interface)
  {
	//-- se_code = { {(32'b) 64-bit data_packages}, {10'b0}, {k = 4, k = 3, k = 2, DEC, ENC, KEY_GEN}, {(16'b)MLKEM} }
	uint64_t next_block = 0;
	uint64_t control = 0;
    while (control != CMD_SE_CODE)
    {
        picorv32_control(interface, &control);
    }

	int k; 
	if (mode == 44) k = 2;
	else if (mode == 65) k = 3;
	else if (mode == 87) k = 4;
	else k = 2; // Default to 44

    const uint8_t mldsa_code  = MLDSA_SE_CODE;
    uint16_t mldsa_op_sel     = ((uint16_t) !ext_key << 15) | ((uint16_t) (*key_id << 9)) | (1 << (k + 1)) | (1 << 1); 
    
    uint64_t se_code = ((uint32_t) mldsa_op_sel << 16) + mldsa_code;
    write_INTF(interface, &se_code, PICORV32_DATA_IN, AXI_BYTES);

	uint32_t LEN_SK;					// Bytes
	uint32_t LEN_SK_packages;			// Packages of 64-bit
	uint32_t LEN_SK_blocks;			// Blocks of #FIFO_DEPTH-1 * 64-bit
	uint32_t LEN_SK_rem;				// Remaining packages of 64-bit
    uint32_t LEN_SIG;					// Bytes
	uint32_t LEN_SIG_packages;			// Packages of 64-bit
	uint32_t LEN_SIG_blocks;			// Blocks of #FIFO_DEPTH-1 * 64-bit
	uint32_t LEN_SIG_rem;				// Remaining packages of 64-bit
	
	//-- ML-DSA-44
	if (mode == 44)							
	{
		LEN_SK 	= 2560;
        LEN_SIG = 2420;
	}
	//-- ML-DSA-65
	else if (mode == 65)							
	{
		LEN_SK 	= 4032;
        LEN_SIG = 3309;
	}
	//-- ML-DSA-87
	else if (mode == 87)						
	{
		LEN_SK 	= 4896;
        LEN_SIG = 4627;
	}
	else
	{
		LEN_SK 	= 2560;
        LEN_SIG = 2420;
	}

	*sig_len = LEN_SIG;

	LEN_SK_packages     = LEN_SK >> 3;
	LEN_SK_blocks 	    = LEN_SK_packages / (FIFO_OUT_DEPTH - 2);
	LEN_SK_rem 		    = LEN_SK_packages % (FIFO_OUT_DEPTH - 2);
    LEN_SIG_packages    = LEN_SIG >> 3;
	LEN_SIG_blocks 	    = LEN_SIG_packages / (FIFO_OUT_DEPTH - 2);
	LEN_SIG_rem 		= LEN_SIG_packages % (FIFO_OUT_DEPTH - 2);

	uint32_t LEN_MSG_packages;			// Packages of 64-bit
	uint32_t LEN_MSG_blocks;			// Blocks of #FIFO_DEPTH-1 * 64-bit
	uint32_t LEN_MSG_rem;				// Remaining packages of 64-bit

    LEN_MSG_packages    = msg_len >> 3;
	LEN_MSG_blocks 	    = LEN_MSG_packages / (FIFO_OUT_DEPTH - 2);
	LEN_MSG_rem 		= LEN_MSG_packages % (FIFO_OUT_DEPTH - 2);

	uint32_t last_msg;
	last_msg = msg_len & 0x7; // last 3 bits

	while (control != CMD_SE_WRITE)
    {
        picorv32_control(interface, &control);
    }

	// Send msg_len & ctx_len
	uint64_t data_len = ((uint64_t)ctx_len << 32) | ((uint64_t)msg_len << 0);
	write_INTF(interface, &data_len, PICORV32_DATA_IN, AXI_BYTES);

	// Send ctx
	uint64_t ctx64[32]; // max size
	memset(ctx64,0,256); 
	memcpy(ctx64, ctx, ctx_len);
	for (int i = 0; i < 32; i++)
		write_INTF(interface, ctx64 + i, PICORV32_DATA_IN, AXI_BYTES);

	while (control != CMD_SE_WAIT)
	{
		picorv32_control(interface, &control);
		if (control == CMD_SE_WAIT) read_INTF(interface, &next_block, PICORV32_DATA_OUT, AXI_BYTES); // Send a read signal to continue
	}

	//-- Send SK
	uint32_t packages_send = 0;
	if (ext_key)
	{
		for (int i = 0; i < LEN_SK_blocks; i++)
		{
			while (control != CMD_SE_WRITE)
			{
				picorv32_control(interface, &control);
			}

			for (int j = 0; j < FIFO_OUT_DEPTH - 2; j++)
			{
				write_INTF(interface, sk + (j + packages_send) * AXI_BYTES, PICORV32_DATA_IN, AXI_BYTES);
				// printf("\n sk[%d]: %02x", j, sk[(j + packages_send) * AXI_BYTES]);
			}
			packages_send += FIFO_OUT_DEPTH - 2;

			while (control != CMD_SE_WAIT)
    		{
    		    picorv32_control(interface, &control);
				if (control == CMD_SE_WAIT) read_INTF(interface, &next_block, PICORV32_DATA_OUT, AXI_BYTES); // Send a read signal to continue
    		}
		}

		if (LEN_SK_rem)
		{
			while (control != CMD_SE_WRITE)
			{
				picorv32_control(interface, &control);
				// printf("\n control = %d", control);
				// fflush(stdout);
			}
		}

		for (int i = 0; i < LEN_SK_rem; i++)
		{
			write_INTF(interface, sk + (i + packages_send) * AXI_BYTES, PICORV32_DATA_IN, AXI_BYTES);
		}
		packages_send += LEN_SK_rem;

		while (control != CMD_SE_WAIT)
    	{
    	    picorv32_control(interface, &control);
			if (control == CMD_SE_WAIT) read_INTF(interface, &next_block, PICORV32_DATA_OUT, AXI_BYTES); // Send a read signal to continue
    	}
	}
	
	//-- Send MSG
	packages_send = 0;
	if(LEN_MSG_blocks) {
		for (int i = 0; i < LEN_MSG_blocks; i++)
		{
			while (control != CMD_SE_WRITE)
			{
				picorv32_control(interface, &control);
			}
			
			for (int j = 0; j < FIFO_OUT_DEPTH - 2; j++)
			{
				write_INTF(interface, msg + (j + packages_send) * AXI_BYTES, PICORV32_DATA_IN, AXI_BYTES);
				// printf("\n sk[%d]: %02x", j, sk[(j + packages_send) * AXI_BYTES]);
			}
			packages_send += FIFO_OUT_DEPTH - 2;

			while (control != CMD_SE_WAIT)
			{
				picorv32_control(interface, &control);
				if (control == CMD_SE_WAIT) read_INTF(interface, &next_block, PICORV32_DATA_OUT, AXI_BYTES); // Send a read signal to continue
			}
		}
		while (control != CMD_SE_WRITE)
		{
			picorv32_control(interface, &control);
		}
	}

	if (LEN_MSG_rem)
	{
		while (control != CMD_SE_WRITE)
		{
			picorv32_control(interface, &control);
		}
	}

	
	
	for (int i = 0; i < LEN_MSG_rem; i++)
	{
		write_INTF(interface, msg + (i + packages_send) * AXI_BYTES, PICORV32_DATA_IN, AXI_BYTES);
	}

	packages_send += LEN_MSG_rem;
	
	while (control != CMD_SE_WAIT)
    {
        picorv32_control(interface, &control);
		if (control == CMD_SE_WAIT) read_INTF(interface, &next_block, PICORV32_DATA_OUT, AXI_BYTES); // Send a read signal to continue
    }

	// last msg
	if(last_msg) {

		while (control != CMD_SE_WRITE)
		{
			picorv32_control(interface, &control);
		}

		uint64_t data_last_msg = 0;
		memcpy(&data_last_msg, msg + packages_send*AXI_BYTES, last_msg);
		write_INTF(interface, &data_last_msg, PICORV32_DATA_IN, AXI_BYTES);

		while (control != CMD_SE_WAIT)
		{
			picorv32_control(interface, &control);
			if (control == CMD_SE_WAIT) read_INTF(interface, &next_block, PICORV32_DATA_OUT, AXI_BYTES); // Send a read signal to continue
		}
	}

	//-- Read sig
	uint32_t packages_read = 0;
	for (int i = 0; i < LEN_SIG_blocks; i++)
	{
		while (control != CMD_SE_READ)
    	{
    	    picorv32_control(interface, &control);
    	}

		for (int j = 0; j < FIFO_OUT_DEPTH - 2; j++)
		{
			read_INTF(interface, sig + (j + packages_read) * AXI_BYTES, PICORV32_DATA_OUT, AXI_BYTES);
		}
		packages_read += FIFO_OUT_DEPTH - 2;

		while (control != CMD_SE_WAIT)
    	{
    	    picorv32_control(interface, &control);
			if (control == CMD_SE_WAIT) read_INTF(interface, &next_block, PICORV32_DATA_OUT, AXI_BYTES); // Send a read signal to continue
    	}
	}

	while (control != CMD_SE_READ)
    {
        picorv32_control(interface, &control);
    }
	
	for (int i = 0; i < LEN_SIG_rem; i++)
	{
		read_INTF(interface, sig + (i + packages_read) * AXI_BYTES, PICORV32_DATA_OUT, AXI_BYTES);
	}

	packages_read += LEN_SIG_rem;

	while (control != CMD_SE_WAIT)
    {
        picorv32_control(interface, &control);
		if (control == CMD_SE_WAIT) read_INTF(interface, &next_block, PICORV32_DATA_OUT, AXI_BYTES); // Send a read signal to continue
    }

	uint64_t last_sig = LEN_SIG & 0x7; // Last sig
	uint64_t data_rec_sig;

	while (control != CMD_SE_READ)
    {
        picorv32_control(interface, &control);
    }
	
	read_INTF(interface, &data_rec_sig, PICORV32_DATA_OUT, AXI_BYTES);
	memcpy(sig + (packages_read * AXI_BYTES), &data_rec_sig, last_sig);

	packages_read = 0;

	while (control != CMD_SE_WAIT)
    {
        picorv32_control(interface, &control);
		if (control == CMD_SE_WAIT) read_INTF(interface, &next_block, PICORV32_DATA_OUT, AXI_BYTES); // Send a read signal to continue
    }


	while (control != CMD_SE_CODE) 
    {
        picorv32_control(interface, &control);
    }
	
}


//==============================================================================
// VERIFICATION
//==============================================================================

void mldsa44_verify_hw(
  	unsigned char* msg, unsigned int msg_len, 
  	unsigned char* pk, 
  	unsigned char* sig, unsigned int sig_len, 
  	unsigned char* ctx, unsigned int ctx_len, 
	unsigned int* result, INTF interface) {
		
		mldsa_verify_hw(44, msg, msg_len, pk, sig, sig_len, ctx, ctx_len, result, interface);

}

void mldsa65_verify_hw(
  	unsigned char* msg, unsigned int msg_len, 
  	unsigned char* pk, 
  	unsigned char* sig, unsigned int sig_len, 
  	unsigned char* ctx, unsigned int ctx_len, 
	unsigned int* result, INTF interface) {
		
		mldsa_verify_hw(65, msg, msg_len, pk, sig, sig_len, ctx, ctx_len, result, interface);

}

void mldsa87_verify_hw(
  	unsigned char* msg, unsigned int msg_len, 
  	unsigned char* pk, 
  	unsigned char* sig, unsigned int sig_len, 
  	unsigned char* ctx, unsigned int ctx_len, 
	unsigned int* result, INTF interface) {
		
		mldsa_verify_hw(87, msg, msg_len, pk, sig, sig_len, ctx, ctx_len, result, interface);

}

void mldsa_verify_hw(
    int mode,
  	unsigned char* msg, unsigned int msg_len, 
  	unsigned char* pk, 
  	unsigned char* sig, unsigned int sig_len, 
  	unsigned char* ctx, unsigned int ctx_len, 
	unsigned int* result, INTF interface)
  {
	//-- se_code = { {(32'b) 64-bit data_packages}, {10'b0}, {k = 4, k = 3, k = 2, DEC, ENC, KEY_GEN}, {(16'b)MLKEM} }
	uint64_t next_block = 0;
	uint64_t control = 0;
    while (control != CMD_SE_CODE)
    {
        picorv32_control(interface, &control);
    }

	int k; 
	if (mode == 44) k = 2;
	else if (mode == 65) k = 3;
	else if (mode == 87) k = 4;
	else k = 2; // Default to 44

    const uint8_t mldsa_code  = MLDSA_SE_CODE;
    uint16_t mldsa_op_sel     = (1 << (k + 1)) | (1 << 2); 
    
    uint64_t se_code = ((uint32_t) mldsa_op_sel << 16) + mldsa_code;
    write_INTF(interface, &se_code, PICORV32_DATA_IN, AXI_BYTES);

	uint32_t LEN_PK;					// Bytes
	uint32_t LEN_PK_packages;			// Packages of 64-bit
	uint32_t LEN_PK_blocks;			// Blocks of #FIFO_DEPTH-1 * 64-bit
	uint32_t LEN_PK_rem;				// Remaining packages of 64-bit
    uint32_t LEN_SIG;					// Bytes
	uint32_t LEN_SIG_packages;			// Packages of 64-bit
	uint32_t LEN_SIG_blocks;			// Blocks of #FIFO_DEPTH-1 * 64-bit
	uint32_t LEN_SIG_rem;				// Remaining packages of 64-bit
	
	//-- ML-DSA-44
	if (mode == 44)							
	{
		LEN_PK 	= 1312;
        LEN_SIG = 2420;
	}
	//-- ML-DSA-65
	else if (mode == 65)							
	{
		LEN_PK 	= 1952;
        LEN_SIG = 3309;
	}
	//-- ML-DSA-87
	else if (mode == 87)						
	{
		LEN_PK 	= 2592;
        LEN_SIG = 4627;
	}
	else
	{
		LEN_PK 	= 1312;
        LEN_SIG = 2420;
	}

	LEN_PK_packages     = LEN_PK >> 3;
	LEN_PK_blocks 	    = LEN_PK_packages / (FIFO_OUT_DEPTH - 2);
	LEN_PK_rem 		    = LEN_PK_packages % (FIFO_OUT_DEPTH - 2);
    LEN_SIG_packages    = LEN_SIG >> 3;
	LEN_SIG_blocks 	    = LEN_SIG_packages / (FIFO_OUT_DEPTH - 2);
	LEN_SIG_rem 		= LEN_SIG_packages % (FIFO_OUT_DEPTH - 2);

	uint32_t LEN_MSG_packages;			// Packages of 64-bit
	uint32_t LEN_MSG_blocks;			// Blocks of #FIFO_DEPTH-1 * 64-bit
	uint32_t LEN_MSG_rem;				// Remaining packages of 64-bit

    LEN_MSG_packages    = msg_len >> 3;
	LEN_MSG_blocks 	    = LEN_MSG_packages / (FIFO_OUT_DEPTH - 2);
	LEN_MSG_rem 		= LEN_MSG_packages % (FIFO_OUT_DEPTH - 2);

	uint32_t last_msg;
	last_msg = msg_len & 0x7; // last 3 bits
	uint32_t last_sig; 
    last_sig = LEN_SIG & 0x7; // last 3 bits

	while (control != CMD_SE_WRITE)
    {
        picorv32_control(interface, &control);
    }

	// Send msg_len & ctx_len
	uint64_t data_len = ((uint64_t)ctx_len << 32) | ((uint64_t)msg_len << 0);
	write_INTF(interface, &data_len, PICORV32_DATA_IN, AXI_BYTES);

	// Send ctx
	uint64_t ctx64[32]; // max size
	memset(ctx64,0,256); 
	memcpy(ctx64, ctx, ctx_len);
	for (int i = 0; i < 32; i++)
		write_INTF(interface, ctx64 + i, PICORV32_DATA_IN, AXI_BYTES);

	while (control != CMD_SE_WAIT)
	{
		picorv32_control(interface, &control);
		if (control == CMD_SE_WAIT) read_INTF(interface, &next_block, PICORV32_DATA_OUT, AXI_BYTES); // Send a read signal to continue
	}

	//-- Send PK
	uint32_t packages_send = 0;
	for (int i = 0; i < LEN_PK_blocks; i++)
	{
		while (control != CMD_SE_WRITE)
		{
			picorv32_control(interface, &control);
		}
		
		for (int j = 0; j < FIFO_OUT_DEPTH - 2; j++)
		{
			write_INTF(interface, pk + (j + packages_send) * AXI_BYTES, PICORV32_DATA_IN, AXI_BYTES);
			// printf("\n sk[%d]: %02x", j, sk[(j + packages_send) * AXI_BYTES]);
		}
		packages_send += FIFO_OUT_DEPTH - 2;

		while (control != CMD_SE_WAIT)
    	{
    	    picorv32_control(interface, &control);
			if (control == CMD_SE_WAIT) read_INTF(interface, &next_block, PICORV32_DATA_OUT, AXI_BYTES); // Send a read signal to continue
    	}
	}
	while (control != CMD_SE_WRITE)
	{
		picorv32_control(interface, &control);
	}
	
	for (int i = 0; i < LEN_PK_rem; i++)
	{
		write_INTF(interface, pk + (i + packages_send) * AXI_BYTES, PICORV32_DATA_IN, AXI_BYTES);
	}
	packages_send += LEN_PK_rem;
	
	while (control != CMD_SE_WAIT)
    {
        picorv32_control(interface, &control);
		if (control == CMD_SE_WAIT) read_INTF(interface, &next_block, PICORV32_DATA_OUT, AXI_BYTES); // Send a read signal to continue
    }

	//-- Send MSG
	packages_send = 0;
	if(LEN_MSG_blocks) {
		for (int i = 0; i < LEN_MSG_blocks; i++)
		{
			while (control != CMD_SE_WRITE)
			{
				picorv32_control(interface, &control);
			}
			
			for (int j = 0; j < FIFO_OUT_DEPTH - 2; j++)
			{
				write_INTF(interface, msg + (j + packages_send) * AXI_BYTES, PICORV32_DATA_IN, AXI_BYTES);
				// printf("\n sk[%d]: %02x", j, sk[(j + packages_send) * AXI_BYTES]);
			}
			packages_send += FIFO_OUT_DEPTH - 2;

			while (control != CMD_SE_WAIT)
			{
				picorv32_control(interface, &control);
				if (control == CMD_SE_WAIT) read_INTF(interface, &next_block, PICORV32_DATA_OUT, AXI_BYTES); // Send a read signal to continue
			}
		}
		while (control != CMD_SE_WRITE)
		{
			picorv32_control(interface, &control);
		}
	}
	
	if(LEN_MSG_rem) {
		while (control != CMD_SE_WRITE)
		{
			picorv32_control(interface, &control);
		}
	}
	for (int i = 0; i < LEN_MSG_rem; i++)
	{
		write_INTF(interface, msg + (i + packages_send) * AXI_BYTES, PICORV32_DATA_IN, AXI_BYTES);
	}
	packages_send += LEN_MSG_rem;
	
	while (control != CMD_SE_WAIT)
    {
        picorv32_control(interface, &control);
		if (control == CMD_SE_WAIT) read_INTF(interface, &next_block, PICORV32_DATA_OUT, AXI_BYTES); // Send a read signal to continue
    }

	// last msg
	if(last_msg) {

		while (control != CMD_SE_WRITE)
		{
			picorv32_control(interface, &control);
		}

		uint64_t data_last_msg = 0;
		memcpy(&data_last_msg, msg + packages_send*AXI_BYTES, last_msg);
		write_INTF(interface, &data_last_msg, PICORV32_DATA_IN, AXI_BYTES);

		while (control != CMD_SE_WAIT)
		{
			picorv32_control(interface, &control);
			if (control == CMD_SE_WAIT) read_INTF(interface, &next_block, PICORV32_DATA_OUT, AXI_BYTES); // Send a read signal to continue
		}
	}

	//-- Send sig
	packages_send = 0;
	if(LEN_SIG_blocks) {
		for (int i = 0; i < LEN_SIG_blocks; i++)
		{
			while (control != CMD_SE_WRITE)
			{
				picorv32_control(interface, &control);
			}
			
			for (int j = 0; j < FIFO_OUT_DEPTH - 2; j++)
			{
				write_INTF(interface, sig + (j + packages_send) * AXI_BYTES, PICORV32_DATA_IN, AXI_BYTES);
				// printf("\n sk[%d]: %02x", j, sk[(j + packages_send) * AXI_BYTES]);
			}
			packages_send += FIFO_OUT_DEPTH - 2;

			while (control != CMD_SE_WAIT)
			{
				picorv32_control(interface, &control);
				if (control == CMD_SE_WAIT) read_INTF(interface, &next_block, PICORV32_DATA_OUT, AXI_BYTES); // Send a read signal to continue
			}
		}
		while (control != CMD_SE_WRITE)
		{
			picorv32_control(interface, &control);
		}
	}

	if(LEN_SIG_rem) {
		while (control != CMD_SE_WRITE)
		{
			picorv32_control(interface, &control);
		}
	}
	
	for (int i = 0; i < LEN_SIG_rem; i++)
	{
		write_INTF(interface, sig + (i + packages_send) * AXI_BYTES, PICORV32_DATA_IN, AXI_BYTES);
	}
	packages_send += LEN_SIG_rem;
	
	while (control != CMD_SE_WAIT)
    {
        picorv32_control(interface, &control);
		if (control == CMD_SE_WAIT) read_INTF(interface, &next_block, PICORV32_DATA_OUT, AXI_BYTES); // Send a read signal to continue
    }

	// last sig
	if(last_sig) {

		while (control != CMD_SE_WRITE)
		{
			picorv32_control(interface, &control);
		}

		uint64_t data_last_sig = 0;
		memcpy(&data_last_sig, sig + packages_send*AXI_BYTES, last_sig);
		write_INTF(interface, &data_last_sig, PICORV32_DATA_IN, AXI_BYTES);

		while (control != CMD_SE_WAIT)
		{
			picorv32_control(interface, &control);
			if (control == CMD_SE_WAIT) read_INTF(interface, &next_block, PICORV32_DATA_OUT, AXI_BYTES); // Send a read signal to continue
		}
	}

	//-- Read RESULT
	uint32_t packages_read = 0;

	while (control != CMD_SE_READ)
	{
		picorv32_control(interface, &control);
	}

	read_INTF(interface, result, PICORV32_DATA_OUT, AXI_BYTES);

	while (control != CMD_SE_WAIT)
    {
        picorv32_control(interface, &control);
		if (control == CMD_SE_WAIT) read_INTF(interface, &next_block, PICORV32_DATA_OUT, AXI_BYTES); // Send a read signal to continue
    }

	while (control != CMD_SE_CODE) 
    {
        picorv32_control(interface, &control);
    }
	
}