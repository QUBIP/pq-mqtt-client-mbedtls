////////////////////////////////////////////////////////////////////////////////////
// Company: IMSE-CNM CSIC
// Engineer: Pablo Navarro Torrero
//
// Create Date: 08/09/2025
// File Name: secmem_hw.c 
// Project Name: SE-QUBIP
// Target Devices: PYNQ-Z2
// Description:
//
//		Secure Memory HW Handler Functions
//
////////////////////////////////////////////////////////////////////////////////////

#include "secmem_hw.h"

secmem_alg_t secmem_aes     = {
                               .alg_id          = "AES",
                               .max_keys        = KEY_NUM_AES,
                               .key_len         = KEY_LEN_AES, 
                               .addr_offset     = KEY_OFFSET_AES,
                               .num_keys_stored = 0,
                               .key_slot_in_use = {false}
                               };
                                  
secmem_alg_t secmem_x25519  = {
                               .alg_id          = "X25519",
                               .max_keys        = KEY_NUM_X25519,
                               .key_len         = KEY_LEN_X25519, 
                               .addr_offset     = KEY_OFFSET_X25519,
                               .num_keys_stored = 0,
                               .key_slot_in_use = {false}
                               };

secmem_alg_t secmem_eddsa   = {
                               .alg_id          = "EDDSA",
                               .max_keys        = KEY_NUM_EDDSA,
                               .key_len         = KEY_LEN_EDDSA, 
                               .addr_offset     = KEY_OFFSET_EDDSA,
                               .num_keys_stored = 0,
                               .key_slot_in_use = {false}
                               };    
                                    
secmem_alg_t secmem_slhdsa  = {
                               .alg_id          = "SLHDSA",
                               .max_keys        = KEY_NUM_SLHDSA,
                               .key_len         = KEY_LEN_SLHDSA, 
                               .addr_offset     = KEY_OFFSET_SLHDSA,
                               .num_keys_stored = 0,
                               .key_slot_in_use = {false}
                               }; 

secmem_alg_t secmem_mlkem   = {
                               .alg_id          = "MLKEM",
                               .max_keys        = KEY_NUM_MLKEM,
                               .key_len         = KEY_LEN_MLKEM, 
                               .addr_offset     = KEY_OFFSET_MLKEM,
                               .num_keys_stored = 0,
                               .key_slot_in_use = {false}
                               };  

secmem_alg_t secmem_mldsa   = {
                               .alg_id          = "MLDSA",
                               .max_keys        = KEY_NUM_MLDSA,
                               .key_len         = KEY_LEN_MLDSA, 
                               .addr_offset     = KEY_OFFSET_MLDSA,
                               .num_keys_stored = 0,
                               .key_slot_in_use = {false}
                               };         

secmem_alg_t* alg_info[] = {
                            &secmem_aes,
                            &secmem_x25519,
                            &secmem_eddsa,
                            &secmem_slhdsa,
                            &secmem_mlkem,
                            &secmem_mldsa
                            };  

/**
 * --- op_select bit mapping ---
 * [15:11]: Select Algorithm
 * [10]:    Key Origin (0 = EXTERNAL, 1 = SECMEM)
 * [9:4]:   Key ID
 * [3]:     Secure Memory Info
 * [2]:     Get Key
 * [1]:     Delete Key
 * [0]:     Store Key
 */ 

void secmem_store_key(uint8_t alg_id, uint8_t* key_id, bool is_external, uint8_t* key_external, uint8_t key_len, INTF interface)
{
    //-- se_code = { {32'b0}, {(16'b)op_select}, {(16'b)SECMEM} }
    uint64_t control = 0;
    while (control != CMD_SE_CODE)
    {
        picorv32_control(interface, &control);
    }

    const uint16_t secmem_code  = SECMEM_SE_CODE;
    uint16_t secmem_op_sel      = ((uint16_t) alg_id << ALG_ID_OFFSET) | ((uint16_t) is_external << KEY_ORIGIN_OFFSET) | OP_STORE_KEY; 

    uint64_t se_code = ((uint32_t) secmem_op_sel << 16) | secmem_code;
    write_INTF(interface, &se_code, PICORV32_DATA_IN, AXI_BYTES);

    if (is_external)
    {
        //-- Wait till control is CMD_SE_WRITE
        while (control != CMD_SE_WRITE) 
        {
            picorv32_control(interface, &control);
        }
        uint32_t num_packages = key_len >> 3;
        uint64_t key_data = 0;
        for (int i = 0; i < num_packages; i++)
        {
            key_data =  ((uint64_t) key_external[AXI_BYTES*i+0]) << 56  |
                        ((uint64_t) key_external[AXI_BYTES*i+1]) << 48  |
                        ((uint64_t) key_external[AXI_BYTES*i+2]) << 40  |
                        ((uint64_t) key_external[AXI_BYTES*i+3]) << 32  |
                        ((uint64_t) key_external[AXI_BYTES*i+4]) << 24  |
                        ((uint64_t) key_external[AXI_BYTES*i+5]) << 16  |
                        ((uint64_t) key_external[AXI_BYTES*i+6]) << 8   |
                        ((uint64_t) key_external[AXI_BYTES*i+7]) << 0;
            
            write_INTF(interface, &key_data, PICORV32_DATA_IN, AXI_BYTES);
        }
    }

    //-- Wait till control is CMD_SE_READ
    while (control != CMD_SE_READ) 
    {
        picorv32_control(interface, &control);
    }

    read_INTF(interface, key_id, PICORV32_DATA_OUT, AXI_BYTES);

    while (control != CMD_SE_CODE) 
    {
        picorv32_control(interface, &control);
    }
}



void secmem_delete_key(uint8_t alg_id, uint8_t key_id, INTF interface)
{
    //-- se_code = { {32'b0}, {(16'b)op_select}, {(16'b)SECMEM} }
    uint64_t control = 0;
    while (control != CMD_SE_CODE)
    {
        picorv32_control(interface, &control);
    }

    const uint16_t secmem_code  = SECMEM_SE_CODE;
    uint16_t secmem_op_sel      = ((uint16_t) alg_id << ALG_ID_OFFSET) | ((uint16_t) key_id << KEY_ID_OFFSET) | OP_DELETE_KEY; 

    uint64_t se_code = ((uint32_t) secmem_op_sel << 16) | secmem_code;
    write_INTF(interface, &se_code, PICORV32_DATA_IN, AXI_BYTES);

    control = 0;
    while (control != CMD_SE_CODE) 
    {
        picorv32_control(interface, &control);
    }
}



void secmem_get_key(uint8_t alg_id, uint8_t key_id, uint8_t* key_data, INTF interface)
{
    //-- se_code = { {32'b0}, {(16'b)op_select}, {(16'b)SECMEM} }
    uint64_t control = 0;
    while (control != CMD_SE_CODE)
    {
        picorv32_control(interface, &control);
    }

    const uint16_t secmem_code  = SECMEM_SE_CODE;
    uint16_t secmem_op_sel      = ((uint16_t) alg_id << ALG_ID_OFFSET) | ((uint16_t) (key_id) << KEY_ID_OFFSET) | OP_GET_KEY; 

    uint64_t se_code = ((uint32_t) secmem_op_sel << 16) | secmem_code;
    write_INTF(interface, &se_code, PICORV32_DATA_IN, AXI_BYTES);

    //-- Wait till control is CMD_SE_READ
    while (control != CMD_SE_READ) 
    {
        picorv32_control(interface, &control);
    }

    uint64_t key_packages = 0;
    read_INTF(interface, &key_packages, PICORV32_DATA_OUT, AXI_BYTES);

    uint64_t data = 0;
    for (int i = 0; i < key_packages; i++)
    {
        read_INTF(interface, &data, PICORV32_DATA_OUT, AXI_BYTES);
        key_data[AXI_BYTES*i+0] = (uint8_t) (data >> 56);
        key_data[AXI_BYTES*i+1] = (uint8_t) (data >> 48);
        key_data[AXI_BYTES*i+2] = (uint8_t) (data >> 40);
        key_data[AXI_BYTES*i+3] = (uint8_t) (data >> 32);
        key_data[AXI_BYTES*i+4] = (uint8_t) (data >> 24);
        key_data[AXI_BYTES*i+5] = (uint8_t) (data >> 16);
        key_data[AXI_BYTES*i+6] = (uint8_t) (data >> 8);
        key_data[AXI_BYTES*i+7] = (uint8_t) (data >> 0);
    }

    while (control != CMD_SE_CODE) 
    {
        picorv32_control(interface, &control);
    }
}



void secmem_info(int DBG, INTF interface)
{
    //-- se_code = { {32'b0}, {(16'b)op_select}, {(16'b)SECMEM} }
    uint64_t control = 0;
    while (control != CMD_SE_CODE)
    {
        picorv32_control(interface, &control);
    }

    const uint16_t secmem_code  = SECMEM_SE_CODE;
    uint16_t secmem_op_sel      = OP_INFO; 

    uint64_t se_code = ((uint32_t) secmem_op_sel << 16) | secmem_code;

    write_INTF(interface, &se_code, PICORV32_DATA_IN, AXI_BYTES);

    //-- Wait till control is CMD_SE_READ
    while (control != CMD_SE_READ) 
    {
        picorv32_control(interface, &control);
    }

    uint64_t num_alg = 0;
    read_INTF(interface, &num_alg, PICORV32_DATA_OUT, AXI_BYTES);

    uint64_t alg_id[num_alg];
    uint64_t mem_occ[num_alg];
    uint64_t key_map[num_alg];

    uint64_t data = 0;
    for (int i = 0; i < num_alg; i++)
    {
        read_INTF(interface, alg_id + i, PICORV32_DATA_OUT, AXI_BYTES);
        read_INTF(interface, mem_occ + i, PICORV32_DATA_OUT, AXI_BYTES);
        read_INTF(interface, key_map + i, PICORV32_DATA_OUT, AXI_BYTES);
    }

    printf("\n\n --- [ Secure Memory Status ] ---\n");

    for (uint32_t i = 0; i < num_alg; i++)
    {
        // --- Decode the packed data for the current algorithm ---
        char alg_name[9];
        alg_name[0] = (alg_id[i] >> 56) & 0xFF;
        alg_name[1] = (alg_id[i] >> 48) & 0xFF;
        alg_name[2] = (alg_id[i] >> 40) & 0xFF;
        alg_name[3] = (alg_id[i] >> 32) & 0xFF;
        alg_name[4] = (alg_id[i] >> 24) & 0xFF;
        alg_name[5] = (alg_id[i] >> 16) & 0xFF;
        alg_name[6] = (alg_id[i] >>  8) & 0xFF;
        alg_name[7] = (alg_id[i] >>  0) & 0xFF;
        alg_name[8] = '\0'; // Null terminate the string
        
        uint8_t max_keys    = (mem_occ[i] >> 0)  & 0xFF;
        uint8_t keys_in_use = (mem_occ[i] >> 8)  & 0xFF;
        uint16_t key_len    = (mem_occ[i] >> 16) & 0xFFFF;
        
        // --- Print the Header Line for this algorithm ---
        printf("\n %-8s|   Keys: %2u / %-2u  |  Size: %4u bytes", alg_name, keys_in_use, max_keys, key_len);
               
    }

    printf("\n");

    if (DBG > 0) {
        // --- DETAILED DEBUG PRINTING (DBG > 0) ---
        for (uint32_t i = 0; i < num_alg; i++) {
            // Decode the info for the current algorithm
            char alg_name[9];
            alg_name[0] = (alg_id[i] >> 56) & 0xFF; 
            alg_name[1] = (alg_id[i] >> 48) & 0xFF;
            alg_name[2] = (alg_id[i] >> 40) & 0xFF; 
            alg_name[3] = (alg_id[i] >> 32) & 0xFF;
            alg_name[4] = (alg_id[i] >> 24) & 0xFF; 
            alg_name[5] = (alg_id[i] >> 16) & 0xFF;
            alg_name[6] = (alg_id[i] >>  8) & 0xFF; 
            alg_name[7] = (alg_id[i] >>  0) & 0xFF;
            alg_name[8] = '\0';
            
            uint8_t max_keys = (mem_occ[i] >> 0)  & 0xFF;
            uint16_t key_len = (mem_occ[i] >> 16) & 0xFFFF;
            
            bool any_keys_found = false;
            
            // Loop through all possible key slots for this algorithm
            for (uint8_t key_id = 0; key_id < max_keys; key_id++) {
                
                bool is_in_use = ((key_map[i] >> (63 - key_id)) & 1);

                // Only if the slot is marked as IN USE, fetch and print the key.
                if (is_in_use) {
                    if (!any_keys_found) {
                        // Print the header only if we find at least one key
                        printf("\n");
                    }
                    any_keys_found = true;
                    
                    uint8_t key_data[key_len];
                    
                    secmem_get_key(i, key_id, key_data, interface);
                    
                    // Print the formatted line for this specific key
                    printf(" %-8s|   Key ID: %2u     | Value:  ", alg_name, key_id);
                    
                    for (size_t k = 0; k < key_len; ++k) {
                        printf("%02X", key_data[k]);
                        if (((k + 1) % 32 == 0) && (k != 0) && ((k + 1) != key_len)) printf("\n                                      ");
                    }
                    printf("\n");
                }
            }
        }

    }

    printf("\n");

    //-- Wait until the command processor is back to idle state
    while (control != CMD_SE_CODE) 
    {
        picorv32_control(interface, &control);
    }
}


