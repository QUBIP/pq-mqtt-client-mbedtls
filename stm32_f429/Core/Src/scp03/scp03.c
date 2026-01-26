#include "scp03/scp03.h"
#include "i2c.h"

// ---------------------------------------------------------
// Helpers
// ---------------------------------------------------------

static void inc_counter(unsigned char *ctr) {
	for (int i = 15; i >= 0; i--) {
		ctr[i]++;
		if (ctr[i] != 0)
			break;
	}
}

// A static inline helper function for bitwise rotation.
static inline uint64_t rotl(const uint64_t x, int k) {
	return (x << k) | (x >> (64 - k));
}

uint64_t scp03_random() {
	// The state for xoshiro256++ is a 256-bit state held in four 64-bit integers.
	// These are static, so they persist across function calls.
	static uint64_t s[4];
	// A flag to ensure the seeding logic is run only once.
	static bool is_seeded = false;

	// Seed the generator ONCE on the very first call.
	if (!is_seeded) {
		// 1. Get a single 64-bit seed value from a non-deterministic source.
		uint64_t seed;
#ifdef _WIN32
            seed = (uint64_t)time(NULL) ^ ((uint64_t)_getpid() << 32);
        #else
		seed = (uint64_t) time(NULL);
#endif

		// 2. Use a high-quality "SplitMix64" generator to initialize the 256-bit state.
		// This is the recommended practice to ensure the initial state is well-distributed.
		uint64_t z = seed;
		for (int i = 0; i < 4; i++) {
			z += 0x9e3779b97f4a7c15;
			uint64_t x = z;
			x = (x ^ (x >> 30)) * 0xbf58476d1ce4e5b9;
			x = (x ^ (x >> 27)) * 0x94d049bb133111eb;
			s[i] = x ^ (x >> 31);
		}

		is_seeded = true;
	}

	// This is the xoshiro256++ algorithm.
	const uint64_t result = rotl(s[1] * 5, 7) * 9;
	const uint64_t t = s[1] << 17;

	s[2] ^= s[0];
	s[3] ^= s[1];
	s[1] ^= s[2];
	s[0] ^= s[3];

	s[2] ^= t;
	s[3] = rotl(s[3], 45);

	return result;
}

//---------------------------------------------------------
// I2C Commands
//---------------------------------------------------------

static void i2c_send_cmd(I2C_FD interface, uint8_t cmd) {
	write_I2C(interface, &cmd, REG_CMD, 1);
}

static uint8_t read_I2C_status(I2C_FD interface) {
	uint8_t status;
	read_I2C(interface, &status, REG_STATUS, 1);
	return status;
}

// Helper to convert uint64_t to byte array (Big Endian) for I2C
static void u64_to_bytes(uint64_t val, uint8_t *bytes) {
	for (int i = 0; i < 8; i++)
		bytes[i] = (val >> ((7 - i) * 8)) & 0xFF;
}

// Helper to convert byte array to uint64_t (Big Endian) from I2C
static uint64_t bytes_to_u64(const uint8_t *bytes) {
	uint64_t val = 0;
	for (int i = 0; i < 8; i++)
		val |= ((uint64_t) bytes[i] << ((7 - i) * 8));
	return val;
}

//---------------------------------------------------------
// BLOCKING WAIT HELPERS
//---------------------------------------------------------

// Blocking wait until BUSY bit (0) is cleared
static void i2c_wait_idle(I2C_FD interface) {
	while (true) {
		uint8_t status = read_I2C_status(interface);
		if ((status & STATUS_BUSY) == 0)
			break;
	}
}

// Blocking wait until DATA_AVAIL bit (1) is set
static void i2c_wait_data(I2C_FD interface) {
	while (true) {
		uint8_t status = read_I2C_status(interface);
		if (status & STATUS_DATA_AVAIL)
			break;
	}
}

// ---------------------------------------------------------
// 1. Connect (Initialize Update + External Auth Gen)
// ---------------------------------------------------------
/**
 * @brief Initialize Secure Channel (Handshake)
 * Performs INIT UPDATE logic internally.
 * Generates the EXTERNAL AUTHENTICATE packet to be sent to the FPGA.
 * 
 * @param session         Session context (Must have static keys set)
 * @param host_challenge  16-byte random challenge
 * @param card_response   Response received from INIT_UPDATE (containing CardChal + CardCrypt)
 * @param ext_auth_out    Output: 37-byte APDU for External Authenticate (5B Header + 16B Crypt + 16B MAC)
 * @return 0 on success, -1 on cryptogram mismatch
 */
static int scp03_connect(scp03_session_t *session,
		unsigned char *host_challenge, unsigned char *card_response,
		unsigned char *ext_auth_out) {
	// 1. Store Host Challenge
	memcpy(session->host_chal, host_challenge, 16);

	// 2. Parse Card Response
	memcpy(session->card_chal, card_response, 16);

	// 3. Derive Session Keys
	scp03_derive_session_keys(session->key_bits, session->static_enc,
			session->static_mac, session->host_chal, session->card_chal,
			session->s_enc, session->s_mac, session->s_rmac);

	// 4. Verify Card Cryptogram
	unsigned char calc_card_crypt[16];
	unsigned char calc_host_crypt[16];
	scp03_calc_cryptograms(session->key_bits, session->s_mac,
			session->host_chal, session->card_chal, calc_card_crypt,
			calc_host_crypt);

	if (memcmp(calc_card_crypt, card_response + 16, 16) != 0) {
		printf("\n\nERROR SCP03 CARD CRYPTOGRAM NOT EQUAL!\n");
		exit(0);
		return -1; // Error
	}

	// 5. Initialize Session State
	memset(session->mac_chain, 0, 16);
	memset(session->counter, 0, 16);
	session->counter[15] = 1;

	// 6. Generate External Authenticate Packet
	unsigned char mac_input[64];
	unsigned int ptr = 0;

	// Block 1: Chain (00...)
	memcpy(&mac_input[ptr], session->mac_chain, 16);
	ptr += 16;

	// Block 2: Header (84 82 33 00 20) + HostCrypt + Padding (80 00 00)
	// Note: Hardcoded header to match FPGA expectation for Ext Auth
	unsigned char header[5] = { 0x84, 0x82, 0x33, 0x00, 0x20 };
	memcpy(&mac_input[ptr], header, 5);
	ptr += 5;
	memcpy(&mac_input[ptr], calc_host_crypt, 16);
	ptr += 16;

	// Pad to 16 bytes
	mac_input[ptr++] = 0x80;
	while (ptr % 16 != 0)
		mac_input[ptr++] = 0x00;

	// Calculate C-MAC
	unsigned int mac_len;
	unsigned char full_mac[16];

	if (session->key_bits == 128)
		AES_128_CMAC(session->s_mac, full_mac, &mac_len, mac_input, ptr);
	else if (session->key_bits == 192)
		AES_192_CMAC(session->s_mac, full_mac, &mac_len, mac_input, ptr);
	else if (session->key_bits == 256)
		AES_256_CMAC(session->s_mac, full_mac, &mac_len, mac_input, ptr);

	// Update Chain
	memcpy(session->mac_chain, full_mac, 16);

	// Output Packet: [Header] [HostCrypt] [MAC]
	memcpy(ext_auth_out, header, 5);
	memcpy(ext_auth_out + 5, calc_host_crypt, 16);
	memcpy(ext_auth_out + 21, full_mac, 16);

	return 0; // Success
}

// ---------------------------------------------------------
// 2. Send Data (Secure Write / CMD_UNWRAP)
// ---------------------------------------------------------
/**
 * @brief Prepare a Secure Write Command (CMD_UNWRAP)
 * Encrypts payload and signs the command with a 128-bit MAC..
 * 
 * @param session         Session context
 * @param header          5-byte APDU Header
 * @param payload         Plaintext Data (Addr + Data)
 * @param payload_len     Length of payload
 * @param apdu_out        Output: Wrapped APDU (Header + Cipher + 16B MAC)
 * @return Total length of apdu_out
 */
static int scp03_send_data(scp03_session_t *session, unsigned char *header,
		unsigned char *payload, int payload_len, unsigned char *apdu_out) {
	unsigned char iv[16];
	unsigned char zero_iv[16] = { 0 };
	unsigned int out_len;

	// A. Encrypt Payload
	// 1. Calculate IV
	if (session->key_bits == 128)
		AES_128_CBC_ENCRYPT(session->s_enc, zero_iv, iv, &out_len,
				session->counter, 16);
	else if (session->key_bits == 192)
		AES_192_CBC_ENCRYPT(session->s_enc, zero_iv, iv, &out_len,
				session->counter, 16);
	else if (session->key_bits == 256)
		AES_256_CBC_ENCRYPT(session->s_enc, zero_iv, iv, &out_len,
				session->counter, 16);
	inc_counter(session->counter);

	// 2. Pad Plaintext
	unsigned char padded_pt[256];
	memcpy(padded_pt, payload, payload_len);
	padded_pt[payload_len] = 0x80;
	unsigned int pad_len = payload_len + 1;
	while (pad_len % 16 != 0)
		padded_pt[pad_len++] = 0x00;

	// 3. Encrypt Data
	unsigned char ciphertext[256];
	if (session->key_bits == 128)
		AES_128_CBC_ENCRYPT(session->s_enc, iv, ciphertext, &out_len, padded_pt,
				pad_len);
	else if (session->key_bits == 192)
		AES_192_CBC_ENCRYPT(session->s_enc, iv, ciphertext, &out_len, padded_pt,
				pad_len);
	else if (session->key_bits == 256)
		AES_256_CBC_ENCRYPT(session->s_enc, iv, ciphertext, &out_len, padded_pt,
				pad_len);

	unsigned int cipher_len = out_len;

	// B. Calculate C-MAC
	unsigned char mac_input[512];
	unsigned int ptr = 0;

	// 1. Chain
	memcpy(&mac_input[ptr], session->mac_chain, 16);
	ptr += 16;

	// 2. Modified Header (CLA=84, Lc includes MAC)
	unsigned char mod_header[5];
	memcpy(mod_header, header, 5);
	mod_header[0] = 0x84;
	mod_header[4] = cipher_len + 16;

	memcpy(&mac_input[ptr], mod_header, 5);
	ptr += 5;

	// 3. Ciphertext
	memcpy(&mac_input[ptr], ciphertext, cipher_len);
	ptr += cipher_len;

	// 4. CMAC
	unsigned char full_mac[16];
	unsigned int mac_len_out;
	if (session->key_bits == 128)
		AES_128_CMAC(session->s_mac, full_mac, &mac_len_out, mac_input, ptr);
	else if (session->key_bits == 192)
		AES_192_CMAC(session->s_mac, full_mac, &mac_len_out, mac_input, ptr);
	else if (session->key_bits == 256)
		AES_256_CMAC(session->s_mac, full_mac, &mac_len_out, mac_input, ptr);

	// Update Chain
	memcpy(session->mac_chain, full_mac, 16);

	// C. Assemble Output
	memcpy(apdu_out, mod_header, 5);
	memcpy(apdu_out + 5, ciphertext, cipher_len);
	memcpy(apdu_out + 5 + cipher_len, full_mac, 16);

	return 5 + cipher_len + 8;
}

// ---------------------------------------------------------
// 3. Receive Data (Secure Read / CMD_WRAP)
// ---------------------------------------------------------
/**
 * @brief Process a Secure Read Response (CMD_WRAP)
 * Verifies R-MAC and Decrypts payload.
 * 
 * @param session         Session context
 * @param response_apdu   Input: Encrypted Response (Cipher + 16B MAC)
 * @param response_len    Length of response (Minimum 32 bytes: 16 Data + 16 MAC)
 * @param plaintext_out   Output: Decrypted Data
 * @return Length of plaintext, or -1 on MAC failure
 */
static int scp03_recv_data(scp03_session_t *session,
		unsigned char *response_apdu, int response_len,
		unsigned char *plaintext_out) {
	if (response_len < 32)
		return -1;

	unsigned char *ciphertext = response_apdu;
	unsigned char *r_mac = response_apdu + 16;

	// A. Calculate Response IV
	unsigned char iv[16];
	unsigned char zero_iv[16] = { 0 };
	unsigned int out_len;

	unsigned char iv_input[16];
	memcpy(iv_input, session->counter, 16);
	iv_input[0] |= 0x80; // Set MSB for Response

	if (session->key_bits == 128)
		AES_128_CBC_ENCRYPT(session->s_enc, zero_iv, iv, &out_len, iv_input,
				16);
	else if (session->key_bits == 192)
		AES_192_CBC_ENCRYPT(session->s_enc, zero_iv, iv, &out_len, iv_input,
				16);
	else if (session->key_bits == 256)
		AES_256_CBC_ENCRYPT(session->s_enc, zero_iv, iv, &out_len, iv_input,
				16);
	inc_counter(session->counter);

	/* printf("\niv_input = ");
	 for (int i = 0; i < 16; i++) printf("%02x", iv_input[i]);
	 printf("\niv       = ");
	 for (int i = 0; i < 16; i++) printf("%02x", iv[i]); */

	// B. Verify R-MAC
	unsigned char mac_input[128];
	unsigned int ptr = 0;

	// 1. Chain
	memcpy(&mac_input[ptr], session->mac_chain, 16);
	ptr += 16;

	// 2. Ciphertext
	memcpy(&mac_input[ptr], ciphertext, 16);
	ptr += 16;

	// 3. Status Word (9000) + Padding
	memset(&mac_input[ptr], 0, 16); // Zero rest
	mac_input[ptr] = 0x90;
	mac_input[ptr + 1] = 0x00;
	ptr += 2;

	// Calculate MAC
	unsigned char full_mac[16];
	unsigned int mac_len;
	if (session->key_bits == 128)
		AES_128_CMAC(session->s_rmac, full_mac, &mac_len, mac_input, ptr);
	else if (session->key_bits == 192)
		AES_192_CMAC(session->s_rmac, full_mac, &mac_len, mac_input, ptr);
	else if (session->key_bits == 256)
		AES_256_CMAC(session->s_rmac, full_mac, &mac_len, mac_input, ptr);

	// Compare
	if (memcmp(full_mac, r_mac, 16) != 0) {
		printf("\n\nERROR SCP03 DECRYPTION MAC NOT EQUAL!\n");
		exit(0);
	}

	// C. Decrypt Payload
	unsigned char padded_pt[256];
	unsigned int pt_len;
	if (session->key_bits == 128)
		AES_128_CBC_DECRYPT(session->s_enc, iv, ciphertext, 16, padded_pt,
				&pt_len);
	else if (session->key_bits == 192)
		AES_192_CBC_DECRYPT(session->s_enc, iv, ciphertext, 16, padded_pt,
				&pt_len);
	else if (session->key_bits == 256)
		AES_256_CBC_DECRYPT(session->s_enc, iv, ciphertext, 16, padded_pt,
				&pt_len);

	// Remove Padding
	unsigned int real_len = 16;
	while (real_len > 0 && padded_pt[real_len - 1] == 0x00)
		real_len--;
	if (real_len > 0 && padded_pt[real_len - 1] == 0x80)
		real_len--;

	memcpy(plaintext_out, padded_pt, real_len);

	return real_len;
}

// ---------------------------------------------------------
// DRIVER LAYER (High Level SCP-03)
// ---------------------------------------------------------

/**
 * @brief Establishes a Secure Channel Protocol 03 session with the hardware.
 * 
 * This function orchestrates the full SCP-03 handshake. It performs the following steps:
 * 1. Sends an INITIALIZE UPDATE command with a host-provided challenge.
 * 2. Receives the card's response (card challenge and card cryptogram).
 * 3. Derives the session keys (S-ENC, S-MAC, S-RMAC) based on the challenges.
 * 4. Verifies the card's cryptogram to authenticate the card.
 * 5. Constructs and sends the EXTERNAL AUTHENTICATE command to authenticate the host.
 * 6. Waits for the hardware to process and verifies the final authenticated status.
 * 
 * @param interface A handle or file descriptor for the I2C bus interface.
 * @param session   A pointer to the session context structure. Must be pre-filled with the 
 *                  static keys (static_enc, static_mac) and the 8-byte host_chal. This 
 *                  function will populate the derived session keys and initialize internal state.
 * @return          `true` if the secure channel is successfully established, `false` otherwise.
 */
bool scp03_init(I2C_FD interface, scp03_session_t *session) {
	session->key_bits = SCP03_KEY_BITS;

	unsigned char k_enc[32] = SCP03_STATIC_KEY_ENC;
	unsigned char k_mac[32] = SCP03_STATIC_KEY_MAC;
	memcpy(session->static_enc, k_enc, 32);
	memcpy(session->static_mac, k_mac, 32);

	uint64_t h_chal_u64_h = scp03_random();
	uint64_t h_chal_u64_l = scp03_random();
	u64_to_bytes(h_chal_u64_h, session->host_chal);
	u64_to_bytes(h_chal_u64_l, session->host_chal + 8);

	i2c_wait_idle(interface);

	// --- PHASE A: INITIALIZE UPDATE ---
	// Send Host Challenge
	write_I2C(interface, session->host_chal, REG_DATA_IN, 8);
	i2c_send_cmd(interface, CMD_LOAD_BUF);

	write_I2C(interface, session->host_chal + 8, REG_DATA_IN, 8);
	i2c_send_cmd(interface, CMD_LOAD_BUF);

	i2c_send_cmd(interface, CMD_INIT_UPDATE);

	// Wait for KDF completion (Data Available)
	i2c_wait_data(interface);

	// Read Card Response
	unsigned char card_resp_sim[32] = { 0 };
	read_I2C(interface, &card_resp_sim[0], REG_DATA_OUT, 8);    // Chal
	read_I2C(interface, &card_resp_sim[8], REG_DATA_OUT, 8);    // Chal
	read_I2C(interface, &card_resp_sim[16], REG_DATA_OUT, 8);   // Crypt
	read_I2C(interface, &card_resp_sim[24], REG_DATA_OUT, 8);   // Crypt

	// printf("    [Driver] Card Chal read.\n");

	// --- PHASE B: EXTERNAL AUTHENTICATE ---
	unsigned char ext_auth_apdu[37];    // 5 Header + 16 Crypt + 16 MAC
	scp03_connect(session, session->host_chal, card_resp_sim, ext_auth_apdu);

	i2c_wait_idle(interface);

	// Packet to Send: [HostCrypt (16B)] [MAC (16B)] -> 32 bytes
	// Skip Header (5 bytes)
	write_I2C(interface, ext_auth_apdu + 5, REG_DATA_IN, 8); // Host Crypt
	i2c_send_cmd(interface, CMD_LOAD_BUF);

	write_I2C(interface, ext_auth_apdu + 13, REG_DATA_IN, 8); // Host Crypt
	i2c_send_cmd(interface, CMD_LOAD_BUF);

	write_I2C(interface, ext_auth_apdu + 21, REG_DATA_IN, 8); // MAC
	i2c_send_cmd(interface, CMD_LOAD_BUF);

	write_I2C(interface, ext_auth_apdu + 29, REG_DATA_IN, 8); // MAC
	i2c_send_cmd(interface, CMD_LOAD_BUF);

	// Trigger Authentication
	i2c_send_cmd(interface, CMD_EXT_AUTH);

	i2c_wait_idle(interface);

	if (read_I2C_status(interface) & STATUS_ERROR) {
		printf("\n\nERROR SCP03 NOT AUTHENTICATED!\n");
		exit(1);
	}

	return (read_I2C_status(interface) & STATUS_AUTH);
}

/**
 * @brief Securely writes a 64-bit data payload to a specific address within the Secure Element.
 * 
 * This function performs a "Secure Write" operation. It takes a cleartext payload,
 * wraps it according to the SCP-03 specification, and transmits it to the hardware.
 * The process involves:
 * 1. Calculating a unique Initialization Vector (ICV) from the session counter.
 * 2. Padding the payload (address + data) to a full AES block.
 * 3. Encrypting the padded payload with the S-ENC session key.
 * 4. Generating a C-MAC over the command header and ciphertext using the S-MAC key and the MAC chaining value.
 * 5. Transmitting the resulting secure APDU over I2C in 64-bit chunks.
 * 6. Triggering the hardware's UNWRAP command.
 * 7. Waiting for the hardware to complete the operation.
 * 
 * @note This function must only be called after a successful call to scp03_init().
 * 
 * @param interface The I2C bus handle.
 * @param session   Pointer to the active session context. The function will use the session keys
 *                  and update the internal MAC chaining value and session counter.
 * @param addr      The 8-bit target register address within the Secure Element.
 * @param data      The 64-bit data payload to write.
 * @return          `true` on successful transmission and acknowledgment from the hardware, `false` otherwise.
 */
bool scp03_write(I2C_FD interface, scp03_session_t *session, uint8_t addr,
		uint64_t *data) {
	i2c_wait_idle(interface);

	unsigned char header[5] = { 0x80, 0xE2, 0x00, 0x00, 0x09 };
	unsigned char payload[9];
	payload[0] = addr;
	u64_to_bytes(*data, payload + 1);

	unsigned char secure_apdu[256];
	int len = scp03_send_data(session, header, payload, 9, secure_apdu);

	// Send 32 bytes (4 Blocks of 8 bytes) skipping 5 byte header
	unsigned char *ptr = secure_apdu + 5;

	for (int b = 0; b < 4; b++) {
		write_I2C(interface, ptr + (b * 8), REG_DATA_IN, 8);
		i2c_send_cmd(interface, CMD_LOAD_BUF);
	}

	i2c_send_cmd(interface, CMD_UNWRAP);

	i2c_wait_idle(interface);

	if (read_I2C_status(interface) & STATUS_ERROR) {
		printf("    [Driver] Error bit set during Write!\n");
		exit(1);
		return false;
	}

	return true; // Should check status for error
}

/**
 * @brief Securely reads a 64-bit data payload from a specific address within the Secure Element.
 * 
 * This function performs a "Secure Read" operation. It requests data from the hardware,
 * which then encrypts and signs the response. The driver receives this secure response,
 * verifies its integrity, and decrypts it. The process involves:
 * 1. Sending the target address and triggering the hardware's WRAP command.
 * 2. Polling the hardware until the response data is ready.
 * 3. Reading the encrypted response (Ciphertext + R-MAC) in 64-bit chunks.
 * 4. Calculating the expected Response IV from the session counter.
 * 5. Verifying the R-MAC using the S-RMAC session key.
 * 6. Decrypting the ciphertext using the S-ENC session key.
 * 
 * @note This function must only be called after a successful call to scp03_init().
 * 
 * @param interface The I2C bus handle.
 * @param session   Pointer to the active session context. The function will use the session keys
 *                  and update the internal session counter.
 * @param addr      The 8-bit target register address within the Secure Element to read from.
 * @param data      A pointer to a 64-bit variable where the decrypted data will be stored.
 * @return          `true` if the read, MAC verification, and decryption were all successful. Returns `false` on any failure.
 */
bool scp03_read(I2C_FD interface, scp03_session_t *session, uint8_t addr,
		uint64_t *data) {
	i2c_wait_idle(interface);

	// 1. Send Request
	// We need to write the address (byte) into the MSB of the 64-bit data register
	uint8_t req_data[8] = { 0 };
	req_data[0] = addr;
	write_I2C(interface, req_data, REG_DATA_IN, 8);
	i2c_send_cmd(interface, CMD_WRAP);

	// 2. Wait for Data
	i2c_wait_data(interface);

	// 3. Read 32 bytes (4 blocks: CipherH, CipherL, MACH, MACL)
	unsigned char resp_apdu[32];
	for (int b = 0; b < 4; b++) {
		read_I2C(interface, &resp_apdu[b * 8], REG_DATA_OUT, 8);
	}

	// 4. Unwrap
	unsigned char plain[16];
	int len = scp03_recv_data(session, resp_apdu, 32, plain);

	if (len < 0)
		return false;

	*data = bytes_to_u64(plain);
	return true;
}
