/*
 * MIT Licensed.
 * Copyright (c) 2014 Isaac Boukris <iboukris@gmail.com>
 *
 * Radius lab module.
 *
 * The C module is responsible for:
 * - challenge response.
 * - password expired.
 * - delay response.
 *
 * It hooks before authentication to normalise the request
 * and after authentication to send the challenge or the 
 * mschap2 password-expired error.
 *
 * It is stateless in the meaning that it keeps nothing 
 * in database and each packet is handled according to
 * its current state.
 * The 'state' attribute in challenge packets is calculated
 * based on some criterias of the request.
 * Also, changed expired passwords aren't saved back to db.
 */

#include <freeradius-devel/radiusd.h>
#include <freeradius-devel/modules.h>
#include <openssl/rc4.h>
#include <openssl/des.h>
#include <iconv.h>

#define STATE_LEN 8
#define NT_DGST_LEN 16
#define	MAX_PASS_LEN 516

#define LAB_DELAY 3301
#define LAB_CHALL 3302
#define LAB_PWEXP 3303

#define PW_MSCHAP2_CPW		((311 << 16) | 27)
#define PW_MSCHAP_NT_ENC_PW	((311 << 16) | 6)

// Clears all AVPs from the reply list
static void clear_reply_vps (REQUEST *request) 
{
	VALUE_PAIR *i, *j;
        i = request->reply->vps;
        while(i) {
		j = i;
		i = i->next;
		pairdelete(&request->reply->vps, j->attribute);
	}
}

// Returns hash of Username + NAS IP + NAS port (used for state)
static uint32_t req_hash (REQUEST *request) 
{
	uint32_t hash;
	hash = fr_hash_string(request->username->vp_strvalue);
	hash = fr_hash_update(&request->packet->src_ipaddr, sizeof(fr_ipaddr_t), hash);
	hash = fr_hash_update(&request->packet->src_port, sizeof(uint16_t), hash);
	return hash;
}

// Wrapper to iconv for encoding conversions - returns the length of the output
static int convert_encoding (const char *in_e, const char *in_buff, uint32_t in_len,
				const char *out_e, char *out_buff, uint32_t out_len) 
{
	int ret, out_orig = out_len;
	iconv_t cd = iconv_open(out_e, in_e);
	ret = iconv(cd, &in_buff, &in_len, &out_buff, &out_len);
	iconv_close(cd);
	if (ret != -1) ret = out_orig - out_len;
	if (ret < 0) ret = 0;
	return ret;
}

// DES encrypt one block 'in' with 'str' as key (as unsigned)
static void des_encrypt (char in[8], char out[8], unsigned char str[7]) 
{
	DES_cblock key;
	DES_key_schedule sched;

	// expand 7 byte str to 8 byte des key
	unsigned int i;
	key[0] = str[0];
	for(i = 1; i < 7; i++) 
		key[i] = (str[i-1] << (8-i)) | (str[i] >> i);
	key[7] = str[6] << 1;
	
	DES_set_key_unchecked (&key, &sched);
	DES_ecb_encrypt((C_Block *) in, (C_Block *) out, &sched, DES_ENCRYPT);
}

// Encrypt an nt-hash with another as key (only 14 bytes of key are used)
static void nt_encrypt(char in[NT_DGST_LEN], char out[NT_DGST_LEN], char key[NT_DGST_LEN]) 
{
	des_encrypt(in, out, key);
	des_encrypt(in + 8, out + 8, key + 7);
}

// Pre authentication hook
static int lab_authorize (void *instance, REQUEST *request) 
{
	VALUE_PAIR *delay = pairfind(request->config_items, LAB_DELAY);
	if (delay && delay->vp_integer < 150  && delay->vp_integer > 0)
		sleep(delay->vp_integer);
	
	// handle mschap2 change password request (CPW), most of the
	// logic is based on code from freeradius-3 mschap module but encoding
	// conversions is done with iconv and des-encryption with openssl
	VALUE_PAIR *cpw = pairfind(request->packet->vps, PW_MSCHAP2_CPW);
	if (cpw) {
		VALUE_PAIR *i, *chall;
		chall = pairfind(request->packet->vps, PW_MSCHAP_CHALLENGE);
		if (!chall || cpw->length != 68 || cpw->vp_octets[0] != 7) {
			RDEBUG("No mschap-challenge or invalid CPW."); 
			return RLM_MODULE_INVALID;
		}
		
		// the new password blob is composed from 3 AVPs (516 bytes)
		// and it is RC4 encrypted with the old password's nt-hash as key
		char new_pwd_enc[MAX_PASS_LEN];
		int seq, npe_len = 0;
		for (seq = 1; seq < 4; seq++) {
			for (i = request->packet->vps; i != NULL; i = i->next) {
				if (i->attribute != PW_MSCHAP_NT_ENC_PW) {
                                        continue;
				}
				if (i->vp_octets[0] != 6 || i->vp_octets[2] != 0)
					return RLM_MODULE_INVALID;
				if (i->vp_octets[3] == seq) {
					memcpy(new_pwd_enc + npe_len,
						i->vp_octets + 4, i->length - 4);
                        		npe_len += i->length - 4;
					break;
				}
			}
		}
		if (npe_len != MAX_PASS_LEN) {
			RDEBUG("Invalid PW_MSCHAP_NT_ENC_PW total length");
                        return RLM_MODULE_INVALID;
		}

		VALUE_PAIR *old_pass;
		old_pass = pairfind(request->config_items, PW_CLEARTEXT_PASSWORD);
		if (!old_pass) {
			RDEBUG("Can't decrypt new pass as we don't have the original");
			return RLM_MODULE_FAIL;
		}
		
		// calculate the nt-hash of old password in order to decrypt
		// the new clear-text password 
		// NT-HASH = MD4 (UTF-16LE (password))
		char old_nt[NT_DGST_LEN], old_pass_utf16[MAX_PASS_LEN];
		uint32_t op_utf16_len;	
		op_utf16_len = convert_encoding("UTF-8", old_pass->vp_strvalue,
			 old_pass->length, "UTF-16LE", old_pass_utf16, MAX_PASS_LEN);
                if (!op_utf16_len) {
			RDEBUG("iconv is not happy (need to check errono)");
                        return RLM_MODULE_FAIL;
		}
		
		fr_md4_calc(old_nt, old_pass_utf16, op_utf16_len);

		char new_pwd_dec[MAX_PASS_LEN];
		RC4_KEY key;
		RC4_set_key(&key, NT_DGST_LEN, old_nt);
                RC4(&key, MAX_PASS_LEN, new_pwd_enc, new_pwd_dec);
		
		// last 4 bytes of decrypted blob [512-515] is new-pass length (BE int)
		// the rest is (512 - pass_len) bytes of padding followed by the new 
		// password UTF-16LE encoded (up to 512).
		uint32_t np_utf16_len = 0;
		np_utf16_len = new_pwd_dec[512];
                np_utf16_len += new_pwd_dec[513] << 8;
		if (new_pwd_dec[514] || new_pwd_dec[515] || np_utf16_len > 512) {
			RDEBUG("Password length is too big\n"
				"Probably crypto gone mad (bad credentials)");
			return RLM_MODULE_REJECT;
		}
	
		char *new_pass_utf16 = new_pwd_dec + 512 - np_utf16_len;
		
		char new_nt[NT_DGST_LEN];
		fr_md4_calc(new_nt, new_pass_utf16, np_utf16_len);
		
		// now we have new pass and new nt-hash, the CPW contains the old
		// nt-hash encrypted with the new one. need to calculate and compare
		char expected_old_nt_enc[NT_DGST_LEN];
		nt_encrypt(old_nt, expected_old_nt_enc, new_nt);
                if (memcmp(expected_old_nt_enc, cpw->vp_octets + 2, NT_DGST_LEN) != 0) {
			RDEBUG("Received old NT encrypted does not match");
                        return RLM_MODULE_REJECT;
		}
		
		// convert new password to UTF-8
		char new_pass[MAX_PASS_LEN];
                uint32_t np_len;
		np_len = convert_encoding ("UTF-16LE", new_pass_utf16, np_utf16_len,
						 "UTF-8", new_pass, MAX_PASS_LEN);
		if (!np_len) {
			RDEBUG("Encoding failed - can't normalise password for AUTH");
                        return RLM_MODULE_FAIL;
		}
		new_pass[np_len] = '\0';
		RDEBUG("Password changed successfully\n"
			"New clear-text password: %s", new_pass);
		
		// change the password on the request so auth module can authenticate it
                pairdelete(&request->config_items, PW_CLEARTEXT_PASSWORD);
		pairadd(&request->config_items, pairmake("Cleartext-Password",
                                                 new_pass, T_OP_SET));

		// remove pw_exp flag to avoid requesting change password again afte auth
		pairdelete(&request->config_items, LAB_PWEXP);
		// extract the mschap-response from the CPW and add it to the request		
		VALUE_PAIR *new_msc2_res = pairmake("MS-CHAP2-Response", "", T_OP_SET);
		new_msc2_res->vp_octets[0] = cpw->vp_octets[1];
		new_msc2_res->vp_octets[1] = 0;
		memcpy(new_msc2_res->vp_octets + 2, cpw->vp_octets + 18, 48);
		new_msc2_res->length = 50;
		pairadd(&request->packet->vps, new_msc2_res);
		
		return RLM_MODULE_OK;
	}
		
	VALUE_PAIR *state = pairfind(request->packet->vps, PW_STATE);
	if (state) {
		// a response to our challenge, clear pw_exp flag as it already happened
		VALUE_PAIR *lab_pwexp = pairfind(request->config_items, LAB_PWEXP);
		if (lab_pwexp) pairdelete(&request->config_items, LAB_PWEXP);
		
		VALUE_PAIR *lab_chall = pairfind(request->config_items, LAB_CHALL);
		if (!lab_chall) {
			RDEBUG("Packet has state but we don't have the challenge");
			return RLM_MODULE_FAIL;
		}
		// check 'state' to match what we expect (could fail if the port changed)
		char expected_state[STATE_LEN];
		snprintf(expected_state, STATE_LEN, "%02x", req_hash(request));
		if (strncmp(state->vp_strvalue, expected_state, STATE_LEN)) {
			RDEBUG("State AVP does not match - check if src-port changed");
			return RLM_MODULE_FAIL;
		}
		// change the password on the request to be the challenge 
		// and let auth modules do authentication
		pairdelete(&request->config_items, PW_CLEARTEXT_PASSWORD);
                pairadd(&request->config_items, pairmake("Cleartext-Password",
                                                 lab_chall->vp_strvalue, T_OP_SET));
		return RLM_MODULE_UPDATED;
	}
	return RLM_MODULE_NOOP; 
}

// Post authentication hook
static int lab_post_auth (void *instance, REQUEST *request) 
{
	VALUE_PAIR *lab_pwexp = pairfind(request->config_items, LAB_PWEXP);
	if (lab_pwexp && lab_pwexp->vp_integer) {
		VALUE_PAIR *auth_type = pairfind(request->config_items, PW_AUTH_TYPE);
		if (!auth_type || auth_type->vp_integer != PW_AUTHTYPE_MS_CHAP) {
			RDEBUG("Password expired flag is set\n"
				"Change password only supported with MS-CHAP2");
			return RLM_MODULE_FAIL;
		}
		
		// reject with MS error 648, to indicate change password requested
		VALUE_PAIR *pwe_reply = pairmake("MS-CHAP-Error", "", T_OP_SET);
		char new_chall[33], buffer[68];
		int i;
		for (i = 0; i < 16; i++) 
			snprintf(new_chall + (i * 2), 3, "%02x", fr_rand() & 0xff);
		snprintf(buffer, sizeof(buffer),
			"E=648 R=0 C=%s V=3 M=Password Expired", new_chall);
		// copy the identification byte from the received mschap2 response
		VALUE_PAIR *mschap2_res = pairfind(request->packet->vps,
							 PW_MSCHAP2_RESPONSE);
		if(!mschap2_res) {
			RDEBUG("Auth-Type is MS-CHAP but no MS-CHAP2-Response");
			return RLM_MODULE_FAIL;
		}
		pwe_reply->vp_strvalue[0] = mschap2_res->vp_strvalue[0];
		memcpy(pwe_reply->vp_octets + 1, buffer, sizeof(buffer));
		pwe_reply->length = sizeof(buffer) + 1;
		clear_reply_vps(request);
		pairadd(&request->reply->vps, pwe_reply);
		return RLM_MODULE_REJECT;
	}
	
	// if packet has 'state' then it's already a success reply to a challenge
	VALUE_PAIR *state = pairfind(request->packet->vps, PW_STATE);
	VALUE_PAIR *lab_chall = pairfind(request->config_items, LAB_CHALL);
	if (lab_chall && !state) {
		// if Reply-Message already exist - use it
		char *msg = "Please enter next PASSCODE:";
		VALUE_PAIR *old_msg = pairfind(request->reply->vps, PW_REPLY_MESSAGE);
		if (old_msg) msg = old_msg->vp_strvalue;
		VALUE_PAIR *reply_msg = pairmake("Reply-Message", msg, T_OP_SET);
		clear_reply_vps(request);
		pairadd(&request->reply->vps, reply_msg);
		
		// the state is based on connection criterias - see req_hash
		char str_state[STATE_LEN]; 
		snprintf(str_state, STATE_LEN, "%x", req_hash(request));
		VALUE_PAIR *new_state = pairmake("State", str_state, T_OP_SET);
		pairadd(&request->reply->vps, new_state);
		request->reply->code = PW_ACCESS_CHALLENGE;
		return RLM_MODULE_HANDLED;
	}		
	return RLM_MODULE_NOOP;
}

module_t rlm_lab = {
        RLM_MODULE_INIT,	/* magic */
        NULL,			/* mod name */
        RLM_TYPE_THREAD_SAFE,   /* type */
        NULL,           	/* instantiation */
        NULL,           	/* detach */
        {
                NULL,		/* authentication */
                lab_authorize,	/* authorization */
                NULL,   	/* preaccounting */
                NULL,   	/* accounting */
                NULL,   	/* checksimul */
                NULL,   	/* pre-proxy */
                NULL,   	/* post-proxy */
                lab_post_auth  	/* post-auth */
        }
};
