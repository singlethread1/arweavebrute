#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <openssl/sha.h>
#include <openssl/md5.h>
#include "hex.h"
#include "aes.h"
#define AES256
#define CBC 1
#define CTR 0
#define ECB 0

///////////////////////////////////////////////////////////////////////////////////////
//		P U Z Z L E # 5
//         \/  \/  \/
//These are taken directly from a base64 to hex of the encrypted message
//This is for puzzle #5. Change these values to work with other puzzles.
///////////////////////////////////////////////////////////////////////////////////////
//8 byte salt - the 8 bytes that follow the "Salted__" prefix
const char ciphersalt[8] = {
	0x84, 0xDB, 0xFF, 0x78, 0x6C, 0x98, 0x3A, 0x3F }; 

//First 16 bytes of ciphertext (from bytes 16 to 32 of encrypted message - after the "Salted__" and 8 byte salt).
//More than enough to check for {"kty":"RSA"
const char ciphertexthex[] = {0xDA, 0x58, 0x01, 0xED, 0x70, 0x91, 0x84, 0xBF, 0x6B, 0x80, 0x3B, 0x71,
0xD4, 0x8E, 0x97, 0x17 }; 
///////////////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////////////

char * decrypt_cbc(char *str) {
//void* decrypt_cbc(void* str) {

SHA512_CTX ctx3;
unsigned char buffer[512];
unsigned char hashedpass[512];
unsigned char hashedpasshex[128];
unsigned char keyandiv[144];
unsigned char key[128];
unsigned char iv[16];
unsigned char temphex[16]; //puzzle 5
int countingsize = 0;


int leng = strlen(str);
int i;
strcpy(buffer,str);

SHA512_Init(&ctx3);
SHA512_Update(&ctx3, buffer, leng);
SHA512_Final(hashedpass, &ctx3);

for (i = 1; i < 11513; ++i) {
    SHA512_Init(&ctx3);
    SHA512_Update(&ctx3, hashedpass, 64);
    SHA512_Final(hashedpass, &ctx3);
 }

MD5_CTX ctx5;
hex(hashedpass, sizeof(hashedpass), hashedpasshex, sizeof(hashedpasshex));
unsigned char digest[16];
while (countingsize < 144 ) {
    MD5_Init(&ctx5);

	if (countingsize > 0) {
		MD5_Update(&ctx5, digest, sizeof(digest));
	}
	MD5_Update(&ctx5, hashedpasshex, sizeof(hashedpasshex));
	MD5_Update(&ctx5, (unsigned char*)ciphersalt, sizeof(ciphersalt));
    MD5_Final(digest, &ctx5);
	

	for (int j = 1; j < 10000; j++) {
			MD5_Init(&ctx5);
			MD5_Update(&ctx5, digest, sizeof(digest));
			MD5_Final(digest, &ctx5);
	}

	memcpy(keyandiv + countingsize, digest, sizeof(digest));
		countingsize += sizeof(digest);
}
	strncpy(key, keyandiv, 128);
	    for(int i5=128; i5<144; i5++){
            iv[i5-128] = keyandiv[i5];
    }

	memcpy(temphex, ciphertexthex, sizeof(ciphertexthex));

	struct AES_ctx ctx1;
    
	AES_init_ctx_iv(&ctx1, key, iv);
    AES_CBC_decrypt_buffer(&ctx1, temphex, sizeof(temphex)); //working with key/iv defined in hex
	

	if (strstr(temphex, "{\"kty\":\"RSA\"") != NULL) {

	return "1";
	} else {
	return "0";
	}
}

int main(void) {
	
	//This can be changed depending on BATCH_SIZE in the python script. I'm sure there's a better way to do this.
	//Not sure exactly why, but changing this messes up the final result and must be adjusted below (with the strcpy)
	char allres[4000]; 
	char finalres[4000];
	/////////////////////////////////
	
	int bufferLength = 64;
	char buffer[bufferLength]; /* not ISO 90 compatible */
	//strcpy(allres, "0");
	while(fgets(buffer, bufferLength, stdin)) {
	buffer[strcspn(buffer, "\n")] = 0;
    strcat(allres, decrypt_cbc(buffer));
	//i++;
	}
	strcpy(finalres, &allres[0]);
	printf("%s", finalres);
    
    return 0;
}

