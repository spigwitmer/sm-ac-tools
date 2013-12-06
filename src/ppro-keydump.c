#include <stdio.h>
#include <math.h>
#include <gcrypt.h>
#include "config.h"
#include "keydump.h"
#include "aes.h"
#include "getkey.h"
#ifdef KD_DEBUG
#include "dbgutil.h"
#endif

void saltHash(uchar *salted, const uchar salt[16], int addition);

void saltHash(uchar *salted, const uchar salt[16], int addition) {
	int cSalt = 0, cSalt2 = 0, cSalt3 = 0;

	cSalt = (int)(salt[0]);
	cSalt2 = (int)(salt[1]);
	cSalt3 = (int)(salt[9]);
	cSalt += addition;
	salted[0] = (char)cSalt;
	cSalt >>= 8;
	cSalt += cSalt2;
	cSalt2 = (int)(salt[2]);
	salted[1] = (char)cSalt;
	cSalt >>= 8;
	cSalt += cSalt2;
	cSalt2 = (int)(salt[3]);
	salted[2] = (char)cSalt;
	cSalt >>= 8;
	cSalt2 += cSalt;
	cSalt = (int)(salt[4]);
	salted[3] = (char)cSalt2;
	cSalt2 >>= 8;
	cSalt2 += cSalt;
	cSalt = (int)(salt[5]);
	salted[4] = (char)cSalt2;
	cSalt2 >>= 8;
	cSalt += cSalt2;
	cSalt2 = (int)(salt[6]);
	salted[5] = (char)cSalt;
	cSalt >>= 8;
	cSalt2 += cSalt;
	cSalt = (int)(salt[7]);
	salted[6] = (char)cSalt2;
	cSalt2 >>= 8;
	cSalt += cSalt2;
	cSalt2 = (int)(salt[8]);
	salted[7] = (char)cSalt;
	cSalt >>= 8;
	cSalt2 += cSalt;
	cSalt = (int)(salt[10]);
	salted[8] = (char)cSalt2;
	cSalt2 >>= 8;
	cSalt3 += cSalt2;
	cSalt2 = (int)(salt[11]);
	salted[9] = (char)cSalt3;
	cSalt3 >>= 8;
	cSalt += cSalt3;
	salted[10] = cSalt;
	cSalt >>= 8;
	cSalt += cSalt2;
	cSalt2 = (int)(salt[12]);
	salted[11] = cSalt;
	cSalt >>= 8;
	cSalt += cSalt2;
	cSalt2 = (int)(salt[13]);
	salted[12] = cSalt;
	cSalt >>= 8;
	cSalt += cSalt2;
	cSalt2 = (int)(salt[14]);
	salted[13] = cSalt;
	cSalt >>= 8;
	cSalt2 += cSalt;
	cSalt = (int)(salt[15]);
	salted[14] = cSalt2;
	cSalt2 >>= 8;
	cSalt += cSalt2;
	salted[15] = cSalt;
}

int main(int argc, char *argv[]) {
	srand(time(NULL));
	int fileSize, i, j, subkeySize, totalBytes = 0;
	// LOOOOOOOOOL
	int padMisses = 0;
	int got, numcrypts;
	char magic[2], dmagic[2];
	uchar *aesKey, verifyBlock[22], plaintext[16], backbuffer[16], *subkey;
	uchar scratchBuffer[60], SHAworkspace[1064];
	uchar candidates[6][16];
	uchar salt[16], salted[16], dsalted[16];
	uchar encbuf[4080], decbuf[4080];

	aes_encrypt_ctx ctx[1];
	char *openFile, *destFile;

	FILE *fd, *dfd;

	printIntro("Pump It Up Pro");

	if (argc < 3) {
		printf("usage: %s <input file> <key output file>\n", argv[0]);
		exit(0);
	}
	openFile = argv[1];
	destFile = argv[2];

	if ((fd = fopen(openFile, "rb")) == NULL) {
		fprintf(stderr, "%s: fopen(%s) failed D=\n", argv[0], argv[1]);
		exit(-1);
	}

	fread(magic, 1, 2, fd);
	if (magic[0] != '>' || magic[1] != '>') {
		fprintf(stderr, "%s: %s is not a Pump It Up Pro encrypted zip file\n", argv[0], openFile);
		fclose(fd);
		exit(-1);
	}
	fread(&subkeySize, 1, 4, fd);
	subkey = (uchar*)malloc(sizeof(uchar) * subkeySize);
	fread(subkey, 1, subkeySize, fd);
	fread(salt, 1, 16, fd);
	fread(&fileSize, 1, 4, fd);
	fread(verifyBlock, 1, 16, fd);
	printf("file size: %u\n", fileSize);

        gcry_md_hash_buffer(GCRY_MD_SHA1, scratchBuffer, subkey, subkeySize);

        memcpy(SHAworkspace, subkey, subkeySize);
        memcpy(SHAworkspace+subkeySize, scratchBuffer, 20);
        gcry_md_hash_buffer(GCRY_MD_SHA1, scratchBuffer+20, SHAworkspace, subkeySize+20);

        memcpy(SHAworkspace, subkey, subkeySize);
        memcpy(SHAworkspace+subkeySize, scratchBuffer, 40);
        gcry_md_hash_buffer(GCRY_MD_SHA1, scratchBuffer+40, SHAworkspace, subkeySize+40);

	aesKey = (uchar*)malloc(24 * sizeof(uchar));
	memset(aesKey, '\0', 24);
	if (getKey(scratchBuffer, aesKey) != 0) {
                fclose(fd);
                exit(-1);
        }

	aes_encrypt_key(aesKey, 24, ctx);

	saltHash(salted, salt, 0x123456);

	aes_encrypt(salted, dsalted, ctx);


	for (i = 0; i < 16; i++) {
		plaintext[i] = dsalted[i] ^ verifyBlock[i];
	}
	
#ifdef KD_DEBUG
	printKey(aesKey);
	printbuffer("salt", salt);
	printbuffer("salted", salted);
	printbuffer("dsalted", dsalted);
	printbuffer("plaintext", plaintext);
#endif

	strncpy(dmagic, plaintext, 2);
	if (strncmp(dmagic, "<<", 2) != 0) {
		printf("Decryption magic not verified, but writing AES key to file anyway...");
	} else {
		printf("Decryption magic verified :D, writing AES key to key output file...\n");
	}
	if ((dfd = fopen(destFile, "wb")) == NULL) {
		fprintf(stderr, "%s: fopen(%s) failed D=\n", argv[0], destFile);
		fclose(fd);
		exit(-1);
	}

	fwrite(aesKey, 1, 24, dfd);

	fclose(dfd);
	fclose(fd);
	return 0;
	
}

