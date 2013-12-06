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
		printf("usage: %s <input file> <output file>\n", argv[0]);
		exit(0);
	}
	openFile = argv[1];
	destFile = argv[2];

	if ((fd = fopen(openFile, "rb")) == NULL) {
		fprintf(stderr, "%s: fopen(%s) failed D=\n", argv[0], argv[1]);
		exit(-1);
	}

	fread(magic, 1, 2, fd);
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
		fprintf(stderr, "%s: unexpected decryption magic (wrong AES key)\n", argv[0]);
		fclose(fd);
		exit(-1);
	}
	printf("verified <<\n");
	printf("decrypting into %s...\n", destFile);

	if ((dfd = fopen(destFile, "wb")) == NULL) {
		fprintf(stderr, "%s: fopen(%s) failed D=\n", argv[0], destFile);
		fclose(fd);
		exit(-1);
	}

	do {
		if ((got = fread(encbuf, 1, 4080, fd)) == -1) {
			fprintf(stderr, "wtf..?\n");
			fclose(dfd);
			fclose(fd);
			exit(-1);
		}
		numcrypts = got / 16;
		if (got % 16 > 0) {
			padMisses++;  // this should be 0 or the zip was not made properly :P
			numcrypts++;
		}
		if (got > 0) {
			for (i = 0; i < numcrypts; i++) {
				//saltHash(salted, salt, numcrypts);
				//memcpy(salted, salt, 16);
				//salted[0] += numcrypts;

				aes_encrypt(salt, dsalted, ctx);
				// LOLOLOLOLOL
				// this should cover about a 320GB file, so we should be good...
				if (salt[0] == 255 && salt[1] == 255 && salt[2] == 255 && salt[3] == 255 && salt[4] == 255) salt[5]++;
				if (salt[0] == 255 && salt[1] == 255 && salt[2] == 255 && salt[3] == 255) salt[4]++;
				if (salt[0] == 255 && salt[1] == 255 && salt[2] == 255) salt[3]++;
				if (salt[0] == 255 && salt[1] == 255) salt[2]++;
				if (salt[0] == 255) salt[1]++;
				salt[0]++;
				for (j = 0; j < 16; j++) {
					decbuf[(i*16)+j] = dsalted[j] ^ encbuf[(i*16)+j];
				}
				//decbuf[i] = dsalted[i%16] ^ encbuf[i];
			}

			totalBytes += got;
			if (totalBytes > fileSize) {
				got -= totalBytes - fileSize;
				totalBytes -= totalBytes - fileSize;
			}
			fwrite(decbuf, 1, got, dfd);
		}
	} while (got > 0);

	printf("padMisses: %u\n", padMisses);
	//fclose(dfd);
	fclose(fd);
	return 0;
	
}

