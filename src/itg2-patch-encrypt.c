#include <stdio.h>
#include <math.h>
#include <gcrypt.h>
#include "config.h"
#include "keydump.h"
#include "aes.h"
#include "patch-constants.h"
#ifdef KD_DEBUG
#include "dbgutil.h"
#endif

#ifndef OW_UCHAR
#define OW_UCHAR
typedef unsigned char uchar;
#endif

int main(int argc, char *argv[]) {
	srand(time(NULL));
	int fileSize, i, j, subkeySize = 1024, totalBytes = 0;
	// LOOOOOOOOOL
	int padMisses = 0;
	int got, numcrypts;
	char magic[2], dmagic[2];
	uchar *aesKey, backbuffer[16], subkey[1024], verifyBlock[16], *SHAworkspace;
	uchar *plaintext = ":Dbyinfamouspat!";
	uchar encbuf[4080], decbuf[4080];

	aes_encrypt_ctx ctx[1];
	char *openFile, *destFile;

	FILE *fd, *dfd;

	printIntro("ITG2");

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

	for (i = 0; i < subkeySize; i++)
		subkey[i] = rand() * 255;

	aesKey = (uchar*)malloc(24 * sizeof(uchar));
	memset(aesKey, '\0', 24);
	
	SHAworkspace = (uchar*)malloc(sizeof(uchar) * (subkeySize+47));
	memcpy(SHAworkspace, subkey, subkeySize);
	memcpy(SHAworkspace+subkeySize, ITG2SubkeySalt, 47);
	gcry_md_hash_buffer(GCRY_MD_SHA512, aesKey, SHAworkspace, subkeySize+47);

	aes_encrypt_key(aesKey, 24, ctx);
	aes_encrypt(plaintext, verifyBlock, ctx);

#ifdef KD_DEBUG
        printKey(aesKey);
        printbuffer("verifyBlock",verifyBlock);
        printbuffer("plaintext",plaintext);
#endif
	printf("encrypting into %s...\n", destFile);

	if ((dfd = fopen(destFile, "wb")) == NULL) {
		fprintf(stderr, "%s: fopen(%s) failed D=\n", argv[0], destFile);
		fclose(fd);
		exit(-1);
	}
	fseek(fd, 0, SEEK_END);
	fileSize = ftell(fd);
	fseek(fd, 0, SEEK_SET);
	fwrite("8O", 2, 1, dfd);
	fwrite(&fileSize, 1, 4, dfd);
	fwrite(&subkeySize, 1, 4, dfd);
	fwrite(subkey, 1, subkeySize, dfd);
	fwrite(verifyBlock, 1, 16, dfd);

	do {
		if ((got = fread(decbuf, 1, 4080, fd)) == -1) {
			fprintf(stderr, "%s: error: fread(%s) returned -1, exiting...\n", argv[0], openFile);
			fclose(dfd);
			fclose(dfd);
			exit(-1);
		}
		totalBytes += got;
		numcrypts = got / 16;
		if (got % 16 > 0) { 
			numcrypts++;
		}
		if (got > 0) {
			memset(backbuffer, '\0', 16);
			for (i = 0; i < numcrypts; i++) {
				for (j = 0; j < 16; j++) {
					((uchar*)(decbuf+(16*i)))[j] ^= (((uchar)backbuffer[j]) - j);
				}
				aes_encrypt(decbuf+(16*i), encbuf+(16*i), ctx);
				memcpy(backbuffer, encbuf+(16*i), 16);
			}
			fwrite(encbuf, 1, numcrypts*16, dfd);
		}
	} while (got > 0);
	printf("done :D\n");
	fclose(dfd);
	fclose(fd);
	return 0;
	
}

