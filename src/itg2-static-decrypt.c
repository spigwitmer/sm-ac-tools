#include <stdio.h>
#include "config.h"
#include "keydump.h"
#include "aes.h"
#ifdef KD_DEBUG
#include "dbgutil.h"
#endif

#ifndef OW_UCHAR
#define OW_UCHAR
typedef unsigned char uchar;
#endif

int main(int argc, char *argv[]) {
	int fileSize, i, j, totalBytes = 0, subkeySize;
	// LOOOOOOOOOL
	int padMisses = 0;
	int got, numcrypts;
	char magic[2], dmagic[2];
	uchar *aesKey, verifyBlock[16], plaintext[16], backbuffer[16];
	uchar encbuf[4080], decbuf[4080];

	aes_decrypt_ctx ctx[1];
	char *openFile, *destFile, *keyFile;

	FILE *fd, *dfd, *kfd;

	//testshit(); return 0;
	printIntro("ITG2");

	if (argc < 4) {
		printf("usage: %s <input file> <output file> <key file>\n", argv[0]);
		exit(0);
	}
	openFile = argv[1];
	destFile = argv[2];

	if ((fd = fopen(openFile, "rb")) == NULL) {
		fprintf(stderr, "%s: fopen(%s) failed D=\n", argv[0], argv[1]);
		exit(-1);
	}

	fread(magic, 2, 1, fd);
	if (magic[0] != ':' || magic[1] != '|') {
		fprintf(stderr, "%s: source file is not an ITG2 encrypted zip\n", argv[0]);
		fclose(fd);
		exit(-1);
	}
	fread(&fileSize, 4, 1, fd);
	printf("file size: %u\n", fileSize);
	fread(&subkeySize, 4, 1, fd);
	fseek(fd, subkeySize, SEEK_CUR);
	fread(verifyBlock, 16, 1, fd);
	aesKey = (uchar*)malloc(24 * sizeof(uchar));

	kfd = fopen(argv[3], "rb");
	if (kfd == NULL) {
		fprintf(stderr, "%s: cannot open key file (you sure you typed the right file?)\n", argv[0]);
		fclose (fd);
		exit(-1);
	}
	if (fread(aesKey, 1, 24, kfd) < 24) {
		fprintf(stderr, "%s: unexpected key file size (sure it\'s the right file?)\n", argv[0]);
	}
	fclose(kfd);

	aes_decrypt_key(aesKey, 24, ctx);

	aes_decrypt(verifyBlock, plaintext, ctx);
	strncpy(dmagic, plaintext, 2);
	if (strncmp(dmagic, ":D", 2) != 0) {
		fprintf(stderr, "%s: unexpected decryption magic (wrong AES key)\n", argv[0]);
		fclose(fd);
		exit(-1);
	}

#ifdef KD_DEBUG
	printKey(aesKey);
	printbuffer("verifyBlock",verifyBlock);
	printbuffer("plaintext",plaintext);
#endif
	printf("decrypting into %s...\n", destFile);

	if ((dfd = fopen(destFile, "wb")) == NULL) {
		fprintf(stderr, "%s: fopen(%s) failed D=\n", argv[0], destFile);
		fclose(fd);
		exit(-1);
	}

	do {
		if ((got = fread(encbuf, 1, 4080, fd)) == -1) {
			fprintf(stderr, "%s: error: fread(%s) returned -1, exiting...\n", argv[0], openFile);
			fclose(dfd);
			fclose(fd);
			exit(-1);
		}
		totalBytes += got;
		numcrypts = got / 16;
		if (got % 16 > 0) { 
			padMisses++; // it means the encrypted zip wasn't made properly, FAIL
			numcrypts++;
		}
		if (totalBytes > fileSize) {
			got -= totalBytes-fileSize;
			totalBytes -= totalBytes-fileSize;
		}
		if (got > 0) {
			memset(backbuffer, '\0', 16);
			for (i = 0; i < numcrypts; i++) {
				aes_decrypt(encbuf+(16*i), decbuf+(16*i), ctx);
				for (j = 0; j < 16; j++) {
					((uchar*)(decbuf+(16*i)))[j] ^= (((uchar)backbuffer[j]) - j);
				}
				memcpy(backbuffer, encbuf+(16*i), 16);
			}
			fwrite(decbuf, 1, got, dfd);
		}
	} while (got > 0);
	printf("done :D\n");
	printf("padMisses: %u\n", padMisses);
	fclose(dfd);
	fclose(fd);
	return 0;
	
}

