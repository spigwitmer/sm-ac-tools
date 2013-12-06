#include <stdio.h>
#include "config.h"
#include "keydump.h"
#include "aes.h"
#include "getkey.h"
#ifdef KD_DEBUG
#include "dbgutil.h"
#endif

int main(int argc, char *argv[]) {
	int fileSize, i, j, subkeySize, totalBytes = 0;
	// LOOOOOOOOOL
	int padMisses = 0;
	int got, numcrypts;
	char magic[2], dmagic[2];
	uchar *aesKey, verifyBlock[16], plaintext[16], backbuffer[16], *subkey;
	uchar encbuf[4080], decbuf[4080];

	aes_decrypt_ctx ctx[1];
	char *openFile, *destFile, *keyFile;

	FILE *fd, *dfd;

	//testshit(); return 0;
	printIntro("ITG2");

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

	fread(magic, 2, 1, fd);
	if (magic[0] != ':' || magic[1] != '|') {
		fprintf(stderr, "%s: source file is not an ITG2 encrypted zip\n", argv[0]);
		fclose(fd);
		exit(-1);
	}
	fread(&fileSize, 4, 1, fd);
	printf("file size: %u\n", fileSize);
	fread(&subkeySize, 4, 1, fd);
	subkey = (uchar*)malloc(sizeof(uchar) * subkeySize);
	fread(subkey, 1, subkeySize, fd);
	fread(verifyBlock, 16, 1, fd);
	aesKey = (uchar*)malloc(24 * sizeof(uchar));
	if (getKey(subkey, aesKey) != 0) {
		fclose(fd);
		exit(-1);
	}

#ifdef KD_DEBUG
	printKey(aesKey);
	printbuffer("verifyBlock",verifyBlock);
	printbuffer("plaintext",plaintext);
#endif

	aes_decrypt_key(aesKey, 24, ctx);

	aes_decrypt(verifyBlock, plaintext, ctx);
	strncpy(dmagic, plaintext, 2);
	if (dmagic[0] != ':' || dmagic[1] != 'D') {
		printf("dmagic not verified, but writing to file anyway :P\n");
	} else {
		printf("dmagic verified :D\n");
	}

	dfd = fopen(destFile, "wb");
	if (dfd == NULL) {
		fprintf(stderr, "%s: failed to open destination file\n", argv[0]);
		fclose(fd);
		exit(-1);
	}

	printf("writing to %s...\n", destFile);
	fwrite(aesKey, 1, 24, dfd);
	fclose(dfd);
	fclose(fd);
	return 0;
	
}

