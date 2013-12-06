#include <stdio.h>
#include "config.h"
#include "ownet.h"
#include "shaib.h"

#ifdef KD_DEBUG
#include "dbgutil.h"
#endif

int getKey(const uchar *subkey, uchar *output) {
	uchar firstDataPage[32], firstScratchPad[32];
	SHACopr copr;
	int i;

	memcpy(firstDataPage, subkey, 32);
	
	if ((copr.portnum = owAcquireEx("/dev/ttyS0")) == -1) {
		printf("getKey(): failed to acquire port.\nCheck to see that:\n=== you have the correct serial drivers loaded in the kernel\nOR\n=== that the security dongle connected to the boxor has not become loose :P\n");
		return -1;
	}
	FindNewSHA(copr.portnum, copr.devAN, TRUE);
	owSerialNum(copr.portnum, copr.devAN, FALSE);
#ifdef DEBUG
	printf("portnum = %d\n", copr.portnum);
	printf("serial: ");
	for (i = 7; i >= 0; i--) printf("%02x", copr.devAN[i]);
	printf("\n");

	printf("written to data page:\n");
	printScratchpad(firstDataPage);
#endif
	WriteDataPageSHA18(copr.portnum, 0, firstDataPage, 0);
	memset(firstScratchPad, '\0', 32);
	memcpy(firstScratchPad+8, subkey+32, 15);
#ifdef DEBUG
	printf("BEFORE:\n");
	printScratchpad(firstScratchPad);
#endif
	WriteScratchpadSHA18(copr.portnum, 0, firstScratchPad, 32, 1);
	SHAFunction18(copr.portnum, 0xC3, 0, 1);
	ReadScratchpadSHA18(copr.portnum, 0, 0, firstScratchPad, 1);
#ifdef DEBUG
	printf("AFTER:\n");
	printScratchpad(firstScratchPad);
#endif
	memset(firstDataPage, '\0', 32);
	WriteDataPageSHA18(copr.portnum, 0, firstDataPage, 0);
	memcpy(output, firstScratchPad+8, 24);
	
	return 0;
}

