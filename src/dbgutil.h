#ifndef DBGUTIL_H
#define DBGUTIL_H

#include "ownet.h"

extern void printIntro(const char *game);
extern void printbuffer(const char *name, uchar buf[16]);
extern void printKey(uchar aesKey[24]);
extern void printScratchpad(uchar scratchPad[32]);

#endif /* DBGUTIL_H */
