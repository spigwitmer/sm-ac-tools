#ifndef GETKEY_H
#define GETKEY_H

#include "shaib.h"

#ifndef OW_UCHAR
#define OW_UCHAR
typedef unsigned char uchar;
#endif /* OW_UCHAR */

extern int getKey(const uchar *subkey, uchar *output);
#endif /* GETKEY_H */
