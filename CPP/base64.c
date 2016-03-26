/*********************************************************************
* Filename:   base64.c
* Author:     Brad Conte (brad AT bradconte.com)
* Copyright:
* Disclaimer: This code is presented "as is" without any guarantees.
* Details:    Implementation of the Base64 encoding algorithm.
*********************************************************************/

/*************************** HEADER FILES ***************************/
#include <stdlib.h>
#include "base64.h"

/****************************** MACROS ******************************/
#define NEWLINE_INVL 76

/**************************** VARIABLES *****************************/
// Note: To change the charset to a URL encoding, replace the '+' and '/' with '*' and '-'
static const BYTE charset[] = {"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"};

/*********************** FUNCTION DEFINITIONS ***********************/

size_t base64_encode(const BYTE in[], BYTE out[], size_t len)
{
    size_t idx, idx2, blks, blk_ceiling, left_over = 0;

    blks = (len / 3);
    left_over = len % 3;

    if (out == NULL)
    {
        idx2 = blks * 4 ;
        if (left_over) idx2 += 4;
    }
    else
    {
        // Since 3 input bytes = 4 output bytes, determine out how many even sets of
        // 3 bytes the input has.
        blk_ceiling = blks * 3;
        for (idx = 0 , idx2 = 0; idx < blk_ceiling; idx += 3 , idx2 += 4)
        {
            out[idx2] = charset[in[idx] >> 2];
            out[idx2 + 1] = charset[((in[idx] & 0x03) << 4) | (in[idx + 1] >> 4)];
            out[idx2 + 2] = charset[((in[idx + 1] & 0x0f) << 2) | (in[idx + 2] >> 6)];
            out[idx2 + 3] = charset[in[idx + 2] & 0x3F];
        }

        if (left_over == 1)
        {
            out[idx2] = charset[in[idx] >> 2];
            out[idx2 + 1] = charset[(in[idx] & 0x03) << 4];
            out[idx2 + 2] = '=';
            out[idx2 + 3] = '=';
            idx2 += 4;
        }
        else if (left_over == 2)
        {
            out[idx2] = charset[in[idx] >> 2];
            out[idx2 + 1] = charset[((in[idx] & 0x03) << 4) | (in[idx + 1] >> 4)];
            out[idx2 + 2] = charset[(in[idx + 1] & 0x0F) << 2];
            out[idx2 + 3] = '=';
            idx2 += 4;
        }
    }

    return(idx2);
}