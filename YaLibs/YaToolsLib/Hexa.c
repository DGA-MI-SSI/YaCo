//  Copyright (C) 2017 The YaCo Authors
//
//  This program is free software: you can redistribute it and/or modify
//  it under the terms of the GNU General Public License as published by
//  the Free Software Foundation, either version 3 of the License, or
//  (at your option) any later version.
//
//  This program is distributed in the hope that it will be useful,
//  but WITHOUT ANY WARRANTY; without even the implied warranty of
//  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
//  GNU General Public License for more details.
//
//  You should have received a copy of the GNU General Public License
//  along with this program.  If not, see <http://www.gnu.org/licenses/>.

#include <stdint.h>
#include <stdio.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include "Hexa.h"

#ifdef _MSC_VER
#   define sscanf sscanf_s
#endif

static void hex2bin(void* pvdst, const void* pvsrc, size_t size)
{
    uint8_t*    pdst = pvdst;
    const char* psrc = pvsrc;
    for(size_t i = 0; i < size; ++i)
    {
        unsigned int value;
        sscanf(&psrc[i*2], "%2X", &value);
        pdst[i] = value & 0xFF;
    }
}

size_t hex_to_buffer(const char* hex_string, size_t byte_count, void* vbinary)
{
    uint8_t*     binary  = vbinary;
    const size_t hexsize = strlen(hex_string);
    const size_t size    = hexsize & ~1;
    const size_t maxsize = byte_count - (hexsize & 1);
    const size_t maxloop = size < maxsize * 2 ? size >> 1 : maxsize;
    // special case for when input is not mod2 in which case
    // we virtually append 0 at the beginning of the string
    if(size != hexsize)
    {
        char buffer[] = {'0', 0, 0};
        buffer[1] = hex_string[0];
        hex2bin(binary, buffer, sizeof buffer - 1);
        binary++;
        hex_string++;
    }
    hex2bin(binary, hex_string, maxloop);
    return byte_count;
}

static const char BIN_TO_HEX[] = "0123456789ABCDEF";

size_t buffer_to_hex(const void* vbinary, size_t byte_count, char* to_hex_string)
{
    const uint8_t*  binary  = vbinary;
    size_t          i       = 0;
    for(i=0; i<byte_count; i++)
    {
        unsigned char b;

        b = (binary[i] & 0xF0) >> 4;
        to_hex_string[i*2] = BIN_TO_HEX[b];

        b = binary[i] & 0x0F;
        to_hex_string[i*2+1] = BIN_TO_HEX[b];
    }

    to_hex_string[byte_count*2] = '\0';
    return byte_count*2+1;
}

