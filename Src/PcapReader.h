/**
 * Copyright(C) 2020 Florian Hisch
 *
 * This program is free software : you can redistribute itand /or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <https://www.gnu.org/licenses/>.
 */

#pragma once

#include "PcapFormat.h"
#include <iostream>
#include <fstream>

using namespace std;

class PcapReader
{
protected:
    ifstream        file;
    unsigned int    fileSize;
    PcapHeaderType  pcapHeader;
    bool            swapByteOrder;
    bool            timeInMicros;
    int32_t         packetNumber;
    int             lastInfoPrint;
    bool            isPcapng;

public:
    PcapReader(void);
    virtual ~PcapReader(void);

    virtual int Open(const char* fileName);
    virtual int Close();

    virtual int ReadPacket(PcapPacketHeaderType *packetHeader, uint8_t *packetData);

    virtual uint32_t MaxSnapLength();

    PcapHeaderType* GetPcapHeader() {
        return &pcapHeader;
    }

    bool IsSwapedbyteOrder() {
        return swapByteOrder;
    }
};

