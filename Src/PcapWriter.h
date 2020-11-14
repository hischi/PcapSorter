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

class PcapWriter
{
private:
    ofstream        file;
    bool    swapByteOrder;    

public:
    PcapWriter(void);
    virtual ~PcapWriter(void);

    int Open(const char* fileName);
    int Close();

    void SetSwapByteOrder(bool swapByteOrder) {
        this->swapByteOrder = swapByteOrder;
    }

    int WritePcapHeader(PcapHeaderType* pcapHeader);
    int WritePacketHeader(PcapPacketHeaderType* packetHeader);
    int WriteData(uint8_t* data, uint32_t len);
};