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

#include "PcapWriter.h"
#include "Logger.h"

PcapWriter::PcapWriter(void)
{
}

PcapWriter::~PcapWriter(void)
{
}

int PcapWriter::Open(const char* fileName)
{
    Close();

    file = ofstream(fileName, ios::out | ios::binary);
    if (!file.is_open()) {
        Logger::GetLogger().Log(LL_ERROR, "Can not open output PCAP file");
        return -1;
    }
    return 0;
}

int PcapWriter::Close()
{
    if (file.is_open()) {
        file.close();
    }
    return 0;
}

int PcapWriter::WritePcapHeader(PcapHeaderType* pcapHeader)
{
    PcapHeaderType pcapHeaderCpy;
    memcpy(&pcapHeaderCpy, pcapHeader, sizeof(PcapHeaderType));

    if (swapByteOrder) {
        pcapHeaderCpy.magicNumber = 0xD4C3B2A1;
        pcapHeaderCpy.versionMajor = _byteswap_ushort(2);
        pcapHeaderCpy.versionMinor = _byteswap_ushort(4);
        pcapHeaderCpy.timezone = _byteswap_ulong(pcapHeaderCpy.timezone);
        pcapHeaderCpy.timestampAccuracy = _byteswap_ulong(pcapHeaderCpy.timestampAccuracy);
        pcapHeaderCpy.maxSnapLength = _byteswap_ulong(pcapHeaderCpy.maxSnapLength);
        pcapHeaderCpy.network = _byteswap_ulong(pcapHeaderCpy.network);
    }
    else {
        pcapHeaderCpy.magicNumber = 0xA1B2C3D4;
        pcapHeaderCpy.versionMajor = 2;
        pcapHeaderCpy.versionMinor = 4;
    }

    file.write((const char*)&pcapHeaderCpy, sizeof(PcapHeaderType));
    return 0;
}

int PcapWriter::WritePacketHeader(PcapPacketHeaderType* packetHeader)
{
    if (swapByteOrder) {
        packetHeader->timestampSeconds = _byteswap_ulong(packetHeader->timestampSeconds);
        packetHeader->timestampMicroSeconds = _byteswap_ulong(packetHeader->timestampMicroSeconds);
        packetHeader->packetLength = _byteswap_ulong(packetHeader->packetLength);
        packetHeader->originalLength = _byteswap_ulong(packetHeader->originalLength);
    }

    file.write((const char*)packetHeader, sizeof(PcapPacketHeaderType));
    return 0;
}

int PcapWriter::WriteData(uint8_t* data, uint32_t len)
{
    file.write((const char*)data, len);
    return 0;
}
