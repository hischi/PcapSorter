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

#include "PcapReader.h"
#include <intrin.h>
#include "Logger.h"


PcapReader::PcapReader(void)
{
    Close();
}


PcapReader::~PcapReader(void)
{
    Close();
}

int PcapReader::Open(const char* fileName) {
    Close();

    file = ifstream(fileName, ios::in | ios::binary | ios::ate);
    if(!file.is_open()) {
        Logger::GetLogger().Log(LL_ERROR, "Can not open input PCAP file");
        return -1;
    }

    fileSize = (unsigned int) file.tellg();
    file.seekg(0, ios::beg);
    lastInfoPrint = -1;

    memset(&pcapHeader, 0, sizeof(pcapHeader));
    file.read((char*) &pcapHeader, sizeof(pcapHeader));
    
    if (pcapHeader.magicNumber == PcapngBlockTypesType::sectionHeader) {
        isPcapng = true;

        // Parse Section Header Block
        PcapngSectionHeaderBlockType sectionHeaderBlock;
        file.seekg(0, ios::beg);
        file.read((char*)&sectionHeaderBlock, sizeof(sectionHeaderBlock));
        if (sectionHeaderBlock.magicNumber == 0x1A2B3C4D) {
            swapByteOrder = false;
        }
        else if (sectionHeaderBlock.magicNumber == 0x4D3C2B1A) {
            swapByteOrder = true;
        }
        else {
            Logger::GetLogger().Log(LL_ERROR, "Not a valid PCAP-NG file. Magic number is wrong");
            Close();
            return -1;
        }
        file.seekg(sectionHeaderBlock.block.blockTotalLength - sizeof(sectionHeaderBlock), ios::cur);

        if (swapByteOrder) {
            sectionHeaderBlock.block.blockTotalLength = _byteswap_ulong(sectionHeaderBlock.block.blockTotalLength);
            sectionHeaderBlock.versionMajor = _byteswap_ushort(sectionHeaderBlock.versionMajor);
            sectionHeaderBlock.versionMinor = _byteswap_ushort(sectionHeaderBlock.versionMinor);
        }

        // Fill pcapHeader for compatibility
        pcapHeader.versionMajor = sectionHeaderBlock.versionMajor;
        pcapHeader.versionMinor = sectionHeaderBlock.versionMinor;

        // Parse Interface Description Block
        PcapngInterfaceDescriptionBlockType ifDescBlock;
        file.read((char*)&ifDescBlock, sizeof(ifDescBlock));
        if (swapByteOrder) {
            ifDescBlock.block.blockType = _byteswap_ulong(ifDescBlock.block.blockType);
            ifDescBlock.block.blockTotalLength = _byteswap_ulong(ifDescBlock.block.blockTotalLength);
            ifDescBlock.linkType = _byteswap_ushort(ifDescBlock.linkType);
            ifDescBlock.snapLen = _byteswap_ulong(ifDescBlock.snapLen);
        }

        if (ifDescBlock.block.blockType != PcapngBlockTypesType::interfaceDescription) {
            Logger::GetLogger().Log(LL_ERROR, "Not a valid PCAP-NG file. Interface-Description-Block is missing");
            Close();
            return -1;
        }

        if (ifDescBlock.linkType != 1) {
            Logger::GetLogger().Log(LL_ERROR, "Not an useable PCAP-NG file. LinkType is not Ethernet (1)");
            Close();
            return -1;
        }

        // Fill pcapHeader for compatibility
        pcapHeader.maxSnapLength = ifDescBlock.snapLen;
        pcapHeader.timestampAccuracy = 0;
        pcapHeader.timezone = 0;
        pcapHeader.network = ifDescBlock.linkType;
        timeInMicros = true;

        // Iterate over options
        uint32_t remOptionsLen = ifDescBlock.block.blockTotalLength - sizeof(PcapngInterfaceDescriptionBlockType) - 4;

        while (remOptionsLen > 0) {
            PcapngOptionType option;
            file.read((char*)&option, sizeof(option));
            remOptionsLen -= sizeof(option);

            if (swapByteOrder) {
                option.optionCode = _byteswap_ushort(option.optionCode);
                option.optionLength = _byteswap_ushort(option.optionLength);
            }

            switch (option.optionCode) {
            case PcapngIfOptionCodesType::if_tsresol:
                uint8_t tsresol;
                file.read((char*)&tsresol, sizeof(tsresol));
                remOptionsLen -= sizeof(tsresol);

                if (tsresol & 0x80) {
                    Logger::GetLogger().Log(LL_WARNING, "Unknown time resolution. Assume microseconds");
                }
                else {
                    if (tsresol != 6 && tsresol != 9) {
                        Logger::GetLogger().Log(LL_WARNING, "Unknown time resolution. Assume microseconds");
                    }
                    else if (tsresol == 9) {
                        timeInMicros = false; // In nanoseconds
                    }
                }
                break;

            case PcapngIfOptionCodesType::if_tzone:
                int32_t timezone;
                file.read((char*)&timezone, sizeof(timezone));
                remOptionsLen -= sizeof(timezone);
                if (swapByteOrder)
                    timezone = _byteswap_ulong(timezone);
                pcapHeader.timezone = timezone;
                break;

            default:
                if (option.optionLength & 0x0003) {
                    option.optionLength = (option.optionLength & 0xFFFC) + 4;
                }
                file.seekg(option.optionLength, ios::cur);
            }
        }
        file.seekg(4, ios::cur);
    }
    else {
        isPcapng = false;

        if (pcapHeader.magicNumber == 0xA1B2C3D4) {
            swapByteOrder = false;
            timeInMicros = true;
        }
        else if (pcapHeader.magicNumber == 0xD4C3B2A1) {
            swapByteOrder = true;
            timeInMicros = true;
        }
        else if (pcapHeader.magicNumber == 0xA1B23C4D) {
            swapByteOrder = false;
            timeInMicros = false;
        }
        else if (pcapHeader.magicNumber == 0x4D3CB2A1) {
            swapByteOrder = true;
            timeInMicros = false;
        }
        else {
            Logger::GetLogger().Log(LL_ERROR, "Not a valid PCAP file. Magic number is wrong");
            Close();
            return -1;
        }

        if (swapByteOrder) {
            pcapHeader.versionMajor = _byteswap_ushort(pcapHeader.versionMajor);
            pcapHeader.versionMinor = _byteswap_ushort(pcapHeader.versionMinor);
            pcapHeader.timezone = _byteswap_ulong(pcapHeader.timezone);
            pcapHeader.timestampAccuracy = _byteswap_ulong(pcapHeader.timestampAccuracy);
            pcapHeader.maxSnapLength = _byteswap_ulong(pcapHeader.maxSnapLength);
            pcapHeader.network = _byteswap_ulong(pcapHeader.network);
        }
    }

    packetNumber = 0;
    return 0;
}

int PcapReader::Close() {
    if(file.is_open()) {
        file.close();
        fileSize = 0;
        lastInfoPrint = -1;
    }
    return 0;
}

int PcapReader::ReadPacket(PcapPacketHeaderType *packetHeader, uint8_t *packetData) {

    uint32_t pcapng_skip = 0;

    if(!file.is_open()) {
        return -1;
    }

    Logger::GetLogger().SetReference(packetNumber, nullptr);

    if (isPcapng) {
        PcapngBlockType block;
        file.read((char*)&block, sizeof(block));
        if (file.eof()) {
            Logger::GetLogger().Log(LL_INFO, "Read Progress ", 100, "%");
            return 0;
        }

        if (swapByteOrder) {
            block.blockType = _byteswap_ulong(block.blockType);
            block.blockTotalLength = _byteswap_ulong(block.blockTotalLength);
        }

        switch (block.blockType) {
        case PcapngBlockTypesType::sectionHeader:
            Logger::GetLogger().Log(LL_WARNING, "Unexpected section-header-block in PCAP-NG");
            file.seekg(block.blockTotalLength - sizeof(block), ios::cur);
            return -1;

        case PcapngBlockTypesType::interfaceDescription:
            Logger::GetLogger().Log(LL_WARNING, "Unexpected interface-description-block in PCAP-NG");
            file.seekg(block.blockTotalLength - sizeof(block), ios::cur);
            return -1;

        case PcapngBlockTypesType::enhancedPacket:
        {
            PcapngEnhancedPacketBlockType packet;
            file.read((char*)&packet + sizeof(packet.block), sizeof(packet) - sizeof(packet.block));
            packetNumber++;

            packet.block = block;
            if (swapByteOrder) {
                packet.interfaceId = _byteswap_ulong(packet.interfaceId);
                packet.timestampHigh = _byteswap_ulong(packet.timestampHigh);
                packet.timestampLow = _byteswap_ulong(packet.timestampLow);
                packet.capturedLen = _byteswap_ulong(packet.capturedLen);
                packet.packetLen = _byteswap_ulong(packet.packetLen);
            }
            uint64_t timestamp = packet.timestampHigh;
            timestamp = (timestamp << 32) + packet.timestampLow;

            if (timeInMicros) {
                packetHeader->timestampSeconds = (uint32_t) (timestamp / 1000000);
                packetHeader->timestampMicroSeconds = (uint32_t)(timestamp % 1000000);
            }
            else {
                packetHeader->timestampSeconds = (uint32_t)(timestamp / 1000000000);
                packetHeader->timestampMicroSeconds = (uint32_t)(timestamp % 1000000000);
            }

            packetHeader->packetLength = packet.capturedLen;
            packetHeader->originalLength = packet.packetLen;

            pcapng_skip = packet.block.blockTotalLength - sizeof(packet) - packetHeader->packetLength;
        }
            break;

        case PcapngBlockTypesType::simplePacket:
        {
            PcapngSimplePacketBlockType packet;
            file.read((char*)&packet + sizeof(packet.block), sizeof(packet) - sizeof(packet.block));
            packetNumber++;

            packet.block = block;
            if (swapByteOrder) {
                packet.packetLen = _byteswap_ulong(packet.packetLen);
            }

            packetHeader->timestampSeconds = 0;
            packetHeader->timestampMicroSeconds = 0;
            packetHeader->packetLength = packet.block.blockTotalLength - sizeof(packet) - 4;
            packetHeader->originalLength = packet.packetLen;

            pcapng_skip = packet.block.blockTotalLength - sizeof(packet) - packetHeader->packetLength;
        }
            break;

        case PcapngBlockTypesType::packet:
        {
            PcapngPacketBlockType packet;
            file.read((char*)&packet + sizeof(packet.block), sizeof(packet) - sizeof(packet.block));
            packetNumber++;

            packet.block = block;
            if (swapByteOrder) {
                packet.interfaceId = _byteswap_ushort(packet.interfaceId);
                packet.dropsCount = _byteswap_ushort(packet.dropsCount);
                packet.timestampHigh = _byteswap_ulong(packet.timestampHigh);
                packet.timestampLow = _byteswap_ulong(packet.timestampLow);
                packet.capturedLen = _byteswap_ulong(packet.capturedLen);
                packet.packetLen = _byteswap_ulong(packet.packetLen);
            }
            uint64_t timestamp = packet.timestampHigh;
            timestamp = (timestamp << 32) + packet.timestampLow;

            if (timeInMicros) {
                packetHeader->timestampSeconds = (uint32_t)(timestamp / 1000000);
                packetHeader->timestampMicroSeconds = (uint32_t)(timestamp % 1000000);
            }
            else {
                packetHeader->timestampSeconds = (uint32_t)(timestamp / 1000000000);
                packetHeader->timestampMicroSeconds = (uint32_t)(timestamp % 1000000000);
            }

            packetHeader->packetLength = packet.capturedLen;
            packetHeader->originalLength = packet.packetLen;

            pcapng_skip = packet.block.blockTotalLength - sizeof(packet) - packetHeader->packetLength;
        }
            break;

        default:
            Logger::GetLogger().Log(LL_WARNING, "Unknown block-type in PCAP-NG: ", block.blockType);
            file.seekg(block.blockTotalLength - sizeof(block), ios::cur);
            return -1;
        }

    }
    else {
        file.read((char*)packetHeader, sizeof(PcapPacketHeaderType));
        if (file.eof()) {
            Logger::GetLogger().Log(LL_INFO, "Read Progress ", 100, "%");
            return 0;
        }

        packetNumber++;

        if (swapByteOrder) {
            packetHeader->timestampSeconds = _byteswap_ulong(packetHeader->timestampSeconds);
            packetHeader->timestampMicroSeconds = _byteswap_ulong(packetHeader->timestampMicroSeconds);
            if (!timeInMicros)
                packetHeader->timestampMicroSeconds /= 1000;
            packetHeader->packetLength = _byteswap_ulong(packetHeader->packetLength);
            packetHeader->originalLength = _byteswap_ulong(packetHeader->originalLength);
        }
    }

    Logger::GetLogger().SetReference(packetNumber, packetHeader);

    if (packetHeader->packetLength > pcapHeader.maxSnapLength) {
        Logger::GetLogger().Log(LL_ERROR, "Packet contains more bytes than max. snap length ", pcapHeader.maxSnapLength);
        return -3;
    }

    file.read((char*)packetData, packetHeader->packetLength);
    if (file.eof()) {
        Logger::GetLogger().Log(LL_ERROR, "Can not read the snap-data of packet. End of file reached");
        return -2;
    }

    if (isPcapng) {
        
        file.seekg(pcapng_skip, ios::cur);
    }

    Logger::GetLogger().Log(LL_DEBUG, "Packet read ok");
    if ((lastInfoPrint < 0) || (lastInfoPrint + 0.1 * fileSize <= file.tellg())) {
        Logger::GetLogger().Log(LL_INFO, "Read Progress ", (int)(file.tellg() / (float)fileSize * 100.0), "%");
        lastInfoPrint = (unsigned int) file.tellg();
    }

    return packetNumber;
}

uint32_t PcapReader::MaxSnapLength() {
    if(file.is_open()) {
        return pcapHeader.maxSnapLength;
    } else {
        return 0;
    }
}