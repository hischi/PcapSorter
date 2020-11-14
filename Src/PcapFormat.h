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

#include <cstdint>

#pragma pack (push,1)

/* PCAP Types */

typedef struct PcapHeaderType {
    uint32_t    magicNumber;
    uint16_t    versionMajor;
    uint16_t    versionMinor;
    int32_t     timezone;
    uint32_t    timestampAccuracy;
    uint32_t    maxSnapLength;
    uint32_t    network;
} PcapHeaderType;

typedef struct PcapPacketHeaderType {
    uint32_t    timestampSeconds;
    uint32_t    timestampMicroSeconds;
    uint32_t    packetLength;
    uint32_t    originalLength;
} PcapPacketHeaderType;

/* PCAP-NG Types */

typedef struct {
    uint16_t optionCode;
    uint16_t optionLength;
} PcapngOptionType;

typedef struct {
    uint32_t    blockType;
    uint32_t    blockTotalLength;
    // Options
    // Block Total Length
} PcapngBlockType;

typedef struct {
    PcapngBlockType block;
    uint32_t        magicNumber;
    uint16_t        versionMajor;
    uint16_t        versionMinor;
    uint64_t        sectionLength;
    // Options
    // Block Total Length
} PcapngSectionHeaderBlockType;

typedef struct {
    PcapngBlockType block;
    uint16_t        linkType;
    uint16_t        reserved;
    uint32_t        snapLen;
    // Options
    // Block Total Length
} PcapngInterfaceDescriptionBlockType;

typedef struct {
    PcapngBlockType block;
    uint32_t        interfaceId;
    uint32_t        timestampHigh;
    uint32_t        timestampLow;
    uint32_t        capturedLen;
    uint32_t        packetLen;
    // Packet Data
    // Options
    // Block Total Length
} PcapngEnhancedPacketBlockType;

typedef struct {
    PcapngBlockType block;
    uint32_t        packetLen;
    // Packet Data
    // Options
    // Block Total Length
} PcapngSimplePacketBlockType;

typedef struct {
    PcapngBlockType block;
    uint16_t        interfaceId;
    uint16_t        dropsCount;
    uint32_t        timestampHigh;
    uint32_t        timestampLow;
    uint32_t        capturedLen;
    uint32_t        packetLen;
    // Packet Data
    // Options
    // Block Total Length
} PcapngPacketBlockType;

#pragma pack(pop)

typedef enum {
    opt_endofopt = 0,
    opt_comment = 1,
} PcapngOptionCodesType;

typedef enum {
    shb_hardware = 2,
    shb_os = 3,
    shb_userappl = 4
} PcapngShbOptionCodesType;

typedef enum {
    if_name = 2,
    if_description = 3,
    if_IPv4addr = 4,
    if_IPv6addr = 5,
    if_MACaddr = 6,
    if_EUIaddr = 7,
    if_speed = 8,
    if_tsresol = 9,
    if_tzone = 10,
    if_filter = 11,
    if_os = 12,
    if_fcslen = 13,
    if_tsoffset = 14
} PcapngIfOptionCodesType;

typedef enum {
    epb_flags = 2,
    epb_hash = 3,
    epb_dropcount = 4
} PcapngEpbOptionCodesType;

typedef enum {
    pack_flags = 2,
    pack_hash = 3
} PcapngPackOptionCodesType;

typedef enum {
    sectionHeader =         0x0A0D0D0A,
    interfaceDescription =  0x00000001,
    enhancedPacket =        0x00000006,
    simplePacket =          0x00000003,
    packet =                0x00000002
} PcapngBlockTypesType;