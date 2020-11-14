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

#include "SortJob.h"
#include "Logger.h"
#include "PcapReader.h"
#include "PcapWriter.h"
#include <list>


struct PcapPacketHdrData {
    PcapPacketHeaderType hdr;
    uint8_t* data;
};

bool str_ends_with(const char* str, const char* suffix) {

    if (str == NULL || suffix == NULL)
        return false;

    size_t str_len = strlen(str);
    size_t suffix_len = strlen(suffix);

    if (suffix_len > str_len)
        return false;

    return (0 == _strnicmp(str + str_len - suffix_len, suffix, suffix_len));
}

void SortJob::CreateJob(string inputFile, string outputFile, size_t sortWindowSize, bool dryRun)
{
    this->inputFile = inputFile;
    this->outputFile = outputFile;
    this->sortWindowSize = sortWindowSize;
    this->dryRun = dryRun;

    Logger::GetLogger().Log(LL_INFO, (string("Job created with input-file: ") + this->inputFile + string(" output-file: ") + outputFile).c_str());
}

bool SortJob::ExecuteJob()
{
    // Locals for the PCAP interface
    PcapReader* pcapReader;
    PcapWriter pcapWriter;
    int32_t packetNumber;
    PcapPacketHdrData newPacket;

    // Locals for sorter
    std::list<PcapPacketHdrData> sortWindow;

    Logger::GetLogger().Log(LL_INFO, "Start sorting file ", inputFile.c_str());

    Logger::GetLogger().Log(LL_DEBUG, "Now let's open the input file...");
    pcapReader = new PcapReader();

    if (pcapReader->Open(inputFile.c_str()) == 0) {
        Logger::GetLogger().Log(LL_DEBUG, "Great. Your input file is ready to use.");
    }
    else {
        Logger::GetLogger().Log(LL_ERROR, "I was not able to open the input PCAP file. Check the path and access rights.");
        delete(pcapReader);
        return false;
    }

    if (!dryRun) {
        Logger::GetLogger().Log(LL_DEBUG, "Now let's open the output file...");

        if (pcapWriter.Open(outputFile.c_str()) == 0) {
            Logger::GetLogger().Log(LL_DEBUG, "Great. Your output file is ready to use.");
        }
        else {
            Logger::GetLogger().Log(LL_ERROR, "I was not able to open the output PCAP file. Check the path and access rights.");
            delete(pcapReader);
            return false;
        }
    }

    newPacket.data = new uint8_t[pcapReader->MaxSnapLength()];

    pcapWriter.SetSwapByteOrder(pcapReader->IsSwapedbyteOrder());
    if (!dryRun) {
        pcapWriter.WritePcapHeader(pcapReader->GetPcapHeader()); // Copy paste the pcap header
    }

    Logger::GetLogger().Log(LL_DEBUG, "Read all the packets in the given PCAP:");
    cout << flush;


    while ((packetNumber = pcapReader->ReadPacket(&newPacket.hdr, newPacket.data)) > 0) {

        std::list< PcapPacketHdrData>::iterator it;
        for (it = sortWindow.begin(); it != sortWindow.end(); ++it) {
            if ((it->hdr.timestampSeconds < newPacket.hdr.timestampSeconds) || ((it->hdr.timestampSeconds == newPacket.hdr.timestampSeconds) && (it->hdr.timestampMicroSeconds <= newPacket.hdr.timestampMicroSeconds)))
                break;
        }
        sortWindow.insert(it, newPacket);
        newPacket.data = new uint8_t[pcapReader->MaxSnapLength()];

        if (sortWindow.size() >= sortWindowSize && !dryRun) {
            PcapPacketHdrData oldestPacket = sortWindow.back();

            pcapWriter.WritePacketHeader(&oldestPacket.hdr);
            pcapWriter.WriteData(oldestPacket.data, oldestPacket.hdr.packetLength);
            delete[](oldestPacket.data);
            sortWindow.pop_back();
        }

    }
    Logger::GetLogger().SetReference(0, nullptr);

    Logger::GetLogger().Log(LL_DEBUG, "Everything was read from the PCAP. Empty buffers and finish output file.");
    while(!sortWindow.empty() && !dryRun) {
        PcapPacketHdrData oldestPacket = sortWindow.back();

        pcapWriter.WritePacketHeader(&oldestPacket.hdr);
        pcapWriter.WriteData(oldestPacket.data, oldestPacket.hdr.packetLength);
        delete[](oldestPacket.data);
        sortWindow.pop_back();
    }

    Logger::GetLogger().Log(LL_DEBUG, "Everything was writen to the output file. Close files and clean up the magic stuff.");
    if (!dryRun) {
        pcapWriter.Close();
    }
    pcapReader->Close();
    delete(pcapReader);

    delete[](newPacket.data);

    Logger::GetLogger().Log(LL_INFO, "Finished sorting file ", inputFile.c_str());
    return true;
}
