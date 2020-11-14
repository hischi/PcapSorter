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

enum LogLevelType {
    LL_ERROR = 0,
    LL_WARNING = 1,
    LL_INFO = 2,
    LL_DEBUG = 3
};

class Logger
{
private:
    int packetNumber;
    PcapPacketHeaderType *pcapHeader;
    uint64_t initialTime;
    uint32_t loggerNumber;

public:
    Logger(void);
    Logger(uint32_t loggerNumber);
    virtual ~Logger(void);

    void SetReference(int packetNumber, PcapPacketHeaderType *pcapHeader);
    void Log(LogLevelType logLevel, const char *msg);
    void Log(LogLevelType logLevel, char *msg, const char* str);
    void Log(LogLevelType logLevel, char *msg, int value);
    void Log(LogLevelType logLevel, char *msg, int value, char* unit);
    
    void PrintLogLevel(LogLevelType logLevel);

    static bool InitLoggingSystem();
    static bool DeinitLoggingSystem();
    static Logger& GetLogger();
    static void SetLogLevel(LogLevelType logLevel);

private:
    void LogHeader(LogLevelType logLevel);
    
};

