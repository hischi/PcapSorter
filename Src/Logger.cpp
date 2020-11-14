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

#include "Logger.h"
#include <iostream>
#include <iomanip>
#include <map>
#include <string>
#include <Windows.h>

using namespace std;

map<unsigned int, Logger*> loggers;
HANDLE mutex = NULL;
LogLevelType globalLogLevel;

void waitForMutex() {
    DWORD   dwWaitResult = WaitForSingleObject(
        mutex,      // handle to mutex
        INFINITE);  // no time-out interval

    switch (dwWaitResult)
    {
        // The thread got ownership of the mutex
    case WAIT_OBJECT_0:
        break;

        // The thread got ownership of an abandoned mutex
        // The database is in an indeterminate state
    case WAIT_ABANDONED:
        cout << "[FATAL]   Wait for logging-mutex failed: " << GetLastError() << endl;
    }
}

void releaseMutex() {
    if (!ReleaseMutex(mutex))
    {
        cout << "[FATAL]   Release of logging-mutex failed: " << GetLastError() << endl;
    }
}

Logger::Logger(void)
{
    this->loggerNumber = 0;
    this->pcapHeader = nullptr;
    this->packetNumber = 0;
    this->initialTime = 0;
}

Logger::Logger(uint32_t loggerNumber)
{
    this->loggerNumber = loggerNumber;
    this->pcapHeader = nullptr;
    this->packetNumber = 0;
    this->initialTime = 0;
}


Logger::~Logger(void)
{
}

void Logger::SetReference(int packetNumber, PcapPacketHeaderType *pcapHeader) {
    if (packetNumber == 1 && pcapHeader != nullptr) {
       initialTime = ((uint64_t)pcapHeader->timestampSeconds) * 1000000 + pcapHeader->timestampMicroSeconds;
    }
    this->packetNumber = packetNumber;
    this->pcapHeader = pcapHeader;
}

Logger& Logger::GetLogger()
{
    if(loggers.count(GetCurrentThreadId()) == 0) {
        waitForMutex();
        loggers[GetCurrentThreadId()] = new Logger(loggers.size());
        releaseMutex();
    }
    return *loggers[GetCurrentThreadId()];
}

void Logger::LogHeader(LogLevelType logLevel) {
    cout << endl;

    if (loggerNumber == 0) {
        cout << "[MAIN] ";
    }
    else {
        cout << "[JOB" << loggerNumber << "] ";
    }

    PrintLogLevel(logLevel);

    if (packetNumber > 0) {
        cout << "#" << setfill('0') << setw(10) << packetNumber << ": ";
    }

    if (pcapHeader) {
        uint64_t time = ((uint64_t)pcapHeader->timestampSeconds) * 1000000 + pcapHeader->timestampMicroSeconds;
        time = time - initialTime;

        cout << setfill(' ') << setw(10) << ((uint32_t)(time / 1000000)) << "," << setfill('0') << setw(6) << ((uint32_t)(time % 1000000)) << " s | " << setfill(' ') << setw(6) << pcapHeader->packetLength << " Byte | ";
    }
}

void Logger::Log(LogLevelType logLevel, const char* msg)
{
    if (logLevel <= globalLogLevel) {
        waitForMutex();
        {
            LogHeader(logLevel);
            cout << msg;
        }
        releaseMutex();
    }
}

void Logger::Log(LogLevelType logLevel, char * msg, const char * str)
{
    if (logLevel <= globalLogLevel) {
        waitForMutex();
        {
            LogHeader(logLevel);
            cout << msg;
            cout << str;
        }
        releaseMutex();
    }
}

void Logger::Log(LogLevelType logLevel, char *msg, int value) {
    if (logLevel <= globalLogLevel) {
        waitForMutex();
        {
            LogHeader(logLevel);
            cout << msg;
            cout << value;
        }
        releaseMutex();
    }
}

void Logger::Log(LogLevelType logLevel, char *msg, int value, char* unit) {
    if (logLevel <= globalLogLevel) {
        waitForMutex();
        {
            LogHeader(logLevel);
            cout << msg;
            cout << value;
            cout << unit;
        }
        releaseMutex();
    }
}

void Logger::SetLogLevel(LogLevelType logLevel) {
    globalLogLevel = logLevel;
}

void Logger::PrintLogLevel(LogLevelType logLevel) {
    switch(logLevel) {
    case LL_ERROR:
        cout << "[ERROR]   ";
        break;
    case LL_WARNING:
        cout << "[WARNING] ";
        break;
    case LL_INFO:
        cout << "[INFO]    ";
        break;
    case LL_DEBUG:
        cout << "[DEBUG]   ";
        break;
    default:
        cout << "          "; 
    }
}

bool Logger::InitLoggingSystem() {
    if (mutex == NULL) {
        mutex = CreateMutex(
            NULL,              // default security attributes
            FALSE,             // initially not owned
            NULL);             // unnamed mutex

        if (mutex == NULL)
        {
            cout << "[FATAL]   Can't create mutex " << endl;
            return false;
        }
    }

    globalLogLevel = LL_INFO;

    return true;
}

bool Logger::DeinitLoggingSystem() {
    if (mutex != NULL) {
        CloseHandle(mutex);
        mutex = NULL;
    }
    return true;
}