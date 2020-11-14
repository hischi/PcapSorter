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

#include "JobList.h"
#include "Logger.h"
#include <windows.h>
#include <tchar.h>

JobList singleton;

JobList::JobList()
{
    mutex = CreateMutex(
        NULL,              // default security attributes
        FALSE,             // initially not owned
        NULL);             // unnamed mutex

    if (mutex == NULL)
    {
        Logger::GetLogger().Log(LL_ERROR, "CreateMutex error : ", GetLastError());
    }
}

JobList::~JobList()
{
    if (mutex != NULL) {
        CloseHandle(mutex);
        mutex = NULL;
    }
}

JobList& JobList::GetJobList()
{
    return singleton;
}

bool JobList::PushSortJob(SortJob* job)
{
    DWORD   dwWaitResult = WaitForSingleObject(
            mutex,      // handle to mutex
            INFINITE);  // no time-out interval

    switch (dwWaitResult)
    {
        // The thread got ownership of the mutex
    case WAIT_OBJECT_0:
        __try {
            Logger::GetLogger().Log(LL_DEBUG, "Got mutex for job-list");
            jobList.push_back(job);
        }

        __finally {
            // Release ownership of the mutex object
            if (!ReleaseMutex(mutex))
            {
                Logger::GetLogger().Log(LL_ERROR, "Release of job-list mutex failed: ", GetLastError());
                return false;
            }
        }
        break;

        // The thread got ownership of an abandoned mutex
        // The database is in an indeterminate state
    case WAIT_ABANDONED:
        Logger::GetLogger().Log(LL_ERROR, "Wait for job-list mutex failed: ", GetLastError());
        return false;
    }

    return true;
}

SortJob* JobList::PopSortJob()
{
    SortJob* nextJob = nullptr;

    DWORD   dwWaitResult = WaitForSingleObject(
        mutex,      // handle to mutex
        INFINITE);  // no time-out interval

    switch (dwWaitResult)
    {
        // The thread got ownership of the mutex
    case WAIT_OBJECT_0:
        __try {
            Logger::GetLogger().Log(LL_DEBUG, "Got mutex for job-list");
            if (!jobList.empty()) {
                nextJob = jobList.back();
                jobList.pop_back();
            }
        }

        __finally {
            // Release ownership of the mutex object
            if (!ReleaseMutex(mutex))
            {
                Logger::GetLogger().Log(LL_ERROR, "Release of job-list mutex failed: ", GetLastError());
            }
        }
        break;

        // The thread got ownership of an abandoned mutex
        // The database is in an indeterminate state
    case WAIT_ABANDONED:
        Logger::GetLogger().Log(LL_ERROR, "Wait for job-list mutex failed: ", GetLastError());
    }

    return nextJob;
}
