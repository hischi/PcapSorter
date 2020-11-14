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

#include "Thread.h"
#include "Logger.h"
#include "JobList.h"
#include <windows.h>
#include <tchar.h>

DWORD WINAPI ThreadFunction(LPVOID lpParam);

Thread::Thread()
{
    handle = nullptr;
}

Thread::~Thread()
{
}

bool Thread::Create()
{
    handle = (void*) CreateThread(
        NULL,                   // default security attributes
        0,                      // use default stack size  
        ThreadFunction,         // thread function name
        this,                   // argument to thread function 
        0,                      // use default creation flags 
        0);                     // returns the thread identifier 


    // Check the return value for success.
    // If CreateThread fails, terminate execution. 
    // This will automatically clean up threads and memory. 

    if (handle == NULL)
    {
        Logger::GetLogger().Log(LL_ERROR, "Failed to create Thread");
        return false;
    }

    return true;
}

bool Thread::Run()
{
    Logger::GetLogger().Log(LL_DEBUG, "Get next job ...");
    SortJob* nextJob = JobList::GetJobList().PopSortJob();
    if (nextJob == nullptr) {
        Logger::GetLogger().Log(LL_DEBUG, "No more jobs available.");
        return false;
    }
    else {
        Logger::GetLogger().Log(LL_DEBUG, "Got a new job.");
        if (nextJob->ExecuteJob()) {
            Logger::GetLogger().Log(LL_DEBUG, "Job executed successfully.");
            return true;
        }
        else {
            Logger::GetLogger().Log(LL_WARNING, "Job executed not successfully.");
            return true;
        }
        delete(nextJob);
    }    
}

bool Thread::Remove()
{
    if (handle == nullptr)
        return false;

    WaitForSingleObject(handle, INFINITE);
    CloseHandle(handle);
    handle = nullptr;
    return true;
}

DWORD WINAPI ThreadFunction(LPVOID lpParam) {
    if (lpParam == NULL) {
        return 1;
    }

    while (((Thread*)lpParam)->Run());

    return 0;
}