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

#include <filesystem>
#include <iostream>
#include <iomanip>
#include "Logger.h"
#include "Thread.h"
#include "JobList.h"

using namespace std;
namespace fs = std::filesystem;

static const unsigned int MaxThreadNumber = 4;
static const unsigned int DefaultThreadNumber = 2;

void printHelpAndWait() {
    cout << endl;
    cout << "Usage: " << endl;
    cout << "PcapSorter.exe -i INPUT_PCAP -o OUTPUT_PCAP -s SORT_WINDOW [-l LOG_LEVEL] [-d] [-j JOBCOUNT]" << endl;
    cout << "----------------------------------------------------------------------------------------------------------------" << endl;
    cout << "  INPUT_PCAP:  path and name to the input PCAP or PCAPNG file or directory.\n" << endl;
    cout << "  OUTPUT_PCAP: path and name to the output PCAP or directory.\n" << endl;
    cout << "  SORT_WINDOW: number of packets which are compared for the sort (neglectable effect on runtime, only on RAM usage). Example: 5000.\n" << endl;

    //cout << "  OUTPUT_H264: path and name to the output h264 file." << endl;

    cout << "  LOG_LEVEL:   optional log level as integer:" << endl;
    cout << "               * 0: ERROR" << endl;
    cout << "               * 1: WARNING" << endl;
    cout << "               * 2: INFO (default)" << endl;
    cout << "               * 3: DEBUG (makes the magic quite slow)\n" << endl;

    cout << "  -d:          execute in DRY mode i.e. nothing will be written\n" << endl;

    cout << "  JOBCOUNT:    Number of conversion jobs which shall be done in parallel (max. " << MaxThreadNumber << ", default " << DefaultThreadNumber << ")" << endl;

    cout << endl;
    cout << "Press any key and then enter to end program..." << endl;
    
    char anyKey;
    cin >> anyKey;
}

int main(int argc, char* argv[])
{
    // Locals for multi-threading
    Thread* threads[MaxThreadNumber];
    unsigned int jobCount = DefaultThreadNumber;

    cout << "********************************************" << endl;
    cout << "* PcapSorter.exe by Florian Hisch          *" << endl;
    cout << "* Copyright (C) 2020                       *" << endl;
    cout << "*                                          *" << endl;
    cout << "* Version: 1.0                             *" << endl;
    cout << "* Date:    2020-11-14                      *" << endl;
    cout << "*                                          *" << endl;
    cout << "*         This program comes with          *" << endl;
    cout << "*         ABSOLUTELY NO WARRANTY           *" << endl;
    cout << "*         Use with special care!           *" << endl;
    cout << "********************************************" << endl;
    cout << endl << flush;

    Logger::InitLoggingSystem();
    Logger::SetLogLevel(LL_INFO);    

    Logger::GetLogger().Log(LL_INFO, "A warm welcome to my dear user!");
    Logger::GetLogger().Log(LL_INFO, "Let's start by checking your parameters:");

    // Search for input file name
    Logger::GetLogger().Log(LL_INFO, " * Checking input file... ");
    int inputFile = -1;
    for(int i = 0; i < argc-1; i++) {
        if(strcmp(argv[i], "-i") == 0) {
            inputFile = i+1;
            break;
        }
    }

    if(inputFile > 0) {
        cout << "ok. You specified input file: " << argv[inputFile];
    } else {
        cout << "not ok. Can't find input file argument. Please specify a valid input PCAP file.";
        printHelpAndWait();
        return 1;
    }

    // Search for output file name
    Logger::GetLogger().Log(LL_INFO, " * Checking output file... ");
    int outputFile = -1;
    for(int i = 0; i < argc-1; i++) {
        if(strcmp(argv[i], "-o") == 0) {
            outputFile = i+1;
            break;
        }
    }

    if(outputFile > 0) {
        cout << "ok. You specified output file: " << argv[outputFile];
    } else {
        cout << "not ok. Can't find output file argument. Please specify a valid output path.";
        printHelpAndWait();
        return 1;
    }

    Logger::GetLogger().Log(LL_INFO, " * Checking optional DRY-run argument... ");
    int sortWindowArg = -1;
    int sortWindowSize = 0;
    for (int i = 0; i < argc; i++) {
        if (strcmp(argv[i], "-s") == 0) {
            sortWindowArg = i+1;
            break;
        }
    }

    if (sortWindowArg > 0) {
        sortWindowSize = atoi(argv[sortWindowArg]);
        if (sortWindowSize <= 0) {
            cout << "not ok. You specified an invalid sort window size: " << argv[sortWindowArg];
            printHelpAndWait();
            return 1;
        }
        else {
            cout << "ok. You specified a sort window size of: " << sortWindowSize;
        }
    }
    else {
        cout << "not ok. Can't find sort-window argument. Please specify a valid sort-window.";
        printHelpAndWait();
        return 1;
    }

    Logger::GetLogger().Log(LL_INFO, " * Checking optional DRY-run argument... ");
    bool dryRun = false;
    for (int i = 0; i < argc; i++) {
        if (strcmp(argv[i], "-d") == 0) {
            dryRun = true;
            break;
        }
    }

    if (dryRun) {
        cout << "ok. This will be a DRY-run. No output files will be written ";
    }
    else {
        cout << "ok. This will be a NORMAL-run. All output files will be written ";
    }

    Logger::GetLogger().Log(LL_INFO, " * Checking optional JOBCOUNT argument... ");
    int jobCountArg = -1;
    for (int i = 0; i < argc-1; i++) {
        if (strcmp(argv[i], "-j") == 0) {
            jobCountArg = i+1;
            break;
        }
    }

    if (jobCountArg > 0) {
        jobCount = atoi(argv[jobCountArg]);
        if (jobCount > 0 && jobCount <= MaxThreadNumber) {
            cout << "ok. You specified " << jobCount << " jobs to run in parallel";
        }
        else {
            cout << "not ok. You specified an invalid or out of range number of jobs";
            printHelpAndWait();
            return 1;
        }

    }
    else {
        cout << "ok. You seem to like the default job-count of " << jobCount;
    }


	Logger::GetLogger().Log(LL_INFO, " * Checking optional log-level argument... ");
    int logArgument = -1;
    for(int i = 0; i < argc-1; i++) {
        if(strcmp(argv[i], "-l") == 0) {
            logArgument = i+1;
            break;
        }
    }    

    if(logArgument > 0) {
        cout << "ok. You specified log-level " << argv[logArgument] << " ";
        LogLevelType logLevel = (LogLevelType) atoi(argv[logArgument]);
        
        Logger::GetLogger().PrintLogLevel(logLevel);
        if(logLevel < LL_INFO) {
            Logger::GetLogger().Log(LL_INFO, "You don't want to see any further INFO messages from me.");
            Logger::GetLogger().Log(LL_INFO, "I hope there are no ERRORs or WARNINGs. So see you at the end again. Doing some magic now!");
        }
        Logger::SetLogLevel(logLevel);
    } else {
        cout << "ok. You seem to like the default log-level " << ((int) LL_INFO) << " [INFO]";
    }
	
    Logger::GetLogger().Log(LL_INFO, "Your arguments are all valid.\n");
    cout << flush;

    

    Logger::GetLogger().Log(LL_INFO, "Prepare jobs...");
    if (fs::is_directory(argv[inputFile]) && fs::is_directory(argv[outputFile])) {

        if (!fs::exists(argv[outputFile] + string("/sorted/"))) {
            fs::create_directory(argv[outputFile] + string("/sorted/"));
            Logger::GetLogger().Log(LL_INFO, "Output directory created: ", (argv[outputFile] + string("/sorted/")).c_str());
        }

        for (auto& p : fs::directory_iterator(argv[inputFile])) {
            string extension_string = p.path().extension().generic_string();
            string filename = p.path().filename().generic_string();
            filename = filename.substr(0, filename.length() - extension_string.length());
            const char* ext = extension_string.c_str();
            if (p.is_regular_file() && ((_stricmp(ext, ".pcap") == 0) || (_stricmp(ext, ".pcapng") == 0))) {
                SortJob* job = new SortJob();
                job->CreateJob(p.path().generic_string(), argv[outputFile] + string("/sorted/") + filename + string(".pcap"), sortWindowSize, dryRun);
                JobList::GetJobList().PushSortJob(job);
            }
        }
    }
    else if(!fs::is_directory(argv[inputFile]) && !fs::is_directory(argv[outputFile])){
        SortJob* job = new SortJob();
        job->CreateJob(argv[inputFile], argv[outputFile], sortWindowSize, dryRun);
        JobList::GetJobList().PushSortJob(job);
    }
    else {
        Logger::GetLogger().Log(LL_ERROR, "Can't create jobs. Your input and output paths must specified either both files or directories.");
        printHelpAndWait();
        return 1;
    } 
    Logger::GetLogger().Log(LL_INFO, "Jobs created.\n");

    for (unsigned int i = 0; i < jobCount; i++) {
        threads[i] = new Thread();
        threads[i]->Create();
    }
    Logger::GetLogger().Log(LL_INFO, "All job-executers have been started. Wait for them to finish...");

    for (unsigned int i = 0; i < jobCount; i++) {
        threads[i]->Remove();
        delete(threads[i]);
        threads[i] = 0;
    }
    Logger::GetLogger().Log(LL_INFO, "All jobs have finished\n");
    
    Logger::GetLogger().SetLogLevel(LL_INFO);    
    Logger::GetLogger().Log(LL_INFO, "That was everything I can do for you. I hope you enjoyed the magic.");
    cout << endl;

    Logger::DeinitLoggingSystem();

	return 0;

}

