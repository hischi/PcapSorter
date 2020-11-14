# PcapSorter
Sorts PCAP files based on capture time

Usage:
PcapSorter.exe -i INPUT_PCAP -o OUTPUT_PCAP -s SORT_WINDOW [-l LOG_LEVEL] [-d] [-j JOBCOUNT]
----------------------------------------------------------------------------------------------------------------
  INPUT_PCAP:  path and name to the input PCAP or PCAPNG file or directory.

  OUTPUT_PCAP: path and name to the output PCAP or directory.

  SORT_WINDOW: number of packets which are compared for the sort (neglectable effect on runtime, only on RAM usage). Example: 5000.

  LOG_LEVEL:   optional log level as integer:
               * 0: ERROR
               * 1: WARNING
               * 2: INFO (default)
               * 3: DEBUG (makes the magic quite slow)

  -d:          execute in DRY mode i.e. nothing will be written

  JOBCOUNT:    Number of conversion jobs which shall be done in parallel (max. 4, default 2)