
//<Copyright Information>
//
//Usage of the works is permitted provided that this instrument is retained with the works, so that any entity that uses the works is notified of this instrument.
//
//DISCLAIMER: THE WORKS ARE WITHOUT WARRANTY.

#define _CRT_SECURE_NO_WARNINGS
#define HAVE_REMOTE
#include "pcap.h"
#include <fstream>
#include <iostream>
#include <vector>
#include <sstream>

#define MAC_ALEN 6  // mac address: xx:xx:xx:xx:xx:xx;;
#define PROTO_ALEN 1  // protocol: xxxx;
#define PACKET_DATA 6000  // xx... it would be more or less;
#define BF_VALID "0123456789abcdefABCDEF"  // filter Hex only

/* If we find the Npcap driver, allow Nmap to load Npcap DLLs from the "\System32\Npcap" directory. */
static void init_npcap_dll_path()
{
// This function is from https://github.com/nmap/nmap/blob/master/mswin32/winfix.cc
/***************************************************************************
 * winfix.cc -- A few trivial windows-compatibility-related functions that *
 * are specific to Nmap.  Most of this has been moved into nbase so it can *
 * be shared.                                                              *
 *                                                                         *
 ***********************IMPORTANT NMAP LICENSE TERMS************************
 *                                                                         *
 * The Nmap Security Scanner is (C) 1996-2020 Insecure.Com LLC ("The Nmap  *
 * Project"). Nmap is also a registered trademark of the Nmap Project.     *
 *                                                                         *
 * This program is distributed under the terms of the Nmap Public Source   *
 * License (NPSL). The exact license text applying to a particular Nmap    *
 * release or source code control revision is contained in the LICENSE     *
 * file distributed with that version of Nmap or source code control       *
 * revision. More Nmap copyright/legal information is available from       *
 * https://nmap.org/book/man-legal.html, and further information on the    *
 * NPSL license itself can be found at https://nmap.org/npsl. This header  *
 * summarizes some key points from the Nmap license, but is no substitute  *
 * for the actual license text.                                            *
 *                                                                         *
 * Nmap is generally free for end users to download and use themselves,    *
 * including commercial use. It is available from https://nmap.org.        *
 *                                                                         *
 * The Nmap license generally prohibits companies from using and           *
 * redistributing Nmap in commercial products, but we sell a special Nmap  *
 * OEM Edition with a more permissive license and special features for     *
 * this purpose. See https://nmap.org/oem                                  *
 *                                                                         *
 * If you have received a written Nmap license agreement or contract       *
 * stating terms other than these (such as an Nmap OEM license), you may   *
 * choose to use and redistribute Nmap under those terms instead.          *
 *                                                                         *
 * The official Nmap Windows builds include the Npcap software             *
 * (https://npcap.org) for packet capture and transmission. It is under    *
 * separate license terms which forbid redistribution without special      *
 * permission. So the official Nmap Windows builds may not be              *
 * redistributed without special permission (such as an Nmap OEM           *
 * license).                                                               *
 *                                                                         *
 * Source is provided to this software because we believe users have a     *
 * right to know exactly what a program is going to do before they run it. *
 * This also allows you to audit the software for security holes.          *
 *                                                                         *
 * Source code also allows you to port Nmap to new platforms, fix bugs,    *
 * and add new features.  You are highly encouraged to submit your         *
 * changes as a Github PR or by email to the dev@nmap.org mailing list     *
 * for possible incorporation into the main distribution. Unless you       *
 * specify otherwise, it is understood that you are offering us very       *
 * broad rights to use your submissions as described in the Nmap Public    *
 * Source License Contributor Agreement. This is important because we      *
 * fund the project by selling licenses with various terms, and also       *
 * because the inability to relicense code has caused devastating          *
 * problems for other Free Software projects (such as KDE and NASM).       *
 *                                                                         *
 * The free version of Nmap is distributed in the hope that it will be     *
 * useful, but WITHOUT ANY WARRANTY; without even the implied warranty of  *
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. Warranties,        *
 * indemnification and commercial support are all available through the    *
 * Npcap OEM program--see https://nmap.org/oem.                            *
 *                                                                         *
 ***************************************************************************/
    BOOL(WINAPI * SetDllDirectory)(LPCTSTR);
    char sysdir_name[512];
    int len;

    SetDllDirectory = (BOOL(WINAPI*)(LPCTSTR)) GetProcAddress(GetModuleHandle("kernel32.dll"), "SetDllDirectoryA");
    if (SetDllDirectory == NULL) {
        printf("Error in SetDllDirectory");
    }
    else {
        len = GetSystemDirectory(sysdir_name, 480);	//	be safe
        if (!len)
            printf("Error in GetSystemDirectory");
        strcat(sysdir_name, "\\Npcap");
        if (SetDllDirectory(sysdir_name) == 0)
            printf("Error in SetDllDirectory(\"System32\\Npcap\")");
    }
}

const char* timeNow() {
    SYSTEMTIME st, lt;
    GetSystemTime(&st);
    char currentTime[84] = "";
    sprintf(currentTime, "%d-%d-%d %d:%d:%d:%d", st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond, st.wMilliseconds);
    return currentTime;
}

int main(int argc, char* argv[])
{
    /* use npcap if possible */
    init_npcap_dll_path();

    pcap_if_t* alldevs;
    pcap_if_t* d;
    int inum;  // interface index
    int i = 0;
    int j = 14;
    int isize;   // a packet data size
    unsigned int mac_part[MAC_ALEN];  // mac address
    int mlen = -1;
    unsigned int proto_part[PROTO_ALEN];  // protocol
    int plen = -1;
    unsigned char packet[PACKET_DATA];  // packet MAX size
    pcap_t* adhandle;
    char errbuf[PCAP_ERRBUF_SIZE];
    
    /* Retrieve the device list on the local machine */
    if (pcap_findalldevs_ex((char*)PCAP_SRC_IF_STRING, NULL, &alldevs, errbuf) == -1)
    {
        fprintf(stderr, "Error in pcap_findalldevs: %s\n", errbuf);
        exit(1);
    }

    /* for CLI one shot, one packet */
    if (argc != 2)
    {
        int ifid = NULL;
        /* set interface index */
        if (argv[1])
        {
            ifid =atoi( argv[1] );
            //std::cout << argv[1] << std::endl;
        }
        /* send a packet */
        if (ifid != NULL && argv[2])
        {
            const char *fn = argv[2]; //filename
            std::ifstream infile(fn, std::fstream::in);
            std::stringstream buffer;
            buffer << infile.rdbuf();
            FILE* pfile;
            fopen_s(&pfile, fn, "r");
            if (pfile == NULL)
            {
                std::cout << "Somethign at Hex stream dump file:" << pfile << std::endl;
                exit(1);
            }
            /* set interface to extid */
            for (d = alldevs, i = 0; i < ifid -1; d = d->next, i++);
            if ((adhandle = pcap_open_live(d->name,   // name of the device
                buffer.str().length()/2,              // HEX stream chr length   
                PCAP_OPENFLAG_PROMISCUOUS,            // promiscuous mode
                1000,                                 // read timeout
                errbuf                                // error buffer
            )) == NULL)
            {
                fprintf(stderr, "\nUnable to open the adapter. %s is not supported by WinPcap\n", d->name);
                /* Free the device list */
                pcap_freealldevs(alldevs);
                return -1;
            }

            /* At this point, we don't need any more the device list. Free it */
            pcap_freealldevs(alldevs);

            // read file as dump
            int blen;
            char buf[PACKET_DATA];
            unsigned int n = 0;
            blen = buffer.str().length();
            char c;
            int x;
            if (infile.is_open())
            {
                while((c = fgetc(pfile)) != EOF)
                {
                    if (strchr(BF_VALID, c))
                        buf[n++] = c;
                        //printf("buf:%c\n", c);
                        //printf("n:%d\n", n);
                }
            }
            unsigned int m = 0;
            for (int i = 0; i < (blen-1); i+=2)
            {
                std::string s = std::string{ buf[i] } + std::string{ buf[i + 1] };
                char a[2] = { buf[i], buf[i+1] };
                //printf("p string:%s\n", s.c_str());
                sscanf(a, "%X", &x);
                packet[m] = x;
                //printf("packet 0x%x\n", packet[m]);
                m++;
                //printf("i:%d\n", i);
            }
            printf("\ninject packet: %s at %s\n", pcap_sendpacket(adhandle, packet, buffer.str().length()/2) == 0 ? "success" : "failed", timeNow());
            return 0;
        }
    }

    /* Print the list */
    for (d = alldevs; d; d = d->next)
    {
        printf("%d. %s", ++i, d->name);
        if (d->description)
            printf(" (%s)\n", d->description);
        else
            printf(" (No description available)\n");
    }

    if (i == 0)
    {
        printf("\nNo interfaces found! Make sure WinPcap is installed.\n");
        return -1;
    }

    printf("Enter the interface number (1-%d):", i);
    scanf_s("%d", &inum);
    if (inum < 1 || inum > i)
    {
        printf("\nInterface number out of range.\n");
        /* Free the device list */
        pcap_freealldevs(alldevs);
        return -1;
    }
    ///* Jump to the selected adapter */
    for (d = alldevs, i = 0; i < inum - 1; d = d->next, i++);

    
    /* Ask data size */
    printf("Enter the packet size in (14-%d):", 65522);  // can be more
    scanf_s("%d", &isize);
    if (isize < 14 || isize > 65522)
    {
        printf("\nData size out of range.\n");
        /* Free the device list */
        pcap_freealldevs(alldevs);
        return -1;
    }

    /* Ask destination */
    printf("Enter the destination mac address as xx:xx:..:");
    //scanf_s("%s", mac);
    if (scanf_s("%x:%x:%x:%x:%x:%x%n", mac_part + 0, mac_part + 1, mac_part + 2, mac_part + 3, mac_part + 4, mac_part + 5, &mlen) < 6 || mlen < 11)
    {
        printf("\nMAC address out of format.\n");
        pcap_freealldevs(alldevs);  // Free the device list
        return -1;
    }
    if (mac_part[0] > 255U || mac_part[1] > 255U || mac_part[2] > 255U ||
        mac_part[3] > 255U || mac_part[4] > 255U || mac_part[5] > 255U)
    {
        printf("\nMAC address out of FF.\n");
        pcap_freealldevs(alldevs);  // Free the device list
        return -1;
    }
    //printf("Dst is %x:%x\n", mac_part[0], mac_part[1]);
    // Dst MAC
    packet[0] = mac_part[0];  // 0x01;
    packet[1] = mac_part[1];  // 0xa0;
    //std::cout << packet[1] << std::endl;
    packet[2] = mac_part[2];  // 0xf8;
    packet[3] = mac_part[3];  // 0x00;
    packet[4] = mac_part[4];  // 0x00;
    packet[5] = mac_part[5];  // 0x00;

    // Src MAC, current fixed
    packet[6] = 0x12;
    packet[7] = 0x34;
    packet[8] = 0x56;
    packet[9] = 0x78;
    packet[10] = 0x9a;
    packet[11] = 0xbc;

    /* Ask protocol */
    printf("Enter the protocol for the packet by HEX 0x0001 without 0x:");
    if (scanf_s("%x%n", proto_part + 0, &plen) < 1 || plen < 2)
    {
        printf("\nProtocol out of format.\n");
        pcap_freealldevs(alldevs);  // Free the device list
        return -1;
    }
    if (proto_part[0] > 65535U)
    {
        printf("\nMalformed protocol.\n");
        pcap_freealldevs(alldevs);  // Free the device list
        return -1;
    }
    //printf("Protocol is 0x%x", proto_part[0]);
    packet[12] = (proto_part[0] >> 8) & 0xff;
    packet[13] = proto_part[0] & 0xff;

    /* Open the device */
    //if ((adhandle = pcap_open(d->name,          // name of the device
    //                          1400,            
    //                          PCAP_OPENFLAG_PROMISCUOUS,    // promiscuous mode
    //                          1000,             // read timeout
    //                          NULL,             // authentication on the remote machine
    //                          errbuf            // error buffer
    //                          )) == NULL)
    // Seems pcap_open_live can handle even jumbo packet (not yet test)
    if ((adhandle = pcap_open_live(d->name,          // name of the device
                                   isize,
                                   PCAP_OPENFLAG_PROMISCUOUS,    // promiscuous mode
                                   1000,             // read timeout
                                   errbuf            // error buffer
                                   )) == NULL)
    {
        fprintf(stderr, "\nUnable to open the adapter. %s is not supported by WinPcap\n", d->name);
        /* Free the device list */
        pcap_freealldevs(alldevs);
        return -1;
    }

    /* At this point, we don't need any more the device list. Free it */
    pcap_freealldevs(alldevs);

    // others
    for (j; j < isize/2; j++)
    {
        packet[j] = 1;
    }

    printf("\ninject packet: %s at %s\n", pcap_sendpacket(adhandle, packet, isize) == 0 ? "success" : "failed", timeNow());
    return 0;
}