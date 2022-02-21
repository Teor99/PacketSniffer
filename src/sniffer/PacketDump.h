/*
 * This file is part of PacketSniffer.
 *
 * PacketSniffer is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.

 * PacketSniffer is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.

 * You should have received a copy of the GNU General Public License
 * along with PacketSniffer.  If not, see <http://www.gnu.org/licenses/>.
 */

#pragma once

#include <ctime>
#include <winsock2.h>
#include <ws2tcpip.h>

// this class encapsulates functions which logging the packets
class PacketDump
{
private:
    boolean isTextLogDumpEnabled = false;
    boolean isBinaryDumpEnabled = false;
    boolean isSocketDumpEnabled = false;

    char textLogDumpFilePath[MAX_PATH] = {0};
    char binaryDumpFilePath[MAX_PATH] = {0};
    char configFilePath[MAX_PATH] = {0};


    char socketHost[MAX_PATH] = {0};
    int socketPort = 0;

    SOCKET dumpSocket = NULL;
    FILE* textLogDumpFile = nullptr;
    FILE* binaryDumpFile = nullptr;


public:
    PacketDump(char *dllDirPath, WORD buildNumber) {
        // gets time/date
        time_t rawTime;
        DWORD now;
        now = (DWORD) time(&rawTime);
        tm* date = localtime(&rawTime);

        // basic file name format:
        // wowsniff_buildNumber_unixTimeStamp_dateYear_dateMonth_dateDay_dateHour_dateMinute_dateSecond.[log/bin]
        char fileNameTemplate[64];
        // the "user friendly" file, .log
        char fileNameText[64];
        // the binary file, .bin
        char fileNameBinary[64];

        // fills the basic file name format
        _snprintf(fileNameTemplate,
                  sizeof(fileNameTemplate),
                  "wowsniff_%hu_%u_%d-%02d-%02d_%02d-%02d-%02d",
                  buildNumber,
                  now,
                  date->tm_year + 1900,
                  date->tm_mon + 1,
                  date->tm_mday,
                  date->tm_hour,
                  date->tm_min,
                  date->tm_sec);

        // fills the specific file names
        _snprintf(fileNameText, sizeof(fileNameText), "%s.log", fileNameTemplate);
        _snprintf(fileNameBinary, sizeof(fileNameBinary), "%s.bin", fileNameTemplate);

        // simply appends the file names to the DLL's location
        _snprintf(textLogDumpFilePath, sizeof(textLogDumpFilePath), "%s\\%s", dllDirPath, fileNameText);
        _snprintf(binaryDumpFilePath, sizeof(binaryDumpFilePath), "%s\\%s", dllDirPath, fileNameBinary);

        // config path
        _snprintf(configFilePath, sizeof(configFilePath), "%s\\%s", dllDirPath, "config.ini");

        // read config
        isBinaryDumpEnabled = GetPrivateProfileInt("Settings", "enableDumpPacketsToBinaryFile", 0, configFilePath) > 0;
        isTextLogDumpEnabled = GetPrivateProfileInt("Settings", "enableDumpPacketsToTextLogFile", 0, configFilePath) > 0;
        isSocketDumpEnabled = GetPrivateProfileInt("Settings", "enableDumpPacketsToSocket", 0, configFilePath) > 0;
        GetPrivateProfileString("Settings", "socketHost", "127.0.0.1", socketHost, sizeof(socketHost), configFilePath);
        socketPort = GetPrivateProfileInt("Settings", "socketPort", 6666, configFilePath);

        // some info
        if (isBinaryDumpEnabled) {
            printf("Binary dump enabled to file:   %s\n", fileNameBinary);
        } else {
            printf("Binary dump disabled\n");
        }

        if (isTextLogDumpEnabled) {
            printf("Text log dump enabled to file: %s\n", fileNameText);
        } else {
            printf("Text log dump disabled\n");
        }

        if (isSocketDumpEnabled) {
            printf("Socket dump enabled to:        %s:%d\n", socketHost, socketPort);
            initSocket();
        } else {
            printf("Socket dump disabled\n");
        }
    }

    virtual ~PacketDump() {
        if (dumpSocket) {
            destroySocket();
        }

        if (textLogDumpFile) {
            fflush(textLogDumpFile);
            fclose(textLogDumpFile);
        }

        if (binaryDumpFile) {
            fflush(binaryDumpFile);
            fclose(binaryDumpFile);
        }
    }

    enum PacketType
    {
        PACKET_TYPE_C2S = 0, // client to server, CMSG
        PACKET_TYPE_S2C = 1  // server to client, SMSG
    };

    // just this method should be used "globally"
    // basically logs the packets via other private functions
    void dumpPacket(PacketType packetType,
                    DWORD packetOpcode,
                    DWORD packetSize,
                    DWORD buffer,
                    WORD initialReadOffset)
    {
        // gets the time
        time_t rawTime;
        time(&rawTime);

        // dumps the binary format of the packet
        dumpPacketBinary(packetType,
                         packetOpcode,
                         packetSize,
                         buffer,
                         rawTime,
                         initialReadOffset);

        // dumps the "user friendly" format of the packet
        dumpPacketTextLog(packetType,
                          packetOpcode,
                          packetSize,
                          buffer,
                          rawTime,
                          initialReadOffset);

    }

private:

    void initSocket() {
        // Initialize Winsock
        WSADATA wsaData;
        int iResult = WSAStartup(MAKEWORD(2, 2), &wsaData);
        if (iResult != NO_ERROR) {
            printf("WSAStartup function failed with error: %d\n", iResult);
            isSocketDumpEnabled = false;
            return;
        }

        SOCKET newSocket;
        newSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (newSocket == INVALID_SOCKET) {
            printf("socket function failed with error: %d\n", WSAGetLastError());
            WSACleanup();
            isSocketDumpEnabled = false;
            return;
        }

        // The sockaddr_in structure specifies the address family,
        // IP address, and port of the server to be connected to.
        sockaddr_in clientService{};
        clientService.sin_family = AF_INET;
        InetPton(AF_INET, socketHost, &clientService.sin_addr.s_addr);
        clientService.sin_port = htons(socketPort);

        // Connect to server.
        iResult = connect(newSocket, (SOCKADDR*)&clientService, sizeof(clientService));
        if (iResult == SOCKET_ERROR) {
            printf("socket connect function failed with error: %d\n", WSAGetLastError());
            iResult = closesocket(newSocket);
            if (iResult == SOCKET_ERROR)
                printf("closesocket function failed with error: %d\n", WSAGetLastError());
            WSACleanup();
            isSocketDumpEnabled = false;
            return;
        }

        printf("Success connected to server.\n");
        dumpSocket = newSocket;
    }

    void destroySocket() {
        if (dumpSocket)
        {
            int iResult = shutdown(dumpSocket, SD_SEND);
            if (iResult == SOCKET_ERROR) {
                printf("socket shutdown failed: %d\n", WSAGetLastError());
            }

            iResult = closesocket(dumpSocket);
            if (iResult == SOCKET_ERROR) {
                printf("closesocket function failed with error: %d\n", WSAGetLastError());
            }

            WSACleanup();

            dumpSocket = NULL;
        }
    }

    // saves the packet in Trinity's WPP format
    // https://github.com/TrinityCore/WowPacketParser
    void dumpPacketBinary(PacketType packetType, DWORD packetOpcode, DWORD packetSize, DWORD buffer, time_t timestamp, WORD initialReadOffset) {
        if (!isBinaryDumpEnabled) return;

        if (!binaryDumpFile) {
            binaryDumpFile = fopen(binaryDumpFilePath, "wb"); // binary mode

            if (!binaryDumpFile) {
                printf("Cannot open file: %s, error code: %d - %s", binaryDumpFilePath, errno, strerror(errno));
                isBinaryDumpEnabled = false;
                return;
            }
        }

        fwrite(&packetOpcode,       4, 1, binaryDumpFile); // opcode
        fwrite(&packetSize,         4, 1, binaryDumpFile); // size of the packet
        fwrite((DWORD*)&timestamp,  4, 1, binaryDumpFile); // timestamp of the packet
        fwrite((BYTE*)&packetType,  1, 1, binaryDumpFile); // direction of the packet

        // loops over the packet and saves the data
        for (DWORD i = 0; i < packetSize; ++i)
        {
            BYTE byte = *(BYTE*)(buffer + initialReadOffset + i);
            fwrite(&byte, 1, 1, binaryDumpFile);
        }

        fflush(binaryDumpFile);
    }

    void dumpPacketTextLog(PacketType packetType, DWORD packetOpcode, DWORD packetSize, DWORD buffer, time_t timestamp, WORD initialReadOffset) {
        if (!isTextLogDumpEnabled) return;

        if (!textLogDumpFile) {
            textLogDumpFile = fopen(textLogDumpFilePath, "w"); // text mode

            if (!textLogDumpFile) {
                printf("Cannot open file: %s, error code: %d - %s", textLogDumpFilePath, errno, strerror(errno));
                isTextLogDumpEnabled = false;
                return;
            }
        }

        // writes a header and a ruler
        WriteTextLogHeader(textLogDumpFile, packetType, packetOpcode, packetSize, timestamp);
        WriteTextLogRuler(textLogDumpFile);

        // really dumps the packet's data
        WriteTextLogPacketDump(textLogDumpFile, packetType, buffer, packetSize, initialReadOffset);

        // ruler again
        WriteTextLogRuler(textLogDumpFile);
        fprintf(textLogDumpFile, "\n\n");

        fflush(textLogDumpFile);
    }

    // a header which contains some details about the packet
    // packet direction, opcode, size, timestamp, date
    void WriteTextLogHeader(FILE* file, PacketType packetType, DWORD packetOpcode, DWORD packetSize, time_t timestamp) {
        tm* date = localtime(&timestamp);
        // date format
        char dateStr[32];
        // fills the date, format: YYYY. mm. dd. - HH:ii:ss
        _snprintf(dateStr,
                  sizeof(dateStr),
                  "%d. %02d. %02d. - %02d:%02d:%02d",
                  date->tm_year + 1900,
                  date->tm_mon + 1,
                  date->tm_mday,
                  date->tm_hour,
                  date->tm_min,
                  date->tm_sec);

        // the 2 rows header
        fprintf(file,
                "Packet type: %s, Opcode: 0x%04lX, Packet size: %lu bytes\n"
                "Timestamp: %lu, Date: %s\n",
                packetType == PACKET_TYPE_C2S ? "CMSG" : "SMSG",
                packetOpcode,
                packetSize,
                (DWORD)timestamp,
                dateStr);
    }

    // a "ruler" which makes easier to read the "user friendly" dump
    void WriteTextLogRuler(FILE* file)
    {
        char* ruler =
        "|--------|-------------------------------------------------|---------------------------------|\n"
        "|        | 00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F | 0 1 2 3 4 5 6 7 8 9 A B C D E F |\n"
        "|--------|-------------------------------------------------|---------------------------------|\n";
        fprintf(file, "%s", ruler);
    }

    // the real work of the "user friendly" packet
    void WriteTextLogPacketDump(FILE* file, PacketType packetType, DWORD buffer, DWORD packetSize, WORD initialReadOffset)
    {
        // empty packet
        if (packetSize == 0)
        {
            fprintf(file, "|        |                   EMPTY PACKET                  |           EMPTY PACKET          |\n");
            return;
        }

        // some magic to get the proper, nice format
        // should be hard to comment that... :)
        DWORD readOffset1 = initialReadOffset;
        DWORD readOffset2 = initialReadOffset;
        for (DWORD i = 0; i < packetSize; ++i)
        {
            if (i % 0x10 != 0)
                continue;
            fprintf(file, "| 0x%04lX | ", i + 1);
            for (DWORD j = 0; j < 0x10; ++j)
            {
                if ((i + j) > packetSize - 1)
                    break;
                BYTE byte = *(BYTE*)(buffer + readOffset1++);
                fprintf(file, "%02X ", byte);
            }
            if (i + 0x0F > packetSize - 1)
                for (DWORD j = 0; j < i + 0x10 - packetSize; ++j)
                    fprintf(file, "%s", "   ");
            fprintf(file, "%s ", "|");
            for (DWORD j = 0; j < 0x10; ++j)
            {
                if ((i + j) > packetSize - 1)
                    break;
                BYTE byte = *(BYTE*)(buffer + readOffset2++);
                if (byte >= 0x20 && byte < 0x7F)
                    fprintf(file, "%c ", (char)byte);
                else
                    fprintf(file, "%s ", ".");
            }
            if (i + 0x0F > packetSize - 1)
                for (DWORD j = 0; j < i + 0x10 - packetSize; ++j)
                    fprintf(file, "%s", "  ");
            fprintf(file, "%s\n", "|");
        }
    }
};
