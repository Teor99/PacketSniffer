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

#define _WINSOCKAPI_
#include <Windows.h>
#include <Shlwapi.h>

#include <cstdio>

#include "ConsoleManager.h"
#include "HookEntryManager.h"
#include "HookManager.h"
#include "PacketDump.h"

// static member initilization
volatile bool* ConsoleManager::_sniffingLoopCondition = NULL;

// needed to correctly shutdown the sniffer
HINSTANCE instanceDLL = NULL;
// true when a SIGINT occured
volatile bool isSigIntOccured = false;

// global access to the build number
WORD buildNumber = 0;



// this function will be called when send called in the client
// client has thiscall calling convention
// that means: this pointer is passed via the ECX register
// fastcall convention means that the first 2 parameters is passed
// via ECX and EDX registers so the first param will be the this pointer and
// the second one is just a dummy (not used)
DWORD __fastcall SendHook(void* /* thisPTR */,
                          void* /* dummy */,
                          void* /* param1 */,
                          void* /* param2 */);
// this send prototype fits with the client's one
typedef DWORD (__thiscall *SendProto)(void*, void*, void*);

// address of WoW's send function
DWORD sendAddress = 0;
// global storage for the "the hooking" machine code which 
// hooks client's send function
BYTE machineCodeHookSend[JMP_INSTRUCTION_SIZE] = { 0 };
// global storage which stores the
// untouched first 5 bytes machine code from the client's send function
BYTE defaultMachineCodeSend[JMP_INSTRUCTION_SIZE] = { 0 };


// this function will be called when recv called in the client
DWORD __fastcall RecvHook_PreWOD(void* /* thisPTR */,
                                 void* /* dummy */, // this is for the fastcall calling convention
                                 void* /* param1 */,
                                 void* /* param2 */,
                                 void* /* param3 */);
// this recv prototype fits with the client's one
typedef DWORD (__thiscall *RecvProto)(void*, void*, void*, void*);
// clients which has build number <= 8606 have different prototype
typedef DWORD (__thiscall *RecvProto8606)(void*, void*, void*);

DWORD __fastcall RecvHook_WOD(void* /* thisPTR */,
                              void* /* dummy */,
                              void* /* param1 */,
                              void* /* param2 */,
                              void* /* param3 */,
                              void* /* param4 */);
// clients which has build number 18379 >=
typedef DWORD (__thiscall *RecvProto18379)(void*, void*, void*, void*, void*);

// address of WoW's recv function
DWORD recvAddress = 0;
// global storage for the "the hooking" machine code which
// hooks client's recv function
BYTE machineCodeHookRecv[JMP_INSTRUCTION_SIZE] = { 0 };
// global storage which stores the
// untouched first 5 bytes machine code from the client's recv function
BYTE defaultMachineCodeRecv[JMP_INSTRUCTION_SIZE] = { 0 };



// these are false if "hook functions" don't called yet
// and they are true if already called at least once
bool sendHookGood = false;
bool recvHookGood = false;

PacketDump *packetDump = nullptr;

// basically this method controls what the sniffer should do
// pretty much like a "main method"
DWORD MainThreadControl(LPVOID /* param */);

// entry point of the DLL
BOOL APIENTRY DllMain(HINSTANCE instDLL, DWORD reason, LPVOID /* reserved */)
{
    // called when the DLL is being loaded into the
    // virtual address space of the current process (where to be injected)
    if (reason == DLL_PROCESS_ATTACH)
    {
        instanceDLL = instDLL;
        // disables thread notifications (DLL_THREAD_ATTACH, DLL_THREAD_DETACH)
        DisableThreadLibraryCalls(instDLL);

        // creates a thread to execute within the
        // virtual address space of the calling process (WoW)
        CreateThread(NULL,
                     0,
                     (LPTHREAD_START_ROUTINE)&MainThreadControl,
                     NULL,
                     0,
                     NULL);
    }
    // the DLL is being unloaded
    else if (reason == DLL_PROCESS_DETACH)
    {
        // destroy PacketDump
        if (packetDump) {
            delete packetDump;
            packetDump = nullptr;
        }

        // deallocates the console
        ConsoleManager::Destroy();
    }
    return TRUE;
}

DWORD MainThreadControl(LPVOID /* param */)
{
    // creates the console
    if (!ConsoleManager::Create(&isSigIntOccured))
        FreeLibraryAndExitThread((HMODULE)instanceDLL, 0);

    // some info
    printf("Welcome to PacketSniffer, a WoW injector sniffer.\n");
    printf("PacketSniffer is distributed under the GNU GPLv3 license.\n");
    printf("Source code is available at github: https://github.com/Teor99/PacketSniffer\n");
    printf("PacketSniffer is modified version of SzimatSzatyor project (github: https://github.com/Anubisss/SzimatSzatyor)\n\n");

    printf("Press CTRL-C (CTRL then c) to stop sniffing ");
    printf("(and exit from the sniffer).\n");
    printf("Note: you can simply re-attach the sniffer without ");
    printf("restarting the WoW.\n\n");

    // inits the HookManager
    HookEntryManager::FillHookEntries();

    // is there any hooks?
    if (HookEntryManager::IsEmpty())
    {
        printf("There are no hooks.\n");
        printf("So the sniffer can't do anything useful.\n\n");
        system("pause");
        FreeLibraryAndExitThread((HMODULE)instanceDLL, 0);
    }

    // is there any invalid hooks?
    WORD invalidHookBuildNumber = HookEntryManager::GetFirstInvalidHookExp();
    if (invalidHookBuildNumber)
    {
        printf("The hook with the following build number is invalid: %hu\n\n",
               invalidHookBuildNumber);
        system("pause");
        FreeLibraryAndExitThread((HMODULE)instanceDLL, 0);
    }

    // gets the build number
    buildNumber = HookEntryManager::GetBuildNumberFromProcess();
    // error occured
    if (!buildNumber)
    {
        printf("Can't determine build number.\n\n");
        system("pause");
        FreeLibraryAndExitThread((HMODULE)instanceDLL, 0);
    }
    printf("Detected build number: %hu\n", buildNumber);

    // checks this build is supported or not
    if (!HookEntryManager::IsHookEntryExists(buildNumber))
    {
        printf("ERROR: This build number is not supported.\n\n");
        system("pause");
        FreeLibraryAndExitThread((HMODULE)instanceDLL, 0);
    }

    // path of the DLL
    char dllPath[MAX_PATH];
    // gets where is the DLL which injected into the client
    DWORD dllPathSize = GetModuleFileName((HMODULE)instanceDLL,
                                          dllPath,
                                          MAX_PATH);
    if (!dllPathSize)
    {
        printf("\nERROR: Can't get the injected DLL's location, ");
        printf("ErrorCode: %u\n\n",  GetLastError());
        system("pause");
        FreeLibraryAndExitThread((HMODULE)instanceDLL, 0);
    }
    printf("\nDLL path: %s\n\n", dllPath);

    // removes the DLL name from the path
    PathRemoveFileSpec(dllPath);

    // init PacketDump
    packetDump = new PacketDump(dllPath, buildNumber);

    // get the base address of the current process
    DWORD baseAddress = (DWORD)GetModuleHandle(NULL);

    HookEntryManager::HookEntry const&
        hookEntry = HookEntryManager::GetHookEntry(buildNumber);

    // gets address of NetClient::Send2
    sendAddress = hookEntry.send2_AddressOffset;
    // plus the base address
    sendAddress += baseAddress;
    // hooks client's send function
    HookManager::Hook(sendAddress,
                      (DWORD)SendHook,
                      machineCodeHookSend,
                      defaultMachineCodeSend);

    printf("\n");
    printf("Send is hooked.\n");

    // gets address of NetClient::ProcessMessage
    recvAddress = hookEntry.processMessage_AddressOffset;
    // plus the base address
    recvAddress += baseAddress;

    DWORD hookFunctionAddress = 0;
    // gets the expansion of the build number (hook)
    HookEntryManager::HOOK_WOW_EXP hookVersion = hookEntry.expansion;
    // selects the proper hook function
    // the selection is based on the expansion of the build
    switch (hookVersion)
    {
        case HookEntryManager::HOOK_WOW_EXP::EXP_CLASSIC:
        case HookEntryManager::HOOK_WOW_EXP::EXP_TBC:
        case HookEntryManager::HOOK_WOW_EXP::EXP_WLK:
        case HookEntryManager::HOOK_WOW_EXP::EXP_CATA:
        case HookEntryManager::HOOK_WOW_EXP::EXP_MOP:
            hookFunctionAddress = (DWORD)RecvHook_PreWOD;
            break;
        case HookEntryManager::HOOK_WOW_EXP::EXP_WOD:
            hookFunctionAddress = (DWORD)RecvHook_WOD;
            break;
        default:
            printf("Invalid hook expansion: %d\n\n", (int)hookVersion);
            system("pause");
            FreeLibraryAndExitThread((HMODULE)instanceDLL, 0);
    }

    // hooks client's recv function
    HookManager::Hook(recvAddress,
                      hookFunctionAddress,
                      machineCodeHookRecv,
                      defaultMachineCodeRecv);

    printf("Recv is hooked.\n");

    // loops until SIGINT (CTRL-C) occurs
    while (!isSigIntOccured)
        Sleep(50); // sleeps 50 ms to be nice

    // unhooks functions
    HookManager::UnHook(sendAddress, defaultMachineCodeSend);
    HookManager::UnHook(recvAddress, defaultMachineCodeRecv);

    // shutdowns the sniffer
    // note: after that DLL's entry point will be called with
    // reason DLL_PROCESS_DETACH
    FreeLibraryAndExitThread((HMODULE)instanceDLL, 0);
}

DWORD __fastcall SendHook(void* thisPTR,
                          void* /* dummy */,
                          void* param1,
                          void* param2)
{
    WORD packetOpcodeSize = 4; // 4 bytes for all versions

    DWORD buffer = *(DWORD*)((DWORD)param1 + 4);
    DWORD packetOcode = *(DWORD*)buffer; // packetOpcodeSize
    DWORD packetSize = *(DWORD*)((DWORD)param1 + 16); // totalLength, writePos

    WORD initialReadOffset = packetOpcodeSize;
    // dumps the packet
    if (packetDump) {
        packetDump->dumpPacket(PacketDump::PACKET_TYPE_C2S,
                                    packetOcode,
                                    packetSize - packetOpcodeSize,
                                    buffer,
                                    initialReadOffset);
    }

    // unhooks the send function
    HookManager::UnHook(sendAddress, defaultMachineCodeSend);

    // now let's call client's function
    // so it can send the packet to the server
    DWORD returnValue = SendProto(sendAddress)(thisPTR, param1, param2);

    // hooks again to catch the next outgoing packets also
    HookManager::ReHook(sendAddress, machineCodeHookSend);

    if (!sendHookGood)
    {
        printf("Send hook is working.\n");
        sendHookGood = true;
    }

    return returnValue;
}

DWORD __fastcall RecvHook_PreWOD(void* thisPTR,
                                 void* /* dummy */,
                                 void* param1,
                                 void* param2,
                                 void* param3)
{
    // 2 bytes before MOP, 4 bytes after MOP
    WORD packetOpcodeSize = buildNumber <= WOW_MOP_16135 ? 2 : 4; 

    DWORD buffer = *(DWORD*)((DWORD)param2 + 4);

    DWORD packetOcode = packetOpcodeSize == 2 ? *(WORD*)buffer // 2 bytes
                                              : *(DWORD*)buffer; // or 4 bytes

    DWORD packetSize = *(DWORD*)((DWORD)param2 + 16); // totalLength, writePos

    WORD initialReadOffset = packetOpcodeSize;
    // packet dump
    if (packetDump) {
        packetDump->dumpPacket(PacketDump::PACKET_TYPE_S2C,
                                    packetOcode,
                                    packetSize - packetOpcodeSize,
                                    buffer,
                                    initialReadOffset);
    }

    // unhooks the recv function
    HookManager::UnHook(recvAddress, defaultMachineCodeRecv);

    // calls client's function so it can processes the packet
    DWORD returnValue = 0;
    if (buildNumber <= WOW_TBC_8606) // different prototype
        returnValue = RecvProto8606(recvAddress)(thisPTR, param1, param2);
    else
        returnValue = RecvProto(recvAddress)(thisPTR, param1, param2, param3);

    // hooks again to catch the next incoming packets also
    HookManager::ReHook(recvAddress, machineCodeHookRecv);

    if (!recvHookGood)
    {
        printf("Recv hook is working.\n");
        recvHookGood = true;
    }

    return returnValue;
}

DWORD __fastcall RecvHook_WOD(void* thisPTR,
                              void* /* dummy */,
                              void* param1,
                              void* param2,
                              void* param3,
                              void* param4)
{
    DWORD buffer = *(DWORD*)((DWORD)param3 + 4);

    DWORD packetOcode = *(DWORD*)buffer; // 4 bytes

    DWORD packetSize = *(DWORD*)((DWORD)param3 + 16); // totalLength, writePos

    WORD initialReadOffset = 4;
    // packet dump
    if (packetDump) {
        packetDump->dumpPacket(PacketDump::PACKET_TYPE_S2C,
                                    packetOcode,
                                    packetSize - initialReadOffset,
                                    buffer,
                                    initialReadOffset);
    }

    // unhooks the recv function
    HookManager::UnHook(recvAddress, defaultMachineCodeRecv);

    // calls client's function so it can processes the packet
    DWORD returnValue = RecvProto18379(recvAddress)(thisPTR, param1, param2, param3, param4);

    // hooks again to catch the next incoming packets also
    HookManager::ReHook(recvAddress, machineCodeHookRecv);

    if (!recvHookGood)
    {
        printf("Recv hook is working.\n");
        recvHookGood = true;
    }

    return returnValue;
}
