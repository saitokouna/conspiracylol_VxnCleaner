
#include <windows.h>
#include <iostream>
#include <fstream>
#include <string>
#include <shlwapi.h>
#include <shlobj_core.h>
#include <string>
#include <filesystem>
#include <TlHelp32.h>
#include <DbgHelp.h>

#include "./Lib/xor.h"
#include "./Lib/spoofer.h"
#include "./Lib/Lazy.h"
#include "./AntiDebug/AntiDebug.h"
#include "./AntiDebug/Misc.h"
#include "./Input/Input.h"

#include "./Cleaner/Registry.h"
#include "./Cleaner/Proc.h"
#include "./Mac/MacWoof.h"
#include "./VolumeID/SpoofVolID.h"
#include "./Spoof/spoof.h"


namespace Cleen
{
    void CleanFort()
    {
        auto CleenStatus = _("[+] Cleaning FuckNite!\r\n");

        printf(CleenStatus.decrypt()); CleenStatus.clear();

        CleanRegistryFortEpic();

        Sleep(100);
    }

    void CleanRegistry() 
    {
        auto CleenStatus = _("[+] Cleaning Registry!\r\n");
       
        printf(CleenStatus.decrypt()); CleenStatus.clear();

        ClearRegistryHWID();

    }

    void CleanMac()
    {
        auto FixingNetworkingStatus = _("[+] Fixing networking!\r\n");
        printf(FixingNetworkingStatus.decrypt()); FixingNetworkingStatus.clear();

        FixNetworking();
        Sleep(210);

        auto CleenStatus = _("[+] Spoofing Mac Addresses!\r\n");
        printf(CleenStatus.decrypt()); CleenStatus.clear();

        MyMACAddr* vMacWoof = new MyMACAddr();
        vMacWoof->AssingRndMAC();

        auto CleenStatus2 = _("[+] Spoofed Mac Addresses!\r\n");
        printf(CleenStatus2.decrypt()); CleenStatus2.clear();
    }

    void CleanOther()
    {
        SpoofAllClasses();

        Sleep(100);

        ClearConsole();     // clear console
        InitConsole();      // init console title and stuff


    }

    void Clean(bool SkipMacSpoof = true)
    {
        printf(_("[+] Starting..\r\n"));

        CleanFort();

        Sleep(1200);

        ClearConsole();     // clear console
        InitConsole();      // init console title and stuff

        SpoofVolumeID();

        Sleep(1000);

        ClearConsole();     // clear console
        InitConsole();      // init console title and stuff

        auto DeepCleaningString = _("[+] Fixing other traces...\r\n");

        printf(DeepCleaningString.decrypt()); DeepCleaningString.clear();

        SpoofAllClasses();

        Sleep(1000);

        CleanRegistry();

        ClearConsole();     // clear console
        InitConsole();      // init console title and stuff

        if (SkipMacSpoof)
        {
            auto NoMacSpoofString = _("[!] Not Mac Spoofing due to CMD override! (-nm/-nomac)\r\n");

            printf(NoMacSpoofString.decrypt()); NoMacSpoofString.clear();
        }
        else
        {
            Cleen::CleanMac();
        }

        Sleep(3000);
        
        system(_("reagentc /enable >nul 2>&1").decrypt()); // yea

        ClearConsole();     // clear console
        InitConsole();      // init console title and stuff
        Watermark();        // show watermark
        ColorCyan();        // set color to cyan

        auto CleenStatusComplete = _("[+] Cleaned FuckNite!\r\n");
        printf(CleenStatusComplete.decrypt()); CleenStatusComplete.clear();

        printf(_("[+] Done..\r\n"));
        printf(_("[+] You can close this window..! if you paid for this software you were scammed.\r\n"));

        Sleep(-1);
    }
}

namespace Protection
{
    bool StripDOSData()
    {
        SPOOF_FUNC;
        uintptr_t Base = reinterpret_cast<uintptr_t>(GetModuleHandleA(0));
        DWORD Protect = 0;
        LI_FN(VirtualProtect).forwarded_safe_cached()((char*)Base, 4096, PAGE_EXECUTE_READWRITE, &Protect);
        IMAGE_DOS_HEADER* pDosHeader = reinterpret_cast<IMAGE_DOS_HEADER*>(Base);
        if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE)
        {
            return false;
        }

        memset(&pDosHeader->e_magic, 0, sizeof(pDosHeader->e_magic));
    }

    inline void antidump() // yes I am very lazy
    {
        SPOOF_FUNC;

        DWORD Protect = 0;
        char* pBaseAddr = (char*)GetModuleHandleA(0);
        LI_FN(VirtualProtect).forwarded_safe_cached()(pBaseAddr, 0x1000, PAGE_GUARD, &Protect);
        ZeroMemory(pBaseAddr, 4096);
    }
}

int main(int argc, char** argv)
{
    Protection::StripDOSData(); // this is just funny tbh
    Protection::antidump();         // anti dump cus imma vmprotect prob

    KillProc();         // kill fort and eac/be/epic games services and stuffz  
    //CreateAntiThread(); // antidebug
   
    bool bNoMacSpoof = false;

    RecacheSerials();   // recache serials
    ColorDefault();     // reset color
    ClearConsole();     // clear console
    InitConsole();      // init console title and stuff
    Watermark();        // show watermark
    ColorCyan();        // set color to cyan
    
    InitProxyCallReverseEngineeringMessage();

    for (int i = 0; i < argc; i++)
    {

        if (std::string(argv[i]) == _("-nomac").decrypt() || std::string(argv[i]) == _("-nm").decrypt())
        {
            bNoMacSpoof = true;
        }
    }

    printf(_("[*] Press any key to clean...\r\n"));

    PressAnyKey();

    printf(_("[+] Starting..\r\n"));

#if NDEBUG
    Sleep(2000);
#endif

    Cleen::Clean(bNoMacSpoof);

    return 0;
}