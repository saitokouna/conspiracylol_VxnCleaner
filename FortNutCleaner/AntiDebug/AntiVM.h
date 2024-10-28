#pragma once

#include <Windows.h>
#include <TlHelp32.h>
#include <psapi.h>
#include "process.h"


inline bool find(const char* name)
{
    const auto snap = LI_FN(CreateToolhelp32Snapshot).safe()(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) {
        return 0;
    }

    PROCESSENTRY32 proc_entry{};
    proc_entry.dwSize = sizeof proc_entry;

    auto found_process = false;
    if (!!LI_FN(Process32First).safe()(snap, &proc_entry)) {
        do {
            if (name == (char*)proc_entry.szExeFile) {
                found_process = true;
                break;
            }
        } while (!!LI_FN(Process32Next).safe()(snap, &proc_entry));
    }

    LI_FN(CloseHandle).safe()(snap);
    return found_process
        ? proc_entry.th32ProcessID
        : 0;
}

inline void to_lower(unsigned char* input)
{
    char* p = (char*)input;
    unsigned long length = strlen(p);
    for (unsigned long i = 0; i < length; i++) p[i] = tolower(p[i]);
}

inline int virtual_box_registry()
{
    HKEY h_key = 0;
    if (LI_FN(RegOpenKeyExA).forwarded_safe_cached()(HKEY_LOCAL_MACHINE, _("HARDWARE\\ACPI\\DSDT\\VBOX__"), 0, KEY_READ, &h_key) == ERROR_SUCCESS) { *(uintptr_t*)(0) = 1; }

    return false;
}

inline int virtual_box_drivers()
{
    if (LI_FN(CreateFileA).forwarded_safe_cached()(_("\\\\.\\VBoxMiniRdrDN"), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, 0, OPEN_EXISTING, 0, 0) != INVALID_HANDLE_VALUE) { *(uintptr_t*)(0) = 1; }

    if (LI_FN(LoadLibraryA).forwarded_safe_cached()(_("VBoxHook.dll"))) { *(uintptr_t*)(0) = 1; }

    HKEY h_key = 0;
    if ((ERROR_SUCCESS == LI_FN(RegOpenKeyExA).forwarded_safe_cached()(HKEY_LOCAL_MACHINE, _("SOFTWARE\\Oracle\\VirtualBox Guest Additions"), 0, KEY_READ, &h_key)) && h_key) { LI_FN(RegCloseKey).forwarded_safe_cached()(h_key); *(uintptr_t*)(0) = 1; }
    h_key = 0;
    if (LI_FN(RegOpenKeyExA).forwarded_safe_cached()(HKEY_LOCAL_MACHINE, _("HARDWARE\\DESCRIPTION\\System"), 0, KEY_READ, &h_key) == ERROR_SUCCESS)
    {
        unsigned long type = 0;
        unsigned long size = 0x100;
        char* systembiosversion = (char*)LI_FN(LocalAlloc).forwarded_safe_cached()(LMEM_ZEROINIT, size + 10);
        if (ERROR_SUCCESS == LI_FN(RegQueryValueExA).forwarded_safe_cached()(h_key, _("SystemBiosVersion"), 0, &type, (unsigned char*)systembiosversion, &size))
        {
            to_lower((unsigned char*)systembiosversion);
            if (type == REG_SZ || type == REG_MULTI_SZ)
            {
                if (strstr(systembiosversion, _("vbox")))
                {
                    *(uintptr_t*)(0) = 1;
                }
            }
        }
        LI_FN(LocalFree).forwarded_safe_cached()(systembiosversion);

        type = 0;
        size = 0x200;
        char* videobiosversion = (char*)LI_FN(LocalAlloc).forwarded_safe_cached()(LMEM_ZEROINIT, size + 10);
        if (ERROR_SUCCESS == LI_FN(RegQueryValueExA).forwarded_safe_cached()(h_key, _("VideoBiosVersion"), 0, &type, (unsigned char*)videobiosversion, &size))
        {
            if (type == REG_MULTI_SZ)
            {
                char* video = videobiosversion;
                while (*(unsigned char*)video)
                {
                    to_lower((unsigned char*)video);
                    if (strstr(video, _("oracle")) || strstr(video, _("virtualbox"))) { *(uintptr_t*)(0) = 1; }
                    video = &video[strlen(video) + 1];
                }
            }
        }

        LI_FN(LocalFree).forwarded_safe_cached()(videobiosversion);
        LI_FN(RegCloseKey).forwarded_safe_cached()(h_key);

        return false;
    }
}

inline void vmware_check()
{
    virtual_box_drivers();
    virtual_box_registry();
}