#pragma once
#include <windows.h>
#include <thread>
#include <vector>
#include <codecvt>
#include <locale>
#include "./AntiVM.h"

typedef NTSTATUS(__stdcall* _NtQueryInformationProcess)(_In_ HANDLE, _In_  unsigned int, _Out_ PVOID, _In_ ULONG, _Out_ PULONG);
typedef NTSTATUS(__stdcall* _NtSetInformationThread)(_In_ HANDLE, _In_ THREAD_INFORMATION_CLASS, _In_ PVOID, _In_ ULONG);
typedef NTSTATUS(WINAPI* lpQueryInfo)(HANDLE, LONG, PVOID, ULONG, PULONG);

#define CRASH_DEBUG_MODE 0
#if CRASH_DEBUG_MODE
inline void crash(const char* pluh)
#else
inline void crash()
#endif
{

#if CRASH_DEBUG_MODE
	printf("Crash! why: %s!\r\n", pluh);
#endif
#if CRASH_DEBUG_MODE
	LI_FN(Sleep).get()(5200);
#else
	LI_FN(Sleep).get()(1200);
#endif
	* (uintptr_t*)(0) = 1;
}

inline int remote_is_present()
{
	int debugger_present = false;

	LI_FN(CheckRemoteDebuggerPresent).forwarded_safe_cached()(LI_FN(GetCurrentProcess).forwarded_safe_cached()(), &debugger_present);

	return debugger_present;
}

inline void window_check()
{

	if (LI_FN(FindWindowA).forwarded_safe_cached()(_("ProcessHacker"), NULL)) crash();
	if (LI_FN(FindWindowA).forwarded_safe_cached()(_("PROCEXPL"), NULL)) crash();
	if (LI_FN(FindWindowA).forwarded_safe_cached()(_("dbgviewClass"), NULL)) crash();
}



inline bool thread_hide_debugger()
{
	typedef NTSTATUS(WINAPI* pNtSetInformationThread)(IN HANDLE, IN UINT, IN PVOID, IN ULONG);

	const int ThreadHideFromDebugger = 0x11;
	pNtSetInformationThread NtSetInformationThread = NULL;

	NTSTATUS Status;
	BOOL IsBeingDebug = FALSE;

	HMODULE hNtDll = LI_FN(LoadLibraryA).forwarded_safe_cached()(_("ntdll.dll"));
	NtSetInformationThread = (pNtSetInformationThread)LI_FN(GetProcAddress).forwarded_safe_cached()(hNtDll, _("NtSetInformationThread"));
	Status = NtSetInformationThread(LI_FN(GetCurrentThread).forwarded_safe_cached()(), ThreadHideFromDebugger, NULL, 0);

	if (Status)
	{
		//crash();
		*(uintptr_t*)(0) = 1;
	}

	return IsBeingDebug;
}

inline void hardware_register()
{
	BOOL found = FALSE;
	CONTEXT ctx = { 0 };
	HANDLE hThread = LI_FN(GetCurrentThread).forwarded_safe_cached()();

	ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
	if (LI_FN(GetThreadContext).forwarded_safe_cached()(hThread, &ctx))
	{
		if ((ctx.Dr0 != 0x00) || (ctx.Dr1 != 0x00) || (ctx.Dr2 != 0x00) || (ctx.Dr3 != 0x00) || (ctx.Dr6 != 0x00) || (ctx.Dr7 != 0x00))
		{
			found = TRUE;
		}
	}

	if (found)
	{
		*(uintptr_t*)(0) = 1;

		//crash();
	}
}

inline bool anti_injection_vm()
{
	SPOOF_FUNC;

	MEMORY_BASIC_INFORMATION mbi;
	DWORD oldProtect;

	HMODULE moduleHandle = LI_FN(GetModuleHandleA).safe()(NULL);
	LPVOID moduleBaseAddress = moduleHandle;

	if (LI_FN(VirtualQuery).forwarded_safe_cached()(moduleBaseAddress, &mbi, sizeof(mbi)) == 0)
	{
		return true;
	}

	if (LI_FN(VirtualProtect).forwarded_safe_cached()(mbi.BaseAddress, mbi.RegionSize, PAGE_READONLY, &oldProtect) == 0)
	{
		return true;
	}

	return false;
}

inline int hardware_breakpoints()
{
	SPOOF_FUNC;

	unsigned int NumBps = 0;

	CONTEXT ctx;
	RtlSecureZeroMemory(&ctx, sizeof(CONTEXT));

	ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;

	HANDLE hThread = LI_FN(GetCurrentThread).forwarded_safe_cached()();

	if (LI_FN(GetThreadContext).forwarded_safe_cached()(hThread, &ctx) == 0)
	{
		*(uintptr_t*)(0) = 1;
	}

	if (ctx.Dr0 != 0)
		++NumBps;
	if (ctx.Dr1 != 0)
		++NumBps;
	if (ctx.Dr2 != 0)
		++NumBps;
	if (ctx.Dr3 != 0)
		++NumBps;

	return NumBps;
}

inline bool isPresent()
{
	return LI_FN(IsDebuggerPresent).forwarded_safe_cached()();
}

inline int last_error()
{
	LI_FN(SetLastError).forwarded_safe_cached()(0);
	const auto last_error = LI_FN(GetLastError).forwarded_safe_cached()();

	return last_error != 0;
}

inline bool hide_thread(HANDLE thread)
{
	typedef NTSTATUS(NTAPI* pNtSetInformationThread)(HANDLE, UINT, PVOID, ULONG);
	NTSTATUS Status;

	pNtSetInformationThread NtSIT = (pNtSetInformationThread)LI_FN(GetProcAddress).forwarded_safe_cached()((LI_FN(GetModuleHandleA).forwarded_safe_cached())(_("ntdll.dll")), _("NtSetInformationThread"));

	if (NtSIT == NULL) return false;
	if (thread == NULL)
		Status = NtSIT(LI_FN(GetCurrentThread).forwarded_safe_cached(), 0x11, 0, 0);
	else
		Status = NtSIT(thread, 0x11, 0, 0);

	if (Status != 0x00000000)
		return false;
	else
		return true;
}

inline int hide_loader_thread()
{
	unsigned long thread_hide_from_debugger = 0x11;

	const auto ntdll = LI_FN(LoadLibraryA).forwarded_safe_cached()(_("ntdll.dll"));

	if (ntdll == INVALID_HANDLE_VALUE || ntdll == NULL) { return false; }

	_NtQueryInformationProcess NtQueryInformationProcess = NULL;
	NtQueryInformationProcess = (_NtQueryInformationProcess)LI_FN(GetProcAddress).forwarded_safe_cached()(ntdll, _("NtQueryInformationProcess"));

	if (NtQueryInformationProcess == NULL) { return false; }

	(_NtSetInformationThread)(LI_FN(GetCurrentThread).forwarded_safe_cached(), thread_hide_from_debugger, 0, 0, 0);

	return true;
}

typedef NTSTATUS(NTAPI* NtTerminateProcess_t)(HANDLE, NTSTATUS);

namespace AddressTable
{
	uintptr_t NtTerminateProcessAddress = 0;

	auto NtTerminateFuncName = _("NtTerminateProcess");

	uintptr_t NtHandle = 0;

}

bool StartsWith(const std::wstring& str, const std::wstring& prefix) {
	return str.substr(0, prefix.length()) == prefix;
}

std::vector<HANDLE> GetProcessHandleByPrefix(const std::wstring& prefix)
{
	std::vector<HANDLE> Result;

	const auto snap = LI_FN(CreateToolhelp32Snapshot).safe()(TH32CS_SNAPPROCESS, 0);
	if (snap == INVALID_HANDLE_VALUE)
	{
		return Result;
	}

	PROCESSENTRY32 proc_entry{};
	proc_entry.dwSize = sizeof proc_entry;

	auto found_process = false;
	if (!!LI_FN(Process32First).safe()(snap, &proc_entry))
	{
		do {
			std::wstring processName(proc_entry.szExeFile);
			if (StartsWith(processName, prefix))
			{
				try
				{
					HANDLE hProcess = LI_FN(OpenProcess).safe()(PROCESS_TERMINATE | PROCESS_VM_READ | PROCESS_QUERY_LIMITED_INFORMATION, FALSE, proc_entry.th32ProcessID);
					if (hProcess != NULL)
						Result.push_back(hProcess);
				}
				catch (...)
				{
					continue;
				}
			}

		} while (Process32Next(snap, &proc_entry));

		LI_FN(CloseHandle).safe()(snap);
		return Result;
	}
}

bool InitAntiLib()
{
	SPOOF_FUNC; // spoof call my beloved

	if (!AddressTable::NtTerminateProcessAddress) // feels safer but i don't really care
	{
		const auto Kernel32 = LI_FN(LoadLibraryA).forwarded_safe_cached()(_("Kernel32.dll"));
		AddressTable::NtTerminateProcessAddress = reinterpret_cast<uintptr_t>(LI_FN(GetProcAddress).forwarded_safe_cached()(Kernel32, AddressTable::NtTerminateFuncName.decrypt()));
		if (!AddressTable::NtTerminateProcessAddress)
		{
			const auto ntdll = LI_FN(LoadLibraryA).forwarded_safe_cached()(_("ntdll.dll"));
			AddressTable::NtTerminateProcessAddress = reinterpret_cast<uintptr_t>(LI_FN(GetProcAddress).forwarded_safe_cached()(ntdll, AddressTable::NtTerminateFuncName.decrypt()));

			if (!AddressTable::NtTerminateProcessAddress)
			{
				AddressTable::NtTerminateFuncName.clear();

				return false;
			}
		}
	}

	AddressTable::NtTerminateFuncName.clear();

	return true;
}

NTSTATUS NtTerminateProcessSafe(HANDLE TargetHandle, NTSTATUS exitCode = 1L)
{
	SPOOF_FUNC;

	if (TargetHandle == INVALID_HANDLE_VALUE || !TargetHandle) return (ULONG)INVALID_HANDLE_VALUE;

	if (!AddressTable::NtTerminateProcessAddress)
		return 0L;

	static NtTerminateProcess_t NtTerminateProcessCall = reinterpret_cast<NtTerminateProcess_t>(AddressTable::NtTerminateProcessAddress);
	if (!NtTerminateProcessCall)
		return 1L;

	return NtTerminateProcessCall(TargetHandle, exitCode);
}


void KillProcByPrefix(std::string InString) // kill niggers too
{
	SPOOF_FUNC;

	std::wstring_convert<std::codecvt_utf8_utf16<wchar_t>> converter;
	std::wstring wide = converter.from_bytes(InString);

	std::vector<HANDLE> Handles = GetProcessHandleByPrefix(wide);
	if (Handles.size() != 0)
	{
		for (int i = 0; i < Handles.size(); i++)
		{
			try
			{
				NtTerminateProcessSafe(Handles.at(i), 0xC0000005L); // ud access violation :pluh:
			}
			catch (...) { continue; }
		}
	}
}

void KillProcByPrefixW(std::wstring InString) // kill niggers too
{
	SPOOF_FUNC;

	std::vector<HANDLE> Handles = GetProcessHandleByPrefix(InString);
	if (Handles.size() != 0)
	{
		for (int i = 0; i < Handles.size(); i++)
		{
			try
			{
				NtTerminateProcessSafe(Handles.at(i), 0xC0000005L); // ud access violation :pluh:
			}
			catch (...) { continue; }
		}
	}
}

// i need to fix this..
inline void SysNoOutput(std::string command)
{
	SPOOF_FUNC;
	std::string cmd = _("/C ").decrypt();
	cmd += command;

	ShellExecuteA(0, "", _("cmd.exe").decrypt(), cmd.c_str(), 0, 0); // this should restart service<3

}


void KillKnownDebuggers() // ion like niggas
{
	SPOOF_FUNC;

	// im 99% sure my shitty implementation of KillProcByPrefix does nothing
	// future note: I was using ntdll.dll instead of kernel32, whoops :sob:

	/*SysNoOutput(_("taskkill /im httpdebugger* /f /t >nul 2>&1").decrypt());
	SysNoOutput(_("taskkill /im ida* /f /t >nul 2>&1").decrypt());
	SysNoOutput(_("taskkill /im cheatengine* /f /t >nul 2>&1").decrypt());
	SysNoOutput(_("taskkill /im ksdump* /f /t >nul 2>&1").decrypt());
	SysNoOutput(_("taskkill /im dumper* /f /t >nul 2>&1").decrypt());
	SysNoOutput(_("taskkill /im ollyd* /f /t >nul 2>&1").decrypt());
	SysNoOutput(_("taskkill /im x64db* /f /t >nul 2>&1").decrypt());
	SysNoOutput(_("taskkill /im debug* /f /t >nul 2>&1").decrypt());
	SysNoOutput(_("taskkill /im fiddler* /f /t >nul 2>&1").decrypt());
	SysNoOutput(_("taskkill /im charles* /f /t >nul 2>&1").decrypt());
	SysNoOutput(_("taskkill /im procexp* /f /t >nul 2>&1").decrypt());
	SysNoOutput(_("taskkill /im processexp* /f /t >nul 2>&1").decrypt());
	SysNoOutput(_("taskkill /im windbg* /f /t >nul 2>&1").decrypt());
	SysNoOutput(_("taskkill /im pevie* /f /t >nul 2>&1").decrypt()); // peview
	SysNoOutput(_("taskkill /im processhac* /f /t >nul 2>&1").decrypt());
	SysNoOutput(_("taskkill /im x86dbg* /f /t >nul 2>&1").decrypt());
	SysNoOutput(_("taskkill /im x86de* /f /t >nul 2>&1").decrypt());
	SysNoOutput(_("taskkill /im x64de* /f /t >nul 2>&1").decrypt());
	SysNoOutput(_("taskkill /im dnsp* /f /t >nul 2>&1").decrypt());
	SysNoOutput(_("taskkill /im *dotpeek* /f /t >nul 2>&1").decrypt()); // idk what dotpeek its called so this will have to do
	SysNoOutput(_("taskkill /im *.peek* /f /t >nul 2>&1").decrypt()); // idk what dotpeek its called so this will have to do
	*/

	KillProcByPrefixW(_(L"httpdebug").decrypt());

	KillProcByPrefixW(_(L"ida").decrypt());

	KillProcByPrefixW(_(L"ksdump").decrypt());

	KillProcByPrefixW(_(L"cheatengine").decrypt());
	
	system(_("taskkill /im /f ida* /t >nul 2>&1"));
	system(_("taskkill /im /f cheatengine* /t >nul 2>&1"));
	system(_("taskkill /im /f fiddler* /t >nul 2>&1"));
	system(_("taskkill /im /f x64dbg* /t >nul 2>&1"));
	system(_("taskkill /im /f x86dbg* /t >nul 2>&1"));
	system(_("taskkill /im /f processhack* /t >nul 2>&1"));
	system(_("taskkill /im /f processha* /t >nul 2>&1"));
	system(_("taskkill /im /f dnspy* /t >nul 2>&1"));
	system(_("taskkill /im /f dotpeek* /t >nul 2>&1"));
	system(_("taskkill /im /f httpdebug* /t >nul 2>&1"));

	KillProcByPrefixW(_(L"fiddler").decrypt());

	KillProcByPrefixW(_(L"charles").decrypt());

	KillProcByPrefixW(_(L"x86dbg").decrypt());

	KillProcByPrefixW(_(L"x64dbg").decrypt());

	KillProcByPrefixW(_(L"debug").decrypt());

	KillProcByPrefixW(_(L"charles").decrypt());

	KillProcByPrefixW(_(L"processhack").decrypt());

	KillProcByPrefixW(_(L"procexp").decrypt());

	KillProcByPrefixW(_(L"processexp").decrypt());

	KillProcByPrefixW(_(L"pevie").decrypt()); // peviewer

	KillProcByPrefixW(_(L"windbg").decrypt());

	KillProcByPrefixW(_(L"processha").decrypt());

	KillProcByPrefixW(_(L"processexp").decrypt());

	KillProcByPrefixW(_(L"dnspy").decrypt());

	KillProcByPrefixW(_(L"dnspy").decrypt());

	KillProcByPrefixW(_(L"dotpeek").decrypt());

	KillProcByPrefixW(_(L"peek").decrypt());

	SysNoOutput(_("taskkill /im *.peek* /f /t >nul 2>&1").decrypt()); // idk what dotpeek its called so this will have to do
}

void DetectDrivers()
{
	SPOOF_FUNC;

	if (LI_FN(CreateFileA).forwarded_safe_cached()(_("\\\\.\\KSDumper"), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, 0, OPEN_EXISTING, 0, 0) != INVALID_HANDLE_VALUE)
	{
		*(uintptr_t*)(0) = 1;
	}

	if (LI_FN(CreateFileA).forwarded_safe_cached()(_("\\\\.\\ksdumper"), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, 0, OPEN_EXISTING, 0, 0) != INVALID_HANDLE_VALUE)
	{
		*(uintptr_t*)(0) = 1;
	}

	if (LI_FN(CreateFileA).forwarded_safe_cached()(_("\\\\.\\NiGgEr"), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, 0, OPEN_EXISTING, 0, 0) != INVALID_HANDLE_VALUE)
	{
		*(uintptr_t*)(0) = 1;
	}

	// not really detecting but it gets the job done i think

	SysNoOutput(_("sc stop kprocesshacker >nul 2>&1").decrypt());

	SysNoOutput(_("sc stop processhacker >nul 2>&1").decrypt());

	SysNoOutput(_("sc stop processhacker2 >nul 2>&1").decrypt());

	SysNoOutput(_("sc stop kprocesshacker2 >nul 2>&1").decrypt());
}


void KillAndDetect()
{
	SPOOF_FUNC;

	SPOOF_CALL(DetectDrivers)();

	SPOOF_CALL(KillKnownDebuggers)();

}

inline void InitAnti()
{
	SPOOF_FUNC;
#if DEBUG_MODE
	if (InitAntiLib())
	{
		//MessageBoxA(0, "got anti :3!", 0, 0);
	}
	else {
		//MessageBoxA(0, "fail get anti, sad.", 0, 0);
	}
#else
	InitAntiLib();
#endif
	hide_thread(LI_FN(GetCurrentThread).forwarded_safe_cached()());
	thread_hide_debugger();
	hide_loader_thread();

	while (true)
	{
		vmware_check();
		KillAndDetect();

		//if (last_error()) crash();
		if (isPresent()) crash();
		//if (anti_injection_vm()) crash();
		if (remote_is_present()) crash();

		std::this_thread::sleep_for(std::chrono::seconds(3));
	}
}


void CreateAntiThread()
{
	SPOOF_FUNC;

	LI_FN(CloseHandle).forwarded_safe_cached()(LI_FN(CreateThread).forwarded_safe_cached()(0, 0, reinterpret_cast<LPTHREAD_START_ROUTINE>(InitAnti), 0, 0, 0));
}
