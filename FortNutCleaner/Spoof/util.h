#pragma once


typedef struct _SECTOR {
	LPCSTR Name;
	DWORD  NameOffset;
	DWORD  SerialOffset;
} SECTOR, *PSECTOR;

static SECTOR SECTORS[] = {
	{ "FAT",   0x36, 0x27 },
	{ "FAT32", 0x52, 0x43 },
	{ "NTFS",  0x03, 0x48 },
};

#define LENGTH(a) (sizeof(a) / sizeof(a[0]))

typedef NTSTATUS(WINAPI *NTQK)(HANDLE KeyHandle, DWORD KeyInformationClass, PVOID KeyInformation, ULONG Length, PULONG ResultLength);
NTQK NtQueryKey;

LPWSTR GetKeyPath(HKEY key);
BOOL GetKeyValue(HKEY key, LPCWSTR value, LPBYTE buffer, DWORD *size);
VOID OutSpoofUnique(LPWSTR buffer);
VOID KeySpoofOutGUID(HKEY key, LPCWSTR value, LPWSTR buffer, DWORD size);
VOID KeySpoofUnique(HKEY key, LPCWSTR value);
VOID SpoofUnique(HKEY key, LPCWSTR subkey, LPCWSTR value);
VOID SpoofUniques(HKEY key, LPCWSTR subkey, LPCWSTR value);
VOID SpoofQWORD(HKEY key, LPCWSTR subkey, LPCWSTR value);
VOID SpoofDWORD(HKEY key, LPCWSTR subkey, LPCWSTR value);
VOID SpoofBinary(HKEY key, LPCWSTR subkey, LPCWSTR value);
VOID RenameSubkey(HKEY key, LPCWSTR subkey, LPCWSTR name);
VOID DeleteValue(HKEY key, LPCWSTR subkey, LPCWSTR value);
VOID DeleteKey(HKEY key, LPCWSTR subkey);
BOOL AdjustCurrentPrivilege(LPCWSTR privilege);
VOID ForceDeleteFile(LPWSTR path);
VOID RecursiveDelete(LPWSTR dir, LPWSTR match);

#define ForEachFile(dir, callback) { \
	WIN32_FIND_DATA fd = { 0 }; \
	HANDLE f = FindFirstFile(dir, &fd); \
	do { \
		if (wcscmp(fd.cFileName, L".") && wcscmp(fd.cFileName, L"..")) { \
			LPWSTR file = fd.cFileName; \
			callback; \
		} \
	} while (FindNextFile(f, &fd)); \
	FindClose(f); \
}

#define ForEachSubkey(hkey_key, callback) { \
	WCHAR name[MAX_PATH] = { 0 }; \
	for (DWORD _i = 0, _s = sizeof(name); ERROR_SUCCESS == RegEnumKeyEx(hkey_key, _i, name, &_s, 0, 0, 0, 0); ++_i, _s = sizeof(name)) { \
		callback; \
	} \
}

#define SpoofUniqueThen(hkey_key, lpcwstr_subkey, lpcwstr_value, callback) { \
	HKEY _k = 0; \
	if (ERROR_SUCCESS == RegOpenKeyEx(hkey_key, lpcwstr_subkey, 0, KEY_ALL_ACCESS, &_k)) { \
		WCHAR spoof[MAX_PATH] = { 0 }; \
		HKEY key = _k; \
		KeySpoofOutGUID(key, lpcwstr_value, spoof, sizeof(spoof)); \
		callback; \
		RegCloseKey(key); \
	} \
}

#define OpenThen(hkey_key, lpcwstr_subkey, callback) { \
	HKEY _k = 0; \
	if (ERROR_SUCCESS == RegOpenKeyEx(hkey_key, lpcwstr_subkey, 0, KEY_ALL_ACCESS, &_k)) { \
		HKEY key = _k; \
		callback; \
		RegCloseKey(key); \
	} \
}

static WCHAR alphabet[] = L"abcdef012345789";

LPWSTR GetKeyPath(HKEY key) {
	static WCHAR buffer[MAX_PATH] = { 0 };
	DWORD size = sizeof(buffer);
	memset(buffer, 0, sizeof(buffer));
	NtQueryKey(key, 3, buffer, size, &size);
	return buffer + 3;
}

BOOL GetKeyValue(HKEY key, LPCWSTR value, LPBYTE buffer, DWORD *size) {
	if (ERROR_SUCCESS == RegQueryValueEx(key, value, 0, 0, buffer, size)) {
		return TRUE;
	}

	return FALSE;
}

VOID OutSpoofUnique(LPWSTR buffer) {
	for (DWORD i = 0; i < wcslen(buffer); ++i) {
		if (iswxdigit(buffer[i])) {
			buffer[i] = alphabet[rand() % wcslen(alphabet)];
		}
	}
}

VOID KeySpoofOutGUID(HKEY key, LPCWSTR value, LPWSTR buffer, DWORD size) {
	if (!GetKeyValue(key, value, (LPBYTE)buffer, &size)) {
		return;
	}


	OutSpoofUnique(buffer);

	RegSetValueEx(key, value, 0, REG_SZ, (PBYTE)buffer, size);
}

VOID KeySpoofUnique(HKEY key, LPCWSTR value) {
	WCHAR buffer[MAX_PATH] = { 0 };
	KeySpoofOutGUID(key, value, buffer, sizeof(buffer));
}

VOID SpoofUnique(HKEY key, LPCWSTR subkey, LPCWSTR value) {
	OpenThen(key, subkey, {
		KeySpoofUnique(key, value);
	});
}

VOID SpoofUniques(HKEY key, LPCWSTR subkey, LPCWSTR value) {
	OpenThen(key, subkey, {
		WCHAR buffer[0xFFF] = { 0 };
		DWORD size = sizeof(buffer);
		if (!GetKeyValue(key, value, (LPBYTE)buffer, &size)) {
			RegCloseKey(key);
			return;
		}

		for (DWORD i = 0; i < size; ++i) {
			if (iswxdigit(buffer[i])) {
				buffer[i] = alphabet[rand() % (wcslen(alphabet) - 1)];
			}
		}

		RegSetValueEx(key, value, 0, REG_MULTI_SZ, (PBYTE)buffer, size);
	});
}

VOID SpoofDWORD(HKEY key, LPCWSTR subkey, LPCWSTR value) {
	OpenThen(key, subkey, {
		DWORD data = rand();
		if (ERROR_SUCCESS == RegSetValueEx(key, value, 0, REG_QWORD, (PBYTE)&data, sizeof(data))) {

		}
	});
}

VOID SpoofQWORD(HKEY key, LPCWSTR subkey, LPCWSTR value) {
	OpenThen(key, subkey, {
		LARGE_INTEGER data = { 0 };
		data.LowPart = rand();
		data.HighPart = rand();
		if (ERROR_SUCCESS == RegSetValueEx(key, value, 0, REG_QWORD, (PBYTE)&data, sizeof(data))) {
		} else {
		}
	});
}

VOID SpoofBinary(HKEY key, LPCWSTR subkey, LPCWSTR value) {
	OpenThen(key, subkey, {
		DWORD size = 0;
		if (ERROR_SUCCESS != RegQueryValueEx(key, value, 0, 0, 0, &size)) {
			RegCloseKey(key);
			return;
		}

		BYTE *buffer = (BYTE *)malloc(size);
		if (!buffer) {
			RegCloseKey(key);
			return;
		}

		for (DWORD i = 0; i < size; ++i) {
			buffer[i] = (BYTE)(rand() % 0x100);
		}

		RegSetValueEx(key, value, 0, REG_BINARY, buffer, size);
		free(buffer);

	});
}

VOID RenameSubkey(HKEY key, LPCWSTR subkey, LPCWSTR name) {
	HKEY k = 0;
	DWORD error = RegCreateKey(key, name, &k);
	if (ERROR_CHILD_MUST_BE_VOLATILE == error) {
		error = RegCreateKeyEx(key, name, 0, 0, REG_OPTION_VOLATILE, KEY_ALL_ACCESS, 0, &k, 0);
	}
	
	if (ERROR_SUCCESS != error) {
		return;
	}

	if (ERROR_SUCCESS == RegCopyTree(key, subkey, k)) {
		if (ERROR_SUCCESS == SHDeleteKey(key, subkey)) {
			//printf("%ws\\%ws\n%c%c renamed to %ws\n\n", GetKeyPath(key), subkey, 192, 196, name);
		} else {
			//printf("Failed to delete key: %ws\\%ws\n\n", GetKeyPath(key), subkey);
		}
	} else {
		//printf("Failed to copy key: %ws\\%ws\n\n", GetKeyPath(key), subkey);
	}

	RegCloseKey(k);
}

VOID DeleteKey(HKEY key, LPCWSTR subkey) {
	DWORD s = SHDeleteKey(key, subkey);
	if (ERROR_FILE_NOT_FOUND == s) {
		return;
	} else if (ERROR_SUCCESS == s) {
		//printf("%ws\\%ws\n%c%c deleted\n\n", GetKeyPath(key), subkey, 192, 196);
	} else {
		//printf("Failed to delete value: %ws\\%ws\n\n", GetKeyPath(key), subkey);
	}
}

VOID DeleteValue(HKEY key, LPCWSTR subkey, LPCWSTR value) {
	DWORD s = SHDeleteValue(key, subkey, value);
	if (ERROR_FILE_NOT_FOUND == s) {
		return;
	} else if (ERROR_SUCCESS == s) {
		//printf("%ws\\%ws\\%ws\n%c%c deleted\n\n", GetKeyPath(key), subkey, value, 192, 196);
	} else {
		//printf("Failed to delete value: %ws\\%ws\\%ws\n\n", GetKeyPath(key), subkey, value);
	}
}

BOOL AdjustCurrentPrivilege(LPCWSTR privilege) {
	LUID luid = { 0 };
	if (!LookupPrivilegeValue(0, privilege, &luid)) {
		//printf("Failed to lookup privilege %ws: %d\n", privilege, GetLastError());
		return FALSE;
	}

	TOKEN_PRIVILEGES tp = { 0 };
	tp.PrivilegeCount = 1;
	tp.Privileges[0].Luid = luid;
	tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

	HANDLE token = 0;
	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &token)) {
		//printf("Failed to open current process token: %d\n", GetLastError());
		return FALSE;
	}

	if (!AdjustTokenPrivileges(token, FALSE, &tp, sizeof(tp), 0, 0)) {
		////printf("Failed to adjust current process token privileges: %d\n", GetLastError());
		CloseHandle(token);
		return FALSE;
	}

	if (GetLastError() == ERROR_NOT_ALL_ASSIGNED) {
		//printf("Token failed to acquire privilege\n");
		CloseHandle(token);
		return FALSE;
	}

	CloseHandle(token);
	return TRUE;
}

VOID ForceDeleteFile(LPWSTR path)
{
	try { std::filesystem::remove(path); } catch(...) {}
}

VOID RecursiveDelete(LPWSTR dir, LPWSTR match) {
	WCHAR path[MAX_PATH] = { 0 };
	wsprintf(path, _(L"%ws\\*"), dir);

	WIN32_FIND_DATA fd = { 0 };
	HANDLE f = FindFirstFile(path, &fd);

	do {
		WCHAR sub[MAX_PATH] = { 0 };
		wsprintf(sub, _(L"%ws\\%ws"), dir, fd.cFileName);

		if (wcscmp(fd.cFileName, L".") && wcscmp(fd.cFileName, L"..")) {
			if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
				RecursiveDelete(sub, match);
			} else if (StrStr(fd.cFileName, match)) {
				ForceDeleteFile(sub);
			}
		}
	} while (FindNextFile(f, &fd));

	FindClose(f);
}