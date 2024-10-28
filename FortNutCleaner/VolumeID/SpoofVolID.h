#pragma once
#include "./Bytes/VolumeID64.h"

bool DropVolumeID64(std::string path)
{
	HANDLE h_file;
	BOOLEAN b_status = FALSE;
	DWORD byte = 0;

	h_file = CreateFileA(path.c_str(), GENERIC_ALL, NULL, NULL, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, NULL);
	if (GetLastError() == ERROR_FILE_EXISTS)
	{
		return true;
	}

	if (h_file == INVALID_HANDLE_VALUE)
		return false;

	b_status = WriteFile(h_file, VolumeID64_Bytes, sizeof(VolumeID64_Bytes), &byte, nullptr);
	CloseHandle(h_file);

	if (!b_status)
		return false;

	return true;
}

std::string RandomHexString(size_t length = 4)
{
    auto randchar = []() -> char
        {
			const char charset[] =
				"0123456789"
				"ABCDEF";
            const size_t max_index = (sizeof(charset) - 1);
            return charset[rand() % max_index];
        };
    std::string str(length, 0);
    std::generate_n(str.begin(), length, randchar);
    return str;
}

bool SpoofVolumeID()
{
	if (!DropVolumeID64(_("C:\\Windows\\System32\\VolumeID.exe").decrypt())) return false;
	auto Command = _("start /MIN \"\" \"C:\\Windows\\System32\\VolumeID.exe\" -nobanner /accepteula C: ");
	std::string VolumeID = RandomHexString() + _("-").decrypt() + RandomHexString();
	std::string FinalCommand = Command.decrypt() + VolumeID;
	system(FinalCommand.c_str());

	Sleep(2000);

	ClearConsole();
	Watermark();
	ColorCyan();

	system(_("del /F \"C:\\Windows\\System32\\VolumeID.exe\" >nul 2>&1").decrypt());

	return true;
}