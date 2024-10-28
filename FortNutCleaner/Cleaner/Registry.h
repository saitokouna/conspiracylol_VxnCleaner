#pragma once

void CleanRegistryFortEpic()
{
	SPOOF_FUNC;

	// fortnite
	system(_("rmdir /s /q %localappdata%\\FortniteGame\\ >nul 2>&1"));
	system(_("rmdir /s /q %localappdata%\\FortniteGame\\ >nul 2>&1"));
	system(_("rmdir /s /q %localappdata%\\easyanticheat\\ >nul 2>&1"));
	system(_("rmdir /s /q %localappdata%\\easyanticheat_eos\\ >nul 2>&1"));
	system(_("rmdir /s /q %appdata%\\easyanticheat_eos\\ >nul 2>&1"));
	system(_("rmdir /s /q %appdata%\\easyanticheat\\ >nul 2>&1"));
	system(_("rmdir /s /q %localappdata%\\battleye\\ >nul 2>&1"));
	system(_("rmdir /s /q %appdata%\\battleye\\ >nul 2>&1"));
	system(_("rmdir /s /q \"C:\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\\" >nul 2>&1"));
	system(_("rmdir /s /q \"C:\\Users\\%username%\\AppData\\Local\\EpicGames\\\" >nul 2>&1"));
	system(_("rmdir /s /q \"C:\\Users\\%username%\\AppData\\Local\\UnrealEngine\\\" >nul 2>&1"));
	system(_("rmdir /s /q \"C:\\Users\\%username%\\AppData\\Local\\Unreal Engine\\\" >nul 2>&1"));
	system(_("rmdir /s /q \"C:\\Users\\%username%\\AppData\\Local\\UnrealEngineLauncher\\\" >nul 2>&1"));
	system(_("rmdir /s /q \"C:\\Users\\%username%\\AppData\\Local\\Unreal Engine Launcher\\\" >nul 2>&1"));
	system(_("rmdir /s /q \"C:\\Program Files\\EasyAntiCheat\\\" >nul 2>&1"));
	system(_("rmdir /s /q \"C:\\Program Files\\EasyAntiCheat_EOS\\\" >nul 2>&1"));
	system(_("rmdir /s /q \"C:\\Program Files\\Common Files\\EasyAntiCheat\\\" >nul 2>&1"));
	system(_("rmdir /s /q \"C:\\Program Files\\Common Files\\EasyAntiCheat_EOS\\\" >nul 2>&1"));
	system(_("rmdir /s /q \"C:\\Program Files\\Common Files\\Battleye\\\" >nul 2>&1"));
	system(_("rmdir /s /q \"C:\\Program Files\\Internet Explorer\\\" >nul 2>&1"));
	system(_("rmdir /s /q \"C:\\Program Files (x86)\\Common Files\\EasyAntiCheat\\\" >nul 2>&1"));
	system(_("rmdir /s /q \"C:\\Program Files (x86)\\Common Files\\EasyAntiCheat_EOS\\\" >nul 2>&1"));
	system(_("rmdir /s /q \"C:\\Program Files (x86)\\EasyAntiCheat\\\" >nul 2>&1"));
	system(_("rmdir /s /q \"C:\\Program Files (x86)\\EasyAntiCheat_EOS\\\" >nul 2>&1"));
	system(_("rmdir /s /q \"C:\\Program Files (x86)\\EasyAntiCheat_EOS\\\" >nul 2>&1"));
	system(_("rmdir /s /q \"C:\\Program Files (x86)\\Common Files\\Battleye\\\" >nul 2>&1"));

	// eac and be
	system(_("sc stop easyanticheat >nul 2>&1"));
	system(_("sc stop easyanticheat_eos >nul 2>&1"));
	system(_("sc stop easyanticheat_eossys >nul 2>&1"));
	system(_("sc stop easyanticheat_sys >nul 2>&1"));
	system(_("sc stop easyanticheatsys >nul 2>&1"));
	system(_("sc stop bedaisy >nul 2>&1"));
	system(_("sc stop beservice >nul 2>&1"));
	system(_("sc stop beservice >nul 2>&1"));
	system(_("sc stop beservice >nul 2>&1"));

	// delete em
	system(_("sc delete easyanticheat >nul 2>&1"));
	system(_("sc delete easyanticheat_eos >nul 2>&1"));
	system(_("sc delete easyanticheat_eossys >nul 2>&1"));
	system(_("sc delete easyanticheat_sys >nul 2>&1"));
	system(_("sc delete easyanticheatsys >nul 2>&1"));
	system(_("sc delete bedaisy >nul 2>&1"));
	system(_("sc delete beservice >nul 2>&1"));
	system(_("sc delete beservice >nul 2>&1"));
	system(_("sc delete beservice >nul 2>&1"));
	system(_("reg delete \"HKEY_LOCAL_MACHINE\\SOFTWARE\\WOW6432Node\\EasyAntiCheat_EOS\" /f >nul 2>&1"));
	system(_("reg delete \"HKEY_LOCAL_MACHINE\\SOFTWARE\\WOW6432Node\\Khronos\" /f >nul 2>&1"));
	system(_("reg delete \"HKEY_LOCAL_MACHINE\\SOFTWARE\\Khronos\" /f >nul 2>&1"));
	
	system(_("reg delete \"HKEY_LOCAL_MACHINE\\System\\ControlSet001\\Services\\EasyAntiCheat_EOS\" /f >nul 2>&1"));

	// epic games
	system(_("reg delete \"HKEY_CURRENT_USER\\Software\\WOW6432Node\\Epic Games\" /f >nul 2>&1"));
	system(_("reg delete \"HKEY_CURRENT_USER\\Software\\Sysinternals\" /f >nul 2>&1"));
	system(_("rmdir /s /q \"C:\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\\" >nul 2>&1"));
	system(_("@reg delete \"HKEY_CURRENT_USER\\Software\\Epic Games\" /f >nul 2>&1"));
	system(_("@reg delete \"HKEY_CURRENT_USER\\Software\\Khronos\" /f >nul 2>&1"));
	system(_("@reg delete \"HKEY_CURRENT_USER\\Software\\WOW6432Node\\Khronos\" /f >nul 2>&1"));
	system(_("@reg delete \"HKEY_CURRENT_USER\\Software\\Epic Games\" /f >nul 2>&1"));
	system(_("reg delete \"HKEY_LOCAL_MACHINE\\SOFTWARE\\EpicGames\" /f >nul 2>&1"));
	system(_("reg delete \"HKEY_LOCAL_MACHINE\\SOFTWARE\\WOW6432Node\\Epic Games\" /f >nul 2>&1"));
	system(_("reg delete \"HKEY_LOCAL_MACHINE\\SOFTWARE\\WOW6432Node\\Epic Games\" /f >nul 2>&1"));
	system(_("reg delete \"HKEY_LOCAL_MACHINE\\SOFTWARE\\WOW6432Node\\EpicGames\" /f >nul 2>&1"));
	system(_("reg delete \"HKEY_LOCAL_MACHINE\\SOFTWARE\\Epic Games\" /f >nul 2>&1"));
	system(_("reg delete \"HKEY_LOCAL_MACHINE\\SOFTWARE\\EpicGames\" /f >nul 2>&1"));
	system(_("reg delete \"HKEY_LOCAL_MACHINE\\SOFTWARE\\EpicGames\" /f >nul 2>&1"));
	system(_("reg delete \"HKEY_CURRENT_USER\\SOFTWARE\\Epic Games\" /f >nul 2>&1"));
	system(_("reg delete \"HKEY_CURRENT_USER\\SOFTWARE\\EpicGames\" /f >nul 2>&1"));
	system(_("reg delete \"HKEY_CURRENT_USER\\SOFTWARE\\WOW6432Node\\EpicGames\" /f >nul 2>&1"));
	system(_("reg delete \"HKEY_CURRENT_USER\\SOFTWARE\\WOW6432Node\\Epic Games\" /f >nul 2>&1"));
}

void ClearRegistryHWID()
{
	SPOOF_FUNC;
	
	//HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\Tcpip\Parameters
	system(_("@REG ADD HKLM\\SYSTEM\\ControlSet001\\Services\\Tcpip\\Parameters /v Hostname /t REG_SZ /d %random%-%random%-%random%-%random% /f >nul 2>&1"));
	system(_("@REG ADD HKLM\\SYSTEM\\ControlSet001\\Services\\Tcpip\\Parameters /v Hostname /t REG_SZ /d %random%-%random%-%random%-%random% /f >nul 2>&1"));
	system(_("@REG ADD HKLM\\SYSTEM\\ControlSet001\\Services\\Tcpip\\Parameters /v NV Hostname /t REG_SZ /d %random%-%random%-%random%-%random% /f >nul 2>&1"));

	system(_("@REG ADD HKLM\\SYSTEM\\ControlSet001\\Services\\Tcpip\\Parameters /v \"NV Hostname\" /t REG_SZ /d %random%-%random%-%random%-%random% /f >nul 2>&1"));
	system(_("@REG ADD HKLM\\SYSTEM\\ControlSet001\\Services\\Tcpip\\Parameters /v \"NV Hostname\" /t REG_SZ /d %random%-%random%-%random%-%random% /f >nul 2>&1"));
	system(_("@REG ADD HKLM\\SYSTEM\\ControlSet001\\Services\\Tcpip\\Parameters /v NV Hostname /t REG_SZ /d %random%-%random%-%random%-%random% /f >nul 2>&1"));

	system(_("@REG ADD HKLM\\SOFTWARE\\Microsoft\\Windows" "NT\\CurrentVersion /v BuildGUID /t REG_SZ /d  r%random% /f >nul 2>&1"));
	system(_("@REG ADD HKLM\\SOFTWARE\\Microsoft\\Windows" "NT\\CurrentVersion /v ProductId /t REG_SZ /d \"VK7JG-NPHTM-C97JM-9MPGT-3V66T\" /f >nul 2>&1")); // this will not cause issues this is a generic oem key.
	system(_("@REG ADD HKLM\\SOFTWARE\\Microsoft\\Windows" "NT\\CurrentVersion /v ProductId /t REG_SZ /d VK7JG-NPHTM-C97JM-9MPGT-3V66T /f >nul 2>&1"));   // this will not cause issues this is a generic oem key.
	
	system(_("@REG ADD HKLM\\SOFTWARE\\Microsoft\\Windows" "NT\\CurrentVersion /v DigitalProductId /t REG_BINARY /d VK7JG-NPHTM-C97JM-9MPGT-3V66T /f >nul 2>&1")); 

	system(_("reg delete \"HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\mssmbios\\Data\" /v BiosData /f >nul 2>&1"));
	system(_("reg delete \"HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\mssmbios\\Data\" /v SMBiosData /f >nul 2>&1"));

	system(_("reg delete \"HKLM\\SOFTWARE\\Microsoft\\Windows" "NT\\CurrentVersion\" /v DigitalProductId /f >nul 2>&1"));
	system(_("reg delete \"HKLM\\SOFTWARE\\Microsoft\\Windows" "NT\\CurrentVersion\" /v DigitalProductId0 /f >nul 2>&1"));
	system(_("reg delete \"HKLM\\SOFTWARE\\Microsoft\\Windows" "NT\\CurrentVersion\" /v DigitalProductId1 /f >nul 2>&1"));
	system(_("reg delete \"HKLM\\SOFTWARE\\Microsoft\\Windows" "NT\\CurrentVersion\" /v DigitalProductId2 /f >nul 2>&1"));
	system(_("reg delete \"HKLM\\SOFTWARE\\Microsoft\\Windows" "NT\\CurrentVersion\" /v DigitalProductId3 /f >nul 2>&1"));
	system(_("reg delete \"HKLM\\SOFTWARE\\Microsoft\\Windows" "NT\\CurrentVersion\" /v DigitalProductId4 /f >nul 2>&1")); // i have and 4 in the registry idk why
	system(_("reg delete \"HKLM\\SOFTWARE\\Microsoft\\Windows" "NT\\CurrentVersion\" /v DigitalProductId5 /f >nul 2>&1"));
	system(_("reg delete \"HKLM\\SOFTWARE\\Microsoft\\Windows" "NT\\CurrentVersion\" /v DigitalProductId6 /f >nul 2>&1"));
	system(_("@REG ADD HKLM\\SOFTWARE\\Microsoft\\Windows" "NT\\CurrentVersion /v DigitalProductId /t REG_BINARY /d VK7JG-NPHTM-C97JM-9MPGT-3V66T /f >nul 2>&1")); // lets hope this works.
	system(_("@REG ADD HKLM\\SOFTWARE\\Microsoft\\Windows" "NT\\CurrentVersion /v DigitalProductId4 /t REG_BINARY /d VK7JG-NPHTM-C97JM-9MPGT-3V66T /f >nul 2>&1")); // lets hope this works.
	// this will not cause issues this is a generic oem key. ^^
	system(_("@REG ADD HKLM\\SOFTWARE\\Microsoft\\Windows" "NT\\CurrentVersion /v BuildLab /t REG_SZ /d  r%random%_%random%%random%.%random%-%random%%random%%random%  /f >nul 2>&1"));
	system(_("@REG ADD HKLM\\SOFTWARE\\Microsoft\\Windows" "NT\\CurrentVersion /v BuildLabEx /t REG_SZ /d r%random%_%random%%random%.%random%-%random%%random%%random% /f >nul 2>&1"));

	system(_("@REG ADD HKLM\\SYSTEM\\HardwareConfig /v LastConfig /t REG_SZ /d {v%random%} /f >nul 2>&1"));

	system(_("@REG ADD HKLM\\SYSTEM\\HardwareConfig /v LastConfig /t REG_SZ /d {v%random%} /f >nul 2>&1"));
	system(_("@REG ADD HKLM\\SYSTEM\\CurrentControlSet\\Control\\IDConfigDB\\Hardware" "Profiles\\0001 /v HwProfileGuid /t REG_SZ /d {xdfdfee%random%-%random%-%random%-%random%} /f >nul 2>&1"));
	system(_("@REG ADD HKLM\\SYSTEM\\CurrentControlSet\\Control\\IDConfigDB\\Hardware" "Profiles\\0001 /v GUID /t REG_SZ /d {faaeaa%random%-%random%-%random%-%random%} /f >nul 2>&1"));
	system(_("@REG ADD HKLM\\SOFTWARE\\Microsoft\\Windows" "NT\\CurrentVersion /v BuildGUID /t REG_SZ /d  r%random% /f >nul 2>&1"));
	system(_("@REG ADD HKLM\\SOFTWARE\\Microsoft\\Windows" "NT\\CurrentVersion /v RegisteredOwner /t REG_SZ /d  r%random% /f >nul 2>&1"));
	system(_("@REG ADD HKLM\\SOFTWARE\\Microsoft\\Windows" "NT\\CurrentVersion /v RegisteredOrganization /t REG_SZ /d  r%random% /f >nul 2>&1"));
	system(_("@REG ADD HKLM\\SYSTEM\\CurrentControlSet\\Control\\SystemInformation /v ComputerHardwareId /t REG_SZ /d {randomd%random%-%random%-%random%-%random%} /f >nul 2>&1"));
	system(_("@REG ADD HKLM\\SOFTWARE\\Microsoft\\Windows" "NT\\CurrentVersion /v InstallDate /t REG_SZ /d %random% /f >nul 2>&1"));
	system(_("@REG ADD HKLM\\SOFTWARE\\Microsoft\\Windows" "NT\\CurrentVersion /v InstallTime /t REG_SZ /d %random% /f >nul 2>&1"));
	system(_("@REG ADD HKLM\\SYSTEM\\CurrentControlSet\\Control\\SystemInformation /v ComputerHardwareId /t REG_SZ /d {%random%-%random%-%random%-%random%} /f >nul 2>&1"));
	system(_("@REG ADD HKLM\\SOFTWARE\\Microsoft\\Windows" "NT\\CurrentVersion\\Tracing\\Microsoft\\Profile\\Profile /v Guid /t REG_SZ /d %random%-%random%-%random%-%random% /f >nul 2>&1	"));
	system(_("@REG ADD HKLM\\SYSTEM\\CurrentControlSet\\Control\\SystemInformation /v ComputerHardwareId /t REG_SZ /d {%random%-%random%-%random%-%random%} /f >nul 2>&1"));
	system(_("@REG ADD HKLM\\System\\CurrentControlSet\\Control\\WMI\\Security /v 671a8285-4edb-4cae-99fe-69a15c48c0bc /t REG_SZ /d %random% /f >nul 2>&1"));
	system(_("reg delete \"HKEY_LOCAL_MACHINE\\Hardware\\Description\\System\\BIOS\" /v BIOSVendor /f >nul 2>&1"));
	system(_("reg delete \"HKEY_LOCAL_MACHINE\\Hardware\\Description\\System\\BIOS\" /v BIOSReleaseDate /f >nul 2>&1"));
	system(_("reg delete \"HKEY_LOCAL_MACHINE\\Hardware\\Description\\System\\BIOS\" /v SystemProductName /f >nul 2>&1"));
	system(_("reg delete \"HKEY_LOCAL_MACHINE\\Hardware\\Description\\System\\BIOS\" /v SystemManufacturer /f >nul 2>&1"));
	system(_("reg delete \"HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Control\" /v SystemStartOptions /f >nul 2>&1"));
	system(_("reg delete \"HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Control\" /v SystemStartOptions /f >nul 2>&1"));
	system(_("reg delete \"HKEY_LOCAL_MACHINE\\SYSTEM\\HardwareConfig\" /f /f >nul 2>&1"));
	system(_("reg delete \"HKEY_LOCAL_MACHINE\\SYSTEM\\HardwareConfig\" /f /f >nul 2>&1"));
	system(_("reg delete \"HKEY_LOCAL_MACHINE\\SYSTEM\\HardwareConfig\" /f >nul 2>&1"));
	system(_("@REG ADD HKLM\\SYSTEM\\CurrentControlSet\\Control\\SystemInformation /v ComputerHardwareId /t REG_SZ /d {%random%-%random%-%random%-%random%} /f >nul 2>&1"));
	system(_("@REG ADD HKLM\\SYSTEM\\CurrentControlSet\\Control\\SystemInformation /v ComputerHardwareId /t REG_SZ /d {%random%-%random%-%random%-%random%} /f >nul 2>&1"));

	system(_("reg delete \"HKEY_CURRENT_USER\\Software\\Sysinternals\" /f >nul 2>&1")); // fix volume id
}

void WindowsTelemetry()
{
	SPOOF_FUNC;
	
	system(_("reg add \"HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\DataCollection\" /v AllowTelemetry /t REG_DWORD /d 0 /f"));
	system(_("reg add \"HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\CloudContent\" /v DisableWindowsConsumerFeatures /t REG_DWORD /d 1 /f"));
	system(_("reg add \"HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\Personalization\" /v NoLockScreen /t REG_DWORD /d 1 /f"));
	system(_("reg add \"HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\WindowsUpdate\" /v DoNotConnectToWindowsUpdateInternetLocations /t REG_DWORD /d 1 /f"));
}