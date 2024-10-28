#include "./util.h"


void InitSpoofUtil()
{
	if (!NtQueryKey)
	{
		NtQueryKey = (NTQK)GetProcAddress(GetModuleHandleA(_("ntdll.dll")), _("NtQueryKey"));
	}

}

int SpoofMonitors()
{
	SPOOF_FUNC;

	InitSpoofUtil();

	// Monitors
	OpenThen(HKEY_LOCAL_MACHINE, _(L"SYSTEM\\CurrentControlSet\\Enum\\DISPLAY").decrypt(), {
		ForEachSubkey(key, {
			OpenThen(key, name, {
				ForEachSubkey(key, {
					OpenThen(key, name, {
						ForEachSubkey(key, {
							if (_wcsicmp(name, _(L"device parameters").decrypt()) == 0) {
								SpoofBinary(key, name, _(L"EDID").decrypt());
								break;
							}
						});
					});
				});
			});
		});
	});

	return 1;
}

void FixNetworking()
{
	/*
	arp -a >nul 2>&1
	arp -d >nul 2>&1
	*/

	system(_("arp -a >nul 2>&1"));
	system(_("arp -d >nul 2>&1"));
	system(_("arp -a >nul 2>&1"));
	system(_("wmic path Win32_PNPEntity where \"caption like \'%bluetooth%\' AND DeviceID like \'USB\\%\'\" call disable >nul 2>&1"));
	system(_("WMIC PATH WIN32_NETWORKADAPTER WHERE PHYSICALADAPTER=TRUE CALL DISABLE >nul 2>&1"));
	system(_("WMIC PATH WIN32_NETWORKADAPTER WHERE PHYSICALADAPTER=TRUE CALL ENABLE >nul 2>&1"));
	system(_("NETSH WINSOCK RESET >nul 2>&1"));
	system(_("NETSH INT IP RESET >nul 2>&1"));
	system(_("netsh advfirewall reset >nul 2>&1"));
	system(_("NETSH INTERFACE IPV4 RESET >nul 2>&1"));
	system(_("NETSH INTERFACE IPV6 RESET >nul 2>&1"));
	system(_("NETSH INTERFACE TCP RESET >nul 2>&1"));
	system(_("NETSH INT RESET ALL >nul 2>&1"));
	system(_("IPCONFIG /RELEASE >nul 2>&1"));
	system(_("IPCONFIG /RELEASE >nul 2>&1"));
	system(_("IPCONFIG /FLUSHDNS >nul 2>&1"));
	system(_("NBTSTAT -R >nul 2>&1"));
	system(_("NBTSTAT -RR >nul 2>&1"));
	system(_("IPCONFIG /FLUSHDNS >nul 2>&1"));

	/*
	* 
	wmic path Win32_PNPEntity where "caption like '%bluetooth%' AND DeviceID like 'USB\\%'" call disable >nul 2>&1
	NETSH WINSOCK RESET >nul 2>&1
	NETSH INT IP RESET >nul 2>&1
	netsh advfirewall reset >nul 2>&1
	NETSH INTERFACE IPV4 RESET >nul 2>&1
	NETSH INTERFACE IPV6 RESET >nul 2>&1
	NETSH INTERFACE TCP RESET >nul 2>&1
	NETSH INT RESET ALL >nul 2>&1
	IPCONFIG /RELEASE >nul 2>&1
	IPCONFIG /RELEASE >nul 2>&1
	IPCONFIG /FLUSHDNS >nul 2>&1
	NBTSTAT -R >nul 2>&1
	NBTSTAT -RR >nul 2>&1
	*/

	system(_("wmic path Win32_PNPEntity where \"caption like \'%bluetooth%\' AND DeviceID like \'USB\\%\'\" call disable >nul 2>&1"));
	
	OpenThen(HKEY_LOCAL_MACHINE, _(L"SYSTEM\\ControlSet001\\Control\\Class\\{4d36e972-e325-11ce-bfc1-08002be10318}").decrypt(),
	{
			ForEachSubkey(key,
			{
				OpenThen(key, name,
				{
					if (_wcsicmp(name, _(L"NetworkInterfaceInstallTimestamp").decrypt()) == 0)
					{
						SpoofBinary(key, name, _(L"NetworkInterfaceInstallTimestamp").decrypt());
					}
					
					if (_wcsicmp(name, _(L"InstallTimeStamp").decrypt()) == 0)
					{
						SpoofQWORD(key, name, _(L"InstallTimeStamp").decrypt());
					}

					break;
				}
			});
	}));

	OpenThen(HKEY_LOCAL_MACHINE, _(L"SYSTEM\\ControlSet001\\Control\\Class\\{4d36e972-e325-11ce-bfc1-08002be10318}").decrypt(),
	{
				ForEachSubkey(key,
				{
					OpenThen(key, name,
					{
						if (_wcsicmp(name, _(L"NetworkInterfaceInstallTimestamp").decrypt()) == 0)
						{
							SpoofBinary(key, name, _(L"NetworkInterfaceInstallTimestamp").decrypt());
						}

						if (_wcsicmp(name, _(L"InstallTimeStamp").decrypt()) == 0)
						{
							SpoofQWORD(key, name, _(L"InstallTimeStamp").decrypt());
						}

						break;
					}
				});
	}));

	//HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Control\Class\
	
// // yea

	// changed
	OpenThen(HKEY_LOCAL_MACHINE, _(L"SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters\\DNSRegisteredAdapters").decrypt(),
	{
		ForEachSubkey(key,
		{
			OpenThen(key, name,
			{
				SpoofBinary(key, name, _(L"Hostname").decrypt());
				break;
			}
		});
	}));

	OpenThen(HKEY_LOCAL_MACHINE, _(L"SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters\\Interfaces").decrypt(),
	{
		ForEachSubkey(key,
		{
			OpenThen(key, name,
			{
				if (_wcsicmp(name, _(L"DhcpNetworkHint").decrypt()) == 0)
				{

					SpoofBinary(key, name, _(L"DhcpNetworkHint").decrypt());
						break;
				}

				if (_wcsicmp(name, _(L"DhcpGatewayHardware").decrypt()) == 0)
				{

					SpoofBinary(key, name, _(L"DhcpGatewayHardware").decrypt());
					break;
				}
			});

			OpenThen(key, name,
				{
					if (_wcsicmp(name, _(L"DhcpNetworkHint").decrypt()) == 0)
					{

						SpoofBinary(key, name, _(L"DhcpNetworkHint").decrypt());
							break;
					}

					/*if (_wcsicmp(name, _(L"DhcpGatewayHardware").decrypt()) == 0)
					{

						SpoofBinary(key, name, _(L"DhcpGatewayHardware").decrypt());
						break;
					}*/
				});
		}));
	}

	SpoofBinary(HKEY_LOCAL_MACHINE, _(L"SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters\\Winsock"), _(L"ProviderGUID"));
	SpoofBinary(HKEY_LOCAL_MACHINE, _(L"SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters"), _(L"Dhcpv6DUID"));

}


void SpoofCleanGPU()
{
	SPOOF_FUNC;

	// NVIDIA
	SpoofUnique(HKEY_LOCAL_MACHINE, _(L"SOFTWARE\\NVIDIA Corporation\\Global").decrypt(), _(L"ClientUUID").decrypt());
	SpoofUnique(HKEY_LOCAL_MACHINE, _(L"SOFTWARE\\NVIDIA Corporation\\Global").decrypt(), _(L"PersistenceIdentifier").decrypt());
	SpoofUnique(HKEY_LOCAL_MACHINE, _(L"SOFTWARE\\NVIDIA Corporation\\Global\\CoProcManager").decrypt(), _(L"ChipsetMatchID").decrypt());
}

void CleanOtherAppsAndMoreMisc()
{
	SPOOF_FUNC;

	DeleteKey(HKEY_LOCAL_MACHINE, _(L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Diagnostics\\DiagTrack\\SettingsRequests"));
	SpoofQWORD(HKEY_LOCAL_MACHINE, _(L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Diagnostics\\DiagTrack\\SevilleEventlogManager"), _(L"LastEventlogWrittenTime"));
	SpoofQWORD(HKEY_LOCAL_MACHINE, _(L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\SoftwareProtectionPlatform\\Activation"), _(L"ProductActivationTime"));
	DeleteValue(HKEY_LOCAL_MACHINE, _(L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\SoftwareProtectionPlatform"), _(L"BackupProductKeyDefault"));
	DeleteValue(HKEY_LOCAL_MACHINE, _(L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\SoftwareProtectionPlatform"), _(L"actionlist"));
	DeleteValue(HKEY_LOCAL_MACHINE, _(L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\SoftwareProtectionPlatform"), _(L"ServiceSessionId"));
	DeleteKey(HKEY_CURRENT_USER, _(L"Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\UserAssist"));
	DeleteKey(HKEY_CURRENT_USER, _(L"Software\\Hex-Rays\\IDA\\History")); // you're welcome!
	DeleteKey(HKEY_CURRENT_USER, _(L"Software\\Hex-Rays\\IDA\\History64")); // you're welcome!
	DeleteKey(HKEY_CURRENT_USER, _(L"Software\\Microsoft\\VisualStudio\\Telemetry\\PersistentPropertyBag")); // you're welcome! (hard ban fix im pretty sure)

}

void CleanSMBiosAndMisc()
{
	SPOOF_FUNC;

	// SMBIOS
	DeleteValue(HKEY_LOCAL_MACHINE, _(L"SYSTEM\\CurrentControlSet\\Services\\mssmbios\\Data"), _(L"SMBiosData"));

	// Misc
	//DeleteKey(HKEY_LOCAL_MACHINE, _(L"SYSTEM\\MountedDevices"));
	/*DeleteKey(HKEY_LOCAL_MACHINE, _(L"SOFTWARE\\Microsoft\\Dfrg\\Statistics"));
	DeleteKey(HKEY_CURRENT_USER, _(L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\BitBucket\\Volume"));
	DeleteKey(HKEY_CURRENT_USER, _(L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\MountPoints2\\CPC\\Volume"));
	DeleteKey(HKEY_CURRENT_USER, _(L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\MountPoints2"));
	DeleteValue(HKEY_CURRENT_USER, _(L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\BitBucket"), _(L"LastEnum"));
	*/

	SpoofBinary(HKEY_LOCAL_MACHINE, _(L"SYSTEM\\CurrentControlSet\\Services\\TPM\\WMI"), _(L"WindowsAIKHash"));
}

void FixDiskTraces()
{

	SPOOF_FUNC;

	
	OpenThen(HKEY_LOCAL_MACHINE, _(L"HARDWARE\\DEVICEMAP\\Scsi"), {
		ForEachSubkey(key, {
			OpenThen(key, name, {
				ForEachSubkey(key, {
					OpenThen(key, name, {
						ForEachSubkey(key, {
							if (wcsstr(name, _(L"arget"))) { // weird ass way of finding but it works
								OpenThen(key, name, {
									ForEachSubkey(key, {
										SpoofUnique(key, name, _(L"Identifier"));
									});
								});
							}
						});
					});
				});
			});
		});
	});
	

	// Misc -> kind of disk related I suppose
	//DeleteKey(HKEY_LOCAL_MACHINE, _(L"SYSTEM\\MountedDevices"));
	DeleteKey(HKEY_LOCAL_MACHINE, _(L"SOFTWARE\\Microsoft\\Dfrg\\Statistics"));
	//DeleteKey(HKEY_CURRENT_USER, _(L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\BitBucket\\Volume"));
	//DeleteKey(HKEY_CURRENT_USER, _(L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\MountPoints2\\CPC\\Volume"));
	//DeleteKey(HKEY_CURRENT_USER, _(L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\MountPoints2"));
	//DeleteValue(HKEY_CURRENT_USER, _(L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\BitBucket"), _(L"LastEnum"));


	/*
	OpenThen(HKEY_LOCAL_MACHINE, _(L"HARDWARE\\DESCRIPTION\\System\\MultifunctionAdapter\\0\\DiskController\\0\\DiskPeripheral"), {
		ForEachSubkey(key, {
			SpoofUnique(key, name, _(L"Identifier"));
		});
	});*/

	SpoofBinary(HKEY_LOCAL_MACHINE, _(L"SYSTEM\\CurrentControlSet\\Services\\TPM\\ODUID"), _(L"RandomSeed")); // tpm is also important i guess
	SpoofUnique(HKEY_LOCAL_MACHINE, _(L"SOFTWARE\\Microsoft\\Cryptography"), _(L"MachineGuid"));
	//SpoofUnique(HKEY_LOCAL_MACHINE, _(L"SYSTEM\\CurrentControlSet\\Control\\IDConfigDB\\Hardware Profiles\\0001"), _(L"HwProfileGuid"));

}

void BasicWindowsSpoof()
{
	// TODO: %windir%\system32\spp\tokens -> found in HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SoftwareProtectionPlatform\Setup\LicenseFolders
	//system(_("vssadmin delete shadows /All /Quiet >nul 2>&1").decrypt());
	system(_("taskkill /im WmiPrv* /f /t >nul 2>&1").decrypt()); // you're a dumb chink nigga

	SpoofUnique(HKEY_LOCAL_MACHINE, _(L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\WindowsUpdate"), _(L"PingID"));
	SpoofUnique(HKEY_LOCAL_MACHINE, _(L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\WindowsUpdate"), _(L"SusClientId"));
	SpoofBinary(HKEY_LOCAL_MACHINE, _(L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\WindowsUpdate"), _(L"SusClientIdValidation"));
	SpoofBinary(HKEY_LOCAL_MACHINE, _(L"SYSTEM\\CurrentControlSet\\Services\\Tcpip6\\Parameters"), _(L"Dhcpv6DUID"));
	SpoofUnique(HKEY_LOCAL_MACHINE, _(L"SYSTEM\\CurrentControlSet\\Control\\SystemInformation"), _(L"ComputerHardwareId"));
	SpoofUniques(HKEY_LOCAL_MACHINE, _(L"SYSTEM\\CurrentControlSet\\Control\\SystemInformation"), _(L"ComputerHardwareIds"));
	SpoofUnique(HKEY_LOCAL_MACHINE, _(L"SOFTWARE\\Microsoft\\SQMClient"), _(L"MachineId"));
	SpoofQWORD(HKEY_LOCAL_MACHINE, _(L"SOFTWARE\\Microsoft\\SQMClient"), _(L"WinSqmFirstSessionStartTime"));
	SpoofQWORD(HKEY_LOCAL_MACHINE, _(L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion"), _(L"InstallTime"));
	SpoofQWORD(HKEY_LOCAL_MACHINE, _(L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion"), _(L"InstallDate"));
	//SpoofBinary(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion", _(L"DigitalProductId")); // i handle this elsewhere
	//SpoofBinary(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion", _(L"DigitalProductId4")); // i handle this elsewhere

	SpoofBinary(HKEY_LOCAL_MACHINE, _(L"SYSTEM\\CurrentControlSet\\Services\\TPM\\WMI"), _(L"WindowsAIKHash")); // tpm real

	SpoofUnique(HKEY_LOCAL_MACHINE, _(L"SYSTEM\\CurrentControlSet\\Services\\ACPI\\Parameters"), _(L"WppRecorder_TraceGuid"));
	SpoofBinary(HKEY_LOCAL_MACHINE, _(L"SYSTEM\\CurrentControlSet\\Services\\ACPI\\Parameters"), _(L"Dhcpv6DUID"));
	SpoofUnique(HKEY_LOCAL_MACHINE, _(L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\WindowsUpdate"), _(L"SusClientId"));

	/*SpoofUnique(HKEY_LOCAL_MACHINE, _(L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion"), _(L"BuildGUID"));
	SpoofUnique(HKEY_LOCAL_MACHINE, _(L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion"), _(L"ProductId"));
	SpoofUnique(HKEY_LOCAL_MACHINE, _(L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion"), _(L"BuildLab"));
	SpoofUnique(HKEY_LOCAL_MACHINE, _(L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion"), _(L"BuildLabEx"));*/
	//SpoofUnique(HKEY_LOCAL_MACHINE, _(L"SYSTEM\\CurrentControlSet\\Control\\Class\\{4d36e968-e325-11ce-bfc1-08002be10318}\\0000"), _(L"_DriverProviderInfo"));
	//SpoofUnique(HKEY_LOCAL_MACHINE, _(L"SYSTEM\\CurrentControlSet\\Control\\Class\\{4d36e968-e325-11ce-bfc1-08002be10318}\\0000"), _(L"UserModeDriverGUID"));
	
	CleanOtherAppsAndMoreMisc();

	system(_("taskkill /im WmiPrv* /f /t >nul 2>&1").decrypt()); // you're a dumb chink nigga
}

bool SpoofAllClasses()
{
	SPOOF_FUNC;

	InitSpoofUtil();

	auto FixingBasicWinShitString = _("[+] Fixing some other shit\r\n");

	printf(FixingBasicWinShitString.decrypt()); FixingBasicWinShitString.clear();
	
	BasicWindowsSpoof(); // yeah

	auto CleaningDisksString = _("[+] Cleaning disk traces.\r\n");

	printf(CleaningDisksString.decrypt()); CleaningDisksString.clear();

	FixDiskTraces();

	auto SpoofingMonitorString = _("[+] Spoofing Monitors...\r\n");

	printf(SpoofingMonitorString.decrypt()); SpoofingMonitorString.clear();

	SpoofMonitors();

	Sleep(1000);

	//auto SMBiosTracesString = _("[+] Fixing SMBios traces...\r\n");

	//printf(SMBiosTracesString.decrypt()); SMBiosTracesString.clear();

	//CleanSMBiosAndMisc();

	auto GPUTracesString = _("[+] Spoofing and cleaning GPU...\r\n");

	printf(GPUTracesString.decrypt()); GPUTracesString.clear();

	SpoofCleanGPU();

	Sleep(200);

	system(_("taskkill /im WmiPrv* /f /t >nul 2>&1").decrypt()); // you're a dumb chink nigga

	ClearConsole();     // clear console
	InitConsole();      // init console title and stuff

	// apparently not good enough since pc still need reinstall win due to sum gay ass shit with userinit idk i already bugcheck since crashlogs made xD
	
	system(_("taskkill /im WmiPrv* /f /t >nul 2>&1").decrypt()); // you're a dumb chink nigga

	system(_("taskkill /im WmiPrv* /f /t >nul 2>&1").decrypt()); // you're a dumb chink nigga

	return true;
}
