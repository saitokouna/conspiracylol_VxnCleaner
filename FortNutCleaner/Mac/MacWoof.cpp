
#include "MacWoof.h"

#define MALLOC(x) HeapAlloc(GetProcessHeap(), 0, (x))
#define FREE(x) HeapFree(GetProcessHeap(), 0, (x))

MyMACAddr::MyMACAddr()
{
	//Seeding for random numbers
	srand((unsigned)time(0));
}

MyMACAddr::~MyMACAddr()
{
}

//-----------------------------------------------
// Generate Random MAC Addresses
//-----------------------------------------------
string MyMACAddr::GenRandMAC()
{
	SPOOF_FUNC;

	stringstream temp;
	int number = 0;
	string result;

	for (int i = 0; i < 6; i++)
	{
		number = rand() % 254;
		temp << setfill('0') << setw(2) << hex << number;
		if (i != 5)
		{
			temp << "-";
		}
	}
	result = temp.str();
	
	for (auto &c : result)
	{
		c = toupper(c);
	}

	return result;
}

//-----------------------------------------------
// Get Network Adapter's Name and MAC addresses
//-----------------------------------------------
unordered_map<string, string> MyMACAddr::getAdapters()
{
	SPOOF_FUNC;

	PIP_ADAPTER_INFO pAdapterInfo;
	PIP_ADAPTER_INFO pAdapter = NULL;
	DWORD dwRetVal = 0;

	unordered_map<string, string> result;
	stringstream temp;
	string str_mac;

	ULONG ulOutBufLen = sizeof(IP_ADAPTER_INFO);
	pAdapterInfo = (IP_ADAPTER_INFO *)MALLOC(sizeof(IP_ADAPTER_INFO));
	if (pAdapterInfo == NULL)
	{
		printf(_("Error allocating memory needed to call GetAdaptersinfo\n").decrypt());
		return result;
	}
	// Make an initial call to GetAdaptersInfo to get
	// the necessary size into the ulOutBufLen variable
	if (GetAdaptersInfo(pAdapterInfo, &ulOutBufLen) == ERROR_BUFFER_OVERFLOW) {
		FREE(pAdapterInfo);
		pAdapterInfo = (IP_ADAPTER_INFO *)MALLOC(ulOutBufLen);
		if (pAdapterInfo == NULL)
		{
			printf(_("Error allocating memory needed to call GetAdaptersinfo\n").decrypt());
			return result;
		}
	}

	if ((dwRetVal = GetAdaptersInfo(pAdapterInfo, &ulOutBufLen)) == NO_ERROR) {
			pAdapter = pAdapterInfo;
			while (pAdapter) {
					for (UINT i = 0; i < pAdapter->AddressLength; i++) {
						temp << setfill('0') << setw(2) << hex << (int)pAdapter->Address[i];
						if (i != pAdapter->AddressLength - 1)
						{
							temp << "-";
						}				
					}			
					str_mac = temp.str();
					temp.str("");
					temp.rdbuf();
					for (auto&c : str_mac)
					{
						c = toupper(c);
					}
			
					result.insert({ pAdapter->Description, str_mac });
					pAdapter = pAdapter->Next;
			}
	}
	else
	{
		printf(_("GetAdaptersInfo failed with error status: %d!\r\n").decrypt(), dwRetVal);
	}

	if (pAdapterInfo)
	{
		FREE(pAdapterInfo);
	}
	
	return result;
}

//-----------------------------------------------
// Assing Random MAC address to Network Interface
//-----------------------------------------------
void MyMACAddr::AssingRndMAC()
{
	SPOOF_FUNC;

	//-------- Copy Network interfaces to Vector
	vector <string> list;
	unordered_map<string, string> AdapterDetails = getAdapters();
	for (auto& itm : AdapterDetails)
	{
		list.push_back(itm.first);
	}

	//cout << "\n[+] List of Available Adapters: " << endl;
	int AttemptedMAC = 0;
	int range = 0;
	for (auto itm = list.begin(); itm != list.end(); itm++)
	{
		//cout << '\t' << range + 1 << ")" << *itm << endl;
		range++;
	}


	for (int selection = 0; range >= selection; selection++)
	{

		if ((selection < 1) || (selection > range))
			continue; // printf(_("bad selection, input: %d!\r\n").decrypt(), selection);

		cout << _("[+] Spoofing adapter: ").decrypt() << list.at(selection - 1) << _(" (").decrypt() << range << _(")").decrypt() << endl;
		cout << _("[+] Old MAC: ").decrypt() << AdapterDetails.at(list.at(selection - 1)) << endl;

		//-------- Converting to Wide characters
		wstring wstr(list.at(selection - 1).begin(), list.at(selection - 1).end());
		const wchar_t* wAdapterName = wstr.c_str();

		//-------- Registry Key for Network Interfaces
		bool bRet = false;
		HKEY hKey = NULL;
		if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, _T("SYSTEM\\CurrentControlSet\\Control\\Class\\{4D36E972-E325-11CE-BFC1-08002bE10318}"),
			0, KEY_ALL_ACCESS, &hKey) == ERROR_SUCCESS)
		{

			DWORD dwIndex = 0;
			TCHAR Name[1024];
			DWORD cName = 1024;
			while (RegEnumKeyEx(hKey, dwIndex, Name, &cName,
				NULL, NULL, NULL, NULL) == ERROR_SUCCESS)
			{
				HKEY hSubKey = NULL;
				if (RegOpenKeyEx(hKey, Name, 0, KEY_ALL_ACCESS, &hSubKey) == ERROR_SUCCESS)
				{
					BYTE Data[1204];
					DWORD cbData = 1024;
					if (RegQueryValueEx(hSubKey, _T("DriverDesc"), NULL, NULL, Data, &cbData) == ERROR_SUCCESS)
					{
						if (_tcscmp((TCHAR*)Data, wAdapterName) == 0)
						{
							string temp = GenRandMAC();
							string newMAC = temp;
							temp.erase(std::remove(temp.begin(), temp.end(), '-'), temp.end());

							wstring wstr_newMAC(temp.begin(), temp.end());
							const wchar_t* newMACAddr = wstr_newMAC.c_str();

							//--------Add new MAC to Registry Subkey and disable and re-enable the interface
							// to effect changes
							if (RegSetValueEx(hSubKey, _T("NetworkAddress"), 0, REG_SZ, (const BYTE*)newMACAddr, sizeof(TCHAR) * ((DWORD)_tcslen(newMACAddr) + 1)) == ERROR_SUCCESS)
							{
								cout << _("[+] New MAC: ").decrypt() << newMAC << endl;
								DisableEnableConnections(false, wAdapterName);
								DisableEnableConnections(true, wAdapterName);
							}
						}
					}
					RegCloseKey(hSubKey);
				}
				cName = 1024;
				dwIndex++;
			}
			RegCloseKey(hKey);
		}
		else
		{
			cerr << _("[!] Cannot Access Registry - Maybe you don't have Administer permission.") << endl;
			return;
		}
	}
}

//-----------------------------------------------
// Original Code: https://social.msdn.microsoft.com/Forums/en-US/ad3ae21d-515d-4f67-8519-216f1058e390/enabledisable-network-card?forum=netfxnetcom
// Modified to only Disable and Re-enable the given Adapter 
//-----------------------------------------------
HRESULT MyMACAddr::DisableEnableConnections(BOOL bEnable , const wchar_t *AdapterName)
{
	SPOOF_FUNC;

	HRESULT hr = E_FAIL;

	try
	{
		HRESULT cat = CoInitialize(NULL);
		if (FAILED(cat) || cat != S_OK)
		{
			printf(_("CoInitialize() failed with code: (0x%08x)\r\n").decrypt(), cat);
		}

		INetConnectionManager* pNetConnectionManager = NULL;
		hr = CoCreateInstance(CLSID_ConnectionManager,
			NULL,
			CLSCTX_LOCAL_SERVER | CLSCTX_NO_CODE_DOWNLOAD,
			IID_INetConnectionManager,
			reinterpret_cast<LPVOID*>(&pNetConnectionManager)
		);



		if (SUCCEEDED(hr))
		{
			/*
			Get an enumurator for the set of connections on the system
			*/
			IEnumNetConnection* pEnumNetConnection;
			pNetConnectionManager->EnumConnections(NCME_DEFAULT, &pEnumNetConnection);

			ULONG ulCount = 0;
			BOOL fFound = FALSE;
			hr = HRESULT_FROM_WIN32(ERROR_FILE_NOT_FOUND);

			HRESULT hrT = S_OK;

			/*
			Enumurate through the list of adapters on the system and look for the one we want
			NOTE: To include per-user RAS connections in the list, you need to set the COM
			Proxy Blanket on all the interfaces. This is not needed for All-user RAS
			connections or LAN connections.
			*/
			do
			{
				NETCON_PROPERTIES* pProps = NULL;
				INetConnection* pConn;

				/*
				Find the next (or first connection)
				*/
				hrT = pEnumNetConnection->Next(1, &pConn, &ulCount);

				if (SUCCEEDED(hrT) && 1 == ulCount)
				{
					/*
					Get the connection properties
					*/
					hrT = pConn->GetProperties(&pProps);

					if (S_OK == hrT)
					{

						NETCON_STATUS pNetStatus = pProps->Status;
						bool bEnabled = (pNetStatus == NETCON_STATUS::NCS_HARDWARE_NOT_PRESENT && pNetStatus == NETCON_STATUS::NCS_HARDWARE_DISABLED);

						//printf("* %S\n", pProps->pszwName);

						if (bEnable && (_tcscmp((TCHAR*)pProps->pszwDeviceName, AdapterName) == 0))
						{
							printf(_("[+] Enabling adapter: %s...\n").decrypt(), pProps->pszwDeviceName);
							hr = pConn->Connect();
						}
						else if (_tcscmp((TCHAR*)pProps->pszwDeviceName, AdapterName) == 0)
						{
							printf(_("[+] Disabling adapter: %s...\n").decrypt(), pProps->pszwDeviceName);
							hr = pConn->Disconnect();
						}

						CoTaskMemFree(pProps->pszwName);
						CoTaskMemFree(pProps->pszwDeviceName);
						CoTaskMemFree(pProps);
					}
					else
					{
						if (FAILED(hr) && hr != HRESULT_FROM_WIN32(ERROR_RETRY))
						{
							printf(_("[!] Could not enable or disable connection (0x%08x)\r\n").decrypt(), hr);
						}
					}

					if (pConn)
					{
						pConn->Release();
						pConn = NULL;
					}
				}

			} while (SUCCEEDED(hrT) && 1 == ulCount && !fFound);

			if (FAILED(hrT))
			{
				hr = hrT;
			}

			pEnumNetConnection->Release();
		}

		if (pNetConnectionManager)
		{
			pNetConnectionManager->Release();
		}

		CoUninitialize();

	} catch(...) {}

	return hr;
}