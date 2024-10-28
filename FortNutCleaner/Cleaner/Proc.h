#pragma once

void KillProc()
{
	SPOOF_FUNC;

	system(_("taskkill /im /f fortnite* /t >nul 2>&1"));
	system(_("taskkill /im /f easyantiche* /t >nul 2>&1"));
	system(_("taskkill /im /f beservice* /t >nul 2>&1"));
	system(_("taskkill /im /f epicweb* /t >nul 2>&1")); // epic web helpers
	system(_("taskkill /im /f epicgames* /t >nul 2>&1")); // epic games launcher
}

void RecacheSerials()
{
	SPOOF_FUNC;

	// WmiPrvSE.exe
	auto Proc = _("taskkill /im /f WmiPrv* /f /t >nul 2>&1");
	LI_FN(system).forwarded_safe_cached()(Proc.decrypt());
	Proc.clear();
}