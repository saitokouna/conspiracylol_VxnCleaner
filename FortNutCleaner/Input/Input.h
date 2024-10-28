#pragma once

void ClearConsole()
{
	SPOOF_FUNC;

	auto CMD = _("cls");
	system(CMD.decrypt());
	CMD.clear();
}

void ColorDefault()
{
	SPOOF_FUNC;

	auto CMD = _("color");
	system(CMD.decrypt());
	CMD.clear();
}

void ColorCyan()
{
	SPOOF_FUNC;

	auto CMD = _("color b");
	system(CMD.decrypt());
	CMD.clear();
}

void InitConsole()
{
	SPOOF_FUNC;

	auto Title = _("Vixen Cleaner");
	LI_FN(SetConsoleTitleA).forwarded_safe_cached()(Title.decrypt());
	Title.clear();
}

void Watermark()
{
	SPOOF_FUNC;

	auto Message = _("[+] Made by conspiracy (t.me/conspiracylol). \r\n[!] This Software is free in: discord.gg/vixen.. Last updated on: ");
	
	LI_FN(printf).forwarded_safe()(Message.decrypt());
	LI_FN(printf).forwarded_safe()(__DATE__);
	LI_FN(printf).forwarded_safe()(_("!\r\n"));

	Message.clear();
}

void PressAnyKey()
{
	SPOOF_FUNC;

	auto CMD = _("pause >nul");
	LI_FN(system).forwarded_safe_cached()(CMD.decrypt());
	CMD.clear();
}