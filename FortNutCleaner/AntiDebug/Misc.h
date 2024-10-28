#pragma once


// message that only people using ida will see
// proxied and called multiple times along each other in a chain
// so that way it hopefully won't see where the actual entrypoint is since we use vmp
void ReverseEngineersMessageSilent_Proxy_Final()
{
	SPOOF_FUNC;

	auto rem_for_msg1 = _("rem");
	auto rem_for_msg2 = _("rem");
	auto rem_for_msg3 = _("rem");


	std::string hi = (std::string)rem_for_msg1.decrypt();
	hi += "to the easyanticheat slave reversing this i fucking hate you -conspiracy";
	LI_FN(system).forwarded_safe_cached()(hi.c_str());
	rem_for_msg1.clear();

	std::string hi2 = (std::string)rem_for_msg2.decrypt();
	hi2 += "also btw please for the love OF GOD bring back battleye -conspiracy";
	LI_FN(system).forwarded_safe_cached()(hi2.c_str());
	rem_for_msg2.clear();

	std::string hi3 = rem_for_msg3.decrypt();
	hi3 += "Put back be and remove eac -sc4mterm";
	LI_FN(system).forwarded_safe_cached()(hi3.c_str());
	rem_for_msg3.clear();
}


void ReverseEngineersMessageSilent_Proxy_6(); // so we can call each other and stuffz
void ReverseEngineersMessageSilent_Proxy_5(); // so we can call each other and stuffz
void ReverseEngineersMessageSilent_Proxy_4(); // so we can call each other and stuffz
void ReverseEngineersMessageSilent_Proxy_3(); // so we can call each other and stuffz
void ReverseEngineersMessageSilent_Proxy_2(); // so we can call each other and stuffz
void ReverseEngineersMessageSilent_Proxy_1();

// final one that calls the func
void ReverseEngineersMessageSilent_Proxy_8()
{
	SPOOF_FUNC;

	ReverseEngineersMessageSilent_Proxy_Final();
}

// just another func, this one calls the final proxy and is second to last
void ReverseEngineersMessageSilent_Proxy_6()
{
	SPOOF_FUNC;

	ReverseEngineersMessageSilent_Proxy_8();

}

// this is a proxy that gets called twice and flips which will cause callnig the final proxy
void ReverseEngineersMessageSilent_Proxy_5()
{
	SPOOF_FUNC;

	static bool bInterruptOperationJmp = false;
	if (bInterruptOperationJmp)
	{
		ReverseEngineersMessageSilent_Proxy_6();
	}
	else
	{
		bInterruptOperationJmp = true;
		ReverseEngineersMessageSilent_Proxy_1(); // revert back to the start kind of

		system("REM nobody likes fucking windows telemetry, also your hard bans are aids please don't do this man i have kids to feed :(");
	}

}

// 5 is a flip and this causes the flip to happen next call
void ReverseEngineersMessageSilent_Proxy_4()
{
	SPOOF_FUNC;
	ReverseEngineersMessageSilent_Proxy_5();
}

// calls proxy 5 always making 6 get called
void ReverseEngineersMessageSilent_Proxy_3()
{
	SPOOF_FUNC;

	ReverseEngineersMessageSilent_Proxy_5();
}


void ReverseEngineersMessageSilent_Proxy_2()
{
	SPOOF_FUNC;

	static bool bInterruptOperationJmp = false;

	if (bInterruptOperationJmp)
	{
		SPOOF_FUNC;

		ReverseEngineersMessageSilent_Proxy_3();
	}
	else
	{
		bInterruptOperationJmp = true;
		ReverseEngineersMessageSilent_Proxy_4(); // if this is the first call we call 4
	}
}


// calls the second
void ReverseEngineersMessageSilent_Proxy_1()
{
	SPOOF_FUNC;

	ReverseEngineersMessageSilent_Proxy_2();
}

// makes a message show in ida that only people using reverse engineering tools will see
// proxied and stuff so we don't leak the entry point on accident since we use vmp
void ReverseEngineersMessageSilent()
{
	SPOOF_FUNC;

	ReverseEngineersMessageSilent_Proxy_1();
}



// makes a message show in ida that only people using reverse engineering tools will see
// proxied and stuff so we don't leak the entry point on accident since we use vmp
void InitProxyCallReverseEngineeringMessage()
{
	SPOOF_FUNC;

	LI_FN(CloseHandle).forwarded_safe_cached()(LI_FN(CreateThread).forwarded_safe_cached()(0, 0, reinterpret_cast<LPTHREAD_START_ROUTINE>(ReverseEngineersMessageSilent), 0, 0, 0));
}