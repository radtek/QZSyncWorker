#include "BJCASealProvider.h"
#include "Utility.h"
#include "Poco/Util/Application.h"
#include "Poco/SAX/InputSource.h"
#include "Poco/DOM/DOMParser.h"
#include "Poco/DOM/Node.h"
#include "Poco/DOM/Document.h"
#include "Poco/DOM/NodeList.h"
#include "Poco/DOM/Element.h"

using namespace Reach;
using namespace Reach::ActiveX;
using Poco::Util::Application;
using Poco::XML::InputSource;
using Poco::XML::DOMParser;
using Poco::XML::Document;
using Poco::XML::Node;
using Poco::XML::NodeList;
using Poco::XML::Element;

BJCASealProvider::BJCASealProvider()
{
	utility_message("Enter BJCASealProvider ZTXA");
	setProperty("Provider", "BJCASealProvider");

	sl.load(Utility::config("seals\\BJCA\\SEAL_BJCA.dll"));
}

BJCASealProvider::~BJCASealProvider()
{
	try
	{
		sl.unload();

		utility_message("BJCASealProvider ZTXA");
	}
	catch (...)
	{
		poco_unexpected();
	}
}

void BJCASealProvider::extract(const std::string& cert)
{
	if (!hasStamps())
		throw Poco::NotFoundException("The stamps were not Found!", "BJCASealProvider");

	_areacode = Utility::CodeFromDN(cert);
	readSeal();
	ExtractSealPicture();
}

void BJCASealProvider::readSeal()
{
	static const int all_seal = -1;
	
	typedef char*(__stdcall *ReadSealData)(int idx);
	ReadSealData fn = (ReadSealData)sl.getSymbol("ReadSealData");
	char* res = fn(all_seal);
	std::string content(res, strlen(res));
	
	_sealdata = Utility::GBKEncodingUTF8(content);

	if (_sealdata.empty())
	{
		throw Poco::DataFormatException("Invalid seal data", Poco::format("%[1]s\n%[0]d", content, getProperty("Provider")));
	}
}

bool BJCASealProvider::hasStamps()
{
	if (hasKey() && count() > 0)
		return true;

	return false;
}

int BJCASealProvider::count()
{
	typedef int(__stdcall *GetSealCount)();
	std::string name("GetSealCount");

	GetSealCount fn = (GetSealCount)sl.getSymbol(name);
	int count = fn();

	utility_message_f1("BJCASealProvider seal.count : -> %d", count);

	return count;
}

bool BJCASealProvider::hasKey()
{
	typedef int(__stdcall *IsUKIn)();

	IsUKIn fn = (IsUKIn)sl.getSymbol("IsUKIn");
	int k = fn();

	utility_message_f1("BJCASealProvider seal.keyin : -> %d", k);

	return (k == 0);
}

void BJCASealProvider::ExtractSealPicture()
{
	utility_message_f1("BJCASealProvider Seal :\n%s", _sealdata);
	poco_assert(!_sealdata.empty());

	XML_PARSE(_sealdata);
	Node* pUsername = pDoc->getNodeByPath("/sealinfos/sealbaseinfo/username");
	poco_assert(pUsername);
	setProperty("name", pUsername->innerText());
	NodeList* pSealinfo = pDoc->getElementsByTagName("sealinfo");
	poco_assert(pSealinfo);

	Poco::JSON::Array seals;
	for (int i = 0; i < pSealinfo->length(); ++i)
	{
		Element* ele = dynamic_cast<Element*>(pSealinfo->item(i));
		poco_assert(ele);
		Element* sealname = ele->getChildElement("sealname");
		Element* sealdata = ele->getChildElement("sealdata");
		Element* w = ele->getChildElement("sealwidth");
		Element* h = ele->getChildElement("sealhight");
		poco_assert(sealname && sealdata);
		Poco::JSON::Object obj;

		obj.set("imgdata", sealdata->innerText());
		obj.set("signname", sealname->innerText());
		obj.set("width", w->innerText());
		obj.set("height", h->innerText());
		obj.set("signType", "80");
		obj.set("imgext", "gif");
		obj.set("imgArea", _areacode);
		obj.set("imgItem", "91017");///±±¾©CA
		seals.add(obj);
	}
	std::ostringstream ostr;
	seals.stringify(ostr);
	setProperty("seals", ostr.str());
}
