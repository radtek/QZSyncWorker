#include "DianJuSealProvider2.h"
#include "Utility.h"
#include "Poco/Util/Application.h"
#include <iosfwd>

#include "Poco/SAX/InputSource.h"
#include "Poco/DOM/DOMParser.h"
#include "Poco/DOM/Document.h"
#include "Poco/DOM/Node.h"
#include "Poco/DOM/NodeList.h"
#include "Poco/DOM/Element.h"

using namespace Reach;
using namespace Reach::ActiveX;
using namespace Poco::XML;

extern std::string SOF_GetCertInfo(std::string Base64EncodeCert, short Type);

DianJuSealProvider2::DianJuSealProvider2()
{
	utility_message("Enter DianJuSealProvider2 dianju");

	sl.load(Utility::config("seals\\DIANJU2\\HWPostil2.ocx"));

	setProperty("Provider", "DianJuSealProvider2");
}

DianJuSealProvider2::~DianJuSealProvider2()
{
	poco_assert(sl.isLoaded());

	//sl.unload();

	utility_message("Exit DianJuSealProvider2 dianju");
}

void DianJuSealProvider2::extract(const std::string& cert)
{
	if (!hasStamps())
		throw Poco::NotFoundException("The stamps were not Found!", "DianJuSealProvider2");

	_areacode = Utility::CodeFromDN(cert);
	_defaultname = SOF_GetCertInfo(cert, 49);

	readSeal();
	ExtractSealPicture();
}

void DianJuSealProvider2::readSeal()
{
	static const int all_seal = -1;
	typedef char* (__stdcall *ReadSealData)(int nIndex);
	ReadSealData fn = (ReadSealData)sl.getSymbol("ReadSealData");
	char* res = fn(all_seal);
	std::string content(res, strlen(res));
	_sealdata = Utility::GBKEncodingUTF8(content);

	if (_sealdata.empty())
		throw Poco::DataFormatException("Invalid seal data", Poco::format("%[1]s\n%[0]d", content, getProperty("Provider")));
}

bool DianJuSealProvider2::hasStamps()
{
	if (hasKey() && count() > 0)
		return true;

	return false;
}


int DianJuSealProvider2::count()
{
	typedef int(__stdcall *GetSealCount)();
	std::string name("GetSealCount");

	GetSealCount fn = (GetSealCount)sl.getSymbol(name);
	int count = fn();

	utility_message_f1("DianJuSealProvider2 seal.count : -> %d", count);

	return count;
}

bool DianJuSealProvider2::hasKey()
{
	typedef int(__stdcall *IsUKIn)();

	IsUKIn fn = (IsUKIn)sl.getSymbol("IsUKIn");
	int k  = fn();

	utility_message_f1("DianJuSealProvider2 seal.keyin : -> %d", k);

	return (k == 0);
}

void DianJuSealProvider2::ExtractSealPicture()
{
	utility_message_f1("DianJuSealProvider2 Seal :\n%s", _sealdata);
	XML_PARSE(_sealdata);
	Node* pUsername = pDoc->getNodeByPath("/sealinfos/sealbaseinfo/username");
	poco_assert(pUsername);
	setProperty("name", (!pUsername->innerText().empty() ? pUsername->innerText() : _defaultname));

	NodeList* pSealinfo = pDoc->getElementsByTagName("sealinfo");
	poco_assert(pSealinfo);

	Poco::JSON::Array seals;
	for (int i = 0; i < pSealinfo->length(); i++)
	{
		Element* ele = dynamic_cast<Element*>(pSealinfo->item(i));
		poco_assert(ele);

		Element* sealname = ele->getChildElement("sealname");
		Element* sealdata = ele->getChildElement("sealdata");
		poco_assert(sealdata && sealname);

		Poco::JSON::Object obj;
		obj.set("imgdata", sealdata->innerText());
		obj.set("signname", sealname->innerText());
		obj.set("width", "4.00");
		obj.set("height", "4.00");
		obj.set("signType", "80");///第三方签章
		obj.set("imgext", "gif");
		obj.set("imgArea", _areacode);
		obj.set("imgItem", "99005");/// 点聚
		seals.add(obj);
	}
	std::ostringstream ostr;
	seals.stringify(ostr);
	setProperty("seals", ostr.str());
}