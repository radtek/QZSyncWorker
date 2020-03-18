#include "BCBSSealProvider.h"
#include "Utility.h"
#include "Poco/DOM/NodeList.h"
#include "Poco/DOM/NodeFilter.h"
#include "Poco/DOM/NodeIterator.h"
#include "GmEsealProvider.h"
#include "Poco/Format.h"

using namespace Reach;
using namespace Reach::ActiveX;
using namespace Poco::XML;

using Poco::format;

BCBSSealProvider::BCBSSealProvider()
{
	utility_message("Enter BCBSSealProvider eseals");

	sl.load(Utility::config("seals\\BCBS\\SEAL_BaiCheng.dll"));

	setProperty("Provider", "BCBSSealProvider");
}

BCBSSealProvider::~BCBSSealProvider()
{
	utility_message("Exit BCBSSealProvider eseals");
}

void BCBSSealProvider::extract(const std::string& cert)
{
	if (!hasStamps())
		throw Poco::NotFoundException("The stamps were not Found!", "BCBSSealProvider");

	_areacode = Utility::CodeFromDN(cert);

	readSeal();
	ExtractSealPicture();
}

void BCBSSealProvider::ExtractSealPicture()
{
	utility_message_f1("eseals Seal :\n%s", _sealdata);
	poco_assert(!_sealdata.empty());

	XML_PARSE(_sealdata);
	Node* pUsername = pDoc->getNodeByPath("/sealinfos/sealbaseinfo/username");
	poco_assert(pUsername);
	setProperty("name", pUsername->innerText());

	NodeList* pSealinfo = pDoc->getElementsByTagName("sealinfo");
	poco_assert(pSealinfo);
	Poco::JSON::Array seals;
	for (int i = 0; pSealinfo && i < pSealinfo->length(); i++)
	{
		Element* ele = dynamic_cast<Element*>(pSealinfo->item(i));
		poco_assert(ele);
		Element* n = ele->getChildElement("sealname");
		Element* d = ele->getChildElement("sealdata");
		Element* w = ele->getChildElement("sealwidth");
		Element* h = ele->getChildElement("sealhight");
		poco_assert(n && d && w && h);

		Poco::JSON::Object ob;
		ob.set("signname", n->innerText());
		ob.set("imgdata", d->innerText());
		ob.set("width", w->innerText());
		ob.set("height", h->innerText());
		ob.set("imgext", "gif");
		ob.set("signType", "80");///������ǩ��
		ob.set("imgArea", _areacode);
		ob.set("imgItem", "99004");/// �ٳ�ǩ��
		seals.add(ob);
	}

	std::ostringstream ostr;
	seals.stringify(ostr);
	setProperty("seals", ostr.str());
}

bool BCBSSealProvider::hasStamps()
{
	int k = hasKey();
	if (!k) return false;

	int c = count();

	if (c > 0) 
		return true;

	return false;
}

bool BCBSSealProvider::hasKey()
{
	typedef int(__stdcall *IsUKIn)();

	IsUKIn fn = (IsUKIn)sl.getSymbol("IsUKIn");
	int k = fn();

	utility_message_f1("share-sun seal.keyin : -> %d", k);

	return (k == 0);
}

int BCBSSealProvider::count()
{
	typedef int(__stdcall *GetSealCount)();
	std::string name("GetSealCount");

	GetSealCount fn = (GetSealCount)sl.getSymbol(name);
	int count = fn();

	utility_message_f1("share-sun seal.count : -> %d", count);

	return count;
}

void BCBSSealProvider::readSeal()
{
	static const int all_seal = -1;
	typedef char* (*ReadSealData)(int nIndex);

	ReadSealData fn = (ReadSealData)sl.getSymbol("ReadSealData");
	char* res = fn(all_seal);
	std::string content(res, strlen(res));
	_sealdata = Utility::GBKEncodingUTF8(content);

	if (_sealdata.empty())
		throw Poco::DataFormatException("Invalid seal data", Poco::format("%[1]s\n%[0]d", content, getProperty("Provider")));
}
