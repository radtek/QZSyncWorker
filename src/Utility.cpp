#include "Utility.h"
#include "Poco/DateTimeFormatter.h"
#include "Poco/Net/HTTPRequest.h"
#include "Poco/Net/HTTPResponse.h"
#include "Poco/Debugger.h"
#include "Poco/String.h"
#include "Poco/StreamCopier.h"
#include "Poco/String.h"
#include "Poco/UnicodeConverter.h"
#include "Poco/RegularExpression.h"
#include "Poco/JSON/Parser.h"
#include "Poco/JSON/Object.h"
#include "Poco/DynamicStruct.h"
#include "Poco/Dynamic/Var.h"
#include "Poco/URI.h"
#include "Poco/ASCIIEncoding.h"
#include "Poco/StreamConverter.h"
#include "Poco/Windows936Encoding.h"
#include "Poco/TextConverter.h"
#include "Poco/Util/Application.h"
#include "Poco/Crypto/X509Certificate.h"
#include "Poco/Util/XMLConfiguration.h"
#include "Poco/MD5Engine.h"
#include "Poco/DigestStream.h"

#include <cassert>
#include <sstream>

using Poco::Net::HTTPRequest;
using Poco::Net::HTTPResponse;
using Poco::Net::HTTPClientSession;
using Poco::UnicodeConverter;
using Poco::StreamCopier;
using Poco::Debugger;
using Poco::format;
using Poco::RegularExpression;
using Poco::JSON::Parser;
using Poco::JSON::Object;
using Poco::DynamicStruct;
using Poco::Dynamic::Var;
using Poco::OutputStreamConverter;
using Poco::UTF8Encoding;
using Poco::Util::Application;
using Poco::Path;
using Poco::replace;
using Poco::Util::XMLConfiguration;
using Poco::Crypto::X509Certificate;

using namespace Reach::ActiveX;


Poco::Net::HTTPClientSession Utility::_session("127.0.0.1", 9900);

Utility::Utility()
{
	_session.reset();
}

std::string Utility::get(const std::string& url)
{
	std::ostringstream ostr;
	try
	{
		HTTPResponse response;
		HTTPRequest request(HTTPRequest::HTTP_GET, url);
		HTTPClientSession session("127.0.0.1", 11200);
		session.sendRequest(request);

		std::istream& receive = session.receiveResponse(response);
		StreamCopier::copyStream(receive, ostr);
	}
	catch (Poco::Exception& e)
	{
		Debugger::message(e.message());
	}
	return ostr.str();
}

void Utility::request(const std::string& url, const std::string& body)
{
	try
	{
		Debugger::message(format("request url [%s] body [%s]", url, body));
		HTTPRequest request(HTTPRequest::HTTP_POST, url);
		request.setContentLength((int)body.length());
		request.setContentType("application/json");
		_session.sendRequest(request) << (body);
	}
	catch (Poco::Exception& e)
	{
		Debugger::message(e.message());
	}

}

std::string Utility::response()
{
	std::ostringstream ostr;
	try
	{
		HTTPResponse response;
		std::istream& receive = _session.receiveResponse(response);
		StreamCopier::copyStream(receive, ostr);
		Debugger::message(format("response {%s}", ostr.str()));
	}
	catch (Poco::Exception& e)
	{
		Debugger::message(e.message());
	}
	return ostr.str();
}

std::string Utility::SuperRequest(const std::string& url, const std::string& body)
{
	std::ostringstream ostr;
	try
	{
		HTTPResponse response;
		HTTPRequest request(HTTPRequest::HTTP_POST, url);
		request.setContentLength((int)body.length());

		HTTPClientSession session("127.0.0.1", 11200);
		session.sendRequest(request) << (body);

		std::istream& receive = session.receiveResponse(response);
		
		StreamCopier::copyStream(receive, ostr);
	}
	catch (Poco::Exception& e)
	{
		Debugger::message(e.message());
	}
	return ostr.str();
}

std::wstring Utility::convert(const std::string& utf8)
{
	std::wstring ucs;
	UnicodeConverter::toUTF16(utf8, ucs);
	return ucs;
}

std::string Utility::config(const std::string& name)
{
	Application& app = Application::instance();

	std::string appName = Path(app.commandPath()).getFileName();
	std::string fullpath = replace(app.commandPath(), appName, std::string(""));

	Path filePath(fullpath, name);

	return filePath.toString();
}

std::string Utility::formatUid(const std::string& entries)
{
	std::string uid;

	try
	{
		Parser ps;
		Var result = ps.parse(entries);
		poco_assert(result.type() == typeid(Object::Ptr));
		DynamicStruct ds = *result.extract<Object::Ptr>();
		if (ds["code"] != "0000")
			throw Poco::Exception("formatUid error", ds.toString());

		std::string userlist = ds["data"]["userlist"];

		std::string pattern("(\\S+)\\|\\|(\\S+)[&&&]*");
		int options = 0;

		RegularExpression re(pattern, options);
		RegularExpression::Match mtch;

		if (!re.match(userlist, mtch)) {
			throw Poco::LogicException();
		}

		std::vector<std::string> tags;
		re.split(userlist, tags, options);
		poco_assert(tags.size() > 1);
		uid = tags[2];
	}
	catch (Poco::Exception& e)
	{
		Debugger::message(e.message());
	}

	return uid;
}

std::string Utility::GBKEncodingUTF8(const std::string & inEncoding)
{
	std::string outstring;
	Poco::UTF8Encoding utf8;
	Poco::Windows936Encoding gbk;
	Poco::TextConverter coverter(gbk, utf8);
	coverter.convert(inEncoding, outstring);
	return outstring;
}

std::string Utility::UTF8EncodingGBK(const std::string & inEncoding)
{
	std::string outstring;
	Poco::UTF8Encoding utf8;
	Poco::Windows936Encoding gbk;
	Poco::TextConverter coverter(utf8, gbk);
	coverter.convert(inEncoding, outstring);
	return outstring;
}

void Utility::message(const std::string& message)
{
	Application& app = Application::instance();

	std::ostringstream ostr;
	std::string stringToken(100, '#');

	ostr << std::endl
		<< stringToken
		<< std::endl
		<< message
		<< std::endl
		<< stringToken
		<< std::endl << std::endl;

	poco_information(app.logger(), ostr.str());
	poco_information(app.logger(), Utility::UTF8EncodingGBK(ostr.str()));
}

std::string Utility::formatX509(const std::string& cert)
{
	std::string PEM;
	PEM.append("-----BEGIN CERTIFICATE-----\n");
	PEM.append(Utility::cat("\n", 64, cert));
	PEM.append("-----END CERTIFICATE-----\n");
	return PEM;
}

std::string Utility::CodeFromDN(const std::string& cert)
{
	std::istringstream ss(Utility::formatX509(cert));

	X509Certificate x509(ss);
	std::string issuer = x509.issuerName(X509Certificate::NID_COMMON_NAME); ///DN - CN
	/// Use DN - O Item  if CN is empty 
	if (issuer.empty())
		issuer = x509.issuerName(X509Certificate::NID_ORGANIZATION_NAME);

	Poco::MD5Engine md5;
	Poco::DigestOutputStream ds(md5);
	ds << issuer;
	ds.close();

	std::string md5str = Poco::DigestEngine::digestToHex(md5.digest());
	std::string xpath = format("CA[@md5=%s].code", md5str);

	std::string signxml = Utility::config("CASignature.xml");
	Poco::AutoPtr<XMLConfiguration> pConf(new XMLConfiguration(signxml));
	return pConf->getString(xpath, "NA");
}

std::string Utility::cat(const std::string& delim, std::size_t pos, const std::string& str)
{
	assert(pos < str.length() || pos > 0);

	std::string result;

	size_t i = 0;
	for (; i < str.length(); ++i)
	{
		result.push_back(str[i]);
		if (i % pos == 0) continue;
		if ((i + 1) % pos == 0)
			result.append(delim);
	}

	if (i % pos != 0)
		result.append(delim);

	return result;
}