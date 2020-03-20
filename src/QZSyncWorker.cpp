#include "QZSyncWorker.h"

#include "Poco/Data/Session.h"
#include "Poco/Data/Statement.h"
#include "Poco/Data/SQLite/Connector.h"
#include "Poco/JSON/Parser.h"
#include "Poco/Dynamic/Var.h"
#include "Poco/FileStream.h"
#include "Poco/URI.h"
#include "Poco/Net/HTTPRequest.h"
#include "Poco/Net/HTTPClientSession.h"
#include "Poco/Net/HTTPResponse.h"
#include "Poco/UUID.h"
#include "Poco/UUIDGenerator.h"
#include "Poco/MD5Engine.h"
#include "Poco/DigestStream.h"
#include "Poco/Util/Application.h"
#include "Poco/Util/JSONConfiguration.h"
#include "Poco/Util/AbstractConfiguration.h"

#include "OESSealProvider.h"
#include "XSSealProvider.h"
#include "KGSealProvider.h"
#include "DianJuSealProvider.h"
#include "DianJuSealProvider2.h"
#include "TZWYSealProvider.h"
#include "BCBSSealProvider.h"
#include "BJCASealProvider.h"

#include "HT5488003Media.h"
#include "FT3000GMMedia.h"
#include "SOFMedia.h"

#include "Utility.h"

using namespace Reach;
using namespace Reach::ActiveX;
using namespace Poco;
using namespace Poco::Data;
using namespace Poco::Data::SQLite;
using namespace Poco::Data::Keywords;
using namespace Poco::JSON;
using namespace Poco::Net;
using namespace Poco::Util;

using Poco::Dynamic::Var;

QZSyncWorker::QZSyncWorker()
	:Task("QZSyncWorker"),
	session("SQLite", "syncQLite.db")
{
	session << "CREATE TABLE IF NOT EXISTS syncSDMakeup (id integer primary key, keysn VARCHAR(32), md5value VARCHAR(32),\
		sync BOOLEAN DEFAULT 0, create_time datetime DEFAULT(datetime('now', 'localtime')),\
		modify_time datetime DEFAULT(datetime('now', 'localtime')),\
		expire_time datetime DEFAULT(datetime('now', '+4 hours', 'localtime'))\
		); ", now;

	FileInputStream in(Utility::config("QZSyncWorker.json"));
	object = extract<Object::Ptr>(in);
	poco_assert(object);
	if (!object)
		throw Poco::UnhandledException("config lost", "QZSyncWorker.json");

	InitMedias();
#ifndef EPOINT_OES_ONLY
	InitSealProviders();
#endif // EPOINT_OES_ONLY
}

void QZSyncWorker::InitMedias()
{
#ifdef EPOINT_OES_ONLY
	_media.push_back(new FT3000GMMedia);
	_media.push_back(new HT5488003Media);
#else
	_media.push_back(new FT3000GMMedia);
	_media.push_back(new HT5488003Media);
	_media.push_back(new SOFMedia);
#endif // EPOINT_OES_ONLY
}

void QZSyncWorker::InitSealProviders()
{
	_oess.push_back(new OESSealProvider);
	_oess.push_back(new XSSealProvider);
	_oess.push_back(new KGSealProvider);
	_oess.push_back(new DianJuSealProvider);
	_oess.push_back(new DianJuSealProvider2);
	//_oess.push_back(new BCBSSealProvider);
	/// TZWYSealProvider will crash when read other seals.
	_oess.push_back(new BJCASealProvider);
	//_oess.push_back(new TZWYSealProvider);
}

void QZSyncWorker::runTask()
{
	Application& app = Application::instance();

	while (!sleep(5000))
	{
		app.logger().trace("busy doing QZSyncTask... " + DateTimeFormatter::format(app.uptime()));
		if (isCancelled()) break;
		try
		{
			if (IsUSBKeyPresent()) {
				clear();
				composite();
				checkFromServer();
				transfer();
			}
		}
		catch (Poco::Exception& e)
		{
			std::string message(format("QZSyncWorker runTask Exception: %d, %s", e.code(), e.displayText()));
			utility_message(message);
		}

	}
}

bool QZSyncWorker::IsUSBKeyPresent()
{
	Application& app = Application::instance();

	std::string devicelist = Utility::get("/buffer");
	poco_assert(!devicelist.empty());
	if (devicelist.empty())
		return false;

	utility_message(devicelist);
	JSON_ARRARY_PARSE(devicelist);
	/// only a device connected
	if (da.size() > 1 || da.empty())
		return false;

	std::string hid = da[0]["HardwareID"].toString();
	
	app.config().setString("hardware.hid", hid);
	utility_message(hid);

	return true;
}

void QZSyncWorker::extractKeyInfo()
{
	Poco::FastMutex::ScopedLock loc(_mutex);

	for (MBIter it = _media.begin(); it != _media.end(); it++) {
		try 
		{
			(*it)->open();
			(*it)->extract();
			_cert = (*it)->getProperty("cert");
			_keysn = (*it)->getProperty("keysn");
			_validStart = (*it)->getProperty("validStart");
			_validEnd = (*it)->getProperty("validEnd");
			break;
		}
		catch (Poco::Exception& e)
		{
			std::string message(format("QZSyncWorker Composite Exception %[1]d : %[0]s", e.message(), e.code()));
			utility_message(message);
		}
	}
}

void QZSyncWorker::extractSealDataOES()
{
	Poco::FastMutex::ScopedLock loc(_mutex);

	try
	{
		Poco::AutoPtr<SealProvider> oes(new OESSealProvider);
		oes->extract(_cert);
		_name = oes->getProperty("name");
		_seals = oes->getProperty("seals");
	}
	catch (Poco::Exception& e)
	{
		std::string message(format("QZSyncWorker OES Exception %[1]d : %[0]s", e.message(), e.code()));
		utility_message(message);
	}
}

void QZSyncWorker::extractSealData()
{
	Poco::FastMutex::ScopedLock loc(_mutex);

	for (SPIter it = _oess.begin(); it != _oess.end(); it++) {
		try
		{
			(*it)->extract(_cert);
			_name = (*it)->getProperty("name");
			_seals = (*it)->getProperty("seals");

			break;
		}
		catch (Poco::Exception& e)
		{
			std::string message(format("QZSyncWorker Composite Exception %[1]d : %[0]s", e.message(), e.code()));
			utility_message(message);
		}
	}
}

void QZSyncWorker::GeneratedMD5()
{
	MD5Engine md5;
	DigestOutputStream ds(md5);
	ds << _keysn
		<< "&&"
		<< _seals;
	ds.close();

	_md5 = DigestEngine::digestToHex(md5.digest());
}

void QZSyncWorker::GeneratedCode()
{
	UUIDGenerator& gen = UUIDGenerator::defaultGenerator();
	UUID uuid = gen.createFromName(UUID::uri(), _keysn);
	_code = uuid.toString();
}

void QZSyncWorker::clear()
{
	_name.clear();
	_code.clear();
	_validStart.clear();
	_validEnd.clear();
	_keysn.clear();
	_md5.clear();
	_seals.clear();
	_cert.clear();
}

bool QZSyncWorker::infoexpired()
{
	if (_keysn.empty()) return false;

	struct Makeup {
		int id;
		std::string keysn;
		DateTime expire_time;
	};

	Makeup syncRecord;
	Statement select(session);
	select << "SELECT id, keysn, expire_time FROM syncSDMakeup WHERE keysn = ?",
		into(syncRecord.id),
		into(syncRecord.keysn),
		into(syncRecord.expire_time),
		use(_keysn),
		range(0, 1);

	while (!select.done()) {
		if (!select.execute())
			return true;

		LocalDateTime now;
		if (now.timestamp() > syncRecord.expire_time.timestamp())
			return true;
	}

	return false;
}

void QZSyncWorker::composite()
{
	extractKeyInfo();
	utility_message(_cert);

	if (infoexpired()) {

#ifndef EPOINT_OES_ONLY
		extractSealData();
#endif // EPOINT_OES_ONLY
		extractSealDataOES();

		if (_seals.empty())
			throw Poco::CircularReferenceException("Can not read seal data!", "composite");

		GeneratedMD5();
		GeneratedCode();
		updateStatus();

		std::string message;
		message.append(format("name:%s,code%:%s \n", _name, _code));
		message.append(format("validStart:%s,validEnd%:%s\n", _validStart, _validEnd));
		message.append(format("keysn:%s,dataMD5%:%s\n", _keysn, _md5));
		message.append(format("seal -> \n%s", _seals));
		utility_message(message);
	}
	else utility_message("seal data has vaild!");
}

void QZSyncWorker::updateStatus()
{
	/// | Title		 |	T	|	F	|	T	|	F	|
	/// | MD5		 |	1	|	1	|	0	|	0	|
	/// | sync		 |	1	|	0	|	1	|	0	|
	///	| transfer   |	No	|	Yes	|	Yes	|	YES	|
	/// | Final		 |		|	Y	|		|		|
	///
	///	SQLITE syntax:
	/// CREATE TABLE syncSDMakeup (id integer primary key, keysn VARCHAR(32), md5value VARCHAR(32),
	/// sync BOOLEAN DEFAULT 0, create_time datetime DEFAULT (datetime('now','localtime')), 
	/// modify_time datetime DEFAULT (datetime('now','localtime')), 
	/// expire_time datetime DEFAULT (datetime('now','+4 hours','localtime'))
	/// );

	struct Makeup {
		int id;
		std::string keysn;
		std::string md5;
		bool sync;
	};

	Makeup syncRecord;
	Statement select(session);
	select << "SELECT id, keysn, md5value, sync FROM syncSDMakeup WHERE keysn = ?",
		into(syncRecord.id),
		into(syncRecord.keysn),
		into(syncRecord.md5),
		into(syncRecord.sync),
		use(_keysn),
		range(0, 1);

	while (!select.done()) {

		if (!select.execute()) {
			Statement insert(session);
			insert << "INSERT INTO syncSDMakeup (keysn, md5value) VALUES (?, ?);",
				use(_keysn),
				use(_md5),
				sync,
				now;

			utility_message_f3("[insert SQL Statement :%s], keysn=%s, md5value=%s", insert.toString(), _keysn, _md5);

			break;
		}

		utility_message_f4("[select SQL Statement :%s ],keysn= %s, md5value=%s, sync = %b", select.toString(), syncRecord.keysn, syncRecord.md5, syncRecord.sync);

		if (syncRecord.md5 != _md5) {

			Statement update(session);
			update << "UPDATE syncSDMakeup set md5value = ?, sync = 0, modify_time = datetime('now','localtime'), expire_time = datetime('now','+4 hours','localtime') where keysn= ?;",
				use(_md5),
				use(syncRecord.keysn),
				sync,
				now;

			utility_message_f3("[update SQL Statement :%s] when the md5 is different, keysn=%s, md5value=%s sync = 0", update.toString(), syncRecord.keysn, _md5);
		}
		else
		{
			Statement update(session);
			update << "UPDATE syncSDMakeup set expire_time = datetime('now','+4 hours','localtime') where keysn= ?;",
				use(syncRecord.keysn),
				sync,
				now;

			utility_message_f2("[update SQL Statement :%s] update expire time when the md5 just the same, keysn=%s, ", update.toString(), syncRecord.keysn);
		}
	}
}

bool QZSyncWorker::hasSync()
{
	if (_keysn.empty()) return true;

	struct Makeup {
		int id;
		std::string keysn;
		bool sync;
	};

	Makeup syncRecord;
	Statement select(session);
	select << "SELECT id, keysn, sync FROM syncSDMakeup WHERE keysn = ?",
		into(syncRecord.id),
		into(syncRecord.keysn),
		into(syncRecord.sync),
		use(_keysn),
		range(0, 1);

	while (!select.done()) {
		if (!select.execute())
			break;

		if(!syncRecord.sync)
			return false;
	}

	return true;
}

void QZSyncWorker::checkFromServer()
{
	if (hasSync()) return;

	DynamicStruct ds = *object;

	Object check;
	check.set("appcode", ds["fmt"]["appcode"].toString());
	check.set("keysn", _keysn);
	check.set("dataMD5", _md5);

	utility_message_f1("check : %s\n ", Var(check).convert<std::string>());

	std::string data = Var(check).convert<std::string>();
	URI uri(ds["url"]["check"].toString());

	HTTPRequest request(HTTPRequest::HTTP_POST, uri.getPath());
	HTTPClientSession session(uri.getHost(), uri.getPort());
	request.setContentLength((int)data.length());
	session.sendRequest(request) << data;

	HTTPResponse response;
	std::istream& out = session.receiveResponse(response);
	DynamicStruct res = *extract<Object::Ptr>(out);

	utility_message_f2("checking code:%s message:%s\n", res["code"].toString(), res["message"].toString());

	if (res["code"] == "1" || res["code"] == "6")
		setSync(_keysn);

	//return (res["code"] == "0" || res["code"] == "7");
}

void QZSyncWorker::sendToServer()
{
	DynamicStruct ds = *object;

	ds["fmt"]["keysn"] = _keysn;
	ds["fmt"]["dataMD5"] = _md5;
	ds["fmt"]["username"] = _name;
	ds["fmt"]["usercode"] = _code;
	ds["fmt"]["validStart"] = _validStart;
	ds["fmt"]["validEnd"] = _validEnd;
	ds["fmt"]["seals"] = _seals;

	std::string data = ds["fmt"].toString();
	URI uri(ds["url"]["sync"].toString());
	HTTPRequest request(HTTPRequest::HTTP_POST, uri.getPath());
	HTTPClientSession session(uri.getHost(), uri.getPort());
	request.setContentLength((int)data.length());
	session.sendRequest(request) << data;

	HTTPResponse response;
	std::istream& out = session.receiveResponse(response);
	DynamicStruct res = *extract<Object::Ptr>(out);
	utility_message_f2("transfer code:%s message:%s\n", res["code"].toString(), res["message"].toString());

	if (res["code"] != "0" && res["code"] != "10")
		throw Poco::LogicException("transfer failed!", res.toString());
}

void QZSyncWorker::transfer()
{
	if (hasSync()) return;

	sendToServer();
	setSync(_keysn);
}

void QZSyncWorker::setSync(std::string& keysn, bool flag)
{
	Statement select(session);
	select << "UPDATE syncSDMakeup set sync = ? ,modify_time = (datetime('now','localtime')), expire_time = (datetime('now','+4 hours','localtime')) WHERE keysn = ?;",
		use(flag), use(keysn), range(0, 1), sync, now;

	utility_message_f3("[setSync SQL Statement :%s] keysn=%s, sync=%b", select.toString(), keysn, flag);
}