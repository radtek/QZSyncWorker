#pragma once
#include "Poco/Task.h"
#include "Poco/JSON/Object.h"
#include "Poco/Data/Session.h"
#include "Poco/Mutex.h"
#include "Poco/ExpireCache.h"
#include <string>
#include <vector>
#include <cassert>
namespace Reach {
	class MediaBase;
	class SealProvider;
	class QZSyncWorker
		: public Poco::Task
	{
	public:
		QZSyncWorker();
		virtual void runTask();
	protected:
		void InitMedias();
		void InitSealProviders();
	private:
		bool IsUSBKeyPresent();
		void composite();
		void updateStatus();
		void checkFromServer();
		void sendToServer();
		void transfer();

		void setSync(std::string& keysn, bool flag = true);

		template<typename T>
		const T extract(std::istream& json)
		{
			Poco::JSON::Parser p;
			Poco::Dynamic::Var result = p.parse(json);
			poco_assert(result.type() == typeid(T));
			return result.extract<T>();
		}

		bool hasSync();
		bool infoexpired();
		void extractKeyInfo();
		void extractSealData();
		void GeneratedMD5();
		void GeneratedCode();
		void clear();
	private:
		Poco::Data::Session session;
		typedef std::vector<Poco::AutoPtr<SealProvider>> SPVec;
		typedef std::vector<Poco::AutoPtr<SealProvider>>::iterator SPIter;
		typedef std::vector<Poco::AutoPtr<MediaBase>> MBVec;
		typedef std::vector<Poco::AutoPtr<MediaBase>>::iterator MBIter;
	private:
		Poco::JSON::Object::Ptr object;
		std::string _name;
		std::string _code;
		std::string _validStart;
		std::string _validEnd;
		std::string _keysn;
		std::string _md5;
		std::string _seals;
		std::string _cert;

		Poco::FastMutex _mutex;

		MBVec _media;
		SPVec _oess;
	};
}