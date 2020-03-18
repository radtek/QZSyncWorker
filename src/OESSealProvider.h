#pragma once
#include <string>
#include "SealProvider.h"
#include "Poco/SharedLibrary.h"
#include "Poco/Util/Application.h"

namespace Reach {
	///
	/// MUST install StampManagev1.0Build1906_1712
	///
	class OESSealProvider
		: public SealProvider
	{
	public:
		OESSealProvider();
		~OESSealProvider();
		virtual void extract(const std::string& cert);
	protected:
		bool hasStamps();
		void readSeal();
		//void GetDeviceInfo(void* hDev);
		void ExtractSealPicture();
	private:
		int count();
		void handleLastError(int code);
	private:
		Poco::SharedLibrary sl;
		std::string _certContent;
		std::string _sealdata;
		std::string _areacode;
	};
}