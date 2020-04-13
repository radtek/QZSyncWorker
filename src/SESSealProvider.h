#pragma once
#include <string>
#include "SealProvider.h"
#include "Poco/SharedLibrary.h"

namespace Reach {
	///
	/// MUST install �ٳɵ���ӡ��_����CA_������˹����20191231
	///
	class SESSealProvider
		: public SealProvider
	{
	public:
		SESSealProvider();
		~SESSealProvider();
		virtual void extract(const std::string& cert);
	protected:
		bool hasStamps();
		bool hasKey();
		int count();
		void readSeal();
		void ExtractSealPicture();
	private:
		Poco::SharedLibrary sl;
		std::string _sealdata;
		std::string _areacode;
	};
}