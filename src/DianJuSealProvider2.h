#pragma once
#include "SealProvider.h"
#include "Poco/SharedLibrary.h"

namespace Reach {
	class DianJuSealProvider2 : 
		public SealProvider
	{
	public:
		DianJuSealProvider2();
		~DianJuSealProvider2();
		virtual void extract(const std::string& cert);

	protected:
		void readSeal();
		bool hasStamps();
		void ExtractSealPicture();
	private:
		int count();
		bool hasKey();
	private:
		std::string _sealdata;
		std::string _areacode;
		std::string _defaultname;
		Poco::SharedLibrary sl;
	};
}

