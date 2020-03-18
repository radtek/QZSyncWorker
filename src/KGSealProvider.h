#pragma once
#include <string>
#include "SealProvider.h"

class CDKG_GetKeyInfo_FJRS;

namespace Reach {
	///
	///	MUST install 
	///
	class KGSealProvider
		: public SealProvider
	{
	public:
		KGSealProvider();
		virtual ~KGSealProvider();
		virtual void extract(const std::string& cert);
	protected:
		void readSeal();
		void ExtractSealPicture();
	private:
		CDKG_GetKeyInfo_FJRS*  _pKG_GetKeyInfo_FJRS;
	private:
		static const int all_seal = -1;
		std::string _sealdata;
		std::string _areacode;
	};
}