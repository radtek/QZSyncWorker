// �����Ϳ������á�����ࡱ�����ļ�������ɵ� IDispatch ��װ��

//#import "../COM/KG_GetKeyInfo_FJRS.ocx" no_namespace
// CDKG_GetKeyInfo_FJRS ��װ��

class CDKG_GetKeyInfo_FJRS : public COleDispatchDriver
{
public:
	CDKG_GetKeyInfo_FJRS(){} // ���� COleDispatchDriver Ĭ�Ϲ��캯��
	CDKG_GetKeyInfo_FJRS(LPDISPATCH pDispatch) : COleDispatchDriver(pDispatch) {}
	CDKG_GetKeyInfo_FJRS(const CDKG_GetKeyInfo_FJRS& dispatchSrc) : COleDispatchDriver(dispatchSrc) {}

	// ����
public:

	// ����
public:


	// _DKG_GetKeyInfo_FJRS ����
public:
	void AboutBox()
	{
		InvokeHelper(DISPID_ABOUTBOX, DISPATCH_METHOD, VT_EMPTY, NULL, NULL);
	}
	CString KGGetKeyInfo()
	{
		CString result;
		InvokeHelper(0x1, DISPATCH_METHOD, VT_BSTR, (void*)&result, NULL);
		return result;
	}

	// _DKG_GetKeyInfo_FJRS ����
public:

};
