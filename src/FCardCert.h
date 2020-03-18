/*************************************************************
 *				����ʡ���ְ�ȫ֤��������޹�˾				 * 
 *					 ����֤��ӿں���˵��					 * 
 *				   ���ò���ϵͳ:Windows����					 *
 *************************************************************/
#ifndef _FCARDCERT_H_
#define _FCARDCERT_H_

#ifndef FJCA_COMMON_DEFINE
#define FJCA_COMMON_DEFINE

//#define calg_md2	1
//#define calg_md4	2
#define calg_md5	3
#define calg_sha1	4
#define calg_sm3	5
#define calg_sha256	6

typedef HANDLE		DEVHANDLE;

/*
*�ٽ�ֵ����
*/
#define MAX_IV_LEN			32		//��ʼ����������󳤶�
#define	MAX_FILE_NAME_LEN	32		//�ļ�����󳤶�
#define MAX_CONTAINER_NAME_LEN	128	//��������󳤶�

/*
 *�㷨��ʶ��
 */
#define SGD_SM1_ECB		0x00000101	//SM1�㷨ECB����ģʽ
#define SGD_SM1_CBC		0x00000102	//SM1�㷨CBC����ģʽ
#define SGD_SM1_CFB		0x00000104	//SM1�㷨CFB����ģʽ
#define SGD_SM1_OFB		0x00000108	//SM1�㷨OFB����ģʽ
#define SGD_SM1_MAC		0x00000110	//SM1�㷨MAC����
#define SGD_SSF33_ECB	0x00000201	//SSF33�㷨ECB����ģʽ
#define SGD_SSF33_CBC	0x00000202	//SSF33�㷨CBC����ģʽ
#define SGD_SSF33_CFB	0x00000204	//SSF33�㷨CFB����ģʽ
#define SGD_SSF33_OFB	0x00000208	//SSF33�㷨OFB����ģʽ
#define SGD_SSF33_MAC	0x00000210	//SSF33�㷨MAC����
#define SGD_SMS4_ECB	0x00000401	//SMS4�㷨ECB����ģʽ
#define SGD_SMS4_CBC	0x00000402	//SMS4�㷨CBC����ģʽ
#define SGD_SMS4_CFB	0x00000404	//SMS4�㷨CFB����ģʽ
#define SGD_SMS4_OFB	0x00000408	//SMS4�㷨OFB����ģʽ
#define SGD_SMS4_MAC	0x00000410	//SMS4�㷨MAC����
/*	0x00000400-0x800000xx	Ϊ�������������㷨Ԥ��	*/

#define SGD_RSA			0x00010000	//RSA�㷨
#define SGD_SM2_1		0x00020100	//��Բ����ǩ���㷨
#define SGD_SM2_2		0x00020200	//��Բ������Կ����Э��
#define SGD_SM2_3		0x00020400	//��Բ���߼����㷨
/*	0x00000400��0x800000xx	Ϊ�����ǶԳ������㷨Ԥ��	*/

#define SGD_SM3			0x00000001	//SM3�Ӵ��㷨
#define SGD_SHA1		0x00000002	//SHA1�Ӵ��㷨
#define SGD_SHA256		0x00000004	//SHA256�Ӵ��㷨
/*	0x00000010��0x000000FF	Ϊ���������Ӵ��㷨Ԥ��	*/

/*
 *Ȩ������
 */
#define SECURE_NEVER_ACCOUNT	0x00000000		//������
#define SECURE_ADM_ACCOUNT		0x00000001		//����ԱȨ��
#define SECURE_USER_ACCOUNT		0x00000010		//�û�Ȩ��
#define SECURE_EVERYONE_ACCOUNT	0x000000FF		//�κ���

#pragma pack(1)

/*
 *�����������
 */
typedef struct Struct_BLOCKCIPHERPARAM{
	BYTE	IV[MAX_IV_LEN];			//��ʼ������MAX_IV_LENΪ��ʼ��������󳤶�
	ULONG	IVLen;					//��ʼ����ʵ�ʳ��ȣ����ֽڼ���
	ULONG	PaddingType;			//��䷽ʽ��0��ʾ����䣬1��ʾ����PKCS#5��ʽ�������
	ULONG	FeedBitLen;				//����ֵ��λ���ȣ����ֽڼ��㣬ֻ���OFB��CFBģʽ
} BLOCKCIPHERPARAM, *PBLOCKCIPHERPARAM;

/*
 *�ļ�����
 */
typedef struct Struct_FILEATTRIBUTE{
	CHAR	FileName[32];			//�ļ���
	ULONG	FileSize;				//�ļ���С
	ULONG	ReadRights;				//��Ȩ��
	ULONG	WriteRights;			//дȨ��
} FILEATTRIBUTE, *PFILEATTRIBUTE;

#pragma pack()

#endif

#ifdef __cplusplus
extern "C"{
#endif

/************************************************************************/
/*	1. �豸���� 														*/
/*	FCardGetDevState													*/
/*	InitFCard															*/
/*	ExitFCard															*/
/*	FCardGetDeviceInfo													*/
/*	FCardGetRandom														*/
/************************************************************************/

/*
 *	�����豸״ֵ̬��
 *	dwStateLen	�豸״ֵ̬�ĳ���
 *	pbState 	�豸״ֵ̬
 *	��ע:
		�����Key��ţ������ţ���0��ʼ�������ӡ�
		����Key���γ�������ſ��С�
		�²����Keyʹ�ÿ�����š���û�п�����ţ���ʹ���µ���š�
		��Keyδ�γ��������ʼ�ձ��ֲ��䡣
 		�������£�
 		��dwStateLen �� 8��
 		��������Key���������Ϊ0��1��2���ú�������ʱ��
 			pbState[0] = 0x31;
 			pbState[1] = 0x31;
 			pbState[2] = 0x31;
 			pbState[3] = 0x0;
 			pbState[4] = 0x0;
 			pbState[5] = 0x0;
 			pbState[6] = 0x0;
 			pbState[7] = 0x0;
		�²���һ��Key���������Ϊ3���ú�������ʱ��
  			pbState[0] = 0x31;
 			pbState[1] = 0x31;
 			pbState[2] = 0x31;
 			pbState[3] = 0x31;
 			pbState[4] = 0x0;
 			pbState[5] = 0x0;
 			pbState[6] = 0x0;
 			pbState[7] = 0x0;
		�γ��ڶ�������Key�����Ϊ1��2�����ú�������ʱ��
 			pbState[0] = 0x31;
 			pbState[1] = 0x0;
 			pbState[2] = 0x0;
 			pbState[3] = 0x31;
 			pbState[4] = 0x0;
 			pbState[5] = 0x0;
 			pbState[6] = 0x0;
 			pbState[7] = 0x0;
		�²���һ��Key���������Ϊ1���ú�������ʱ��
 			pbState[0] = 0x31;
 			pbState[1] = 0x31;
 			pbState[2] = 0x0;
 			pbState[3] = 0x31;
 			pbState[4] = 0x0;
 			pbState[5] = 0x0;
 			pbState[6] = 0x0;
 			pbState[7] = 0x0;
 */
BOOL FCardGetDevState(
	IN DWORD	dwStateLen,
	OUT BYTE	*pbState
	);

/*
 *	�����豸�������豸�ľ����
 *	szDevName		����USB��д����Key��ָ��Ҫ�򿪵����ܿ���д�豸
 					szDevNameΪUSB1��USB2 ...
 					USBX��XΪKey��ż�1���Ȳ�����豸ΪUSB1��������ΪUSB2
 *	phDev			�����豸�������
 */
BOOL InitFCard(
	IN char			*szDevName = "USB1",
	OUT DEVHANDLE	*phDev = NULL
	);

/*
 *	�Ͽ�һ���Ѿ����ӵ��豸�����ͷž����
 *	hDev			�����豸ʱ���ص��豸���
 */
BOOL ExitFCard(
	IN DEVHANDLE	hDev = NULL
	);

/*
 *	ȡ�豸��Ϣ��
 *	szDeviceInfo	�豸����ϸ��Ϣ�����ޣ��ɷ��ؿմ�
 *	szVID			Vender ID�������̱�ţ�����4�ֽڡ��磺"D6A3"
 *	szPID			Product ID������Ʒ��ţ�����4�ֽڡ��磺"2599"
 *	szSN			Serial Number������ƷΨһ���кš��磺"03081612130000001895"
 *	szPD			Produce Date�����������ڣ�����8�ֽڡ��磺"20061213"
 *	szPI			������Ϣ�����ޣ��ɷ��ؿմ�
 *	szAF			Ԥ�������ޣ��ɷ��ؿմ�
 *	szLabel 		��ǩ
 *	pdwTotalSpace	�豸�洢�ռ�
 *	pdwFreeSpace	�豸ʣ��ռ�
 *	hDev			�����豸ʱ���ص��豸���
 *	��ע��			���صĸ����ַ�����������ֻ�����ɴ�ӡ�ַ���
 					����Ӧ��֤����ÿ��Key��pszVID��pszPID��pszSN��3���������Ľ����Ψһ�ġ�
 */
BOOL FCardGetDeviceInfo(
	OUT char		*szDeviceInfo,
	OUT char		*szVID,
	OUT char		*szPID,
	OUT char		*szSN,
	OUT char		*szPD,
	OUT char		*szPI,
	OUT char		*szAF,
	OUT char		*szLabel,
	OUT DWORD		*pdwTotalSpace,
	OUT DWORD		*pdwFreeSpace,
	IN DEVHANDLE	hDev = NULL
	);

/*
 *	�����������
 *	dwRandomDataLen		������ĳ���
 *	pbRandomData		�����
 *	hDev				�����豸ʱ���ص��豸���
 */
BOOL FCardGetRandom(
	IN DWORD		dwRandomDataLen,
	OUT BYTE		*pbRandomData,
	IN DEVHANDLE	hDev = NULL
	);

/************************************************************************/
/*	2. ���ʿ��� 														*/
/*	FCardVerifyUserPin													*/
/*	FCardChangeUserPin													*/
/************************************************************************/

/*
 *	�˶��û����
 *	pbUserPin		�û�����
 *	byUserPinLen	�û�����ĳ���
 *	hDev			�����豸ʱ���ص��豸���
 *	��ע��			��У�����ʧ�ܣ����ں�������ǰ����SetLastError���ô����룺
 						0x6983		Key�ѱ�����
 						0x63CX		XΪKey����ɳ��Դ���
 */
BOOL FCardVerifyUserPin(
	IN BYTE			*pbUserPin,
	IN BYTE			byUserPinLen,
	IN DEVHANDLE	hDev = NULL
	);

/*
 *	�˶Բ��޸��û����
 *	pbOldUserPin	���û�����
 *	byOldUserPinLen ���û�����ĳ���
 *	pbNewUserPin	���û�����
 *	byNewUserPinLen ���û�����ĳ���
 *	hDev			�����豸ʱ���ص��豸���
 *	��ע��			��У�����ʧ�ܣ����ں�������ǰ����SetLastError���ô����룺
 						0x6983		Key�ѱ�����
 						0x63CX		XΪKey����ɳ��Դ���
 */
BOOL FCardChangeUserPin(
	IN BYTE			*pbOldUserPin,
	IN BYTE			byOldUserPinLen,
	IN BYTE			*pbNewUserPin,
	IN BYTE			byNewUserPinLen,
	IN DEVHANDLE	hDev = NULL
	);

/************************************************************************/
/*	3. ֤����� 														*/
/*	FCardGetCertNo														*/
/*	FCardSetCertNo														*/
/*	FCardReadCert 														*/
/************************************************************************/

/*
 *	���ؿ��ڴ�ŵ�֤��״̬:
 		0			������֤��
 		1			���ڴ��ڵ�һ��֤�� 
 		2			���ڴ��ڵڶ���֤��	 
 		3			���ڴ��ڶ���֤��
 *	pbCertNo		֤��״̬
 *	hDev			�����豸ʱ���ص��豸���
 */
BOOL FCardGetCertNo(
	OUT BYTE		*pbCertNo,
	IN DEVHANDLE	hDev = NULL
	);

/*
 *	ѡ��ǰ������֤�飬����Ϊ��һ��֤�顣
 *	byCertNo		֤��ţ�1-2��
 					��Key�ڴ��˫֤��ʱ����һ��֤��Ϊǩ��֤�飬�ڶ���֤��Ϊ����֤�顣
 *	hDev			�����豸ʱ���ص��豸���
 */
BOOL FCardSetCertNo(
	IN BYTE			byCertNo,
	IN DEVHANDLE	hDev = NULL
	);

/*
 *	�����ܿ���Key�ж�ȡ��ǰ֤�飨DER���룩��
 *	pbCert			֤������
 *	pdwCertLen		����Ϊ֤�����ݻ������ĳ��ȣ����Ϊʵ��֤�����ݵĳ���
 *	hDev			�����豸ʱ���ص��豸���
 *	��ע��			���ȵ���FCardSetCertNoѡ��ǰ������֤�顣
 */
BOOL FCardReadCert(
	OUT BYTE		*pbCert,
	IN OUT DWORD	*pdwCertLen,
	IN DEVHANDLE	hDev = NULL
	);

/************************************************************************/
/*	4. RSA����	 														*/
/*	FCardSign 															*/
/*	FCardSignDigest														*/
/*	FCardVerifyDigest													*/
/************************************************************************/

/*
 *	��RSA˽Կ�����ݽ��м��ܡ�
 *	pbData				����������
 *	dwDataLen			���������ݵĳ���
 *	pbSignedData		��������
 *	pdwSignedDataLen	����Ϊ�������ݻ������ĳ��ȣ����Ϊʵ�ʼ������ݵĳ���
 *	hDev				�����豸ʱ���ص��豸���
 *	��ע��				���ȵ���FCardSetCertNoѡ��ǰ������֤�顣
 */
BOOL FCardSign(
	IN BYTE				*pbData,
	IN DWORD			dwDataLen,
	OUT BYTE			*pbSignedData,
	IN OUT DWORD		*pdwSignedDataLen,
	IN DEVHANDLE		hDev = NULL
	);

/*
 *	��RSA˽Կ�����ݽ���ǩ����
 *	pbData				��ǩ������
 *	dwDataLen			��ǩ�����ݵĳ���
 *	byHashAlgID			ժҪ�㷨
 *	pbSignedData		ǩ������
 *	pdwSignedDataLen	����Ϊǩ�����ݻ������ĳ��ȣ����Ϊʵ��ǩ�����ݵĳ���
 *	hDev				�����豸ʱ���ص��豸���
 *	��ע��				���ȵ���FCardSetCertNoѡ��ǰ������֤�顣
 */
BOOL FCardSignDigest(
	IN BYTE				*pbData,
	IN DWORD			dwDataLen,
	IN BYTE				byHashAlgID,
	OUT BYTE			*pbSignedData,
	IN OUT DWORD		*pdwSignedDataLen,
	IN DEVHANDLE		hDev = NULL
	);

/*
 *	��֤RSA����ǩ����
 *	pbSignedData	ǩ������
 *	dwSignedDataLen	ǩ�����ݵĳ���
 *	byHashAlgID		ժҪ�㷨
 *	pbData			��ǩ������
 *	dwDataLen		��ǩ�����ݵĳ���
 *	hDev			�����豸ʱ���ص��豸���
 *	��ע��			���ȵ���FCardSetCertNoѡ��ǰ������֤�顣
 */
BOOL FCardVerifyDigest(
	IN BYTE			*pbSignedData,
	IN DWORD		dwSignedDataLen,
	IN BYTE			byHashAlgID,
	IN BYTE			*pbData,
	IN DWORD		dwDataLen,
	IN DEVHANDLE	hDev = NULL
	);

/************************************************************************/
/*	5. ECC֤����� 														*/
/*	FCardECCGetCertNo													*/
/*	FCardECCSetCertNo													*/
/*	FCardECCReadCert 													*/
/************************************************************************/

/*
 *	���ؿ��ڴ�ŵ�֤��״̬:
 		0			������֤��
 		1			���ڴ��ڵ�һ��֤�� 
 		2			���ڴ��ڵڶ���֤��	 
 		3			���ڴ��ڶ���֤��
 *	pbCertNo		֤��״̬
 *	hDev			�����豸ʱ���ص��豸���
 */
BOOL FCardECCGetCertNo(
	OUT BYTE		*pbCertNo,
	IN DEVHANDLE	hDev = NULL
	);

/*
 *	ѡ��ǰ������֤�飬����Ϊ��һ��֤�顣
 *	byCertNo		֤��ţ�1-2��
 					��Key�ڴ��˫֤��ʱ����һ��֤��Ϊǩ��֤�飬�ڶ���֤��Ϊ����֤�顣
 *	hDev			�����豸ʱ���ص��豸���
 */
BOOL FCardECCSetCertNo(
	IN BYTE			byCertNo,
	IN DEVHANDLE	hDev = NULL
	);

/*
 *	�����ܿ���Key�ж�ȡ��ǰ֤�飨DER���룩��
 *	pbCert			֤������
 *	pdwCertLen		����Ϊ֤�����ݻ������ĳ��ȣ����Ϊʵ��֤�����ݵĳ���
 *	hDev			�����豸ʱ���ص��豸���
 *	��ע��			���ȵ���FCardECCSetCertNoѡ��ǰ������֤�顣
 */
BOOL FCardECCReadCert(
	OUT BYTE		*pbCert,
	IN OUT DWORD	*pdwCertLen,
	IN DEVHANDLE	hDev = NULL
	);

/************************************************************************/
/*	6. ECC����															*/
/*	FCardECCSign														*/
/*	FCardExtECCVerify													*/
/*	FCardECCSignDigest													*/
/*	FCardExtECCVerifyDigest												*/
/************************************************************************/
//	��ע��
//	x||y��x��y��ƴ��

/*
 *	��ECC��Կ������ǩ����
 *	pbData				��ǩ�����ݣ�����Ϊ32�ֽ�
 *	dwDataLen			��ǩ�����ݵĳ���
 *	pbSignedData		ǩ�����ݣ���ʽ��r||s
 *	pdwSignedDataLen	����Ϊǩ�����ݻ������ĳ��ȣ����Ϊʵ��ǩ�����ݵĳ���
 *	hDev				�����豸ʱ���ص��豸���
 *	��ע��				���ȵ���FCardECCSetCertNoѡ��ǰ������֤�顣
 */
BOOL FCardECCSign(
	IN BYTE 			*pbData,
	IN DWORD			dwDataLen,
	OUT BYTE			*pbSignedData,
	IN OUT DWORD		*pdwSignedDataLen,
	IN DEVHANDLE		hDev = NULL
	);

/*
 *	ʹ���ⲿ�����ECC��Կ��ǩ����֤��
 *	pbSignedData		ǩ�����ݣ���ʽ��r||s
 *	dwSignedDataLen		ǩ�����ݵĳ���
 *	pbECCPubKey 		��Կ���ݣ���ʽ��x||y
 *	dwECCPubKeyLen		��Կ���ݵĳ���
 *	pbData				��ǩ�����ݣ�����Ϊ32�ֽ�
 *	dwDataLen			��ǩ�����ݵĳ���
 *	hDev				�����豸ʱ���ص��豸���
 */
BOOL FCardExtECCVerify(
	IN BYTE 			*pbSignedData,
	IN DWORD			dwSignedDataLen,
	IN BYTE 			*pbECCPubKey,
	IN DWORD			dwECCPubKeyLen,
	IN BYTE 			*pbData,
	IN DWORD			dwDataLen,
	IN DEVHANDLE		hDev = NULL
	);

/*
 *	��ECC��Կ������ǩ����
 *	pbData				��ǩ������
 *	dwDataLen			��ǩ�����ݵĳ���
 *	byHashAlgID 		ժҪ�㷨
						��byHashAlgIDΪSM3��dwUserIDLen��Ϊ0�������pbUserID��Ч
						��ʱִ��SM2�㷨ǩ��Ԥ����1��Ԥ����2����
 *	pbUserID			�û�ID
 *	dwUserIDLen 		�û�ID�ĳ���
 *	pbSignedData		ǩ�����ݣ���ʽ��r||s
 *	pdwSignedDataLen	����Ϊǩ�����ݻ������ĳ��ȣ����Ϊʵ��ǩ�����ݵĳ���
 *	hDev				�����豸ʱ���ص��豸���
 *	��ע��				���ȵ���FCardECCSetCertNoѡ��ǰ������֤�顣
 */
BOOL FCardECCSignDigest(
	IN BYTE 			*pbData,
	IN DWORD			dwDataLen,
	IN BYTE 			byHashAlgID,
	IN BYTE 			*pbUserID,
	IN DWORD			dwUserIDLen,
	OUT BYTE			*pbSignedData,
	IN OUT DWORD		*pdwSignedDataLen,
	IN DEVHANDLE		hDev = NULL
	);

/*
 *	ʹ���ⲿ�����ECC��Կ��ǩ����֤��
 *	pbSignedData		ǩ�����ݣ���ʽ��r||s
 *	dwSignedDataLen		ǩ�����ݵĳ���
 *	byHashAlgID 		ժҪ�㷨
						��byHashAlgIDΪSM3��dwUserIDLen��Ϊ0�������pbUserID��Ч
						��ʱִ��SM2�㷨ǩ��Ԥ����1��Ԥ����2����
 *	pbECCPubKey 		��Կ���ݣ���ʽ��x||y
 *	dwECCPubKeyLen		��Կ���ݵĳ���
 *	pbUserID			�û�ID
 *	dwUserIDLen 		�û�ID�ĳ���
 *	pbData				��ǩ������
 *	dwDataLen			��ǩ�����ݵĳ���
 *	hDev				�����豸ʱ���ص��豸���
 */
BOOL FCardExtECCVerifyDigest(
	IN BYTE 			*pbSignedData,
	IN DWORD			dwSignedDataLen,
	IN BYTE 			byHashAlgID,
	IN BYTE 			*pbECCPubKey,
	IN DWORD			dwECCPubKeyLen,
	IN BYTE 			*pbUserID,
	IN DWORD			dwUserIDLen,
	IN BYTE 			*pbData,
	IN DWORD			dwDataLen,
	IN DEVHANDLE		hDev = NULL
	);

#ifdef __cplusplus
}
#endif

#endif
