//
// SealVendor.h
//
//
// Definition of the DOM Document class.
//
// Copyright (c) 2019-2021, Fujian Reach Informatics Software Engineering GmbH.
// and Contributors.
//
// SPDX-License-Identifier:	BSL-1.0
//

#ifndef SEAL_VENDOR_INCLUDED
#define SEAL_VENDOR_INCLUDED

/// 本标准规定的接口以C标准DLL（非com格式）形式提供
/// 
/// 部署说明：
/// 将两个文件放在系统目录下或者应用程序同级目录下即可。

/// 描述：判断签章设备是否连接
/// 返回值：0 签章设备存在 其他值签章设备不存在
int __stdcall IsUKIn();

/// 描述：获取签章数目
/// 返回值：签章数目

int __stdcall GetSealCount();

///
/// 描述：获取签章数据
/// 参数：nIndex 签章索引 0为第一个章，以此类推 -1获取所有签章
/// 返回值：签章数据
/// ReadSealData 返回值格式如下：
/// 
/// <sealinfos>
///   <sealbaseinfo>
///     <username>用户名称</username>
///     <projectname>项目名称</projectname>
///   </sealbaseinfo>
///   <sealinfo>
///     <sealname>签章名称</sealname>
///     <sealtime>签章到期时间</sealtime>
///     <sealwidth>图片宽度(cm, 精确到小数点后2位)</sealwidth>
///     <sealhight>图片高度(cm, 精确到小数点后2位)</sealhight>
///     <sealdata>签章印模base64数据</sealdata>
///	 </sealinfo>
/// </sealinfos>

char* __stdcall ReadSealData(int nIndex);

#endif // SEAL_VENDOR_INCLUDED