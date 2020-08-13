//
//  CommonEncryption.h
//  DESThreeTest
//
//  Created by zhang alan on 7/27/14.
//  Copyright (c) 2014 zhang alan. All rights reserved.
//

#import <Foundation/Foundation.h>
#import <CommonCrypto/CommonDigest.h>

@interface CommonEncryption : NSObject

//32位MD5加密
+ (NSString *)getMD5_32Bit_srString:(NSString *)srcString;

//16位MD5加密
+ (NSString *)getMD5_16Bit_srString:(NSString *)srcString;

//sha1 加密 sha256 sha384 sha512相似
+ (NSString *)getSHA1String:(NSString *)srcString;

+ (NSString *)sha1_base64:(NSString *)srcString;

+ (NSString *)aes128Encrypt:(NSData *)data with:(NSString *)key;

+ (NSString *)stringFromHexString:(NSString *)hexString;


@end
