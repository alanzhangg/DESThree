//
//  RSAOpenSSL.h
//  DESThreeTest
//
//  Created by zyyk on 2020/9/7.
//  Copyright © 2020 zhang alan. All rights reserved.
//

#import <Foundation/Foundation.h>
#import <openssl/pem.h>
#import <openssl/rsa.h>

NS_ASSUME_NONNULL_BEGIN

@interface RSAOpenSSL : NSObject

+ (BOOL)generateRSAKeyPairWithKeySize:(int)keySize publicKey:(RSA **)publicKey privateKey:(RSA **)privateKey;

/**
 将 RSA 类型的 key 转化为 Pem 格式的字符串

 @param rsaKey 公钥或者私钥
 @param isPublickey 是否是公钥标志
 @return pem 格式的字符串
 */
+ (NSString *)PEMFormatRSAKey:(RSA *)rsaKey isPublic:(BOOL)isPublickey;

+ (NSString *)base64EncodedFromPEMFormat:(NSString *)PEMFormat;

@end

NS_ASSUME_NONNULL_END
