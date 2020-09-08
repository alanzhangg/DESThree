//
//  RSAOpenSSL.m
//  DESThreeTest
//
//  Created by zyyk on 2020/9/7.
//  Copyright © 2020 zhang alan. All rights reserved.
//

#import "RSAOpenSSL.h"

@implementation RSAOpenSSL

#pragma mark ---生成密钥对
+ (BOOL)generateRSAKeyPairWithKeySize:(int)keySize publicKey:(RSA **)publicKey privateKey:(RSA **)privateKey {
    
    if (keySize == 512 || keySize == 1024 || keySize == 2048) {
        
        /* 产生RSA密钥 */
        RSA *rsa = RSA_new();
        BIGNUM* e = BN_new();
        
        /* 设置随机数长度 */
        BN_set_word(e, 65537);
        
        /* 生成RSA密钥对 */
        RSA_generate_key_ex(rsa, keySize, e, NULL);
        
        if (rsa) {
            *publicKey = RSAPublicKey_dup(rsa);
            *privateKey = RSAPrivateKey_dup(rsa);
            return YES;
        }
    }
    return NO;
}

+ (NSString *)PEMFormatRSAKey:(RSA *)rsaKey isPublic:(BOOL)isPublickey
{
    if (!rsaKey) {
        return nil;
    }
    
    BIO *bio = BIO_new(BIO_s_mem());
    if (isPublickey)
        PEM_write_bio_RSA_PUBKEY(bio, rsaKey);
    
    else
    {
        //此方法生成的是pkcs1格式的,IOS中需要pkcs8格式的,因此通过PEM_write_bio_PrivateKey 方法生成
        // PEM_write_bio_RSAPrivateKey(bio, rsaKey, NULL, NULL, 0, NULL, NULL);
        
        EVP_PKEY* key = NULL;
        key = EVP_PKEY_new();
        EVP_PKEY_assign_RSA(key, rsaKey);
        PEM_write_bio_PrivateKey(bio, key, NULL, NULL, 0, NULL, NULL);
    }
    
    BUF_MEM *bptr;
    BIO_get_mem_ptr(bio, &bptr);
    BIO_set_close(bio, BIO_NOCLOSE); /* So BIO_free() leaves BUF_MEM alone */
    BIO_free(bio);
    return [NSString stringWithUTF8String:bptr->data];
    
}

//返回需要的 key 字符串
+ (NSString *)base64EncodedFromPEMFormat:(NSString *)PEMFormat
{
    /*
     -----BEGIN RSA PRIVATE KEY-----
     中间是需要的 key 的字符串
     -----END RSA PRIVATE KEY----
     */
    
    PEMFormat = [PEMFormat stringByReplacingOccurrencesOfString:@"\r" withString:@""];
    PEMFormat = [PEMFormat stringByReplacingOccurrencesOfString:@"\n" withString:@""];
    PEMFormat = [PEMFormat stringByReplacingOccurrencesOfString:@"\t" withString:@""];
    PEMFormat = [PEMFormat stringByReplacingOccurrencesOfString:@" "  withString:@""];
    if (![PEMFormat containsString:@"-----"]) {
        return PEMFormat;
    }
    NSString *key = [[PEMFormat componentsSeparatedByString:@"-----"] objectAtIndex:2];
    
    
    
    return key?key:PEMFormat;
}

@end
