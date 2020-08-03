//
//  CommonEncryption.m
//  DESThreeTest
//
//  Created by zhang alan on 7/27/14.
//  Copyright (c) 2014 zhang alan. All rights reserved.
//

#import "CommonEncryption.h"
#import "GTMBase64.h"
#import <CommonCrypto/CommonCryptor.h>

@implementation CommonEncryption

+ (NSString *)getMD5_32Bit_srString:(NSString *)srcString{
    
    const char * cStr = [srcString UTF8String];
    unsigned char digest[CC_MD5_DIGEST_LENGTH];
    
    CC_MD5(cStr, strlen(cStr), digest);
    NSMutableString * result = [[NSMutableString alloc] initWithCapacity:CC_MD5_DIGEST_LENGTH * 2];
    
    for (int i = 0; i < CC_MD5_DIGEST_LENGTH; i++) {
        [result appendFormat:@"%02x", digest[i]];
    }
    
    return result;
    
}

+ (NSString *)getMD5_16Bit_srString:(NSString *)srcString{
    
    NSString * md5_32Bit_String = [self getMD5_32Bit_srString:srcString];
    NSString * md5_16Bit_String = [[md5_32Bit_String substringToIndex:24] substringFromIndex:8]; //即9 ~ 25位
    
    return md5_16Bit_String;
    
}

+ (NSString *)getSHA1String:(NSString *)srcString{
    
    const char * cstr = [srcString cStringUsingEncoding:NSUTF8StringEncoding];
    NSData * data = [NSData dataWithBytes:cstr length:srcString.length];
    uint8_t digest[CC_SHA1_DIGEST_LENGTH];
    
    CC_SHA1(data.bytes, data.length, digest);
    
    NSMutableString * string = [[NSMutableString alloc] initWithCapacity:CC_SHA1_DIGEST_LENGTH * 2];
    for (int i = 0; i < CC_SHA1_DIGEST_LENGTH; i++) {
        [string appendFormat:@"%02x", digest[i]];
    }
    return string;
}

+ (NSString *)sha1_base64:(NSString *)srcString{
    
    const char * cstr = [srcString cStringUsingEncoding:NSUTF8StringEncoding];
    NSData * data = [NSData dataWithBytes:cstr length:srcString.length];
    uint8_t digest[CC_SHA1_DIGEST_LENGTH];
    
    CC_SHA1(data.bytes, data.length, digest);
    
    NSData * base64 = [NSData dataWithBytes:digest length:CC_SHA1_DIGEST_LENGTH];
    base64 = [GTMBase64 encodeData:base64];
    NSString * output = [[NSString alloc] initWithData:base64 encoding:NSUTF8StringEncoding];
    
    return output;
}

+ (NSString *)aes128Encrypt:(NSData *)data with:(NSString *)key{
    if (key.length == 0) {
        key = @"AES128Key";
    }
//    key = [[NSString alloc] initWithString:@"3c3109ef1afb56cf"];
    char keyPtr[kCCKeySizeAES128 + 1];
    memset(keyPtr, 0, sizeof(keyPtr));
//    key = [[NSString alloc] initWithData:keyData encoding:NSUTF8StringEncoding];
//    const void *keyPtr = (const void *) [[CommonEncryption dataWithHexString:key] bytes];
    NSData * keydata = [CommonEncryption dataWithHexString:key];
    [keydata getBytes:keyPtr length:16];
    for (int i = 0; i <= 16; i++) {
        NSLog(@"%d", keyPtr[i]);
    }
    
//    [key getCString:keyPtr maxLength:sizeof(keyPtr) encoding:NSUTF8StringEncoding];
    NSUInteger datalength = data.length;
    size_t bufferSize = datalength + kCCBlockSizeAES128;
    void * buffer = malloc(bufferSize);
    size_t numBytesEncrypted = 0;
    
    CCCryptorStatus cryptStatus = CCCrypt(kCCEncrypt,
    
                                             kCCAlgorithmAES,
    
                                             kCCOptionPKCS7Padding | kCCOptionECBMode,
    
                                             keyPtr,
    
                                             kCCBlockSizeAES128,
    
                                             NULL,
    
                                             [data bytes],
    
                                             datalength,
    
                                             buffer,
    
                                             bufferSize,
    
                                             &numBytesEncrypted);
    if (cryptStatus == kCCSuccess) {
    
        NSData *resultData = [NSData dataWithBytesNoCopy:buffer length:numBytesEncrypted];
        
        NSString *base64String = [resultData base64EncodedStringWithOptions:0];
    
           return base64String;
    
       }
    
       free(buffer);
    
       return nil;
}

+(NSData*)dataWithHexString:(NSString*)hexString{
    
    const char *chars = [hexString UTF8String];
    int i = 0;
    NSUInteger len = hexString.length;

    NSMutableData *data = [NSMutableData dataWithCapacity:len / 2];
    char byteChars[3] = {'\0','\0','\0'};
    unsigned long wholeByte;

    while (i < len) {
        byteChars[0] = chars[i++];
        byteChars[1] = chars[i++];
        wholeByte = strtoul(byteChars, 0, 16);
        [data appendBytes:&wholeByte length:1];
    }

    return data;
    
}


@end
