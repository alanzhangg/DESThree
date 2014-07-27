//
//  CommonEncryption.m
//  DESThreeTest
//
//  Created by zhang alan on 7/27/14.
//  Copyright (c) 2014 zhang alan. All rights reserved.
//

#import "CommonEncryption.h"
#import "GTMBase64.h"

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


@end
