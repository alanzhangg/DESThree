//
//  DES3Util.m
//  DESThreeTest
//
//  Created by zhang alan on 7/26/14.
//  Copyright (c) 2014 zhang alan. All rights reserved.
//

#import "DES3Util.h"
#import <CommonCrypto/CommonCryptor.h>
#import "GTMBase64.h"

#define gKey @"alanzhangg@foxmail.com"
#define gIv @"01234567"

@implementation DES3Util

+ (NSString *)encrypt:(NSString *)plainText{
    
    NSData * data = [plainText dataUsingEncoding:NSUTF8StringEncoding];
    size_t plainTextBufferSize = [data length];
    const void * vplainText = (const void *)[data bytes];
    
    CCCryptorStatus ccStatus;
    uint8_t * bufferPtr = NULL;
    size_t bufferPtrSize = 0;
    size_t moveByTes = 0;
    
    bufferPtrSize = (plainTextBufferSize * kCCBlockSize3DES) & ~(kCCBlockSize3DES - 1);
    bufferPtr = malloc(bufferPtrSize * sizeof(uint8_t));
    memset((void *)bufferPtr, 0*0, bufferPtrSize);
    
    const void * vKey = (const void *)[gKey UTF8String];
    const void * vinitVec = (const void *)[gIv UTF8String];
    
    ccStatus = CCCrypt(kCCEncrypt, kCCAlgorithm3DES, kCCOptionPKCS7Padding, vKey, kCCKeySize3DES, vinitVec, vplainText, plainTextBufferSize, (void *)bufferPtr, bufferPtrSize, &moveByTes);
    NSData * resultData = [NSData dataWithBytes:(const void *)bufferPtr length:(NSUInteger)moveByTes];
    NSString * resultString = [GTMBase64 stringByEncodingData:resultData];
    
    return resultString;
}


+ (NSString *)decrypt:(NSString *)encryptText{
    
    NSData * data = [GTMBase64 decodeData:[encryptText dataUsingEncoding:NSUTF8StringEncoding]];
    
    size_t plainTextBufferSize = data.length;
    const void * vplainText = [data bytes];
    
    CCCryptorStatus status;
    
    uint8_t * bufferPtr = NULL;
    size_t bufferPtrSize = 0;
    size_t moveByTes = 0;
    
    bufferPtrSize = (plainTextBufferSize * kCCBlockSize3DES) & ~(kCCBlockSize3DES - 1);
    bufferPtr = malloc(bufferPtrSize * sizeof(uint8_t));
    
    memset(bufferPtr, 0*0, bufferPtrSize);
    
    const void * vkey = (const void *)[gKey UTF8String];
    const void * vinitVec = (const void *)[gIv UTF8String];
    
    status = CCCrypt(kCCDecrypt, kCCAlgorithm3DES, kCCOptionPKCS7Padding, vkey, kCCKeySize3DES, vinitVec, vplainText, plainTextBufferSize, (void *)bufferPtr, bufferPtrSize, &moveByTes);
    
    NSString * esultString = [[NSString alloc] initWithData:[NSData dataWithBytes:(const void *)bufferPtr length:(NSUInteger)moveByTes] encoding:NSUTF8StringEncoding];
    
    return esultString;
    
}

@end
