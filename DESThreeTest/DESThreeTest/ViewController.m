//
//  ViewController.m
//  DESThreeTest
//
//  Created by zhang alan on 7/26/14.
//  Copyright (c) 2014 zhang alan. All rights reserved.
//

#import "ViewController.h"
#import "DES3Util.h"
#import "CommonEncryption.h"
#import "NSData+AES256.h"
#import "BARSA.h"
#import "GTMBase64.h"
#import "RSAOpenSSL.h"

@interface ViewController ()

@end

@implementation ViewController{
    SecKeyRef _publicKey;
    SecKeyRef _privateKey;
    
    
    NSString *_publicKeyBase64;
    NSString *_privateKeyBase64;
}

- (void)viewDidLoad
{
    [super viewDidLoad];
	// Do any additional setup after loading the view, typically from a nib.
    
    NSLog(@"%@", [DES3Util encrypt:@"nihao"]);
    
    NSString * str = [DES3Util encrypt:@"nihao"];
    NSString * str_1 = [DES3Util decrypt:str];
    NSLog(@"%@   %@", str, str_1);
    
    NSLog(@"md5_32Bit: %@",[CommonEncryption getMD5_32Bit_srString:@"nihao"]);
    NSLog(@"md5_16Bit: %@", [CommonEncryption getMD5_16Bit_srString:@"nihao"]);
    
    NSLog(@"sha1: %@", [CommonEncryption getSHA1String:@"nihao"]);
    NSDictionary * dic = @{
        @"code": @"Bb6GC01Fh0zR9t2t68C5",
        @"clientid": @"fb38e81626d643829af7e86e26d5500d",
        @"masterSecret": @"39d542dc79c1fa7cde20337d3ebe8681"
    };
    NSLog(@"%@", dic);
    NSError * error;
    NSData * data = [NSJSONSerialization dataWithJSONObject:dic options:0 error:&error];
    NSLog(@"%lu", (unsigned long)data.length);
    if (error) {
        NSLog(@"%@", error);
    }
    NSLog(@"%@", [CommonEncryption aes128Encrypt:data with:@"3c3109ef1afb56cf522501d4ee3c95fa"]);
    
    NSString* message = @"qwertyuisfdlsajdxcvnkhsakfh1332487";
    
    str = [NSData AES256EncryptWithPlainText:message withKey:@"asdfwetyhjuytrfd"];
    NSString* res = [NSData AES256DecryptWithCiphertext:str withkey:@"asdfwetyhjuytrfd"];
    NSLog(@"%@", str);
    NSLog(@"%@",res);
    
    //rsa
    __block NSString * publickey = @"";
    __block NSString * privatekey = @"";
    
    message = @"1234567890";
    NSString * enStr = [BARSA encryptString:message publicKey:@"MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDC+XMCciMdcEcKhVkTb4MhajiBZeLFtbRoezY1EYVyzeNRaf+31r0w850uM8LcyG08hj+kTm/KBofDSfIlWudQOnKuST5qFuH7wiSvJlS5fZ6tdbuAvmY2OOPln099/azE8Cm5hoHs1oocJtVqDCwuA0ZJ6VrefZ/bIEhKjxrlZQIDAQAB"];
    NSLog(@"%@", enStr);
    NSLog(@"%@", [BARSA decryptString:enStr privateKey:@"MIICdQIBADANBgkqhkiG9w0BAQEFAASCAl8wggJbAgEAAoGBAML5cwJyIx1wRwqFWRNvgyFqOIFl4sW1tGh7NjURhXLN41Fp/7fWvTDznS4zwtzIbTyGP6ROb8oGh8NJ8iVa51A6cq5JPmoW4fvCJK8mVLl9nq11u4C+ZjY44+WfT339rMTwKbmGgezWihwm1WoMLC4DRknpWt59n9sgSEqPGuVlAgMBAAECgYBTFKRTSHt6EdvTudqpE31XAcIuMVIeWT0UwFvq5RpuPxk8GeTjW1emwkgZ5eiE18rkXXhE9T9hYML9Dkdmb4PcxsGvzQsSUWpwII0wPQzzebAEkNGjbanQYt8sCpotIPVpLTS5QvusLEIPX9KGbM+HnSvZ3iOAT8D3TxPRjtE8yQJBAPROdZZgQynYdDZiRORvckB0xu/nOG7nUd/Svw7KsSa1+y5j165W2falEgjaL/hgBNbpHeBZQtI9sMnnuLHVqZMCQQDMToNnXBO1DlsFgSzDLWG51zYHx6qR2p4MZcXV5KwHi2wG6XudoxQfOAFH96+kYZSWNkaVSWs8x7C1SGr4w7AnAkAB1JCm9sOqDZgZTDUt7PPTLczLwVS35/3CCocp6jTXkGd4WoEkKjxpz6TJ8jCH0NhYb9isdJ6+in3HlXfZxTsHAkATy6+zvhoyutda6y85IhaL+SxFCLWgODyEGwBWPzfj60BmUw0lMv3qIHUPUhJ0rPfGri+cm2aGlxqqFgA3Zk6VAkBHwCAaYoD6hS5rM1TUmuj7kmxs4idw4vPk89/V41NEq9I/vIF+evkLzYfFWWhbkmL2UP/fLipu5ilDFj1Rh/6l"]);
    
    NSLog(@"============秘钥对=============\n");
    
//    RSA * openSSLPublicKey;
//    RSA * openSSLPrivateKey;
//
//    BOOL yes = [RSAOpenSSL generateRSAKeyPairWithKeySize:1024 publicKey:&openSSLPublicKey privateKey:&openSSLPrivateKey];
//    if (yes) {
//
//        NSString *pemPublickey =[RSAOpenSSL PEMFormatRSAKey:openSSLPublicKey isPublic:YES];
//        NSString *pemPrivatekey = [RSAOpenSSL PEMFormatRSAKey:openSSLPrivateKey isPublic:NO];
//
//        //除去-----PUBLICKEY-----获取的纯key 字符串
//        _publicKeyBase64 = [RSAOpenSSL base64EncodedFromPEMFormat:pemPublickey];
//        _privateKeyBase64 = [RSAOpenSSL base64EncodedFromPEMFormat:pemPrivatekey];
//
//        NSLog(@"%@", _publicKeyBase64);
//        NSLog(@"%@", _privateKeyBase64);
//    }
    
    
//    [RSA getRSAKeyPairWithKeySize:1024 keyPair:^(SecKeyRef publicKey, SecKeyRef privateKey) {
//        _publicKey = publicKey;
//        _privateKey = privateKey;
//        NSData * pubData = [RSA KeyBitsFromSecKey:publicKey];
//        NSData * privateData = [RSA KeyBitsFromSecKey:privateKey];
//        publickey = [pubData base64EncodedStringWithOptions:0];
//        privatekey = [privateData base64EncodedStringWithOptions:0];
//        NSLog(@"%@", publickey);
//        NSLog(@"%@", privatekey);
//    }];
//    publickey = @"MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDC1qFlx38qkWxMq3kDKjVRCxfWq/I8SzMetIKeM1zS5+ECqNeUlzznXM3Qfabqat3bU2brRWBytfGTMUigTTWnXplQzy3Vnl+Dgc3jAfNnGRiTcyoNDxtlmiHZsLwAW7R4po0Ulda0jp0feKJz47/MTcUB9GKujUnGb8PNQgce2wIDAQAB";
//    @"MIGJAoGBAMHFBHaGsrUaOw+G9+ZhjBlZNUOnKlJHVNJdryi+pHbCkk9plZsYvC4YZg9zMIJflf3tSTs213jAafmUaiHBdhGb8XS+SqxEeSH251M3GLPxZ4LvEpGR/hjGp4xQPX3wiMrEWH2zlp3Xwmhou/bWafouWJ/ytWzn4UDe7HQ2fTkdAgMBAAE="
    
//    NSData * enMessage = [RSA encryptData:[message dataUsingEncoding:NSUTF8StringEncoding] withKeyRef:_publicKey isSign:NO];
//    NSLog(@"公钥===>%@", [enMessage base64EncodedStringWithOptions:0]);
//    NSLog(@"====>%@", [RSA decryptData:enMessage privateKey:privatekey]);
}

- (void)didReceiveMemoryWarning
{
    [super didReceiveMemoryWarning];
    // Dispose of any resources that can be recreated.
}

@end
