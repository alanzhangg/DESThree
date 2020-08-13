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
#import "RSA.h"
#import "GTMBase64.h"

@interface ViewController ()

@end

@implementation ViewController

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
    
    NSString* message = @"神奇的AES";
    
    str = [NSData AES256EncryptWithPlainText:message];
    NSString* res = [NSData AES256DecryptWithCiphertext:str];
    NSLog(@"%@", str);
    NSLog(@"%@",res);
    
    //rsa
    NSString * publickey = @"MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCA91ZpU3dzWknAxp6/7c/5THw+Ctk9r8RGAEn8i0X4D2xzeHX0ASg7rPuVGCO95dpzX05Vgkp4NW22K4ClJ4q+bIPuhA1k9iaPBOqFAmhCtMURO1QuivXNo+iQpMMCK63WttvEY51uMMKtnPJ+q5PORt4fF9mhzMspL3LD6LAj0QIDAQAB";
    NSString * privateKey = @"MIICdQIBADANBgkqhkiG9w0BAQEFAASCAl8wggJbAgEAAoGBAID3VmlTd3NaScDGnr/tz/lMfD4K2T2vxEYASfyLRfgPbHN4dfQBKDus+5UYI73l2nNfTlWCSng1bbYrgKUnir5sg+6EDWT2Jo8E6oUCaEK0xRE7VC6K9c2j6JCkwwIrrda228RjnW4wwq2c8n6rk85G3h8X2aHMyykvcsPosCPRAgMBAAECgYBdE6Vu4MmOHDSsh+zc8kKuVzA4CtZc+fT63IyJUu8Np/wKnn7quscRwrfUFBb/n9t4dulvN1iNx2nGF0GCcLZlw7GJV2uTMAwDV6Ivn/fwR6sLg1SmOH3z60NXGAWQzUGR4GTgaxUlSETUDiGUgDGPqAGmSKoi23gGFDzYEI+17QJBAPen+qK9O6BRWmZ4GDL/dcDyvIzUP/l970waH6wMZcFJJfWMKCUNq+6MjjCHk9dIflPKKARTgQGD8HoZ1P9A4L8CQQCFT6nmCeDjI1jqjvEDFtAEmSSDzlfrXIinMDbFMdtwMuP01pBEWuvVktcll9/e1O2eq5ok4RBkKuwylxe+/I9vAkA7vnhGPiRePoHyalJcKyh7DZPS3Xk5dNn/n+W4GZ2KjVzs6Yzds3igqaO7rVlK/CANkp0ovgRHG08uBYFOupX9AkBYrJHdo0qEq7l0ZFpqbJ03wcopJnMS6n03gHmeF7jYW/GHpcVWwofGi6MyrWBLb6UTex/QUii+CFMOn7Q65PJfAkBmITmSE8EiQebWfbR7ouZkZZDs8axLsblaTG7OchrV/TVbw2Gd/VwJFLrahOOILiLfAiQrWCrj6XJXn4eLNE4+";
    
    message = @"7856412346543216";
    NSString * enMessage = [RSA encryptString:message publicKey:publickey];
    NSLog(@"===>%@", enMessage);
    NSLog(@"====>%@", [RSA decryptString:enMessage privateKey:privateKey]);
    
}

- (void)didReceiveMemoryWarning
{
    [super didReceiveMemoryWarning];
    // Dispose of any resources that can be recreated.
}

@end
