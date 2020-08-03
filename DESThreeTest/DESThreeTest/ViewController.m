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
}

- (void)didReceiveMemoryWarning
{
    [super didReceiveMemoryWarning];
    // Dispose of any resources that can be recreated.
}

@end
