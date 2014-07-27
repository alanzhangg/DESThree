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
}

- (void)didReceiveMemoryWarning
{
    [super didReceiveMemoryWarning];
    // Dispose of any resources that can be recreated.
}

@end
