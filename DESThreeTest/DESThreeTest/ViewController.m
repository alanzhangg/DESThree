//
//  ViewController.m
//  DESThreeTest
//
//  Created by zhang alan on 7/26/14.
//  Copyright (c) 2014 zhang alan. All rights reserved.
//

#import "ViewController.h"
#import "DES3Util.h"

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
}

- (void)didReceiveMemoryWarning
{
    [super didReceiveMemoryWarning];
    // Dispose of any resources that can be recreated.
}

@end
