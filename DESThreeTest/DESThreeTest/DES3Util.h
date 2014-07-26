//
//  DES3Util.h
//  DESThreeTest
//
//  Created by zhang alan on 7/26/14.
//  Copyright (c) 2014 zhang alan. All rights reserved.
//

#import <Foundation/Foundation.h>

@interface DES3Util : NSObject

+ (NSString *)encrypt:(NSString *)plainText;
+ (NSString *)decrypt:(NSString *)encryptText;

@end
