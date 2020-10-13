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
    
//    NSString* message = @"qwertyuisfdlsajdxcvnkhsakfh1332487";
//
//    str = [NSData AES256EncryptWithPlainText:message withKey:@"asdfwetyhjuytrfd"];
//    NSString* res = [NSData AES256DecryptWithCiphertext:str withkey:@"asdfwetyhjuytrfd"];
//    NSLog(@"%@", str);
//    NSLog(@"%@",res);
    
    NSFileManager * magager = [NSFileManager defaultManager];
    NSString * filepath = [NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES) lastObject];
    //加密
    NSData * amrdeData = [NSData dataWithContentsOfFile:[[NSBundle mainBundle] pathForResource:@"1602301917588_decrypt" ofType:@"amr"]];
    NSData * amrendata = [NSData AES256EncryptWithPlainData:amrdeData withKey:@"asdfwetyhjuytrfd"];
    NSLog(@"%d", [magager createFileAtPath:[NSString stringWithFormat:@"%@/enss.amr", filepath] contents:amrendata attributes:nil]);
    
    //解密
    NSData * amrdedata = [NSData AES256DecryptWithCipherData:amrendata withKey:@"asdfwetyhjuytrfd"];
    NSLog(@"%d", [magager createFileAtPath:[NSString stringWithFormat:@"%@/dess.amr", filepath] contents:amrdedata attributes:nil]);
        
    
//    //rsa
//    __block NSString * publickey = @"";
//    __block NSString * privatekey = @"";
//
//    message = @"汉皇重色思倾国，御宇多年求不得。杨家有女初长成，养在深闺人未识。天生丽质难自弃，一朝选在君王侧。回眸一笑百媚生，六宫粉黛无颜色。春寒赐浴华清池，温泉水滑洗凝脂。侍儿扶起娇无力，始是新承恩泽时。云鬓花颜金步摇，芙蓉帐暖度春宵。春宵苦短日高起，从此君王不早朝。承欢侍宴无闲暇，春从春游夜专夜。后宫佳丽三千人，三千宠爱在一身。金屋妆成娇侍夜，玉楼宴罢醉和春。姊妹弟兄皆列土，可怜光彩生门户。遂令天下父母心，不重生男重生女。骊宫高处入青云，仙乐风飘处处闻。缓歌慢舞凝丝竹，尽日君王看不足。渔阳鼙鼓动地来，惊破《霓裳羽衣曲》。九重城阙烟尘生，千乘万骑西南行。翠华摇摇行复止，西出都门百余里。六军不发无奈何，\n宛转娥眉马前死。\
//    花钿委地无人收，翠翘金雀玉搔头。\
//    君王掩面救不得，回看血泪相和流。\
//    黄埃散漫风萧索，云栈萦纡登剑阁。\
//    峨嵋山下少人行，旌旗无光日色薄。\
//    蜀江水碧蜀山青，圣主朝朝暮暮情。\
//    行宫见月伤心色，夜雨闻铃肠断声。\
//    天旋日转回龙驭，到此踌躇不能去。(日转 一作：地转)\
//    马嵬坡下泥土中，不见玉颜空死处。\
//    君臣相顾尽沾衣，东望都门信马归。\
//    归来池苑皆依旧，太液芙蓉未央柳。\
//    芙蓉如面柳如眉，对此如何不泪垂？\
//    春风桃李花开夜，秋雨梧桐叶落时。(花开夜 一作：花开日)\
//    西宫南内多秋草，落叶满阶红不扫。(南内 一作：南苑)\
//    梨园弟子白发新，椒房阿监青娥老。\
//    夕殿萤飞思悄然，孤灯挑尽未成眠。\
//    迟迟钟鼓初长夜，耿耿星河欲曙天。\
//    鸳鸯瓦冷霜华重，翡翠衾寒谁与共？\
//    悠悠生死别经年，魂魄不曾来入梦。\
//    临邛道士鸿都客，能以精诚致魂魄。\
//    为感君王辗转思，遂教方士殷勤觅。\
//    排空驭气奔如电，升天入地求之遍。\
//    上穷碧落下黄泉，两处茫茫皆不见。\
//    忽闻海上有仙山，山在虚无缥缈间。\
//    楼阁玲珑五云起，其中绰约多仙子。\
//    中有一人字太真，雪肤花貌参差是。\
//    金阙西厢叩玉扃，转教小玉报双成。\
//    闻道汉家天子使，九华帐里梦魂惊。\
//    揽衣推枕起徘徊，珠箔银屏迤逦开。\
//    云鬓半偏新睡觉，花冠不整下堂来。";
//
//    message = @"hello world";
//
//    NSString * enStr = [BARSA encryptString:message publicKey:@"MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCI7kyD1/drBbI7XJWuFmzrvgyuSM/pafcl3yVe3/QIMZqUDV1AVlRYkg/e8F+QYUzzCy7VAtdP2b+5xhZJkQkMv3HtkLiqXLjEF9RAR7ablqC6PShmOfxJpiHOopprMm/umgkzCFbXg0yeSjRxBDZBxtdzcA0oPPPE1pOOTb+PmQIDAQAB"];
//    NSLog(@"====》%@", enStr);
//    NSString * deStr = [BARSA decryptString:enStr privateKey:@"MIICXAIBAAKBgQCI7kyD1/drBbI7XJWuFmzrvgyuSM/pafcl3yVe3/QIMZqUDV1AVlRYkg/e8F+QYUzzCy7VAtdP2b+5xhZJkQkMv3HtkLiqXLjEF9RAR7ablqC6PShmOfxJpiHOopprMm/umgkzCFbXg0yeSjRxBDZBxtdzcA0oPPPE1pOOTb+PmQIDAQABAoGARa9AMTiPKV/UvHD5m4a+F5q4SVm0tUzAAf31vrqqLiFQUVgbxMoqUojCmuopOAjMaEOgqbawbGqcL6anYPj2aU4LibMnvhX742xruuynkRJ00lLwOpo4iy/iGa77FD4ZTc98Vyryuhf+rOrW8TkoRC2+U0U9EUA1+tJX2sK0yAECQQDWpVbREEa8SFSh34QuiZ6PMJLTYSlzkfF5b3NsJ9EhzTZQ2ALfOp8eau1Nx38z8QMIelK/ey1Aqp8wo5i0kuO5AkEAo0/v+yYTsa3UiDMwdYK6Y3Cbx1dAn/OLYjOqHFBQD+rnIeBED7w0Yb533gAKjytKfMNr8hZh7BSfOpRtAzm64QJBAL+a3ELHqr0MPDA7nH0GcDoV/BshEqWN0+a47GnRqUfpLeFA0l9+rueyP588xHoTXMfGmfM/+4dMR8pdX0ViElECQHjvUiPmL4FM22y8k28BjqrikckNGMMZ46al4Zuz8YXICr6wR1ZrpVKYbEVOPIOGqFM5l68e2garwrnrfcp8rqECQGlHKYasYmuQMVEjtUOfEwMGnRT4GPF+Tf2Zyi+zTe4tcRO2ZElsGvS6Piz0ZdaK85yhDe/5IhKbBaCJd2gZBUk="];
//    NSLog(@"解密----%@", deStr);
//
//    NSLog(@"============秘钥对=============");

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
