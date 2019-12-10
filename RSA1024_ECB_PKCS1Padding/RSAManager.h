//
//  RSAManager.h
//  RSA1024_ECB_PKCS1Padding
//
//  Created by syt on 2019/12/5.
//  Copyright © 2019 syt. All rights reserved.
//

#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

@interface RSAManager : NSObject

+ (NSString *)encryptRSA:(NSString *)message PublicKey:(NSString *)pubKey;


@end

NS_ASSUME_NONNULL_END
