//
//  XORCipher.h
//  lab1
//
//  Created by Olga Saliy on 10/1/17.
//  Copyright © 2017 Olga Saliy. All rights reserved.
//

#import <Foundation/Foundation.h>

typedef enum {
    TaskFirst,
    TaskSecond
} Task;

@interface XORCipher : NSObject

- (instancetype)initWithText:(NSString *)text;
- (void)setEncryptedText:(NSString *)text;
- (NSString *)getDecryptedTextFrom:(Task)task;

@end
