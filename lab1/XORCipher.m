//
//  XORCipher.m
//  lab1
//
//  Created by Olga Saliy on 10/1/17.
//  Copyright © 2017 Olga Saliy. All rights reserved.
//

#import "XORCipher.h"

@interface XORCipher ()

@property (nonatomic) NSString *text;

@end

@implementation XORCipher

- (instancetype)initWithText:(NSString *)text {
    self = [super init];
    if (self) {
        _text = text;
    }
    return self;
}

- (void)setEncryptedText:(NSString *)text {
    _text = text;
}

#pragma mark Specified for Second task

- (NSString *)transalteTextFromHexIntoChar:(NSString *)text {
    NSMutableString *output = [[NSMutableString alloc] init];
    for (NSUInteger i=0; i<[text length]-1; i=i+2) {
        NSString *str = [text substringWithRange:NSMakeRange(i, 2)];

        //Rescale from hex to dec
        unsigned int outVal;
        NSScanner* scanner = [NSScanner scannerWithString:str];
        [scanner scanHexInt:&outVal];

        if (outVal == 0)
            [output appendFormat:@"%@", @"\0"]; // append a single null
        else
            [output appendFormat:@"%c", (char)outVal];
    }

    return output;
}

- (NSInteger)calculateKeyLength:(NSString *)text {
    NSMutableArray *frequencyArray = [[NSMutableArray alloc] initWithObjects:[NSNumber numberWithDouble: 0], nil];
    int k = 0;
    //Count frequency while shifting
    for (int shift = 1; shift < self.text.length; shift++) {
        for (int i = 0; i < self.text.length; i++) {
            if (i <= shift) {
                if ([self.text characterAtIndex:i] == [self.text characterAtIndex:self.text.length - 1 - shift + i])
                    k++;
            } else {
                if (i + shift >= self.text.length) {
                    [frequencyArray addObject:[NSNumber numberWithDouble:(double) k / self.text.length]];
                    k = 0;
                    break;
                }
                if ([self.text characterAtIndex:i] == [self.text characterAtIndex:i - shift])
                    k++;
            }
        }
    }
    
    
    //Array with possible key lengths
    NSMutableArray *keyLengths = [[NSMutableArray alloc] init];
    
    BOOL flag = NO;
    NSInteger prevFreq = 0, currFreq = 0;
    //The value of the Index of Coincidence was taken from http://practicalcryptography.com/cryptanalysis/stochastic-searching/cryptanalysis-vigenere-cipher/
    for (int i = 1; i < frequencyArray.count/2; i++) {
        if ([[frequencyArray objectAtIndex:i-1] doubleValue] < [[frequencyArray objectAtIndex:i] doubleValue]
            && [[frequencyArray objectAtIndex:i] doubleValue] > [[frequencyArray objectAtIndex:i+1] doubleValue]
            && [[frequencyArray objectAtIndex:i] doubleValue] > 0.045) {
            if (flag) {
                flag = NO;
                prevFreq = i;
            } else {
                flag = YES;
                currFreq = i;
                [keyLengths addObject:[NSNumber numberWithInteger:currFreq - prevFreq]];
            }
        }
    }
    
    NSInteger keyLength = [self findMostCommonlyNumberInArray:keyLengths];
    return keyLength;
}

- (NSInteger)findMostCommonlyNumberInArray:(NSArray *)array {
    NSCountedSet *setOfObjects = [[NSCountedSet alloc] initWithArray:array];
    
    //Declaration of objects
    NSNumber *mostOccurringObject = [NSNumber numberWithInteger:0];
    NSUInteger highestCount = 0;
    
    //Iterate in set to find highest count for a object
    for (NSNumber *strObject in array) {
        NSUInteger tempCount = [setOfObjects countForObject:strObject];
        if (tempCount > highestCount) {
            highestCount = tempCount;
            mostOccurringObject = strObject;
        }
    }
    return mostOccurringObject.integerValue;
}

-(NSArray *)splitTextInto:(NSInteger)parts {
    NSMutableArray *general = [[NSMutableArray alloc] initWithCapacity:parts];
    
    for (int i = 0; i < parts; i++) {
        NSMutableString *part = [[NSMutableString alloc] init];
        for (int j = i; j < self.text.length; j += parts) {
            if ([self.text characterAtIndex:j] == 0) {
                [part appendFormat:@"%@", @"\0"];
            } else {
                [part appendFormat:@"%c", [self.text characterAtIndex:j]];
            }
        }
        [general addObject:part];
    }
    return general;
}

#pragma mark Specified for third task


#pragma mark General methods

- (NSString *)getDecryptedTextFrom:(Task)task {
    if (![self.text length])
        return nil;
    _text = [self.text
             stringByReplacingOccurrencesOfString:@" " withString:@""];
    
    NSString *result;
    
    switch (task) {
        case TaskFirst: {
            //    First step
            char common = [self findMostCommonlyUsedCharacterInHex:self.text];
            //    Second step
            char key = [self findKeyWithMostCommonlyUsedCharacter:common];
            //    Third step
            result = [self encryptDecryptHex:self.text withKey:[NSString stringWithFormat:@"%c", key]];
        }
            break;
        case TaskSecond: {
            //Translate to array of charachters
            self.text = [self transalteTextFromHexIntoChar:self.text];
            //Find a key's length
            NSInteger keyLength = [self calculateKeyLength:self.text];
            //Split text into several parts. The count of parts is equal keys length
            NSArray *general = [self splitTextInto:keyLength];
            NSMutableString *key = [[NSMutableString alloc] initWithCapacity:keyLength];
            for (NSString *eachText in general) {
                //    First step
                char common = [self findMostCommonlyUsedCharacterInDec:eachText];
                //    Second step
                [key appendFormat:@"%c", [self findKeyWithMostCommonlyUsedCharacter:common]];
            }
            result = [self encryptDecryptDec:self.text withKey:key];
        }
            break;
        default:
            break;
    }
    return  result;
}

- (char)findMostCommonlyUsedCharacterInDec:(NSString *)text {
    //Create dictionary with counts of repeated characters
    NSMutableDictionary *dict = [NSMutableDictionary dictionary];
    for (NSUInteger i=0; i<[text length]; i++) {
        NSUInteger preCount = 0;
        NSString *charStr = [NSString stringWithFormat:@"%c", [text characterAtIndex:i]];
        if ([dict objectForKey:charStr]) {
            preCount = [[dict objectForKey:charStr] unsignedIntegerValue];
        }
        [dict setObject:@(preCount+1) forKey:charStr];
    }
    //Sort to find the most commonly used character
    NSArray *keys =  [dict keysSortedByValueWithOptions:
                      NSSortStable usingComparator:^NSComparisonResult(id obj1, id obj2) {
                          return (int)obj1 > (int)obj2;
                      }];
    return [(NSString *)[keys lastObject] characterAtIndex:0];
}

- (char)findMostCommonlyUsedCharacterInHex:(NSString *)text {
    //Create dictionary with counts of repeated characters
    NSMutableDictionary *dict = [NSMutableDictionary dictionary];
    for (NSUInteger i=0; i<[text length]-2; i=i+2) {
        NSString *charStr = [text substringWithRange:NSMakeRange(i, 2)];
        NSUInteger preCount = 0;
        if ([dict objectForKey:charStr]) {
            preCount = [[dict objectForKey:charStr] unsignedIntegerValue];
        }
        [dict setObject:@(preCount+1) forKey:charStr];
    }
    //    NSLog([dict description]);
    
    //Sort to find the most commonly used character
    NSArray *keys =  [dict keysSortedByValueWithOptions:
                      NSSortStable usingComparator:^NSComparisonResult(id obj1, id obj2) {
                          return (int)obj1 > (int)obj2;
                      }];
    
    //Rescale from hex to dec
    unsigned int outVal;
    NSScanner* scanner = [NSScanner scannerWithString:[keys lastObject]];
    [scanner scanHexInt:&outVal];
    
    //Get char
    return (char)outVal;
}

- (NSString *)encryptDecryptDec:(NSString *)text withKey:(NSString *)key {
    NSMutableString *output = [[NSMutableString alloc] init];
    NSInteger j = 0;
    for (NSUInteger i=0; i<[text length]; i++) {
        unsigned int outVal = [text characterAtIndex:i];
        //Get XOR value
        outVal ^= [key characterAtIndex: j++ % key.length/sizeof(char)];
        [output appendFormat:@"%c", outVal];
    }
    
    return output;
}

- (NSString *)encryptDecryptHex:(NSString *)text withKey:(NSString *)key {
    NSMutableString *output = [[NSMutableString alloc] init];
    NSInteger j = 0;
    for (NSUInteger i=0; i<[text length]-2; i=i+2) {
        NSString *str = [text substringWithRange:NSMakeRange(i, 2)];
        
        //Rescale from hex to dec
        unsigned int outVal;
        NSScanner* scanner = [NSScanner scannerWithString:str];
        [scanner scanHexInt:&outVal];
        
        //Get XOR value
        outVal ^= [key characterAtIndex: j++ % key.length/sizeof(char)];
        [output appendFormat:@"%c", outVal];
    }
    
    return output;
}

- (char)findKeyWithMostCommonlyUsedCharacter:(char)common {
    return common ^ ' ';
}



@end
