#import "BaseAuthenticator.h"

// Don't declare interface again as it's already declared in BaseAuthenticator.h
@interface ElyAuthenticator (Methods)

+ (void)downloadLatestAuthlibInjector:(void (^)(BOOL success, NSString *message))callback;
+ (NSString *)getAuthlibInjectorPath;

@end 