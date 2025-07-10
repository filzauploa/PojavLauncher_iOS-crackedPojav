#import "BaseAuthenticator.h"

// Don't declare interface again as it's already declared in BaseAuthenticator.h
@interface ElyAuthenticator (Methods)

// Add declaration for initWithData: method
- (id)initWithData:(NSMutableDictionary *)data;

+ (void)downloadLatestAuthlibInjector:(void (^)(BOOL success, NSString *message))callback;
+ (NSString *)getAuthlibInjectorPath;

@end 