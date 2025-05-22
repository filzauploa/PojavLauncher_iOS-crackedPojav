#import "BaseAuthenticator.h"

// Интерфейс ElyAuthenticator уже объявлен в BaseAuthenticator.h

@interface ElyAuthenticator : BaseAuthenticator

+ (void)downloadLatestAuthlibInjector:(void (^)(BOOL success, NSString *message))callback;
+ (NSString *)getAuthlibInjectorPath;

@end 