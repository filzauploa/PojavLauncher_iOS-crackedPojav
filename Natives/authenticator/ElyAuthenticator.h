#import "BaseAuthenticator.h"

// Интерфейс уже объявлен в BaseAuthenticator.h, так что здесь его повторять не нужно

@interface ElyAuthenticator : BaseAuthenticator

+ (void)downloadLatestAuthlibInjector:(void (^)(BOOL success, NSString *message))callback;
+ (NSString *)getAuthlibInjectorPath;

@end 