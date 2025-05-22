#import <Security/Security.h>
#import <Foundation/Foundation.h>
#import "AFNetworking.h"
#import "ElyAuthenticator.h"
#import "../LauncherPreferences.h"
#import "../ios_uikit_bridge.h"
#import "../utils.h"

@implementation ElyAuthenticator

static NSString *elyAuthServerURL = @"https://authserver.ely.by";
static NSString *authlibInjectorURL = @"https://github.com/yushijinhun/authlib-injector/releases/latest/download/authlib-injector.jar";

- (id)initWithInput:(NSString *)string {
    NSMutableDictionary *data = [[NSMutableDictionary alloc] init];
    data[@"input"] = string;
    data[@"isElyby"] = @YES;
    return [self initWithData:data];
}

- (void)loginWithCallback:(Callback)callback {
    if (self.authData[@"input"] == nil) {
        callback(self.authData, YES);
        return;
    }
    
    NSString *input = self.authData[@"input"];
    
    NSRange separatorRange = [input rangeOfString:@":"];
    if (separatorRange.location == NSNotFound) {
        callback(@"Invalid username and password format. Use username:password", NO);
        return;
    }
    
    NSString *username = [input substringToIndex:separatorRange.location];
    NSString *password = [input substringFromIndex:separatorRange.location + 1];
    
    AFHTTPSessionManager *manager = [AFHTTPSessionManager manager];
    manager.requestSerializer = [AFJSONRequestSerializer serializer];
    manager.responseSerializer = [AFJSONResponseSerializer serializer];
    
    NSDictionary *payload = @{
        @"username": username,
        @"password": password,
        @"clientToken": [NSUUID UUID].UUIDString,
        @"requestUser": @YES
    };
    
    [manager POST:[NSString stringWithFormat:@"%@/authserver/authenticate", elyAuthServerURL]
       parameters:payload
          headers:nil
         progress:nil
          success:^(NSURLSessionDataTask * _Nonnull task, id  _Nullable responseObject) {
        
        self.authData[@"accessToken"] = responseObject[@"accessToken"];
        self.authData[@"clientToken"] = responseObject[@"clientToken"];
        self.authData[@"profileId"] = responseObject[@"selectedProfile"][@"id"];
        self.authData[@"username"] = responseObject[@"selectedProfile"][@"name"];
        self.authData[@"xboxGamertag"] = responseObject[@"selectedProfile"][@"name"];
        self.authData[@"xboxUserId"] = responseObject[@"selectedProfile"][@"id"];
        self.authData[@"uuid"] = responseObject[@"selectedProfile"][@"id"];
        self.authData[@"oldusername"] = self.authData[@"username"];
        self.authData[@"isElyby"] = @YES;
        
        // Скачиваем authlib-injector
        [ElyAuthenticator downloadLatestAuthlibInjector:^(BOOL success, NSString *message) {
            if (!success) {
                NSLog(@"[ElyAuthenticator] Warning: Failed to download authlib-injector: %@", message);
            } else {
                NSLog(@"[ElyAuthenticator] Successfully downloaded authlib-injector");
            }
            
            [self saveChanges];
            callback(self.authData, YES);
        }];
    } failure:^(NSURLSessionDataTask * _Nullable task, NSError * _Nonnull error) {
        NSData *errorData = error.userInfo[AFNetworkingOperationFailingURLResponseDataErrorKey];
        NSString *errorMessage = @"Неизвестная ошибка";
        
        if (errorData) {
            NSDictionary *serializedData = [NSJSONSerialization JSONObjectWithData:errorData options:0 error:nil];
            if (serializedData[@"errorMessage"]) {
                errorMessage = serializedData[@"errorMessage"];
            }
        }
        
        callback(errorMessage, NO);
    }];
}

- (void)refreshTokenWithCallback:(Callback)callback {
    if (self.authData[@"clientToken"] == nil || self.authData[@"accessToken"] == nil) {
        callback(@"No token to refresh", NO);
        return;
    }
    
    AFHTTPSessionManager *manager = [AFHTTPSessionManager manager];
    manager.requestSerializer = [AFJSONRequestSerializer serializer];
    manager.responseSerializer = [AFJSONResponseSerializer serializer];
    
    NSDictionary *payload = @{
        @"accessToken": self.authData[@"accessToken"],
        @"clientToken": self.authData[@"clientToken"],
        @"requestUser": @YES
    };
    
    [manager POST:[NSString stringWithFormat:@"%@/authserver/refresh", elyAuthServerURL]
       parameters:payload
          headers:nil
         progress:nil
          success:^(NSURLSessionDataTask * _Nonnull task, id  _Nullable responseObject) {
        
        self.authData[@"accessToken"] = responseObject[@"accessToken"];
        // clientToken должен остаться прежним
        
        [self saveChanges];
        callback(self.authData, YES);
    } failure:^(NSURLSessionDataTask * _Nullable task, NSError * _Nonnull error) {
        NSData *errorData = error.userInfo[AFNetworkingOperationFailingURLResponseDataErrorKey];
        NSString *errorMessage = @"Неизвестная ошибка";
        
        if (errorData) {
            NSDictionary *serializedData = [NSJSONSerialization JSONObjectWithData:errorData options:0 error:nil];
            if (serializedData[@"errorMessage"]) {
                errorMessage = serializedData[@"errorMessage"];
            }
        }
        
        callback(errorMessage, NO);
    }];
}

+ (void)downloadLatestAuthlibInjector:(void (^)(BOOL success, NSString *message))callback {
    NSString *authlibPath = [self getAuthlibInjectorPath];
    NSString *authlibDir = [authlibPath stringByDeletingLastPathComponent];
    
    // Проверим, существует ли уже authlib-injector
    if ([[NSFileManager defaultManager] fileExistsAtPath:authlibPath]) {
        NSLog(@"[ElyAuthenticator] authlib-injector already exists, skipping download");
        if (callback) callback(YES, @"Already exists");
        return;
    }
    
    // Создаем директорию для authlib-injector если не существует
    NSError *error;
    if (![[NSFileManager defaultManager] fileExistsAtPath:authlibDir]) {
        [[NSFileManager defaultManager] createDirectoryAtPath:authlibDir
                                  withIntermediateDirectories:YES
                                                   attributes:nil
                                                        error:&error];
        if (error) {
            NSLog(@"[ElyAuthenticator] Failed to create directory: %@", error.localizedDescription);
            if (callback) callback(NO, [NSString stringWithFormat:@"Не удалось создать директорию: %@", error.localizedDescription]);
            return;
        }
    }
    
    NSLog(@"[ElyAuthenticator] Downloading authlib-injector from %@", authlibInjectorURL);
    
    // Скачиваем authlib-injector из GitHub
    NSURLSessionConfiguration *configuration = [NSURLSessionConfiguration defaultSessionConfiguration];
    AFURLSessionManager *manager = [[AFURLSessionManager alloc] initWithSessionConfiguration:configuration];
    
    NSURL *url = [NSURL URLWithString:authlibInjectorURL];
    NSURLRequest *request = [NSURLRequest requestWithURL:url];
    
    NSURLSessionDownloadTask *downloadTask = [manager downloadTaskWithRequest:request
                                                                     progress:nil
                                                                  destination:^NSURL *(NSURL *targetPath, NSURLResponse *response) {
        return [NSURL fileURLWithPath:authlibPath];
    } completionHandler:^(NSURLResponse *response, NSURL *filePath, NSError *error) {
        if (error) {
            NSLog(@"[ElyAuthenticator] Download error: %@", error.localizedDescription);
            if (callback) callback(NO, [NSString stringWithFormat:@"Ошибка загрузки: %@", error.localizedDescription]);
        } else {
            NSLog(@"[ElyAuthenticator] Download complete: %@", filePath.path);
            if ([[NSFileManager defaultManager] fileExistsAtPath:authlibPath]) {
                if (callback) callback(YES, @"Успешно загружен");
            } else {
                if (callback) callback(NO, @"Файл не был сохранён после загрузки");
            }
        }
    }];
    
    [downloadTask resume];
}

+ (NSString *)getAuthlibInjectorPath {
    return [NSString stringWithFormat:@"%s/authlib-injector/authlib-injector.jar", getenv("POJAV_HOME")];
}

@end 