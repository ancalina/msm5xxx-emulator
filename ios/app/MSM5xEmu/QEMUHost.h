#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN
@protocol QEMUProcessHost <NSObject>
- (BOOL)startArguments:(NSArray<NSString *> *)arguments error:(NSError **)error
    NS_SWIFT_NAME(start(arguments:error:)) NS_SWIFT_NOTHROW;
- (nullable NSNumber *)poll;
- (void)requestQuit;
- (void)requestKill;
- (nullable NSNumber *)waitForExit:(double)timeout error:(NSError **)error
    NS_SWIFT_NAME(wait(timeout:error:)) NS_SWIFT_NOTHROW;
@end

@protocol QEMUSessionService <NSObject>
- (void)startArguments:(NSArray<NSString *> *)arguments
            bookmarks:(NSArray<NSData *> *)bookmarks
                  log:(NSFileHandle *)log
           completion:(void (^)(BOOL, NSString * _Nullable))completion
    NS_SWIFT_NAME(start(arguments:bookmarks:log:completion:));
- (void)requestQuit;
- (void)terminate;
@end

@protocol QEMUSessionEvents <NSObject>
- (void)finishedWithStatus:(int)status reply:(void (^)(void))reply
    NS_SWIFT_NAME(finished(status:reply:));
@end

@interface QEMUSessionCore : NSObject
+ (BOOL)startArguments:(NSArray<NSString *> *)arguments error:(NSError **)error
              finished:(void (^)(int))finished
    NS_SWIFT_NAME(start(arguments:error:finished:)) NS_SWIFT_NOTHROW;
+ (void)requestQuit;
@end
NS_ASSUME_NONNULL_END
