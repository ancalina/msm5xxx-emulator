#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN
/// One interpreter and one QEMU invocation per app lifetime. Call on a serial queue.
@interface PythonBridge : NSObject
+ (void)configureQEMUEntry:(void *)entry requestQuit:(void *)requestQuit;
+ (BOOL)initializeRuntime:(NSError **)error;
+ (nullable NSString *)call:(NSString *)function argument:(nullable NSString *)argument error:(NSError **)error;
+ (nullable NSData *)bytes:(NSString *)function error:(NSError **)error;
@end
NS_ASSUME_NONNULL_END
