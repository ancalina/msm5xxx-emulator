#import <Foundation/Foundation.h>
#import "QEMUHost.h"

NS_ASSUME_NONNULL_BEGIN
/// One interpreter; QEMU sessions use the configured host. Call on a serial queue.
@interface PythonBridge : NSObject
+ (void)configureProcessHost:(id<QEMUProcessHost>)host;
+ (void)configureQEMUEntry:(void *)entry requestQuit:(void *)requestQuit;
+ (BOOL)initializeRuntime:(NSError **)error;
+ (nullable NSString *)call:(NSString *)function argument:(nullable NSString *)argument error:(NSError **)error;
+ (nullable NSData *)bytes:(NSString *)function error:(NSError **)error;
@end
NS_ASSUME_NONNULL_END
