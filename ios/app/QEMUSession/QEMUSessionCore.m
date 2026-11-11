#import "../MSM5xEmu/QEMUHost.h"
#include <dlfcn.h>
#include <pthread.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

typedef int (*Entry)(int, char **);
typedef void (*Quit)(void);
static Entry entry;
static Quit requestQuit;
static char **arguments;
static int argumentCount;
static BOOL attempted;
static int exitStatus = -1;
static void (^didFinish)(int);

// Entry-thread completion ends this helper process. Nothing from its machine,
// including remaining threads and library globals, can reach the next session.
static void childFinished(void *unused) {
    (void)unused;
    if (didFinish) didFinish(exitStatus);
    fflush(NULL);
    _exit(exitStatus == 0 ? 0 : 1);
}

static void *childMain(void *unused) {
    (void)unused;
    @autoreleasepool {
        pthread_cleanup_push(childFinished, NULL);
        exitStatus = entry(argumentCount, arguments);
        pthread_cleanup_pop(1);
    }
    return NULL;
}

@implementation QEMUSessionCore
+ (BOOL)startArguments:(NSArray<NSString *> *)values error:(NSError **)error finished:(void (^)(int))finished {
    @synchronized(self) {
        NSString *failure = nil;
        if (attempted || values.count == 0 || values.count > 4096) {
            failure = @"Invalid or repeated QEMU start";
        } else {
            // The helper has its own executable-memory permissions. TCI works
            // independently of any debugger attached to the host application.
            NSString *framework = [NSBundle.mainBundle.privateFrameworksPath
                stringByAppendingPathComponent:@"QEMUTCI.framework/QEMUTCI"];
            void *handle = framework ? dlopen(framework.fileSystemRepresentation, RTLD_NOW | RTLD_LOCAL) : NULL;
            int (*abi)(void) = handle ? dlsym(handle, "msm5xxx_qemu_embedding_abi") : NULL;
            entry = handle ? dlsym(handle, "qemu_entry") : NULL;
            requestQuit = handle ? dlsym(handle, "msm5xxx_qemu_request_quit") : NULL;
            if (!abi || abi() != 1 || !entry || !requestQuit) {
                failure = @"QEMU session framework unavailable; rebuild the app";
            } else {
                arguments = calloc(values.count + 1, sizeof(char *));
                if (!arguments) failure = @"Cannot allocate QEMU arguments";
                for (NSUInteger i = 0; !failure && i < values.count; ++i) {
                    const char *value = values[i].UTF8String;
                    if (!value || strlen(value) != [values[i] lengthOfBytesUsingEncoding:NSUTF8StringEncoding]
                        || !(arguments[i] = strdup(value))) failure = @"Invalid QEMU argument";
                }
                if (!failure) {
                    argumentCount = (int)values.count;
                    didFinish = [finished copy];
                    pthread_t thread;
                    int result = pthread_create(&thread, NULL, childMain, NULL);
                    if (result) failure = @"Cannot create QEMU session thread";
                    else { attempted = YES; pthread_detach(thread); return YES; }
                }
                if (arguments) {
                    for (NSUInteger i = 0; i < values.count; ++i) free(arguments[i]);
                    free(arguments); arguments = NULL;
                }
            }
        }
        if (error) *error = [NSError errorWithDomain:@"QEMUSession" code:1
            userInfo:@{NSLocalizedDescriptionKey: failure}];
        return NO;
    }
}
+ (void)requestQuit {
    Quit quit;
    @synchronized(self) { quit = attempted ? requestQuit : NULL; }
    if (quit) quit();
}
@end
