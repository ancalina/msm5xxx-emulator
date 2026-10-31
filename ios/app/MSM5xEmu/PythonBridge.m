#import "PythonBridge.h"
#include <Python/Python.h>
#include <pthread.h>
#include <errno.h>
#include <stdlib.h>
#include <time.h>
#include <math.h>
#include <string.h>

typedef int (*QEMUEntry)(int, char **);
typedef void (*QEMUQuit)(void);
static QEMUEntry qemuEntry;
static QEMUQuit qemuQuit;
static pthread_mutex_t engineLock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t engineChanged = PTHREAD_COND_INITIALIZER;
static BOOL attempted, running, initialized;
static int resultCode = -1, engineArgc;
static char **engineArgv;

static void engineFinished(void *unused) {
    (void)unused;
    pthread_mutex_lock(&engineLock);
    for (int i = 0; i < engineArgc; ++i) free(engineArgv[i]);
    free(engineArgv);
    engineArgv = NULL;
    running = NO;
    pthread_cond_broadcast(&engineChanged);
    pthread_mutex_unlock(&engineLock);
}

static void *engineWorker(void *unused) {
    (void)unused;
    @autoreleasepool {
        pthread_cleanup_push(engineFinished, NULL);
        int status = qemuEntry(engineArgc, engineArgv);
        pthread_mutex_lock(&engineLock);
        resultCode = status;
        pthread_mutex_unlock(&engineLock);
        pthread_cleanup_pop(1);
    }
    return NULL;
}

static PyObject *hostStart(PyObject *self, PyObject *args) {
    (void)self;
    PyObject *values;
    if (!PyArg_ParseTuple(args, "O!:start", &PyList_Type, &values)) return NULL;
    Py_ssize_t count = PyList_Size(values);
    if (count < 1 || count > 4096) return PyErr_Format(PyExc_ValueError, "invalid QEMU argv");
    pthread_mutex_lock(&engineLock);
    if (attempted || !qemuEntry || !qemuQuit) {
        pthread_mutex_unlock(&engineLock);
        return PyErr_Format(PyExc_RuntimeError, "QEMU unavailable or already used; relaunch app");
    }
    char **argv = calloc((size_t)count + 1, sizeof(char *));
    if (!argv) { pthread_mutex_unlock(&engineLock); return PyErr_NoMemory(); }
    for (Py_ssize_t i = 0; i < count; ++i) {
        Py_ssize_t length;
        const char *value = PyUnicode_AsUTF8AndSize(PyList_GetItem(values, i), &length);
        if (!value || (Py_ssize_t)strlen(value) != length || !(argv[i] = strdup(value))) {
            for (Py_ssize_t j = 0; j < i; ++j) free(argv[j]);
            free(argv);
            pthread_mutex_unlock(&engineLock);
            if (!PyErr_Occurred()) PyErr_SetString(PyExc_ValueError, "invalid QEMU argument");
            return NULL;
        }
    }
    engineArgv = argv; engineArgc = (int)count; attempted = YES; running = YES;
    pthread_t thread;
    int status = pthread_create(&thread, NULL, engineWorker, NULL);
    if (status) {
        running = NO;
        for (int i = 0; i < engineArgc; ++i) free(engineArgv[i]);
        free(engineArgv); engineArgv = NULL;
        pthread_mutex_unlock(&engineLock);
        return PyErr_Format(PyExc_RuntimeError, "QEMU thread creation failed: %d", status);
    }
    pthread_detach(thread);
    pthread_mutex_unlock(&engineLock);
    Py_RETURN_NONE;
}

static PyObject *hostPoll(PyObject *self, PyObject *unused) {
    (void)self; (void)unused;
    pthread_mutex_lock(&engineLock);
    BOOL active = running; int code = resultCode;
    pthread_mutex_unlock(&engineLock);
    if (active) Py_RETURN_NONE;
    return PyLong_FromLong(code);
}

static PyObject *hostTerminate(PyObject *self, PyObject *unused) {
    (void)self; (void)unused;
    pthread_mutex_lock(&engineLock);
    BOOL active = running;
    pthread_mutex_unlock(&engineLock);
    if (active && qemuQuit) qemuQuit();
    Py_RETURN_NONE;
}

static PyObject *hostWait(PyObject *self, PyObject *args) {
    (void)self;
    PyObject *timeout = Py_None;
    if (!PyArg_ParseTuple(args, "|O:wait", &timeout)) return NULL;
    double seconds = timeout == Py_None ? 30.0 : PyFloat_AsDouble(timeout);
    if (PyErr_Occurred()) return NULL;
    if (!isfinite(seconds) || seconds < 0) return PyErr_Format(PyExc_ValueError, "invalid timeout");
    struct timespec deadline;
    clock_gettime(CLOCK_REALTIME, &deadline);
    deadline.tv_sec += (time_t)seconds;
    deadline.tv_nsec += (long)((seconds - (time_t)seconds) * 1000000000);
    if (deadline.tv_nsec >= 1000000000) { deadline.tv_sec++; deadline.tv_nsec -= 1000000000; }
    int code, status = 0;
    BOOL active;
    Py_BEGIN_ALLOW_THREADS
    pthread_mutex_lock(&engineLock);
    while (running && !status) status = pthread_cond_timedwait(&engineChanged, &engineLock, &deadline);
    active = running; code = resultCode;
    pthread_mutex_unlock(&engineLock);
    Py_END_ALLOW_THREADS
    if (active) return PyErr_Format(PyExc_TimeoutError, "QEMU did not stop; relaunch app");
    return PyLong_FromLong(code);
}

static PyMethodDef hostMethods[] = {
    {"start", hostStart, METH_VARARGS, NULL}, {"poll", hostPoll, METH_NOARGS, NULL},
    {"terminate", hostTerminate, METH_NOARGS, NULL}, {"kill", hostTerminate, METH_NOARGS, NULL},
    {"wait", hostWait, METH_VARARGS, NULL}, {NULL, NULL, 0, NULL}
};
static struct PyModuleDef hostModule = {PyModuleDef_HEAD_INIT, "_msm5xxx_ios_host", NULL, -1, hostMethods};
static PyObject *PyInit_msm5xxx_ios_host(void) { return PyModule_Create(&hostModule); }

static void bridgeError(NSError **error, NSString *message) {
    if (error) *error = [NSError errorWithDomain:@"MSM5xEmu.Python" code:1
                                     userInfo:@{NSLocalizedDescriptionKey: message}];
}
static void pythonError(NSError **error) {
    PyObject *exception = PyErr_GetRaisedException();
    PyObject *description = exception ? PyObject_Str(exception) : NULL;
    const char *text = description ? PyUnicode_AsUTF8(description) : NULL;
    bridgeError(error, text ? [NSString stringWithUTF8String:text] : @"Python call failed");
    Py_XDECREF(description); Py_XDECREF(exception); PyErr_Clear();
}

@implementation PythonBridge
+ (void)configureQEMUEntry:(void *)entry requestQuit:(void *)requestQuit {
    pthread_mutex_lock(&engineLock);
    if (!attempted) { qemuEntry = (QEMUEntry)entry; qemuQuit = (QEMUQuit)requestQuit; }
    pthread_mutex_unlock(&engineLock);
}
+ (BOOL)initializeRuntime:(NSError **)error {
    @synchronized(self) {
        if (initialized) return YES;
        NSString *home = [[NSBundle mainBundle].resourcePath stringByAppendingPathComponent:@"python"];
        if (PyImport_AppendInittab("_msm5xxx_ios_host", PyInit_msm5xxx_ios_host) != 0) {
            bridgeError(error, @"Cannot register iOS host module"); return NO;
        }
        PyConfig config;
        PyConfig_InitIsolatedConfig(&config);
        config.install_signal_handlers = 0;
        config.write_bytecode = 0;
        config.parse_argv = 0;
        PyStatus status = PyConfig_SetBytesString(&config, &config.home, home.fileSystemRepresentation);
        if (!PyStatus_Exception(status)) status = PyConfig_SetBytesString(&config, &config.program_name, NSBundle.mainBundle.executablePath.fileSystemRepresentation);
        if (!PyStatus_Exception(status)) status = PyConfig_SetBytesString(&config, &config.executable, NSBundle.mainBundle.executablePath.fileSystemRepresentation);
        NSArray<NSString *> *paths = @[
            [[NSBundle mainBundle].resourcePath stringByAppendingPathComponent:@"app"],
            [home stringByAppendingPathComponent:@"lib/python3.14"],
            [home stringByAppendingPathComponent:@"lib/python3.14/lib-dynload"],
            [home stringByAppendingPathComponent:@"lib/python3.14/site-packages"]
        ];
        config.module_search_paths_set = 1;
        for (NSString *path in paths) {
            if (PyStatus_Exception(status)) break;
            wchar_t *wide = Py_DecodeLocale(path.fileSystemRepresentation, NULL);
            if (!wide) { status = PyStatus_Error("Cannot decode Python search path"); break; }
            status = PyWideStringList_Append(&config.module_search_paths, wide);
            PyMem_RawFree(wide);
        }
        if (!PyStatus_Exception(status)) status = Py_InitializeFromConfig(&config);
        if (PyStatus_Exception(status)) {
            bridgeError(error, status.err_msg ? [NSString stringWithUTF8String:status.err_msg] : @"Python initialization failed");
            PyConfig_Clear(&config); return NO;
        }
        PyConfig_Clear(&config);
        initialized = YES;
        PyEval_SaveThread();
        return YES;
    }
}
+ (id)invoke:(NSString *)name argument:(NSString *)argument binary:(BOOL)binary error:(NSError **)error {
    if (!initialized) { bridgeError(error, @"Python is not initialized"); return nil; }
    PyGILState_STATE gil = PyGILState_Ensure();
    PyObject *module = PyImport_ImportModule("msm5xxx_ios_runtime");
    PyObject *function = module ? PyObject_GetAttrString(module, name.UTF8String) : NULL;
    PyObject *result = function ? (argument ? PyObject_CallFunction(function, "s", argument.UTF8String) : PyObject_CallNoArgs(function)) : NULL;
    id response = nil;
    if (result && binary && PyBytes_Check(result)) {
        response = [NSData dataWithBytes:PyBytes_AS_STRING(result) length:(NSUInteger)PyBytes_GET_SIZE(result)];
    } else if (result && !binary && PyUnicode_Check(result)) {
        const char *text = PyUnicode_AsUTF8(result);
        if (text) response = [NSString stringWithUTF8String:text];
    }
    if (!response) {
        if (!PyErr_Occurred()) PyErr_SetString(PyExc_TypeError, "Unexpected bridge result type");
        pythonError(error);
    }
    Py_XDECREF(result); Py_XDECREF(function); Py_XDECREF(module);
    PyGILState_Release(gil);
    return response;
}
+ (NSString *)call:(NSString *)function argument:(NSString *)argument error:(NSError **)error {
    return [self invoke:function argument:argument binary:NO error:error];
}
+ (NSData *)bytes:(NSString *)function error:(NSError **)error {
    return [self invoke:function argument:nil binary:YES error:error];
}
@end
