#include <jni.h>
#include <limits.h>
#include <pthread.h>
#include <Python.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

static pthread_mutex_t INIT_LOCK = PTHREAD_MUTEX_INITIALIZER;
static int initialized;

static void throw_runtime(JNIEnv *env, const char *message) {
    jclass type = (*env)->FindClass(env, "java/lang/RuntimeException");
    if (type != NULL) {
        (*env)->ThrowNew(env, type, message);
    }
}

static void throw_python_error(JNIEnv *env, const char *stage) {
    PyObject *type = NULL;
    PyObject *value = NULL;
    PyObject *traceback = NULL;
    const char *name = "PythonError";
    char message[160];
    PyErr_Fetch(&type, &value, &traceback);
    if (type != NULL && PyType_Check(type)) {
        name = ((PyTypeObject *)type)->tp_name;
    }
    snprintf(message, sizeof(message), "%s failed (%s)", stage, name);
    Py_XDECREF(type);
    Py_XDECREF(value);
    Py_XDECREF(traceback);
    throw_runtime(env, message);
}

static int join_path(char *result, size_t size, const char *directory,
                     const char *name) {
    int written = snprintf(result, size, "%s/%s", directory, name);
    return written >= 0 && (size_t)written < size;
}

static int initialize_python(JNIEnv *env, const char *home,
                             const char *native_dir, const char *state_dir) {
    pthread_mutex_lock(&INIT_LOCK);
    if (initialized) {
        pthread_mutex_unlock(&INIT_LOCK);
        return 1;
    }

    char cwd[PATH_MAX];
    if (!join_path(cwd, sizeof(cwd), home, "cwd")
            || chdir(cwd) != 0
            || setenv("LIBUNICORN_PATH", native_dir, 1) != 0
            || setenv("LD_LIBRARY_PATH", native_dir, 1) != 0
            || setenv("MSM5XXX_STATE_DIR", state_dir, 1) != 0) {
        pthread_mutex_unlock(&INIT_LOCK);
        throw_runtime(env, "Python runtime directories are unavailable.");
        return 0;
    }

    PyConfig config;
    PyStatus status;
    PyConfig_InitPythonConfig(&config);
    char *argv[] = {"msm5xxx-android", NULL};
    status = PyConfig_SetBytesArgv(&config, 1, argv);
    if (!PyStatus_Exception(status)) {
        status = PyConfig_SetBytesString(&config, &config.home, home);
    }
    if (!PyStatus_Exception(status)) {
        status = Py_InitializeFromConfig(&config);
    }
    PyConfig_Clear(&config);
    if (PyStatus_Exception(status)) {
        pthread_mutex_unlock(&INIT_LOCK);
        throw_runtime(env, "CPython initialization failed.");
        return 0;
    }

    initialized = 1;
    PyEval_SaveThread();
    pthread_mutex_unlock(&INIT_LOCK);
    return 1;
}

static jstring call_python(JNIEnv *env, const char *function_name,
                           const char *argument) {
    PyGILState_STATE gil = PyGILState_Ensure();
    PyObject *module = PyImport_ImportModule("msm5xxx_android_runtime");
    PyObject *function = module == NULL ? NULL
                                        : PyObject_GetAttrString(module, function_name);
    PyObject *result = NULL;
    if (function != NULL && PyCallable_Check(function)) {
        result = argument == NULL ? PyObject_CallNoArgs(function)
                                  : PyObject_CallFunction(function, "s", argument);
    }
    if (result == NULL || !PyUnicode_Check(result)) {
        Py_XDECREF(result);
        Py_XDECREF(function);
        Py_XDECREF(module);
        throw_python_error(env, function_name);
        PyGILState_Release(gil);
        return NULL;
    }
    const char *text = PyUnicode_AsUTF8(result);
    jstring response = text == NULL ? NULL : (*env)->NewStringUTF(env, text);
    if (response == NULL && !(*env)->ExceptionCheck(env)) {
        throw_python_error(env, function_name);
    }
    Py_DECREF(result);
    Py_DECREF(function);
    Py_DECREF(module);
    PyGILState_Release(gil);
    return response;
}

static jbyteArray call_python_bytes(JNIEnv *env, const char *function_name) {
    PyGILState_STATE gil = PyGILState_Ensure();
    PyObject *module = PyImport_ImportModule("msm5xxx_android_runtime");
    PyObject *function = module == NULL ? NULL
                                        : PyObject_GetAttrString(module, function_name);
    PyObject *result = NULL;
    if (function != NULL && PyCallable_Check(function)) {
        result = PyObject_CallNoArgs(function);
    }
    if (result == NULL || !PyBytes_Check(result)
            || PyBytes_GET_SIZE(result) > INT_MAX) {
        Py_XDECREF(result);
        Py_XDECREF(function);
        Py_XDECREF(module);
        throw_python_error(env, function_name);
        PyGILState_Release(gil);
        return NULL;
    }
    jsize size = (jsize)PyBytes_GET_SIZE(result);
    const jbyte *data = (const jbyte *)PyBytes_AS_STRING(result);
    jbyteArray response;
    Py_BEGIN_ALLOW_THREADS
    response = (*env)->NewByteArray(env, size);
    if (response != NULL) {
        (*env)->SetByteArrayRegion(env, response, 0, size, data);
    }
    Py_END_ALLOW_THREADS
    Py_DECREF(result);
    Py_DECREF(function);
    Py_DECREF(module);
    PyGILState_Release(gil);
    return response;
}

JNIEXPORT jstring JNICALL
Java_org_msm5xxx_emulator_PythonRuntime_nativeProbe(
        JNIEnv *env, jclass type, jstring home_value, jstring native_dir_value,
        jstring state_dir_value) {
    (void)type;
    const char *home = (*env)->GetStringUTFChars(env, home_value, NULL);
    if (home == NULL) {
        return NULL;
    }
    const char *native_dir = (*env)->GetStringUTFChars(env, native_dir_value, NULL);
    if (native_dir == NULL) {
        (*env)->ReleaseStringUTFChars(env, home_value, home);
        return NULL;
    }
    const char *state_dir = (*env)->GetStringUTFChars(env, state_dir_value, NULL);
    if (state_dir == NULL) {
        (*env)->ReleaseStringUTFChars(env, home_value, home);
        (*env)->ReleaseStringUTFChars(env, native_dir_value, native_dir);
        return NULL;
    }
    int ready = initialize_python(env, home, native_dir, state_dir);
    (*env)->ReleaseStringUTFChars(env, home_value, home);
    (*env)->ReleaseStringUTFChars(env, native_dir_value, native_dir);
    (*env)->ReleaseStringUTFChars(env, state_dir_value, state_dir);
    return ready ? call_python(env, "probe", NULL) : NULL;
}

JNIEXPORT jstring JNICALL
Java_org_msm5xxx_emulator_PythonRuntime_nativeDetect(
        JNIEnv *env, jclass type, jstring firmware_value) {
    (void)type;
    if (!initialized) {
        throw_runtime(env, "CPython is not initialized.");
        return NULL;
    }
    const char *firmware = (*env)->GetStringUTFChars(env, firmware_value, NULL);
    if (firmware == NULL) {
        return NULL;
    }
    jstring result = call_python(env, "detect_profile", firmware);
    (*env)->ReleaseStringUTFChars(env, firmware_value, firmware);
    return result;
}

JNIEXPORT jstring JNICALL
Java_org_msm5xxx_emulator_PythonRuntime_nativeStart(
        JNIEnv *env, jclass type, jstring request_value) {
    (void)type;
    const char *request = (*env)->GetStringUTFChars(env, request_value, NULL);
    if (request == NULL) {
        return NULL;
    }
    jstring result = call_python(env, "start_session", request);
    (*env)->ReleaseStringUTFChars(env, request_value, request);
    return result;
}

JNIEXPORT jbyteArray JNICALL
Java_org_msm5xxx_emulator_PythonRuntime_nativeFrame(
        JNIEnv *env, jclass type) {
    (void)type;
    return call_python_bytes(env, "session_frame");
}

JNIEXPORT jbyteArray JNICALL
Java_org_msm5xxx_emulator_PythonRuntime_nativeAudio(
        JNIEnv *env, jclass type) {
    (void)type;
    return call_python_bytes(env, "session_audio");
}

JNIEXPORT jstring JNICALL
Java_org_msm5xxx_emulator_PythonRuntime_nativeStatus(
        JNIEnv *env, jclass type) {
    (void)type;
    return call_python(env, "session_status", NULL);
}

JNIEXPORT jstring JNICALL
Java_org_msm5xxx_emulator_PythonRuntime_nativeCanKey(
        JNIEnv *env, jclass type, jstring request_value) {
    (void)type;
    const char *request = (*env)->GetStringUTFChars(env, request_value, NULL);
    if (request == NULL) {
        return NULL;
    }
    jstring result = call_python(env, "can_session_key", request);
    (*env)->ReleaseStringUTFChars(env, request_value, request);
    return result;
}

JNIEXPORT jstring JNICALL
Java_org_msm5xxx_emulator_PythonRuntime_nativeKey(
        JNIEnv *env, jclass type, jstring request_value) {
    (void)type;
    const char *request = (*env)->GetStringUTFChars(env, request_value, NULL);
    if (request == NULL) {
        return NULL;
    }
    jstring result = call_python(env, "set_session_key", request);
    (*env)->ReleaseStringUTFChars(env, request_value, request);
    return result;
}

JNIEXPORT jstring JNICALL
Java_org_msm5xxx_emulator_PythonRuntime_nativeStop(
        JNIEnv *env, jclass type) {
    (void)type;
    return call_python(env, "stop_session", NULL);
}
