cmake_minimum_required(VERSION 3.22.1)
project(msm5xxx_python C)

include_directories("${PYTHON_PREFIX_DIR}/include/python3.14")
link_directories("${PYTHON_PREFIX_DIR}/lib")
link_libraries(log python3.14)

add_library(msm5xxx_python SHARED msm5xxx_python.c)
get_filename_component(ANDROID_CLIENT_ROOT
    "${CMAKE_CURRENT_SOURCE_DIR}/../../../.." ABSOLUTE)
foreach(path IN ITEMS "${PYTHON_PREFIX_DIR}" "${CMAKE_CURRENT_SOURCE_DIR}"
                      "${CMAKE_CURRENT_BINARY_DIR}" "${ANDROID_CLIENT_ROOT}"
                      "${ANDROID_NDK}")
    target_compile_options(msm5xxx_python PRIVATE
        "-ffile-prefix-map=${path}=."
        "-fmacro-prefix-map=${path}=.")
endforeach()
target_link_options(msm5xxx_python PRIVATE "-Wl,-z,max-page-size=16384")
