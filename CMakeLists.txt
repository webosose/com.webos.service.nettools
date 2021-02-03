# Copyright (c) 2021 LG Electronics, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# SPDX-License-Identifier: Apache-2.0

#
# webos-nettools/CMakeLists.txt
#


cmake_minimum_required(VERSION 2.8.7)

project(webos-nettools C)

include(webOS/webOS)
webos_modules_init(1 0 0 QUALIFIER RC4)
webos_component(1 1 0)

include(FindPkgConfig)

pkg_check_modules(GLIB2 REQUIRED glib-2.0)
include_directories(${GLIB2_INCLUDE_DIRS})
webos_add_compiler_flags(ALL ${GLIB2_CFLAGS_OTHER})

pkg_check_modules(GIO-UNIX REQUIRED gio-unix-2.0)
include_directories(${GIO-UNIX_INCLUDE_DIRS})
webos_add_compiler_flags(ALL ${GIO-UNIX_CFLAGS_OTHER})

pkg_check_modules(LUNASERVICE2 REQUIRED luna-service2)
include_directories(${LUNASERVICE2_INCLUDE_DIRS})
webos_add_compiler_flags(ALL ${LUNASERVICE2_CFLAGS_OTHER})

pkg_check_modules(PBNJSON_C REQUIRED pbnjson_c)
include_directories(${PBNJSON_C_INCLUDE_DIRS})
webos_add_compiler_flags(ALL ${PBNJSON_C_CFLAGS_OTHER})

webos_add_compiler_flags(ALL -Wall -g)

webos_add_linker_options(ALL --no-undefined)

add_definitions(-DHOSTNAME_FILE_DIR="${WEBOS_INSTALL_LOCALSTATEDIR}")

file(GLOB SOURCE_FILES src/*.c)

add_executable(webos-nettools ${SOURCE_FILES})
target_link_libraries(webos-nettools
                        ${GLIB2_LDFLAGS}
                        ${GIO-UNIX_LDFLAGS}
                        ${LUNASERVICE2_LDFLAGS}
                        ${PBNJSON_C_LDFLAGS}
                        rt
                        pthread)

webos_build_daemon()
webos_build_system_bus_files()

#webos_config_build_doxygen(doc Doxyfile)
