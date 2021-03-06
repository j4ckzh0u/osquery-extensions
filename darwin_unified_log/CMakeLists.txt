# Copyright (c) 2018 Trail of Bits, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

cmake_minimum_required(VERSION 3.10)
project(darwin_unified_log)

function(main)
  set(project_common_source_files
    src/system_log.h
    src/system_log.cpp
  )

  set(project_libraries thirdparty_boost_random)

  addOsqueryExtensionEx("UnifiedLogTablePlugin" "table" "darwin_unified_log"
    SOURCES ${project_common_source_files} src/darwinlogtable.h src/darwinlogtable.cpp
    INCLUDEDIRS "${CMAKE_CURRENT_SOURCE_DIR}/src" "${TOB_EXTENSIONS_ROOT}"
    MAININCLUDES darwinlogtable.h
    LIBRARIES ${project_libraries}
  )

endfunction()

main()
