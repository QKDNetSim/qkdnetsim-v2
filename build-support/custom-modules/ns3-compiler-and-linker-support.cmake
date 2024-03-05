# Copyright (c) 2023 Universidade de Brasília
#
# This program is free software; you can redistribute it and/or modify it under
# the terms of the GNU General Public License version 2 as published by the Free
# Software Foundation;
#
# This program is distributed in the hope that it will be useful, but WITHOUT
# ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
# FOR A PARTICULAR PURPOSE.  See the GNU General Public License for more
# details.
#
# You should have received a copy of the GNU General Public License along with
# this program; if not, write to the Free Software Foundation, Inc., 59 Temple
# Place, Suite 330, Boston, MA  02111-1307 USA
#
# Author: Gabriel Ferreira <gabrielcarvfer@gmail.com>

# Compiler-specific version checks and flag/feature setting should be done here

# Identify compiler and check version
set(below_minimum_msg "compiler is below the minimum required version")
set(CLANG FALSE)
if("${CMAKE_CXX_COMPILER_ID}" MATCHES "AppleClang")
  if(CMAKE_CXX_COMPILER_VERSION VERSION_LESS ${AppleClang_MinVersion})
    message(
      FATAL_ERROR
        "Apple Clang ${CMAKE_CXX_COMPILER_VERSION} ${below_minimum_msg} ${AppleClang_MinVersion}"
    )
  endif()
  set(CLANG TRUE)
endif()

if((NOT CLANG) AND ("${CMAKE_CXX_COMPILER_ID}" MATCHES "Clang"))
  if(CMAKE_CXX_COMPILER_VERSION VERSION_LESS ${Clang_MinVersion})
    message(
      FATAL_ERROR
        "Clang ${CMAKE_CXX_COMPILER_VERSION} ${below_minimum_msg} ${Clang_MinVersion}"
    )
  endif()
  set(CLANG TRUE)
endif()

if(CLANG)
  if(${NS3_COLORED_OUTPUT} OR "$ENV{CLICOLOR}")
    add_definitions(-fcolor-diagnostics) # colorize clang++ output
  endif()
endif()

set(GCC FALSE)
if("${CMAKE_CXX_COMPILER_ID}" MATCHES "GNU")
  if(CMAKE_CXX_COMPILER_VERSION VERSION_LESS ${GNU_MinVersion})
    message(
      FATAL_ERROR
        "GNU ${CMAKE_CXX_COMPILER_VERSION} ${below_minimum_msg} ${GNU_MinVersion}"
    )
  endif()
  if((CMAKE_CXX_COMPILER_VERSION VERSION_GREATER_EQUAL "12.2.0"))
    # PCH causes weird errors on certain versions of GCC when C++20 is enabled
    # https://gcc.gnu.org/bugzilla/show_bug.cgi?id=106799
    set(NS3_PRECOMPILE_HEADERS OFF
        CACHE BOOL "Precompile module headers to speed up compilation" FORCE
    )
  endif()
  if((CMAKE_CXX_COMPILER_VERSION VERSION_GREATER_EQUAL "12.1.0")
     AND (CMAKE_CXX_COMPILER_VERSION VERSION_LESS "12.3.2")
  )
    # Disable warnings-as-errors for certain versions of GCC when C++20 is
    # enabled https://gcc.gnu.org/bugzilla/show_bug.cgi?id=105545
    add_compile_options(-Wno-restrict)
  endif()
  set(GCC TRUE)
  add_definitions(-fno-semantic-interposition)
  if(${NS3_COLORED_OUTPUT} OR "$ENV{CLICOLOR}")
    add_definitions(-fdiagnostics-color=always) # colorize g++ output
  endif()
endif()
unset(below_minimum_msg)

set(LIB_AS_NEEDED_PRE "")
set(LIB_AS_NEEDED_POST "")
set(STATIC_LINK_FLAGS -static -static-libstdc++ -static-libgcc)
if(${GCC} AND NOT APPLE)
  # using GCC
  set(LIB_AS_NEEDED_PRE -Wl,--no-as-needed)
  set(LIB_AS_NEEDED_POST -Wl,--as-needed)
  set(LIB_AS_NEEDED_PRE_STATIC -Wl,--whole-archive,-Bstatic)
  set(LIB_AS_NEEDED_POST_STATIC -Wl,--no-whole-archive)
  set(LIB_AS_NEEDED_POST_STATIC_DYN -Wl,-Bdynamic,--no-whole-archive)
endif()

if(${CLANG} AND APPLE)
  # using Clang set(LIB_AS_NEEDED_PRE -all_load)
  set(LIB_AS_NEEDED_POST "")
  set(LIB_AS_NEEDED_PRE_STATIC -Wl,-all_load)
  set(STATIC_LINK_FLAGS "")
endif()

if(${NS3_FAST_LINKERS})
  # Search for faster linkers mold and lld, and use them if available
  mark_as_advanced(MOLD LLD)
  find_program(MOLD mold)
  find_program(LLD ld.lld)

  # USING_FAST_LINKER will be defined if a fast linker is being used and its
  # content will correspond to the fast linker name

  # Mold support was added in GCC 12.1.0
  if(NOT USING_FAST_LINKER
     AND NOT (${MOLD} STREQUAL "MOLD-NOTFOUND")
     AND LINUX
     AND ${GCC}
     AND (CMAKE_CXX_COMPILER_VERSION VERSION_GREATER_EQUAL 12.1.0)
  )
    set(USING_FAST_LINKER MOLD)
    add_link_options("-fuse-ld=mold")
  endif()

  if(NOT USING_FAST_LINKER AND NOT (${LLD} STREQUAL "LLD-NOTFOUND")
     AND (${GCC} OR ${CLANG})
  )
    set(USING_FAST_LINKER LLD)
    add_link_options("-fuse-ld=lld")
    if(WIN32)
      # Clear unsupported linker flags on Windows
      set(LIB_AS_NEEDED_PRE "")
    endif()
  endif()
endif()
