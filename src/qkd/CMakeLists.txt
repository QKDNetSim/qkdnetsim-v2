find_external_library(
  DEPENDENCY_NAME CRYPTOPP
  HEADER_NAME cryptlib.h
  LIBRARY_NAME crypto++
               cryptopp 
  SEARCH_PATHS /usr/include/cryptopp
               ${NS3_WITH_CRYPTOPP}
)


set(NS3_WITH_UUID
    ""
    CACHE PATH
          "Build with UUID support"
)
set(NS3_UUID
    "OFF"
    CACHE INTERNAL
          "ON if UUID is found in NS3_WITH_UUID"
)

if((NOT
    CRYPTOPP_FOUND)
   AND (NOT
       ${CRYPTOPP_FOUND})
)
  message(
    ${HIGHLIGHTED_STATUS}
    "Skipping src/qkd"
  )
  return()
endif()

# Only process module if include folder and library have been found
include_directories(${CRYPTOPP_INCLUDE_DIRS}) 
set(NS3_CRYPTOPP
    "ON"
    CACHE INTERNAL
          "ON if CRYPTOPP is found in NS3_WITH_CRYPTOPP"
)

find_external_library(
  DEPENDENCY_NAME uuid
  HEADER_NAME uuid.h
  LIBRARY_NAME uuid
  SEARCH_PATHS /usr/include/uuid
               ${NS3_WITH_UUID}
)
# If the header(s) and library(ies) are not found, a message will be printed during the configuration
# If the header(s) and the library(ies) are found, we can use the information found by the buildsystem
if(${uuid_FOUND}) # Notice that the contents of DEPENDENCY_NAME became a prefix for the _FOUND variable
    # The compiler will not be able to find the include that is not on
    # a system include path, unless we explicitly inform it

    # This is the equivalent of -I/optional/search/path/to/custom/uuid/include
    # and AFFECTS ALL the targets in the CURRENT DIRECTORY and ITS SUBDIRECTORIES
    include_directories(${uuid_INCLUDE_DIRS})

    # The compiler should be able to locate the headers, but it still needs to be
    # informed of the libraries that should be linked

    # This is the equivalent of -l/optional/search/path/to/custom/sqlite3/library/libsqlite3.so
    # and AFFECTS ALL the targets in the CURRENT DIRECTORY and ITS SUBDIRECTORIES
    link_libraries(${uuid_LIBRARIES})
endif()

build_lib(
  LIBNAME qkd
  SOURCE_FILES
    model/qkd-buffer.cc
    model/qkd-control.cc
    model/qkd-graph.cc
    model/qkd-total-graph.cc
    model/qkd-graph-manager.cc 
    model/qkd-key.cc 
    model/qkd-encryptor.cc
    model/qkd-key-association-link-entry.cc
    model/qkd-application-entry.cc
    model/qkd-connection-register.cc
    helper/qkd-link-helper.cc
    helper/qkd-encryptor-container.cc 
    helper/qkd-control-container.cc 
    utils/uuid.cc
  HEADER_FILES
    model/qkd-buffer.h
    model/qkd-control.h
    model/qkd-graph.h
    model/qkd-total-graph.h
    model/qkd-graph-manager.h
    model/qkd-key.h 
    model/qkd-encryptor.h
    model/qkd-key-association-link-entry.h
    model/qkd-application-entry.h
    model/qkd-connection-register.h
    helper/qkd-link-helper.h
    helper/qkd-encryptor-container.h 
    helper/qkd-control-container.h 
    utils/uuid.h

  LIBRARIES_TO_LINK ${libinternet}
                    ${CRYPTOPP_LIBRARIES}

)
