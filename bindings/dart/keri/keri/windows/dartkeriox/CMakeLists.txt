
include(../../cmake/dartkeriox.cmake)

set_property(TARGET ${CRATE_NAME} PROPERTY IMPORTED_LOCATION "${CMAKE_CURRENT_SOURCE_DIR}/dartkeriox.dll")
set_property(TARGET ${CRATE_NAME} PROPERTY IMPORTED_IMPLIB "${CMAKE_CURRENT_SOURCE_DIR}/dartkeriox.lib")