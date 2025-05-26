
add_compile_options(-Wextra -Wall -Wno-implicit-fallthrough -Werror)

include_directories("${CMAKE_CURRENT_SOURCE_DIR}/plugin/src/asn1c")

# The following executables are for testing purposes only

file(GLOB asn1c_files RELATIVE "${CMAKE_CURRENT_SOURCE_DIR}" "plugin/src/asn1c/*.c")
add_library(asn1c OBJECT ${asn1c_files})

add_executable(test-cp $<TARGET_OBJECTS:asn1c> testing/Files/asn1c-test.c)
target_compile_definitions(test-cp PRIVATE PDU=CP_type)

add_executable(test-cpa $<TARGET_OBJECTS:asn1c> testing/Files/asn1c-test.c)
target_compile_definitions(test-cpa PRIVATE PDU=CPA_PPDU)

add_executable(test-cpc $<TARGET_OBJECTS:asn1c> testing/Files/asn1c-test.c)
target_compile_definitions(test-cpc PRIVATE PDU=CPC_type)

add_executable(test-data $<TARGET_OBJECTS:asn1c> testing/Files/asn1c-test.c)
target_compile_definitions(test-data PRIVATE PDU=Typed_data_type)

add_executable(test-abort $<TARGET_OBJECTS:asn1c> testing/Files/asn1c-test.c)
target_compile_definitions(test-abort PRIVATE PDU=Abort_type)
