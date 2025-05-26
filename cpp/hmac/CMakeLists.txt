
add_executable(generate license_gen.cpp
hardware_utils.cpp)

target_link_libraries(generate
                        cryptopp
                        )

add_executable(verify license_verify.cpp
hardware_utils.cpp)

target_link_libraries(verify
                        cryptopp
                        )
