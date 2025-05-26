add_executable(rsa_generate generate.cpp)

target_link_libraries(rsa_generate
                        cryptopp
                        )

add_executable(rsa_verify verify.cpp)

target_link_libraries(rsa_verify
                        cryptopp
                        )
