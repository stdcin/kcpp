include_directories(../src)

add_executable(crypto_test ../src/crypto.cpp crypto_test.cpp)
target_link_libraries(crypto_test gtest_main OpenSSL::Crypto)
add_test(crypto_test crypto_test)
