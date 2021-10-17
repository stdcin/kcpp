## Build (linux) [![Build Status](https://travis-ci.com/stdcin/kcpp.svg?branch=master)](https://travis-ci.com/stdcin/kcpp)
```
sudo apt-get update
sudo apt-get install libevent-dev libpcap-dev libssl-dev

git clone ...
git submodule update --init
mkdir build && cd build
cmake ..
make
make install
```


## Build (Windows) [![Build status](https://ci.appveyor.com/api/projects/status/iia6lh928te7ctri/branch/master?svg=true)](https://ci.appveyor.com/project/vitamincpp/kcpp/branch/master)
[](https://slproweb.com/products/Win32OpenSSL.html)

```
git clone ...
git submodule update --init
mkdir build
cd build
cmake ..
cmake --build .
```
