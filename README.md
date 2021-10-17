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


## Build (Windows) [![Build status](https://ci.appveyor.com/api/projects/status/se4vy0yi9g8lrtb1?svg=true)](https://ci.appveyor.com/project/vitamincpp/kcpp)

```
git clone ...
git submodule update --init
mkdir build
cd build
cmake ..
cmake --build .
```
