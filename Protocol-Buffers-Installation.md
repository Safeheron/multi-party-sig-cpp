# Protocol Buffers Installation 

You should switch to version v3.14.x or v3.20.x.

## Installation On Linux

On Ubuntu/Debian, you can install them with:
```shell
sudo apt-get install autoconf automake libtool curl make g++ unzip
```
On other platforms, please use the corresponding package managing tool to install them before proceeding.

You can also get the source by "git clone" our git repository. Make sure you have also cloned the submodules and generated the configure script (skip this if you are using a release .tar.gz or .zip package):

```shell
git clone https://github.com/protocolbuffers/protobuf.git
cd protobuf
git checkout v3.14.0
git submodule update --init --recursive
./autogen.sh
```

To build and install the C++ Protocol Buffer runtime and the Protocol Buffer compiler (protoc) execute the following:
```shell
./configure
make -j$(nproc) # $(nproc) ensures it uses all cores for compilation
make check
sudo make install
sudo ldconfig # refresh shared library cache.
```


## Installation On Mac

You can install them with:
```shell
brew install autoconf automake libtool
```

You can also get the source by "git clone" our git repository. Make sure you have also cloned the submodules and generated the configure script (skip this if you are using a release .tar.gz or .zip package):
```shell
git clone https://github.com/protocolbuffers/protobuf.git
cd protobuf
git checkout v3.14.0
git submodule update --init --recursive
./autogen.sh
```

To build and install the C++ Protocol Buffer runtime and the Protocol Buffer compiler (protoc) execute the following:
```shell
./configure
make -j$(nproc) # $(nproc) ensures it uses all cores for compilation
make check
sudo make install
sudo ldconfig # refresh shared library cache.
```

You should add the path to the LD_LIBRARY_PATH environment variable for compilation:
```shell
export LIBRARY_PATH=$LIBRARY_PATH:/usr/local/lib/
```
