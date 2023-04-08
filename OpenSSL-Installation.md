# OpenSSL Installation

## Installation on Linux
- CentOS / Red Hat
  By default, OpenSSL is already included in CentOS. If this is not the case with your instance, then run the following command line:

```shell
yum install openssl
```
- Ubuntu
  By default, OpenSSL is already included in Ubuntu. If this is not the case with your instance, then run the following command line:

```shell
apt install openssl
```

## Installation on macOS
By default, OpenSSL is already installed in macOS. However, your version may be outdated. If so, then you can install the latest version with Homebrew. After installing Homebrew, simply run the following command line:

```shell
brew install openssl
```

## Warning on StarkCurve

The StarkCurve is a new curve proposed by StarkWare. It is a 256-bit curve with a 128-bit security level. It is designed to be used in the StarkEx protocol. The StarkCurve is not supported by OpenSSL. We have extended OpenSSL to support the StarkCurve. If you want to use the StarkCurve, you must install the [extended OpenSSL](https://github.com/Safeheron/openssl/tree/stark_curve) (refer to the "stark_curve" branch). Otherwise, you will get an error when you use the StarkCurve. 
