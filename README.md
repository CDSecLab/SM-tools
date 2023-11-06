# sm-tools

> 测试环境:
>
> - Ubuntu 22.04
> - GmSSL 3.1.1 PR1
> - gmssl-python 2.2.2



[gmssl-python](https://github.com/GmSSL/GmSSL-Python) 实现的功能可以覆盖除SSL/TLS/TLCP之外的国密算法主要应用开发场景。在此基础上，我们封装了其中的常用算法，以作为一个工具集方便后续的调用。



## 环境配置

1. 安装编译需要的工具

   ```sh
   sudo apt install cmake
   ```

2. 下载gmssl[源码](https://github.com/guanzhi/GmSSL)

   进入文件夹, 执行下述操作

   ```sh
   mkdir build
   cd build
   cmake ..
   make
   make test
   sudo make install
   ```

   验证gmssl是否安装成功

   ```sh
   gmssl version
   # GmSSL 3.1.1 PR1
   ```

   > 遇到 libgmssl.so.3: cannot open shared object file: No such file or directory 问题: [参考解决方案](https://github.com/guanzhi/GmSSL/issues/1406)
   >
   > ```sh
   > sudo cp /usr/local/lib/libgmssl.so.3 /usr/lib/ && sudo ldconfig
   > ```

3. 安装gmssl-python

   ```sh
   # 安装
   pip install gmssl-python
   # 查看本地安装版本
   pip show gmssl-python
   ```



## 功能

- [x] SM2加密和签名，SM2密钥生成、私钥口令加密保护、密钥PEM文件导入导出
- [ ] SM2数字证书的导入、解析和验证
- [x] SM3哈希函数、HMAC-SM3消息认证码、基于SM3的PBKDF2密钥导出函数
- [x] SM4分组加密，以及SM4的CBC、CTR、GCM三种加密模式
- [x] SM9加密和签名，以及SM9密钥生成、密钥口令加密保护、密钥PEM文件导入导出
- [x] ZUC序列密码加密



