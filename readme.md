

# 密钥完整生成、加密解密流程



1. ### 整体流程

   	> 类似的整体流程可见[离散椭圆曲线加密介绍](https://wenku.baidu.com/view/a45824a0bdeb19e8b8f67c1cfad6195f312be8e5.html)
	>
    	> 可以作为某些细节上的补充和梳理。

    1. ##### 加密流程

       ![](C:\Users\16423\Desktop\毕设\SUPI-SUCI加密方案\pics\image002.png)

        1. Eph. key pair generation

           终端（UE）通过椭圆曲线加密方案生成一对密钥，其中私钥是一个256位的随机数k，由终端保管；公钥K是以该随机数对基元进行标量乘法，即K=k*G，生成的新的坐标。这里椭圆曲线的参数和基元G的选定是通信双方事先商量好的。基站的一对密钥生成方法类似。

        2. Key agreement

           终端获得来自基站的公钥H，用标量乘法乘以自己的私钥k，即R=k*H，获得协商密钥Eph. shared key。协商密钥的位数为256位，尚不满足后续的需求。

        3. Key derivation

           使用key derivation function，将输入的256位协商密钥变成128+128+256位。取高字节位（MSB）作为对称加密的密钥Eph. enc. key，低字节位（LSB）作为MAC的密钥Eph. mac key，而中间的128位作为偏置模块ICB。

        4. Symmetric encryption

           使用密钥Eph. enc. key对明文Plaintext进行加密得到密文Ciphertext。这里的明文具体就是SUPI，密文具体就是SUCI。ICB是加密时的偏置项。

        5. MAC function

           MAC全称Message Authentication Code，类似于数字证书中的标签。对得到的密文Ciphertext以Eph. mac key为密钥做SHA-256，取高64位得到标签MAC-tag value。

        6. 最后的输出为终端公钥、密文、MAC-tag连接成的比特串，后面可以跟有可选的其他参数。

           

    2. ##### 解密流程

       ![](C:\Users\16423\Desktop\毕设\SUPI-SUCI加密方案\pics\image004.png)

        1. Key agreement

           基站获得来自终端消息，并根据字节分割为的终端公钥，SUCI，MAC-tag。将终端公钥K乘以基站的私钥h，即R‘=h*K获得协商密钥Eph. shared key，和终端计算得到的协商密钥相同，即R=R'。
    
        2. 后续步骤与加密流程完全相同。由于协商密钥Eph. shared key相同，在后续Key derivation过程中产生的Eph. enc. key、ICB、Eph. mac key也完全相同。只是MAC function在字节分割后最先执行，若生成的tag与消息中分割得到的tag不同则证明消息被篡改或者有误码，终止验证程序。若tag对应相同，则通过Symmetric decryption对Ciphertext解密得到Plaintext。



2. ### 技术细节

     

    1. ##### 备选方案

       3GPP在33.501中规定了三种可用的加密方案：

       > null-scheme     0x0;
       >
       > Profile <A>     0x1;
       >
       > Profile <B>     0x2.

       之后0xC - 0xF 的值保留做运营商自己制定的规范方案。

       传输数据尺寸为：

       > null-scheme     size of input, i.e., size of username used in case of NAI format or MSIN in case of IMSI;
       >
       > Profile <A>     total of 256-bit public key, 64-bit MAC, plus size of input; 
       >
       > Profile <B>     total of 264-bit public key, 64-bit MAC, plus size of input.

       其中null-scheme即为透明传输，不对SUPI加密；

       Profile<A>方案如下：

       > -	EC domain parameters							: Curve25519 
       > -	EC Diffie-Hellman primitive					: X25519 
       > -	point compression								: N/A
       > -	KDF												: ANSI-X9.63-KDF 
       > -	Hash												: SHA-256
       > -	SharedInfo1										:   $\overline{R}$
       > -	MAC												: HMAC–SHA-256
       > -	mackeylen										: 32 octets (256 bits)
       > -	maclen											: 8 octets (64 bits)
       > -	SharedInfo2										: the empty string
       > -	ENC												: AES–128 in CTR mode
       > -	enckeylen											: 16 octets (128 bits)
       > -	icblen												: 16 octets (128 bits)
       > -	backwards compatibility mode					: false

       Profile<B>方案如下：

       > -	EC domain parameters							: secp256r1 
       > -	EC Diffie-Hellman primitive					: Elliptic Curve Cofactor Diffie-Hellman Primitive 
       > -	point compression								: true
       > -	KDF												: ANSI-X9.63-KDF 
       > -	Hash												: SHA-256
       > -	SharedInfo1										:   $\overline{R}$
       > -	MAC												: HMAC–SHA-256
       > -	mackeylen										: 32 octets (256 bits)
       > -	maclen											: 8 octets (64 bits)
       > -	SharedInfo2										: the empty string
       > -	ENC												: AES–128 in CTR mode
       > -	enckeylen											: 16 octets (128 bits)
       > -	icblen												: 16 octets (128 bits)
       > -	backwards compatibility mode					: false

       >  具体细节见[1]。

       

    2. ##### 椭圆曲线加密

       这里不具体讨论椭圆曲线加密算法的理论基础，仅讨论方案。

       > 数学基础见
       >
       > + [现代密码学中的数论基础知识梳理](https://www.cnblogs.com/qcblog/p/8976017.html)
       >
       > + [信息安全数学基础(数论)](https://wenku.baidu.com/view/c105fa936bec0975f465e24b.html?rec_flag=default&sxts=1580397628213)
       >
       > + [同余方程总结](https://blog.csdn.net/dylan_frank/article/details/68953274)
       >
       > + [快速幂](https://www.cnblogs.com/yewanting/p/10743018.html)
       >
       > 加密原理见
       >
       > + [有趣的椭圆曲线加密](https://www.cnblogs.com/qcblog/p/8998045.html)
       > + [ECC椭圆曲线加密算法原理](https://blog.csdn.net/jingcheng345413/article/details/54969289)

       Profile<A>选择了Curve25519和X25519函数。

       其中Curve25519是一条Montgomery曲线，参数如下：

       > $v^2 = u^3 + A*u^2 + u$
       >
       > p $2^{255} - 19$
       >
       > A 486662
       > order $2^{252}$ + 0x14def9dea2f79cd65812631a5cf5d3ed
       > cofactor 8
       > U(P) 9
       > V(P) 147816194475895447910205935684099868872646061346164752889648818
       > 37755586237401
       > The base point is u = 9, v = 1478161944758954479102059356840998688726
       > 4606134616475288964881837755586237401.

       X25519是对Curve25519上的点进行标量乘法的函数。其输入是<标量scalar，基元的u坐标>，输出是标量乘法产生的新的u坐标。由于所有运算在U域上，不需要point compression方案。

       > X25519具体实现方法见[7]、[8]，或
       >
       > [Montgomery curve的运算（1）——add/double运算](https://blog.csdn.net/mutourend/article/details/96315761)
       >
       > [Montgomery curve的运算（2）——montgomery ladder运算](https://blog.csdn.net/mutourend/article/details/96426020)
       
       Profile<B>选择了secp256r1曲线，这是一条Weierstrass曲线，参数如下：
       
         > The verifiably random elliptic curve domain parameters over Fp secp256r1 are specified by the
         > sextuple T = (p, a, b, G, n, h) where the finite field Fp is defined by:
         >
         > p = FFFFFFFF 00000001 00000000 00000000 00000000 FFFFFFFF FFFFFFFF
         > FFFFFFFF
         > = $2^{224}(2^{32} − 1) + 2^{192} + 2^{96} − 1$
         > The curve E: $y^2 = x^3 + ax + b$ over F~p~ is defined by:
         > a = FFFFFFFF 00000001 00000000 00000000 00000000 FFFFFFFF FFFFFFFF
         > FFFFFFFC
         > b = 5AC635D8 AA3A93E7 B3EBBD55 769886BC 651D06B0 CC53B0F6 3BCE3C3E
         > 27D2604B
         > E was chosen verifiably at random as specified in ANSI X9.62 [X9.62] from the seed:
         > S = C49D3608 86E70493 6A6678E1 139D26B7 819F7E90
         > The base point G in compressed form is:
         > G = 03 6B17D1F2 E12C4247 F8BCE6E5 63A440F2 77037D81 2DEB33A0
         > F4A13945 D898C296
         > and in uncompressed form is:
         > G = 04 6B17D1F2 E12C4247 F8BCE6E5 63A440F2 77037D81 2DEB33A0
         > F4A13945 D898C296 4FE342E2 FE1A7F9B 8EE7EB4A 7C0F9E16 2BCE3357 
         >
         > 6B315ECE CBB64068 37BF51F5 Finally the order n of G and the cofactor are: 
         >
         > n = FFFFFFFF 00000000 FFFFFFFF FFFFFFFF BCE6FAAD A7179E84 F3B9CAC2 FC632551 
         >
        > h = 01
    
      方案采用了Elliptic Curve Cofactor Diffie-Hellman Primitive，但由于协因子h=1，因此和其实Elliptic Curve Diffie-Hellman Primitive相同。注意到这里采取了点压缩方案，即将点的二维坐标原本需要32+32字节储存，通过压缩算法压缩为1+32字节。因此Profile<B>传输的公钥会比Profile<A>多一个字节。
    
   3. ##### 点压缩方案
   
      椭圆曲线上的任一仿射点(x, y)（非无穷远点）都可以压缩成利用其y坐标的最后一比特（记为y'）和x坐标来表示，即(x, y')，这就是点的压缩。反过来，利用(x, y')恢复y坐标，还原仿射点(x, y)的过程就称为点的解压缩。
   
      其原理可以用简单的数论知识解释，即椭圆曲线上对应一个x值的y有且仅有两个，且满足y~1~+y~2~=p，显然y~1~和y~2~奇偶性不同。
   
      > 具体细节见[椭圆曲线点的压缩](https://blog.csdn.net/samsho2/article/details/88104236)
   
      
   
   4. ##### 密码导出函数
   
      设置一个4字节的计数器counter，counter从00000001~16~开始递增。
   
      $For \quad i=1 \quad to \quad  \lceil keydatalen/hashlen \rceil :$
   
      ​	$K_i=HASH(Z||Counter||[SharedInfo])$
   
      $K=K_1||K_2||...||K_{ \lceil keydatalen/hashlen \rceil}$
   
      其中HASH函数设定为SHA-256。实际使用时keydatalen=512，hashlen=256,因此K由K~1~||K~2~组成。K~1~又分为128位的对称加密的密钥Eph. enc. key，和128位的偏置模块ICB。
   
      > 具体细节见[2]3.6节。
   
      
   
   5. ##### AES-128 CTR模式
   
      其中对称加密模块采用128位AES的CTR模式。
   
      其原理图如下：
   
      ![](C:\Users\16423\Desktop\毕设\SUPI-SUCI加密方案\pics\CTR.PNG)
   
      其中原文PLAINTEXT被分割128位一块；COUNTER是计数器模块，COUNTER1就是ICB(Initial Counter Block)，初始值起到偏置的作用，COUNTER每次加1。COUNTER用密钥函数CIPH~K~加密后与原文块取异或得到密文块CIPHERTEXT。解码时步骤完全相同，两次异或运算重新得到明文。最后一个块中明文长度可能不足一个块长，设为u位，那么其与加密块的前u位取异或生成密文，后面多余的部分抛弃，因此明文长度和密文长度相同。
   
         > CIPH函数具体细节见[6]、[AES 加密算法的原理详解](https://blog.csdn.net/gulang03/article/details/81175854)
   
   6. ##### AES-128 CTR模式
   
      其中对称加密模块采用128位AES的CTR模式。
   
      其原理图如下：
   
      ![](C:\Users\16423\Desktop\毕设\SUPI-SUCI加密方案\pics\CTR.PNG)
   
      其中原文PLAINTEXT被分割128位一块；COUNTER是计数器模块，COUNTER1就是ICB(Initial Counter Block)，初始值起到偏置的作用，COUNTER每次加1。COUNTER用密钥函数CIPH~K~加密后与原文块取异或得到密文块CIPHERTEXT。解码时步骤完全相同，两次异或运算重新得到明文。最后一个块中明文长度可能不足一个块长，设为u位，那么其与加密块的前u位取异或生成密文，后面多余的部分抛弃，因此明文长度和密文长度相同。
   
         > CIPH函数具体细节见[6]、[AES 加密算法的原理详解](https://blog.csdn.net/gulang03/article/details/81175854)
   
   7. ##### HMAC-SHA-256与SHA-256
   
        HMAC流程图如下：
   
        ![](C:\Users\16423\Desktop\毕设\SUPI-SUCI加密方案\pics\HMAC.png)
   
        > HMAC具体细节见[HMAC（Hash-based Message Authentication Code）实现原理](https://www.cnblogs.com/yvivid/p/hmac_basic.html)、
        >
        > SHA-256具体细节见[SHA-2 安全散列算法2 算法详解](https://blog.csdn.net/jerry81333/article/details/78566418?utm_source=blogxgwz4)

   ​    

3. ### 函数接口说明

     1. ##### 异常处理

        ```c++
        void handleError(int e)
        ```

        该函数输入一个错误类型e，在屏幕上打印错误类型说明，没有返回值。

     2. ##### 打印函数

        ```C++
        void display(const unsigned char* buf, int buflen)
        ```

        该函数输入需要打印的字节串的缓存区buf，以及需要打印的字节长度buflen，将字节串以十六进制的形式打印在屏幕上。

     3. ##### 字符转换

        ```c++
        int str2byte(const unsigned char* str, unsigned char* byte_stream,int datalen)
        ```

        该函数输入字符串str，并将字符串转为长度为datalen的字节串，并储存到byte_stream缓存区中，成功时返回1。

        例如字符串为：

        “00012080f6”

        对应转化为

        {0x00, 0x01, 0x020, 0x80, 0xf6}

        这个字节串。

     4. ##### 数据读入

        ```C++
        int dataReader(unsigned char* outBuf)
        ```

        该函数从标准输入流cin中读取字符串，并调用字符转换函数str2byte()将字符串转换为字节串，并储存到outBuf缓存区中，成功时返回数据字节长度datalen，datalen=0时认为数据读入失败。

     5. ##### 密钥导出

        ```C++
        int KDF(const unsigned char* sharedkey, unsigned char* derivedkey)
        ```

        该函数将32字节共享密钥sharedkey导出为需要的长度（这里长度规定为64字节），并储存到derivedkey缓存区中，成功时返回1，失败时返回0。

     6. ##### 对称加密

        ```C++
        int EVP_AES_128_CTR(const unsigned char* enckey,const unsigned char* ICB, const unsigned char* plaintext, unsigned char* ciphertext, int datalen)
        ```

        对称加密方案采用AES-128 in CTR mode，输入16字节密钥enckey，16字节初始向量ICB，需要加密的明文plaintext，明文长度datalen，并储存到ciphertext缓存区中，成功时返回加密后密文长度enclen，失败时返回0。注意CTR模式下明文长度和密文长度相同，因此enclen应该等于datalen。

     7. ##### 密文摘要

        ```C++
        int HMAC_SHA_256(const unsigned char* mackey,const unsigned char* ciphertext,int datalen,unsigned char* mactag )
        ```

        该函数输入32字节密钥mackey，密文ciphertext，密文长度datalen，生成32字节摘要并储存到outbuf缓存区中，并复制高8字节到mactag缓存区中。成功时返回摘要长度mdlen，mdlen应该为32字节，失败时返回0。

     8. ##### 密钥生成

        ```C++
        int keyGenerator(const int io,const int profile,void** UE_key,void** home_key)
        ```

        该函数生成两组密钥UE_key和home_key。

        io指定了密钥输入设备：io=STDIN为从标准输入流输入两组私钥，并根据给定的私钥产生密钥对；io=NULL为随机生成两组密钥对。

        profile指定了加密方案：profile=NULL为透明传输；profile=PROFILE_A为curve25519方案传输；profile=PROFILE_B为secp256r1方案传输。

        成功时返回1，失败时返回0。

        为了传递指针的值，输入事实上为指针的指针。如下：

        ```C++
        //...
        void* UE_key;
        void* home_key;
        if (!keyGenerator(STDIN,PROFILE_A,&UE_key,&home_key)) 
            return 0;
        ```

     9. ##### 加密解密

        ```C++
        int procedure(
        	const int mode,
        	const int profile,
        	unsigned char* databuf,
        	int* datalen,
        	unsigned char* IObuf,
        	int* IOlen,
        	const void* UE_key,
        	const void* home_key
        )
        ```

        该函数通过改变参数，同时实现了加密和解密流程。

        mode指定了加密或者解密：mode=ENCRYPTION指加密流程；mode=DECRTPTION指解密流程。

        profile指定了加密方案：profile=NULL为透明传输；profile=PROFILE_A为curve25519方案传输；profile=PROFILE_B为secp256r1方案传输。

        databuf作为传递明文的缓存区。mode=ENCRYPTION时，该区作为输入缓存区存放需要加密的明文；mode=DECRTPTION时，该区作为输出缓存区存放解密后的密文（应与明文一致）。

        datalen作为传递明文长度的缓存区。mode=ENCRYPTION时，该指针作为输入存放明文长度；mode=DECRTPTION时，该指针作为输出存放解密后密文长度（应与明文长度一致）。

        IObuf作为传递比特流的缓存区，即模拟了信道的功能。该区存放UE公钥、密文和密文摘要组成的字节串，mode=ENCRYPTION时作为输出缓存区，mode=DECRTPTION时作为输入缓存区。

        IOlen作为传递IO字节串长度的缓存区。真实传输时，通常会加上校验头和校验尾，因此我们可以获得信息的字节串长度。IOlen在这里模拟了这个功能，存放IObuf中字节串长度。mode=ENCRYPTION时，该指针作为输出缓存区；mode=DECRTPTION时，该指针作为输入缓存区。

        UE_key为密钥生成函数keyGenerator生成的UE端密钥对。

        home_key为密钥生成函数keyGenerator生成的home端密钥对。

        

4. ### 参考文献

     + [1]    3GPP TS 33.501 V15.3.1 (2018-12)    Annex C (normative):
       Protection schemes for concealing the subscription permanent identifier 

     + [2]    nistspecialpublication800-38a    

       Recommendation for Block Cipher Modes of Operation

     + [3]    sec1-v2    SEC 1: Elliptic Curve Cryptography

     + [4]    sec2-v2    SEC 2: Recommended Elliptic Curve Domain Parameters

     + [5]    rfc7748    Elliptic Curves for Security

     + [6]    fips-197    ADVANCED ENCRYPTION STANDARD (AES)

     + [7]    2017-212    Montgomery curves and their arithmetic

     + [8]    S0025-5718-1987-0866113-7    

       Speeding the Pollard and Elliptic Curve Methods of Factorization

