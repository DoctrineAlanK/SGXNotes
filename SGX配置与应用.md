SGX 程序分为可信部分和非可信部分，这两部分代码需要分别构建，因此将分别创建两个项目，作为演示项目。此应用程序将实现使用 ECDSA 算法（椭圆曲线数字签名算法）对消息进行签名、所有的加密部分比如密钥生成、签名、验签等都将在 Enciave 中完成，私钥将并保存在 Enclave 或密封保存在文件系统中。非可信部分代码将无法访问并获取私钥，所有的加密功能都使用 SGX 提供的可信码库的 API。

## 1. 创建 SGX Enclave 项目
打开 Visual Studio, 在菜单栏中依次点击“文件”→“新建”→“项目”，选择 Intel@SGX Enclave Project 后输入项目名称（比如这里使用 CryptoEnclave)入项目位置、解决方案名称（比如这里使用 SecureCrypto)等信息后点击“创建”按钮。Intel®SGX SDK Project Wizard 将展示默认的 Enclave 设置，其中几个设置含义如下：
(1）Project Type
* Enclave: 创建 Enclave 项目。通常第一次创建 SGX Enclave 项目时都会选择这个选项。
* Enclave library: 为 SGX Enclave 项目创建多个应用之间共享的 Enclave 静态库。
(2) Additional Libraries
* C+11: 链接到 C++11 的库。如果选择使用 C++语言编写代码，需要选中该选项。如果使用 C 语言编写代码，则应取消勾选该选项。如果创建的项目类型是 Enclave 静态库，该选项将被置灰。另外，如果创建的 Enclave 使用了 C+的静态库，创建 Enclave 项目时必须勾选这个选项，即使 Enclave 本身没有使用 C++。
* EDL File: 链接一个 EDL 文件到 Enclave 项目。如果构建的 Enclave 需要对外暴露 Enclave 接口，则必须选中该选项。
(3) Signing Key
该选项用于导入将在 Enclave 中使用的密钥。如果不选择将其导入本文件，Visual Studio 将自动生成一个随机密钥。除了用于构建生产用的 Release 模式的 Enclave 之外，Enclave 签名工具也可使用这个密钥对 Enclave 进行签名。如果是在构建 Enclave 静态库，则不需要导入密钥，因为 Enclave 静态库无须签名。

## 2. 配置 SGX Enclave 项目
创建完项目后，需要对 Enclave 进行配置，可以使用 Enclave Settings 窗口来创建和靠护 Enclave 配置文件（Enclave Configuration File，ECF）。ECF 是 Enclave 项自的一一部分，用来提供 Enclave 元数据信息。基础设置的各项含义如下：

| 设置项名称        | 描述                                  | ECF 标签       |
| ----------------- | ------------------------------------- | -------------- |
| Product ID        | ISV（独立软件提供商）分配的 ProductID | \<ProdID>       |
| ISV SVN           | ISV 分配的 SVN                        | \<ISVSVN>       |
| Thread Stack Size | 每个可信线程的栈大小（字节数）        | \<StackMaxSize> |
| Global Heap Size  | Enclave 的堆大小（字节数）            | \<HeapSizeMax>  |
| Thread Number     | 可信线程的数目                        |       \<TCSNum>         |
| Thread Bound Policy           |        TCS 管理策略                               |      \<TCSPolicy>          |

## 3. 编写 EDL
EDL (Enclave Definition Language)文件定义了应用程序中可信部分与兼可信部分之间的交互接口。代码清单 8-1 是 Visual Studio 中创建的 EDL 文件模板，主要分为 Trusted 和Untrusted 两部分。可信函数需要在 Enclave 的 cpp 文件中编写，非可信函数侧必须在应用程序中实现。

```c++
//代码清单8-1 EDL文件模板

enclave {
    From "sgx_tstdc. Edl" import *;

    trusted {
        /* define ECALLs here. */

    };

    untrusted {
        /* define OCALLs here. */

    };
};
```

在代码清单 8-1 中，关键字 from 和 import 是指将 EDL 库文件中的指定函数添加到当前 Enclave EDL 文件中。其中，ECALL （即 Enclave Call）是指 Enclave 提供的可供外部非可信应用程序调用的接口；OCALL （即 Outside Call）是指 Enclave 内部调用外部非可信应用程序的接口。在 EDL 文件的接口说明中，我们还可定义 Enclave 边界需要检查和处理的输入和输出参数。Visual Studio 插件会自动读取 EDL 文件并生成边缘例程 （Edge Routine)的代码，而边界检查（为了安全）是由运行在 Enclave 中的可信桥 （Trusted Bridge)以及可信代理 (Trusted Proxy）在运行时完成的。

### 1. EDL 支持的基本数据类型
EDL 支持的的输入和输出参数基本类型有 char、short、long、int、float、double、void、int 8_t、int 16_t、int 32_t、int 64_t、size_t、wchar_t、uint 8_t、uint 16_t、uint 32_t、uint 64_t、unsigned、struct、enum、union、long long、long double。除此之外，其还支持指针（不包括函数指针）和数组。

代码清单 8-2 定义了一个数据签名的接口 esv_sign。该接口将在 Enclave 中执行，传入参数为需要签名的 message，类型为 const char*；传出参数为经过签名的 signature，类型为 void*。

```c++
 //代码清单8-2 EDL定义ECALL函数的示例
 
 trusted {
        /* define ECALLs here. */
        public int crypto_sign([in, string] const char* message, 
                [out, size=sig_len] void* signature, size_t sig_len);

    };
```

### 2. const 关键字
EDL 支持 const 关键字，其与在 C 语言中的作用类似。但是，这个关键字在 EDL 中是有限制的，只能用于指针，并且是最外层的修饰符。C 语言的 const 的其他作用在EDL 中不支持。

### 3. 指针参数
在代码清单 8-2 中，指针参数使用了特殊的属性修饰符。下面为指针可以使用的属性。
#### Ⅰ. in（方向属性）
当指针参数指定为 in 属性时，参数将从调用过程传递到被调用过程。也就是说，对于 ECALL，参数从应用程序传递到 Enclave；对于 OCALL。参数从 Enclave 传递到应用程序。如图中的Ⅰ所示，当一个应用租序调用一个带有被 in 属性修饰的指针参数的 ECALL 时，可信边缘例程就会将指针指向的内存内客复制到可信内存区域，然后将这份复制内容传递给可信环境。

#### Ⅱ. out（方向属性）
其调用过程与 in 属性时的过程相反。边缘例程根据方向属性复制被指针指定的缓存。为了复制缓存内容，边缘例程必须知道有多少需要去复制。因此，方向属性通常带有 size 或者 count 修饰符。in 和 out 属性组合时，参数是双向传递的。

如图中的②所示，当一个应用程序调用一个带有被 out 属性修饰的指针参数的 ECALL 时，边缘例程会在可信内存区域分配一个缓冲区（Buffer)将其初始化为并传送给可信环境。然后当可信函数返回时，可信桥会复制缓冲区中的内容到非可信内存中（见图中的③）。也就是说，可信内存是不会直接对外暴露的。

#### Ⅲ. size
其通常用于 void 指针，以指定缓存区大小（以字节为单位）。当 size 没有被指定时、则默认缓存区大小为 sizeof（由指针指向的元素大小）。

#### Ⅳ. count
count 和 size 属性修饰符具有相同的目的，即告知边缘例程需要复制的缓存区内容的大小。count 可以是整型常量，也可以是函数的参数之一。count 和 size 属性组合在一起时、边缘例程复制的字节数取决于参数指向的数据的 size 和 count 的乘积。当 count 没有被指定时，默认 count 为 1，总字节为 size\*1。

#### V. string 和 wstring
属性 string 和 wstring 表明参数是以“\\0”结尾的字符串。string 和 wstring 属性在使用上有一些限制：不能和 size、count 属性同时使用；不能和 out 属性单独同时使用，但是 in、out 可以和 wsting、string 同时使用；string 属性只能用于 char 指针、而 wsting 属性只能用于 wchar_t 指针。


#### Ⅵ. sizefunc
sizefunc 属性作用是便于开发者指定一个用于计算函数参数长度的函数。为了阻止“先检查，后使用”的攻击，sizefunc 会被调用两次：第一次在不可信内存中调用；第二次在数据复制到可信内存时调用。如果两次调用返回的数据大小不一样，可信桥函数会取消此次 ECALL 调用，然后报告一个错误给不可信应用程序。

sizefunc 决不能和 size 属性一起使用，也不能和 out 属性单独使用，但可以和 in 和 out 属性同时使用。另外，不能定义 sizefunc 为 strlen 或者 wcslen。 String 属性不能使 sizefunc 修饰符传递，但可使用 string 或者 wstring 关键字。下面是需要在 Enclave 内定义的可信 sizefunc 的函数原型：

`size_t sizefunc_function_name(const parameter_type * p) ;
`

parameter_type 是使用 sizefunc 标记的参数的数据类型。如果没有提供 sizefunc 的定义，链接器会报错。如代码清单 8-3 所示，sizefunc 还可以和 count 一起使用，此时复制的全部字节数将是 sizefunc×count。

```c++
//代码清单8-3 使用sizefunc的示例

enclave{
    trusted {
		//复制get_packet_size 个字节，开发者必须
		// 定义get_packet_size函数: size_t get_packet_size(const void* ptr);
		void demo_sizefunc([in, sizefunc=get_packet_size] void* ptr);
		// 复制(get_packet_size ＊ cnt）个字节
		void demo_sizefunc2(
		  [in, sizefunc=get_packet_size, count=cnt] void*
		  ptr, unsigned cnt);
	};

    untrusted {
        /* define OCALLs here. */
    };
};
```

#### Ⅶ. user_check
对于一些特殊的场景，比如数据太大，一个 Enclave 放不下，需要切分成多个区块，使用多个 Enclave 通过一系列 ECALL 进行处理（开发者可以创建一对多的可信 Enclave 一起工作来支持分布式体系），而方向属性不支持 Enclave 间的数据通信，此时使用 user_check 属性来表示不对指针进行任何验证。

#### Ⅷ. isptr
isptr 用于指定用户定义的参数是指针类型。

#### Ⅸ. readonly
当 ECALL 或者 OCALL 使用用户自定义的 const 数据类型时，参数需要被注明是 readonly 属性。readonly 只能与 isptr 属性一起使用。

### 4. 数组
正如上面所述，EDL 除了支持指针还支持多维、固定大小的数组。数组类似于指针，使用 in、out、user_check 属性。当参数是一个用户定义的数组类型时，我们需要使用 isary 属性来修饰。需要注意的是，数组不能使用 size、count 属性，因为根据数组类型，攻击者就可以推断出所需缓存的大小。另外，数组也不支持指针类型。

### 5. 头文件
C 结构体、联合体、typedefs 等一般都定义在头文件中。如果 EDL 中引用了这些类型却没有包含头文件，自动生成代码将不能被编译，因此需要使用 include 来包含头文件。如代码清单 8-4 所示，头文件可以是全局的，也可以单独包含在 trusted 和 unstrusted 块中。

```c++
//代码清单8-4 使用include包含头文件的示例

enclave{
	include "stdio.h" //全局的
	include "../../util.h"
	trusted{
		include "foo.h" //只为可信函数
	};
	untrusted{
		include "bar.h" //只为非可信函数
	};
};
```

### 6. 授权访问
默认情况下、ECALL 函数不可被任何不可信函数调用，如需被不可信函数直接调用、需要使用关键词 public 来修饰。需要注意的是，一个 Enclave 中必须有一个 public ECALL 函数，否则无法启动。
为了保证 OCALL 函数可以调用 ECALL 函数，我们必须通过 allow 关键字来指定。pubic 或者 private 的 ECALL 函数都可以使用 allow 关键字来指定。在代码清单8-5中，不可信代码被授予了对 ECALL 函数不同的访问权限。下表列出了相应的授权精况。

```c++
//代码清单8-5 ECALL和OCALL函数授权访问的示例

enclave{
	trusted{
	  pubiic void ciear_secret () ;
	  public void get_secret([out] secret_t* secret);
	  void set_secret([in] secret_t* secret) };
	  };
	untrusted{
	  void replace_secret([in] secret_t* new_secret, [out] secret_t* old_secret)
						  allow (set_secret, clear_secret);

	};
};
```

| ECALL        | 是否可作为 root ECALL 被调用 | 是否可被 replace_secret 调用 |
| ------------ | ---------------------------- | ---------------------------- |
| clear_secret | Y                            | Y                            |
|        get_secret     | Y                            | N                            |
|    set_secret          |               N               |             Y                 |

### 7. 宏定义和条件编译
EDL 支持宏定义和条件编译指令。如代码清单 8-6 所示，开发者可以通过定义简单的宏和条件编译指令来方便地移除调试和测试功能。

```c++
//代码清单8-6 EDL中使用宏定义的示例

#define SGX_DEBUG
enclave{
    trusted {
        /* define ECALLs here. */
    };

    untrusted {
       #ifdef SGX_DEBUG
       void print([in,string] const char * str*);
       #endif 
    };
};
```

作为演示项目，这里设计由 Enclave 提供 5 个接口（分别是 cryplo_init,crypto_seal_keys、crypto_sign、crypto_verify 和 crypto_close），并且由非可信应用程序提供 crypto_read_data 和 crypto_write_data 两个接口，以便 Enclave 读写文件。如代码清单 8-7 所示。

```c++
//代码清单8-7 CryptoEnclave项目中的EDL文件

enclave {
    from "sgx_tstdc.edl" import *;

    trusted {
        /* define ECALLs here. */
        public int crypto_init([in, string] const char* sealed_data_file);
        public int crypto_seal_keys([in, string] const char* sealed_data_file);
        public int crypto_sign([in, string] const char* message, 
                [out, size=sig_len] void* signature, size_t sig_len);
        public int crypto_verify([in, string] const char* message, 
                [in, size=sig_len] void* signature, size_t sig_len);
        public int crypto_close();
    };

    untrusted {
        /* define OCALLs here. */
        void crypto_write_data([in, string] const char* file_name, 
                [in, size=len] const unsigned char* p_data, size_t len);
        void crypto_read_data([in, string] const char* file_name, 
                [out] unsigned char** pp_data, [out] size_t* len);
    };
};
```

## 4. 编写 ECALL 函数
编写 ECALL 函数可以说是实现 SGX 应用程序可信部分最主要的环节了。基于 SGX SDK 和 Visual Studio 构建 Enclave 时，Enclave 函数只能使用 C 和 C++ 编写。不同于普通应用程序，Enclave 程序会被放在 Enclave Page 中、与其他内存隔离，无法链接动态链接库来实现传统应用所拥有的各种丰富的功能、Enclave 程序只能链接静态链接库，也就是将需要用到的静态链接库两数详放到工 Enclave 内存中。因此，静态链接库的丰富程度决定了 Enclave 程序开发的便利程度。

为了尽可能使 Enclave 程序开发便利、Intel SGX SDK 和 PSW 提供了 C 和 C++ 运接。静态接库一旦出观安全间题、就会直接影响 Enclave 程序的安全，因此 Enclave 使用STL(Standard Template Library)的特殊版本、可信密码库等源码用于静态链差序所能使用的库两数需要经过安全审计。这也是一些不安全的库函数被剔除或者被髓机函数，新以被剔除了、Intel 为此提供了 sgx_read_rand 来生成随机数。当然，用户重新实现的原因。比如、Enclave 不支持 C/C++标准库里的 rand、srand，因为它们是伪可以使用其他的可信库、但是要遵循内部 Enclave 函数的编写规范。总而言之，提供的可信库函数既需要满足便利性，也需要满足安全性。

在演示项目中、需要编辑 CryptoEnclave.cpp，创建并实现已经在 EDL 中定义的 ECALL 函数: crypto_init、crypto_seal_keys、crypto_sign、crypto_verify 和 crypto_close。

### 1.  crypto_init
在 crypto_init 函数中需要初始化签名、验签函数所需要用到的所有资源。如代码清单 8-8 所示，它接收一个可选的文件名参数，如果指定了文件名，则通过 OCALL 调用 crypto_read_data 函数从磁盘加载经 SGX 密封过的密钥文件，并解封数据到 Enclave 内存。解封过程中使用的缓冲区必须位于 Enclave 可信内存，否则解封失败。如果传入crypto_init 函数的参数为 nul，调用 SGX 的库函数 sgx_ecc 256_create_key_pair 生成一个新的密钥对。

```c++
//代码清单8-8 crypto_init的代码片段

//初始化ECDSA上下文，如果参数不为null，则从磁盘加载密钥文件，否则生成一个新的密钥对
int crypto_init(const char* sealed_data_file_name) {
    sgx_status_t ret = SGX_ERROR_INVALID_PARAMETER;
    crypto_sealed_data_t* unsealed_data = NULL;
    sgx_sealed_data_t* enc_data = NULL;
    size_t enc_data_size;
    uint32_t dec_size = 0;
    ret = sgx_ecc256_open_context(&ctx);
    if (ret != SGX_SUCCESS)
        goto error;
    if (sealed_data_file_name != NULL) {
        //OCALL:从磁盘加载密钥文件
        ret = crypto_read_data(sealed_data_file_name, 
            (unsigned char**)&enc_data, &enc_data_size);
        if (ret != SGX_SUCCESS)
            goto error;
        dec_size = sgx_get_encrypt_txt_len(enc_data);
        if (dec_size != 0) {
            unsealed_data = (crypto_sealed_data_t*)malloc(dec_size);
            sgx_sealed_data_t* tmp = (sgx_sealed_data_t*)malloc(enc_data_size);
            //将数据拷贝到可信Enclave内存
            memcpy(tmp, enc_data, enc_data_size);
            //解封密钥
            ret = sgx_unseal_data(tmp, NULL, NULL, (uint8_t*)unsealed_data, &dec_size);
            if (ret != SGX_SUCCESS)
                goto error;
            p_private = unsealed_data->p_private;
            p_public = unsealed_data->p_public;
        }
    }
    else
        //生成一个新的密钥对
        ret = sgx_ecc256_create_key_pair(&p_private, &p_public, ctx);

error:
    if (unsealed_data != NULL)
        free(unsealed_data);
    return ret;
}
```

### 2. crypto_seal_keys
crypto_seal_keys 函数主要用于将密钥对使用 SGX 提供的数据密封功能(Data Sealing)密封，之后保存到磁盘。如代码清单 8-9 所示，为了防止密钥泄露，首先调用 sgx_cale_sealed_data_size 函数计算需要密封的数据的大小，然后创建对应的缓冲区。
再使用 sgx_seal_data_ex 函数将数据加密，之后保存到缓冲区，最后通过 OCALL 调用crypto_write_data 将缓冲区中内容写到磁盘。

```c++
//代码清单8-9  crypto_seal_keys的代码片段

//将密钥对密封保存到磁盘
int crypto_seal_keys(const char* sealed_data_file_name) {
    sgx_status_t ret = SGX_ERROR_INVALID_PARAMETER;
    sgx_sealed_data_t* sealed_data = NULL;
    uint32_t sealed_size = 0;
    crypto_sealed_data_t data;
    data.p_private = p_private;
    data.p_public = p_public;
    size_t data_size = sizeof(data);
    sealed_size = sgx_calc_sealed_data_size(NULL, data_size);
    if (sealed_size != 0){
        sealed_data = (sgx_sealed_data_t*)malloc(sealed_size);
        sgx_attributes_t attribute_mask;
        attribute_mask.flags = SGX_FLAGS_INITTED | SGX_FLAGS_DEBUG;
        attribute_mask.xfrm = 0;
        ret = sgx_seal_data_ex(SGX_KEYPOLICY_MRSIGNER, attribute_mask, 0xF0000000, 
            NULL, NULL, data_size, (uint8_t*)&data, sealed_size, sealed_data);
        if (ret == SGX_SUCCESS)
            ret = crypto_write_data(sealed_data_file_name, (unsigned char*)sealed_data, sealed_size);
        else
            free(sealed_data);
    }
    return ret;
}
```

SGX 提供了两种密封策略（sgx_seal_data_ex 函数的第一个参数就是用来设置密封策略的）：MRENCLAVE 和 MRSIGNER。
MRENCLAVE 策略将生成该 Enclave 独有的密钥，其值为 SHA 256 的摘要结果。SHA 256 的内容包括从 Enclave 构建开始到初始化完成之间的活动记录日志。不同的 Enclave,MRENCLAVE 值不同，即使用 MRENCLAVE 策略时，只有同一台电脑的同一个 Enclave 可以解封数据。

MRSIGNER 策略则基于 Enclave 密封授权方的密钥来生成一个密钥，这也使得一个 Enclave 密封的数据可以被另一个 Enclave 来解封（只要在同一台电脑上并且具有相同的密封授权方的密钥即可）.MRSIGNER 可以允许旧版本应用程序密封的数据被新版本应用程序或者其他版本的应用程序解封。也可以使用这种方法在不同的应用程序的不同的 Enclave 中共享数据（只要在同一台电脑上）。

Debug 模式下构建的 Enclave 无法解封 Release 模式下构建的 Enclave 密封的数据，反之亦然。这是为了防止 Intel SGX 调试器在调试 Debug 模式的 Enclave 时泄露 Release 模式下 Enclave 密封的数据。另外，Enclave 不会检查非可信应用程序的真实性，任何人、任何程序都可以加载你的 Enclave，并且按照他们希望的顺序执行 ECALL。因此，Enclave 的 API 不能因为数据密封和解封而泄露机密或者校予不该授予的权限。

### 3. crypto_sign
crypto_sign 函数负责对消息进行签名并将签名后的文件保存到磁盘。如代码清单 8-10 所示，签名使用 SDK 提供的 sgx_ecdsa_sign 函数，并通过 OCALL 调用 crypto_write_data 函数将签名写到磁盘。

```c++
//代码清单8-10  crypto_sign的代码片段

//对消息进行签名，签名文件保存到磁盘
int crypto_sign(const char* message, void* signature, size_t sig_len) {
    sgx_status_t ret = SGX_ERROR_INVALID_PARAMETER;
    const size_t MAX_MESSAGE_LENGTH = 255;
    char signature_file_name[MAX_MESSAGE_LENGTH];
    snprintf(signature_file_name, MAX_MESSAGE_LENGTH, "%s.sig", message);
    ret = sgx_ecdsa_sign((uint8_t*)message, strnlen(message, MAX_MESSAGE_LENGTH), &p_private, (sgx_ec256_signature_t*)signature, ctx);
    if (ret == SGX_SUCCESS)
        ret = crypto_write_data(signature_file_name, (unsigned char*)signature, sizeof(sgx_ec256_signature_t));
    return ret;
}
```

### 4. crypto_verify
crypto_verify 函数负责对消息进行验签。如代码清单 8-11 所示，验签使用 SDK 提供的 sgx_ecdsa_verify 函数。
```c++
//代码清单8-11  crypto__verify的代码片段

//验证消息签名，验证通过返回SGX_EC_VALID，验证失败返回SGX_EC_INVALID_SIGNATURE
int crypto_verify(const char* message, void* signature, size_t sig_len) {
    const size_t MAX_MESSAGE_LENGTH = 255;
    uint8_t res;
    sgx_ec256_signature_t* sig = (sgx_ec256_signature_t*)signature;
    sgx_ecdsa_verify((uint8_t*)message, strnlen(message, MAX_MESSAGE_LENGTH), &p_public, sig, &res, ctx);
    return res;
}
```

### 5. crypto_close
crypto_close 函数最简单，负责清理加密相关的上下文。如代码清单&-12 所示，调用 SDK 提供的 sgx_ecc 256_close_context 函数清理即可。

```c++
//代码清单8-11  crypto__close的代码片段

//关闭清理ECDSA上下文
int crypto_close() {
    sgx_status_t ret = sgx_ecc256_close_context(ctx);
    return ret;
}
```

## 5. 创建非可信应用程序项目并导入 EDL 文件
在 Visual Studio 解决方案资源管理器中、右击“解决方案”，点击“添加” -“新建项目”，创建一个控制台应用项目 CryptoApp. 
创建成功后，右击该项目，依次点击 Intel@ SGX Configuration - Import Enclave 就可以看到等赛口。之后，确认 CryptoEnclave.edl 被选中，点击 Apply 即可导入。
导入完成后，就可以在项目中看到 Visual Studio 自动创建了两个文件：Crypto-Enclave_u.c 和 CryptoEnclave_u.h（这两个文件包含 Untrusted Proxy 和 Untrusted Bridge）。

演示项目的可信都分（即 CryptoEnclave 项目）与非可信部分（即 CryptoApp 项日）的代码都会基于 EDL 文件生成，CryptoApp 私 CrypioEnclaveepp 都通过引用自动生成的代码（包含可信代理，可信桥函数和非可信代理，非可信桥函数）完成可信代码与非可信代码之间的互相调用。
根据 EDL 文件自动生成代码实际上是由 sgx_edger8rexe 工具完成的。该工具可在 SGX SDK 的安装目录下找到。如果导入 EDL 后发现生成的文件中并未生成相关代码，可以在 Visual Studio 的解决方案资源管理器中右键点击 EDL 文件并选择“编译”来完成。

## 6. 编写 OCALL 函数
在演示项目中，可信应用程序需要执行文件读写操作。但是，SGX SDK 并不直接提供这类操作。也就是说，Enclave 内的程序需要使用 Enclave 外的操作累境象进行读写操作。为此，在非可信程序中我们需要实现 EDL 文件中定义的两个 OCALL 函数：crypto_write_data 和 crypto_read_data。如代码清单 8-13 所示，直接在 CryptoApp. cpp 中实现这两个丽数。其实现依赖 C 语言的标准函数库，与普通应用程序实现并无大的区别。


```c++
//代码清单8-13 在非可信程序中实现OCALL函数的代码片段

long readFromFile(const char* file_name, unsigned char** pp_data) {
    FILE* infile;
    errno_t err;
    long fsize = 0;
    err = fopen_s(&infile, file_name, "rb");
    if (err == 0) {
        fseek(infile, 0L, SEEK_END);
        fsize = ftell(infile);
        rewind(infile);
        *pp_data = (unsigned char*)calloc(fsize, sizeof(unsigned char));
        unsigned char* tmp = *pp_data;
        size_t len = fread(tmp, sizeof(unsigned char), fsize, infile);
        fclose(infile);
    } else {
        printf("Failed to open File %s", file_name);
    }
    return fsize;
}

void crypto_write_data(const char* file_name, const unsigned char* p_data, size_t len) {
    FILE* outfile;
    errno_t err;
    err = fopen_s(&outfile, file_name, "wb");
    if (err == 0) {
        for (size_t i = 0; i < len; i++) {
            fputc(p_data[i], outfile);
        }
        fclose(outfile);
    }
    else {
        printf("Failed to open File %s", file_name);
    }
}

void crypto_read_data(const char* file_name, unsigned char** pp_data, size_t* len) {
    *len = readFromFile(file_name, pp_data);
}

```

## 7. 创建和销毁 Enclave
Enclave 源码会被编译成动态链接库，比如 CryptoEnclave 项目会被编译成 CryptoEnclave. dll 文件。为了调用 Enclave，非可信应用程序需要将经 sgx_sign. exe 签名的 DLL 文件加载到受保护的内存中。加载并创建 Enclave 时需要调用 sgx_create_enclave 或者 sgx_create_encalve_ex 函数。代码清单 8-14 是 sgx_create_enclave 接口定义。

```c++
//代码清单8-14 sgx_create_enclave接口定义
sgx_status_t sgx_create_enclave{
const char afiie_name,      //Enclave文件名，比如演示项目中的cryptoEnclave.signed.dll
const int debug,            //是否在Debug模式下创建Enclave，0表示非调试，1表示调试

sgx_launch_token_t *launch_token，//用于初始化Enclave的启动令牌
int *launch_token_updated,       //启动令牌是否有更新，1表示更新，0表示未更新
sgx_enclave_id_t *enclave_id,    //保存创建的Enclave ID或者句柄，不能为空
sgx_misc_attribute_t *misc_attr //可选，保存Enclave属性

};
```

sgx_create_enclave 需要个启动令牌来初始化 Enclave。如果在上次运行过程中保存了这个令牌，其可以被直接取出来使用；否则，需要传递一个全 0 的缓冲区给 sgx create_enclave 来创建一个启动令牌。在 Enclave 成功创建和初始化之后，如果令牌改变了，需要更新并保存。我们可通过参数 launch_token_updated 确认令牌是否有更新，要销毁 Enclave，我们需要调用 sgx_destroy_enclave，并传入创建 Enclave 时返回的 EnclaveID。代码清单 8-15 是创建和销毁 Enclave 的示例。

```c++
//代码清单8-15 创建和销毁Enclave的示例
#include <stdio.h>
#include <tchar.h>
#include "sgx_urts.h"
#define ENCLAVE_FILE _T("CryptoEnclave.signed.dll")
int main(int argc, char* argv[]) {
    sgx_enclave_id_t   eid;
    sgx_status_t       ret = SGX_SUCCESS;
    sgx_launch_token_t token = { 0 };
    int updated = 0;
    ...//使用上面的启动令牌创建Enclave，此处省略尝试读取本地保存的token
	ret = sgx_create_enclave(ENCLAVE_FILE, SGX_DEBUG_FLAG, &token, &updated,
    &eid， NULL);
    if （ret != SGX_SUCCESS） {
	  printf("App: error %#x, failed to create enclave.In", ret);
      return -l;
    }
    …//此处省略token的保存以及ECALL函数的调用
    if (SGX_SUCCESS != sgx_destroy_enclave(eid)) // 卸载enclave
        return -1;
    return 0;
}
```
## 8. 调用 ECALL 函数
前面已经提到，在非可信应用程序中导入 EDL 时，Visual Studio 插件会自动为ECALL 和 OCALL 生成代理函数和桥函数。比如，下面的代码段就是插件自动生成的函数。该函数接收的第一个参数 eid 就是创建 Enclave 时返回的 EnclavelD。生成的代理函数的返回类型 sgx_status_t。如果代理函数成功运行，它将返回 SGX_SUCCESS，否则返回 ErrorCode。

`sgx_status_t crypto_verify (sgx_enclave_idt eid, int* retvel, const char* message, void* signature, size_t sig_len) ;` `

因此，如代码清单 8-16 所示，在 CryptApp.cpp 中就可以直接调用 ECALL 函数来完成相应的功能。

```c++
//代码清单8-16 非可信应用程序调用ECALL函数进行验签的代码片段

#include "CryptoEnclave_u.h"
...
ret = crypto_init(eid, &res, sealed_data_name);
...
switch (mode) {
    case VERIFY:
        if (sig_file_name != NULL) {
            sgx_ec256_signature_t* sig;
            readFromFile(sig_file_name, (unsigned char**)&sig);

            ret = crypto_verify(eid, &res, message, (void*)sig, sizeof(sgx_ec256_signature_t));
			...
            break;
        } else {
            fprintf(stderr, "Signature file not specified");
            goto error;
        }

    case SIGN:
	...
    default:
    ...
    }
	...
    ret = crypto_close(eid, &res);
    error:
	...
    if (SGX_SUCCESS != sgx_destroy_enclave(eid)) // 卸载enclave
        return -1;
    return 0;
}
```

## 9. 编译和调试运行
其中，除 Debug 和 Release 外，其他几个为 Intel SGX SDK 提供的选项。
* Prerelease：对于编译器优化来讲，这个选项同 Release。为了性能测试，Enciave会在 enclave-debug 模式下启动。
* CVE-2020-0551-Load-Prerelease：项目采用 Prerelease 模式构建，同时包含 CVE-2020-0551 漏洞的加载级别（LoadLevel）修复。
* CVE-2020-0551-Load-Release：项目采用 Release 模式构建，同时包含 CVE-2020-0551 漏洞的加载级别修复。
* CVE-2020-0551-CF-Prerelease：项目采用 Prerelease 模式构建，同时包含 CVE-2020-0551 漏洞的控制流级别（ControlFlowLevel）修复。
* CVE-2020-0551-CF-Release：项目采用 Release 模式构建，同时包含CVE-2020-0551 漏洞的控制流级别修复。
* Simulation：在没有编译器优化的情况下构建 Enclave，并且链接的是用于模拟Intel SGX 指令的库。也就是说，这种模式允许 Enclave 运行在任何没有 Intel SGX 的平台上。
