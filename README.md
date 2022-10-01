
# µAES

A minimalist ANSI-C compatible code for most of the AES-related algorithms.

This library is a highly flexible, all-in-one implementation of different AES encryption schemes and block ciphers modes. Before you continue, please keep in mind that, most security experts strongly warn *against* implementing your own version of AES—or other ciphering algorithms; AND THEY ARE ABSOLUTELY RIGHT!

Everyone who is becoming familiar with cryptography, should first sign [Jeff Moser's](https://www.moserware.com/2009/09/stick-figure-guide-to-advanced.html) so-called "Foot Shooting Prevention Agreement". I have put a copy of it at the bottom of this page.

With that in mind, I shall say that the main purpose of developing µAES was purely educational. I learned a lot during writing these codes and I hope that somebody, some day, would gain a bit of knowledge from it.

## Features

* **Comprehensive —** supports any form of the AES standard with all different key sizes, i.e. you can use AES-128 or AES-192 or AES-256 simply by setting a macro.
* **All in one —** all popular (and some unpopular) blocks ciphering modes of the AES are implemented into a single file; such as **_ECB_**, **_CBC_**, **_CFB_**, **_OFB_**, **_CTR_**, **_XTS_**, **_KW_** / **_KWA_**, FPE, **_GCM_**, **_CCM_**, **_OCB_**, **_EAX_**, **_SIV_**, and GCM-SIV.
* **Clear and readable code —** hopefully, the code is written in a layman-friendly way. Lots of comments are added along the way to make its purpose more understandable. Also the code styling is a bit different, and IMO more eye-catching, than what you might see in other implementations.
* **Flexible —** many features of µAES are controllable by macros, so that you can just pick up what you need and disable the unnecessary parts. These macros are defined in the header file `micro_aes.h` and comments are added for each of them to explain what they represent. *Please read those comments carefully before using the code*.
* **Lightweight —** the API has very little memory footprint and compiled code size. In my own tests and benchmarks, the amount of RAM used by the functions didn't exceed a few hundred bytes in most extreme cases. I might update this repo later with some of those benchmarks, and you are also cheerfully welcome to run yours.

  Furthermore, the ROM space of µAES is optimized as much as possible. For example, if you disable all other macros and just stick with the GCM, the compiled code size will be less than 3.5KB on an x86 machine for either AES-128-GCM or AES-256-GCM.
* **Fast —** the encryption or decryption speed is often an order of magnitude higher than some .net based implementations and even C++ libraries. Since code simplicity and portability was a main concern, paralellization or advanced CPU optimizations are not a feature of µAES, which might affect its overall speed.

  Anyway, speed is not always a blessing in cryptography and even sometimes slower codes turn out to be more secure. One must be wary of those speedups that make the code more susceptible to [timing attacks](https://en.wikipedia.org/wiki/Timing_attack).
* **Portable —** µAES is all-in-one with no dependencies on any other library. It is fully compatible with ANSI-C or C89 standard which, combined with its small size, makes it a competent candidate for embedded systems and mini applications.

  You can even compile it with [Tiny C Compiler](https://bellard.org/tcc/):

    ```
    tcc -c main.c      -o main.o
    tcc -c micro_aes.c -o micro_aes.o
    tcc -o micro_aes.exe  main.o micro_aes.o
    ```

## Remarks

For the sake of simplicity, it is assumed that the input parameters of the functions are well defined, and the user knows what they're doing. As a result, many error checks are just skipped. Obviously, this is a very naive and sometimes dangerous assumption. One must be aware that in a serious application, anything can be fed into the functions and they must take all the necessary precautions for erroneous parameters.

µAES is heavily influenced by [kokke's tiny-AES](https://github.com/kokke/tiny-AES-c) library, but I have made some modifications which makes it a bit smaller and faster. I shall give kudos to their great effort which paved the way for many other branches.

All the contents of this repository (except the ones that I didn't write!) are subject to the terms of Apache 2.0 license.

Copyright © 2022 - polfosol

![The foot-shooting prevention agreement taken from Jeff Moser's blog](https://i.stack.imgur.com/SoY7x.png)
