# µAES

**A minimalist ANSI-C compatible code for most of the AES-related algorithms**.

[![GitHub release](https://img.shields.io/static/v1?message=%C2%B5AES&logo=github&labelColor=gray&color=blue&logoColor=white&label=%20)](https://github.com/polfosol/micro-AES) ![C](https://img.shields.io/badge/langauge-C-blue.svg) [![Build Status](https://img.shields.io/badge/v1.2.0-blue)](https://github.com/polfosol/micro-AES/files/10149095/micro_aes-v1.2.0.zip) [![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)

This library is a highly flexible and portable implementation of different AES encryption schemes and block cipher modes.

## Features

* $\textrm{\textbf{Comprehensive}}$ — supports all standard AES key sizes (128, 192 and 256 bits) along with almost every block-cipher mode.

  All popular (and some unpopular) block ciphering modes of the AES are implemented in this library, such as [**_ECB_**, **_CBC_**, **_CFB_**, **_OFB_**, **_CTR_**](https://csrc.nist.gov/publications/detail/sp/800-38a/final), [**_GCM_**](https://csrc.nist.gov/publications/detail/sp/800-38d/final), [**_CCM_**](https://csrc.nist.gov/publications/detail/sp/800-38c/final), [**_XTS_**](https://csrc.nist.gov/publications/detail/sp/800-38e/final), [**_OCB_**](https://www.rfc-editor.org/rfc/rfc7253.html), [**_EAX_**](https://en.wikipedia.org/wiki/EAX_mode), [**_KW_** (**_KWA_**)](https://csrc.nist.gov/publications/detail/sp/800-38f/final), [**_SIV_**](https://www.rfc-editor.org/rfc/rfc5297.html), [**_GCM-SIV_**](https://www.rfc-editor.org/rfc/rfc8452.html), [**_FPE_**](https://csrc.nist.gov/publications/detail/sp/800-38g/final), and furthermore, authentication APIs for [**_CMAC_**](https://csrc.nist.gov/publications/detail/sp/800-38b/final) and [**_Poly1305-AES_**](https://cr.yp.to/mac.html).

* $\textrm{\textbf{All in one}}$ — the whole implementation code is in a single C file with no external dependencies.

* $\textrm{\textbf{Clear and readable code}}$ — hopefully, the code is written in a layman-friendly way with lots of comments to clarify its purpose. Also the code styling is a bit different, and IMHO more eye-catching, than what you might see in other implementations.

* $\textrm{\textbf{Flexible}}$ — many features of µAES are controllable by macros, so that you can just pick up what you need and disable the unnecessary parts. These macros are defined in the header file `micro_aes.h` and comments are added for each of them to explain what they represent. *Please read those comments carefully before using the code*.

* $\textrm{\textbf{Lightweight}}$ — the API has very little memory footprint and compiled code size. In my own tests, the amount of RAM used by the functions didn't exceed a few hundred bytes in most extreme cases. Moreover, the ROM space of µAES is optimized as much as possible. For example if you disable all other macros and just stick with the GCM, the compiled code size will be around **3KB** with `gcc -Os` on x86 machine for either AES-128-GCM or AES-256-GCM.

* $\textrm{\textbf{Fast}}$ — the encryption or decryption speed is fairly high, especially when there is no authentication. Since code simplicity and minimizing memory usage was a top priority, some functions may not look so efficient speed-wise. But it is worth noting that faster methods are hardly portable or easy to understand. So it's no surprise that paralellization or advanced CPU optimizations are not a feature of µAES —which will affect its overall speed.

  As a side note, speed is not always a blessing in cryptography and sometimes slower codes turn out to be more secure. One must be wary of those speedups that make the code more susceptible to [timing attacks](https://en.wikipedia.org/wiki/Timing_attack).

* $\textrm{\textbf{Portable}}$ — µAES is fully compliant with the ANSI-C or C89 standard which, combined with its small size and independence from external libraries, makes it a competent candidate for embedded systems and mini applications.

  You can even compile it with [Tiny C Compiler](https://bellard.org/tcc/):

  ```
  tcc -c main.c      -o main.o
  tcc -c micro_aes.c -o micro_aes.o
  tcc -o micro_aes.exe  main.o micro_aes.o
  ```
## Examples
See the `main.c` file which has some example codes illustrating how to use the API functions, along with test vectors.

## Remarks

* First, please keep in mind that most security experts strongly warn *against* implementing your own version of AES—or other ciphering algorithms; AND THEY ARE ABSOLUTELY RIGHT!

  Everyone who is becoming familiar with cryptography, should first sign [Jeff Moser's](https://www.moserware.com/2009/09/stick-figure-guide-to-advanced.html) so-called "Foot Shooting Prevention Agreement". To save you a click and scroll, I have put a copy of it below (but it is recommended to follow the link and read that article if you haven't).

  With that in mind, I shall say that the main purpose of developing µAES was purely educational. I learned a lot during writing these codes and I hope that somebody, some day, would gain a bit of knowledge from it.

* For the sake of simplicity, it is often assumed that the input parameters of the functions are well defined, and the user knows what they're doing. As a result, a bunch of error checks are just skipped. Obviously, this is a naive and sometimes dangerous assumption. One must be aware that in a serious application, anything can be fed into the functions and they must take all the necessary precautions for erroneous parameters.

* Part of µAES is palpably influenced by [kokke's tiny-AES](https://github.com/kokke/tiny-AES-c) library, but I have made some modifications to make it smaller and more efficient. I shall give kudos to their great effort which paved the way for many other branches.

<p align="center">
  <img src="https://i.stack.imgur.com/SoY7x.png" alt="The foot-shooting prevention agreement taken from Jeff Moser's blog"/>
</p>

---

All the contents of this repository (except the ones that I didn't write!) are subject to the terms of Apache 2.0 license.

Copyright © 2022 - polfosol

$In$ $sorrowful$ $memory$ $of$ [**_Mahsa  Amini_**](https://en.wikipedia.org/wiki/Death_of_Mahsa_Amini) :black_heart:
