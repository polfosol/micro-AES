# <img src="https://user-images.githubusercontent.com/1939363/221410382-9c26e5ae-6115-4fb4-8cb0-cb40b771d3ec.png"/> µAES

**A minimalist ANSI-C compatible code for the AES encryption and block cipher modes**.

[![here](https://img.shields.io/badge/%C2%B5AES-white.svg?logo=data:image/svg+xml;base64,PD94bWwgdmVyc2lvbj0iMS4wIiBlbmNvZGluZz0iVVRGLTgiPz4KPCFET0NUWVBFIHN2ZyBQVUJMSUMgIi0vL1czQy8vRFREIFNWRyAxLjEvL0VOIiAiaHR0cDovL3d3dy53My5vcmcvR3JhcGhpY3MvU1ZHLzEuMS9EVEQvc3ZnMTEuZHRkIj4KPHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHZlcnNpb249IjEuMSIgd2lkdGg9IjQ4cHgiIGhlaWdodD0iNDhweCIgc3R5bGU9InNoYXBlLXJlbmRlcmluZzpnZW9tZXRyaWNQcmVjaXNpb247IHRleHQtcmVuZGVyaW5nOmdlb21ldHJpY1ByZWNpc2lvbjsgaW1hZ2UtcmVuZGVyaW5nOm9wdGltaXplUXVhbGl0eTsgZmlsbC1ydWxlOmV2ZW5vZGQ7IGNsaXAtcnVsZTpldmVub2RkIiB4bWxuczp4bGluaz0iaHR0cDovL3d3dy53My5vcmcvMTk5OS94bGluayI+CjxnPjxwYXRoIHN0eWxlPSJvcGFjaXR5OjAuNjYzIiBmaWxsPSIjZjRlZGViIiBkPSJNIDEyLjUsMy41IEMgMTcuNzAxOSwyLjc1NjE4IDIyLjM2ODYsMy45MjI4NCAyNi41LDdDIDMyLjk2MTMsOC4wMDYyIDM5LjI5NDcsOC4xNzI4NyA0NS41LDcuNUMgNDUuNjYxMSwxMC41Mjc5IDQ0Ljk5NDQsMTMuMzYxMiA0My41LDE2QyA0NS4wMjg4LDE3LjU4MiA0NS41Mjg4LDE5LjQxNTMgNDUsMjEuNUMgNDIuMDAzNSwyMi45MTA2IDM4LjgzNjksMjMuOTEwNiAzNS41LDI0LjVDIDMzLjQ5MywzMC42Nzc2IDMwLjgyNjQsMzYuNTEwOSAyNy41LDQyQyAxOS41Nzg4LDQzLjU2NzUgMTEuNTc4OCw0My45MDA5IDMuNSw0M0MgMi4yMDQxMSwzOS4wOTEzIDEuNTM3NDQsMzQuOTI0NiAxLjUsMzAuNUMgMC42MjIxMzcsMjIuNTk0NCAyLjEyMjE0LDE1LjI2MSA2LDguNUMgNy45NjUxNCw2LjQ0OTY1IDEwLjEzMTgsNC43ODI5OSAxMi41LDMuNSBaIE0gMTYuNSwxMS41IEMgMTguNzIyNSwxMi4xMTQ1IDIwLjM4OTIsMTMuNDQ3OCAyMS41LDE1LjVDIDE4LjUsMTYuODMzMyAxNS41LDE2LjgzMzMgMTIuNSwxNS41QyAxMy41NDg3LDEzLjc4NDQgMTQuODgyLDEyLjQ1MTEgMTYuNSwxMS41IFogTSAxNS41LDI4LjUgQyAxNi4wNzY4LDI3LjIyNjcgMTYuNzQzNSwyNy4yMjY3IDE3LjUsMjguNUMgMTcuMDMwMiwyOS40NjMgMTYuMzYzNSwyOS40NjMgMTUuNSwyOC41IFoiLz48L2c+CjxnPjxwYXRoIHN0eWxlPSJvcGFjaXR5OjEiIGZpbGw9IiNmZjM2MzQiIGQ9Ik0gMTIuNSw1LjUgQyAxOS42NzYyLDQuNDI1MyAyNC42NzYyLDcuMDkxOTYgMjcuNSwxMy41QyAyNi4zODU5LDE3LjQ5MDggMjYuMzg1OSwyMS40OTA4IDI3LjUsMjUuNUMgMjUuODAwOCwyNS4zMzk4IDI0LjEzNDEsMjUuNTA2NSAyMi41LDI2QyAyMi4wMTE2LDI4LjE3NjEgMjEuMDExNiwzMC4wMDk0IDE5LjUsMzEuNUMgMTkuMzQ1OSwzMC4wOTA5IDE5LjE3OTIsMjguNDI0MiAxOSwyNi41QyAxNy42MTI0LDI1LjQ0NjQgMTYuMTEyNCwyNS4yNzk3IDE0LjUsMjZDIDE0Ljc5MTEsMjkuNzU0NiAxNC40NTc4LDMzLjU4OCAxMy41LDM3LjVDIDE3LjMyNDYsMzYuNzg4NyAyMC4zMjQ2LDM3Ljk1NTQgMjIuNSw0MUMgMTYuNSw0MS42NjY3IDEwLjUsNDEuNjY2NyA0LjUsNDFDIDMuMDE5MSwzMS43Nzc2IDMuNTE5MSwyMi42MTA5IDYsMTMuNUMgNy4zMDQ1OSwxMC4wMzg2IDkuNDcxMjUsNy4zNzE5NyAxMi41LDUuNSBaIE0gMTYuNSwxMS41IEMgMTQuODgyLDEyLjQ1MTEgMTMuNTQ4NywxMy43ODQ0IDEyLjUsMTUuNUMgMTUuNSwxNi44MzMzIDE4LjUsMTYuODMzMyAyMS41LDE1LjVDIDIwLjM4OTIsMTMuNDQ3OCAxOC43MjI1LDEyLjExNDUgMTYuNSwxMS41IFogTSAxNS41LDI4LjUgQyAxNi4zNjM1LDI5LjQ2MyAxNy4wMzAyLDI5LjQ2MyAxNy41LDI4LjVDIDE2Ljc0MzUsMjcuMjI2NyAxNi4wNzY4LDI3LjIyNjcgMTUuNSwyOC41IFoiLz48L2c+CjxnPjxwYXRoIHN0eWxlPSJvcGFjaXR5OjEiIGZpbGw9IiMxMTYxMGMiIGQ9Ik0gMjkuNSw5LjUgQyAzMS4xNjY3LDkuNSAzMi44MzMzLDkuNSAzNC41LDkuNUMgMzMuNSwxMi44MzMzIDMyLjUsMTYuMTY2NyAzMS41LDE5LjVDIDMyLjU1MiwxOS42NDk1IDMzLjU1MiwxOS40ODI4IDM0LjUsMTlDIDM2LjkwNjYsMTUuNjQ2NiAzOS40MDY2LDEyLjQ3OTkgNDIsOS41QyA0Mi41LDkuNjY2NjcgNDMsOS44MzMzMyA0My41LDEwQyA0Mi4zNjc3LDEyLjQzMzYgNDEuMzY3NywxNC45MzM2IDQwLjUsMTcuNUMgNDMuMTI2NSwxOS4zNDQgNDIuOTU5OSwyMC42NzczIDQwLDIxLjVDIDM4LjExNzgsMjAuMzk0IDM2LjI4NDQsMjAuMzk0IDM0LjUsMjEuNUMgMzEuNzI0LDI3LjM4NTMgMjkuMjI0LDMzLjM4NTMgMjcsMzkuNUMgMjUuOTg4Nyw0MC4zMzY2IDI0LjgyMjEsNDAuNjcgMjMuNSw0MC41QyAyMy42NDk1LDM5LjQ0OCAyMy40ODI4LDM4LjQ0OCAyMywzNy41QyAyMS41MTM0LDM2Ljg0NDggMjAuMzQ2NywzNS44NDQ4IDE5LjUsMzQuNUMgMjEuNzEzOCwzMy45NTk0IDIzLjg4MDUsMzMuNjI2MSAyNiwzMy41QyAyNi4xNjY3LDMzIDI2LjMzMzMsMzIuNSAyNi41LDMyQyAyNS40OTExLDMwLjgzMTkgMjQuNDkxMSwyOS42NjUyIDIzLjUsMjguNUMgMjkuNTQwNSwyNy4wODg4IDMxLjIwNzIsMjMuNzU1NSAyOC41LDE4LjVDIDI4Ljk2NzIsMTYuNDMxNyAyOS42MzM5LDE0LjQzMTcgMzAuNSwxMi41QyAyOC41NjUsMTEuNzg3IDI4LjIzMTcsMTAuNzg3IDI5LjUsOS41IFoiLz48L2c+CjxnPjxwYXRoIHN0eWxlPSJvcGFjaXR5OjAuNjY1IiBmaWxsPSIjZmZmMmYyIiBkPSJNIDIzLjUsMTguNSBDIDE5LjE2NjcsMTguNSAxNC44MzMzLDE4LjUgMTAuNSwxOC41QyAxMC41LDE3LjE2NjcgMTAuNSwxNS44MzMzIDEwLjUsMTQuNUMgMTMuOTgzLDguMjcxMTQgMTguMTQ5Nyw3LjkzNzggMjMsMTMuNUMgMjMuNDkzNSwxNS4xMzQxIDIzLjY2MDIsMTYuODAwOCAyMy41LDE4LjUgWiBNIDE2LjUsMTEuNSBDIDE0Ljg4MiwxMi40NTExIDEzLjU0ODcsMTMuNzg0NCAxMi41LDE1LjVDIDE1LjUsMTYuODMzMyAxOC41LDE2LjgzMzMgMjEuNSwxNS41QyAyMC4zODkyLDEzLjQ0NzggMTguNzIyNSwxMi4xMTQ1IDE2LjUsMTEuNSBaIi8+PC9nPgo8Zz48cGF0aCBzdHlsZT0ib3BhY2l0eToxIiBmaWxsPSIjZmZhYWE5IiBkPSJNIDEwLjUsMTQuNSBDIDEwLjUsMTUuODMzMyAxMC41LDE3LjE2NjcgMTAuNSwxOC41QyAxNC44MzMzLDE4LjUgMTkuMTY2NywxOC41IDIzLjUsMTguNUMgMTkuMDMsMTkuNDg2MSAxNC4zNjMzLDE5LjgxOTUgOS41LDE5LjVDIDkuMjE1NTIsMTcuNTg1MyA5LjU0ODg1LDE1LjkxODcgMTAuNSwxNC41IFoiLz48L2c+Cjwvc3ZnPgo=)](https://github.com/polfosol/micro-AES "µAES") ![C](https://img.shields.io/badge/langauge-C-blue.svg) [![version](https://img.shields.io/badge/version-1.7.2-blue)](https://github.com/polfosol/micro-AES/files/10833713/micro_aes-v1.7.2.zip "micro_aes-v1.7.2.zip") [![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)

This library is a highly flexible and portable implementation of most of the AES related algorithms.

## Features

* <font size="4">Comprehensive</font> — supports all standard AES key sizes (128, 192 and 256 bits) along with almost every block-cipher mode.

  All popular (and some unpopular) block ciphering modes of the AES are implemented in this library, such as [**_ECB_**, **_CBC_**, **_CFB_**, **_OFB_**, **_CTR_**](https://csrc.nist.gov/publications/detail/sp/800-38a/final "Described in NIST SP 800-38A"), [**_GCM_**](https://csrc.nist.gov/publications/detail/sp/800-38d/final "NIST SP 800-38D"), [**_CCM_**](https://csrc.nist.gov/publications/detail/sp/800-38c/final "NIST SP 800-38C"), [**_XTS_**](https://csrc.nist.gov/publications/detail/sp/800-38e/final "NIST SP 800-38E"), [**_KW_**](https://csrc.nist.gov/publications/detail/sp/800-38f/final "NIST SP 800-38F") [(_KWA_)](https://www.rfc-editor.org/rfc/rfc3394 "RFC-3394"), [**_OCB_**](https://www.rfc-editor.org/rfc/rfc7253.html "RFC-7253"), [**_EAX_**](https://github.com/polfosol/micro-AES/files/10318260/eax.pdf "Bellare-Rogaway-Wagner paper. For more info, see wikipedia.") / [**_EAX'_**](https://github.com/polfosol/micro-AES/files/10318265/eax-prime.pdf "It is theoretically broken and shouldn't be used. The ANSI C12.22 has not withdrawn it yet, so here we go."), [**_SIV_**](https://github.com/polfosol/micro-AES/files/10318348/siv.pdf "You may also refer to the RFC-5297"), [**_GCM-SIV_**](https://www.rfc-editor.org/rfc/rfc8452.html "RFC-8452"), [**_FPE_** (**_FF1_** / **_FF3-1_**)](https://csrc.nist.gov/publications/detail/sp/800-38g/final "NIST SP 800-38G"), and furthermore, authentication APIs for [**_CMAC_**](https://csrc.nist.gov/publications/detail/sp/800-38b/final "NIST SP 800-38B") and [**_Poly1305-AES_**](https://github.com/polfosol/micro-AES/files/10319003/poly1305.pdf "From D. J. Bernstein's website: cr.yp.to/mac.html").

* <font size="4">All in one</font> — the whole implementation code is in a single C file with no external dependencies.

* <font size="4">Clear and readable code</font> — hopefully, the code is written in a layman-friendly way with lots of comments to clarify its purpose. Also the code styling is a bit different, and IMHO more eye-catching, than what you might see in other implementations.

* <font size="4">Flexible</font> — many features of µAES are controllable by macros, so that you can just pick up what you need and disable the unnecessary parts. These macros are defined in the header file `micro_aes.h` and comments are added for each of them to explain what they represent. *Please read those comments carefully before using the code*.

* <font size="4">Lightweight</font> — the API has very little memory footprint and compiled code size. In my own tests, the amount of RAM used by the functions didn't exceed a few hundred bytes in most extreme cases. Moreover, the ROM space of µAES is optimized as much as possible. For example if you disable all other macros and just stick with the GCM, the compiled code size will be around **3KB** with `gcc -Os` on x86 machine for either AES-128-GCM or AES-256-GCM.

* <font size="4">Fast</font> — the encryption or decryption speed is fairly high, especially when there is no authentication. Since code simplicity and minimizing memory usage was a top priority, some functions may not look so efficient speed-wise. But it is worth noting that faster methods are hardly portable or easy to understand. So it's no surprise that paralellization or advanced CPU optimizations are not a feature of µAES —which will affect its overall speed.

  As a side note, speed is not always a blessing in cryptography and sometimes slower codes turn out to be more secure. One must be wary of those speedups that make the code more susceptible to [timing attacks](https://en.wikipedia.org/wiki/Timing_attack).

* <font size="4">Portable</font> — µAES is fully compliant with the ANSI-C or C89 standard which, combined with its small size and independence from external libraries, makes it a competent candidate for embedded systems and mini applications.

  You can even compile it with [Tiny C Compiler](https://bellard.org/tcc/):

  ```
  path/to/tcc.exe -c micro_aes.c
  path/to/tcc.exe micro_aes.c -run main.c
  ```

## Examples
See the `main.c` file which has some example codes demonstrating how to use the API functions, along with test vectors. Also check out the `/testvectors` directory.

## Remarks

* First, please keep in mind that most security experts strongly warn *against* implementing your own version of AES—or other ciphering algorithms; AND THEY ARE ABSOLUTELY RIGHT!

  Everyone who is becoming familiar with cryptography, should first sign [Jeff Moser's](https://www.moserware.com/2009/09/stick-figure-guide-to-advanced.html "A stick figure guide to AES") so-called "Foot Shooting Prevention Agreement". To save you a click and scroll, I have put a copy of it below (but it is recommended to follow the link and read that article if you haven't).

  With that in mind, I shall say that the main purpose of developing µAES was purely educational. I learned a lot during writing these codes and I hope that somebody, some day, would gain a bit of knowledge from it.

* For the sake of simplicity, it is often assumed that the input parameters of the functions are well defined, and the user knows what they're doing. As a result, a bunch of error checks are just skipped. Obviously, this is a naive and sometimes dangerous assumption. One must be aware that in a serious application, anything can be fed into the functions and they must take all the necessary precautions for erroneous parameters.

* Part of µAES is palpably influenced by [kokke's tiny-AES](https://github.com/kokke/tiny-AES-c) library, but I have made some modifications to make it smaller and more efficient. I shall give kudos to their great effort which paved the way for many other branches.

<p align="center">
  <img src="https://user-images.githubusercontent.com/1939363/221410529-ea6bc2ab-b44c-4a34-a617-4a2ec3d16d0f.png" alt="The foot-shooting prevention agreement taken from Jeff Moser's blog"/>
</p>

---

All the contents of this repository (except the ones that I didn't write!) are subject to the terms of Apache 2.0 license.

Copyright © 2022 - polfosol

<font size="3" face="Georgia">_In sorrowful memory of_ [**_Mahsa  Amini_**](https://en.wikipedia.org/wiki/Death_of_Mahsa_Amini "MAY ALL THE DICTATORS ROT IN HELL")</font> :black_heart:
