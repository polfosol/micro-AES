# **µAES**

**A minimalist ANSI-C compatible API for the AES encryption and block cipher modes**.

[![this](https://img.shields.io/badge/%C2%B5AES-white.png?logo=data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAACAAAAAgCAYAAABzenr0AAAFGklEQVR42r1XA5RjSxD9Wtu2bWX2e23btm3btm17Nxpmx8zYiK3XLzO/6vz0nuxb7yQ759xJ0l1V93Z1tX762r+cnJyCFoulJnxWART5Cvu8n+n+atLShJBlgCCi1WrtsbEpbHx8CnzXQZsUsAtEVef6sSzb12w1m6FfAXgIv/tgO8MwF+C3HuAL2Avxy3ySHIynEr1eyW7dKrB37ChlW7fOBuRQ2D084sjcuXwik8mA4AAEy099IbhXlVlV/POMzqPusb2HAAltNlsjaZo0Fdp0xSYVi3wc+DgEOCZ9bNS/QMc5wucHs+3apSLZZ9GmjZ5cveoDJBLwLQm+zcOTwxN/G/VbNiBnzvk5KGAFiDzRbWs3AbYBbCmKlEywr8zlx/QdJvfvSyA4gwRfiWx240Yk8gEB5ztt7kSJTHKdXA6jb6A1apUweg22N17S2AtsH3yMfCATEhIDAU1cEjuPF0tGjhSSceP49n/+CYE2O8fGjsJ1Zp2JErVZ1UYEgq4B5q25uUaEbQhMPwjo9kHqoTGcdOoU+F7gtm0zyNOnflh0IPAQFh6OlISERENtRL1n2727ZO2NtWJKJIwQRoHtn4AonHdsKzKhSDTEiUW+9wSgIfH2DuPMr46Ni0uCvgVcB6x0VqPJYni8eGpP9u8XlZteLgiJik4oiuRhaPcs+FkYFbXo0iIhtC/CGFwBe8iMGQJnATiv2P6ZlTKdvHz5LmMmiV84kLBIVGF6hUDozzKajRn4nQp44P8A0/8CBpSHK+CJvVOnIOfCIqmpGWBY6TP7xG/Eas2A1ZKFPno/LxyplZLlH5s/Jf+Y/Jn0NwLqQ2+wGPTgW4wrQGz/448op/RroS3zI7xcv5dQlMHoQ+bP548/Oh5XgJ0S4pRg0RUcVzABfzdf1lwMPne4IykGjTFY6c7zD20qwLYvIAKLj64Ext8/qvKMyv604KA/C7DLxtiU/HB+ZKIsEX//4UxeGBqi2ePHxbipOE0Bw/bv7/01AD+5Q7QxPjYkDsgJClhxbYUIC5hOF9RES/jN4xbSHPbECTEGyDXGjRMO3DuQ75hrncagUQBxiS/N4Wpa/bmFOdA/Kt/ofFko4M+NfwphCZ5Gjh8igPz9d/DeJ3u9kRyQHZAQEA/ZbfXjBJw/74UVT/cAPAExvisFMOzAgV7s8OHcYsXtWuEv9Y6iJ+CBpwd8IP1jXSqAPH7sj2se0nqdjYjA5Wp51zdvHt9jnYfQsflkmS1mPGoLuE5Au3YpMKI4CPqrw+cZ6dFDQjcsVWxEfJ5ReQwoYPC+wXzo34l2LhMAJCpiMOC2XN7h85bufriEeWt5QiQHkISshAyr1VrLtQIAZM0aPJg2OE7ChJTU2DTy4IHEpFKo6dYL6U+HKUqksV1bhKtWYWqXQxYKAYkJDxrcanc92uWF5Ihpp6bxoe+yWwSQmzd9YeQD8HbjG+sb3XJFSzGS0ttPwfEF4+HqlQoCy7pFgF0qjYe5rYPnBpIhqRPo5XM5xnSHAAuc+wxeQOC+z+ClkiPAqNAp5Dh69wiAjQangGRmKrpv7y4oMblEhLOAdqvb4eXzEsZziwAKMnq06Ib3Nf+qs6u+LTu1bDAV4CX1wnPfw+0CEHgTZqOjEyvP+v/SUWZKGbzjBX/3+w8rm0gkEfQt8DUgly550zo4zT8twWfc9/LTLOxjMzOziL9/5NeAzcjAa5UyWZEsg88AfBe64iVcAp/fX4ka+E4AlAH8lhve/wC9phuOb7e8lwAAAABJRU5ErkJggg==)](../../ "µAES")
![C](https://img.shields.io/badge/langauge-C-blue.svg)
[![version](https://img.shields.io/badge/version-1.11.0-blue)](../../../../user-attachments/files/22698833/micro_aes-v1.11.0.zip "µAES-v1.11.0.zip")
[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)

This is a highly flexible, small and portable implementation of most of the AES related algorithms.

## Features

* <font size="4">Comprehensive</font> — supports all standard AES key sizes (128, 192 and 256 bits) along with almost every block-cipher mode.

  All popular (and some unpopular) block ciphering modes of the AES are implemented in this library, such as
[**_ECB_**, **_CBC_**, **_CFB_**, **_OFB_**, **_CTR_**](https://csrc.nist.gov/publications/detail/sp/800-38a/final "Described in NIST SP 800-38A"),
[**_GCM_**](https://csrc.nist.gov/publications/detail/sp/800-38d/final "NIST SP 800-38D"),
[**_CCM_**](https://csrc.nist.gov/publications/detail/sp/800-38c/final "NIST SP 800-38C"),
[**_XTS_**](https://csrc.nist.gov/publications/detail/sp/800-38e/final "NIST SP 800-38E"),
[**_KW_**](https://csrc.nist.gov/publications/detail/sp/800-38f/final "NIST SP 800-38F")
[(_KWA_)](https://www.rfc-editor.org/rfc/rfc3394 "RFC-3394"),
[**_OCB_**](https://www.rfc-editor.org/rfc/rfc7253.html "RFC-7253"),
[**_EAX_**](../../files/10318260/eax.pdf "Bellare-Rogaway-Wagner paper. For more info, see wikipedia.")
/[**_EAX'_**](../../files/10318265/eax-prime.pdf "Theoretically broken, but ANSI C12.22 has not withdrawn it yet. so here we go..."),
[**_SIV_**](../../files/10318348/siv.pdf "Also described in the RFC-5297"),
[**_GCM-SIV_**](https://www.rfc-editor.org/rfc/rfc8452.html "RFC-8452"),
[**_FPE_** (**_FF1_** /**_FF3-1_**)](https://csrc.nist.gov/publications/detail/sp/800-38g/final "NIST SP 800-38G"),
and furthermore, authentication APIs for
[**_CMAC_**](https://csrc.nist.gov/publications/detail/sp/800-38b/final "NIST SP 800-38B") and
[**_Poly1305-AES_**](../../files/10319003/poly1305.pdf "D. J. Bernstein's website: cr.yp.to/mac.html").

* <font size="4">All in one</font> — the whole implementation code is in a single C file with no external dependencies.

* <font size="4">Clear and readable code</font> — written in a layman-friendly way with lots of comments to clarify its purpose. Also the code styling is a bit different, and IMHO more eye-catching, than what you might see in other implementations.

* <font size="4">Flexible</font> — most features are controllable by macros, so that you can just pick up what you need and disable the unnecessary parts. These [macros](micro_aes.h#L544) are defined in the header file and comments are added for each of them to explain what they represent. *Please read [those comments](micro_aes.h#L481) carefully before using the code*.

* <font size="4">Lightweight</font> — the API has very little memory footprint and compiled code size. The amount of RAM used by the functions doesn't exceed a few hundred bytes in most extreme cases. Moreover, the ROM space of µAES is optimized as much as possible.

  For example if you disable all other macros and just stick with the GCM, the compiled code size with `gcc -Os` will be less than **2.5KB** for either _AES-128-GCM_ or _AES-256-GCM_. This can be verified by running:
  ```
  $ arm-none-eabi-gcc      -Os -c micro_aes.c -o arm.o
  $ avr-gcc -mmcu=atmega16 -Os -c micro_aes.c -o avr.o
  ```
  and checking the results with `size` command. See [this page](https://stackoverflow.com/q/31217181/5358284) for more info.
  ```
  $ size arm.o
     text      data     bss     dec     hex filename
     2112         0     176     2288    8f0 arm.o

  $ avr-size avr.o
     text      data     bss     dec     hex filename
     2242         0     176     2418    972 avr.o
  ```

* <font size="4">Portable</font> — µAES is fully compliant with the ANSI-C or C89 standard which, combined with its small size and independence from external libraries, makes it a competent candidate for embedded systems and mini applications.

  You can even [compile it](../../../../user-attachments/files/21704976/TCPROJ.zip "instructions and prerequisites") with a vintage [Borland Turbo C](https://hackaday.com/2023/04/08/revisiting-borland-turbo-c-and-c/) or a teeny [tiny C compiler](https://bellard.org/tcc/):
  ```
  path/to/tcc.exe -c micro_aes.c
  path/to/tcc.exe micro_aes.c -run main.c
  ```

* <font size="4">Fast</font> — the encryption or decryption speed is fairly high, especially when there is no authentication. Since code simplicity and minimizing memory usage was a top priority, some functions may not look so efficient speed-wise; though faster methods are hardly portable or easy to understand. As a result, paralellization or advanced CPU optimizations are not a feature of µAES —which might affect its overall speed.

  For 32-bit CPUs a few tweaks are discussed in [x86 improvements](x86-improvements). It's worth noting that speed is not always a blessing in cryptography and sometimes slower codes turn out to be more secure. One must be wary of those speedups that make the code more susceptible to [timing attacks](https://en.wikipedia.org/wiki/Timing_attack).

## Examples
See the [main C](main.c) file which has some example codes demonstrating how to use the API functions, along with test vectors.
Also check out the [/testvectors](testvectors/README.md) directory.

## Remarks

* First, please keep in mind that most security experts strongly warn *against* implementing your own version of AES—or other ciphering algorithms; AND THEY ARE ABSOLUTELY RIGHT!

  Everyone who is becoming familiar with cryptography, should first sign [Jeff Moser's](https://www.moserware.com/2009/09/stick-figure-guide-to-advanced.html "A stick figure guide to AES") so-called "Foot Shooting Prevention Agreement". It's a great article if you haven't read it yet. But to save you a click and scroll, I put a copy of the contract below.

  With that in mind, I shall say that the main purpose of developing µAES was purely educational. I learned a lot during writing these codes and hope that somebody, some day, would gain a bit of knowledge from it.

* The code is optimized for small embedded systems and 8-bit microcontrollers with limited amount of memory. So for stronger CPUs it is plausible to speed-up the code [by applying some simple changes](x86-improvements). If you are working with an 8-bit microcontroller, it is recommended to take a look at Nigel Jones' rather old article "[Efficient C Code for 8-bit Microcontrollers](https://barrgroup.com/embedded-systems/how-to/efficient-c-code)". It contains some highly useful tips to better program such systems.

* There are some standard encryption algorithms specifically designed for small embedded systems, that minimize the use of computational resources while maintaining a high level of security. The most prominent one is the ASCON cipher suite which recently got [approved by the NIST](https://csrc.nist.gov/Projects/lightweight-cryptography/finalists). **_I have created [another repository](../../../simple-ASCON "Simple ASCON") to implement those algorithms as well_**.

* For the sake of simplicity, it is often assumed that the input parameters of the functions are well defined, and the user knows what they're doing. As a result, a bunch of error checks are just skipped. Obviously, this is a naive and sometimes dangerous assumption. One must be aware that in a serious application, anything can be fed into the functions and they must take all the necessary precautions for erroneous parameters.

* µAES was originally influenced by [kokke's tiny-AES](https://github.com/kokke/tiny-AES-c) library, but I have made a handful of modifications to make it smaller and more efficient.

<p align="center">
  <img src="https://user-images.githubusercontent.com/1939363/221410529-ea6bc2ab-b44c-4a34-a617-4a2ec3d16d0f.png" alt="The foot-shooting prevention agreement taken from Jeff Moser's blog"/>
</p>

---

All the contents of this repository (except the ones that I didn't write!) are subject to the terms of Apache 2.0 license.

![µAES](https://user-images.githubusercontent.com/1939363/223065653-57eb5da3-6826-4939-a4f8-88992731e976.png "µAES")

Copyright © 2022 - polfosol

<font size="3" face="Georgia">_In sorrowful memory of_ [**_Mahsa  Amini_**](https://en.wikipedia.org/wiki/Death_of_Mahsa_Amini "MAY ALL THE DICTATORS ROT IN HELL")</font> :black_heart:
