---
title: "CTF Writeup: “Secure Runner” from SDCTF 2023"
publishDate: 2023-05-08
img: /assets/sdctf-2023/challenge.png
description: While I didn’t have much time to participate in this CTF, I had a goal of solving at least one challenge, a goal that I achieved with a day to spare.
tags: 
    - CTF-writeups
---

In CTFs, “Misc.” challenges are some of my favorite to solve (and write): unbounded by the tropes of a defined category, they offer bits and pieces from many cybersecurity topics, and serve as a reflection of the author’s interests at the time. Secure Runner is one of those challenges: I didn’t feel like it quizzed me on any specific cybersecurity knowledge, instead the challenge felt like an exercise in the detective skills one builds up as they solve more CTF challenges.

## The Prompt

> I made a service where people can upload C code to my server and run it! The best part is that it's completely secure! Try running the number guessing game I made :)
> Connect via `cat program.c - | nc secure-runner.sdc.tf 1337`
> (program.c)[]

Just from reading the description, this sounds like the world’s easiest RCE: we can upload anything and the computer will just run it no questions asked? Let’s do some testing to actually see if this works.

## First Tests

I made (read: adapted from StackOverflow) a simple payload that uses C's system() function to list the contents of the current directory:

``` c
//inertprogram.c
#include <stdio.h>
#include <stdlib.h>


int main( int argc, char *argv[] )
{

  FILE *fp;
  char path[1035];

  /* Open the command for reading. */
  fp = popen("ls", "r");
  if (fp == NULL) {
    printf("Failed to run command\n" );
    exit(1);
  }

  /* Read the output a line at a time - output it. */
  while (fgets(path, sizeof(path), fp) != NULL) {
    printf("%s", path);
  }

  /* close */
  pclose(fp);

  return 0;
}
```

Let's see what happens when we try to upload it to the server.

``` plaintext
❯ cat inertprogram.c - | nc secure-runner.sdc.tf 1337
ERROR: Refusing to run file, invalid checksum (f2cc55a6)!
```

As we can see, the server refuses to run the file: claiming that the checksum of our file is invalid. In fact, uploading anything other than the provided C file gives us the same error. If we want to run some sort of payload, we need to bypass this checksum. Since the invalid checksum is provided to us, we can figure out what algorithm the server is using.

## Checking the Checksum

The first thing I tried was pasting the checksum into an online [hash analyzer](https://www.tunnelsup.com/hash-analyzer/). While it didn’t end up telling me the specific algorithm, it did provide me with some important information: the checksum is a 32-bit hexadecimal value. Simply searching for “32 bit hexadecimal checksum” gives us a convincing result: [CRC-32](https://en.wikipedia.org/wiki/Cyclic_redundancy_check). Running the algorithm on our file, we can see that the checksum is the same as the one given to us.

``` plaintext
❯ crc32 inertprogram.c
f2cc55a6
```

## The Exploit: Forging a CRC-32 Value

CRC-32 (and all other CRC algorithms), is not a cryptographically secure hashing algorithm: it is designed to detect transmission errors in the network, not create unique fingerprints for files. Because of this, we can easily modify our payload so it shares the same checksum as the original program. I used the Python script from [this blogpost](https://www.nayuki.io/page/forcing-a-files-crc-to-any-value) to do so.

The process is pretty simple, we:

1. Find the checksum we want to forge.
2. Find the byte offset (location in the file) we want to inset our "dummy bytes" at. I chose the end of the file, minus the 4 bytes needed for the patch.
3. Run the script.

In the shell, the process looks like this:

``` plaintext
❯ crc32 program.c
38df65f2
❯ stat -f%z inertprogram.c
428
❯ cp inertprogram.c testprogram.c
❯ python3 forcecrc32.py testprogram.c 424 38df65f2
Original CRC-32: F2CC55A6
Computed and wrote patch
New CRC-32 successfully verified
```

Now we have two different files with matching checksums:

``` plaintext
❯ crc32 program.c
38df65f2
❯ crc32 testprogram.c
38df65f2
```

## Testing Our Exploit

However, when we try to upload our program, we run into a new error:

``` plaintext
❯ cat testprogram.c - | nc secure-runner.sdc.tf 1337
ERROR: Compilation failed!
```

When we compile the program locally, the issue becomes clear: our patch overwrites part of our program, and is interpreted by the compiler, which then throws an error.

``` plaintext
❯ gcc testprogram.c
testprogram.c:26:11: error: source file is not valid UTF-8
  return 0<B8>r<U+0017><9A>
          ^
testprogram.c:26:11: error: expected ';' after return statement
  return 0<B8>r<U+0017><9A>
          ^
          ;
testprogram.c:26:14: error: source file is not valid UTF-8
  return 0<B8>r<U+0017><9A>
                       ^
testprogram.c:26:15: error: expected '}'
  return 0<B8>r<U+0017><9A>
                           ^
testprogram.c:6:1: note: to match this '{'
{
^
4 errors generated.
```

Luckily, this can be fixed by adding a comment ot the end of our program, which can be used as a buffer for our patch.

``` plaintext
❯ xxd inertprogram.c
00000000: 2369 6e63 6c75 6465 203c 7374 6469 6f2e  #include <stdio.
00000010: 683e 0a23 696e 636c 7564 6520 3c73 7464  h>.#include <std
00000020: 6c69 622e 683e 0a0a 0a69 6e74 206d 6169  lib.h>...int mai
00000030: 6e28 2069 6e74 2061 7267 632c 2063 6861  n( int argc, cha
00000040: 7220 2a61 7267 765b 5d20 290a 7b0a 0a20  r *argv[] ).{.. 
00000050: 2046 494c 4520 2a66 703b 0a20 2063 6861   FILE *fp;.  cha
00000060: 7220 7061 7468 5b31 3033 355d 3b0a 0a20  r path[1035];.. 
00000070: 202f 2a20 4f70 656e 2074 6865 2063 6f6d   /* Open the com
00000080: 6d61 6e64 2066 6f72 2072 6561 6469 6e67  mand for reading
00000090: 2e20 2a2f 0a20 2066 7020 3d20 706f 7065  . */.  fp = pope
000000a0: 6e28 226c 7322 2c20 2272 2229 3b0a 2020  n("ls", "r");.  
000000b0: 6966 2028 6670 203d 3d20 4e55 4c4c 2920  if (fp == NULL) 
000000c0: 7b0a 2020 2020 7072 696e 7466 2822 4661  {.    printf("Fa
000000d0: 696c 6564 2074 6f20 7275 6e20 636f 6d6d  iled to run comm
000000e0: 616e 645c 6e22 2029 3b0a 2020 2020 6578  and\n" );.    ex
000000f0: 6974 2831 293b 0a20 207d 0a0a 2020 2f2a  it(1);.  }..  /*
00000100: 2052 6561 6420 7468 6520 6f75 7470 7574   Read the output
00000110: 2061 206c 696e 6520 6174 2061 2074 696d   a line at a tim
00000120: 6520 2d20 6f75 7470 7574 2069 742e 202a  e - output it. *
00000130: 2f0a 2020 7768 696c 6520 2866 6765 7473  /.  while (fgets
00000140: 2870 6174 682c 2073 697a 656f 6628 7061  (path, sizeof(pa
00000150: 7468 292c 2066 7029 2021 3d20 4e55 4c4c  th), fp) != NULL
00000160: 2920 7b0a 2020 2020 7072 696e 7466 2822  ) {.    printf("
00000170: 2573 222c 2070 6174 6829 3b0a 2020 7d0a  %s", path);.  }.
00000180: 0a20 202f 2a20 636c 6f73 6520 2a2f 0a20  .  /* close */. 
00000190: 2070 636c 6f73 6528 6670 293b 0a0a 2020   pclose(fp);..  
000001a0: 7265 7475 726e 2030 3b0a 7d0a 2f2f 3030  return 0;.}.//00
000001b0: 3030 3030 3030 3030 3030 3030 3030 3030  0000000000000000 <--- Part of our comment
000001c0: 0a                                       .
❯ cp inertprogram.c testprogram.c
❯ python3 forcecrc32.py testprogram.c 432 38df65f2
Original CRC-32: F329EFA1
Computed and wrote patch
New CRC-32 successfully verified
```

## It Works!

After applying the new patch, we can upload our code and see the contents of the directory.

``` plaintext
❯ cat testprogram.c - | nc secure-runner.sdc.tf 1337
build
flag.txt
node_modules
package.json
```

Actually getting the flag is now just a simple question of reading `flag.txt` to stdout.
