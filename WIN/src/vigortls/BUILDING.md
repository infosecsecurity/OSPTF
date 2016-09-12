VigorTLS Building Instructions
==============================
------------------------------

Building in a *NIX environment
------------------------------
----
## Requirements
* CMake 2.8.8+
* GCC or Clang
* Perl

----
## Building
	$ mkdir build
	$ cd build
	$ cmake ..
	$ make

------------------------------

Building in a Windows environment
---------------------------------
----
## Requirements
* CMake 2.8.8+
* Visual Studio 2013+ (Might work on older versions [NOT TESTED])
* ActiveState Perl
* Yasm

----
## Building
	Launch VS2013 x86/x64 Native Tools Command Prompt
	$ mkdir build
	$ cd build
	$ cmake -G"NMake Makefiles" ..
	$ nmake -f Makefile
