**Godivert**

Forked from [https://github.com/williamfhe/godivert](https://github.com/williamfhe/godivert) with some changes made as needed.

This is a Windows executable which wraps kernel driver, **WinDriver.sys** and a companion user mode **WinDriver.dll** which allows to control this driver.

In addition, Godivert uses **TCPHelper.dll** which is necessary for its proper collaboration with Ghostery Desktop Proxy proxy

The code is written in golang, which wraps and makes use of binary components, but may be reimplemented in C/C++.

On 32-bit platform, obviously, all binaries should be 32-bit.

**Proxydivert/main.go**

This is where the code which connects diverted traffic with proxy lives.

We create separate hooks for HTTP and HTTPS traffic and run them on two independent go threads.

Godivert finds and connects with proxy ports, once proxy starts and there is some &quot;action&quot; on the port.

**Godivert should start in high integrity mode**

Otherwise it fails to start. You should have WinDriver.sys, WinDriver.dll and TCPHelper.dll in the same directory where you have godivert.exe.

Check README of the Master brunch for more information.
