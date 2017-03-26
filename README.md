checksec for x64dbg

This plugin was inspired by OllySSEH by Mario Ballano and the linux checksec.sh by Tobias Klein.
Please report any bugs/improvements/suggestions.

Screenshots
-----------
![ScreenShot](https://raw.githubusercontent.com/klks/checksec/master/screenshot/screenshot1.PNG)

![ScreenShot](https://raw.githubusercontent.com/klks/checksec/master/screenshot/screenshot2.PNG)

Compiling
---------
Compile with Visual Studio 2017.

v0.1
----
- Initial Release.
- Supports checking of
 - SafeSEH
 - DEP
 - ASLR
 - /GS (Not 100% reliably)
 - Control Flow Guard
 - Signature