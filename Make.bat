call egcc.bat
ld -r -b binary ntvdm.exe -o ntvdm.o


gcc dosEx64.cc ntvdm.o %CCFLAGS2% -lstdshit -o dosEx64.exe %LFLAGS%
