!include "LogicLib.nsh"
!include "x64.nsh"

Unicode true
RequestExecutionLevel user
SilentInstall silent
AutoCloseWindow true
ShowInstDetails nevershow

OutFile "Deliriuum-Direct-Windows.exe"
Name "Deliriuum Direct"

Section
    InitPluginsDir

    ${If} ${IsNativeARM64}
        File /oname=$PLUGINSDIR\setup.exe "arm64-setup.exe"
    ${Else}
        File /oname=$PLUGINSDIR\setup.exe "x64-setup.exe"
    ${EndIf}

    ExecWait '"$PLUGINSDIR\setup.exe"' $0

    SetErrorLevel $0
SectionEnd
