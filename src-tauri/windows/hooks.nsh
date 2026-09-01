!macro NSIS_HOOK_PREINSTALL
  ; Nettoyage d'une installation/service précédent
  nsExec::ExecToLog 'sc.exe stop "WireGuardTunnel$$Deliriuum"'
  nsExec::ExecToLog 'sc.exe delete "WireGuardTunnel$$Deliriuum"'

  nsExec::ExecToLog 'sc.exe stop "DeliriuumDirectService"'
  nsExec::ExecToLog 'sc.exe delete "DeliriuumDirectService"'
!macroend


!macro NSIS_HOOK_POSTINSTALL
  DetailPrint "Installation du service Deliriuum Direct..."

  nsExec::ExecToStack 'sc.exe create "DeliriuumDirectService" binPath= "\"$INSTDIR\resources\windows\deliriuum-direct-service.exe\"" start= auto DisplayName= "Deliriuum Direct Service"'
  Pop $0
  Pop $1

  ${If} $0 != 0
    MessageBox MB_ICONSTOP "Impossible d'installer le service Deliriuum Direct.$\r$\nCode : $0$\r$\n$1"
    Abort
  ${EndIf}

  nsExec::ExecToStack 'sc.exe start "DeliriuumDirectService"'
  Pop $0
  Pop $1

  ${If} $0 != 0
    MessageBox MB_ICONSTOP "Le service Deliriuum Direct a été installé mais n'a pas pu démarrer.$\r$\nCode : $0$\r$\n$1"
    Abort
  ${EndIf}
!macroend


!macro NSIS_HOOK_PREUNINSTALL
  DetailPrint "Arrêt des services Deliriuum..."

  nsExec::ExecToLog 'sc.exe stop "WireGuardTunnel$$Deliriuum"'
  nsExec::ExecToLog 'sc.exe delete "WireGuardTunnel$$Deliriuum"'

  nsExec::ExecToLog 'sc.exe stop "DeliriuumDirectService"'
  nsExec::ExecToLog 'sc.exe delete "DeliriuumDirectService"'
!macroend


!macro NSIS_HOOK_POSTUNINSTALL
!macroend
