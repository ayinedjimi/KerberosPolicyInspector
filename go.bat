@echo off
REM go.bat - Compilation et execution de KerberosPolicyInspector
REM (c) 2025 Ayi NEDJIMI Consultants

echo ========================================
echo Kerberos Policy Inspector - Compilation
echo (c) Ayi NEDJIMI Consultants
echo ========================================
echo.

set SRC=KerberosPolicyInspector.cpp
set EXE=KerberosPolicyInspector.exe
set LIBS=comctl32.lib activeds.lib adsiid.lib netapi32.lib wevtapi.lib advapi32.lib ole32.lib oleaut32.lib user32.lib gdi32.lib shell32.lib

REM Recherche du compilateur
where cl.exe >nul 2>&1
if %errorlevel% neq 0 (
    echo [ERREUR] Compilateur MSVC non trouve dans PATH
    echo Veuillez executer depuis "Developer Command Prompt for VS"
    echo ou "x64 Native Tools Command Prompt for VS"
    pause
    exit /b 1
)

echo [1/3] Compilation en cours...
cl.exe /nologo /W3 /O2 /EHsc /D_UNICODE /DUNICODE /D_WIN32_DCOM %SRC% /Fe:%EXE% /link %LIBS%

if %errorlevel% neq 0 (
    echo.
    echo [ERREUR] Echec de la compilation
    pause
    exit /b 1
)

echo.
echo [2/3] Nettoyage des fichiers intermediaires...
if exist *.obj del *.obj
if exist *.pdb del *.pdb

echo.
echo [3/3] Compilation reussie!
echo.

if exist %EXE% (
    echo Executable genere: %EXE%
    echo Taille:
    dir /-c %EXE% | find "%EXE%"
    echo.
    echo ========================================
    echo Lancement de l'application...
    echo ========================================
    echo.
    %EXE%
) else (
    echo [ERREUR] Executable non genere
    pause
    exit /b 1
)
