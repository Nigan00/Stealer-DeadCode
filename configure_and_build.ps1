# configure_and_build.ps1

# Проверка зависимостей g++
Write-Host "Checking g++ dependencies..."
$mingwBinPath = "C:/Qt/Tools/mingw810_64/bin"  # Исправлен путь в соответствии с build.yml
$requiredDlls = @("libgcc_s_seh-1.dll", "libstdc++-6.dll", "libwinpthread-1.dll")
foreach ($dll in $requiredDlls) {
    if (-not (Test-Path "$mingwBinPath/$dll")) {
        Write-Host "Error: $dll not found in $mingwBinPath/"
        # Пытаемся найти DLL в альтернативной директории
        $fallbackPath = "C:/ProgramData/mingw64/mingw64/bin/$dll"
        if (Test-Path $fallbackPath) {
            Write-Host "Found $dll at $fallbackPath, copying to $mingwBinPath/"
            Copy-Item -Path $fallbackPath -Destination $mingwBinPath -Force
        } else {
            Write-Host "Error: $dll not found in fallback path $fallbackPath"
            exit 1
        }
    } else {
        Write-Host "$dll found in $mingwBinPath/"
    }
}

# Проверка утилит MinGW
Write-Host "Checking MinGW utilities..."
$requiredUtils = @("gcc.exe", "g++.exe", "as.exe", "ld.exe", "ar.exe", "cpp.exe", "nm.exe", "strip.exe", "mingw32-make.exe")
foreach ($util in $requiredUtils) {
    if (-not (Test-Path "$mingwBinPath/$util")) {
        Write-Host "Error: $util not found in $mingwBinPath/"
        # Пытаемся найти утилиту в альтернативной директории
        $fallbackPath = "C:/ProgramData/mingw64/mingw64/bin/$util"
        if (Test-Path $fallbackPath) {
            Write-Host "Found $util at $fallbackPath, copying to $mingwBinPath/"
            Copy-Item -Path $fallbackPath -Destination $mingwBinPath -Force
        } else {
            Write-Host "Error: $util not found in fallback path $fallbackPath"
            exit 1
        }
    } else {
        Write-Host "$util found in $mingwBinPath/"
    }
}

# Проверка зависимостей vcpkg
Write-Host "Checking vcpkg dependencies..."
$vcpkgLibPath = "C:/vcpkg/installed/x64-mingw-dynamic/lib"
$vcpkgBinPath = "C:/vcpkg/installed/x64-mingw-dynamic/bin"
$vcpkgIncludePath = "C:/vcpkg/installed/x64-mingw-dynamic/include"

# Проверка наличия директорий vcpkg
if (-not (Test-Path $vcpkgLibPath)) {
    Write-Host "Error: vcpkg library directory not found at $vcpkgLibPath"
    exit 1
}
if (-not (Test-Path $vcpkgBinPath)) {
    Write-Host "Error: vcpkg binary directory not found at $vcpkgBinPath"
    exit 1
}
if (-not (Test-Path $vcpkgIncludePath)) {
    Write-Host "Error: vcpkg include directory not found at $vcpkgIncludePath"
    exit 1
}

# Список зависимостей для проверки
$requiredVcpkgLibs = @("libsqlite3.dll.a", "libzip.dll.a", "libzlib.dll.a", "libbz2.dll.a", "libcurl.dll.a", "libssl.dll.a", "libcrypto.dll.a")
$requiredVcpkgDlls = @("sqlite3.dll", "libzip.dll", "zlib1.dll", "bz2.dll", "libcurl.dll", "libssl.dll", "libcrypto.dll")
$requiredVcpkgHeaders = @("sqlite3.h", "zip.h", "zlib.h", "bzlib.h", "curl/curl.h", "openssl/ssl.h", "openssl/crypto.h")
$missingDeps = @()

# Проверка библиотек (.dll.a)
foreach ($lib in $requiredVcpkgLibs) {
    if (-not (Test-Path "$vcpkgLibPath/$lib")) {
        $missingDeps += $lib
    }
}

# Проверка DLL
foreach ($dll in $requiredVcpkgDlls) {
    if (-not (Test-Path "$vcpkgBinPath/$dll")) {
        $missingDeps += $dll
    }
}

# Проверка заголовочных файлов
foreach ($header in $requiredVcpkgHeaders) {
    if (-not (Test-Path "$vcpkgIncludePath/$header")) {
        $missingDeps += $header
    }
}

if ($missingDeps) {
    Write-Host "Error: Missing vcpkg dependencies: $missingDeps"
    Write-Host "Please ensure vcpkg is installed and dependencies are built with triplet x64-mingw-dynamic"
    Write-Host "Listing contents of $vcpkgLibPath:"
    dir $vcpkgLibPath -Recurse -ErrorAction SilentlyContinue
    Write-Host "Listing contents of $vcpkgBinPath:"
    dir $vcpkgBinPath -Recurse -ErrorAction SilentlyContinue
    Write-Host "Listing contents of $vcpkgIncludePath:"
    dir $vcpkgIncludePath -Recurse -ErrorAction SilentlyContinue
    exit 1
} else {
    Write-Host "All vcpkg dependencies found."
}

# Установка путей
$qmakePath = "C:/Qt/5.15.2/mingw81_64/bin/qmake.exe"
$makePath = "C:/Qt/Tools/mingw810_64/bin/mingw32-make.exe"  # Исправлен путь
$gppPath = "C:/Qt/Tools/mingw810_64/bin/g++.exe"  # Исправлен путь
$gccPath = "C:/Qt/Tools/mingw810_64/bin/gcc.exe"  # Исправлен путь
$proFile = "DeadCode.pro"

# Проверка наличия qmake и mingw32-make
if (-not (Test-Path $qmakePath)) {
    Write-Host "Error: qmake.exe not found at $qmakePath"
    exit 1
}
if (-not (Test-Path $makePath)) {
    Write-Host "Error: mingw32-make.exe not found at $makePath"
    exit 1
}
if (-not (Test-Path $gppPath)) {
    Write-Host "Error: g++.exe not found at $gppPath"
    exit 1
}
if (-not (Test-Path $gccPath)) {
    Write-Host "Error: gcc.exe not found at $gccPath"
    exit 1
}

# Проверка текущей директории
Write-Host "Current directory: $(Get-Location)"
Write-Host "Contents of current directory:"
Get-ChildItem -Path . | ForEach-Object { Write-Host $_.Name }

# Проверка PATH
$env:Path = "C:/Qt/5.15.2/mingw81_64/bin;$mingwBinPath;$vcpkgBinPath;" + $env:Path
Write-Host "PATH: $env:Path"

# Установка QML2_IMPORT_PATH
$env:QML2_IMPORT_PATH = "C:/Qt/5.15.2/mingw81_64/qml"
Write-Host "QML2_IMPORT_PATH set to: $env:QML2_IMPORT_PATH"

# Проверка доступности g++
Write-Host "Verifying g++ is accessible..."
& $gppPath --version
if ($LASTEXITCODE -ne 0) {
    Write-Host "Error: g++ is not accessible at $gppPath"
    exit 1
}

# Проверка версии qmake
Write-Host "qmake version:"
& $qmakePath --version
if ($LASTEXITCODE -ne 0) {
    Write-Host "Error: qmake --version failed"
    exit 1
}

# Создание директории build, если она не существует
if (-not (Test-Path "build")) {
    Write-Host "Creating build directory..."
    New-Item -Path "build" -ItemType Directory -Force | Out-Null
}
Set-Location -Path "build"
Write-Host "Current directory after moving to build: $(Get-Location)"

# Проверка наличия DeadCode.pro
if (-not (Test-Path "../ui/$proFile")) {
    Write-Host "Error: $proFile not found in ../ui"
    exit 1
}

# Вывод содержимого DeadCode.pro
Write-Host "Contents of DeadCode.pro:"
Get-Content "../ui/$proFile"

# Проверка текущих значений TEMP и TMP
Write-Host "Current TEMP: $env:TEMP"
Write-Host "Current TMP: $env:TMP"

# Тестовая компиляция для отладки с verbose output
Write-Host "Running a test compilation to verify g++ with verbose output..."
$testDir = "test_temp"
if (-not (Test-Path $testDir)) {
    New-Item -ItemType Directory -Path $testDir -Force | Out-Null
}
$testCppFile = "$testDir/test.cpp"
$testExeFile = "$testDir/test.exe"
Set-Content -Path $testCppFile -Value @"
#include <iostream>
int main() {
    std::cout << "Test compilation successful" << std::endl;
    return 0;
}
"@
Write-Host "Running g++ with verbose output..."
& $gppPath -v 2>&1 | Tee-Object -FilePath "gpp_verbose.log"
Write-Host "Contents of gpp_verbose.log:"
Get-Content "gpp_verbose.log"

Write-Host "Compiling $testCppFile..."
& $gppPath -v -o $testExeFile $testCppFile 2>&1 | Tee-Object -FilePath "test_compile.log"
if ($LASTEXITCODE -ne 0) {
    Write-Host "Error: Test compilation failed"
    if (Test-Path "test_compile.log") {
        Write-Host "Contents of test_compile.log:"
        Get-Content "test_compile.log"
    }
    exit 1
}

# Проверка, что тестовый исполняемый файл был создан и может быть запущен
if (-not (Test-Path $testExeFile)) {
    Write-Host "Error: Test executable $testExeFile was not created"
    exit 1
}
Write-Host "Running test executable..."
& $testExeFile
if ($LASTEXITCODE -ne 0) {
    Write-Host "Error: Test executable failed to run"
    exit 1
}
Write-Host "Test compilation and execution successful"

# Запуск qmake
Write-Host "Running qmake..."
$qmakeArgs = @(
    "../ui/$proFile",
    "CONFIG+=release",
    "INCLUDEPATH+=$vcpkgIncludePath",
    "LIBS+=-L$vcpkgLibPath",
    "-spec", "win32-g++"
)
& $qmakePath $qmakeArgs 2>&1 | Tee-Object -FilePath "qmake_output.log"
if ($LASTEXITCODE -ne 0) {
    Write-Host "Error: qmake failed"
    if (Test-Path "qmake_output.log") {
        Write-Host "Contents of qmake_output.log:"
        Get-Content "qmake_output.log"
    }
    exit 1
}

# Запуск mingw32-make
Write-Host "Running mingw32-make..."
& $makePath -f Makefile.Release -j1 2>&1 | Tee-Object -FilePath "make_output.log"
if ($LASTEXITCODE -ne 0) {
    Write-Host "Error: mingw32-make failed"
    if (Test-Path "make_output.log") {
        Write-Host "Contents of make_output.log:"
        Get-Content "make_output.log"
    }
    exit 1
}

# Проверка наличия DeadCode.exe
if (-not (Test-Path "release/DeadCode.exe")) {
    Write-Host "Error: DeadCode.exe not found in release directory"
    dir "release" -Recurse -ErrorAction SilentlyContinue
    exit 1
}

Write-Host "Build completed successfully"
Write-Host "Executable located at: $(Get-Location)/release/DeadCode.exe"