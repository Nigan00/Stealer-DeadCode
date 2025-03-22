# configure_and_build.ps1

# Проверка зависимостей g++
Write-Host "Checking g++ dependencies..."
$requiredDlls = @("libgcc_s_seh-1.dll", "libstdc++-6.dll", "libwinpthread-1.dll")
$mingwBinPath = "C:/Qt/Qt/5.15.2/mingw81_64/bin"
foreach ($dll in $requiredDlls) {
    if (-not (Test-Path "$mingwBinPath/$dll")) {
        Write-Host "Error: $dll not found in $mingwBinPath/"
        # Пытаемся найти DLL в исходной директории MinGW
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
$requiredUtils = @("gcc.exe", "as.exe", "ld.exe", "ar.exe", "cpp.exe", "nm.exe", "strip.exe")
foreach ($util in $requiredUtils) {
    if (-not (Test-Path "$mingwBinPath/$util")) {
        Write-Host "Error: $util not found in $mingwBinPath/"
        # Пытаемся найти утилиту в исходной директории MinGW
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

# Установка путей
$qmakePath = "C:/Qt/Qt/5.15.2/mingw81_64/bin/qmake.exe"
$makePath = "C:/Qt/Qt/5.15.2/mingw81_64/bin/mingw32-make.exe"
$gppPath = "C:/Qt/Qt/5.15.2/mingw81_64/bin/g++.exe"
$gccPath = "C:/Qt/Qt/5.15.2/mingw81_64/bin/gcc.exe"
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

# Проверка текущей директории
Write-Host "Текущая директория после перехода в корень проекта: $(Get-Location)"
Write-Host "Содержимое корневой директории:"
Get-ChildItem -Path . | ForEach-Object { Write-Host $_.Name }

# Проверка PATH
$env:Path = "$mingwBinPath;" + $env:Path
Write-Host "PATH: $env:Path"

# Проверка доступности g++
Write-Host "Verifying g++ is accessible..."
& $gppPath --version
if ($LASTEXITCODE -ne 0) {
    Write-Host "Error: g++ is not accessible at $gppPath"
    exit 1
}

# Определение версии MinGW
Write-Host "Determining MinGW version..."
$gppVersionOutput = & $gppPath --version | Select-Object -First 1
$gppVersion = $gppVersionOutput -replace ".* (\d+\.\d+\.\d+).*", '$1'
Write-Host "Detected MinGW version: $gppVersion"

# Проверка наличия cc1plus.exe
Write-Host "Checking for cc1plus.exe..."
$cc1plusPath = "C:/Qt/Qt/5.15.2/mingw81_64/libexec/gcc/x86_64-w64-mingw32/$gppVersion/cc1plus.exe"
if (-not (Test-Path $cc1plusPath)) {
    Write-Host "Error: cc1plus.exe not found at $cc1plusPath"
    $cc1plusPath = (Get-ChildItem -Path "C:/Qt" -Filter cc1plus.exe -Recurse -ErrorAction SilentlyContinue | Select-Object -First 1).FullName
    if (-not $cc1plusPath) {
        Write-Host "Error: cc1plus.exe not found in C:/Qt"
        dir "C:/Qt/Qt/5.15.2/mingw81_64/libexec" -Recurse
        exit 1
    }
    Write-Host "Found cc1plus.exe at $cc1plusPath"
} else {
    Write-Host "cc1plus.exe found at $cc1plusPath"
}

# Дополнительная проверка g++ с использованием пути, переданного в QMAKE_CXX
Write-Host "Verifying g++ with the path specified in QMAKE_CXX..."
$testGppPath = $gppPath
& $testGppPath --version
if ($LASTEXITCODE -ne 0) {
    Write-Host "Error: g++ at $testGppPath is not accessible"
    exit 1
}

# Создание кастомного mkspec
Write-Host "Creating custom mkspec..."
$customMkspecDir = "$(Get-Location)/custom-mkspec"
$customWin32GppDir = "$customMkspecDir/win32-g++"
$customCommonDir = "$customMkspecDir/common"

# Создаём директории для кастомного mkspec
if (-not (Test-Path $customWin32GppDir)) {
    New-Item -ItemType Directory -Path $customWin32GppDir -Force | Out-Null
}
if (-not (Test-Path $customCommonDir)) {
    New-Item -ItemType Directory -Path $customCommonDir -Force | Out-Null
}

# Копируем win32-g++ и common
try {
    Copy-Item -Path "C:/Qt/Qt/5.15.2/mingw81_64/mkspecs/win32-g++/*" -Destination $customWin32GppDir -Recurse -Force -ErrorAction Stop
    Copy-Item -Path "C:/Qt/Qt/5.15.2/mingw81_64/mkspecs/common/*" -Destination $customCommonDir -Recurse -Force -ErrorAction Stop
} catch {
    Write-Host "Error: Failed to copy mkspec files. Error: $($_.Exception.Message)"
    exit 1
}

# Модификация qmake.conf в кастомном mkspec
$qmakeConfPath = "$customWin32GppDir/qmake.conf"
if (-not (Test-Path $qmakeConfPath)) {
    Write-Host "Error: qmake.conf not found at $qmakeConfPath after copying"
    exit 1
}

try {
    $qmakeConfContent = Get-Content $qmakeConfPath -Raw -ErrorAction Stop
    $qmakeConfContent = $qmakeConfContent -replace 'QMAKE_CXX\s*=\s*\$\${CROSS_COMPILE}g\+\+', "QMAKE_CXX = $gppPath"
    $qmakeConfContent = $qmakeConfContent -replace 'QMAKE_CC\s*=\s*\$\${CROSS_COMPILE}gcc', "QMAKE_CC = $gccPath"
    $qmakeConfContent = $qmakeConfContent -replace 'QMAKE_LINK\s*=\s*\$\${CROSS_COMPILE}g\+\+', "QMAKE_LINK = $gppPath"
    $qmakeConfContent = $qmakeConfContent -replace 'QMAKE_LINK_C\s*=\s*\$\${CROSS_COMPILE}gcc', "QMAKE_LINK_C = $gccPath"
    Set-Content -Path $qmakeConfPath -Value $qmakeConfContent -ErrorAction Stop
} catch {
    Write-Host "Error: Failed to modify qmake.conf. Error: $($_.Exception.Message)"
    exit 1
}
Write-Host "Custom mkspec created at $customWin32GppDir"

# Вывод содержимого qmake.conf для отладки
Write-Host "Contents of custom qmake.conf:"
Get-Content $qmakeConfPath

# Проверка mkspec, используемого qmake
Write-Host "Default mkspec used by qmake:"
& $qmakePath -query QMAKE_SPEC

# Проверка, где qmake ищет g++
Write-Host "Checking where qmake looks for g++..."
& $qmakePath -query QMAKE_CXX

# Переход в директорию ui
if (-not (Test-Path "ui")) {
    Write-Host "Error: ui directory not found in $(Get-Location)"
    exit 1
}
Set-Location -Path "ui"
Write-Host "Рабочая директория после перехода в ui: $(Get-Location)"

# Проверка наличия DeadCode.pro
if (-not (Test-Path $proFile)) {
    Write-Host "Error: $proFile not found in $(Get-Location)"
    exit 1
}

# Проверка версии qmake
Write-Host "qmake version:"
& $qmakePath --version

# Вывод содержимого DeadCode.pro
Write-Host "Contents of DeadCode.pro:"
Get-Content $proFile

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

# Запуск qmake с кастомным mkspec
Write-Host "Running qmake with custom mkspec..."
& $qmakePath -spec $customWin32GppDir $proFile 2>&1 | Tee-Object -FilePath "qmake_output.log"
if ($LASTEXITCODE -ne 0) {
    Write-Host "Error: qmake failed"
    if (Test-Path "qmake_output.log") {
        Write-Host "Contents of qmake_output.log:"
        Get-Content "qmake_output.log"
    }
    exit 1
}

# Проверка, где qmake ищет g++ после вызова
Write-Host "Checking where qmake looks for g++ after running qmake..."
& $qmakePath -query QMAKE_CXX

# Запуск mingw32-make
Write-Host "Running mingw32-make..."
& $makePath 2>&1 | Tee-Object -FilePath "make_output.log"
if ($LASTEXITCODE -ne 0) {
    Write-Host "Error: mingw32-make failed"
    if (Test-Path "make_output.log") {
        Write-Host "Contents of make_output.log:"
        Get-Content "make_output.log"
    }
    exit 1
}

Write-Host "Build completed successfully"