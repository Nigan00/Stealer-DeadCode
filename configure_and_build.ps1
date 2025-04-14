# configure_and_build.ps1

# Проверка текущей директории
Write-Host "Current directory: $(Get-Location)"
Write-Host "Contents of current directory:"
Get-ChildItem -Path . | ForEach-Object { Write-Host $_.Name }

# Проверка MinGW зависимостей
Write-Host "Checking MinGW dependencies..."
$mingwBinPath = "C:/Qt/Tools/mingw1120_64/bin"
$requiredDlls = @("libgcc_s_seh-1.dll", "libstdc++-6.dll", "libwinpthread-1.dll")
foreach ($dll in $requiredDlls) {
    if (-not (Test-Path "$mingwBinPath/$dll")) {
        Write-Host "Error: $dll not found in $mingwBinPath/"
        exit 1
    } else {
        Write-Host "$dll found in $mingwBinPath/"
    }
}

# Проверка утилит MinGW
Write-Host "Checking MinGW utilities..."
$requiredUtils = @("gcc.exe", "g++.exe", "mingw32-make.exe")
foreach ($util in $requiredUtils) {
    if (-not (Test-Path "$mingwBinPath/$util")) {
        Write-Host "Error: $util not found in $mingwBinPath/"
        exit 1
    } else {
        Write-Host "$util found in $mingwBinPath/"
    }
}

# Проверка vcpkg зависимостей
Write-Host "Checking vcpkg dependencies..."
$vcpkgLibPath = "C:/vcpkg/installed/x64-windows-static/lib"
$vcpkgBinPath = "C:/vcpkg/installed/x64-windows-static/bin"
$vcpkgIncludePath = "C:/vcpkg/installed/x64-windows-static/include"

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

$requiredVcpkgDlls = @("sqlite3.dll", "libcurl.dll", "libssl-3-x64.dll", "libcrypto-3-x64.dll", "libzip.dll")
$missingDeps = @()
foreach ($dll in $requiredVcpkgDlls) {
    if (-not (Test-Path "$vcpkgBinPath/$dll")) {
        $missingDeps += $dll
    }
}

if ($missingDeps) {
    Write-Host "Error: Missing vcpkg dependencies: $missingDeps"
    Write-Host "Listing contents of $vcpkgBinPath:"
    dir $vcpkgBinPath -Recurse -ErrorAction SilentlyContinue
    exit 1
} else {
    Write-Host "All vcpkg dependencies found."
}

# Установка путей
$qmakePath = "C:/Qt/6.5.3/mingw_64/bin/qmake.exe"
$makePath = "C:/Qt/Tools/mingw1120_64/bin/mingw32-make.exe"
$gppPath = "C:/Qt/Tools/mingw1120_64/bin/g++.exe"
$proFile = "DeadCode.pro"

# Проверка инструментов
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

# Проверка PATH
$env:Path = "C:/Qt/6.5.3/mingw_64/bin;$mingwBinPath;$vcpkgBinPath;" + $env:Path
Write-Host "PATH: $env:Path"

# Проверка версии qmake
Write-Host "qmake version:"
& $qmakePath --version
if ($LASTEXITCODE -ne 0) {
    Write-Host "Error: qmake --version failed"
    exit 1
}

# Проверка версии g++
Write-Host "g++ version:"
& $gppPath --version
if ($LASTEXITCODE -ne 0) {
    Write-Host "Error: g++ --version failed"
    exit 1
}

# Создание директории build
if (-not (Test-Path "build")) {
    Write-Host "Creating build directory..."
    New-Item -Path "build" -ItemType Directory -Force | Out-Null
}
Set-Location -Path "build"
Write-Host "Current directory: $(Get-Location)"

# Проверка DeadCode.pro
if (-not (Test-Path "../ui/$proFile")) {
    Write-Host "Error: $proFile not found in ../ui"
    exit 1
}

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
& $makePath -f Makefile.Release -j4 2>&1 | Tee-Object -FilePath "make_output.log"
if ($LASTEXITCODE -ne 0) {
    Write-Host "Error: mingw32-make failed"
    if (Test-Path "make_output.log") {
        Write-Host "Contents of make_output.log:"
        Get-Content "make_output.log"
    }
    exit 1
}

# Проверка DeadCode.exe
if (-not (Test-Path "release/DeadCode.exe")) {
    Write-Host "Error: DeadCode.exe not found in release directory"
    dir "release" -Recurse -ErrorAction SilentlyContinue
    exit 1
}

# Развёртывание Qt зависимостей
Write-Host "Deploying Qt dependencies..."
$windeployqtPath = "C:/Qt/6.5.3/mingw_64/bin/windeployqt.exe"
if (-not (Test-Path $windeployqtPath)) {
    Write-Host "Error: windeployqt.exe not found at $windeployqtPath"
    exit 1
}
Set-Location -Path "release"
& $windeployqtPath DeadCode.exe --release --no-translations --no-opengl-sw --no-system-d3d-compiler 2>&1 | Tee-Object -FilePath "windeployqt_output.log"
if ($LASTEXITCODE -ne 0) {
    Write-Host "Error: windeployqt failed"
    if (Test-Path "windeployqt_output.log") {
        Write-Host "Contents of windeployqt_output.log:"
        Get-Content "windeployqt_output.log"
    }
    exit 1
}

# Копирование vcpkg зависимостей
Write-Host "Copying vcpkg dependencies..."
foreach ($dll in $requiredVcpkgDlls) {
    if (Test-Path "$vcpkgBinPath/$dll") {
        Copy-Item -Path "$vcpkgBinPath/$dll" -Destination . -Force
        Write-Host "Copied $dll"
    } else {
        Write-Host "Warning: $dll not found in $vcpkgBinPath"
    }
}

# Копирование дополнительных файлов
Write-Host "Copying additional files..."
if (Test-Path "../../config.json") {
    Copy-Item -Path "../../config.json" -Destination . -Force
    Write-Host "Copied config.json"
} else {
    Write-Host "Warning: config.json not found, creating stub"
    Set-Content -Path "config.json" -Value "{}"
}
if (Test-Path "../../icon.ico") {
    Copy-Item -Path "../../icon.ico" -Destination . -Force
    Write-Host "Copied icon.ico"
} else {
    Write-Host "Warning: icon.ico not found"
}
New-Item -Path "data" -ItemType Directory -Force | Out-Null
Write-Host "Created data directory"

# Проверка всех файлов
Write-Host "Verifying files..."
$requiredFiles = @(
    "DeadCode.exe",
    "Qt6Core.dll",
    "Qt6Gui.dll",
    "Qt6Widgets.dll",
    "Qt6Network.dll",
    "Qt6Sql.dll",
    "sqlite3.dll",
    "libcurl.dll",
    "libssl-3-x64.dll",
    "libcrypto-3-x64.dll",
    "libzip.dll",
    "plugins\platforms\qwindows.dll",
    "plugins\sqldrivers\qsqlite.dll",
    "config.json",
    "icon.ico",
    "data"
)
foreach ($file in $requiredFiles) {
    if (-not (Test-Path $file)) {
        Write-Host "Error: $file is missing"
        exit 1
    }
}
Write-Host "All required files are present"

Write-Host "Build completed successfully"
Write-Host "Executable located at: $(Get-Location)/DeadCode.exe"