# configure_and_build.ps1

# Проверка зависимостей g++
Write-Host "Checking g++ dependencies..."
$requiredDlls = @("libgcc_s_seh-1.dll", "libstdc++-6.dll", "libwinpthread-1.dll")
foreach ($dll in $requiredDlls) {
    if (-not (Test-Path "C:/Qt/Qt/5.15.2/mingw81_64/bin/$dll")) {
        Write-Host "Error: $dll not found in C:/Qt/Qt/5.15.2/mingw81_64/bin/"
        exit 1
    } else {
        Write-Host "$dll found in C:/Qt/Qt/5.15.2/mingw81_64/bin/"
    }
}

# Установка путей
$qmakePath = "C:/Qt/Qt/5.15.2/mingw81_64/bin/qmake.exe"
$makePath = "C:/Qt/Qt/5.15.2/mingw81_64/bin/mingw32-make.exe"
$gppPath = "C:/Qt/Qt/5.15.2/mingw81_64/bin/g++.exe"
$gccPath = "C:/Qt/Qt/5.15.2/mingw81_64/bin/gcc.exe"
$proFile = "DeadCode.pro"

# Проверка текущей директории
Write-Host "Текущая директория после перехода в корень проекта: $(Get-Location)"
Write-Host "Содержимое корневой директории:"
Get-ChildItem -Path . | ForEach-Object { Write-Host $_.Name }

# Проверка PATH
$env:Path = "C:/Qt/Qt/5.15.2/mingw81_64/bin;" + $env:Path
Write-Host "PATH: $env:Path"

# Проверка доступности g++
Write-Host "Verifying g++ is accessible..."
& $gppPath --version
if ($LASTEXITCODE -ne 0) {
    Write-Host "Error: g++ is not accessible"
    exit 1
}

# Дополнительная проверка g++ с использованием пути, переданного в QMAKE_CXX
Write-Host "Verifying g++ with the path specified in QMAKE_CXX..."
$testGppPath = "C:/Qt/Qt/5.15.2/mingw81_64/bin/g++.exe"
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
    New-Item -ItemType Directory -Path $customWin32GppDir -Force
}
if (-not (Test-Path $customCommonDir)) {
    New-Item -ItemType Directory -Path $customCommonDir -Force
}

# Копируем win32-g++ и common
Copy-Item -Path "C:/Qt/Qt/5.15.2/mingw81_64/mkspecs/win32-g++/*" -Destination $customWin32GppDir -Recurse -Force
Copy-Item -Path "C:/Qt/Qt/5.15.2/mingw81_64/mkspecs/common/*" -Destination $customCommonDir -Recurse -Force

# Модификация qmake.conf в кастомном mkspec
$qmakeConfPath = "$customWin32GppDir/qmake.conf"
$qmakeConfContent = Get-Content $qmakeConfPath -Raw
$qmakeConfContent = $qmakeConfContent -replace 'QMAKE_CXX\s*=\s*\$\${CROSS_COMPILE}g\+\+', "QMAKE_CXX = $gppPath"
$qmakeConfContent = $qmakeConfContent -replace 'QMAKE_CC\s*=\s*\$\${CROSS_COMPILE}gcc', "QMAKE_CC = $gccPath"
$qmakeConfContent = $qmakeConfContent -replace 'QMAKE_LINK\s*=\s*\$\${CROSS_COMPILE}g\+\+', "QMAKE_LINK = $gppPath"
$qmakeConfContent = $qmakeConfContent -replace 'QMAKE_LINK_C\s*=\s*\$\${CROSS_COMPILE}gcc', "QMAKE_LINK_C = $gccPath"
Set-Content -Path $qmakeConfPath -Value $qmakeConfContent
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
Set-Location -Path "ui"
Write-Host "Рабочая директория после перехода в ui: $(Get-Location)"

# Проверка версии qmake
Write-Host "qmake version:"
& $qmakePath --version

# Вывод содержимого DeadCode.pro
Write-Host "Contents of DeadCode.pro:"
Get-Content $proFile

# Запуск qmake с кастомным mkspec (без отладочного режима)
Write-Host "Running qmake with custom mkspec..."
& $qmakePath -spec $customWin32GppDir "QMAKE_CXX=$gppPath" "QMAKE_CC=$gccPath" $proFile 2>&1 | Tee-Object -FilePath "qmake_output.log"
if ($LASTEXITCODE -ne 0) {
    Write-Host "Error: qmake failed"
    if (Test-Path qmake_output.log) {
        Write-Host "Contents of qmake_output.log:"
        Get-Content qmake_output.log
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
    if (Test-Path make_output.log) {
        Write-Host "Contents of make_output.log:"
        Get-Content make_output.log
    }
    exit 1
}

Write-Host "Build completed successfully"