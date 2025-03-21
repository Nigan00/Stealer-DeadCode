# configure_and_build.ps1

# Установка корня проекта
$projectRoot = "D:\a\Stealer-DeadCode\Stealer-DeadCode\Stealer-DeadCode"
cd $projectRoot
Write-Host "Текущая директория после перехода в корень проекта: $(Get-Location)"

# Логирование содержимого корневой директории для отладки
Write-Host "Содержимое корневой директории:"
Get-ChildItem -Path $projectRoot | ForEach-Object { Write-Host $_.Name }

# Проверка наличия директории ui
if (-not (Test-Path "$projectRoot\ui")) {
    Write-Host "Ошибка: Директория 'ui' не найдена в корне проекта: $projectRoot"
    Write-Host "Пожалуйста, убедитесь, что директория 'ui' существует и содержит файл DeadCode.pro."
    exit 1
}

# Проверка наличия DeadCode.pro
if (-not (Test-Path "$projectRoot\ui\DeadCode.pro")) {
    Write-Host "Ошибка: Файл DeadCode.pro не найден в $projectRoot\ui"
    exit 1
}

$qmakePath = "C:/Qt/Qt/5.15.2/mingw81_64/bin/qmake.exe"
$makePath = "C:/Qt/Qt/5.15.2/mingw81_64/bin/mingw32-make.exe"
$gppPath = "C:/Qt/Qt/5.15.2/mingw81_64/bin/g++.exe"

# Проверка наличия файлов
if (-not (Test-Path $qmakePath)) {
    Write-Host "Error: qmake not found at $qmakePath"
    exit 1
}
if (-not (Test-Path $makePath)) {
    Write-Host "Error: mingw32-make not found at $makePath"
    exit 1
}
if (-not (Test-Path $gppPath)) {
    Write-Host "Error: g++ not found at $gppPath"
    exit 1
}

# Проверка зависимостей g++
Write-Host "Checking g++ dependencies..."
$requiredDlls = @("libgcc_s_seh-1.dll", "libstdc++-6.dll", "libwinpthread-1.dll")
foreach ($dll in $requiredDlls) {
    if (-not (Test-Path "C:/Qt/Qt/5.15.2/mingw81_64/bin/$dll")) {
        Write-Host "Error: $dll not found in C:/Qt/Qt/5.15.2/mingw81_64/bin/"
        exit 1
    }
}

# Настройка PATH
$qtBinPath = "C:/Qt/Qt/5.15.2/mingw81_64/bin"
$env:Path = $qtBinPath + ";" + $env:Path
Write-Host "PATH: $env:Path"

# Переход в директорию ui
cd "$projectRoot\ui"
Write-Host "Рабочая директория после перехода в ui: $(Get-Location)"

# Проверка версии qmake
Write-Host "qmake version:"
& $qmakePath --version

# Запуск qmake с флагом -nocache
Write-Host "Running qmake..."
& "$qmakePath" "DeadCode.pro" -spec win32-g++ -nocache -o "Makefile" 2>&1 | Tee-Object -FilePath "$projectRoot\qmake_output.log"
if ($LASTEXITCODE -ne 0) {
    Write-Host "Error: qmake failed"
    Get-Content "$projectRoot\qmake_output.log"
    exit 1
}

# Проверка Makefile
if (-not (Test-Path "Makefile")) {
    Write-Host "Error: Makefile not generated in $(Get-Location)"
    exit 1
}

# Запуск mingw32-make
Write-Host "Running mingw32-make..."
& "$makePath" -f Makefile 2>&1 | Tee-Object -FilePath "$projectRoot\make_output.log"
if ($LASTEXITCODE -ne 0) {
    Write-Host "Error: mingw32-make failed"
    Get-Content "$projectRoot\make_output.log"
    exit 1
}

# Проверка результата
if (-not (Test-Path "$projectRoot\build\DeadCode.exe")) {
    Write-Host "Error: DeadCode.exe not created in $projectRoot\build"
    exit 1
}
Write-Host "Build completed successfully"