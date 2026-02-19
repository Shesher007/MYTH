$packageName = 'myth'
$url64 = 'https://github.com/shesher010/MYTH/releases/download/v1.1.6/MYTH_1.1.6_x64-setup.exe'
$silentArgs = '/S'

Install-ChocolateyPackage -PackageName $packageName `
                          -FileType 'exe' `
                          -SilentArgs $silentArgs `
                          -Url64bit $url64 `
                          -Checksum64 '' `
                          -ChecksumType64 'sha256'
