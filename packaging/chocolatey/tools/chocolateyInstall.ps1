$packageName = 'myth'
$url64 = '{{REPO_URL}}/releases/download/v1.1.1/MYTH_1.1.1_x64-setup.exe'
$silentArgs = '/S'

Install-ChocolateyPackage -PackageName $packageName `
                          -FileType 'exe' `
                          -SilentArgs $silentArgs `
                          -Url64bit $url64 `
                          -Checksum64 '' `
                          -ChecksumType64 'sha256'
