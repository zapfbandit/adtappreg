Import-Module powershell-yaml

function Get-DefaultAppInfo {
    $info = @{ "@odata.type" = "#microsoft.graph.win32LobApp" }
    $info.displayName = $null
    $info.description = $null
    $info.publisher = $null
    $info.largeIcon = $null
    $info.createdDateTime = $null
    $info.lastModifiedDateTime = $null
    $info.isFeatured = $false
    $info.privacyInformationUrl = $null
    $info.informationUrl = $null
    $info.owner = $null
    $info.notes = $null
    $info.fileName = "IntunePackage.intunewin"
    $info.installCommandLine = $null
    $info.uninstallCommandLine = $null
    $info.applicableArchitectures = "x64,x86"
    $info.rules = $null
    $info.installExperience = $null
    $info.returnCodes = $null
    
    $info
}

function Create-AppInfo {
    param (
        $IntunePackagePath,
        $AppConfigPath
    )
    
    $appConfigContents = Get-Content -Path $AppConfigPath -Raw
    
    $appConfig = ConvertFrom-Yaml $appConfigContents
    # TODO: validate appConfig contents/format
    
    $app = Get-DefaultAppInfo
    
    $app.displayName = "$($appInfo.applicationName) ($($appInfo.Version))"
    $app.description = $appInfo.description
    
    $appInfo = @{
        app = $app
        assignments = $null
    }
}

# Testing
Create-AppInfo "..\apps\test\wsl_update.x64.intunewin" "..\apps\test\info.yml"
pause