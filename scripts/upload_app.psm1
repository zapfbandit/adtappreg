Import-Module powershell-yaml
Import-Module -Name $(Join-Path -Path $PSScriptRoot -ChildPath "config")
# Stolen codes
##########################################

##consts
$baseUrl = "https://graph.microsoft.com/v1.0/deviceAppManagement/"

$logRequestUris = $true;
$logHeaders = $false;
$logContent = $true;

$azureStorageUploadChunkSizeInMb = 6l;

$connectionConfig = Get-Config

$sleep = 30

$storageAcc = $connectionConfig.storageAccount
$containerName = $connectionConfig.containerName
$azcopyExe = Join-Path -Path $PSScriptRoot -ChildPath "azcopy.exe"
$intuneWinAppUtilExe = Join-Path -Path $PSScriptRoot -ChildPath "IntuneWinAppUtil.exe"
##

function FinalizeAzureStorageUpload($sasUri, $ids){

	$uri = "$sasUri&comp=blocklist";
	$request = "PUT $uri";

	$xml = '<?xml version="1.0" encoding="utf-8"?><BlockList>';
	foreach ($id in $ids)
	{
		$xml += "<Latest>$id</Latest>";
	}
	$xml += '</BlockList>';

	if ($logRequestUris) { Write-Host $request; }
	if ($logContent) { Write-Host -ForegroundColor Gray $xml; }

	try
	{
		Invoke-RestMethod $uri -Method Put -Body $xml;
	}
	catch
	{
		Write-Host -ForegroundColor Red $request;
		Write-Host -ForegroundColor Red $_.Exception.Message;
		throw;
	}
}

function RenewAzureStorageUpload($fileUri){

	$renewalUri = "$fileUri/renewUpload";
	$actionBody = "";
	$rewnewUriResult = MakePostRequest $renewalUri $actionBody;
	
	$file = WaitForFileProcessing $fileUri "AzureStorageUriRenewal" $azureStorageRenewSasUriBackOffTimeInSeconds;

}

function UploadAzureStorageChunk($sasUri, $id, $body){

	$uri = "$sasUri&comp=block&blockid=$id";
	$request = "PUT $uri";

	$iso = [System.Text.Encoding]::GetEncoding("iso-8859-1");
	$encodedBody = $iso.GetString($body);
	$headers = @{
		"x-ms-blob-type" = "BlockBlob"
	};

	if ($logRequestUris) { Write-Host $request; }
	if ($logHeaders) { WriteHeaders $headers; }

	try
	{
		$response = Invoke-WebRequest $uri -Method Put -Headers $headers -Body $encodedBody;
	}
	catch
	{
		Write-Host -ForegroundColor Red $request;
		Write-Host -ForegroundColor Red $_.Exception.Message;
		throw;
	}

}

function UploadFileToAzureStorage($sasUri, $filepath, $fileUri){

	try {

        $chunkSizeInBytes = 1024l * 1024l * $azureStorageUploadChunkSizeInMb;
		
		# Start the timer for SAS URI renewal.
		$sasRenewalTimer = [System.Diagnostics.Stopwatch]::StartNew()
		
		# Find the file size and open the file.
		$fileSize = (Get-Item $filepath).length;
		$chunks = [Math]::Ceiling($fileSize / $chunkSizeInBytes);
		$reader = New-Object System.IO.BinaryReader([System.IO.File]::Open($filepath, [System.IO.FileMode]::Open));
		$position = $reader.BaseStream.Seek(0, [System.IO.SeekOrigin]::Begin);
		
		# Upload each chunk. Check whether a SAS URI renewal is required after each chunk is uploaded and renew if needed.
		$ids = @();

		for ($chunk = 0; $chunk -lt $chunks; $chunk++){

			$id = [System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes($chunk.ToString("0000")));
			$ids += $id;

			$start = $chunk * $chunkSizeInBytes;
			$length = [Math]::Min($chunkSizeInBytes, $fileSize - $start);
			$bytes = $reader.ReadBytes($length);
			
			$currentChunk = $chunk + 1;			

            Write-Progress -Activity "Uploading File to Azure Storage" -status "Uploading chunk $currentChunk of $chunks" `
            -percentComplete ($currentChunk / $chunks*100)

            $uploadResponse = UploadAzureStorageChunk $sasUri $id $bytes;
			
			# Renew the SAS URI if 7 minutes have elapsed since the upload started or was renewed last.
			if ($currentChunk -lt $chunks -and $sasRenewalTimer.ElapsedMilliseconds -ge 450000){

				$renewalResponse = RenewAzureStorageUpload $fileUri;
				$sasRenewalTimer.Restart();
			
            }

		}

        Write-Progress -Completed -Activity "Uploading File to Azure Storage"

		$reader.Close();

	}

	finally {

		if ($reader -ne $null) { $reader.Dispose(); }
	
    }
	
	# Finalize the upload.
	$uploadResponse = FinalizeAzureStorageUpload $sasUri $ids;

}

function MakeGetRequest($collectionPath){

	$uri = "$baseUrl$collectionPath";
	$request = "GET $uri";
	
	if ($logRequestUris) { Write-Host $request; }
	if ($logHeaders) { WriteHeaders $authToken; }

	try
	{
		Test-AuthToken
		$response = Invoke-RestMethod $uri -Method Get -Headers $authToken;
		$response;
	}
	catch
	{
		Write-Host -ForegroundColor Red $request;
		Write-Host -ForegroundColor Red $_.Exception.Message;
		throw;
	}
}

function WaitForFileProcessing($fileUri, $stage){

	$attempts= 600;
	$waitTimeInSeconds = 10;

	$successState = "$($stage)Success";
	$pendingState = "$($stage)Pending";
	$failedState = "$($stage)Failed";
	$timedOutState = "$($stage)TimedOut";

	$file = $null;
	while ($attempts -gt 0)
	{
		$file = MakeGetRequest $fileUri;

		if ($file.uploadState -eq $successState)
		{
			break;
		}
		elseif ($file.uploadState -ne $pendingState)
		{
			Write-Host -ForegroundColor Red $_.Exception.Message;
            throw "File upload state is not success: $($file.uploadState)";
		}

		Start-Sleep $waitTimeInSeconds;
		$attempts--;
	}

	if ($file -eq $null -or $file.uploadState -ne $successState)
	{
		throw "File request did not complete in the allotted time.";
	}

	$file;
}

function CloneObject($object){

	$stream = New-Object IO.MemoryStream;
	$formatter = New-Object Runtime.Serialization.Formatters.Binary.BinaryFormatter;
	$formatter.Serialize($stream, $object);
	$stream.Position = 0;
	$formatter.Deserialize($stream);
}

function MakeRequest($verb, $collectionPath, $body){

	$uri = "$baseUrl$collectionPath";
	$request = "$verb $uri";
	
	$clonedHeaders = CloneObject $authToken;
	$clonedHeaders["content-length"] = $body.Length;
	$clonedHeaders["content-type"] = "application/json";

	if ($logRequestUris) { Write-Host $request; }
	if ($logHeaders) { WriteHeaders $clonedHeaders; }
	if ($logContent) { Write-Host -ForegroundColor Gray $body; }

	try
	{
		Test-AuthToken
		$response = Invoke-RestMethod $uri -Method $verb -Headers $clonedHeaders -Body $body;
		$response;
	}
	catch
	{
		Write-Host -ForegroundColor Red $request;
		Write-Host -ForegroundColor Red $_.Exception.Message;
        
        $streamReader = [System.IO.StreamReader]::new($_.Exception.Response.GetResponseStream())
        $ErrResp = $streamReader.ReadToEnd()
        $streamReader.Close()
        Write-Host $ErrResp
        
		throw;
	}
}

function Get-AuthToken {

<#
.SYNOPSIS
This function is used to authenticate with the Graph API REST interface
.DESCRIPTION
The function authenticate with the Graph API Interface with the tenant name
.EXAMPLE
Get-AuthToken
Authenticates you with the Graph API interface
.NOTES
NAME: Get-AuthToken
#>


    try {

    $authResult = Get-MsalToken `
      -ClientId $connectionConfig.auth.clientId `
      -Scope "https://graph.microsoft.com/DeviceManagementApps.ReadWrite.All" `
      -Authority $connectionConfig.auth.authority `
      -RedirectUri $connectionConfig.auth.redirectUri

        # If the accesstoken is valid then create the authentication header
        
        if($authResult.AccessToken){

        # Creating header for Authorization token

        $authHeader = @{
            'Content-Type'='application/json'
            'Authorization'="Bearer " + $authResult.AccessToken
            'ExpiresOn'=$authResult.ExpiresOn
            }

        return $authHeader

        }

        else {

        Write-Host
        Write-Host "Authorization Access Token is null, please re-run authentication..." -ForegroundColor Red
        Write-Host
        break

        }

    }

    catch {

    write-host $_.Exception.Message -f Red
    write-host $_.Exception.ItemName -f Red
    write-host
    break

    }

}

Function Test-AuthToken(){

    # Checking if authToken exists before running authentication
    if($global:authToken){

        # Setting DateTime to Universal time to work in all timezones
        $DateTime = (Get-Date).ToUniversalTime()

        # If the authToken exists checking when it expires
        $TokenExpires = ($authToken.ExpiresOn.datetime - $DateTime).Minutes

            if($TokenExpires -le 0){

            write-host "Authentication Token expired" $TokenExpires "minutes ago" -ForegroundColor Yellow
            write-host

            $global:authToken = Get-AuthToken -User $User

            }
    }

    # Authentication doesn't exist, calling Get-AuthToken function

    else {

    # Getting the authorization token
    $global:authToken = Get-AuthToken

    }
}

Function Test-SourceFile(){

param
(
    [parameter(Mandatory=$true)]
    [ValidateNotNullOrEmpty()]
    $SourceFile
)

    try {

            if(!(test-path "$SourceFile")){

            Write-Host
            Write-Host "Source File '$sourceFile' doesn't exist..." -ForegroundColor Red
            throw

            }

        }

    catch {

		Write-Host -ForegroundColor Red $_.Exception.Message;
        Write-Host
		break

    }

}

Function Get-IntuneWinXML(){

param
(
[Parameter(Mandatory=$true)]
$SourceFile,

[Parameter(Mandatory=$true)]
$fileName,

[Parameter(Mandatory=$false)]
[ValidateSet("false","true")]
[string]$removeitem = "true"
)

Test-SourceFile "$SourceFile"

$Directory = [System.IO.Path]::GetDirectoryName("$SourceFile")

Add-Type -Assembly System.IO.Compression.FileSystem
$zip = [IO.Compression.ZipFile]::OpenRead("$SourceFile")

    $zip.Entries | where {$_.Name -like "$filename" } | foreach {

    [System.IO.Compression.ZipFileExtensions]::ExtractToFile($_, "$Directory\$filename", $true)

    }

$zip.Dispose()

[xml]$IntuneWinXML = gc "$Directory\$filename"

return $IntuneWinXML

if($removeitem -eq "true"){ remove-item "$Directory\$filename" }

}

Function Get-IntuneWinFile(){

param
(
[Parameter(Mandatory=$true)]
$SourceFile,

[Parameter(Mandatory=$true)]
$fileName,

[Parameter(Mandatory=$false)]
[string]$Folder = "win32"
)

    $Directory = [System.IO.Path]::GetDirectoryName("$SourceFile")

    if(!(Test-Path "$Directory\$folder")){

        New-Item -ItemType Directory -Path "$Directory" -Name "$folder" | Out-Null

    }

    Add-Type -Assembly System.IO.Compression.FileSystem
    $zip = [IO.Compression.ZipFile]::OpenRead("$SourceFile")

        $zip.Entries | where {$_.Name -like "$filename" } | foreach {

        [System.IO.Compression.ZipFileExtensions]::ExtractToFile($_, "$Directory\$folder\$filename", $true)

        }

    $zip.Dispose()

    return "$Directory\$folder\$filename"

    if($removeitem -eq "true"){ remove-item "$Directory\$filename" }

}

function Get-DefaultReturnCodes(){

@{"returnCode" = 0;"type" = "success"}, `
@{"returnCode" = 1707;"type" = "success"}, `
@{"returnCode" = 3010;"type" = "softReboot"}, `
@{"returnCode" = 1641;"type" = "hardReboot"}, `
@{"returnCode" = 1618;"type" = "retry"}

}
############################################################

function Get-DefaultAppInfo {
    $info = @{ "@odata.type" = "#microsoft.graph.win32LobApp" }
    $info.displayName = $null
    $info.description = $null
    $info.publisher = $null
    $info.largeIcon = $null
    $info.isFeatured = $false
    $info.privacyInformationUrl = $null
    $info.informationUrl = $null
    $info.owner = $null
    $info.notes = $null
    $info.fileName = "IntunePackage.intunewin"
    $info.installCommandLine = $null
    $info.uninstallCommandLine = $null
    $info.applicableArchitectures = "x64,x86"
    $info.minimumSupportedOperatingSystem = @{
        "v10_1607" = $true
    }
    $info.runAs32Bit = $false
    $info.rules = $null
    $info.installExperience = $null
    $info.returnCodes = Get-DefaultReturnCodes
    
    $info
}

function Create-AppInfo {
    param (
        $AppConfig,
        $IntuneDetectionConfig,
        $FileSize
    )
    
    # calc app info
    $app = Get-DefaultAppInfo
    
    $app.displayName = "$($AppConfig.applicationName) ($($AppConfig.appVersion))"
    $app.description = $AppConfig.description
    
    # calc install info
    $app.rules = @()
    if ($AppConfig.installInfo.ContainsKey("msi"))
    {
        $app.installExperience = @{ "runAsAccount" = $AppConfig.installInfo.runAsAccount }
        $app.setupFilePath = $AppConfig.installInfo.setupFile
        $app.uninstallCommandLine = "msiexec /x `"$($IntuneDetectionConfig.ApplicationInfo.MsiInfo.MsiProductCode)`""
        $app.installCommandLine = "msiexec /i `"$($AppConfig.installInfo.setupFile)`""
        
        $msiExecutionContext = $IntuneDetectionConfig.ApplicationInfo.MsiInfo.MsiExecutionContext
        $msiPackageType = "DualPurpose";
        if($msiExecutionContext -eq "System") { $msiPackageType = "PerMachine" }
        elseif($msiExecutionContext -eq "User") { $msiPackageType = "PerUser" }
        $app.msiInformation = @{
            "packageType" = "$msiPackageType"
            "productCode" = "$($IntuneDetectionConfig.ApplicationInfo.MsiInfo.MsiProductCode)"
            "productName" = "$($app.displayName)"
            "productVersion" = "$($IntuneDetectionConfig.ApplicationInfo.MsiInfo.MsiProductVersion)"
            "publisher" = "$($IntuneDetectionConfig.ApplicationInfo.MsiInfo.MsiPublisher)"
            "requiresReboot" = "$($IntuneDetectionConfig.ApplicationInfo.MsiInfo.MsiRequiresReboot)"
            "upgradeCode" = "$($IntuneDetectionConfig.ApplicationInfo.MsiInfo.MsiUpgradeCode)"
        }
        
        $detectionRule = @{
            "@odata.type" = "#microsoft.graph.win32LobAppProductCodeRule"
            "ruleType" = "detection"
            "productVersion" = $IntuneDetectionConfig.ApplicationInfo.MsiInfo.MsiProductVersion
            "productVersionOperator" = "equal"
            "productCode" = $IntuneDetectionConfig.ApplicationInfo.MsiInfo.MsiProductCode
            
        }
        $app.rules += ,$detectionRule
    }
    
    # calc assignments info
    $assignments = @()
    foreach ($target in $AppConfig.assignments.available)
    {
        $assign = @{ "@odata.type" = "#microsoft.graph.mobileAppAssignment" }
        $assign.intent = "available"
        $assign.target = @{
            "@odata.type" = "#microsoft.graph.groupAssignmentTarget"
            "groupId" = Get-TargetId $target
        }
        $assign.settings = @{ "@odata.type" = "#microsoft.graph.win32LobAppAssignmentSettings" }
        $assign.settings.notifications = "showAll"
        $assign.settings.restartSettings = $null
        $assign.settings.installTimeSettings = $null
        $assign.settings.deliveryOptimizationPriority = "notConfigured"
        
        $assignments += ,$assign
    }
    
    # calc commit
    $commit = @{
        "fileEncryptionInfo" = @{
            "encryptionKey" = $IntuneDetectionConfig.ApplicationInfo.EncryptionInfo.EncryptionKey
            "macKey" = $IntuneDetectionConfig.ApplicationInfo.EncryptionInfo.macKey
            "initializationVector" = $IntuneDetectionConfig.ApplicationInfo.EncryptionInfo.initializationVector
            "mac" = $IntuneDetectionConfig.ApplicationInfo.EncryptionInfo.mac
            "profileIdentifier" = "ProfileVersion1"
            "fileDigest" = $IntuneDetectionConfig.ApplicationInfo.EncryptionInfo.fileDigest
            "fileDigestAlgorithm" = $IntuneDetectionConfig.ApplicationInfo.EncryptionInfo.fileDigestAlgorithm
        }
    }
    
    # calc file
    $file = @{
        "@odata.type" = "#microsoft.graph.mobileAppContentFile"
        "isDependency" = $false
        "name" = $app.fileName
        "size" = [int64]$IntuneDetectionConfig.ApplicationInfo.UnencryptedContentSize
        "sizeEncrypted" = $FileSize
        "manifest" = $null
    }
    
    $appInfo = @{
        app = $app
        assignments = $assignments
        commit = $commit
        file = $file
    }
    
    $appInfo
}

function Create-Intunewin {
    param (
        $LocalSetupFiles,
        $RemoteSetupFiles,
        $SetupFilename
    )
    
    
    # TODO: do we need this
    Write-Host
    Write-Host "Getting permissions..." -ForegroundColor Yellow
    Test-AuthToken
    
    # create intune file
    Write-Host
    Write-Host "Creating application intune file..." -ForegroundColor Yellow
    $tempDir = "C:\adt_temp"
    if (Test-Path $tempDir)
    {
        Remove-Item -path $tempDir -recurse
    }
    New-Item -path "C:\" -name "adt_temp" -ItemType "directory"
    New-Item -path $tempDir -name "setup_files" -ItemType "directory"
    New-Item -path $tempDir -name "output" -ItemType "directory"
    $remoteDir = Join-Path -Path $tempDir -ChildPath "remote_files" # TODO: unused?!?
    $setupDir = Join-Path -Path $tempDir -ChildPath "setup_files"
    $outputDir = Join-Path -Path $tempDir -ChildPath "output"
    # Download remote 
    if ($RemoteSetupFiles -ne $null)
    {
        & $azcopyExe login status
        if ($LastExitCode -ne 0)
        {
            Write-Host
            Write-Host "Wake up! The instructions below require user interaction..." -ForegroundColor Yellow
            & $azcopyExe login
        }
        
        foreach ($dir in $RemoteSetupFiles)
        {
            & $azcopyExe copy "https://$storageAcc.blob.core.windows.net/$containerName/$dir/*" $setupDir --recursive
        }
    }
    # Copy local files
    if ($LocalSetupFiles -ne $null)
    {
        $allFilesInFolder = Join-Path -Path $LocalSetupFiles -ChildPath "*"
        Copy-Item -Path $allFilesInFolder -Destination $setupDir
    }
    # TODO: call app using absolute path
    $setupFile = $SetupFilename
    & $intuneWinAppUtilExe -c $setupDir -s $setupFile -o $outputDir
    # TODO: this feels very fragile - convert to function so it is easier to fix
    $intuneFile = Join-Path -Path $outputDir -ChildPath "$($setupFile -replace `"\.[^\.]*$`", `"`").intunewin"
    
    # Extract intune info
    $detectionXml = Get-IntuneWinXML $intuneFile -fileName "detection.xml"

    $intuneWinFile = Get-IntuneWinFile $intuneFile -fileName "$($detectionXml.ApplicationInfo.FileName)"
    $fileSize = (Get-Item "$intuneWinFile").Length
    
    $info = @{
        detectionXml = $detectionXml
        intuneWinFile = $intuneWinFile
        fileSize = $fileSize
    }
    
    return $info
}

function Upload-Intunewin {
    param (
        $AppId,
        $AppInfo,
        $IntuneWinFile
    )
    
    # TODO: do we need this?!?
    Write-Host
    Write-Host "Getting permissions..." -ForegroundColor Yellow
    Test-AuthToken
    
    $LOBType = "microsoft.graph.win32LobApp"

    $appInfo = $AppInfo
    
    # Get the content version for the new app (this will always be 1 until the new app is committed).
    Write-Host
    Write-Host "Creating Content Version in the service for the application..." -ForegroundColor Yellow
    $appId = $AppId
    $contentVersionUri = "mobileApps/$appId/$LOBType/contentVersions"
    $contentVersion = MakeRequest "POST" $contentVersionUri "{}"

    # Create a new file for the app.
    Write-Host
    Write-Host "Creating a new file entry in Azure for the upload..." -ForegroundColor Yellow
    $contentVersionId = $contentVersion.id
    $filesUri = "mobileApps/$appId/$LOBType/contentVersions/$contentVersionId/files"
    $file = MakeRequest "POST" $filesUri ($appInfo.file | ConvertTo-Json)
    
    # Wait for the service to process the new file request.
    Write-Host
    Write-Host "Waiting for the file entry URI to be created..." -ForegroundColor Yellow
    $fileId = $file.id
    $fileUri = "mobileApps/$appId/$LOBType/contentVersions/$contentVersionId/files/$fileId"
    $file = WaitForFileProcessing $fileUri "AzureStorageUriRequest"
    
    # Upload the content to Azure Storage.
    Write-Host
    Write-Host "Uploading file to Azure Storage..." -f Yellow

    $sasUri = $file.azureStorageUri
    $intuneWinFile = $IntuneWinFile
    UploadFileToAzureStorage $file.azureStorageUri "$intuneWinFile" $fileUri

    # Need to Add removal of IntuneWin file
    $IntuneWinFolder = [System.IO.Path]::GetDirectoryName("$intuneWinFile")
    Remove-Item "$intuneWinFile" -Force
    
    # Commit the file.
    Write-Host
    Write-Host "Committing the file into Azure Storage..." -ForegroundColor Yellow
    $commitFileUri = "mobileApps/$appId/$LOBType/contentVersions/$contentVersionId/files/$fileId/commit";
    MakeRequest "POST" $commitFileUri ($appInfo.commit | ConvertTo-Json);
    
    # Wait for the service to process the commit file request.
    Write-Host
    Write-Host "Waiting for the service to process the commit file request..." -ForegroundColor Yellow
    $file = WaitForFileProcessing $fileUri "CommitFile";

    # Commit the app.
    Write-Host
    Write-Host "Committing the file into Azure Storage..." -ForegroundColor Yellow
    $commitAppUri = "mobileApps/$appId";
    $commitAppBody = @{
        "@odata.type" = "#$LOBType"
        "committedContentVersion" = $contentVersionId
    }
    MakeRequest "PATCH" $commitAppUri ($commitAppBody | ConvertTo-Json);
    
    Write-Host "Sleeping for $sleep seconds to allow patch completion..." -f Magenta
    Start-Sleep $sleep
    Write-Host
}

function Add-Application {
    param (
        $LocalSetupFiles, # TODO: make this a list?!?
        $Config
    )

    
    # TODO: cleanup on failure
    # TODO: handle failure
    
    $appConfigContents = Get-Content -Path $config -Raw
    $appConfig = ConvertFrom-Yaml $appConfigContents
    # TODO: validate appConfig contents/format
    
    Write-Host
    Write-Host "Getting permissions..." -ForegroundColor Yellow
    Test-AuthToken
    
    # create intune file
    $intuneInfo = Create-Intunewin $LocalSetupFiles $appConfig.installInfo.remoteFilesPaths $appConfig.installInfo.setupFile 
    $detectionXml = $intuneInfo.detectionXml
    $fileSize = $intuneInfo.fileSize
    
    # Add new app
    $appInfo = Create-AppInfo $appConfig $detectionXml $fileSize
    Write-Host
    Write-Host "Creating application in Intune..." -ForegroundColor Yellow
    $mobileApp = MakeRequest "POST" "mobileApps" ($appInfo.app | ConvertTo-Json)
    
    $appId = $mobileApp.id
    
    Write-Host
    Write-Host "Adding assignments..." -ForegroundColor Yellow
    $listAssignmentsUri = "mobileApps/$appId/assignments"
    foreach ($target in $appInfo.assignments)
    {
        MakeRequest "POST" $listAssignmentsUri $($target | ConvertTo-Json)
    }
    
    
    # Upload intune file
    $intuneWinFile = $intune.infointuneWinFile
    Upload-Intunewin $appId $appInfo $intuneWinFile
    
    # Done!
    Write-Host
    Write-Host "Done..." -ForegroundColor Yellow
}

Export-ModuleMember -Function Add-Application

# SIG # Begin signature block
# MIIf7QYJKoZIhvcNAQcCoIIf3jCCH9oCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCBbUMAujIg9JG8j
# bgP4xgLeT7c8aaXYw3JT6k1q6KG3cqCCGbswggWRMIIEeaADAgECAhMVAAAACBly
# 8cTzWvVnAAEAAAAIMA0GCSqGSIb3DQEBDQUAMCMxITAfBgNVBAMTGEFEVC1ST09U
# Q0VSVDAxLUFEVENBMjAyMDAeFw0yMTEwMjQwNDQxMzlaFw0yMjEwMjQwNDUxMzla
# MG4xEjAQBgoJkiaJk/IsZAEZFgJhdTETMBEGCgmSJomT8ixkARkWA2NvbTETMBEG
# CgmSJomT8ixkARkWA2FkdDESMBAGCgmSJomT8ixkARkWAmFkMRowGAYDVQQDExFB
# RFQtQ0VSVFNFUlYwMS1DQTCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIB
# AM2UtdyF1E7J5Xnwr6184YOnk3wd3Vag6u+WVG/mrDvKWbVciJULlGbzsadIHDXH
# AVx4pePBjJigEwyzKQQXb4VcggwKG1zQBEYeqBvf72SrXkioGS9usdCZ7SwSETtC
# Hy5T8wmGkEOKzupfd29lhm5rzvJa+hnELU1UllOv7cRPCn9Q419MuaAYbY2XKA0e
# K21m4K8OtZXoRabRN620tu9iVQT/C9HkF+DglzGZ48SJFv2gxbFXNB0B+jlFrxRp
# OYRtd31XE5AeCrQ1J5sLKP1BCScHxWr3EGcMhAmbC65bc2iafKRnosq4ZV6AqGTL
# 4gdRVz3RvFnMzzfRnRwb6uJVMdkvEAWRm94vJspCndlTZaV81Zc0WI0ujWZXWRVj
# vDW4DxuhsSz5ryEvhFJPUHxOv4PDPaYYO/xwcBcAqKxx5JS21kiNGQkYsd/xz7Os
# lAE1YTPCxDnIGo+5Wz48y2zRhBTpdCVWbV4OwODlHhT2X8eQ1jiKXa6c6fUIRLue
# fkc/Co5BwWG71EfjUK6QJa8A5JiRCCkhAlnPE3cmOisonDSAMHO7oVbjK278ck7I
# nx/IhjKVIF2LzFdY8zVSCUgogATkuyvL7ftCpcu8lHpQGtzQpHoyuWTTIXHTdXtX
# Pey+88w4md8kJSZ09oOsQHDZYv2HICgrtjYz68j0BLC/AgMBAAGjggFxMIIBbTAQ
# BgkrBgEEAYI3FQEEAwIBAjAjBgkrBgEEAYI3FQIEFgQUO5+Yb02tXPYRajwUpz3s
# YNIfeX8wHQYDVR0OBBYEFBPx8yEcEeQdeZjQ8eAmAdi9Er8KMBkGCSsGAQQBgjcU
# AgQMHgoAUwB1AGIAQwBBMAsGA1UdDwQEAwIBhjAPBgNVHRMBAf8EBTADAQH/MB8G
# A1UdIwQYMBaAFF8c0yTQ7WUX8RdWYLh8XhabefUHME4GA1UdHwRHMEUwQ6BBoD+G
# PWh0dHA6Ly9jcmwuYWR0LmNvbS5hdS9DZXJ0RW5yb2xsL0FEVC1ST09UQ0VSVDAx
# LUFEVENBMjAyMC5jcmwwawYIKwYBBQUHAQEEXzBdMFsGCCsGAQUFBzAChk9odHRw
# Oi8vY3JsLmFkdC5jb20uYXUvQ2VydEVucm9sbC9BRFQtUk9PVENFUlQwMV9BRFQt
# Uk9PVENFUlQwMS1BRFRDQTIwMjAoMSkuY3J0MA0GCSqGSIb3DQEBDQUAA4IBAQAI
# ATHaD6F++qn0XiaGWj58OK+dUHDE832JzFR4tQEdiJQFe604dOvDsoQs+X51UrRk
# 3Yfl+sNEnzAzWhFRv5IjedtuMl011XfjDN995ogv899OqyG2fBgU6zGqFrZ3M4ka
# TRxnmeZ/A9X6ShNkqAcGP+frifm6FaVyk1jpBVmhEPD/rxNFjQZkymV0QZw3pGYW
# Dm06rZZje+mA048xzTknvTWPK17I3tCg0iqIEqewIPYUvy/v8qAhRzMcdWJGOPAE
# Vh7Nejqwc3QWQN2ZS6xqWhctInvOm5nOTXGj9xtNBFXa1Hcb3IFA9Tsqv4bqwGbQ
# ie34zzBmAitNy1H+DTCqMIIGODCCBCCgAwIBAgITOgAAASX5BO4qbgcSmgACAAAB
# JTANBgkqhkiG9w0BAQ0FADBuMRIwEAYKCZImiZPyLGQBGRYCYXUxEzARBgoJkiaJ
# k/IsZAEZFgNjb20xEzARBgoJkiaJk/IsZAEZFgNhZHQxEjAQBgoJkiaJk/IsZAEZ
# FgJhZDEaMBgGA1UEAxMRQURULUNFUlRTRVJWMDEtQ0EwHhcNMjExMDI5MDM1NDA4
# WhcNMjIxMDI0MDQ1MTM5WjCBhjESMBAGCgmSJomT8ixkARkWAmF1MRMwEQYKCZIm
# iZPyLGQBGRYDY29tMRMwEQYKCZImiZPyLGQBGRYDYWR0MRIwEAYKCZImiZPyLGQB
# GRYCYWQxDDAKBgNVBAsTA0FEVDEOMAwGA1UECxMFVXNlcnMxFDASBgNVBAMTC0ln
# b3IgRG9waXRhMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAlcSeKObD
# PkuodS8zlD3aHjgUy49YwjYLjIqiUJHYqlGdUrHT9Hy4xiRGFPMZ8kETK7dVXYe6
# DQrwP57a1wVrpv9gvBbeW2wFVNqbQn0rLoeaiUSUNjOuG1sP4VrjKxppqeLWImkE
# v0jgqF081QgVkFZ5pzGaMiGmhe3WqBM7OP+p4u0z/dAiEwyB1cMiMQjltz3TVtlH
# wfqPYahO3SfRTbLlrM9FDMr2E8O/Kn5trtc7Vws/nrx/py68ozP8omsaw+abj+y6
# HC0zBUg9lSUYzT0nUtlBwYG4efRtOQnTZ6D30CskoNGzqc6fdsOhA0HprmaDNEhi
# rmi29QRL7RzcUQIDAQABo4IBtDCCAbAwPAYJKwYBBAGCNxUHBC8wLQYlKwYBBAGC
# NxUIgcXOZoSihDKGnZMDg6+AcN75MVODncYZgfvgcwIBZAIBAzATBgNVHSUEDDAK
# BggrBgEFBQcDAzAOBgNVHQ8BAf8EBAMCB4AwGwYJKwYBBAGCNxUKBA4wDDAKBggr
# BgEFBQcDAzAxBgNVHREEKjAooCYGCisGAQQBgjcUAgOgGAwWaWdvci5kb3BpdGFA
# YWR0LmNvbS5hdTAdBgNVHQ4EFgQUjwBt76aoMAEXpmvH/EehrbbJ9v4wHwYDVR0j
# BBgwFoAUE/HzIRwR5B15mNDx4CYB2L0SvwowRwYDVR0fBEAwPjA8oDqgOIY2aHR0
# cDovL2NybC5hZHQuY29tLmF1L0NlcnRFbnJvbGwvQURULUNFUlRTRVJWMDEtQ0Eu
# Y3JsMHIGCCsGAQUFBwEBBGYwZDBiBggrBgEFBQcwAoZWaHR0cDovL2NybC5hZHQu
# Y29tLmF1L0NlcnRFbnJvbGwvQURULUNFUlRTRVJWMDEuYWQuYWR0LmNvbS5hdV9B
# RFQtQ0VSVFNFUlYwMS1DQSgyKS5jcnQwDQYJKoZIhvcNAQENBQADggIBACEyzX+3
# gil0lTlHcrsuPJV+nx4b5IUtQtvM8AKFWkIE86G+PJHLxIeiAjt7Pq5d+NzGEBBZ
# LZ51YDdh0uFBZLkhhp2QpG5jurS/DMQ90Y4cmx1/vPrx/xIYWnxwQ18b0/rTW+cO
# 4tk7wlGVOeq70tZwEnnPErPZmGQuHPbKRFL394MRC/4hixbiULmK7v5fx2o8I27C
# oo9AVg+JRvlyOXp66m5VyF+eVVauobDiAIkLsH2Qhp3m1MXkyd3uJI1b8DJOBNED
# snlaUwFmRZdkhAx0TbesXd7EOUzAaLOLkq90LWtHL43cra9zJvev3lqeRMdnEu5m
# 699ebzvte+OrlFrr2oVMZkN06sQuxsIYPatR0Vft0EW25OBK26rIfl3L5X8HLJLS
# pFtj5wqdAo7p/zvtS5HTG040PHpkwvNVTZSYzbGiiCNhBdXbR9j/6PFybyj7m+Di
# UmIUslzhhjFRiyqaP4HCebmYspvkbz6aPOrC2pKgmQ8Hm5nYI0EDlUv4+O0EmR8T
# WjZeg/y4b+KMBvrND6+zX/8S8npCoB7qNbOcix7I1ud5Xp6nONbN6zH7xtuU9dwJ
# 7NuxUcj4NaLS779YRJM2v+32YBThFiXbxjnuUst6k9uL17CHi7JVyR+C8Sg7NYQx
# pXo2x28FfmTz/+yre/xf+vGrIsqmpuhQrrBvMIIG7DCCBNSgAwIBAgIQMA9vrN1m
# mHR8qUY2p3gtuTANBgkqhkiG9w0BAQwFADCBiDELMAkGA1UEBhMCVVMxEzARBgNV
# BAgTCk5ldyBKZXJzZXkxFDASBgNVBAcTC0plcnNleSBDaXR5MR4wHAYDVQQKExVU
# aGUgVVNFUlRSVVNUIE5ldHdvcmsxLjAsBgNVBAMTJVVTRVJUcnVzdCBSU0EgQ2Vy
# dGlmaWNhdGlvbiBBdXRob3JpdHkwHhcNMTkwNTAyMDAwMDAwWhcNMzgwMTE4MjM1
# OTU5WjB9MQswCQYDVQQGEwJHQjEbMBkGA1UECBMSR3JlYXRlciBNYW5jaGVzdGVy
# MRAwDgYDVQQHEwdTYWxmb3JkMRgwFgYDVQQKEw9TZWN0aWdvIExpbWl0ZWQxJTAj
# BgNVBAMTHFNlY3RpZ28gUlNBIFRpbWUgU3RhbXBpbmcgQ0EwggIiMA0GCSqGSIb3
# DQEBAQUAA4ICDwAwggIKAoICAQDIGwGv2Sx+iJl9AZg/IJC9nIAhVJO5z6A+U++z
# WsB21hoEpc5Hg7XrxMxJNMvzRWW5+adkFiYJ+9UyUnkuyWPCE5u2hj8BBZJmbyGr
# 1XEQeYf0RirNxFrJ29ddSU1yVg/cyeNTmDoqHvzOWEnTv/M5u7mkI0Ks0BXDf56i
# XNc48RaycNOjxN+zxXKsLgp3/A2UUrf8H5VzJD0BKLwPDU+zkQGObp0ndVXRFzs0
# IXuXAZSvf4DP0REKV4TJf1bgvUacgr6Unb+0ILBgfrhN9Q0/29DqhYyKVnHRLZRM
# yIw80xSinL0m/9NTIMdgaZtYClT0Bef9Maz5yIUXx7gpGaQpL0bj3duRX58/Nj4O
# MGcrRrc1r5a+2kxgzKi7nw0U1BjEMJh0giHPYla1IXMSHv2qyghYh3ekFesZVf/Q
# OVQtJu5FGjpvzdeE8NfwKMVPZIMC1Pvi3vG8Aij0bdonigbSlofe6GsO8Ft96XZp
# kyAcSpcsdxkrk5WYnJee647BeFbGRCXfBhKaBi2fA179g6JTZ8qx+o2hZMmIklnL
# qEbAyfKm/31X2xJ2+opBJNQb/HKlFKLUrUMcpEmLQTkUAx4p+hulIq6lw02C0I3a
# a7fb9xhAV3PwcaP7Sn1FNsH3jYL6uckNU4B9+rY5WDLvbxhQiddPnTO9GrWdod6V
# QXqngwIDAQABo4IBWjCCAVYwHwYDVR0jBBgwFoAUU3m/WqorSs9UgOHYm8Cd8rID
# ZsswHQYDVR0OBBYEFBqh+GEZIA/DQXdFKI7RNV8GEgRVMA4GA1UdDwEB/wQEAwIB
# hjASBgNVHRMBAf8ECDAGAQH/AgEAMBMGA1UdJQQMMAoGCCsGAQUFBwMIMBEGA1Ud
# IAQKMAgwBgYEVR0gADBQBgNVHR8ESTBHMEWgQ6BBhj9odHRwOi8vY3JsLnVzZXJ0
# cnVzdC5jb20vVVNFUlRydXN0UlNBQ2VydGlmaWNhdGlvbkF1dGhvcml0eS5jcmww
# dgYIKwYBBQUHAQEEajBoMD8GCCsGAQUFBzAChjNodHRwOi8vY3J0LnVzZXJ0cnVz
# dC5jb20vVVNFUlRydXN0UlNBQWRkVHJ1c3RDQS5jcnQwJQYIKwYBBQUHMAGGGWh0
# dHA6Ly9vY3NwLnVzZXJ0cnVzdC5jb20wDQYJKoZIhvcNAQEMBQADggIBAG1UgaUz
# XRbhtVOBkXXfA3oyCy0lhBGysNsqfSoF9bw7J/RaoLlJWZApbGHLtVDb4n35nwDv
# QMOt0+LkVvlYQc/xQuUQff+wdB+PxlwJ+TNe6qAcJlhc87QRD9XVw+K81Vh4v0h2
# 4URnbY+wQxAPjeT5OGK/EwHFhaNMxcyyUzCVpNb0llYIuM1cfwGWvnJSajtCN3wW
# eDmTk5SbsdyybUFtZ83Jb5A9f0VywRsj1sJVhGbks8VmBvbz1kteraMrQoohkv6o
# b1olcGKBc2NeoLvY3NdK0z2vgwY4Eh0khy3k/ALWPncEvAQ2ted3y5wujSMYuaPC
# Rx3wXdahc1cFaJqnyTdlHb7qvNhCg0MFpYumCf/RoZSmTqo9CfUFbLfSZFrYKiLC
# S53xOV5M3kg9mzSWmglfjv33sVKRzj+J9hyhtal1H3G/W0NdZT1QgW6r8NDT/LKz
# H7aZlib0PHmLXGTMze4nmuWgwAxyh8FuTVrTHurwROYybxzrF06Uw3hlIDsPQaof
# 6aFBnf6xuKBlKjTg3qj5PObBMLvAoGMs/FwWAKjQxH/qEZ0eBsambTJdtDgJK0kH
# qv3sMNrxpy/Pt/360KOE2See+wFmd7lWEOEgbsausfm2usg1XTN2jvF8IAwqd661
# ogKGuinutFoAsYyr4/kKyVRd1LlqdJ69SK6YMIIG9jCCBN6gAwIBAgIRAJA5f5rS
# SjoT8r2RXwg4qUMwDQYJKoZIhvcNAQEMBQAwfTELMAkGA1UEBhMCR0IxGzAZBgNV
# BAgTEkdyZWF0ZXIgTWFuY2hlc3RlcjEQMA4GA1UEBxMHU2FsZm9yZDEYMBYGA1UE
# ChMPU2VjdGlnbyBMaW1pdGVkMSUwIwYDVQQDExxTZWN0aWdvIFJTQSBUaW1lIFN0
# YW1waW5nIENBMB4XDTIyMDUxMTAwMDAwMFoXDTMzMDgxMDIzNTk1OVowajELMAkG
# A1UEBhMCR0IxEzARBgNVBAgTCk1hbmNoZXN0ZXIxGDAWBgNVBAoTD1NlY3RpZ28g
# TGltaXRlZDEsMCoGA1UEAwwjU2VjdGlnbyBSU0EgVGltZSBTdGFtcGluZyBTaWdu
# ZXIgIzMwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQCQsnE/eeHUuYoX
# zMOXwpCUcu1aOm8BQ39zWiifJHygNUAG+pSvCqGDthPkSxUGXmqKIDRxe7slrT9b
# CqQfL2x9LmFR0IxZNz6mXfEeXYC22B9g480Saogfxv4Yy5NDVnrHzgPWAGQoViKx
# SxnS8JbJRB85XZywlu1aSY1+cuRDa3/JoD9sSq3VAE+9CriDxb2YLAd2AXBF3sPw
# Qmnq/ybMA0QfFijhanS2nEX6tjrOlNEfvYxlqv38wzzoDZw4ZtX8fR6bWYyRWkJX
# VVAWDUt0cu6gKjH8JgI0+WQbWf3jOtTouEEpdAE/DeATdysRPPs9zdDn4ZdbVfcq
# A23VzWLazpwe/OpwfeZ9S2jOWilh06BcJbOlJ2ijWP31LWvKX2THaygM2qx4Qd6S
# 7w/F7KvfLW8aVFFsM7ONWWDn3+gXIqN5QWLP/Hvzktqu4DxPD1rMbt8fvCKvtzgQ
# mjSnC//+HV6k8+4WOCs/rHaUQZ1kHfqA/QDh/vg61MNeu2lNcpnl8TItUfphrU3q
# Jo5t/KlImD7yRg1psbdu9AXbQQXGGMBQ5Pit/qxjYUeRvEa1RlNsxfThhieThDls
# deAdDHpZiy7L9GQsQkf0VFiFN+XHaafSJYuWv8at4L2xN/cf30J7qusc6es9Wt34
# 0pDVSZo6HYMaV38cAcLOHH3M+5YVxQIDAQABo4IBgjCCAX4wHwYDVR0jBBgwFoAU
# GqH4YRkgD8NBd0UojtE1XwYSBFUwHQYDVR0OBBYEFCUuaDxrmiskFKkfot8mOs8U
# pvHgMA4GA1UdDwEB/wQEAwIGwDAMBgNVHRMBAf8EAjAAMBYGA1UdJQEB/wQMMAoG
# CCsGAQUFBwMIMEoGA1UdIARDMEEwNQYMKwYBBAGyMQECAQMIMCUwIwYIKwYBBQUH
# AgEWF2h0dHBzOi8vc2VjdGlnby5jb20vQ1BTMAgGBmeBDAEEAjBEBgNVHR8EPTA7
# MDmgN6A1hjNodHRwOi8vY3JsLnNlY3RpZ28uY29tL1NlY3RpZ29SU0FUaW1lU3Rh
# bXBpbmdDQS5jcmwwdAYIKwYBBQUHAQEEaDBmMD8GCCsGAQUFBzAChjNodHRwOi8v
# Y3J0LnNlY3RpZ28uY29tL1NlY3RpZ29SU0FUaW1lU3RhbXBpbmdDQS5jcnQwIwYI
# KwYBBQUHMAGGF2h0dHA6Ly9vY3NwLnNlY3RpZ28uY29tMA0GCSqGSIb3DQEBDAUA
# A4ICAQBz2u1ocsvCuUChMbu0A6MtFHsk57RbFX2o6f2t0ZINfD02oGnZ85ow2qxp
# 1nRXJD9+DzzZ9cN5JWwm6I1ok87xd4k5f6gEBdo0wxTqnwhUq//EfpZsK9OU67Rs
# 4EVNLLL3OztatcH714l1bZhycvb3Byjz07LQ6xm+FSx4781FoADk+AR2u1fFkL53
# VJB0ngtPTcSqE4+XrwE1K8ubEXjp8vmJBDxO44ISYuu0RAx1QcIPNLiIncgi8RNq
# 2xgvbnitxAW06IQIkwf5fYP+aJg05Hflsc6MlGzbA20oBUd+my7wZPvbpAMxEHwa
# +zwZgNELcLlVX0e+OWTOt9ojVDLjRrIy2NIphskVXYCVrwL7tNEunTh8NeAPHO0b
# R0icImpVgtnyughlA+XxKfNIigkBTKZ58qK2GpmU65co4b59G6F87VaApvQiM5Dk
# hFP8KvrAp5eo6rWNes7k4EuhM6sLdqDVaRa3jma/X/ofxKh/p6FIFJENgvy9TZnt
# yeZsNv53Q5m4aS18YS/to7BJ/lu+aSSR/5P8V2mSS9kFP22GctOi0MBk0jpCwRoD
# +9DtmiG4P6+mslFU1UzFyh8SjVfGOe1c/+yfJnatZGZn6Kow4NKtt32xakEnbgOK
# o3TgigmCbr/j9re8ngspGGiBoZw/bhZZSxQJCZrmrr9gFd2G9TGCBYgwggWEAgEB
# MIGFMG4xEjAQBgoJkiaJk/IsZAEZFgJhdTETMBEGCgmSJomT8ixkARkWA2NvbTET
# MBEGCgmSJomT8ixkARkWA2FkdDESMBAGCgmSJomT8ixkARkWAmFkMRowGAYDVQQD
# ExFBRFQtQ0VSVFNFUlYwMS1DQQITOgAAASX5BO4qbgcSmgACAAABJTANBglghkgB
# ZQMEAgEFAKCBhDAYBgorBgEEAYI3AgEMMQowCKACgAChAoAAMBkGCSqGSIb3DQEJ
# AzEMBgorBgEEAYI3AgEEMBwGCisGAQQBgjcCAQsxDjAMBgorBgEEAYI3AgEVMC8G
# CSqGSIb3DQEJBDEiBCBDLAqc3TZuA6mTFch6+9BI+zfu/hMu1PeCjeHlNYhLczAN
# BgkqhkiG9w0BAQEFAASCAQBFKNO5Dn0gmC8WnPngyVUce2YMi4UgundHj4Mb3IJx
# sRVEmJzmH8oC45VQrSap5P8ILV5hYSEwcJ6YwAn3A880IaYq6UdJr7ZvsDNzMoeY
# I7mvNbBI5aU7wjoMtGulBu6dEcJ6gTRd4tcLNZtspyGT0Jkzp3FXnWIaeHmZW6cR
# NQyEv3Ociqp82wk3LU7eda5eYtBx9nSaIqUuW9dhYoDVyMCrznxhUuJ2v4rr3BRK
# iax2oIGzLlT7PweCTiGhH8SmzXXCelGitIcphSB55kQb61Drm+Y0x87+5/RpShi4
# uuW3zyxc1DwZAVJRP1FaOuoWrcU1Tni93MEkmAPoVjWMoYIDTDCCA0gGCSqGSIb3
# DQEJBjGCAzkwggM1AgEBMIGSMH0xCzAJBgNVBAYTAkdCMRswGQYDVQQIExJHcmVh
# dGVyIE1hbmNoZXN0ZXIxEDAOBgNVBAcTB1NhbGZvcmQxGDAWBgNVBAoTD1NlY3Rp
# Z28gTGltaXRlZDElMCMGA1UEAxMcU2VjdGlnbyBSU0EgVGltZSBTdGFtcGluZyBD
# QQIRAJA5f5rSSjoT8r2RXwg4qUMwDQYJYIZIAWUDBAICBQCgeTAYBgkqhkiG9w0B
# CQMxCwYJKoZIhvcNAQcBMBwGCSqGSIb3DQEJBTEPFw0yMjA1MjYwNjM3NDJaMD8G
# CSqGSIb3DQEJBDEyBDD4qyIiKJmPzGL7pKtes62itMQYlUp10h/DY1pdfNW3s+8w
# 6q56XWbu1SnZl4v/6rcwDQYJKoZIhvcNAQEBBQAEggIAXbuXgbJ7AZA0At3Bq02+
# 471hbtoV41ey6DYoxIujXaMEWnQ60o8DGAPNYmekODzUvioplx0Pjwcb2FdViqLU
# bYjzLqvOPla2K55lMpjueDVRQ0yxGQbcusEEPN0MNiJ1w4SpWjgRVDG4LbGEd+9p
# j56AeXt9te0yurEZRmWc4hPOj9X4nwv+QF2ufXL1KEMsGkF7keXwIuF9bcqr0/RR
# uWBmQSEt3SPj6dHrj8qwTZs2fqk7Ts6fyCU6yF3nFEp35iHGtJG418Xi2qU+Qqtr
# a8H18RyZNcAcZeJd4TCec0AMxGkXN4Ic5rP+eF3tBsEHDQgqTmlTnTwa8FUWuGva
# 0K+qR6q8vSxTCOV7YL42zrEl8fgyckQSqcVzK3ZJcLuQXsFpI/D98ljc9WPkd0E7
# ZRD5AYvkBynGouwLTivRW3OXg+ZTvrluxW4eVoQsamnrY5gCCnu+6xvMlKCpxodq
# uQaxB5vWZVGBiwXANYs9ew6ydO7Tzoa95tphdX6cPL9T62a/iLEL7Pm4dEeC22Ug
# 26NYVwG0Vm5ztHtMCeTcxCHMJMywgOvWaFZDsTIdzgH3kayKDaS4SSzofdOCxkr7
# 0dou7GJCSUTIUVxPqKqfIORi1/UuOZKZqM5W3iMs6UKowVX/9R0vl+VDgvJ4yMSl
# C0NOMhEBY2rbe1JOoi7UrvE=
# SIG # End signature block
