#49676f7220697320746865206265737465737420636f64657220696e2074686520776f726c642021#
#                                                                                #
#  Classification: ADT-CONFIDENTIAL/ENGINEERING                                  #
#  File:           Installers/IsoCreator/Common.ps1                              #
#  Modified:       Wed May 25 15:40:51 AUSEST 2022                               #
#  Author:         igor.dopita@adt.com.au                                        #
#                                                                                #
#  The contents of this file (including this header) belongs to ADT RnD Pty Ltd  #
#  This code must not be distributed, used, reproduced or modified for any       #
#  purpose without the explicit permission of ADT.                               #
#                                                                                #
#  Copyright and all Rights Reserved ADT RnD Pty Ltd                             #
#                                                                                #
#4f7572732c2062757420776520776f6e74206265206675636b6564206966206974206c65616b730a#

$name = "adtappreg"
$loc  = "australiacentral"

$storageAccountName = "adtappregacc"
$storageContainerName = "adtappregcont"

$subscriptionName = "ADTTest01"

$rgGroup  = $name + "-rg"

$sid = "S-1-1-0"

# Functions

function ShowIt($txt)
{
   Write-Output "**************************************************************************"
   Write-Output $txt
   Write-Output "**************************************************************************"
}


function UploadFile($filePath, $azDest)
{
   ShowIt("Uploading `"$filePath`" to $storageAccountName/$storageContainerName/$azDest")
   
   $fileName = $(Split-Path $filePath -leaf)
   
   echo "$filePath"
   echo "$fileName"
   echo "$azDest/$fileName"
   
   $storageAccount = Get-AzStorageAccount `
      -ResourceGroupName $rgGroup `
      -Name $storageAccountName;
      
   if ($storageAccount -eq $null)
   {
      Write-Output "Unable to locate Storage Account ($storageAccountName), unable to continue..."
      exit -1
   }

   $storageContext = $storageAccount.Context
      
   Set-AzStorageBlobContent `
      -Context $storageContext `
      -Container $storageContainerName `
      -File "$filePath" `
      -Blob "$azDest/$fileName" `
      -Force;
}


function GetFile($filePath, $azSrc)
{
   ShowIt("Download `"$filePath`" from $storageAccountName/$storageContainerName/$azSrc")

   $fileName = $(Split-Path $filePath -leaf)
   
   echo "$filePath"
   echo "$fileName"
   echo "$azDest/$fileName"
   
   $storageAccount = Get-AzStorageAccount `
      -ResourceGroupName $rgGroup `
      -Name $storageAccountName;
      
   if ($storageAccount -eq $null)
   {
      Write-Output "Unable to locate Storage Account ($storageAccountName), unable to continue..."
      exit -1
   }

   $storageContext = $storageAccount.Context
   
   Get-AzStorageBlobContent `
      -Context $storageContext `
      -Container $storageContainerName `
      -Blob $azSrc/$fileName `
      -Destination "$PSScriptRoot" `
      -Force;
}


function GetPackages
{
   # Only try and install packages if we are in admin mode   
   if (([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole( `
        [Security.Principal.WindowsBuiltInRole] "Administrator") -eq $true)
   {
      $nuGetInfo = Get-PackageProvider "NuGet" -ErrorAction SilentlyContinue
      $nuGetVers = $nuGetInfo.version
      if ($nuGetVers -lt "2.8.5.201")
      {
         ShowIt("Installing NuGet package provider (at least version 2.8.5.201)")
         Install-PackageProvider -Name "NuGet" -Force
      }

      $azResInfo = Get-Package "Az.Storage" -ErrorAction SilentlyContinue
      if ($azResInfo -eq $null)
      {
         ShowIt("Installing Az.Storage module")
         Install-Module -Name "Az.Storage" -Force
      }

       $azResInfo = Get-Package "Az.Resources" -ErrorAction SilentlyContinue
      if ($azResInfo -eq $null)
      {
         ShowIt("Installing Az.Resources module")
         Install-Module -Name "Az.Resources" -Force
      }
   }
}


function _LoginWithFlag($useManagedId)
{
   $connected = $null
   
   if ($useManagedId -eq $true)
   {
      ShowIt("Connecting to Azure using the managed identity")
      $connected = Login-AzAccount -identity
   }
   else
   {
      ShowIt("Connecting to Azure using subscription `"$subscriptionName`"")
      $connected = Login-AzAccount -SubscriptionName "$subscriptionName"
   }
   
   if ($connected -eq $null)
   {
      Write-Output "Unable to continue"
      pause
      exit -1
   }
}


function LoginAsManagedId
{
   _LoginWithFlag($true)
}


function LoginAsSubscription
{
   _LoginWithFlag($false)
}


function LocateStorage
{
   ShowIt("Locating the Resource Group ($rgGroup)")
   $resourceGroup = Get-AzResourceGroup `
      -Name $rgGroup;
      
   if ($resourceGroup -eq $null)
   {
      ShowIt("Creating the Resource group ($rgGroup) since it was not found.")
      $storageAccount = New-AzResourceGroup `
         -Name $rgGroup `
         -location $loc;
   }
   
   ShowIt("Locating the Storage Account ($storageAccountName)")
   $storageAccount = Get-AzStorageAccount `
      -ResourceGroupName $rgGroup `
      -Name $storageAccountName;
      
   if ($storageAccount -eq $null)
   {
      ShowIt("Creating the Storage Account ($storageAccountName) since it was not found.")
      $storageAccount = New-AzStorageAccount `
         -ResourceGroupName $rgGroup `
         -Name $storageAccountName `
         -SkuName "Standard_GRS"`
         -location $loc;
   }

   $context = $storageAccount.Context

   ShowIt("Locating the Storage Container ($storageContainerName)")
   $storageContainer = Get-AzStorageContainer `
      -Name $storageContainerName `
      -Context $context;
      
   if ($storageContainer -eq $null)
   {
      ShowIt("Creating the Storage Container ($storageContainerName) since it was not found.")
      $storageContainer = New-AzStorageContainer `
         -Name $storageContainerName `
         -Context $context;
   }
}
