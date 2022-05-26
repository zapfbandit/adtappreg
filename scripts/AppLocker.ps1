#49676f7220697320746865206265737465737420636f64657220696e2074686520776f726c642021#
#                                                                                #
#  Classification: ADT-CONFIDENTIAL/ENGINEERING                                  #
#  File:           Installers/IsoCreator/AppLocker.ps1                           #
#  Modified:       Wed May 25 15:40:50 AUSEST 2022                               #
#  Author:         igor.dopita@adt.com.au                                        #
#                                                                                #
#  The contents of this file (including this header) belongs to ADT RnD Pty Ltd  #
#  This code must not be distributed, used, reproduced or modified for any       #
#  purpose without the explicit permission of ADT.                               #
#                                                                                #
#  Copyright and all Rights Reserved ADT RnD Pty Ltd                             #
#                                                                                #
#4f7572732c2062757420776520776f6e74206265206675636b6564206966206974206c65616b730a#


function CreateAppLockerPolicy {param([string]$sid, [string]$appLockerXmlPath, [string]$folderPath)

   $appLockerXmlPath = $appLockerXmlPath.trim("`"")
   $folderPath = $folderPath.trim("`"")

   Write-Output "**************************************************************************"
   Write-Output "Creating Applocker configuration `"$appLockerXmlPath`" for `"$folderPath`""
   Write-Output "**************************************************************************"

   $hashRegExp = "^SHA256 (.*)$";

   Remove-Item $appLockerXmlPath -ErrorAction SilentlyContinue
   
   echo "<AppLockerPolicy Version=`"1`">`n" > $appLockerXmlPath
   
   $allFiles = get-childitem $folderPath -recurse

   $types = @("Exe", "Msi", "Dll")
   foreach ($type in $types)
   {      
      $files = $allFiles | where {$_.extension -like ".$type"}
      
      if ($files.Count -gt 0)
      {
         $fileHashBody = ""
         
         foreach ($file in $files)
         {
            $filePath = $file.FullName
            
            $signInfo = Get-AppLockerFileInformation -path $filePath
            if ($signInfo -ne $null)
            {
               $fileInfo = Get-ChildItem $filePath
                  
               $fileName = $fileInfo.Name
               $fileSize = $fileInfo.Length
               
               $hashInfo = $signInfo.Hash
               
               $ok = $hashInfo -match $hashRegExp
               if ($ok -eq $true)
               {
                  $hash = $matches[1]
               }
               else
               {
                  Write-Information "Hash reg exp didn't match for $filePath ($hashInfo)" -InformationAction Continue
               }
               
               if ($fileHashBody -ne "")
               {
                  $fileHashBody += "`n"
               }
               $fileHashBody += "          <FileHash Type=`"SHA256`" Data=`"$hash`" SourceFileName=`"$fileName`" SourceFileLength=`"$fileSize`" />"
            }
            else
            {
               Write-Information "Unable to gather app locker info for $filepath" -InformationAction Continue
            }
         }

         $guid = [guid]::NewGuid().ToString()

         $fileHashHeader = @"
    <FileHashRule Id=`"$guid`" Name=`"$name`" Description=`"$name`" UserOrGroupSid=`"$sid`" Action=`"Allow`">
      <Conditions>
        <FileHashCondition>
"@
              
         $fileHashFooter = @"
        </FileHashCondition>
      </Conditions>
    </FileHashRule>
       
"@

         echo "  <RuleCollection Type=`"$type`" EnforcementMode=`"Enabled`">`n" >> $appLockerXmlPath
         
         if ($fileHashBody -ne "")
         {
            echo $fileHashHeader $fileHashBody $fileHashFooter >> $appLockerXmlPath
         }
         
         echo "  </RuleCollection>`n" >> $appLockerXmlPath
      }
   }

   echo "</AppLockerPolicy>" >> $appLockerXmlPath
}
