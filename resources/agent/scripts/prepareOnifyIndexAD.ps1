param (
    [switch]$returnObjects = $false, 
    [switch]$deltaSync = $false, 
    [switch]$includeDeletedObjects = $false, 
    [switch]$useTemplate = $false, 
    [string[]]$arrSearchConfig
)

function Remove-DiacriticsAndSpaces
{
    Param(
        [String]$inputString
    )
    #replace diacritics
    $sb = [Text.Encoding]::ASCII.GetString([Text.Encoding]::GetEncoding("Cyrillic").GetBytes($inputString))

    #remove spaces and anything the above function may have missed
    return($sb -replace '[^a-zA-Z0-9]', '')
}

$InformationPreference = 'continue'
$scriptName = $MyInvocation.MyCommand.Name
$modulePath = (Join-Path -Path $PSScriptRoot -ChildPath .\Onify.ActiveDirectory -Resolve)
$logFile = "$modulePath\logs\$($scriptName)" + $((get-date).ToString("yyyy-MM-dd")) + ".log"

Import-Module $modulePath -Force
$templatePath = "$($modulePath)\templates"

Write-Log -Message ("Starting script - $($scriptName)..") -Path $logFile -Level "Info"

if (Test-Path "$($modulePath)\config.json") {
    $config = Get-Content -Raw -Path "$($modulePath)\config.json" | ConvertFrom-Json
    Write-Log -Message ("Imported config-file") -Path $logFile -Level "Info"
}
else {
    Write-Log -Message ("No config.json file found - Exiting script..") -Path $logFile -Level "Error"
    throw "No config.json file found - Exiting script.."
}

$result = @()
foreach ($domain in $config.domains) {
    $domainResult = @{
        'name' = $domain.domainName
        'searchConfig' = @(
        )
    }
    if (!(Test-Path "$($modulePath)\cache\$($domain.domainName)\usnCache.json")) {
        Write-Log -Message ("USN cache missing for $($domain.domainName) - no support for delta sync..") -Path $logFile -Level "Warn"  
        $deltaSync = $false
    }
    if ($arrSearchConfig) {
        $searchConfigs = ($domain.searchConfig | Where-Object { $arrSearchConfig -match $_.name })
        if ($searchConfigs) {
            $errSearchConfigs = (Compare-Object $arrSearchConfig $searchConfigs.name).InputObject
        }
        else {
            $errObj = @{
                'error' = 999
                'message' = "No search configs for '$($arrSearchConfig)' found in config-file"
            }
            $domainResult.searchConfig += $errObj
            $result += $domainResult
            Write-Log -Message ("No search configs for '$($arrSearchConfig)' found in config-file") -Path $logFile -Level "Error" 
            return $result
        }
    }
    else {
        $searchConfigs = $domain.searchConfig
    }
    foreach ($searchConfig in $searchConfigs) {
        if ($searchConfig.enabled) {
            if ($deltaSync) {
                if ($useTemplate) {
                    $template = $true
                    if (Test-Path "$($templatePath)\$($domain.domainName)\delta$($searchConfig.name).json") {
                         $adObjectBaseTemplate = Get-Content -Raw -Path "$($templatePath )\$($domain.domainName)\delta$($searchConfig.name).json" | ConvertFrom-Json
                    }
                    else {
                        $template = $false
                        Write-Log -Message ("No delta$($searchConfig.name).json for $($domain.domainName) template file found - skipping template..") -Path $logFile -Level "Warn"  
                    }
                }
            }
            else {
                if ($useTemplate) {
                    $template = $true
                    if (Test-Path "$($templatePath)\$($domain.domainName)\$($searchConfig.name).json") {
                         $adObjectBaseTemplate = Get-Content -Raw -Path "$($templatePath )\$($domain.domainName)\$($searchConfig.name).json" | ConvertFrom-Json
                    }
                    else {
                        $template = $false
                        Write-Log -Message ("No $($searchConfig.name).json for $($domain.domainName) template file found - skipping template..") -Path $logFile -Level "Warn"   
                    }
                }
            }
            #Write-Information "Get AD objects from search config '$($searchConfig.name)' in $($domain.domainName).."
            $adObjects = foreach($searchBase in $searchConfig.searchBases) {
                if ($searchBase.enabled) {
                    if ($deltaSync) {
                        if ($includeDeletedObjects) {
                            Get-ADDSObject -LDAPFilter $searchBase.ldapFilter -SearchBase $searchBase.searchBase -DomainName $domain.domainName -Property $searchBase.property -Delta -IncludeDeletedObjects
                        }
                        else {
                            Get-ADDSObject -LDAPFilter $searchBase.ldapFilter -SearchBase $searchBase.searchBase -DomainName $domain.domainName -Property $searchBase.property -Delta 
                        }
                    }
                    else {
                        Get-ADDSObject -LDAPFilter $searchBase.ldapFilter -SearchBase $searchBase.searchBase -DomainName $domain.domainName -Property $searchBase.property
                    }
                }
            }
            $usnCache = Get-Content -Raw -Path "$($modulePath)\cache\$($domain.domainName)\usnCache.json" | ConvertFrom-Json
            if ($adObjects) {
                $adObjects = ($adObjects | Sort-Object -Unique objectGuid)
                Write-Log -Message ("Preparing $($adObjects.Count) objects for indexing in Onify") -Path $logFile -Level "Info"
                $onifyADObjects = foreach ($adObject in $adObjects) {
                    if (($useTemplate) -and ($template)) {
                        $adObjectTemplate = $adObjectBaseTemplate | ConvertTo-Json | ConvertFrom-Json
                        if ($adObject.Enabled -eq $false) { 
                            $status = "Disabled"
                        }
                        elseif ($adObject.LockedOut -eq $true) {
                            $status = "Locked"
                        }
                        elseif ($adObject.AccountExpirationDate) {
                            if ((get-date) -ge $adObject.AccountExpirationDate) {
                                $status = "Exipred"
                            }
                        }
                        else {
                            $status = "Active"
                        }
                        $adObjectTemplate.status = $($status)
                        $adObjectTemplate.color = $searchConfig.statusColor."$($status)"
                        foreach($adObjectProp in $adObjectTemplate.PsObject.Properties) {
                            if ($adObjectProp.TypeNameOfValue -eq "System.Management.Automation.PSCustomObject") {
                                foreach ($prop in $adObjectProp.Value.PsObject.Properties) {
                                    $regexMatches = [regex]::Matches($prop.Value,"\<(.*?)\>")
                                    if ($regexMatches) {
                                        foreach ($match in $regexMatches) {
                                            if ($adObject.PsObject.Properties.Name.ToLower().Contains(("$($match.Value)" -replace "[\<\>]",""))){ 
                                                $adObjectTemplate."$($adObjectProp.Name)"."$($prop.Name)" = $adObjectTemplate."$($adObjectProp.Name)"."$($prop.Name)" -replace "$($match.Value)",$adObject.("$($match.Value)" -replace "[\<\>]","")
                                            }
                                            else {
                                                $adObjectTemplate."$($adObjectProp.Name)"."$($prop.Name)" = $adObjectTemplate."$($adObjectProp.Name)"."$($prop.Name)" -replace "$($match.Value)",""
                                            }
                                        }
                                    }
                                }
                            }
                            else {
                                $regexMatches = [regex]::Matches($adObjectProp.Value,"\<(.*?)\>")
                                if ($regexMatches) {
                                    foreach ($match in $regexMatches) {
                                        if ($adObject.PsObject.Properties.Name.ToLower().Contains(("$($match.Value)" -replace "[\<\>]",""))){
                                            $adObjectTemplate."$($adObjectProp.Name)" = $adObjectTemplate."$($adObjectProp.Name)" -replace "$($match.Value)",$adObject.("$($match.Value)" -replace "[\<\>]","")
                                        }
                                        else {
                                            $adObjectTemplate."$($adObjectProp.Name)" = $adObjectTemplate."$($adObjectProp.Name)" -replace "$($match.Value)",""
                                        }
                                    }
                                }
                            }   
                        }
                        $adObjectTemplate
                    }
                    else {
                        $adObject
                    }
                }

                if ($searchConfig.cache) {
                    if ($deltaSync) {
                        Write-Log -Message ("Writing delta AD cache for '$($searchConfig.name)' search config $($domain.domainName)..") -Path $logFile -Level "Info"
                        $filePath = "$($modulePath)\cache\$($domain.domainName)\$($usnCache.HighestCommittedUSN)_$($domain.domainName)_$($searchConfig.name)_adCache_delta.json"
                        (ConvertTo-Json $onifyADObjects -Depth 5) | Out-File $filePath -Encoding UTF8
                    }
                    else {
                        Write-Log -Message ("Writing full AD cache for '$($searchConfig.name)' search config in $($domain.domainName)..") -Path $logFile -Level "Info"
                        $usnCache = Get-Content -Raw -Path "$($modulePath)\cache\$($domain.domainName)\usnCache.json" | ConvertFrom-Json
                        $filePath = "$($modulePath)\cache\$($domain.domainName)\$($usnCache.HighestCommittedUSN)_$($domain.domainName)_$($searchConfig.name)_adCache_full.json"
                        (ConvertTo-Json $onifyADObjects -Depth 5) | Out-File $filePath -Encoding UTF8
                    }
                    $searchConfigResult = @{
                        $($searchConfig.name) = @{
                            'error' = 0
                            'message' = $null
                            'filePath' = $filePath
                        }
                    }
                    $domainResult.searchConfig += $searchConfigResult
                }
            }
            else {
                if ($deltaSync) {
                    $message = "No AD objects created, modified or deleted since latest 'HighestCommitedUSN: $($usnCache.HighestCommittedUSN)' for search config '$($searchConfig.name)' in $($domain.domainName).."
                    Write-Log -Message $message -Path $logFile -Level "Info"
                    $searchConfigResult = @{
                        $($searchConfig.name) = @{
                            'error' = 998
                            'message' = $message
                        }
                    }
                    $domainResult.searchConfig += $searchConfigResult
                }
                else {
                    $message = "No AD objects found for search config '$($searchConfig.name)' in $($domain.domainName).."
                    Write-Log -Message $message -Path $logFile -Level "Info"
                    $searchConfigResult = @{
                        $($searchConfig.name) = @{
                            'error' = 998
                            'message' = $message
                        }
                    }
                    $domainResult.searchConfig += $searchConfigResult
                }
            }
        }
    }
    if ($returnObjects) {
        $domainResult.ADObjects = $onifyADObjects
    }
    if ($errSearchConfigs) {
        foreach ($errSearchConfig in $errSearchConfigs) {
            $errConfigResult = @{
                $errSearchConfig = @{
                    'error' = 999
                    'message' = "No search config for '$($errSearchConfig)' found in config-file for $($domain.domainName)"
                }
            }
            $domainResult.searchConfig += $errConfigResult
        }
    }
    $result += $domainResult
}

Write-Log -Message "Script-result $($result | ConvertTo-Json -Depth 10)" -Path $logFile -Level "Info"
return ($result | ConvertTo-Json -Depth 10)
