$scriptName = $MyInvocation.MyCommand.Name
$logFile = "$PSScriptRoot\logs\$($scriptName)" + $((get-date).ToString("yyyy-MM-dd")) + ".log"

function Get-ADDSObject {
    [cmdletbinding()]
    param(
        [parameter(Mandatory = $true)]
        [string]$LDAPFilter,
        
        [parameter(Mandatory = $false)]
        [ValidatePattern("^(?:(?<cn>CN=(?<name>(?:[^,]|\,)*)),)?(?:(?<path>(?:(?:CN|OU)=(?:[^,]|\,)+,?)+),)?(?<domain>(?:DC=(?:[^,]|\,)+,?)+)$")]
        [string]$SearchBase,

        [parameter(Mandatory = $false)]
        [string]$DomainName,

        [parameter(Mandatory = $false)]
        [string[]]$Property,

        [parameter(Mandatory = $false)]
        [UInt32]$PageSize = 100,

        [Parameter(Mandatory=$false)]
        [switch]$Delta
    )
    
    DynamicParam {
        if ($delta) {
            $dynamicParamDictionary = New-Object System.Management.Automation.RuntimeDefinedParameterDictionary
            $includeDeletedObjectsAttribute = New-Object System.Management.Automation.ParameterAttribute -Property @{
                Mandatory = $false
            }
            $attributeCollection = new-object System.Collections.ObjectModel.Collection[System.Attribute]  
            $attributeCollection.Add($includeDeletedObjectsAttribute)
            $includeDeletedObjectsParam = New-Object System.Management.Automation.RuntimeDefinedParameter('IncludeDeletedObjects',[switch],$attributeCollection)
            $dynamicParamDictionary.Add('IncludeDeletedObjects',$includeDeletedObjectsParam)
            return $dynamicParamDictionary
        }
    }

    Process {
        if ($PSBoundParameters.IncludeDeletedObjects) {
            $IncludeDeletedObjects = $true
        }
	    try {
            if (Test-Path "$($PSScriptRoot)\config.json") {
                $config = Get-Content -Raw -Path "$($PSScriptRoot)\config.json" | ConvertFrom-Json
            }
            else {
                Write-Log -Message ("No config.json file found - no support for delta sync") -Path $logFile -Level "Error"
            }
            if ($config) {
                if ($domainName) {
                    $domainConfig = $config.domains.domainName | Where-Object { $_.DomainName -eq $DomainName }
                    if (!$domainConfig) {
                        $domainConfig = $config.domains[0]
                    }
                }
                else {
                    $domainConfig = $config.domains[0]
                }
                if (!(Test-Path "$($PSScriptRoot)\cache\$($domainConfig.domainName)\usnCache.json")) {
                    Write-Log -Message ("Write highestCommitedUSN to cache..") -Path $logFile -Level "Info"
				    $RootDSE = [ADSI] "LDAP://$($domainConfig.domainController)/RootDSE"
                    (@{"DomainController"=$($domainConfig.domainController);"HighestCommittedUSN"= [Int64]$RootDSE.HighestCommittedUSN[0]} | ConvertTo-Json) | Out-File "$($PSScriptRoot)\cache\$($domainConfig.domainName)\usnCache.json" -Encoding UTF8
                }
                if ($delta) {
                    Write-Log -Message ("Fetching delta AD objects with LDAPFilter: $($ldapFilter) in SearchBase: $($searchBase)") -Path $logFile -Level "Info"
                    $usnCache = Get-Content -Raw -Path "$($PSScriptRoot)\cache\$($domainConfig.domainName)\usnCache.json" | ConvertFrom-Json
                    $deltaLdapFilter = $($ldapFilter.substring(0,$ldapFilter.LastIndexOf(')')))+"(!IsDeleted=*)(!USNChanged<=$($usnCache.HighestCommittedUSN)))"

                    $domain = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$($domainConfig.domainController)/$($searchBase)")
                    $directorySearcher = New-Object -TypeName System.DirectoryServices.DirectorySearcher -ArgumentList ([ADSI] "LDAP://$($domainConfig.domainController)/$($domainConfig.domainDN)")
                    $directorySearcher.Sort.PropertyName = "USNChanged"
                    $directorySearcher.PageSize = 1000
                    $directorySearcher.Tombstone = $true
                    $directorySearcher.Filter = $deltaLdapFilter
                    $directorySearcher.SearchScope = "Subtree"
                    $directorySearcher.SearchRoot = $domain

                    switch ($deltaLdapFilter)
                    {
                        { $_.Contains("objectClass=user") } { $property += @("DistinguishedName", "GivenName", "UserAccountControl", "Name", "ObjectClass", "ObjectGUID", "SamaccountName", "ObjectSID", "Sn", "UserPrincipalName", "msds-user-account-control-computed", "Enabled","USNChanged","USNCreated") }
                        { $_.Contains("objectClass=computer") } { $property += @("DistinguishedName", "DNSHostName", "UserAccountControl", "Name", "ObjectClass", "ObjectGUID", "SamaccountName", "ObjectSID", "UserPrincipalName","USNChanged","USNCreated") }
                        { $_.Contains("objectClass=group") } { $property += @("DistinguishedName", "GroupType", "Name", "ObjectClass", "ObjectGUID", "SamaccountName", "ObjectSID","USNChanged","USNCreated") }
                        { $_.Contains("objectClass=organizationalunit") } { $property += @("DistinguishedName", "Name", "ObjectClass", "ObjectGUID","USNChanged","USNCreated") }
                        default { $property += @("DistinguishedName", "Name", "ObjectClass", "ObjectGUID","USNChanged","USNCreated") }
                    }
                    $property = $property | ConvertTo-DSADProperty | Sort-Object -Unique
                    foreach ($prop in $property) { 
	                    $directorySearcher.PropertiesToLoad.Add($prop) | out-null
                    }
                    [array]$objArr = $directorySearcher.FindAll() | ForEach-Object {
			            $deltaObject = Expand-DSADEntry -ADObject $_ -Property $Property
                        $deltaObject | Add-Member -MemberType NoteProperty -Name 'Action' -Value ""
                        if ($_.Properties.usncreated -ge $usnCache.HighestCommittedUSN)
                        {
                            $deltaObject.Action = "CREATE"
                        }
                        else
                        {
                            $deltaObject.Action = "MODIFY"
                        }
                        $deltaObject
		            }
                
                    if ($IncludeDeletedObjects) {
                        switch ($ldapFilter)
                        {
                            { $_.Contains("objectClass=user") } { $deletedObjLdapFilter = "(&(objectClass=user)(IsDeleted=TRUE)(!USNChanged<=$($usnCache.HighestCommittedUSN)))" }
                            { $_.Contains("objectClass=computer") } { $deletedObjLdapFilter = "(&(objectClass=computer)(IsDeleted=TRUE)(!USNChanged<=$($usnCache.HighestCommittedUSN)))" }
                            { $_.Contains("objectClass=group") } { $deletedObjLdapFilter = "(&(objectClass=group)(IsDeleted=TRUE)(!USNChanged<=$($usnCache.HighestCommittedUSN)))" }
                            { $_.Contains("objectClass=organizationalunit") } { $deletedObjLdapFilter = "(&(objectClass=organizationalunit)(IsDeleted=TRUE)(!USNChanged<=$($usnCache.HighestCommittedUSN)))"  }
                            default { $deletedObjLdapFilter = "(&(IsDeleted=TRUE)(!USNChanged<=$($usnCache.HighestCommittedUSN)))" }
                        }

                        $directorySearcher = New-Object -TypeName System.DirectoryServices.DirectorySearcher -ArgumentList ([ADSI] "LDAP://$($domainConfig.domainController)/$($domainConfig.domainDN)")
                        $directorySearcher.Sort.PropertyName = "USNChanged"
                        $directorySearcher.PageSize = 1000
                        $directorySearcher.Tombstone = $true
                        $directorySearcher.Filter = $deletedObjLdapFilter
                        $directorySearcher.SearchScope = "Subtree"

                        $property = @("DistinguishedName", "Name", "ObjectClass", "ObjectGUID","USNChanged","USNCreated","IsDeleted","msDS-LastKnownRDN","LastKnownParent")

                        foreach ($prop in $property) { 
	                        $directorySearcher.PropertiesToLoad.Add($prop) | out-null
                        }
                        [array]$objArr += $directorySearcher.FindAll() | ForEach-Object {
			                $deletedObj = Expand-DSADEntry -ADObject $_ -Property $Property
                            $deletedObj | Add-Member -MemberType NoteProperty -Name 'Action' -Value "DELETE"
                            $deletedObj | Add-Member -MemberType NoteProperty -Name 'OldCN' -Value ($_.Properties.distinguishedname.split("\")[0] + "," + $_.Properties.lastknownparent)
                            $deletedObj
		                }
                    }
                    if ($objArr) {
                        Write-Log -Message ("Fetched $($objArr.Count) delta objects with LDAPFilter: $($ldapFilter) in SearchBase: $($searchBase)") -Path $logFile -Level "Info"
                        $objArr
                    }
			    }	
                else {
                    Write-Log -Message ("Fetching AD objects with LDAPFilter: $($ldapFilter) in SearchBase: $($searchBase)") -Path $logFile -Level "Info"
                    $domain = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$($domainConfig.domainController)/$($searchBase)")
		            $directorySearcher = New-Object System.DirectoryServices.DirectorySearcher($domain)
		            $directorySearcher.Filter = $ldapFilter
		            $directorySearcher.SearchScope = "Subtree"
		            $directorySearcher.SearchRoot = $domain
		            $directorySearcher.PageSize = $pageSize
		            switch ($ldapFilter)
                    {
                        { $_.Contains("objectClass=user") } { $property += @("DistinguishedName", "GivenName", "UserAccountControl", "Name", "ObjectClass", "ObjectGUID", "SamaccountName", "ObjectSID", "Sn", "UserPrincipalName", "msds-user-account-control-computed", "Enabled") }
                        { $_.Contains("objectClass=computer") } { $property += @("DistinguishedName", "DNSHostName", "UserAccountControl", "Name", "ObjectClass", "ObjectGUID", "SamaccountName", "ObjectSID", "UserPrincipalName") }
                        { $_.Contains("objectClass=group") } { $property += @("DistinguishedName", "GroupType", "Name", "ObjectClass", "ObjectGUID", "SamaccountName", "ObjectSID") }
                        { $_.Contains("objectClass=organizationalunit") } { $property += @("DistinguishedName", "Name", "ObjectClass", "ObjectGUID") }
                        default { $property += @("DistinguishedName", "Name", "ObjectClass", "ObjectGUID") }
                    }
		            $property = $property | ConvertTo-DSADProperty | Sort-Object -Unique
		            foreach ($prop in $property) { 
			            $directorySearcher.PropertiesToLoad.Add($prop) | out-null
		            }
		            [array]$objArr = $directorySearcher.FindAll() | ForEach-Object {
			            Expand-DSADEntry -ADObject $_ -Property $Property
		            }
                    $RootDSE = [ADSI]"LDAP://$($domainConfig.domaincontroller)/RootDSE"
                    $usnCache = Get-Content -Raw -Path "$($PSScriptRoot)\cache\$($domainConfig.domainName)\usnCache.json" | ConvertFrom-Json
                    if ([Int64]$RootDSE.HighestCommittedUSN[0] -ne $usnCache.HighestCommittedUSN) {
                        Write-Log -Message ("Write highestCommitedUSN to cache..") -Path $logFile -Level "Info"
				        (@{"DomainController"=$($domainConfig.domainController);"HighestCommittedUSN"= [Int64]$RootDSE.HighestCommittedUSN[0]} | ConvertTo-Json) | Out-File "$($PSScriptRoot)\cache\$($domainConfig.domainName)\usnCache.json" -Encoding UTF8
                    }
		            if ($objArr) {
                        Write-Log -Message ("Fetched $($objArr.Count) AD objects with LDAPFilter: $($ldapFilter) in SearchBase: $($searchBase)") -Path $logFile -Level "Info"
                        $objArr
                    }
                }
            
            }
            else {
                if ($SearchBase) {
                    Write-Log -Message ("Fetching AD objects with LDAPFilter: $($ldapFilter) in SearchBase: $($searchBase)") -Path $logFile -Level "Info"
                    $domain = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$searchBase")
                }
                else {
                    Write-Log -Message ("Fetching AD objects with LDAPFilter: $($ldapFilter)") -Path $logFile -Level "Info"
                    $RootDSE = [System.DirectoryServices.DirectoryEntry]([ADSI]"LDAP://RootDSE")
                    $domain = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$($RootDSE.Get("defaultNamingContext"))")
                }
		        $directorySearcher = New-Object System.DirectoryServices.DirectorySearcher($domain)
		        $directorySearcher.Filter = $ldapFilter
		        $directorySearcher.SearchScope = "Subtree"
		        $directorySearcher.SearchRoot = $domain
		        $directorySearcher.PageSize = $pageSize
		        switch ($ldapFilter)
                {
                    { $_.Contains("objectClass=user") } { $property += @("DistinguishedName", "GivenName", "UserAccountControl", "Name", "ObjectClass", "ObjectGUID", "SamaccountName", "ObjectSID", "Sn", "UserPrincipalName", "msds-user-account-control-computed", "Enabled") }
                    { $_.Contains("objectClass=computer") } { $property += @("DistinguishedName", "DNSHostName", "UserAccountControl", "Name", "ObjectClass", "ObjectGUID", "SamaccountName", "ObjectSID", "UserPrincipalName") }
                    { $_.Contains("objectClass=group") } { $property += @("DistinguishedName", "GroupType", "Name", "ObjectClass", "ObjectGUID", "SamaccountName", "ObjectSID") }
                    { $_.Contains("objectClass=organizationalunit") } { $property += @("DistinguishedName", "Name", "ObjectClass", "ObjectGUID") }
                    default { $property += @("DistinguishedName", "Name", "ObjectClass", "ObjectGUID") }
                }
		        $property = $property | ConvertTo-DSADProperty | Sort-Object -Unique
		        foreach ($prop in $property) { 
			        $directorySearcher.PropertiesToLoad.Add($prop) | out-null
		        }
		        [array]$objArr = $directorySearcher.FindAll() | ForEach-Object {
			        Expand-DSADEntry -ADObject $_ -Property $Property
		        }
		        if ($objArr) {
                    Write-Log -Message ("Fetched $($objArr.Count) AD objects with LDAPFilter: $($ldapFilter)") -Path $logFile -Level "Info"
                    $objArr
                }
		    }
	    }
	    catch {
		    throw $_
	    }
    }
}

function Expand-DSADEntry
{
    param(
        [parameter(Mandatory = $true, ValueFromPipeLine = $true)]
        $ADObject,

        [parameter(Mandatory = $true)]
        [string[]]$Property,

        [switch]$Force
    )
    $encoding = [System.Text.Encoding]::UTF8

    $value = @{}
    [int]$propertyNo = 0

    $propertyNo++
    #$psObject = New-Object PSObject
    $hashObject = @{}
    $getSid = $ADObject.Properties['objectsid']

    if ([string]$getSid) {
        $sid = $getSID.Clone()              
        $objectSID = (New-Object -TypeName System.Security.Principal.SecurityIdentifier -ArgumentList @([byte[]]$sid, 0)).Value
    } else {
        $objectSID = $null
    }

    foreach ($prop in $Property) {
        try {
            $propertyNo++    
            if ($ADObject.Properties.Contains($prop)) {
                if ($prop -match "objectclass") {
                    $value[$propertyNo] = $($ADObject.Properties[$prop])[-1]
                } elseif ($prop -eq "objectguid") {
                    $value[$propertyNo] = ([guid][byte[]]$($ADObject.Properties[$prop])).ToString()
                } elseif ($prop -eq "objectsid") {
                    $value[$propertyNo]=$objectSID
                } elseif ($prop -eq "memberof") {
                    for ($index = 0; $index -lt $ADObject.Properties[$prop].Count; $index++) {
                        [string[]]$value[$propertyNo] += $ADObject.Properties[$prop][$index].ToString();
                    }
                } elseif ($prop -eq "member") {
                    for ($index = 0; $index -lt $ADObject.Properties[$prop].Count; $index++)
                    {
                    [string[]]$value[$propertyNo] += $ADObject.Properties[$prop][$index].ToString();
                    }
                } elseif ($prop -eq "UserAccountControl") {
                    if ($property -contains "Enabled") {
                        if (($($ADObject.Properties[$prop][0]) -band 0x0002) -eq 0) {
                            $accountEnabled = $true
                        } else {
                            $accountEnabled = $false
                        }
                        $hashObject["Enabled"] = $accountEnabled
                    }
                    if ($property -contains "Script") {
                        if (($($ADObject.Properties[$prop][0]) -band 0x0001) -eq 0) {
                            $script = $false
                        } else {
                            $script = $true
                        }
                        $hashObject["Script"] = $script
                    }
                    if ($property -contains "Disabled") {
                        if (($($ADObject.Properties[$prop][0]) -band 0x0002) -eq 0) {
                            $accountDisabled = $false
                        } else {
                            $accountDisabled = $true
                        }
                        $hashObject["Disabled"] = $accountDisabled
                    }
                    if ($property -contains "HomeDirectoryRequired") {
                        if (($($ADObject.Properties[$prop][0]) -band 0x0008) -eq 0) {
                            $homeDirectoryRequired = $false
                        } else {
                            $homeDirectoryRequired = $true
                        }
                        $hashObject["HomeDirectoryRequired"] = $homeDirectoryRequired
                    }

                    if ($property -contains "PasswordNotRequired") {
                        if (($($ADObject.Properties[$prop][0]) -band 0x0020) -eq 0) {
                            $passwordNotRequired = $false
                        } else {
                            $passwordNotRequired = $true
                        }
                        $hashObject.PasswordNotRequired = $passwordNotRequired
                    }
                    if ($property -contains "PasswordCannotChange") {
                        if (($($ADObject.Properties[$prop][0]) -band 0x0040) -eq 0) {
                            $passwordCannotChange = $false
                        } else {
                            $passwordCannotChange = $true
                        }
                        $hashObject["PasswordCannotChange"] = $passwordCannotChange
                    }
                    if ($property -contains "EncyptedTextPasswordAllowed") {
                        if (($($ADObject.Properties[$prop][0]) -band 0x0080) -eq 0) {
                            $encryptedTextPasswordAllowed = $false
                        } else {
                            $encryptedTextPasswordAllowed = $true
                        }
                        $hashObject["EncyptedTextPasswordAllowed"] = $encryptedTextPasswordAllowed
                    }
                    if ($property -contains "TempDuplicateAccount") {
                        if (($($ADObject.Properties[$prop][0]) -band 0x0100) -eq 0) {
                            $tempDuplicateAccount = $false
                        } else {
                            $tempDuplicateAccount = $true
                        }
                        $hashObject["TempDuplicateAccount"] = $tempDuplicateAccount
                    }
                    if ($property -contains "NormalAccount") {
                        if (($($ADObject.Properties[$prop][0]) -band 0x0200) -eq 0) {
                            $normalAccount = $false
                        } else {
                            $normalAccount = $true
                        }
                        $hashObject["NormalAccount"] = $normalAccount
                    }
                    if ($property -contains "InterDomainTrustAccount") {
                        if (($($ADObject.Properties[$prop][0]) -band 0x0800) -eq 0) {
                            $interdomainTrustAccount = $false
                        } else {
                            $interdomainTrustAccount = $true
                        }
                        $hashObject["InterDomainTrustAccount"] = $interdomainTrustAccount
                    }
                    if ($property -contains "WorkstationTrustAccount") {
                        if (($($ADObject.Properties[$prop][0]) -band 0x1000) -eq 0) {
                            $workstationTrustAccount = $false
                        } else {
                            $workstationTrustAccount = $true
                        }
                        $hashObject["WorkstationTrustAccount"] = $workstationTrustAccount
                    }
                    if ($property -contains "ServerTrustAccount") {
                        if (($($ADObject.Properties[$prop][0]) -band 0x2000) -eq 0) {
                            $serverTrustAccount = $false
                        } else {
                            $serverTrustAccount = $true
                        }
                        $hashObject["ServerTrustAccount"] = $serverTrustAccount
                    }
                    if ($property -contains "PasswordNeverExpires") {
                        if (($($ADObject.Properties[$prop][0]) -band 0x10000) -eq 0) {
                            $dontExpirePassword = $false
                        } else {
                            $dontExpirePassword = $true
                        }
                        $hashObject["PasswordNeverExpires"] = $dontExpirePassword
                    }
                    if ($property -contains "MnsLogonAccount") {
                        if (($($ADObject.Properties[$prop][0]) -band 0x20000) -eq 0) {
                            $mnsLogonAccount = $false
                        } else {
                            $mnsLogonAccount = $true
                        }
                        $hashObject["MnsLogonAccount"] = $mnsLogonAccount
                    }
                    if ($property -contains "SmartCardRequired") {
                        if (($($ADObject.Properties[$prop][0]) -band 0x40000) -eq 0) {
                            $smartcardRequired = $false
                        } else {
                            $smartcardRequired = $true
                        }
                        $hashObject["SmartCardRequired"] = $smartcardRequired
                    }
                    if ($property -contains "TrustedForDelegation") {
                        if (($($ADObject.Properties[$prop][0]) -band 0x80000) -eq 0) {
                            $trustedForDelegation = $false
                        } else {
                            $trustedForDelegation = $true
                        }
                        $hashObject["TrustedForDelegation"] = $trustedForDelegation
                    }
                    if ($property -contains "NotDelegated") {
                        if (($($ADObject.Properties[$prop][0]) -band 0x100000) -eq 0) {
                            $notDelegated = $false
                        } else {
                            $notDelegated = $true
                        }
                        $hashObject["NotDelegated"] = $notDelegated
                    }
                    if ($property -contains "DesKeyOnly") {
                        if (($($ADObject.Properties[$prop][0]) -band 0x200000) -eq 0) {
                            $useDesKeyOnly = $false
                        } else {
                            $useDesKeyOnly = $true
                        }
                        $hashObject["DesKeyOnly"] = $useDesKeyOnly
                    }
                    if ($property -contains "DontRequirePreAuth") {
                        if (($($ADObject.Properties[$prop][0]) -band 0x400000) -eq 0) {
                            $dontRequirePreauth = $false
                        } else {
                            $dontRequirePreauth = $true
                        }
                        $hashObject["DontRequirePreAuth"] = $dontRequirePreauth
                    }
                    if ($property -contains "PasswordExpired") {
                        if($property -contains "msds-user-account-control-computed") {
                            $passwordexpiredflagcontainer = "msds-user-account-control-computed"
                        } else {
                                $passwordexpiredflagcontainer = $prop
                        }
                        if (($($ADObject.Properties[$passwordexpiredflagcontainer][0]) -band 0x800000) -eq 0) {
                            $passwordExpired = $false
                        } else {
                            $passwordExpired = $true
                        }
                        $hashObject["PasswordExpired"] = $passwordExpired
                    }
                    if ($property -contains "TrustedToAuthenticateForDelegation") {
                        if (($($ADObject.Properties[$prop][0]) -band 0x1000000) -eq 0) {
                            $trustedToAuthenticateForDelegation = $false
                        } else {
                            $trustedToAuthenticateForDelegation = $true
                        }
                        $hashObject["TrustedToAuthenticateForDelegation"] = $trustedToAuthenticateForDelegation
                    }
                    continue
                } elseif ($prop -eq "grouptype") {
                    switch ($ADObject.Properties[$prop][0]) {
                        2 {
                            $hashObject["GroupCategory"] = "Distribution"
                            $hashObject["GroupScope"] = "Global"
                        }
                        4 {
                            $hashObject["GroupCategory"] = "Distribution"
                            $hashObject["GroupScope"] = "Local"
                        }
                        8 {
                            $hashObject["GroupCategory"] = "Distribution"
                            $hashObject["GroupScope"] = "Universal"
                            }
                        -2147483646 {
                                        $hashObject["GroupCategory"] = "Security"
                                        $hashObject["GroupScope"] = "Global"
                                    }
                        -2147483644 {
                                        $hashObject["GroupCategory"] = "Security"
                                        $hashObject["GroupScope"] = "Local"
                                    }
                        -2147483640 {
                                        $hashObject["GroupCategory"] = "Security"
                                        $hashObject["GroupScope"] = "Universal"
                                    }
                    }
                    continue
                } elseif ($prop -eq "msds-user-account-control-computed") {
                    if ($property -contains "LockedOut") {
                        if ($ADObject.Properties[$prop][0] -band 16) {
                            $hashObject["LockedOut"] = $true
                                
                        } else {
                            $hashObject["LockedOut"] = $false
                                
                        }
                    }
                    Continue
                } elseif ($prop -eq "accountexpires") {
                    $value[$propertyNo] = $($ADObject.Properties[$prop])
                    if (!$psObject.AccountExpirationDate) {
                        $convertedValue = $value[$propertyNo] -as [int64]
                        $accountExpires = ConvertTo-DSADDate $convertedValue
                        $hashObject["AccountExpirationDate"] = $accountExpires
                    }
                } elseif ($prop -eq "lastlogontimestamp") {
                    $value[$propertyNo] = $($ADObject.Properties[$prop])
                    $convertedValue = $value[$propertyNo] -as [int64]
                    $lastLogonDate = ConvertTo-DSADDate $convertedValue
                    $hashObject["LastLogonDate"] = $lastLogonDate

                } elseif ($prop -eq "PwdLastSet") {
                    $value[$propertyNo] = $($ADObject.Properties[$prop])
                    if ($value[$propertyNo] -eq 0) {
                        $changePasswordAtNextLogon = $true
                    } else {
                        $changePasswordAtNextLogon = $false
                    }
                    $hashObject["ChangePasswordAtNextLogon"] = $changePasswordAtNextLogon

                } elseif ($prop -eq "LockoutTime") {                        
                    $value[$propertyNo] = $($ADObject.Properties[$prop])
                    if ($value[$propertyNo]) {
                        $convertedValue = $value[$propertyNo] -as [int64]
                        $lockOutTime = ConvertTo-DSADDate $convertedValue
                        $hashObject["AccountLockoutTime"] = $lockOutTime
                    }
                } elseif ($prop -eq "Enabled") {

                } elseif ($prop -eq "thumbnailPhoto") {
                    $value[$propertyNo] = ($ADObject.Properties[$prop])[0]
                    if ($value[$propertyNo]) {
				        $hashObject["thumbnailPhoto"] = $value[$propertyNo]
                    }
		        } else {
                    if (-not([string]::IsNullOrEmpty($prop) ) ) {
                        if ((($ADObject.Properties[$prop]) -as [array]).Count -ne 1) {
                            $itemCount = (($ADObject.Properties[$prop]) -as [array]).Count
                            for ($i = 0; $i -lt $itemCount; $i++) {
                                [array]$value[$propertyNo] += ($ADObject.Properties[$prop])[$i]
                            }
                        } elseif ($($ADObject.Properties[$prop]) -match '^\d{14}\.\d\w$') {
                            $value[$propertyNo] = $($ADObject.Properties[$prop])
                            $dateTime = [DateTime]::ParseExact($value[$propertyNo], "yyyyMMddHHmmss.f'Z'", [cultureInfo]::InvariantCulture)
                            $hashObject[$prop] = $dateTime
                            continue
                        } else {
                            $value[$propertyNo] = $($ADObject.Properties[$prop])
                        }

                    }
                }
                if ($prop -notmatch "groupcategory|groupscope") {
                    $hashObject[$prop] = $value[$propertyNo]
                }
            }
         }
         catch {
            $_
         }    
    }
    $psObject = [PSCustomObject]$hashObject
    if([string]$psObject.ObjectGUID) {
        $psObject
    } 
}

function ConvertTo-DSADDate
{
    param (
        [Parameter(ValueFromPipeline=$true, Mandatory=$true)]
        [int64]$Value
    )

    process {
        $lngValue = $value
        if (($lngValue -eq 0) -or ($lngValue -gt [DateTime]::MaxValue.Ticks)) {
            $acctExpire = $null
        } else {
            $date = [DateTime]$lngValue
            $acctExpire = $Date.AddYears(1600).ToLocalTime()
        }
        $acctExpire
    }
}

function ConvertTo-DSADProperty
{
    param (
        [parameter(Mandatory = $true, ValueFromPipeLine = $true)]
        [string]$Property
    )

    process {
        switch ($Property) {
            "Office" { "PhysicalDeliveryOfficeName"; break }
            "Organization" { "O"; break }
            "EmailAddress" { "Mail"; break }
            "Fax" { "FacsimileTelephoneNumber"; break }
            "OfficePhone" { "TelephoneNumber"; break }
            "State" { "ST"; break }
            "City" { "L"; break }
            "MobilePhone" { "Mobile"; break }
            "OtherName" { "MiddleName"; break }
            "HomePage" { "WWWHomePage"; break }
            "POBox" { "PostOfficeBox"; break }
            "AccountLockoutTime" { "LockoutTime"; break }
            Default { $_ }
        }
    }
}

function Write-Log { 
    [CmdletBinding()] 
    Param 
    ( 
        [Parameter(Mandatory=$true, 
        ValueFromPipelineByPropertyName=$true)] 
        [ValidateNotNullOrEmpty()] 
        [Alias("LogContent")] 
        [string]$Message, 
 
        [Parameter(Mandatory=$false)] 
        [Alias('LogPath')] 
        [string]$Path,
         
        [Parameter(Mandatory=$false)] 
        [ValidateSet("Error","Warn","Info","Debug")] 
        [string]$Level="Info"
    ) 
 
    Process 
    { 
        if (!(Test-Path $Path)) { 
            $NewLogFile = New-Item $Path -Force -ItemType File 
        } 
        $FormattedDate = Get-Date -Format "yyyy-MM-dd HH:mm:ss" 
        switch ($Level) { 
            'Error' { 
                #Write-Warning $Message 
                #Write-Error $Message 
                $LevelText = 'ERROR:' 
                } 
            'Warn' { 
                #Write-Warning $Message 
                $LevelText = 'WARNING:' 
                } 
            'Info' { 
                #Write-Verbose $Message 
                $LevelText = 'INFO:' 
                } 
            'Debug' { 
                    #Write-Verbose $Message 
                    $LevelText = 'DEBUG:' 
            } 
        }
        if ($Level -eq "Debug" -AND $global:LogLevel -ne "debug") {
            return
        }
        if ($global:pipeline) {
            $LevelText = $global:pipeline + " " + $LevelText
        }
        #"$FormattedDate $LevelText $Message" | Out-File -FilePath $Path -Append 
        Add-Content -Path $Path -Value ("$FormattedDate $LevelText $Message") -Encoding utf8
        if ($global:ConsoleLogging) {
            "$FormattedDate $LevelText $Message"
        }

    } 

}