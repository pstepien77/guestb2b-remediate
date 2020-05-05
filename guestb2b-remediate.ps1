<#
.SYNOPSIS
   Remediate target service principals with following:

   1.	Add the selected dynamic group assignment to the service principal object with the "Default Access" role
   2.	Set AppRoleAssignmentRequired to "True"
   3.	Add "HideApp" value in the Tags property of target service principal
   Script includes verification, and roll-back funcionality

.DESCRIPTION
    Script is specifically developed as part of certain project, where selected list of service principal in target Azure tenant will be remediated in terms of authorization/access.
    Currently all type of users (including Guests) are able to authenticate against all applications (Service Principals).
    With this script, based on input service principal list, ability to authenticate for Guest users will be revoked - authentication will be allowed for users of Member type only (members of dedicated ALL-MEMBER-USERS-R* group).
    Additionally appliaction will be hidden.

.NOTES
	File Name: guestb2b-remediate.ps1
	Version:   1.3
	Author:    Piotr Stepien, March 3, 2020
	Requires:  AzureAD Preview PowerShell Module (or AzureAD), Established connection to the Azure AD Tenant, valid input file
	Run From:  Regular workstation

.INPUTS
    None. You cannot pipe objects to guestb2b-remediate.ps1 script.

.OUTPUTS
    None.

.PARAMETER verifygroup
	Switch parameter to start script in verification mode - verify if group [targetGroup] was assigned to all service principals from [inputFile]

.PARAMETER verifyoptions
	Switch parameter to start script in verification mode - verify if application is hidden, and user assignment is required on all service principals from [inputFile]

.PARAMETER fixgroup
	Switch parameter to start script in fix mode - assign [targetGroup] to all service principals from [inputFile]

.PARAMETER fixoptions
	Switch parameter to start script in fix mode - hide application, and set user assignment is required on all service principals from [inputFile]

.PARAMETER rollbackgroup
	Switch parameter to start script in rollback mode - remove [targetGroup] assignment from service principals from [inputFile]

.PARAMETER rollbackoptions
	Switch parameter to start script in rollback mode - unhide application, and set user assignment is not required on all service principals from [inputFile]

.EXAMPLE
    PS> guestb2b-remediate.ps1 -verifygroup -inputFile ".\QA.csv" -targetGroup "ALL-MEMBER-USERS-R1"
    Verify all Service Principals listed in input.csv from target tenant, and check if ALL-MEMBER-USERS-R1 group was assigned to all service principals from input file.
    Generate output .csv file with current assignment status as well.

.EXAMPLE
    PS> guestb2b-remediate.ps1 -fixoptions -inputFile ".\DEV.csv"
    Remediate all Service Principals listed in DEV.csv - hide application, and set User Assignment required to YES.

.EXAMPLE
    PS> guestb2b-remediate.ps1 -rollbackgroup -inputFile ".\UA-rollback.csv" -targetGroup "ALL-MEMBER-USERS"
    Rollback change on all Service Principals listed in EY-rollback.csv - remove ALL-MEMBER-USERS-R1 group from assignment only if it was assigned
#>
Param(
    <#
    Build ParameterSetNames according to below pattern:

    guestb2b-remediate.ps1 -verifygroup -inputFile <string> -targetGroup <string>
    guestb2b-remediate.ps1 -verifyoptions -inputFile <string>
    guestb2b-remediate.ps1 -fixgroup -inputFile <string> -targetGroup <string>
    guestb2b-remediate.ps1 -fixoptions -inputFile <string>
    guestb2b-remediate.ps1 -rollbackgroup -inputFile <string> -targetGroup <string>
    guestb2b-remediate.ps1 -rollbackoptions -inputFile <string>
    #>
    [Parameter(Mandatory = $true, ParameterSetName = "Verifyg+GroupAssigned")]
    [alias("vg")]
    [Switch] $verifygroup,

    [Parameter(Mandatory = $true, ParameterSetName = "Verifya+HideApplicationRequireAssignment")]
    [alias("vo")]
    [Switch] $verifyoptions,

    [Parameter(Mandatory = $true, ParameterSetName = "Fixg+GroupAssigned")]
    [alias("fg")]
    [Switch] $fixgroup,

    [Parameter(Mandatory = $true, ParameterSetName = "Fixa+HideApplicationRequireAssignment")]
    [alias("fo")]
    [Switch] $fixoptions,

    [Parameter(Mandatory = $true, ParameterSetName = "Rollbackg+GroupAssigned")]
    [alias("rg")]
    [switch] $rollbackgroup,

    [Parameter(Mandatory = $true, ParameterSetName = "Rollbacka+HideApplicationRequireAssignment")]
    [alias("ro")]
    [switch] $rollbackoptions,

    [Parameter(Mandatory = $true, ParameterSetName = "Verifyg+GroupAssigned")]
    [Parameter(Mandatory = $true, ParameterSetName = "Verifya+HideApplicationRequireAssignment")]
    [Parameter(Mandatory = $true, ParameterSetName = "Fixg+GroupAssigned")]
    [Parameter(Mandatory = $true, ParameterSetName = "Fixa+HideApplicationRequireAssignment")]
    [Parameter(Mandatory = $true, ParameterSetName = "Rollbackg+GroupAssigned")]
    [Parameter(Mandatory = $true, ParameterSetName = "Rollbacka+HideApplicationRequireAssignment")]
    [alias("i")]
    [String] $inputFile,

    [Parameter(Mandatory = $true, ParameterSetName = "Verifyg+GroupAssigned")]
    [Parameter(Mandatory = $true, ParameterSetName = "Fixg+GroupAssigned")]
    [Parameter(Mandatory = $true, ParameterSetName = "Rollbackg+GroupAssigned")]
    [alias("g")]
    [String] $targetGroup
)


# Create .\Logs folder in current directory if missing
$LogsFolder = "$PSScriptRoot\Logs"
New-Item -ItemType Directory -Force -Path $LogsFolder | Out-Null

# Generate current time-stamp
$DateTimeStamp = Get-Date -F yyyyMMddHHmmss

# Check if required PS module is loaded, exit if not
if (Get-Module -Name AzureAD) {
    Write-Host "AzureAD PowerShell Module loaded." -foregroundcolor Green
} elseif (Get-Module -Name AzureADPreview) {
    Write-Host "AzureADPreview Module loaded." -foregroundcolor Green
} else {
    Write-Host "Required AzureAD or AzureADPreview PowerShell module is not loaded. Hard Stop!" -Type "Error" -foregroundcolor Red
    Exit 1
}

# Verify connectivity to Azure AD, grab current Azure tenant display name
try {
    $var = Get-AzureADTenantDetail
    $targetTenant = $var.DisplayName
} catch [Microsoft.Open.Azure.AD.CommonLibrary.AadNeedAuthenticationException] { # hard stop - not connected to AAD
    Write-Host "You're not connected. Connect to target tenant first with Connect-AzureAD(). Hard Stop!" -foregroundcolor Red
    Exit 1
}
Write-Host "You are connected to $targetTenant Azure tenant." -foregroundcolor Green

# Verify if input file is readable
try {
    $check = Import-Csv $inputFile -ErrorAction Stop
} catch { # Hard stop - can't read input file
    Write-Host "Can't read input file! Hard stop." -foregroundcolor Red
    Exit 1
}

Write-Host "You are using $inputFile as input file for target operation." -foregroundcolor Green

# Go thru all ParameterSetName scenarios
switch ($PSCmdlet.ParameterSetName) {

    #############################################################
    # Verification part - check if dynamic group was assigned
    #############################################################
    "Verifyg+GroupAssigned" {
        Write-Host "Script is running in verification mode (verify if dynamic group $targetGroup was assigned)." -foregroundcolor Green

        # Verify if target dynamic group is present in tenant
        If ((Get-AzureADGroup -Filter "DisplayName eq '$targetGroup'").Count -ne 1) {
            Write-Host "Required group $targetGroup is not present in target Azure tenant or we have more than one group with same name. Hard Stop!" -foregroundcolor Red
            Exit 1
        } else {
            $targetGroupID=(Get-AzureADGroup -Filter "DisplayName eq '$targetGroup'").ObjectId
        }

        # Get all current assignments related to target dynamic group
        $currentGroupAssignments=Get-AzureADGroupAppRoleAssignment -All $true -ObjectId $targetGroupID | select-object ResourceDisplayName, ResourceId

        # Construct output file name under Logs folder, following pattern <tenant>-verifygroup-<base name of input file>-<time stamp>.csv
        $outputFile=".\Logs\$targetTenant-verifygroup-"+ [io.path]::GetFileNameWithoutExtension($inputFile) + "-$DateTimeStamp.csv"

        # Get the list of service principal object Ids from input file, generate output object which holds service principal object Id, dynamic group name,
        # and calculated status of assignment => TRUE if service principal object Id is present on the current assignment list of dynamic group as resource Id.
        # Then select all, and export to output file
        import-csv $inputFile | `
        select-object `
            @{name = 'ObjectId'; expression = {$_.ObjectId}}, `
            @{name = 'TargetGroup'; expression = {$targetGroup}}, `
            @{name = 'Assigned'; expression ={ $_.ObjectId -in $currentGroupAssignments.ResourceId}} | `
        select-object * | `
        export-csv -Path $outputFile -NoTypeInformation -Append

        Write-Host "`nVerification file : $outputFile`n" -foregroundcolor Gree
        break;
    }

    #############################################################
    # Verification part - check if options are set
    #############################################################
    "Verifya+HideApplicationRequireAssignment" {
        Write-Host "Script is running in verification mode (verify if application is hidden, and require assignment)." -foregroundcolor Green

        # Construct output file name under Logs folder, following pattern <tenant>-verifyoptions-<base name of input file>-<time stamp>.csv
        $outputFile=".\Logs\$targetTenant-verifyoptions-"+ [io.path]::GetFileNameWithoutExtension($inputFile) + "-$DateTimeStamp.csv"

        # Object to hold output data
        $verifyOutput = @()

        # Counter used for progress bar
        $verifiedPrincipals = 0

        # Import data, and count total number of service principal objects to process
        $inputData = import-csv $inputFile
        $totalServicePrincipals = $inputData.count

        # Loop thru all service principal object Ids
        foreach ($servicePrincipalId in $inputData.objectId) {

            # Display progress bar
            $verifiedPrincipals++
            [int]$intVerificationBar = [Math]::Round(([int]$verifiedPrincipals / [int]$totalServicePrincipals) * 100)
            Write-Progress -Activity "Verifying $servicePrincipalId" -Status "$intVerificationBar% Complete" -PercentComplete $intVerificationBar

            # Try to get current value of AppRoleAssignmentRequired, and verify if 'HideApp' tag is present
            try {
                $currentServicePrincipalObject = Get-AzureADServicePrincipal -ObjectId $servicePrincipalId
                $appRoleAssignmentRequired = $currentServicePrincipalObject.AppRoleAssignmentRequired
                $displayName = $currentServicePrincipalObject.DisplayName
                $Tags = $currentServicePrincipalObject.Tags
                $HiddenApp = $Tags.Contains('HideApp')


                # Construct output PSObject (service principal is present)
                $verifyObj = New-Object PSObject
                $verifyObj | Add-Member -MemberType NoteProperty -Name "ObjectId" -Value $servicePrincipalId
                $verifyObj | Add-Member -MemberType NoteProperty -Name "DisplayName" -Value $displayName
                $verifyObj | Add-Member -MemberType NoteProperty -Name "IsHidden" -Value $HiddenApp
                $verifyObj | Add-Member -MemberType NoteProperty -Name "IsAppRoleAssignmentRequired" -Value $appRoleAssignmentRequired
            } catch {
                # If above is not successful, assumption here that target service principal simply is not present in Azure tenant
                # Ask to remove service principal from input file, and exit from script
                Write-Host "Service principal $servicePrincipalId is not present in target tenant. Please remove it from input file." -foregroundcolor Red
                Exit 1
            }

            # Add verify object to final output objects
            $verifyOutput += $verifyObj
        }

        # Export to .csv file, and finish verification part
        $verifyOutput | Export-csv -NoTypeInformation $outputFile
        Write-Host "`nVerification file : $outputFile`n" -foregroundcolor Green

        break;
    }

    #############################################################
    # Fix part - assign target dynamic group
    #############################################################
    "Fixg+GroupAssigned" {
        Write-Host "Script is running in fix mode (assign $targetGroup to target service principal). This operation will alter AAD data." -foregroundcolor Red

        # Confirm that we are clear to go with remediation
        $reply = Read-Host -Prompt "Are you sure ? [y/n]"
        if ( $reply -notmatch "[yY]" ) {
            Write-Host "Aborted." -foregroundcolor Red
            Exit 1
        }

        # Verify if target dynamic group is present in tenant
        If ((Get-AzureADGroup -Filter "DisplayName eq '$targetGroup'").Count -ne 1) {
            Write-Host "Required group $targetGroup is not present in target Azure tenant. Hard Stop!" -foregroundcolor Red
            Exit 1
        } else {
            $targetGroupID=(Get-AzureADGroup -Filter "DisplayName eq '$targetGroup'").ObjectId
        }

        # Counter for progress bar
        $FixedPrincipals = 0

        # Import data, and count total number of service principal objects to process
        $inputData = import-csv $inputFile
        $totalServicePrincipals = $inputData.count

        # Loop thru all service principal object Ids
        foreach ($servicePrincipalId in $inputData.objectId) {

            # Display progress bar
            $FixedPrincipals++
            [int]$intVerificationBar = [Math]::Round(([int]$FixedPrincipals / [int]$totalServicePrincipals) * 100)
            Write-Progress -Activity "Fixing $servicePrincipalId" -Status "$intVerificationBar% Complete" -PercentComplete $intVerificationBar

            # Try to assign selected dynamic group to target service principal
            # Do the dummy catch to deal with service principals which have group assigned already
            Try {
                New-AzureADGroupAppRoleAssignment -ObjectId $targetGroupID -PrincipalId $targetGroupID -ResourceId $servicePrincipalId -Id ([Guid]::Empty) | Out-Null
            } Catch {}
        }

        Write-Host "`nRemediation completed. Please execute verification steps after 15 minutes.`n" -foregroundcolor Red
        break;
    }

    #############################################################
    # Fix part - set options to hide application, and require assignment
    #############################################################
    "Fixa+HideApplicationRequireAssignment" {
        Write-Host "Script is running in fix mode (hide application, and require assignment). This operation will alter AAD data." -foregroundcolor Red

        # Confirm that we are clear to go with remediation
        $reply = Read-Host -Prompt "Are you sure ? [y/n]"
        if ( $reply -notmatch "[yY]" ) {
            Write-Host "Aborted." -foregroundcolor Red
            Exit 1
        }

        # Counter for progress bar
        $verifiedPrincipals = 0

        # Import data, and count total number of service principal objects to process
        $inputData = import-csv $inputFile
        $totalServicePrincipals = $inputData.count

        # Loop thru all service principal object Ids
        foreach ($servicePrincipalId in $inputData.objectId) {

            # Display progress bar
            $verifiedPrincipals++
            [int]$intVerificationBar = [Math]::Round(([int]$verifiedPrincipals / [int]$totalServicePrincipals) * 100)
            Write-Progress -Activity "Fixing $servicePrincipalId" -Status "$intVerificationBar% Complete" -PercentComplete $intVerificationBar

            # Grab current tags object, add 'HideApp' to tags array, then remove duplicate objects as it is possible that application was hidden already
            # Then go back, and update service principals with amended tags object
            # Finally, set AppRoleAssignmentRequired to True
            $currentServicePrincipalObject = Get-AzureADServicePrincipal -ObjectId $servicePrincipalId
            $tags = $currentServicePrincipalObject.Tags
            $tags.Add("HideApp")
            $tags = $tags | select-object -Uniq
            Set-AzureADServicePrincipal -ObjectId $servicePrincipalId -Tags $tags
            Set-AzureADServicePrincipal -ObjectId $servicePrincipalId -AppRoleAssignmentRequired $true
        }

        Write-Host "`nRemediation completed. Please execute verification steps after 15 minutes.`n" -foregroundcolor Red
        break;
    }
    #############################################################
    # Rollback part - remove target dynamic group from assignment
    #############################################################
    "Rollbackg+GroupAssigned" {
        Write-Host "Script is running in roll-back mode (remove $targetGroup assignment from target service principal)." -foregroundcolor Yellow

        # Confirm that we are clear to go with remediation
        $reply = Read-Host -Prompt "Are you sure ? [y/n]"
        if ( $reply -notmatch "[yY]" ) {
            Write-Host "Aborted." -foregroundcolor Red
            Exit 1
        }

        # Verify if target dynamic group is present in tenant
        If ((Get-AzureADGroup -Filter "DisplayName eq '$targetGroup'").Count -ne 1) {
            Write-Host "Required group $targetGroup is not present in target Azure tenant. Hard Stop!" -foregroundcolor Red
            Exit 1
        } else {
            $targetGroupID=(Get-AzureADGroup -Filter "DisplayName eq '$targetGroup'").ObjectId
        }

        # Counter for progress bar
        $rolledbackPrincipals = 0

        # Import data, and count total number of service principal objects to process
        $inputData = import-csv $inputFile
        $totalServicePrincipals = $inputData.count

        # Loop thru all service principal object Ids
        foreach ($servicePrincipal in $inputData) {

            # Display progress bar
            $rolledbackPrincipals++
            [int]$intVerificationBar = [Math]::Round(([int]$rolledbackPrincipals / [int]$totalServicePrincipals) * 100)
            Write-Progress -Activity "Rolling-back $servicePrincipalId" -Status "$intVerificationBar% Complete" -PercentComplete $intVerificationBar

            # Fetch expected values from input file (original verification file)
            $TargetGroup = $servicePrincipal.TargetGroup
            $Assigned = $servicePrincipal.Assigned
            $ObjectId = $servicePrincipal.ObjectId

            # We have to remove group if initial status was FALSE, as only then it was assigned
            # Fine the assignment on all dynamic group assignment where resource Id to match service principal Id
            # Do the dummy catch for service principals not assigned
            If ($Assigned -eq $false) {
                try {
                    $targetAssignment = Get-AzureADGroupAppRoleAssignment -ObjectId $targetGroupID -All $true | Where-Object {$_.ResourceId -eq "$ObjectId"}
                    # Remove assignment from group
                    Remove-AzureADGroupAppRoleAssignment -ObjectId $targetGroupID -AppRoleAssignmentId $targetAssignment.ObjectId
                } catch { }
            }
        }

        Write-Host "`nRollback completed. Please execute verification steps after 15 minutes.`n" -foregroundcolor Yellow
        break;
    }

    #############################################################
    # Rollback part - unset both options - to hide application, and require assignment
    #############################################################
    "Rollbacka+HideApplicationRequireAssignment" {
        Write-Host  "Script is running in roll-back mode (unhide application, and do not require assignment)." -foregroundcolor Yellow

        $reply = Read-Host -Prompt "Are you sure ? [y/n]"
        if ( $reply -notmatch "[yY]" ) {
            Write-Host "Aborted." -foregroundcolor Red
            Exit 1
        }

        # Counter for progress bar
        $rolledbackPrincipals = 0

        # Import data, and count total number of service principal objects to process
        $inputData = import-csv $inputFile
        $totalServicePrincipals = $inputData.count

        # Loop thru all service principal object Ids
        foreach ($servicePrincipal in $inputData) {

            # Display progress bar
            $rolledbackPrincipals++
            [int]$intVerificationBar = [Math]::Round(([int]$rolledbackPrincipals / [int]$totalServicePrincipals) * 100)
            Write-Progress -Activity "Rolling-back $servicePrincipalId" -Status "$intVerificationBar% Complete" -PercentComplete $intVerificationBar

            # Fetch expected values from input file (original verification file)
            $IsHidden = $servicePrincipal.IsHidden
            $IsAppRoleAssignmentRequired = $servicePrincipal.IsAppRoleAssignmentRequired
            $ObjectId = $servicePrincipal.ObjectId

            # Fetch current values - current tags, and AppRoleAssignmentRequired status
            $currentServicePrincipalObject = Get-AzureADServicePrincipal -ObjectId $ObjectId
            $currentTags = $currentServicePrincipalObject.Tags
            $currentIsAppRoleAssignmentRequired = $currentServicePrincipalObject.AppRoleAssignmentRequired

            # Set AppRoleAssignmentRequired do expected values
            if ($IsAppRoleAssignmentRequired -eq $true) {
                Set-AzureADServicePrincipal -ObjectId $ObjectId -AppRoleAssignmentRequired $true
            } else {
                Set-AzureADServicePrincipal -ObjectId $ObjectId -AppRoleAssignmentRequired $false
            }

            # If IsHidden is set, means that initially app was hidden already. In theory we may do nothing, but to be on a safe side
            # add 'HideApp' tag to tags, remove duplicates, and update service principal
            if ($IsHidden -eq $true) {
                $currentTags.Add("HideApp")
                $currentTags = $currentTags | select-object -Uniq
            } else {
                # Initially app was not hidden, hence force tag removal, and update service principal
                $currentTags.remove("HideApp") | Out-Null
            }
            Set-AzureADServicePrincipal -ObjectId $ObjectId -Tags $currentTags
        }

        Write-Host "`nRollback completed. Please execute verification steps after 15 minutes.`n" -foregroundcolor Yellow
        break;
    }

} # end switch $PSCmdlet.ParameterSetName