#Requires -Modules @{ ModuleName = 'Microsoft.Graph'; ModuleVersion = '1.27.0' }
#Requires -Modules @{ ModuleName = 'AzAuth'; ModuleVersion = '2.2.1' }
# Require modules with versions tested, might work with earlier versions
# https://api.azrbac.mspim.azure.com/api/v2/$metadata for endpoint information

function Register-PimAadGroup {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$Token,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$GroupId
    )

    $Headers = @{
        Authorization = "Bearer $Token"
    }

    # Register AAD Group in PIM
    $Body = @{ externalId = $GroupId } | ConvertTo-Json
    $ApiSplat = @{
        Method      = 'Post'
        Headers     = $Headers
        ContentType = 'application/json'
        Body        = $Body
        Uri         = 'https://api.azrbac.mspim.azure.com/api/v2/privilegedAccess/aadGroups/resources/register'
    }
    $null = Invoke-RestMethod @ApiSplat
}

function Get-PimAadGroupRoleSettings {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$Token,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$GroupId,

        [Parameter(Mandatory)]
        [ValidateSet('Member', 'Owner')]
        [string]$RoleType
    )

    $Headers = @{
        Authorization = "Bearer $Token"
    }

    # Get group Member and Owner objects in PIM settings
    $FilterString = "(resource/id+eq+'$GroupId')"
    $Roles = (Invoke-RestMethod -Uri ('https://api.azrbac.mspim.azure.com/api/v2/privilegedAccess/aadGroups/roleSettingsv2?$expand=roleDefinition($expand=resource)&$filter=' + $FilterString) -Headers $Headers).Value
    # Filter based on requested RoleType
    $Role = $Roles | Where-Object { $_.roleDefinition.displayName -eq $RoleType }
    Write-Output $Role
}

function New-PimAadGroupRoleSettingRuleObject {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, ParameterSetName = 'ExpirationRule')]
        [switch]$ExpirationRule,

        [Parameter(Mandatory, ParameterSetName = 'ExpirationRule')]
        [timespan]$ExpirationTime,

        [Parameter(Mandatory, ParameterSetName = 'MfaRule')]
        [switch]$MfaRule,

        [Parameter(Mandatory, ParameterSetName = 'MfaRule')]
        [bool]$MfaRequired,

        [Parameter(Mandatory, ParameterSetName = 'JustificationRule')]
        [switch]$JustificationRule,

        [Parameter(ParameterSetName = 'JustificationRule')]
        [bool]$JustificationRequired = $true,

        [Parameter(Mandatory, ParameterSetName = 'TicketingRule')]
        [switch]$TicketingRule,

        [Parameter(Mandatory, ParameterSetName = 'TicketingRule')]
        [bool]$TicketingRequired,

        [Parameter(Mandatory, ParameterSetName = 'ApprovalRule')]
        [switch]$ApprovalRule,

        [Parameter(Mandatory, ParameterSetName = 'ApprovalRule')]
        [bool]$ApprovalEnabled,

        [Parameter(Mandatory, ParameterSetName = 'ApprovalRule')]
        [AllowEmptyCollection()]
        [string[]]$Approvers,

        [Parameter(Mandatory, ParameterSetName = 'AcrsRule')]
        [switch]$AcrsRule,

        [Parameter(Mandatory, ParameterSetName = 'AcrsRule')]
        [bool]$AcrsRequired,

        [Parameter(Mandatory, ParameterSetName = 'AcrsRule')]
        [AllowEmptyString()]
        [string]$Acrs,

        [Parameter(Mandatory, ParameterSetName = 'NotificationRule')]
        [switch]$NotificationRule
    )

    switch ($PSCmdlet.ParameterSetName) {
        'ExpirationRule' { 
            @{
                ruleIdentifier = 'ExpirationRule'
                setting        = @{
                    permanentAssignment         = $false
                    maximumGrantPeriodInMinutes = $ExpirationTime.TotalMinutes
                } | ConvertTo-Json -Compress # Each rule setting must be nested JSON
            }
        }
        'MFARule' {
            @{
                ruleIdentifier = 'MfaRule'
                setting        = @{ mfaRequired = $MfaRequired } | ConvertTo-Json -Compress # Each rule setting must be nested JSON
            }
        }
        'JustificationRule' {
            @{
                ruleIdentifier = 'JustificationRule'
                setting        = @{ required = $JustificationRequired } | ConvertTo-Json -Compress # Each rule setting must be nested JSON
            }
        }
        'TicketingRule' { 
            @{
                ruleIdentifier = 'TicketingRule'
                setting        = @{ ticketingRequired = $TicketingRequired } | ConvertTo-Json -Compress # Each rule setting must be nested JSON
            }
        }
        'ApprovalRule' { 
            @{
                ruleIdentifier = 'ApprovalRule'
                setting        = @{ enabled = $ApprovalEnabled; approvers = $Approvers } | ConvertTo-Json -Compress # Each rule setting must be nested JSON
            }
        }
        'AcrsRule' { 
            @{
                ruleIdentifier = 'AcrsRule'
                setting        = @{ acrsRequired = $AcrsRequired; acrs = $Acrs } | ConvertTo-Json -Compress # Each rule setting must be nested JSON
            }
        }
        'NotificationRule' { 
            @{
                ruleIdentifier = 'NotificationRule'
                setting        = @{
                    policies = @(
                        @{
                            deliveryMechanism = 'email'
                            setting           = @(
                                @{
                                    customreceivers          = $null
                                    isdefaultreceiverenabled = $true
                                    notificationlevel        = 2
                                    recipienttype            = 0
                                }
                                @{
                                    customreceivers          = $null
                                    isdefaultreceiverenabled = $true
                                    notificationlevel        = 2
                                    recipienttype            = 1
                                }
                                @{
                                    customreceivers          = $null
                                    isdefaultreceiverenabled = $true
                                    notificationlevel        = 2
                                    recipienttype            = 2
                                }
                            )
                        }
                    )
                } | ConvertTo-Json -Depth 10 -Compress # Each rule setting must be nested JSON
            }
        }
    }
}

function Update-PimAadGroupRoleSettings {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$Token,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$RoleId,

        [Parameter(Mandatory)]
        [ValidateSet('Member', 'Owner')]
        [string]$RoleType,

        [Parameter(Mandatory)]
        [ValidateSet('Activation', 'Assignment')]
        [string]$SettingType,

        [Parameter(Mandatory)]
        [ValidateSet('EndUser', 'Admin')]
        [string]$User,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$GroupId,

        # One or several rules from New-PimAadGroupRoleSettingRuleObject
        [Parameter(Mandatory)]
        [psobject[]]$Rule
    )

    # Get current settings
    $CurrentRoleSettings = Get-PimAadGroupRoleSettings -Token $Token -RoleType $RoleType -GroupId $GroupId

    # Translate from understandable terms to API
    $Level = switch ($SettingType) {
        'Activation' { 'Eligible' }
        'Assignment' { 'Member' }
    }

    # Set variables needed for body
    $Resource = $CurrentRoleSettings.roleDefinition.resource
    $LifeCycleSettings = $CurrentRoleSettings.lifeCycleManagement
    $CurrentRoleSettings.lifeCycleManagement = @{
        caller    = $User
        level     = $Level
        operation = 'ALL'
        value     = @($Rule)
    }

    # Create body for API request to update PIM group settings 
    $Body = @{
        id                  = $GroupId
        lifeCycleManagement = $LifeCycleSettings
        resource            = $Resource
        roleDefinition      = @{
            displayName = $RoleType
            id          = $RoleId
            resource    = $Resource
            templateId  = $CurrentRoleSettings.roleDefinition.templateId # Id of the setting itself
        }
    } | ConvertTo-Json -Depth 20
    
    $Headers = @{
        Authorization = "Bearer $Token"
    }
    $UpdateSplat = @{
        Uri         = "https://api.azrbac.mspim.azure.com/api/v2/privilegedAccess/aadGroups/roleSettingsv2/$($CurrentRoleSettings.id)"
        Headers     = $Headers
        Body        = $Body
        Method      = 'Patch'
        ContentType = 'application/json'
    }
    $UpdatedSettings = Invoke-RestMethod @UpdateSplat
}

function New-PimAadGroupRoleAssignment {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$Token,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$TenantId,
        
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$RoleDefinitionId,
        
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$GroupId,
        
        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [string]$State = 'Active',
        
        # The reason that will show up in the PIM role assignment
        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [string]$Reason = "Created from script $(Get-Date -Format 'yyyy-MM-dd')"
    )

    $Headers = @{
        Authorization = "Bearer $Token"
    }

    $Body = @{
        resourceId       = $TenantId # The tenant is the resource to operate on
        roleDefinitionId = $RoleDefinitionId
        subjectId        = $GroupId
        assignmentState  = $State
        type             = 'AdminAdd'
        schedule         = @{
            type          = 'Once'
            startDateTime = Get-Date
            endDateTime   = $null
        }
        reason           = $Reason # Reason is a required parameter when adding an active assignment, it's optional if eligible assignment
        # scopedResourceId = ''
        # condition = ''
        # conditionVersion = ''
    } | ConvertTo-Json
    Invoke-RestMethod -Uri 'https://api.azrbac.mspim.azure.com/api/v2/privilegedAccess/aadroles/roleAssignmentRequests' -Body $Body -Headers $Headers -Method Post -ContentType 'application/json'
}

Export-ModuleMember -Function @(
    Register-PimAadGroup
    Get-PimAadGroupRoleSettings
    New-PimAadGroupRoleSettingRuleObject
    New-PimAadGroupRoleAssignment
    Update-PimAadGroupRoleSettings
)