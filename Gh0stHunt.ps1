<#
.SYNOPSIS  
    Gh0stHunt is an Incident Repsonse Investigative Framework written in PowerShell that computer network defenders, hunt teams and forensic analysts can use to retrieve and analyze information from remote Windows systems. The framework will baseline and enumerate systems and domains, hunt for known IOCs, and compare current results against baseline. The 
    framework also parses a number Windows Event Logs types. The framework uses a text-based user interface to allow any operator to be able run the functions regardless of their experience level. The framework will require administrative rights and WinRM on the remote systems, as well as the WinRM port to be allowed thru the Windows Firewall. WinRM and PSRemoting must be enabled on the operators system.

    Gh0stHunt has 7 main menus which complete the following tasks:       
            - Setup Menu
                - Sets up a working directory, modifies trusted hosts file, sets target host(s), sets credentials and loads Indicator of Compromise(IOC) files.
            - Hunt Menu
                - Conduct a hunt across systems using lists of IOCs: Files, Registry Keys, Scheduled Tasks, Services, ips, domains and hashes.
            - System Information Menu
                - List registry keys commonly used for persistence
                - List registry keys used in Sticky Keys attacks
                - List Schedule Tasks
                - Find Specific files on disk
                - List Directory Contents
                - List Services
                - List Processes
                - List Autoruns
                - Get Local User Information
                - Get Local Group Information
                - List Network Shares
                - List Logical Drives
                - List Hotfixes
                - List Named Pipes
            - Baseline Menu
                - Baseline systems filesystem, services, processes, users, groups and other information.
                NOTE: Just about every task will output to csv and therefore can be baselined. The Baseline
                Menu only offers some perspective on key tasks to baseline.
            - Comparison Menu
                - Compares baseline csv files of systems against current ones.
                - Requires full path when inputing csv filenames. Right-Click the file and choose "Copy as Path" will work everytime.
            - Windows Log Parser Menu
                - Parses the XML of Windows Event Log Messages into objects so that PowerShell can process them. 
                - User logon success/failures
                - Password change attempts
                - Scheduled tasks Creation\Starting
                - Service Creation, 
                - Group membership changes
                - User account changes
                - And More. And plans for more in the future.
            - Domain Enumeration
                - Uses the Active-Directory Module to enumerate users, groups, computers and trusts from a domain.
                - This is only run against a Domain Controller. 
            - IOC Removal Menu
                - Menu allows you to stop, delete or mitigate some of the bad you found
                - Kill bad processes
                - Stop & delete bad services
                - Unregister and delete bad scheduled tasks
                - Deleted bad executables, dlls and other files from the filesystem.
                
.NOTES  
    File Name      : Gh0stHunt.ps1
    Version        : v0.2
    Author         : tbar317
    GitHub         : https://github.com/tbar317/Gh0stHunt
    Created        : 22 Sept 2019
     
#>

Set-ExecutionPolicy -ExecutionPolicy Bypass -Force

Function Show-MainMenu {
    param (
    [string]$Title = "Main Menu"
    )
    Clear-Host
    
    DisplayLogo
        
    Write-Host " "   
    Write-Host "=========================================== $Title ================================================" -ForegroundColor Yellow
    Write-Host " "
    $Options=@"
        [1] : Setup Menu 
        [2] : Hunt Menu 
        [3] : System Info Menu 
        [4] : Baseline Menu 
        [5] : Comparison Menu
        [6] : Windows Log Parser Menu 
        [7] : Domain Enumeration Menu
        [8] : IOC Removal Menu
        [Q] : Exit the Program
"@
    

    $Options

    Write-Host " "
    Write-Host "Please make a selection: " -NoNewLine -ForegroundColor yellow
    $selection = Read-Host 
    
    try{
    
        switch ($selection) {
            
            '1' {
                Write-Host "Getting the Setup Menu..." -ForegroundColor Cyan
                Show-SetupMenu
            }
            '2' {
                Write-Host "Getting the Hunt Menu..." -ForegroundColor Cyan
                Show-HuntMenu
            }
            '3' {
                Write-Host "Getting the System Info Menu..." -ForegroundColor Cyan
                Show-SystemInfoMenu
            }
            '4' {
                Write-Host "Getting the Baseline Menu..." -ForegroundColor Cyan
                Show-BaselineMenu
            }
            '5' {
                Write-Host "Getting the Comparison Menu..." -ForegroundColor Cyan
                Show-ComparisonMenu
            }
            '6' {
                Write-Host "Getting Log Parser Menu..." -ForegroundColor Cyan
                Show-LogParserMenu
            }
            '7' {
                Write-Host "Getting Domain Enumeration Menu..." -ForegroundColor Cyan
                Show-DomainMenu
            }
            '8' {
                Write-Host "Getting the IOC Removal Menu..." -ForegroundColor Cyan
                Show-IOCRemovalMenu
            }
            'Q' {
                Write-Host "Are you sure you want to exit the program: yes or no?" -ForegroundColor yellow
                $Answer = Read-Host
                if ($Answer -eq 'yes') {
                    Write-Host "Quiting..." -ForegroundColor Cyan
                    Exit
                }
                else {
                    Show-MainMenu
                }
            }
            default {
                Write-Host ""
                Write-Host "You did not select a valid option. Please try again. " -ForegroundColor Cyan
                Write-Host ""
                Write-Host "Please hit ENTER to acknowledge and continue." -ForegroundColor Yellow
                Read-Host
                Show-MainMenu
            }
        }
 
    }
    catch {
        Show-MainMenu
    }
}

Function DisplayLogo {
    Write-Host ""
    Write-Host ""
    Write-Host "     ********  **      **   *******    ******** ********** **      ** **     ** ****     ** ********** "  -ForegroundColor Yellow
    Write-Host "    **//////**/**     /**  **/////**  **////// /////**/// /**     /**/**    /**/**/**   /**/////**///  "  -ForegroundColor Yellow
    Write-Host "   **      // /**     /** **     //**/**           /**    /**     /**/**    /**/**//**  /**    /**     "  -ForegroundColor Yellow
    Write-Host "  /**         /**********/**      /**/*********    /**    /**********/**    /**/** //** /**    /**    "  -ForegroundColor Yellow
    Write-Host "  /**    *****/**//////**/**      /**////////**    /**    /**//////**/**    /**/**  //**/**    /**    "  -ForegroundColor Green
    Write-Host "  //**  ////**/**     /**//**     **        /**    /**    /**     /**/**    /**/**   //****    /**    "  -ForegroundColor Green 
    Write-Host "   //******** /**     /** //*******   ********     /**    /**     /**//******* /**    //***    /**     "  -ForegroundColor Green
    Write-Host "    ////////  //      //   ///////   ////////      //     //      //  ///////  //      ///     //      "  -ForegroundColor Green
    Write-Host ""
    Write-Host ""
}


#The Setup Menu is complete. Needs Testing. Contents of the Setup Menu may need additional work.
Function Show-SetupMenu {
    param (
        [string]$Title = "Setup Menu"
        )

    Clear-Host

    DisplayLogo

    Write-Host ""
    Write-Host "=========================================== $Title ================================================" -ForegroundColor Yellow
    Write-Host ""

    $options=
@" 
            [1] : Run Full Setup
            [2] : Setup Execution Policy
            [3] : Setup Working Directory
            [4] : Setup Trusted Hosts Information
            [5] : Gather Host Information
            [6] : Gather Credentials
            [7] : Gather IOC Information
            [8] : Setup Domain Info
            [M] : Return to the Main Menu
            [Q] : Exit the Program
"@    
    
    $Options
    Write-Host " "
    Write-Host "Please make a selection: " -NoNewLine -ForegroundColor yellow
    $selection = Read-Host  
    
    try {
        switch ($selection) {
        
            '1' {
                Write-Host "Running Setup..." -ForegroundColor Cyan
                Write-Host ""
                Set-ExPol
                Set-WorkingDirectory
                Set-TrustedHosts
                Set-Hosts
                Set-DomainInfo
                Set-Creds
                Set-IOCInformation
                Write-Host ""
                Write-Host "Setup is Complete..." -ForegroundColor Green
                Write-Host ""
                Write-Host "Hit ENTER to continue..." -ForegroundColor yellow
                Read-Host
                Show-MainMenu
            }
            '2' {
                Set-ExPol
                Show-SetupMenu
            }
            '3' {
                Set-WorkingDirectory
                Show-SetupMenu
            }
            '4' {
                Set-TrustedHosts
                Show-SetupMenu
            }
            '5' {
                Set-Hosts
                Show-SetupMenu
            }
            '6' {
                Set-Creds
                Show-SetupMenu
            }
            '7' {
                Set-IOCInformation
                Show-SetupMenu
            }
            '8' {
                Set-DomainInfo
                Show-SetupMenu
            }
            'M' {
                Show-MainMenu
            }
            'Q' {
                Write-Host "Are you sure you want to exit the program: yes or no?" -ForegroundColor yellow
                $Answer = Read-Host
                if ($Answer -eq 'yes') {
                    Write-Host "Quiting..." -ForegroundColor Cyan
                    Exit
                }
                else {
                    Show-SetupMenu
                }
                
            }
            default {
                Write-Host ""
                Write-Host "You did not select a valid option. Please try again. " -ForegroundColor Cyan
                Write-Host ""
                Write-Host "Please hit ENTER to acknowledge and continue." -ForegroundColor Yellow
                Read-Host
                Show-SetupMenu
            }
        }
    }
    catch {
        Show-MainMenu
    }
}

Function Show-HuntMenu {
    param (
        [string]$Title = "Hunt Menu"
        )
    Clear-Host

    DisplayLogo

    Write-Host ""
    Write-Host "=========================================== $Title ================================================" -ForegroundColor Yellow 
    Write-Host ""

    $options=
@" 
            [1] : Check for Known File IOCs
            [2] : Check for Known Scheduled Task IOCs
            [3] : Check for Known Registry IOCs
            [4] : Check for Known IP Address IOCs
            [5] : Check for Known Domain Name IOCs
            [6] : Check for Known Service IOCs
            [7] : Check for Known Hash IOCs
            [M] : Return to Main Menu
            [Q] : Exit the Program
"@

    $options

    Write-Host ""

    Write-Host "Please make a selection: " -NoNewLine -ForegroundColor yellow
    $selection = Read-Host 
    
    switch ($selection)
    {
        
        '1' {
            Write-Host "Searching the Remote System for Known File IOCs..." -ForegroundColor Cyan
            Find-FileIOCs
        }
        '2' {
            Write-Host "Searching the Remote System for Known Scheduled Tasks IOCs..." -ForegroundColor Cyan
            Find-ScheduledTaskIOCs
        }
        '3' {
            Write-Host "Searching the Remote System for Known Registry IOCs..." -ForegroundColor Cyan
            Find-RegistryIOCs
        }
        '4' {
            Write-Host "Searching the Remote System for Known IP Address IOCs..." -ForegroundColor Cyan
            Find-IpIOCs
        }
        '5' {
            Write-Host "Searching the Remote System for Known Domain Name IOCs..." -ForegroundColor Cyan
            Find-DomainIOCs
        }
        '6' {
            Write-Host "Searching the Remote System for Known Service Name IOCs..." -ForegroundColor Cyan
            Find-ServiceIOCs
        }
        '7' {
            Write-Host "Searching the Remote System for Known Hash IOCs..." -ForegroundColor Cyan
            Find-HashIOCs
        }
        'M' {
            Show-MainMenu
        }
        'Q' {
            
            Write-Host "Are you sure you want to exit the program: yes or no?" -ForegroundColor yellow
            $Answer = Read-Host
            if ($Answer -eq 'yes') {
                Write-Host "Quiting..." -ForegroundColor Cyan
                Exit
            }
            else {
                Show-HuntMenu
            }
        }
        default {
            Write-Host ""
            Write-Host "You did not select a valid option. Please try again. " -ForegroundColor Cyan
            Write-Host ""
            Write-Host "Please hit ENTER to acknowledge and continue." -ForegroundColor Yellow
            Read-Host
            Show-HuntMenu
        }
    }
 }
 
 Function Show-SystemInfoMenu {       
    param (
        [string]$Title = "System Information Menu"
        )
    Clear-Host
    DisplayLogo
    Write-Host " "
    Write-Host "=========================================== $Title ================================================" -ForegroundColor Yellow
    Write-Host " "
    $options=
@" 
            [1] : Get System Information
            [2] : Get Common Registry Persistence Keys
            [3] : Get Scheduled Tasks
            [4] : Find A Specific File on the C: Drive
            [5] : Get Directory Contents
            [6] : Get Services
            [7] : Get Processes
            [8] : Get AutoRuns
            [9] : Get User Information
            [10] : Get Group Information
            [11] : Get LocalGroup Information
            [12] : Get Network Shares
            [13] : Get Logical Drives
            [14] : Get HotFixes
            [15] : Get Processes w/ Network Activity
            [16] : Get Named Pipes
            [17] : Get Network Connection
            [18] : Get Sticky Keys Registry Keys
            [M] : Return to the Main Menu
            [Q] : Exit the Program

"@    
    
    $options

    Write-Host ""
    Write-Host "Please make a selection: " -NoNewLine -ForegroundColor Yellow
    $selection = Read-Host 
    
    switch ($selection) {
           
        '1' {
            Write-Host "Getting system information..." -ForegroundColor Cyan
            $SysInfo = 'True'
            Get-SysInfo
            $SysInfo = 'False'
        }
        '2' {
            Write-Host "Getting contents of registry keys for common persistence locations..." -ForegroundColor Cyan
            $SysInfo = 'True'
            Get-PersistentRegistryKeys
            $SysInfo = 'False'
        }
        '3' {
            Write-Host "Listing all scheduled tasks on the remote systems..." -ForegroundColor Cyan
            $SysInfo = 'True'
            Get-SchTasks
            $SysInfo = 'False'
        }
        '4' {
            Write-Host "Checking the filesystem for a specific file..." -ForegroundColor Cyan
            $SysInfo = 'True'
            Invoke-FindFile
            $SysInfo = 'False'
        }
        '5' {
            Write-Host "Listing the contents of a specific path on the host(s)." -ForegroundColor Cyan
            $SysInfo = 'True'
            Get-DirectoryContents
            $SysInfo = 'False'
        }
        '6' {
            Write-Host "Listing all services on the remote system..." -ForegroundColor Cyan
            $SysInfo = 'True'
            Get-ServiceInfo
            $SysInfo = 'False'
        }
        '7' {
            Write-Host "Listing all processes on the remote system..." -ForegroundColor Cyan
            $SysInfo = 'True'
            Get-ProcessInfo
            $SysInfo = 'False'
        }
        '8' {
            Write-Host "Listing all autoruns on the remote system..." -ForegroundColor Cyan
            $SysInfo = 'True'
            Get-AutoRuns
            $SysInfo = 'False'
        }
        '9' {
            Write-Host "Listing all users on the remote system..." -ForegroundColor Cyan
            $SysInfo = 'True'
            Get-UserInfo
            $SysInfo = 'False'
        }
        '10' {
            Write-Host "Listing all groups on the remote system..." -ForegroundColor Cyan
            $SysInfo = 'True'
            Get-GroupInfo
            $SysInfo = 'False'
        }
        '11' {
            Write-Host "Listing all local groups on the remote system..." -ForegroundColor Cyan
            $SysInfo = 'True'
            Get-LocalGroupInfo
            $SysInfo = 'False'
        }
        '12' {
            Write-Host "Getting network drive information on the remote system(s)" -ForegroundColor Cyan
            $SysInfo = 'True'
            Get-NetworkDrives
            $SysInfo = 'False'
        }
        '13' {
            Write-Host "Getting logical drive information on the remote system(s)" -ForegroundColor Cyan
            $SysInfo = 'True'
            Get-LogicalDrives
            $SysInfo = 'False'
        }
        '14' {
            Write-Host "Getting all hotfixes that have been installed on the remote system(s)" -Foreground Cyan
            $SysInfo = 'True'
            Get-HotFixes
            $SysInfo = 'False'
        }
        '15' {
            Write-Host "Inspect processes running on the remote system that have a network connection or port listening" -Foreground Cyan
            $SysInfo = 'True'
            Get-ProcessCallOuts
            $SysInfo = 'False'
        }
        '16' {
            Write-Host "Getting all named pipes that are currently running on the remote system(s)" -ForegroundColor Cyan
            $SysInfo = 'True'
            Get-NamedPipes
            $SysInfo = 'False'
        }
        '17' {
            Write-Host "Getting all named pipes that are currently running on the remote system(s)" -ForegroundColor Cyan
            $SysInfo = 'True'
            Get-NetConns
            $SysInfo = 'False'
        }
        '18' {
            Write-Host "Getting the contents of registry keys that are set during a sticky keys attack..." -ForegroundColor Cyan
            $SysInfo = 'True'
            Check-StickyKeys
            $SysInfo = 'False'
        }
        'M' {
            Show-MainMenu
        }
        'Q' {
            
            Write-Host "Are you sure you want to exit the program: yes or no?" -ForegroundColor yellow
            $Answer = Read-Host
            if ($Answer -eq 'yes') {
                Write-Host "Quiting..." -ForegroundColor Cyan
                Exit
            }
            else {
                Show-SystemInfoMenu
            }
        }
        default {
            Write-Host ""
            Write-Host "You did not select a valid option. Please try again. " -ForegroundColor Cyan
            Write-Host ""
            Write-Host "Please hit ENTER to acknowledge and continue." -ForegroundColor Yellow
            Read-Host
            
            Show-SystemInfoMenu
        }
    }
} 

 

Function Show-BaselineMenu {
param (
        [string]$Title = "Baseline Menu"
        
        )
    Clear-Host
    DisplayLogo
    Write-Host ""
    Write-Host "=========================================== $Title ================================================" -ForegroundColor Yellow
    Write-Host " "
    Write-Host "The Baseline Menu will run a series of tasks and outputs the results of those tasks to your current working Directory."
    Write-Host "Use the Comparison Menu to run scripts that will re-run the same commands and run comparisons against this baseline."

    Write-Host " "
    $options=
@" 
            [1] : Baseline of Common Registry Keys used for Persistence
            [2] : Baseline Scheduled Tasks
            [3] : Baseline Services
            [4] : Baseline Processes
            [5] : Baseline Local User Information
            [6] : Baseline Local Group Information
            [7] : Baseline Shares
            [8] : Baseline Filesystem
            [A] : Baseline All the Things
            [M] : Return to the Main Menu
            [Q] : Exit the Program

"@    
    
    $options

    Write-Host ""
    Write-Host "Please make a selection: " -NoNewLine -ForegroundColor Yellow
    $selection = Read-Host

    switch ($selection) {
           
        '1' {
            $Baseline = 'True'
            List-PersistentRegistryKeys
            $Baseline = 'False'
            Show-BaselineMenu
        }
        '2' {

            $Baseline = 'True'
            Get-SchTasks
            $Baseline = 'False'
            Show-BaselineMenu
        }
        '3' {
            $Baseline = 'True'
            Get-ServiceInfo
            $Baseline = 'False'
            Show-BaselineMenu
        }
        '4' {
            $Baseline = 'True'
            Get-ProcessInfo
            $Baseline = 'False'
            Show-BaselineMenu
        }
        '5' {
            $Baseline = 'True'
            Get-UserInfo
            $Baseline = 'False'
            Show-BaselineMenu
        }
        '6' {
            $Baseline = 'True'
            Get-LocalGroupInfo
            $Baseline = 'False'
            Show-BaselineMenu
        }
        '7' {
            $Baseline = 'True'
            Get-NetworkDrives
            $Baseline = 'False'
            Show-BaselineMenu
        }
        '8' {
            $Baseline = 'True'
            Get-FileSystemHash
            $Baseline = 'False'
            Show-BaselineMenu
        }
        'A' {
            $Baseline = 'True'
            List-PersistentRegistryKeys
            Get-ServiceInfo
            Get-SchTasks
            Get-ProcessInfo
            Get-UserInfo
            Get-LocalGroupinfo
            Get-NetworkDrives
            Get-FileSystemHash
            $Baseline = 'False'
            Show-BaselineMenu
        }
        'M' {
            Show-MainMenu
        }
        'Q' {
            Write-Host "Are you sure you want to exit the program: yes or no?" -ForegroundColor yellow
            $Answer = Read-Host
            if ($Answer -eq 'yes') {
                Write-Host "Quiting..." -ForegroundColor Cyan
                Exit
            }
            else {
                Show-BaselineMenu
            }
        }
        default {
            Write-Host ""
            Write-Host "You did not select a valid option. Please try again. " -ForegroundColor Cyan
            Write-Host ""
            Write-Host "Please hit ENTER to acknowledge and continue." -ForegroundColor Yellow
            Read-Host
            
            Show-BaselineMenu
        }
    }
}        

Function Show-DomainMenu {
param (
        [string]$Title = "Enumerate Domain Menu"
        
        )
    Clear-Host
    DisplayLogo
    Write-Host ""
    Write-Host "=========================================== $Title ================================================" -ForegroundColor Yellow
    Write-Host " "
    #Write-Host "The Baseline Menu will run a series of tasks and outputs the results of those tasks to your current working Directory."
    #Write-Host "Use the Comparison Menu to run scripts that will re-run the same commands and run comparisons against this baseline."

    Write-Host " "
    $options=
@" 
            [1] : Enumerate Domain Users
            [2] : Enumerate Domain Groups
            [3] : Enumerate Domain Trusts
            [4] : Enumerate Domain Computers
            [M] : Return to the Main Menu
            [Q] : Exit the Program

"@    
    
    $options

    Write-Host ""
    Write-Host "Please make a selection: " -NoNewLine -ForegroundColor Yellow
    $selection = Read-Host

    switch ($selection) {
           
        '1' {
            Get-DomainUsers
        }
        '2' {
            Get-DomainGroups
        }
        '3' {
            Get-DomainTrusts
        }
        '4' {
            Get-DomainComputers
        }
        'M' {
            Show-MainMenu
        }
        'Q' {
            Write-Host "Are you sure you want to exit the program: yes or no?" -ForegroundColor yellow
            $Answer = Read-Host
            if ($Answer -eq 'yes') {
                Write-Host "Quiting..." -ForegroundColor Cyan
                Exit
            }
            else {
                Show-DomainMenu
            }
        }
        default {
            Write-Host ""
            Write-Host "You did not select a valid option. Please try again. " -ForegroundColor Cyan
            Write-Host ""
            Write-Host "Hit ENTER to acknowledge and continue." -ForegroundColor Yellow
            Read-Host
            Show-DomainMenu
            
        }
    }
}

Function Show-LogParserMenu {
param (
        [string]$Title = "Windows Log Parser Menu"
        
        )
    Clear-Host
    DisplayLogo
    Write-Host ""
    Write-Host "=========================================== $Title ================================================" -ForegroundColor Yellow
    Write-Host " "
    #Write-Host "The Baseline Menu will run a series of tasks and outputs the results of those tasks to your current working Directory."
    #Write-Host "Use the Comparison Menu to run scripts that will re-run the same commands and run comparisons against this baseline."

    Write-Host " "
    $options=
@" 
            [1] : Show Scheduled Tasks Launched Logs
            [2] : Show Services Created Logs
            [3] : Show Registry Changes Logs
            [4] : Show User Creation Logs
            [5] : Show User Enabled Logs
            [6] : Show User Account Change Logs
            [7] : Show User Password Change Attempt Logs
            [8] : Show Process Events
            [9] : Show User added to domain group logs
            [10] : Show Logs indicating local group membership enumeration
            [M] : Return to the Main Menu
            [Q] : Exit the Program

"@    
    
    $options

    Write-Host ""
    
    Write-Host "Please make a selection: " -NoNewLine -ForegroundColor Yellow
    $selection = Read-Host

    switch ($selection) {
           
        '1' {
            Get-ScheduledTasksLaunched
        }
        '2' {
            Get-ServicesCreated
        }
        '3' {
            Get-RegistryChangeLogs
        }
        '4' {
            Get-DomainUserCreation
        }
        '5' {
            Get-DomainUserEnabled
        }
        '6' {
            Get-UserAccountChange
        }
        '7' {
            Get-UserPasswordChangeAttempt
        }
        '8' {
            Get-ProcessEvents
        }
        '9' {
            Get-UserAddedToDomainGroup
        }
        '10'{
            Get-LocalGroupMembershipEnumeration
        }
        '11'{
            Get-LogonSuccesses
        }
        '12'{
            Get-LogonFailures
        }
        'M' {
            Show-MainMenu
        }
        'Q' {
            Write-Host "Are you sure you want to exit the program: yes or no?" -ForegroundColor yellow
            $Answer = Read-Host
            if ($Answer -eq 'yes') {
                Write-Host "Quiting..." -ForegroundColor Cyan
                Exit
            }
            else {
                Show-LogParserMenu
            }
            
        }
        default {
            Write-Host ""
            Write-Host "You did not select a valid option. Please try again. " -ForegroundColor Cyan
            Write-Host ""
            Write-Host "Please hit ENTER to acknowledge and continue." -ForegroundColor Yellow
            Read-Host
            
            Show-LogParserMenu
        }
    }
}

Function Show-ComparisonMenu {
param (
        [string]$Title = "Baseline => Current Comparison Menu"
        
        )
    Clear-Host
    DisplayLogo
    Write-Host ""
    Write-Host "=========================================== $Title ================================================" -ForegroundColor Yellow
    Write-Host " "
    #Write-Host "The Baseline Menu will run a series of tasks and outputs the results of those tasks to your current working Directory."
    #Write-Host "Use the Comparison Menu to run scripts that will re-run the same commands and run comparisons against this baseline."

    Write-Host " "
    $options=
@" 
            [1] : Compare FileSystem Hashes
            [2] : Compare Scheduled Tasks
            [3] : Compare Services
            [4] : Compare Processes
            [5] : Compare Domain User Accounts
            [6] : Compare Domain Group Accounts
            [7] : Compare Domain Computer Accounts
            [8] : Compare Local User Accounts
            [M] : Return to the Main Menu
            [Q] : Exit the Program

"@    
    
    $options

    Write-Host ""
    Write-Host "Please make a selection: " -NoNewLine -ForegroundColor Yellow
    $selection = Read-Host

    switch ($selection) {
           
        '1' {
            $global:PROP = "Hash"
            $global:Task = "filesystem_comparison"
            Compare-BaselineToCurrent
        }
        '2' {
            $global:Task = "schtask_comparison"
            $global:PROP = "taskname"
            $global:HEAD = "Date,Taskname,Taskpath,Author,Triggers,Description"
            Compare-BaselineToCurrent
        }
        '3' {
            $global:Task = "services_comparison"
            $global:PROP = "Name"
            Compare-BaselineToCurrent
        }
        '4' {
            $global:Task = "processes_comparison"
            $global:PROP = "ProcessName"
            Compare-BaselineToCurrent
        }
        '5' {
            $global:Task = "domain_users_comparison"
            $global:PROP = "name"
            Compare-BaselineToCurrent
        }
        '6' {
            $global:Task = "domain_groups_comparison"
            $global:PROP = "name"
            Compare-BaselineToCurrent
        }
        '7' {
            $global:Task = "domain_computers_comparison"
            Compare-BaselineToCurrent
        }
        '8' {
            $global:Task = "local_user_comparison"
            Compare-BaselineToCurrent
        }
        'M' {
            Show-MainMenu
        }
        'Q' {
            Write-Host "Are you sure you want to exit the program: yes or no?" -ForegroundColor yellow
            $Answer = Read-Host
            if ($Answer -eq 'yes') {
                Write-Host "Quiting..." -ForegroundColor Cyan
                Exit
            }
            else {
                Show-ComparisonMenu
            }
        }
        default {
            Write-Host ""
            Write-Host "You did not select a valid option. Please try again. " -ForegroundColor Cyan
            Write-Host ""
            Write-Host "Please hit ENTER to acknowledge and continue." -ForegroundColor Yellow
            Read-Host
            
            Show-ComparisonMenu
        }
    }
}

Function Show-IOCRemovalMenu {
    param (
        [string]$Title = "IOC Removal Menu"
        )
    Clear-Host

    DisplayLogo

    Write-Host ""
    Write-Host "=========================================== $Title ================================================" -ForegroundColor Yellow 
    Write-Host ""

    Write-Host "The IOC removal menu will allow you to remove all IOCs that you discovered in the hunt menu or during host enumeration. Your IOCs may have dependencies that need removed, for example, a File IOC may not be deletable until an associated Process and Service IOC(s) are stopped and deleted. Always verify that the action taken worked and adjust your removal strategy as needed." -ForegroundColor Cyan
    Write-Host ""
    $options=
@" 
            [1] : Remove Process IOCs
            [2] : Remove Scheduled Task IOCs
            [3] : Remove Registry IOCs
            [4] : Remove Service IOCs
            [5] : Remove File IOCs
            [6] : Mitigate IP IOCs
            [7] : Mitigate Domain Name IOCs
            [M] : Return to Main Menu
            [Q] : Exit the Program
"@

    $options

    Write-Host ""

    Write-Host "Please make a selection: " -NoNewLine -ForegroundColor yellow
    $selection = Read-Host 
    
    switch ($selection)
    {
        
        '1' {
            Write-Host "Stopping and Remvoing Process IOCs..." -ForegroundColor Cyan
            Remove-ProcessIOC
        }
        '2' {
            Write-Host "Stopping, Unregistering and Removing Schedule Task IOCs..." -ForegroundColor Cyan
            Remove-ScheduledTaskIOC
        }
        '3' {
            Write-Host "Removing Registry IOCs from the remote host(s)..." -ForegroundColor Cyan
            Remove-RegistryIOC
        }
        '4' {
            Write-Host "Stopping and Removing Service IOCs from the remote host(s)..." -ForegroundColor Cyan
            Remove-ServiceIOC
        }
        '5' {
            Write-Host "Removing File IOCs from the remote host(s)..." -ForegroundColor Cyan
            Remove-FileIOC
        }
        '6' {
            Write-Host "Mitigating IP IOCs by adding a block statement for the IPs to the Windows Advanced Firewall..." -ForegroundColor Cyan
            Remove-IPIOC
        }
        '7' {
            Write-Host "Mitigating domain IOCs by black holing the domain name..." -ForegroundColor Cyan
            Write-Host ""
            Write-Host "This will make add a line in the computers host file aligning the domain name with localhost (127.0.0.1)." -ForegroundColor Cyan
            Remove-DomainIOC
        }
        'M' {
            Show-MainMenu
        }
        'Q' {
            
            Write-Host "Are you sure you want to exit the program: yes or no?" -ForegroundColor yellow
            $Answer = Read-Host
            if ($Answer -eq 'yes') {
                Write-Host "Quiting..." -ForegroundColor Cyan
                Exit
            }
            else {
                Show-IOCRemovalMenu
            }
        }
        default {
            Write-Host ""
            Write-Host "You did not select a valid option. Please try again. " -ForegroundColor Cyan
            Write-Host ""
            Write-Host "Please hit ENTER to acknowledge and continue." -ForegroundColor Yellow
            Read-Host
            Show-IOCRemovalMenu
        }
    }
 }
Function Set-ExPol {
    Write-Host "Settin up the Execution Policy on the box..." -ForegroundColor Cyan
    if((Get-ExecutionPolicy) -ne 'Unrestricted') 
    { 
        Set-ExecutionPolicy -ExecutionPolicy Bypass -Force
        Write-Host ""
        Write-Host "Execution Policy is set to Bypass." -ForegroundColor Green
    }
    else {
        Write-Host ""
        Write-Host "Execution Policy is already set." -ForegroundColor Green
    }
}

Function Set-WorkingDirectory {
    Write-Host ""
    Write-Host "You can specify a working directory or use the current working directory to save your results." -ForegroundColor Cyan
    Write-Host ""
    Write-Host "Do you want to save your work in the current working directory @ '$pwd'?" -ForegroundColor Yellow
    $wd = Read-Host
    if ($wd -eq 'yes') {
        
        $global:Directory = $pwd.Path

    }
    else {
    
        $path = Read-Host "Please enter the path to your working directory"
        Write-Host ""
        $global:Directory = $path
        $pathBase = $path.split('\')[!-1]
        $folder = $path.split('\')[-1]
        
        Write-Host "Checking if the current working directory exists..." -ForegroundColor Cyan 
        If ([System.IO.Directory]::Exists($Directory)) {
            Write-Host ""
            Write-Host "Current Working Directory exists at $Directory"
        
        }
        else {
            Write-Host "Current Directory doesn't exist..." -ForegroundColor Cyan
            Write-Host ""
            Write-Host "Setting up your working directory @ $Directory" -ForegroundColor Cyan
            new-item -Path "$pathBase" -Name "$folder" -ItemType Directory
        }
    }

    Set-Location $Directory
    Write-Host ""
    Write-Host "The Working Directory is set @ $Directory" -ForegroundColor Green
    Write-Host ""
    Write-Host "Please hit enter to continue" -NoNewline -ForegroundColor Yellow
    $input = Read-Host
} 

Function Set-HostDirectory {
    Write-Host "Setting up a directory in the working directory for each discovered host." -ForegroundColor Cyan
    foreach ($h in $remotehosts) {
        
        Write-Host " "
        Write-Host "Checking if the host directory: $h exists..." -ForegroundColor Cyan
        Write-Host " "
        If (Test-Path $h) {
            Write-Host "The host directory: $h already exists in your working directory: $Directory" -ForegroundColor Green
            Write-Host " "
        }
        else {
            Write-Host "The host directory doesn't exist..." -ForegroundColor Cyan
            Write-host " "
            Write-Host "Creating the host directory in your working directory: $Directory..." -ForegroundColor Cyan
            new-item -Path "$Directory" -Name "$h" -ItemType Directory
            Write-Host "The host directory: $h has been created in your working directory: $Directory..." -ForegroundColor Green
        } 
    }
}      

    
Function Set-TrustedHosts {
        Param (
        [string]$TrustedHosts
        )
        
        Enable-PSRemoting -Force -SkipNetworkProfileCheck
        Write-Host ""
        Write-Host "Setting up the Trusted Hosts file..." -ForegroundColor Cyan
        Write-Host ""
        #Set the path for trusted Hosts
        $trustedhostpath = "WSMan:\localhost\Client\TrustedHosts"
        Write-Host
        Write-Host "Enter a subnet for your IP address range (Example: 172.16.12.* or 172.16.12.0/24)" -ForegroundColor Yellow
        $subnet = Read-Host
        Write-Host ""
        Write-Host "Checking information on Trusted Hosts..." -ForegroundColor Cyan
        #check if the $subnet is part of trusted hosts, if not, add the subnet ot 
        Write-Host ""
        if((Get-Item -Path $trustedhostpath).Value -ne $subnet) 
        { 

            Write-Host "Setting Trusted Host information for Trusted Hosts..." -ForegroundColor Cyan
            Set-Item $trustedhostpath -Value * -Force 
        }
        Write-Host ""
        Write-Host "Information on Trusted Host is set..." -ForegroundColor green
        Write-Host ""
        Write-Host "Please hit ENTER in to continue."  -NoNewLine -ForegroundColor yellow
        Read-Host 
    }

Function Set-Hosts {
  
    
    Write-Host "You can load a host file from the current directory or let the system discover it from the subnet provided." -ForegroundColor Cyan     
    Write-Host ""
    Write-Host "Do you want to specify the path to a host file? yes or no " -ForegroundColor Yellow
    $Input_Host_File = Read-Host
    Write-Host ""
    
    if ($Input_Host_File -eq 'yes') {
        Write-Host "Host file must be located in $Directory." -ForegroundColor Cyan
        Write-Host ""
        Write-Host "Hit ENTER to continue." -ForegroundColor Yellow
        Read-Host
        Write-Host "Please enter the name of the host file in $($Directory) " -ForegroundColor Yellow
        $Remote_Hosts = Read-Host
        if (Test-Path "$Remote_Hosts") {
            $global:remotehosts = @(Get-Content "$Remote_Hosts")
        }
    }
    else {
        try {
            if (Test-Path "Remote-Hosts.txt") {
                Remove-Item "Remote-Hosts.txt" -Force -ErrorAction SilentlyContinue
                New-Item -Path . -Name "Remote-Hosts.txt" -ItemType "File"  
            }
            else {
                New-Item -Path . -Name "Remote-Hosts.txt" -ItemType "File"
            }
        }
        catch {
            $msg = "Error: Failed on line number '{0}' column '{1}' ('{2}'). The error was '{3}'." -f 
            $_.Exception.Line, $_.Exception.Offset, $_.Exception.CommandInvocation.Line.Trim(), $_.Exception.Message
            $msg
        }
         
        Write-Host ""
        $global:network = Read-Host "Enter your target network ending in a zero: "
        $global:start = Read-Host "Enter the first IP address in the target network: "
        $global:end = Read-Host "Enter the last IP address in the target network: "
        $global:pings = Read-Host "Enter the # of pings to attempt: "
        
        Write-Host ""
        Write-Host "This will take several minutes for a /24 Subnet." -ForegroundColor Yellow
        Find-RemoteHosts -network $network -start $start -end $end -ping $pings
        $global:remotehosts = @(Get-Content "Remote-Hosts.txt")
    }

    Set-HostDirectory

    Write-Host "Hosts have been identified." -ForegroundColor Green
    Write-Host ""
    Write-Host "Host Directories have been created in $($Directory)." -ForegroundColor Green
    Write-Host ""
    Write-Host "Please hit ENTER in to continue."  -NoNewLine -ForegroundColor yellow
    $input = Read-Host
}

Function Set-DomainInfo {
    Write-Host ""
    Write-Host "Enter the ip address of the target domain controller " -ForegroundColor Yellow
    $global:dc = Read-Host
    Write-Host ""
    Write-Host "Domain Controller at $($dc) is set." -ForegroundColor Green
    
}

Function Find-RemoteHosts {
    [cmdletbinding()]
    Param(
    [Parameter(HelpMessage="Enter an IPv4 subnet ending in 0.")]
    [ValidatePattern("\d{1,3}\.\d{1,3}\.\d{1,3}\.0")]
    [string]$network,
    #$Subnet= ((Get-NetIPAddress -AddressFamily IPv4).Where({$_.InterfaceAlias -notmatch "Bluetooth|Loopback"}).IPAddress -replace "\d{1,3}$","0"),
 
    [ValidateRange(1,254)]
    [int]$start,
 
    [ValidateRange(1,254)]
    [int]$end,
 
    [ValidateRange(1,10)]
    [Alias("count")]
    [int]$ping = 1
    )
    
    $Remote_Hosts_Path = "Remote-Hosts.txt"
    if ($Remote_Hosts_Path) {
        Remove-Item $Remote_Hosts_Path -Force
        New-Item -Path $Directory -Name $Remote_Hosts_Path -Force
    }
    Write-Host ""
    Write-Host "Pinging $network from $start to $end" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "Testing with $ping pings(s)" -ForegroundColor Cyan
    Write-Host ""

    $proghash = @{
     Activity = "Ping Sweep"
     CurrentOperation = "None"
     Status = "Pinging IP Address"
     PercentComplete = 0
    }

    $count = ($end - $start)+1
    
    $base = $network.split(".")[0..2] -join "."
    $i = 0
 
    while ($end - $start) {
      $i++
      #calculate % processed for Write-Progress
      $progHash.PercentComplete = ($i/$count)*100
 
      #define the IP address to be pinged by using the current value of $start
      $IP = "$base.$start" 
 
      #Use the value in Write-Progress
      $proghash.currentoperation = $IP
      Write-Progress @proghash

      #test the connection
      if (Test-Connection -ComputerName $IP -Count $ping -Quiet) {
        #if the IP is not local get the MAC
        Write-Host "Host [$IP] responded to ping!" -ForegroundColor Green
        $IP | Out-File -FilePath $Remote_Hosts_Path -Append -Force
        }
        $start++
    }
    Write-Progress -Activity "Complete" -Completed
    Write-Host ""          
    Write-Host "The host file $($Remote_Hosts_Path) has been created in $($Directory)." -ForegroundColor Green
    Write-Host ""
} 

         
Function Set-Creds {
    Write-Host ""
    Write-Host "Setting up Credentials to use on the remote host(s)..." -ForegroundColor Cyan
    Write-Host ""
    Write-Host "Enter the domain short name " -ForegroundColor Yellow
    $Domain = Read-Host
    Write-Host ""
    Write-Host "Enter the username to connect to the remote system(s)" -ForegroundColor Yellow
    $UserName = Read-Host 
    
    $domainCreds = "$Domain\$Username"
    Write-Host ""
    $password = Read-Host "Please enter the password to connect to the remote system(s)" -AsSecureString
    Write-Host ""
    #Add a variable for credentials
    $UserPassSecure = $password 
    $UserCredentials = New-Object -TypeName System.Management.Automation.PSCredential $domainCreds,$UserPassSecure 
        
    
    $global:UserCredentials = New-Object -TypeName System.Management.Automation.PSCredential $domainCreds,$UserPassSecure
    Write-Host "User Credentials loaded..." -ForegroundColor Green
    Write-Host ""
    Write-Host "Please hit ENTER in to continue."  -NoNewLine -ForegroundColor yellow
    Read-Host
    

}

Function Set-ErrorMsg {
    $global:msg = "Error: Failed on line number '{0}' column '{1}' ('{2}'). The error was '{3}'." -f 
            $_.Exception.Line, $_.Exception.Offset, $_.Exception.CommandInvocation.Line.Trim(), $_.Exception.Message
    $msg
}
Function Set-Output {
    Write-Host ""
    Write-Host "Results can be Displayed to console or sent to a csv file." -ForegroundColor Cyan
    Write-Host ""     
    Write-Host "Do you want to Display the results to the csv: yes or no ?" -ForegroundColor Yellow
    $global:Output_To_File = Read-Host
    $global:enddate = (Get-Date).ToString("yyyyMMdd_hhmmss")
}

Function Set-Target {
    Write-Host ""
    Write-Host "You can specify a specific target host or select all hosts." -ForegroundColor Cyan
    Write-Host ""
    Write-Host "Do you want to specify a specific target host: yes or no?" -ForegroundColor Yellow
    $HostInput = Read-Host

    If ($HostInput -eq 'yes') {
         Write-Host ""
         Write-Host "Enter the target host: " -ForegroundColor Yellow
         $global:hosts = Read-Host
         Write-Host
         Write-Host "Target Host $hosts is set." -ForegroundColor Green
         Write-Host ""
    }
    else {
        Write-Host ""
        $global:hosts = $remotehosts
        Write-Host "Target Hosts are set." -ForegroundColor Green
    }
}

Function Compare-BaselineToCurrent {
    $enddate = (Get-Date).ToString("yyyyMMdd_hhmmss")
    if ($Task -ne 'Filesystem_Comparison') {
        Set-Output
    }
    else {
        Write-Host "Task File comparsion will only output to csv." -ForegroundColor Cyan
    }
    
    Write-Host ""
    Write-Host "Enter location of your baseline $Task file (copy & paster file name) " -ForegroundColor Yellow
    $File_Baseline = Read-Host
    Write-Host ""
    Write-Host "Enter location of your current $Task file (copy & paster file name) " -ForegroundColor Yellow
    $File_Current = Read-Host
    Write-Host ""

    $split1 = $File_Baseline.Split('"')[1]
    $split2 = $File_Current.Split('"')[1]
    $HostName = $split1.Split('\')[3]
    $filename1 = $split1.split('\')[4]
    $filename2 = $split2.split('\')[4]

    Set-Location $HostName

    $file1 = Import-Csv $filename1 
    $file2 = Import-Csv $filename2 

    if (Test-Path "$($Directory)\Comparison") {
        Write-Host "Directory $($Directory)\Comparison exists" -ForegroundColor Green
    }
    else {
        New-Item -ItemType Directory -Path "$($Directory)" -Name "Comparison"
        Write-Host "Directory $($Directory)\Comparison created" -ForegroundColor Green
    }
    
    Write-Host ""
    
    if ($task -eq 'Filesystem_Comparison')  {
        Compare-Object $File1 $File2 -Property $PROP -PassThru | 
        Where-Object { $_.sideindicator -eq '=>' } |
        Export-Csv "$($Directory)\Comparison\$($HostName)_$($Task)_$($enddate).csv" -NoTypeInformation -Append -Force -ErrorAction SilentlyContinue
    }
    else {
        $Compare_Results = Compare-Object $File1 $File2 -Property $PROP -PassThru | 
        Where-Object { $_.sideindicator -eq '=>' } 
        if ($Output_To_File -eq 'yes') {
            Export-Csv -InputObject $Compare_Results "$($Directory)\Comparison\$($HostName)_$($Task)_$($enddate).csv" -NoTypeInformation -Append -Force -ErrorAction SilentlyContinue
        }
        else {
            $Compare_Results
        }
    }
         
    Write-Host "Comparison of $File_Baseline and $File_Current complete..." -ForegroundColor Green
    Write-host ""
    Write-Host "Hit ENTER to continue..." -ForegroundColor yellow
    Read-Host
    
    Set-Location $Directory
    Show-ComparisonMenu
}

Function Get-SysInfo {
Set-Output
Set-Target
Write-Host "Getting System Information on remote hosts..." -ForegroundColor Cyan
    foreach ($h in $hosts) {
        try {
        
            $Sys_Results = Invoke-Command -ComputerName $h -Credential $UserCredentials -ScriptBlock {
                if ($Output_To_File -eq "yes") {
                    Get-WmiObject -Class win32_operatingsystem | Select-Object PsComputername,caption,OSArchitecture,Version,NumberofProcesses,NumberofUsers,lastBootuptime,localdatetim
                    #Get-CimInstance Win32_OperatingSystem | Select-Object Caption, Version, ServicePackMajorVersion, OSArchitecture, CSName, WindowsDirectory
                    #Get-ComputerInfo -Property "os*" | select osname,osversion,OSArchitecture,OsLocalDateTime,OSLastBootUpTime,OSuptime,OsNumberOfProcesses,OSNumberOfUsers
                }
                else {
                    Get-WmiObject -Class win32_operatingsystem | Select-Object PsComputername,caption,OSArchitecture,Version,NumberofProcesses,NumberofUsers,lastBootuptime,localdatetim
                    #Get-CimInstance Win32_OperatingSystem | Select-Object Caption, Version, ServicePackMajorVersion, OSArchitecture, CSName, WindowsDirectory
                    #Get-ComputerInfo -Property "os*" | select osname,osversion,OSArchitecture,OsLocalDateTime,OSLastBootUpTime,OSuptime,OsNumberOfProcesses,OSNumberOfUsers
                }
            }
            if ($Output_To_File -eq "yes") {
                foreach ($result in $Sys_Results) {
                Export-Csv -InputObject $result -Path "$Directory\$h\$($h)_SystemInformation_$($enddate).csv" -NoTypeInformation -Append -ErrorAction SilentlyContinue
                }
            }
            else {
                foreach ($result in $Sys_Results) {
                    $result
                }
            Write-Host "Hit ENTER when you are ready to see the next host." -NoNewLine -ForegroundColor yellow
            Read-Host
            }
        }
        
        catch {
            Set-ErrorMsg
        }
    }

    Write-Host "Hit ENTER to continue."  -NoNewLine -ForegroundColor yellow
    Read-Host
    Clear-Host
    if ($SysInfo) {
        Show-SystemInfoMenu
    }
}
Function Set-IOCInformation {
    Write-Host "Verify you put IOC text files in $Directory." -ForegroundColor cyan
    Write-Host "" 
    Write-Host "Hit ENTER to continue" -nonewline -ForegroundColor yellow
    Read-Host 
    Write-Host ""
    #File IOC section
    Write-Host "Do you want to enter file IOCs? yes or no" -ForegroundColor Yellow
    $input = Read-Host
    if ($input -eq 'yes'){
        Write-Host "Please enter a path to your File IOCs: " -ForegroundColor yellow
        $files_path = Read-Host
                    
        if (Test-Path "$($files_path)") {
            $global:fileIOCs = @(Get-Content "$($Directory)\$($files_path)")
            $fileCount = $fileIOCs.Count
            Write-Host "Loading $fileCount known file IOCs..." -ForegroundColor Green
            
        }
        else {
            Write-Host "File $($files_path) doesn't exist..." -ForegroundColor Red
            Write-Host "File not loaded. Skipping to next IOC file." -ForegroundColor Red
        }
        
    }
    Write-Host ""
    #Network IOC section
    Write-Host "Do you want to enter Network Connection IOCs? yes or no" -ForegroundColor Yellow
    $input = Read-Host    
    if ($input -eq 'yes') {
        Write-Host "Please enter a path to your Network Connection IOCs: " -ForegroundColor yellow
        $IPs_path = Read-Host

        if (Test-Path "$($IPs_path)") {
            $global:ipIOCs = @(Get-Content "$($Directory)\$($IPs_path)")
            $ipCount = $ipIOCs.Count
            Write-Host "Loading $ipCount known IP IOCS..." -ForegroundColor Green
        }
        else {
            Write-Host "File $($IPs_path) doesn't exist..." -ForegroundColor Red
            Write-Host "File not loaded. Skipping to next IOC file." -ForegroundColor Red
        }
    }
    Write-Host ""
    #Registry IOC section
    Write-Host "Do you want to enter Registry IOCs? yes or no" -ForegroundColor Yellow
    $input = Read-Host    
    if ($input -eq 'yes') {
        Write-Host "Please enter a path to your Registry IOCs: " -ForegroundColor yellow
        $registry_path = Read-Host
        Write-Host ""

        if (Test-Path "$($registry_path)") {
            $global:regIOCs = @(Get-Content "$($Directory)\$($registry_path)") 
            $regCount = $regIOCs.Count
            Write-Host "Loading $regCount known Registry IOCs..." -ForegroundColor Green
        }
        else {
            Write-Host "File $($registry_path) doesn't exist..." -ForegroundColor Red
            Write-Host "File not loaded. Skipping to next IOC file." -ForegroundColor Red
        }
    }
    
    Write-Host ""
    #Scheduled Task IOC section
    Write-Host "Do you want to enter Schedule Task IOCs? yes or no" -ForegroundColor Yellow
    $input = Read-Host    
    if ($input -eq 'yes') {
        Write-Host "Please enter a path to your Scheduled Task IOCs: " -ForegroundColor yellow
        $jobs_path = Read-Host
        Write-Host ""
        
        if (Test-Path "$($jobs_path)") {
            $global:taskIOCs = @(Get-Content "$($Directory)\$($jobs_path)")
            $taskCount = $taskIOCs.Count
            Write-Host "Loading $taskCount known Scheduled Task IOC..." -ForegroundColor Green
        }
        else {
            Write-Host "File $($jobs_path) doesn't exist..." -ForegroundColor Red
            Write-Host "File not loaded. Skipping to next IOC file." -ForegroundColor Red
        }
    }
    Write-Host ""
    #Domain IOC section
    Write-Host "Do you want to enter Domain IOCs? yes or no" -ForegroundColor Yellow
    $input = Read-Host    
    if ($input -eq 'yes') {
        Write-Host "Please enter a path to your Domain IOCs: " -ForegroundColor yellow
        $domains_path = Read-Host
        Write-Host ""

        if (Test-Path "$($domains_path)") {
            $global:domainIOCs = @(Get-Content "$($Directory)\$($domains_path)")
            $domainCount = $domainIOCs.Count
            Write-Host "Loading $domainCount known Domain IOCs..." -ForegroundColor Green
        }
        else {
            Write-Host "File $($domains_path) doesn't exist..." -ForegroundColor Red
            Write-Host "File not loaded. Skipping to next IOC file." -ForegroundColor Red
        }
    }
    Write-Host ""
    #Service IOC section
    Write-Host "Do you want to enter Service IOCs? yes or no" -ForegroundColor Yellow
    $input = Read-Host    
    if ($input -eq 'yes') {
        Write-Host "Please enter a path to your Service IOCs: " -ForegroundColor yellow
        $services_path = Read-Host
        Write-Host ""

        if (Test-Path "$($services_path)") {
            $global:serviceIOCs = @(Get-Content "$($Directory)\$($services_path)")
            $serviceCount = $serviceIOCs.Count
            Write-Host "Loading $serviceCount known Service IOCs..." -ForegroundColor Green
        }
        else {
            Write-Host "File $($services_path) doesn't exist..." -ForegroundColor Red
            Write-Host "File not loaded. Skipping to next IOC file." -ForegroundColor Red
        }
    }
    Write-Host ""
    #hash IOC section
    Write-Host "Do you want to enter filesystem hash IOCs? yes or no" -ForegroundColor Yellow
    $input = Read-Host    
    if ($input -eq 'yes') {
        Write-Host "Please enter a path to your Hash IOCs: " -ForegroundColor yellow
        $hashes_path = Read-Host
        Write-Host ""

        if (Test-Path "$($hashes_path)") {
            $global:HashIOCs = @(Get-Content "$($Directory)\$($hashes_path)")
            $hashCount = $hashIOCs.Count
            Write-Host "Loading $hashCount known Hash IOCs..." -ForegroundColor Green
        }
        else {
            Write-Host "File $($hashes_path) doesn't exist..." -ForegroundColor Red
            Write-Host "File not loaded. Skipping to next IOC file." -ForegroundColor Red
        }
    }
    Write-Host ""
    Write-Host "IOC Information has been set..." -ForegroundColor Green
    Write-Host ""
    
    Write-Host "Hit ENTER to continue."  -NoNewLine -ForegroundColor yellow
    Read-Host
} 
Function Find-FileIOCs {
    Set-Output
    Set-Target
    Write-Host "Do you want to specify a path to check for the file IOCs: yes or no" -ForegroundColor Yellow
    $file_Awnser = Read-Host
    Write-Host ""
    if ($file_Awnser -eq 'yes') {
        Write-Host "Enter the path for the filesystem location that you want to hash" -ForegroundColor Yellow
        $recurse = 'no'
        $file_Path = Read-Host
        
    }
    else {
        $recurse = 'yes'
        $file_Path = "C:\"
    }
    $ProgressBar = @{
    Activity = "File Investigation"
    CurrentOperation = "None"
    Status = "Checking Hosts for known APT Suspicious Files"
    PercentComplete = 0
    }
    
    $i = 0
    
    foreach ($h in $hosts) {
        $i++
        $ProgressBar.PercentComplete = ($i/$hosts.Count)*100
        $ProgressBar.CurrentOperation = $h
        Write-Progress @ProgressBar

        try {
            $File_Results = Invoke-Command -ComputerName $h -Credential $UserCredentials -ScriptBlock {
                if ($using:recurse -eq 'no') {
                    Get-ChildItem -Path $using:file_Path -Force -ErrorAction SilentlyContinue | 
                    Select-Object -Property Name,Directory,CreationTime,CreationTimeUtc,LastAccessTime,LastAccessTimeUtc,LastWriteTime,LastWriteTimeUtc
                }
                else {
                    Get-ChildItem -Path $using:file_Path -Recurse -Force -ErrorAction SilentlyContinue | 
                    Select-Object -Property Name,Directory,CreationTime,CreationTimeUtc,LastAccessTime,LastAccessTimeUtc,LastWriteTime,LastWriteTimeUtc
                }
            }

            $fileIOC_Count = 0
            $filearray = @()
            foreach ($result in $File_Results) {
                $fileResult = $result.name
                foreach ($file in $fileIOCs) {
                    if ($fileResult -eq $file) {
                        $filearray += $result
                        $fileIOC_Count++
                    }
                }
                
            }
            Write-Host "$($FileIOC_Count) file IOCs were found on the system $h" -ForegroundColor Green
            if ($OutPut_To_File -eq "yes") {
                foreach ($result in $filearray) {
                
                Export-Csv -InputObject $result -Path "$Directory\$h\$($h)_IOCFileResults_$($enddate).csv" -NoTypeInformation -Append -ErrorAction SilentlyContinue
                }
            }
            else {
                foreach ($result in $filearray) {
                    $result
                }
            }
        }
        
        catch {
            $e = $_.Exception
            $LineNumber = $_.InvocationInfo.ScriptLineNumber
            Write-Host "Exception     : $e" -ForegroundColor Red 
            Write-Host "Line number   : $LineNumber"  -ForegroundColor Red
            Write-Host "Help Info     : Input expected is either a path to a file or comma separated list of IPv4 addresses" -ForegroundColor Yellow
        
        
            #$msg = "Error: Failed on line number '{0}' column '{1}' ('{2}'). The error was '{3}'." -f $_.Exception.Line, $_.Exception.Offset, $_.Exception.CommandInvocation.Line.Trim(), $_.Exception.Message
        }    
    }
    Write-Progress -Activity "Complete" -Completed
    Write-Host "Hit ENTER to continue."  -NoNewLine -ForegroundColor yellow
    Read-Host
    Clear-Host
    Show-HuntMenu
}

Function Find-ServiceIOCs {
    Set-Output
    Set-Target
    $ProgressBar = @{
    Activity = "Service Investigation"
    CurrentOperation = "None"
    Status = "Checking Hosts for known APT Service Names"
    PercentComplete = 0
    }
    
    $i = 0
    
    foreach ($h in $hosts) {
        $i++
        $ProgressBar.PercentComplete = ($i/$hosts.Count)*100
        $ProgressBar.CurrentOperation = $h
        Write-Progress @ProgressBar

        try {
            $Svc_Results = Invoke-Command -ComputerName $h -Credential $UserCredentials -ScriptBlock {
                foreach ($svc in $using:svcIOCs) {
                    Get-Service -ErrorAction SilentlyContinue | Select-Object -Property name,status,displayname,starttype
                    }
            }

            $ServiceIOC_Count = 0

            foreach ($result in $Svc_Results) {
                $ServiceIOC_Count++
                
            }
            Write-Host "$($ServiceIOC_Count) Service IOCs were found on the system $h" -ForegroundColor Green
            if ($OutPut_To_File -eq "yes") {
                foreach ($result in $Svc_Results) {
                
                Export-Csv -InputObject $result -Path "$Directory\$h\$($h)_IOCFileResults_$($enddate).csv" -NoTypeInformation -Append -ErrorAction SilentlyContinue
                }
            }
            else {
                foreach ($result in $Svc_Results) {
                    $result
                }
            }
        }
        
        catch {
            Set-ErrorMsg
        }    
    }
    Write-Progress -Activity "Complete" -Completed
    Write-Host "Hit ENTER to continue."  -NoNewLine -ForegroundColor yellow
    Read-Host
    Clear-Host
    Show-HuntMenu
}
#Find ScheduledTasks on a system that match IOCs
Function Find-ScheduledTaskIOCs {
    Set-Output
    Set-Target
    $ProgressBar = @{
    Activity = "Scheduled Task Investigation"
    CurrentOperation = "None"
    Status = "Checking for known APT Scheduled Tasks"
    PercentComplete = 0
    }
    
    $i = 0
    
    foreach ($h in $hosts) {
    $i++
    $ProgressBar.PercentComplete = ($i/$hosts.Count)*100
    $ProgressBar.CurrentOperation = $h
    Write-Progress @ProgressBar

        try {
    
            $Schtasks_Results = Invoke-Command -ComputerName $h -Credential $UserCredentials -ScriptBlock {
            #Look for specific jobs on a system that match Scheduled Tasks IOCS
                foreach ($task in $using:taskIOCs) {
                    
                    Get-ScheduledTask -ErrorAction SilentlyContinue | Where-Object { $_.TaskName -eq $task } | Select-Object Date,Taskname,TaskPath,Author,Triggers,Description
                    Get-ScheduledTask -ErrorAction SilentlyContinue | Where-Object { $_.TaskName -eq $task } | Select-Object -ExpandProperty Actions | Select-Object Execute,Arguments
                    }
                }
                $Schtask_Results_Count = 0

                foreach ($result in $Schtasks_Results) {
                    $Schtask_Results_Count++
                
                }
                $count = $Schtask_Results_Count/2
                Write-Host "$($count) scheduled Task IOCs were found on the system $h" -ForegroundColor Green  
    

                if ($OutPut_To_File -eq "yes") {
                    foreach ($result in $Schtasks_Results) {
                    
                    Export-Csv -InputObject $result -Path "$Directory\$h\$($h)_SchtaskIOCs_$($enddate).csv" -NoTypeInformation -Append -ErrorAction SilentlyContinue
                    }
                }
                else {
                    foreach ($result in $Schtasks_Results) {
                        $result
                }
            }
        
        }
        catch {
            Set-ErrorMsg
        }
    }
    Write-Progress -Activity "Complete" -Completed
    Write-Host "Hit ENTER to continue."  -NoNewLine -ForegroundColor yellow
    Read-Host
    clear-host    
    Show-HuntMenu
}
    
#findregs will search thru the primary registry runkeys to match a list of IOCs
Function Find-RegistryIOCs {
    Set-Output
    Set-Target
    $ProgressBar = @{
    Activity = "Registry Investigation"
    CurrentOperation = "None"
    Status = "Checking for known APT Registry Key\Value Pairs"
    PercentComplete = 0
    }
    
    $i = 0
    
    foreach ($h in $hosts) {
        $i++
        $ProgressBar.PercentComplete = ($i/$hosts.Count)*100
        $ProgressBar.CurrentOperation = $h
        Write-Progress @ProgressBar
        
        try {
        
            $RunKey_Results = Invoke-Command -ComputerName $h -Credential $UserCredentials -ScriptBlock {
                foreach ($ioc in $using:RegIOCs) {
            
                    (Get-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run -ErrorAction SilentlyContinue).PSObject.Properties | 
                    Where-Object { $_.Name -eq $ioc } | Select-Object -Property PSComputerName,Name,Value
                    (Get-ItemProperty -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run -ErrorAction SilentlyContinue).PSObject.Properties | 
                    Where-Object { $_.Name -eq $ioc } | Select-Object -Property PSComputerName,Name,Value
                    (Get-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce -ErrorAction SilentlyContinue).PSObject.Properties | 
                    Where-Object { $_.Name -eq $ioc } | Select-Object -Property PSComputerName,Name,Value
                    (Get-ItemProperty -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce -ErrorAction SilentlyContinue).PSObject.Properties | 
                    Where-Object { $_.Name -eq $ioc } | Select-Object -Property PSComputerName,Name,Value
                    }
        
                }
        
                $RegIOC_Count = 0

                foreach ($result in $RunKey_Results) {
                    $RegIOC_Count++
                
                }
                Write-Host "$($RegIOC_Count) registry IOCs were found on the system $h" -ForegroundColor Green

                if ($Output_To_File -eq 'yes') {
                    foreach ($result in $RunKey_Results) {
                        
                        Export-Csv -InputObject $result -Path "$Directory\$h\$($h)_RegistryIOCs_$($enddate).csv" -NoTypeInformation -Append -newline -Force -ErrorAction SilentlyContinue
                    }
                }
                else {
                  foreach ($result in $RunKey_Results) {
                    $result
                }
            }
        }
        catch {
            Set-ErrorMsg
        }
    }
    Write-Progress -Activity "Complete" -Completed
    Write-Host "Hit ENTER in to continue."  -NoNewLine -ForegroundColor yellow
    Read-Host
    Clear-Host
    Show-HuntMenu   
}
    
#findips will loop thru each host, Get the TCP Connection Remote Addresses, and then compare those addresses to the IOC list.
Function Find-IpIOCs {
    Set-Output
    Set-Target
    $ProgressBar = @{
    Activity = "Network Connections Investigation"
    CurrentOperation = "None"
    Status = "Checking for known APT IPs"
    PercentComplete = 0
    }
    
    $i = 0
    
    foreach ($h in $hosts) {
        $i++
        $ProgressBar.PercentComplete = ($i/$hosts.Count)*100
        $ProgressBar.CurrentOperation = $h
        Write-Progress @ProgressBar
    
        try {

            $IP_Results = Invoke-Command -ComputerName $h -Credential $UserCredentials -ScriptBlock {
                $results = ((Get-NetTCPConnection).RemoteAddress)
                foreach ($result in $results) {
                    foreach ($IP in $using:IPIOCs) {
                        if ($IP -eq $result) {
                            $IP
                        }
                    }
                }
            }
    
            $Ip_Count = 0

            foreach ($result in $IP_Results) {
                $Ip_Count++
                
            }
            Write-Host "$($Ip_Count) IP IOCs were found on the system $h" -ForegroundColor Green
            Write-Host ""

            if ($Output_To_file -eq 'yes') {
                foreach ($result in $IP_Results) {
                    
                    Export-Csv -InputObject $result -Path "$Directory\$h\$($h)_IPIOCs_$($enddate).csv" -NoTypeInformation -Append -newline -Force -ErrorAction SilentlyContinue
                   }
            }
            else {
                foreach ($result in $IP_Results) {
                    $result
                }
            }
        }
        catch {
            Set-ErrorMsg
        }
    }    
    Write-Progress -Activity "Complete" -Completed
    Write-Host ""
    Write-Host "Hit ENTER to continue."  -NoNewLine -ForegroundColor yellow
    Read-Host
    Clear-Host
    Show-HuntMenu
}

#finddomains will loop thru a list of domain IOCs and check the DnsClientCache of each host for each IOC
Function Find-DomainIOCs {
    Set-Output
    Set-Target
    $ProgressBar = @{
    Activity = "DNS Request Investigation"
    CurrentOperation = "None"
    Status = "Investigating known APT Domain Names"
    PercentComplete = 0
    }
    
    $i = 0
    
    foreach ($h in $hosts) {
        $i++
        $ProgressBar.PercentComplete = ($i/$hosts.Count)*100
        $ProgressBar.CurrentOperation = $h
        Write-Progress @ProgressBar
    
        try {
        
            $Domain_Results = Invoke-Command -ComputerName $h -Credential $UserCredentials -ScriptBlock {
                foreach ($name in $using:domainIOCs) {
                    Get-DnsClientCache | Where-Object { $_.Entry -eq $name }
                } 
            }
            
            $DomainIOC_Count = 0

            foreach ($result in $DomainIOC_Count) {
                $DomainIOC_Count++
                
            }
            Write-Host "$($DomainIOC_Count) Domain IOCs were found on the system $h" -ForegroundColor Green

            if ($Output_To_File -eq 'yes') {
                foreach ($result in $Domain_Results) {
                    
                    Export-Csv -InputObject $result -Path "$Directory\$h\$($h)_DomainIOCs_$($enddate).csv" -NoTypeInformation -Append -newline -Force -ErrorAction SilentlyContinue
                }
            }
            else {
                foreach ($result in $Domain_Results) {
                    $result
                }
            }
        }
        catch {
            Set-ErrorMsg
        }
    }
    Write-Progress -Activity "Complete" -Completed
    Write-Host "Hit ENTER to continue."  -NoNewLine -ForegroundColor yellow
    Read-Host
    Clear-Host
    Show-HuntMenu
}

Function Find-HashIOCs {
    Set-Target
    Set-Output
    Write-Host "You can specify a specific path to hash or hash the entire filesystem" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "Do you want to specify a path to hash: yes or no" -ForegroundColor Yellow
    $Hash_Awnser = Read-Host
    Write-Host ""
    if ($Hash_Awnser -eq 'yes') {
        Write-Host "Enter the path for the filesystem location that you want to hash" -ForegroundColor Yellow
        $Hash_Path = Read-Host
        $recurse = 'no'
    }
    else {
        $Hash_Path = "C:\"
        $recurse = 'yes'
    }
    Write-Host ""
    Write-Host "Creating a baseline of the filesystem recursively from $($Hash_Path)..." -ForegroundColor Cyan
    Write-Host ""
    Write-Host "This will take approximately 1 hour per host for the entire filesystem or 5 minutes per host for a location similar to the size of c:\windows\system32..." -ForegroundColor Cyan
    Write-Host ""
    
    $ProgressBar = @{
    Activity = "Investigating Filesystem Hashes"
    CurrentOperation = "None"
    Status = "Hashing the Filesystem recursively from $($Hash_Path) looking for known IOC hashes."
    PercentComplete = 0
    }
    
    $i = 0
    
    foreach ($h in $hosts) {
        $i++
        $ProgressBar.PercentComplete = ($i/$hosts.Count)*100
        $ProgressBar.CurrentOperation = $h
        Write-Progress @ProgressBar

        try {     
         
            #Execute commands on the remote host to take an MD5 hash of all items in the C:\ and store those result in the $Hash_Results variable.
            $global:Hash_Results = Invoke-Command -Computername $h -Credential $UserCredentials -ScriptBlock {
                if ($using:recurse -eq 'no') {
                    Get-ChildItem -Path $using:Hash_Path -Force -ErrorAction SilentlyContinue | Get-Filehash -Algorithm MD5 -ErrorAction SilentlyContinue
                }
                else {
                    Get-ChildItem -Path $using:Hash_Path -Force -recurse -ErrorAction SilentlyContinue | Get-Filehash -Algorithm MD5 -ErrorAction SilentlyContinue
                }
            }
            $hashIOC_Count = 0
            $hasharray = @()
            foreach ($result in $Hash_Results) {
                $hashResult = $result.hash
                foreach ($hash in $HashIOCs) {
                    if ($hashResult -eq $hash) {
                        $hasharray += $result
                        $hashIOC_Count++
                    }
                }
            
            }
            Write-Host "$($hashIOC_Count) hash IOCs were found on the system $h" -ForegroundColor Green
             
            if ($Output_To_File -eq 'yes') {
                foreach ($result in $Hash_Results) {
                    
                    Export-Csv -InputObject $hash -Path "$Directory\$h\$($h)_HashIOCs_$($enddate).csv" -NoTypeInformation -Append -ErrorAction SilentlyContinue 
                }
            } 
            else {
                foreach ($hash in $hasharray) {
                    $hash
                }
            }
        
        }

        catch {
            Set-ErrorMsg
        }
          
    } 
    Write-Progress -Activity "Complete" -Completed
    Write-Host "Hashing the Filesystem is Complete..." -ForegroundColor Green
    Write-Host ""
    Write-Host "Hit ENTER to continue."  -NoNewLine -ForegroundColor yellow
    Read-Host
    
    Show-HuntMenu
}

#NOTE: Need to add all major persistence keys following the class...
Function Get-PersistentRegistryKeys {
    Set-Output
    Set-Target   
    $ProgressBar = @{
    Activity = "Registry Key Enumeration"
    CurrentOperation = "none"
    Status = "Enumerating Registry Key\Values for Host:"
    PercentComplete = 0
    }
    
    $i = 0
    
    foreach ($h in $hosts) {
        $i++
        $ProgressBar.PercentComplete = ($i/$hosts.Count)*100
        $ProgressBar.CurrentOperation = $h
        Write-Progress @ProgressBar
        
        try {

            $Persistence_Results = Invoke-Command -ComputerName $h -Credential $UserCredentials -ScriptBlock {
                #These hives are the primary run & RunOnce keys
                Get-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\ -ErrorAction SilentlyContinue
                Get-ItemProperty -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\ -ErrorAction SilentlyContinue
                Get-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce\ -ErrorAction SilentlyContinue
                Get-ItemProperty -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce\ -ErrorAction SilentlyContinue
                Get-ItemProperty -Path HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run\ -ErrorAction SilentlyContinue
                #These hives are the startup locations
                Get-ItemProperty -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\User Shell Folders\' -ErrorAction SilentlyContinue
                Get-ItemProperty -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Shell Folders\' -ErrorAction SilentlyContinue
                Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\User Shell Folders\' -ErrorAction SilentlyContinue
                Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Shell Folders\' -ErrorAction SilentlyContinue
                <#
                #key should point at explorer.exe (should be string: explorer.exe and not full path)
                Get-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\Shell -ErrorAction SilentlyContinue
                #Should always have the value of autochk*. Otherwise, could be malicious
                Get-ItemProperty -Path HKLM:\SYSTEM\ControlSet002\Control\Session -ErrorAction SilentlyContinue
                #smss.exe loads before the Windows Subsystem so it calls the configuration subsystem to load this hive.
                Get-ItemProperty -Path HKLM\SYSTEM\CurrentControlSet\Control\hivelist -ErrorAction SilentlyContinue
                #This key should point to a PSPath under winlogon only. This is the Boot Key.
                Get-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\IniFileMapping\system.ini\boot -ErrorAction SilentlyContinue
                #This key running userinit is good. It can be manipulated and then the key will be executed by the winlogon process at login.
                Get-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon -ErrorAction SilentlyContinue
                #notify event handles when SAS happens and loads a DLL. DLL is modifiable. 
                Get-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\Notify -ErrorAction SilentlyContinue
                #>
            }
    
            if ($Output_To_File -eq 'yes') {
                foreach ($result in $Persistence_Results) {
                    Export-Csv -InputObject $result -Path "$Directory\$h\$($h)_PersistentRegistryKeys_$($enddate).csv" -NoTypeInformation -Append -newline -Force -ErrorAction SilentlyContinue
                }
            }
            else {
                foreach ($result in $Persistence_Results) {
                    $result
                }
            Write-Host "Hit ENTER when you are ready to see the next host." -NoNewLine -ForegroundColor yellow
            Read-Host
            }
        }

        catch {
            Set-ErrorMsg
        }
    }
    Write-Progress -Activity "Complete" -Completed
    Write-Host "Gathering Persistent Registry Keys Information for each host is complete." -ForegroundColor Green
    Write-Host ""
    Write-Host "Hit ENTER to continue."  -NoNewLine -ForegroundColor yellow
    Read-Host
    
    Clear-Host

    if ($SysInfo) {
        Show-SystemInfoMenu
    }
}

#Enumerate the Registry keys that are set when sticky keys is enabled...
#NOT COMPLETE - needs testing and see if this can be more precise to the sticky keys exploit
Function  Get-StickyKeysValue {
    Set-Output
    Set-Target
    $ProgressBar = @{
    Activity = "Sticky Key Attack Check"
    CurrentOperation = "None"
    Status = "Enumerating Sticky Key Values for Host:"
    PercentComplete = 0
    }
    
    $i = 0
    
    foreach ($h in $hosts) {
        $i++
        $ProgressBar.PercentComplete = ($i/$hosts.Count)*100
        $ProgressBar.CurrentOperation = $h
        Write-Progress @ProgressBar
        
        try {
        
            $StickyIcky_Results = Invoke-Command -ComputerName $h -Credential $UserCredentials -ScriptBlock {
            Get-ItemProperty -Path 'HKCU:\Control Panel\Accessibility\StickyKeys' -ErrorAction SilentlyContinue
        
            }
    

            if ($Output_To_File -eq 'yes') {
                foreach ($result in $StickyIcky_Results) {
                    Export-Csv -InputObject $result -Path "$Directory\$h\$($h)_StickyKeysCheck_$($enddate).csv" -NoTypeInformation -Append -Force -ErrorAction SilentlyContinue
                }
            }
            else {
                foreach ($result in $StickyIcky_Results) {
                    $result
                }
            Write-Host "Hit ENTER when you are ready to see the next host." -NoNewLine -ForegroundColor yellow
            Read-Host
            }
        }
        catch {
            Set-ErrorMsg
        }
    }    
    Write-Progress -Activity "Complete" -Completed
    Write-Host "Gathering Sticky Keys Information for each host is complete." -ForegroundColor Green
    Write-Host ""
    Write-Host "Hit ENTER to continue."  -NoNewLine -ForegroundColor yellow
    Read-Host
    Clear-Host
    if ($SysInfo) {
        Show-SystemInfoMenu
    }
}
    
Function Get-SchTasks{
    Set-Output
    Set-Target
    foreach ($h in $hosts) {
        try {

            if ($Output_To_File -eq 'yes') {
                $Schtasks_Results = Invoke-Command -ComputerName $h -Credential $UserCredentials -ScriptBlock {
                Get-ScheduledTask | Select-Object -Property Date,Taskname,TaskPath,Author,Triggers,Description -ErrorAction SilentlyContinue
                }
                
                foreach ($result in $Schtasks_Results) {
                    
                    Export-Csv -InputObject $result -Path "$Directory\$h\$($h)_ScheduledTasks_$($enddate).csv" -NoTypeInformation -Append -Force -ErrorAction SilentlyContinue
                }
            }
            else {
                $Schtasks_Results = Invoke-Command -ComputerName $h -Credential $UserCredentials -ScriptBlock {
                Get-ScheduledTask | Select-Object -Property Date,Taskname,TaskPath,Author,Triggers,Description -ErrorAction SilentlyContinue
                }

                
                Write-Host "Hit ENTER when you are ready to see the next host." -NoNewLine -ForegroundColor yellow
                Read-Host 
            }
            
            if ($Output_To_File -eq 'yes') {
                foreach ($result in $SchTasks_Results) {
                    Export-Csv -InputObject $result -Path "$Directory\$h\$($h)_ServicesInfo_$($enddate).csv" -NoTypeInformation -Append -ErrorAction SilentlyContinue
                    }
                }
            else {
                $SchTasks_Results | Format-Table
            }
        }
        catch {
            Set-ErrorMsg
        }
    }

    Write-Host "Gathering scheduled task information for each host is complete." -ForegroundColor Green
    Write-Host ""
    Write-Host "Hit ENTER to continue."  -NoNewLine -ForegroundColor yellow
    Read-Host
    Clear-Host
    if ($SysInfo) {
        Show-SystemInfoMenu
    }
}
    
Function Invoke-FindFile {
    Set-Target
    Write-Host " "
    $filename = Read-Host "Enter the filename: " 
                
    Write-Host "Recursively Dir the C:\ looking for $filename..." -ForegroundColor Cyan
    Invoke-Command -ComputerName $hosts -Credential $UserCredentials -ScriptBlock {
    #Recursively search the c drive for the filename
    Get-ChildItem c:\ -Include $using:filename -Recurse -Force -ErrorAction SilentlyContinue
    
    }
    
    Write-Host "Hit ENTER to continue."  -NoNewLine -ForegroundColor yellow
    Read-Host
    Clear-Host    
    if ($SysInfo) {
        Show-SystemInfoMenu
    }
}

Function Get-DirectoryContents {
    Set-Output
    Set-Target
    Write-Host ""
    $ProgressBar = @{
    Activity = "Listing Directory Contents"
    CurrentOperation = "None"
    Status = "Getting Directory Contents"
    PercentComplete = 0
    }
    
    $i = 0

    Write-Host "Please enter the directory name: " -ForeGroundColor yellow
    $path = Read-Host

    foreach ($h in $hosts) {
        $i++
        $ProgressBar.PercentComplete = ($i/$hosts.Count)*100
        $ProgressBar.CurrentOperation = $h
        Write-Progress @ProgressBar
        $Directory_Results = Invoke-Command -ComputerName $h -Credential $UserCredentials -ScriptBlock {
            #Recursively search the c drive for the filename provided at command line
            Get-ChildItem $using:path -Force -ErrorAction SilentlyContinue
           
        }

        if ($Output_To_File -eq 'yes') {
            foreach ($result in $Directory_Results) {
                
                Export-Csv -InputObject $result -Path "$Directory\$h\$($h)_DirectoryContents_$($enddate).csv" -NoTypeInformation -Append -ErrorAction SilentlyContinue
            }
        }
        else {
            foreach ($result in $Directory_Results) {
                $result
            }
        }
        Write-Host "Hit ENTER when you are ready to see the next host." -NoNewLine -ForegroundColor yellow
        Read-Host
    }
    
    Write-Progress -Activity "Complete" -Completed
    Write-Host "Gathering directory contents information for each host is complete." -ForegroundColor Green
    Write-Host ""
    
    Write-Host "Hit ENTER to continue."  -NoNewLine -ForegroundColor yellow
    $input = Read-Host
    Clear-Host
    if ($SysInfo) {
        Show-SystemInfoMenu
    }
}

#Need to Add functionality to list just running Services
Function Get-ServiceInfo {
    Set-Output
    Set-Target
    $ProgressBar = @{
    Activity = "System Services Enumeration"
    CurrentOperation = "None"
    Status = "Gathering Service Information"
    PercentComplete = 0
    }
    
    $i = 0      
           
    Write-Host "Getting the Taskname,DisplayName and Status for all services on the remote system(s)..." -ForegroundColor Cyan
    
    foreach ($h in $hosts) {
        $i++
        $ProgressBar.PercentComplete = ($i/$hosts.Count)*100
        $ProgressBar.CurrentOperation = $h
        Write-Progress @ProgressBar
        
        try {
                
        $Service_Results = Invoke-Command -ComputerName $h -Credential $UserCredentials -ScriptBlock {
            if ($using:Output_To_File -eq 'yes') {
                Get-Service -ErrorAction SilentlyContinue | Select-Object -Property name,status,displayname,starttype
            }
            else {
                Get-Service -ErrorAction SilentlyContinue | Select-Object -Property name,status,displayname,starttype | Where-Object {$_.status -eq 'running'} 
            }
        }

            if ($Output_To_File -eq 'yes') {
                foreach ($result in $Service_Results) {
                    
                    Export-Csv -InputObject $result -Path "$Directory\$h\$($h)_ServicesInfo_$($enddate).csv" -NoTypeInformation -Append -ErrorAction SilentlyContinue
                    }
                }
            else {
                $Service_Results | Format-Table
            }
            Write-Host "Hit ENTER when you are ready to see the next host." -NoNewLine -ForegroundColor yellow
            Read-Host

        }
        catch {
            Set-ErrorMsg
        }
    }
    Write-Progress -Activity "Complete" -Completed
    Write-Host "Hit ENTER to continue" -NoNewline -ForegroundColor Yellow
    $input = Read-Host
    Clear-Host
    if ($SysInfo) {
        Show-SystemInfoMenu
    }
}

Function Get-ProcessInfo {
    Set-Output
    Set-Target      
    $ProgressBar = @{
    Activity = "System Process Enumeration"
    CurrentOperation = "None"
    Status = "Gathering Process Information"
    PercentComplete = 0
    }
    
    $i = 0
           
    Write-Host "Getting the Taskname,DisplayName and Status for all services on the remote system(s)..." -ForegroundColor Cyan
    foreach ($h in $hosts) {
        $i++
        $ProgressBar.PercentComplete = ($i/$hosts.Count)*100
        $ProgressBar.CurrentOperation = $h
        Write-Progress @ProgressBar
        
        try {
        
            $Process_Results = Invoke-Command -ComputerName $h -Credential $UserCredentials -ScriptBlock {
                if ($using:Output_To_File -eq 'yes') {
                   Get-WMIObject -class win32_process | Select-Object processname,processid,parentprocessid,commandline,path 
                }
                else {
                    Get-WMIObject -class win32_process | Select-Object PSComputername,processname,processid,parentprocessid,commandline 
                }
            }   
                
            
            if ($Output_To_File -eq 'yes') {
                foreach ($result in $Process_Results) {
                    Export-Csv -InputObject $result -Path "$Directory\$h\$($h)_Processes_$($enddate).csv" -NoTypeInformation -Append -ErrorAction SilentlyContinue
                    }
                }
            else {
                $Process_Results | format-table

                }
            Write-Host "Hit ENTER when you are ready to see the next host." -NoNewLine -ForegroundColor yellow
            Read-Host
            
            
        }
        catch {
            $msg = "Error: Failed on line number '{0}' column '{1}' ('{2}'). The error was '{3}'." -f $_.Exception.Line, $_.Exception.Offset, $_.Exception.CommandInvocation.Line.Trim(), $_.Exception.Message
            $msg
        }
    }
    Write-Progress -Activity "Complete" -Completed
    Write-Host "Gathering Process Information for each host is complete." -ForegroundColor Green
    Write-Host ""
    Write-Host "Hit ENTER to continue."  -NoNewLine -ForegroundColor yellow
    Read-Host
    Clear-Host
    if ($SysInfo) {
        Show-SystemInfoMenu
    }
}
    
Function Get-Hotfixes {
    Set-Output
    Set-Target
    Write-Host "Getting information on what KBs have been patched..." -ForegroundColor Cyan
    foreach ($h in $hosts) {
        try {
        
            $Patch_Results = Invoke-Command -ComputerName $h -Credential $UserCredentials -ScriptBlock {
                Get-Hotfix
                }
        
            if ($Output_To_File -eq "yes") {
                foreach ($result in $Patch_Results) {
                Export-Csv -InputObject $result -Path "$Directory\$h\$($h)_HotFix_Information_$($enddate).csv" -NoTypeInformation -Append -ErrorAction SilentlyContinue
                }
            }
            else {
                $Patch_Results | Format-Table
            }
            Write-Host "Hit ENTER when you are ready to see the next host." -NoNewLine -ForegroundColor yellow
            Read-Host
            
        }
        
        catch {
            Set-ErrorMsg
        }
    }

    Write-Host "Hit ENTER to continue."  -NoNewLine -ForegroundColor yellow
    Read-Host
    Clear-Host
    if ($SysInfo) {
        Show-SystemInfoMenu
    }
}

Function Get-NetConns {
Set-Output
Set-Target

Write-Host "Getting information on network connections..." -ForegroundColor Cyan
    foreach ($h in $hosts) {
        try {
        
            $Conn_Results = Invoke-Command -ComputerName $h -Credential $UserCredentials -ScriptBlock {
                Get-NetTCPConnection | Select-Object -property localaddress,localport,remoteaddress,remoteport,state,OwningProcess 
            }
            if ($Output_To_File -eq "yes") {
                foreach ($result in $Conn_Results) {
                Export-Csv -InputObject $result -Path "$Directory\$h\$($h)_NetworkConnections_$($enddate).csv" -NoTypeInformation -Append -ErrorAction SilentlyContinue
                }
            }
            else {
                $Conn_Results | Format-Table -AutoSize
            }
            Write-Host "Hit ENTER when you are ready to see the next host." -NoNewLine -ForegroundColor yellow
            Read-Host
            
        }
        catch {
            Set-ErrorMsg
        }
    }

    Write-Host "Hit ENTER to continue."  -NoNewLine -ForegroundColor yellow
    Read-Host
    Clear-Host
    if ($SysInfo) {
        Show-SystemInfoMenu
    }
}
 

    
Function Get-AutoRuns {
    Set-Output
    Set-Target
    $ProgressBar = @{
    Activity = "AutoRuns Investigation"
    CurrentOperation = "None"
    Status = "Checking AutoRun Locations"
    PercentComplete = 0
    }
    
    $i = 0

    Write-Host "Getting host autorun information..." -ForegroundColor Cyan
    foreach ($h in $hosts) {
        $i++
        $ProgressBar.PercentComplete = ($i/$hosts.Count)*100
        $ProgressBar.CurrentOperation = $h
        Write-Progress @ProgressBar
        
        try {
        
            $AutoRun_Results = Invoke-Command -ComputerName $h -Credential $UserCredentials -ScriptBlock {
                Get-WmiObject -class win32_startupcommand | Select-Object Name,command,location,User
            }
    

            if ($Output_To_File -eq "yes") {
                foreach ($result in $AutoRun_Results) {
                    Export-Csv -InputObject $result -Path "$Directory\$h\$($h)_AutoRuns_$($enddate).csv" -NoTypeInformation -Append -ErrorAction SilentlyContinue
                }
            }
            else {
                $AutoRun_Results | Format-Table -AutoSize
            }
            Write-Host "Hit ENTER when you are ready to see the next host." -NoNewLine -ForegroundColor yellow
            Read-Host
            
        }

        catch {
            Set-ErrorMsg
        }
    }
    Write-Progress -Activity "Complete" -Completed
    Write-Host "Hit ENTER to continue."  -NoNewLine -ForegroundColor yellow
    Read-Host
    Clear-Host
    if ($SysInfo) {
        Show-SystemInfoMenu
    }
}
    
Function Get-UserInfo {
    Set-Output
    Set-Target
    $ProgressBar = @{
    Activity = "User Information Investigation"
    CurrentOperation = "None"
    Status = "Gathering User Information from each host"
    PercentComplete = 0
    }
    
    $i = 0

    foreach ($h in $hosts) {
        $i++
        $ProgressBar.PercentComplete = ($i/$hosts.Count)*100
        $ProgressBar.CurrentOperation = $h
        Write-Progress @ProgressBar
    
        try {

            $User_Results = Invoke-Command -ComputerName $h -Credential $UserCredentials -ScriptBlock {
            #If Lockout is True, the account is locked.
               #Update later so that PasswordExpires is the Date. 
              Get-WmiObject Win32_UserAccount | Select-Object Name,Fullname,Domain,Lockout,PasswordExpires,SID
            }
    

            if ($Output_To_File -eq "yes") {
                foreach ($result in $User_Results) {
                   Export-Csv -InputObject $result -Path "$Directory\$h\$($h)_UserInfo_$($enddate).csv" -NoTypeInformation -Append -ErrorAction SilentlyContinue
                }
            }
            else {
                $User_Results | Format-Table -AutoSize
            }
            Write-Host "Hit ENTER when you are ready to see the next host." -NoNewLine -ForegroundColor yellow
            Read-Host
            
        }

        catch {
            Set-ErrorMsg
        }
    }
    Write-Progress -Activity "Complete" -Completed
    Write-Host "Hit ENTER to continue."  -NoNewLine -ForegroundColor yellow
    Read-Host 
    Clear-Host
    if ($SysInfo) {
        Show-SystemInfoMenu
    }
}
    
Function Get-GroupInfo {
    Set-Output
    Set-Target
    $ProgressBar = @{
    Activity = "Group Information Enumeration"
    CurrentOperation = "None"
    Status = "Gathering Group Information from each host"
    PercentComplete = 0
    }
    
    $i = 0

    foreach ($h in $hosts) {
        $i++
        $ProgressBar.PercentComplete = ($i/$hosts.Count)*100
        $ProgressBar.CurrentOperation = $h
        Write-Progress @ProgressBar
        
        try {
        
            $Group_Results = Invoke-Command -ComputerName $h -Credential $UserCredentials -ScriptBlock {
                #If Lockout is True, the account is locked.
                #Update later so that PasswordExpires is the Date. 
                Get-WMIObject Win32_Group | Select-Object Name,Domain,Description,SID
            }
    
            if ($Output_To_File -eq "yes") {
                foreach ($result in $Group_Results) {
                    Export-Csv -InputObject $result -Path "$Directory\$h\$($h)_GroupInfo_$($enddate).csv" -NoTypeInformation -Append -ErrorAction SilentlyContinue
                }
            }
            else {
                $Group_Results | Format-Table -AutoSize
            }
            Write-Host "Hit ENTER when you are ready to see the next host." -NoNewLine -ForegroundColor yellow
            Read-Host
            
        }

        catch {
           Set-ErrorMsg
        }
    }
    Write-Progress -Activity "Complete" -Completed
    Write-Host "Hit ENTER to continue."  -NoNewLine -ForegroundColor yellow
    Read-Host
    Clear-Host
    if ($SysInfo) {
        Show-SystemInfoMenu
    }
}
    
Function Get-LocalGroupinfo {
    Set-Output
    Set-Target
    $ProgressBar = @{
    Activity = "Local Group Information Enumeration"
    CurrentOperation = "None"
    Status = "Gathering Group Information from each host"
    PercentComplete = 0
    }
    
    $i = 0

    Write-Host "Getting information about what users are in the localgroup Administrators..." -ForegroundColor Cyan
    foreach ($h in $hosts) {
        $i++
        $ProgressBar.PercentComplete = ($i/$hosts.Count)*100
        $ProgressBar.CurrentOperation = $h
        Write-Progress @ProgressBar
        
        try {
        
            $LocalAdmin_Results = Invoke-Command -ComputerName $h -Credential $UserCredentials -ScriptBlock {
                Get-LocalGroupMember -Name Administrators
            }

            if ($Output_To_File -eq "yes") {
                foreach ($result in $LocalAdmin_Results) {
                    Export-Csv -InputObject $result -Path "$Directory\$h\$($h)_LocalGroupInfo_$($enddate).csv" -NoTypeInformation -Append -ErrorAction SilentlyContinue
                }
            }
            else {
                foreach ($result in $LocalAdmin_Results) {
                    $result
                }
            Write-Host "Hit ENTER when you are ready to see the next host." -NoNewLine -ForegroundColor yellow
            Read-Host
            }
        }

        catch {
            Set-ErrorMsg
        }
    }
    Write-Progress -Activity "Complete" -Completed
    Write-Host "Hit ENTER to continue."  -NoNewLine -ForegroundColor yellow
    Read-Host
    Clear-Host
    if ($SysInfo) {
        Show-SystemInfoMenu
    }
}


Function Get-NetworkDrives {
    Set-Output
    Set-Target
    #Retrieve network drives from remote hosts
    foreach ($h in $hosts) {
        
        try {
        
            $Share_Results = Invoke-Command -ComputerName $h -Credential $UserCredentials -ScriptBlock {
                Get-WmiObject Win32_LogicalDisk | Select-Object Name, DriveType, FreeSpace, size 
                }

            if (!$Share_Results) {
                Write-Host "$h does not have mapped shares" -ForegroundColor Green
            }
            else {
                if ($Output_To_File -eq "yes") {
                    foreach ($result in $Share_Results) {
                        Export-Csv -InputObject $result -Path "$Directory\$h\$($h)_Shares_$($enddate).csv" -NoTypeInformation -Append -ErrorAction SilentlyContinue
                    }
                }
                else {
                    foreach ($result in $Share_Results) {
                        $result
                    }
                Write-Host "Hit ENTER when you are ready to see the next host." -NoNewLine -ForegroundColor yellow
                Read-Host
                }
            }
        }

        catch {
           Set-ErrorMsg
        }
    }
    

    Write-Host "Hit ENTER to continue."  -NoNewLine -ForegroundColor yellow
    Read-Host

    if ($SysInfo) {
        Show-SystemInfoMenu
    }
}
 
Function Get-LogicalDrives {
    Set-Output
    Set-Target
    #Retrieve network drives from remote hosts
   
    foreach ($h in $hosts) {
        
        try {
            Write-Host $h
            $global:DriveInfo = Invoke-Command -ComputerName $h -Credential $UserCredentials -ScriptBlock {
                Get-WmiObject Win32_LogicalDisk | Select-Object DeviceID, DriveType, FreeSpace, size
                #Get-PSDrive -PSProvider FileSystem 
            }    
    
    
            if ($Output_To_File -eq 'yes') {

                foreach ($result in $DriveInfo) {
                    Export-Csv -InputObject $result -Path c"$Directory\$h\$($h)_LogicalDrives_$($enddate).csv" -NoTypeInformation -Append
                }
            }
            else {
                foreach ($result in $DriveInfo) {
                    $result
                }
            Write-Host "Hit ENTER when you are ready to see the next host." -NoNewLine -ForegroundColor yellow
            Read-Host
            }
        }

        catch {
            Set-ErrorMsg
        }
    }

    Write-Host "Hit ENTER to continue."  -NoNewLine -ForegroundColor yellow
    Read-Host

    if ($SysInfo) {
        Show-SystemInfoMenu
    }
    
}

Function Get-ProcessCallOuts {
    Set-Output
    Set-Target
    foreach ($h in $hosts) {
        
        try {
            
            $ProcCall_Results = Invoke-Command -ComputerName $h -Credential $UserCredentials -ScriptBlock {
                $procinfo = Get-WmiObject win32_process| Select-Object -Property name,processid,parentprocessid,executablepath,commandline
                $netinfo = Get-NetTCPConnection | Select-Object -Property localaddress,localport,remoteaddress,remoteport,state,OwningProcess
                foreach ($line in $procinfo) {
                    foreach ($conn in $netinfo) {
                        if ($line.processid -eq $conn.Owningprocess) {
                            "$($line.name)`t`t$($line.processid)`t`t$($line.parentprocessid)`t`t$($conn.localaddress)`t`t$($conn.localport)`t`t$($conn.remoteaddress)`t`t$($conn.remoteport)`t`t$($conn.state)`t`t$($line.executablepath)`t`t$($line.commandline)"
   
                        }
                    }
                }
            }

            if ($Output_To_File -eq 'yes') {

                foreach ($result in $CommandLine_Results) {
                    Export-Csv -InputObject $result -Path "$Directory\$h\$($h)_CommandLineInspection_$($enddate).csv" -NoTypeInformation -Append -Force -ErrorAction SilentlyContinue
                }
            }
            else {
                write-Host "ProcessName`t`tProcessID`t`tParentProcessID`t`tLocalAddress`t`tLocalPort`t`tRemoteAddress`t`tRemotePort`t`tState`t`tExecutablePath`t`tCommandLineArgs"
                foreach ($result in $ProcCall_Results) {
                    $result
                    Write-Host ""
                } 
            }
            Write-Host "Hit ENTER when you are ready to see the next host." -NoNewLine -ForegroundColor yellow
            Read-Host
            
        }

        catch {
            Set-ErrorMsg
        }
    }

    Write-Host "Complete" -ForegroundColor Green

    Write-Host "Hit ENTER to continue."  -NoNewLine -ForegroundColor yellow
    Read-Host

    if ($SysInfo) {
        Show-SystemInfoMenu
    }
    
}

Function Get-NamedPipes {
    Set-Output
    Set-Target
    foreach ($h in $hosts) {
        
        try {
            
            $NamedPipe_Results = Invoke-Command -ComputerName $h -Credential $UserCredentials -ScriptBlock {
                [System.IO.Directory]::GetFiles("\\.\\pipe\\")
                
            }    
    
    
            if ($Output_To_File -eq 'yes') {

                foreach ($result in $NamedPipe_Results) {
                    Export-Csv -InputObject $result -Path "$Directory\$h\$($h)_NamedPipeResults_$($enddate).csv" -NoTypeInformation -Append -Force -ErrorAction SilentlyContinue
                }
            }
            else {
                foreach ($result in $NamedPipe_Results) {
                    $result
                }
            Write-Host ""
            Write-Host "Hit ENTER when you are ready to see the next host." -NoNewLine -ForegroundColor yellow
            Read-Host
            }
        }

        catch {
            Set-ErrorMsg
        }
    }
    Write-Host ""
    Write-Host "Getting named pipes on the remote systems is complete." -ForegroundColor Green
    Write-Host ""
    Write-Host "Hit ENTER to continue."  -NoNewLine -ForegroundColor yellow
    Read-Host

    if ($SysInfo) {
        Show-SystemInfoMenu
    }
    
}

Function Get-FileSystemHash {
    
    Write-Host "The recommended output of hashing the filesystem is csv." -ForegroundColor Cyan
    Set-Target
    Set-Output
    Write-Host "You can specify a specific path to hash or hash the entire filesystem" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "Do you want to specify a path to hash: yes or no" -ForegroundColor Yellow
    $Hash_Awnser = Read-Host
    if ($Hash_Awnser -eq 'yes') {
        Write-Host "Enter the path for the filesystem location that you want to hash" -ForegroundColor Yellow
        $Hash_Path = Read-Host
    }
    else {
        $Hash_Path = "C:\"
    }
    Write-Host ""
    Write-Host "Creating a baseline of the filesystem recursively from $($Hash_Path)..." -ForegroundColor Cyan
    Write-Host ""
    Write-Host "This will take approximately 1 hour per host for the entire filesystem or 10 minutes per host for a location similar to the size of c:\windows\system32..." -ForegroundColor Cyan
    Write-Host ""
    
    $ProgressBar = @{
    Activity = "Creating System Baseline"
    CurrentOperation = "None"
    Status = "Hashing the Filesystem recursively from $($Hash_Path)."
    PercentComplete = 0
    }
    
    $i = 0
    
    foreach ($h in $hosts) {
        $i++
        $ProgressBar.PercentComplete = ($i/$hosts.Count)*100
        $ProgressBar.CurrentOperation = $h
        Write-Progress @ProgressBar

        try {     
         
            #Execute commands on the remote host to take an MD5 hash of all items in the C:\ and store those result in the $Hash_Results variable.
            $global:Hash_Results = Invoke-Command -Computername $h -Credential $UserCredentials -ScriptBlock {
                #Recursively identify the contents of each drive
                Get-ChildItem -Path $using:Hash_Path -Recurse -Force -ErrorAction SilentlyContinue | Get-Filehash -Algorithm MD5 -ErrorAction SilentlyContinue
                Write-Host "Hit Enter when ready to process next drive."
                Read-Host
                }
            
             
            if ($Output_To_File -eq 'yes') {
                foreach ($result in $Hash_Results) {
                    
                    Export-Csv -InputObject $result -Path "$Directory\$h\$($h)_HashList_$($enddate).csv" -NoTypeInformation -Append -ErrorAction SilentlyContinue 
                }
            }
            else {
                foreach ($result in $Hash_Results) {
                    $result
                }
            }
        
        }

        catch {
            Set-ErrorMsg
        }
          
    } 
    Write-Progress -Activity "Complete" -Completed
    Write-Host "Hashing the Filesystem is Complete..." -ForegroundColor Green
    Write-Host ""
    Write-Host "Hit ENTER to continue."  -NoNewLine -ForegroundColor yellow
    Read-Host
    
    Show-BaselineMenu
}

Function Get-DomainUsers {
    Set-Output
    Write-Host ""
    Write-Host "You can get all attibutes of a single user or list all users." -ForegroundColor Cyan
    Write-Host ""
    Write-Host "Do you want to display attributes of a single user? yes or no " -ForegroundColor Yellow
    $SingleUser = Read-Host
    Write-Host ""
    if ($SingleUser -eq 'no') {
        Write-Host "Enumerating Domain Users from $($dc)..." -ForegroundColor Cyan
        Write-Host ""
    }
    else {
        Write-Host "Enter the username:" -ForegroundColor Yellow
        $username = Read-Host
        Write-Host ""
        Write-Host "Enumerating user attributes for $($username) from $($dc)..." -ForegroundColor Cyan
    }
    
    
    try {

        $DomainUsers_Results = Invoke-Command -ComputerName $dc -Credential $UserCredentials -ScriptBlock {
            Import-Module ActiveDirectory
            if ($using:SingleUser -eq 'no') {
                Get-ADUser -Filter * | Select-Object -Property Name,SamAccountName,distinguishedname
            }
            else {
                Get-ADUser $using:username -property * 
            }
             
        }
    
        if ($Output_To_File -eq 'yes') {
            foreach ($result in $DomainUsers_Results) {
                
                Export-Csv -InputObject $result -Path "$Directory\$dc\$($dc)_DomainUsers_$($enddate).csv" -NoTypeInformation -Append -Force -ErrorAction SilentlyContinue 
            }
        }
        else {
            if ($SingleUser -eq 'no') {
                $DomainUsers_Results | Format-Table -AutoSize
            }
            else {
                $DomainUsers_Results
            }
        }
    }

    catch {
        Set-ErrorMsg    
    }
        
    Write-Host "Complete..." -ForegroundColor Green
    Write-Host "Hit Enter to Continue..."
    Read-Host
    Show-DomainMenu

}
Function Get-DomainGroups {
    Set-Output
    Write-Host ""
    Write-Host "You can get all attibutes of a single group or list all groups." -ForegroundColor Cyan
    Write-Host ""
    Write-Host "Do you want to display attributes of a single group? yes or no " -ForegroundColor Yellow
    $SingleGroup = Read-Host
    Write-Host ""
    if ($SingleGroup -eq 'no') {
        Write-Host "Enumerating Domain Groups from $($dc)..." -ForegroundColor Cyan
        Write-Host ""
    }
    else {
        Write-Host "Enter the group name:" -ForegroundColor Yellow
        $groupname = Read-Host
        Write-Host ""
        Write-Host "Enumerating group attributes for $($groupname) from $($dc)..." -ForegroundColor Cyan
    }
    try {

        $DomainGroups_Results = Invoke-Command -ComputerName $dc -Credential $UserCredentials -ScriptBlock {
            Import-Module ActiveDirectory
            if ($using:SingleGroup -eq 'no') {
                Get-ADGroup -Filter * | Select-Object  name,samaccountname,distinguishedname,SID
            }
            else {
                Get-ADGroup $using:groupname -property * 
            }
             
        }
    
        if ($Output_To_File -eq 'yes') {
            foreach ($result in $DomainGroups_Results) {
                Export-Csv -InputObject $result -Path "$Directory\$dc\$($dc)_DomainGroups_$($enddate).csv" -NoTypeInformation -Append -ErrorAction SilentlyContinue 
            }
        }
        else {
            if ($SingleGroup -eq 'no') {
                $DomainGroups_Results | Format-Table -AutoSize
            }
            else {
                $DomainGroups_Results
            }
            
        }
    }

    catch {
        Set-ErrorMsg
    }
        
    Write-Host "Complete..." -ForegroundColor Green
    Write-Host "Hit Enter to Continue..." -NoNewline -ForegroundColor Yellow
    Read-Host
    Show-DomainMenu
}

Function Get-DomainComputers {
    Set-Output
    Write-Host ""
    Write-Host "You can get all attibutes of a single computer or list all computers." -ForegroundColor Cyan
    Write-Host ""
    Write-Host "Do you want to display attributes of a single computer? yes or no " -ForegroundColor Yellow
    $SingleComputer = Read-Host
    Write-Host ""
    if ($SingleComputer -eq 'no') {
        Write-Host "Enumerating Domain Computers from $($dc)..." -ForegroundColor Cyan
        Write-Host ""
    }
    else {
        Write-Host "Enter the computer name:" -ForegroundColor Yellow
        $computername = Read-Host
        Write-Host ""
        Write-Host "Enumerating computer attributes for $($computername) from $($dc)..." -ForegroundColor Cyan
    }
    try {

        $DomainComputers_Results = Invoke-Command -ComputerName $dc -Credential $UserCredentials -ScriptBlock {
            Import-Module ActiveDirectory
            if ($using:SingleComputer -eq 'no') {
                Get-ADComputer -Filter * | Select-Object -property name,samaccountname,distinguishedname
            }
            else {
                Get-ADComputer $using:computername -property * 
            }
        }

        if ($Output_To_File -eq 'yes') {
            foreach ($result in $DomainComputers_Results) {
                Export-Csv -InputObject $result -Path "$Directory\$dc\$($dc)_DomainComputers_$($enddate).csv" -NoTypeInformation -Append -ErrorAction SilentlyContinue 
            }
        }
        else {
            $DomainComputers_Results
        }
    }

    catch {
        Set-ErrorMsg
    }
        
    Write-Host "Complete..." -ForegroundColor Green
    Write-Host "Hit Enter to Continue..." -NoNewline -ForegroundColor Yellow
    Read-Host
    Show-DomainMenu
}

Function Get-DomainTrusts {
    Set-Output
    
    Write-Host "Enumerating Domain Trusts from $dc..." -ForegroundColor Cyan
    
    try {

        $DomainTrusts_Results = Invoke-Command -ComputerName $dc -Credential $UserCredentials -ScriptBlock {
            Import-Module ActiveDirectory
            Get-ADTrust -Filter * | Select-Object name,direction,source,target,trusttype
        }
    
        if ($Output_To_File -eq 'yes') {
            foreach ($result in $DomainTrusts_Results) {
                Export-Csv -InputObject $result -Path "$Directory\$dc\$($dc)_DomainTrusts_$($enddate).csv" -NoTypeInformation -Append -ErrorAction SilentlyContinue 
            }
        }
        else {
            $DomainTrusts_Results | Format-Table -AutoSize
        }
    }

    catch {
        Set-ErrorMsg
    }
    
    Write-Host "Complete..." -ForegroundColor Green    
    Write-Host "Hit Enter to Continue..." -nonewline -ForegroundColor yellow
    Read-Host
    Show-DomainMenu
}

function Get-LogonSuccesses 
{
    Set-Output
    Set-LogTimeFrame
    Set-Target
    try {
        foreach ($h in $hosts) {
            $Event_Results = Invoke-Command -ComputerName $h -Credential $UserCredentials -ScriptBlock {
                #$EventsToParse = $using:events
                $events = Get-WinEvent -FilterHashtable @{LogName=$using:Logname; ID=$using:ID;StartTime=$using:EarliestTime;EndTime=$using:LatestTime}
                #$Events | format-list *
                #$Events.Properties
    
                foreach ($event in $events)
                {
                    $eventXML = [xml]$event.ToXml()
                    $eventArray = New-Object -TypeName PSObject -Property @{

                    EventID = $event.id
                    TimeCreated = $event.timecreated
                    SubjectAccountName = $eventXML.Event.EventData.Data[1].'#text'
                    SubjectAccountDomain = $eventXML.Event.EventData.Data[2].'#text'
                    UserName = $eventXML.Event.EventData.Data[5].'#text'
                    Domain = $eventXML.Event.EventData.Data[6].'#text'
                    LogonType = $eventXML.Event.EventData.Data[8].'#text'
                    ProcessName = $eventXML.Event.EventData.Data[17].'#text'
                    ProcessID = $event.ProcessID
                    }
                
                    $eventArray | Select-Object EventID,TimeCreated,SubjectAccountName,SubjectAccountDomain,Username,Domain,logontype,processname,ProcessID
                } 
            }    
            #Set-LogFormat
            if ($Output_To_File -eq 'yes') {
                foreach ($result in $Event_Results) {
                    Export-Csv -InputObject $result -Path "$Directory\$h\$($h)_LogonSuccessLogs_$($enddate).csv" -NoTypeInformation -Append -ErrorAction SilentlyContinue 
                }
            }
            else {
                foreach ($result in $Event_Results) {
                    $result
                }
            }
        }
    }
    catch {
        Set-ErrorMsg
    }
    Write-Host "Complete..." -ForegroundColor Green    
    Write-Host "Hit Enter to Continue..." -nonewline -ForegroundColor yellow
    Read-Host
    Show-LogParserMenu
}

Function Get-DomainUserCreation
{
    Set-Output
    Set-LogTimeFrame
    Set-Target
    try {
        foreach ($h in $hosts) {
            $Event_Results = Invoke-Command -ComputerName $h -Credential $UserCredentials -ScriptBlock {
    
                $events = Get-WinEvent -FilterHashtable @{LogName='Security';ID=4727;StartTime=$using:EarliestTime;EndTime=$using:LatestTime} -MaxEvents 100
    
                foreach ($event in $events)
                {
                    $eventXML = [xml]$event.ToXml()
                    $eventArray = New-Object -TypeName PSObject -Property @{

                    EventID = $event.id
                    TimeCreated = $event.timecreated
                    SubjectSID = $eventXML.Event.EventData.Data[3].'#text'
                    SubjectAccountName = $eventXML.Event.EventData.Data[4].'#text'
                    SubjectDomain = $eventXML.Event.EventData.Data[5].'#text'
                    NewAccountSID = $eventXML.Event.EventData.Data[2].'#text'
                    NewAccountName = $eventXML.Event.EventData.Data[0].'#text'
                    NewAccountDomain = $eventXML.Event.EventData.Data[1].'#text'
                    NewAccountSamAccountName = $eventXML.Event.EventData.Data[8].'#text'
                    ProcessID = $event.ProcessID
                    }

                    $eventArray | Select-Object EventID,TimeCreated,SubjectSID,SubjectAccountName,SubjectDomain,NewAccountSID,NewAccountName,NewAccountDomain,NewAccountSamAccountName,ProcessID
                }
            }

            if ($Output_To_File -eq 'yes') {
                foreach ($result in $Event_Results) {
                    Export-Csv -InputObject $result -Path "$Directory\$h\$($h)_DomainUserCreatedLogs_$($enddate).csv" -NoTypeInformation -Append -ErrorAction SilentlyContinue 
                }
            }
            else {
                foreach ($result in $Event_Results) {
                    $result 
                }
            }
        }
    }
    catch {
        Set-ErrorMsg
    }
    Write-Host "Complete..." -ForegroundColor Green    
    Write-Host "Hit Enter to Continue..." -nonewline -ForegroundColor yellow
    Read-Host
    Show-LogParserMenu
}


Function Get-DomainUserEnabled
{
    Set-Output
    Set-LogTimeFrame
    Set-Target
    try {
        foreach ($h in $hosts) {
            $Event_Results = Invoke-Command -ComputerName $h -Credential $UserCredentials -ScriptBlock {
    
            $events = Get-WinEvent -FilterHashtable @{LogName='Security';ID=4722;StartTime=$using:EarliestTime;EndTime=$using:LatestTime} -MaxEvents 100 
            #$Events | format-list *
            #$Events.Properties
    
            foreach ($event in $events)
            {
                $eventXML = [xml]$event.ToXml()
                $eventArray = New-Object -TypeName PSObject -Property @{

                EventID = $event.id
                TimeCreated = $event.timecreated
                SubjectSID = $eventXML.Event.EventData.Data[3].'#text'
                SubjectAccountName = $eventXML.Event.EventData.Data[4].'#text'
                SubjectDomain = $eventXML.Event.EventData.Data[5].'#text'
                NewAccountSID = $eventXML.Event.EventData.Data[2].'#text'
                NewAccountName = $eventXML.Event.EventData.Data[0].'#text'
                NewAccountDomain = $eventXML.Event.EventData.Data[1].'#text'
                ProcessID = $event.ProcessID
                }
                $eventArray | Select-Object EventID,TimeCreated,SubjectSID,SubjectAccountName,SubjectDomain,NewAccountSID,NewAccountName,NewAccountDomain,ProcessID
                }
            }

            if ($Output_To_File -eq 'yes') {
                foreach ($result in $Event_Results) {
                    Export-Csv -InputObject $result -Path "$Directory\$h\$($h)_DomainUserEnabledLogs_$($enddate).csv" -NoTypeInformation -Append -ErrorAction SilentlyContinue 
                }
            }
            else {
                foreach ($result in $Event_Results) {
                    $result 
                }
            }
        }
    }
    catch {
        Set-ErrorMsg
    }
    Write-Host "Complete..." -ForegroundColor Green    
    Write-Host "Hit Enter to Continue..." -nonewline -ForegroundColor yellow
    Read-Host
    Show-LogParserMenu
}

Function Get-UserPasswordChangeAttempt
{
    #$PasswordEventIDs = 4724
    Set-Output
    Set-LogTimeFrame
    Set-Target
    try {

        foreach ($h in $hosts) {
           $Event_Results = Invoke-Command -ComputerName $h -Credential $UserCredentials -ScriptBlock {
    
                $events = Get-WinEvent -FilterHashtable @{LogName='Security';ID=4724;StartTime=$using:EarliestTime;EndTime=$using:LatestTime} -MaxEvents 100
                foreach ($event in $events)
                {
                    $eventXML = [xml]$event.ToXml()
                    $eventArray = New-Object -TypeName PSObject -Property @{

                    EventID = $event.id
                    TimeCreated = $event.timecreated
                    SubjectSID = $eventXML.Event.EventData.Data[3].'#text'
                    SubjectAccountName = $eventXML.Event.EventData.Data[4].'#text'
                    SubjectDomain = $eventXML.Event.EventData.Data[5].'#text'
                    AccountSID = $eventXML.Event.EventData.Data[2].'#text'
                    AccountName = $eventXML.Event.EventData.Data[0].'#text'
                    AccountDomain = $eventXML.Event.EventData.Data[1].'#text'
                    ProcessID = $event.ProcessID
                    }
        
                    $eventArray | Select-Object EventID,TimeCreated,SubjectSID,SubjectAccountName,SubjectDomain,AccountSID,AccountName,AccountDomain,ProcessID
                }
            }

            if ($Output_To_File -eq 'yes') {
                foreach ($result in $Event_Results) {
                    Export-Csv -InputObject $result -Path "$Directory\$h\$($h)_UserPasswordAttemptChangeLogs_$($enddate).csv" -NoTypeInformation -Append -ErrorAction SilentlyContinue 
                }
            }
            else {
                foreach ($result in $Event_Results) {
                    $result
                }
            }
        }
    }
    catch {
        Set-ErrorMsg
    }
    Write-Host "Complete..." -ForegroundColor Green    
    Write-Host "Hit Enter to Continue..." -nonewline -ForegroundColor yellow
    Read-Host
    Show-LogParserMenu
}

Function Get-UserAccountChange
{
    Set-Output
    Set-LogTimeFrame
    Set-Target
    try {
        foreach ($h in $hosts) {
            $Event_Results = Invoke-Command -ComputerName $h -Credential $UserCredentials -ScriptBlock {

                $events = Get-WinEvent -FilterHashtable @{LogName='Security';ID=4738;;StartTime=$using:EarliestTime;EndTime=$using:LatestTime} -MaxEvents 100 
                #$Events | format-list *
                #$Events.Properties
    
                foreach ($event in $events)
                {
                    $eventXML = [xml]$event.ToXml()
                    $eventArray = New-Object -TypeName PSObject -Property @{

                    EventID = $event.id
                    TimeCreated = $event.timecreated
                    SubjectSID = $eventXML.Event.EventData.Data[4].'#text'
                    SubjectAccountName = $eventXML.Event.EventData.Data[5].'#text'
                    SubjectDomain = $eventXML.Event.EventData.Data[6].'#text'
                    AccountSID = $eventXML.Event.EventData.Data[3].'#text'
                    AccountName = $eventXML.Event.EventData.Data[1].'#text'
                    AccountDomain = $eventXML.Event.EventData.Data[2].'#text'
                    PasswordLastSet = $eventXML.Event.EventData.Data[17].'#text'
                    ProcessID = $event.ProcessID
                    }
                    $eventArray | Select-Object EventID,TimeCreated,SubjectSID,SubjectAccountName,SubjectDomain,AccountSID,AccountName,AccountDomain,PasswordLastSet,ProcessID
                }
            }

            if ($Output_To_File -eq 'yes') {
                foreach ($result in $Event_Results) {
                    Export-Csv -InputObject $result -Path "$Directory\$h\$($h)_UserAccountChangeLogs_$($enddate).csv" -NoTypeInformation -Append -ErrorAction SilentlyContinue 
                }
            }
            else {
                foreach ($result in $Event_Results) {
                    $result
                } 
            }
        }
    }
    catch {
        Set-ErrorMsg
    }
    Write-Host "Complete..." -ForegroundColor Green    
    Write-Host "Hit Enter to Continue..." -nonewline -ForegroundColor yellow
    Read-Host
    Show-LogParserMenu
}

function Get-UserAddedToDomainGroup 
{
    Set-Output
    Set-LogTimeFrame
    Set-Target
    try {
        foreach ($h in $hosts) {
            $Event_Results = Invoke-Command -ComputerName $h -Credential $UserCredentials -ScriptBlock {
                $events = Get-WinEvent -FilterHashtable @{LogName='Security';ID=4720;StartTime=$using:EarliestTime;EndTime=$using:LatestTime} -MaxEvents 100 

                foreach ($event in $events) {
                    $eventXML = [xml]$event.ToXml()
                    $eventArray = New-Object -TypeName PSObject -Property @{

                    EventID = $event.id
                    TimeCreated = $event.timecreated
                    SubjectSID = $eventXML.Event.EventData.Data[3].'#text'
                    SubjectAccountName = $eventXML.Event.EventData.Data[4].'#text'
                    SubjectDomain = $eventXML.Event.EventData.Data[5].'#text'
                    GroupSID = $eventXML.Event.EventData.Data[2].'#text'
                    GroupName = $eventXML.Event.EventData.Data[0].'#text'
                    GroupDomain = $eventXML.Event.EventData.Data[1].'#text'
                    ProcessID = $event.ProcessID
                    }
                    $eventArray | Select-Object EventID,TimeCreated,SubjectSID,SubjectAccountName,SubjectDomain,GroupSID,GroupName,GroupDomain,ProcessID
                }
            }

            if ($Output_To_File -eq 'yes') {
                foreach ($result in $Event_Results) {
                    Export-Csv -InputObject $result -Path "$Directory\$h\$($h)_UserAddedToDomainGroupLogs_$($enddate).csv" -NoTypeInformation -Append -ErrorAction SilentlyContinue 
                }
            }
            else {
                foreach ($result in $Event_Results) {
                    $result
                } 
            }
        }
    }
    catch {
        Set-ErrorMsg
    }
    Write-Host "Complete..." -ForegroundColor Green    
    Write-Host "Hit Enter to Continue..." -nonewline -ForegroundColor yellow
    Read-Host
    Show-LogParserMenu
}

function Get-LocalGroupMembershipEnumeration
{
    Set-Output
    Set-LogTimeFrame
    Set-Target
    try {
        foreach ($h in $hosts) {
            $Event_Results = Invoke-Command -ComputerName $h -Credential $UserCredentials -ScriptBlock {

                $events = Get-WinEvent -FilterHashtable @{LogName='Security';ID=4798;StartTime=$using:EarliestTime;EndTime=$using:LatestTime} -MaxEvents 100
                #Write-Host ""
                #Write-Host "Windows logs this event when a process enumerates the local groups to which a the specified user belongs on that computer."
                foreach ($event in $events) {
                    $eventXML = [xml]$event.ToXml()
                    $eventArray = New-Object -TypeName PSObject -Property @{

                    EventID = $event.id
                    TimeCreated = $event.timecreated
  
                    SubjectAccountName = $eventXML.Event.EventData.Data[4].'#text'
                    SubjectDomain = $eventXML.Event.EventData.Data[5].'#text'
                    UserSID = $eventXML.Event.EventData.Data[2].'#text'
                    UserName = $eventXML.Event.EventData.Data[0].'#text'
                    ProcessName = $eventXML.Event.EventData.Data[8].'#text'
                    ProcessID = $event.ProcessID
                    }
                    $eventArray | Select-Object EventID,TimeCreated,SubjectAccountName,SubjectDomain,UserSID,Username,ProcessName,ProcessID 
                } 
            }

            if ($Output_To_File -eq 'yes') {
                foreach ($result in $Event_Results) {
                    Export-Csv -InputObject $result -Path "$Directory\$h\$($h)_LocalGroupMembershipEnumerationLogs_$($enddate).csv" -NoTypeInformation -Append -ErrorAction SilentlyContinue 
                }
            }
            else {
                foreach ($result in $Event_Results) {
                    $result
                } 
            }
        }
    }
    catch {
        Set-ErrorMsg
    }
    Write-Host "Complete..." -ForegroundColor Green    
    Write-Host "Hit Enter to Continue..." -nonewline -ForegroundColor yellow
    Read-Host
    Show-LogParserMenu
}

function Get-LogonFailures 
{
    Set-Output
    Set-LogTimeFrame
    Set-Target
    try {
        foreach ($h in $hosts) {
            $Event_Results = Invoke-Command -ComputerName $h -Credential $UserCredentials -ScriptBlock {

                $events = Get-WinEvent -FilterHashtable @{LogName='Security';ID=4625;StartTime=$using:EarliestTime;EndTime=$using:LatestTime} -MaxEvents 100 
                #$Events | format-list *
                #$Events.Properties
    
                foreach ($event in $events) {
                    $eventXML = [xml]$event.ToXml()
                    $eventArray = New-Object -TypeName PSObject -Property @{

                    EventID = $event.id
                    TimeCreated = $event.timecreated
  
                    UserName = $eventXML.Event.EventData.Data[5].'#text'
                    WorkstationName = $eventXML.Event.EventData.Data[13].'#text'
                    IpAddress = $eventXML.Event.EventData.Data[19].'#text'
                    LogonType = $eventXML.Event.EventData.Data[10].'#text'
                    ProcessName = $eventXML.Event.EventData.Data[18].'#text'
                    }
            
                    $eventArray | Select-Object eventid,eventtime,username,workstationname,ipaddress,logontype,processname
                }
            }

    
            if ($Output_To_File -eq 'yes') {
                foreach ($result in $Event_Results) {
                    Export-Csv -InputObject $result -Path "$Directory\$h\$($h)_LoginFailureLogs_$($enddate).csv" -NoTypeInformation -Append -ErrorAction SilentlyContinue 
                }
            }
            else {
                foreach ($result in $Event_Results) {
                    $result
                }
            }
        }
    }
    catch {
        Set-ErrorMsg
    }
    Write-Host "Complete..." -ForegroundColor Green    
    Write-Host "Hit Enter to Continue..." -nonewline -ForegroundColor yellow
    Read-Host
    Show-LogParserMenu
}


function Get-ProcessEvents
{
    Set-Output
    Set-LogTimeFrame
    Set-Target
    try {
        foreach ($h in $hosts) {
            $Event_Results = Invoke-Command -ComputerName $h -Credential $UserCredentials -ScriptBlock {
                $Events = Get-WinEvent -FilterHashtable @{LogName='Security';ID=4688;StartTime=$using:EarliestTime;EndTime=$using:LatestTime} 

                foreach ($event in $events) {
                    $eventXML = [xml]$event.ToXml()
                    $eventArray = New-Object -TypeName PSObject -Property @{

                    EventID = $event.id
                    TimeCreated = $event.timecreated
                    Task = $event.TaskDisplayName
                    NewProcessName = $eventXML.Event.EventData.Data[5].'#text'
                    PID = ($eventXML.Event.EventData.Data[4].'#text')
                    ParentProcessName = $eventXML.Event.EventData.Data[13].'#text'
                    PPID = $eventXML.Event.EventData.Data[7].'#text'
            
                    }
                    $eventArray | Select-Object eventid,timecreated,Task,NewProcessName,PID,ParentProcessName,PPID
                }
            }
            if ($Output_To_File -eq 'yes') {
                foreach ($result in $Event_Results) {
                    Export-Csv -InputObject $result -Path "$Directory\$h\$($h)_ProcessEventLogs_$($enddate).csv" -NoTypeInformation -Append -ErrorAction SilentlyContinue 
                }
            }
            else {
                foreach ($result in $Event_Results) {
                    $result 
                }
            }
            
        }
    }
    catch {
        Set-ErrorMsg
    }
    Write-Host "Complete..." -ForegroundColor Green    
    Write-Host "Hit Enter to Continue..." -nonewline -ForegroundColor yellow
    Read-Host
    Show-LogParserMenu
}

function Get-RegistryChangeLogs
{
    Set-Output
    Set-LogTimeFrame
    Set-Target
    try {
        foreach ($h in $hosts) {
            $Event_Results = Invoke-Command -ComputerName $h -Credential $UserCredentials -ScriptBlock {
                $Events = Get-WinEvent -FilterHashtable @{LogName='Security';ID=4657;StartTime=$using:EarliestTime;EndTime=$using:LatestTime} 
                #$Events | format-list *
                #$Events.Properties
                foreach ($event in $events) {
                    $eventXML = [xml]$event.ToXml()
                    $eventArray = New-Object -TypeName PSObject -Property @{

                    EventID = $event.id
                    TimeCreated = $event.timecreated
                    Task = $event.TaskDisplayName
                    NewProcessName = $eventXML.Event.EventData.Data[5].'#text'
                    PID = ($eventXML.Event.EventData.Data[4].'#text')
                    ParentProcessName = $eventXML.Event.EventData.Data[13].'#text'
                    PPID = $eventXML.Event.EventData.Data[7].'#text'
            
                    }
                    $eventArray | Select-Object eventid,timecreated,Task,NewProcessName,PID,ParentProcessName,PPID
                }
            }
            if ($Output_To_File -eq 'yes') {
                foreach ($result in $Event_Results) {
                    Export-Csv -InputObject $result -Path "$Directory\$h\$($h)_RegistryChangeLogs_$($enddate).csv" -NoTypeInformation -Append -ErrorAction SilentlyContinue 
                }
            }
            else {
                foreach ($result in $Event_Results) {
                    $result 
                }
            }
            
        }
    }
    catch {
        Set-ErrorMsg
    }
    Write-Host "Complete..." -ForegroundColor Green    
    Write-Host "Hit Enter to Continue..." -nonewline -ForegroundColor yellow
    Read-Host
    Show-LogParserMenu
}

function Get-ScheduledTasksLaunched
{
    Set-Output
    Set-LogTimeFrame
    Set-Target
    try {
        foreach ($h in $hosts) {
            $Event_Results = Invoke-Command -ComputerName $h -Credential $UserCredentials -ScriptBlock { 
                $Events = Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-TaskScheduler/Operational';ID=129;StartTime=$using:EarliestTime;EndTime=$using:LatestTime}

                foreach ($event in $events) {
                    $eventXML = [xml]$event.ToXml()
                    $eventArray = New-Object -TypeName PSObject -Property @{

                    EventID = $event.id
                    EventTaskName = $event.TaskDisplayName
                    TimeCreated = $event.timecreated
                    ProcessID = $event.ProcessID
                    ProcessUserID = $event.UserID
                    ScheduledTaskName = $eventXML.Event.EventData.Data[0].'#text'
                    TaskExecuted = ($eventXML.Event.EventData.Data[1].'#text')
                    TaskExecutedPID = $eventXML.Event.EventData.Data[2].'#text'
                    }
                    $eventArray | Select-Object eventid,eventtaskname,timecreated,ProcessID,ProcessUserID,ScheduledTaskName,TaskExecuted,TaskExecutedPID 
                }
            }
            if ($Output_To_File -eq 'yes') {
                foreach ($result in $Event_Results) {
                    Export-Csv -InputObject $result -Path "$Directory\$h\$($h)_ScheduledTasksLaunchedLogs_$($enddate).csv" -NoTypeInformation -Append -ErrorAction SilentlyContinue 
                }
            }
            else {
                foreach ($result in $Event_Results) {
                    $result 
                }
            }
            
        }
    }
    catch {
        Set-ErrorMsg
    }
    Write-Host "Complete..." -ForegroundColor Green    
    Write-Host "Hit Enter to Continue..." -nonewline -ForegroundColor yellow
    Read-Host
    Show-LogParserMenu
}

Function Set-LogTimeFrame {
    
    Write-Host ""
    Write-Host "Please select earliest time period for the logs you want to see." -ForegroundColor Yellow
    $options=
@" 
            [1]  : Last Hour
            [2]  : Last 2 Hours
            [3]  : Last 12 Hours
            [4]  : Last 24 Hours
            [5]  : Last 48 Hours
            [6]  : Last 72 Hours
            [7]  : Last week
            [8]  : Last month
            [9]  : Last 3 months
            [10] : Last 6 months
            [11] : Last year
 
"@  
    
    $options
    $Selection = Read-Host

    try{
    
        switch ($Selection) {
            
            '1' {
                Write-Host "Setting the earliest time to 1 hour ago..." -ForegroundColor Cyan
                $global:EarliestTime = (Get-Date).AddHours(-1)
            }
            '2' {
                Write-Host "Setting the earliest time to 12 hours ago..." -ForegroundColor Cyan
                $global:EarliestTime = (Get-Date).AddHours(-2)
            }
            '3' {
                Write-Host "Setting the earliest time to 12 hours ago..." -ForegroundColor Cyan
                $global:EarliestTime = (Get-Date).AddHours(-12)
            }
            '4' {
                Write-Host "Setting the earliest time to 24 hours ago..." -ForegroundColor Cyan
                $global:EarliestTime = (Get-Date).AddHours(-24)
            }
            '5' {
                Write-Host "Setting the earliest time to 2 Days ago..." -ForegroundColor Cyan
                $global:EarliestTime = (Get-Date).AddDays(-2)
            }
            '6' {
                Write-Host "Setting the earliest time to 3 Days ago..." -ForegroundColor Cyan
                $global:EarliestTime = (Get-Date).AddDays(-3)
            }
            '7' {
                Write-Host "Setting the earliest time to 7 Days ago..." -ForegroundColor Cyan
                $global:EarliestTime = (Get-Date).AddDays(-7)
            }
            '8' {
                Write-Host "Setting the earliest time to 1 month ago..." -ForegroundColor Cyan
                $global:EarliestTime = (Get-Date).AddMonths(-1)
            }
            '9' {
                Write-Host "Setting the earliest time to 3 months ago..." -ForegroundColor Cyan
                $global:EarliestTime = (Get-Date).AddMonths(-3)
            }
            '10' {
                Write-Host "Setting the earliest time to 6 months ago..." -ForegroundColor Cyan
                $global:EarliestTime = (Get-Date).AddMonths(-6)
            }
            '11' {
                Write-Host "Setting the earliest time to 1 year ago..." -ForegroundColor Cyan
                $global:EarliestTime = (Get-Date).AddMonths(-12)
            }
            default {
                Write-Host ""
                Write-Host "You did not select a valid option. Please try again. " -ForegroundColor Cyan
                Write-Host ""
                Write-Host "Please hit ENTER to acknowledge and continue." -ForegroundColor Yellow
                Read-Host
                Set-LogTimeFrame
            } 
        }
    }
    catch {
        Set-ErrorMsg
    }
    
    $global:LatestTime = [System.DateTime]::now

    Write-Host "The timeframe is set from $EarliestTime to $LatestTime." -ForegroundColor Green

    $global:TimeFilter = {($_.TimeCreated -ge $StartTime) -and ($_.TimeCreated -le $EndTime)}
              
}

Function Remove-ProcessIOC {
    Set-Target
    Write-Host "Enter the name of the process you want to kill" -ForegroundColor Yellow        
    $Proc = Read-Host
    Write-Host ""
    
    try {
        foreach ($h in $hosts) {
            Invoke-Command -ComputerName $h -Credential $UserCredentials -ScriptBlock {
                Write-Host "Verifying the process $($using:Proc) is still on the $($using:h)..." -ForegroundColor Cyan
                Write-Host ""
                $P = Get-Process -ProcessName $using:Proc -ErrorAction SilentlyContinue
                
                if ($P) {
                    Write-Host "Process $($using:Proc) was discovered on $($using:h)..." -ForegroundColor Green
                    Write-Host ""
                    Write-Host "Preparing to kill the process $($using:Proc) on host $($using:h)." -ForegroundColor Cyan
                    Stop-Process -name $using:Proc -Force -ErrorAction SilentlyContinue
                    Write-Host ""
                    Write-Host "Verifying if process $using:Proc was stopped..." -ForegroundColor Cyan
                    try {                    
                        $CheckProc = Get-Process -Name $using:Proc -ErrorAction SilentlyContinue
                        if (!$CheckProc) {
                            Write-Host ""
                            Write-Host "Process $($using:Proc) was killed on host $($using:h)..." -ForegroundColor Green
                        }
                        else {
                            Write-Host ""
                            Write-Host "Process was NOT stopped."
                        }
                    }
                    catch {
                        Set-ErrorMsg
                    }
                }
                else {
                    Write-Host "Process $($using:Proc) was not found on host $($using:h) ..." -ForegroundColor Red
                }
            }
            Write-Host ""
            if ($procCheck -eq 'yes'){
                Write-Host "Hit ENTER to continue." -ForegroundColor Yellow
            }
            else {
                Write-Host "Hit Enter when you are ready to see the next host." -ForegroundColor Yellow
                Read-Host
            }
 
        }
    }
    catch {
        Set-ErrorMsg
    }
    Write-Host ""
    if ($procCheck -eq 'yes'){
        Write-Host "Hit ENTER to continue." -ForegroundColor Yellow
    }
    else {
        Write-Host "Hit Enter To Continue." -ForegroundColor Yellow
        Read-Host
        Show-IOCRemovalMenu
    }
}

Function Remove-ScheduledTaskIOC {
    Set-Target
    Write-Host "Enter the name of the ScheduleTask you want to delete." -ForegroundColor Yellow        
    $Task = Read-Host
    Write-Host ""
    try {
        foreach ($h in $hosts) {
            Invoke-Command -ComputerName $h -Credential $UserCredentials -ScriptBlock {
                Write-Host "Verifying the scheduled task $($using:Task) is still on the $($using:h)..." -ForegroundColor Cyan
                Write-Host ""
                $CheckTask = Get-ScheduledTask -TaskName $using:Task | Select-Object -Property Taskname,State -ErrorAction SilentlyContinue
                if ($CheckTask){
                    Write-Host "ScheduledTask $($using:Task) was discovered on $($using:h)." -ForegroundColor Green
                    Write-Host ""
                    Write-Host "Preparing to Unregister and Delete the task $using:Task." -ForegroundColor Cyan
                    Write-Host ""
                    Unregister-ScheduledTask -TaskName $using:Task -confirm:$false -ErrorAction SilentlyContinue
                    Write-Host "Verifying if task $using:Task was deleted (RED message output is expected if deleted)" -ForegroundColor Cyan
                    $CheckTask = Get-ScheduledTask -TaskName $using:Task | Select-Object -Property TaskName -ErrorAction SilentlyContinue
                    if ($CheckTask) {
                        Write-Host "Task $using:Task was not deleted." -ForegroundColor Red
                    }
                    else {
                        Write-Host "Task $using:Task has been deleted." -ForegroundColor Green
                        Write-Host ""
                        Write-Host "You can now delete the executable or dll that was being executed by task $($using:Task)." -ForegroundColor Cyan
                        Write-Host ""
                    }
                }
                else {
                    Write-Host "Task $($using:Task) does not exist on host $($h)."
                }
            }    
        }
    
        Write-Host "Hit Enter when you are ready to see the next host." -ForegroundColor Yellow
        Read-Host
    }
    catch {
        Set-ErrorMsg
    }
    Write-Host "Hit Enter To Continue." -ForegroundColor Yellow
    Read-Host
    Show-IOCRemovalMenu
}

Function Remove-RegistryIOC {
    Set-Target
    Write-Host "Enter the path to the Registry Hive that hosts the key you want to delete" -ForegroundColor Yellow
    Write-Host "Example: HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\" -ForegroundColor Cyan
    $RegPath = Read-Host    
    Write-Host "Enter the name of the Registry Key you want to delete." -ForegroundColor Yellow        
    $global:RegKey = Read-Host
    try {
        foreach ($h in $hosts) {
            Invoke-Command -ComputerName $h -Credential $UserCredentials -ScriptBlock {
                
                Write-Host "Checking to see if the process associated with the registry key $($Regkey) is running." -ForegroundColor Cyan
                Write-Host ""
                $RegCheck = Get-ItemProperty -Path $using:RegPath | Select-Object -ExpandProperty $using:RegKey
                $Proc = ($RegCheck.split('\')[-1]).split('.')[0]
                
                Write-Host "Verifying the process $($Proc) is still on the $($using:h)..." -ForegroundColor Cyan
                Write-Host ""
                $P = Get-Process -ProcessName $Proc -ErrorAction SilentlyContinue
                
                if ($P) {
                    Write-Host "Process $($Proc) was discovered on $($using:h)..." -ForegroundColor Green
                    Write-Host ""
                    Write-Host "Preparing to kill the process $($Proc) on host $($using:h)." -ForegroundColor Cyan
                    Stop-Process -name $Proc -Force -ErrorAction SilentlyContinue
                    Write-Host ""
                    Write-Host "Verifying if process $Proc was stopped..." -ForegroundColor Cyan
                    try {                    
                        $CheckProc = Get-Process -Name $Proc -ErrorAction SilentlyContinue
                        if (!$CheckProc) {
                            Write-Host ""
                            Write-Host "Process $($Proc) was killed on host $($using:h)..." -ForegroundColor Green
                        }
                        else {
                            Write-Host ""
                            Write-Host "Process was NOT stopped." -ForegroundColor Red
                        }
                    }
                    catch {
                        Set-ErrorMsg
                    }
                }
                Write-Host ""
                
                Write-Host "Verifying the registry key $($using:RegKey) is still on the $($using:h)..." -ForegroundColor Cyan
                Write-Host ""
                $CheckRegKey = Get-ItemProperty -Path $using:RegPath -name $using:RegKey -ErrorAction SilentlyContinue
                if ($CheckRegKey){
                    Write-Host "Registry key $($using:RegKey) was discovered on $($using:h)." -ForegroundColor Green
                    Write-Host ""
                    Write-Host "Preparing to delete the registry key $using:RegKey." -ForegroundColor Cyan
                    Write-Host ""
                    Remove-ItemProperty -Path $using:RegPath -Name $using:RegKey -Force -ErrorAction SilentlyContinue
                    Write-Host "Verifying if registry key $using:Regkey was deleted." -ForegroundColor Cyan
                    $CheckRegKey = Get-ItemProperty -Path $using:RegPath -name $using:RegKey -ErrorAction SilentlyContinue
                    if ($CheckRegKey) {
                        Write-Host "Registry key $using:RegKey was not deleted." -ForegroundColor Red
                    }
                    else {
                        Write-Host "Registry key $using:RegKey has been deleted." -ForegroundColor Green
                        Write-Host ""
                        Write-Host "You can now delete the executable or dll that was being executed by registry key $($using:RegKey)." -ForegroundColor Cyan
                        Write-Host ""
                    }
                }
                else {
                    Write-Host "Registry key $($using:RegKey) does not exist on host $($h)."
                }
            }    
        }
        Write-Host "Hit Enter when you are ready to see the next host." -ForegroundColor Yellow
        Read-Host

        
    }
    catch {
        Set-ErrorMsg
    }

    Write-Host "Hit Enter To Continue." -ForegroundColor Yellow
    Read-Host
    Show-IOCRemovalMenu
}

Function Remove-ServiceIOC {
    Set-Target
    Write-Host "Enter the name of the service you want to kill" -ForegroundColor Yellow        
    $Service = Read-Host
    Write-Host ""
    try {
        foreach ($h in $hosts) {
            Invoke-Command -ComputerName $h -Credential $UserCredentials -ScriptBlock {
                Write-Host "Verifying the service $($using:Service) is still on the $($using:h)..." -ForegroundColor Cyan
                Write-Host ""
                $Serv = Get-Service -Name $using:Service | Select-Object -Property Name,Status -ErrorAction SilentlyContinue
                if ($serv) {
                    Write-Host "Service $($using:Service) was discovered on $($using:h) and the service is $($Serv.Status)." -ForegroundColor Green
                    Write-Host ""
                    if ($Serv.Status -eq 'Running') {
                        Write-Host "Preparing to stop the service $($using:Service) on host $($using:h)." -ForegroundColor Cyan
                        Stop-Service -name $using:Service -Force -ErrorAction SilentlyContinue
                        Write-Host ""
                        Write-Host "Verifying if service $using:Service was stopped..." -ForegroundColor Cyan
                        try {
                                                
                            $CheckServ = Get-Service -Name $using:Service | Select-Object -Property Name,Status -ErrorAction SilentlyContinue
                            if ($CheckServ.Status -eq 'Running') {
                                Write-Host ""
                                Write-Host "Service $($using:Service) is still running $($using:h)..." -ForegroundColor Red
                                Write-Host
                                Write-Host "There may be a dependency to the service that needs addressed. Please continue investigation." -ForegroundColor Cyan
                                Show-IOCRemovalMenu
                            }
                            else {
                                Write-Host ""
                                Write-Host "Service was stopped." -ForegroundColor Green
                                Write-Host ""
                                Write-Host "Preparing to delete the service $using:Service..." -ForegroundColor Cyan
                                Write-Host ""
                                sc.exe delete $using:Service
                                Write-Host "Verifying if service $using:Service was deleted..." -ForegroundColor Cyan
                                try {
                                    $CheckServ = Get-Service -Name $using:Service | Select-Object -Property Name -ErrorAction SilentlyContinue
                                    if ($CheckServ) {
                                        Write-Host "Service $using:Service was not deleted." -ForegroundColor Red
                                    }
                                    else {
                                        Write-Host "Service $using:Service has been deleted." -ForegroundColor Green
                                        Write-Host ""
                                        Write-Host "You can now delete the executable or dll that was being executed by service $($using:Service)." -ForegroundColor Cyan
                                        Write-Host ""
                                    }
                                }   
                                catch {
                                    Set-ErrorMsg
                                }
                            }
                        }
                        catch {
                            Set-ErrorMsg
                        }
                    }
                    else {
                        Write-Host "Service $($using:Service) is not running on the host $($using:h)." -ForegroundColor Cyan
                        Write-Host ""
                        Write-Host "Preparing to delete the service $using:Service..." -ForegroundColor Cyan
                        Write-Host ""
                        sc.exe delete $using:Service
                        Write-Host "Verifying if service $using:Service was deleted..." -ForegroundColor Cyan
                        $CheckServ = Get-Service -Name $using:Service | Select-Object -Property Name -ErrorAction SilentlyContinue
                        if ($CheckServ) {
                            Write-Host "Service $using:Service was not deleted." -ForegroundColor Red
                        }
                        else {
                            Write-Host "Service $using:Service has been deleted." -ForegroundColor Green
                            Write-Host ""
                            Write-Host "You can now delete the executable or dll that was being executed by service $($using:Service)." -ForegroundColor Cyan
                            write-Host ""
                        }
                        
                    }
                }
                else {
                    Write-Host "Service $($using:Service) does not exist on host $($h)." -ForegroundColor Cyan
                }
            }
            Write-Host "Hit Enter when you are ready to see the next host." -ForegroundColor Yellow
            Read-Host
        }
    }
    catch {
        Set-ErrorMsg
    }
    Write-Host "Hit Enter To Continue." -ForegroundColor Yellow
    Read-Host
    Show-IOCRemovalMenu
}
Function Remove-FileIOC {
    Set-Target
    Write-Host "Enter the path to the file you want to delete (Example: c:\programdata\example.exe)" -ForegroundColor Yellow        
    $FilePath = Read-Host
    Write-Host ""
    try {
        foreach ($h in $hosts) {
            Invoke-Command -ComputerName $h -Credential $UserCredentials -ScriptBlock {
                Write-Host "Verifying the file is still on the filesystem..." -ForegroundColor Cyan
                Write-Host ""
                $File = Get-ChildItem -Path $using:FilePath -Force -ErrorAction SilentlyContinue
                Write-Host "File $($using:FilePath) was discovered..." -ForegroundColor Green
                Write-Host ""
                if ($File) {
                    Write-Host "Preparing to delete the file $($using:FilePath)." -ForegroundColor Cyan
                    Remove-Item -Path $using:FilePath -Force
                    Write-Host ""
                    Write-Host "Verifying if file $using:FilePath was removed..." -ForegroundColor Cyan
                    try {                    
                        $CheckFile = Get-ChildItem -Path $using:FilePath -Force -ErrorAction SilentlyContinue
                        if (!$CheckFile) {
                            Write-Host ""
                            Write-Host "File $($using:filepath) was removed...." -ForegroundColor Green
                        }
                        else {
                            Write-Host ""
                            Write-Host "File was NOT Deleted. Verify that you put the correct path for the file."
                        }
                    }
                    catch {
                        $msg = "Error: Failed on line number '{0}' column '{1}' ('{2}'). The error was '{3}'." -f $_.Exception.Line, $_.Exception.Offset, $_.Exception.CommandInvocation.Line.Trim(), $_.Exception.Message 
                        $msg
                        Write-Host "Something went wrong. Verify that you put the correct path for the file." -ForegroundColor Red
                    }
                }
                else {
                    Write-Host "File was not found..." -ForegroundColor Red
                }
            }
            Write-Host "Hit Enter when you are ready to see the next host." -ForegroundColor Yellow
            Read-Host
        }
    }
    catch {
        Set-ErrorMsg
    }
    Write-Host "Hit Enter To Continue." -ForegroundColor Yellow
    Read-Host
    Show-IOCRemovalMenu
}

Function Remove-IPIOC {
    Set-Target
    Write-Host "Enter the IP address that you want to block " -ForegroundColor Yellow        
    $IP = Read-Host
    
    Write-Host ""
    try {
        foreach ($h in $hosts) {
            Invoke-Command -ComputerName $h -Credential $UserCredentials -ScriptBlock {
                
                Write-Host "Adding a rule in Windows Firewall to block $($using:IP)." -ForegroundColor Cyan
                New-NetFirewallRule -name Block-$using:IP-in -DisplayName Block-$using:IP-in -profile any -Direction Inbound -LocalPort any -Protocol any -Action Block -RemoteAddress $using:IP -Enabled True
                New-NetFirewallRule -name Block-$using:IP-out -DisplayName Block-$using:IP-out -Profile any -Direction Outbound -LocalPort any -Protocol any -Action Block -RemoteAddress $using:IP -Enabled True

                Write-Host "IP Address $($using:IP) is blocked on outbound and inbound interfaces on all profiles." -ForegroundColor Green
        
            }   
            Write-Host "Hit Enter when you are ready to see the next host." -ForegroundColor Yellow
            Read-Host
        }
    }
    catch {
        Set-ErrorMsg
    }
    Write-Host "Hit Enter To Continue." -ForegroundColor Yellow
    Read-Host
    Show-IOCRemovalMenu
}
Function Remove-DomainIOC {
    Set-Target
    Write-Host "Enter the domain that you want to block " -ForegroundColor Yellow        
    $Domain = Read-Host
    $HostsFile = "c:\windows\system32\drivers\etc\hosts"
    Write-Host ""
    try {
        foreach ($h in $hosts) {
            Invoke-Command -ComputerName $h -Credential $UserCredentials -ScriptBlock {
                Write-Host "Making a copy of $($using:HostsFile)." -ForegroundColor Cyan
                $CopyFormat = (Get-Date).ToString("yyyyMMdd_hhmmss")
                $HostsCopy = $using:HostsFile + "." + $CopyFormat
                Copy-Item -Path $using:HostsFile -Destination $HostsCopy -Force -ErrorAction SilentlyContinue

                Write-Host "Copy of $($using:HostsFile) saved at $($HostsCopy)." -ForegroundColor Green
                $File = Get-Content $using:HostsFile -ErrorAction SilentlyContinue

                if ($File -contains "127.0.0.1  $($using:Domain)") {
                    Write-Host "Domain Entry already exits in file $($using:HostsFile)." -ForegroundColor Cyan                
                }
                else {
                    Add-Content -path $using:HostsFile -Value "127.0.0.1 $($using:Domain)" -ErrorAction SilentlyContinue
                    Write-Host "Domain name $($using:Domain) blackholed to localhost via $($using:HostsFile)." -ForegroundColor Green
                } 
                     
            }   
            Write-Host "Hit Enter when you are ready to see the next host." -ForegroundColor Yellow
            Read-Host
        }
    }
    catch {
        Set-ErrorMsg
    }
    Write-Host "Hit Enter To Continue." -ForegroundColor Yellow
    Read-Host
    Show-IOCRemovalMenu
}



Show-MainMenu
