# FIM-Powershell

FIM solutions allow the monitoring of critical files to detect unauthorized changes. This allows the detection of intrusions in the early stages, even when other security controls have been compromised.

FIM works by calculating hashes of monitored files and storing them as a reference. Then, it periodically recalculates the hashes and compares them with the reference values. If there is a change, the FIM solution generates an alert so that the incident response team can investigate. Some of the files commonly monitored are: operating system files, application files, configuration files, and other critical files.

There are commercial FIM solutions, but for small companies with tight budgets, a homemade solution can be an alternative. As an example, the following script in PowerShell is proposed as a basic FIM solution...


```powershell
# Prompting the user for their desired action
# Display the available options
Write-Host ""
Write-Host "What would you like to do?"
Write-Host ""
Write-Host "    A) Collect new Baseline?"
Write-Host "    B) Begin monitoring files with saved Baseline?"
Write-Host ""

# Read and return the user's response
$response = Read-Host -Prompt "Please enter 'A' or 'B'"
Write-Host ""
Write-Host "User entered $($response)"
Write-Host ""

# Function to calculate the file hash using SHA512 algorithm
Function Calculate-File-Hash($filepath) {
    $filehash = Get-FileHash -Path $filepath -Algorithm SHA512
    return $filehash
}


if ($response -eq "A".ToUpper()){
    Collect-New-Baseline{}
}
elseif($response -eq "B".ToUpper()){
    Monitor-Files-With-Saved-BaseLine{}
}

# Function to collect a new baseline by calculating file hashes and storing them in a file
Function Collect-New-Baseline() {
    #Delete baseline.txt if it already exists
    Erase-Baseline-If-Already-Exists{}

    #Collect all files in the target folder
    $files = Get-ChildItem -Path .\FilesTest
    
    # For each file, calculate the hash and write it to the baseline file
    foreach ($f in $files) {
        $hash = Calculate-File-Hash $f.FullName
        "$($hash.Path)|$($hash.Hash)" | Out-File -FilePath .\baseline.txt -Append
    }
}

# Function to monitor files using the saved baseline and report any changes
Function Monitor-Files-With-Saved-Baseline() {
    # Create an empty dictionary to store file paths and their corresponding hashes
    $fileHashDictionary = @{}

    # Read the baseline file and store the file paths and hashes in the dictionary
    $filePathsAndHashes = Get-Content -Path .\baseline.txt
    
    foreach ($f in $filePathsAndHashes) {
         $fileHashDictionary.add($f.Split("|")[0],$f.Split("|")[1])
    }

    # Continuously monitor the files for changes
    while ($true) {
        # Wait for 1 second before checking again
        Start-Sleep -Seconds 1

        $files = Get-ChildItem -Path .\FilesTest
        
        # For each file, calculate the hash and compare it with the saved baseline
        foreach ($f in $files){
            $hash = Calculate-File-Hash $f.FullName

            # Notify if there is a new file
            if ($fileHashDictionary[$hash.Path] -eq $null){
                # A new file has been created!
                Write-Host "$($hash.Path) has been created!" -ForegroundColor Green
            }

            else {

            # Notify if a new file has been changed
            if ($fileHashDictionary[$hash.Path] -eq $hash.Hash){
                # The file has not changed
            }

            else {
                # A file has been compromised! Notify the user
                Write-Host "$($hash.Path) has changed!!!" -ForegroundColor Yellow
            }

            }

            # Check if any files from the baseline have been deleted
            foreach ($key in $fileHashDictionary.Keys){
                $baselineFileStillExists = Test-Path -Path $key
                if (-Not $baselineFileStillExists){
                    # One of the baseline files must have been deleted, notify the user
                    Write-Host "$($key) has been deleted!!" -ForegroundColor DarkRed -BackgroundColor Gray
                }
            }

        }       

    }

}

# Function to remove the baseline file if it already exists
Function Erase-Baseline-If-Already-Exists(){
    $baselineExists = Test-Path -Path .\baseline.txt

    if ($baselineExists){
        #Delete it
        Remove-Item -Path .\baseline.txt
    }
}
```

This script monitors the specified files by calculating their SHA512 hashes and comparing them with the reference hashes. If a change is detected in any file, a warning is displayed. The script runs continuously, checking the files every hour.

To sum up, FIMs are crucial controls that should be present in any robust cyber security strategy. Using commercial tools or homemade scripts like the one proposed, companies can monitor their critical files and thus improve their security posture.
