####################################################################################
#   Author: Kristek Jan
#   Date: 1.4.2022
#   Last date change: 23.5.2023
#   Version: 1.4.1
#   description: script for whole management of AD     
#
#   Changelog:
#       
#  
####################################################################################

#special characters translator
function Convert-Characters
{
  param([Parameter(Mandatory)]$Text)
  $Text=$Text.Replace('ö','oe').Replace('ä','ae').Replace('ü','ue').Replace('ß','ss').Replace('Ö','Oe').Replace('Ü','Ue').Replace('Ä','Ae')
  $Text=$Text.Replace('é','e').Replace('á','a').Replace('ú','u').Replace('ů','u').Replace('í','i').Replace('ý','y').Replace('É','E').Replace('Á','A').Replace('Ú','U').Replace('Ů','U').Replace('Í','I').Replace('Ý','Y')
  $Text=$Text.Replace('ě','e').Replace('č','c').Replace('ř','r').Replace('š','s').Replace('ž','z').Replace('ó','o').Replace('Ó','O').Replace('Ě','Ě').Replace('Č','C').Replace('Ř','R').Replace('Š','S').Replace('Ž','Z')
  return $Text
}

#function that validates if email input is in right format
#https://stackoverflow.com/questions/48253743/powershell-to-validate-email-addresses
function IsValidEmail { 
    param([string]$Email)
    $Regex = '^([\w-\.]+)@((\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.)|(([\w-]+\.)+))([a-zA-Z]{2,4}|[0-9]{1,3})(\]?)$'

   try {
        $obj = [mailaddress]$Email
        if($obj.Address -match $Regex){
            return 1
        }
        return 0
    }
    catch {
        return 0
    } 
}

#data validation for user creation
function Validate_Data{
    $startButton.Text = "START"
    if($startButton.Enabled){
        $startButton.Enabled=0
        $familynamebox.Enabled=1
        $givennamebox.Enabled=1
        $loginbox.Enabled=1
        $samaccountbox.Enabled=1
        $departmentbox.Enabled=1
        $companybox.Enabled=1
        $emailbox.Enabled=1
        $listBox.Enabled=1
    }
    else{
       $error_found=0
       $firstName =$givennamebox.Text.Trim().Replace(" ","")
       $lastName = $familynamebox.Text.Trim().Replace(" ","")
       $firstName=$firstName.substring(0,1).toupper()+$firstName.substring(1).tolower()
       $lastName =$lastName.substring(0,1).toupper()+$lastName.substring(1).tolower()
       $firstName=Convert-Characters $firstName
       $lastName=Convert-Characters $lastName
       $upn = $loginbox.Text.Trim().ToLower()
       $userID = $samaccountbox.Text.Trim().ToUpper()
       $department = $departmentbox.Text.Trim()

       if($companybox.Text -ne "" -and $listBox.SelectedItem.ToString() -eq "External"){
           $company = $companybox.Text.Trim()
           $companystatus.ResetText()
       }elseif($companybox.Text -eq "" -and $listBox.SelectedItem.ToString() -eq "External"){
           $companystatus.Text="Company not inputed"
           $error_found=1
       }
   
       #Check users input in text boxes
       if($firstName -eq ''){
         $givennamestatus.Text="Given Name not inputed"
         $error_found=1
       }else{
         $givennamestatus.ResetText()
       }
       if ($lastName -eq ''){
         $familynamestatus.Text= "Family Name not inputed"
         $error_found=1
       }else{
         $familynamestatus.ResetText()
       }
       if ($upn -eq ''){
          $loginstatus.Text="UPN not inputed"
          $error_found=1
       }else{
          $loginstatus.ResetText()
       }
       if ($userID -eq ''){
          $samaccountstatus.Text="UserID not inputed"
          $error_found=1
       }else{
          $samaccountstatus.ResetText()
       }
       if($department -eq ''){
          $departmentstatus.Text="department not inputed"
          $error_found=1
       }else{
          $departmentstatus.ResetText()
       }

       if($lastName -match '\d'-and $lastName -ne ''){
         $familynamestatus.Text= "Family Name cant contain number"
         $error_found=1
       }
       if($firstName -match '\d'-and $firstName -ne ''){
          $givennamestatus.Text="Given Name cant contain number"
          $error_found=1
       }
       if(!(($listBox.SelectedItem.ToString() -eq 'Internal' -and $upn.StartsWith($lastName.ToLower()+"."+$firstName.ToLower()+"@")) -or `
       ($listBox.SelectedItem.ToString() -eq 'External' -and $upn.StartsWith($lastName.ToLower()+"."+$firstName.ToLower()+".external@")))){
          $loginstatus.Text="Login in wrong format"
          $error_found=1
       }
       if($userID -ne $logonnamefield.Text.Trim()){
          $samaccountstatus.Text="Login doesnt match to login above"
          $error_found=1
       }
       if($userID -match '^[0-9]+$'){
           $samaccountstatus.Text="UserID in wrong format"
           $error_found=1
       }
       if($company -match '\d'-and $company -ne '' -and $listBox.SelectedItem.ToString() -eq "External"){
          $companystatus.Text= "company cant contain number"
          $error_found=1
       }
   
       #check email format
       if($emailbox.Text -ne ''){
          $test=IsValidEmail($emailbox.Text.Trim())
          if($test -eq 0){
            $emailstatus.Text="Email in wrong format";
            $error_found=1
           }else{
            $emailstatus.ResetText()
           }
        }

        #if problem was found return to user
        if($error_found -eq 1){return}

        $startButton.Enabled=1
        $familynamebox.Enabled=0
        $givennamebox.Enabled=0
        $loginbox.Enabled=0
        $samaccountbox.Enabled=0
        $departmentbox.Enabled=0
        $companybox.Enabled=0
        $emailbox.Enabled=0
        $listBox.Enabled=0
    }
}

function Create_User{
   $firstName =$givennamebox.Text.Trim().Replace(" ","-").replace("_","-")
   $lastName = $familynamebox.Text.Trim().Replace(" ","-").replace("_","-")
   $firstName=$firstName.substring(0,1).toupper()+$firstName.substring(1).tolower()
   $lastName =$lastName.substring(0,1).toupper()+$lastName.substring(1).tolower()
   if($lastName.Contains("-")){
      $array=$lastName.Split("-")
      for($i=0;$i -lt $array.length;$i++){
        $array[$i]=$array[$i].substring(0,1).toUpper()+$array[$i].substring(1)
      }
      $lastName=$array[0]
      for($i=1;$i -lt $array.length;$i++){
        $lastName=$lastName + "-"+ $array[$i]
      }
   }
   if($firstName.Contains("-")){
      $array=$firstName.Split("-")
      for($i=0;$i -lt $array.length;$i++){
        $array[$i]=$array[$i].substring(0,1).toUpper()+$array[$i].substring(1)
      }
      $firstName=$array[0]
      for($i=1;$i -lt $array.length;$i++){
        $firstName=$firstName + "-"+ $array[$i]
      }
   }

   $upn = $loginbox.Text.Trim().ToLower()
   $userID = $samaccountbox.Text.Trim().ToUpper()
   $department = $departmentbox.Text.Trim()
   $password=ConvertTo-SecureString "Default1234#" -AsPlainText -Force

#create account based on selected type
Switch ($listBox.SelectedItem.ToString()){
   'Internal' {
        $city="Praha"
        $country="CZ"
        $street="U Gustava 26"
        $postalCode="72766"
        $company="EE"
        $DisplayName=$lastName+", "+$firstName
        $description="Normal User, Department "+$department.substring(0,4)
        $scriptPath="startlogin.cmd"
        $homeDrive="Y"
        $homeDirectory="\\EE\User$\"+$userID
        $path = "OU=EE,OU=User,"+(Get-ADDomain).DistinguishedName
        try{
             new-aduser -AccountPassword $password -UserPrincipalName $upn -ChangePasswordAtLogon 1 -Description $description -City $city -Path $path `
             -DisplayName $DisplayName -Enabled 1 -Name $DisplayName -GivenName $firstName -HomeDirectory $homeDirectory -StreetAddress $street -postalCode $postalCode `
             -SamAccountName $userID -Surname $lastName -country $country -homedrive $homeDrive -scriptpath $scriptPath -department $department -Company $company
             set-aduser -Identity $userID -Replace @{c=$country;co="Czech Republic";countrycode="203"}
             $logbox.Text =$logbox.Text+"`r`n"+"account with ID "+$userID+" created"
             New-Item -path $homeDirectory -ItemType Directory
             $AccessRule = new-object System.Security.AccessControl.FileSystemAccessRule(((Get-ADDomain).DNSRoot+"\"+$userID),[System.Security.AccessControl.FileSystemRights]::FullControl,@([System.Security.AccessControl.InheritanceFlags]::ContainerInherit, [System.Security.AccessControl.InheritanceFlags]::ObjectInherit),[System.Security.AccessControl.PropagationFlags]::None,[System.Security.AccessControl.AccessControlType]::Allow)
             $ACL = Get-Acl -Path $homeDirectory
             $ACL.AddAccessRule($AccessRule)
             Set-Acl -Path $homeDirectory -AclObject $ACL
            $logbox.Text =$logbox.Text+"`r`n"+"DisplayName: "+$DisplayName
            $logbox.Text =$logbox.Text+"`r`n"+"Description: "+$description
            $logbox.Text =$logbox.Text+"`r`n"+"Company: "+$company
            $logbox.Text =$logbox.Text+"`r`n"+"Home folder: "+$homeDirectory
            $logbox.Text =$logbox.Text+"`r`n"+"Path: "+$path
            $logbox.Text =$logbox.Text+"`r`n"+"UPN: "+$upn

             $givennamebox.ResetText()
             $familynamebox.ResetText()
             $loginbox.ResetText()
             $samaccountbox.ResetText()
             $departmentbox.ResetText()
             $companybox.ResetText()
        }catch{
            $ErrorMessage = $_.Exception.Message
            [System.Windows.Forms.MessageBox]::Show("$ErrorMessage","Error",0)
        }  
       break}
   'External'{
        if($checkboxmun.Checked){
           $city="Brno"
           $country="CZ"
           $street="Nádražní 20"
           $postalCode="88877"
           $company="Slunéčko sro"
        }
        elseif($checkboxcc.Checked){
           $city="Praha"
           $country="CZ"
           $street="U Gustava 21"
           $postalCode="77766"
           $company="Testing Intership Masters as"
        }
        $DisplayName=$lastName+", "+$firstName
        $description="Department "+$department.substring(0,4)+" - Comp. "+$company
        $scriptPath="startlogin.cmd"
        $homeDrive="Y"
        $homeDirectory="\\EE\User$\"+$userID
        $path = "OU=EE,OU=User,OU=Externe,"+(Get-ADDomain).DistinguishedName
        if($companybox.Text -ne ""){
            $company = $companybox.Text.Trim()
        }
        try{
            new-aduser -AccountPassword $password -UserPrincipalName $upn -ChangePasswordAtLogon 1 -Description $description -City $city -Path $path `
             -DisplayName $DisplayName -Enabled 1 -Name $DisplayName -GivenName $firstName -HomeDirectory $homeDirectory -StreetAddress $street -postalCode $postalCode `
             -SamAccountName $userID -Surname $lastName -country $country -homedrive $homeDrive -scriptpath $scriptPath -department $department -company $company
             set-aduser -Identity $userID -Replace @{c=$country;co="Czech Republic";countrycode="203"}
             $logbox.Text =$logbox.Text+"`r`n"+"account with ID "+$userID+" created"
             New-Item -path $homeDirectory -ItemType Directory
             $AccessRule = new-object System.Security.AccessControl.FileSystemAccessRule(((Get-ADDomain).DNSRoot+"\"+$userID),[System.Security.AccessControl.FileSystemRights]::FullControl,@([System.Security.AccessControl.InheritanceFlags]::ContainerInherit, [System.Security.AccessControl.InheritanceFlags]::ObjectInherit),[System.Security.AccessControl.PropagationFlags]::None,[System.Security.AccessControl.AccessControlType]::Allow)
             $ACL = Get-Acl -Path $homeDirectory
             $ACL.AddAccessRule($AccessRule)
             Set-Acl -Path $homeDirectory -AclObject $ACL
            $logbox.Text =$logbox.Text+"`r`n"+"DisplayName: "+$DisplayName
            $logbox.Text =$logbox.Text+"`r`n"+"Description: "+$description
            $logbox.Text =$logbox.Text+"`r`n"+"Company: "+$company
            $logbox.Text =$logbox.Text+"`r`n"+"Home folder: "+$homeDirectory
            $logbox.Text =$logbox.Text+"`r`n"+"Path: "+$path
            $logbox.Text =$logbox.Text+"`r`n"+"UPN: "+$upn

             $givennamebox.ResetText()
             $familynamebox.ResetText()
             $loginbox.ResetText()
             $samaccountbox.ResetText()
             $departmentbox.ResetText()
             $companybox.ResetText()
        }catch{
            $ErrorMessage = $_.Exception.Message
            [System.Windows.Forms.MessageBox]::Show("$ErrorMessage","Error",0)
        }
      break}
     }
     if($emailbox.Text -ne ''){
           $email=$emailbox.Text.Trim()
           $Session = New-PSSession -ConfigurationName Microsoft.Exchange -ConnectionUri http://EE02/PowerShell/ -Authentication Kerberos
           Import-PSSession $Session –DisableNameChecking
           try{
             Enable-Mailbox -Identity $userID -Alias $userID -DisplayName $DisplayName -Database "CreateUserDB" -PrimarySmtpAddress $email
             Start-Sleep 2
             if($email.StartsWith("Hidden") -or $email.StartsWith("hidden")){
                Set-Mailbox -Identity $userID -HiddenFromAddressListsEnabled 1
             }else{
                Set-Mailbox -Identity $userID -EmailAddressPolicyEnabled 1
                Start-Sleep 2
                Set-Mailbox -Identity $userID -EmailAddressPolicyEnabled 0 -PrimarySmtpAddress $email
             }
             $logbox.Text =$logbox.Text+"`r`n"+"mailbox created with primary SMTP: "+$email
           }catch{
             $ErrorMessage = $_.Exception.Message
             [System.Windows.Forms.MessageBox]::Show("$ErrorMessage","Error",0)
           }
           Remove-PSSession $Session
           $emailbox.ResetText()
    }
    Add-ADGroupMember -Identity "ad_sync" -Members $userID
    $logbox.Text =$logbox.Text+"`r`n"+"Group added: ad_sync"

    $startButton.Enabled=0
    $familynamebox.Enabled=1
    $givennamebox.Enabled=1
    $loginbox.Enabled=1
    $samaccountbox.Enabled=1
    $departmentbox.Enabled=1
    if($listBox.SelectedItem.ToString() -eq 'External'){
        $companybox.Enabled=1
    }
    $listBox.Enabled=1
    $emailBox.Enabled=1
    $startButton.Text = "CREATED"
    $checkButton.Enabled=0
    $findButton.PerformClick()
}

#user finder on top of GUI
function Find_User{
   if ($logonnamefield.Enabled -eq 1) {
       $name=($logonnamefield.Text.Trim())
       $userfoundlabel.ResetText()
       $users2=Get-ADUser -filter "SamAccountName -eq `"$name`""
       if($users2 -eq $null){
            $Form2 = New-Object System.Windows.Forms.Form
            $Form2.width = 400
            $Form2.height = 130
            $Form2.Text = ”selector formular”
            $Form2.MaximizeBox=0
            $Form2.MinimizeBox=0
            $userfoundbox = New-Object System.Windows.Forms.ComboBox
            $userfoundbox.Location = new-object System.Drawing.Size(0,0)
            $userfoundbox.Size = new-object System.Drawing.Size(380, 30)
            $Form2.Controls.Add($userfoundbox)
            $name="*"+$name+"*"
            $checkboxEnabledOnly= new-object System.Windows.Forms.Checkbox
            $checkboxEnabledOnly.Location = new-object System.Drawing.Size(50, 40)
            $checkboxEnabledOnly.Size = new-object System.Drawing.Size(100, 30)
            $checkboxEnabledOnly.Text = "Enabled Only"
            $checkboxEnabledOnly.Checked=1
            $Form2.Controls.Add($checkboxEnabledOnly)
            $label= new-object System.Windows.Forms.Label
            $label.Location = new-object System.Drawing.Size(200, 40)
            $label.Size = new-object System.Drawing.Size(170, 30)
            $label.Text = "Select User and close window"
            $Form2.Controls.Add($label)

            function Refresh_ComboBox{
                $userfoundbox.Items.Clear()
                $userfoundbox.Text=""
                if($checkboxEnabledOnly.Checked){
                    $Enabled=$true
                }else{
                    $Enabled=$false
                }
                $users2=get-aduser -Filter "Surname -Like `"$name`" -and Enabled -eq `"$Enabled`""
                if($users2 -eq $null){
                    $users2=get-aduser -Filter "GivenName -Like `"$name`"-and Enabled -eq `"$Enabled`""
                    if($users2 -ne $null){
                        foreach($User in  $users2){
                            [string] $userfoundbox.Items.Add($User.SamAccountName+";"+$User.Name)
                        }
                    }
                }else{
                    foreach($User in  $users2){
                        [string] $userfoundbox.Items.Add($User.SamAccountName+";"+$User.Name)
                    }
                }
                if($userfoundbox.Items.Count -ne 0){
                    $userfoundbox.SelectedItem = $userfoundbox.Items[0]
                }else{
                    $userfoundbox.SelectedItem = $null
                }
            }
            Refresh_ComboBox
                        
            $checkboxEnabledOnly.Add_CheckStateChanged({
                if ($checkboxEnabledOnly.Checked) {
                    $checkboxEnabledOnly.Text = "Enabled Only"
                    Refresh_ComboBox
                }
                else {
                    $checkboxEnabledOnly.Text = "Disabled Only"
                    Refresh_ComboBox
                }
            })

            $Form2.Add_Shown({$Form2.Activate()})
            $Form2.ShowDialog()
            if($userfoundbox.SelectedItem -eq $null){
                $userfoundlabel.Text = "user not found"
                $checkButton.Enabled=1
                $samaccountbox.Text=$logonnamefield.Text.Trim()
                $Form2.Close()
                return
            }else{
                $logonnamefield.Text=$userfoundbox.SelectedItem.ToString().split(";")[0]
            }
        }
        $userfoundlabel.Text = "user found"
        $logbox.Text += "`r`n" + "user " + $logonnamefield.Text.Trim() + " loaded"
        $checkButton.Enabled=0
        $logonnamefield.Enabled=0
        $addGroupbutton.Enabled=1
        $deleteuserbutton.Enabled=1
        $checkButton2.Enabled=1
    }
    else {
        $userfoundlabel.ResetText()
        $logonnamefield.Enabled=1
        $checkButton.Enabled=0
        $addGroupbutton.Enabled=0
        $checkButton2.Enabled=0
        $deleteuserbutton.Enabled=0
    }
}

#function that adds permissions to found account
function Add_Group{
    $addGrouplabel.ResetText()
    $addGrouplabel2.ResetText()
    $field=$logonnamefield.Text.Trim()
    $user=get-aduser -Filter {samAccountName -eq $field}
    if($addGroupfield.Text -ne ""){
        try{
             Add-ADGroupMember -Identity $addGroupfield.Text.Trim() -Members $user
              $addGrouplabel.Text="Group added"
              $addGroupfield.ResetText()
              $logbox.Text =$logbox.Text+"`r`n"+"group added: "+$addGroupfield.Text.Trim()
            }
            catch{
             $addGrouplabel.Text="Group cant be added"
             $ErrorMessage = $_.Exception.Message
            [System.Windows.Forms.MessageBox]::Show("$ErrorMessage","Error",0)
            }
        }
    if($addGroupfield2.Text -ne ""){
        try{
             Add-ADGroupMember -Identity $addGroupfield2.Text.Trim() -Members $user
              $addGrouplabel2.Text="Group added"
              $addGroupfield2.ResetText()
              $logbox.Text =$logbox.Text+"`r`n"+"group added: "+$addGroupfield2.Text.Trim()
            }
            catch{
             $addGrouplabel2.Text="Group cant be added"
             $ErrorMessage = $_.Exception.Message
             [System.Windows.Forms.MessageBox]::Show("$ErrorMessage","Error",0)
            }
        }

    if($checkboxsofttoken.Checked){
         try{
             Add-ADGroupMember -Identity "SoftToken" -Members $user
             $logbox.Text =$logbox.Text+"`r`n"+"group added: SoftToken"
         }catch{
             $ErrorMessage = $_.Exception.Message
             [System.Windows.Forms.MessageBox]::Show("$ErrorMessage","Error",0)
         }    
    }
    if($checkboxconfluence.Checked){
         try{
             Add-ADGroupMember -Identity "adConfluence" -Members $user
             $logbox.Text =$logbox.Text+"`r`n"+"group added: adConfluence"
         }catch{
             $ErrorMessage = $_.Exception.Message
             [System.Windows.Forms.MessageBox]::Show("$ErrorMessage","Error",0)
         }    
    }

    $findButton.PerformClick()
    $addGroupfield.ResetText()
    $addGroupfield2.ResetText()
    $addGroupbutton.Enabled=0
}

function Delete_User{
    $deletestatus.ResetText()
    if($deleteusercheckbox.Checked){
        try{
          $field=$logonnamefield.Text.Trim()
          $user=get-aduser -Filter {samAccountName -eq $field}
          mkdir .\Documents\long-files
          if(Test-Path -Path ("\\EE\User$\"+$field)){
             try{
                 #robocopy used because users sometimes have files we dont have rights to remove, but they can be removed by robocopy. Change $myemptyfolder to empty folder on your profile
                 $myemptyfolder=".\Documents\long-files"
                 $deletestatus.Text="Removing home folder, please wait"
                 robocopy $myemptyfolder ("\\EE\User$\"+$field) /purge
                 Remove-Item ("\\EE\User$\"+$field) -Recurse -Force
                 $logbox.Text =$logbox.Text+"`r`n"+"Home folder \\EE\User$\"+$field+" removed"
                 $deletestatus.ResetText()
             }catch{
                  [System.Windows.Forms.MessageBox]::Show("Error in deleting home folder","Error",0)
             }
           }
           rmdir .\Documents\long-files

            Remove-ADObject -Identity ($user.DistinguishedName) -Recursive -Confirm:$false
            $logbox.Text =$logbox.Text+"`r`n"+"account removed"
            $deletestatus.Text="user deleted"
            $deleteusercheckbox.Checked=$false
         }catch{
            $deletestatus.Text="user cant be deleted"
            $ErrorMessage = $_.Exception.Message
            [System.Windows.Forms.MessageBox]::Show("$ErrorMessage","Error",0)
         }       
    }
    else{
        $deletestatus.Text="Check if you want to delete user"
    }
    $deleteuserbutton.Enabled=0
    $findButton.PerformClick()
}

function Log_Reset {
    if ($checkboxsure.Checked) {
        $logbox.ResetText()
        $logbox.Text = "Script started"
        $checkboxsure.Checked = 0
    }
}

#data validation for user modification
function Validate_Data2{
    $startButton2.Text = "START"
    if($startButton2.Enabled){
        $startButton2.Enabled=0
        $loginbox2.Enabled=1
        $samaccountbox2.Enabled=1
        $departmentbox2.Enabled=1
        $companybox2.Enabled=1
        $emailbox2.Enabled=1
        $listBox2.Enabled=1
    }
    else{
       $error_found=0
       $upn = $loginbox2.Text.Trim().ToLower()
       $userID = $samaccountbox2.Text.Trim().ToUpper()
       if($departmentbox2.Text -ne ""){
           $department = $departmentbox2.Text.Trim()
       }

       if($companybox2.Text -ne "" -and $listBox2.SelectedItem.ToString() -eq "External"){
           $company = $companybox2.Text.Trim()
           $companystatus2.ResetText()
       }elseif($companybox2.Text -eq "" -and $listBox2.SelectedItem.ToString() -eq "External"){
           $companystatus2.Text="Company not inputed"
           $error_found=1
       }
   
       #Check users input in text boxes
       if ($upn -eq ''){
          $loginstatus2.Text="UPN not inputed"
          $error_found=1
       }else{
          $loginstatus2.ResetText()
       }
       if ($userID -eq ''){
          $samaccountstatus2.Text="UserID not inputed"
          $error_found=1
       }else{
          $samaccountstatus2.ResetText()
       }

       if($userID -eq $logonnamefield.Text.Trim()){
          $samaccountstatus2.Text="Login matches to login above"
          $error_found=1
       }
       if($userID -match '^[0-9]+$'){
           $samaccountstatus2.Text="UserID in wrong format"
           $error_found=1
       }
        if($company -match '\d'-and $company -ne '' -and $listBox2.SelectedItem.ToString() -eq "External"){
          $companystatus2.Text= "company cant contain number"
          $error_found=1
        }
   
       #check email format
       if($emailbox2.Text -ne ''){
          $test=IsValidEmail($emailbox2.Text.Trim())
          if($test -eq 0){
            $emailstatus2.Text="Email in wrong format";
            $error_found=1
           }else{
            $emailstatus2.ResetText()
            }
        }else{$emailstatus2.ResetText()
        }

        #if problem was found return to user
        if($error_found -eq 1){return}

        $startButton2.Enabled=1
        $loginbox2.Enabled=0
        $samaccountbox2.Enabled=0
        $departmentbox2.Enabled=0
        $companybox2.Enabled=0
        $emailbox2.Enabled=0
        $listBox2.Enabled=0
    }
}

function Change_User{
    $field=$logonnamefield.Text.Trim()
    $upn = $loginbox2.Text.Trim().ToLower()
    $userID = $samaccountbox2.Text.Trim().ToUpper()
    $user = get-aduser -Identity $field -properties *
    $logbox.Text =$logbox.Text+"`r`n"+"changing user: "+$field
    #create account based on selected type
    Switch ($listBox2.SelectedItem.ToString()){
       'Internal' {         
            $city="Praha"
            $country="CZ"
            $street="U Gustava 26"
            $postalCode="72766"
            $company="EE"
           if($departmentbox2.Text -ne ""){
            $department = $departmentbox2.Text.Trim()
            $description="normal User, Department "+$department.substring(0,4)
           }else{
            $description="normal User, Department "+$user.department.substring(0,2)
            $department=$user.department  
           }
            $scriptPath="startlogin.cmd"
            if($user.homedirectory -ne ""){
                $new_folder_path=$user.homedirectory.replace($user.samaccountname,$userID)
            }else{
                $new_folder_path=$null
            }
            $path = "OU=EE,OU=Benutzer,"+(Get-ADDomain).DistinguishedName
            try{
            Move-ADObject -Identity $user.distinguishedname -TargetPath $path
            Start-Sleep 10
            set-aduser -identity $field -UserPrincipalName $upn -Description $description -City $city -Enabled 1 -HomeDirectory $new_folder_path -StreetAddress $street -postalCode $postalCode `
            -SamAccountName $userID -country $country -scriptpath $scriptPath -department $department -Company $company
            Start-Sleep 10
            $logbox.Text =$logbox.Text+"`r`n"+"path: "+$path
            $logbox.Text =$logbox.Text+"`r`n"+"home folder: "+$new_folder_path
            $logbox.Text =$logbox.Text+"`r`n"+"department: "+$department
            $logbox.Text =$logbox.Text+"`r`n"+"company: "+$company
            $logbox.Text =$logbox.Text+"`r`n"+"description: "+$description
            $logbox.Text =$logbox.Text+"`r`n"+"UPN: "+$upn
            $logbox.Text =$logbox.Text+"`r`n"+"login: "+$userID

            if(Test-Path -Path ("\\EE\User$\"+$field)){
                 try{
                     Rename-Item -Path $user.homedirectory -NewName $userID
                 }catch{
                      [System.Windows.Forms.MessageBox]::Show("Error in renaming home folder","Error",0)
                 }
               }
         
               $loginbox2.ResetText()
               $samaccountbox2.ResetText()
               $departmentbox2.ResetText()
               $companybox2.ResetText()
            }catch{
                $ErrorMessage = $_.Exception.Message
                [System.Windows.Forms.MessageBox]::Show("$ErrorMessage","Error",0)
            }  
           break}
       'External'{
            if($checkboxmun2.Checked){
               $city="Brno"
               $country="CZ"
               $street="Nádražní 20"
               $postalCode="88877"
               $company="Slunéčko sro"
            }
            elseif($checkboxcc2.Checked){
               $city="Praha"
               $country="CZ"
               $street="U Gustava 21"
               $postalCode="77766"
               $company="Testing Intership Masters as"           
            }

           if($companybox2.Text -ne ""){
            $company=$companybox2.Text.Trim()
           }else{
            $company=$user.company
           }
           if($departmentbox2.Text -ne ""){
            $department = $departmentbox2.Text.Trim()
            $description="Department "+$department.substring(0,4)+" - Comp. "+$company
           }else{
            $description="Department "+$user.department.substring(0,2)+" - Comp. "+$company
            $department=$user.department   
           }

            $scriptPath="startlogin.cmd"
            if($user.homedirectory -ne ""){
                $new_folder_path=$user.homedirectory.replace($user.samaccountname,$userID)
            }else{
                $new_folder_path=$null
            }
            $path = "OU=EE,OU=Benutzer,OU=Externe,"+(Get-ADDomain).DistinguishedName
            try{
            Move-ADObject -Identity $user.distinguishedname -TargetPath $path
            Start-Sleep 10
            set-aduser -identity $field -UserPrincipalName $upn -Description $description -City $city -Enabled 1 -HomeDirectory $new_folder_path -StreetAddress $street -postalCode $postalCode `
            -SamAccountName $userID -country $country -scriptpath $scriptPath -department $department -Company $company
            Start-Sleep 10
            $logbox.Text =$logbox.Text+"`r`n"+"path: "+$path
            $logbox.Text =$logbox.Text+"`r`n"+"home folder: "+$new_folder_path
            $logbox.Text =$logbox.Text+"`r`n"+"department: "+$department
            $logbox.Text =$logbox.Text+"`r`n"+"company: "+$company
            $logbox.Text =$logbox.Text+"`r`n"+"description: "+$description
            $logbox.Text =$logbox.Text+"`r`n"+"UPN: "+$upn
            $logbox.Text =$logbox.Text+"`r`n"+"login: "+$userID

            if(Test-Path -Path ("\\EE\User$\"+$field)){
                 try{
                     Rename-Item -Path $user.homedirectory -NewName $userID
                 }catch{
                      [System.Windows.Forms.MessageBox]::Show("Error in renaming home folder","Error",0)
                 }
               }

                 $loginbox2.ResetText()
                 $samaccountbox2.ResetText()
                 $departmentbox2.ResetText()
                 $companybox2.ResetText()
            }catch{
                $ErrorMessage = $_.Exception.Message
                [System.Windows.Forms.MessageBox]::Show("$ErrorMessage","Error",0)
            }
          break}
     }
     if($emailbox2.Text -ne ''){
           $email=$emailbox2.Text.Trim()
           $Session = New-PSSession -ConfigurationName Microsoft.Exchange -ConnectionUri http://EE02/PowerShell/ -Authentication Kerberos
           Import-PSSession $Session –DisableNameChecking
           try{
            Set-Mailbox -identity ($user.mail) -PrimarySmtpAddress $upn -EmailAddressPolicyEnabled 0 -Alias $userID
            $logbox.Text =$logbox.Text+"`r`n"+"email: "+$upn
            Start-Sleep 5
            Set-Mailbox -Identity $userID -EmailAddresses @{remove=$user.mail}
           }catch{
             $ErrorMessage = $_.Exception.Message
             [System.Windows.Forms.MessageBox]::Show("$ErrorMessage","Error",0)
           }
           Remove-PSSession $Session
           $emailbox2.ResetText()        
    }
    $startButton2.Enabled=0
    $loginbox2.Enabled=1
    $samaccountbox2.Enabled=1
    $departmentbox2.Enabled=1
    if($listBox2.SelectedItem.ToString() -eq 'External'){
        $companybox2.Enabled=1
    }
    $listBox2.Enabled=1
    $emailbox2.Enabled=1
    $startButton2.Text = "CHANGED"
    $checkButton2.Enabled=0
    $findButton.PerformClick()
}


#GUI itself
function GUI{
    [void] [System.Reflection.Assembly]::LoadWithPartialName("System.Windows.Forms")
    [void] [System.Reflection.Assembly]::LoadWithPartialName("System.Drawing")
    
    # Set the size of your form
    $Form = New-Object System.Windows.Forms.Form
    $Form.Text = ”AD formular”
    $Form.Size=new-object System.Drawing.Size(700,560)
 
    # Set the font of the text to be used within the form
    $Font = New-Object System.Drawing.Font("Times New Roman",11)
    $Form.Font = $Font

    #check user
    $logonnamelabel = New-Object System.Windows.Forms.Label
    $logonnamelabel.Location = new-object System.Drawing.Size(20,2)
    $logonnamelabel.Size = new-object System.Drawing.Size(200,27)
    $logonnamelabel.Text = "check if user exists by UserID:"
    $Form.Controls.Add($logonnamelabel)
    $logonnamefield = New-Object System.Windows.Forms.TextBox
    $logonnamefield.Location = new-object System.Drawing.Size(20,30)
    $logonnamefield.Size = new-object System.Drawing.Size(200,30)
    $Form.Controls.Add($logonnamefield)
    $userfoundlabel = New-Object System.Windows.Forms.Label
    $userfoundlabel.Location = new-object System.Drawing.Size(330,30)
    $userfoundlabel.Size = new-object System.Drawing.Size(200,27)
    $Form.Controls.Add($userfoundlabel)
    $findButton = new-object System.Windows.Forms.Button
    $findButton.Location = new-object System.Drawing.Size(225,20)
    $findButton.Size = new-object System.Drawing.Size(100,40)
    $findButton.Text = "find user"
    $findButton.Add_Click({Find_User})
    $form.Controls.Add($findButton)

    $tabControl = New-object System.Windows.Forms.TabControl
    $tabControl.Size = new-object System.Drawing.Size(700,450)
    $tabControl.Location = new-object System.Drawing.Size(0,70)
    $form.Controls.Add($tabControl)

    $createUser = New-Object System.Windows.Forms.TabPage
    $createUser.UseVisualStyleBackColor = 1
    $createUser.Text = "Create User”
    $tabControl.Controls.Add($createUser)
    $addGroups = New-Object System.Windows.Forms.TabPage
    $addGroups.UseVisualStyleBackColor = 1
    $addGroups.Text = "add groups”
    $tabControl.Controls.Add($addGroups)
    $modify = New-Object System.Windows.Forms.TabPage
    $modify.UseVisualStyleBackColor = 1
    $modify.Text = "User type change”
    $tabControl.Controls.Add($modify)
    $delete = New-Object System.Windows.Forms.TabPage
    $delete.UseVisualStyleBackColor = 1
    $delete.Text = "Delete”
    $tabControl.Controls.Add($delete)
    $log = New-Object System.Windows.Forms.TabPage
    $log.UseVisualStyleBackColor = 1
    $log.Text = "Log”
    $tabControl.Controls.Add($log)

    #C$InitialFormWindowState = New-Object System.Windows.Forms.FormWindowState
#-------------------------------------------------------------------------------------------------------------------------------------
    #User Creation
    $companylabel = New-Object System.Windows.Forms.Label
    $companylabel.Location = new-object System.Drawing.Size(20,240)
    $companylabel.Size = new-object System.Drawing.Size(140,30)
    $companylabel.Text = "Company:"
    $createUser.Controls.Add($companylabel)
    $companybox = new-object System.Windows.Forms.Textbox
    $companybox.Location = new-object System.Drawing.Size(160,240)
    $companybox.Size = new-object System.Drawing.Size(150,40)
    $createUser.Controls.Add($companybox)  
    $companystatus = New-Object System.Windows.Forms.Label
    $companystatus.Location = new-object System.Drawing.Size(310,240)
    $companystatus.Size = new-object System.Drawing.Size(320,30)
    $createUser.Controls.Add($companystatus)

    $listboxlabel = New-Object System.Windows.Forms.Label
    $listboxlabel.Location = new-object System.Drawing.Size(20,0)
    $listboxlabel.Size = new-object System.Drawing.Size(130,30)
    $listboxlabel.Text = "account type:"
    $createUser.Controls.Add($listboxlabel)
    $listBox = New-Object System.Windows.Forms.ListBox
    $listBox.Location = new-object System.Drawing.Size(160,0)
    $listBox.Size = new-object System.Drawing.Size(100,40)
    [string] $listBox.Items.Add('Internal')
    [string] $listBox.Items.Add('External')
    $createUser.Controls.Add($listBox)
    $listboxstatus = New-Object System.Windows.Forms.Label
    $listboxstatus.Location = new-object System.Drawing.Size(260,0)
    $listboxstatus.Size = new-object System.Drawing.Size(200,30)
    $createUser.Controls.Add($listboxstatus)
    $listBox.add_SelectedIndexChanged({
        if($listBox.SelectedItem.ToString() -eq 'External'){
            $companybox.Enabled=1
        }else{
            $companybox.Enabled=0
        }      
        $listboxstatus.Text = $listBox.SelectedItem+" is selected"
    })
    $listBox.SelectedItem=$listBox.Items[1]


    $familynamelabel = New-Object System.Windows.Forms.Label
    $familynamelabel.Location = new-object System.Drawing.Size(20,50)
    $familynamelabel.Size = new-object System.Drawing.Size(140,30)
    $familynamelabel.Text = "Family Name:"
    $createUser.Controls.Add($familynamelabel)
    $familynamebox = new-object System.Windows.Forms.Textbox
    $familynamebox.Location = new-object System.Drawing.Size(160,50)
    $familynamebox.Size = new-object System.Drawing.Size(150,40)
    $createUser.Controls.Add($familynamebox)  
    $familynamestatus = New-Object System.Windows.Forms.Label
    $familynamestatus.Location = new-object System.Drawing.Size(310,50)
    $familynamestatus.Size = new-object System.Drawing.Size(320,30)
    $createUser.Controls.Add($familynamestatus)

    $givennamelabel = New-Object System.Windows.Forms.Label
    $givennamelabel.Location = new-object System.Drawing.Size(20,80)
    $givennamelabel.Size = new-object System.Drawing.Size(140,30)
    $givennamelabel.Text = "Given Name:"
    $createUser.Controls.Add($givennamelabel)
    $givennamebox = new-object System.Windows.Forms.Textbox
    $givennamebox.Location = new-object System.Drawing.Size(160,80)
    $givennamebox.Size = new-object System.Drawing.Size(150,40)
    $createUser.Controls.Add($givennamebox)  
    $givennamestatus = New-Object System.Windows.Forms.Label
    $givennamestatus.Location = new-object System.Drawing.Size(310,80)
    $givennamestatus.Size = new-object System.Drawing.Size(320,30)
    $createUser.Controls.Add($givennamestatus)
    
    $loginlabel = New-Object System.Windows.Forms.Label
    $loginlabel.Location = new-object System.Drawing.Size(20,110)
    $loginlabel.Size = new-object System.Drawing.Size(140,30)
    $loginlabel.Text = "UPN:"
    $createUser.Controls.Add($loginlabel)
    $loginbox = new-object System.Windows.Forms.Textbox
    $loginbox.Location = new-object System.Drawing.Size(160,110)
    $loginbox.Size = new-object System.Drawing.Size(150,40)
    $createUser.Controls.Add($loginbox)  
    $loginstatus = New-Object System.Windows.Forms.Label
    $loginstatus.Location = new-object System.Drawing.Size(310,110)
    $loginstatus.Size = new-object System.Drawing.Size(320,30)
    $createUser.Controls.Add($loginstatus)

    $samaccountlabel = New-Object System.Windows.Forms.Label
    $samaccountlabel.Location = new-object System.Drawing.Size(20,140)
    $samaccountlabel.Size = new-object System.Drawing.Size(140,30)
    $samaccountlabel.Text = "UserID:"
    $createUser.Controls.Add($samaccountlabel)
    $samaccountbox = new-object System.Windows.Forms.Textbox
    $samaccountbox.Location = new-object System.Drawing.Size(160,140)
    $samaccountbox.Size = new-object System.Drawing.Size(150,40)
    $createUser.Controls.Add($samaccountbox)  
    $samaccountstatus = New-Object System.Windows.Forms.Label
    $samaccountstatus.Location = new-object System.Drawing.Size(310,140)
    $samaccountstatus.Size = new-object System.Drawing.Size(320,30)
    $createUser.Controls.Add($samaccountstatus)
        $checkboxmun = new-object System.Windows.Forms.radioButton
    $checkboxmun.Location = new-object System.Drawing.Size(10,170)
    $checkboxmun.Size = new-object System.Drawing.Size(210,30)
    $checkboxmun.Text = "Slunéčko sro"
    $checkboxmun.Checked=1
    $createUser.Controls.Add($checkboxmun)  
    $checkboxcc = new-object System.Windows.Forms.radioButton
    $checkboxcc.Location = new-object System.Drawing.Size(220,170)
    $checkboxcc.Size = new-object System.Drawing.Size(300,30)
    $checkboxcc.Text = "Testing Intership Masters as"
    $createUser.Controls.Add($checkboxcc)

    $departmentlabel = New-Object System.Windows.Forms.Label
    $departmentlabel.Location = new-object System.Drawing.Size(20,200)
    $departmentlabel.Size = new-object System.Drawing.Size(140,30)
    $departmentlabel.Text = "Department:"
    $createUser.Controls.Add($departmentlabel)
    $departmentbox = new-object System.Windows.Forms.Textbox
    $departmentbox.Location = new-object System.Drawing.Size(160,200)
    $departmentbox.Size = new-object System.Drawing.Size(150,40)
    $createUser.Controls.Add($departmentbox)  
    $departmentstatus = New-Object System.Windows.Forms.Label
    $departmentstatus.Location = new-object System.Drawing.Size(310,200)
    $departmentstatus.Size = new-object System.Drawing.Size(320,30)
    $createUser.Controls.Add($departmentstatus)

    $emaillabel = New-Object System.Windows.Forms.Label
    $emaillabel.Location = new-object System.Drawing.Size(20,280)
    $emaillabel.Size = new-object System.Drawing.Size(140,30)
    $emaillabel.Text = "Email:"
    $createUser.Controls.Add($emaillabel)
    $emailbox = new-object System.Windows.Forms.Textbox
    $emailbox.Location = new-object System.Drawing.Size(160,280)
    $emailbox.Size = new-object System.Drawing.Size(150,40)
    $createUser.Controls.Add($emailbox)  
    $emailstatus = New-Object System.Windows.Forms.Label
    $emailstatus.Location = new-object System.Drawing.Size(310,280)
    $emailstatus.Size = new-object System.Drawing.Size(320,30)
    $createUser.Controls.Add($emailstatus)
    
    $checkButton = new-object System.Windows.Forms.Button
    $checkButton.Location = new-object System.Drawing.Size(20,320)
    $checkButton.Size = new-object System.Drawing.Size(140,40)
    $checkButton.Text = "Check Data"
    $checkButton.Enabled=0
    $checkButton.Add_Click({Validate_Data})
    $createUser.Controls.Add($checkButton)

    $startButton = new-object System.Windows.Forms.Button
    $startButton.Location = new-object System.Drawing.Size(160,320)
    $startButton.Size = new-object System.Drawing.Size(100,40)
    $startButton.Text = "START"
    $startButton.Enabled=0
    $startButton.Add_Click({Create_User})
    $createUser.Controls.Add($startButton)
     
#-------------------------------------------------------------------------------------------------------------------------------------    
    #add Groups
    $addGrouplabel = New-Object System.Windows.Forms.Label
    $addGrouplabel.Location = new-object System.Drawing.Size(20,52)
    $addGrouplabel.Size = new-object System.Drawing.Size(150,27)
    $addGrouplabel.Text = "add group:"
    $addGroups.Controls.Add($addGrouplabel)
    $addGroupfield = New-Object System.Windows.Forms.TextBox
    $addGroupfield.Location = new-object System.Drawing.Size(20,80)
    $addGroupfield.Size = new-object System.Drawing.Size(200,30)
    $addGroups.Controls.Add($addGroupfield)
    $addGrouplabel = New-Object System.Windows.Forms.Label
    $addGrouplabel.Location = new-object System.Drawing.Size(330,80)
    $addGrouplabel.Size = new-object System.Drawing.Size(200,27)
    $addGroups.Controls.Add($addGrouplabel)
    $addGrouplabel2 = New-Object System.Windows.Forms.Label
    $addGrouplabel2.Location = new-object System.Drawing.Size(20,122)
    $addGrouplabel2.Size = new-object System.Drawing.Size(150,27)
    $addGrouplabel2.Text = "add group 2:"
    $addGroups.Controls.Add($addGrouplabel2)
    $addGroupfield2 = New-Object System.Windows.Forms.TextBox
    $addGroupfield2.Location = new-object System.Drawing.Size(20,150)
    $addGroupfield2.Size = new-object System.Drawing.Size(200,30)
    $addGroups.Controls.Add($addGroupfield2)
    $addGrouplabel2 = New-Object System.Windows.Forms.Label
    $addGrouplabel2.Location = new-object System.Drawing.Size(330,150)
    $addGrouplabel2.Size = new-object System.Drawing.Size(200,27)
    $addGroups.Controls.Add($addGrouplabel2)

    $checkboxsofttoken = new-object System.Windows.Forms.checkBox
    $checkboxsofttoken.Location = new-object System.Drawing.Size(20,260)
    $checkboxsofttoken.Size = new-object System.Drawing.Size(200,30)
    $checkboxsofttoken.Text = "soft token"
    $addGroups.Controls.Add($checkboxsofttoken)
    $checkboxconfluence = new-object System.Windows.Forms.checkBox
    $checkboxconfluence.Location = new-object System.Drawing.Size(420,260)
    $checkboxconfluence.Size = new-object System.Drawing.Size(200,30)
    $checkboxconfluence.Text = "confluence"
    $addGroups.Controls.Add($checkboxconfluence)

    $addGroupbutton= new-object System.Windows.Forms.Button
    $addGroupbutton.Location = new-object System.Drawing.Size(120,320)
    $addGroupbutton.Size = new-object System.Drawing.Size(100,40)
    $addGroupbutton.Text = "Add"
    $addGroupbutton.Enabled=0
    $addGroupbutton.Add_Click({Add_Group})
    $addGroups.Controls.Add($addGroupbutton)

#-------------------------------------------------------------------------------------------------------------------------------------
#delete user
    $deleteusercheckbox = New-Object System.Windows.Forms.CheckBox
    $deleteusercheckbox.Location = new-object System.Drawing.Size(100,100)
    $deleteusercheckbox.Size = new-object System.Drawing.Size(160,30)
    $deleteusercheckbox.Text = "delete user?"
    $delete.Controls.Add($deleteusercheckbox)
    $deleteuserbutton= new-object System.Windows.Forms.Button
    $deleteuserbutton.Location = new-object System.Drawing.Size(100,130)
    $deleteuserbutton.Size = new-object System.Drawing.Size(130,40)
    $deleteuserbutton.Text = "delete user"
    $deleteuserbutton.Enabled=0
    $deleteuserbutton.Add_Click({Delete_User})
    $delete.Controls.Add($deleteuserbutton)
    $deletestatus = New-Object System.Windows.Forms.Label
    $deletestatus.Location = new-object System.Drawing.Size(100,170)
    $deletestatus.Size = new-object System.Drawing.Size(300,30)
    $delete.Controls.Add($deletestatus)

#-------------------------------------------------------------------------------------------------------------------------------------
    #Modify user
    $companylabel2 = New-Object System.Windows.Forms.Label
    $companylabel2.Location = new-object System.Drawing.Size(20,240)
    $companylabel2.Size = new-object System.Drawing.Size(140,30)
    $companylabel2.Text = "Company:"
    $modify.Controls.Add($companylabel2)
    $companybox2 = new-object System.Windows.Forms.Textbox
    $companybox2.Location = new-object System.Drawing.Size(160,240)
    $companybox2.Size = new-object System.Drawing.Size(150,40)
    $modify.Controls.Add($companybox2)  
    $companystatus2 = New-Object System.Windows.Forms.Label
    $companystatus2.Location = new-object System.Drawing.Size(310,240)
    $companystatus2.Size = new-object System.Drawing.Size(320,30)
    $modify.Controls.Add($companystatus2)

    $listBox2label2 = New-Object System.Windows.Forms.Label
    $listBox2label2.Location = new-object System.Drawing.Size(20,0)
    $listBox2label2.Size = new-object System.Drawing.Size(130,30)
    $listBox2label2.Text = "account type:"
    $modify.Controls.Add($listBox2label2)
    $listBox2 = New-Object System.Windows.Forms.ListBox
    $listBox2.Location = new-object System.Drawing.Size(160,0)
    $listBox2.Size = new-object System.Drawing.Size(100,40)
    [string] $listBox2.Items.Add('Internal')
    [string] $listBox2.Items.Add('External')
    $modify.Controls.Add($listBox2)
    $listBox2status = New-Object System.Windows.Forms.Label
    $listBox2status.Location = new-object System.Drawing.Size(260,0)
    $listBox2status.Size = new-object System.Drawing.Size(200,30)
    $modify.Controls.Add($listBox2status)
    $listBox2.add_SelectedIndexChanged({
        if($listBox2.SelectedItem.ToString() -eq 'External'){
            $companybox2.Enabled=1
        }else{
            $companybox2.Enabled=0
        }      
        $listBox2status.Text = $listBox2.SelectedItem+" is selected"
    })
    $listBox2.SelectedItem=$listBox2.Items[1]

    $messagelabel = New-Object System.Windows.Forms.Label
    $messagelabel.Location = new-object System.Drawing.Size(20,60)
    $messagelabel.Size = new-object System.Drawing.Size(510,30)
    $messagelabel.Text = "Change secondary SMTP addresses after type change is done"
    $modify.Controls.Add($messagelabel)

    $loginlabel2 = New-Object System.Windows.Forms.Label
    $loginlabel2.Location = new-object System.Drawing.Size(20,110)
    $loginlabel2.Size = new-object System.Drawing.Size(140,30)
    $loginlabel2.Text = "UPN:"
    $modify.Controls.Add($loginlabel2)
    $loginbox2 = new-object System.Windows.Forms.Textbox
    $loginbox2.Location = new-object System.Drawing.Size(160,110)
    $loginbox2.Size = new-object System.Drawing.Size(150,40)
    $modify.Controls.Add($loginbox2)  
    $loginstatus2 = New-Object System.Windows.Forms.Label
    $loginstatus2.Location = new-object System.Drawing.Size(310,110)
    $loginstatus2.Size = new-object System.Drawing.Size(320,30)
    $modify.Controls.Add($loginstatus2)

    $samaccountlabel2 = New-Object System.Windows.Forms.Label
    $samaccountlabel2.Location = new-object System.Drawing.Size(20,140)
    $samaccountlabel2.Size = new-object System.Drawing.Size(140,30)
    $samaccountlabel2.Text = "UserID:"
    $modify.Controls.Add($samaccountlabel2)
    $samaccountbox2 = new-object System.Windows.Forms.Textbox
    $samaccountbox2.Location = new-object System.Drawing.Size(160,140)
    $samaccountbox2.Size = new-object System.Drawing.Size(150,40)
    $modify.Controls.Add($samaccountbox2)  
    $samaccountstatus2 = New-Object System.Windows.Forms.Label
    $samaccountstatus2.Location = new-object System.Drawing.Size(310,140)
    $samaccountstatus2.Size = new-object System.Drawing.Size(320,30)
    $modify.Controls.Add($samaccountstatus2)
        $checkboxmun2 = new-object System.Windows.Forms.radioButton
    $checkboxmun2.Location = new-object System.Drawing.Size(10,170)
    $checkboxmun2.Size = new-object System.Drawing.Size(210,30)
    $checkboxmun2.Text = "Slunéčko sro"
    $checkboxmun2.Checked=1
    $modify.Controls.Add($checkboxmun2)  
    $checkboxcc2 = new-object System.Windows.Forms.radioButton
    $checkboxcc2.Location = new-object System.Drawing.Size(220,170)
    $checkboxcc2.Size = new-object System.Drawing.Size(320,30)
    $checkboxcc2.Text = "Testing Intership Masters as"
    $modify.Controls.Add($checkboxcc2)

    $departmentlabel2 = New-Object System.Windows.Forms.Label
    $departmentlabel2.Location = new-object System.Drawing.Size(20,200)
    $departmentlabel2.Size = new-object System.Drawing.Size(140,30)
    $departmentlabel2.Text = "Department:"
    $modify.Controls.Add($departmentlabel2)
    $departmentbox2 = new-object System.Windows.Forms.Textbox
    $departmentbox2.Location = new-object System.Drawing.Size(160,200)
    $departmentbox2.Size = new-object System.Drawing.Size(150,40)
    $modify.Controls.Add($departmentbox2)  
    $departmentstatus2 = New-Object System.Windows.Forms.Label
    $departmentstatus2.Location = new-object System.Drawing.Size(310,200)
    $departmentstatus2.Size = new-object System.Drawing.Size(320,30)
    $modify.Controls.Add($departmentstatus2)

    $emaillabel2 = New-Object System.Windows.Forms.Label
    $emaillabel2.Location = new-object System.Drawing.Size(20,280)
    $emaillabel2.Size = new-object System.Drawing.Size(140,30)
    $emaillabel2.Text = "Email:"
    $modify.Controls.Add($emaillabel2)
    $emailbox2 = new-object System.Windows.Forms.Textbox
    $emailbox2.Location = new-object System.Drawing.Size(160,280)
    $emailbox2.Size = new-object System.Drawing.Size(150,40)
    $modify.Controls.Add($emailbox2)  
    $emailstatus2 = New-Object System.Windows.Forms.Label
    $emailstatus2.Location = new-object System.Drawing.Size(310,280)
    $emailstatus2.Size = new-object System.Drawing.Size(320,30)
    $modify.Controls.Add($emailstatus2)
      
    $checkButton2 = new-object System.Windows.Forms.Button
    $checkButton2.Location = new-object System.Drawing.Size(20,320)
    $checkButton2.Size = new-object System.Drawing.Size(140,40)
    $checkButton2.Text = "Check Data"
    $checkButton2.Enabled=0
    $checkButton2.Add_Click({Validate_Data2})
    $modify.Controls.Add($checkButton2)

    $startButton2 = new-object System.Windows.Forms.Button
    $startButton2.Location = new-object System.Drawing.Size(160,320)
    $startButton2.Size = new-object System.Drawing.Size(100,40)
    $startButton2.Text = "START"
    $startButton2.Enabled=0
    $startButton2.Add_Click({Change_User})
    $modify.Controls.Add($startButton2)

#-------------------------------------------------------------------------------------------------------------------------------------
    #log
    $logbutton = new-object System.Windows.Forms.Button
    $logbutton.Location = new-object System.Drawing.Size(50, 30)
    $logbutton.Size = new-object System.Drawing.Size(100, 30)
    $logbutton.Text = "ResetText"
    $logbutton.Add_Click({ Log_Reset })
    $log.Controls.Add($logbutton)
    $checkboxsure = New-Object System.Windows.Forms.CheckBox
    $checkboxsure.Location = new-object System.Drawing.Size(150, 30)
    $checkboxsure.Size = new-object System.Drawing.Size(80, 30)
    $checkboxsure.Text = "sure?"
    $log.Controls.Add($checkboxsure)
    $logbox = New-Object System.Windows.Forms.TextBox
    $logbox.ReadOnly = 1
    $logbox.Multiline = 1
    $logbox.ScrollBars = "Vertical"
    $logbox.Text = "Script started"
    $logbox.Location = new-object System.Drawing.Size(50, 70)
    $logbox.Size = new-object System.Drawing.Size(600, 310)
    $log.Controls.Add($logbox)

#-------------------------------------------------------------------------------------------------------------------------------------        
    # Activate the form
    $Form.Add_Shown({$Form.Activate()})
    [void] $Form.ShowDialog() 
}
 
#Call the function
GUI