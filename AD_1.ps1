####################################################################################
#   Author: Kristek Jan
#   Date: 12.1.2022
#   Last date change: 2.6.2023
#   Version: 1.1.3
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

#password generator
#https://stackoverflow.com/questions/37256154/powershell-password-generator-how-to-always-include-number-in-string
Function Create-Password{
    $Chars = @(); $TokenSet = @();[Char[]]$CharSets = "ULNS"
    If (!$TokenSets) {$Global:TokenSets = @{
        U = [Char[]]'ABCDEFGHIJKLMNOPQRSTUVWXYZ'  #Upper case
        L = [Char[]]'abcdefghijklmnopqrstuvwxyz'  #Lower case
        N = [Char[]]'0123456789'                  #Numerals
        S = [Char[]]'!()+-.:<=>?@'                #Symbols
    }}
        $CharSets | ForEach {
        $Tokens = $TokenSets."$_"
        If ($Tokens) {
            $TokensSet += $Tokens
            If ($_ -cle [Char]"Z") {$Chars += $Tokens | Get-Random}             #Character sets defined in upper case are mandatory
        }
    }
    While ($Chars.Count -lt 13) {$Chars += $TokensSet | Get-Random}
    ($Chars | Sort-Object {Get-Random}) -Join ""                                #Mix the (mandatory) characters and output string
};

#data validation for user creation
function Validate_Data{
    $startButton.Text = "START"
    $expstatus.Text="Use dd.MM.yyyy from Ticket"
    $credentials.Text = "Credentials"
    $credentials.Enabled=0
    if($startButton.Enabled){
        $startButton.Enabled=0
        $familynamebox.Enabled=1
        $givennamebox.Enabled=1
        $loginbox.Enabled=1
        $ameibox.Enabled=1
        $expbox.Enabled=1
        $referenceuserbox.Enabled=1
        $listBox.Enabled=1
    }
    else{
       $firstName =$givennamebox.Text.Trim().Replace(" ","-")
       $lastName = $familynamebox.Text.Trim().Replace(" ","-")
       $firstName=Convert-Characters $firstName
       $lastName=Convert-Characters $lastName
       $login = $loginbox.Text.Trim()
       $amei = $ameibox.Text.Trim()
       if($expbox.Text -ne ""){
           $expiration_date = $expbox.Text.Trim()
           if($expiration_date.IndexOf("/") -eq 1){$expiration_date=$expiration_date.Insert(0,0)}
           if($expiration_date.LastIndexOf("/") -eq 4){$expiration_date=$expiration_date.Insert(3,0)}
       }
       if($referenceuserbox.Text -ne ""){
           $reference_user = $referenceuserbox.Text.Trim()
       }
       $error_found=0

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
       if ($login -eq ''){
          $loginstatus.Text="Login not inputed"
          $error_found=1
       }else{
          $loginstatus.ResetText()
       }

       if ($ameibox.Text -eq '' -and $listBox.SelectedItem.ToString() -ne 'Internal'){
          $ameistatus.Text="AMEI not inputed"
          $error_found=1
       }else{
          $ameistatus.ResetText()
       }

       if( $lastName -match '\d'-and $lastName -ne ''){
         $familynamestatus.Text= "Family Name cant contain number"
         $error_found=1
       }
       if( $firstName -match '\d'-and $firstName -ne ''){
          $givennamestatus.Text="Given Name cant contain number"
          $error_found=1
       }

       if($login -ne $logonnamefield.Text.Trim()){
          $loginstatus.Text="Login doesnt match to login above"
          $error_found=1
       }
       if($ameibox.Text -ne "" -and $listBox.SelectedItem.ToString() -ne 'CGI_SRV'){
           if($amei -notmatch '\d'){
              $ameistatus.Text="AMEI in wrong format"
              $error_found=1
           }else{
                if($amei.StartsWith(0) -eq $false -and $amei.Length -eq 6){
                $allameis=(get-aduser -Filter * -Properties Fax).Fax
                $match_detected=0
                foreach($allamei in $allameis){
                   if($amei.Insert(0,0) -eq $allamei){
                      $match_detected=1
                  }
                 }
                 if($match_detected -eq 1){
                      $ameistatus.Text="AMEI already exists"
                      $error_found=1
                   }else{
                      $ameistatus.ResetText()
                  }
               }
               elseif($amei.StartsWith(1) -eq $true -and $amei.Length -eq 7){
                $allameis=(get-aduser -Filter * -Properties Fax).Fax
                $match_detected=0
                foreach($allamei in $allameis){
                   if($amei -eq $allamei){
                      $match_detected=1
                  }
                 }
                 if($match_detected -eq 1){
                      $ameistatus.Text="AMEI already exists"
                      $error_found=1
                   }else{
                      $ameistatus.ResetText()
                  }
           
               }
               else{
                    $ameistatus.Text="AMEI in wrong format"
                    $error_found=1
               }
           }
       }
       if($expbox.Text -ne ""){
           $expiration_date = [DateTime]::ParseExact($expiration_date, "dd.MM.yyyy", [Globalization.CultureInfo]::InvariantCulture)
            if (!$expiration_date){  
              $expstatus.Text="Date in wrong format. Use dd.MM.yyyy from Ticket"
              $error_found=1
            }
        }else{
         $expstatus.ResetText()
       }
        if($referenceuserbox.Text -ne ""){
            try{
                get-aduser -Filter {samAccountName -eq $reference_user}
                $referenceuserstatus.ResetText()
            }
            catch{
                $referenceuserstatus.Text="Ref. user not found"
                $error_found=1
            }
        }

        #if problem was found return to user
        if($error_found -eq 1){return}

        $startButton.Enabled=1
        $familynamebox.Enabled=0
        $givennamebox.Enabled=0
        $loginbox.Enabled=0
        $ameibox.Enabled=0
        $expbox.Enabled=0
        $referenceuserbox.Enabled=0
        $listBox.Enabled=0
       }
}

function Create_User{
   $firstName =$givennamebox.Text.Trim().Replace(" ","-").replace("_","-")
   $lastName =$familynamebox.Text.Trim().Replace(" ","-").replace("_","-")
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

   $login = $loginbox.Text.Trim().ToUpper()
   if($ameibox.Text -ne ""){
       $amei = $ameibox.Text.Trim()
        if($amei.Length -eq 6){
            $amei = $amei.Insert(0,0)
        }
   }

   if($expbox.Text -ne ""){
     $expiration_date = $expbox.Text.Trim()
     if($expiration_date.IndexOf(".") -eq 1){$expiration_date=$expiration_date.Insert(0,0)}
     if($expiration_date.LastIndexOf(".") -eq 4){$expiration_date=$expiration_date.Insert(3,0)}
     $expbox.ResetText()
   }
   if($referenceuserbox.Text -ne ""){
     $reference_user = $referenceuserbox.Text.Trim()
     $referenceuserbox.ResetText()
   }

   #call password generator
   $password= Create-Password
   $credentials.Text = $login+"  "+$password
   $credentials.Enabled=1
   $password=ConvertTo-SecureString $password -AsPlainText -Force

    #create account based on selected type
    Switch ($listBox.SelectedItem.ToString()){
       'Internal' {
            $path = "OU=Users,"+(Get-ADDomain).DistinguishedName 
            if(!$reference_user){
                $reference_user="_Copy_User"
            }        
            try{
                get-aduser -Filter {samAccountName -eq $reference_user}
            }catch{
                $referenceuserstatus.Text="Ref. user not found"
                return
            }
            $displayName=$lastName+", "+$firstName
            try{
                new-aduser  -AccountPassword $password -UserPrincipalName ($login+"@aa.cz") -ChangePasswordAtLogon 1 -DisplayName $displayName -Enabled 1 -Name $displayName -GivenName $firstName -Path $path `
                 -SamAccountName $login -Surname $lastName -Instance (get-aduser -Filter {samAccountName -eq $reference_user}  -Properties StreetAddress,city,postalCode,country,c,co,countrycode,homedirectory,homedrive,department,company,scriptpath) `
                 -OtherAttributes @{'businessCategory'="Internal"}
                 Start-Sleep 5
                 if($ameibox.Text -ne ""){
                     set-aduser -Identity $login -replace @{'Fax'=$amei}
                     Start-Sleep 2
                 }
                 set-aduser -Identity $login -replace @{'mS-DS-ConsistencyGuid'=(get-aduser -Filter {sAMAccountName -eq $login} -Properties objectGUID |Select-Object objectGUID).objectGUID}
                 $logbox.Text =$logbox.Text+"`r`n"+"account with ID "+$login+" created"
                if($expiration_date){
                    $expiration_date = [DateTime]::ParseExact($expiration_date, "dd.MM.yyyy", [Globalization.CultureInfo]::InvariantCulture)
                    Set-ADAccountExpiration -Identity $login -DateTime $expiration_date.AddDays(2)
                    $logbox.Text =$logbox.Text+"`r`n"+"Expiration date set "+$expiration_date.AddDays(2)
                 }
                 $givennamebox.ResetText()
                 $familynamebox.ResetText()
                 $loginbox.ResetText()
                 $ameibox.ResetText()
            }catch{
                $credentials.Text = "unable to create user"
                $ErrorMessage = $_.Exception.Message
                [System.Windows.Forms.MessageBox]::Show("$ErrorMessage","Error",0)
            }
       
           break}
       'External'{
            $displayName=$lastName+", "+$firstName+" (External)"
            $path = "OU=ExternalUsers,OU=Users,"+(Get-ADDomain).DistinguishedName 
            if(!$reference_user){
               $reference_user="_Copy_External_Users" 
            }
            try{
                get-aduser -Filter {samAccountName -eq $reference_user}
            }catch{
                $referenceuserstatus.Text="Ref. user not found"
                return
            }
            try{
                new-aduser -AccountPassword $password -UserPrincipalName ($login+"@aa.cz") -ChangePasswordAtLogon 0 -DisplayName $displayName -Enabled 1 -Name $displayName -GivenName $firstName -Path $path `
                 -SamAccountName $login -Surname $lastName -Instance (get-aduser -Filter {samAccountName -eq $reference_user} -Properties StreetAddress,city,postalCode,country,c,co,countrycode,homedirectory,homedrive,department,company,scriptpath) `
                  -OtherAttributes @{'businessCategory'="External"}
                  Start-Sleep 5
                 if($ameibox.Text -ne ""){
                     set-aduser -Identity $login -replace @{'Fax'=$amei}
                     Start-Sleep 2
                 }
                  set-aduser -Identity $login -replace @{'mS-DS-ConsistencyGuid'=(get-aduser -Filter {sAMAccountName -eq $login} -Properties objectGUID |Select-Object objectGUID).objectGUID}
                  $logbox.Text =$logbox.Text+"`r`n"+"account with ID "+$login+" created"
                if($expiration_date){
                    $expiration_date = [DateTime]::ParseExact($expiration_date, "dd.MM.yyyy", [Globalization.CultureInfo]::InvariantCulture)
                    Set-ADAccountExpiration -Identity $login -DateTime $expiration_date.AddDays(2)
                    $logbox.Text =$logbox.Text+"`r`n"+"Expiration date set "+$expiration_date.AddDays(2)
                 }
                 $givennamebox.ResetText()
                 $familynamebox.ResetText()
                 $loginbox.ResetText()
                 $ameibox.ResetText()
            }catch{
                $credentials.Text = "unable to create user"
                $ErrorMessage = $_.Exception.Message
                [System.Windows.Forms.MessageBox]::Show("$ErrorMessage","Error",0)
            }

          break}
    }
    if($reference_user){
      try{
          $newuser=get-aduser -Identity $login -Properties homedirectory
          if($newuser.homedirectory){
               $newhomedir=$newuser.homedirectory.Replace((get-aduser -Filter {samAccountName -eq $reference_user} | Select-object samaccountname).samaccountname,$newuser.samaccountname)
                   set-aduser -Identity $newuser -homedirectory $newhomedir
                   New-Item -path $newhomedir -ItemType Directory
                   Start-Sleep 5
                   $AccessRule = new-object System.Security.AccessControl.FileSystemAccessRule(((Get-ADDomain).Name+"\"+$newuser.samaccountname),[System.Security.AccessControl.FileSystemRights]::FullControl,@([System.Security.AccessControl.InheritanceFlags]::ContainerInherit, [System.Security.AccessControl.InheritanceFlags]::ObjectInherit),[System.Security.AccessControl.PropagationFlags]::None,[System.Security.AccessControl.AccessControlType]::Allow)
                   $ACL = Get-Acl -Path $newhomedir
                   $ACL.AddAccessRule($AccessRule)
                   Set-Acl -Path $newhomedir -AclObject $ACL
                   $logbox.Text =$logbox.Text+"`r`n"+"Home directory created"
      }}catch{
          $ErrorMessage = $_.Exception.Message
          [System.Windows.Forms.MessageBox]::Show("$ErrorMessage","Error in home folder",0)
      }
      try{
        Add-ADGroupMember -Identity "AD-PSO" -Members $login
        start-sleep 5
        $userq=get-aduser -Identity $login
        $groups=Get-ADGroup -LDAPFilter "(member=$($userq.DistinguishedName))" | select Name | Sort-Object Name
        $userq=Get-ADUser -Filter {SamAccountNAme -eq $reference_user}
        $groups2=Get-ADGroup -LDAPFilter "(member=$($userq.DistinguishedName))" | select Name | Sort-Object Name
        $diff=Compare-Object $groups $groups2 -Property Name
        $groups=""
        foreach($dif in $diff){
            if($dif.SideIndicator -eq "=>"){
                $groups=$groups+$dif.Name+";"
            }
        }
        $groups=$groups.Split(";")
        foreach($group in $groups){
            if($group -ne ""){
                Add-ADGroupMember -Identity $group -Members $login
                $logbox.Text =$logbox.Text+"`r`n"+"Same group as Ref. User "+$reference_user+" has added "+$group
            }
         }
       }catch{
         $ErrorMessage = $_.Exception.Message
         [System.Windows.Forms.MessageBox]::Show("$ErrorMessage","Error in adding ref. user groups",0)
      }
      Remove-Variable Reference_user
    }
    if($expiration_date){
      Remove-Variable Expiration_date
    }
   
    $startButton.Enabled=0
    $familynamebox.Enabled=1
    $givennamebox.Enabled=1
    $loginbox.Enabled=1
    $ameibox.Enabled=1
    $expbox.Enabled=1
    $referenceuserbox.Enabled=1
    $listBox.Enabled=1
    $startButton.Text = "CREATED"
    $checkButton.Enabled=0
    $findButton.PerformClick()
}


#user finder on top of GUI
function Find_User{
    if($logonnamefield.Enabled -eq 1){
        try{
            get-aduser -Identity $logonnamefield.Text.Trim()
            $userfoundlabel.Text = "user found"
            $logbox.Text =$logbox.Text+"`r`n"+"user "+$logonnamefield.Text.Trim()+" loaded"
            $logonnamefield.Enabled=0
            $findGroup.Enabled = 1
            $findGroups.Enabled = 1
            $deleteuserbutton.Enabled=1
            $flagbutton.Enabled=1
            $ameibox2.Text= (get-aduser -Identity $logonnamefield.Text.Trim() -properties Fax).Fax
            if($ameibox2.Text -eq ""){
                $ameibox2.Enabled = 1
            }
        }
        catch{
         $userfoundlabel.Text = "user not found"
         $checkButton.Enabled=1
         $loginbox.Text=$logonnamefield.Text.Trim()
        }
    }else{
        $userfoundlabel.ResetText()
        $logonnamefield.Enabled=1
        $checkButton.Enabled=0
        $findGroup.Enabled = 0
        $findGroups.Enabled = 0
        $deleteuserbutton.Enabled=0
        $flagbutton.Enabled=0
        $ameibox2.Enabled = 0
        $ameibox2.ResetText()
    }
}

#function that checks that account and group with provided name exists
function Find_Group {
    $foundGroups.Items.Clear()
    $foundGroups2.Items.Clear()
    $addGroups2.Enabled = 0
    $selectGroups.Enabled = 0
    $removeGroups.Enabled = 0
    $selectGroups2.Enabled = 0
    $groupfoundlabel.ResetText()
    if ($groupname.Enabled -eq 1) {
        $name2 = "*" + $groupname.Text.Trim() + "*"
        if (($groupname.Text.Trim()) -eq "") {
            $groupfoundlabel.Text = "enter groups name"
            return
        }
        if (Get-ADGroup -Filter "Name -like `"$name2`"") {
            $groupfoundlabel.Text = "group found"
            $groupname.Enabled = 0
        }
        else {
            $groupfoundlabel.Text = "group not found"
        }
        if ($groupname.Enabled -eq 0) {
            List_Groups
        }
    }
    else {
        $groupname.Enabled = 1
    }
}

#function lists unique group from provided name that user doesnt already have
function List_Groups {
    try {
        $name = $logonnamefield.Text.Trim()
        $name2 = "*" + $groupname.Text.Trim() + "*"
        $userq=Get-ADUser -Filter "SamAccountNAme -eq `"$name`""
        $groups=Get-ADGroup -LDAPFilter "(member=$($userq.DistinguishedName))" | select Name | Sort-Object Name
        $groups2 = Get-ADGroup -Filter "Name -like `"$name2`"" | Select-Object -property Name | Sort-Object Name
    }
    Catch {
        $groupfoundlabel.Text = "groups not found"
        $groupname.Enabled = 1
        return
    }

    $diff = Compare-Object $groups $groups2 -Property Name -IncludeEqual
    $groups = ""
    $groups2 = ""
    foreach ($dif in $diff) {
        if ($dif.SideIndicator -eq "==") {
            $groups = $groups + $dif.Name + ";"
        }
        elseif ($dif.SideIndicator -eq "=>") {
            $groups2 = $groups2 + $dif.Name + ";"
        }
    }
    $groups = $groups.Split(";")
    $groups2 = $groups2.Split(";")

    foreach ($group in $groups) {
        $group = Out-String -InputObject $group
        $group = (($group.Remove(0, $group.LastIndexOf("=") + 1)).Trim()).Replace("}", "")
        $foundGroups2.Items.Add($group)      
    }

    foreach ($group in $groups2) {
        $group = Out-String -InputObject $group
        $group = (($group.Remove(0, $group.LastIndexOf("=") + 1)).Trim()).Replace("}", "")
        $foundGroups.Items.Add($group)      
    }
    $foundGroups2.Items.Remove("")
    $foundGroups.Items.Remove("")
    $groupname.Enabled = 1
    $groupfoundlabel.ResetText()
    if ($foundGroups.Items.Count -gt 0) {
        $addGroups2.Enabled = 1
        $selectGroups.Enabled = 1
    }
    if ($foundGroups2.Items.Count -gt 0) {
        $removeGroups.Enabled = 1
        $selectGroups2.Enabled = 1
    }
}
# function that adds selected groups to user
function Add_Groups {
    if ($foundGroups.SelectedItems -gt 0) {
        $name = $logonnamefield.Text.Trim()
        try {
            foreach ($item in $foundGroups.SelectedItems) {
                $group2 = (get-adgroup -Filter "Name -eq `"$item`"").samAccountName
                Add-ADGroupMember -Identity $group2 -Members (Get-ADUser -Filter "SamAccountNAme -eq `"$name`"").samAccountName
                $logbox.Text += "`r`n" + "group added:  " + $item
            }            
        }
        Catch {
            $ErrorMessage = $_.Exception.Message
            [System.Windows.Forms.MessageBox]::Show("$ErrorMessage", "Error", 0)
        }
        $addGroups2.Enabled = 0
        $foundGroups.items.Clear()
        $foundGroups2.items.Clear()
        Start-Sleep 10
        List_Groups
    }
}
#function that selects\deselects all listed groups
function Select_Groups {
    if ($foundGroups.items.Count -ne $foundGroups.selecteditems.Count) {
        for ($i = 0; $i -lt $foundGroups.items.Count; $i++) {
            $foundGroups.SetSelected($i, 1)
        }
    }
    else {
        for ($i = 0; $i -lt $foundGroups.items.Count; $i++) {
            $foundGroups.SetSelected($i, 0)
        }
    }
}

#function that adds permissions to found account
function Add_Group {
    $field = $logonnamefield.Text.Trim()
    $user = get-aduser -Filter "samAccountName -eq `"$field`""
    if ($addGroupfield.Text -ne "") {
        try {
            if($groupname2.Text -ne "" ){
                $group = $groupname2.Text.Trim() 
                $group2 = (get-adgroup -Filter "Name -eq `"$group`"").samAccountName
                Add-ADGroupMember -Identity $group2 -Members $user.samAccountName
                $logbox.Text += "`r`n" + "group added: " + $groupname2.Text.Trim()
            }
            $groupname2.Text = "Group added"
        }
        catch {
            $groupname2.Text = "Group cant be added"
            $ErrorMessage = $_.Exception.Message
            [System.Windows.Forms.MessageBox]::Show("$ErrorMessage", "Error", 0)
        }
    }
}
#function that removes selected groups from user
function Remove_Groups {
    if ($foundGroups2.SelectedItems -gt 0) {
        $name = $logonnamefield.Text.Trim()
        try {
            foreach ($item in $foundGroups2.SelectedItems) {
                $group2 = (get-adgroup -Filter "Name -eq `"$item`"").samAccountName
                Remove-ADGroupMember -Identity $group2 -Members (Get-ADUser -Filter "SamAccountNAme -eq `"$name`"").samAccountName -confirm:$false
                $logbox.Text += "`r`n" + "group removed:  " + $item
            }
        }
        Catch {
            $ErrorMessage = $_.Exception.Message
            [System.Windows.Forms.MessageBox]::Show("$ErrorMessage", "Error", 0)
        }
        $removeGroups.Enabled = 0
        $foundGroups.items.Clear()
        $foundGroups2.items.Clear()
        Start-Sleep 10
        List_Groups
    }
}

#function that selects\deselects all listed groups
function Select_Groups2 {
    if ($foundGroups2.items.Count -ne $foundGroups2.selecteditems.Count) {
        for ($i = 0; $i -lt $foundGroups2.items.Count; $i++) {
            $foundGroups2.SetSelected($i, 1)
        }
    }
    else {
        for ($i = 0; $i -lt $foundGroups2.items.Count; $i++) {
            $foundGroups2.SetSelected($i, 0)
        }
    }
}

#function that deletes user
function Delete_User{
    $deletestatus.ResetText()
    if($deleteusercheckbox.Checked){
        try{
         $field=$logonnamefield.Text.Trim()
         $user=get-aduser -Filter {samAccountName -eq $field} -properties homeDirectory
         remove-aduser -Identity $user -Confirm:$false
         if((Test-Path -Path $user.homeDirectory) -eq 1){
            try{
                    Remove-Item $user.homeDirectory -Recurse -Force
            }catch{
                    $ErrorMessage = "home directory doesnt exists"
                    [System.Windows.Forms.MessageBox]::Show("$ErrorMessage","Error",0)
            }
         }
            $deletestatus.Text="user deleted"
            $logbox.Text =$logbox.Text+"`r`n"+"account "+$user.SamAccountName+" deleted"
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

#function that gives user a flag and checks amei
function Flag_User{
    $flagstatus.ResetText()
    $field=$logonnamefield.Text.Trim()
    $user=get-aduser -Filter {samAccountName -eq $field}
    switch($flagBox.SelectedItem.ToString()){
        'B1'{
             try{
                 set-aduser -Identity $user -Replace @{info='|B1|'}
                 $logbox.Text =$logbox.Text+"`r`n"+"flag B1 added"
                 $flagstatus.Text="flag added"
             }catch{
                 $flagstatus.Text="cant add flag"
                 $ErrorMessage = $_.Exception.Message
                 [System.Windows.Forms.MessageBox]::Show("$ErrorMessage","Error",0)
             }
            break
         }
        'B2'{
             try{
                 set-aduser -Identity $user -Replace @{info='|B2|'}
                 $logbox.Text =$logbox.Text+"`r`n"+"flag B2 added"
                 $flagstatus.Text="flag added"
             }catch{
                 $flagstatus.Text="cant add flag"
                 $ErrorMessage = $_.Exception.Message
                 [System.Windows.Forms.MessageBox]::Show("$ErrorMessage","Error",0)
             }
            break
        }
        'B3'{
             try{
                 set-aduser -Identity $user -Replace @{info='|B3|'}
                 $logbox.Text =$logbox.Text+"`r`n"+"flag B3 added"
                 $flagstatus.Text="flag added"
             }catch{
                 $flagstatus.Text="cant add flag"
                 $ErrorMessage = $_.Exception.Message
                 [System.Windows.Forms.MessageBox]::Show("$ErrorMessage","Error",0)
             }
            break
        }
    }
    $amei = $ameibox2.Text.Trim()
    if($amei -ne "" -and $ameibox2.Enabled -eq 1){
           if($amei -notmatch '\d'){
              $ameistatus2.Text="AMEI in wrong format"
           }else{
                if($amei.StartsWith(0) -eq $false -and $amei.Length -eq 6){
                    $allameis=(get-aduser -Filter * -Properties Fax).Fax
                    $match_detected=0
                    foreach($allamei in $allameis){
                       if($amei.Insert(0,0) -eq $allamei){
                          $match_detected=1
                      }
                     }
                     if($match_detected -eq 1){
                          $ameistatus2.Text="AMEI already exists"
                       }else{
                          $ameistatus2.ResetText()
                          $amei=$amei.Insert(0,0)
                          set-aduser -Identity $user -Replace @{Fax=$amei}
                      }
                }
                elseif($amei.StartsWith(1) -eq $true -and $amei.Length -eq 7){
                    $allameis=(get-aduser -Filter * -Properties Fax).Fax
                    $match_detected=0
                    foreach($allamei in $allameis){
                       if($amei -eq $allamei){
                          $match_detected=1
                      }
                     }
                     if($match_detected -eq 1){
                          $ameistatus2.Text="AMEI already exists"
                       }else{
                          $ameistatus2.ResetText()
                          set-aduser -Identity $user -Replace @{Fax=$amei}
                      }
                }
                else{
                    $ameistatus2.Text="AMEI in wrong format"
               }
           }
    }
    $flagbutton.Enabled=0
    $findButton.PerformClick()
}

function Log_Reset{
    if($checkboxsure.Checked){
        $logbox.ResetText()
        $logbox.Text="Script started"
        $checkboxsure.Checked=0
    }
}

#GUI itself
function GUI{
    [void] [System.Reflection.Assembly]::LoadWithPartialName("System.Windows.Forms")
    [void] [System.Reflection.Assembly]::LoadWithPartialName("System.Drawing")
    
    # Set the size of your form
    $Form = New-Object System.Windows.Forms.Form
    $Form.Text = ”AD formular”
    $Form.Size=new-object System.Drawing.Size(700,555)
 
    # Set the font of the text to be used within the form
    $Font = New-Object System.Drawing.Font("Times New Roman",11)
    $Form.Font = $Font

    #check user
    $logonnamelabel = New-Object System.Windows.Forms.Label
    $logonnamelabel.Location = new-object System.Drawing.Size(20,2)
    $logonnamelabel.Size = new-object System.Drawing.Size(200,27)
    $logonnamelabel.Text = "check if user exists:"
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
    $tabControl.Size = new-object System.Drawing.Size(700,430)
    $tabControl.Location = new-object System.Drawing.Size(0,70)
    $form.Controls.Add($tabControl)

    $CreateUser = New-Object System.Windows.Forms.TabPage
    $CreateUser.UseVisualStyleBackColor = 1
    $CreateUser.Text = "Create User”
    $tabControl.Controls.Add($CreateUser)
    $addGroups = New-Object System.Windows.Forms.TabPage
    $addGroups.UseVisualStyleBackColor = 1
    $addGroups.Text = "add groups”
    $tabControl.Controls.Add($addGroups)
    $flag = New-Object System.Windows.Forms.TabPage
    $flag.UseVisualStyleBackColor = 1
    $flag.Text = "Flag”
    $tabControl.Controls.Add($flag)
    $delete = New-Object System.Windows.Forms.TabPage
    $delete.UseVisualStyleBackColor = 1
    $delete.Text = "Delete”
    $tabControl.Controls.Add($delete)
    $Log = New-Object System.Windows.Forms.TabPage
    $Log.UseVisualStyleBackColor = 1
    $Log.Text = "Log”
    $tabControl.Controls.Add($Log)

    #C$InitialFormWindowState = New-Object System.Windows.Forms.FormWindowState
#-------------------------------------------------------------------------------------------------------------------------------------
    #User Creation
    $listboxlabel = New-Object System.Windows.Forms.Label
    $listboxlabel.Location = new-object System.Drawing.Size(20,0)
    $listboxlabel.Size = new-object System.Drawing.Size(130,30)
    $listboxlabel.Text = "account type:"
    $CreateUser.Controls.Add($listboxlabel)
    $listBox = New-Object System.Windows.Forms.ListBox
    $listBox.Location = new-object System.Drawing.Size(160,0)
    $listBox.Size = new-object System.Drawing.Size(100,100)
    [string] $listBox.Items.Add('Internal')
    [string] $listBox.Items.Add('External')
    $CreateUser.Controls.Add($listBox)
    $listboxstatus = New-Object System.Windows.Forms.Label
    $listboxstatus.Location = new-object System.Drawing.Size(260,0)
    $listboxstatus.Size = new-object System.Drawing.Size(200,30)
    $CreateUser.Controls.Add($listboxstatus)
    $listBox.add_SelectedIndexChanged({
        if($listBox.SelectedItem.ToString() -eq 'Internal'){
            $expbox.Enabled=0
        }else{
            $expbox.Enabled=1
        }      
        $listboxstatus.Text = $listBox.SelectedItem+" is selected"
    })
    $listBox.SelectedItem=$listBox.Items[0]


    $familynamelabel = New-Object System.Windows.Forms.Label
    $familynamelabel.Location = new-object System.Drawing.Size(20,130)
    $familynamelabel.Size = new-object System.Drawing.Size(140,30)
    $familynamelabel.Text = "Family Name:"
    $CreateUser.Controls.Add($familynamelabel)
    $familynamebox = new-object System.Windows.Forms.Textbox
    $familynamebox.Location = new-object System.Drawing.Size(160,130)
    $familynamebox.Size = new-object System.Drawing.Size(100,40)
    $CreateUser.Controls.Add($familynamebox)  
    $familynamestatus = New-Object System.Windows.Forms.Label
    $familynamestatus.Location = new-object System.Drawing.Size(260,130)
    $familynamestatus.Size = new-object System.Drawing.Size(320,30)
    $CreateUser.Controls.Add($familynamestatus)

    $givennamelabel = New-Object System.Windows.Forms.Label
    $givennamelabel.Location = new-object System.Drawing.Size(20,160)
    $givennamelabel.Size = new-object System.Drawing.Size(140,30)
    $givennamelabel.Text = "Given Name:"
    $CreateUser.Controls.Add($givennamelabel)
    $givennamebox = new-object System.Windows.Forms.Textbox
    $givennamebox.Location = new-object System.Drawing.Size(160,160)
    $givennamebox.Size = new-object System.Drawing.Size(100,40)
    $CreateUser.Controls.Add($givennamebox)  
    $givennamestatus = New-Object System.Windows.Forms.Label
    $givennamestatus.Location = new-object System.Drawing.Size(260,160)
    $givennamestatus.Size = new-object System.Drawing.Size(320,30)
    $CreateUser.Controls.Add($givennamestatus)
    
    $loginlabel = New-Object System.Windows.Forms.Label
    $loginlabel.Location = new-object System.Drawing.Size(20,190)
    $loginlabel.Size = new-object System.Drawing.Size(140,30)
    $loginlabel.Text = "Login:"
    $CreateUser.Controls.Add($loginlabel)
    $loginbox = new-object System.Windows.Forms.Textbox
    $loginbox.Location = new-object System.Drawing.Size(160,190)
    $loginbox.Size = new-object System.Drawing.Size(100,40)
    $CreateUser.Controls.Add($loginbox)  
    $loginstatus = New-Object System.Windows.Forms.Label
    $loginstatus.Location = new-object System.Drawing.Size(260,190)
    $loginstatus.Size = new-object System.Drawing.Size(320,30)
    $CreateUser.Controls.Add($loginstatus)

    $ameilabel = New-Object System.Windows.Forms.Label
    $ameilabel.Location = new-object System.Drawing.Size(20,220)
    $ameilabel.Size = new-object System.Drawing.Size(140,30)
    $ameilabel.Text = "AMEI:"
    $CreateUser.Controls.Add($ameilabel)
    $ameibox = new-object System.Windows.Forms.Textbox
    $ameibox.Location = new-object System.Drawing.Size(160,220)
    $ameibox.Size = new-object System.Drawing.Size(100,40)
    $CreateUser.Controls.Add($ameibox)  
    $ameistatus = New-Object System.Windows.Forms.Label
    $ameistatus.Location = new-object System.Drawing.Size(260,220)
    $ameistatus.Size = new-object System.Drawing.Size(320,30)
    $CreateUser.Controls.Add($ameistatus)

    $explabel = New-Object System.Windows.Forms.Label
    $explabel.Location = new-object System.Drawing.Size(20,250)
    $explabel.Size = new-object System.Drawing.Size(140,30)
    $explabel.Text = "Exp. Date:"
    $CreateUser.Controls.Add($explabel)
    $expbox = new-object System.Windows.Forms.Textbox
    $expbox.Location = new-object System.Drawing.Size(160,250)
    $expbox.Size = new-object System.Drawing.Size(100,40)
    $CreateUser.Controls.Add($expbox)  
    $expstatus = New-Object System.Windows.Forms.Label
    $expstatus.Location = new-object System.Drawing.Size(260,250)
    $expstatus.Size = new-object System.Drawing.Size(320,30)
    $expstatus.Text="Use dd.MM.yyyy from Ticket"
    $CreateUser.Controls.Add($expstatus)

    $referenceuserlabel = New-Object System.Windows.Forms.Label
    $referenceuserlabel.Location = new-object System.Drawing.Size(20,280)
    $referenceuserlabel.Size = new-object System.Drawing.Size(140,30)
    $referenceuserlabel.Text = "Ref. User"
    $CreateUser.Controls.Add($referenceuserlabel)
    $referenceuserbox = new-object System.Windows.Forms.Textbox
    $referenceuserbox.Location = new-object System.Drawing.Size(160,280)
    $referenceuserbox.Size = new-object System.Drawing.Size(100,40)
    $CreateUser.Controls.Add($referenceuserbox)  
    $referenceuserstatus = New-Object System.Windows.Forms.Label
    $referenceuserstatus.Location = new-object System.Drawing.Size(260,280)
    $referenceuserstatus.Size = new-object System.Drawing.Size(320,30)
    $CreateUser.Controls.Add($referenceuserstatus)
      
    $checkButton = new-object System.Windows.Forms.Button
    $checkButton.Location = new-object System.Drawing.Size(20,310)
    $checkButton.Size = new-object System.Drawing.Size(120,40)
    $checkButton.Text = "Check Data"
    $checkButton.Enabled=0
    $checkButton.Add_Click({Validate_Data})
    $CreateUser.Controls.Add($checkButton)

    $startButton = new-object System.Windows.Forms.Button
    $startButton.Location = new-object System.Drawing.Size(140,310)
    $startButton.Size = new-object System.Drawing.Size(100,40)
    $startButton.Text = "START"
    $startButton.Enabled=0
    $startButton.Add_Click({Create_User})
    $CreateUser.Controls.Add($startButton)
   
    $credentials = new-object System.Windows.Forms.Textbox
    $credentials.Location = new-object System.Drawing.Size(335,310)
    $credentials.Size = new-object System.Drawing.Size(240,40)
    $credentials.Text = "Credentials"
    $credentials.Enabled=0
    $credentials.ReadOnly=1
    $CreateUser.Controls.Add($credentials)
    
#-------------------------------------------------------------------------------------------------------------------------------------    
    #add Groups
    $findgrouplabel = New-Object System.Windows.Forms.Label
    $findgrouplabel.Location = new-object System.Drawing.Size(25, 0)
    $findgrouplabel.Size = new-object System.Drawing.Size(230, 27)
    $findgrouplabel.Text = "enter group name"
    $addGroups.Controls.Add($findgrouplabel)
    $findGroups = new-object System.Windows.Forms.Button
    $findGroups.Location = new-object System.Drawing.Size(260, 30)
    $findGroups.Size = new-object System.Drawing.Size(100, 40)
    $findGroups.Text = "find group"
    $findGroups.Enabled = 0
    $findGroups.Add_Click({ Find_Group })
    $addGroups.Controls.Add($findGroups)
    $groupname = New-Object System.Windows.Forms.TextBox
    $groupname.Location = new-object System.Drawing.Size(25, 30)
    $groupname.Size = new-object System.Drawing.Size(200, 30)
    $addGroups.Controls.Add($groupname)
    $groupfoundlabel = New-Object System.Windows.Forms.Label
    $groupfoundlabel.Location = new-object System.Drawing.Size(20, 60)
    $groupfoundlabel.Size = new-object System.Drawing.Size(205, 27)
    $addGroups.Controls.Add($groupfoundlabel)
    $foundGroups = New-Object System.Windows.Forms.ListBox
    $foundGroups.Location = new-object System.Drawing.Size(20, 90)
    $foundGroups.Size = new-object System.Drawing.Size(500, 150)
    $foundGroups.HorizontalScrollbar = 1
    $foundGroups.SelectionMode = 2
    $addGroups.Controls.Add($foundGroups)
    $labeladd = New-Object System.Windows.Forms.Label
    $labeladd.Location = new-object System.Drawing.Size(520, 150)
    $labeladd.Size = new-object System.Drawing.Size(80, 27)
    $labeladd.Text="Add"
    $addGroups.Controls.Add($labeladd)

    $foundGroups2 = New-Object System.Windows.Forms.ListBox
    $foundGroups2.Location = new-object System.Drawing.Size(20, 230)
    $foundGroups2.Size = new-object System.Drawing.Size(500, 150)
    $foundGroups2.HorizontalScrollbar = 1
    $foundGroups2.SelectionMode = 2 #was 0
    $addGroups.Controls.Add($foundGroups2)
    $labelremove = New-Object System.Windows.Forms.Label
    $labelremove.Location = new-object System.Drawing.Size(520, 290)
    $labelremove.Size = new-object System.Drawing.Size(90, 27)
    $labelremove.text="Remove"
    $addGroups.Controls.Add($labelremove)

    $findgrouplabel2 = New-Object System.Windows.Forms.Label
    $findgrouplabel2.Location = new-object System.Drawing.Size(420, 0)
    $findgrouplabel2.Size = new-object System.Drawing.Size(200, 27)
    $findgrouplabel2.Text = "enter group name"
    $addGroups.Controls.Add($findgrouplabel2)
    $findGroup = new-object System.Windows.Forms.Button
    $findGroup.Location = new-object System.Drawing.Size(480, 60)
    $findGroup.Size = new-object System.Drawing.Size(110, 30)
    $findGroup.Text = "add group"
    $findGroup.Enabled = 0
    $findGroup.Add_Click({ Add_Group })
    $addGroups.Controls.Add($findGroup)
    $groupname2 = New-Object System.Windows.Forms.TextBox
    $groupname2.Location = new-object System.Drawing.Size(420, 30)
    $groupname2.Size = new-object System.Drawing.Size(240, 30)
    $addGroups.Controls.Add($groupname2)

    $addGroups2 = new-object System.Windows.Forms.Button
    $addGroups2.Location = new-object System.Drawing.Size(130, 370)
    $addGroups2.Size = new-object System.Drawing.Size(140, 30)
    $addGroups2.Text = "add group\s"
    $addGroups2.Enabled = 0
    $addGroups2.Add_Click({ Add_Groups })
    $addGroups.Controls.Add($addGroups2)

    $selectGroups = new-object System.Windows.Forms.Button
    $selectGroups.Location = new-object System.Drawing.Size(20, 370)
    $selectGroups.Size = new-object System.Drawing.Size(100, 30)
    $selectGroups.Text = "select all"
    $selectGroups.Enabled = 0
    $selectGroups.Add_Click({ Select_Groups })
    $addGroups.Controls.Add($selectGroups)

    $removeGroups = new-object System.Windows.Forms.Button
    $removeGroups.Location = new-object System.Drawing.Size(320, 370)
    $removeGroups.Size = new-object System.Drawing.Size(150, 30)
    $removeGroups.Text = "remove group\s"
    $removeGroups.Enabled = 0
    $removeGroups.Add_Click({ Remove_Groups })
    $addGroups.Controls.Add($removeGroups)

    $selectGroups2 = new-object System.Windows.Forms.Button
    $selectGroups2.Location = new-object System.Drawing.Size(480, 370)
    $selectGroups2.Size = new-object System.Drawing.Size(100, 30)
    $selectGroups2.Text = "select all"
    $selectGroups2.Enabled = 0
    $selectGroups2.Add_Click({ Select_Groups2 })
    $addGroups.Controls.Add($selectGroups2)

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
#flag user
    $flagBox = New-Object System.Windows.Forms.ListBox
    $flagBox.Location = new-object System.Drawing.Size(100,50)
    $flagBox.Size = new-object System.Drawing.Size(100,250)
    [string] $flagBox.Items.Add('B1')
    [string] $flagBox.Items.Add('B2')
    [string] $flagBox.Items.Add('B3')
    $flag.Controls.Add($flagBox)
    $flagBoxstatus = New-Object System.Windows.Forms.Label
    $flagBoxstatus.Location = new-object System.Drawing.Size(210,50)
    $flagBoxstatus.Size = new-object System.Drawing.Size(200,30)
    $flag.Controls.Add($flagBoxstatus)
    $flagBox.add_SelectedIndexChanged({      
        $flagBoxstatus.Text = $flagBox.SelectedItem+" is selected"
    })
    $flagBox.SelectedItem=$flagBox.Items[0]
    $flagbutton= new-object System.Windows.Forms.Button
    $flagbutton.Location = new-object System.Drawing.Size(100,310)
    $flagbutton.Size = new-object System.Drawing.Size(130,40)
    $flagbutton.Text = "flag user"
    $flagbutton.Enabled=0
    $flagbutton.Add_Click({Flag_User})
    $flag.Controls.Add($flagbutton)
    $flagstatus = New-Object System.Windows.Forms.Label
    $flagstatus.Location = new-object System.Drawing.Size(100,350)
    $flagstatus.Size = new-object System.Drawing.Size(300,30)
    $flag.Controls.Add($flagstatus)

    $ameilabel2 = New-Object System.Windows.Forms.Label
    $ameilabel2.Location = new-object System.Drawing.Size(220,160)
    $ameilabel2.Size = new-object System.Drawing.Size(140,30)
    $ameilabel2.Text = "AMEI:"
    $flag.Controls.Add($ameilabel2)
    $ameibox2 = new-object System.Windows.Forms.Textbox
    $ameibox2.Location = new-object System.Drawing.Size(220,190)
    $ameibox2.Size = new-object System.Drawing.Size(100,40)
    $ameibox2.Enabled = 0
    $flag.Controls.Add($ameibox2)  
    $ameistatus2 = New-Object System.Windows.Forms.Label
    $ameistatus2.Location = new-object System.Drawing.Size(220,230)
    $ameistatus2.Size = new-object System.Drawing.Size(320,30)
    $flag.Controls.Add($ameistatus2)

#-------------------------------------------------------------------------------------------------------------------------------------
#log
    $logbutton= new-object System.Windows.Forms.Button
    $logbutton.Location = new-object System.Drawing.Size(50,10)
    $logbutton.Size = new-object System.Drawing.Size(100,30)
    $logbutton.Text = "ResetText"
    $logbutton.Add_Click({Log_Reset})
    $log.Controls.Add($logbutton)
    $checkboxsure = New-Object System.Windows.Forms.CheckBox
    $checkboxsure.Location = new-object System.Drawing.Size(150,10)
    $checkboxsure.Size = new-object System.Drawing.Size(80,30)
    $checkboxsure.Text = "sure?"
    $log.Controls.Add($checkboxsure)
    $logbox = New-Object System.Windows.Forms.TextBox
    $logbox.ReadOnly=1
    $logbox.Multiline=1
    $logbox.ScrollBars="Vertical"
    $logbox.Text="Script started"
    $logbox.Location = new-object System.Drawing.Size(50,40)
    $logbox.Size = new-object System.Drawing.Size(600,350)
    $log.Controls.Add($logbox)
#-------------------------------------------------------------------------------------------------------------------------------------        
    # Activate the form
    $Form.Add_Shown({$Form.Activate()})
    [void] $Form.ShowDialog() 
}
 
#Call the function
GUI