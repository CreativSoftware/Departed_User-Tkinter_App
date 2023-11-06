from tkinter import *
from tkinter import ttk
from ttkthemes import ThemedTk
import subprocess
import threading

#<------------------------------------- Functions ------------------------------------------------------------------------------------------------------------------------------------->#

def validate():
    domain_username = domain_username_entry.get()
    password = password_entry.get()
    
    powershell_command = f"""
    $username = '{domain_username}'
    $passwordChars = '{password}'.ToCharArray()
    $securePwd = New-Object -TypeName System.Security.SecureString
    $passwordChars | ForEach-Object {{ $securePwd.AppendChar($_) }}

    $credentials = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $username, $securePwd
    try {{
        $session = New-PSSession -ComputerName 'doidc02' -Credential $credentials -ErrorAction Stop
        Remove-PSSession $session
        Write-Output 'Authentication successful'
    }} catch {{
        Write-Output 'Failed to authenticate please try again'
    }}
    """
    powershell = subprocess.Popen(["C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", powershell_command], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    output, error = powershell.communicate()
    output = output.decode().strip()
    error = error.decode().strip()

    if "Authentication successful" in output:
        loading_label.config(text="✔️", foreground="green")
        validate_label.config(text="Authentication successful", foreground="green")
        validate_button.config(state="disabled")
        domain_username_entry.config(state="disabled")
        password_entry.config(state="disabled")
    else:
        loading_label.config(text="❌", foreground="red")
        validate_label.config(text="Failed to authenticate please try again", foreground="red")
        validate_button.config(state="enabled")
    
    

def submit():
    domain_username = domain_username_entry.get()
    password = password_entry.get()
    if not domain_username or not password:
        submit_loading_label.config(text="🛑", foreground="red")
        submit_label.config(text="No Credentials. Please Authenticate First", foreground="red")
        return
    
    departedUser = offboard_user_entry.get()
    if not departedUser:
        submit_loading_label.config(text="🛑", foreground="red")
        submit_label.config(text="No username provided", foreground="red")
        return   

    powershell_command_two = f"""
    $username = '{domain_username}'
    $passwordChars = '{password}'.ToCharArray()
    $securePwd = New-Object -TypeName System.Security.SecureString
    $passwordChars | ForEach-Object {{ $securePwd.AppendChar($_) }}
    $credentials = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $username, $securePwd

    $departedUser = '{departedUser}'
    Invoke-Command -ComputerName "doidc02" -Credential $credentials -ScriptBlock {{
        param (
            $departedUser
        )
        try {{
            $username_details = Get-ADUser -Identity $departedUser -ErrorAction Stop
            $name_string = $username_details.Name.ToString()
            if ($username_details.distinguishedName -eq "CN=$name_string,OU=Departed Users,DC=DOI,DC=NYCNET"){{
                Write-Output "The user $($name_string) is already departed"
                exit
            }}
        }} catch {{
            Write-Output "The username '$departedUser' does not exist"
            exit
        }}
        $account_name = $username_details.Name
        Write-Output "Are you sure you want to terminate $account_name ?"
    }} -ArgumentList $departedUser
    """
    powershell = subprocess.Popen(["C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", powershell_command_two], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    output, error = powershell.communicate()
    output = output.decode().strip()
    error = error.decode().strip()
    
    if "is already departed" in output:
        submit_label.config(text="") 
        submit_loading_label.config(text="❗️", foreground="dark orange")
        submit_label.config(text=output, foreground="red") 
    elif "does not exist" in output:
        submit_label.config(text="") 
        submit_loading_label.config(text="❌", foreground="red")
        submit_label.config(text=output, foreground="red")
    else:
        submit_label.config(text="") 
        submit_loading_label.config(text="")
        global message
        message = Toplevel(theme)
        message.title("TERMINATION VERIFICATION")
        message.iconbitmap(".\photos\DOI.ico")
        
        l1=Label(message, image="::tk::icons::question")
        l1.grid(row=0, column=0, pady=(3, 0), padx=(3, 8), sticky="e")
        l2=Label(message,text=output, font=3)
        l2.grid(row=0, column=1, columnspan=2, pady=(7, 10), padx=(3, 8), sticky="w")

        b1=Button(message, text="Yes", command=start_departed, width=10)
        b1.grid(row=1, column=1, padx=(2, 35), pady=(0, 10))
        b2=Button(message, text="No", command=message.destroy, width=10)
        b2.grid(row=1, column=2, padx=(2, 35), pady=(0, 10))

        message.update_idletasks()
        x = theme.winfo_x() + (theme.winfo_width() - message.winfo_reqwidth()) // 2
        y = theme.winfo_y() + theme.winfo_height()
        message.geometry(f"+{x}+{y}")



def departed():
    domain_username = domain_username_entry.get()
    password = password_entry.get()
    departedUser = offboard_user_entry.get()

    powershell_command_three = f"""
    $username = '{domain_username}'
    $passwordChars = '{password}'.ToCharArray()
    $securePwd = New-Object -TypeName System.Security.SecureString
    $passwordChars | ForEach-Object {{ $securePwd.AppendChar($_) }}
    $credentials = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $username, $securePwd

    $name = whoami.exe
    $name = $name.split("\\")
    $login = $name[1]

    $login_name = Get-ADUser -Identity $login 
    $emailfrom = $login_name.UserPrincipalName

    $username = '{departedUser}'
    Invoke-Command -ComputerName "doidc02" -Credential $credentials -ScriptBlock {{
        param (
            $username,
            $emailfrom,
            $credentials
        )
    
        $assignedgroups = Get-ADPrincipalGroupMembership -Identity $username | Select-Object Name | Out-String

        Disable-ADAccount -Identity $username -Credential $credentials

        Set-ADUser -Identity $username -Clear Manager -Credential $credentials
        $directreports = Get-ADUser -Identity $username -properties DirectReports | select-object -ExpandProperty DirectReports
        foreach($user in $directreports){{
            Set-ADUser -Identity $user -Clear Manager -Credential $credentials
        }}

        $membershipgroups = Get-ADPrincipalGroupMembership -Identity $username

        foreach ($membership in $membershipgroups){{
            if ($membership.distinguishedName -eq 'CN=Domain Users,OU=General SG,OU=Security Groups,OU=Groups,DC=DOI,DC=NYCNET')
            {{
            continue
            }}
            Remove-ADPrincipalGroupMembership -Identity $username -MemberOf $membership.distinguishedName -Credential $credentials -Confirm:$false
        }}

        $username_details = Get-ADUser -Identity $username
        Move-ADObject -Identity $username_details.distinguishedName -TargetPath 'OU=Departed Users,DC=DOI,DC=NYCNET' -Credential $credentials

        $Folder_Name = $username
        $Path1 = "\\doiarchive01\\home_archive\\$Folder_Name"
        New-Item -Path $Path1 -ItemType Directory 
        $Path2 = "\\doiarchive01\\profile_archive\\$Folder_Name"
        New-Item -Path $Path2 -ItemType Directory 

        $Source_Home_Folder = "\\doi.nycnet\\doi_share\\home_folder\\$Folder_Name"
        $Destination_Home_Folder = "\\DOIARCHIVE01\\HOME_ARCHIVE\\$Folder_name"

        $Source_Profile_folder = "\\DOIPROFILE01\\USER_FOLDER_REDIRECTION\\$Folder_name"
        $Destination_Profile_folder = "\\DOIARCHIVE01\\PROFILE_ARCHIVE\\$Folder_name"

        #Robocopy Execute
        robocopy $Source_Home_Folder $Destination_Home_Folder /COPYALL /Z /E /W:1 /R:2 /tee /Move 
        robocopy $Source_Profile_folder $Destination_Profile_folder /COPYALL /Z /E /W:1 /R:2 /tee /Move 

        #Sends Email with user's memberships
        $EmailTo = "eperry@doi.nyc.gov"
        $fullname = $username_details.Name
        Send-MailMessage -From $emailfrom -To $EmailTo -Subject "Departed User $fullname" -body "The Departed account $fullname is now completed. Their home and profile folders have been moved to the Archived Server. Here is a list of Group Memberships he/she was assigned to: `n$assignedgroups" -SmtpServer 'smtp.doi.nycnet' -Port '25'

    }} -ArgumentList $username, $emailfrom, $credentials
    """
    powershell = subprocess.Popen(["C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", powershell_command_three], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    output, error = powershell.communicate()
    output = output.decode().strip()
    error = error.decode().strip()
    
    submit_loading_label.config(text="✔️", foreground="green")
    complete = Toplevel(theme)
    complete.title("TERMINATION COMPLETE!")
    complete.iconbitmap(".\photos\DOI.ico")
    
    l1=Label(complete, image="::tk::icons::question")
    l1.grid(row=0, column=0, pady=(3, 0), padx=(3, 8), sticky="e")
    l2=Label(complete, text="Completed. Do you want to generate a report?", font=3)
    l2.grid(row=0, column=1, columnspan=2, pady=(7, 10), padx=(3, 8), sticky="w")

    b1=Button(complete, text="Yes", command=complete.destroy, width=10)
    b1.grid(row=1, column=1, padx=(2, 35), pady=(0, 10))
    b2=Button(complete, text="No", command=complete.destroy, width=10)
    b2.grid(row=1, column=2, padx=(2, 35), pady=(0, 10))

    complete.update_idletasks()
    x = theme.winfo_x() + (theme.winfo_width() - complete.winfo_reqwidth()) // 2
    y = theme.winfo_y() + theme.winfo_height()
    complete.geometry(f"+{x}+{y}")


def start_departed():
    message.destroy()
    submit_loading_label.config(text="⭕", foreground="deep sky blue")
    thread = threading.Thread(target=departed)
    thread.start()


def start_powershell():
    loading_label.config(text="⭕", foreground="deep sky blue")
    validate_button.config(state="disabled")
    thread = threading.Thread(target=validate)
    thread.start()
    

def start_powershell_submit():
    submit_loading_label.config(text="⭕", foreground="deep sky blue")
    thread = threading.Thread(target=submit)
    thread.start()


#<------------------------------------------------------------- UI Setup ------------------------------------------------------------------------------------------------------------------------------------------->#

class Tktheme(ThemedTk):
    def __init__(self, theme="arc"): 
        ThemedTk.__init__(self, fonts=True, themebg=True)
        self.set_theme(theme)
        self.label = ttk.Label(self)
        self.entry = ttk.Entry(self)
        self.button = ttk.Button(self)


theme = Tktheme()
theme.eval('tk::PlaceWindow . center')
theme.title("OFFBOARDING SETUP".center(25))
theme.config(padx=25, pady=25)
theme.iconbitmap(".\photos\DOI.ico")

pscommand = f"""
$name = whoami
$name = $name.split("\\")
$username = $name[1]

$username = Get-ADUser -Identity $username -Properties *
$full_name = $username.Name
$email = $username.UserPrincipalName

Write-Output $full_name.ToString() $email.ToString()
"""
powershell = subprocess.Popen(["C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", pscommand], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
output, error = powershell.communicate()
output = output.decode().strip()

canvas = Canvas(theme, width=70, height=70)
doi_logo = PhotoImage(file=".\photos\image.png")
canvas.create_image(35, 35, image=doi_logo)
canvas.grid(column=0, row=9)

technician_label = ttk.Label(text="Technician:", font=10)
technician_name_label = ttk.Label(text=output, font=10)
technician_label.grid(column=0, row=1)
technician_name_label.grid(column=1, row=1, sticky=W)

domain_username_label = ttk.Label(text="Domain\\Username:")
domain_username_entry = ttk.Entry(width=30)
domain_username_label.grid(column=0, row=4, pady=(20, 0))
domain_username_entry.grid(column=1, row=4, sticky=W, pady=(20, 0))

password_label = ttk.Label(text="Password:")
password_entry = ttk.Entry(width=30, show="*")
password_label.grid(column=0, row=5)
password_entry.grid(column=1, row=5, sticky=W)

validate_button = ttk.Button(text="Validate", width=9, command=start_powershell)
validate_button.grid(column=1, row=6, sticky=W)

offboard_user_label = ttk.Label(text="Employee's Username:")
offboard_user_entry = ttk.Entry(width=30)
offboard_user_label.grid(column=0, row=8, pady=(25, 0))
offboard_user_entry.grid(column=1, row=8, sticky=W, pady=(20, 0))

submit_button = ttk.Button(text="Submit", width=9, command=start_powershell_submit)
submit_button.grid(column=1, row=9, sticky=W, pady=(25, 0))

validate_label = ttk.Label(text="")
validate_label.grid(column=0, row=7, columnspan=2)

submit_label = ttk.Label(text="")
submit_label.grid(column=0, row=10, columnspan=2)

loading_label = ttk.Label(text="", font=("Arial", 12))
loading_label.grid(column=1, row=6)

submit_loading_label = ttk.Label(text="", font=("Arial", 12))
submit_loading_label.grid(column=1, row=9, pady=(25, 0))

theme.mainloop()


