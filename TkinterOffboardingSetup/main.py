from tkinter import *
from tkinter import ttk
from ttkthemes import ThemedTk
from datetime import datetime
from tkcalendar import Calendar
import subprocess
import threading
from PIL import Image, ImageTk, ImageSequence
import time
import os

#<------------------------------------- Button Functions ---------------------------------------->#

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
        $session = New-PSSession -ComputerName 'ServerName' -Credential $credentials -ErrorAction Stop
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
        stop_animation_validate()
        valid_loading_label.config(image=checkmark_img)
        valid_loading_label.image = checkmark_img
        validate_label.config(text="Authentication successful", foreground="green")
        validate_button.config(state="disabled")
        domain_username_entry.config(state="disabled")
        password_entry.config(state="disabled")
    else:
        stop_animation_validate()
        valid_loading_label.config(image=wrong_img)
        valid_loading_label.image = wrong_img
        validate_label.config(text="Failed to authenticate please try again", foreground="red")
        validate_button.config(state="enabled")  


def submit():
    domain_username = domain_username_entry.get()
    password = password_entry.get()
    if not domain_username or not password:
        stop_animation_submit()
        submit_loading_label.config(image=notice_img)
        submit_loading_label.image = notice_img
        submit_label.config(text="No Credentials. Please Authenticate First", foreground="red")
        return
    
    departedUser = offboard_user_entry.get()
    if not departedUser:
        stop_animation_submit()
        submit_loading_label.config(image=notice_img)
        submit_loading_label.image = notice_img
        submit_label.config(text="No username provided", foreground="red")
        return
    
    if checkbox_var.get() == 0:
        selected_date = calendar_date.selection_get()
        selected_time = time_combobox.get()

        selected_datetime_str = f"{selected_date.strftime('%m-%d-%Y')} {selected_time}"
        selected_datetime = datetime.strptime(selected_datetime_str, "%m-%d-%Y %I:%M %p")
        formatted_selected_datetime = selected_datetime.strftime("%#I:%M%p on %m/%d/%Y")

        current_datetime = datetime.now()
        time_difference = (selected_datetime - current_datetime).total_seconds()
        if time_difference <= 0:
            submit_loading_label.config(text="")
            stop_animation_submit()
            time_label_text.config(text="Scheduled time should be in the future.", foreground="red")
            return
    
        time_label_text.config(text="")

        powershell_command_two = f"""
        $username = '{domain_username}'
        $passwordChars = '{password}'.ToCharArray()
        $securePwd = New-Object -TypeName System.Security.SecureString
        $passwordChars | ForEach-Object {{ $securePwd.AppendChar($_) }}
        $credentials = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $username, $securePwd

        $selected_datetime = '{formatted_selected_datetime}'
        $departedUser = '{departedUser}'
        Invoke-Command -ComputerName "ServerName" -Credential $credentials -ScriptBlock {{
            param (
                $departedUser,
                $selected_datetime
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
            Write-Output "Are you sure you want to terminate $account_name at $selected_datetime ?"
        }} -ArgumentList $departedUser, $selected_datetime
        """
    else:
        time_label_text.config(text="")

        powershell_command_two = f"""
        $username = '{domain_username}'
        $passwordChars = '{password}'.ToCharArray()
        $securePwd = New-Object -TypeName System.Security.SecureString
        $passwordChars | ForEach-Object {{ $securePwd.AppendChar($_) }}
        $credentials = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $username, $securePwd

        $departedUser = '{departedUser}'
        Invoke-Command -ComputerName "ServerName" -Credential $credentials -ScriptBlock {{
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
        stop_animation_submit()
        submit_label.config(text="") 
        submit_loading_label.config(image=notice_img)
        submit_loading_label.image = notice_img
        submit_label.config(text=output, foreground="red") 
    elif "does not exist" in output:
        submit_label.config(text="") 
        stop_animation_submit()
        submit_loading_label.config(image=wrong_img)
        submit_loading_label.image = wrong_img
        submit_label.config(text=output, foreground="red")
    else:
        submit_label.config(text="") 
        submit_loading_label.config(text="")
        stop_animation_submit()
        global message
        message = Toplevel(theme)
        message.title("TERMINATION VERIFICATION")
        message.iconbitmap(".\photos\DOI.ico")
        
        l1=Label(message, image="::tk::icons::question")
        l1.grid(row=0, column=0, pady=(3, 0), padx=(3, 8), sticky="e")
        l2=Label(message,text=output, font=("Arial", 13, "bold"))
        l2.grid(row=0, column=1, columnspan=2, pady=(7, 10), padx=(3, 8), sticky="w")

        b1=Button(message, text="Yes", command=start_powershell_departed, width=10)
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

    $username = '{departedUser}'
    Invoke-Command -ComputerName "ServerName" -Credential $credentials -ScriptBlock {{
        param (
            $username,
            $login,
            $credentials
        )

        $login_name = Get-ADUser -Identity $login 
        $emailfrom = $login_name.UserPrincipalName

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
        $Path1 = "\\ServerName\\home_archive\\$Folder_Name"
        New-Item -Path $Path1 -ItemType Directory 
        $Path2 = "\\ServerName\\profile_archive\\$Folder_Name"
        New-Item -Path $Path2 -ItemType Directory 

        $Source_Home_Folder = "\\ServerName\\doi_share\\home_folder\\$Folder_Name"
        $Destination_Home_Folder = "\\ServerName\\HOME_ARCHIVE\\$Folder_name"

        $Source_Profile_folder = "\\ServerName\\USER_FOLDER_REDIRECTION\\$Folder_name"
        $Destination_Profile_folder = "\\ServerName\\PROFILE_ARCHIVE\\$Folder_name"

        #Robocopy Execute
        robocopy $Source_Home_Folder $Destination_Home_Folder /COPYALL /Z /E /W:1 /R:2 /tee /Move 
        robocopy $Source_Profile_folder $Destination_Profile_folder /COPYALL /Z /E /W:1 /R:2 /tee /Move 

        #Sends Email with user's memberships
        $EmailTo = "desktoptechs@domain.com", "SecurityAlert@domain.com"
        $fullname = $username_details.Name
        Send-MailMessage -From $emailfrom -To $EmailTo -Subject "Departed User $fullname" -body "The Departed account $fullname is now completed. Their home and profile folders have been moved to the Archived Server. Here is a list of Group Memberships he/she was assigned to: `n$assignedgroups" -SmtpServer 'smtp.doi.nycnet' -Port '25'

    }} -ArgumentList $username, $login, $credentials
    """
    powershell = subprocess.Popen(["C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", powershell_command_three], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    output, error = powershell.communicate()
    output = output.decode().strip()
    error = error.decode().strip()
    
    stop_animation_submit()
    submit_loading_label.config(image=checkmark_img)
    complete = Toplevel(theme)
    complete.title("TERMINATION COMPLETE!")
    complete.iconbitmap(".\photos\DOI.ico")
    
    l1=Label(complete, image="::tk::icons::question")
    l1.grid(row=0, column=0, pady=(3, 0), padx=(3, 8), sticky="e")
    l2=Label(complete, text="Completed. Do you want to generate a report?", font=("Arial", 12, "bold"))
    l2.grid(row=0, column=1, columnspan=2, pady=(7, 10), padx=(3, 8), sticky="w")

    b1=Button(complete, text="Yes", command=complete.destroy, width=10)
    b1.grid(row=1, column=1, padx=(2, 35), pady=(0, 10))
    b2=Button(complete, text="No", command=complete.destroy, width=10)
    b2.grid(row=1, column=2, padx=(2, 35), pady=(0, 10))

    complete.update_idletasks()
    x = theme.winfo_x() + (theme.winfo_width() - complete.winfo_reqwidth()) // 2
    y = theme.winfo_y() + theme.winfo_height()
    complete.geometry(f"+{x}+{y}")

#<------------------------------------- Threading Functions ---------------------------------------------->#


def start_powershell_departed():
    if checkbox_var.get() == 1:
        message.destroy()
        start_animation_submit(submit_loading_label)
        threading.Thread(target=departed).start()
    else:
        selected_date = calendar_date.selection_get()
        selected_time = time_combobox.get()
        selected_datetime_str = f"{selected_date.strftime('%m-%d-%Y')} {selected_time}"
        selected_datetime = datetime.strptime(selected_datetime_str, "%m-%d-%Y %I:%M %p")
        formatted_time = selected_datetime.strftime("%#I:%M%p")
        time_difference = (selected_datetime - datetime.now()).total_seconds()
        message.destroy()
        start_animation_submit(submit_loading_label)
        offboard_user_entry.config(state="disabled")
        time_combobox["state"] = "disabled"
        calendar_date["state"] = "disabled"
        checkbox["state"] = "disabled"
        current_date_time = datetime.now()
        if selected_date.strftime('%m-%d-%Y') == current_date_time.strftime('%m-%d-%Y'):
            submit_label.config(text=f"Termination will begin at {formatted_time} Today.", foreground="blue")
        else:
            submit_label.config(text=f"Termination will begin at {formatted_time} on {selected_date.strftime('%m-%d-%Y')}.", foreground="blue")
        threading.Timer(time_difference, departed).start()
        

def start_powershell_validate():
    start_animation_validate(valid_loading_label)
    valid_loading_label.config(image="")
    validate_button.config(state="disabled")
    validate_label.config(text="")
    thread = threading.Thread(target=validate)
    thread.start()
    
def start_powershell_submit():
    start_animation_submit(submit_loading_label)
    submit_loading_label.config(image="")
    submit_label.config(text="")
    thread = threading.Thread(target=submit)
    thread.start()

def on_closing():
    theme.destroy()
    os._exit(0)
        
#<------------------------------------- Checkbox Function  ---------------------------------------------->#

def toggle_combobox_state():
    if checkbox_var.get() == 1: 
        time_combobox["state"] = "disabled"
        calendar_date["state"] = "disabled"
    else:
        time_combobox["state"] = "normal"
        calendar_date["state"] = "normal"

#<------------------------------------- loading animation ---------------------------------------------->#

def start_animation_validate(valid_loading_label):
    img = Image.open(".\photos\loading.gif")
    frames = [ImageTk.PhotoImage(img_frame) for img_frame in ImageSequence.Iterator(img)]
    global animation_flag
    animation_flag = True
    return animate_validate(valid_loading_label, frames, 0)

def start_animation_submit(submit_loading_label):
    img = Image.open(".\photos\loading.gif")
    frames = [ImageTk.PhotoImage(img_frame) for img_frame in ImageSequence.Iterator(img)]
    global animation_flag
    animation_flag = True
    return animate_submit(submit_loading_label, frames, 0)

def animate_validate(valid_loading_label, frames, idx):
    if animation_flag: 
        valid_loading_label.configure(image=frames[idx])
        valid_loading_label.image = frames[idx]
        valid_loading_label.after(10, animate_validate, valid_loading_label, frames, (idx + 1) % len(frames))

def animate_submit(submit_loading_label, frames, idx):
    if animation_flag: 
        submit_loading_label.configure(image=frames[idx])
        submit_loading_label.image = frames[idx]
        submit_loading_label.after(10, animate_submit, submit_loading_label, frames, (idx + 1) % len(frames))

def stop_animation_validate():
    global animation_flag
    animation_flag = False 
    valid_loading_label.configure(image=None)
    valid_loading_label.image = None

def stop_animation_submit():
    global animation_flag
    animation_flag = False 
    submit_loading_label.configure(image=None)
    submit_loading_label.image = None

#<--------------------------------------- Time Function ---------------------------------------------->#

def get_current_time():
    current_time = time.localtime(time.time())
    current_hour = current_time.tm_hour
    current_minute = current_time.tm_min // 30 * 30  # Round to the nearest 30 minutes
    period = "AM" if current_hour < 12 else "PM"
    current_time_str = f"{current_hour % 12:02d}:{current_minute:02d} {period}"
    return current_time_str

#<--------------------------------------- UI Setup --------------------------------------------------->#

class Tktheme(ThemedTk):
    def __init__(self, theme="breeze"): 
        ThemedTk.__init__(self, fonts=True, themebg=True)
        self.set_theme(theme)
        self.label = ttk.Label(self)
        self.entry = ttk.Entry(self)
        self.button = ttk.Button(self)

theme = Tktheme()
theme.eval('tk::PlaceWindow . center')
theme.title("OFFBOARDING SETUP".center(25))
theme.config(padx=20, pady=20)
theme.iconbitmap(".\photos\DOI.ico")

canvas = Canvas(theme, width=70, height=70)
doi_logo = PhotoImage(file=".\photos\image.png")
canvas.create_image(35, 35, image=doi_logo)
canvas.grid(column=0, row=12)

canvas2 = Canvas(theme, width=300, height=60)
offboard_logo = PhotoImage(file=".\photos\offboard.png")
canvas2.create_image(150, 30, image=offboard_logo)
canvas2.grid(column=0, row=1, columnspan=2)

checkmark_img = PhotoImage(file=".\photos\check.png")
wrong_img = PhotoImage(file=".\photos\wrong.png")
notice_img = PhotoImage(file=".\photos\exclamation.png")

domain_username_label = ttk.Label(text="Domain\\Username:")
domain_username_entry = ttk.Entry(width=30)
domain_username_label.grid(column=0, row=4, sticky=E, pady=(10, 0))
domain_username_entry.grid(column=1, row=4, sticky=W, pady=(10, 0))
domain_username_entry.bind("<Return>", lambda event=None: start_powershell_validate())

password_label = ttk.Label(text="Password:")
password_entry = ttk.Entry(width=30, show="*")
password_label.grid(column=0, row=5, sticky=E)
password_entry.grid(column=1, row=5, sticky=W)
password_entry.bind("<Return>", lambda event=None: start_powershell_validate())

validate_button = ttk.Button(text="Validate", width=9, command=start_powershell_validate)
validate_button.grid(column=1, row=6, sticky=W)
validate_label = ttk.Label(text="")
validate_label.grid(column=0, row=7, columnspan=2)
valid_loading_label = ttk.Label(text="", font=("Arial", 12))
valid_loading_label.grid(column=1, row=6)

calendar_date = Calendar(theme, selectmode="day", year=datetime.now().year, month=datetime.now().month, day=datetime.now().day)
calendar_date.grid(column=1, row=8, pady=(5, 0))

time_label = ttk.Label(theme, text="Select Date & Time:")
time_label.grid(column=0, row=8, sticky=E)
time_values = [f"{h:02d}:{m:02d} {period}" for period in ["AM", "PM"] for h in range(1, 13) for m in range(0, 60, 30)]
time_combobox = ttk.Combobox(theme, values=time_values, state="normal")
time_combobox.set(get_current_time()) 
time_combobox.grid(row=9, column=1, pady=(2, 0), sticky=W)
time_label_text = ttk.Label(text="")
time_label_text.grid(column=1, row=10)

checkbox_var = IntVar()
checkbox = Checkbutton(theme, text="Now", font=("Arial", 12), variable=checkbox_var, command=toggle_combobox_state)
checkbox.grid(column=1, row=9, sticky=E)

offboard_user_label = ttk.Label(text="Employee's Username:")
offboard_user_entry = ttk.Entry(width=30)
offboard_user_label.grid(column=0, row=11, pady=(10, 0))
offboard_user_entry.grid(column=1, row=11, sticky=W, pady=(10, 0))
offboard_user_entry.bind("<Return>", lambda event=None: start_powershell_submit())

submit_button = ttk.Button(text="Submit", width=9, command=start_powershell_submit)
submit_button.grid(column=1, row=12, sticky=W, pady=(15, 0))

submit_label = ttk.Label(text="")
submit_label.grid(column=0, row=13, columnspan=2)

submit_loading_label = ttk.Label(text="", font=("Arial", 12))
submit_loading_label.grid(column=1, row=12, pady=(10, 0))

theme.protocol("WM_DELETE_WINDOW", on_closing)
toggle_combobox_state()
theme.mainloop()


