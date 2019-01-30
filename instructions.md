# Implementing Microsoft Cloud App Security

## Self paced lab LAB - MCASHOL

## Introduction

This lab is designed to be used as a supplement to Instructor Led Training and has several sections that you will go through over the next hour. Please click the links below to first prepare your environment and then go through different tasks to explore Microsoft Cloud App Security capabilities.  

### [Lab Environment Configuration](#lab-environment-configuration)

### [Lab: Microsoft Cloud App Security](#microsoft-cloud-app-security)

> [!ALERT] If you need to interrupt your lab, please ensure that you SAVE the session rather than END the lab.  If you end the lab, all configuration will be reset to initial state

===

# Tips and Tricks
[:arrow_left: Home](#introduction)

There are a few extras throughout this lab that are designed to make your lab experience a smooth and simple process.  Below are some icons you should watch out for that will save you time during each task.

## Interactive Elements

- Each task contains a series of steps required for successful completion of the lab.  To track your progress throughout the lab, check the Box to the left of the numbered series.  

	!IMAGE[6mfi1ekm.jpg](\Media\6mfi1ekm.jpg)

- When you see an instruction for switching computers, click on the **blue link** in the text to have that VM loaded automatically.

	!IMAGE[12i85vgl.jpg](\Media\12i85vgl.jpg)

- Throughout the lab, you will see text with a letter **T** in a square to the left.  This indicates that you can **click on the text** and it will **type it for you** in the VM.  **This will save you lots of time**.

	!IMAGE[cnyu1tdi.jpg](\Media\cnyu1tdi.jpg)

- The last interactive element you will see throughout the lab is the **Open Screenshot** text below many steps.  To reduce clutter, most screenshots have been configured to launch in a popup window.  The only ones left visible are ones that could cause issues if they are missed or if there are multiple elements that are easier to understand with visual representation.

	!IMAGE[n4cqn070.jpg](\Media\n4cqn070.jpg)

## Additional Information

There are also Knowledge Items, Notes, and Hints throughout the lab.

- Knowledge Items are used to provide additional information about a topic related to the task or step.  These are often collapsed to reduce the amount of space they use, but it is recommended that you review these items if you want more information on the subject.

	!IMAGE[8g9nif1j.jpg](\Media\8g9nif1j.jpg)

- Notes are steps that do not require action or modification of any elements.  This includes general observations and reviewing the results of previous steps.

	!IMAGE[kxrbzsr2.jpg](\Media\kxrbzsr2.jpg)

- Hints are recommendations or observations that help with the completion of a step.

	!IMAGE[w11x99oo.jpg](\Media\w11x99oo.jpg)

===

# Lab Environment Configuration
[:arrow_left: Home](#introduction)

There are a few prerequisites that need to be set up to complete all the sections in this lab.  This Exercise will walk you through the items below.

- [Azure AD User Configuration](#azure-ad-user-configuration)
- [MCAS Environment Proparation](#mcas-environment-preparation)
  
===

# Azure AD User Configuration
[:arrow_left: Home](#lab-environment-configuration)

In this task, we will create new Azure AD users and assign licenses via PowerShell.  In a procduction evironment this would be done using Azure AD Connect or a similar tool to maintain a single source of authority, but for lab purposes we are doing it via script to reduce setup time.

1. [] Log into @lab.VirtualMachine(Scanner01).SelectLink using the password +++@lab.VirtualMachine(Client01).Password+++
2. [] On the desktop, **right-click** on **AADConfig.ps1** and click **Run with PowerShell**.

	!IMAGE[AADConfig](\Media\AADConfig.png)

	> [!NOTE] If prompted to change the execution policy, type **y** and **Enter**.

1. [] When prompted for the **Tenant name**, **click in the text box** and enter ```@lab.CloudCredential(134).TenantName```.
1. [] When prompted, provide the credentials below:

	```@lab.CloudCredential(134).Username```

	```@lab.CloudCredential(134).Password``` 
   
	> [!KNOWLEDGE] We are running the PowerShell code below to create the accounts and groups in AAD and assign licenses for EMS E5 and Office E5. This script is also available at [https://aka.ms/labscripts](https://aka.ms/labscripts) as AADConfig.ps1.
    > 
    > #### Azure AD User and Group Configuration
    > $tenantfqdn = "@lab.CloudCredential(134).TenantName"
    > $tenant = $tenantfqdn.Split('.')[0]
	> 
    > #### Build Licensing SKUs
    > $office = $tenant+":ENTERPRISEPREMIUM"
    > $ems = $tenant+":EMSPREMIUM"
	> 
    > #### Connect to MSOLService for licensing Operations
    > Connect-MSOLService -Credential $cred
	> 
    > #### Remove existing licenses to ensure enough licenses exist for our users
    > $LicensedUsers = Get-MsolUser -All  | where {$_.isLicensed -eq $true}
    > $LicensedUsers | foreach {Set-MsolUserLicense -UserPrincipalName $_.UserPrincipalName -RemoveLicenses $office, $ems}
	> 
    > #### Connect to Azure AD using stored credentials to create users
    > Connect-AzureAD -Credential $cred
	> 
    > #### Import Users from local csv file
    > $users = Import-csv C:\users.csv
	> 
    > foreach ($user in $users){
    > 	
    > #### Store UPN created from csv and tenant
    > $upn = $user.username+"@"+$tenantfqdn
	> 
    > #### Create password profile preventing automatic password change and storing password from csv
    > $PasswordProfile = New-Object -TypeName Microsoft.Open.AzureAD.Model.PasswordProfile 
    > $PasswordProfile.ForceChangePasswordNextLogin = $false 
    > $PasswordProfile.Password = $user.password
	> 
    > #### Create new Azure AD user
    > New-AzureADUser -AccountEnabled $True -DisplayName $user.displayname -PasswordProfile $PasswordProfile -MailNickName $user.username -UserPrincipalName $upn
    > }
    > 
    > #### MCAS user and group creation
	> $upn = "mcasAdminUS@"+$tenantfqdn
	> New-AzureADUser -AccountEnabled $True -DisplayName "MCAS US admin" -PasswordProfile $PasswordProfile -MailNickName "mcasadminUS" -UserPrincipalName $upn
    > New-AzureADGroup -DisplayName "US employees" -MailNickName "USemployees" -SecurityEnabled $true -MailEnabled $false
    > $groupId = Get-AzureADGroup -SearchString "usemployees"
    > $userId = Get-AzureADUser -SearchString "mcasadminus"
    > Add-AzureADGroupMember -RefObjectId $userId.ObjectId -ObjectId $groupId.ObjectId
	> 
	> Start-Sleep -s 10
	> foreach ($user in $users){
	> 
    > #### Store UPN created from csv and tenant
    > $upn = $user.username+"@"+$tenantfqdn
	> 
    > #### Assign Office and EMS licenses to users
    > Set-MsolUser -UserPrincipalName $upn -UsageLocation US
    > Set-MsolUserLicense -UserPrincipalName $upn -AddLicenses $office, $ems
    > }
	> 
    > #### Assign Office and EMS licenses to Admin user
    > $upn = "admin@"+$tenantfqdn
    > Set-MsolUser -UserPrincipalName $upn -UsageLocation US
    > Set-MsolUserLicense -UserPrincipalName $upn -AddLicenses $office, $ems

	> [!NOTE] The PowerShell window will automatically close once users have been created and licenses have been assigned.

===

# MCAS Environment Preparation
[:arrow_left: Home](#lab-environment-configuration)

To be able to complete the different parts of the Cloud App Security labs, the following configuration steps are required.

* [Enabling Office 365 Auditing](#enabling-office-365-auditing)
* [Enabling File Monitoring](#enabling-file-monitoring)
* [Create a Developer Box Account](#create-a-developer-box-account)
* [Connect Office 365 and Box to Cloud App Security](#connect-office-365-and-box-to-cloud-app-security)
* [Enabling Azure Information Protection integration](#enabling-azure-information-protection-integration)

---

## Enabling Office 365 Auditing
[:arrow_up: Top](#mcas-environment-preparation)

Most Cloud App Security treat detections capabilities rely on auditing being enabled in your environment. By default, auditing is not enabled in Office 365 and must then be turned on using the **Security & Compliance** admin console or PowerShell.

> [!ALERT] As this operation can take up to 24h, your instructor will provide you access to another environment to review the alerts for the threat detection lab.

1. [] Switch to @lab.VirtualMachine(Client01).SelectLink and log in with the password +++@lab.VirtualMachine(Client01).Password+++.
2. [] Open a new InPrivate tab and navigate to ```https://protection.office.com```.	
	
	> [!KNOWLEDGE] If needed, log in using the credentials below:
	>
	>```@lab.CloudCredential(134).Username```
	>
	>```@lab.CloudCredential(134).Password```

4. [] In the **Security & Compliance Center**, Expand **Search & investigation** and click on **Audit log search**.
   
	^IMAGE[Audit log](\Media\conf-auditlog.png "Audit log")

5. [] You can see here that auditing is not enabled. Click on the **Turn on auditing** button to enable it and click **yes** at the prompt.

    ^IMAGE[Turn on auditing](\Media\conf-enableauditing.png "Turn on on auditing")

    ^IMAGE[Auditing enabled](\Media\conf-auditenabled.png "Auditing enabled")

    

### Exchange Auditing Configuration
[:arrow_up: Top](#mcas-environment-preparation)

In addition to enabling auditing in Office 365, some applications like Exchange Online require extra configuration. After enabling auditing at the Office 365 level, we have to enable auditing at the mailBox level. We will perform this configuration before going to the labs.

1. [] On the desktop, right-click on **EnableMailboxAudit.ps1** and click **Run with PowerShell**.

1. [] When prompted, use the credentials below:

	+++@lab.CloudCredential(134).Username+++

	+++@lab.CloudCredential(134).Password+++

	> [!KNOWLEDGE] The following commands will be run to connect to Exchange Online and Enable Mailbox Auditing on the Admin account.
    >
	> ```$UserCredential = Get-Credential```
    >
	> ```$Session = New-PSSession –ConfigurationName Microsoft.Exchange –ConnectionUri https://outlook.office365.com/powershell-liveid/ -Credential $UserCredential –Authentication Basic -AllowRedirection```
	>
	>```Import-PSSession $Session```
    >
	> ```Get-MailBox -ResultSize Unlimited -Filter {RecipientTypeDetails -eq "UserMailBox"} | Set-MailBox -AuditEnabled $true```
    >
	> ```Get-MailBox admin | fl audit*```
    
    > [!ALERT] When you create new mailBoxes, **auditing is not enabled** by default. You will have to use the same commands again to enable auditing for those newly created mailBoxes.

    !IMAGE[MailBox auditing](\Media\MailboxAudit.png "MailBox Auditing")

>[!HINT] **Reference:** [Enabling auditing for Exchange Online mailBoxes](https://docs.microsoft.com/en-us/office365/securitycompliance/enable-mailBox-auditing?redirectSourcePath=%252fen-us%252farticle%252fenable-mailBox-auditing-in-office-365-aaca8987-5b62-458b-9882-c28476a66918).

---

## Enabling File Monitoring
[:arrow_up: Top](#mcas-environment-preparation)

1. [] Go to Cloud App Security portal at ```https://portal.cloudappsecurity.com``` and click on the **Gear** and then **Settings**.

    !IMAGE[Settings](\Media\conf-settings.png "Settings")

1. [] Under the **Information Protection** section click on **Files** and check the **Enable file monitoring** checkbox and click on the "**Save** button.

    !IMAGE[Enable files](\Media\conf-files.png "Enable files")

---

## Create a Developer Box Account
[:arrow_up: Top](#mcas-environment-preparation)

1. [] Next, navigate to ```https://developer.box.com``` and click on **Get Started**. 

	!IMAGE[Boxdev](\Media\box-getstarted.png)

2. [] **Enter the values** from the table below, **check the box** to solve the captcha, and click **Submit**.

	|||
	|-----|-----|
	|**Full Name**|```MOD Admin```|
	|**Email Address**|```@lab.CloudCredential(134).UserName```|

	^IMAGE[Open Screenshot](\Media\box-signup.png)

3. [] In a new tab, browse to ```https://outlook.office365.com/OWA```. 
1. [] Choose a time zone and click **Save**.
1. [] In the MOD Admin inbox, click on **Other** mail, and click the **Verify Email** link in the email from Box.

	^IMAGE[Open Screenshot](\Media\box-verify.png)

1. [] In the new window that opens, enter ```@lab.CloudCredential(134).password``` in **each of the password boxes** and click the **Update** button. 

---

## Connect Office 365 and Box to Cloud App Security 
[:arrow_up: Top](#mcas-environment-preparation)

To connect Cloud App Security to Office 365, you will have to use the Office 365 app connector. App connectors use the APIs of app providers to enable greater visibility and control by Microsoft Cloud App Security over the apps you connect to.  We will also use this method to show integration with the 3rd Party API for Box.

1. [] Open a new in Private tab in your browser and navigate to ```https://portal.cloudappsecurity.com```

2. [] Go to the gear icon and select **App connectors**.

    !IMAGE[App connector](\Media\conf-appconnector.png "App connector")

3. [] Click on the **+** button and select Office 365.

    !IMAGE[Add Office](\Media\conf-addoffice.png "Add Office")

4. [] Click on **Connect Office 365**. Cloud App Security will then have access to Office 365 activities and files.

    ^IMAGE[Open Screenshot](\Media\conf-connectoffice.png "Connect Office")

5. [] Click on **Test now** to validate the configuration.

    ^IMAGE[Open Screenshot](\Media\conf-testoffice.png "Test connectivity")

	> [!NOTE] If the connection is taking more than 1 minute - close out of the portal and log back in to check if it's been connected. 

---

## Connecting Box to Cloud App Security
[:arrow_up: Top](#mcas-environment-preparation)

1. []  Click on the **+** button again, and this time click on **Box**.

	!IMAGE[2](\Media\box-connect.png)

3. [] In the Instance name box, type ```Box API Demo```, and click **Connect Box**.

	^IMAGE[Open Screenshot](\Media\apiBox3.JPG)

4. [] In the Connect Box dialog, click **follow this link**.

	!IMAGE[4](\Media\box-follow.png)

5. [] Log into Box using the credentials below:

	```@lab.CloudCredential(134).Username```

	```@lab.CloudCredential(134).Password```

6. [] Click on **Grant access to Box**

	^IMAGE[Open Screenshot](\Media\box-grant.png)

7. [] Close the Connect Box dialog and click on **Box API Demo** to expand.
1. [] Click on the **Test now** link.

	^IMAGE[Open Screenshot](\Media\apiBox7.JPG)

	> [!KNOWLEDGE] Once the connection is succesful - it will say **Connected.** 
	>
	> !IMAGE[8](\Media\apiBox8.JPG)

8. []  Close the dialog and you should be able to see **Box API Demo** as a **Connected** app in the list. 

	^IMAGE[Open Screenshot](\Media\apiBox9.JPG) 

---

## Enabling Azure Information Protection integration
[:arrow_up: Top](#mcas-environment-preparation)

To prepare the **Information Protection** lab, we have to enable the integration between Cloud App Security and Azure Information Protection as explained in the [Cloud App Security documentation](https://docs.microsoft.com/en-us/cloud-app-security/azip-integration). Enabling the integration between the two solutions is as easy as selecting one single checkBox.

1. [] Go to Cloud App Security settings.

    !IMAGE[Settings](\Media\conf-settings.png "Settings")

2. [] Go down in the settings to the **Azure Information Protection** section and check the **Automatically scan new files** checkBox and click on the "**Save** button.
    !IMAGE[Enable AIP](\Media\conf-aip.png "Enable AIP")

>:memo: It takes up to **1h** for Cloud App Security to sync the Azure Information classifications.

===

# Lab Environment Setup Complete

The lab environment setup is now complete. In the next section you will start the lab.

!IMAGE[Save](\Media\save.png)

===

# Microsoft Cloud App Security
[:arrow_left: Home](#introduction)

## Introduction

Microsoft Cloud App Security is Microsoft **CASB** (Cloud Access Security Broker) and is a critical component of the Microsoft Cloud Security stack.
It's a comprehensive solution that can help your organization as you move to take full advantage of the promise of cloud applications, but keeps you in control through improved visibility into activity. It also helps increase the protection of critical data across cloud applications (Microsoft **and** 3rd parties).
With tools that help uncover shadow IT, assess risk, enforce policies, investigate activities, and stop threats, your organization can more safely move to the cloud while maintaining control of critical data.

The diagram below describe typical use cases for CASB's.

!IMAGE[MCAS intro](\Media\mcasintro-1.png "MCAS intro")

This lab will guide you through some of Microsoft Cloud App Security (MCAS) capabilities and top use cases.

===

## Lab environment
[:arrow_left: MCAS Home](#microsoft-cloud-app-security)

!IMAGE[Lab environment](\Media\mcaslabenvironment.png "Lab environment")

* **Client01** is a Windows 10 VM that will be used to access Office 365 and Cloud app Security management consoles and configure the log collector running on LinuxVM, using Putty.
* **LinuxVM** is an Ubuntu 18.04 computer on which we install Docker to run the Cloud App Security Discovery log collector.
* Office 365 and Cloud App Security are test tenants for the labs.



### Portals URLs

* Office 365:```https://portal.office.com```
* Cloud App Security: ```https://portal.cloudappsecurity.com```
* Security & Compliance Center: ```https://protection.office.com```
* Windows Defender ATP: ```https://securitycenter.windows.com```

===

## Labs
[:arrow_left: MCAS Home](#microsoft-cloud-app-security)

> [!ALERT] Before going to the different labs section, please be sure to complete the **[environment preparation](#mcas-environment-preparation)**.

The different Cloud App Security capabilities covered in the labs are:

* [Cloud apps Discovery](#cloud-app-security-discovery-lab)
* [Conditional Access App Control with Office 365](#conditional-access-app-control-with-office-365)
* [Automate alerts management with Microsoft Flow](#automate-alerts-management-with-microsoft-flow)
* [Threats Protection](#threats-protection)
* [Information Protection](#information-protection)

### Optional/Follow on labs

* [Management with PowerShell](#management-with-powershell)
* [Log collector troubleshooting](#log-collector-troubleshooting)

>:question: If you have questions or want to go further in your Cloud App Security journey, join our **[Tech community](https://techcommunity.microsoft.com/t5/Microsoft-Cloud-App-Security/bd-p/MicrosoftCloudAppSecurity)** !

===

# Cloud App Security Discovery
[:arrow_left: MCAS Home](#microsoft-cloud-app-security)

On average, more than 1,100 cloud applications are used by enterprises today, of which 61% are **not** sanctioned by IT. This results in duplicate capabilities, apps not meeting compliance standards or posing a security risk to the organization without any IT oversight.
**Discovery** identifies current cloud apps, provides risk assessments and ongoing analytics and lifecycle management capabilities to control the use.


!IMAGE[Discovery](\Media\discovery3.JPG)


To provide this visibility on Shadow IT and cloud apps usage, Cloud App Security ingest and analyze network logs from proxy, firewall but also from **Windows 10** clients within or **ouside** the corporate network, using the native integration with **Windows Defender ATP**.

!IMAGE[Discovery intro](\Media\dis-intro1.png "Discovery intro")


Once the logs have been analyzed, Cloud App Security provides the visibility on **Shadow IT** and alerts you when it detects risky apps or anomalous usage.

!IMAGE[Discovery intro](\Media\dis-intro2.png "Discovery intro")


> [!NOTE] In this lab, we will simulate the upload of network logs from a SQUID proxy to analyze the apps used withing your company. We will not test the Windows Defender ATP integration at it can take up to **2h** before the logs are parsed and the results are visible in the console.

===
# Cloud App Security Discovery Lab
[:arrow_left: Discovery lab](#cloud-app-security-discovery)

* [Cloud Discovery Snapshot Report](#cloud-discovery-snapshot-report)
* [Configure and Test Continuous Reports](#configure-and-test-continuous-reports)

===

# Cloud Discovery Snapshot Report
[:arrow_left: Discovery lab](#cloud-app-security-discovery-lab)

In this lab, we will create a Discovery **Snapshot report**.
Snapshot Reports is the manual method of uploading files into Cloud App Security. This process is a great and easy way to validate your logs format of have a quick look at the Cloud App Security Discovery capability.
You can upload batches of 20 logs of 1 GB max at a time and they will parse into their own separate report. Any discovery policies you create **will not** apply to these types of reports.

To create snapshot reports:

1. [] Go to the **Discover** section and click on **Create snapshot report**.

    ^IMAGE[Open Screenshot](\Media\dis-newsnaphsot.png "Create snapshot")

1. [] In the Add data source window, use the settings below (do not close the window yet) and click on **View and verify...**.

    >|||
    >|---------|---------|
    >|Report Name| ```**Demo report**```|
    >|Description| 
    >|Data Source| **SQUID (Common)**|
    >|Anonymize private information |**Check the Box**|

1. [] Click on **View and Verify** in the window and then click on the **Download sample log** button and save it to your desktop. 

	!IMAGE[Open Screenshot](\Media\dis-createsnapshot.png "New snapshot")

    ^IMAGE[Open Screenshot](Media\dis-squiddownload.png "Download log")

1. [] Close that window.

1. [] Click on the **Browse** button and in the new window, select the log you downloaded and click **Open**.

    ^IMAGE[Open Screenshot](\Media\dis-browse.png "Browse logs")

    ^IMAGE[Open Screenshot](\Media\dis-squidselect.png "Select logs")

1. [] Now that the log has been selected, click on the **Create** button to create your report.

    ^IMAGE[Open Screenshot](\Media\dis-squidcreate.png "Create snapshot")

1. [] Your report will then be processed. It will take a couple of minutes before it's marked as **Ready**.

    !IMAGE[Report processing](\Media\dis-processing.png "Report processing")

    !IMAGE[Report processing](\Media\dis-reportready.png "Report processing")

1. [] Once your report is marked as ready, click on the text **Ready**. You will be redirected to your snapshot report where you can start exploring the discovered apps, users, IPs. Your instructor can give you more details on how to use the dashboard.

    ^IMAGE[Open Screenshot](\Media\dis-reportready2.png "Report ready")

    !IMAGE[Report dashboard](\Media\dis-dashboard.png "Report dashboard")

    !IMAGE[Report dashboard -risk](\Media\dis-risk.png "Report dashboard - risk")

===

# Conditional Access App Control with Office 365
[:arrow_left: MCAS Home](#microsoft-cloud-app-security) :clock10: 15 min

## Introduction

Conditional Access App Control utilizes a reverse proxy architecture and is uniquely integrated with Azure AD conditional access.
Azure AD conditional access allows you to enforce access controls on your organization’s apps based on certain conditions. The conditions define who (for example a user, or group of users) and what (which cloud apps) and where (which locations and networks) a conditional access policy is applied to. After you’ve determined the conditions, you can route users to the Microsoft Cloud App Security where you can protect data with Conditional Access App Control by applying access and session controls.

Conditional Access App Control enables user app access and sessions to be **monitored and controlled in real time** based on access and session policies.

!IMAGE[AAD portal](\Media\caac1.jpg)

> [!NOTE] **App Control Access and Session policies give you the capability to the following:**
* **Block on download**: You can block the download of sensitive documents. For example, on unmanaged devices.
* **Protect on download**: Instead of blocking the download of sensitive documents, you can require documents to be protected via encryption on download. This ensures that the document is protected, and user access is authenticated, if the data is downloaded to an untrusted device.
* **Monitor low-trust user sessions**: Risky users are monitored when they sign into apps and their actions are logged from within the session. You can investigate and analyze user behavior to understand where, and under what conditions, session policies should be applied in the future.
* **Block access**: You can completely block access to specific apps for users coming from unmanaged devices or from non-corporate networks.
* **Create read-only mode**: By monitoring and blocking custom in-app activities you can create a read-only mode to specific apps for specific users.
* **Restrict user sessions from non-corporate networks**: Users accessing a protected app from a location that is not part of your corporate network, are allowed restricted access and the download of sensitive materials is blocked or protected.

===
# App Control Lab
[:arrow_left: Discovery lab](#cloud-app-security-discovery)

* [App Control Configuration](#app-control-configuration)
* [Testing the Session Policy](#testing-the-session-policy)

===

## App Control Configuration

1. [] Go to the Azure portal ```https://portal.azure.com``` and open the **Azure Active Directory** blade.

   ^IMAGE[Open Screenshot](\Media\aad-1.png)

1. [] Scroll down to **Security** and click on **Conditional Access**.

   ^IMAGE[Open Screenshot](\Media\aad-2.png)

1. [] Create a new conditional access policy with the following settings:

   |Name|Assignments|Apps|
   |-----|-----|-----|
   |Office365 AppControl|All users|Exchange, SharePoint|

    1. Click on **New Policy**

	    ^IMAGE[Open Screenshot](\Media\cond-policy-1.png)

    1. Name it ```Office365 App Control```

    1. Under assignments: Click on **All users** and then **Done**

       ^IMAGE[Open Screenshot](\Media\cond-policy-2.png)

    1. Go to the next section: Cloud Apps: Select Apps and choose Office 365 Exchange Online and Office 365 SharePoint Online and **Done**

       ^IMAGE[Open Screenshot](\Media\cond-policy-3.png)

    1. Under **Acess Controls**, click on **Session** and check off **Use Conditional Access App Control** 

       ^IMAGE[Open Screenshot](\Media\cond-policy-4.png)

    1. Click on **ON** in *Enable the policy* and click **Create**

       ^IMAGE[Open Screenshot](\Media\cond-policy-5.png)

1. [] Sign out of the Azure Portal and close you browser.

1. [] Open your browser and go to the Exchange Web App ```https://outlook.office.com```.

1. [] Connect using :

    >```@lab.CloudCredential(134).Username```
    >
    >```@lab.CloudCredential(134).Password```

    > [!HINT] This is done to force the use of conditional access. Once a session has been redirected to Cloud App Security, you will be able to configure the application for App Control in Cloud App Security.

1. [] Go back to Cloud App Security ```https://portal.cloudappsecurity.com```, click on the **Gear** icon and click on **Conditional Access App Control**.
  
   ^IMAGE[Open Screenshot](\Media\appc-office-1.png)

    > [!HINT] You will see that **Exchange Online** has now appeared as an application and can now be configured.

   ^IMAGE[Open Screenshot](\Media\appc-office-2.png)

1. [] Click on **Continue setup** to enable session control and click on **Add**.

   ^IMAGE[Open Screenshot](\Media\appc-office-3.png)

   ^IMAGE[Open Screenshot](\Media\appc-office-4.png)
  
1. [] You are now notified that the application is under Session Control.

   !IMAGE[Setup](\Media\appc-office-5.png)

1. [] On the left hand side click on **Control** and then **Policies**.

   !IMAGE[Open Screenshot](\Media\appc-office-6.png)

1. [] Click on **Create Polic** and click on **Session policy**.

        ^IMAGE[Open Screenshot](\Media\appc-office-7.png)

    1. **Name**: ```Proxy - Block sensitive files download```

    1. Under Session Control Type choose **Control filedownload (with DLP)**

        ^IMAGE[Open Screenshot](\Media\appc-office-8.png)

    1. Add Activity Filters: **Device Tag** does not equal **Compliant, Domain joined**

    1. **App** equals **Office 365 Exchange Online and Office 365 SharePoint Online**

       !IMAGE[Session policy](\Media\appc-office-9.png)

   1. Content inspection check **Enabled**
   Include files that match a preset expression anc choose US: **PII: Social Security Number**

       !IMAGE[Session policy](\Media\appc-office-10.png)

   1. Under Actions: go to **Block**

   1. Click: **Customize block message**: ```This file containes SSN information and cannot be downloaded on non-coporate devices.```

   1. Click: Verify that  **Create an alert for each matching event with the policy's severity** is checked. 

   1. Click: **Create**

       !IMAGE[Session policy](\Media\appc-office-11.png)

====

# Testing the Session Policy
[:arrow_left: Home](#app-control-labs)

Now is time to test our configuration. We will here simulate the userexperience while accessing company apps protected by Cloud App Security from an unmanaged device

1. [] Sign out, close you browser and open the Exchange Web App ```https://outlook.office.com```. Use the following credentials to connect:
  
   >```@lab.CloudCredential(134).Username```
   >
   >```@lab.CloudCredential(134).Password```

1. You should receive the following message, as you are redirected through Cloud App Security before accessing the application.
  
  Click **Continue to Exchange Online**.

   !IMAGE[Warning](\Media\appc-office-12.png)

1. [] You are now directed to Exchange Online and your session is now passing **through** Cloud App Security.

    > [!HINT] By taking a look at the **URL**, you can verify that your session is actually being redirected to **Cloud App Security**.

   !IMAGE[Session](\Media\appc-office-13.png)

1. [] To test our policy, perform the following:

    1. Create a new mail and attach the Word document named **Personal employees information.docx** and the Excel spreadsheet named **Workplace Innovation.xlsx** stored on **Client01** desktop. Send the mail to your user, ```@lab.CloudCredential(134).Username```

       !IMAGE[Test](\Media\appc-office-14.png)

    1. [] Wait until you receive your email in the webmail. 

    1. Once the message is received, click on the attached document **Personal employees information.docx**. This will open the file preview.
    As you can see, the user can access the document using the Office Online app.

        !IMAGE[Warning](\Media\appc-office-15.png)

    1. [] Try now to download the **Personal employees information.docx** document. As this file contains social security numbers, the download will be blocked and will trigger an alert in Cloud App Security.

       !IMAGE[Test](\Media\appc-office-16.png)
    
       !IMAGE[Test](\Media\appc-office-17.png)

    1. [] Now let's try to download the **Workplace Innovation.xlsx** spreadsheet. As this file **do not** contain social security numbers, the download will be allowed.

       !IMAGE[Test](\Media\appc-office-18.png)
    
       !IMAGE[Test](\Media\appc-office-19.png)
    
       !IMAGE[Test](\Media\appc-office-20.png)
    
       !IMAGE[Test](\Media\appc-office-21.png)

> [!KNOWLEDGE] We just demonstrated App Control capabilities to go further than just allow/block scenarios, based on session risks. This capability can open many scenarios, like BYOD access for example.

====

# Reviewing the Alerts
[:arrow_left: Home](#labs)

Now that we validated our configuration, let's go back to the admin view.

1. [] Go back to the Cloud App Security console ```https://portal.cloudappsecurity.com```

1. [] Go to the **Alerts** page.

   ^IMAGE[Open Screenshot](\Media\appc-admin-1.png)

1. [] Click on the alert generated by our policy.

   !IMAGE[Menu](\Media\appc-admin-2.png)

1. [] On the alert page, you can see that the **admin** user tried to download a file named **Personal employees information.docx** but **Session control** blocked the download. You also see the name of the policy that triggered the alert.

   !IMAGE[Menu](\Media\appc-admin-3.png)

1. [] To go further in the investigation, click on  **View all user activity**. This will redirect you to the Activity log where you can see all the user activities.

   !IMAGE[Menu](\Media\appc-admin-4.png)

1. [] By looking at the user activities, you can follow her/his trace:

    1. Below, you can see that the user was **redirected** to Cloud App Security

        !IMAGE[Menu](\Media\appc-admin-5.png)

    1. Here, you can see that during her/his session, the user **successfuly downloaded** a file named **Worplace Innovation.xlsx**, as this file didn't match any blocking policy.

        !IMAGE[Menu](\Media\appc-admin-6.png)

===

# Automate alerts management with Microsoft Flow

to do (Seb)

===

# Threats Protection
[:arrow_left: MCAS Home](#microsoft-cloud-app-security)

Cloud App Security provides several threats detection policies using machine learning and **user behavior analytics** to detect suspicious activities across your different applications.
Those policies are enabled by default and after an initial learning period, Cloud App Security will start alerting you when suspicious actions like activity from anonymous IP addresses, infrequent country, suspicious IP addresses, impossible travel, ransomware activity, suspicious inBox forwarding configuration or unusual file download are detected.

!IMAGE[Thret protection](\Media\tp-intro.png)

===

> [!ALERT] It can take **up to 24 hours** for the auditing in Office 365 to be configured, meaning that Cloud App Security will not receive the activities events. As many alerts relies on activities events to work, we will be using a pre-populated tenant for this portion of the lab so we can see alerts and have the ability to investigate them.

> [!HINT] LOG OUT OF YOUR CURRENT CLOUD APP SECURITY TENANT AND LOG BACK IN USING THE CREDENTIALS BELOW.

|Portal               |Username                   |Password
|----------------- |----------------------------------- |---------------------
| ```https://portal.cloudappsecurity.com``` | viewer@emslab.tech |EventP@ssword

**URLs**

* Office 365: ```https://portal.office.com```
* Cloud App Security: ```https://portal.cloudappsecurity.com```

## Labs

* [Anonymous access:](#anonymous-access)
* [Impossible travel:](#impossible-travel)
* [Activity from infrequent country:](#activity-from-infrequent-country)
* [Malware detection:](#malware-detection)
* [Email exfiltration using suspicious inBox forwarding:](#email-exfiltration-using-suspicious-inBox-forwarding)
* [Ransomware activity:](#ransomware-activity)
* [Suspicious application consent:](#suspicious-application-consent)

===

## Anonymous access

[:arrow_up: Top](#threats-protection)

This detection identifies that users were active from an IP address that has been identified as an anonymous proxy IP address. These proxies are used by people who want to hide their device’s IP address, and may be used for malicious intent. This detection uses a machine learning algorithm that reduces "false positives", such as mis-tagged IP addresses that are widely used by users in the organization.

### Investigate

As your authentication during the previous steps came from an anonymous IP address, it will be detected as suspicious by Cloud App Security.

1. [] Go back to the Cloud App Security portal and review the alerts.

   !IMAGE[MCAS alerts menu](\Media\td-alerts.png "Security Alerts")

   You will see an alert similar  to this one:

   !IMAGE[TOR alert](\Media\td-toralert.png "TOR alert")

2. [] Click on the alert to open it.
   You see in this page more information on the alert and the related activities:

   !IMAGE[TOR alert](\Media\td-toralert-details.png "TOR alert details")

3. [] Click on the activities to get more information on the specific activity, the user and the IP address:

   !IMAGE[TOR alert](\Media\td-toralert-details-user.png "TOR alert user")
   !IMAGE[TOR alert](\Media\td-toralert-details-ip.png "TOR alert IP address")

4. [] You can go further in your investigation by looking at the related actions performed during that session by clicking on the “investigate in activity log" button:

   !IMAGE[TOR alert](\Media\td-toralert-details-activities.png "TOR alert activities")

5. [] You will then be redirected to the activity log where you will be able to investigate on the actions performed during that session, like configuration changes or data exfiltration.

---

## Impossible travel

[:arrow_up: Top](#threats-protection)

This detection identifies two user activities (is a single or multiple sessions) originating from geographically distant locations within a time period shorter than the time it would have taken the user to travel from the first location to the second, indicating that a different user is using the same credentials. This detection uses a machine learning algorithm that ignores obvious "false positives" contributing to the impossible travel condition, such as VPNs and locations regularly used by other users in the organization. The detection has an initial learning period of seven days during which it learns a new user’s activity pattern.

### Investigate

As the first and the second authentication came from distinct locations, Cloud App Security will detect that those time to travel between those two locations was to short and will then alert you.

1. [] Go back to the Cloud App Security portal and review the alerts.

   !IMAGE[MCAS alerts menu](\Media\td-alerts.png "Security Alerts")

   You will see an alert similar  to this one:

   !IMAGE[Impossible travel alert](\Media\td-impossibletravelalert.png "Impossible travel alert")

2. [] The investigation steps are similar to the anonymous access but by looking at the IP address details and the **ISP**, you will be able to determine the possible risk:

   !IMAGE[Impossible travel alert](\Media\td-impossibletravelalert-details.png "Impossible travel alert details")

	> [!KNOWLEDGE] To reduce the amount of false positives, edit the impossible travel policy. 
	>  
	> **You can adjust the policy by clicking on the alert and *Resolve* and click on *Adjust policy.**
	> 
	> Each anomaly detection policy can be independently scoped so that it applies only to the users and 
	groups you want to include and exclude in the policy. For example, you can set the Activity from infrequent county detection to ignore a specific user who travels frequently.
	> 
	> **To scope an anomaly detection policy:**
	> 
    > 1. Click Control and then Policies, and set the Type filter to Anomaly detection policy.
	> 2. Click on the policy you want to scope. 
    > 3. Under Scope, change the drop-down from the default setting of All users and groups, to Specific users and groups. 
	> 4. Select Include to specify the users and groups for whom this policy will apply. Any user or group not selected here won't be    considered a threat and won't generate an alert.
	> 5. Select Exclude to specify users for whom this policy won't apply. Any user selected here won't be considered a threat and won't generate an alert, even if they're members of groups selected under Include.
	> 
	> **Sensitivity Slider:**
	> 
    > You can set the sensitivity slider to determine the level of anomalous behavior needed before an alert is triggered. For example, if you set it to low, it will suppress Impossible Travel alerts from a user’s common locations, and if you set it to high, it will surface such alerts.
	> 
	>  !IMAGE[Impossible Travel Sensitivity Bar](\Media\updatedimpossibletravel.JPG)  

---

## Activity from infrequent country

[:arrow_up: Top](#threats-protection)

This detection considers past activity locations to determine new and infrequent locations. The anomaly detection engine stores information about previous locations used by users in the organization. An alert is triggered when an activity occurs from a location that wasn't recently or never visited by any user in the organization.

### Investigate

After an initial learning period, Cloud App Security will detect that this location was not used before by your user or other people within the organization and will then alert you.

1. [] Go back to the Cloud App Security portal and review the alerts.

   !IMAGE[MCAS alerts menu](\Media\td-alerts.png "Security Alerts")

   You will see an alert similar  to this one:

   !IMAGE[Infrequent country alert](\Media\td-infrequentcountryalert.png "Infrequent country alert")

2. [] The investigation steps are similar to the anonymous access but by looking at the IP address details and the ISP, you will be able to determine the possible risk. In this specific example, we see it’s coming from a TOR IP, so this authentication is suspicious:

   !IMAGE[Infrequent country alert](\Media\td-infrequentcountryalert-details.png "Infrequent country alert details")

	> [!NOTE] Possible resolution options are available on the top bar for single click remediation. 

	!IMAGE[Infrequent country alert](\Media\infrequentcountry1.JPG)


---

## Malware detection

[:arrow_up: Top](#threats-protection)

This detection identifies malicious files in your cloud storage, whether they're from your Microsoft apps or third-party apps. Microsoft Cloud App Security uses Microsoft's threat intelligence to recognize whether certain files are associated with known malware attacks and are potentially malicious. This built-in policy is disabled by default. Not every file is scanned, but heuristics are used to look for files that are potentially risky. After files are detected, you can then see a list of **Infected files**. Click on the malware file name in the file drawer to open a malware report that provides you with information about that type of malware the file is infected with.

### Investigate

1. [] Go back to the Cloud App Security portal and review the alerts.

   !IMAGE[MCAS alerts menu](\Media\td-alerts.png "Security Alerts")

   You will see an alert similar  to this one:

   !IMAGE[Malware detected alert](\Media\td-malwarealert.png "Malware detected alert")

2. [] Click on the alert to open it. You see in this page more information on the alert and the related activities:

   !IMAGE[Malware detected alert](\Media\td-malwarealert-details.png "Malware detected alert")

3. [] In the alert, you have more information on the file and its location, but also the malware that we identified:

   !IMAGE[Malware family](\Media\td-malwarefamily.png "Malware family")

4. [] Click on the malware type link to have access to the Microsoft Threat Intelligence report regarding this file:

   !IMAGE[Malware family](\Media\td-malwarefamilymti.png "Malware family")

5. [] Back in the alert, you can scroll down to the related activities. There, you will have more information on how the file was uploaded to OneDrive and possibly who downloaded it:

   !IMAGE[Malware family](\Media\td-malwarealert-activities.png "Malware family")

---

## Email exfiltration using suspicious inBox forwarding

[:arrow_up: Top](#threats-protection)

This detection looks for suspicious email forwarding rules, for example, if a user created an inBox rule that forwards a copy of all emails to an external address.

### Investigate

As the rules redirects your user’s emails to a suspicious external address, Cloud App Security will detect this rule creation and will then alert you.

1. [] Go back to the Cloud App Security portal and review the alerts.

   !IMAGE[MCAS alerts menu](\Media\td-alerts.png "Security Alerts")

   You will see an alert similar  to this one:

   !IMAGE[Suspicious forwarding alert](\Media\td-suspiciousforwardingalert.png "Suspicious forwarding alert")

2. [] Click on the alert to open it. You see in this page more information on the alert, like the **destination address** and the related activities:

   !IMAGE[Suspicious forwarding alert](\Media\td-suspiciousforwardingalert-details.png "Suspicious forwarding alert")

3. [] With this information, you can now go back to the user to remove this rule but also investigate in Exchange trace logs which emails were sent to that destination address.

---

## Ransomware activity

[:arrow_up: Top](#threats-protection)

Cloud App Security extended its ransomware detection capabilities with anomaly detection to ensure a more comprehensive coverage against sophisticated Ransomware attacks. Using our security research expertise to identify behavioral patterns that reflect ransomware activity,Cloud App Security ensures holistic and robust protection. If Cloud App Security identifies, for example, a high rate of file uploads or file deletion activities it may represent an adverse encryption process. This data is collected in the logs received from connected APIs and is then combined with learned behavioral patterns and threat intelligence, for example, known ransomware extensions. For more information about how Cloud App Security detects ransomware, see Protecting your organization against ransomware.

### Investigate

As the rules redirects your user’s emails to a suspicious external address, Cloud App Security will detect this rule creation and will then alert you.

1. [] Go back to the Cloud App Security portal and review the alerts.

   !IMAGE[MCAS alerts menu](\Media\td-alerts.png "Security Alerts")

   You will see an alert similar  to this one:

   !IMAGE[Ransomware alert](\Media\td-ransomwarealert.png "Ransomware alert")

2. [] Click on the alert to open it. You see in this page more information on the impacted user, the number of encrypted files, the location of the files and the related activities:

   !IMAGE[Ransomware alert](\Media\td-ransomwarealert-details.png "Ransomware alert")

3. [] Now that we’ve seen the alert, let’s go back to the policies:

   !IMAGE[Policies](\Media\td-policies.png "Policies")

4. [] Search for the “Ransomware activity” policy and open it:

   !IMAGE[Ransomware policy](\Media\td-policiesransomware.png "Ransomware policies")

5. [] At the bottom of the policy, review the possible alerts and governance actions:

   !IMAGE[Ransomware policy](\Media\td-policiesransomware-governance.png "Ransomware policies")

---

## Suspicious application consent

[:arrow_up: Top](#threats-protection)

Many third-party productivity apps that might be installed by business users in your organization request permission to access user information and data and sign in on behalf of the user in other cloud apps, such as Office 365, G Suite and Salesforce. 
When users install these apps, they often click accept without closely reviewing the details in the prompt, including granting permissions to the app. This problem is compounded by the fact that IT may not have enough insight to weigh the security risk of an application against the productivity benefit that it provides.
Because accepting third-party app permissions is a potential security risk to your organization, monitoring the app permissions your users grant gives you the necessary visibility and control to protect your users and your applications. The Microsoft Cloud App Security app permissions enable you to see which user-installed applications have access to Office 365 data, G Suite data and Salesforce data, what permissions the apps have, and which users granted these apps access to their Office 365, G Suite and Salesforce accounts. 

Here is an example of such user consent:

!IMAGE[App consent](\Media\td-appconsent.png "App consent")

### Investigate

1. [] Without even creating policies, Cloud App Security shows you the applications that received permissions from your users:

   !IMAGE[App permissions](\Media\td-oauth.png "App permissions")

2. [] From this page, you can easily see who granted permissions to those apps, if they are commonly used or their permissions level:

   !IMAGE[App commodity](\Media\td-zapiercommodity.png "App commodity")

3. [] If you detect that an application should not be granted access to your environment, you can revoke the app access.
   > **IMPORTANT:** This operation will apply to the **entire** organization:

   !IMAGE[App revoke](\Media\td-apprevoke.png "App revoke")

4. [] When investigating, you can search for apps rarely used in Office 365 which were granted high privileges and create a **policy** to be automatically alerted when such action is performed:

   !IMAGE[App filter](\Media\td-appfilter.png "App filter")

5. [] After clicking on the “New policy from search” button, you can see that your filter will be used to create a new policy:

   !IMAGE[App policy](\Media\td-apppolicy.png "App policy")

6. [] Go down on that page and review the possible alerts and governance automatic actions that you can configure:

   !IMAGE[App policy](\Media\td-apppolicy-governance.png "App policy")

7. [] To go further in your investigation, let’s now pivot to the “Activity log”:

   !IMAGE[Activity log](\Media\td-activitylog.png "Activity log")

8. [] In the activity log, search for "**Consent to application**" activities:

   !IMAGE[Activity log](\Media\td-activitylog-consent01.png "Activity log")

9. [] You will then be able to investigate on who, when and from where your users granted access to applications:

   !IMAGE[Activity log](\Media\td-activitylog-consent02.png "Activity log")

---

## Create your own policies

[:arrow_up: Top](#threats-protection)

Now that we reviewed some of the default detection capabilities of Cloud App Security, you should start creating your own policies.
Cloud App Security provides by default many has policies templates to start creating your custom policies.

1. [] To create your policies, go to “Policies”:

   !IMAGE[Policies](\Media\td-policies.png "Policies")

2. [] Click on “Create policy” and select the type of policy you want to create:

   !IMAGE[Policies types](\Media\td-policiestypes.png "Policies types")

3. [] In the policy screen, choose the policy template you want to use:

   !IMAGE[Policies templates](\Media\td-policiestemplates.png "Policies templates")

4. [] Apply the template:

   !IMAGE[Apply template](\Media\td-applytemplate.png "Apply template")

5. [] Cloud App Security will then populate the different properties of the policy:

   !IMAGE[Policy template filter](\Media\td-policytemplatefilter.png "Policy template filter")

6. [] Review those properties and customize them if needed.

7. [] Explore other types of policies and review the proposed templates.

===

# Information Protection
[:arrow_left: MCAS Home](#microsoft-cloud-app-security)

In a perfect world, all your employees understand the importance of information protection and work within your policies. But in a real world, it's probable that a partner who works with accounting uploads a document to your Box repository with the wrong permissions, and a week later you realize that your enterprise's confidential information was leaked to your competition.
Microsoft Cloud App Security helps you prevent this kind of disaster before it happens.

!IMAGE[IP](\Media\IPCAS.JPG)

===
## Information Protection Lab

File policies are a great tool for finding threats to your information protection policies, for instance finding places where users stored sensitive information, credit card numbers and third-party ICAP files in your cloud. With Cloud App Security, not only can you detect these unwanted files stored in your cloud that leave you vulnerable, but you can take im/mediate action to stop them in their tracks and lock down the files that pose a threat.
Using Admin quarantine, you can protect your files in the cloud and remediate problems, as well as prevent future leaks from occurring.

* [Apply AIP classification to SSN documents:](#apply-aip-classification-to-ssn-documents)
* [Quarantine sensitive PDF for review:](#quarantine-sensitive-pdf-for-review)
* [Test our policies:](#test-our-policies)

## Apply AIP classification to SSN documents
[:arrow_up: Top](#information-protection)

In this lab, we are going to configure a file policy to apply an **Azure Information Protection** template on documents containing social security numbers. This method could be compared to the **Azure Information Protection Scanner** for documents that are stored on file servers.

1. [] In the Cloud App Security portal, go to **Control** and then click on **Policies.**

    !IMAGE[Open Screenshot](\Media\info-policies.png "Policies")

1. [] Create a Policy click on  **File policy**.

    ^IMAGE[Open Screenshot](\Media\info-newpolicy.png "New policy")

1. [] Provide the following settings to that policy:

    >|||
    >|---------|---------|
    >|Policy Name| ```Protect SSN documents in sensitive site```|
    >|Files matching all of the following| **App equals Box** |
    >|Apply to| **All Files** |


    ^IMAGE[Open Screenshot](\Media\allfilesBox1.png)  

1. [] In the inspection method, select **Data Classification Service**.

    ^IMAGE[Open Screenshot](\Media\info-dcs.png "DCS")

    > [!KNOWLEDGE] **Microsoft Data Classification Service** provides a **unified** information protection experience across Office 365, Azure Information Protection, and Microsoft Cloud App Security.
    > [!KNOWLEDGE]
    > [!KNOWLEDGE] The classification service allows you to extend your data classification efforts to the third-party cloud apps protected by Cloud App Security, using the decisions you already made across an even greater number of apps.

1. [] Click on **Choose inspection type** and then on **sensitive information type**.

    ^IMAGE[Open Screenshot](\Media\info-type.png "SSN type")


1. Search and select the **all** the information types matching ```SSN``` and click on **Done**.

    > [!HINT] Be sure to select the checkboxes as clicking on the name do not select the information type.

    !IMAGE[SSN type](\Media\info-ssn.png "SSN type")

1. [] Click on the **Unmask the last 4 characters of a match** and the **Create an alert for each matching file** checkboxes.

    ^IMAGE[Open Screenshot](\Media\info-unmask.png "Unmask")

    > [!KNOWLEDGE] In production scenarios, as you will probably have thousands of matches, you will **not** create alerts but use the **policy matches** approach instead.

1. [] In the Governance actions, click on **Box** and select **Apply classification label**. Select the **Highly Confidental - All Employees** label. 

    > [!ALERT] If you are not able to select Azure Information Protection templates, verify that you configured the integration in the prerequisites section or that you waited the 1h for the classifications to sync. In addition log out of the Cloud App Security Portal and log back in and see and if you're able to apply the label. 

  !IMAGE[gov](\Media\Boxgovssn.JPG)


1. [] Click **Create** to finish the policy creation.

---

## Quarantine sensitive PDF for review
[:arrow_up: Top](#information-protection)

In this lab, we are going to configure a file policy to quarantine sensitive PDF files that are shared externally, so an admin can review those files and validate if they could or not be shared externally. **Admin quarantine** can also be used to isolate files that should not have been uploaded to cloud storage apps.

1. [] In the Cloud App Security portal, go to **Control** and then click on **Policies.**

    !IMAGE[Open Screenshot](\Media\info-policies.png "Policies")

1. [] Create a Polick and click on **File policy** that will determine which files should be placed in quarantine.

    ^IMAGE[Open Screenshot](\Media\info-newpolicy.png "New policy")

1. [] Provide the following settings to that policy:

    >|Policy name|Files matching all of the following|
    >|---------|---------|
    >|```Quarantine sensitive pdf```| Extension equals pdf **and** Access level equals Public, External|

    ^IMAGE[Open Screenshot](\Media\info-policy3.png "New policy")

1. [] Check the **Create an alert for each matching file** checkBox. 

1. [] In Governance actions of the policy, select **Put in admin quarantine** for Box and click on the **Create** button.

    !IMAGE[Unmask](\Media\Boxgovadmin.JPG)

---

## Test our Policies
[:arrow_up: Top](#information-protection)

We are now going to test our files policies by performing the following actions.

1. [] On Client01, unzip the content of the **Demo files.zip**.

1. [] Go to the **Box** files ```https://app.box.com/folder/0```

1. [] Upload the unzipped files to the site.

    ^IMAGE[Open Screenshot](\Media\info-uploadbox.png "Upload")

1. [] After upload is complete, **share** the PDF document named **Protect with Microsoft Cloud App Security proxy.pdf**

    ^IMAGE[Open Screenshot](\Media\info-share1.png "Upload")

    ^IMAGE[Open Screenshot](\Media\info-share2.png "Upload")

1. [] Cloud App Security will now scan those documents and search for matches to your created policies.

    > [!HINT] The scan can take **several minutes** before completion.

1. [] To monitor the evolution of the scan, go back to Cloud App Security, select **Investigate** and open the **Files** page.

    ^IMAGE[Open Screenshot](\Media\info-files1.png "Search files")

1. [] You can search for the files you uploaded using different criteria, like **file name**, **type**, ... or just look at all the files discovered by Cloud App Security. When a policy match is discovered, you will notice it on this page by looking at the icones next to the file name. You will also have icons related to the applied **Governance action** (AIP label or Admin Quarantine in our lab).

    ^IMAGE[Open Screenshot](\Media\Boxfilesmatch.png)

1. [] To open the details of the file, click on its name. You can see there the matched policies and the scan status of the files.

    ^IMAGE[Scan status](\Media\info-files5.png "Scan status")

1. [] You can also view the related governance actions, like applying the Azure Information classification or moving the file to the quarantine folder, at the file level or in the **Governance log**.

    !IMAGE[Governance log](\Media\Boxgovlog.jpg)

1. [] As we configured **Alerts** in our lab, you can also review the related alerts in the **Alerts page**.

    ^IMAGE[Alert](\Media\Boxalert1.png)

    ^IMAGE[Alert](\Media\Boxalert2.png)

1. [] If you go back to **Box**, you will also notice that the quarantined files will be replaced by **placeholders**. The original file will be moved to the **Quarantine**.

    > [!KNOWLEDGE]  For Box, the quarantine folder location and user message **can't be customized**. The folder location is the drive of the admin who connected Box to Cloud App Security. For **SharePoint and OneDrive**, the location and the message can be customized in Cloud App Security settings.

    ^IMAGE[Open Screenshot](\Media\boxquarantine2.png)

    ^IMAGE[Open Screenshot](\Media\boxquarantine1.png)

1. [] The other way to review the policy matches is to go back to the **Policies page** and look at the **matches number**.

    !IMAGE[Matches](\Media\info=matches.png)

===

# Management with PowerShell
[:arrow_left: MCAS Home](#microsoft-cloud-app-security)) :clock10: 15 min

To help administrators interact with MCAS in a programmatic way, two
Microsoft employees created a non-official PowerShell module for Cloud
App Security. For this lab, you will install this module and discover
the available cmdlets.

Note: the module relies on the Cloud App Security API. You can find its
documentation in the MCAS portal.

!IMAGE[f847xhzx.jpg](\Media\f847xhzx.jpg)

The module is available in the PowerShell gallery and can be installed
using the ```*Install-Module mcas*``` command.

!IMAGE[6j16dgs2.jpg](\Media\6j16dgs2.jpg)

More information on the module is available on GitHub:
[https://github.com/powershellshock/MCAS-Powershell](https://github.com/powershellshock/MCAS-Powershell)

After installing the module, read how to connect to MCAS in the
PowerShell help and start exploring the cmdlets.

Hint: you'll have to create an API token in Cloud App Security.

!IMAGE[0x2tzeqd.jpg](\Media\0x2tzeqd.jpg)

Using PowerShell:

1.  [] Review the list of MCAS administrators and when they were granted
    those permissions

2.  [] Review your security alerts and close them in bulk

3.   [] Download a sample SQUID log and send it to MCAS as a snapshot
    report.

4.   [] In the portal, in Discovery, tag some apps as unsanctioned and
    generate a blocking script for your appliance to block access to
    those apps.

5.   [] You are asked to define corporate IP's in MCAS. Subnets go from
    10.50.50.0/24 to 10.50.80.0/24

===

# Log Collector Troubleshooting
[:arrow_left: Home](#labs) :clock10: 15 min

In this task, you will review possible troubleshooting steps to identify issues in automatic logs upload from the log collector.
There are several things to test at different locations: in the log collector, in MCAS, at the network level.

## Useful commands

* `cd` : *Used to navigate in the directories*
    >**Examples:**
    >
    >`cd /var/adallom` : *to go to the specified directory*
    >
    >`cd /` : *to go to the root directory*
    >
    >`cd ..` : *to go to the parent directory*

* `more` or `cat` : *Used to display the content of the logs*
    > **Examples:**
    >
    >`more trace.log` : *to display the content of the trace.log file*

* `tail` : *Used for outputting the last part of files*

* `ll` : *Used to display the content of the directory as a list*. This command is an alias for `ls -l`

* `clear` : *Used to clear the screen*

* `tab key` : Used to perform autocompletion

## Verify the log collector (container) status

1. [] On **Client01**, open a session on PuTTY to **192.168.141.125** and use the credentials below.
    In the PuTTY Configuration window, enter **192.168.141.125** and click **Open**.

    ^IMAGE[Open Screenshot](\Media\dis-puttyconfig.png "Putty config")

    Log in using the credentials below.
    >|Username|Password|
    >|---|---|
    >|user01|Passw0rd1|
    >
    >:warning:The password doesn't appear in the command prompt, you can safely press enter to validate the credentials.

2. [] Run the following commands:

    ``` 
    sudo -i
    docker stats
    ```
    !IMAGE[Docker stats](\Media\dis-dockerstats.png "Docker stats")

     > [!HINT] This command will show you the status of the log collector instance.

3. [] Press `Ctrl-C` to end the command.

4. [] Next, run the command below:

    ``` 
    docker logs --details LogCollector
    ```
    !IMAGE[Docker log](\Media\dis-dockerlog.png "Docker log")

     > [!HINT] This command will show you the container logs to verify if it encountered errors when initiating.

### Verify the log collector logs

1. [] Type the following command:

    ``` 
    docker exec -it LogCollector bash
    ```
     > [!HINT] This command will execute the container's bash. You will then be able to execute commands *from inside* of the log collector.

2. [] You can now explore the container filesystem and inspect the **/var/adallom** directory. This directory is where you will investigate most of the issues with the syslog or ftp logs being sent to the log collector.

    ``` 
    cd /var/adallom
    ll
    ```

    !IMAGE[adallom folder](\Media\dis-dockerll.png "adallom folder")

    Go to the following folders and review their log files using `more`:
    * **/adallom/ftp/discovery**: this folder contains the data source folders where you send the log files for automated upload. This is also the default folder when logging into the collector with FTP credentials.
    * **/adallom/syslog/discovery**: if you setup the log collector to receive syslog messages, this is where the flat file of aggregated messages will reside until it is uploaded.
    * **/adallom/discoverylogsbackup**: this folder contains the last file that was sent to MCAS. This is useful for looking at the raw log in case there are parsing issues.

3. [] To validate that logs are correctly received from the network appliance, you can also verify the **/var/log/pure-ftpd** directory and check the transfer log:

    ``` 
    tail transfer.log
    ```

    !IMAGE[FTP logs](\Media\dis-pureftp.png "FTP logs")

4. [] Now, move to the **/var/log/adallom** directory.

    !IMAGE[var log](\Media\dis-varlog.png "var log")

    Go to the following folders and review their content and log files using `ll` and `more` or `tail`:
    * **/var/log/adallom/columbus**: this folder is where you will find log files useful for troubleshooting issues with the collector sending files to Cloud App Security. In the **log-archive** folder you can find previous logs compressed as *.tar.gz* files that could be used to send to support for example.
    * **/var/log/adallom/columbusInstaller**: this is where you will investigate issues with the log collector itself. You will find here logs related to the configuration and bootstrapping of the collector. For example, **trace.log** will show you the bootstrapping process:

    !IMAGE[Bootstrapping log](\Media\dis-bootstrapping.png "bootstrapping log")

## Verify the connectivity between the log collector and Cloud App Security

An easy way to test the connectivity after configuring the log collector is to download a sample of your appliance logs from and use WinSCP to connect to the log collector to upload it and see if it gets uploaded to Cloud App Security, as you did in the previous exercise

!IMAGE[Pending log](\Media\dis-pending.png "Log pending")

> [!HINT] If the log stays in the source folder for too long, then you know you probably have a connection issue between the log collector and Cloud App Security and should go investigate the logs reviewed previously.
