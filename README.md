# SOC-Automation-Lab
## Network Diagram
![image](https://github.com/Mutimber/SOC-Automation-Lab/assets/113706552/169c3864-ce94-4239-956b-b5e94c1a04f3)
## Install virtual machines

### Install virtualisation software 
- Vbox installed on Windows machine
- Downloaded, configured, and launched Windows 10 agent
- Configured sysmon on the Windows 10 VM to monitor the agent
- Created a free account on Digital Ocean to set up free VMs - Wazuh and Hive

# Wazuh - SIEM solution
- Installed Wazuh using using the Droplet function - create
![image](https://github.com/Mutimber/SOC-Automation-Lab/assets/113706552/9d57dbc1-649c-4152-9bcf-f2e029adb91f)

- Ubuntu 22.04, 8GB / 160GB chosen
- Machine metrics 
![image](https://github.com/Mutimber/SOC-Automation-Lab/assets/113706552/002cd9c3-2873-4d5d-b906-0d7f0dde0602)

-	Added a Firewall to the droplet - Wazuh
  - Created a Firewall called Firewall for the machines to secure them
  ![image](https://github.com/Mutimber/SOC-Automation-Lab/assets/113706552/cc3dbdd9-ebeb-46a5-819f-ba50c7b6aeb3)

-	Added Firewall rules
  -	Enabled All TCP Access to the machine from my IP address
  -	Enabled All UDP access to the machine from my IP address.
  -	Enabled SSH to allow console access 
![image](https://github.com/Mutimber/SOC-Automation-Lab/assets/113706552/ee475682-0402-4720-aab1-3f6ba5024824)

- Linked Wazuh to Firewall
![image](https://github.com/Mutimber/SOC-Automation-Lab/assets/113706552/f01037c3-ba4c-4727-b874-533578056a7e)

- Accessed the Wazuh machine via terminal 
  -	Clicked Access Access and Launch Droplet Console
![image](https://github.com/Mutimber/SOC-Automation-Lab/assets/113706552/93e12d58-a6fa-46e5-84d2-d5d6daf883ad)
-	Updated and upgraded the machine using apt-get update && apt-get upgrade command
![image](https://github.com/Mutimber/SOC-Automation-Lab/assets/113706552/69d74b87-8567-4b71-aa18-5030c297664d)

-	Enter Y when prompted then press Enter when prompted to fully update the machine.
![image](https://github.com/Mutimber/SOC-Automation-Lab/assets/113706552/c7a6b24a-712f-4fb7-863f-807b577dbcc1)
![image](https://github.com/Mutimber/SOC-Automation-Lab/assets/113706552/3cc18e3f-394e-475a-9f47-7289897aea44)

-	At the end, this shows an updated machine 
![image](https://github.com/Mutimber/SOC-Automation-Lab/assets/113706552/6bc60dc0-7324-442c-b17c-88fc36fa3ee4)

-	Installed Wazuh on the Ubuntu machine
-	command : curl -sO https://packages.wazuh.com/4.7/wazuh-install.sh && sudo bash ./wazuh-install.sh -a
![image](https://github.com/Mutimber/SOC-Automation-Lab/assets/113706552/b8954035-7de4-4ea6-a6c4-d6fe534cbf0f)

-	Noted the login credentials for Wazuh dashboard access 
  - User: admin-
  - Password: 2yJe?DGWUM9LZF+doYKG94Gs7rsppqna
-	Login to Wazuh dashboard
  -	Take note of the Wazuh VM public IP
  -	Paste it in a new browser window, i.e https://45.55.202.84
  -	Access the site even despite the warning - Advanced options
![image](https://github.com/Mutimber/SOC-Automation-Lab/assets/113706552/d1e304bb-1f8e-4049-8a01-4cbb1f03cb63)
![image](https://github.com/Mutimber/SOC-Automation-Lab/assets/113706552/7f5afa53-27c8-4971-9c01-03476bfc5f69)

-	Enter Wazuh credentials from before to access the dashboard
-	Wazuh credentials are also accessible via: sudo tar -xvf wazuh-install-files.tar
![image](https://github.com/Mutimber/SOC-Automation-Lab/assets/113706552/45c2faf0-e1af-4b0c-81b4-5b7868ee1e04)

![image](https://github.com/Mutimber/SOC-Automation-Lab/assets/113706552/42e7d654-4590-4be3-b982-fc053ca67575)



# The Hive - Case Management
-	Create the Hive machine from the Droplet feature on Digital Ocean with same specs as Wazuh
![image](https://github.com/Mutimber/SOC-Automation-Lab/assets/113706552/10cf1bee-365a-456e-af52-38cfe8583fa7)
  
-	Add Firewall to the Hive
  -	Open thehive instance
  -	Navigate to Networking
  -	Scroll down to Firewall, then select Edit
  -	Select the existing Firewall on the next page
![image](https://github.com/Mutimber/SOC-Automation-Lab/assets/113706552/0c95e595-3112-4866-930f-c28cab38b246)
 
-	Add droplets
![image](https://github.com/Mutimber/SOC-Automation-Lab/assets/113706552/438a2eaf-065d-4cdd-8394-aa12c3de1dfb)
-	Search and select thehive then add it
![image](https://github.com/Mutimber/SOC-Automation-Lab/assets/113706552/fb6d159c-099d-4fc7-9606-c1ca642a30e8)

![image](https://github.com/Mutimber/SOC-Automation-Lab/assets/113706552/91c85ff6-66b9-4adc-b7c6-7d1e424c3e7b)

- SSH into thehive
![image](https://github.com/Mutimber/SOC-Automation-Lab/assets/113706552/ad4cfc08-d1bf-4653-a61a-f3611b9ef686)

## Install prerequisites
	apt install wget gnupg apt-transport-https git ca-certificates ca-certificates-java curl  software-properties-common python3-pip lsb-release
![image](https://github.com/Mutimber/SOC-Automation-Lab/assets/113706552/f5760ecd-7f0f-4a9f-b070-938ebb491e11)
![image](https://github.com/Mutimber/SOC-Automation-Lab/assets/113706552/42db03e2-284a-42b5-adeb-680a40bb4f3d)

### Install 5 hive dependencies
#### Java 
wget -qO- https://apt.corretto.aws/corretto.key | sudo gpg --dearmor  -o /usr/share/keyrings/corretto.gpg
echo "deb [signed-by=/usr/share/keyrings/corretto.gpg] https://apt.corretto.aws stable main" |  sudo tee -a /etc/apt/sources.list.d/corretto.sources.list
sudo apt update
sudo apt install java-common java-11-amazon-corretto-jdk
echo JAVA_HOME="/usr/lib/jvm/java-11-amazon-corretto" | sudo tee -a /etc/environment 
export JAVA_HOME="/usr/lib/jvm/java-11-amazon-corretto"

#### Install Cassandra
wget -qO -  https://downloads.apache.org/cassandra/KEYS | sudo gpg --dearmor  -o /usr/share/keyrings/cassandra-archive.gpg
echo "deb [signed-by=/usr/share/keyrings/cassandra-archive.gpg] https://debian.cassandra.apache.org 40x main" |  sudo tee -a /etc/apt/sources.list.d/cassandra.sources.list
sudo apt update
sudo apt install cassandra

#### Install ElasticSearch
wget -qO - https://artifacts.elastic.co/GPG-KEY-elasticsearch |  sudo gpg --dearmor -o /usr/share/keyrings/elasticsearch-keyring.gpg
sudo apt-get install apt-transport-https
echo "deb [signed-by=/usr/share/keyrings/elasticsearch-keyring.gpg] https://artifacts.elastic.co/packages/7.x/apt stable main" |  sudo tee /etc/apt/sources.list.d/elastic-7.x.list
sudo apt update
sudo apt install elasticsearch

#### Install TheHive
wget -O- https://archives.strangebee.com/keys/strangebee.gpg | sudo gpg --dearmor -o /usr/share/keyrings/strangebee-archive-keyring.gpg
echo 'deb [signed-by=/usr/share/keyrings/strangebee-archive-keyring.gpg] https://deb.strangebee.com thehive-5.2 main' | sudo tee -a /etc/apt/sources.list.d/strangebee.list
sudo apt-get update
sudo apt-get install -y thehive


## Configure Wazuh and thehive
### The Hive 
-	Cassandra: nano /etc/cassandra/cassandra.yaml 
  -	Customize listen address to thehive public IP
  -	Change rpc address to thehive public IP
  -	Edit cluster name to preferred title
  -	Save and exit nano
  -	Change seed provider to thehive public IP:7000
  -	Stop cassandra: systemctl stop cassandra.service
  -	Remove all files from cassandra: rm -rf /var/lib/cassandra/*
  -	Start cassandra: systemctl start cassandra.service
  -	Check status: systemctl status cassandra.service

![image](https://github.com/Mutimber/SOC-Automation-Lab/assets/113706552/8267d1a3-7f96-42b0-a0c7-b5597597efdc)

### Elastic Stack 
  -	Used in querying data
  -	Configure it:  nano /etc/elasticsearch/elasticsearch.yml
      -	Uncomment cluster.name, change name to ‘thehive’
      -	Uncomment node.name
      -	Uncomment network.host, change the IP to thehive VM public IP
      -	Uncomment http.port
      -	Uncomment cluster.initial_master_nodes, delete node-2
  -	Start elasticsearch: systemctl start elasticsearch
  -	Enable service: systemctl enable elasticsearch
  -	Check status: systemctl status elasticsearch
![image](https://github.com/Mutimber/SOC-Automation-Lab/assets/113706552/7ad311da-4858-48b2-a6c3-da6107410c79)

-	Doublecheck cassandra, it often stalls
-	Now configure thehive:
  -	Check thehive owner:  ls -la /opt/thp
![image](https://github.com/Mutimber/SOC-Automation-Lab/assets/113706552/2e34b5eb-a63f-445a-b998-7308d1ea4b5e)
-	Change owner: chown -R thehive:thehive /opt/thp
![image](https://github.com/Mutimber/SOC-Automation-Lab/assets/113706552/8f500a75-0072-44ce-8200-64f42732989d)

-	Configure thehive file: nano /etc/thehive/application.conf
  -	Change hostname to thehive public IP
  -	Change application.baseURL to public IP
  -	Change cluster name to one set earlier in cassandra 
-	Start up thehive: systemctl start thehive
-	Enable: systemctl enable thehive
-	Status: systemctl status thehive
-	If it’s down, check all three services - cassandra, elastic, thehive
![image](https://github.com/Mutimber/SOC-Automation-Lab/assets/113706552/7f327206-fd52-4bb3-9cc1-e0d78550fb66)

-	Access thehive webpage - http://142.93.190.93:9000
-	Log in to thehive with default credentials 
  -	Default Credentials on port 9000
  -	credentials are 'admin@thehive.local' with a password of 'secret'
  -	If it doesnt work, elasticsearch may be down
![image](https://github.com/Mutimber/SOC-Automation-Lab/assets/113706552/486ef158-b2d1-44be-aaa1-9d81fbcf6f4d)
-	Therefore, create a jvm.options file under /etc/elasticsearch/jvm.options.d and put the following configurations in that file.
  -Dlog4j2.formatMsgNoLookups=true
  -Xms2g
  -Xmx2g
-	nano /etc/elasticsearch/jvm.options.d/jvm.options
-	Dashboard becomes accessible from the correction 

![image](https://github.com/Mutimber/SOC-Automation-Lab/assets/113706552/175a8c7a-bf75-4a40-b005-6febd42229b9)

## Configure Wazuh
![image](https://github.com/Mutimber/SOC-Automation-Lab/assets/113706552/7f4e7fa8-4603-4737-b747-cc178a4861dc)
-	Add agent
  -	Choose Windows, our agent 
  -	Add Wazuh public IP address as the server address; 45.55.202.84
  -	Copy the code and run it on Windows Powershell - Run as admin
  Invoke-WebRequest -Uri https://packages.wazuh.com/4.x/windows/wazuh-agent-4.7.3-1.msi -OutFile ${env.tmp}\wazuh-agent; msiexec.exe /i ${env.tmp}\wazuh-agent /q WAZUH_MANAGER='45.55.202.84' WAZUH_AGENT_NAME='Robin' WAZUH_REGISTRATION_SERVER='45.55.202.84' 
  -	Start the wazuh service: net start wazuhsvc
![image](https://github.com/Mutimber/SOC-Automation-Lab/assets/113706552/a37c7eaf-be78-450b-8f51-ff2f851cd393)
![image](https://github.com/Mutimber/SOC-Automation-Lab/assets/113706552/ca81fbf8-a69e-4e86-92d7-39a75f1ca667)
  - Agent is connected to Wazuh
![image](https://github.com/Mutimber/SOC-Automation-Lab/assets/113706552/32c9ac4e-23b9-4cf5-9ec7-86ed4c6158de)

![image](https://github.com/Mutimber/SOC-Automation-Lab/assets/113706552/7e039d3c-5de0-41ac-8169-2c0a2f3c17b5)

- Click on Security Events to start querying for events

### Generate Telemetry and send traffic from Windows to Wazuh
	- In Windows, go to search bar and find ossec.conf file found in Program Files x86
	- Edit the file with notepad admin privileges, adding sysmon file location in the code and deleting security and system set ups.
	- In wazuh security events, search for sysmon
![image](https://github.com/Mutimber/SOC-Automation-Lab/assets/113706552/fbf989eb-c384-405c-a0c4-ab55a8077f5b)

- Download mimikatz to the agent
	- First  exclude mimikatz from Windows sec check	
 ![image](https://github.com/Mutimber/SOC-Automation-Lab/assets/113706552/d173de70-5b01-4b1b-b659-a9a161aa4df6)
 	- Exclude downloads folder
![image](https://github.com/Mutimber/SOC-Automation-Lab/assets/113706552/5e253ca6-bcaa-48c5-bfe2-0b78a27278a7)
- Download and extract mimikatz files
- In powershell admin terminal, cd to mimikatz x64 address: 
- Launch mimikatz
![image](https://github.com/Mutimber/SOC-Automation-Lab/assets/113706552/5ddd6226-40c3-41d8-bc1c-7ba8ae9ba02b)
- Check mimikatz events in wazuh
- Modify ossec config to log everything
![image](https://github.com/Mutimber/SOC-Automation-Lab/assets/113706552/6159c69e-3f6b-42f4-a39a-b4d5b7105ded)
- Update archives logging to true in filebeat then restart service
- In Wazuh, go to Management > Stack Management > Index Patterns > Create index for archives
![image](https://github.com/Mutimber/SOC-Automation-Lab/assets/113706552/9974bb60-22fe-44ff-9d70-b3b581116ff2)
![image](https://github.com/Mutimber/SOC-Automation-Lab/assets/113706552/727693fc-76ab-4130-b6b0-48a6a39fb3aa)
- Custom rule for mimikatz detection
![image](https://github.com/Mutimber/SOC-Automation-Lab/assets/113706552/d247d92d-b064-43df-8d30-dba2eccad86b)
![image](https://github.com/Mutimber/SOC-Automation-Lab/assets/113706552/5047498a-8a40-4a19-aef5-3f16b7411314)

## Connect Shuffle - SOAR Platform
	- Sends an alert to the Hive
	- Email the SOC Analyst
- Create an account at Shuffle.io
- Create new workflow
![image](https://github.com/Mutimber/SOC-Automation-Lab/assets/113706552/abb18943-c52f-40c3-939f-de787f5c968e)

![image](https://github.com/Mutimber/SOC-Automation-Lab/assets/113706552/0becb509-435f-493f-86e2-a6fb3f46f13a)

- Copy webhook URI and edit the integration code in /var/ossec/etc/ossec.conf file
### Integrating Wazuh with Shuffle
<integration>
<name>shuffle</name>
<hook_url>https://shuffler.io/api/v1/hooks/webhook_cbac39b1-eb55-4531-b4e8-078703a12ee3 </hook-url>
<rule_id>100002</rule_id>
<alert_format>json</alert_format>
</integration>

![image](https://github.com/Mutimber/SOC-Automation-Lab/assets/113706552/a14d9809-7f8b-430e-8acb-f628c57da0c2)
- Restart wazuh manager and check status
![image](https://github.com/Mutimber/SOC-Automation-Lab/assets/113706552/ed5db626-3d9e-4327-95ea-7419545a1709)
- Rerun mimikatz on client
![image](https://github.com/Mutimber/SOC-Automation-Lab/assets/113706552/bf332610-758e-4a69-8927-422792575384)

- View Workflows on Shuffle
![image](https://github.com/Mutimber/SOC-Automation-Lab/assets/113706552/afd0db5a-4296-4351-93d1-e22ca7c37cd4)

![image](https://github.com/Mutimber/SOC-Automation-Lab/assets/113706552/4069b6ee-9087-4c8e-a0bb-c231297e09eb)

![image](https://github.com/Mutimber/SOC-Automation-Lab/assets/113706552/0e3bdbb9-59da-41cf-953b-8d0875bceb71)

#### Workflow 
- Mimikatz alerts sent to shuffle
- Shuffle receives alert - extracts SHA256 Hash from file
- Check reputation score with VirusTotal
- Send details to thehive to create alert
- Send email to SOC analyst to begin investigation 

- Change parameters in Change me to Execution argument - hashes 
- For the Regex parameter, create a command. ChatGPT useful here

![image](https://github.com/Mutimber/SOC-Automation-Lab/assets/113706552/62b3a2d7-ac09-40b3-998a-87dd4d048091)

![image](https://github.com/Mutimber/SOC-Automation-Lab/assets/113706552/1302b9ce-1bec-4eb5-925e-12115e7dd30d)
- Upon checking workflows, SHA256 parsing is a success
 ![image](https://github.com/Mutimber/SOC-Automation-Lab/assets/113706552/98130cc6-846e-4552-a042-4fdae2c5eb11)

- Change me => SHA256_Regex
![image](https://github.com/Mutimber/SOC-Automation-Lab/assets/113706552/2e192469-b000-4443-8121-c50366d6b12d)
- Link to VirusTotal API
	- Create an account
 - copy API Key for authentication
![image](https://github.com/Mutimber/SOC-Automation-Lab/assets/113706552/4e894af9-663c-4b64-bdb8-554b0ebc1953)

 - Add VirusTotal on Shuffle and configure using the API key, SHA256-Regex and hash - generate hash report
![image](https://github.com/Mutimber/SOC-Automation-Lab/assets/113706552/90a08480-001b-47a6-af80-418240a13b23)
- We get a 404 error when we run VirusTotal hash, indicating a potential problem
- Change url to virustotal recommended one
![image](https://github.com/Mutimber/SOC-Automation-Lab/assets/113706552/1acc9522-45f7-43f3-ba71-0e0ffa29d0cc)
![image](https://github.com/Mutimber/SOC-Automation-Lab/assets/113706552/955e6ac1-d2d1-439b-b50c-90674b15b7bc)
- You can view the file's results in detail to ID how many scans show a malicious file in VirusTotal.
![image](https://github.com/Mutimber/SOC-Automation-Lab/assets/113706552/a7223a37-c95e-43f8-aaa9-a36843442bd1)

  - Now add TheHive case manager on Shuffle
  - First, create new organisation and users on theHive GUI

![image](https://github.com/Mutimber/SOC-Automation-Lab/assets/113706552/f9a1b4cc-a49a-491b-b49c-cbc7abb1751f)

- Create password for the first user account
- Create API key for the second user account
- Logout of admin account and use the first user creds to log into thehive
![image](https://github.com/Mutimber/SOC-Automation-Lab/assets/113706552/9e37bf5c-859b-4f6c-8530-96d7b0f26e20)
- Authenticate thehive using the API Key from above and add thehive public IP:9000
![image](https://github.com/Mutimber/SOC-Automation-Lab/assets/113706552/4cf2bf66-1e15-487b-a727-4fb487761655)
- Add new firewall rule to allow TCP access to thehive using port 9000 from all IPV4

![image](https://github.com/Mutimber/SOC-Automation-Lab/assets/113706552/5f8d7441-cede-4fe8-b7cb-25a2949d0bda)
- With correct configuration on various data fields, Shuffle should send alerts to the thehive GUI as shown below
![image](https://github.com/Mutimber/SOC-Automation-Lab/assets/113706552/e525bc7b-8cae-4335-8cc0-42efbe0f29d6)
![image](https://github.com/Mutimber/SOC-Automation-Lab/assets/113706552/c485174f-575c-4388-bf1a-85b8a920b4d5)
- Now link Email on Shuffle
![image](https://github.com/Mutimber/SOC-Automation-Lab/assets/113706552/04c1ef5b-3dc9-4188-8963-4f784f053945)
- Add email address, body text, and subject and run workflow to email the SOC analyst

## Build a an Automatic Response
## Use Ubuntu machine
 - TBD











