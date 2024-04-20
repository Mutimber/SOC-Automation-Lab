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


