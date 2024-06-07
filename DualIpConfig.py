#!/usr/bin/python3
import pexpect
import os
from pexpect import pxssh
import subprocess
import time
import re
import sys
import logging


subprocess.run(['pip3', 'install', 'requests'], check=True)
# subprocess.run(['pip3', 'install','--upgrade', 'requests'], check=True)


import requests



# Set environment variables
os.environ['http_proxy'] = 'http://10.144.1.10:8080'
os.environ['https_proxy'] = 'http://10.144.1.10:8080'

# Upgrade pip and setuptools
subprocess.run(['pip3', 'install', '--upgrade', 'pip'], check=True)
subprocess.run(['pip3', 'install', '--upgrade', 'setuptools'], check=True)

# Install paramiko
subprocess.run(['pip3', 'install', 'paramiko'], check=True)

import paramiko

def scp_file_between_servers(source_host, source_username, source_password, source_path,
                             destination_host, destination_username, destination_password, destination_path):
    try:
        # Create SSH client for source server
        source_ssh = paramiko.SSHClient()
        source_ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        source_ssh.connect(source_host, username=source_username, password=source_password)

        # Create SCP client for source server
        source_scp = source_ssh.open_sftp()

        # Create SSH client for destination server
        destination_ssh = paramiko.SSHClient()
        destination_ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        destination_ssh.connect(destination_host, username=destination_username, password=destination_password)

        # Create SCP client for destination server
        destination_scp = destination_ssh.open_sftp()

        # Copy the file from source to destination
        source_scp.get(source_path, destination_path)

        # Close connections
        source_scp.close()
        source_ssh.close()
        destination_scp.close()
        destination_ssh.close()

        print(f"File copied successfully from {source_host}:{source_path} to {destination_host}:{destination_path}")

    except Exception as e:
        print(f"Error: {e}")


def insert_resource_rootpath(local_host, username, password, file_path, position_to_insert, new_line_to_insert):
    try:
        s = pxssh.pxssh(options={"StrictHostKeyChecking": "no", "UserKnownHostsFile": "/dev/null"})
        s.login(local_host, username, password, auto_prompt_reset=False)

        with open(file_path, 'r') as file:
            lines = file.readlines()

        lines.insert(position_to_insert - 1, f"\t{new_line_to_insert}\n")

        with open(file_path, 'w') as file:
            file.writelines(lines)

        s.logout()

        print(f"{new_line_to_insert} is inserted ")

    except IOError as e:
        print(f"Error reading/writing file: {e}")


def restart_server(local_host, username, password, target_user, command_to_run, bin_directory):
    try:
        s = pxssh.pxssh(options={"StrictHostKeyChecking": "no", "UserKnownHostsFile": "/dev/null"})
        s.login(local_host, username, password, auto_prompt_reset=False)
        os.chdir(bin_directory)

        subprocess.run(['su', '-c', command_to_run, target_user], check=True)
        time.sleep(300)
        s.logout()

    except subprocess.CalledProcessError as e:
        print(f"Error switching user: {e}")


def check_server_status_with_pattern(local_host, username, password, log_file_path, status_pattern):
    try:
        s = pxssh.pxssh(options={"StrictHostKeyChecking": "no", "UserKnownHostsFile": "/dev/null"})
        s.login(local_host, username, password, auto_prompt_reset=False)
        with open(log_file_path, 'r') as log_file:
            log_content = log_file.read()

            if re.search(status_pattern, log_content):
                print(f"Server status matches the pattern: {status_pattern}")
                return True
            else:
                print(f"Server status does not match the pattern: {status_pattern}")
                return False
        s.logout()

    except FileNotFoundError:
        print(f"Log file not found: {log_file_path}")
        return False


def check_server_status_continuously(log_file_path, status_keyword, poll_interval=5):
    while True:
        if check_server_status_with_pattern(local_host, username, password, log_file_path, status_keyword):
            print("Server is active. Exiting.")
            break
        else:
            print("Server is not active. Waiting for the next check...")
            time.sleep(poll_interval)


def update_nms_server(local_host, username, password, nameserver_path):
    try:
        s = pxssh.pxssh(options={"StrictHostKeyChecking": "no", "UserKnownHostsFile": "/dev/null"})
        s.login(local_host, username, password, auto_prompt_reset=False)

        with open(nameserver_path, 'r') as file:
            lines = file.readlines()

        new_lines = ['  <CmmDualIpMgmt>\n',
                     '\t<entry siteId="10.39.144.84" oamAccessIp="10.39.144.84"/>\n',
                     '\t<entry siteId="10.39.144.88" oamAccessIp="10.39.144.88"/>\n',
                     '\t<entry siteId="10.39.140.135" oamAccessIp="10.39.140.135"/>\n',
                     '\t<entry siteId="10.39.140.140" oamAccessIp="10.39.140.140"/>\n',
                     '\t<entry siteId="10.39.140.145" oamAccessIp="10.39.140.145"/>\n',
                     '\t<entry siteId="10.39.140.158" oamAccessIp="10.39.140.158"/>\n',
                     '\t<entry siteId="10.39.140.171" oamAccessIp="10.39.140.171"/>\n',
                     '\t<entry siteId="10.39.140.180" oamAccessIp="10.39.140.180"/>\n',
                     '\t<entry siteId="10.39.140.189" oamAccessIp="10.39.140.189"/>\n',
                     '\t<entry siteId="10.39.140.198" oamAccessIp="10.39.140.198"/>\n',
                     '  </CmmDualIpMgmt>\n']
        index = lines.index('</configuration>\n')
        lines[index:index] = new_lines

        with open(nameserver_path, 'w') as file:
            file.writelines(lines)

        s.logout()
        print("nms-server.xml is updated ")

    except IOError as e:
        print(f"Error reading/writing file: {e}")


def run_readconfig(local_host, username, password, target_user, read_config_command, bin_directory):
    try:
        s = pxssh.pxssh(options={"StrictHostKeyChecking": "no", "UserKnownHostsFile": "/dev/null"})
        s.login(local_host, username, password, auto_prompt_reset=False)
        os.chdir(bin_directory)

        subprocess.run(['su', '-c', read_config_command, target_user], check=True)
        print(f"Command executed 1 time")
        time.sleep(30)
        subprocess.run(['su', '-c', read_config_command, target_user], check=True)
        print(f"Command executed 2 times")
        time.sleep(10)
        s.logout()

    except subprocess.CalledProcessError as e:
        print(f"Error switching user: {e}")


def send_xml_to_api(api_url, data):
    try:
        headers = {'Content-Type': 'test/xml;charset=UTF-8'}

        # Make a POST request to the API with XML data
        response = requests.post(api_url, headers=headers, data=data, verify=False)

        if response.status_code == 200:
            logging.info("XML data sent successfully")
            print(response.status_code)
            print(response.text)
        else:
            logging.error(f"Failed to send XML data. Status Code: {response.status_code}")
            logging.error(response.text)


    except Exception as e:

        logging.error(f"Error sending XML data: {e}")
        logging.exception("Exception traceback:")



if __name__ == "__main__":

    if len(sys.argv) != 2:
        print("Usage: ./pp.py <NFMM-IP> <CMM-IP>")
        sys.exit(1)
    logging.basicConfig(level=logging.INFO)

    # Extract the IP address and the second input from the command-line arguments
    local_host = sys.argv[1]
    inputs = []

    num_inputs = int(input("Enter the number of CMM ATEs you want to discover: "))

    # Loop to take inputs and store them in the list
    for i in range(num_inputs):
        value = input("Enter IP address of CMM ATE {}: ".format(i + 1))
        inputs.append(value)

    # Display the inputs
    print("Inputs:", inputs)

    # Extract the IP address from the command-line argument


    # Now you can use the nfm_ip variable in the rest of your script
    print(f"Provided IP address: {local_host}")
    file_name = "dualIpMgmt.jar"
    rpath = '/root/'
    remote_host = "10.93.99.48"
    remote_path = rpath + file_name
    local_path = ("/opt/5620sam/server/nms/jboss-eap/sam-specific/externalmodules/mainservermodules/com/alu/server"
                  "/default/main/")
    username = "root"
    password = "arthur"

    source_host = "10.93.99.48"
    xmlfile_name = "module.xml"
    source_username = "root"
    source_password = "arthur"
    source_path = "/root/dualIpMgmt.jar"
    destination_username = "root"
    destination_password = "arthur"

    file_path = local_path + xmlfile_name
    position_to_insert = 14  # Specify the position where you want to insert the line
    new_line_to_insert = '<resource-root path="dualIpMgmt.jar"/>'
    bin_directory = "/opt/nsp/nfmp/server/nms/bin"
    command_to_run = './nmsserver.bash force_restart'
    target_user = 'nsp'
    status_pattern = r'NFM-P Service is Active'
    log_file_path = '/opt/nsp/nfmp/server/nms/log/server/server_console.log'
    nameserver_path = '/opt/nsp/nfmp/server/nms/config/nms-server.xml'
    read_config_command = './nmsserver.bash read_config'
    destination_path = ("/opt/5620sam/server/nms/jboss-eap/sam-specific/externalmodules/mainservermodules/com/alu"
                        "/server/default/main/dualIpMgmt.jar")

    # Specify the API URL and XML data
    # nfmm_ip = "10.93.28.185"
    # url = "http://{}/xmlapi/invoke".format(node_ip)
    url = f"https://{local_host}:8443/xmlapi/invoke"
    xml_data = '''<?xml version="1.0" encoding="UTF-8"?>
<SOAP:Envelope
xmlns:SOAP="http://schemas.xmlsoap.org/soap/envelope/"
xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
<SOAP:Header>
<header xmlns="xmlapi_1.0">
<security>
<user>SAMqa</user>
<password hashed="false">5620Sam!</password>
</security>
<requestID>client1:0</requestID>
</header>
</SOAP:Header>
<SOAP:Body>
<generic.GenericObject.configureChildInstance xmlns="xmlapi_1.0">

  <deployer>immediate</deployer>
  <distinguishedName>SR Local User</distinguishedName>
  <childConfigInfo>
    <sitesec.LocalUser>
      <actionMask>
        <bit>create</bit>
      </actionMask>
      <lastLogin>0</lastLogin>
      <ne3sPassword></ne3sPassword>
      <access>
        <bit>snmp</bit>
      </access>
      <allowedIpAddresses></allowedIpAddresses>
      <description></description>
      <policyMode>static</policyMode>
      <snmpAccessPrivilege>AdminGroup</snmpAccessPrivilege>
      <loginFailures>0</loginFailures>
      <isPasswordEncrypted>true</isPasswordEncrypted>
      <configurationAction>failIfExists</configurationAction>
      <password></password>
      <snmpAuthProtocol>md5</snmpAuthProtocol>
      <linuxPassword2></linuxPassword2>
      <templateObject></templateObject>
      <consoleLoginExecFile></consoleLoginExecFile>
      <password2></password2>
      <consoleMemberProfile8>N/A</consoleMemberProfile8>
      <id>0</id>
      <consoleCannotChangePassword>false</consoleCannotChangePassword>
      <linuxPassword></linuxPassword>
      <passwordAging>0</passwordAging>
      <consoleMemberProfile2>N/A</consoleMemberProfile2>
      <consoleMemberProfile3>N/A</consoleMemberProfile3>
      <homeDirectory></homeDirectory>
      <isRestrictedToHome>false</isRestrictedToHome>
      <consoleMemberProfile1>default</consoleMemberProfile1>
      <consoleMemberProfile6>N/A</consoleMemberProfile6>
      <linuxOldPassword></linuxOldPassword>
      <consoleMemberProfile7>N/A</consoleMemberProfile7>
      <consoleMemberProfile4>N/A</consoleMemberProfile4>
      <consoleMemberProfile5>N/A</consoleMemberProfile5>
      <nwi3Password></nwi3Password>
      <displayedName>cmm_privUser1</displayedName>
      <snmpAuthPassword>authUser</snmpAuthPassword>
      <userIdAgingInterval>60</userIdAgingInterval>
      <consoleNewPasswordAtLogin>false</consoleNewPasswordAtLogin>
      <nwi3Password2></nwi3Password2>
      <snmpAuthPassword2>authUser</snmpAuthPassword2>
      <snmpPrivPassword2>privUser</snmpPrivPassword2>
      <ne3sPassword2></ne3sPassword2>
      <snmpPrivPassword>privUser</snmpPrivPassword>
      <userLocalLockout>true</userLocalLockout>
      <sessionInactivityTimeout>0</sessionInactivityTimeout>
      <snmpRowStatus>enabled</snmpRowStatus>
      <rowStatus>enabled</rowStatus>
      <accessPrivilege>observer</accessPrivilege>
      <snmpPrivProtocol>aes128</snmpPrivProtocol>
    </sitesec.LocalUser>
  </childConfigInfo>
</generic.GenericObject.configureChildInstance>
</SOAP:Body>
</SOAP:Envelope>
    '''

    xml_data1 = '''<?xml version="1.0" encoding="UTF-8"?>
    <SOAP:Envelope
    xmlns:SOAP="http://schemas.xmlsoap.org/soap/envelope/"
    xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
    <SOAP:Header>
    <header xmlns="xmlapi_1.0">
    <security>
    <user>SAMqa</user>
    <password hashed="false">5620Sam!</password>
    </security>
    <requestID>client1:0</requestID>
    </header>
    </SOAP:Header>
    <SOAP:Body>
    <generic.GenericObject.configureInstance xmlns="xmlapi_1.0">
     
  <deployer>immediate</deployer>
  <distinguishedName>pollerManager</distinguishedName>
  <configInfo>
    <snmp.PollerManager>
	<actionMask>
            <bit>modify</bit>
          </actionMask>
          <objectFullName>pollerManager</objectFullName>
          <pollingSyncTime>79200000</pollingSyncTime>
          <targetName>005056954707:main1</targetName>

          <ftpResyncAdminState>down</ftpResyncAdminState>

          <peerTargetName>005056954707:main2</peerTargetName>
          <snmpStreamingAdminState>up</snmpStreamingAdminState>


          <administrativeState>up</administrativeState>
          <topologyScanInterval>1hour_30minutes</topologyScanInterval>
          <basePollingInterval>5minutes</basePollingInterval>


          <children-Set>
            <security.MediationPolicy>
              <actionMask>
                <bit>create</bit>
              </actionMask>
     
        
          <netconfUserObjectPointer></netconfUserObjectPointer>
          <netconfReadTimeout>120</netconfReadTimeout>
          <ftpConnectTimeout>10</ftpConnectTimeout>
          <userObjectPointer>SR Local User:cmm_privUser1</userObjectPointer>
          <fileTransferType>secure</fileTransferType>
          <gRpcPassword>disable-gRPC-updates</gRpcPassword>
          <cliPreLoginUserName>cli</cliPreLoginUserName>
          <gRpcPort>57400</gRpcPort>
		  <samRegistrationUserName></samRegistrationUserName>												 
          <corbaResponseTimeout>120</corbaResponseTimeout>
          <lteNe3sSessionManagerUserObjectPointer></lteNe3sSessionManagerUserObjectPointer>
          <snmpTimeout>100000</snmpTimeout>
		  <agentHttpPort>8443</agentHttpPort>
          <id>2</id>
          <netconfUserName>sam5620</netconfUserName>
          
          <agentHttpPasswd>wspassword</agentHttpPasswd>
          <cliCommunicationProtocol>ssh2</cliCommunicationProtocol>
          <tl1Port>6084</tl1Port>
          <community>private</community>
          <sshCommunicationPort>22</sshCommunicationPort>
          <ftpUserName>admin</ftpUserName>
          <tl1TransportProtocol>ssh2</tl1TransportProtocol>
          <cliPassword>CMMsam@1234</cliPassword>
          <snmpPort>161</snmpPort>
          <ftpServerPassword>admin</ftpServerPassword>
          <netconfUserPassword>CMMsam@1234</netconfUserPassword>
          <samRegistrationPassword></samRegistrationPassword>
          <lteOmsSessionManagerUserObjectPointer></lteOmsSessionManagerUserObjectPointer>
          <cliIdleTimeout>3600</cliIdleTimeout>
          <cliPreLoginPassword>cli</cliPreLoginPassword>
          <netconfPort>830</netconfPort>
          <cliUserName>sam5620</cliUserName>
          <ftpUserPassword>admin</ftpUserPassword>
          <netconfUserType>manually</netconfUserType>
          <agentHttpUserName>wsuser</agentHttpUserName>
          <securityModel>snmpv3</securityModel>
          <snmpRetry>1</snmpRetry>
          <ftpReadTimeout>50</ftpReadTimeout>
          <cliConnectTimeout>30000</cliConnectTimeout>
          <netconfTransportProtocol>ssh2</netconfTransportProtocol>
          <gRpcUserName>admin</gRpcUserName>
          <gRpcConnectionTimeout>10</gRpcConnectionTimeout>
          <sshUserName>tl13082</sshUserName>
          <tl1UserName>admin</tl1UserName>
          <tl1ConnectTimeout>10</tl1ConnectTimeout>
          <ftpServerUsername>admin</ftpServerUsername>
          <displayedName>CMM</displayedName>
          <netconfConnectTimeout>10</netconfConnectTimeout>
          <gRpcSecure>true</gRpcSecure>
          <netconfRetry>1</netconfRetry>
          <tl1UserPassword>admin</tl1UserPassword>
        </security.MediationPolicy>
      </children-Set>
    </snmp.PollerManager>
  </configInfo>
</generic.GenericObject.configureInstance>


    </SOAP:Body>
    </SOAP:Envelope>
    '''



    # Call the function to send XML data


    scp_file_between_servers(source_host, source_username, source_password, source_path,
                             local_host, destination_username, destination_password, destination_path)
    insert_resource_rootpath(local_host, username, password, file_path, position_to_insert, new_line_to_insert)
    restart_server(local_host, username, password, target_user, command_to_run, bin_directory)
    check_server_status_continuously(log_file_path, status_pattern)
    check_server_status_with_pattern(local_host, username, password, log_file_path, status_pattern)
    update_nms_server(local_host, username, password, nameserver_path)
    run_readconfig(local_host, username, password, target_user, read_config_command, bin_directory)

    send_xml_to_api(url, xml_data)
    send_xml_to_api(url, xml_data1)


    for item in inputs:
            xml_data2 = f'''<?xml version="1.0" encoding="UTF-8"?>
            <SOAP:Envelope
            xmlns:SOAP="http://schemas.xmlsoap.org/soap/envelope/"
            xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
            <SOAP:Header>
            <header xmlns="xmlapi_1.0">
            <security>
            <user>SAMqa</user>
            <password hashed="false">5620Sam!</password>
            </security>
            <requestID>client1:0</requestID>
            </header>
            </SOAP:Header>
            <SOAP:Body>
            <generic.GenericObject.configureInstance xmlns="xmlapi_1.0">
                     <deployer>immediate</deployer>
                     <synchronousDeploy>false</synchronousDeploy>
                     <deployRetries>1</deployRetries>
                     <clearOnDeployFailure>false</clearOnDeployFailure>
                     <distinguishedName>network:topology</distinguishedName>
                     <configInfo>
                        <netw.Topology>
                           <actionMask>
                              <bit>modify</bit>
                           </actionMask>
                           <objectFullName>network:topology</objectFullName>
                           <children-Set>
                              <netw.TopologyDiscoveryRule>
                                 <actionMask>
                                    <bit>create</bit>
                                 </actionMask>
                                 <backupPolicyPointer>network:backup-policy-1</backupPolicyPointer>
                                 <dcInterconnectPointer />
                                 <writeMediationPolicyId>2</writeMediationPolicyId>
                                 <statsPollingPolicyId>2</statsPollingPolicyId>
                                 <description>CMM discovery</description>
                                 <discoveryProtocol>snmp</discoveryProtocol>
                                 <topologyGroupPointer>topologyGroup:Network-Network</topologyGroupPointer>
                                 <revertOlcState>false</revertOlcState>
                                 <administrativeState>up</administrativeState>
                                 <dualReadMediationPolicyId>2</dualReadMediationPolicyId>
                                 <dualTrapMediationPolicyId>2</dualTrapMediationPolicyId>
                                 <id>0</id>
                                 <securityMediationPolicyId>2</securityMediationPolicyId>
                                 <trapMediationPolicyId>2</trapMediationPolicyId>

                                 <dualWriteMediationPolicyId>2</dualWriteMediationPolicyId>
                                 <standbyCpmPingPolicyId>2</standbyCpmPingPolicyId>
                                 <defaultExternalEms />
                                 <ipAddressType>ipv4</ipAddressType>
                                 <olcState>inService</olcState>
                                 <inBandPingPolicyId>2</inBandPingPolicyId>
                                 <scanInterval>global</scanInterval>
                                 <readMediationPolicyId>2</readMediationPolicyId>
                                 <postDiscoveryActionPointer />
                                 <outOfBandPingPolicyId>2</outOfBandPingPolicyId>
                                 <children-Set>
                                    <netw.TopologyDiscoveryRuleSpan>
                                       <actionMask>
                                          <bit>create</bit>
                                       </actionMask>
                                       <spanId>2</spanId>
                                    </netw.TopologyDiscoveryRuleSpan>
                                    <netw.TopologyDiscoveryRuleElement>
                                       <actionMask>
                                          <bit>create</bit>
                                       </actionMask>
                                       <usage>include</usage>
                                       <ipAddress>{item}</ipAddress>
                                       <ipAddressType>ipv4</ipAddressType>
                                       <maskBits>32</maskBits>
                                    </netw.TopologyDiscoveryRuleElement>
                                 </children-Set>
                              </netw.TopologyDiscoveryRule>
                           </children-Set>
                        </netw.Topology>
                     </configInfo>
                  </generic.GenericObject.configureInstance>

            </SOAP:Body>
            </SOAP:Envelope>

            
            '''

            send_xml_to_api(url, xml_data2)

            xml_data3 = f'''<SOAP:Envelope xmlns:SOAP="http://schemas.xmlsoap.org/soap/envelope/" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
                <SOAP:Header>
                    <header xmlns="xmlapi_1.0">
                        <security>
                            <user>SAMqa</user>
                            <password hashed="false">5620Sam!</password>
                        </security>
                        <requestID>client1:0</requestID>
                    </header>
                </SOAP:Header>
                <SOAP:Body>
                    <find xmlns="xmlapi_1.0">
                        <fullClassName>netw.NetworkElement</fullClassName>
                        <filter>
                            <equal name="ipAddress" value='${item}'/>
                        </filter>
                        <resultFilter>
                            <attribute>resyncStatus</attribute>
                            <attribute>siteName</attribute>
                            <attribute>siteId</attribute>
                            <children/>
                        </resultFilter>
                    </find>
                </SOAP:Body>
            </SOAP:Envelope>
            '''
            send_xml_to_api(url, xml_data3)