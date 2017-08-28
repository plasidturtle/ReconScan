#!/usr/bin/env python
import subprocess
import multiprocessing
from multiprocessing import Process, Queue
import os
import time
import fileinput
import atexit
import sys
import socket
import shutil
import requests
from requests.exceptions import ConnectionError

start = time.time()

class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'


# Creates a function for multiprocessing. Several things at once.
def multProc(targetin, scanip, port):
    jobs = []
    p = multiprocessing.Process(target=targetin, args=(scanip,port))
    jobs.append(p)
    p.start()
    return

def connect_to_port(ip_address, port, service):

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((ip_address, int(port)))
    banner = s.recv(1024)

    if service == "ftp":
        s.send("USER anonymous\r\n")
        user = s.recv(1024)
        s.send("PASS anonymous\r\n")
        password = s.recv(1024)
        total_communication = banner + "\r\n" + user + "\r\n" + password
        write_to_file(ip_address, "ftp-connect", total_communication)
    elif service == "smtp":
        total_communication = banner + "\r\n"
        write_to_file(ip_address, "smtp-connect", total_communication)
    elif service == "ssh":
        total_communication = banner
        write_to_file(ip_address, "ssh-connect", total_communication)
    elif service == "pop3":
        s.send("USER root\r\n")
        user = s.recv(1024)
        s.send("PASS root\r\n")
        password = s.recv(1024)
        total_communication = banner +  user +  password
        write_to_file(ip_address, "pop3-connect", total_communication)
    s.close()

def Write_to_file_search_text(enum_type):
    searchText = 'TestText'
    if enum_type == "portscan":
        searchText = "INSERTTCPSCAN"
    elif enum_type == "dirb":
        searchText = "INSERTDIRBSCAN"
    elif enum_type == "nikto":
        searchText = "INSERTNIKTOSCAN"
    elif enum_type == "ftp-connect":
        searchText = "INSERTFTPTEST"
    elif enum_type == "smtp-connect":
        searchText = "INSERTSMTPCONNECT"
    elif enum_type == "ssh-connect":
        searchText = "INSERTSSHCONNECT"
    elif enum_type == "pop3-connect":
        searchText = "INSERTPOP3CONNECT"
    elif enum_type == "curl":
        searchText = "INSERTCURLHEADER"
    else:
        print "Text to replace in file is invalid"
    return searchText

def write_to_file(ip_address, enum_type, data):

    file_path_linux = '/root/oscp/exam/%s/mapping-linux.md' % (ip_address)
    file_path_windows = '/root/oscp/exam/%s/mapping-windows.md' % (ip_address)
    paths = [file_path_linux, file_path_windows]
    print bcolors.OKGREEN + "INFO: Writing " + enum_type + " to template files:\n " + file_path_linux + "   \n" + file_path_windows + bcolors.ENDC
    TextToFind = Write_to_file_search_text(enum_type)
    for path in paths:
        try:
            for line in fileinput.FileInput(path,inplace=1):
                line = line.replace(TextToFind,data)
                sys.stdout.write(line)
        except:
            print "Error Writing to " + path
    return

def updateStatus(scan_type, ip_address, status):
    file_path = '/root/oscp/exam/%s/Status.txt' % (ip_address)
    replace_Text = scan_type + " : " + status
    for line in fileinput.FileInput(file_path, inplace=1):
        lineList = line.split()
        line = line.replace(scan_type, replace_Text)
        sys.stdout.write(line)

    for line in fileinput.FileInput(file_path):
        current_status = line.split(":")
        if len(current_status) > 2 :
            print line

def dirb(ip_address, port, url_start):
    print bcolors.HEADER + "INFO: Starting dirb scan for " + ip_address + bcolors.ENDC
    DIRBSCAN = "dirb %s://%s:%s -w -o /root/oscp/exam/%s/dirb-%s.txt -r" % (url_start, ip_address, port, ip_address, ip_address)
    print bcolors.HEADER + DIRBSCAN + bcolors.ENDC
    updateStatus("Dirb", ip_address, "Running")
    results_dirb = subprocess.check_output(DIRBSCAN, shell=True)
    print bcolors.OKGREEN + "INFO: RESULT BELOW - Finished with dirb scan for " + ip_address + bcolors.ENDC
    updateStatus("Dirb", ip_address, "Done")
    print results_dirb
    write_to_file(ip_address, "dirb", results_dirb)
    return

def nikto(ip_address, port, url_start):
    print bcolors.HEADER + "INFO: Starting nikto scan for " + ip_address + bcolors.ENDC
    NIKTOSCAN = "nikto -h %s://%s -o /root/oscp/exam/%s/nikto-%s-%s.txt" % (url_start, ip_address, ip_address, url_start, ip_address)
    print bcolors.HEADER + NIKTOSCAN + bcolors.ENDC
    updateStatus("Nikto", ip_address, "Running")
    results_nikto = subprocess.check_output(NIKTOSCAN, shell=True)
    updateStatus("Nikto", ip_address, "Done")
    print bcolors.OKGREEN + "INFO: RESULT BELOW - Finished with NIKTO-scan for " + ip_address + bcolors.ENDC
    print results_nikto
    write_to_file(ip_address, "nikto", results_nikto)
    return


def httpEnum(ip_address, port):
    print bcolors.HEADER + "INFO: Detected http on " + ip_address + ":" + port + bcolors.ENDC
    print bcolors.HEADER + "INFO: Performing nmap web script scan for " + ip_address + ":" + port + bcolors.ENDC

    dirb_process = multiprocessing.Process(target=dirb, args=(ip_address,port,"http"))
    dirb_process.start()
    nikto_process = multiprocessing.Process(target=nikto, args=(ip_address,port,"http"))
    nikto_process.start()
    url = "http://" + ip_address
    try:
        CURLSCAN = requests.get(url)
        print CURLSCAN.url + " " + " with Status Code: " + str(CURLSCAN.status_code)
        for key in CURLSCAN.headers:
            print key + " : " + CURLSCAN.headers[key]
    except ConnectionError:
        print 'Failed to open url, ' + url
    write_to_file(ip_address, "curl", curl_results)

    HTTPSCAN = "nmap -sV -Pn -vv -p %s --script=http-vhosts,http-userdir-enum,http-apache-negotiation,http-backup-finder,http-config-backup,http-default-accounts,http-methods,http-method-tamper,http-passwd,http-robots.txt,http-devframework,http-enum,http-frontpage-login,http-git,http-iis-webdav-vuln,http-php-version,http-robots.txt,http-shellshock,http-vuln-cve2015-1635 -oN /root/oscp/exam/%s/%s_http.nmap %s" % (port, ip_address, ip_address, ip_address)
    print bcolors.HEADER + HTTPSCAN + bcolors.ENDC
    http_results = subprocess.check_output(HTTPSCAN, shell=True)
    print bcolors.OKGREEN + "INFO: RESULT BELOW - Finished with HTTP-SCAN for " + ip_address + bcolors.ENDC
    print http_results


    return

def httpsEnum(ip_address, port):
    print bcolors.HEADER + "INFO: Detected https on " + ip_address + ":" + port + bcolors.ENDC
    print bcolors.HEADER + "INFO: Performing nmap web script scan for " + ip_address + ":" + port + bcolors.ENDC

    dirb_process = multiprocessing.Process(target=dirb, args=(ip_address,port,"https"))
    dirb_process.start()
    nikto_process = multiprocessing.Process(target=nikto, args=(ip_address,port,"https"))
    nikto_process.start()

    SSLSCAN = "sslscan %s:%s >> /root/oscp/exam/%s/ssl_scan_%s" % (ip_address, port, ip_address, ip_address)
    print bcolors.HEADER + SSLSCAN + bcolors.ENDC
    ssl_results = subprocess.check_output(SSLSCAN, shell=True)
    print bcolors.OKGREEN + "INFO: CHECK FILE - Finished with SSLSCAN for " + ip_address + bcolors.ENDC

    HTTPSCANS = "nmap -sV -Pn -vv -p %s --script=http-vhosts,http-userdir-enum,http-apache-negotiation,http-backup-finder,http-config-backup,http-default-accounts,http-methods,http-method-tamper,http-passwd,http-robots.txt,http-devframework,http-enum,http-frontpage-login,http-git,http-iis-webdav-vuln,http-php-version,http-robots.txt,http-shellshock,http-vuln-cve2015-1635 -oN /root/oscp/exam/%s/%s_http.nmap %s" % (port, ip_address, ip_address, ip_address)
    print bcolors.HEADER + HTTPSCANS + bcolors.ENDC
    https_results = subprocess.check_output(HTTPSCANS, shell=True)
    print bcolors.OKGREEN + "INFO: RESULT BELOW - Finished with HTTPS-scan for " + ip_address + bcolors.ENDC
    print https_results
    return

def mssqlEnum(ip_address, port):
    print bcolors.HEADER + "INFO: Detected MS-SQL on " + ip_address + ":" + port + bcolors.ENDC
    print bcolors.HEADER + "INFO: Performing nmap mssql script scan for " + ip_address + ":" + port + bcolors.ENDC
    MSSQLSCAN = "nmap -sV -Pn -p %s --script=ms-sql-info,ms-sql-config,ms-sql-dump-hashes --script-args=mssql.instance-port=1433,smsql.username-sa,mssql.password-sa -oN /root/oscp/exam/%s/mssql_%s.nmap %s" % (port, ip_address, ip_address)
    print bcolors.HEADER + MSSQLSCAN + bcolors.ENDC
    mssql_results = subprocess.check_output(MSSQLSCAN, shell=True)
    print bcolors.OKGREEN + "INFO: RESULT BELOW - Finished with MSSQL-scan for " + ip_address + bcolors.ENDC
    print mssql_results
    return


def smtpEnum(ip_address, port):
    print bcolors.HEADER + "INFO: Detected smtp on " + ip_address + ":" + port  + bcolors.ENDC
    connect_to_port(ip_address, port, "smtp")
    SMTPSCAN = "nmap -sV -Pn -p %s --script=smtp-commands,smtp-enum-users,smtp-vuln-cve2010-4344,smtp-vuln-cve2011-1720,smtp-vuln-cve2011-1764 %s -oN /root/oscp/exam/%s/smtp_%s.nmap" % (port, ip_address, ip_address, ip_address)
    print bcolors.HEADER + SMTPSCAN + bcolors.ENDC
    smtp_results = subprocess.check_output(SMTPSCAN, shell=True)
    print bcolors.OKGREEN + "INFO: RESULT BELOW - Finished with SMTP-scan for " + ip_address + bcolors.ENDC
    print smtp_results
    # write_to_file(ip_address, "smtp", smtp_results)
    return

def smbNmap(ip_address, port):
    print "INFO: Detected SMB on " + ip_address + ":" + port
    smbNmap = "nmap --script=smb-enum-shares.nse,smb-ls.nse,smb-enum-users.nse,smb-mbenum.nse,smb-os-discovery.nse,smb-security-mode.nse,smbv2-enabled.nse,smb-vuln-cve2009-3103.nse,smb-vuln-ms06-025.nse,smb-vuln-ms07-029.nse,smb-vuln-ms08-067.nse,smb-vuln-ms10-054.nse,smb-vuln-ms10-061.nse,smb-vuln-regsvc-dos.nse,smbv2-enabled.nse %s -oN /root/oscp/exam/%s/smb_%s.nmap" % (ip_address, ip_address, ip_address)
    smbNmap_results = subprocess.check_output(smbNmap, shell=True)
    print bcolors.OKGREEN + "INFO: RESULT BELOW - Finished with SMB-Nmap-scan for " + ip_address + bcolors.ENDC
    print smbNmap_results
    return

def smbEnum(ip_address, port):
    print "INFO: Detected SMB on " + ip_address + ":" + port
    enum4linux = "enum4linux -a %s > /root/oscp/exam/%s/enum4linux_%s" % (ip_address, ip_address, ip_address)
    enum4linux_results = subprocess.check_output(enum4linux, shell=True)
    print bcolors.OKGREEN + "INFO: CHECK FILE - Finished with ENUM4LINUX-Nmap-scan for " + ip_address + bcolors.ENDC
    print enum4linux_results
    return

def ftpEnum(ip_address, port):
    print bcolors.HEADER + "INFO: Detected ftp on " + ip_address + ":" + port  + bcolors.ENDC
    connect_to_port(ip_address, port, "ftp")
    FTPSCAN = "nmap -sV -Pn -vv -p %s --script=ftp-anon,ftp-bounce,ftp-libopie,ftp-proftpd-backdoor,ftp-vsftpd-backdoor,ftp-vuln-cve2010-4221 -oN '/root/oscp/exam/%s/ftp_%s.nmap' %s" % (port, ip_address, ip_address, ip_address)
    print bcolors.HEADER + FTPSCAN + bcolors.ENDC
    results_ftp = subprocess.check_output(FTPSCAN, shell=True)
    print bcolors.OKGREEN + "INFO: RESULT BELOW - Finished with ENUM4LINUX-Nmap-scan for " + ip_address + bcolors.ENDC
    print results_ftp
    return

def udpScan(ip_address):
    print bcolors.HEADER + "INFO: Detected UDP on " + ip_address + bcolors.ENDC
    UDPSCAN = "nmap -vv -Pn -A -sC -sU -T 4 --top-ports 200 -oN '/root/oscp/exam/%s/udp_%s.nmap' %s"  % (ip_address, ip_address, ip_address)
    print bcolors.HEADER + UDPSCAN + bcolors.ENDC
    udpscan_results = subprocess.check_output(UDPSCAN, shell=True)
    print bcolors.OKGREEN + "INFO: RESULT BELOW - Finished with UDP-Nmap scan for " + ip_address + bcolors.ENDC
    print udpscan_results
    UNICORNSCAN = "unicornscan -mU -v -I %s > /root/oscp/exam/%s/unicorn_udp_%s.txt" % (ip_address, ip_address, ip_address)
    unicornscan_results = subprocess.check_output(UNICORNSCAN, shell=True)
    print bcolors.OKGREEN + "INFO: CHECK FILE - Finished with UNICORNSCAN for " + ip_address + bcolors.ENDC


def sshScan(ip_address, port):
    print bcolors.HEADER + "INFO: Detected SSH on " + ip_address + ":" + port  + bcolors.ENDC
    connect_to_port(ip_address, port, "ssh")

def pop3Scan(ip_address, port):
    print bcolors.HEADER + "INFO: Detected POP3 on " + ip_address + ":" + port  + bcolors.ENDC
    connect_to_port(ip_address, port, "pop3")

def snmpEnum(ip_address, port):
    SNMPCHECK = "snmp-check %s > /root/oscp/exam/%s/snmpcheck.txt" % (ip_address, ip_address)
    subprocess.check_output(SNMPCHECK, shell=True)

def nmapScan(ip_address):
    ip_address = ip_address.strip()
    print bcolors.OKGREEN + "INFO: Running general TCP/UDP nmap scans for " + ip_address + bcolors.ENDC


    TCPSCAN = "nmap -O -Pn -sS -sV -sU -p T:1-65535,U:53,67-69,111,123,135,137-139,161-162,445,500,514,520,631,996-999,1434,1701,1900,3283,4500,5353,49152-49154 %s -oN '/root/oscp/exam/%s/%s.nmap'"  % (ip_address, ip_address, ip_address)
    print bcolors.HEADER + TCPSCAN + bcolors.ENDC
    updateStatus("TCPNmap", ip_address, "Running")
    results = subprocess.check_output(TCPSCAN, shell=True)
    updateStatus("TCPNmap", ip_address, "Done")
    print bcolors.OKGREEN + "INFO: RESULT BELOW - Finished with BASIC Nmap-scan for " + ip_address + bcolors.ENDC
    print results

    p = multiprocessing.Process(target=udpScan, args=(scanip,))
    p.start()

    write_to_file(ip_address, "portscan", results)
    lines = results.split("\n")
    serv_dict = {}
    for line in lines:
        ports = []
        line = line.strip()
        if ("tcp" in line) and ("open" in line) and not ("Discovered" in line):
            # print line
            while "  " in line:
                line = line.replace("  ", " ");
            linesplit= line.split(" ")
            service = linesplit[2] # grab the service name

            port = line.split(" ")[0] # grab the port/proto
            # print port
            if service in serv_dict:
                ports = serv_dict[service] # if the service is already in the dict, grab the port list

            ports.append(port)
            # print ports
            serv_dict[service] = ports # add service to the dictionary along with the associated port(2)



   # go through the service dictionary to call additional targeted enumeration functions
    for serv in serv_dict:
        ports = serv_dict[serv]
        if (serv == "http") or (serv == "http-proxy") or (serv == "http-alt") or (serv == "http?"):
            for port in ports:
                port = port.split("/")[0]
                multProc(httpEnum, ip_address, port)
        elif (serv == "ssl/http") or ("https" == serv) or ("https?" == serv):
            for port in ports:
                port = port.split("/")[0]
                multProc(httpsEnum, ip_address, port)
        elif "smtp" in serv:
            for port in ports:
                port = port.split("/")[0]
                multProc(smtpEnum, ip_address, port)
        elif "ftp" in serv:
            for port in ports:
                port = port.split("/")[0]
                multProc(ftpEnum, ip_address, port)
        elif ("microsoft-ds" in serv) or ("netbios-ssn" == serv):
            for port in ports:
                port = port.split("/")[0]
                multProc(smbEnum, ip_address, port)
                multProc(smbNmap, ip_address, port)
        elif "ms-sql" in serv:
            for port in ports:
                port = port.split("/")[0]
                multProc(mssqlEnum, ip_address, port)
        elif "ssh" in serv:
            for port in ports:
                port = port.split("/")[0]
                multProc(sshScan, ip_address, port)
        elif "snmp" in serv: # this isn't going to run logic flaw needs to be fixed
            for port in ports:
                port = port.split("/")[0]
                multProc(snmpEnum, ip_address, port)
    return


print bcolors.HEADER
print "------------------------------------------------------------"
print "!!!!                      RECON SCAN                   !!!!!"
print "!!!!            A multi-process service scanner        !!!!!"
print "!!!!        dirb, nikto, ftp, ssh, mssql, pop3, tcp    !!!!!"
print "!!!!                    udp, smtp, smb                 !!!!!"
print "------------------------------------------------------------"



if len(sys.argv) < 2:
    print ""
    print "Usage: python reconscan.py <ip> <ip> <ip>"
    print "Example: python reconscan.py 192.168.1.101 192.168.1.102"
    print ""
    print "############################################################"
    pass
    sys.exit()

print bcolors.ENDC

if __name__=='__main__':

    # Setting ip targets
    targets = sys.argv
    targets.pop(0)

    dirs = os.listdir("/root/oscp/exam")
    for scanip in targets:
        scanip = scanip.rstrip()
        if not scanip in dirs:
            folder = "/root/oscp/exam/" + scanip
            print bcolors.HEADER + "INFO: No folder was found for " + scanip + ". Setting up folder." + bcolors.ENDC
            os.makedirs(folder)
            os.makedirs((folder + "/exploits"))
            os.makedirs((folder + "/privesc"))
            print bcolors.OKGREEN + "INFO: Folder created here: " + "/root/oscp/exam/" + scanip + bcolors.ENDC
            shutil.copy(("/root/oscp/reports/windows-template.md"), ("/root/oscp/exam/" + scanip + "/mapping-windows.md"))
            shutil.copy(("/root/oscp/reports/linux-template.md"), ("/root/oscp/exam/" + scanip + "/mapping-linux.md"))
            shutil.copy(("/root/oscp/reports/Status.txt"), ("/root/oscp/exam/" + scanip + "/Status.txt"))
            print bcolors.OKGREEN + "INFO: Added pentesting templates: " + "/root/oscp/exam/" + scanip + bcolors.ENDC
            subprocess.check_output("sed -i -e 's/INSERTIPADDRESS/" + scanip + "/g' /root/oscp/exam/" + scanip + "/mapping-windows.md", shell=True)
            subprocess.check_output("sed -i -e 's/INSERTIPADDRESS/" + scanip + "/g' /root/oscp/exam/" + scanip + "/mapping-linux.md", shell=True)
            #subprocess.check_output("sed -i -e 's/INSERTIP/" + scanip + "/g' /root/oscp/exam/" + scanip + "/Status.txt", shell=True)
        p = multiprocessing.Process(target=nmapScan, args=(scanip,))
        p.start()
