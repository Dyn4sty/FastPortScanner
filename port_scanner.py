#!/usr/bin/env python3
import os, sys, time, socket, argparse, threading
from datetime import datetime
from colorama import init, Fore, Back, Style

init() # Initialize colorama for windows
mutex = threading.Lock()
threads_list = []
open_ports_list = []
store_host = [] # Store the target's host name to be written in output file.
common_open_ports = {1: 'tcpmux', 7: 'echo', 9: 'discard', 11: 'systat', 13: 'daytime', 15: 'netstat', 17: 'qotd', 18: 'msp', 19: 'chargen', 20: 'ftp-data', 21: 'ftp', 22: 'ssh', 23: 'telnet', 25: 'smtp', 37: 'time', 42: 'nameserver', 43: 'whois', 49: 'tacacs', 50: 're-mail-ck', 53: 'domain', 57: 'mtp', 65: 'tacacs-ds', 67: 'bootps', 68: 'bootpc', 70: 'gopher', 77: 'rje', 79: 'finger', 80: 'http', 87: 'link', 88: 'kerberos', 95: 'supdup', 98: 'linuxconf', 101: 'hostnames', 102: 'iso-tsap', 104: 'acr-nema', 105: 'csnet-ns', 106: 'poppassd', 107: 'rtelnet', 109: 'pop2', 110: 'pop3', 111: 'sunrpc', 113: 'auth', 115: 'sftp', 117: 'uucp-path', 119: 'nntp', 123: 'ntp', 129: 'pwdgen', 135: 'loc-srv', 137: 'netbios-ns', 138: 'netbios-dgm', 139: 'netbios-ssn', 143: 'imap2', 161: 'snmp', 162: 'snmp-trap', 163: 'cmip-man', 164: 'cmip-agent', 174: 'mailq', 177: 'xdmcp', 178: 'nextstep', 179: 'bgp', 191: 'prospero', 194: 'irc', 199: 'smux', 201: 'at-rtmp', 202: 'at-nbp', 204: 'at-echo', 206: 'at-zis', 209: 'qmtp', 210: 'z3950', 213: 'ipx', 220: 'imap3', 345: 'pawserv', 346: 'zserv', 347: 'fatserv', 369: 'rpc2portmap', 370: 'codaauth2', 371: 'clearcase', 372: 'ulistserv', 389: 'ldap', 406: 'imsp', 427: 'svrloc', 443: 'https', 444: 'snpp', 445: 'microsoft-ds', 464: 'kpasswd', 465: 'urd', 487: 'saft', 500: 'isakmp', 512: 'exec', 513: 'login', 514: 'shell', 515: 'printer', 526: 'tempo', 530: 'courier', 531: 'conference', 532: 'netnews', 538: 'gdomap', 540: 'uucp', 543: 'klogin', 544: 'kshell', 546: 'dhcpv6-client', 547: 'dhcpv6-server', 548: 'afpovertcp', 549: 'idfp', 554: 'rtsp', 556: 'remotefs', 563: 'nntps', 587: 'submission', 607: 'nqs', 610: 'npmp-local', 611: 'npmp-gui', 612: 'hmmp-ind', 628: 'qmqp', 631: 'ipp', 636: 'ldaps', 655: 'tinc', 706: 'silc', 749: 'kerberos-adm', 750: 'kerberos4', 751: 'kerberos-master', 754: 'krb-prop', 760: 'krbupdate', 765: 'webster', 775: 'moira-db', 777: 'moira-update', 783: 'spamd', 808: 'omirr', 871: 'supfilesrv', 873: 'rsync', 901: 'swat', 989: 'ftps-data', 990: 'ftps', 992: 'telnets', 993: 'imaps', 994: 'ircs', 995: 'pop3s', 1001: 'customs', 1080: 'socks', 1093: 'proofd', 1094: 'rootd', 1099: 'rmiregistry', 1109: 'kpop', 1127: 'supfiledbg', 1178: 'skkserv', 1194: 'openvpn', 1214: 'kazaa', 1236: 'rmtcfg', 1241: 'nessus', 1300: 'wipld', 1313: 'xtel', 1314: 'xtelw', 1352: 'lotusnote', 1433: 'ms-sql-s', 1434: 'ms-sql-m', 1524: 'ingreslock', 1525: 'prospero-np', 1529: 'support', 1645: 'datametrics', 1646: 'sa-msg-port', 1649: 'kermit', 1677: 'groupwise', 1701: 'l2f', 1812: 'radius', 1813: 'radius-acct', 1863: 'msnp', 1957: 'unix-status', 1958: 'log-server', 1959: 'remoteping', 2000: 'cisco-sccp', 2003: 'cfinger', 2010: 'search', 2049: 'nfs', 2053: 'knetd', 2086: 'gnunet', 2101: 'rtcm-sc104', 2105: 'eklogin', 2111: 'kx', 2119: 'gsigatekeeper', 2121: 'iprop', 2135: 'gris', 2150: 'ninstall', 2401: 'cvspserver', 2430: 'venus', 2431: 'venus-se', 2432: 'codasrv', 2433: 'codasrv-se', 2583: 'mon', 2600: 'zebrasrv', 2601: 'zebra', 2602: 'ripd', 2603: 'ripngd', 2604: 'ospfd', 2605: 'bgpd', 2606: 'ospf6d', 2607: 'ospfapi', 2608: 'isisd', 2628: 'dict', 2792: 'f5-globalsite', 2811: 'gsiftp', 2947: 'gpsd', 2988: 'afbackup', 2989: 'afmbackup', 3050: 'gds-db', 3130: 'icpv2', 3260: 'iscsi-target', 3306: 'mysql', 3493: 'nut', 3632: 'distcc', 3689: 'daap', 3690: 'svn', 4031: 'suucp', 4094: 'sysrqd', 4190: 'sieve', 4224: 'xtell', 4353: 'f5-iquery', 4369: 'epmd', 4373: 'remctl', 4557: 'fax', 4559: 'hylafax', 4569:'iax', 4600: 'distmp3', 4691: 'mtn', 4899: 'radmin-port', 4949: 'munin', 5002: 'rfe', 5050: 'mmcc', 5051: 'enbd-cstatd', 5052: 'enbd-sstatd', 5060: 'sip', 5061: 'sip-tls', 5151: 'pcrd', 5190: 'aol', 5222: 'xmpp-client', 5269: 'xmpp-server', 5308: 'cfengine', 5353: 'mdns', 5354: 'noclog', 5355: 'hostmon', 5432: 'postgresql', 5556: 'freeciv', 5666: 'nrpe', 5667: 'nsca', 5671: 'amqps', 5672: 'amqp', 5674: 'mrtd', 5675: 'bgpsim', 5680: 'canna', 5688: 'ggz', 6000: 'x11', 6001: 'x11-1', 6002: 'x11-2', 6003: 'x11-3', 6004: 'x11-4', 6005: 'x11-5', 6006: 'x11-6', 6007: 'x11-7', 6346: 'gnutella-svc', 6347: 'gnutella-rtr', 6444: 'sge-qmaster', 6445: 'sge-execd', 6446: 'mysql-proxy', 6514: 'syslog-tls', 6566: 'sane-port', 6667: 'ircd', 7000: 'afs3-fileserver', 7001: 'afs3-callback', 7002: 'afs3-prserver', 7003: 'afs3-vlserver', 7004: 'afs3-kaserver', 7005: 'afs3-volser', 7006: 'afs3-errors', 7007: 'afs3-bos', 7008: 'afs3-update', 7009: 'afs3-rmtsys', 7100: 'font-service', 8021: 'zope-ftp', 8080: 'http-alt', 8081: 'tproxy', 8088: 'omniorb', 8990: 'clc-build-daemon', 9098: 'xinetd', 9101: 'bacula-dir', 9102: 'bacula-fd', 9103: 'bacula-sd', 9418: 'git', 9667: 'xmms2', 9673: 'zope', 10000: 'webmin', 10050: 'zabbix-agent', 10051: 'zabbix-trapper', 10080: 'amanda', 10081: 'kamanda', 10082: 'amandaidx', 10083: 'amidxtape', 10809: 'nbd', 11112: 'dicom', 11201: 'smsqp', 11371: 'hkp', 13720: 'bprd', 13721: 'bpdbm', 13722: 'bpjava-msvc', 13724: 'vnetd', 13782: 'bpcd', 13783: 'vopied', 15345: 'xpilot', 17004: 'sgi-cad', 17500: 'db-lsp', 20011: 'isdnlog', 20012: 'vboxd', 22125: 'dcap', 22128: 'gsidcap', 22273: 'wnn6', 24554: 'binkp', 27374: 'asp', 30865: 'csync2'}

def validate_hostname(hostname):
    store_host.append(hostname)
    try: return socket.gethostbyname(hostname)
    except socket.error: raise argparse.ArgumentTypeError("invalid host %s" % str(hostname))

def validate_port(port):
    try:
        port_ranges = port.split('-')
        for num in port_ranges:
            if not num.isdigit() or int(num) > 65535: 
                raise argparse.ArgumentTypeError("invalid port %s" % str(port))
        port_ranges = [int(num) for num in port_ranges]
        if len(port_ranges) < 2: port_ranges.append(port_ranges[0])
        return port_ranges
    except: 
        raise argparse.ArgumentTypeError("invalid port %s" % str(port))

def write_to_output_file(filename, data=False):
    if filename == None: return False
    try:
        with open(filename,'a') as output_file:
            if data != False: output_file.write(data)
        return filename
    except KeyboardInterrupt:
        raise argparse.ArgumentTypeError("Couldn't create Output file %s" % filename)

def port_checker(host, port, connect_timeout):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(connect_timeout)
        result = sock.connect_ex((host, port))
        if result == 0: 
            port_service = common_open_ports.get(port,'')
            if port_service != '': port_service = " (" + port_service + ")"
            mutex.acquire()
            print(Style.BRIGHT + "[+] Open Port: %s%s" % (port,port_service))
            mutex.release()
            open_ports_list.append("%s%s" % (str(port), port_service))

def start_scan_threads(options):
    if type(options.port) is not list: # scan default ports
        print("\nScanning default ports:\n%s\n-----------------" % (list(options.port.keys())))
        for port in options.port: launch_thread(options, port)
    else: # scan ports by user input
        print("\nScanning ports by range:\nFROM PORT %s\n-----------------" % (" TO PORT ".join(list(map(lambda x:str(x),options.port)))))
        for port in range(options.port[0], options.port[1] + 1): launch_thread(options, port)
    if len(threads_list) > 0:
        for thread in threads_list: thread.join()

def launch_thread(options, port):
    if threading.active_count() > options.threads_number: time.sleep(options.threads_execution_sleeptime)
    t = threading.Thread(target=port_checker, args=[options.target_host, int(port), options.connect_timeout])
    t.start()
    threads_list.append(t)

def args_parse():
    parser = argparse.ArgumentParser(description='''usage example: %s -t example.com -p 80-81''' % sys.argv[0])
    parser.add_argument('-t', dest="target_host",  type=validate_hostname, help='the target hostname or ip address' ,required=True)
    parser.add_argument('-p', dest="port", type=validate_port, help='the port or port-range to scan for. Default = common ports', default=common_open_ports)
    parser.add_argument('-ct', dest="connect_timeout", type=float, help='the socket connect timeout in second(s) for each port checking. Default = 0.2 second(s)', default=0.2)
    parser.add_argument('-th', dest="threads_number", type=int, help='the threads number for port scan operation. Default = 500 threads', default=500)
    parser.add_argument('-tes', dest="threads_execution_sleeptime", type=float, help='the sleep time in second(s) between threads execution. Default = 0.2 second(s)', default=0.2)
    parser.add_argument('-o', dest="output_file", type=write_to_output_file, help='output file name to save the scan results.', default=None)
    options = parser.parse_args()
    return options

def main():
    try:
        options = args_parse() 
        start_time = time.time()
        start_scan_threads(options)
        end_time = time.time()
        total_time = end_time - start_time
        print(Style.BRIGHT + "\nOpen Ports:", open_ports_list, Style.RESET_ALL,"\nPort scanning has been completed in %f second(s)!" % (total_time))
        if options.output_file: write_to_output_file(options.output_file, "[%s] <%s> Open Ports: %s\n" % (datetime.today().strftime('%Y-%m-%d'), store_host[0], open_ports_list)) # how the output will be implemented
    except KeyboardInterrupt: 
        print("%s Terminated." % (sys.argv[0]))
        os._exit(0)

if __name__ == "__main__": main()
