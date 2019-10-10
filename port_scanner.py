#!/usr/bin/env python3
import os, sys, time, socket, argparse, threading
from datetime import datetime
from colorama import init, Fore, Back, Style

init() # Initialize colorama for windows
mutex = threading.Lock()
open_ports = []
store_host = "" # Store the target's host name to be written in output file.
common_open_ports = {21: 'ftp',22: 'ssh',23: 'telnet',25: 'smtp',53: 'DNS',80: 'http',110: 'pop3',111: 'rpcbind',135: 'msrpc',139: 'netbios-ssn',143: 'imap',443: 'https',445: 'microsoft-ds',993: 'imaps',995: 'pop3s',1723: 'pptp',3306: 'mysql',3389: 'ms-wbt-server',5900: 'vnc',8080: 'http-proxy'}

def validate_hostname(hostname):
    global store_host
    store_host = hostname
    try: return socket.gethostbyname(hostname)
    except socket.error: raise argparse.ArgumentTypeError("invalid host %s" % str(hostname))

def validate_port(port):
    error_msg = "invalid port %s" % str(port)
    try:
        port_ranges = port.split('-')
        for num in port_ranges:
            if not num.isdigit() or int(num) > 65535: 
                raise argparse.ArgumentTypeError(error_msg)
        port_ranges = [int(num) for num in port_ranges]
        if len(port_ranges) < 2: port_ranges.append(port_ranges[0])
        return port_ranges
    except: 
        raise argparse.ArgumentTypeError(error_msg)

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
            open_ports.append("%s%s" % (str(port), port_service))

def start_scan_threads(options):
    threads_list = []
    if type(options.port) is not list: # scan default ports
        print("\nScanning default ports:\n%s\n-----------------" % (list(options.port.keys())))
        for key in options.port:
            if threading.active_count() > options.threads_number: time.sleep(options.threads_execution_sleeptime)
            t1 = threading.Thread(target=port_checker, args=[options.target_host, int(key), options.connect_timeout])
            t1.start()
            threads_list.append(t1)
        for thread in threads_list: thread.join()
    else: # scan ports by user input
        print("\nScanning ports by range:\nFROM PORT %s\n-----------------" % (" TO PORT ".join(list(map(lambda x:str(x),options.port)))))
        for port in range(options.port[0], options.port[1] + 1):
            if threading.active_count() > options.threads_number: time.sleep(options.threads_execution_sleeptime)
            t1 = threading.Thread(target=port_checker, args=[options.target_host, int(port), options.connect_timeout])
            t1.start()
            threads_list.append(t1)
        for thread in threads_list: thread.join()

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
        print(Style.BRIGHT + "\nOpen Ports:", open_ports, Style.RESET_ALL,"\nPort scanning has been completed in %f second(s)!" % (total_time))
        if options.output_file: write_to_output_file(options.output_file, "[%s] <%s> Open Ports: %s\n" % (datetime.today().strftime('%Y-%m-%d'), store_host, open_ports)) # how the output will be implemented
    except KeyboardInterrupt: 
        print("%s Terminated." % (sys.argv[0]))
        os._exit(0)

if __name__ == "__main__": main()