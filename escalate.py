"""
Windows Privilege Checker - Daniele Linguaglossa
"""
from win32com.client import GetObject
from win32com.client.gencache import EnsureDispatch
import win32com
import win32api
import win32serviceutil
import os
import random
import subprocess
import re
import glob
import socket
import sys


def open_process_allaccess(pid):
    try:
        handle = win32api.OpenProcess(0x000F0000L | 0x00100000L | 0xFFF, False, pid)
    except Exception as e:
        if e[0] in [5, 87]:  # return access denied or bad pid
            return False
    return True

        
def random_name(length=10):
    charset = "abcdefghijklmnopqrstuvxyzABCDEFGHIJKLMNOPQRSTUVXYZ0123456789"
    return "%s.txt" % "".join(charset[random.randint(0, len(charset)-1)] for x in range(0, length))

def find_paths(executables):
    path = 'C:\\'
    path = os.path.normpath(path)
    for root, dirs, files in os.walk(path, topdown=True):
        depth = root[len(path) + len(os.path.sep):].count(os.path.sep)
        if depth in [0, 1, 2, 3]:
            for d in dirs:
                for executable in executables:
                    if os.path.isfile(os.path.join(root, d)+"\\%s" % executable):
                        yield [os.path.join(root, d), executable]
            if depth == 3:
                dirs[:] = []

def check_list_pipes():
    pipes = glob.glob("//./pipe/*")
    for pipe in pipes:
        print "[INFO] Found named pipe %s" % pipe

def check_process_injection():
    WMI = GetObject('winmgmts:')
    WMI = EnsureDispatch(WMI._oleobj_)
    processes = WMI.ExecQuery('select * from Win32_Process')
    for process in processes:
        if process.Properties_("Name").Value not in ["svchost.exe","lsass.exe","wininit.exe", "System", "services.exe"]:
            try:
                if process.ExecMethod_('GetOwner').Properties_("User").Value == None:
                    proc_name = process.Properties_("Name").Value
                    proc_pid = process.Properties_("ProcessId").Value
                    if open_process_allaccess(int(process.Properties_("ProcessId").Value)):
                        print "[VULN] Process with pid %s(%s) is vulnerable to DLL Injection" % (proc_name, proc_pid)
            except:
                pass

def check_elevate_process_permission():
    WMI = GetObject('winmgmts:')
    WMI = EnsureDispatch(WMI._oleobj_)
    elevated = []
    processes = WMI.ExecQuery('select * from Win32_Process')
    for process in processes:
        if process.Properties_("Name").Value not in ["svchost.exe","lsass.exe","wininit.exe", "System", "services.exe"]:
            try:
                if process.ExecMethod_('GetOwner').Properties_("User").Value == None:
                    elevated.append(process.Properties_("Name").Value)
            except:
                pass
    for path in find_paths(elevated):
        try:
            name = random_name()
            check = open(path[0] + "\\%s" % name,"wb")
            check.close()
            os.remove(path[0] + "\\%s" % name)
            print "[VULN] Process %s may be VULNERABLE we have write permission on %s" % (path[1], path[0])
        except Exception as e:
            pass

def check_elevated_processes():
    WMI = GetObject('winmgmts:')
    WMI = EnsureDispatch(WMI._oleobj_)
    processes = WMI.ExecQuery('select * from Win32_Process') 
    for process in processes:
        if process.Properties_("Name").Value not in ["svchost.exe","lsass.exe","wininit.exe", "System", "services.exe"]:
            try:
                if process.ExecMethod_('GetOwner').Properties_("User").Value == None:
                    print "[INFO] Found elevated process %s" % process.Properties_("Name").Value
            except:
                pass


def check_path_write():
    paths = os.environ["PATH"].split(";")
    for path in paths:
        try:
            name = random_name()
            check = open(path + "\\%s" % name,"wb")
            check.close()
            os.remove(path + "\\%s" % name)
            print "[VULN] Environment path %s is WRITEABLE" % path
        except Exception as e:
            pass


def check_port_pids():
    pids = []
    WMI = GetObject('winmgmts:')
    WMI = EnsureDispatch(WMI._oleobj_)
    nestat_regex = re.compile("\s+(?P<type>TCP|UDP)\s+(0.0.0.0|127.0.0.1):(?P<port>[0-9]+)\s+[0-9.:]+\s+(?P<listen>LISTENING)\s+(?P<pid>[0-9]+)")
    proc = subprocess.Popen(['netstat', '-ano'],creationflags=0x08000000, stdout=subprocess.PIPE)
    output = proc.communicate()[0]
    proc.stdout.close()
    for port in output.split("\r\n"):
        if nestat_regex.search(port):
            pids.append(nestat_regex.search(port).groupdict())
    for pid in pids:
        processes = WMI.ExecQuery('select * from Win32_Process where ProcessId = %s' % pid["pid"])
        for process in processes:
            if process.Properties_("Name").Value not in ["svchost.exe","lsass.exe","wininit.exe", "System", "services.exe"]:
                if process.ExecMethod_('GetOwner').Properties_("User").Value == None:
                    print "[VULN] Elevated process %s with pid %s on port %s %s" % (process.Properties_("Name").Value,
                                                                            pid["pid"], pid["port"], pid["type"])
                    if pid["type"] == "TCP":
                        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    else:
                        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                    s.setblocking(1)
                    s.settimeout(0.5)
                    try:
                        s.connect(("127.0.0.1", int(pid["port"])))
                        s.send("GET / HTTP/1.1\r\n\r\n")
                        print ">     [INFO] Port %s (%s) answer with banner \"%s\"" % (pid["port"], process.Properties_("Name").Value, s.recv(50).replace("\r\n"," "))
                    except Exception as e:
                        print ">     [INFO] Port %s (%s) won't answer to dummy packet" % (pid["port"],  process.Properties_("Name").Value)
                                  

def check_services():
    paths = []
    wmi=win32com.client.GetObject('winmgmts:')
    for p in wmi.InstancesOf('Win32_Service'):
        path = os.path.dirname(str(p.Properties_("PathName").Value).replace("\"","").split(".exe ")[0])
        stop = False
        try:
            win32serviceutil.StopService(p.Properties_("Name").Value)
            win32serviceutil.StartService(p.Properties_("Name").Value)
            stop = True
        except Exception as e:
            if e[0] == 5:  # Access denied
                stop = False
            else:
                stop = True
        paths.append({"Name": p.Properties_("Name").Value, "Path": path, "startStop": stop})
    for path in paths:
        try:
            name = random_name()
            check = open(path["Path"] + "\\%s" % name,"wb")
            check.close()
            os.remove(path["Path"] + "\\%s" % name)
            print "[VULN] Service %s is VULNERABLE %s\\" % (path["Name"], path["Path"])
        except Exception as e:
            pass
        if path["startStop"]:
            print "[VULN] Service %s may be VULNERABLE 'cause you can start/stop it" % path["Name"]
  
if len(sys.argv) > 1:
    if sys.argv[1] == "info":
        check_list_pipes()
        check_elevated_processes()
    elif sys.argv[1] == "vuln":
        check_path_write()
        check_services()
        check_port_pids()
        check_elevate_process_permission()
        check_process_injection()
    elif sys.argv[1] == "all":
        check_list_pipes()
        check_elevated_processes()
        check_path_write()
        check_services()
        check_port_pids()
        check_elevate_process_permission()
        check_process_injection()
    else:
        print "\nUsage: %s <vuln|info|all>" % sys.argv[0]
else:
    print "\nUsage: %s <vuln|info|all>" % sys.argv[0]
