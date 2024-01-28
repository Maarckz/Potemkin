import os
import socket
import threading
import time as t

port_responses = {
        1: "TCPMUX (TCP PORT SERVICE MULTIPLEXER)",
        3: "COMPRESSNET",
        7: "ECHO",
        9: "DISCARD",
        13: "DAYTIME",
        17: "QOTD",
        19: "CHARGEN",
        20: "FTP-DATA (FTP - DADOS)",
        21: "FTP (FTP - CONTROLE)",
        22: "SSH-2.0-OpenSSH_9.3p1 Ubuntu-1ubuntu3.2",
        23: "TELNET",
        24: "PRIV-MAIL",
        25: "SMTP (SIMPLE MAIL TRANSFER PROTOCOL)",
        26: "RSFTP",
        33: "DSP",
        37: "TIME",
        42: "NAMESERVER",
        43: "WHOIS",
        49: "TACACS",
        70: "GOPHER",
        79: "FINGER",
        80: f''''HTTP/1.1 400 Bad Request
Server: Apache/2.4.57 (Ubuntu)
Content-Length: 330
Connection: close
Content-Type: text/html; charset=iso-8859-1

<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">
<html><head>
<title>400 Bad Request</title>
</head><body>
<h1>Bad Request</h1>
<p>Your browser sent a request that this server could not understand.<br />
</p>
<hr>
<address>Apache/2.4.57 (Ubuntu) Server at Port 80</address>
</body></html>''',
        81: "HOSTS2-NS",
        82: "XFER",
        83: "MIT-ML-DEV",
        84: "CTF",
        85: "MIT-ML-DEV",
        88: "KERBEROS-SEC",
        89: "SU-MIT-TG",
        90: "DNSIX",
        99: "METAGRAM",
        100: "NEWACCT",
        106: "POP3PW",
        109: "POP2",
        110: "POP3",
        111: "RPCBIND",
        113: "IDENT",
        119: "NNTP",
        123: "NTP (NETWORK TIME PROTOCOL)",
        125: "LOCUS-MAP",
        135: "MSRPC",
        137: "NETBIOS-NS (NETBIOS NAME SERVICE)",
        138: "NETBIOS-DGM (NETBIOS DATAGRAM SERVICE)",
        139: "NETBIOS-SSN (NETBIOS SESSION SERVICE)",
        143: "IMAP (INTERNET MESSAGE ACCESS PROTOCOL)",
        144: "NEWS",
        146: "ISO-TP0",
        161: "SNMP (SIMPLE NETWORK MANAGEMENT PROTOCOL)",
        163: "CMIP-MAN",
        179: "BGP",
        194: "IRC (INTERNET RELAY CHAT)",
        199: "SMUX",
        211: "914C-G",
        212: "ANET",
        222: "RSH-SPX",
        256: "FW1-SECUREREMOTE",
        259: "ESRO-GEN",
        264: "BGMP",
        280: "HTTP-MGMT",
        301: "THINLINC WEB ACCESS, SPARTAN PROTOCOL",
        308: "NOVASTOR ONLINE BACKUP",
        311: "ASIP-WEBADMIN",
        340: "MATIP TYPE B",
        366: "ODMR",
        389: "LDAP (LIGHTWEIGHT DIRECTORY ACCESS PROTOCOL)",
        406: "IMSP",
        407: "TIMBUKTU",
        416: "SILVERPLATTER",
        417: "ONMUX",
        425: "ICAD-EL",
        427: "SVRLOC",
        443: "HTTPS (HTTP SECURE)",
        444: "SNPP",
        445: "MICROSOFT-DS (MICROSOFT DIRECTORY SERVICES)",
        458: "APPLEQTC",
        464: "KPASSWD5",
        465: "SMTPS",
        481: "DVS",
        497: "RETROSPECT",
        500: "ISAKMP",
        512: "EXEC",
        513: "LOGIN (USED BY RLOGIN)",
        514: "SYSLOG (SYSLOG PROTOCOL)",
        515: "PRINTER (LINE PRINTER DAEMON - LPD)",
        517: "TALK",
        518: "NTALK",
        520: "EFS (EXTENDED FILE NAME SERVER)",
        525: "TIMED (TIMESERVER)",
        530: "COURIER (RPC)",
        531: "CHAT (RPC)",
        532: "NETNEWS",
        533: "NETWALL",
        540: "UUCP (UNIX-TO-UNIX COPY PROTOCOL)",
        543: "KLOGIN (KERBEROS LOGIN)",
        544: "KSHELL (KERBEROS SHELL)",
        546: "DHCPV6-CLIENT",
        547: "DHCPV6-SERVER",
        548: "AFP (APPLE FILING PROTOCOL)",
        549: "IDFP (INTERNET DIRECTORY FACILITY)",
        554: "RTSP (REAL TIME STREAMING PROTOCOL)",
        556: "REMOTEFS (RFS, RFS_SERVER)",
        563: "NNTP (NNTP OVER TLS/SSL - USENET)",
        587: "SUBMISSION (MESSAGE SUBMISSION AGENT)",
        591: "FILEMAKER",
        593: "HTTP-RPC-EPMAP",
        631: "IPP (INTERNET PRINTING PROTOCOL)",
        636: "LDAPS (LDAP OVER SSL)",
        639: "MSDP (MULTICAST SOURCE DISCOVERY PROTOCOL)",
        646: "LDP (LABEL DISTRIBUTION PROTOCOL)",
        647: "DHCP-FAILOVER",
        648: "RRP (REGISTRY REGISTRAR PROTOCOL)",
        652: "DTCP (DYNAMIC TUNNEL CONFIGURATION PROTOCOL)",
        653: "SADMS (SADMS MANAGEMENT)",
        654: "AODV (AD-HOC ON-DEMAND DISTANCE VECTOR)",
        665: "SUN-DR (SOLARIS 'DOOR' SERVICE)",
        666: "DOOM (VIDEO GAME) - UNOFFICIAL BUT OFTEN USED",
        674: "ACAP (APPLICATION CONFIGURATION ACCESS PROTOCOL)",
        691: "MS-EXCHANGE-ROUTING",
        692: "HYPERWAVE-ISP",
        695: "IEEE-MMS-SSL (IEEE MEDIA MANAGEMENT SYSTEM OVER SSL)",
        698: "OLSR (OPTIMIZED LINK STATE ROUTING)",
        993: "IMAPS (IMAP OVER TLS/SSL)",
        995: "POP3S (POP3 OVER TLS/SSL)",
        1080: "SOCKS (SOCKET SECURE)",
        1194: "OPENVPN (SSL/TLS)",
        1433: "MS-SQL-S (MICROSOFT SQL SERVER)",
        1521: "ORACLE",
        3306: "MYSQL",
    }

fake_ports = [1, 3, 7, 9, 13, 17, 19, 20, 21, 22, 23, 24, 25, 26, 33, 37, 42, 43, 49, 70, 79, 80, 81, 82, 83, 84, 85, 88, 89, 90, 99, 100, 106, 109, 110, 111, 113, 119, 123, 125, 135, 137, 138, 139, 143, 144, 146, 161, 163, 179, 194, 199, 211, 212, 222, 256, 259, 264, 280, 301, 308, 311, 340, 366, 389, 406, 407, 416, 417, 425, 427, 443, 444, 445, 458, 464, 465, 481, 497, 500, 512, 513, 514, 515, 517, 518, 520, 525, 530, 531, 532, 533, 540, 543, 544, 546, 547, 548, 549, 554, 556, 563, 587, 591, 593, 631, 636, 639, 646, 647, 648, 652, 653, 654, 665, 666, 674, 691, 692, 695, 698, 993, 995, 1080, 1194, 1433, 1521, 3306]
locks = []
threads = []
ip_count = {}
bloqueados = set()
locks_ban = {}
last_ban_time = {}
ban_interval = 60 
funtime = t.strftime("%Y-%m-%d %H:%M:%S", t.localtime())
def ban(ip):
    global bloqueados, last_ban_time, locks_ban
    current_time = t.time()

    if ip not in bloqueados and ip_count[ip] > 10:
        if ip not in last_ban_time or (current_time - last_ban_time[ip]) >= ban_interval:
            with locks_ban.setdefault(ip, threading.Lock()):
                if ip not in bloqueados:
                    print(f'''sudo firewall-cmd --permanent --add-rich-rule='rule family="ipv4" source address="{ip}" reject"''')
                    bloqueados.add(ip)
                    last_ban_time[ip] = current_time
                    with open('Bloqueados', "a") as file:
                        file.write(f"{ip} - {funtime}\n")

def handle_client(client_socket, port, addr):
    try:
        response = port_responses.get(port, f"No custom service for port {port}")
        client_socket.send(response.encode())
    except Exception as e:
        pass
    finally:
        try:
            client_socket.shutdown(socket.SHUT_RDWR)
        except Exception as e:
            pass
        client_socket.close()
        with locks[port % len(locks)]:
            ip_count[addr] = ip_count.get(addr, 0) + 1
            threading.Thread(target=ban, args=(addr,)).start()

def run_fake_service(port, lock):
    try:
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.bind(('0.0.0.0', port))
        server_socket.listen(5)
        while True:
            try:
                client_socket, addr = server_socket.accept()
                threading.Thread(target=handle_client, args=(client_socket, port, addr[0])).start()
            except Exception as e:
                print(f"Erro ao aceitar conexão: {e}")
    except OSError as e:
        pass

if os.geteuid() == 0:
    t.sleep(2)
    print("Fake Potemkin em execução.")

    try:
        for port in fake_ports:
            if not socket.socket(socket.AF_INET, socket.SOCK_STREAM).connect_ex(('', port)) == 0:
                try:
                    lock = threading.Lock()
                    locks.append(lock)
                    thread = threading.Thread(target=run_fake_service, args=(port, lock))
                    threads.append(thread)
                    thread.start()
                except OSError as e:
                    print(f"Erro ao criar socket: {e}")
            else:
                print(f"A porta {port} está em uso e será pulada.")

        for thread in threads:
            thread.join()
    except KeyboardInterrupt:
        print("\nBye, Bye! ;)")
else:
    print("O código NÃO está sendo executado como root.")
