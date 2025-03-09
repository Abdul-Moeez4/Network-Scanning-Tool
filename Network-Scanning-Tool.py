from scapy.all import *
import sys
import time
import ipaddress



#information about tool function
def info():
    print("="*50)

    print("              TOOL INFORMATION")  # tool info banner/message

    print("="*50)

    print("\n")

    print("Created by Abdul Moeez Siddiqui, this tool helps you explore different network scanning techniques using the Scapy Library.")
    print("From simple ICMP pings to advanced scans like XMAS and ACK, easily check if a target is online and analyze its network behavior.\n")

    print("Starting tool...")
    time.sleep(1.5)
    print("\n")

    start_tool()
    
#execeutes the tool etc function
def start_tool():
    #will first need to ask user for either target/victim ip or network range 

    target = input("Enter target/victim IP or network range: ").strip() # checking validaity, also trying to validate if part of different classes eg class A, B, C etc., strip = removes any leading, and trailing whitespaces

    #also create sort or conditions whether its only ip or network range

    #for network
    if "/" in target:
        try:
            network_range = ipaddress.ip_network(target, strict=False)
            network_add = str(network_range.network_address)  # Get network address
            first_ip = str(network_range.network_address + 1)  # Get first IP in the network
            first_octet = int(first_ip.split(".")[0])  #extracts the first part (octet) of an IP address by splitting the IP string at '.' and converting the first part into an integer.

            if 1 <= first_octet <= 127:
                ip_class = "Class A"

            elif 128 <= first_octet <= 191:
                ip_class = "Class B"

            elif 192 <= first_octet <= 223:
                ip_class = "Class C"

            else:
                ip_class = "Not Class A, B, or C"
        
            print(f"\n[+] Valid Network: {target}")
            print(f"[+] Network Address: {network_add}")
            print(f"[+] First IP in Network: {first_ip}")
            print(f"[+] IP Class: {ip_class}")

        except ValueError:
            print("\n[-] Invalid network range! Please enter a correct format (e.g., 192.168.1.0/24).")
            exit()        

    # other wise do for single ip (no range or "/")
    else:
        try:
            ip_address = ipaddress.ip_address(target)
            first_octet = int(str(ip_address).split(".")[0])


            if 1 <= first_octet <= 127:
                ip_class = "Class A"

            elif 128 <= first_octet <= 191:
                ip_class = "Class B"

            elif 192 <= first_octet <= 223:
                ip_class = "Class C"

            else:
                ip_class = "Not Class A, B, or C"
        
            print(f"\n[+] Valid IP: {target}")
            print(f"[+] IP Class: {ip_class}")

        except ValueError:
            print("\n[-] Invalid IP address! Please enter a correct format (e.g., 192.168.1.1).")
            exit()

    time.sleep(1.5)
    show_scan_options(target)



#create different fucntions for each option

    #===============================================================================================#
                                        #1. ICMP Ping
    #===============================================================================================#
def icmp_ping(target):

    #need to add fucntionalities or make it in a way that works for both single ip and netwwork
    verbosity_choice = input("Would you like to enable Verbosity? (y/n): ")

    if verbosity_choice == 'N' or verbosity_choice == 'n':
        print(f"Ping {target} [56(84) bytes of data]")

        try:
            #keep pingigng until user stops themselves
            while True:
                try:
                    if "/" in target:
                        network = ipaddress.ip_network(target, strict=False)  #strcit = false meaning allows the function to accept host addresses as valid input instead of requiring a network address
                        hosts = list(network.hosts())
                    else:
                        hosts = [target] #for single ip
                    
                    while True: #as we need to keep it pingg until user stops
                        for host in hosts:
                            packet = IP(dst=str(host))/ICMP()
                            reply = sr1(packet, timeout=2, verbose=0)

                            if reply:
                                print(f"[+] Target {host} is UP!")
                            else:
                                print(f"[-] Target {host} is DOWN or not responding.")

                            time.sleep(1.5)  #delay before sending another packet

                except KeyboardInterrupt:
                    print("\n[-] ICMP Ping Scan Stopped...")
                    break

        except ValueError:
            print("\n[-] Invalid IP or network range. Please enter a correct format (e.g., 192.168.1.1 or 192.168.1.0/24).")


             ##commented previous code ##
            '''
                packet = IP(dst=target)/ICMP()
                reply = sr1(packet, timeout=2, verbose=0)

                if reply:
                    print(f"[+] Target {target} is UP!")
                else:
                    print(f"[-] Target {target} is DOWN or not responding.")
            
                time.sleep(1.5)  #delay before sending another packet
    
        except KeyboardInterrupt:
            print("\n[-] ICMP Ping Scan Stopped...")
            '''
    #===============================================================================================#

    elif verbosity_choice == 'Y' or verbosity_choice == 'y':
        print(f"Ping {target} [56(84) bytes of data]")

        try:
            #keep pingigng until user stops themselves
            while True:
                try:
                    if "/" in target:
                        network = ipaddress.ip_network(target, strict=False)
                        hosts = list(network.hosts())
                    else:
                        hosts = [target] #for single ip
                    
                    while True: #as we need to keep it pingg until user stops
                        for host in hosts:
                            packet = IP(dst=str(host))/ICMP()
                            reply = sr1(packet, timeout=2, verbose=1)

                            if reply:
                                print(f"[+] Target {host} is UP!")
                            else:
                                print(f"[-] Target {host} is DOWN or not responding.")

                            time.sleep(1.5)  #delay before sending another packet
                except KeyboardInterrupt:
                    print("\n[-] ICMP Ping Scan Stopped...")
                    break

        except ValueError:
            print("\n[-] Invalid IP or network range. Please enter a correct format!")
    
    else:
        print("\n[-] Invalid choice. Please choose a valid option.")
    

    '''
        try:

            #keep pingigng ntil user stops
            while True:
                packet = IP(dst=target)/ICMP()
                reply = sr1(packet, timeout=2, verbose=1)

                if reply:
                    print(f"[+] Target {target} is UP!")
                else:
                    print(f"[-] Target {target} is DOWN or not responding.")
            
                time.sleep(1.5)  #delay before sending another packet
    
        except KeyboardInterrupt:
            print("\n[-] ICMP Ping Scan Stopped...")
    
    else:
        print("\n[-] Invalid option! Please enter either 'y' or 'n'.")
    '''




                        # ⚠️ ⚠️ ⚠️  UPDATE: APPRANTLEY WORKS NOW
    #===============================================================================================#
                                        #2. TCP Ack Ping
    #===============================================================================================#

#2. TCP Ack Ping
def tcp_ack_ping(target): 

    dstport = input("Enter destination port (default: 80, type 443 for HTTPS): ").strip() #(port = 80 by default is sent, ack flag (A))  not sure if this ping must be continious or single packet send only, UPDATE: KEEP SENDING CASUE PING

     # Use 80 if input is empty, otherwise convert input to int
    dstport = int(dstport) if dstport.isdigit() else 80  

    verbosity_choice = input("Would you like to enable Verbosity? (y/n): ")  

    if verbosity_choice == 'N' or verbosity_choice == 'n':
         try:
            while True:
                try:
            # Handle both single IP and network range
                    if "/" in target:
                        network = ipaddress.ip_network(target, strict=False)
                        hosts = list(network.hosts())  # Extract usable hosts

                    else:
                        hosts = [target]  # Single IP

                    while True:  # Continuous Ping until user stops
                        for host in hosts:
                            print(f"\n[+] Sending TCP ACK Ping to {host} on port {dstport}")

                            packet = IP(dst=str(host)) / TCP(sport=RandShort(), dport=dstport, flags="A")
                            reply = sr1(packet, timeout=2, verbose=(1 if verbosity_choice == 'y' else 0))

                            if reply:
                                if reply.haslayer(TCP) and reply[TCP].flags == 0x14:  # RST received
                                    print(f"[+] Host {host} is UP! (RST PACKET RECEIVED)")
                                else:
                                    print(f"[?] {host} responded, but not with RST. May be filtered.")
                            else:
                                print(f"[-] No response from {host}. Host may be DOWN or filtered.")

                            time.sleep(1.5)  # Delay before next ping

                except KeyboardInterrupt:
                    print("\n[-] TCP ACK Ping Scan Stopped.")
                    break

         except ValueError:
            print("\n[-] Invalid input! Please enter a correct port or IP format.")

    #===============================================================================================#

    elif verbosity_choice == 'Y' or verbosity_choice == 'y':
        try:
            while True:  # Continuous ping until user stops
                try:
                    # Handle both single IP and network range
                    if "/" in target:
                        network = ipaddress.ip_network(target, strict=False)
                        hosts = list(network.hosts())  # Extract usable hosts
                    else:
                        hosts = [target]  # Single IP

                    while True: 
                        for host in hosts:
                            packet = IP(dst=str(host)) / TCP(sport=RandShort(), dport=dstport, flags="A")
                            reply = sr1(packet, timeout=2, verbose=1)

                            if reply:
                                if reply.haslayer(TCP) and reply[TCP].flags == 0x14:  # RST received
                                    print(f"[+] Host {host} is UP! (RST PACKET RECEIVED)")
                                else:
                                    print(f"[?] {host} responded, but not with RST. May be filtered.")
                            else:
                                print(f"[-] No response from {host}. Host may be DOWN or filtered.")

                            time.sleep(1.5)  # Delay before next ping

                except KeyboardInterrupt:
                    print("\n[-] TCP ACK Ping Scan Stopped.")
                    break

        except ValueError:
            print("\n[-] Invalid input! Please enter a correct port or IP format.")
    
    else:
        print("\n[-] Invalid choice. Please choose a valid option.")





                        # ⚠️ ⚠️ ⚠️  UNDER CONSTRUCTION (ISSUES WITH THIS, WORK ON THIS LATER)
    #===============================================================================================#
                                        #3. SCTP Init Ping
    #===============================================================================================#
def sctip_init_ping(target, dst_port = 80):  #default port for it ut will see if need to take input from user or not
    #dstport = input("Enter destination port (default: 80, type 443 for HTTPS): ").strip()
    
    # Use 80 if input is empty, otherwise convert input to int
    #dstport = int(dstport) if dstport.isdigit() else 80  

    verbosity_choice = input("Would you like to enable Verbosity? (y/n): ")

    if verbosity_choice == 'N' or verbosity_choice == 'n':
        try:
            # Handle both single IP and network range
            if "/" in target:
                network = ipaddress.ip_network(target, strict=False)
                hosts = list(network.hosts())  # Extract usable hosts

            else:
                hosts = [target]  # Single IP

            while True:
                for host in hosts:
                    packet = IP(dst=str(host))/SCTP(dport=dst_port)/SCTPChunkInit() 
                    reply = sr1(packet, timeout=2, verbose = 0)

                    if reply:
                        if reply.haslayer(SCTP) and reply[SCTP].chunks[0].type == 2:  # INIT-ACK chunk
                            print(f"[+] TARGET {target} is UP! (Init Ack PACKED RECIEVED)")
                        else:
                            print(f"[-] {target} responded, but not with INIT-ACK. Host may be filtered.")
                    else:
                        print(f"[-] No response from {target}. Host may be DOWN/Not Exist or filtered.")

                    time.sleep(1.5)  # Delay before next ping

        except KeyboardInterrupt:
            print("\n[-] SCTP Init Ping Scan Stopped.")

        except ValueError:
            print("\n[-] Invalid input! Please enter a correct port or IP format.")
            
    #===============================================================================================#

    elif verbosity_choice == 'Y' or verbosity_choice == 'y':
        try:
            if "/" in target:
                network = ipaddress.ip_network(target, strict=False)
                hosts = list(network.hosts())  # Extract usable hosts
            else:
                hosts = [target]  # Single IP
                    
            while True:
                for host in hosts:
                    packet = IP(dst=str(host))/SCTP(dport=dst_port)/SCTPChunkInit() 
                    reply = sr1(packet, timeout=2, verbose = 1)

                    if reply:
                        if reply.haslayer(SCTP) and reply[SCTP].chunks[0].type == 2:  # INIT-ACK chunk
                            print(f"[+] TARGET {host} is UP! (Init Ack PACKET RECIEVED)")
                        else:
                            print(f"[?] {host} responded, but not with INIT-ACK. May be filtered.")

                    else:
                        print(f"[-] No response from {host}. Host may be DOWN/Not Exist or filtered.")

                    time.sleep(1.5)  # Delay before next ping

        except KeyboardInterrupt:
            print("\n[-] ICMP Timestamp Ping Scan Stopped.")
    
        except ValueError:
            print("\n[-] Invalid input! Please enter a correct port or IP format.")
    
    else:
        print("\n[-] Invalid choice. Please choose a valid option.")



  #===============================================================================================#
                                        #4. ICMP Timestamp ping
  #===============================================================================================#


def icmp_timestamp_ping(target):

    verbosity_choice = input("Would you like to enable Verbosity? (y/n): ")

    if verbosity_choice ==  'N' or verbosity_choice == 'n':
        try:
            # Handle both single IP and network range
            if "/" in target:
                network = ipaddress.ip_network(target, strict=False)
                hosts = list(network.hosts())  # Extract all usable hosts
            else:
                hosts = [target]  # Single IP case

            while True:
                for host in hosts:
                    packet = IP(dst=str(host)) / ICMP(type=13)  # Type 13 = Timestamp Request
                    reply = sr1(packet, timeout=2, verbose=0)

                    if reply:
                        if reply.haslayer(ICMP) and reply[ICMP].type == 14:  # Type 14 = Timestamp Reply

                            ts_originate = reply[ICMP].ts_ori  # Original timestamp from sender

                            ts_receive = reply[ICMP].ts_rx  # Receiver timestamp

                            ts_transmit = reply[ICMP].ts_tx  # Transmit timestamp

                            print(f"[+] Host {host} is UP! (ICMP Timestamp Reply Received)\n")
                            
                            print(f"    - Original Timestamp: {ts_originate} ms")
                            print(f"    - Received Timestamp: {ts_receive} ms")
                            print(f"    - Transmit Timestamp: {ts_transmit} ms")

                            time.sleep(1.5)
                        else:
                            print(f"[-] {host} responded, but not with a Timestamp Reply. May be filtered.")
                    else:
                        print(f"[-] No response from {host}. Host may be DOWN or filtered.")

                    time.sleep(1.5)  # Delay before next ping
        
        except KeyboardInterrupt:
            print("\n[-] ICMP Timestamp Ping Scan Stopped.")

        except ValueError:
            print("\n[-] Invalid input! Please enter a correct IP or network format.")

        #===============================================================================================#

    elif verbosity_choice == 'Y' or verbosity_choice == 'y':
        try:
            # Handle both single IP and network range
            if "/" in target:
                network = ipaddress.ip_network(target, strict=False)
                hosts = list(network.hosts())  # Extract all usable hosts
            else:
                hosts = [target]  # Single IP case

            while True:
                for host in hosts:
                    packet = IP(dst=str(host)) / ICMP(type=13)  # Type 13 = Timestamp Request
                    reply = sr1(packet, timeout=2, verbose=1)


                    if reply:
                        if reply.haslayer(ICMP) and reply[ICMP].type == 14:  # Type 14 = Timestamp Reply

                            ts_originate = reply[ICMP].ts_ori  # Original timestamp from sender

                            ts_receive = reply[ICMP].ts_rx  # Receiver timestamp

                            ts_transmit = reply[ICMP].ts_tx  # Transmit timestamp

                            print(f"[+] Host {host} is UP! (ICMP Timestamp Reply Received)")

                            print(f"    - Original Timestamp: {ts_originate} ms")
                            print(f"    - Received Timestamp: {ts_receive} ms")
                            print(f"    - Transmit Timestamp: {ts_transmit} ms")

                        else:       
                            print(f"[-] {host} responded, but not with a Timestamp Reply. May be filtered.")
                    else:
                        print(f"[-] No response from {host}. Host may be DOWN or filtered.")

                    time.sleep(1.5)  # Delay before next ping
        
        except KeyboardInterrupt:
            print("\n[-] ICMP Timestamp Ping Scan Stopped.")

        except ValueError:
            print("\n[-] Invalid input! Please enter a correct IP or network format.")
    
    else:
        print("\n[-] Invalid choice. Please choose a valid option.")



  #===============================================================================================#
                                    #5. ICMP Address Mask Ping
  #===============================================================================================#

def icmp_add_mask_ping(target):   #device sends an "ICMP Address Mask Request" message to a target host, essentially asking for the subnet mask of that network

    verbosity_choice = input("Would you like to enable Verbosity? (y/n): ")

    if verbosity_choice ==  'N' or verbosity_choice == 'n':
        try:
            if "/" in target:
                network = ipaddress.ip_network(target, strict=False)
                hosts = list(network.hosts())  # Extract all usable hosts

            else:
                hosts = [target]  # Single IP case
            
            while True:
                for host in hosts:
                    packet = IP(dst=str(host)) / ICMP(type=17)  # Type 17 = Address Mask Request
                    reply = sr1(packet, timeout=2, verbose=0)

                    if reply:
                        if reply.haslayer(ICMP) and reply[ICMP].type == 18:  # Type 18 = Address Mask Reply

                            mask_value = reply[ICMP].unused  # Extract raw data
                            mask_str = ".".join(str((mask_value >> (i * 8)) & 0xFF) for i in range(4))  # Convert to subnet format

                            print(f"[+] Host {host} is UP! (ICMP Address Mask Reply Received)")
                            print(f"    - Subnet Mask: {mask_str}")

                        else:
                            print(f"[-] {host} responded, but not with a Address Mask Reply. May be filtered.")

                    else:
                        print(f"[-] No response from {host}. Host may be DOWN or filtered.")

                    time.sleep(1.5)  # Delay before next ping
        
        except KeyboardInterrupt:
            print("\n[-] ICMP Address Mask Ping Scan Stopped.")

        except ValueError:
            print("\n[-] Invalid input! Please enter a correct IP or network format.")


            #===============================================================================================#
    
    elif verbosity_choice == 'Y' or verbosity_choice == 'y':
        try:
            if "/" in target:
                network = ipaddress.ip_network(target, strict=False)
                hosts = list(network.hosts())  # Extract all usable hosts

            else:
                hosts = [target]  # Single IP case
            
            while True:
                for host in hosts:
                    packet = IP(dst=str(host)) / ICMP(type=17)  # Type 17 = Address Mask Request
                    reply = sr1(packet, timeout=2, verbose=1)

                    if reply:
                        if reply.haslayer(ICMP) and reply[ICMP].type == 18:  # Type 18 = Address Mask Reply
                            print(f"[+] Host {host} is UP! (ICMP Address Mask Reply Received)")

                            print(f"Subnet Mask: {reply[ICMP].mask}")
                        else:
                            print(f"[-] {host} responded, but not with a Address Mask Reply. May be filtered.")
                    
                    else:
                        print(f"[-] No response from {host}. Host may be DOWN or filtered.")

                    time.sleep(1.5)  # Delay before next ping
        
        except KeyboardInterrupt:
            print("\n[-] ICMP Address Mask Ping Scan Stopped.")

        except ValueError:
            print("\n[-] Invalid input! Please enter a correct IP or network format.")
    
    else:
        print("\n[-] Invalid choice. Please choose a valid option.")




             # ⚠️ ⚠️ ⚠️  UNDER CONSTRUCTION (ISSUES WITH THIS, WORK ON THIS LATER) -> ISSUES RELATED WITH WHEN NETWORK GIVEN AS INPUT, SINGLE IPS (MAYBE) WORK FINE
  #===============================================================================================#
                                    #6. ARP Ping
  #===============================================================================================#
def arp_ping(target):  #uses the Address Resolution Protocol (ARP) to test if an IP address is reachable on a local network

    verbosity_choice = input("Would you like to enable Verbosity? (y/n): ")

    if verbosity_choice ==  'N' or verbosity_choice == 'n':
        try:
            if "/" in target:
                network = ipaddress.ip_network(target, strict=False)
                hosts = list(network.hosts())  # Extract all usable hosts

            else:
                hosts = [target]  # Single IP case

            while True:
                for host in hosts:
                    arp_packet = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=str(host))  # all f's as it broadcasts to all hosts in local and sees from there

                    #srp() → Sends and receives packets at Layer 2 (Data Link Layer)
                    #[0] takes only answered packets, ignores unanswered ones unless want that, just convert to 1
                    reply = srp(arp_packet, timeout=2, verbose=0)[0]

                if reply:  # If a reply is received
                    for sent, received in reply:
                        print(f"[+] Host {host} is UP! (MAC: {received.hwsrc})")

                else:  # If no reply is received
                    print(f"[-] Host {host} is DOWN or not responding.")

                time.sleep(1.5)  # Delay before next ping

        except KeyboardInterrupt:
            print("\n[-] ARP Ping Scan Stopped.")

        except ValueError:
            print("\n[-] Invalid input! Please enter a correct IP or network format.")

        
         #===============================================================================================#
    
    elif verbosity_choice == 'Y' or verbosity_choice == 'y':
        try:
            if "/" in target:
                network = ipaddress.ip_network(target, strict=False)
                hosts = list(network.hosts())  # Extract all usable hosts

            else:
                hosts = [target]  # Single IP case

            while True:
                for host in hosts:
                    arp_packet = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=str(host))  # all f's as it broadcasts to all hosts in local and sees from there
                    reply = srp(arp_packet, timeout=2, verbose=1)[0]

                    if reply:  # If a reply is received
                        for sent, received in reply:
                            print(f"[+] Host {host} is UP! (MAC: {received.hwsrc})")

                    else:  # If no reply is received
                        print(f"[-] Host {host} is DOWN or not responding.")
                    
                    time.sleep(1.5) # Delay before next ping

        except KeyboardInterrupt:
            print("\n[-] ARP Ping Scan Stopped.")

        except ValueError:
            print("\n[-] Invalid input! Please enter a correct IP or network format.")

    else:
        print("\n[-] Invalid choice. Please choose a valid option.")

 


                        # ⚠️ ⚠️ ⚠️  UNDER CONSTRUCTION (ISSUES WITH THIS, WORK ON THIS LATER) -> ISSUES RELATED WITH WHEN NETWORK GIVEN AS INPUT, SINGLE IPS (MAYBE) WORK FINE
  #===============================================================================================#
                                    #7. Find MAC Address of Victim
  #===============================================================================================#       
def find_mac(target):
    verbosity_choice = input("Would you like to enable Verbosity? (y/n): ")

    if verbosity_choice ==  'N' or verbosity_choice == 'n':
        try:
            if "/" in target:
                network = ipaddress.ip_network(target, strict=False)
                hosts = list(network.hosts())  # Extract all usable hosts
            else:
                hosts = [target]  # Single IP case
            
            while True:
                for host in hosts:
                    packet = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=str(host))  # all f's as it broadcasts to all hosts in local
                    reply = srp(packet, timeout=2, verbose=0)[0]

                    if reply:
                         for sent, received in reply:
                            print(f"[+] MAC: {received.hwsrc}")
                    else:
                        print(f"[-] MAC: NOT FOUND (Host is DOWN or not responding)")
                    
                    time.sleep(1.5)  # Delay before next ping
        except KeyboardInterrupt:
            print("\n[-] Scan Stopped.")

        except ValueError:
            print("\n[-] Invalid input! Please enter a correct IP or network format.")

            #===============================================================================================#

    elif verbosity_choice == 'Y' or verbosity_choice == 'y':
        try:
            if "/" in target:
                network = ipaddress.ip_network(target, strict=False)
                hosts = list(network.hosts())  # Extract all usable hosts
            else:
                hosts = [target]  # Single IP case
            
            while True:
                for host in hosts:
                    packet = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=str(host))  # all f's as it broadcasts to all hosts in local
                    reply = srp(packet, timeout=2, verbose=1)[0]

                    if reply:
                        for sent, received in reply:
                            print(f"[+] MAC: {received.hwsrc}")
                    else:
                        print(f"[-] MAC: NOT FOUND (Host is DOWN or not responding)")

                    time.sleep(1.5)  # Delay before next ping

        except KeyboardInterrupt:
            print("\n[-] Scan Stopped.")
        
        except ValueError:
            print("\n[-] Invalid input! Please enter a correct IP or network format.")
    
    else:
        print("\n[-] Invalid choice. Please choose a valid option.")





#                                      OS DISCOVERY
  #===============================================================================================#
                                    #8. OS DETECTION
  #===============================================================================================#    

def os_detection(target):   #this will work on ttl as each os haas their own sort of ttl value (something like that)
    verbosity_choice = input("Would you like to enable Verbosity? (y/n): ")

    if verbosity_choice ==  'N' or verbosity_choice == 'n':

        try:
            if "/" in target:
                network = ipaddress.ip_network(target, strict=False)
                hosts = list(network.hosts())  # Extract all usable hosts
            
            else:
                hosts = [target]  # Single IP case

            for host in hosts:
                packet = IP(dst=str(host)) / ICMP()  # Sending ICMP packet to target
                reply = sr1(packet, timeout=2, verbose=0)

                if reply:
                    ttl = reply[IP].ttl  # Extract TTL value from reply

                    if ttl <= 64:
                        os_guess = "Linux/Unix/MacOS"
                    elif ttl <= 128:
                        os_guess = "Windows"
                    elif ttl <= 255:
                        os_guess = "Solaris/AIX/Cisco Devices"
                    else:
                        os_guess = "Unknown"

                    print(f"[+] HOST {host} is UP! OS Guess: {os_guess} (TTL: {ttl})")

                else:
                    print(f"[-] No response from {host}. Host may be DOWN or unreachable.")
                    print("\n")
        except KeyboardInterrupt:
            print("\n[-] Scan Stopped.")
        
        except ValueError:
            print("\n[-] Invalid input! Please enter a correct IP or network format.")


        #===============================================================================================#
    
    elif verbosity_choice == 'Y' or verbosity_choice == 'y':
        try:
            if "/" in target:
                network = ipaddress.ip_network(target, strict=False)
                hosts = list(network.hosts())  # Extract all usable hosts
            
            else:
                hosts = [target]  # Single IP case

            for host in hosts:
                packet = IP(dst=str(host)) / ICMP()  # Sending ICMP packet to target
                reply = sr1(packet, timeout=2, verbose=1)

                if reply:
                    ttl = reply[IP].ttl  # Extract TTL value from reply

                    if ttl <= 64:
                        os_guess = "Linux/Unix/MacOS"
                    elif ttl <= 128:
                        os_guess = "Windows"
                    elif ttl <= 255:
                        os_guess = "Solaris/AIX/Cisco Devices"
                    else:
                        os_guess = "Unknown"
                    print(f"[+] HOST {host} is UP! OS Guess: {os_guess} (TTL: {ttl})")

                else:
                    print(f"[-] No response from {host}. Host may be DOWN or unreachable.")
                    print("\n")

        except KeyboardInterrupt:
            print("\n[-] Scan Stopped.")
        
        except ValueError:
            print("\n[-] Invalid input! Please enter a correct IP or network format.")

    else:
        print("\n[-] Invalid choice. Please choose a valid option.")



#                                      PORT SCANNING
  #===============================================================================================#
                                    #9. TCP CONNECT SCAN
  #===============================================================================================#    

# Dictionary of common ports and their services
COMMON_PORTS = {
    20: "FTP (Data Transfer)",
    21: "FTP (Control)",
    22: "SSH",
    23: "Telnet",
    25: "SMTP (Email)",
    53: "DNS",
    80: "HTTP",
    110: "POP3 (Email)",
    143: "IMAP (Email)",
    443: "HTTPS",
    3306: "MySQL",
    3389: "RDP (Remote Desktop)",
    8080: "HTTP (Alternate)",
}

def tcp_connect(target):
    dstport = input("Enter the destination port (default 80, type 443 for HTTPS, or 'all' to scan all common ports): ").strip()

    # If user types "all", scan all common ports
    if dstport == "all" or dstport == "ALL":
        ports_to_scan = COMMON_PORTS.keys()
    else:
        # Default to port 80 if input is invalid
        dstport = int(dstport) if dstport.isdigit() else 80
        ports_to_scan = [dstport]

    verbosity_choice = input("Would you like to enable Verbosity? (y/n): ").strip()

    if verbosity_choice ==  'N' or verbosity_choice == 'n':
        try:
            # Handle single IP or network range
            if "/" in target:
                network = ipaddress.ip_network(target, strict=False)
                hosts = list(network.hosts())  # Extract all usable hosts
            else:
                hosts = [target]  # Single IP case

            for host in hosts:
                for port in ports_to_scan:

                    # Send SYN packet
                    packet = IP(dst=str(host)) / TCP(dport=port, flags="S")
                    reply = sr1(packet, timeout=5, verbose=0)

                    if reply:
                        if reply.haslayer(TCP):
                            if reply[TCP].flags == 0x12:  # SYN-ACK received (Open)
                                service = COMMON_PORTS.get(port, "Unknown Service")
                                print(f"[+] Port {port} ({service}) on {host} is OPEN.")
                                # Send RST to gracefully close the connection
                                send(IP(dst=str(host)) / TCP(dport=port, flags="R"), verbose=0)

                            elif reply[TCP].flags == 0x14:  # RST-ACK received (Closed)
                                print(f"[-] Port {port} on {host} is CLOSED.")

                        else:
                            print(f"[?] {host} responded, but not with expected TCP flags. Might be filtered.")
                    else:
                        print(f"[-] No response from {host}. Port might be FILTERED or HOST is down.")

        except ValueError:
            print("\n[-] Invalid input! Please enter a correct IP or network format.")

        except KeyboardInterrupt:
            print("\n[-] TCP Connect Scan Stopped.")

        #===============================================================================================#

    elif verbosity_choice == 'Y' or verbosity_choice == 'y':
        try:
            # Handle single IP or network range
            if "/" in target:
                network = ipaddress.ip_network(target, strict=False)
                hosts = list(network.hosts())  # Extract all usable hosts
            else:
                hosts = [target]  # Single IP case

            for host in hosts:
                for port in ports_to_scan:

                    # Send SYN packet
                    packet = IP(dst=str(host)) / TCP(dport=port, flags="S")
                    reply = sr1(packet, timeout=5, verbose=1)

                    if reply:
                        if reply.haslayer(TCP):
                            if reply[TCP].flags == 0x12:  # SYN-ACK received (Open)
                                service = COMMON_PORTS.get(port, "Unknown Service")
                                print(f"[+] Port {port} ({service}) on {host} is OPEN.")
                                # Send RST to gracefully close the connection
                                send(IP(dst=str(host)) / TCP(dport=port, flags="R"), verbose=1)

                            elif reply[TCP].flags == 0x14:  # RST-ACK received (Closed)
                                print(f"[-] Port {port} on {host} is CLOSED.")

                        else:
                            print(f"[?] {host} responded, but not with expected TCP flags. Might be filtered.")
                    else:
                        print(f"[-] No response from {host}. Port might be FILTERED or HOST is down.")

        except ValueError:
            print("\n[-] Invalid input! Please enter a correct IP or network format.")

        except KeyboardInterrupt:
            print("\n[-] TCP Connect Scan Stopped.")

    else:
        print("\n[-] Invalid choice. Please choose a valid option.")




  #===============================================================================================#
                                    #10. UDP SCAN
  #===============================================================================================#

# Dictionary of common UDP ports and their services
COMMON_UDP_PORTS = {
    53: "DNS",
    67: "DHCP (Server)",
    68: "DHCP (Client)",
    69: "TFTP",
    123: "NTP",
    161: "SNMP",
    162: "SNMP Trap",
    500: "ISAKMP",
    514: "Syslog",
    520: "RIP",
    1900: "UPnP",
    5353: "mDNS",
}    

def udp_scan(target):

    dstport = input("Enter the destination port (default 53, type 123 for NTP): ").strip()


    # If user types "all", scan all common ports
    if dstport == "all" or dstport == "ALL":
        ports_to_scan = COMMON_UDP_PORTS.keys()
    else:
        # Default to port 80 if input is invalid
        dstport = int(dstport) if dstport.isdigit() else 53
        ports_to_scan = [dstport]
        

    #dstport = int(dstport) if dstport.isdigit() else 53  # Default to port 53 (DNS) if input is invalid

    verbosity_choice = input("Would you like to enable Verbosity? (y/n): ").strip()

    if verbosity_choice ==  'N' or verbosity_choice == 'n':
        try:
            if "/" in target:
                network = ipaddress.ip_network(target, strict=False)
                hosts = list(network.hosts())  # Extract all usable hosts
            else:
                hosts = [target]  # Single IP case
            
            for host in hosts:
                for port in ports_to_scan:

                #send udp packet
                    packet = IP(dst=str(host)) / UDP(dport=port)
                    reply = sr1(packet, timeout=2, verbose=0)

                    if reply:
                        if reply.haslayer(ICMP):

                            # ICMP Type 3, Code 3 means "Port Unreachable" (Closed)
                            if reply[ICMP].type == 3 and reply[ICMP].code == 3:
                                print(f"[-] Port {port} on {host} is CLOSED.")

                            elif reply.haslayer(UDP):  # If a UDP response is received, the port is likely open
                                service = COMMON_UDP_PORTS.get(port, "Unknown Service")
                                print(f"[+] Port {port} ({service}) on {host} is OPEN.")
                    else:
                        print(f"[?] {host} responded, but not with expected UDP or ICMP. Might be filtered.")
                else:
                    # No response could mean the port is open or filtered
                    service = COMMON_UDP_PORTS.get(port, "Unknown Service")
                    print(f"[?] Port {port} ({service}) on {host} is OPEN|FILTERED (No response).")

        except ValueError:
            print("\n[-] Invalid input! Please enter a correct IP or network format.")
        except KeyboardInterrupt:
            print("\n[-] UDP Scan Stopped.")

         #===============================================================================================#

    elif verbosity_choice == "Y" or verbosity_choice == 'y':
        try:
            if "/" in target:
                network = ipaddress.ip_network(target, strict=False)
                hosts = list(network.hosts())  # Extract all usable hosts
            else:
                hosts = [target]  # Single IP case
            
            for host in hosts:
                for port in ports_to_scan:

                  #send udp packet
                    packet = IP(dst=str(host)) / UDP(dport=port)
                    reply = sr1(packet, timeout=2, verbose=1)

                    if reply:
                        if reply.haslayer(ICMP):

                            # ICMP Type 3, Code 3 means "Port Unreachable" (Closed)
                            if reply[ICMP].type == 3 and reply[ICMP].code == 3:
                                print(f"[-] Port {port} on {host} is CLOSED.")

                            elif reply.haslayer(UDP):  # If a UDP response is received, the port is likely open
                                service = COMMON_UDP_PORTS.get(port, "Unknown Service")
                                print(f"[+] Port {port} ({service}) on {host} is OPEN.")
                    else:
                        print(f"[?] {host} responded, but not with expected UDP or ICMP. Might be filtered.")
                else:
                    # No response could mean the port is open or filtered
                    service = COMMON_UDP_PORTS.get(port, "Unknown Service")
                    print(f"[?] Port {port} ({service}) on {host} is OPEN|FILTERED (No response).")

        except ValueError:
            print("\n[-] Invalid input! Please enter a correct IP or network format.")
        except KeyboardInterrupt:
            print("\n[-] UDP Scan Stopped.")

    else:
        print("\n[-] Invalid choice. Please choose a valid option.")


  #===============================================================================================#
                                    #11. TCP NULL SCAN
  #===============================================================================================#

# Dictionary of common ports and their services
COMMON_PORTS = {
    20: "FTP (Data Transfer)",
    21: "FTP (Control)",
    22: "SSH",
    23: "Telnet",
    25: "SMTP (Email)",
    53: "DNS",
    80: "HTTP",
    110: "POP3 (Email)",
    143: "IMAP (Email)",
    443: "HTTPS",
    3306: "MySQL",
    3389: "RDP (Remote Desktop)",
    8080: "HTTP (Alternate)",
}

#sort of tcp connect scan but with flags set as 0!
def tcp_null_scan(target):
    dstport = input("Enter the destination port (default 80, type 443 for HTTPS, or 'all' to scan all common ports): ").strip()

    # If user types "all", scan all common ports
    if dstport.lower() == "all":
        ports_to_scan = COMMON_PORTS.keys()
    else:
        # Default to port 80 if input is invalid
        dstport = int(dstport) if dstport.isdigit() else 80
        ports_to_scan = [dstport]

    verbosity_choice = input("Would you like to enable Verbosity? (y/n): ")

    if verbosity_choice == 'N' or verbosity_choice == 'n':
        try:
            # Handle single IP or network range
            if "/" in target:
                network = ipaddress.ip_network(target, strict=False)
                hosts = list(network.hosts())  # Extract all usable hosts
            else:
                hosts = [target]  # Single IP case

            for host in hosts:
                for port in ports_to_scan:
                    #print(f"\n[+] Scanning {host} on TCP port {port} (NULL Scan)...")

                    # Send TCP Null packet (no flags set)
                    packet = IP(dst=str(host)) / TCP(dport=port, flags=0)
                    reply = sr1(packet, timeout=2, verbose=0)

                    if reply:
                        if reply.haslayer(TCP):
                            if reply[TCP].flags == 0x14:  # RST-ACK received (Closed)
                                print(f"[-] Port {port} on {host} is CLOSED.")
                        else:
                            print(f"[?] {host} responded, but not with expected TCP flags. Might be filtered.")
                    else:
                        # No response means the port is open or filtered
                        service = COMMON_PORTS.get(port, "Unknown Service")
                        print(f"[?] Port {port} ({service}) on {host} is OPEN|FILTERED (No response).")

        except ValueError:
            print("\n[-] Invalid input! Please enter a correct IP or network format.")

        except KeyboardInterrupt:
            print("\n[-] TCP Null Scan Stopped.")

        #===============================================================================================#

    elif verbosity_choice == "Y" or verbosity_choice == 'y':
        try:
            # Handle single IP or network range
            if "/" in target:
                network = ipaddress.ip_network(target, strict=False)
                hosts = list(network.hosts())  # Extract all usable hosts
            else:
                hosts = [target]  # Single IP case

            for host in hosts:
                for port in ports_to_scan:
                    print(f"\n[+] Scanning {host} on TCP port {port} (NULL Scan)...")

                    # Send TCP Null packet (no flags set)
                    packet = IP(dst=str(host)) / TCP(dport=port, flags=0)
                    reply = sr1(packet, timeout=2, verbose=1)

                    if reply:
                        if reply.haslayer(TCP):
                            if reply[TCP].flags == 0x14:  # RST-ACK received (Closed)
                                print(f"[-] Port {port} on {host} is CLOSED.")
                        else:
                            print(f"[?] {host} responded, but not with expected TCP flags. Might be filtered.")
                    else:
                        # No response means the port is open or filtered
                        service = COMMON_PORTS.get(port, "Unknown Service")
                        print(f"[?] Port {port} ({service}) on {host} is OPEN|FILTERED (No response).")

        except ValueError:
            print("\n[-] Invalid input! Please enter a correct IP or network format.")
            
        except KeyboardInterrupt:
            print("\n[-] TCP Null Scan Stopped.")

    else:
        print("\n[-] Invalid choice. Please choose a valid option.")


  #===============================================================================================#
                                    #12. TCP FIN SCAN
  #===============================================================================================#

# Dictionary of common ports and their services
COMMON_PORTS = {
    20: "FTP (Data Transfer)",
    21: "FTP (Control)",
    22: "SSH",
    23: "Telnet",
    25: "SMTP (Email)",
    53: "DNS",
    80: "HTTP",
    110: "POP3 (Email)",
    143: "IMAP (Email)",
    443: "HTTPS",
    3306: "MySQL",
    3389: "RDP (Remote Desktop)",
    8080: "HTTP (Alternate)",
}

#sort of tcp connect scan but with flags set as 'f!
def tcp_fin_scan(target):
    dstport = input("Enter the destination port (default 80, type 443 for HTTPS, or 'all' to scan all common ports): ").strip()

    # If user types "all", scan all common ports
    if dstport.lower() == "all":
        ports_to_scan = COMMON_PORTS.keys()
    else:
        # Default to port 80 if input is invalid
        dstport = int(dstport) if dstport.isdigit() else 80
        ports_to_scan = [dstport]

    verbosity_choice = input("Would you like to enable Verbosity? (y/n): ")

    if verbosity_choice == 'N' or verbosity_choice == 'n':
        try:
            # Handle single IP or network range
            if "/" in target:
                network = ipaddress.ip_network(target, strict=False)
                hosts = list(network.hosts())  # Extract all usable hosts
            else:
                hosts = [target]  # Single IP case

            for host in hosts:
                for port in ports_to_scan:
                    print(f"\n[+] Scanning {host} on TCP port {port} (NULL Scan)...")

                    # Send TCP fin packet (FIN flags set)
                    packet = IP(dst=str(host)) / TCP(dport=port, flags="F")
                    reply = sr1(packet, timeout=2, verbose=0)

                    if reply:
                        if reply.haslayer(TCP):
                            if reply[TCP].flags == 0x14:  # RST-ACK received (Closed)
                                print(f"[-] Port {port} on {host} is CLOSED.")
                        else:
                            print(f"[?] {host} responded, but not with expected TCP flags. Might be filtered.")
                    else:
                        # No response means the port is open or filtered
                        service = COMMON_PORTS.get(port, "Unknown Service")
                        print(f"[?] Port {port} ({service}) on {host} is OPEN|FILTERED (No response).")

        except ValueError:
            print("\n[-] Invalid input! Please enter a correct IP or network format.")

        except KeyboardInterrupt:
            print("\n[-] TCP FIN Scan Stopped.")

        #===============================================================================================#

    elif verbosity_choice == "Y" or verbosity_choice == 'y':
        try:
            # Handle single IP or network range
            if "/" in target:
                network = ipaddress.ip_network(target, strict=False)
                hosts = list(network.hosts())  # Extract all usable hosts
            else:
                hosts = [target]  # Single IP case

            for host in hosts:
                for port in ports_to_scan:
                    print(f"\n[+] Scanning {host} on TCP port {port} (NULL Scan)...")

                    # Send TCP fin packet (FIN flags set)
                    packet = IP(dst=str(host)) / TCP(dport=port, flags="F")
                    reply = sr1(packet, timeout=2, verbose=1)

                    if reply:
                        if reply.haslayer(TCP):
                            if reply[TCP].flags == 0x14:  # RST-ACK received (Closed)
                                print(f"[-] Port {port} on {host} is CLOSED.")
                        else:
                            print(f"[?] {host} responded, but not with expected TCP flags. Might be filtered.")
                    else:
                        # No response means the port is open or filtered
                        service = COMMON_PORTS.get(port, "Unknown Service")
                        print(f"[?] Port {port} ({service}) on {host} is OPEN|FILTERED (No response).")

        except ValueError:
            print("\n[-] Invalid input! Please enter a correct IP or network format.")
            
        except KeyboardInterrupt:
            print("\n[-] TCP FIN Scan Stopped.")

    else:
        print("\n[-] Invalid choice. Please choose a valid option.")


 #===============================================================================================#
                                    #13. XMAS SCAN
 #===============================================================================================#

def xmas_scan(target):
    dstport = input("Enter the destination port (default 80, type 443 for HTTPS, or 'all' to scan all common ports): ").strip()

    # If user types "all", scan all common ports
    if dstport.lower() == "all":
        ports_to_scan = COMMON_PORTS.keys()
    else:
        # Default to port 80 if input is invalid
        dstport = int(dstport) if dstport.isdigit() else 80
        ports_to_scan = [dstport]

    verbosity_choice = input("Would you like to enable Verbosity? (y/n): ")

    if verbosity_choice == 'N' or verbosity_choice == 'n':
        try:
            # Handle single IP or network range
            if "/" in target:
                network = ipaddress.ip_network(target, strict=False)
                hosts = list(network.hosts())  # Extract all usable hosts
            else:
                hosts = [target]  # Single IP case

            for host in hosts:
                for port in ports_to_scan:
                    print(f"\n[+] Scanning {host} on TCP port {port} (XMAS Scan)...")

                    # Send XMAS packet (FIN, PSH, URG flags set)
                    packet = IP(dst=str(host)) / TCP(dport=port, flags="FPU")
                    reply = sr1(packet, timeout=2, verbose=0)

                    if reply:
                        if reply.haslayer(TCP):
                            if reply[TCP].flags == 0x14:  # RST-ACK received (Closed)
                                print(f"[-] Port {port} on {host} is CLOSED.")
                        else:
                            print(f"[?] {host} responded, but not with expected TCP flags. Might be filtered.")
                    else:
                        # No response means the port is open or filtered
                        service = COMMON_PORTS.get(port, "Unknown Service")
                        print(f"[?] Port {port} ({service}) on {host} is OPEN|FILTERED (No response).")

        except ValueError:  
            print("\n[-] Invalid input! Please enter a correct IP or network format.")

        except KeyboardInterrupt:
            print("\n[-] XMAS Scan Stopped.")
    
            #===============================================================================================#

    elif verbosity_choice == "Y" or verbosity_choice == 'y':
        try:
            # Handle single IP or network range
            if "/" in target:
                network = ipaddress.ip_network(target, strict=False)
                hosts = list(network.hosts())  # Extract all usable hosts
            else:
                hosts = [target]  # Single IP case

            for host in hosts:
                for port in ports_to_scan:
                    print(f"\n[+] Scanning {host} on TCP port {port} (XMAS Scan)...")

                    # Send XMAS packet (FIN, PSH, URG flags set)
                    packet = IP(dst=str(host)) / TCP(dport=port, flags="FPU")
                    reply = sr1(packet, timeout=2, verbose=1)

                    if reply:
                        if reply.haslayer(TCP):
                            if reply[TCP].flags == 0x14:  # RST-ACK received (Closed)
                                print(f"[-] Port {port} on {host} is CLOSED.")
                        else:
                            print(f"[?] {host} responded, but not with expected TCP flags. Might be filtered.")
                    else:
                        # No response means the port is open or filtered
                        service = COMMON_PORTS.get(port, "Unknown Service")
                        print(f"[?] Port {port} ({service}) on {host} is OPEN|FILTERED (No response).")

        except ValueError:  
            print("\n[-] Invalid input! Please enter a correct IP or network format.")

        except KeyboardInterrupt:
            print("\n[-] XMAS Scan Stopped.")

    else:
        print("\n[-] Invalid choice. Please choose a valid option.")


#===============================================================================================#
                                    #14.TCP ACK SCAN  
 #===============================================================================================#

# Dictionary of common ports and their services
COMMON_PORTS = {
    20: "FTP (Data Transfer)",
    21: "FTP (Control)",
    22: "SSH",
    23: "Telnet",
    25: "SMTP (Email)",
    53: "DNS",
    80: "HTTP",
    110: "POP3 (Email)",
    143: "IMAP (Email)",
    443: "HTTPS",
    3306: "MySQL",
    3389: "RDP (Remote Desktop)",
    8080: "HTTP (Alternate)",
}
def tcp_ack_scan(target):
    dstport = input("Enter the destination port (default 80, type 443 for HTTPS, or 'all' to scan all common ports): ").strip()

    # If user types "all", scan all common ports
    if dstport.lower() == "all":
        ports_to_scan = COMMON_PORTS.keys()
    else:
        # Default to port 80 if input is invalid
        dstport = int(dstport) if dstport.isdigit() else 80
        ports_to_scan = [dstport]

    verbosity_choice = input("Would you like to enable Verbosity? (y/n): ")

    if verbosity_choice == 'N' or verbosity_choice == 'n':
        try:
            # Handle single IP or network range
            if "/" in target:
                network = ipaddress.ip_network(target, strict=False)
                hosts = list(network.hosts())  # Extract all usable hosts
            else:
                hosts = [target]  # Single IP case

            for host in hosts:
                for port in ports_to_scan:
                    print(f"\n[+] Scanning {host} on TCP port {port} (ACK Scan)...")

                    # Send TCP ACK packet (ACK flag set)
                    packet = IP(dst=str(host)) / TCP(dport=port, flags="A")
                    reply = sr1(packet, timeout=5, verbose=0)

                    if reply:
                        if reply.haslayer(TCP):
                            if reply[TCP].flags == 0x14:  # RST-ACK received (Port is unfiltered)
                                print(f"[+] Port {port} on {host} is **UNFILTERED** (RST-ACK Received).")
                            else:
                                print(f"[?] Port {port} on {host} responded, but not with RST-ACK. Might be **FILTERED**.")
                        else:
                            print(f"[?] Unexpected response from {host}, possible firewall or interference.")
                    else:
                        print(f"[-] No response from {host}, port {port}. Might be **FILTERED/DROPPED**.")

        except ValueError:
            print("\n[-] Invalid input! Please enter a correct IP or network format.")
        except KeyboardInterrupt:
            print("\n[-] TCP ACK Scan Stopped.")


       #===============================================================================================#

    elif verbosity_choice == 'y' or verbosity_choice == 'Y':
        try:
            if "/" in target:
                network = ipaddress.ip_network(target, strict=False)
                hosts = list(network.hosts())  # Extract all usable hosts
            else:
                hosts = [target]  # Single IP case

            for host in hosts:
                for port in ports_to_scan:
                    print(f"\n[+] Scanning {host} on TCP port {port} (ACK Scan)...")

                    # Send TCP ACK packet (ACK flag set)
                    packet = IP(dst=str(host)) / TCP(dport=port, flags="A")
                    reply = sr1(packet, timeout=5, verbose=1)

                    if reply:
                        if reply.haslayer(TCP):
                            if reply[TCP].flags == 0x14:  # RST-ACK received (Port is unfiltered)
                                print(f"[+] Port {port} on {host} is **UNFILTERED** (RST-ACK Received).")
                            else:
                                print(f"[?] Port {port} on {host} responded, but not with RST-ACK. Might be **FILTERED**.")
                        else:
                            print(f"[?] Unexpected response from {host}, possible firewall or interference.")
                    else:
                        print(f"[-] No response from {host}, port {port}. Might be **FILTERED/DROPPED**.")

        except ValueError:
            print("\n[-] Invalid input! Please enter a correct IP or network format.")
        except KeyboardInterrupt:
            print("\n[-] TCP ACK Scan Stopped.")

    else:
        print("\n[-] Invalid choice. Please choose a valid option.")





 #===============================================================================================#
                                    #15.TCP WINDOW SCAN
 #===============================================================================================#  

# Dictionary of common ports and their services
COMMON_PORTS = {
    20: "FTP (Data Transfer)",
    21: "FTP (Control)",
    22: "SSH",
    23: "Telnet",
    25: "SMTP (Email)",
    53: "DNS",
    80: "HTTP",
    110: "POP3 (Email)",
    143: "IMAP (Email)",
    443: "HTTPS",
    3306: "MySQL",
    3389: "RDP (Remote Desktop)",
    8080: "HTTP (Alternate)",
}

def tcp_windows_scan(target):
    dstport = input("Enter the destination port (default 80, type 443 for HTTPS, or 'all' to scan all common ports): ").strip()

    # If user types "all", scan all common ports
    if dstport.lower() == "all":
        ports_to_scan = COMMON_PORTS.keys()
    else:
        # Default to port 80 if input is invalid
        dstport = int(dstport) if dstport.isdigit() else 80
        ports_to_scan = [dstport]

    verbosity_choice = input("Would you like to enable Verbosity? (y/n): ")

    if verbosity_choice == 'N' or verbosity_choice == 'n':
        try:
            if "/" in target:
                network = ipaddress.ip_network(target, strict=False)
                hosts = list(network.hosts())  # Extract all usable hosts
            else:
                hosts = [target]  # Single IP case

            for host in hosts:
                for port in ports_to_scan:
                    packet = IP(dst=str(host)) / TCP(dport=port, flags="A")  # Send TCP ACK packet
                    reply = sr1(packet, timeout=2, verbose=0)


                    if reply:
                        if reply.haslayer(TCP) and reply[TCP].flags == 0x14:  # RST received
                            window_size = reply[TCP].window

                            if window_size > 0:
                                print(f"[+] Port {port} is **OPEN/UNFILTERED** (Window Size: {window_size})")

                            else:
                                print(f"[-] Port {port} is **CLOSED** (Window Size: {window_size})")
                        else:
                            print(f"[?] Unexpected response on port {port}. Might be filtered.")
                    else:
                        print(f"[-] No response from port {port}. Likely **FILTERED**.")

        except ValueError:
            print("\n[-] Invalid input! Please enter a correct IP or network format.")
        except KeyboardInterrupt:
            print("\n[-] TCP ACK Scan Stopped.")

      #===============================================================================================#

    elif verbosity_choice == 'y' or verbosity_choice == 'Y':
        try:
            if "/" in target:
                network = ipaddress.ip_network(target, strict=False)
                hosts = list(network.hosts())  # Extract all usable hosts
            else:
                hosts = [target]  # Single IP case

            for host in hosts:
                for port in ports_to_scan:
                    packet = IP(dst=str(host)) / TCP(dport=port, flags="A")  # Send TCP ACK packet
                    reply = sr1(packet, timeout=2, verbose=1)


                    if reply:
                        if reply.haslayer(TCP) and reply[TCP].flags == 0x14:  # RST received
                            window_size = reply[TCP].window

                            if window_size > 0:
                                print(f"[+] Port {port} is **OPEN/UNFILTERED** (Window Size: {window_size})")

                            else:
                                print(f"[-] Port {port} is **CLOSED** (Window Size: {window_size})")
                        else:
                            print(f"[?] Unexpected response on port {port}. Might be filtered.")
                    else:
                        print(f"[-] No response from port {port}. Likely **FILTERED**.")

        except ValueError:
            print("\n[-] Invalid input! Please enter a correct IP or network format.")
        except KeyboardInterrupt:
            print("\n[-] TCP ACK Scan Stopped.")



 #===============================================================================================#
                                    #16.TCP Maimon SCAN
 #===============================================================================================#  

# Dictionary of common ports and their services
COMMON_PORTS = {
    20: "FTP (Data Transfer)",
    21: "FTP (Control)",
    22: "SSH",
    23: "Telnet",
    25: "SMTP (Email)",
    53: "DNS",
    80: "HTTP",
    110: "POP3 (Email)",
    143: "IMAP (Email)",
    443: "HTTPS",
    3306: "MySQL",
    3389: "RDP (Remote Desktop)",
    8080: "HTTP (Alternate)",
}

def tcp_mainmon_scan(target):
    dstport = input("Enter the destination port (default 80, type 443 for HTTPS, or 'all' to scan all common ports): ").strip()

    # If user types "all", scan all common ports
    if dstport.lower() == "all":
        ports_to_scan = COMMON_PORTS.keys()
    else:
        # Default to port 80 if input is invalid
        dstport = int(dstport) if dstport.isdigit() else 80
        ports_to_scan = [dstport]

    verbosity_choice = input("Would you like to enable Verbosity? (y/n): ")

    if verbosity_choice == 'N' or verbosity_choice == 'n':
        try:
            if "/" in target:
                network = ipaddress.ip_network(target, strict=False)
                hosts = list(network.hosts())
            else:
                hosts = [target]  # Single IP

            for host in hosts:
                for port in ports_to_scan:
                    print(f"\n[+] Scanning {host} on TCP port {port} (Maimon Scan)...")

                    # Send FIN-ACK packet
                    packet = IP(dst=str(host)) / TCP(dport=port, flags="FA")
                    reply = sr1(packet, timeout=2, verbose=0)

                    if reply:
                        if reply.haslayer(TCP) and reply[TCP].flags == 0x14:  # RST received (Closed)
                            print(f"[-] Port {port} on {host} is **CLOSED**.")
                        else:
                            print(f"[?] Unexpected response from {host} on port {port}. Might be filtered.")
                    else:
                        print(f"[+] Port {port} on {host} is **OPEN/FILTERED** (No response).")

        except ValueError:
            print("\n[-] Invalid input! Please enter a correct IP or network format.")
        except KeyboardInterrupt:
            print("\n[-] TCP Maimon Scan Stopped.")


      #===============================================================================================#

    elif verbosity_choice == 'Y' or verbosity_choice == 'y':
        try:
            if "/" in target:
                network = ipaddress.ip_network(target, strict=False)
                hosts = list(network.hosts())
            else:
                hosts = [target]  # Single IP

            for host in hosts:
                for port in ports_to_scan:
                    print(f"\n[+] Scanning {host} on TCP port {port} (Maimon Scan)...")

                    # Send FIN-ACK packet
                    packet = IP(dst=str(host)) / TCP(dport=port, flags="FA")
                    reply = sr1(packet, timeout=2, verbose=1)

                    if reply:
                        if reply.haslayer(TCP) and reply[TCP].flags == 0x14:  # RST received (Closed)
                            print(f"[-] Port {port} on {host} is **CLOSED**.")
                        else:
                            print(f"[?] Unexpected response from {host} on port {port}. Might be filtered.")
                    else:
                        print(f"[+] Port {port} on {host} is **OPEN/FILTERED** (No response).")

        except ValueError:
            print("\n[-] Invalid input! Please enter a correct IP or network format.")
        except KeyboardInterrupt:
            print("\n[-] TCP Maimon Scan Stopped.")


#===============================================================================================#
                                    #17.IP protocol SCAN
 #===============================================================================================#  
 # Common protocol numbers
PROTOCOLS = {
    1: "ICMP",
    6: "TCP",
    17: "UDP",
    47: "GRE",
    50: "ESP",
    51: "AH",
    132: "SCTP"
}
def ip_protocol_scan(target):

    verbosity_choice = input("Would you like to enable Verbosity? (y/n): ")

    if verbosity_choice == 'N' or verbosity_choice == 'n':
        try:
            if "/" in target:
                network = ipaddress.ip_network(target, strict=False)
                hosts = list(network.hosts())
            else:
                hosts = [target]  # Single IP case

            for host in hosts:
                print(f"\n[+] Scanning {host} for supported IP protocols...\n")
            
                for proto_num, proto_name in PROTOCOLS.items():
                    print(f"[+] Testing protocol {proto_name} ({proto_num})...")

                    packet = IP(dst=str(host), proto=proto_num) / Raw(load="Hello")  # Send packet with specified protocol
                    reply = sr1(packet, timeout=2, verbose=0)

                    if reply:
                        print(f"[+] Protocol {proto_name} ({proto_num}) is **SUPPORTED** on {host}.")
                    else:
                        print(f"[-] No response for {proto_name} ({proto_num}) - Might be **FILTERED or UNSUPPORTED**.")

            print("\n[+] IP Protocol Scan Complete.")

        except ValueError:  
            print("\n[-] Invalid input! Please enter a correct IP or network format.")
        except KeyboardInterrupt:
            print("\n[-] IP Protocol Scan Stopped.")

      #===============================================================================================#

    elif verbosity_choice == 'Y' or verbosity_choice == 'y':
        try:
            if "/" in target:
                network = ipaddress.ip_network(target, strict=False)
                hosts = list(network.hosts())
            else:
                hosts = [target]  # Single IP case

            for host in hosts:
                print(f"\n[+] Scanning {host} for supported IP protocols...\n")
            
                for proto_num, proto_name in PROTOCOLS.items():
                    print(f"[+] Testing protocol {proto_name} ({proto_num})...")

                    packet = IP(dst=str(host), proto=proto_num) / Raw(load="Hello")  # Send packet with specified protocol
                    reply = sr1(packet, timeout=2, verbose=1)

                    if reply:
                        print(f"[+] Protocol {proto_name} ({proto_num}) is **SUPPORTED** on {host}.")
                    else:
                        print(f"[-] No response for {proto_name} ({proto_num}) - Might be **FILTERED or UNSUPPORTED**.")

            print("\n[+] IP Protocol Scan Complete.")

        except ValueError:  
            print("\n[-] Invalid input! Please enter a correct IP or network format.")
        except KeyboardInterrupt:
            print("\n[-] IP Protocol Scan Stopped.")



scan_options = {                  

        #host discovery
        "1": icmp_ping,
        "2": tcp_ack_ping,
        "3": sctip_init_ping,
        "4": icmp_timestamp_ping,
        "5": icmp_add_mask_ping,
        "6": arp_ping,
        "7": find_mac,

        #os discovery
        "8": os_detection,

        #port scanning (i think)
        "9": tcp_connect,
        "10": udp_scan,
        "11": tcp_null_scan,
        "12": tcp_fin_scan,
        "13": xmas_scan,
        "14": tcp_ack_scan,
        "15": tcp_windows_scan,
        "16": tcp_mainmon_scan,
        "17": ip_protocol_scan
    }




def show_scan_options(target):
    print("\n")
    print("="*50)

    print("                 Main Options")  # choices for user

    print("="*50)

    print("\nChoose a scanning technique:\n")
    
    #host discovery part 
    print("Host Discovery:\n")

    print("1. ICMP Ping")
    print("2. TCP ACK Ping")
    print("3. SCTP Init Ping")
    print("4. ICMP Timestamp Ping")
    print("5. ICMP Address Mask Ping")
    print("6. ARP Ping")
    print("7. Find MAC Address of Victim\n")

    #os part 
    print("OS Discovery:\n")

    print("8. OS Detection (TTL-Based)")

    #port scanning
    print("Port Scanning:\n")

    print("9. TCP Connect() Scan")
    print("10. UDP Scan")
    print("11. TCP Null Scan")
    print("12. TCP FIN Scan")
    print("13. Xmas Scan")
    print("14. TCP ACK Scan")
    print("15. TCP Window Scan")
    print("16. TCP Maimon Scan")
    print("17. IP Protocol Scan")

    #exit
    print("0. Exit")

    choice = input("\nEnter your choice (1-17, Type 0 to exit): ").strip()

    if choice == '0':
        print("\nExiting tool...\n")
        time.sleep(1.5)

        print("="*50)

        print("                 GoodBye")  # choices for user

        print("="*50)

        exit()

    elif choice in scan_options:
        scan_options[choice](target)
    
    else:
        print("\n[-] Invalid choice! Please choose a number between 1 and 17.")



#main fucntion, called beginning to ask user about s or r
def main():
    print("="*50)

    print("   Welcome to the A.M.S Network Scanning Tool")  # give a welcoming meesage for the user

    print("="*50)

    print("\n")

    choice = input("Would you like to get started or read what this tool is about? (S/s OR R/r): ") # give a choice whether to start the tool or read about it

    print("\n")

    if choice == 'S' or choice =='s':

        print("Starting tool...")
        time.sleep(1.5)
        
        start_tool()

    elif choice == 'R' or choice == 'r':
        info()

    else:
        print("[-] Invalid choice. Please choose eithr one of the choices!")

main()
