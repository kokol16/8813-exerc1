import argparse
import pyshark






def ParseArguments():
    argParser = argparse.ArgumentParser()
    argParser.add_argument("--file")
    argParser.add_argument("--protocols", default=False, action="store_true")
    argParser.add_argument("--contx", default=False, action="store_true")
    argParser.add_argument("-n", type=int)
    argParser.add_argument("--dests", default=False, action="store_true")
    argParser.add_argument("--sources", default=False, action="store_true")
    argParser.add_argument("--windows", default=False, action="store_true")
    argParser.add_argument("--evasive", default=False, action="store_true")
    argParser.add_argument("--talkers", default=False, action="store_true")

    args = argParser.parse_args()
    if args.n and (not args.dests and not args.sources):
        print("error")
        return None
    if not args.n and (args.dests or args.sources):
        print("error")
        return None
    return args

def getTopTalkers(cap):
    talkers = {}
    for pkt in cap:
        dst = pkt["ip"].dst
        source = pkt["ip"].src
        str1 = dst + "-" + source
        str2 = source + "-" + dst
        if str1 not in talkers:
            if str2 not in talkers:
                talkers[str2] = 1
            else:
                talkers[str2] += 1
        else:
            talkers[str1]+=1
    talkers = dict(sorted(talkers.items(), key = lambda item:item[1],reverse=True ))
    print(talkers)
    return talkers

def getSuspiciousConnections(cap):
    standardPorts = {"http" : 80, "https":443,"dns":53}
    for pkt in cap:
        port = 0
        if pkt.transport_layer == "TCP":
            port = pkt.tcp.dstport
        elif pkt.transport_layer == "UDP":
            port = pkt.udp.dstport
        if port ==0: continue
        for layer in pkt.layers:
            layer_name = layer.layer_name.lower()
            if layer_name in standardPorts:
                if int(port) != standardPorts[layer_name]:
                    #HTTP
                    if layer_name == "http":
                        #print(dir(pkt.http))
                        #print(type(pkt.http.host))
                        #if  "host" in str(pkt.http):
                        #    print(pkt.http.host)
                        print("Source IP Address: ",pkt["ip"].src)
                        print("Destination IP Address: ",pkt["ip"].dst)
                        print("port: ",port)
                        try:
                            print("URL:", pkt.http.response_for_uri)
                        except AttributeError:
                            pass
                        try:
                            print("Content:" , pkt.http.content_type)
                        except AttributeError:
                            pass
                        try:                            
                            print("Host:", pkt.http.host)
                        except AttributeError:
                            pass
                        print("=" * 30)

                        #print(pkt.http.host)
                        #print(pkt.http.uri)



                    #print(layer_name,port)
def getDestinationAddresses(cap,n):
    dest_ips_count = {}
    for pkt in cap:
        dst = pkt["ip"].dst
        if dst not in dest_ips_count:
            dest_ips_count[dst] = 1
        else:
            dest_ips_count[dst] += 1
    return dict(sorted(dest_ips_count.items() , key = lambda item:item[1],reverse=True))
    
def getSourceAddresses(cap,n):
    src_ips_count = {}
    for pkt in cap:
        src = pkt["ip"].src
        if src not in src_ips_count:
            src_ips_count[src] = 1
        else:
            src_ips_count[src] += 1
    return dict(sorted(src_ips_count.items() , key = lambda item:item[1],reverse=True))

def print_addresses(addrs,n):
    print("IP Address \t Tx Packets")
    for count,(addr,freq) in enumerate(addrs.items()):
        print(addr, "\t" ,freq)
        if count == n: break

def printProtocols(protocols):
    print("Layer\tProtocol\tRank")
    for key,val in protocols.items():
        print(key, "\t",end =" ")
        count =0
        for protocol,freq in val.items():
            if count ==0:
                count+=1
                print(protocol, "\t",freq)
            else:
                print("\t",protocol, "\t",freq)



"""
we have a dictionary {"Transport" : { "TCP": 1 , "UDP: 2}}
"""
layer_4_protocols = ["tcp","udp"]
layer_2_protocols = ["eth"]
layer_3_protocols = ["ip","igmp"]
layer_7_protocols = ["http","https","dns","dhcp","llmnr","mdns","nbns"]
def getProtocolsFrequencyPerLevel(cap):
    protocols = {"Application":{}, "Transport" : {}, 'Network' : {}, "Data Link" : {}}
    for pkt in cap:
        for layer in pkt.layers:
            layer_name = layer.layer_name.lower()
            #print(layer_name)
            if layer_name in layer_4_protocols:
                if layer_name not in protocols["Transport"]:
                    print(layer_name)
                    protocols["Transport"][layer_name] = 1
                else:
                    protocols["Transport"][layer_name]+=1
            elif layer_name in layer_2_protocols:
                if layer_name not in protocols["Data Link"]:
                    protocols["Data Link"][layer_name] = 1
                else:
                    protocols["Data Link"][layer_name]+=1
            elif layer_name in layer_3_protocols:
                if layer_name not in protocols["Network"]:
                    protocols["Network"][layer_name] = 1
                else:
                    protocols["Network"][layer_name]+=1
            elif layer_name in layer_7_protocols:
                if layer_name not in protocols["Application"]:
                    protocols["Application"][layer_name] = 1
                else:
                    protocols["Application"][layer_name]+=1
    
    printProtocols(protocols)
    return protocols
            #print((layer))
            #print()
            #print(layer.id)
            #print(layer.type)
            #print("=" * 30)
            
        #print(pkt)
        #layer = pkt.highest_layer
        #print(layer)
        #print("=" * 30)

        #
        # print(layer,",", pkt.layers)
        #break
"""
    look for a tcp handshake

"""
def getNumberOfSuccessfulTcpConnections(cap):
    syn_flag = 0x0002  # SYN flag value
    ack_flag = 0x0010  # ACK flag value
    syn_ack = 0x012
    active_connections = {}
    established_connections = 0
    for pkt in cap:
        if pkt.transport_layer == "TCP":
            #probably a TCP connection just opening
            #print(pkt.tcp.seq)
            #print(pkt.tcp.flags)
            #print("=========")
            if(int(pkt.tcp.flags,base=16) == int(syn_flag) )and (int(pkt.tcp.seq) == 0):
                active_connections[pkt.ip.dst] = 1
            #probably finishing the handshake
            if(int(pkt.tcp.flags,base=16) == int(ack_flag)) and (int(pkt.tcp.seq) == 1):
                if(pkt.ip.dst in active_connections ):
                    established_connections+=1
                    del active_connections[pkt.ip.dst]
            #Probably a handshake just finished
            #print((pkt.tcp))
            #print(pkt.tcp.ack)
            #print(pkt.tcp.seq)
            #print(pkt.tcp.flags)

        #if("TCP" in str(pkt.layers)):
            #print(dir(pkt.tcp))
    print("established connections: ", established_connections)
    return established_connections
def getCompromisedIpsConnections(cap):
    ips = ["192.168.204.146", "192.168.204.139" , "192.168.204.137"]
    communications = {"192.168.204.146":[], "192.168.204.139" :[], "192.168.204.137": []}
    communications_domains = {"192.168.204.146":[], "192.168.204.139" :[], "192.168.204.137": []}

    src = None
    for pkt in cap:
        if 'ip' in pkt:
            src = pkt["ip"].src
            if src in ips:
                if pkt["ip"].dst not in communications[src]:
                    communications[src].append(pkt["ip"].dst)
            else: src=None
        if 'dns' in pkt:
            if src:
                if "qry_name" in pkt.dns.field_names:
                    if pkt.dns.qry_name not in communications_domains[src]:
                        communications_domains[src].append((pkt.dns.qry_name))

    table_data = []
    for key in communications_domains.keys():
        table_data.append([key] + communications_domains[key])
    
    # Print the table
    #for elem in communications:
        #print(elem , ":", communications[elem])
    #print(communications_domains)
    #df = pandas.DataFrame(communications_domains)
    #print(df)
    print(communications_domains)
    print(communications)



#assuming that http header is not maliciously altered
#What a bad assumption 
def getWindowsHosts(cap):
    windows_versions = {"6.1" : "Windows 7", "6.0" : "Windows vista",  "6.2" : "Windows 8", "6.3" : "Windows 8.1" , "5.1": "Windows XP", "10.0" : "Windows 10/11"}
    hosts = []
    for pkt in cap:
        Windows_host = {"Host Name": None, "Work Group" : None , "Mac Address": None, "IP Address" : None, "OS" : None}
        if 'ip' in pkt:
            src = pkt["ip"].src
            Windows_host["IP Address"] = src
        if 'nbns' in pkt:
            if "name" in pkt.nbns.field_names:
                #print("lala")
                Windows_host["Host Name"] = pkt.nbns.name.split("<")[0]
                Windows_host["Work Group"] = pkt.nbns.name.split("<")[1].replace(">","")
        if 'http' in pkt:
            http_packet = pkt.http
            if 'user_agent' in http_packet.field_names:
                #print("OS:" ,http_packet.user_agent.split(";"))
                user_agent = http_packet.user_agent.split(";")
                for elem in user_agent:
                    if "Windows" in elem:
                        val = elem.split(" ")
                        for index , elem in enumerate(val):
                            if "Windows" in elem:
                                Windows_host["OS"] = windows_versions[val[index+2]]
                                break
        if 'eth' in pkt:
            Windows_host["Mac Address"] = pkt.eth.src
        #if Windows_host["OS"] == None: continue
        if not hosts :  hosts.append(Windows_host);continue
        found = False
        for host in hosts:
            if Windows_host["Mac Address"] == host["Mac Address"]:
                for val in host:
                    if host[val] == None:
                        host[val] = Windows_host[val]    
                found = True
                break
            
        if not found and  Windows_host["OS"] != None:
            hosts.append(Windows_host)
    
    for host in hosts:
        print(host)
        

def main():
    args = ParseArguments()
    if not args: return
    cap = pyshark.FileCapture(args.file)
    #getNumberOfSuccessfulTcpConnections(cap)
    #getProtocolsFrequencyPerLevel(cap)
    #getTopTalkers(cap)
    #getSuspiciousConnections(cap)
    #getWindowsHosts(cap)
    #getCompromisedIpsConnections(cap)
    if args.dests:
        dests = getDestinationAddresses(cap,args.n)
        print("top " , args.n , "Destination Addresses")
        print_addresses(dests,args.n)
    if args.sources:
        srcs = getSourceAddresses(cap,args.n)
        print("top " , args.n , "Source Addresses")
        print_addresses(srcs,args.n)
    if args.windows:
        getWindowsHosts(cap)
    if args.evasive:
        getSuspiciousConnections(cap)
    if args.talkers:
        getTopTalkers(cap)

    #return
    #print(cap[0]["ip"].dst)
    #for pkt in cap:   
        #print(pkt)
        #break
main()
