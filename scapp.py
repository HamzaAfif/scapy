from scapy.all import conf, sniff, TCP
import time
from scapy.all import conf

print()
print()


print("*********************************************************************************************")
print("**                                                                                         **")
print("**     _    _ ______ __  __  __          ________ ____    _______ ____   ____  _           **")
print("**    | |  | |  ____|  \/  | \ \        / /  ____|  _ \  |__   __/ __ \ / __ \| |          **")
print("**    | |__| | |__  | \  / |  \ \  /\  / /| |__  | |_) |    | | | |  | | |  | | |          **")
print("**    |  __  |  __| | |\/| |   \ \/  \/ / |  __| |  _ <     | | | |  | | |  | | |          **")
print("**    | |  | | |____| |  | |    \  /\  /  | |____| |_) |    | | | |__| | |__| | |____      **")
print("**    |_|  |_|______|_|  |_|     \/  \/   |______|____/     |_|  \____/ \____/|______|     **")
print("**                                                                                         **")
print("**                                                                                         **")
print("*********************************************************************************************")


print()
print()

print("Pour siniffer les paquets cliquer 1  ")
print("Pour blocker des sites web cliquer 2 ")
print("Pour voire les paquets suspect cliquer 3 ")

print()
print()


z = input("Tapper votre choix : ")

if z.isdigit() and int(z) == 1:

        def process_packet(packet):
            packet_size = len(packet)
            print(f"{packet.summary()}, Size: {packet_size} bytes")

            if packet.haslayer(TCP):
                tcp_layer = packet[TCP]
                
                if tcp_layer.flags & 0x02 and tcp_layer.flags & 0x01:
                    with open("C://Users//Hamza//Desktop//worrying_packets.txt", "a") as file:
                        file.write(f"Paquet préoccupant trouvé: {packet.summary()}\n")
                    print("Paquet préoccupant trouvé (TCP avec SYN et FIN)")

            time.sleep(1)

        def list_interfaces():

            interfaces = [(iface, conf.ifaces[iface].description, conf.ifaces[iface].name) for iface in conf.ifaces]
            print("Les interfaces dispo:")
            for idx, (iface_idx, description, name) in enumerate(interfaces):
                print(f"Index: {idx}")
                print(f"  Description: {description}")
                print(f"  ID: {iface_idx}")
                print(f"  Nom: {name}")
                print("-" * 30)  
            return interfaces
        
        
        interfaces = list_interfaces()
        choice = input("Entrer le num d'interface (tapper 'general' pour toute les interface): ")

        if choice.lower() == 'general':
            print("Sniffing tout les interfaces...")
            sniff(prn=process_packet, store=False)

        elif choice.isdigit() and int(choice) < len(interfaces):

            selected_interface_idx = int(choice)
            selected_interface = conf.ifaces[interfaces[selected_interface_idx][0]].name
            print(f"Sniffing L'interface: {selected_interface}")
            sniff(prn=process_packet, store=False, iface=selected_interface)
            
        else:
            print("Choix invalide.")
        
        
        


elif z.isdigit() and int(z) == 2:

        def get_websites_to_block():
            websites = []
            print("Enterer les sites web a blocker, tapper '00' pour terminer.")
            while True:
                website = input("Enterer le site web: ")
                if website == '00':
                    break
                websites.append(website)
            return websites


        def block_websites(websites):
            hosts_path = "/etc/hosts"  # pour Windows, il faut utiliser 'C://Windows//System32//drivers//etc//hosts'
            redirect_ip = "127.0.0.1"

            with open(hosts_path, 'a') as file:
                for website in websites:
                    file.write(f"\n{redirect_ip} {website}")
                    print(f"{website} blocked")


        websites_to_block = get_websites_to_block()
        block_websites(websites_to_block)


elif  z.isdigit() and int(z) == 3:

     with open("C://Users//Hamza//Desktop//worrying_packets.txt", "r") as file:
            data = file.read()
            if data:
                print("Paquets dangeureux enregistrees :")
                print(data)
            else:
                print("Aucun paquet dangeureux enregistree.")


else:
     
    print("Choix non valide")