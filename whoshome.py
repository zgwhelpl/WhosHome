import nmap
import configparser
from tabulate import tabulate

config = configparser.ConfigParser()

config.read("config.ini")
router = config["SETTINGS"]["Router"]


mac_mapping = dict(config.items("MAC_MAPPING"))

nm = nmap.PortScanner()


nm.scan(hosts = router + '/24', arguments = '-sP')

#for every device in all hosts that has a mac address, append to list
mac_address_list = list(set([nm[host]['addresses']['mac'] for host in nm.all_hosts() if 'mac' in nm[host]['addresses']]))

known_present = [mapping for mapping in mac_mapping.items() if mapping[1] in  mac_address_list]  
known_absent = [mapping for mapping in mac_mapping.items() if mapping[1] not in mac_address_list]
unknown_present = [mac for mac in mac_address_list if mac not in mac_mapping.values()]

print("\n-----KNOWN  HOSTS-----")
print(tabulate(known_present, headers = ["Host", "Mac Address"]))
print("\n-----KNOWN ABSENT-----")
print(tabulate(known_absent, headers = ["Host", "Mac Address"]))
print("\n---STRANGER DANGER!---")
print(tabulate([[mac] for mac in unknown_present], headers = ["Mac Address"]))

