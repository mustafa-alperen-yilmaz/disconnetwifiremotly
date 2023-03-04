import uuid
from scapy.all import ARP, Ether, srp
import paramiko

# Function to get the MAC address of the Wi-Fi interface
def get_mac_address():
    mac_address = ':'.join(['{:02x}'.format((uuid.getnode() >> ele) & 0xff) 
                  for ele in range(0,8*6,8)][::-1])
    return mac_address

# Function to discover MAC addresses of devices on the local network
def discover_devices():
    # Define the IP address range to scan
    ip_range = '192.168.1.0/24'

    # Create an ARP request packet to send to each IP address in the range
    arp_request = ARP(pdst=ip_range)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = ether/arp_request

    # Send the ARP request packet and retrieve the response
    result = srp(arp_request_broadcast, timeout=3, verbose=0)[0]

    # Parse the response and return the MAC addresses of the discovered devices
    devices = []
    for sent, received in result:
        devices.append({'ip': received.psrc, 'mac': received.hwsrc})
    return devices

# Function to disconnect a device from the network using SSH
def disconnect_device(device_mac_address):
    # Set the credentials for the router
    router_address = '192.168.1.1'
    router_username = 'admin'
    router_password = 'password'

    # Log in to the router via SSH
    ssh_client = paramiko.SSHClient()
    ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh_client.connect(router_address, username=router_username, password=router_password)

    # Issue commands to disconnect the specified device
    stdin, stdout, stderr = ssh_client.exec_command('arp -a')
    output = stdout.readlines()

    for line in output:
        if device_mac_address in line:
            ip_address = line.split()[1].strip('()')
            ssh_client.exec_command(f'arp -d {ip_address}')

    # Close the SSH connection
    ssh_client.close()

# Get the MAC address of the Wi-Fi interface
my_mac_address = get_mac_address()
print(f"My MAC address: {my_mac_address}")

# Discover MAC addresses of devices on the local network
devices = discover_devices()
print("Discovered devices:")
for device in devices:
    print(f"IP: {device['ip']}, MAC: {device['mac']}")

# Disconnect a device from the network (replace with the MAC address of a device on your network)
# disconnect_device('00:11:22:33:44:55')
