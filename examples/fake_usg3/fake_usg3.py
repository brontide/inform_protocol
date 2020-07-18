
from pprint import pprint
import sys
from aioedgeos import EdgeOS, find_subkey, TaskEvery
#from contextlib import AsyncExitStack
from time import time, sleep
import json
from random import randint
import asyncio
from aiohttp import ClientSession,Fingerprint

from ipaddress import ip_address,ip_network

from binascii import a2b_hex
import inform

########################
#
# Config items 
#
########################
from dotenv import load_dotenv
load_dotenv()
import os

DEBUG_MODE=os.environ.get('DEBUG_MODE', False)

EDGE_USERNAME=os.environ['EDGE_USERNAME']
EDGE_PASSWORD=os.environ['EDGE_PASSWORD']
EDGE_URL=os.environ['EDGE_URL']
INFORM_URL=os.environ['INFORM_URL']
EDGE_SSL=os.environ.get('EDGE_SSL', 'f'*64).lower() # Default to enforcing ssl

WAN_IFNAME=os.environ.get('WAN_IFNAME','eth0')
LAN_IFNAME=os.environ.get('LAN_IFNAME','eth1')

ssl_check = True
if isinstance(EDGE_SSL, str) and len(EDGE_SSL) == 64:
    # presume this is a fingerprint
    ssl_check = Fingerprint(a2b_hex(EDGE_SSL))
elif EDGE_SSL in [ 'no', 'false']:
    ssl_check = False
elif EDGE_SSL in [ 'yes', 'true']:
    ssl_check = True
else:
    raise Exception(f"EDGE_SSL {EDGE_SSL} is invalid")

#gateway_lan_ip = '192.168.15.1'
#gateway_lan_mac = 'fc:ec:da:46:d5:95'
#gateway_wan_ip = '96.236.36.94'
#gateway_wan_def = '96.236.36.1'
#gateway_wan_net = '96.236.36.0/24'
#gateway_wan_mac = '46:ce:eb:5a:80:83'
#serialno = 'FCECDA46D595'
state = 2
edge_device = None

def fake_mac():
    mac = [ hex(randint(0,255))[2:] for _ in range(6) ]
    return ":".join(mac)

# Load the mgt data or setup for adoption
try:
    mgt = json.load(open('data/mgt.json'))
except:
    mgt = {
        'authkey': "ba86f2bbe107c7c57eb5f2690775c712",
        'version': "4.4.51.5287926",
        'gateway_lan_mac': fake_mac(),
        }

# If we have the adoption key then we are in the default state
default = ( mgt['authkey'] == "ba86f2bbe107c7c57eb5f2690775c712" )

# Used to convert IPs to MACs since EdgeOS uses IPs and controller wants MACs
ip2mac1 = {}
ip2mac2 = {}


def config_extract_map(config):
    ip2mac = {}
    for mapping in find_subkey(config, 'static-mapping'):
        for name, value in mapping.items():
            ip2mac[value['ip-address']] = {
                'ip': value['ip-address'],
                'mac': value['mac-address'],
                'name': name,
                }
    global ip2mac1
    ip2mac1.update(ip2mac)
    return ip2mac

def leases_extract(leases):
    ip2mac = {}
    for lan, lan_lease in leases['dhcp-server-leases'].items():
        if not isinstance(lan_lease, dict): continue
        for ip, value in lan_lease.items():
            name = value['client-hostname']
            if len(name) == 0:
                name = None
            ip2mac[ip] = {
                'ip': ip,
                'mac': value['mac'],
                'name': name
                }
    global ip2mac2
    ip2mac2.update(ip2mac)
    return ip2mac

def best_id_name(ip):
    if ip in ip2mac1:
        return ip2mac1[ip]['mac'], ip2mac1[ip]['name']
    if ip in ip2mac2:
        return ip2mac2[ip]['mac'], ip2mac2[ip]['name']
    return None, None

async def dhcp_refresh_loop(router):
    try:
        while True:
            config_extract_map(router.sysconfig)
            await router.dhcp_leases()
            leases_extract(router.sysdata['dhcp_leases'])
            await asyncio.sleep(600)
    except asyncio.CancelledError:
        pass

#
# Convert EdgeOS export data ( DPI ) to the format needed
#  for the inform protocol
#
def export_to_hosts(network):
    network = ip_network(network,strict=False)
    ret = []
    export = edge_device.sysdata['export']
    for ip, dpi in export.items():
        if not ip_address(ip) in network: continue
        mac, hostname = best_id_name(ip)
        if not mac: continue
        temp = {
            'authorized': True,
            'mac': mac,
            'ip': ip,
            'rx_bytes': 0,
            'tx_bytes': 0,
            }
        if hostname:
            temp['hostname'] = hostname
        for app, value in dpi.items():
            temp['rx_bytes'] += int(value['rx_bytes'])
            temp['tx_bytes'] += int(value['tx_bytes'])
        ret.append(temp)
    return ret

def dict_to_array(foo):
    temp = []
    for key, value in foo.items():
        temp2 = value.copy()
        temp2['name'] = key
        if temp2.get('duplex','full') == 'full':
            temp2['full_duplex'] = True
        else:
            temp2['full_duplex'] = False
        try:
            del temp2['duplex']
        except:
            pass
        if 'speed' not in temp2: # ERx hack
            temp2['speed'] = '1000'
        temp.append(temp2)
    return temp

def generate_inform():
    temp = {
     'bootrom_version': 'unknown',
     'cfgversion': mgt.get('cfgversion','?'),
     'config_network_wan': {
         'type': 'dhcp',
     },
#     'config_port_table': [
#         {
#             'ifname': 'eth0',
#             'name': 'WAN 1'
#         },
#         {
#             'ifname': 'eth1',
#             'name': 'LAN 1'
#         },
#         {
#             'ifname': 'eth1.10',
#             'name': 'MGT'
#         },
#         {
#             'ifname': 'eth1.20',
#             'name': 'GST'
#         },
#         {
#             'ifname': 'eth2',
#             'name': 'LAN 2'
#         }
#     ],
     'uplink': WAN_IFNAME,
     # STUN PORT TODO
     'connect_request_ip': '127.0.0.1',
     'connect_request_port': 65535,
     # END STUN
     'default': default,
     'discovery_response': False,
     'fw_caps': 3,
     'guest_token': '4C1D46707239C6EB5A2366F505A44A91',
     'has_default_route_distance': True,
     'has_dnsmasq_hostfile_update': False,
     'has_eth1': True,
     'has_porta': True,
     'has_ssh_disable': True,
     'has_vti': True,
#     'hostname': 'tesing',
     'inform_url': INFORM_URL,
#     'ip': gateway_lan_ip,  # Shows as IP in device list
     'isolated': False,
     'locating': False,
     'mac': mgt.get('gateway_lan_mac'),
     'model': 'UGW3',
#     'model_display': 'EdgeRouter 4',
#     'netmask': '255.255.255.0',
     'required_version': '4.0.0',
     'selfrun_beacon': True,
#     'serial': serialno,
     'state': state,
     'system-stats': edge_device.sysdata.get('system-stats', dict()),
#     'system-stats': {
#         'cpu': '2',
#         'mem': '20',
#         'uptime':  time() - 1590603501
#     },
#     'routes': dumont.sysdata.get('routes', dict()),
#     'routes': [
#         {
#             'nh': [
#                 {
#                     'intf': 'eth0',
#                     'metric': '1/0',
#                     't': 'S>*',
#                     'via': gateway_wan_def,
#                 }
#             ],
#             'pfx': '0.0.0.0/0'
#         },
#         {
#             'nh': [
#                 {
#                     'intf': 'eth0',
#                     't': 'C>*'
#                 }
#             ],
#             'pfx': gateway_wan_net,
#         },
#         {
#             'nh': [
#                 {
#                     'intf': 'eth1',
#                     't': 'C>*'
#                 }
#             ],
#             'pfx': '192.168.1.0/24'
#         },
#     ],
#     'if_table': [
#         {
#	     'name': 'eth0',
#             'enable': True,
#             'speed': 1000,
#             'full_duplex': True,
#             'up': True,
#             'mac': gateway_wan_mac,
#             'ip': gateway_wan_ip,
#             'netmask': '255.255.255.0',
#             'gateways': [
#                 gateway_lan_ip
#             ],
#             'latency': randint(5,50),
#             'rx_bytes': 353519562926 + randint(0, 200000),
#             'rx_dropped': 19137 + randint(0, 2000),
#             'rx_errors': 0,
#             'rx_multicast': 65629 + randint(0, 2000),
#             'rx_packets': 645343103 + randint(0, 200000),
#             'tx_bytes': 953646055362 + randint(0, 200000),
#             'tx_dropped': 0,
#             'tx_errors': 0,
#             'tx_packets': 863173990 + randint(0, 200000),
#             'uptime': time() - 1590603501, 
#     #        'xput_down': 8,
#     #        'xput_up': 1,
#             'num_port': 1,
#         },
#         {
#	     'name': 'eth1',
#             'speed': 100,
#             'enable': True,
#             'full_duplex': True,
#             'up': True,
#             'mac': gateway_lan_mac,
#             'ip': gateway_lan_ip,
#             'netmask': '255.255.255.0',
#             'uptime': time() - 1590603501, 
#             'num_port': 2,
#             'rx_bytes': 353519562926 + randint(0, 200000),
#             'rx_dropped': 19137 + randint(0, 2000),
#             'rx_errors': 0,
#             'rx_multicast': 65629 + randint(0, 2000),
#             'rx_packets': 645343103 + randint(0, 200000),
#             'tx_bytes': 953646055362 + randint(0, 200000),
#             'tx_dropped': 0,
#             'tx_errors': 0,
#             'tx_packets': 863173990 + randint(0, 200000),
#         },
#         {
#             'enable': False,
#             'full_duplex': True,
#             'up': False,
#             'num_port': 3,
#         }
#     ],
#     'network_table': [
#         {
#             'address': '192.168.111.1/24',
#             'addresses': [
#                 '%s/24' % gateway_lan_ip
#             ],
#             'autoneg': 'true',
#             'duplex': 'full',
##             'host_table': [
##                 {
##                     'age': 0,
##                     'authorized': True,
##                     'bc_bytes': 4814073447,
##                     'bc_packets': 104642338,
##                     'dev_cat': 1,
##                     'dev_family': 4,
##                     'dev_id': 239,
##                     'dev_vendor': 47,
##                     'ip': '192.168.1.8',
##                     'mac': '80:2a:a8:f0:ef:78',
##                     'mc_bytes': 4814073447,
##                     'mc_packets': 104642338,
##                     'os_class': 15,
##                     'os_name': 19,
##                     'rx_bytes': 802239963372,
##                     'rx_packets': 805925675,
##                     'tx_bytes': 35371476651,
##                     'tx_packets': 104136843,
##                     'uptime': 5822032
##                 },
##                 {
##                     'age': 41,
##                     'authorized': True,
##                     'bc_bytes': 9202676,
##                     'bc_packets': 200043,
##                     'hostname': 'switch',
##                     'ip': '192.168.1.10',
##                     'mac': 'f0:9f:c2:09:2b:f2',
##                     'mc_bytes': 21366640,
##                     'mc_packets': 406211,
##                     'rx_bytes': 30862046,
##                     'rx_packets': 610310,
##                     'tx_bytes': 13628015,
##                     'tx_packets': 204110,
##                     'uptime': 5821979
##                 },
##                 {
##                     'age': 8,
##                     'authorized': True,
##                     'bc_bytes': 2000,
##                     'bc_packets': 3000,
##                     'mac': 'f0:9f:c2:09:2b:f3',
##                     'mc_bytes': 21232297,
##                     'mc_packets': 206139,
##                     'rx_bytes': 21232297,
##                     'rx_packets': 206139,
##                     'tx_bytes': 4000,
##                     'tx_packets': 5000,
##                     'uptime': 5822017
##                 }
##             ],
#             'l1up': 'true',
#             'mac': '80:2a:a8:cd:a9:53',
#             'mtu': '1500',
#             'name': 'eth1',
#             'speed': '1000',
#             'stats': {
#                 'multicast': '412294',
#                 'rx_bps': '342',
#                 'rx_bytes': 52947224765,
#                 'rx_dropped': 2800,
#                 'rx_errors': 0,
#                 'rx_multicast': 412314,
#                 'rx_packets': 341232922,
#                 'tx_bps': '250',
#                 'tx_bytes': 792205417381,
#                 'tx_dropped': 0,
#                 'tx_errors': 0,
#                 'tx_packets': 590930778
#             },
#             'up': 'true'
#         },
#         {
#             'address': f'{gateway_wan_ip}/24',
#             'addresses': [
#                 f'{gateway_wan_ip}/24'
#             ],
#             'autoneg': 'true',
#             'duplex': 'full',
#             'gateways': [
#                 f'{gateway_wan_def}'
#             ],
#             'l1up': 'true',
#             'mac': gateway_wan_mac,
#             'mtu': '1500',
#             'name': 'eth0',
#             'nameservers': [
#                 gateway_lan_ip,
#             ],
#             'speed': '1000',
#             'stats': {
#                 'multicast': '65627',
#                 'rx_bps': '262',
#                 'rx_bytes': 353519562926,
#                 'rx_dropped': 19137,
#                 'rx_errors': 0,
#                 'rx_multicast': 65629,
#                 'rx_packets': 645343103,
#                 'tx_bps': '328',
#                 'tx_bytes': 953646055362,
#                 'tx_dropped': 0,
#                 'tx_errors': 0,
#                 'tx_packets': 863173990
#             },
#             'up': 'true'
#         }
#     ],
     'time': time(),
     'uptime': edge_device.sysdata['system-stats']['uptime'],
     'version': mgt.get('version'),
    }
    temp['if_table'] = dict_to_array(edge_device.sysdata['interfaces'])
    #print(temp['if_table'])
    temp['network_table'] = temp['if_table'].copy()
    for x in temp['if_table']:
        stats = x['stats']
        del x['stats']
        for k,v in stats.items():
            x[k] = v
        k = x.get('name', None)
        if k == 'eth0':
            #x['gateways'] = [ gateway_lan_ip, ]
            x['latency'] = int(edge_device.sysdata['ping-data']['1.1.1.1']['avg']) # needed to register internet connection
        #if k == 'eth1':
        #    x['gateways'] = [ gateway_lan_ip, ]
        try:
            x['ip'] = x['addresses'][0].split("/")[0]
        except:
            pass
    for x in temp['network_table']:
        try:
            x['address'] = x['addresses'][0]
            x['host_table'] = export_to_hosts(x['address'])
        except:
            pass
    #print(temp['network_table'])
    #temp['network_table'] = temp['if_table']
    #del temp['if_table']
    #pprint(temp['if_table'])
    return temp


def update_mgt(data):
    for foo in data.splitlines():
        key, value = foo.split('=',1)
        mgt[key] = value
    json.dump(mgt, open('data/mgt.json','wt'),indent=4)

async def inform_send_async(session, data, url):
    if DEBUG_MODE:
        print(data)
    try:
        async with session.post(url, data=data.raw_packet) as resp:
           return inform.Packet(key=data.key, from_packet=await resp.content.read())
    except:
        return None


async def main():
    global mgt, edge_device
    async with ClientSession(raise_for_status=True) as session, EdgeOS(EDGE_USERNAME,EDGE_PASSWORD,EDGE_URL,ssl=ssl_check) as edge_device:
        asyncio.create_task(edge_device.ping_every(interval=90))
        asyncio.create_task(edge_device.data_every('routes', 1800))
        asyncio.create_task(edge_device.data_every('dhcp_leases', 600))
        asyncio.create_task(edge_device.background_stats())
        
        await asyncio.sleep(5)
        while not edge_device.sysdata.get('export',False):
            print("waiting for exports")
            await asyncio.sleep(5)

        await edge_device.config() 
        config_extract_map(edge_device.sysconfig)
        leases_extract(edge_device.sysdata['dhcp_leases'])

        while True:
            inform_data=generate_inform()
            inform_packet = inform.Packet(
                                 key=mgt['authkey'], 
                                 payload_decoded=json.dumps(inform_data), 
                                 flags=11, 
                                 mac_address=inform_data['mac'],
                                 )
            inform_packet.encode()
            out = await inform_send_async(session, inform_packet, INFORM_URL)
            if not out:
                print("No reply")
                await asyncio.sleep(15)
            else:
                # If we got a reply decode it and then sleep based
                # on the reply
                reply = json.loads(out.payload_decoded)
                await asyncio.sleep(min(60,process_reply(reply)))

def process_reply(reply):
    global mgt
    if '_type' not in reply:
        print(f"I don't know how to handle {reply}")
        return 0
    if reply['_type'] == 'setparam':
        for filename in reply.keys():
            if filename == '_type':
                continue
            with open(f'data/{filename}','wt') as fout:
                fout.write(f"{reply[filename]}")
                default = False
            if filename == 'cfgversion':
                mgt['cfgversion'] = reply['cfgversion']
                update_mgt('')
            if filename == 'mgmt_cfg':
                update_mgt(reply['mgmt_cfg'])
    elif reply['_type'] == 'upgrade':
        mgt['version'] = reply['version']
        update_mgt('')
    elif reply['_type'] == 'noop':
        if DEBUG_MODE:
            print(f'Type noop sleeping {reply["interval"]}')
        return reply['interval']
    else:
        print(f'unknown reply {reply}')
    return 0


asyncio.run(main())
