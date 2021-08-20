from __future__ import print_function
import bloxonedhcpleases
from bloxonedhcpleases.rest import ApiException
from pprint import pprint
import json
from time import datetime

# Configure API key authorization: ApiKeyAuth
configuration = bloxonedhcpleases.Configuration()
configuration.api_key['Authorization'] = '79ee2a3d87ac1bdf3c6732c5b281b69d7bc354df2699af79eeb53649e41a6fff'
configuration.api_key_prefix['Authorization'] = 'token'

#create an instance of the API class
apiKey = '79ee2a3d87ac1bdf3c6732c5b281b69d7bc354df2699af79eeb53649e41a6fff'
api_instance = bloxonedhcpleases.LeaseApi(bloxonedhcpleases.ApiClient(configuration))
api_instance = bloxonedhcpleases.LeaseApi(bloxonedhcpleases.ApiClient(configuration))
try:
    # List Lease objects.
    api_response = api_instance.lease_list()
    pprint(api_response)
except ApiException as e:
    print("Exception when calling LeaseApi->lease_list: %s\n" % e)
sleep(300)
CSPleases = api_response.results
# Load JSON test file with 50+ fake leases to test if the counters are updating correctly
with open('/Volumes/Vault/WarehouseScripts/BloxOne/infoblox-scripts/compDHCPLeases/testleases.json', 'r') as ft:
    NIOSDHCPLeases = json.load(ft)
    sleep(300)
    temp_dict = {}
    for lease in CSPleases:
        # Reset active value, which is the current lease count for any network.
        temp_dict['active'] = 0
        # description has already a CIDR network address that we will use to classify the leases
        if csvheader[i].lower() == 'description':
            cidr = row[i]
        elif csvheader[i].lower() == 'source_lease_activity':
            temp_dict['source_lease_activity'] = row[i]
        elif csvheader[i].lower() == 'network_view':
            temp_dict['network_view'] = row[i]
        elif csvheader[i].lower() == 'dhcp_members':
            temp_dict['dhcp_members'] = row[i]
        elif csvheader[i].lower() == 'dest_lease_activity':
            # if network present in past iteration, copy the old current leases into the dest_least field (to
            # compare past with present results)
            if cidr in last_pass_dict.keys():
                temp_dict['dest_lease_activity'] = last_pass_dict[cidr]['active']
                
# Update the field 
for x in range(len(NIOSDHCPLeases)):
    # Capture the error in case is not a valid IP address
    try:
        # If the lease IP address is contained in the IP network and the network_view
        #  also matches, then we know the IP can only belong to the current network/address block
        if ipaddress.IPv4Address(NIOSDHCPLeases[x]['address']) in ipaddress.IPv4Network(cidr):
            if NIOSDHCPLeases[x]['space'] == temp_dict['network_view']:
                temp_dict['active'] += 1
    except ipaddress.AddressValueError:
        print('IP address format not valid')
        continue
        # Record is added to the dictionary only if source_lease_activity=yes
if temp_dict['source_lease_activity'].lower() == 'yes':
    leaseCountDict[cidr] = temp_dict


{'address': '192.168.1.169',
 'client_id': '',
 'ends': datetime.datetime(2021, 8, 20, 12, 52, 52, tzinfo=tzutc()),
 'fingerprint': 'Espressif',
 'fingerprint_processed': 'processed',
 'ha_group': None,
 'hardware': '84:cc:a8:95:5c:54',
 'host': 'dhcp/host/311639',
 'hostname': 'esp-955c54.ml107.net',
 'last_updated': datetime.datetime(2021, 8, 20, 8, 52, 52, 831579, tzinfo=tzutc()),
 'options': '{"Options":[{"Code":"12","Value":"RVNQLTk1NUM1NA=="},{"Code":"50","Value":"wKgBqQ=="},{"Code":"53","Value":"Aw=="},{"Code":"54","Value":"CioAaw=="},{"Code":"55","Value":"AQMcBg8sLi8fIXkr"},{"Code":"57","Value":"Bdw="},{"Code":"82","Value":"CwTAqAES"}]}',
 'space': 'ipam/ip_space/f966ac2e-c7b3-11eb-ba4d-02610c2e00af',
 'starts': datetime.datetime(2021, 8, 20, 8, 52, 52, tzinfo=tzutc()),
 'state': 'used'}