import requests
import json

requests.packages.urllib3.disable_warnings()
def_view_url = "https://csp.infoblox.com/api/ddi/v1//dns/view?_fields=id&_filter=name==\"default\""     # This customer only has a view: default so the viewid will not change
csp_url = "https://csp.infoblox.com/api/ddi/v1//dns/record"
grid_ip = "10.99.4.1"

headers = {'Authorization': 'Basic YWRtaW46aW5mb2Jsb3g=','Cookie': 'ibapauth="group=Super%20Admin,ctime=1628897356,ip=10.99.4.5,su=1,client=API,auth=LOCAL,timeout=6000,mtime=1628915380,user=admin,fwyxDek7iDZ1AlNlkan6Klib0V6TUkflf/w"'}
headers_csp = {'Content-Type': 'application/json','Authorization': 'Token 2b71a72f344ddf9602f56c81f16f6a872b2fff889069bb01f3d8f1a803b4b2be'}

nios_url = "https://"+grid_ip+"/wapi/v2.3/"
sharedRecGroups = {	'CST externat_internal DNS': 	['cst.werum.com'],
                    'Exchange_Mail_MX': 			['werum.com'],
                    'Loadbalancer_URLS': 			['werum.com'],
                    'Lync2013_internal_com': 		['werum.com'],
                    'OneNote TXT': 				    ['werum.com'],
                    'SPF Mailcheck': 				['werum.com'],
                    'Stage Records': 				['werum.com'],
                    'Telephony': 					['werum.com'],
                    'VPN Resolveable': 			    ['werum.com'],
                    'WWW C3/F7': 					['werum.com'],
                    'WWW External': 				['werum.com'],
                    'external MX Records': 			['werum.com'],
                    'Lync2013_internal': 			['werum.net'],
                    'werum.net': 					['werum.net'],
                    'Werum Requied Domain Entrys':  ['_tcp.th.werum.net', '_tcp.us.werum.net', '_tcp.werum.net'],
                    'Videokonferenz': 				['de.werum.com'],
                    'x.de.werum.com': 				['de.werum.com'],
                    'tnt.werum.com': 				['tnt.werum.com'],
                    'x.werum.asia': 				['werum.asia'],
                    'x.us.werum.com': 				['us.werum.com'],
                    'x.th.werum.com': 				['th.werum.com'],
                    'WWW Bitmotion': 				['de.werum.com', 'werum.asia', 'werum.com']
                    }

def buildPayload (fqdn,rectype,record, zone, viewid):
    if rectype == 'a':
        payload = json.dumps({'absolute_name_spec' : fqdn, 'view': viewid, 'rdata': { 'address': record['ipv4addr']}, 'type': 'A'})
    elif rectype == 'mx':
        payload = json.dumps({'absolute_name_spec' : fqdn, 'rdata': { 'exchange': record['mail_exchanger'], 'preference': record['preference']}, 'view': viewid, 'type': 'MX'})
    elif rectype == 'txt':
        payload = json.dumps({'absolute_name_spec' : fqdn, 'view': viewid, 'rdata': { 'text': record['text']}, 'type': 'TXT'})
    elif rectype == 'cname':
        payload = json.dumps({'absolute_name_spec' : fqdn, 'view': viewid, 'rdata': { 'cname': record['canonical']}, 'type': 'CNAME'})
    elif rectype == 'srv':
        payload = json.dumps({'absolute_name_spec' : fqdn, 'view': viewid, 'rdata': { 'priority': record['priority'], 'weight': record['weight'], "target": record['target'], 'port': record['port']}, 'type': 'SRV'})
    return payload

def createDNSRecord (rectype, csp_url, record, zone, viewid):
    if record['name'] != '':                                #TXT records with empty name will fail
        record['name'] = record['name'] + '.'  
    if len(zone) == 1:                          #Those Shared Groups associated with just a single zone                      
        fqdn = record['name'] + zone[0]
        payload = buildPayload (fqdn,rectype,record, zone, viewid)
        response = requests.request( 'POST', csp_url, headers=headers_csp, verify=False, data=payload).json()
        #print(json.dumps(response))
        
    elif len(zone) > 1:                         #Those Shared Groups associated with more than one zone
        for z in zone:
            fqdn = ''
            fqdn = record['name'] + z
            payload = buildPayload (fqdn,rectype,record, zone, viewid)
            response = requests.request( 'POST', csp_url, headers=headers_csp, verify=False, data=payload).json()
            print(json.dumps(response))
    return

view = requests.request("GET", def_view_url, headers=headers_csp,verify=False, data={}).json()     #This API call returns the view
viewid = view['results'][0]['id']
for rectype in ['a', 'cname', 'txt', 'srv', 'mx']:      #Only these record types are supported with Shared Record Groups
    url = nios_url + "sharedrecord:" + rectype          # This string will be the URL of the 5 types of shared records in NIOS
    dictsharedrec = requests.request("GET", url, headers=headers, verify=False).json()
    for record in dictsharedrec:
        zone = sharedRecGroups[record['shared_record_group']]   # sharedRecGroups[record['shared_record_group']] returns the zone where the record should be created
        createDNSRecord(rectype, csp_url, record, zone, viewid)