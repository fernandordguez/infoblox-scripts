# **infoblox-scripts**

<p> This repository contains multiple Python scripts that have been developed primarily to automate some of workflows that usually are taken to migrated a NIOS envrionment to BloxOne

[createHWFilter](https://github.com/fernandordguez/infoblox-scripts) :                Creates IPv4 Hardware Filter in BloxOne DDI from a CSV file with a list of MACs (column must have a header called       mac_address)

[nios2b1ddi_bulkhosts.py](https://github.com/fernandordguez/infoblox-scripts):        Enables processing of the NIOS bulkhost records
 
[nios2b1ddi_dhcpLeasesB1vsNios.py](https://github.com/fernandordguez/infoblox-scripts): Compares all the NIOS DHCP leases (collected either from WAPI or Grid Backup file) with the leases available in BloxOne. This should provide improved visibility of the changes after a NIOS to BloxOne migration

[hostsWithinDHCPRanges.py](https://github.com/fernandordguez/infoblox-scripts):         When importing Host records into B1DDI, these are split into different types of objects: 
                                                                                        - DNS record types (A, PTR...) 
                                                                                        - Fixed addresses (after validating that IPs have not been added by DHCP). With NIOS hostrecprds, the IP will not be dynamically assigned to a DHCP client. 
In BloxOne, the IP can fall into an active DHCP drange so the corresponding exclusion ranges (if range) or a fixed addresses (if single) to make sure the IP is not handed to another client. Only those addreses with a valid MAC address are subject to be imported

[nios2b1ddi_SharedRecords2B1DDI.py](https://github.com/fernandordguez/infoblox-scripts): Enables processing of the NIOS Shared Records groups items
  
 
