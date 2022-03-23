## Change Log

### Version 0.5 - Mar 23, 2022
* compares_dhcp_leases_nios_b1ddi.py - Included network view as a command line option (simplifies the code)
   
### Version 0.4 - Mar 21, 2022
* compares_dhcp_leases_nios_b1ddi.py
  * Added logging to local file. 
  * Simplified the function to print the output report

### Version 0.3 - Mar 08, 2022
* compares_dhcp_leases_nios_b1ddi.py
  * Removed support for NIOS WAPI as a source for NIOS leases (replaced with DB or Grid Backup, it was inefficient and slow)
  * Integrated functions (verify_api_key, read_b1_ini) from external custom module into the main script (removed ext module)
  * Added option to only gather the active leases in NIOS (ignores BloxOne)    
  * Added support for Grid Backup files as input 

### Version 0.2 
* nios2b1ddi.py - Rolled up into 0.4
  * Added input option XML with Grid Backup file (.bak or .tar.gz)
  * Added configuration with multiple to avoid terminal input requiring user action
  * Code optimizations to improve performance of some of the fucntions used to process the leases
  * Minor code optimizations
  * When exporting to Google spreadsheets, report will be created always a new worksheet which. Worksheets names
    have a timestamp so this could be used as references to different moments in time when leases were captured
  * Added support for 3 different output options (it can be defined with -r when running the script

### Version 0.1 - Sept 02, 2021
* compares_dhcp_leases_nios_b1ddi.py
  * First complete version, supports WAPI and Grid Backup for NIOS (BloxOne API is obvisouly through the API)
 
