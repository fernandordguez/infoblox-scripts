import gspread

SCOPES = ['https://www.googleapis.com/auth/spreadsheets','https://www.googleapis.com/auth/drive'] #There could be more required for writing permission

gc = gspread.service_account('service_account.json')
sh = gc.create('SampleGsheetName')  #To have at least some data to create the document
wks = sh.sheet1
sh.share( '<Your Google Account>','user','writer') #Share with our own account and with the service account email, otherwise it will not show up in Gsheets (it´s been created by the service account, not by us)
sh.share ('<Your Service Account email address>','user','writer')