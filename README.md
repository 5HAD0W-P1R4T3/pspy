    ___________________/\\\\\\\\\\\_______________________________        
     _________________/\\\/////////\\\_____________________________       
      ___/\\\\\\\\\___\//\\\______\///____/\\\\\\\\\_____/\\\__/\\\_      
       __/\\\/////\\\___\////\\\__________/\\\/////\\\___\//\\\/\\\__     
        _\/\\\\\\\\\\_______\////\\\______\/\\\\\\\\\\_____\//\\\\\___    
         _\/\\\//////___________\////\\\___\/\\\//////_______\//\\\____   
          _\/\\\__________/\\\______\//\\\__\/\\\__________/\\_/\\\_____  
           _\/\\\_________\///\\\\\\\\\\\/___\/\\\_________\//\\\\/______ 
            _\///____________\///////////_____\///___________\////________ 


#Usage:

```

Process Spy 0.001
usage: Process Spy [-h] [-v] [-t] [-k KEY] [-V] [pid]

Fetch VirusTotal File Scans Reports for running processes.

positional arguments:
  pid                process ID

optional arguments:
  -h, --help         show this help message and exit
  -v, --verbose      increase verbosity (use --vv for greater effect)
  -t, --test         test mode
  -k KEY, --key KEY  VirusTotal 2 Public API key
  -V, --version      show program's version number and exit

The APIKEY environment variable can used instead of --key KEY.

```

#Notes

##ps + VirusTotal = psyp.py

psyp.py is a triage tool for *rapid incident response*.  

- If a pid # is specified, Process Spy will fetch the VirusTotal "File Scan" reports for that process' exe.
- If no pid is specified, Process Spy will enumerate all running processes and fetch VirusTotal File Scan reports for each process exe. 

###Notes

- The VirusTotal 2 Public API has rate limits.  Only 4 requests can submitted per minute.  Luckily, in the case of File Scan reports, reports for up to 25 individual files can be submitted per request.  In short, Process Spy can pull 100 reports per minute.

- Kudo's to Mark Russinovich for his work to integrate VirusTotal data with SysInternal's Process Explorer (https://twitter.com/markrussinovich/status/428655728002203648). Process Explorer was certainly the inspiration for this project.  pspy.py aims to bring similar system triage capability to multiple platforms.

Happy Hunting.