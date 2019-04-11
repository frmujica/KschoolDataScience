# KschoolDataScience

This might be a personal project which trends to normalize all the vulnerabilities into categories and then try to make a patch report independent of tools. At the moment I will try to normalize Openvas plugins a Qualys Knowledge Base. 

The file VendorReferences.csv has a group of regular expressions for all the differents vendor references, I studied different kind of vulns and differents plugins from openvas and Qualys. All the providers, except Microsoft (As always fucking Microsoft), has something like a standard so the file will extract the vendor reference from a lot of providers. I might miss some of then but we can add more vendor references and get a richer file. The vendor reference will help us to make a patch report without caring of the vulnerability scanner. 
