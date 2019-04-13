# KschoolDataScience

This is a personal project which trends to normalize all the vulnerabilities into categories and make vulnerability management easier a patch report independent of tools. This project is divided into different phases.

## Openvas

1. Exploration.
2. Data wrangling and cleaning.
3. Apply a Natural Processing Language.
4. Test the results.

## Other tools

1. To do.

### Data structure

There are different directories.

- PluginsCategorization has all the scripts to download the data and parse into a custom dataset.At the moment there is a incomplete script to parse Qualys and I am going to focus all my efforts to Openvas because it is an opensource tool and its data is available for free.

- VulnerabilityHatstall has the jupyter-notebook with the project draft.

- If you do not like anything from this project I think you might find "VendorReferences.csv" interesting, this file it's an effort to compile the most important vendor references from different tools, in many cases the vendor reference it is normally the same patch. I studied different kind of vulns and different plugins from Openvas and Qualys. All the providers, except Microsoft (As always fucking Microsoft), has something like a standard so the file will extract the vendor reference from a lot of providers. I might miss some of then but we can add more vendor references and get a richer file. The vendor reference will help us to make a patch report without caring of the vulnerability scanner.
