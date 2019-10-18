# SMTPTester

SMTPTester is a python3 tool to test SMTP server for 3 common vulnerabilities:
* Spoofing - The ability to send a mail on behalf of an internal user
* Relay - Using this SMTP server to send email to other address outside of the organization
* user enumeration - using the SMTP VRFY command to check if specific username and\or email address exist within the organization.

## How to use it
First, install the needed dependencies:
```
pip install -r requirments.txt
```
Second, run the tool with the needed flags:
```
python SMTPTester.py --tester [tester email] --targets [SMTP IP or file containing multiple IPs]
```

## Options to consider
* -i\\--internal
  * testing only for mail spoofing
* -e\\--external
  * only testing for mail relay
* -v\\--vrfy
  * only perform user enumeration
the tool will perform both internal and external when no specific test type is specified, and will append the output to a log file on the same folder as the SMTPTester.py file. 

## Docker Build
```
docker build -t <IMAGE NAME> .
docker build -t xshuden/smtptester .
```

## Docker Run
```
docker run --rm -it xshuden/smtptester
```


### Donations
Did my work helped you? Did it saved you some time and money?
Well, just in case you want to buy me coffee (or beer), feel free to make a donation, it will be highly appreciated!

Thanks in advance!

[![Donate with Ethereum](https://en.cryptobadges.io/badge/big/0xC1c9F71cb7845D7c3254Fa6b8b968ceDb5FA1bBE)](https://en.cryptobadges.io/donate/0xC1c9F71cb7845D7c3254Fa6b8b968ceDb5FA1bBE)[![Donate with Bitcoin](https://en.cryptobadges.io/badge/big/1Nkqjt7fZ8NDJdeRKZcGKUQREoaSyLhvde)](https://en.cryptobadges.io/donate/1Nkqjt7fZ8NDJdeRKZcGKUQREoaSyLhvde)
>_If you use another crypto, please send me a message and i will pass you a specific address for that coin_

### Issues, bugs and other code-issues
Yeah, I know, this code isn't the best. I'm fine with it as I'm not a developer and this is part of my learning process.
If there is an option to do some of it better, please, let me know.

_Not how many, but where._

v0.1

