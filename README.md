# Prisma-SD-WAN-Site-Automation (Preview)
This is a GUI to solution built on Flask and Mongodb to provide an easy way to make csv/jinjas, deploy sites and run other automation scripts. 

#### License
MIT

#### Requirements
* Docker

#### Installation: 
 - **Github:** Download files to a local directory
 - Update mongo-init.js if you want to change the MONGODB DB, Username and Password
 - Update Dockerfile if you want to change any of the MONGODB, Admin or Support information
 - Update Dockercompose if you want to change any of the MONGODB DB, Username and Password
 
 - Built on the following below
 * CloudGenix/sdk-python = 6.2.2b1
 * CloudGenix/cloudgenix_config = 2.0.0b1
 
### Caveats and known issues:
 - This is a PREVIEW release, hiccups to be expected. Please file issues on Github for any problems.
 
 - docker-compose build --no-cache
 - docker-compose up -d

 - Access via http://localhost:5001/
 
#### Version
| Version | Build | Changes |
| ------- | ----- | ------- |
| **1.0.0** | **b1** | Initial Release. |

#### For more info
 * Get help and additional Prisma SD-WAN Documentation at <https://docs.paloaltonetworks.com/prisma/cloudgenix-sd-wan.html>
