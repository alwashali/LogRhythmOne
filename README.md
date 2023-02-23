# LogRhythmOne
Controle Multiple LogRhythm SIEMs Alert and Cases from a Single API

The tool is written to control multiple LogRhythm SIEMs cases and alerts from one place. The need for an easy way to search for IOCs or keywords in all SIEMS Cases and Alarms content. The tool basically replicate one API similar to the LogRhythm default API to multiple instances of LogRhythm. 

![gopher.drawio.png](images/gopher.drawio.png)

## Table of Contents

 - [LogRhythmOne](#logrhythmone)
  * [Table of Contents](#table-of-contents)
  * [Use Cases](#use-cases)
  * [Installation](#installation)
  * [How to use it](#how-to-use-it)
  * [Usage](#usage)
  * [SIEM Configuration](#siem-configuration)
- [**Authentication**](#--authentication--)
  * [Token Authentication](#token-authentication)
    + [Example](#example)
  * [User authentication](#user-authentication)
    + [Example](#example-1)
- [Run API Server](#run-api-server)
- [API Docs](#api-docs)
  * [Cases API](#cases-api)
  * [Case API](#case-api)
  * [Alarms API](#alarms-api)
  * [Alarm API](#alarm-api)
 

## Use Cases

**Reporting**: creating SOC metrics from all SIEMS from one API

**Automation**: automating reporting and alert and cases fetching 

**IOCs searching**: Sometimes it’s useful to know if a certain case or IOC is already reporting in recent case or appeared in an alert. 


## Installation


```
go install github.com/alwashali/LogRhythmOne@latest

```

## How to use it

In order to be able to control multiple SIEMs, host information and token need to be added to the configuration as well as a LogRhythmOne token with permission to interact with the added SIEMs. 

## Usage

For each command, help page can be viewed by executing **LogRhythmOne.exe  help [Command]**

```
NAME:
   Unified LogRhythm API - Control multiple LogRhythm SIEMs from one API

USAGE:
   LogRhythmOne.exe [global options] command [command options] [arguments...]

AUTHOR:
   @Ali_Alwashali

COMMANDS:
   run      Run Server
   user     Add a new user account
   token    Generate a new token
   join     Join a new LogRhtyhm SIEM
   help, h  Shows a list of commands or help for one command

GLOBAL OPTIONS:
   --help, -h  show help
```

## SIEM Configuration

The tools accepts configuration from command line by using the **join** command 

```
C:\Users\ali.washali\go\src\LogRhythmOne> LogRhythmOne.exe help join

NAME:
   LogRhythmOne.exe join - Join a new LogRhtyhm SIEM

USAGE:
   LogRhythmOne.exe join [command options] [arguments...]

OPTIONS:
   --name value, -n value    LogRhythm Instance Name
   --host value, --ip value  LogRhythm IP Address or domain
   --token value, -t value   LogRhythm Token
```

Joining a SIEM instance to the configuration is reflected in secrets folder as a yaml file for each SIEM 

```
LogRhythmOne.exe join --name LR1 --host 10.10.10.11 --token [LogRhythm Token Here]
```

 

# **Authentication**

Tool accepts JWT username password and token authentications. Token is easier to work with in case the tool is used with SOAR or automation workflows and Username and Password authentication in case it’s linked with a UI interface. Permission has to be set which is basically the name of the LogRhythm instance added using **join** command.

## Token Authentication

Use command **token** generate token to access specific SIEM or Multiple SIEMS. The token has default of 365 days lifetime and can be changed using **-d** option. 

```
C:\Users\ali.washali\go\src\LogRhythmOne> LogRhythmOne.exe help token
NAME:
   LogRhythmOne.exe token - Generate a new token

USAGE:
   LogRhythmOne.exe token [command options] [arguments...]

OPTIONS:
   --days value, -d value        Number of days to use for token life time (default: 365)
   --permission value, -p value  LogRhythm SIEMS allowed to be searched. Use 'all' for all SIEMs
```

### Example

Creating a token that has permission to access multiple SIEMs. SIEMs names can’t be used as permission if not first added as SIEMs using join command.

```
C:\Users\ali.washali\go\src\LogRhythmOne>LogRhythmOne.exe token -p LR1 -p LR2 -p LR3

Token Generated:
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ0b2tlbiI6IiIsInVzZXJuYW1lIjoiIiwicGVybWlzc2lvbiI6WyJMUjEiLCJMUjIiLCJMUjMiXSwiZXhwIjoxNzA4NjMwOTk1fQ.HHGv12uJP8xbeCcs0oXYrz4jNu5-ctcQLo2y_zG5rLY
```

Token generated by LogRhythmOne tool must be passed in **authorization** header for each API call**.**

## User authentication

Username and password can be used as a mean of authentication if the tools is linked with UI. Command **user** can be used to create users. Each user password and permission is stored in a yaml file inside secrets folder. The account info are used with login API inside POST request JSON body. 

```
C:\Users\ali.washali\go\src\LogRhythmOne>LogRhythmOne.exe help user
NAME:
   LogRhythmOne.exe user - Add a new user account

USAGE:
   LogRhythmOne.exe user [command options] [arguments...]

OPTIONS:
   --username value, -u value    Account username
   --password value, --pw value  Account Password
   --permission value, -p value  LogRhythm SIEMS allowed to be searched. (default: "all")
```

### Example

Creating a user that has access to LR1 and LR2 SIEMs only. SIEMs names can’t be used as permission if not first added as SIEMs using join command. 

```
C:\Users\ali.washali\go\src\LogRhythmOne>LogRhythmOne.exe user --username ali --password Passw0rd! -p LR1 -p LR2
2023/02/22 22:52:19 User ali was added successfuly

C:\Users\ali.washali\go\src\LogRhythmOne>
```

User info are stored inside secrets/users/ali.yaml file. 

```yaml
username: ali
password: $2a$14$WqYOpW8VGQUib5z7YzJVceWT1dHD4YZDDCzme268O03YDGvd3uzdq
permission:
- LR1
- LR2
```

# Run API Server

The run option execute the mux server listening for incoming API calls. 

```yaml
set lrport=8080
LogRhythmOne.exe run 
```

---

# API Docs

Most important part in the request is the **name** header. It contains the names of LogRhythm SIEMs to be queried or ‘all’ to query all allowed SIEMs. 

## Cases API

```
GET /cases
```

Cases API is used to fetch all cases from all SIEMs allowed as per the included token, header **name** can be used to specific SIEM name or value ‘all’ for all SIEMs.

Header **keyword** can be used to filter for specific case that contains value in case title or content.

## Case API

```
Get /case/[id]
```

Case API to fetch a particular case by ID. SIEM instance name must be set in **name** header.

## Alarms API

```
GET /alarms
```

Alarms API is used to fetch all alarms from all SIEMs allowed as per the included token, header **name** can be used to specific SIEM name or value ‘all’ for all SIEMs.

Header **keyword** can be used to filter for specific alarm that contains value in alarm rule name.

## Alarm API

```
Get /alarm/[id]
```

Alarm API to fetch a particular alarm by ID. SIEM instance name must be set in **name** header.

APIs results can be controlled using filters in request headers such as following LogRhythm default API headers. Refer to LogRhythm docs page at https://IPAddress:8501/lr-case-api/docs for more information about the headers. 

- CreatedAfter
- CreatedBefore
- updatedAfter
- updatedBefore
- statusNumber
- priority
- Name
- Count
- alarmStatus
- entityName
- dateInserted
