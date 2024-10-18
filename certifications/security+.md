---
title: CompTIA Security+ Exam Notes
---

# About

## Exam Details

Exam number: SY0-601

Maximum number of questions: 90

Types of questions:

- Multiple choice
- Performance based

Exam duration: 90 minutes

Passing score: 750

Possible scores: 100 - 900

## Exam Objectives

Security+ (SY0-601) covers 5 domains:

- 1.0 Attacks, Threats and Vulnerabilities (24%)
- 2.0 Architecture and Design (21%)
- 3.0 Implementation (25%)
- 4.0 Operations and Incident Response (16%)
- 5.0 Governance, Risk and Compliance (14%)

# 1.0 Threats, Attacks and Vulnerabilities

## 1.1 Compare and contrast different types of social engineering techniques

Spam: unwanted/unsolicited advertisement. Can come in various forms, including:

- Spam emails
- SPIT (spam over Internet Telephone)
- SPIM (spam over Instant Messaging)
    - SPIM includes instant messaging technologies, e.g. private messaging
      functions on social media platforms, etc.

Social engineering: manipulating people into performing some action or
revealing specific information, typically for illegitimate/malicious purposes.

Phishing: social engineering designed to make users reveal personal
information/perform some action, usually through spoofing - impersonating a
legitimate source:

- Impersonation done by creating fake websites with similar URLs: user
  is enticed to enter personal information into fake website and send
  data to attackers.
- Attack can be carried out via:
    - Email
    - Short Message System (SMS)/Instant Messaging (IM) (also known as smishing)
    - Voice over Internet Protocol (VoIP) (e.g. via phone call) (also known as vishing)
- Phishing typically affects many users, however can be more targeted.
- Phishing usually presents as a legitimate request but trick victims into
  performing some action.

Spear phishing: phishing which targets a specific subset of users.

- Spear phishing is typically personalised towards the victims, to make the
  attack more realistic.
- Whaling is a kind of spear phishing where an attacker targets a high profile
  user (e.g. an executive, etc.) to steal their credentials/perform some
  privileged action.

Phishing typically uses either the same URL as some legitimate source (e.g.
spoofing domains that do not have DMARC set up) or a similar URL:

- Typosquatting: an attacker registers a website under a URL where the URL
  string is similar but not exactly the same (e.g. googlr.com instead of
  google.com) - the idea is that a user would make a typing mistake or overlook
  the incorrect URL.
- Prepending: similar to typosquatting, but instead the attacker prepends the
  URL with extra characters.

Attackers typically use pretexting to gain influence over users - they devise
some story to convince users to click on a particular link. For example:

- An attacker might pretend they are emailing from the bank, and suggest that
  there is a new message the user needs to view, and that they should click on
  the link to login to their account. The link is illegitimate and any
  credentials the user enters onto the website will be stolen.
- Similar scenario, however the attacker may suggest that there is an issue
  with the users bank account and that they should transfer some amount of
  money to some other bank account.

In both these scenarios, the attacker gives the user a reason to reveal
personal information/perform some action through their pretext - the pretext is
a lie however.

Pharming: phishing attack where users are redirected from a legitimate site to
a bogus one. This kind of attack is designed to affect many users at once and
is relatively general - the opposite of spear phishing. Pharming can be carried
out through:

- Domain hijacking, where an attacker takes over the domain and uses it to
  point to a new website.
- DNS poisoning attacks, where an attacker (illegitimately) modifies the DNS
  records of a website to point to their bogus website.
- Client vulnerabilities, where an attacker modifies the hosts file on a users
  computer to redirect traffic to a particular website.

Pharming is often used in conjunction with phishing:

1. An attacker gathers a large number of users to a website with pharming.
2. The attacker then uses phishing to collect information/convince users to
   carry out some action.

Phishing is difficult to prevent - an end user may have difficulty
differentiating between legitimate and illegitimate websites. Training and
email/firewall filters can prevent some spam/phishing, but is not guaranteed.

Phishing is done for several reasons, mainly:

- Credential harvesting: stealing personal information from users (e.g. names,
  email addresses, passwords, etc.). This can be then used to gain unauthorised
  access to systems or commit fraud.
- Identity fraud: personal information stolen from users can be used to commit
  fraud, e.g. forge signatures, open bank accounts, make payments, etc.

Eliciting information: gathering information from people. Typically, this is
done in such a way that the victim does not realise they are being targeted,
and the information being collected is confidential.

Dumpster diving: salvaging items from rubbish containers which still have some
use. In the context of cybersecurity, dumpster diving can be used to collect
data/information regarding existing systems (e.g. old employee ID cards,
hardware systems which may still contain data, etc.).

Shoulder surfing: collecting sensitive information from individuals by spying
over their shoulder (e.g. at an ATM or on their computer).

Tailgating: gaining unauthorised access to sensitive areas by following
someone, typically as they pass some security checkpoint.

Invoice scams: an attacker sends a victim some fraudulent invoice in the hopes
that they will pay the invoice for some non-existent services rendered/items.

Hoax: an attacker suggests that a system is compromised or that a computer is
infected with a virus, however this is not true. The aim of the attacker is to
get the user to give up personal information/install some software that will
actually infect the users computer.

Watering hole attack: an attacker identifies some website/computer resource
that is regularly and typically used by a community (e.g. a forum, etc.). They
then attempt to attack the site/the users on the site to gain access to some
further resources. Watering hole attacks differ from typical phishing attacks:
in phishing, the goal is to gain access to confidential information. In
watering hole attacks, the goal is to infect victim systems and gain further
access to a system.

Influence campaign: these are large scale campaigns typically done to influence
public opinion/behavior.Influence campaign: these are large scale campaigns
typically done to influence public opinion/behavior. Various vehicles including
hybrid warfare or social media can be used to carry this out.

Social engineering can be made more effective through the following principles:

- Authority: an attacker can pretend to be someone of high authority (e.g. a
  manager or law enforcement) to get a victim to carry out some action.
- Intimidation: an attacker can threaten, outline negative consequences or
  otherwise intimidate a victim.
- Consensus: an attacker can create a false sense of agreement from a community
  around some action (e.g. creating a post on a forum encouraging users to
  download some malware, and following up with additional fake accounts
  commenting on their positive reviews).
- Scarcity: an attacker may pretend that a resource is rare/in limited supply
  and may not be available to influence a victim to take action.
- Urgency: similar to scarcity, an attacker may convince a victim that some
  event is time sensitive and must be completed as soon as possible to
  influence victim behaviour.
- Trust: an attacker pretends to be a trusted source to get a victim to perform
  some action. This can be done by impersonating a known trusted source or
  developing a relationship with the victim.
- Familiarity: the attacker pretends to be someone the victim may like.

## 1.2 Given a scenario, analyze potential indicators to determine the type of attack

Malware: malicious software intended to harm a computer system and its users.
Malware may steal private data, cause disruption to services, spy on users, or
otherwise carry out some activity which violates a users privacy/security.

Types of malware:

- Ransomware: malware which encrypts files on a computer system and holds them
  for ransom in exchange for a key which can decrypt the files.
- Trojans: malware which poses as legitimate files/software.
- Worms: malware which is self-propagating - these malware infect one victim
  computer before scanning for other targets and automatically forwarding
  themselves onwards.
- Potentially Unwanted Programs (PUPs): software which is installed alongside
  other programs but may not be wanted or required by the user. Typical PUPs
  modify browser settings, display unwanted advertisements or act as
  spyware/adware.
- Virus: malware which replicates itself and infects other software/systems.
  Unlike a worm, a virus must be triggered by some user interaction first, and
  thus may not spread as effectively.
- Fileless virus: a virus which does not exist as a file but instead resides in
  computer memory (RAM). These viruses do not leave behind many tracks for
  digital forensics and can be difficult to capture with antivirus software,
  however also only exist until the computer system is switched off.
- Command and Control (C2/C&C): server/software used by attackers to command/control
  malware remotely. These can be used to trigger some action,
  encrypt/decrypt/modify/delete/upload/recover files, etc.
- Bots: a program designed to automatically carry out a specific tasks. Bots
  can be harmful, e.g. they can be used to carry out DDoS attacks. A botnet is
  a network of bots working together to carry out some task.
- Cryptomalware: malware that uses computer resources to mine for
  cryptocurrency without the user knowing.
- Logic bomb: malware that is triggered when some specific conditions are met
  (e.g. a certain date passes or a users access is revoked/granted).
- Spyware: malware that spies on users activities and covertly records what
  they do.
- Keyloggers: malware that logs keystrokes from users. Is typically used to
  recover passwords or other sensitive data.
- Remote Access Trojan (RAT): a trojan malware that allows an attacker to
  remotely access a victims computer. These are typically a combination of
  spyware/keyloggers and trojan malware.
- Rootkit: malware which attackers can use to directly attack a system and gain
  high level/administrator/root privileges. Attackers typically use these to
  gain full control over systems.
- Backdoor: a covert method of bypassing security mechanisms (e.g. via a
  rootkit or trojan) and allowing an attacker (sometimes remote) access to
  a system without needing to authenticate.


Password attacks: users/systems use passwords (secret strings) to prevent/limit
access to certain systems. An attacker who wishes to access these systems must
guess or otherwise recover the password to access the system. Several attacks
exist to guess passwords:

- Brute force attack: an attacker simply guesses passwords until the correct
  password is found. This attack takes a significant amount of time however is
  simple and reliable. Brute force attacks can be online or offline:
    - Online: an attacker is attempting to authenticate with some online
      resource, e.g. a website or server.
    - Offline: an attacker is attempting to guess the password to some resource
      that is available offline, e.g. some encrypted file which has been
      downloaded.
- Spraying: a type of brute force attack where an attacker uses a single
  password to attempt to break into multiple accounts.
- Dictionary attack: an attacker uses a list of commonly known/used passwords
  to carry out a brute force attack against a system.
- Rainbow table: if a hacker has access to password hashes, they may try brute
  force/dictionary attacks to crack the hash (i.e. generate a hash for a given
  password and match it to the target). Rainbow tables contain precomputed
  hashes for given passwords reducing the time to guess the password, however
  take up significant space.
- Plaintext/unencrypted password attack: an attacker can try to attack password
  storage locations if they know that the passwords are not encrypted.

Physical attacks: several physical attacks exist beyond simply stealing a
server/hardware which may allow an attacker to gain control over or otherwise
compromise the security of a computer system. These include:

- Malicious USB cable/drive attacks: USBs may contain harmful software which is
  automatically executed to run code. USBs may pose as regular storage
  devices and contain malicious code or could pose as input devices such as
  keyboards or mice, which automatically carry out key presses or other input
  on the computer system. Malicious USB devices may also include cables as
  well as flash drives, which can carry out similar attacks.
- Card cloning: cards can be used to carry out certain operations, e.g. access
  secure facilities or carry out transactions. An attacker can "clone" a card
  by copying the information on a card and using it on another card.
- Skimming: this is the process through which an attacker can steal card
  information. This is a machine typically installed on top of a regular card
  machine that reads and copies the information on the card.

Machine learning uses datasets to train models that can automatically carry out
certain tasks. AI/ML can pose a threat to users however, and may be abused to
carry out malicious attacks. When implementing AI/ML, the following needs to be
considered:

- Tainted AI/ML datasets: the data used to train the model may contain examples
  which when trained on can cause the model to predict outputs which are not
  correct. Attackers can use this to carry out attacks, e.g. polluting a spam
  filter dataset so that spam is not correctly filtered by ML models.
- Security of ML: ML can make mistakes and may not always correctly carry out
  certain tasks. 

Security researchers/analysts should also consider the security of the supply
chain: whether or not software libraries used by software used primarily by
their organisation is secure. For example, if the software used by some
organisation depends on another library, and that library contains
vulnerabilities, the new software also contains vulnerabilities.

Security researchers/analysts need to consider the risks of using cloud based
assets vs on-premises assets. The risks and potential issues arising can be
very different depending on where software systems are run:

| Cloud | On-premises |
| --- | --- |
| Systems may be shared with untrusted users | Systems only used by authorised users |
| Data spread across several servers, harder to steal | Data resides in specific servers, easier to steal |
| Evaluation/assurance of physical security/personnel may be required from cloud | Physical security systems in place with personnel to secure system |
| May need to rely on cloud resilience/security architecture | May need to create in house solutions for security architecture |
| Cheaper for small organisations | May have more benefits for large organisations |

Cryptographic attacks occur when an attacker attempts to modify or breach
cryptographic mechanisms used to secure data. Examples include:

- Birthday attacks: an attacker attempts to carry out a brute force collision
  attack against a hashing algorithm (i.e. find a pair of inputs that produce
  the same hash value. This specific attack exploits the birthday problem in
  probability theory to carry out attacks - the process to find the collision
  is somewhat random.
- Collision attacks: an attacker attempts to find 2 values which produce the
  same hash. This may be found as a result of the algorithm itself instead of
  the birthday problem (e.g. MD5).
- Downgrade attack: an attacker may try to convince a computer system to use
  and older/more insecure algorithm instead of a high quality cryptographic
  algorithm to exploit the system. This can be achieved due to compatibility or
  version rollbacks, where systems may be allowed to fallback to unencrypted
  communications if the system cannot use a higher version of the encryption
  scheme.

## 1.3 Given a scenario, analyse potential indicators associated with application attacks

Improper input handling: not correctly handling inputs can lead to several
issues, from system crashes to privilege escalation to arbitrary code
execution to leaked data. Input needs to be correctly validated, sanitised,
filtered and proper encoding/decoding rules must be followed in order to
prevent input from being abused. Input should be handled appropriately on both
the client and server side to ensure that data is not tampered with while in
transit.

Privilege escalation: an attacker attempts to gain access to higher privileges
(e.g. unauthenticated to authenticated, standard user to root, etc.). This can
be done through several methods, including using stolen credentials, social
engineering, weak/unconfigured credentials, other misconfigurations or using
malware to attack and gain elevated access to system resources. Privilege
escalation can be vertical or horizontal:

- Vertical privilege escalation is where an attacker attempts to increase the
  level of their current privileges, e.g. elevating from a standard user to an
  administrator.
- Horizontal privilege escalation is where an attacker attempts to access the
  privileges of another user account in the same level as them, e.g. accessing
  user 2's resources while logged in as user 1.

Injection attacks: this is any attack where a program is tricked into
misinterpreting some code to execute a command. Several types of attack exist,
including:

- XSS attack
- SQL injection
- DLL injection
- XML injection
- LDAP injection

Cross-site scripting (XSS): XSS is an injection attack where
malicious/untrusted scripts are inserted into regular websites. An attacker may
be able to input some code into a website, and that code is then executed by
different end users when they visit the site. This attack occurs where user
input is not validated correctly and allows attackers to insert scripts where
they should not be able to do so. XSS attacks can be categorised into reflected
or stored:

- Stored: an attacker creates a script and uploads it to a website (e.g.
  through some insecure form that does not validate input). The script is then
  stored on the server and served to new users when they visit the site. The
  browser has no way of knowing that the script is malicious and executes the
  code. This is also known as persistent XSS.
- Reflected: this attack occurs when an application handles HTTP requests in an
  unsafe manner but does not necessarily store the data. For example, if a user
  enters some data onto the website and that data is used to create content on
  the site but is not stored (i.e. searching for an item) then an attacker can
  create a malicious payload that contains some code to execute. This code can
  then be used to execute code in the context of a users browser. This is also
  known as non-persistent XSS as no data is stored on the server.

An attacker can carry out JavaScript XSS attacks by inserting `<script>` tags
into a HTML form that does not carry out the proper sanitisation or a HTTP
request which does not correctly handle input. When the form/request is
submitted, the script is either stored/reflected to another user whose browser
will then execute the script.

SQL injection (SQLi): Structured Query Language (SQL) is a Domain Specific
Language (DSL) used to interact with databases. An SQL injection attack occurs
when an input used to execute a query (e.g. an item to search for on a store)
is not properly handled and allows an attacker to execute arbitrary queries on
the server. This attack can then be used to allow an attacker to view data that
they are not usually able to view, e.g. the usernames/passwords of every user
in the database. Additionally, an attacker may be able to carry out other
operations, including deleting or modifying data to get access to a server.

To detect SQL injections, an attacker might try to submit different strings:

- The single quote character `'`.
- Boolean conditions (e.g. `OR 1=1` and `OR 1=2`).

SQLi typically occurs in the `WHERE` clause of a `SELECT` statement, however
can also occur in `UPDATE` or `INSERT` statements as well.

SQLi attacks can result in several different consequences depending on the type
of attack:

- Retrieval of data (e.g. passwords, etc.).
- Modification of logic (e.g. updating/inserting/deleting unauthorised data,
  etc.).
- `UNION` attacks where data from alternative tables might be retrieved.
- Blind SQLi where the data is not returned in the application response.

DLL injection: Dynamic Link Libraries (DLLs) contain data and programs. These
are loaded by programs to carry out library functions, and programs using these
may be vulnerable to DLL injections. An attacker can force a program to load a
particular DLL by injecting code that causes unintended side effects, including
reading input information or intercepting system calls. Attackers can
essentially modify the libraries/code that existing programs load/run to
execute their own programs.

LDAP injection: Lightweight Directory Access Protocol (LDAP) allows users to
access and read directories containing information - essentially it allows user
to read/modify data on a remote system. LDAP injection occurs when a web
application uses user input to construct LDAP queries but does not properly
validate them - an attacker can access resources that they may not be
authorised to access such as passwords or secret data.

XML injection: EXtensible Markup Language (XML) is a markup language used to
define and store arbitrary data, with a similar syntax to HTML. An XML
injection occurs when XML input fails to be validated properly - an attacker
can access sensitive data, modify data, or modify logic in the application. An
XML injection can occur using the following strings:

- The single quote character `'`.
- The ampersand character `&`.
- The XML comment strings `<!--` and `-->`.

Pointer/object dereference: objects in memory typically have a pointer
associated with them so that they can be referenced. Several vulnerabilities
might be associated with dereferencing pointers, including:

- Null pointer dereference: if a pointer does not point to a valid location,
  the program may crash or otherwise exit (if it doesn't previously check
  whether the pointer is valid or not). Null pointer dereferences typically
  cause software reliability issues but can also be used to bypass security
  logic or reveal information about the program.
- Untrusted pointer dereference: if a pointer is loaded from an untrusted
  location, an attacker can similarly cause a program to crash or bypass logic.
  Additionally, an attacker can also modify state variables or execute
  arbitrary code.

Directory traversal: also known as path traversal, this is a vulnerability
where an attacker can read arbitrary files on a server. Websites may load
resources from the local directory by specifying a path to load. An attacker
can modify the path and use this to load data from other paths. This
vulnerability is typically carried out by using the `..` string in a path which
specifies the parent directory of the current directory - an attacker can
navigate up to the root of the filesystem and then back down to any arbitrary
file (`/etc/passwd` is a typical target).

Buffer overflows: programs use buffers to store input data. Buffers have fixed
size, however users can input data that is larger than the size allocated to
the buffer. When this happens, data that is next to the buffer may be
overwritten with arbitrary data. Attackers can exploit this and use it to
deliberately crash programs (e.g. causing denial of service attacks) or execute
arbitrary code (e.g. launching a shell).

Race condition: a race condition occurs where execution of code/program
behaviour is dependent on timing of other, external events. An attacker can
exploit this to bypass checks, elevate or escalate privileges, or access
certain resources without being authorised to do so.

Time-of-check-to-time-of-use (TOCTOU): this is a race condition caused by
checking the state of some object and then using that object. The state of the
resource may change between different checks, causing unauthorised use of the
object.

Error handling: a website may encounter errors from time to time (e.g. unable
to access certain resources, etc.). When these errors occur, an error message
may be displayed which describes the error. These error messages can be
configured to display different information depending on the use case, for
example a debug version of the system will display the full error message
while a user-facing application may display only a simple error message.
Improperly configuring/handling error messages can lead to vulnerabilities in
systems, as attackers can infer information about a system that should be kept
secret. For example: if a user attempts to access a file that they do not have
permission to access, a message stating "Access Denied" indicates that
the file exists, while a message stating "File Not Found" indicates that the
file may not exist. A hostile user can use this to deduce the directory
structure of a system.

Replay attack: an attacker intercepts communication between two parties
(on-path/MITM attack) and delays/redirects/repeats certain traffic. Replay
attacks allow an attacker to deceive other participants in the communication
into believing the legitimacy of some communication. For example, an attacker
may try to repeat or delay certain bank transactions to commit fraud.

Session replay attack: an attacker records the "session" of a user and uses
that to carry out replay attacks.

Integer overflow: this occurs when an arithmetic operation results in a value
too large to be stored in the allowed space, and thus the value "overflows".
For example, for an integer with 32 bits of space, the maximum allowed value is
4,294,967,295. Adding 1 to this value causes the value to overflow. Overflow
varies depending on the compiler, system, and language, however generally
causes issues including crashing the program or modifying the value to be
something else instead of the expected result.

Request forgery: an attacker can forge requests that appear to come from a
legitimate user but are illegitimate. Two different types exist:

- Cross-site request forgery: an attacker circumvents the same-origin policy
    and causes a user to execute actions inadvertently by clicking on a link.
    These attacks abuse cookies from a legitimate website and exploit the fact
    that the browser is trusted by the vulnerable website.
- Server-side request forgery: an attacker causes a server-side action to
    occur allowing an attacker to read server configurations or site details.

API attacks: an Application Programming Interface may be vulnerable to attacks,
allowing an attacker to carry out injection attacks, DoS/DDoS attacks and so
on.

Resource sxhaustion: an attack where a computer resource (e.g. a server or
application) is deliberately crashed, caused to hang or otherwise interfered
with which prevents legitimate users from accessing the resources as they are
exhausted.

Memory leak: programs allocate memory to store dynamic objects. When the
program completes, it may not properly free the memory, which can cause memory
leaks. These can cause multiple issues:

- The amount of available memory is reduced so the RAM is exhausted.
- Other programs may terminate due to inability to allocate memory.

Secure Sockets Layer stripping: an attacker intercepts traffic between a user
and the server and removes any SSL content from the traffic. This causes the
server to return an unencrypted version of the page which an attacker can read.
This is a kind of downgrade attack where an attacker uses MITM techniques to
change the protocol from HTTPS to HTTP.

Driver manipulation: attackers manipulate/alter the drivers of the system to
carry out attacks. Two types of driver manipulation attacks exist:

- Shimming: an attacker inserts a layer/shim between the application and OS to
    manipulate/modify/bypass security features.
- Refactoring: an attacker modifies the driver itself to create backdoors,
    bypass controls or create new vulnerabilities.

Pass-the-Hash attack: an attacker obtains the hash of a password (instead of
the actual password). An attacker can then use password cracking engines to
crack the password, or can use this to gain access to a resource that accepts a
hashed version of the password instead of the password itself. This can affect
single sign-on applications which may use password hashes instead of the actual
password.

# 5.0 Governance, Risk and Compliance

## 5.1 Compare and contrast various types of controls

Vulnerability: a flaw in the design of a system which can be exploited by a
threat.

Threat: an agent that can exploit vulnerabilities to cause harm or damage.

Risk: the potential for loss when a negative event occurs. This typically
involves likelihood/uncertainty around the impacts of the event and typically
focuses on the consequences. Risks are formed of two main components:

- Impact: what will be damaged if the risk is realised? How badly?
- Likelihood: how likely is it that the risk will occur?

Control: a measure taken to reduce or neutralise the impact or likelihood of a
risk. A risk which can be controlled still be acted on by a threat or may still
relate to a vulnerability but the consequences of the risk have been mitigated.
Several categories and types of control exist.

Control categories:

- Managerial: processes/controls that specify e.g. the standard operating
  procedures or security policies of an organisation.
- Operational: controls managed by people, e.g. training, security systems
  (such as CCTV), etc.
- Technical: controls managed/implemented on systems, e.g. firewalls,
  antivirus, etc.

Control types:

- Preventive: controls that prevent access to a resource or area.
    - Examples include firewalls, physical locks, etc.
- Detective: controls that detect if a problem has occurred. These do not
  prevent problems and need to be followed up on to be effective.
    - Examples include logging systems, inventory checks, etc. 
- Corrective: controls which correct errors and repair damage which might have
  occurred. Additionally, these can pre
    - Examples include patching systems, restoring databases or rebooting a
      system.
- Deterrent: controls which deter threats from acting. These do not detect or
  actually prevent a risk from being realised.
    - Examples include using a login/warning banner or lights/CCTV systems.
- Compensating: controls which support the security requirement if the actual
  requirement is unfeasible or cannot be met.
    - Examples include using dual control or signatures instead of other data.
- Physical: controls which have a physical presence.
    - Examples include fences, security guards, etc.

It is important to note that a single control might belong to multiple
different types.

## 5.2 Explain the importance of applicable regulations, standards, or frameworks that impact an organisations security posture

Several regulations, standards and frameworks govern how organisations should
handle data and secure systems. The most common are listed and discussed below.

General Data Protection Regulation (GDPR):
- EU regulation governing how organisations process personal information of
  individuals within and outside of the EU.

- National/territory/state laws:
    - USA: Computer Fraud and Abuse Act (CFAA)
        - USA federal law to address hacking
    - UK: Computer Misuse Act (CMA)
        - UK law to address hacking
- Frameworks and guidelines:
    - Centre for Internet Security (CIS)
        - Nonprofit organisation with several guidelines/controls
    - National Institute for Standards and Technology (NIST)
        - Risk Management Framework (RMF)
            - Framework for managing risk
            - Aimed at federal agencies/complying with legal requirements
        - Cybersecurity Framework (CSF)
            - Framework for managing/reducing cybersecurity risks
            - Aimed at organisations seeking to improve security posture
        - Special Publication 800-53 Security and Privacy Controls for
          Information Systems and Organisations
            - Standard guideline of controls for managing information security
    - International Standards Organisation (ISO)
        - ISO 27001 Information Security Management Systems Requirements
        - ISO 27002 Information Security Controls
        - ISO 27701 Security Techniques (Extension to ISO 27001 and ISO 27002)
        - ISO 31000 Risk Management
    - Statement on Standards for Attestation Engagements (SSAE)/International
      Standard on Assurance Engagements (ISAE)
        - System and Organisation Controls (SOC) 2
            - Type 1
            - Type 2
    - Cloud Security Alliance
        - Cloud Controls Matrix
        - Reference Architecture

## 5.3 Explain the importance of policies to organisational security

Policies: internal guidelines which govern how members of an organisation act.
These exist to ensure that personnel carry out their duties in a way that is
appropriate and minimises damage, by specifying what needs to be done/not done
and why.

Security policies: policies that dictate how members of an organisation should
act in order to maintain security (confidentiality, integrity and availability)
and minimise the risk to security breaches. Policies may apply to specific
areas of an organisation; the following policies apply to personnel acting
within an organisation.

Acceptable use policy (AUP): a policy which specifies what actions are
acceptable when using an organisations IT resources, e.g. devices, networks,
intranet or data. For example, an AUP may specify that employees not use
devices to play video games.

Job rotation: a policy where members maybe transferred to other roles within an
organisation with different requirements/responsibilities. The aim is to
prevent a single member gaining excessive knowledge or control over a
particular system - that employee may then become critical to their function
and irreplaceable or may become an insider threat. For example, job rotation
may be applied to security guards to ensure that an area is always guarded.

Mandatory vacation: a policy specifying that employees must take vacation. This
is done to improve employee morale and to give them a break from work.
Additionally, it prevents multiple employees from working together to carry out
malicious actions by forcing them to be away from work for certain extended
periods of time.

Separation of duties: a concept where more than one person is required to
complete a task, preventing a single person from misusing resources/systems.
For example, the person responsible for creating invoices must not be the
person responsible for authorising them. Separation of duties can be static or
dynamic:

- Static: define roles which are juxtaposed/conflicting, i.e. no two roles have
  shared responsibilities. For example, two separate roles may be created for
  modifying firewall rules: an "editor" who is responsible for changing
  firewall rules and an "approver" who is responsible for approving and
  integrating the changes into the firewall system.
- Dynamic: define rules which dynamically enforce access to resources/carry out
  actions. For example, an organisation may require that certain actions
  follow the two person rule: any authorised user can carry out the action,
  however they must be joined by another authorised user which must be
  different from the first.

Least privilege: a policy which specifies that a member of an organisation
should have access to the least amount of privileges necessary to carry out
their duties. For example, a user that carries out database management
operations should not be allowed to also install packages unless that is also
part of their job requirement.

Clean desk space: a policy which requires members of organisations to clear
their desk at the end of the working day. This is done to ensure that sensitive
information is not leaked and that devices such as laptops or mobile phones are
not stolen.

Background checks: a policy which requires an organisation to check the
criminal or other history of a potential employee before hiring them. This is
done to understand their past and what potential risks exist when hiring a
certain employee. For example, if a potential hire was convicted of stealing
from their last job, they may be a greater security risk.

Non-disclosure agreement (NDA): a policy which creates a confidentiality
agreement between two agreeing parties. Both parties agree to not disclose
certain information (typically an organisation and its members) to prevent data
loss through leaks and protect intellectual property or sensitive information.
NDAs may not be used to prevent employees from disclosing illegal actions.
Examples include attorney-client privileges or agreements between an employee
and employer to prevent leakage of trade secrets.

Social media analysis: an organisation may track the social media accounts of
employees or specify how employees conduct themselves on social media. This is
done to prevent privacy and security.

Onboarding: a policy which specifies how employees should be onboarded into an
organisation. This includes ensuring they complete mandatory training on
security, etc., reading policies relating to security and ensuring that they
have the necessary tools and equipment to carry out their job correctly (e.g.
ensuring they have access to necessary systems, ensuring they have necessary
security tools such as smart cards or TOTP tokens, etc.).

Offboarding: a policy which specifies the actions to take when an employee
leaves an organisation. This includes ensuring that all resources (devices,
information, files, etc.) that belong to an organisation are returned to the
organisation, ensuring that access privileges are revoked and the user is
removed from all systems to prevent them from accessing company systems again,
etc.

User training: training should be carried out regularly in line with
laws/regulations to ensure that employees remain up to date with their
knowledge on how to stay safe and prevent security breaches. Security awareness
training may be carried out to ensure that users are aware of and understand
the dangers that security threats pose to the organisation, and are equipped
with the tools and understanding to prevent them from becoming a threat.
Several strategies can be used to train users:

- Gamification: the process of adding game like mechanics to learning systems
  to improve engagement and retention of knowledge. Security training may use
  quizzes or other gamification techniques to improve the effectiveness of
  training.
- Capture the flag: training programs where employees assume the role of
  adversaries and attempt to capture "flags" by carrying out malicious
  activities in a simulated environment. The aim is to teach employees the
  possible methods attacker may use to breach security so that they may prevent
  them from occurring.
- Phishing campaigns: an organisation may simulate a phishing campaign to
  understand the effectiveness of existing security training and policies and
  to understand how to improve user understanding of phishing emails. A
  company may also offer general training to recognise and identify phishing
  emails, with specialist training offered to employees that are at a higher
  risk (e.g. C-level executives, etc.)

A diversity of training methods is necessary to ensure that training is
comprehensive and that employees recall training appropriately. This may
include presentations, interactive sessions, workshops and labs, conferences
and more. Additionally, training material must be revised to ensure that it
is kept up to date and that users find the training engaging and memorable -
this will help to reduce the risks associated with employees and can help avoid
regulatory issues including fines or other penalties.

Security policies may also apply to data and how it is handled within an
organisation. The following policies apply to data.

Data classification: an organisation may document how different data is
classified and create different categories of data based on its sensitivity.
These different categories may have different requirements on how they should
be handled (e.g. they must be encrypted at rest/in transit) and who can access
them (public/employees/specific employees only).

Data governance: a policy specifying how an organisation manages the
accessibility, availability and integrity of data within itself, including how
data is processed, how data is collected, how data is stored and how it is
disposed of.

Data retention: a policy which specifies how long data should be kept for
before being deleted, and additionally may specify what measures should be
taken to securely delete data and how data should be stored (e.g. encryption,
etc.).

Security policies may apply to credentials - information that can be used to
verify access to a system or a resource. The following policies apply to
different types of credentials.

Credential management policies are put in place to ensure that credentials are
used and stored appropriately. This may include specifying which protocols are
used to authorise and authenticate users, how passwords should be stored and
that different accounts have different privileges - access to certain resources
are controlled and only authorised to users who need access to those
researchers.

Personnel credentials: a policy which specifies how employees should store,
create and use credentials. This may include items such as password
reuse/history/complexity and guide employees as to how credentials should be
used/shared (e.g. PINs should never be shared). Additionally, it may specify
different privileges of employees and how they can access different resources.

Third party credentials: a policy which specifies how third party credentials
are created/stored in a system. This may include how access to third party
systems are managed, or alternatively how third parties are granted access to
internal systems.

Device credentials: a policy for managing the credentials used to access a
particular device. These may differ between devices which may be higher risk,
e.g. a mainframe system or a mobile device used by a high level employee (e.g.
the CEO).

Service accounts: a policy for managing service accounts. Service accounts may
be used for performing automated actions without user direction, however still
need to be monitored to prevent intrusion. Credentials used to access and
manage these accounts need to be managed appropriately as there may be a need
to share these with multiple team members, and there may need to be a
"chain of custody" to determine who is responsible for owning and managing a
service account.

Administrator/root accounts: a policy which specifies how the credentials of
users with privileged access are managed. These users have significantly more
control over computer systems, consequently they may be subject to more
stringent measures (e.g. changing passwords every 3 months instead of
annually).

Organisational policies dictate how organisational processes are performed.
These include what security controls are put in place and at what stages,
determining how systems should be set up, maintained, and shut down
appropriately. Organisational policies apply to processes - not to personnel -
and specify how a process should be carried out in order to maintain security.
The following policies apply to organisational processes.

Change management and change control: these policies dictates how changes are
to be made and how they should be managed throughout their lifetime, from
assessing the necessity, impact and risk of the change, to designing and
developing the change, to documentation, to fallback procedures in case the
change needs to be reversed. These policies may specify that different
environments may need to be created to ensure that changes do not impact
uptime (e.g. creating development, staging and production environments) or
specifying that changes must be approved by change advisory boards before being
implemented.

Asset management: a policy to manage assets, including endpoints, servers,
software, information and data. This policy includes how the asset should be
set up, identified, stored, tracked and managed till its end of life and who is
responsible for owning, maintaining and securing that asset. This may be used
to track licenses, how particular applications are used across the
organisation, workstations that need to be returned when an employee leaves,
etc. and many other processes relating to managing assets to ensure that the
asset themselves are secure.

Third party risk management is how an organisation chooses to manage its third
parties. These include both the clients and the suppliers/vendors that the
organisation will work with. Several different policies and contracts may be
enforced to manage expectations and risk associated with doing business with
third parties.

An organisation will typically keep a database of suppliers or vendors. This is a
record of all third parties from whom the organisation procures some service or
product. The database typically contains details about what the third party
provides, any risks associated with that third party (and how these are
managed), the appropriate contact details in case of issues, and others.
Additionally, an organisation will have measures to onboard, regularly
monitor/evaluate and offboard vendors, including due diligence to be
performed and different risks to be considered and evaluated.

An organisation may use their database to construct an understanding of the
wider supply chain network that an organisation relies on. Say organisation A
buys a service from organisation B, who in turn buys a product from
organisation C. The product sold from C to B is critical to the service
provided by B to A. It would be prudent for A to monitor C in addition to B, as
they form part of the supply chain that enables A to sell its own
products/services.

Business partners are a form of alliances between two or more organisations,
where they agree to work together to achieve some mutual outcome. These may be
contractual or casual in nature, however it is important to note that these
relationships might exist and should be managed appropriately.

To manage the relationship with third parties, organisations use several
documents and policies to reduce risk and set expectations. These include:

- Service level agreements (SLAs): these set the expected service uptime for
  the organisation and provides details on how these should be monitored, what
  to do if these are breached, and risks which may impact SLAs.
- Memorandum of Understanding (MoU): this is a statement of intent between two
  or more parties to carry out some agreed activity. While not necessarily
  legally binding, MoUs form an agreement between the involved parties that is
  formal and documented.
- Measurement systems analysis (MSA): a method for measuring the impact of a
  service.
- Business partnership agreement (BPA): an agreement between two or more
  organisations to achieve some common goal.
- End of Life (EoL), End of Sevice Life (EoSL): a particular product or service
  may be supported for a limited amount of time, after which it will be classed
  as end of life. An organisation may need to consider the additional costs of
  using services with closer EoLs, whether or not they can transition to a new
  product or service, and what security fixes or updates may still be applied
  when a product/service reaches EoL and for how long.
- Non-disclosure agreements (NDAs): used for preventing trade secrets and other
  sensitive/confidential material from being leaked or disclosed by third
  party organisations.

