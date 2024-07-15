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

## 1.3 Given a scenario, analyse potential indicators associated with application attacks

## 1.4 Given a scenario, analyse potential indicators associated with network attacks

## 1.5 Explain different threat actors, vectors, and intelligence sources

## 1.6 Explain the security concerns associated with various types of vulnerabilities

## 1.7 Summarise the techniques used in security assessments

## 1.8 Explain the techniques used in penetration testing

