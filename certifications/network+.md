---
title: CompTIA Network+ Exam Notes
---

# About

## Exam Details

Exam number: N10-008

Maximum number of questions: 90

Types of questions:

- Multiple choice
- Performance based

Exam duration: 90 minutes

Passing score: 720

Possible scores: 100 - 900

## Exam Objectives

Network+ (N10-008) covers 5 domains:

- 1.0 Networking Fundamentals (24%)
- 2.0 Network Implementations (19%)
- 3.0 Network Operations (16%)
- 4.0 Network Security (19%)
- 5.0 Network Troubleshooting (22%)

# 1.0 Networking Fundamentals

## 1.1 Compare and contrast the Open Systems Interconnection (OSI) model layers
and encapsulation concepts

OSI model - Open Systems Interconnection model
This is a reference model used to describe how computers can communicate and
share information with each other. It is an abstract model (guideline which
doesn't represent all aspects of reality) however can be used as a universal
model to represent how data is shared across networks. The OSI model consists
of 7 abstract layers, one stack on top of the other, as follows:

1. Physical
2. Data link
3. Network
4. Transport
5. Session
6. Presentation
7. Application

Each layer contains a different set of protocols, for example the network layer
includes the Internet Protocol (IP), the application layer includes the Hypertext
Transport Protocol (HTTP), etc. which depends on the kind of traffic going over
the network. Each of these layers is an abstraction and these abstractions
stack starting with the physical layer and ending with the application layer.
The OSI model has been standardised by the International Organisation for
Standardisation (ISO/IEC 7498-1:1998) and is used across the industry to
understand, diagnose, troubleshoot and develop network systems.

Layers in the OSI model can be divided into 2 groups:

- The top 3 layers (application, presentation, and session) specify how data is
  shared between applications and users.
- The bottom 4 layers (transport, network, data link and physical) specify how
  the actual data is stored and transmitted between computer systems and
  devices.

The following describes each layer of the OSI model, including key protocols
that are used.

Layer 7 - Application: this layer is where users (people or other applications)
interact with the data. The application layer determines the common interfaces
and protocols that are used across the network. The application layer acts as
an interface between users/applications and the rest of the network stack,
finding and establishing resources necessary to communicate data.

Example application layer protocols include:

- Hypertext Transport Protocol (HTTP)
- Simple Mail Transfer Protocol (SMTP)
- File Transfer Prtocol (FTP)

Layer 6 - Presentation: this layer is responsible for presenting the data that
is being transmitted in an appropriate format. This includes:

- Encoding: converting data from one format (e.g. EBCDIC to ASCII or UTF-8).
- Encryption: ensuring that data is encrypted or decrypted before being
  read/sent (e.g. using RSA, ECDSA, etc.).
- Compression: ensuring that data is compressed/decompressed before being
  sent/read (e.g. using the LZ77, LZW, DEFLATE, etc. algorithms).

The main purpose of this layer is to act as a translator for data, so that data
sent from the application layer of one system can be read by the application
layer of another system. 

Layer 5 - Session: this layer is responsible for creating, destroying and
managing the lifetime of sessions between two systems on a network. The session
layer organises communication and offers 3 modes of communication:

- Simplex: single directional flow of communication.
- Half-duplex: bidirectional flow of communication, but only one direction at a
  time.
- Duplex: bidirectional flow of information.

Session protocols enable separation and organisation of communications,
allowing a single system to initiate and handle network conversations with
multiple devices.

Layer 4 - Transport: this layer handles segmentation, transport and reassembly
of data between networked systems. The data from the application, presentation
and session layers is divided into chunks called segments or packets by the
system that sends the data, and is reassembled on the other side by the
receivng system.  Transport layer protcols are responsible for establishing and
maintaining connections between devices, transporting data and ensuring that
data streams are segmented and assembled appropriately. Protocols in this layer
are either connectionless or connection-oriented:

- Connection-oriented: before data can be transmitted, a virtual circuit is
  established which defines the parameters and methods of communication between
  2 parties. Typically, an initial handshake is performed where the 2 parties
  agree common rules of communication such as transmission rates, the amount of
  information to be sent, etc. The initial setup is known as overhead, and
  these protocols typically implement methods to check on the health of the
  connection. Typically, they are more expensive and require more time to
  communicate data, however are also more reliable (see below for details).
- Connectionless: a connection does not need to be established for
  communication to take place. Instead, data can simply be sent to any
  system, and it is up to the receiver to handle the data appropriately. This
  method is faster, however is much less reliable.

For a protocol to be reliable, it must establish three key components:

- Flow control: the receiver can govern the amount of data sent by the
  sender. This ensures that the sender does not flood the receiver with too
  much data, who may not be able to process all the data in time and exhaust
  their memory buffers resulting in a loss of data. The receiver can send the
  sender a flag to let them know to stop sending data as they are near/at
  capacity, and later can send a flag to ask the sender to resume data
  trasmission.
    - Windowing: during transmission, the sender will send a packet to the
      receiver. However, there is some time available after the sender sends
      the data and the amount of time it takes for the receiver to process
      data. This is known as the window, and some protocols allow a window to
      be set. This determines the amount of time to wait for an acknowledgement
      of each packet of data before transmitting more data. For example, with a
      window size of 5, 5 packets may be transmitted before the sender waits
      for an acknowledgement by the receiver.
- Acknowledgement: the receiver acknowledges data that is has received from the
  sender, allowing the sender to retransmit packets that might have been lost.
  The sender also uses timers/other mechanisms to retransmit data that it has
  not yet received an acknowledgement for.
- Sequencing: packets are numbered (sequenced) so they can be uniquely
  identified. This allows for retransmission, flow control and acknowledgement
  to take place.

The main two protocols used for transport are:

- Transmission Control Protocol (TCP): this is a reliable connection oriented
  protocol.
- User Datagram Protocol (UDP): this is a connectionless protocol.

Layer 3 - Network: this layer is responsible for addressing devices. This is
used to locate devices on a network and includes routing data through a network
so that data transmitted from one system can find its way to another
appropriately. A router, which is a layer 3 device, is used to carry this out.
A device will initially send data to the router, which then forwards the data
on to other routers or to the receiving system. When the data is received by a
router, the router checks the header to determine where it needs to be sent -
it uses its internal router table to do so. Routers can receive 2 types of
packets:

- Data packets which contain actual data.
- Router update packets which contain data to update the routing table. This is
  (done using Routing Information Protocol (RIP), Enhanced Interior Gateway
  Routing Protocol (EIGRP) or Open Shortest Path First (OSPF).

To carry out routing, a network address must be provided. The most common
protocol for defining logical network addresses is the Internet Protocol (IP)
system.

Layer 2 - Data Link: while network layer routers are responsible for
transmitting data across networks, data link devices are responsible for
transmitting data within a network. This typically happens within the
first/large stage of a data transmission, where the packet reaches its initial
router or final destination. The data link layer is responsible for
encapsulating data within a data frame, which contains information about the
hardware addresses of devices within the network.
