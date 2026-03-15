# pv204_gigaprojekt

Project in subject Security Technologies at FI MUNI.
The whole project is split in different phases I-V.
 - Phase I
    - finding team, choosing project topic, creating repository
 - Phase II
    - project design, prototype implementation, short report
 - Phase III
    - final implementation, preparation of project presentation
 - Phase IV
    - analysis of another teams project, project presentation
 - Phase V
    - discussion about project and discovered problems

Currently the project is in phase II. 
Choosen topic is **Trusted timestamping server with threshold signing key**.

## Project design

The design of a trusted timestamping system using a threshold signature scheme (TSS) requires a division into several main components: the client application or an interface for submitting documents , a some sort of network of signing nodes, and a some sort of communication layer for nodes coordination, key storage.

<div align="center">
  <img src="design/designdemo3.png" alt="Design">
</div>

### Basic workflow

On the start, the servers/nodes need to setup communication and share the parts private of key each of them generated as well with public key that needs to be provided for sharing with users. 
The sharing and creating of key package needs to be done via secure channels, and some further verification like all the nodes have corresponding share via broadcast channel.


Users workflow:

- user sends document for timestamping
- interface sends to document/hash of document and some information like time to corresponding **n** servers/nodes
- than the process of threshold signing 
    - nodes need to have the appropriate information
    - the **k** of **n** nodes generate sign
    - some sort of aggregation to final signature **$\sigma$**
- user gets signature (timestamp) **$\sigma$** (and  corresponding public key) 
- verification of the signature (timestamp) **$\sigma$** could be done either: 
    - by user with public key which was provided when signing the document
    - by the nodes/serves via the interface or some API

Also we would need to take in consideration of some authentication of the user.

### Technology choices
Key sharing: 
FROST(Flexible Round-Optimised Schnorr Threshold signatures) 

Interface/API:
FastAPI/gRCP

Cryptography:
ECDSA signatures

As we choose Python as language for this project. Corresponding libraries will be choosen.
