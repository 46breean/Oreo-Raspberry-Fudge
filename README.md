# Oblivious Revocable Functions and Encrypted Indexing in Inter-School Networks

This project is part of the Research @ Young Defence Scientists Programme (R@YDSP), jointly organised by the Defence Science and Technology Agency (DSTA) and DSO National Laboratories. 

Refer to the Meetings folder for our weekly progress, and refer to the Source Code folder for the source code to our system. Executables are in the root directory.

## Abstract

Secure multi-device encrypted indexing on untrusted servers presents a fundamental challenge. Firstly, authorised devices must obtain consistent access to shared data, while revoked devices must be denied access without relying on the server to actively enforce access control. Secondly, the server cannot gain information about encrypted data through identifiers used for indexing.

Oblivious Revocable Functions (ORFs) resolve this cryptographically. ORFs allow authorised devices to jointly evaluate a function with consistent output across devices of the same user, while ensuring revoked devices are no longer capable of producing valid evaluations. The server also learns nothing about the secret inputs.

We implement an ORF-based system in Python for a multi-school server setting, where teachers upload encrypted student data of their respective schools and query them via encrypted indexes. Teachers can be revoked when they are no longer part of the school. During implementation, we identified security weaknesses in naïve constructions, including vulnerabilities in key derivation and encrypted indexing. We then introduce improved algorithms with mathematical justifications.

Our prototype demonstrates that ORFs offer an elegant and practical solution to secure, revocable, and oblivious access control in real-world multi-device systems, and highlights the practical design choices needed to make ORF-based access control secure and usable.

## Project Report and Poster

You can refer to our project report and poster for more information on our system.

[(Coming soon!)](https://www.dsta.gov.sg/staticfile/ydsp/projects/index.html)

## How to run the system

Run the executables in the following order: server.exe -> serveradmin.exe -> useradmin.exe -> device.exe. Multiple user administrators can be instantiated, and multiple devices can be instantiated under each user administrator. There can only be one server and one server administrator per session.

Currently, the IP Address stated in the source code is a loopback address, causing the system to only run on one device. However, our system works across multiple devices on the same Wi-Fi network too! Simply change the IP Address under the global variable SERVER in all source code files (except server.py itself) to the IPv4 address of the device that the server is hosted on.

## Acknowledgements

We would like to thank our mentors, Dr Ruth Ng Ii-Yung, Mr Low Zhi You Gabriel, and Mr Lee Mung Liang Ryan, for their constant support and guidance throughout our project.
