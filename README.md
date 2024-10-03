# Hierarchical DNS Project

<!-- TABLE OF CONTENTS -->
<details>
  <summary>Table of Contents</summary>
  <ol>
    <li><a href="#about-the-application">About the Application</a></li>
    <li><a href="#DNS-servers-logic">DNS Servers Logic</a></li>
    <li><a href="#iterative-DNS-servers">Iterative DNS Servers</a></li>
    <li><a href="#kathara-environment">Kathara Environment</a></li>
    <li><a href="#learning-challenges">Learning Challenges</a></li>
    <li><a href="#contact">Contact</a></li>
  </ol>
</details>

<!-- ABOUT THE APPLICATION -->
## About the Application

A project built in C++ to simulate a DNS server that recieves a domain name from the client and sends the message 
to the corresponding server using UDP. 


<!-- DNS SERVERS LOGIC -->
## DNS Servers Logic
Logic implemented in ```cd-dns.c``` and ```ut-dns.c``` files in ```shared/src```
- Each server binds it's address to a UDP socket.
- The domain zone is created and DNS records are added and assigned an associated IP address.
- If the server receives a message from a client that is a valid query it finds the corresponding DNS record to the domain name proved. Then the server sends back to the client the IP address that corresponds to the domain name.
- Note: The ```cd-dns.c``` and ```ut-dns.c``` are both authoritative nameservers therefore when they receive a response from the client as long as it is a valid query they will have the associated IP address and can then directly respond back to the client.


<!-- ITERATIVE DNS SERVERS -->
## Iterative DNS Servers
Logic implemented in ```local-dns.c``` file in ```shared/src```



<!-- KATHARA ENVIRONMENT -->
## Kathara Environment
Features

<!-- LEARNING CHALLENGES -->
## Learning Challenges
- Because of the nature of DNS queries, when a server receives a response the code logic needs to determine if the response is an authoritative response or non-authoritative response. Non-authoritative responses required a more complex logic to ensure that the query is forwarded to the correct nameserver in order to receive an authoritative response. I adapted my code in ```local-dns.c``` to accommodate both receiving authoritative responses and non-authoritative responses and being robust enough to handle both cases.
- Ensuring comprehensive testing of the code. I utilized ```dig``` and ```ping``` commands to send A queries and check their responses and to ping servers.


<!-- CONTACT -->
## Contact
Built as course work for CS 356 (Computer Networks) at the University of Texas at Austin

The C DNS library used in this assignment built on top of the tdns c++ library from the hello-dns project.

Lucy Mahlmann - lmahlmann@utexas.edu

Project Link: [https://github.com/lucy-mahlmann/Hierarchical-DNS-Project](https://github.com/lucy-mahlmann/Hierarchical-DNS-Project)

<p align="right">(<a href="#readme-top">back to top</a>)</p>


