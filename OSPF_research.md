Computer Networks 167 (2020) 107031 

**==> picture [61 x 66] intentionally omitted <==**

Contents lists available at ScienceDirect 

## ~~Computer Networks~~ 

journal homepage: www.elsevier.com/locate/comnet 

**==> picture [57 x 72] intentionally omitted <==**

## Identifying OSPF LSA falsification attacks through non-linear analysis[,][∗] Bahaa Al-Musawi[a] , Philip Branch[b] , Mohammed Falih Hassan[a] , Shiva Raj Pokhrel[c] 

**==> picture [29 x 29] intentionally omitted <==**

> a _Faculty of Engineering, University of Kufa, Najaf, Iraq_ 

> b _School of Software and Electrical Engineering, Swinburne University of Technology, Melbourne, Australia_ 

> c _School of Info Technology, Deakin University, Melbourne, Australia_ 

|a r t i c l e<br>i n f o<br>_Article_ _history:_<br>Received 15 August 2019<br>Revised 16 October 2019<br>Accepted 26 November 2019<br>Available online 28 November 2019<br>_Keywords:_<br>Intra-domain routing<br>OSPF<br>Anomaly detection<br>Non-linear analysis<br>Testbed<br>CORE|a b s t r a c t|
|---|---|
||Open Shortest Path First (OSPF) is one of the most widely used intra-domain routing protocols. Unfortu-<br>nately, it has many serious security issues. Falsifcation over OSPF is one of the most critical vulnerabili-<br>ties that can cause routing loops and a black hole. In this paper, we introduce a novel approach by using<br>a technique from non-linear statistical analysis to identify OSPF attacks. Firstly, we evaluate the capabil-<br>ity of the non-linear technique to identify OSPF attacks using a controlled testbed where we introduce<br>different types of LSA falsifcations. Secondly, we evaluate our approach to detect different types of OSPF<br>attacks using OSPF trafc associated with a single OSPF router and OSPF trafc associated with a set of<br>OSPF routers. In both cases, our approach can detect anomalous behaviour quickly. Finally, we use various<br>successful machine learning classifers to analyze the outputs obtained from the non-linear analysis and<br>calibrate their suitability in discovering such anomalies.<br>© 2019 Published by Elsevier B.V.|



## **1. Introduction** 

Open Shortest Path First (OSPF) has been designed to be deployed within a single Autonomous System (AS) where an AS represents a large organisation or an Internet Service Provider (ISP). OSPF is one of the most widely used interior gateway protocols [1,2]. Being a link-state routing protocol each OSPF router maintains a database that describes the AS’s topology [3]. The main responsibility of the OSPF routing protocol is to allow all routers within an AS to construct their routing tables and updates them when a change in the AS’s topology occurs. With the growing presence of OSPF, several serious security issues have been identified and reported, which needs action. For example, Link State Advertisement (LSA) falsification reported in [1] is one of the most critical vulnerability causing routing loops and black holes. Although OSPF supports authentication where every packet sent between two peers can be authenticated through using a secret shared key, this is rarely implemented. It also provides “fight-back” mechanism, an approach that is used by the OSPF router to prevent illegitimate routers send LSAs on behalf a legitimate router. When a router receives a false LSA that was advertised by another router on its behalf, the router immediately advertises a newer instance of the LSA which cancels out the false one [3]. 

> ∗ Corresponding author. _E-mail addresses:_ bahaa.almusawi@uokufa.edu.iq (B. Al-Musawi), pbranch@swin.edu.au (P. Branch), mohammedf.aljanabi@uokufa.edu.iq (M.F. Hassan), shiva.pokhrel@deakin.edu.au (S.R. Pokhrel). 

Although OSPF supports authentication and fight-back mechanism, it is vulnerable to different types of LSA falsification. LSA falsification is mainly classified into self-LSA and other-LSA. Self-LSA falsification occurs when an attacker within a router falsifies only the router’ s LSA. In other-LSA, the attacker forces a target router to send a false LSA on behalf of other routers within the same AS. Recent work on OSPF vulnerability shows serious types of OSPF attacks that can evade the fight-back mechanism and spoof the routing table for the whole OSPF routing domain [4]. Such type of OSPF attack has been noticed in real case at ISPs that use the OSPF router. Most well-known vendors such as Cisco, Juniper, IBM and NEC had acknowledged the existence of fight-back evasion attacks [5]. 

OSPF research has mainly focused on finding different types of OSPF attacks such as Seq++ and MaxSeq [6] and detecting these attacks [7]. However, these attacks have limited effects on OSPF networks. In particular, introducing Seq++ and MaxSeq will trigger a “fight-back” by the victim router reverting the attacks’ effects [8]. Other attacks have also been ameliorated after updating the firmware of OSPF routers [5]. However, real momentum has been building for investigation OSPF vulnerability and some serious OSPF attacks and their consequences that can evade the fight-back mechanism and/or authentication has been reported recently. The partitioning attack [4], disguised attack [8], and adjacency spoofing attack [1] are relevant examples. Although many research works have been introduced to detect OSPF attacks such as [9–12], but as far as we know this is the first attempt to detect 

https://doi.org/10.1016/j.comnet.2019.107031 1389-1286/© 2019 Published by Elsevier B.V. 

_B. Al-Musawi, P. Branch and M.F. Hassan et al. / Computer Networks 167 (2020) 107031_ 

2 

the serious OSPF attacks (partitioning attack, disguised attack, and adjacency spoofing attack). In summary, revisiting OSPF anomaly detection is crucial and operators need to investigate and identity such attacks along with their consequences. 

In this paper, we investigate and evaluate the characteristics of normal and anomalous OSPF traffic and exploit a non-linear statistical analysis approach based on the concepts of phase plane trajectory to filter the anomalous OSPF traffic. Our investigation includes OSPF traffic associated with a single OSPF router and OSPF traffic associated with all OSPF routers within a single OSPF area (aggregated OSPF traffic). Further, we propose a machine learning based approach to detect OSPF attacks. For extensive evaluation, we use Common Open Research Emulator (CORE), a real-time network emulator that supports routers, hosts and simulates the network links between them, as a controlled testbed and provides new insights for different types of OSPF attacks. 

We also exploit the classification approach, a process of predicting different classes from given data set, one of the most successful techniques from machine learning. It is worth noting that the learning-based classifier algorithms can be categorized into supervised, semi-supervised and unsupervised algorithms and is quite rich in literature; however, none of them are superior over others in all data sets. In fact, it is based on the application and underlying characteristics of the data set itself [13]. For example, linear classifier with logistic regression has the potential to outperform more sophisticated classification algorithms when the classes in the datasets are linearly separable [14]. Therefore, later in this paper, we evaluate and compare the performance of different successful algorithms in terms of their accuracy, sensitivity, precision, and success (F-score) in detecting anomalies. In Sec V. B later, we have used support vector machine, discriminant analysis, K-nearest neighbour, decision tree and random under sampling boosting classifier for our comparisons. 

Our evaluation for the proposed non-linear technique shows its ability to detect different types of OSPF attacks using OSPF traffic associated with a single OSPF router as well as the aggregated OSPF traffic. The ability of the proposed approach to detect OSPF attacks in a series of the aggregated OSPF traffic reduces the need to apply the detection approach on each OSPF router within an OSPF area. In addition, the proposed approach helps demonstrate the effectiveness of each OSPF attacks on the characteristics of OSPF traffic. 

The rest of this paper is organised as follows. We explore related work in detection of OSPF attacks in Section 2. Section 3 introduces a brief background of OSPF and different types of LSA updates while Section 4 explores the most well-known OSPF attacks. In Section 5, we introduce our testbed and discuss the selection of monitoring point to capture OSPF traffic. Section 6 outlines our approach using RQA. We evaluate our approach to detecting OSPF attacks in Section 7 and finally conclude our work in Section 8. 

## **2. Related work** 

Previous work on OSPF vulnerability has been largely focused on attack analysis and detection. In this section we briefly cover OSPF research related to our topic. This has been in two areas: finding vulnerabilities [1,2,4,5,8,15] and detecting attacks [7,9– 12,16]. 

Cohen et al. [4] introduced OSPF partitioning attack. The idea of partitioning attack is using false-self LSA from a subverted router. When the subverted router producing different versions of false self-originated LSA instances which contain different network information is then sent out on different outgoing interfaces, different routers in the network would have different view in the network topology. Introducing partitioning attack will not trigger 

“fight-back mechanism” because of false-LSAs generated by the subverted router. 

In [1], the authors introduced a novel OSPF attack called adjacency spoofing attack with the ability to modify routing tables. Unlike the other types of OSPF which require a compromised router to be used, this attack can be done by a common host. The ability of a common host to introduce OSPF attacks is based on the assumption that most gateways of subnets in large ISPs act as OSPF nodes where a broadcast “Hello” packets can be captured which includes some useful network parameters such as Router ID, Area ID, HelloInterval and RouterDeadInterval. Using these parameters, an attacker can construct the false LSAs to spoof the routing tables of the whole OSPF network. 

One of the earliest efforts at detecting OSPF anomalies was by Qu et al. [7]. The authors introduced a statistical approach based on statistical Intrusion detection algorithm, using historical data to build a profile for normal system behaviour using information such as means and frequency, described in [17] to detect OSPF attacks. Three types of OSPF attacks including maxseq, maxage, and seq++ were used to evaluate the detection capability. This approach, however, did not show its ability to detect OSPF attacks created by false self-originated LSAs. 

OSPF Vulnerability Checking (OSV) is a tool to help the network operator detecting their security issues in term of OSPF vulnerability [10]. OSV checks password strength and performs different OSPF attacks by generating spoofed OSPF packets and thereby report generation to find the vulnerabilities. However, OSV is not able to detect disguised and persistent OSPF attacks. In addition, when OSPF routers within a network run different firmware versions or operating systems, the vulnerability checking needs to be repeated for each router. 

Shaikh and Greenberg in [12] introduced the OSPF monitoring toolkit. The toolkit listens to LSAs updates and provides real-time tracking of OSPF behaviour and reporting for network events. It also provides off-line analysis for further investigation. However, the toolkit has not been tested to track LSAs resulted from adjacency spoofing attack. 

In this paper, we introduce a novel approach based on using a non-linear statistical analysis technique to detect different types of OSPF attacks. The concept of our approach is to find out the characteristics of normal behaviour of OSPF traffic by calculating the measurements of the non-linear analysis technique and then applying a classifier algorithm to identify OSPF attacks. The evaluation of our technique is based on data collected from a controlled testbed where we introduce different types of OSPF attacks. 

## **3. OSPF Background** 

The Internet is a decentralized global network comprised of tens of thousands of Autonomous Systems (ASes). An AS is a set of routers under a single technical administration using an Interior Gateway Protocol (IGP) such as Open Shortest Path First (OSPF) to communicate with other routers within the AS and an Exterior Gateway Protocol (EGP) such as Border Gateway Protocol (BGP) to communicate with other ASes [18]. OSPF is one of the most widely used IGPs. In addition to its wide use as an intra-domain routing protocol, OSPF is popular in the mobile ad-hoc network [19] and Ethernet-based data centers [20]. OSPF was firstly described in RFC1131 and revised by RFC 2328 [3]. There are two versions of OSPF, OSPF v2 supports IPv4 described in [3] and OSPF v3 that supports IPv6 described in [21] which retained the fundamentals mechanisms of OSPF v2. OSPF also supports Classless Inter-Domain Routing (CIDR) described in RFC4632 [22]. 

Routing protocols are mainly classified based on their routing algorithm into link-state such as OSPF, distance vector such as Interior Gateway Routing Protocol (IGRP) and path vector such as BGP. 

_B. Al-Musawi, P. Branch and M.F. Hassan et al. / Computer Networks 167 (2020) 107031_ 

3 

OSPF does not use a TCP/IP transport protocol, its messages are encapsulated directly in Internet Protocol (IP) datagrams with protocol number 89. Error detection and correction functions of OSPF are managed by itself. The main responsibility of OSPF routing protocol is to allow routers within a single AS to build their tables and dynamically update them when there is a change in the topology. This is done through sending Link State Advertisement (LSA) messages about the topology. For example, when a link between two routers comes down, the two routers have to originate and flood their LSAs with a new link included in it. From the link-state database, each router constructs a tree of shortest paths with itself as root. This shortest-path tree gives the entire path to each destination in the AS. 

OSPF is a link state routing protocol where each OSPF router advertises the state of its links to its neighbouring routers. When an OSPF protocol is enabled for a particular link, information associated with that router is added to the local Link State Database (LSDB). Afterward, the router sends Hello messages on its operational links to determine whether other link state routers are operating on the interfaces as well. In addition to neighbour discovery purpose, Hello messages are sent to maintain adjacencies between neighbour routers. There are three components in the Hello packet header to maintain information about the status of routers: “Hello interval”, “router dead interval”, and a neighbour list. “Hello interval” indicates how frequently the sender should retransmit its Hello packets; “router dead interval” tells how long it takes to declare a router unavailable, and the neighbour list describes the neighbours that the sender has already formed adjacency with. 

The purpose of setting up an adjacency is to make sure that the two routers have identical copies of the LSA database. This is done by having each router send to its peer the summaries of LSAs currently installed in its database. The summaries are sent using Database Description (DBD) messages. At the beginning of the exchange, the two routers negotiate their master/slave status. The router with the higher ID is chosen to be the master, the router ID is usually the IP address of one of the router’s interfaces. The exchange of the database description packets is done in a stopand-wait fashion. A router sends its next message only after it receives one from its peer. To distinguish between database description messages, a Sequence number is included in every message. The Sequence number is initialized arbitrarily by the master and incremented by the master with every new message it sends. The slave sends its messages with a Sequence number that equals the last message received from the master. A DBD message includes 3 flags: I, M, and MS. The ‘I’ flag is set to indicate a master/ salve negotiation. The ‘M’ flag is set to indicate the router has more LSA summaries to send. The ‘MS’ flag is set to indicate the router declares itself to be the master. Fig. 1 describes an example of an adjacency set up where R1 is chosen to be the master. 

After establishing the adjacency between two OSPF routers, these routers exchange DBD messages. Each OSPF router compares the received summary with its local LSDB to ensure it is up to date. If one router realizes that it requires an update, it will request the new information from the adjacency router. 

OSPF is a hierarchical routing protocol which supports subdomains or areas. When an OSPF domain is divided into multiple areas, routers connected to multiple areas are called area border routers. All areas must be connected to an area called backbone, a special OSPF Area 0 (often written as Area 0.0.0.0, since OSPF Area ID’ s are typically formatted as IP addresses). The backbone enables the exchange of summary information between area border routers. Dividing one domain into areas limits the scope of LSAs flooding within the OSPF domain. Consequently, each area has its own database. When a domain is divided into areas, OSPF routers do not need to know the entire topology of all the areas, they need only to learn the topology of its area. They also need to learn the 

**==> picture [103 x 57] intentionally omitted <==**

**Fig. 1.** An example of setting up adjacencies between two OSPF routers. 

weights of shortest paths from one or more border routers to each node in remote areas. OSPF networks can be classified into transit and stub network. An area can be configured as a stub when there is a single exit point from the area, or when the choice of exit point need not be made on a per-external-destination basis. A transit network carries data traffic that is neither locally destined nor locally originated. When OSPF routers connected to transit networks, they advertise links to the networks rather than to the neighbouring routers. In addition, one of the neighbouring routers is chosen to act as a designated router, which is elected by the Hello protocol. The concept of the designated router is to reduce the number of adjacencies required on broadcast. The designated router becomes adjacent to all other routers on the network. This leads to reducing the amount of routing traffic required. The designated router originates network LSAs that lists the set of routers attached to the network including the designated router (including itself). 

In addition to sending LSAs when there is a change in the network topology, OSPF routers send LSAs every 30 min, by default, to refresh their routers database. An LSA includes an Age field indicating the elapsed time since the LSA’ s origination. When it reaches 1 h the LSA instance is removed from the LSA database. LSAs contain the cost of each link which is usually statistically configured by the administrator. The router will use the interface with a lower cost to forward traffic. LSAs also include a Sequence Number field which is incremented for every new instance. A fresh LSA instance with a higher Sequence number will always take precedence over an older instance with a lower Sequence number. Fig. 2 shows the LSA header format. A description for each of the LSA header fields is given bellow: 

LS Age - Time in seconds since the LSA was originated. - Options Supported optional capabilities. 

LS type - The type of the LSA. There are five LSA types which are summarised in Table 1. 

Link State ID - Identifies the portion of the AS topology that is being described by the LSA. 

Advertising Router - Identifies the router that originated the LSA. LS Sequence number - The Sequence number of the LSA. 

_B. Al-Musawi, P. Branch and M.F. Hassan et al. / Computer Networks 167 (2020) 107031_ 

4 

**Table 1** A summary of LSA types. 

|LSA type|Description|
|---|---|
|Type-1|Router LSAs which describe the states of router’ s interfaces|
|Type-2|Network LSAs which describe the set of routers attached to the network|
|Type-3|Summary LSAs which describe routers to networks|
|Type-4|Summary LSAs which describe routers to AS boundary routers|
|Type-5|AS-external LSAs which describes routes to destinations external to the AS|



**==> picture [147 x 85] intentionally omitted <==**

**Fig. 2.** LSA header format. 

LS Checksum - The Checksum of the complete contents of the LSA. 

Length - The length in bytes of the LSA. 

LSAs messages are disseminated throughout the entire OSPF domain, when the domain is not divided into areas, enabling every router to compile a database of all the LSAs. This database is identical in all routers and it is used by routers to obtain a complete view of the AS topology. This process allows OSPF routers to calculate the shortest paths using Dijkstra’s algorithm [23]. 

OSPF supports authentication where every packet sent between two peers can be authenticated using a secret shared key. To prevent processing of OSPF packets from attackers, re-authentication is applied at each hop. However, the mechanism of managing shared secret key is not well defined; therefore, ISP operators use the same secret key between all peers within a single an AS when there is only one area or within one area. In addition to authentication support, OSPF advertisements will be taken into account of routing table if and only if a link is advertised by both its ends. An attacker advertising a non-existing link to another router will not influence the routing tables since that other router will never advertise a link back to the attacker. 

When an LSA is flooded throughout the AS, a malicious router cannot prevent that LSA from reaching other routers as long as there is a path from the originator of the LSA that does not go through the malicious router. Furthermore, LSA content holds only a small part of the topology; only the links to its immediate neighbours. Therefore, in order for an attacker to significantly influence a router’ s view of the AS topology and consequently influence its routing table it must falsify many LSAs of many routers in the AS 

[5]. 

OSPF provides a “fight-back” mechanism, a mechanism that is used by an OSPF router to prevent illegitimate OSPF routers to send LSAs on behalf a legitimate OSPF router. When a router receives a false LSA that was advertised by another router on its behalf, the router immediately advertises a newer instance of the LSA which cancels out the false one [1,4,5]. 

## **4. OSPF Attacks** 

Although OSPF supports authentication and fight-back mechanism, it is vulnerable to different types of attacks. The most serious type of attack is LSA falsification. There are two types of LSA falsifi- 

cation including self-LSA and other-LSA. Self-LSA falsification happens when an attacker within a router falsifies an LSA associated with that router. Other-LSA happens when an attacker forces a target router to send a false LSA on behalf of a victim router within the same AS. Two techniques can mitigate the other-LSA attacks, fight-back mechanism and digital signatures. Although a few attacks have been introduced to overcome this mechanism, they are either not powerful for every topology or hard to deploy. However, a digital signature can be used to prevent such types of attacks. 

Generally, the consequences of LSA falsification can be divided into three possibilities: loops that don’t necessarily include the attacker, a loop that includes the attacker and diverts the traffic to a longer path, may lead to forwarding loops. Based on these three possibilities, forwarding loops that don’t include the attacker represents the most serious where it is not possible to track the attacker [24]. 

Partitioning, disguised and adjacency are the most serious and well-known OSPF attacks. We now describe these attacks in some detail. 

## _4.1. Partitioning attack_ 

It has been widely believed that self-LSA falsification has a limited effect on other routers. However, Cohen et al. [4] demonstrate that a special type of self-LSA, named partitioning attack, can cause serious damage to the entire AS without a clear track that leads to the attacker. This attack cannot even be prevented using LSA signature based method nor on the fight-back mechanism because the compromised router does not change the LSA of any other router. 

The idea of a partitioning attack is that a compromised router sends different LSAs to its neighbours. For example, assume R1 is a compromised router with two neighbours R2 and R3. R1 sends an LSA1 to R2 with no existent link between R1-R2 and sends LSA2 to R3 with no existent link between R1-R3. As a result, R2 and R3 have different topologies. Furthermore, LSA1 and LSA2 are propagated to other OSPF routers that build their topology based on whether they receive any of LSA1 or LSA2 first. 

This type of attacks overload remote links and routers that are far a way from the attacker leaving no obvious data-plane traces which may be used to track the attacker. The consequences of partitioning attacks include forwarding loops, longer routing paths and routers become disconnected. 

## _4.2. Disguised attack_ 

The disguised attack is a type of other-LSA falsification where the attacker can affect routing advertisements of other routers while evading the “fight-back” mechanism. Attackers send false LSAs with a higher rate than MinLSInterval, at least one packet per 5 s. The minimum time between distinct originations of any particular LSA, is default 5 s. In this case, the attacker can disable the fight-back mechanism of the victim router [8]. 

The idea of disguised attack is: whenever a router A sends an LSA, the subverted router B sends another LSA called a disguised LSA. The disguised LSA contains false link information but it is identical to the LSA sent by router A in terms of Sequence Num- 

_B. Al-Musawi, P. Branch and M.F. Hassan et al. / Computer Networks 167 (2020) 107031_ 

5 

ber, Checksum, and Age. If router C receives the disguised LSA, it simply accepts the disguised LSA and rejects the correct one. On the other hand, router A will consider the disguised LSA a duplicate of the fresh instance it just generated and will not activate the “fight-back” mechanism. Disguised attack enables an attacker to fully control the entire content of an LSA of a remote router. When an attacker successfully evades the fight-back mechanism, the attacker can persistently subvert the view of other routers within the AS and affect their routing tables. Hence, the attacker can divert traffic away from its intended routes and hence enables a number of attacks on the AS. 

## _4.3. Adjacency attack_ 

Unlike the other types of OSPF attacks which require a compromised router to be used, this attack can be done by a common host [1]. The ability of a common host to introduce OSPF attacks is based on the assumption that most gateways of subnets in large ISPs act as OSPF nodes where a broadcast “Hello” packets can be captured then some useful network parameters can be obtained such as Router ID, Area ID, “Hello interval” and “router dead interval”. Based on these obtained parameters, an attacker can construct the false LSAs to spoof the routing tables of the whole OSPF networks. In addition, the gateway is assumed to be a designated router, it starts to set up an adjacency with the attacker. This attack can be used for numerous purposes such as black-hole traffic, eavesdropping, etc. 

## **5. OSPF** 

In this section we discuss how to collect OSPF traffic from a monitoring point. Unlike the inter-domain routing protocol that its traffic is publicly available [18], traffic of the intra-domain routing protocol does not include normal and anomalous traffic. This because ISPs are not willing to reveal their network topology by sharing their OSPF traffic and hence expose their networks to security issues. Furthermore, ISPs usually do not report OSPF events when they experience OSPF attacks as this can affect their business reputation. 

As a result of the lack of OSPF traffic, we introduce a controlled testbed where we can collect normal and anomalous OSPF traffic through introducing different types of OSPF attacks. Such a testbed has another advantage, it can be used to provide timestamps, what time in seconds when an anomaly occurs. The Common Open Research Emulator (CORE) is a real-time network emulator. It supports routers, hosts and simulates the network links between them [25]. CORE can provide a realistic running of emulated networks with relatively inexpensive hardware. CORE combines the ability of simulation tools such as ns-3 [26] and emulation tools such as PlanetLab [27] by emulating the network stack of routers or hosts through virtualization and simulating the links that connect them together. 

In this paper, we use the CORE in our experiment where the routers were configured to use OSPF v2 with equal weights. We also use tcpdump, a Linux tool to capture packets on a network interface, and Scapy, a Python-based powerful interactive manipulation framework which is able to decode a wide range of protocols [28], to manipulate or create OSPF packets that generate OSPF attacks. 

**==> picture [70 x 176] intentionally omitted <==**

**==> picture [38 x 93] intentionally omitted <==**

**Fig. 3.** An example of sending OSPF traffic between two nodes. 

have to originate and flood their LSAs with a new link included in it. Although LSA updates disseminate through the entire OSPF domain, selecting a monitoring point to capture LSA updates needs care. 

In the OSPF domain, networks are classified into transit and stub networks. Transit networks send and receive LSA updates with other networks while stub network receive only LSA update. Using OSPF traffic captured from the transit network might not reflect the actual behaviour. This can occur when two OSPF routers within the same area send an LSA update to each other which are identical except LS age, an OSPF field that specifies the age of the LSA in seconds. It is set to 0 when the LSA is originated and incremented on every hop of the flooding as well as they are held in each router’ s database [3]. In such a scenario, the LSA which have the smaller age value should be accepted by the received router and this router should acknowledge this LSA by sending an acknowledgment update. To clarify such a scenario, consider Fig. 3 where R1 and R2 are two adjacencies OSPF routers. In this scenario, there are three cases that can describe the exchanging of OSPF updates between R1 and R2. 

- Case 1. R1 or R2 sends an LSA update and the other router acknowledges it. Such a case can be seen in stub routers. 

- Case 2. R1 sends an LSA with age 4 and R2 sends the same LSA but with a higher value of age, such as 5. Although R2 sent LSA after R1, R2 has to acknowledge the LSA sent by R1 as it has a smaller age value. 

- Case 3. R1 sends an LSA with age 4 and R2 sends the same LSA but with a lower value of age, such as 3. R1 discards the LSA that sent and will acknowledge the LSA sent by R2 as it has a smaller age value. 

As we can see from case 2 and 3, there is extra information sent between the two nodes that can lead to produce inaccurate representation for OSPF traffic. Therefore, we will monitor OSPF traffic by using LSA updates sent by stub networks. 

## _5.2. Collecting OSPF traffic_ 

In this section we discuss the process of collecting normal and anomalous OSPF traffic. 

## _5.1. Selecting monitoring point_ 

## _5.2.1. Normal OSPF traffic_ 

OSPF routers send a periodic refresh of LSAs, the default value of the refresh period is 30 min. In addition, OSPF routers flood LSAs when there is a change in the network topology. For example, when a link between two routers comes down, the two routers 

In order to collect OSPF traffic that has similar characteristics to that one found in ISP networks, we have emulated a large corporate network with a core layer, a distribution layer and an access layer as shown in Fig. 4. In this topology, we use 20 OSPF routers 

6 

**==> picture [253 x 7] intentionally omitted <==**

**----- Start of picture text -----**<br>
B. Al-Musawi, P. Branch and M.F. Hassan et al. / Computer Networks 167 (2020) 107031<br>**----- End of picture text -----**<br>


**==> picture [499 x 290] intentionally omitted <==**

**==> picture [92 x 8] intentionally omitted <==**

**----- Start of picture text -----**<br>
Fig. 4. Experimental topology.<br>**----- End of picture text -----**<br>


**==> picture [233 x 154] intentionally omitted <==**

**==> picture [129 x 7] intentionally omitted <==**

**----- Start of picture text -----**<br>
Fig. 5. An example of normal OSPF traffic.<br>**----- End of picture text -----**<br>


with different number of peers per OSPF router, for example, abr1 has five peers, r5 has four peers, r6 has three peers, r10 has two peers and r7 has only one. In this case we explore a single area OSPF network which is our focus in this paper. Multiple areas OSPF network is an area for future research. 

To emulate this large network, we use the CORE emulator. The end-hosts were configured to be Linux systems executing Ubuntu 16.04, kernel version 4.8.0-53-generic, while the routers executed Quagga images [29]. The routers were configured to use OSPF v2 and equal weights were used for all the inter-router links. We collected OSPF traffic from multiple monitoring points such as r7, r11, r13 and r16. Fig. 5 shows a sample of aggregated OSPF traffic and OSPF traffic originated by OSPF router r3 and collected at r11. 

_5.2.2. Anomalous OSPF traffic_ In this section we describe our experiment setup to introduce different types of OSPF attacks. These include partitioning attack, disguised attack and adjacency attack. 

_a) Partitioning Attack:_ In this attack, we assumed that r8 is a compromised router. It will send out different versions of false-self LSA to r3 and r4. To introduce a successful partitioning attack, it is necessary for those two versions to have the same Sequence number and Checksum, while Age field can be set to 0. However, after looking at the algorithm in [30], we found that it is much easier to create two Checksum-equally LSAs if they have the same length, rather than adding dummy link to the end of LSAs. Followed by this feature, we now can create two “identical” LSAs quickly. The LSA which sends out to r4 shows that there is no link between r8 and r3, while the one sends out to r3 shows that there is no link between r8 and r4. 

False_self LSA may cause a longer traffic path or even create a forwarding loop [4]. In our experimental attack, we expect a loop between r3 and r4. To verify this, we use “tracepath” command from host1 to host2 (Fig. 6) where we can see that there is a loop between router ID 10.200.100.1 (r3) and 10.110.60.22 (r4). Fig. 7 shows OSPF traffic (total number of LSAs per second) associated to all OSPF routers collected by router rcs1. In this example, we introduced the partitioning attack at timestamp 2000 s. Although it is clear to see the affect the partitioning attack on the data plane (Figure 6), finding out the affect of partitioning attack on the control plane data represents a challenge particularly for aggregated OSPF traffic (Fig. 7a). 

_b) Disguised Attack:_ To evaluate the impact of disguised LSA attack, we assume the cost in the link r3-r4 is 10, r3-r8 is 30 and r4-r8 is 15. Hence, if a packet comes from h1 and directs to h2, the proper route is: h1-r7-r3-r4-r8-h2. In this attack, we assume r8 is the compromised router. It will send the false peer LSA on behalf of r3, through eth1 to r4. In this case, the first packet would con- 

_B. Al-Musawi, P. Branch and M.F. Hassan et al. / Computer Networks 167 (2020) 107031_ 

7 

**==> picture [247 x 161] intentionally omitted <==**

**Fig. 6.** Tracepath command from host1 to host2-Partitioning attack. 

**==> picture [223 x 150] intentionally omitted <==**

**Fig. 7.** A sample of OSPF traffic during partitioning attack. 

**==> picture [247 x 139] intentionally omitted <==**

**Fig. 8.** Tracepath command from host1 to host2-Disguised attack. 

tain the “trigger LSA”, then after 5 s, we would send the disguised LSA. The disguised LSA has the same length as the LSA produced by router r3, hence one can make them have the same Sequence Number and Checksum, while Age is set to 0 in disguised LSA. 

In the disguised LSA, the link between r3-r8 was announced with the cost of 1. Hence, in r4’ s perspective, the path r4-r3-r8 has cost metric (10 + 1 = 11) less than that one in the path r4-r8 (15). As a result, the loop is made between r3 and r4. To verify this, we type the “tracepath” command from host h1 to h2 (Fig. 8). Fig. 9 shows aggregated OSPF traffic and OSPF traffic generated by a single OSPF router when disguised attack introduced at time 2000 s. 

_c) Adjacency Attack:_ In this attack, we sent dynamically packets from h2 to establish an adjacent relationship between h2 and r8. From h2, Hello packet is sent periodically with h2’ s ID which 

**==> picture [228 x 146] intentionally omitted <==**

**Fig. 9.** A sample of OSPF traffic during disguised aattack. 

**==> picture [247 x 144] intentionally omitted <==**

**Fig. 10.** Adjacency establishment process between h2 and r8-Adjacency attack. 

**==> picture [247 x 191] intentionally omitted <==**

**Fig. 11.** IP routing in r8-Adjacency attack. 

is larger than r8’ s ID (we used 200.200.200.200 for example). After receiving the first Database Description from r8, h2 would send back Database Description, Request, LS Update and LS ACK packets to set up an adjacency. After that, Hello packets are still sent out periodically to maintain the relationship (Fig. 10). 

In LS Update, h2 sent out an LSA which specifies that it has the connection to a stub network (10.1.6.0/24, for example). It may cause the black hole traffic in that network. Looking at the IP route of router r8, we can see that the route to the subnet 10.1.6.0/24 is now forwarded through h2 (Fig. 11). Figure 12 shows OSPF traffic where we introduced adjacency attack at time 2000 s. 

8 _B. Al-Musawi, P. Branch and M.F. Hassan et al. / Computer Networks 167 (2020) 107031_ 

**==> picture [227 x 43] intentionally omitted <==**

**==> picture [227 x 85] intentionally omitted <==**

**Fig. 12.** A sample of OSPF traffic during adjacency attack. 

## **6. A proposed approach for detecting OSPF attacks** 

Anomalies refer to any activity that deviates from its standard, normal, or expected behaviour [31]. One essentially has to define what is the characteristics of normal traffic then define any deviation from this behaviour as an anomaly. At first glance, this seems straightforward. However, not all deviations may result in serious consequences. Generally, anomaly detection techniques use two main types of data. These are data plane and control plane. For example, in OSPF domain, data collected from tracepath (Fig. 6) and ping are examples for OSPF data plane while OSPF traffic (Fig. 5) is an example of OSPF control plane. Our interest in this paper is in the later, in particular we are investigating a new approach to detect OSPF anomalies using control plane OSPF traffic. 

Anomalous OSPF traffic can be a result of a topology change, link or node failure or an attempt from attacks to subvert a part or the whole OSPF domain. To that end, we introduce a novel approach based on using a non-linear statistical analysis technique and a Machine Learning (ML) algorithm to differentiate between normal OSPF traffic and anomalous one that identifies OSPF attacks. Our proposed approach consists of two stages. The first stage is calculating the total number of LSAs (associated with all types of LSAs) sent per second then finding out variation in the underlying time series for a set of LSAs. The output of this stage is a set of measurements that measure the system behaviour over time. At the second stage, we apply a machine learning algorithm to classify anomalous behaviour that identifies OSPF attacks. 

## _6.1. A non-linear statistical analysis technique_ 

The states of systems typically change over time. The study of transitions of these states provides a way of understanding these systems and predicting their behaviour [32]. Such systems are defined as dynamical systems consisting of a set of variables that describes their current state and a law that describes how their state changes with time. A dynamical system can be defined by a phase space where each point corresponds to a definite system state and as the system propagates through time a trajectory is formed. The state of a system at time _t_ can be specified by _d_ variables to form a vector _x_ ( _t_ ) in _d_ -dimensional phase space. That is 

_⃗ x(t )_ = _(x_ 1 _(t ), x_ 2 _(t ), . . . , xd(t ))[T] ._ 

**==> picture [13 x 10] intentionally omitted <==**

To reconstruct phase space trajectories using time embedding method, embedding dimension ( _m_ ) and time delay ( _τ_ ) parameters need to be calculated. Different algorithms can be used to determine these parameters. The Auto-correlation function (ACF) and Mutual Information (MI) are the most well-known methods to determine the time delay [33]. Unlike ACF which measures lin- 

**==> picture [247 x 484] intentionally omitted <==**

**Fig. 13.** Examples of different OSPF topologies. 

ear correlation, MI measures both linear and non-linear correlation. Therefore, we use the MI method to determine the time delay parameter. To estimate the embedding dimension parameter, False Nearest Neighbour (FNN), a tool for determining the proper embedding dimension in dynamic systems, can be used. The first minimum values of MI and FNN represent the values of time delay and embedding dimension respectively. We use OSPF traffic collected at stub networks to calculate the values of time delay and embedding dimension. We also go further to investigate if these values are constrained with the topology used in Fig. 4 or can be generalised with different topologies. Fig. 13 shows example of two different topologies. The maximum number of peers in topology 1 is 4 while in topology 2 is 6. Whatever the number of OSPF routers and the number of peers per OSPF router, we can see that the val- 

_B. Al-Musawi, P. Branch and M.F. Hassan et al. / Computer Networks 167 (2020) 107031_ 

9 

ues of time delay and embedding dimension are 10 and 3 respectively for the aggregated OSPF traffic and they are equal to 2 for OSPF traffic originated by a single OSPF router. 

Phase plane trajectory is able to uncover patterns that may not be apparent from simply analysing a one dimensional series of values. Although phase plane trajectory is powerful in understanding deterministic and non-deterministic systems, investigating dynamics of systems in phase space trajectory is a complex task particularly for an _m_ -dimensional phase space trajectory when _m_ ≥ 3. In addition, the phase plane cannot be directly used for automated detection of system behaviour changes or real-time anomaly detection. To reduce the difficulty of phase plane interpretation, Recurrence Quantification Analysis (RQA) has been introduced. RQA is an advanced non-linear statistical analysis technique which uses the concepts of phase plane trajectory. RQA has been previously used to detect instability and anomalies in different disciplines such as physics, medicine, and engineering [34]. RQA is based on measurement from a Recurrence Plot (RP) of the phase space trajectory. An RP captures recurrent behaviour of the trajectory through phase space [33]. RQA provides several measures of complexity that are called RQA measurements. To calculate RQA measurements, three parameters have to be estimated. These are the two used in reconstructing phase space: time delay ( _τ_ ) and embedding dimension ( _m_ ), and a new one, the threshold ( _ε_ ) which refers to the distance between a pair of states in the RP less than which indicates recurrent used of the trajectories in the phase space. Although there is not a well-established method to determine the optimal values of the threshold, the value of threshold has to be selected to be as small as possible. A recommendation from Marwan et al. [35] suggests that the threshold has to be selected less than 10% of the maximum phase space diameter. 

RQA measurements demonstrate the characteristics of systems at different times. For example, the ENT measurement measures the complexity of a deterministic structure in the system. The ENT value is high for the more complex the dynamics while it is low for uncorrelated data. The most well-known RQA measurements are Determinism (DET), Laminarity (LAM), Trapping Time (TT), Recurrence Rate (RR) and Shannon entropy (ENT). 

Recurrence Rate (RR) refers to the probability that a system recurs after several states. It measures the density of recurrence points in the RP which simply counts the number of black dots in the RP. RR can be calculated as 

**==> picture [252 x 28] intentionally omitted <==**

where _Ri,j_ is an element of the recurrence matrix _R_ . R is a square matrix where each element corresponds to a point in time states [33]. 

Determinism (DET) can be interpreted as the predictability of a system. DET is a measure based on diagonal lines of the RP. The length of the diagonal lines differ from one system to another. They are long for periodic signals, short for chaotic signals, and absent for stochastic signals. DET can be calculated as the ratio of recurrence points that form diagonal structures to all recurrence points. 

**==> picture [252 x 26] intentionally omitted <==**

where _lmin_ is a threshold which excludes the diagonal lines formed by the tangential motion of the phase space trajectory, _lmin_ is typically set to two. Setting _lmin_ to one will result in DET and RR being identical. _P_ ( _l_ ) is the histogram of the lengths _l_ of the diagonal lines [35]. 

Laminarity (LAM) is a measure of whether the system is in a stable state or if it is transitioning from one state to another. LAM 

refers to the percentage of recurrence points which form vertical lines in the RP. LAM can be calculated as 

**==> picture [252 x 25] intentionally omitted <==**

where _P_ ( _v_ ) is the histogram of the lengths _v_ of the vertical lines and the typical value for _vmin_ is set to two. 

Trapping Time (TT) can be used to measure how long the system remains in a specific state. It contains information about the vertical structures in the RP. The computation of TT uses the minimal length _vmin_ as in Theorem 4 [35]. 

**==> picture [252 x 26] intentionally omitted <==**

**==> picture [253 x 71] intentionally omitted <==**

Entropy (ENTR) can be used to measure system’s predictability. For example, the value of ENTR is small for uncorrelated data. It is the Shannon entropy of the frequency distribution of the diagonal line lengths. ENTR reflects RP complexity in term of the diagonal lines. ENTR can be calculated as 

**==> picture [253 x 27] intentionally omitted <==**

This measurement has been extended to L-entr, W-entr, and V-entr that refer to entropy of diagonal line length distribution, entropy of the distribution of line lengths, and entropy of vertical line length distribution respectively. 

L-MAX is a RQA measurement that is based on diagonal lines of the RP. L-MAX refers to the longest diagonal line found in the RP which can be calculated as 

**==> picture [253 x 9] intentionally omitted <==**

L-MEAN is the average diagonal line length in the RP which represents the mean prediction time. It is the average time that two segments of the trajectory are close to each other. L-MEAN is calculated as 

**==> picture [252 x 25] intentionally omitted <==**

Before applying RQA and calculating its measurements, the window size of the LSAs set need to be chosen carefully. A large window may fail to identify some transitions in system behaviour while a small window can generate spurious fluctuations in RQA measurements. We evaluate window sizes from 100 s to 1200 s with an increment of 50 s. Our selection of the window size is based on a notable change on the values of RQA measurements during OSPF attacks, we don’t consider system accuracy at this stage but will consider them at the next stage (described in Section 7). Fig. 14 shows the total number of LSAs during the partitioning attack and its corresponding values of LAM measurements when the window size 200 s and 1200 s. In addition to the notable change in LAM values when the window size is 200 s, the detection period of LAM measurement is shorter. It is 200 s when the window size is 200 s and 1200 s when the window is 1200 s. Therefore, we will use the window size of 200 s in our calculation of RQA measurements. 

_B. Al-Musawi, P. Branch and M.F. Hassan et al. / Computer Networks 167 (2020) 107031_ 

10 

**==> picture [219 x 228] intentionally omitted <==**

**==> picture [164 x 8] intentionally omitted <==**

**----- Start of picture text -----**<br>
Fig. 14. Effect of window size on RQA measurements.<br>**----- End of picture text -----**<br>


## _6.2. Quantifying classifiers_ 

In this section, we use different classifiers and compare their performance to classify OSPF attacks. We use accuracy, sensitivity, precision and F-score as metrics for quantifying the performance different classification algorithms for our research, all of which are explained shortly in the following. Accuracy regards normal events as being as important as anomalous events while F-score reflects the success of detecting anomalies rather than detecting both anomalies and normal events. Precision measures the ability of the system to identify classified and unclassified anomalies while sensitivity measures the ability of the system to correctly classify anomalies in the data set. These evaluation metrics are calculated as follows: 

**==> picture [252 x 20] intentionally omitted <==**

where TP refers to numbers of anomalies that are classified as anomalies while TN refers to numbers of normal events that are classified as normal. FP refers to normal events that are classified as anomalous while FN refers to anomalous events that are classified as normal. 

**==> picture [252 x 87] intentionally omitted <==**

Generally, the performance of machine learning classifiers strictly depends on a given dataset whether it is balanced or imbalanced. Support Vector Machine (SVM), Discriminant Analysis (DA), K-Nearest Neighbour (KNN), Decision Tree (DT) are the wellknown examples to classify balanced dataset [36] while Random Under Sampling Boosting (RUSBoost) is a well-known example to classify imbalanced dataset [37]. The SVM is a supervised ML algorithm. It is based on creating sets of multidimensional hyperplanes that can be used for classification or regression. The hyperplanes are constructed based on the maximum distance to the 

closet training data for each class in which the larger distance the better generalization error. DA algorithm is another example of a supervised ML algorithm. It fits each class to a multivariate normal distribution and then classifies data based on decision boundary estimated from the fitted model. The KNN algorithm works on classification instances by majority votes to its neighbours. For each new instance, the class is assigned based on minimum distance to K nearest samples in training data for each class. The DT is a tree classification structure; the classification starts from the root node toward a leaf node. The RUSBoost is a deep decision tree classifier that designed specifically for classifying imbalance data in which instances of one class greatly outnumber instances of the other class(es). The RUSBoost algorithm samples N training point from class with fewer samples. Classes that have more training points are under sampled by taking N samples for every class. The algorithm uses procedure called Adaptive Boosting for Multiclass Classification for creating the ensemble [37]. 

The input to the above classifiers is a set of RQA measurements calculated in Section 6.1. Each of these classifiers consists of two phases, training and testing. In the training phase, all the RQA measurements corresponding to the steady state are used to build a model, which captures the state of the system. In the testing phase, any new incoming RQA measurements are checked against the built model. A decision value is then generated, which is akin to a score on how well this new data fit with the model. A negative decision value means that this new data is outside the model boundaries and thus indicates an anomaly. The total number of instances in our experiments is 57,686 divided into 57,312 instances of normal state and 374 instances of anomalous state. This type of data set is considered as imbalanced, the number of normal state instances (57312) is greatly outnumbered the number of anomalous state instances (374). This represents a challenge to construct a classifier that effectively identifies the instances of the underrepresented class which may cause a trained model to overfitting a class with large number of instances in favor of the other class. To avoid the problem of overfitting, we divide the data set into two equal parts, 28,656 of normal states and 187 of anomalous states for training and test respectively. 

## **7. Results and discussion** 

In this section, we evaluate our approach to detect the most well-known OSPF attacks. These are partitioning attack [4], disguised attack [8], and adjacency spoofing attack [1]. Our evaluation includes investigating the ability of our approach to detect OSPF attacks in the underlying aggregated OSPF traffic (OSPF traffic associated with all OSPF routers within the OSPF area shown in Fig. 4) and OSPF traffic associated with a single OSPF router. We use an automation script that introduces the three well-known attacks. We introduced partitioning, disguised, and adjacency attacks at timestamps 14385, 28785, and 43194 s respectively. We assume r8 is the compromised router for disguised and partitioning attacks while host2 is the attacker for adjacency spoofing attack. 

## _7.1. Detecting OSPF attacks using the aggregated OSPF traffic_ 

We collect OSPF traffic from one of the monitoring points then apply the two stages (the non-linear statistical analysis and the classifiers) of our approach to detect OSPF attacks. Before applying our approach to detect OSPF attacks, we investigate the effectiveness of the most well-known OSPF attacks on the characteristics of OSPF traffic. This can be done through tracking the changes of RQA measurements before and during the events. Fig. 15 shows the total numbers of LSAs per second collected from OSPF router rcs1 and its corresponding values of DET and LAM measurements. In this figure, we can see notable changes in the values of DET 

_B. Al-Musawi, P. Branch and M.F. Hassan et al. / Computer Networks 167 (2020) 107031_ 

11 

**==> picture [229 x 232] intentionally omitted <==**

**Fig. 15.** Number of all LSAs updates collected by rcs1 and its corresponding values of LAM and DET. 

**==> picture [228 x 212] intentionally omitted <==**

**Fig. 16.** Number of all LSAs updates originated by r8 and its corresponding values of RQA measurements. 

**Table 2** 

Detection Accuracy for Aggregated OSPF traffic. 

|Evaluation|Classifcation Algorithm|Classifcation Algorithm|Classifcation Algorithm|||
|---|---|---|---|---|---|
|metrics||||||
||SVM|DT|DA|KNN|RUSBoost|
|TN|28,655|28,652|28,652|28,644|28651|
|FP|1|4|4|12|5|
|FN|89|6|7|40|5|
|TP|98|181|180|147|182|
|Precision|**0.9899**|0.9784|0.9783|0.9245|0.9733|
|Sensitivity<br>Accuracy<br>F-score|0.5241<br>0.9969<br>0.6853|0.9679<br>**0.9997**<br>0.9731|0.9626<br>0.9996<br>0.9704|0.7861<br>0.9982<br>0.8497|**0.9733**<br>**0.9997**<br>**0.9733**|



and LAM during partitioning and disguised attacks, 14,385 and 28,785 s. Although the maximum number of LSAs collected during the partitioning attacks and disguised attack (2 LSAs per second, see Figs. 7 and 9), RQA measurements show notable changes during these events. These changes are based on changing the characteristics of a series of the aggregated OSPF traffic in the underlying system behaviour. This figure also shows that the partitioning attack has a greater effect on the characteristics of the aggregated OSPF than disguised attack. For example, the minimum values of LAM during partitioning attack are 0.9213 compared to 0.9519 during the disguised attack. In addition to its ability to subvert routing table without leaving an obvious data-plane traces to track the attacker [4], partitioning attack has a significant impact on the characteristics of the aggregated OSPF traffic which RQA measurements, deterministic and Laminarity, can identify it. 

However, we can not see a notable change for RQA measurements during adjacency spoofing attack. In term of detection delay. we can see that our approach can detect the partitioning attack with a detection delay is 1270 s and the detection delay for the disguised attack is 21 s. 

Table 2 shows the performance of the classification algorithms to detect OSPF attacks using the outputs of our non-linear statistical analysis (RQA measurements). As highlighted in Table 2 we can observe that RUSBoost outperforms over other classifiers. This reason being the property inside our data set where the normal state instances vastly outnumbers anomalous instances. Moreover, 

observe in Table 2 that the sensitivities and F-scores values of both SVM and KNN reflects that they are not quite suitable for such datasets. 

## _7.2. Detecting OSPF attacks using OSPF traffic originated by a single OSPF router_ 

In this section, we use OSPF traffic originated by one of the OSPF routers. It is important to choose an OSPF router that is a designated router, originates a network-LSA on behalf of the network; otherwise, we will not see any OSPF traffic originated by this router. Figure 16 shows total number of LSAs originated by r8 and collected from rcs1 and the corresponding values of RQA measurements. looking at the total number of LSAs updates originated by r8, we can see a notable change in the number of LSAs during the adjacency spoofing attack (number of LSAs before the adjacency attack is 2 LSAs while it is 4 LSAs during the attack) which RQA measurements quickly change to reflect the deviation in the underlying system behaviour. In this example, the detection delay is 185 s for adjacency spoofing attack and 73 s for partitioning attack. 

However, using OSPF traffic originated by OSPF router r8 we can not see a notable change in the values of RQA measurements during the disguised attack. In other word, sending a false other-LSA from the OSPF router r8 does not change the characteristics of underlying system behaviour of r8 (the compromised router). We go further to see if the characteristics of underlying system behaviour for the victim router, r3 in this case, changes during the disguised attack. Figure 17 shows OSPF traffic originated by r3 and its corresponding values of RQA measurements. Although OSPF traffic does not show a notable increase in the number of LSAs during the disguised attack, we introduced the disguised attack at timestamp 28785 s, TT and Entropy show a notable change during the event. Table 3 shows the performance of the classifier algorithms to detect OSPF attacks using the outputs of our non-linear statistical analysis. Once again, as highlighted in Table 3 RUSBoost shows better performance over other classifiers. To that end, we conclude that non-linear statistical analysis technique to detect anomalous behaviour. Furthermore, our investigation on the characteristics of OSPF traffic using aggregated OSPF traffic and OSPF traffic origi- 

_B. Al-Musawi, P. Branch and M.F. Hassan et al. / Computer Networks 167 (2020) 107031_ 

12 

**==> picture [228 x 212] intentionally omitted <==**

## **Author contributions** 

All authors have participated in (a) conception and design, or analysis and interpretation of the data; (b) drafting the article or revising it critically for important intellectual content; and (c) approval of the final version. 

## **Supplementary material** 

Supplementary material associated with this article can be found, in the online version, at doi:10.1016/j.comnet.2019.107031. 

## **References** 

- [1] Y. Song, S. Gao, A. Hu, B. Xiao, Novel attacks in OSPF networks to poison routing table, in: Communications (ICC), 2017 IEEE International Conference on, IEEE, 2017, pp. 1–6. 

- [2] A. Sosnovich, O. Grumberg, G. Nakibly, Finding security vulnerabilities in a network protocol using parameterized systems, in: Proceedings of the 25th International Conference on Computer Aided Verification, in: CAV’13, Springer-Verlag, Berlin, Heidelberg, 2013, pp. 724–739. 

- [3] J. Moy, OSPF Version 2, RFC 2328 (Standards Track), 1998, Internet Engineering Task Force, April. [Online]. Available: http://tools.ietf.org/html/rfc2328. 

- [4] R. Cohen, R. Hess-Green, G. Nakibly, Small lies, lots of damage: a partition attack on link-state routing protocols, in: Communications and Network Security (CNS), 2015 IEEE Conference on, IEEE, 2015, pp. 397–405. 

**Fig. 17.** Number of all LSAs updates originated by r3 and its corresponding values of RQA measurements. 

## **Table 3** 

Detection Accuracy for OSPF traffic originated by a single OSPF router. 

|Evaluation|Classifcation Algorithm|Classifcation Algorithm|Classifcation Algorithm|||
|---|---|---|---|---|---|
|metrics||||||
||SVM|DT|DA|KNN|RUSBoost|
|TN<br>FP|28,100<br>10|28,093<br>17|27,854<br>256|28,093<br>17|28099<br>11|
|FN<br>TP|58<br>15|15<br>58|9<br>64|27<br>46|12<br>61|
|Precision<br>Sensitivity|0.6000<br>0.2055|0.7733<br>**0.9745**|0.2000<br>0.8767|0.7302<br>0.6301|**0.8472**<br>0.8356|
|Accuracy|0.9976|0.9989|0.9906|0.9984|**0.9992**|
|F-score|0.3061|0.7838|0.3257|0.6765|**0.8414**|



- [5] G. Nakibly, A. Sosnovich, E. Menahem, A. Waizel, Y. Elovici, OSPF Vulnerability to persistent poisoning attacks: a systematic analysis, in: Proceedings of the 30th Annual Computer Security Applications Conference, in: ACSAC ’14, ACM, New York, NY, USA, 2014, pp. 336–345, doi:10.1145/2664243.2664278. [Online]. Available: 

- [6] Y.F. Jou, F. Gong, C. Sargor, X. Wu, S.F. Wu, H.-C. Chang, F. Wang, Design and implementation of a scalable intrusion detection system for the protection of network infrastructure, in: DARPA Information Survivability Conference and Exposition, 2000. DISCEX’00. Proceedings, vol. 2, IEEE, 2000, pp. 69–83. 

- [7] D. Qu, B.M. Vetter, F. Wang, R. Narayan, S.F. Wu, Y. Hou, F. Gong, C. Sargor, Statistical anomaly detection for link-state routing protocols, in: Proceedings Sixth International Conference on Network Protocols (Cat. No. 98TB100256), IEEE, 1998, pp. 62–70. 

- [8] G. Nakibly, A. Kirshon, D. Gonikman, D. Boneh, Persistent OSPF Attacks, NDSS, 2012. 

- [9] F. Wang, F. Gong, F.S. Wu, R. Narayan, Intrusion detection for link state routing protocol through integrated network management, in: Proceedings Eight International Conference on Computer Communications and Networks (Cat. No. 99EX370), IEEE, 1999, pp. 634–639. 

- [10] P. Kasemsuwan, V. Visoottiviseth, OSV: OSPF vulnerability checking tool, in: 2017 14th International Joint Conference on Computer Science and Software Engineering (JCSSE), IEEE, 2017, pp. 1–6. 

nated by a single OSPF router shows the effect of the partitioning, disguised and adjacency attacks on the OSPF control-plane. 

## **8. Conclusions** 

Different types of attacks have exploited OSPF vulnerability even though it has been used extensively since last two decades. We have thoroughly analyzed the LSA falsification, one of the most serious attacks that has threaten OSPF protocol in recent years. We observed that rapid identification of OSPF anomalies helps to mitigate the adverse impact of LSA, which can potentially lead to worst consequences such as route loop and black hole. We have demonstrated a nonlinear statistical analysis technique based on phase plane concepts, can help to identify such critical anomalies. We have evaluated the capability of our technique using data collected from a (controlled) testbed where different types of OSPF attacks were introduced. Furthermore, we have also used machine learning based classifiers to quantify the results obtained from our technique. Our extensive evaluation has concluded that the proposed technique is successful to detect OSPF attacks timely and with high accuracy. Further investigation in the underlying capability of RQA to differentiate between different OSPF attacks is ongoing. 

## **Declaration of Competing Interest** 

## None. 

- [11] H.-Y. Chang, S.F. Wu, Y.F. Jou, Real-time protocol analysis for detecting link-state routing protocol attacks, ACM Trans. Inf. Syst. Secur.(TISSEC) 4 (1) (2001) 1–36. 

- [12] A. Shaikh, A.G. Greenberg, OSPF Monitoring: architecture, design, and deployment experience, in: NSDI, 2004, pp. 57–70. 

- [13] I.S. Thaseen, C.A. Kumar, Intrusion detection model using fusion of chi-square feature selection and multi class SVM, J. King Saud Univ.-Comput.Inf. Sci. 29 (4) (2017) 462–472. 

- [14] A.L. Buczak, E. Guven, A survey of data mining and machine learning methods for cyber security intrusion detection, IEEE Communications Surveys & Tutorials 18 (2) (2015) 1153–1176. 

- [15] S.T. Niari, A.H. Jahangir, Verification of OSPF vulnerabilities by colored petri net, in: Proceedings of the 6th International Conference on Security of Information and Networks, ACM, 2013, pp. 102–109. 

- [16] A. Sosnovich, O. Grumberg, G. Nakibly, Formal black-box analysis of routing protocol implementations, 2017 arXiv:1709.08096. 

- [17] H.S. Javitz, A. Valdes, C. NRaD, The NIDES statistical component: description and justification, Contract 39 (92–C) (1993) 15. 

- [18] B. Al-Musawi, P. Branch, G. Armitage, BGP Anomaly detection techniques: a Survey, IEEE Communications Surveys & Tutorials 19 (1) (2017) 377–396, doi:10.1109/COMST.2016.2622240. 

- [19] T. Clausen, P. Jacquet, Optimized link state routing protocol (OLSR), 2003, RFC 3626 (Experimental), Internet Engineering Task Force, October. [Online]. Available: http://tools.ietf.org/html/rfc3626. 

- [20] A. Greenberg, J.R. Hamilton, N. Jain, S. Kandula, C. Kim, P. Lahiri, D.A. Maltz, P. Patel, S. Sengupta, VL2: a scalable and flexible data center network, in: ACM SIGCOMM Computer Communication Review, vol. 39, ACM, 2009, pp. 51–62. 

- [21] R.C.D.F.J. Moy, A. Lindem, OSPF for IPv6, 2008, RFC 5340 (Standards Track), Internet Engineering Task Force, July. [Online]. Available: http://tools.ietf.org/ html/rfc5340. 

- [22] V. Fuller, T. Li, Classless inter-domain routing (CIDR): the internet address assignment and aggregation plan, 2006, RFC 4632 (Best Current Practice), Internet Engineering Task Force, August. [Online]. Available: http://tools.ietf.org/ html/rfc4632. 

_B. Al-Musawi, P. Branch and M.F. Hassan et al. / Computer Networks 167 (2020) 107031_ 

13 

- [23] D.B. Johnson, A note on Dijkstra’s shortest path algorithm, J. ACM 20 (3) (1973) 385–388. 

- [24] B. Al-Musawi, P. Branch, Identifying OSPF anomalies using recurrence quantification analysis, 2018 arXiv:1805.08087. 

- [25] J. Ahrenholz, C. Danilov, T.R. Henderson, J.H. Kim, CORE: a real-time network emulator, in: Military Communications Conference, 2008. MILCOM 2008. IEEE, IEEE, 2008, pp. 1–7. 

- [26] G.F. Riley, T.R. Henderson, The ns-3 Network Simulator, Springer Berlin Heidelberg, Berlin, Heidelberg, pp. 15–34. 

- [27] B. Chun, D. Culler, T. Roscoe, A. Bavier, L. Peterson, M. Wawrzoniak, M. Bowman, PlanetLab: an overlay testbed for broad-coverage services, SIGCOMM Comput. Commun. Rev. 33 (3) (2003) 3–12, doi:10.1145/956993.956995. 

**==> picture [73 x 96] intentionally omitted <==**

**Philip Branch** received the Ph.D. degree in engineering from Monash University, VIC, Australia, in 2000. Since 2003, he has been an Associate Professor with the Telecommunications Engineering, Swinburne University of Technology, conducting research within the Centre for Advanced Internet Architectures. His research interests are in game traffic, network security, and lawful interception. He has co-authored the book entitled Networking and Online Games: Understanding and Engineering Multiplayer Internet Games (Wiley 2006). 

- [28] P. Biondi, Scapy, [Online]. Available: http://www.secdev.org/projects/scapy/ 

- [29] K. Ishiguro, Quagga Routing Suite, [Online]. Available: http://www.nongnu.org/ quagga/. 

- [30] A. Mckenzie, ISO Transport protocol specification ISO DP 8073, 1984, RFC 905 (ISO), Internet Engineering Task Force, April. [Online]. Available: http://tools. ietf.org/html/rfc905. 

- [31] V. Chandola, A. Banerjee, V. Kumar, Anomaly detection: a survey, ACM Comput. Surv. (CSUR) 41 (3) (2009) 15. 

- [32] B. AL-Musawi, Detecting BGP Anomalies Using Recurrence Quantification Analysis, Swinburne University of Technology, 2018 Ph.D. thesis. January 

- [33] N. Marwan, J. Webber, L. Charles, Mathematical and computational foundations of recurrence quantifications, in: Recurrence Quantification Analysis, in: Understanding Complex Systems, Springer International Publishing, 2015, pp. 3–43. 

- [34] B. Al-Musawi, P. Branch, G. Armitage, Detecting BGP instability using recurrence quantification analysis (RQA), in: 2015 IEEE 34th International Performance Computing and Communications Conference (IPCCC), 2015, pp. 1–8, doi:10.1109/PCCC.2015.7410340. 

- [35] N. Marwan, M.C. Romano, M. Thiel, J. Kurths, Recurrence plots for the analysis of complex systems, Phys. Rep. 438 (5) (2007) 237–329. 

- [36] F. Palmieri, U. Fiore, Network anomaly detection through nonlinear analysis, Comput. Secur. 29 (7) (2010) 737–755. 

- [37] C. Seiffert, T.M. Khoshgoftaar, J. Van Hulse, A. Napolitano, RUSBoost: a hybrid approach to alleviating class imbalance, IEEE Trans. Syst. ManCybern. Part A 40 (1) (2009) 185–197. 

**Bahaa Al-Musawi** received the B.E./M.E. degree in 2003/2005 from University of Technology, Iraq and the Ph.D. degree in 2018 from Swinburne University of Technology, Australia. Dr. Al-Musawi had led a project titled Rapid Detection of BGP Anomalies funded by ISIF. He has been a Lecturer with the University of Kufa, Iraq, since 2006. His research interests include routing and network security, network traffic classification, IoT security and anomaly detection. 

**==> picture [73 x 96] intentionally omitted <==**

**Mohammed Falih Hassan** received BSc and MSc degrees in electrical and electronic engineering from University of Technology, Baghdad, Iraq, in 1999 and 2002 respectively. In 2017, he received the Ph.D. degree in electrical and computer engineering from Western Michigan University, Kalamazoo, MI, USA. Since 2004 he has been with electronic and communication engineering departments, University of Kufa working as a lecturer. His current research interest in machine learning includes stochastic modelling of multiple classifier systems and its applications to different areas such as incremental learning, data fusion, feature selection, bio-metric applications and computer vision. 

**==> picture [73 x 96] intentionally omitted <==**

**Shiva Raj Pokhrel** received the B.E./M.E. degree in 2007/2013 from Pokhara University, Nepal and the PhD degree in 2017 from Swinburne University of Technology, Australia. He is currently a Lecturer with the School of Information Technology, Deakin University, Australia. He was a research fellow at the University of Melbourne (2017–2018) and a telecom engineer at Nepal Telecom (2007-–2014). His research interests include modeling and optimization, recommender systems, cognitive wireless communications, cloud computing, dynamics control, Internet of Things and cyber-physical systems as well as their applications smart manufacturing, transportation and cities. He was a recipient of the prestigious Marie 

**==> picture [73 x 96] intentionally omitted <==**

Skłodowska-Curie grant Fellowship in 2017. 

