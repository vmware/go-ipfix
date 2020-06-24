# go-ipfix
go-ipfix is an IPFIX library that can be used to implement an IPFIX exporter, which can export flow records. go-ipfix follows RFC 7011 and other referenced RFCs. Specifically, this release mainly implements the IPFIX exporting process feature and provides the required IPFIX entities such as information elements, records, sets, message, etc. In addition, this library supports loading IPFIX information elements from IANA registry, reverse information elements (enterprise ID: 29305), and information elements from the private Antrea registry (enterprise ID: 55829) [1].

[1]https://antrea.io/
