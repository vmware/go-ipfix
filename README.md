# GO-IPFIX

## Overview
go-ipfix is an IPFIX library that can be used to implement an IPFIX exporter, which can export flow records. go-ipfix follows RFC 7011 and other referenced RFCs. Specifically, this release mainly implements the IPFIX exporting process feature and provides the required IPFIX entities such as information elements, records, sets, message, etc. In addition, this library supports loading IPFIX information elements from IANA registry, reverse information elements (enterprise ID: 29305), and information elements from the private Antrea registry (enterprise ID: 55829) to support [Project Antrea](https://antrea.io/).

## Try it out
This IPFIX library can be used to build an exporter. Please check out the [exporter tests](https://github.com/vmware/go-ipfix/blob/master/pkg/exporter/process_test.go) to get an idea on how to build exporter on top of TCP and UDP transport protocols given a IPFIX collector.

## Contributing

The go-ipfix project team welcomes contributions from the community. Before you start working with go-ipfix, please
read our [Developer Certificate of Origin](https://cla.vmware.com/dco). All contributions to this repository must be
signed as described on that page. Your signature certifies that you wrote the patch or have the right to pass it on
as an open-source patch. For more detailed information, refer to [CONTRIBUTING.md](CONTRIBUTING.md).

## License
GO-IPFIX is licensed under the [Apache License, version 2.0](https://github.com/vmware/go-ipfix/blob/master/LICENSE)
