# GO-IPFIX

## Overview
go-ipfix is an IPFIX library that can be used to implement an IPFIX exporter, which can export flow records. go-ipfix follows RFC 7011 and other referenced RFCs. Specifically, this release mainly implements the IPFIX exporting process feature and provides the required IPFIX entities such as information elements, records, sets, message, etc. In addition, this library supports loading IPFIX information elements from IANA registry, reverse information elements (enterprise ID: 29305), and information elements from the private Antrea registry (enterprise ID: 56506) to support [Project Antrea](https://antrea.io/).

## Try it out
This IPFIX library can be used to build an exporter. Please check out the [exporter tests](https://github.com/vmware/go-ipfix/blob/master/pkg/exporter/process_test.go) to get an idea on how to build exporter on top of TCP and UDP transport protocols given a IPFIX collector.

## Build Registry
To build the registry from [IANA registry](https://www.iana.org/assignments/ipfix/ipfix.xhtml) or [Antrea registry](pkg/registry/registry_antrea.csv), run following commands:
```
go run pkg/registry/build_registry/build_registry.go [REGISTRY_NAME]
# REGISTRY_NAME: "Antrea", "IANA", ""(build both registries)
```
Above will generate two files: `pkg/registry/registry_antrea.go` and/or `pkg/registry/registry_IANA.go` to enable local registry loading functions.

To account for changes in either registry, please make sure to re-execute  `build_registry.go` to regenerate corresponding go files.
## Contributing

The go-ipfix project team welcomes contributions from the community. If you wish to contribute code and you have not signed our contributor license agreement (CLA), our bot will update the issue when you open a Pull Request. For any questions about the CLA process, please refer to our [FAQ](https://cla.vmware.com/faq). For more detailed information, refer to [CONTRIBUTING.md](CONTRIBUTING.md).

## License
GO-IPFIX is licensed under the [Apache License, version 2.0](https://github.com/vmware/go-ipfix/blob/master/LICENSE)
