# Changelog

All notable changes to this project will be documented in this file.  The format is based on [Keep a
Changelog](https://keepachangelog.com/en/1.0.0/).

## Unreleased
## 0.16.0 07-08-2025
### Added
- Add new IEs for K8s object UUIDs to Antrea registry. (#433, @antoninbas)
### Changed
- Do not close the UDP connection to the collector if there are errors while sending. (#427, @vlet)
### Fixed
- Remove some unnecessary error logs with typo. (#432, @antoninbas)
## 0.15.0 06-11-2025
### Added
- Support for more TLS config options in Collector and Exporter. (#423, @antoninbas)
- Add curl and jq to ipfix-collector Docker image. (#429, @antoninbas)
### Changed
- Bump Go to 1.24. (#425, @antoninbas)
### Fixed
- Ignore Read error in TCP collector when server is closed. (#428, @antoninbas)
## 0.14.0 03-24-2025
### Fixed
- Fix Record length computation so that IPFIX UDP messages can be sized
  correctly by the buffered exporter. (#417, @antoninbas)
- Fix sequence number incrementing in IPFIX exporter. (#418, @antoninbas)
## 0.13.0 02-19-2025
### Added
- Support configurable decoding mode in reference collector program. (#396, @antoninbas)
- Add Path MTU to Exporter inputs. (#407, @antoninbas)
- Add buffered exporter for IPFIX messages. (#409, @antoninbas)
### Changed
- Improve received stats in collector. (#394, @antoninbas)
- Improve IPFIX header decoding in collector. (#395, @antoninbas)
- Prevent unnecessary memory allocations in WriteIPFIXMsgToBuffer. (#397, @antoninbas)
- Re-use same buffer when receiving messages in TCP collector. (#399, @antoninbas)
- Improve collector program for data sets with multiple records. (#410, @antoninbas)
### Fixed
- Do not embed Record interface into baseRecord. (#398, @antoninbas)
## 0.12.0 01-02-2025
### Added
- Ability to support unknown IEs when decoding template sets. (#380, @antoninbas)
- Add SendDataRecords to IPFIX Exporter to send multiple data records at once. (#391, @antoninbas)
- Support Records as input for AggregationProcess. (#389, @antoninbas)
- Add clusterId IE to Antrea registry. (#379, @antoninbas)
### Changed
- Manage templates per session instead of globally. (#386, @antoninbas)
- Close TCP connection in case of error. (#384, @antoninbas)
- Remove CloseMsgChan method from collector process. (#388, @antoninbas)
- Improve IPFIX Set implementation: add AddRecordV3 method to interface and
  optimize ResetSet to avoid memory allocations. (#390, @antoninbas)
- Delete existing template if a new invalid one is received. (#383, @antoninbas)
- Stop using projects.registry.vmware.com registry for Kafka images. (#373, @antoninbas)
### Fixed
- Fix UDP template expiry in collector process. (#381, @antoninbas)
## 0.11.0 09-13-2024
### Changed
- Bump Go to 1.23. (#365, @antoninbas)
- Add a few log messages to exporter process. (#367, @antoninbas)
- Bump Ubuntu to 24.04 for Docker images. (#369, @antoninbas)
## 0.10.1 09-06-2024
Go module version v0.10.0 has been retracted; it should not be used.
### Fixed
- Restore check for closed TCP connection in exporter process. (#360, @antoninbas)
## 0.10.0 08-30-2024
### Added
- Add more features to the test IPFIX collector web API. (#351, @antoninbas)
### Changed
- Return receive-only channel in the GetMsgChan() method of the collector
  process. (#350, @antoninbas)
- Use recommended default value of 600s for templateRefreshTimeout. (#353,
  @antoninbas)
- Stop referencing the VMware Harbor registry for ipfix-collector. (#347,
  @antoninbas)
### Fixed
- Fix how decoding errors are handled for UDP clients in collector
  process. (#352, @antoninbas)
- Fix how collector connections are closed in exporter process. (#354, @antoninbas)
## 0.9.0 02-15-2024
### Added
- Add EgressNodeName field to the Antrea registry. (#343, @Atish-iaf)
## 0.8.2 12-19-2023
### Changed
- Improve IPFIX collector. (#338, @yuntanghsu)
## 0.8.1 12-07-2023
### Added
- Added new Go Benchmarks. (#329, @antoninbas)
### Changed
- Improve memory performance of collector. (#330 #331, @antoninbas)
- Rename l7ProtocolName to appProtocolName. (#333, @tushartathgur)
- Updated aggregation logic for httpVals field. (#334, @tushartathgur)
## 0.8.0 10-02-2023
### Added
- Add L7 visibility fields. (#315, @tushartathgur)
### Changed
- Change datatype of flowEndSecondsFromSourceNode and
  flowEndSecondsFromDestinationNode. (#320, @tushartathgur)
- Improve handling of string IEs. (#322, @antoninbas)
- Avoid error logs in BenchmarkMultipleExportersToCollector. (#323,
  @antoninbas)
- Improve integration tests. (#325, @antoninbas)
### Fixed
- Fix aggregation bug that throughput common fields should be only updated
  when the receiving record is the latest. (#324, @antoninbas)
## 0.7.0 09-21-2023
### Changed
- Upgrade Go to v1.21, as Go v1.19 is no longer maintained. (#317, @antoninbas)
- Replace github.com/golang/mock with go.uber.org/mock, as
  github.com/golang/mock is no longer maintained. (#316, @antoninbas)
### Fixed
- Fix collector klog flag not supported error by adding registration of the
  flag. (#311, @heanlan)
## 0.6.2 06-07-2023
### Added
- Add fields for Egress information support. (#308, @dreamtalen)
## 0.6.1 05-17-2023
### Changed
- Increase log verbosity when skipping aggregation. (#303, @heanlan)
## 0.6.0 01-09-2023
### Changed
- Upgrade Go to v1.19. Upgrade Go modules to their latest version.
  Upgrade Antrea base image to ubuntu 22.04. (#293, @antoninbas)
- Refactor TLS client config for exporter. (#294, @antoninbas)
## 0.5.13 12-05-2022
### Added
- Add APIs for custom registries. (#288, @praveingk)
### Changed
- Renew fake cert for tests. (#290, @yanjunz97)
## 0.5.12 02-23-2022
### Changed
- Fix the throughput burst issue. (#278, @yanjunz97)
## 0.5.11 12-10-2021
### Added
- Add throughput calculation into aggregation process. (#270, @heanlan)
## 0.5.10 11-05-2021
### Changed
- Update GetRecords in AggregationProcess to return map format records. (#271, @yanjunz97)
## 0.5.9 10-18-2021
### Added
- Add GetName and GetDataType method to infoElementWithValue. (#259, @zyiou)
- Add GetRecords method to AggregationProcess. (#261, @yanjunz97)
### Changed
- Remove UDP message checks. (#241, @srikartati)
- Modify flow visibility methods and return type. (#262, @zyiou)
## 0.5.8 09-17-2021
### Added
- Add visibility of collector ingest rate and aggregator connection count. (#253, @zyiou)
### Changed
- Remove connection mutex for exporting process. (#248, @antoninbas)
- Modify the basic structure NewInfoElementWithValue to reduce memory consumption. (#252, @stati)
- Remove duplicated code in ie_value.go. (#254, @stati)
## 0.5.7 08-12-2021
### Fixed
- Fix unnecessary allocations in the code related to iterating through
  list of elements and casting to interface pointer. (#246 @stati)
## 0.5.6 08-11-2021
### Added
- Add support for sending JSON record. (#237, @zyiou)
- Add new method for adding record with extra elements. (#243, @stati)
### Changes
- Skip sending template record for JSON records. (#242, @zyiou)
### Fixed
- Fix image tag in kafka flow collector manifest. (#233, @stati)
- Fix collector close issue and add perf test for multiple exporters to collector. (#236, @zyiou)
- Performance fix for collecting and intermediate process. (#239, @stati)
- Fix partial buffer read issues on TCP connection. (#240, @stati)
## 0.5.5 07-26-2021
### Added
- Add convertor interface input into Kafka producer. (#223, @stati)
- Add consumer, broker and related deployment yaml for consuming records from Kafka producer. (#214, @zyiou)
### Changed
- Cleanup unnecessary producer files. (#228, @stati)
- Improve Kafka consumer application by adding retry mechanism for consumer initialization. (#230, @stati)
- Change Docker version of images used in kafka server deployment yaml. (#224, @zyiou)
### Fixed
- Fix bug that after stopping the TCP collector process, new connections should not be established. (#227, @stati)
- Fix bug that after stopping the collector process, no write should be processed on existing connections. (#229, @zyiou)
## 0.5.4 07-06-2021
### Changed
- Clear original export fields in the aggregation process. (#220, @stati)
- Move bytes.buffer to []byte for set and message. Optimize the encoding of record, set and message entities. (#215, @zyiou)
## 0.5.3 06-17-2021
### Added
- Add Pod Labels to the Antrea registry. (#203, @dreamtalen)
- Add Kafka TLS support to the Kafka Producer. (#178, @stati)
- Add more methods to the Kafka Producer. (#210, @stati)
- Add `AreExternalFieldsFilled` metadata field for AggregationFlowRecord. (#211, @dreamtalen)
- Add more metadata to the aggregated flow record. (#216, @stati)
### Changed
- Modify record entity and encoding/decoding methods to use byte datatype directly. (#207, @stati)
- Remove element map from the record. (#206, @zyiou)
- Modify the proto format of Kafka flow message. (#208, @stati)
### Fixed
- Remove unnecessary allocations in record entity code. (#200, @stati)
- Optimize encoding code when adding element to data record and decrease memory allocations. (#204, @stati)
- Fix the aggregation process set/get methods by modifying the aggregate record
  map. (#212, @zyiou)
- Fix the buffer management in the Collection Process. (#213, @stati)   
## 0.5.2 05-17-2021
### Added
- Add support for isMetadataFilled for aggregation process (#196 @zyiou)
### Changed
- Remove the portion of updating the version of Helm Chart in generating manifest process, 
and fix the issue that manifest of ipfix-collector cannot be uploaded to release assets. 
(#194 @heanlan)
- Update some package versions to keep consistent with Antrea go.mod (#195 @zyiou)
## 0.5.1 05-13-2021
### Added
- Create K8s deployment yaml to deploy ipfix-collector and add instructions on 
deploying the latest go-ipfix collector . (#159, #182, @heanlan)
- Add aggregation process support for deny connections tracking. (#175, #183, @zyiou)
### Changed
- Modify aggregation process to maintain records in a heap based on active and 
inactive expiry timeouts. (#185, @stati)
- Modify rule priority types in Antrea registry. (#184, #189, @heanlan)
- Delete unrequired method of deleting record from record map witout lock. (#181, @stati)
- Modify network policy related fields in Antrea registry. (#179, @zyiou)
- Move klog to klog/v2. (#187, @zyiou)
### Fixed
- Remove codecov token from script. (#176, @zyiou)
## 0.5.0 04-16-2021
Includes all the bug fixes from [0.4.1](https://github.com/vmware/go-ipfix/blob/main/CHANGELOG.md#041-12-09-2020),
[0.4.2](https://github.com/vmware/go-ipfix/blob/main/CHANGELOG.md#042-12-15-2020),
[0.4.3](https://github.com/vmware/go-ipfix/blob/main/CHANGELOG.md#043-02-04-2021),
[0.4.4](https://github.com/vmware/go-ipfix/blob/main/CHANGELOG.md#044-02-10-2021),
[0.4.5](https://github.com/vmware/go-ipfix/blob/main/CHANGELOG.md#045-02-17-2021),
[0.4.6](https://github.com/vmware/go-ipfix/blob/main/CHANGELOG.md#046-02-25-2021),
[0.4.7](https://github.com/vmware/go-ipfix/blob/main/CHANGELOG.md#047-03-15-2021),
and [0.4.8](https://github.com/vmware/go-ipfix/blob/main/CHANGELOG.md#048-03-19-2021).
### Added
- Added Kafka Producer that is initialized given the address of Kafka broker
  system. It gathers the IPFIX messages from the collecting process
  and turns them into Kafka messages. (#88, @stati)
- Demonstrate the ability to support multiple proto schemas in Kafka Producer. (#99, @stati)
- Add new fields to Antrea Registry for enhancing network policy info and adding
  all the tcp states of the connection. (#165, @zyiou)
### Changed
- Change the name of master branch to main. (#144, @zyiou)
- Change the names of Flow Types. (#171, @zyiou)
- Enhance the debug logs with useful info. (#170, @zyiou)
### Fixed
- Fix the default expiration time of TLS certificates in tests by increasing it
  from one month to one year. (#127, @zyiou)
- Fix the code in pkg/producer when cherrypicking commits from v0.4.5 release. (#143, @stati)
- Fix the branch name in go-ipfix collector image workflow. (#160, @stati)
- Fix an issue of cleaning up slice in the IPFIX set Reset method. (#163, @stati)
## 0.4.8 03-19-2021
### Changed
- Move from klog to klog/v2. (#155, @zyiou)
## 0.4.7 03-15-2021
### Added
- Added new field flowType in Antrea registry. (#148, @stati)
### Changed
- Modify aggregation process to consume flow end reason. (#150, @stati)
- Support consuming tcpState in aggregation process. (#151, @zyiou)
## 0.4.6 02-25-2021
### Added
- Added tcpState information element for Antrea registry. (#145, @zyiou)
## 0.4.5 02-17-2021
### Added
- Added new methods in Set interface to reduce set allocations for user. (#139,
  @stati)
### Changed
- Simplified the network address consumption in exporter and collector processes.
  (#140, @stati)
### Fixed
- Fix standalone collector issue. (#136, @zyiou)
## 0.4.4 02-10-2021
### Changed
- Modify address resolution method in exporter and collector. (#134, @zyiou)
## 0.4.3 02-04-2021
### Changed
- Modify the input of Exporting and Collecting process. (#129, @stati)
- Improve testing coverage on IPv6. (#130, @zyiou)
- Add log information for debugging. (#132, @zyiou)
### Fixed
- Fix slicing problem on TCP collector. (#126, @zyiou)
- Validate data records in aggregation process. (#125, @stati)
- Fix testing issues: update TLS certificate in tests (#128, @zyiou), fix flaky tests problem and golangci-lint error (#114, @zyiou).
## 0.4.2 12-15-2020
### Added
- Exposed message size limit in exporter. (#115, @zyiou)
- Added a function in aggregation process to delete flow key from flowKeyRecord
  map without a lock. (#113, @stati)
## 0.4.1 12-09-2020
### Changed
- Expose fields in AggregateElements and add integration tests. (#104, @zyiou)
## 0.4.0 12-08-2020
Includes all the bug fixes from [0.3.1](https://github.com/vmware/go-ipfix/blob/main/CHANGELOG.md#031-11-21-2020).
### Added
- Supported message size check for UDP transport. (#92, @stati)
- Added stats support in aggregation process. (#99, @stati)
- Added security support (TLS and DTLS) and client authentication for TLS. (#57, #101, @zyiou)
- Added issue templates. (#94, @stati)
### Changed
- Modified correlating process in aggregation process. (#99, @stati)
### Fixed
- Fixed the unit tests with -race of pkg/exporter (#91, @stati), pkg/collector and pkg/intermediate(#93, @zyiou)
## 0.3.1 11-21-2020
### Changed
- Simplified standalone collector code. (#83, @stati)
- Improved intermediate process. (#81, @zyiou)
- Exposed collecting process and aggregation process as public struct. (#84, @zyiou)
### Fixed
- Modified versions of some packages in go.mod to keep it consistent with Antrea, the main user of go-ipfix library. (#82, @zyiou)
## 0.3.0 11-06-2020
Includes all the bug fixes from [0.2.1](https://github.com/vmware/go-ipfix/blob/main/CHANGELOG.md#021-09-23-2020),
[0.2.2](https://github.com/vmware/go-ipfix/blob/main/CHANGELOG.md#022-09-25-2020),
[0.2.3](https://github.com/vmware/go-ipfix/blob/master/CHANGELOG.md#023-10-30-2020),
and [0.2.4](https://github.com/vmware/go-ipfix/blob/master/CHANGELOG.md#024-11-05-2020).
### Added
- Added the intermediate process feature for the implementation of IPFIX mediator.
(#52, @zyiou)
- Added standalone IPFIX collector. (#71, @stati)
- Added github workflow for unit tests and code generation. (#39, #44, @stati)
- Added code coverage for unit tests and integration tests. (#52, #56, @zyiou)
- Added encoding and decoding support for IPv6 addresses. (#64 @stati)
### Changed
- Refactored and changed the entites abstraction, specifically sets and records.
(#49, @zyiou)
- Refactored encoding support for IPFIX exporter. (#20, @zyiou)
- Changed the InfoElement data type to length association from list to the map.
(#58, @shihhaoli) 
### Fixed
- Added locks for clients map in the collector process. (#46, @zyiou)
## 0.2.4 11-05-2020
### Changed
- Change reverse information element naming. (#68, @zyiou)
### Fixed
- Remove unnecessary testing log. (#67, @zyiou)
## 0.2.3 10-30-2020
### Added
- Support IPv6 cluster IP field in Antrea repo. (#63, @srikartati)
### Changed
- Change `DateTimeSeconds` type for information elements to `uint32` following RFC7011. (#59, @zyiou)
- Change PEN number for Antrea to '56506' (assigned by IANA). (#60, @zyiou)
## 0.2.2 09-25-2020
### Changed
- Change reverse information element and const naming. (#45, @zyiou)
### Fixed
- Fix collector concurrent map writes failure in unit tests. (#42, @zyiou)
## 0.2.1 09-23-2020
### Changed
- Revert klog version from 2.0 to 1.0. (#33, @zyiou)
## 0.2.0 09-18-2020
### Added 
- IPFIX collector support based on RFC 7011, which can stream and decode the IPFIX packets.
(#13, #21, @zyiou)
- Add new fields related to the Kubernetes network policy to the Antrea registry.
(#23 @srikartati)
### Changed
- Global registry support that initializes both IANA and Antrea registries. (#24, @zyiou)
- Update the klog version to 2.0. (#16, @srikartati)
## 0.1.0 08-13-2020
### Added
- IPFIX exporter support based on RFC 7011.
- Support for IANA and Antrea Registries.
