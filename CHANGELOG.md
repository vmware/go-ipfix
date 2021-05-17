# Changelog

All notable changes to this project will be documented in this file.  The format is based on [Keep a
Changelog](https://keepachangelog.com/en/1.0.0/).

## Unreleased
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
