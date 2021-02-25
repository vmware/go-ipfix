# Changelog

All notable changes to this project will be documented in this file.  The format is based on [Keep a
Changelog](https://keepachangelog.com/en/1.0.0/).

## Unreleased
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
Includes all the bug fixes from [0.3.1](https://github.com/vmware/go-ipfix/blob/master/CHANGELOG.md#031-11-21-2020).
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
Includes all the bug fixes from [0.2.1](https://github.com/vmware/go-ipfix/blob/master/CHANGELOG.md#021-09-23-2020),
[0.2.2](https://github.com/vmware/go-ipfix/blob/master/CHANGELOG.md#022-09-25-2020),
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
