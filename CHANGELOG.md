# Changelog

All notable changes to this project will be documented in this file.  The format is based on [Keep a
Changelog](https://keepachangelog.com/en/1.0.0/).

## Unreleased
## 0.3.2 12-14-2020
## Added
- Added a function in aggregation process to delete flow key from flowKeyRecord
  map without a lock. (#110, @stati)
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
