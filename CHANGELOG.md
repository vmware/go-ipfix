# Changelog

All notable changes to this project will be documented in this file.  The format is based on [Keep a
Changelog](https://keepachangelog.com/en/1.0.0/).

## Unreleased
## 0.2.4 11-05-2020
## Changed
- Change reverse information element naming (#68, @zyiou)
## Fixed
- Remove unnecessary testing log (#67, @zyiou)
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
