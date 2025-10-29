# Remote HSM prototype implementation

This folder includes code for developing and testing a protocol for providing remote resources and functions for an EU wallet implementation.

Specifications:

- [Remote PAKE protected Services Operations Protocol (RPS-OPS)](secure-channel-commons/docs/rps-ops%20protocol.md)
- [Common service types for RPS-Ops](secure-channel-commons/docs/common-rps-ops-service-types.md)

## Demo

To build and run a demo using Docker compose, run:

> make demo

To just build the project and the docker images, run:

> make build

To restart or just start the demo if the project and images are already built, run

> make start

The `make demo`, and `make start` commands will also automatically fire up a browser window at the login page.
