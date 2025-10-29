#!/usr/bin/env bash

# Build script that builds all artifacts and docker images.

mvn clean install
cd remote-hsm-bff || exit
docker build -f Dockerfile-demo -t rhsm-bff .
cd ../remote-hsm-client || exit
docker build -f Dockerfile-demo -t rhsm-client .
cd ../remote-hsm-hsmserver || exit
docker build -f Dockerfile-softhsm -t rhsm-hsm .
cd ..

#docker compose up
