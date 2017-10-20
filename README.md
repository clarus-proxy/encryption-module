# CLARUS Simple Encryption Module
[![Build Status](https://travis-ci.org/clarus-proxy/encryption-module.svg?branch=master)](https://travis-ci.org/clarus-proxy/encryption-module)

## Description

This is the Simple Encryption Module for the CLARUS Proxy.
The protection of the data is provided by Java's embedded ciphers.
In particular, this module uses a "AES/CBC/PKCS5PADDING" cipher to
protect the data.

## Initializaiton Vector and Key management

The AES cipher implements a symetric encryption schema which requires
both an *Initialization Vector* and a *Secret Key*. 

The security policy specifies the ID of the protected data. This is information
is used by this module in order to find the right *Initialization Vector*
and *Secret Key* in the database. If no record is found, this module is capable
of generating both parameters and store it in a mongo database for further
usage.

The AES Key length is stored in the key sotre. If this configuration is
not available, a default lenght of 128 bits will be used to generate the keys.

The connection data of the mongo Key Store is specified in the file:
`/etc/clarus/clarus-keystore.conf`
which is a JSON-based file with multiple configurations. The lines concerned
with this module are:

* CLARUS_keystore_db_hostname: "localhost"
* CLARUS_keystore_db_port: 27017
* CLARUS_keystore_db_name: "CLARUS"

Please note that this file is required for the correct execution of the module.

## Obtaining the code and compilation

The module depends only on the `dataoperations-api` project, whose code
can be found [here](https://github.com/clarus-proxy/dataoperations-api).
Please refer to its README.md to compile this project.

Once this requirement is met, the Encryption Module can be downloaded and compiled:


`# Get the code`

`git clone git@github.com:clarus-proxy/encryption-module.git`

`# Compile it`

`cd encryption-module/`

`mvn install`

After this procedure, the compiled jar file can be found under `target/dataoperations.encryption-(version)-SNAPSHOT.jar`

Finally, it is required to install the configuraiton file in the machine.
This is done by executing the script `install_conf.sh` as superuser. This is
required since the script will create a folder under `/etc` and copy a file
into it:

`sudo ./install_conf.sh`
