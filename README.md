# Ascon_SPARK

## Introduction

This is an Ada 2012 / SPARK 2014 project that implements the [Ascon](http://ascon.iaik.tugraz.at) 
Authenticated Encryption with Additional Data Algorithm, the [NIST Lightweight 
Cryptography](https://csrc.nist.gov/projects/lightweight-cryptography) standard. It was also 
selected as a finalist in the [CAESAR](http://competitions.cr.yp.to/caesar.html) competition. Ascon 
was designed by Christoph Dobraunig, Maria Eichlseder, Florian Mendel and Martin Schläffer.

This project implements both of the recommended Ascon variants in v1.1 and v1.2 of the
specification. A single generic package can be instantiated with the relevant parameters. There are
a few additional requirements on the target system which should not be a problem - for example it
must support operations on the `Interfaces.Unsigned_64` type.

This project is free software (using the ISC permissive licence) and is provided with no
warranties, as set out in the file `LICENSE`.

## Overview of the packages

The main generic package is `Ascon` which implements the high-level API. This consists of just two
procedures, `AEADEnc` and `AEADDec`. The former procedure takes in a key `K`, a 'nonce' `N`,
optional associated data `A` (not encrypted) and the optional message to be encrypted `M` and
returns the encrypted cipher-text `C` and the authentication tag `T`. The latter procedure performs
the decryption and returns the decoded message and a Boolean that indicates whether the message was
valid. If either of the  `A` or `M` parameters are not used, the constant `Null_Storage_Array` can
be passed to the routines.

Packages `Ascon128v11` and `Ascon128av11` are instantiations of the generic package with the
parameters recommended in version 1.1 of the specification. Packages `Ascon128v12` and
`Ascon128av12` are instantiations of the generic package with the parameters recommended in version
1.2 of the specification.

`Ascon_Definitions` defines some constrained types used in the generic formal parameters and
`Ascon.Load_Store` contains functions that convert between standard word sizes and `Storage_Array`
in Little-Endian format.

`Ascon.Access_Internals` allows access to the lower-level API which allows you to follow the
internal state of the cipher as it processes some data. `Ascon.Utils` contains useful helper
functions for printing out `Storage_Array` and `State` types.

## Examples

Three example programs are included. `ascon128_demo` is a simple example of using the high-level
API and demonstrates successful encryption and decryption, and also unsuccessful decryption if the
tag is altered.

`ascon_test_vectors` uses the lower-level API to print the trace of a sample encryption for both of
the suggested variants of Ascon128. These can be compared with the output of the reference C code
provided by the Ascon designers. In order to get a more detailed trace from the reference C code,
the line `//#define PRINTSTATE` in `ascon.c` should be un-commented.

`ascon_check_padding` checks that authenticated encryption and decryption works correctly when the
lengths of the associated data and message vary. This is primarily to check for any bugs in the
implementation of the padding.

## Status of SPARK proof

As the code is written in the SPARK 2014 subset of Ada 2012, it is possible to formally verify
properties of the code and eliminate the possibility of run-time exceptions.

The GPL SPARK prover `gnatprove` shipped with GNAT Community 2021 from [AdaCore](https://www.adacore.com/community)
is used for this project. It is also able to prove the absence of all potential sources of run-time
exceptions without manual intervention. This includes checking for the non-initialization of arrays,
which was not possible before GNAT Community 2020. It also proves that `AEADDec` will not return any
decrypted data if the tag verification failed.

## Project files

Three project files for use with `GPRBuild` are provided. `ascon_spark.gpr` builds the ASCON code
as a static library. It takes two optional parameters:

- `mode` can be set to `debug` (the default) or `optimise`/`optimize`. This sets appropriate
compiler flags.

- `load_store` can only be set to `explicit` (the default). This setting is reserved for possible
future accelerated big-/little-endian conversions.

The project file `ascon_spark_external.gpr` covers the same code, but does not trigger rebuilds of
the library. `ascon_spark_examples.gpr` builds the example code.

## Using GNATprove for verification

To verify the code, GNATprove can be invoked via the GnatStudio IDE. Alternatively the following command
line can be used:

- SPARK from GNAT Community 2021

    gnatprove -P ascon_spark.gpr -j0 -Xload_store=explicit -Xmode=debug --level=0

Add `--report=all` if you want to see the checks that are proved as well.

