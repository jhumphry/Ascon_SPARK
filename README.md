# Ascon_SPARK

## Introduction

This is an Ada 2012 / SPARK 2014 project that implements the [Ascon](http://ascon.iaik.tugraz.at)
Authenticated Encryption with Additional Data Algorithm, a finalist in the
[CAESAR](http://competitions.cr.yp.to/caesar.html) competition. Ascon was designed by Christoph
Dobraunig, Maria Eichlseder, Florian Mendel and Martin Schläffer.

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

The GPL SPARK prover `gnatprove` shipped with SPARK GPL 2016, SPARK Discovery GPL 2017 or GNAT
Community 2018 from [AdaCore](https://www.adacore.com/community) is used for this project. It is
not able to prove the complete initialisation of output arrays where they are written to one
element at a time (common in this code) rather than as a single aggregate expression. It is able to
prove the absence of all other potential sources of run-time exceptions, which amount to 97% of the
checks, without manual intervention. It also proves that `AEADDec` will not return any decrypted
data if the tag verification failed.

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

To verify the code, GNATprove can be invoked via the GPS IDE. Alternatively the following command
line can be used:

- SPARK GPL 2016

    gnatprove -P ascon_spark.gpr -U -j0 --level=1 --proof=progressive --warnings=continue

- SPARK Discovery GPL 2017

    gnatprove -P ascon_spark.gpr -j0 -Xload_store=explicit -Xmode=debug --level=2

- SPARK from GNAT Community 2018

    gnatprove -P ascon_spark.gpr -j0 -Xload_store=explicit -Xmode=debug --level=0

Add `--report=all` if you want to see the checks that are proved as well.

For SPARK Discovery GPL 2017 the built-in SMT solver, Alt-Ergo, may not be able to prove all of the
VC. Add the alternative Z3 and/or CVC4 provers as explained in the SPARK user guide. The 2016 and
2018 GPL releases of SPARK contain these provers out-of-the-box.
