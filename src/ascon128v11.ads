-- Ascon128v11

-- an instantiation of the Ascon-128 (v 1.1) variant of the Ascon Authenticated
-- Encryption Algorithm created by Christoph Dobraunig, Maria Eichlseder,
-- Florian Mendel and Martin Schläffer.

-- Copyright (c) 2016-2018, James Humphry - see LICENSE file for details

pragma SPARK_Mode(On);

with Ascon;

package Ascon128v11 is new Ascon(a_rounds => 12,
                                 b_rounds => 6,
                                 b_round_constants_offset => 0,
                                 rate     => 64);
