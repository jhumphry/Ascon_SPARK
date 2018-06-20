-- Ascon128v12

-- an instantiation of the Ascon-128 (v 1.2) variant of the Ascon Authenticated
-- Encryption Algorithm created by Christoph Dobraunig, Maria Eichlseder,
-- Florian Mendel and Martin Schläffer.

-- Copyright (c) 2018, James Humphry - see LICENSE file for details

pragma SPARK_Mode(On);

with Ascon;

package Ascon128v12 is new Ascon(a_rounds => 12,
                                 b_rounds => 6,
                                 b_round_constants_offset => 6,
                                 rate     => 64);
