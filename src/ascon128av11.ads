-- Ascon128av11

-- an instantiation of the Ascon-128a (v 1.1) variant of the Ascon Authenticated
-- Encryption Algorithm created by Christoph Dobraunig, Maria Eichlseder,
-- Florian Mendel and Martin Schläffer.

-- Copyright (c) 2016, James Humphry - see LICENSE file for details

pragma SPARK_Mode(On);

with Ascon;

package Ascon128av11 is new Ascon(a_rounds => 12,
                                  b_rounds => 8,
                                  rate     => 128);
