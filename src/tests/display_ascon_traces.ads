-- Display_Ascon_Traces

-- A utility to display traces of the encryption process for the test vectors
-- in the demo of the reference implementations

-- Copyright (c) 2016, James Humphry - see LICENSE file for details

with System.Storage_Elements;

with Ascon;

generic
     with package Ascon_Package is new Ascon(<>);
procedure Display_Ascon_Traces;
