-- Test_Input_Lengths

-- Ensure that associated data of different length are accepted and messages
-- of different lengths correctly encrypt and decrypt. This is largely aimed
-- at checking the implementation of padding.

-- Copyright (c) 2016, James Humphry - see LICENSE file for details

with Ascon;

with System.Storage_Elements;
use System.Storage_Elements;

generic
   with package Ascon_Package is new Ascon(<>);
   Max_Size : System.Storage_Elements.Storage_Offset := 2000;
   Other_Size : System.Storage_Elements.Storage_Offset := 73;
procedure Test_Input_Lengths;
