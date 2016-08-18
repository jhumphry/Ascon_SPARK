-- Ascon.Load_Store

-- Functions to load and store 64-bit words from Storage_Array in Big Endian
-- format. Currently these are not optimised for the case where the machine
-- itself is BE or has dedicated assembly instructions that can perform the
-- conversion. Some compilers may have a peephole optimisation for these
-- routines.

-- Copyright (c) 2016, James Humphry - see LICENSE file for details

-- Note that all the Unsigned_xx types count as Implementation_Identifiers
pragma Restrictions(No_Implementation_Attributes,
                    No_Implementation_Units,
                    No_Obsolescent_Features);

with System.Storage_Elements;
use System.Storage_Elements;

with Interfaces;
use Interfaces;

private package Ascon.Load_Store
  with SPARK_Mode => On is

   subtype E is Storage_Element;

   function Storage_Array_To_Unsigned_64 (S : in Storage_Array)
                                          return Unsigned_64 is
     (Shift_Left(Unsigned_64(S(S'First)), 56) or
          Shift_Left(Unsigned_64(S(S'First + 1)), 48) or
          Shift_Left(Unsigned_64(S(S'First + 2)), 40) or
          Shift_Left(Unsigned_64(S(S'First + 3)), 32) or
          Shift_Left(Unsigned_64(S(S'First + 4)), 24) or
          Shift_Left(Unsigned_64(S(S'First + 5)), 16) or
          Shift_Left(Unsigned_64(S(S'First + 6)), 8) or
          Unsigned_64(S(S'First + 7)))
   with Inline, Pre => (S'Length = 8);

   function Unsigned_64_To_Storage_Array (W : in Unsigned_64)
                                          return Storage_Array is
     (Storage_Array'(E(Shift_Right(W, 56) mod 16#100#),
                     E(Shift_Right(W, 48) mod 16#100#),
                     E(Shift_Right(W, 40) mod 16#100#),
                     E(Shift_Right(W, 32) mod 16#100#),
                     E(Shift_Right(W, 24) mod 16#100#),
                     E(Shift_Right(W, 16) mod 16#100#),
                     E(Shift_Right(W, 8) mod 16#100#),
                     E(W mod 16#100#)))
     with Inline, Post => (Unsigned_64_To_Storage_Array'Result'Length = 8);

end Ascon.Load_Store;
