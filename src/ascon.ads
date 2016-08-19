-- Ascon

-- an Ada implementation of the Ascon Authenticated Encryption Algorithm
-- created by Christoph Dobraunig, Maria Eichlseder, Florian Mendel and
-- Martin Schläffer

-- Copyright (c) 2016, James Humphry - see LICENSE file for details

pragma Restrictions(No_Implementation_Attributes,
                    No_Implementation_Units,
                    No_Obsolescent_Features);

with System.Storage_Elements;

private with Interfaces;

with Ascon_Definitions;
use Ascon_Definitions;

generic
   a_rounds : Round_Count := 12;
   b_rounds : Round_Count := 6;
   rate : Rate_Bits := 64;
package Ascon
with SPARK_Mode => On
is

   -- These constants are the same for all variants of Ascon
   key_bits : constant := 128;
   nonce_bits : constant := 128;
   tag_bits : constant := 128;

   use System.Storage_Elements;

   subtype Key_Type is Storage_Array(0..Storage_Offset(key_bits/8)-1);
   -- A Storage_Array subtype containing key material.

   subtype Nonce_Type is Storage_Array(0..Storage_Offset(nonce_bits/8)-1);
   -- A Storage_Array subtype containing the nonce material. This must be unique
   -- per-message.

   subtype Tag_Type is Storage_Array(0..Storage_Offset(tag_bits/8)-1);
   -- A Storage_Array subtype containing an authentication tag.

   Null_Storage_Array : constant Storage_Array(1..0) := (others => 0);
   -- A null Storage_Array that can be passed to AEADEnc and AEADDec if one
   -- of the header, message or trailer parameters is not required.

   -- High-level API for Ascon

   procedure AEADEnc(K : in Key_Type;
                     N : in Nonce_Type;
                     A : in Storage_Array;
                     M : in Storage_Array;
                     C : out Storage_Array;
                     T : out Tag_Type)
     with Pre => (C'Length = M'Length and
                    Valid_Storage_Array_Parameter(A'Length, A'Last) and
                      Valid_Storage_Array_Parameter(M'Length, M'Last) and
                      Valid_Storage_Array_Parameter(C'Length, C'Last));
   -- AEADEnc carries out an authenticated encryption
   -- K : key data
   -- N : nonce
   -- A : optional (unencrypted) header
   -- M : optional message to be encrypted
   -- C : encrypted version of M
   -- T : authentication tag for (A,M,Z)

   procedure AEADDec(K : in Key_Type;
                     N : in Nonce_Type;
                     A : in Storage_Array;
                     C : in Storage_Array;
                     T : in Tag_Type;
                     M : out Storage_Array;
                     Valid : out Boolean)
     with Pre => (M'Length = C'Length and
                    Valid_Storage_Array_Parameter(A'Length, A'Last) and
                      Valid_Storage_Array_Parameter(C'Length, C'Last) and
                      Valid_Storage_Array_Parameter(M'Length, M'Last)),
     Post => (Valid or (for all I in M'Range => M(I) = 0));
   -- AEADEnc carries out an authenticated decryption
   -- K : key data
   -- N : nonce
   -- A : optional (unencrypted) header
   -- C : optional ciphertext to be decrypted
   -- T : authentication tag
   -- M : contains the decrypted C or zero if the input does not authenticate
   -- Valid : indicates if the input authenticates correctly

   type State(<>) is private;
   -- This type declaration makes the Ascon.Access_Internals package easier to
   -- write. It is not intended for normal use.

   function Valid_Storage_Array_Parameter(Length : in Storage_Offset;
                                          Last : in Storage_Offset)
                                          return Boolean;
   -- This function simplifies the preconditions

private

   function Valid_Storage_Array_Parameter(Length : in Storage_Offset;
                                          Last : in Storage_Offset)
                                          return Boolean is
      (Length < Storage_Offset'Last and
         Last < Storage_Offset'Last - Storage_Offset(rate/8));

   subtype Word is Interfaces.Unsigned_64;

   type State is array (Integer range 0..4) of Word;

   -- Low-level API for Ascon. These routines can be accessed by instantiating
   -- the Ascon.Access_Internals child package

   function Make_State return State;

   function Initialise (Key : in Key_Type; Nonce : in Nonce_Type) return State;

   procedure Absorb (S : in out State; X : in Storage_Array)
     with Pre=> (Valid_Storage_Array_Parameter(X'Length, X'Last));

   procedure Encrypt (S : in out State;
                      M : in Storage_Array;
                      C : out Storage_Array)
     with Pre => (C'Length = M'Length and
                    Valid_Storage_Array_Parameter(M'Length, M'Last) and
                      Valid_Storage_Array_Parameter(C'Length, C'Last));

   procedure Decrypt (S : in out State;
                      C : in Storage_Array;
                      M : out Storage_Array)
     with Pre => (C'Length = M'Length and
                    Valid_Storage_Array_Parameter(C'Length, C'Last) and
                      Valid_Storage_Array_Parameter(M'Length, M'Last));

   procedure Finalise (S : in out State; Key : in Key_Type; Tag : out Tag_Type);

   -- These compile-time checks test requirements that cannot be expressed
   -- in the generic formal parameters. Currently compile-time checks are
   -- not supported in GNATprove so the related warnings are suppressed.
   pragma Warnings (GNATprove, Off, "Compile_Time_Error");
   pragma Compile_Time_Error (key_bits /= tag_bits,
                              "The tag has to be the same length as the key");
   pragma Compile_Time_Error (rate mod 64 /= 0,
                              "The rate is not a multiple of 64 bits");
   pragma Compile_Time_Error (System.Storage_Elements.Storage_Element'Size /= 8,
                              "This implementation of Ascon cannot work " &
                                "with Storage_Element'Size /= 8");
   pragma Warnings (GNATprove, On, "Compile_Time_Error");

end Ascon;
