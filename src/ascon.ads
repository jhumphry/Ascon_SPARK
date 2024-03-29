-- Ascon

-- an Ada / SPARK implementation of the Ascon Authenticated Encryption Algorithm
-- created by Christoph Dobraunig, Maria Eichlseder, Florian Mendel and
-- Martin Schläffer

-- Copyright (c) 2016-2018, James Humphry - see LICENSE file for details

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
   b_round_constants_offset : Round_Offset := 6;
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
   -- A null Storage_Array that can be passed to AEADEnc and AEADDec if one of
   -- the associated data or message parameters is not required.

   -- High-level API for Ascon

   procedure AEADEnc(K : in Key_Type;
                     N : in Nonce_Type;
                     A : in Storage_Array;
                     M : in Storage_Array;
                     C : out Storage_Array;
                     T : out Tag_Type)
     with Pre => (
                    (Valid_Storage_Array_Parameter(A) and
                      Valid_Storage_Array_Parameter(M) and
                         Valid_Storage_Array_Parameter(C'First, C'Last))
                      and then C'Length = M'Length
                    );
   -- AEADEnc carries out an authenticated encryption
   -- K : key data
   -- N : nonce
   -- A : optional (unencrypted) associated data
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
     with Pre => (
                    (Valid_Storage_Array_Parameter(A) and
                      Valid_Storage_Array_Parameter(C) and
                         Valid_Storage_Array_Parameter(M'First, M'Last))
                 and then M'Length = C'Length
                 ),
     Post => (Valid or (for all I in M'Range => M(I) = 0));
   -- AEADEnc carries out an authenticated decryption
   -- K : key data
   -- N : nonce
   -- A : optional (unencrypted) associated data
   -- C : optional ciphertext to be decrypted
   -- T : authentication tag
   -- M : contains the decrypted C or zero if the input does not authenticate
   -- Valid : indicates if the input authenticates correctly

   type State is private;
   -- This type declaration makes the Ascon.Access_Internals package easier to
   -- write. It is not intended for normal use.

   function Valid_Storage_Array_Parameter(X : in Storage_Array)
                                          return Boolean
     with Ghost;
   -- This ghost function simplifies the preconditions

   function Valid_Storage_Array_Parameter(First : in Storage_Offset;
                                          Last : in Storage_Offset)
                                          return Boolean
     with Ghost;
   -- This ghost function simplifies the preconditions

private

   function Valid_Storage_Array_Parameter(X : in Storage_Array)
                                          return Boolean is
     (
      if X'First <= 0 then
        ((Long_Long_Integer (X'Last) < Long_Long_Integer'Last +
              Long_Long_Integer (X'First))
         and then
         X'Last < Storage_Offset'Last - Storage_Offset(rate/8))
      else
         X'Last < Storage_Offset'Last - Storage_Offset(rate/8)
   );

   function Valid_Storage_Array_Parameter(First : in Storage_Offset;
                                          Last : in Storage_Offset)
                                          return Boolean is
     (
      if First <= 0 then
        ((Long_Long_Integer (Last) < Long_Long_Integer'Last +
              Long_Long_Integer (First))
         and then
         Last < Storage_Offset'Last - Storage_Offset(rate/8))
      else
         Last < Storage_Offset'Last - Storage_Offset(rate/8)
   );

   subtype Word is Interfaces.Unsigned_64;

   type State is array (Integer range 0..4) of Word;

   -- Low-level API for Ascon. These routines can be accessed by instantiating
   -- the Ascon.Access_Internals child package

   function Make_State return State;

   function Initialise (Key : in Key_Type; Nonce : in Nonce_Type) return State;

   procedure Absorb (S : in out State; X : in Storage_Array)
     with Pre=> (Valid_Storage_Array_Parameter(X));

   procedure Encrypt (S : in out State;
                      M : in Storage_Array;
                      C : out Storage_Array)
     with Relaxed_Initialization => C,
       Pre => (
                  (Valid_Storage_Array_Parameter(M) and
                    Valid_Storage_Array_Parameter(C'First, C'Last))
                  and then C'Length = M'Length
              ),
     Post => C'Initialized;

   procedure Decrypt (S : in out State;
                      C : in Storage_Array;
                      M : out Storage_Array)
     with Relaxed_Initialization => M,
       Pre => (
                    (Valid_Storage_Array_Parameter(C) and
                    Valid_Storage_Array_Parameter(M'First, M'Last))
                  and then C'Length = M'Length
              ),
     Post => M'Initialized;

   procedure Finalise (S : in out State; Key : in Key_Type; Tag : out Tag_Type)
   with Relaxed_Initialization => Tag, Post => Tag'Initialized;

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
   pragma Compile_Time_Error (b_rounds + b_round_constants_offset > 12,
                              "Ascon requires b_rounds +" &
                                " b_round_constants_offset to be <= 12");
   pragma Warnings (GNATprove, On, "Compile_Time_Error");

end Ascon;
