-- Ascon.Access_Internals

-- Allow access to some internal parts of Ascon for testing and verification
-- purposes. Not part of the standard API

-- Copyright (c) 2016, James Humphry - see LICENSE file for details

generic
package Ascon.Access_Internals is

   subtype State is Ascon.State;

   function Make_State return State;

   function Initialise (Key : in Key_Type; Nonce : in Nonce_Type) return State;

   procedure Absorb (S : in out State; X : in Storage_Array);

   procedure Encrypt (S : in out State;
                      M : in Storage_Array;
                      C : out Storage_Array)
     with Pre => (C'Length = M'Length);

   procedure Decrypt (S : in out State;
                      C : in Storage_Array;
                      M : out Storage_Array)
     with Pre => (C'Length = M'Length);

   procedure Finalise (S : in out State; Key : in Key_Type; Tag : out Tag_Type);

private

   function Make_State return State renames Ascon.Make_State;

   function Initialise (Key : in Key_Type; Nonce : in Nonce_Type) return State
                        renames Ascon.Initialise;

   procedure Absorb (S : in out State; X : in Storage_Array)
                     renames Ascon.Absorb;

   procedure Encrypt (S : in out State;
                      M : in Storage_Array;
                      C : out Storage_Array) renames Ascon.Encrypt;

   procedure Decrypt (S : in out State;
                      C : in Storage_Array;
                      M : out Storage_Array) renames Ascon.Decrypt;

   procedure Finalise (S : in out State; Key : in Key_Type; Tag : out Tag_Type)
                       renames Ascon.Finalise;

end Ascon.Access_Internals;
