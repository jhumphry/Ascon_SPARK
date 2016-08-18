-- Display_Ascon_Traces

-- A utility to display traces of the encryption process for the test vectors
-- in the demo of the reference implementations

-- Copyright (c) 2016, James Humphry - see LICENSE file for details

with Ada.Text_IO;
use Ada.Text_IO;
with System.Storage_Elements;
use System.Storage_Elements;

with Ascon.Access_Internals;
with Ascon.Utils;

procedure Display_Ascon_Traces is
   use Ascon.Access_Internals;

   package Ascon_Utils is new Ascon.Utils;
   use Ascon_Utils;

   State_Trace : State := Make_State;

   K : Ascon.Key_Type := (others => 0);
   N : Ascon.Nonce_Type := (others => 0);
   A : Storage_Array(0..4) := (16#41#, 16#53#, 16#43#, 16#4f#, 16#4e#);
   M : Storage_Array(0..4) := (16#61#, 16#73#, 16#63#, 16#6f#, 16#6e#);
   C : Storage_Array(0..4);
--     T : Ascon.Tag_Type;
--
--     M2 : Storage_Array(0..Test_Message_Length-1);
--     T2 : Ascon.Tag_Type;

begin

   Put_Line("ENCRYPTION");
   New_Line;

   State_Trace := Initialise(K, N);
   Put_Line("State after initialisation (with key and nonce):");
   Put_State(State_Trace);
   New_Line;

   Absorb(State_Trace, A);
   Put_Line("State after associated data processing:");
   Put_State(State_Trace);
   New_Line;

   Encrypt(State_Trace, M, C);
   Put_Line("State after message encryption:");
   Put_State(State_Trace);
   New_Line;

--     Finalise(State_Trace, T, 16#08#);
--     Put_Line("State after finalisation:");
--     Put_State(State_Trace);
--     New_Line;
--
   Put_Line("Ciphertext:");
   Put_Storage_Array(C);
--     Put_Line("Tag:");
--     Put_Storage_Array(T);
--     New_Line;
--     New_Line;
--
--     Put_Line("DECRYPTION");
--     New_Line;
--
--     State_Trace := Initialise(K, N);
--     Put_Line("Initialise state with key and nonce");
--
--     Absorb(State_Trace, A, 16#01#);
--     Put_Line("Absorbing header into state");
--
--     Decrypt(State_Trace, C, M2, 16#02#);
--     Put_Line("Decrypting message");
--
--     Finalise(State_Trace, T2, 16#08#);
--     Put_Line("Finalising state");
--     New_Line;
--
--     Put_Line("Recovered plaintext:");
--     Put_Storage_Array(M2);
--     Put_Line("Recovered Tag:");
--     Put_Storage_Array(T2);
--     New_Line;
--
--     Put_Line((if M /= M2
--              then "ERROR :Plaintexts don't match"
--              else "Plaintexts match"));
--     Put_Line((if T /= T2
--              then "ERROR: Tags don't match"
--              else "Tags match"));
--     New_Line;

end Display_Ascon_Traces;