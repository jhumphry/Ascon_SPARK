-- Ascon_Demo

-- Copyright (c) 2016-2018, James Humphry - see LICENSE file for details

with Ada.Text_IO;
use Ada.Text_IO;
with System.Storage_Elements;
use System.Storage_Elements;

with Ascon.Utils;

with Ascon128v12;
use Ascon128v12;

procedure Ascon128_Demo is

   package Ascon128v12_Utils is new Ascon128v12.Utils;
   use Ascon128v12_Utils;

   K : Key_Type;
   N : Nonce_Type;
   A, M, C, M2 : Storage_Array(0..127);
   T : Tag_Type;
   Valid : Boolean;

begin
   Put_Line("Ascon-128 v1.2 Example");
   Put_Line("Encrypting and decrypting a message using the high-level API");
   New_Line;

   -- Setting up example input data

   for I in K'Range loop
      K(I) := Storage_Element(I);
   end loop;

   for I in N'Range loop
      N(I) := (15 - Storage_Element(I)) * 16;
   end loop;

   for I in A'Range loop
      A(I) := Storage_Element(I);
      M(I) := Storage_Element(I);
   end loop;

   -- Displaying example input data

   Put_Line("Key:"); Put_Storage_Array(K);
   Put_Line("Nonce:"); Put_Storage_Array(N);
   Put_Line("Header and Message (both the same):");
   Put_Storage_Array(M);
   New_Line;

   -- Performing the encryption

   Put_Line("Calling AEADEnc");
   AEADEnc(K, N, A, M, C, T);
   New_Line;

   -- Displayng the result of the encryption

   Put_Line("Ciphertext:"); Put_Storage_Array(C);
   Put_Line("Tag:"); Put_Storage_Array(T);
   New_Line;

   -- Performing the decryption

   Put_Line("Calling AEADDec");
   AEADDec(K, N, A, C, T, M2, Valid);
   if Valid then
      Put_Line("Result of decryption is valid as expected");
   else
      Put_Line("ERROR - Result of decryption is invalid");
   end if;
   New_Line;

   -- Displaying the result of the decryption

   Put_Line("Decrypted message:"); Put_Storage_Array(M2);
   New_Line;

   -- Corrupting the tag
   Put_Line("Now corrupting one bit of the tag");
   T(7) := T(7) xor 8;

   -- Now checking that decryption with the corrupt tag fails
   Put_Line("Calling AEADDec again with the corrupted tag");
   AEADDec(K, N, A, C, T, M2, Valid);
   if Valid then
      Put_Line("ERROR Result of decryption is valid despite the corrupt tag");
   else
      Put_Line("Result of decryption with corrupt tag is invalid, as expected");
   end if;
   New_Line;

end Ascon128_Demo;
