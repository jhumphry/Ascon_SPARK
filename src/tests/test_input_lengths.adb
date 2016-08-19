-- Test_Input_Lengths

-- Ensure that associated data of different length are accepted and messages
-- of different lengths correctly encrypt and decrypt. This is largely aimed
-- at checking the implementation of padding.

-- Copyright (c) 2016, James Humphry - see LICENSE file for details

with Ada.Text_IO;
use Ada.Text_IO;

with System.Storage_Elements;
use System.Storage_Elements;

with Interfaces;
use Interfaces;

with Ascon.Utils;

procedure Test_Input_Lengths is

   use Ascon_Package;

   package Storage_Offset_Text_IO is
     new Ada.Text_IO.Integer_IO(Num => Storage_Offset);
   use Storage_Offset_Text_IO;

   package Ascon_Utils is new Ascon_Package.Utils;
   use Ascon_Utils;

   function Generate (G : in out Unsigned_64) return Storage_Element is
      -- xorshift64 generator from: An experimental exploration of Marsaglia's
      -- xorshift generators, scrambled Sebastiano Vigna - arXiv 1402.6246v2

      M32 : constant := 2685821657736338717;
   begin
      G := G xor Shift_Right(G, 12);
      G := G xor Shift_Left(G, 25);
      G := G xor Shift_Right(G, 17);
      return Storage_Element((G * M32)  mod Storage_Element'Modulus);
   end Generate;

   K : Key_Type;
   N : Nonce_Type;
   A, M, C, M2 : Storage_Array(0..Max_Size-1);
   T : Tag_Type;
   Valid : Boolean;
   G : Unsigned_64 := 314_159_265;

begin
   -- Setting up example input data

   for I in K'Range loop
      K(I) := Generate(G);
   end loop;

   for I in N'Range loop
      N(I) := Generate(G);
   end loop;

   for I in A'Range loop
      A(I) := Generate(G);
      M(I) := Generate(G);
   end loop;

   -- Testing different header lengths

   Put("Testing associated data lengths from 0 .. ");
   Put(Max_Size, Width=>0);
   New_Line;

   for I in Storage_Offset range 0..Max_Size loop
      AEADEnc(K => K,
              N => N,
              A => A(0..I-1),
              M => M(0..Other_Size-1),
              C => C(0..Other_Size-1),
              T => T);
      AEADDec(K     => K,
              N     => N,
              A     => A(0..I-1),
              C     => C(0..Other_Size-1),
              T     => T,
              M     => M2(0..Other_Size-1),
              Valid => Valid);
      if not Valid then
         Put("Error: Failed to authenticate decryption with associated data " &
               "size:");
         Put(I, Width=>0);
         New_Line;
      elsif (for some J in Storage_Offset range 0..Other_Size-1 =>
               M(J) /= M2(J))
      then
         Put("Error: Decryption authenticated but message was corrupted " &
               "for data associated size:");
         Put(I, Width=>0);
         New_Line;
      end if;
   end loop;

   -- Testing different message lengths

   Put("Testing message lengths from 0 .. ");
   Put(Max_Size, Width=>0);
   New_Line;

   for I in Storage_Offset range 0..Max_Size loop
      AEADEnc(K => K,
              N => N,
              A => A(0..Other_Size-1),
              M => M(0..I-1),
              C => C(0..I-1),
              T => T);
      AEADDec(K     => K,
              N     => N,
              A     => A(0..Other_Size-1),
              C     => C(0..I-1),
              T     => T,
              M     => M2(0..I-1),
              Valid => Valid);
      if not Valid then
         Put("Error: Failed to authenticate decryption with message size:");
         Put(I, Width=>0);
         New_Line;
      elsif (for some J in Storage_Offset range 0..I-1 =>
               M(J) /= M2(J))
      then
         Put("Error: Decryption authenticated but message was corrupted " &
               "for message size:");
         Put(I, Width=>0);
         New_Line;
      end if;
   end loop;

   New_Line;

end Test_Input_Lengths;
