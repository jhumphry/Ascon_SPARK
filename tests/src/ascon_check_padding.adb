-- Ascon_Check_Padding

-- Ensure that associated data of different length are accepted and messages
-- of different lengths correctly encrypt and decrypt. This is largely aimed
-- at checking the implementation of padding.

-- Copyright (c) 2016, James Humphry - see LICENSE file for details

with Ada.Text_IO;
use Ada.Text_IO;

with Test_Input_Lengths;

with Ascon128v11;
with Ascon128av11;
with Ascon128v12;
with Ascon128av12;

procedure Ascon_Check_Padding is

   procedure Ascon128v11_Test is
     new Test_Input_Lengths(Ascon_Package => Ascon128v11);
   procedure Ascon128av11_Test is
     new Test_Input_Lengths(Ascon_Package => Ascon128av11);
   procedure Ascon128v12_Test is
     new Test_Input_Lengths(Ascon_Package => Ascon128v12);
   procedure Ascon128av12_Test is
     new Test_Input_Lengths(Ascon_Package => Ascon128av12);

begin

   Put_Line("Checking padding and input-length flexibility for Ascon routines");
   New_Line;

   Put("Associated data and message lengths from 0-2000 are checked for " &
         "correct authenticated encryption and decryption. While the length " &
         "of one input is being varied, the lengths of the other is held " &
         "constant.");
   New_Line;
   New_Line;

   Put_Line("-----------");
   Put_Line("Ascon128v11");
   Put_Line("-----------");
   Ascon128v11_Test;

   Put_Line("------------");
   Put_Line("Ascon128av11");
   Put_Line("------------");
   Ascon128av11_Test;

   Put_Line("-----------");
   Put_Line("Ascon128v12");
   Put_Line("-----------");
   Ascon128v12_Test;

   Put_Line("------------");
   Put_Line("Ascon128av12");
   Put_Line("------------");
   Ascon128av12_Test;

end Ascon_Check_Padding;
