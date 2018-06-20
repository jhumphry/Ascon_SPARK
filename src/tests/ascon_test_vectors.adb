-- Ascon_Test_Vectors

-- Copyright (c) 2016-2018, James Humphry - see LICENSE file for details

with Ada.Text_IO;
use Ada.Text_IO;

with Ascon128v11;
with Ascon128av11;
with Ascon128v12;
with Ascon128av12;

with Display_Ascon_Traces;

procedure Ascon_Test_Vectors is

   procedure Ascon128v11_Display is
     new Display_Ascon_Traces(Ascon_Package => Ascon128v11);

   procedure Ascon128av11_Display is
     new Display_Ascon_Traces(Ascon_Package => Ascon128av11);

   procedure Ascon128v12_Display is
     new Display_Ascon_Traces(Ascon_Package => Ascon128v12);

   procedure Ascon128av12_Display is
     new Display_Ascon_Traces(Ascon_Package => Ascon128av12);

begin
   Put_Line("Ascon Test Vectors");
   New_Line;

   Put_Line("-----------");
   Put_Line("Ascon128v11");
   Put_Line("-----------");
   Ascon128v11_Display;
   New_Line;

   Put_Line("------------");
   Put_Line("Ascon128av11");
   Put_Line("------------");
   Ascon128av11_Display;
   New_Line;

   Put_Line("-----------");
   Put_Line("Ascon128v12");
   Put_Line("-----------");
   Ascon128v12_Display;
   New_Line;

   Put_Line("------------");
   Put_Line("Ascon128av12");
   Put_Line("------------");
   Ascon128av12_Display;
   New_Line;

end Ascon_Test_Vectors;
