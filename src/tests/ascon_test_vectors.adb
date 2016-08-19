-- Ascon_Test_Vectors

-- Copyright (c) 2016, James Humphry - see LICENSE file for details

with Ada.Text_IO;
use Ada.Text_IO;

with Ascon128v11;
with Ascon128av11;

with Display_Ascon_Traces;

procedure Ascon_Test_Vectors is

   procedure Ascon128v11_Display is
     new Display_Ascon_Traces(Ascon_Package => Ascon128v11);

   procedure Ascon128av11_Display is
     new Display_Ascon_Traces(Ascon_Package => Ascon128av11);

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

end Ascon_Test_Vectors;
