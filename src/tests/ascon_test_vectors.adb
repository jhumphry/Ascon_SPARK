-- Ascon_Test_Vectors

-- Copyright (c) 2016, James Humphry - see LICENSE file for details

with Ada.Text_IO;
use Ada.Text_IO;

with Display_Ascon_Traces;

procedure Ascon_Test_Vectors is

   procedure Ascon128v11_Display is
     new Display_Ascon_Traces;

begin
   Put_Line("Ascon Test Vectors");
   New_Line;

   Put_Line("-----------");
   Put_Line("Ascon128v11");
   Put_Line("-----------");
   Ascon128v11_Display;

end Ascon_Test_Vectors;
