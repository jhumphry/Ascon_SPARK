-- Ascon_Definitions

-- Some type / subtype definitions in common use in the Ascon code.
-- As some uses of these types are in generic parameters, it is not possible
-- to hide them.

-- Copyright (c) 2016-2018, James Humphry - see LICENSE file for details

pragma Restrictions(No_Implementation_Attributes,
                    No_Implementation_Identifiers,
                    No_Implementation_Units,
                    No_Obsolescent_Features);

package Ascon_Definitions
with Pure, SPARK_Mode => On is

   subtype Rate_Bits is Integer
     with Static_Predicate => Rate_Bits in 64 | 128;

   subtype Round_Count is Integer range 1..12;
   subtype Round_Offset is Integer range 0..11;

end Ascon_Definitions;
