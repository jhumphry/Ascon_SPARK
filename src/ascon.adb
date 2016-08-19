-- Ascon

-- an Ada / SPARK implementation of the Ascon Authenticated Encryption Algorithm
-- created by Christoph Dobraunig, Maria Eichlseder, Florian Mendel and
-- Martin Schläffer

-- Copyright (c) 2016, James Humphry - see LICENSE file for details

pragma Restrictions(No_Implementation_Attributes,
                    No_Implementation_Units,
                    No_Obsolescent_Features);

with Ascon.Load_Store;
with Ascon.Compare_Tags;

package body Ascon
with SPARK_Mode => On
is

   use all type Interfaces.Unsigned_64;

   package Ascon_Load_Store is new Ascon.Load_Store;

   function Storage_To_Word (S : in Storage_Array) return Word
     renames Ascon_Load_Store.Storage_Array_To_Unsigned_64;

   function Word_To_Storage (W : in Word) return Storage_Array
     renames Ascon_Load_Store.Unsigned_64_To_Storage_Array;

   -- ***
   -- Constants and types used internally
   -- ***

   Round_Constants : constant array (Integer range 1..12) of Word
     := (16#000000000000000000f0#, 16#000000000000000000e1#,
         16#000000000000000000d2#, 16#000000000000000000c3#,
         16#000000000000000000b4#, 16#000000000000000000a5#,
         16#00000000000000000096#, 16#00000000000000000087#,
         16#00000000000000000078#, 16#00000000000000000069#,
         16#0000000000000000005a#, 16#0000000000000000004b#);

   Rate_SE : constant Storage_Offset := Storage_Offset(rate/8);
   Rate_Words : constant Integer := rate/64;
   Key_Words : constant := key_bits / 64;
   Tag_Words : constant := tag_bits / 64;
   Nonce_Words : constant := nonce_bits / 64;

   subtype Rate_Storage_Array is Storage_Array(1..Rate_SE);

   -- ***
   -- Implementation of the the permutation p as described in Section 1.5
   -- of the Ascon specification
   -- ***

   procedure p_C (S : in out State; Round : in Round_Count)
     with Inline is
   begin
      S(2) := S(2) xor Round_Constants(Round);
   end p_C;

   procedure p_S (S : in out State)
     with Inline is
      T : State;
   begin
      -- x0 ^= x4;    x4 ^= x3;    x2 ^= x1;
      S(0) := S(0) xor S(4);
      S(4) := S(4) xor S(3);
      S(2) := S(2) xor S(1);

      -- t0  = x0;    t1  = x1;    t2  = x2;    t3  = x3;    t4  = x4;
      -- t0 =~ t0;    t1 =~ t1;    t2 =~ t2;    t3 =~ t3;    t4 =~ t4;
      T := (0 => not S(0),
            1 => not S(1),
            2 => not S(2),
            3 => not S(3),
            4 => not S(4));

      -- t0 &= x1;    t1 &= x2;    t2 &= x3;    t3 &= x4;    t4 &= x0;
      T(0) := T(0) and S(1);
      T(1) := T(1) and S(2);
      T(2) := T(2) and S(3);
      T(3) := T(3) and S(4);
      T(4) := T(4) and S(0);

      -- x0 ^= t1;    x1 ^= t2;    x2 ^= t3;    x3 ^= t4;    x4 ^= t0;
      S(0) := S(0) xor T(1);
      S(1) := S(1) xor T(2);
      S(2) := S(2) xor T(3);
      S(3) := S(3) xor T(4);
      S(4) := S(4) xor T(0);

      -- x1 ^= x0;    x0 ^= x4;    x3 ^= x2;    x2 =~ x2;
      S(1) := S(1) xor S(0);
      S(0) := S(0) xor S(4);
      S(3) := S(3) xor S(2);
      S(2) := not S(2);
   end p_S;

   procedure p_L (S : in out State)
     with Inline is
   begin
      S(0) := S(0) xor Rotate_Right(S(0), 19) xor Rotate_Right(S(0), 28);
      S(1) := S(1) xor Rotate_Right(S(1), 61) xor Rotate_Right(S(1), 39);
      S(2) := S(2) xor Rotate_Right(S(2), 01) xor Rotate_Right(S(2), 06);
      S(3) := S(3) xor Rotate_Right(S(3), 10) xor Rotate_Right(S(3), 17);
      S(4) := S(4) xor Rotate_Right(S(4), 07) xor Rotate_Right(S(4), 41);
   end p_L;

   -- p_a and p_b are declared separately, rather than using a single routine
   -- with a parameter to indicate how many rounds to perform, as this may make
   -- it easier for compilers to identify the potential for loop unrolling /
   -- vectorisation when high optimisation levels are used.

   procedure p_a (S : in out State)
     with Inline is
   begin
      for I in 1..a_rounds loop
         p_C(S, I);
         p_S(S);
         p_L(S);
      end loop;
   end p_a;

   procedure p_b (S : in out State)
     with Inline is
   begin
      for I in 1..b_rounds loop
         p_C(S, I);
         p_S(S);
         p_L(S);
      end loop;
   end p_b;

   -- ***
   -- Internal use routines
   -- ***

   function Pad_r (X : in Storage_Array) return Rate_Storage_Array
     with Inline, Pre=> (X'Length < rate / 8 and
                           X'Last < Storage_Offset'Last - Rate_SE) is
      Zero_Pad_Length : constant Storage_Offset
        := Rate_SE - 1 - Storage_Offset(X'Length);
      Padding : constant Storage_Array(1 .. Zero_Pad_Length) := (others => 0);
   begin
      return X & 16#80# & Padding;
   end Pad_r;

   function Compare_Tags_Constant_Time is new Ascon.Compare_Tags;

   -- ***
   -- Low-level API exposed by Ascon.Access_Internals
   -- ***

   function Make_State return State is (State'(others => 0));

   function Initialise (Key : in Key_Type; Nonce : in Nonce_Type)
                        return State is
      S : State := (others => 0);
      Nonce_Ptr : Storage_Offset := Nonce'First;
      Key_Ptr : Storage_Offset := Key'First;
   begin
      S(0) := S(0) or Shift_Left(Word(key_bits), 56);
      S(0) := S(0) or Shift_Left(Word(rate), 48);
      S(0) := S(0) or Shift_Left(Word(a_rounds), 40);
      S(0) := S(0) or Shift_Left(Word(b_rounds), 32);

      for I in 1..Nonce_Words loop
         pragma Loop_Invariant (Nonce_Ptr = Nonce'First + Storage_Offset(I-1)*8);
         S(4-I+1) := Storage_To_Word(Nonce(Nonce_Ptr..Nonce_Ptr+7));
         Nonce_Ptr := Nonce_Ptr + 8;
      end loop;

      for I in 1..Key_Words loop
         pragma Loop_Invariant (Key_Ptr = Key'First + Storage_Offset(I-1)*8);
         S(4-Nonce_Words-I+1) := Storage_To_Word(Key(Key_Ptr..Key_Ptr+7));
         Key_Ptr := Key_Ptr + 8;
      end loop;

      p_a(S);

      Key_Ptr := Key'First;
      for I in 1..Key_Words loop
         pragma Loop_Invariant (Key_Ptr = Key'First + Storage_Offset(I-1)*8);
         S(4-Key_Words+I) := S(4-Key_Words+I) xor
           Storage_To_Word(Key(Key_Ptr..Key_Ptr+7));
         Key_Ptr := Key_Ptr + 8;
      end loop;

      return S;
   end Initialise;

   procedure Absorb_AD_Block (S : in out State;
                              X : in Storage_Array)
     with Inline, Pre => (X'Length = Rate_SE and X'Last < Storage_Offset'Last) is
      X_Index : Storage_Offset := X'First;
   begin
      for I in 0..Rate_Words - 1 loop
         pragma Loop_Invariant (X_Index = X'First + Storage_Offset(I) * 8);
         S(I) := S(I) xor
           Storage_To_Word(X(X_Index .. X_Index + 7));
         X_Index := X_Index + 8;
      end loop;
      pragma Assert (X_Index = X'Last + 1);

      p_b(S);
   end Absorb_AD_Block;

   procedure Absorb (S : in out State; X : in Storage_Array) is
      Number_Full_Blocks : constant Storage_Offset := X'Length / Rate_SE;
      X_Index : Storage_Offset := X'First;
   begin
      if X'Length > 0 then

         for I in 1..Number_Full_Blocks loop
            pragma Loop_Invariant (X_Index = X'First + (I-1) * Rate_SE);
            Absorb_AD_Block(S, X(X_Index .. X_Index + Rate_SE-1));
            X_Index := X_Index + Rate_SE;
         end loop;

         Absorb_AD_Block(S, Pad_r(X(X_Index..X'Last)));
      end if;

      S(4) := S(4) xor 1;
   end Absorb;

   procedure Absorb_M_Block (S : in out State;
                             M : in Storage_Array;
                             C : out Storage_Array)
     with Inline, Pre => (M'Length = Rate_SE and C'Length = Rate_SE and
                            M'Last < Storage_Offset'Last and
                              C'Last < Storage_Offset'Last) is
      M_Index : Storage_Offset := M'First;
      C_Index : Storage_Offset := C'First;
   begin
      for I in 0..Rate_Words - 1 loop
         pragma Loop_Invariant(M_Index = M'First + Storage_Offset(I) * 8);
         pragma Loop_Invariant(C_Index = C'First + Storage_Offset(I) * 8);

         S(I) := S(I) xor Storage_To_Word(M(M_Index .. M_Index + 7));
         C(C_Index .. C_Index + 7) := Word_To_Storage(S(I));
         M_Index := M_Index + 8;
         C_Index := C_Index + 8;
      end loop;

      pragma Assert (M_Index = M'Last + 1);
      pragma Assert (C_Index = C'Last + 1);
   end Absorb_M_Block;

   pragma Annotate (GNATprove, False_Positive,
                    """C"" might not be initialized",
                    "The assertion on C_Index");

   procedure Encrypt (S : in out State;
                      M : in Storage_Array;
                      C : out Storage_Array) is
      Number_Full_Blocks : constant Storage_Offset := M'Length / Rate_SE;
      M_Index : Storage_Offset := M'First;
      C_Index : Storage_Offset := C'First;
   begin
      if M'Length > 0 then
         for I in 1..Number_Full_Blocks loop
            pragma Loop_Invariant(M_Index = M'First + (I-1) * Rate_SE);
            pragma Loop_Invariant(C_Index = C'First + (I-1) * Rate_SE);
            Absorb_M_Block(S => S,
                           M => M(M_Index..M_Index+Rate_SE-1),
                           C => C(C_Index..C_Index+Rate_SE-1)
                          );
            p_b(S);
            M_Index := M_Index + Rate_SE;
            C_Index := C_Index + Rate_SE;
         end loop;

         declare
            Last_M: constant Storage_Array := Pad_r(M(M_Index..M'Last));
            Last_C : Storage_Array(1..Rate_SE);
         begin
            Absorb_M_Block(S => S,
                           M => Last_M,
                           C => Last_C
                          );
            C(C_Index..C'Last) := Last_C(1..(C'Last - C_Index)+1);
         end;

      end if;
   end Encrypt;

   pragma Annotate (GNATprove, False_Positive,
                    """C"" might not be initialized",
                    "The loop initialises C from C'First to C_Index-1 and the second block of code initialises C_Index to C'Last");

   procedure Absorb_C_Block (S : in out State;
                             C : in Storage_Array;
                             M : out Storage_Array)
     with Inline, Pre => (M'Length = Rate_SE and C'Length = Rate_SE and
                            M'Last < Storage_Offset'Last and
                              C'Last < Storage_Offset'Last) is
      C_i : Word;
      M_Index : Storage_Offset := M'First;
      C_Index : Storage_Offset := C'First;
   begin
      for I in 0..Rate_Words - 1 loop
         pragma Loop_Invariant(M_Index = M'First + Storage_Offset(I) * 8);
         pragma Loop_Invariant(C_Index = C'First + Storage_Offset(I) * 8);

         C_i := Storage_To_Word(C(C_Index .. C_Index + 7));
         M(M_Index .. M_Index + 7) := Word_To_Storage(S(I) xor C_i);
         S(I) := C_i;

         M_Index := M_Index + 8;
         C_Index := C_Index + 8;
      end loop;

      pragma Assert (M_Index = M'Last + 1);
      pragma Assert (C_Index = C'Last + 1);
   end Absorb_C_Block;

   pragma Annotate (GNATprove, False_Positive,
                    """M"" might not be initialized",
                    "The assertion on the final value of M_Index shows that the whole of M is initialised");

   procedure Absorb_Last_C_Block (S : in out State;
                                  C : in Storage_Array;
                                  M : out Storage_Array)
     with Inline, Pre => (M'Length = C'Length and
                            C'Length < Rate_SE and
                              M'Last < Storage_Offset'Last and
                                C'Last < Storage_Offset'Last) is
      Last_Block : Storage_Array(1..Rate_SE);
      Index : Storage_Offset := Last_Block'First;
      C_Index : Storage_Offset := C'First;
   begin

      for I in 0..Rate_Words-1 loop
         pragma Loop_Invariant (Index = Last_Block'First + Storage_Offset(I) * 8);
         Last_Block(Index .. Index + 7) := Word_To_Storage(S(I));
         Index := Index + 8;
      end loop;

      pragma Assert (Index = Last_Block'Last+1);

      Index := Last_Block'First;
      for I in M'Range loop
         pragma Loop_Invariant(C_Index = C'First + (I - M'First));
         pragma Loop_Invariant(Index = Last_Block'First + (I - M'First));
         M(I) := Last_Block(Index) xor C(C_Index);
         Index := Index + 1;
         C_Index := C_Index + 1;
      end loop;

      Last_Block(1..C'Length) := C;
      Last_Block(C'Length+1) := Last_Block(C'Length+1) xor 16#80#;

      Index := Last_Block'First;
      for I in 0..Rate_Words-1 loop
         pragma Loop_Invariant (Index = Last_Block'First + Storage_Offset(I) * 8);
         S(I) := Storage_To_Word(Last_Block(Index .. Index + 7));
         Index := Index + 8;
      end loop;

   end Absorb_Last_C_Block;

   pragma Annotate (GNATprove, False_Positive,
                    """M"" might not be initialized",
                    "The loop over M'Range demonstrates that M is fully initialised");

   pragma Annotate (GNATprove, False_Positive,
                    """Last_Block"" might not be initialized",
                    "The assertion demonstrates that Last_Block is fully initialised");

   procedure Decrypt (S : in out State;
                      C : in Storage_Array;
                      M : out Storage_Array) is
      Number_Full_Blocks : constant Storage_Offset := C'Length / Rate_SE;
      M_Index : Storage_Offset := M'First;
      C_Index : Storage_Offset := C'First;
   begin
      if M'Length > 0 then
         for I in 1..Number_Full_Blocks loop
            pragma Loop_Invariant(M_Index = M'First + (I-1) * Rate_SE);
            pragma Loop_Invariant(C_Index = C'First + (I-1) * Rate_SE);
            Absorb_C_Block(S => S,
                           C => C(C_Index..C_Index+Rate_SE-1),
                           M => M(M_Index..M_Index+Rate_SE-1));
            p_b(S);
            M_Index := M_Index + Rate_SE;
            C_Index := C_Index + Rate_SE;
         end loop;

         Absorb_Last_C_Block(S => S,
                             C => C(C_Index..C'Last),
                             M => M(M_Index..M'Last));

      end if;
   end Decrypt;

   pragma Annotate (GNATprove, False_Positive,
                    """M"" might not be initialized",
                    "The loop initialises M from M'First to M_Index-1 and the call to Decrypt_Last_Block initialises M_Index to M'Last");

   procedure Finalise (S : in out State; Key : in Key_Type; Tag : out Tag_Type) is
      Key_Ptr : Storage_Offset := Key'First;
      Tag_Ptr : Storage_Offset := Tag'First;
   begin
      for I in 1..Key_Words loop
         pragma Loop_Invariant (Key_Ptr = Key'First + Storage_Offset(I-1)*8);
         S(Rate_Words + I - 1) := S(Rate_Words + I - 1) xor
           Storage_To_Word(Key(Key_Ptr..Key_Ptr+7));
         Key_Ptr := Key_Ptr + 8;
      end loop;

      p_a(S);

      for I in 1..Tag_Words loop
         pragma Loop_Invariant (Tag_Ptr = Tag'First + Storage_Offset(I-1)*8);
         Tag(Tag_Ptr .. Tag_Ptr+7) := Word_To_Storage(S(4-Tag_Words+I));
         Tag_Ptr := Tag_Ptr + 8;
      end loop;

      pragma Assert (Tag_Ptr = Tag'Last + 1);

      Key_Ptr := Key'First;
      for I in Tag'Range loop
         pragma Loop_Invariant (Key_Ptr = Key'First + I-Tag'First);
         Tag(I) := Tag(I) xor Key(Key_Ptr);
         Key_Ptr := Key_Ptr + 1;
      end loop;

   end Finalise;

   pragma Annotate (GNATprove, False_Positive,
                    """Tag"" might not be initialized",
                    "Initialisation and assertion demonstrate that Tag_Index is incremented over every element of Tag");

   -- ***
   -- High-level API as described in Algorithm 1 of the Ascon specification
   -- ***

   procedure AEADEnc(K : in Key_Type;
                     N : in Nonce_Type;
                     A : in Storage_Array;
                     M : in Storage_Array;
                     C : out Storage_Array;
                     T : out Tag_Type) is
      S : State := Initialise(K, N);
   begin
      Absorb(S, A);
      Encrypt(S, M, C);
      Finalise(S, K, T);
      pragma Unreferenced (S);
   end AEADEnc;

   procedure AEADDec(K : in Key_Type;
                     N : in Nonce_Type;
                     A : in Storage_Array;
                     C : in Storage_Array;
                     T : in Tag_Type;
                     M : out Storage_Array;
                     Valid : out Boolean) is
      S : State := Initialise(K, N);
      T2 : Tag_Type;
   begin
      Absorb(S, A);
      Decrypt(S, C, M);
      Finalise(S, K, T2);
      pragma Unreferenced (S);
      if Compare_Tags_Constant_Time(T, T2) then
         Valid := True;
      else
         -- Section 1.4.5 of the specification requires that the decrypted
         -- data not be returned to the caller if verification fails, to try to
         -- prevent callers from forgetting to check the validity of the result.
         M := (others => 0);
         Valid := False;
      end if;
   end AEADDec;

end Ascon;
