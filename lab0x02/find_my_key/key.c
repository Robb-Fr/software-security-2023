#include <stdio.h>

int FUN_001007af(int param_1)

{
  int iVar1;
  int uVar2;

  iVar1 = param_1 + -0x4153;
  if (iVar1 < 1)
  {
    uVar2 = 0;
  }
  else if (iVar1 * 3 + -0x80 < iVar1 % 2 + iVar1)
  {
    uVar2 = 1;
  }
  else
  {
    uVar2 = 0;
  }
  return uVar2;
}

int FUN_00100843(unsigned int param_1)

{
  int uVar1;

  if ((param_1 & 1) == 0)
  {
    printf("Failed first\n");
    uVar1 = 0;
  }
  else if ((int)param_1 % 7 == 0)
  {
    if ((int)param_1 < 0x1f0f3)
    {
      printf("Failed third\n");
      uVar1 = 0;
    }
    else if ((int)(param_1 * 5) < (int)(((int)param_1 / 0x6930) * param_1))
    {
      printf("Failed fourth\n");
      uVar1 = 0;
    }
    else
    {
      uVar1 = 1;
    }
  }
  else
  {
    printf("Failed second: %d mod 7 = %d\n", param_1, (int)param_1 % 7);
    uVar1 = 0;
  }
  return uVar1;
}

int FUN_001008e0(unsigned int param_1)

{
  int uVar1;

  if ((int)param_1 >> 4 < 0x395eb)
  {
    printf("Failed first\n");
    uVar1 = 0;
  }
  else if ((int)(param_1 * 2) < 0x72bde0)
  {
    if ((param_1 & 1) == 0)
    {
      uVar1 = 1;
    }
    else
    {
      printf("Failed third\n");
      uVar1 = 0;
    }
  }
  else
  {
    printf("Failed second : val=%d\n", (int)(param_1 * 2));
    uVar1 = 0;
  }
  return uVar1;
}

int FUN_0010076a(int param_1)

{
  int uVar1;

  if (param_1 < 0x38)
  {
    uVar1 = 0;
  }
  else if (param_1 < 0x6c)
  {
    if (param_1 / 2 < param_1 + -0x31)
    {
      uVar1 = 1;
    }
    else
    {
      uVar1 = 0;
    }
  }
  else
  {
    uVar1 = 0;
  }
  return uVar1;
}

int main()

{
  int uVar1;
  long in_FS_OFFSET;
  int local_28 = 100;
  int local_24 = 16750;
  unsigned int local_20 = 44851;
  unsigned int local_1c = 3759800;
  int local_18;
  int local_14;
  long local_10;

  puts("Please enter the key for activating the program:");
  // scanf("%d-%d-%d-%d", &local_28, &local_24, &local_20, &local_1c);
  uVar1 = FUN_0010076a(local_28);
  if (((int)uVar1 != 0) && (10 < (int)local_20))
  {
    printf("Passed first\n");
    local_20 = (local_20 - 2) * 3;
    uVar1 = FUN_001007af(local_24);
    printf("Passed second\n");
    local_18 = (int)uVar1;
    uVar1 = FUN_00100843(local_20);
    printf("Passed third\n");
    local_14 = (int)uVar1;
    printf("local18:  %d\n", local_18);
    printf("local14:  %d\n", local_14);
    if ((local_18 != 0) && (local_14 != 0))
    {
      printf("Passed fourth\n");
      uVar1 = FUN_001008e0(local_1c);
      if ((int)uVar1 != 0)
      {
        printf("Win");
      }
    }
  }
  puts("Invalid key! This program is uncrackable!");
  return 0;
}
