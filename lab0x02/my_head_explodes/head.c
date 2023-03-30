#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

typedef unsigned long ulong;
typedef unsigned int uint;
typedef long undefined4;

// void FUN_001008ca(int param_1, int param_2)

// {
//   undefined4 uVar1;
//   int iVar2;
//   int iVar3;
//   int local_18;

//   DAT_00302084 = (int)(double)((ulong)(double)param_1 & 0x7fffffffffffffff);
//   DAT_00302088 = (int)(double)((ulong)(double)param_2 & 0x7fffffffffffffff);
//   for (local_18 = 0; local_18 < 0x10; local_18 = local_18 + 1) {
//     iVar2 = DAT_00302084 % 2;
//     DAT_00302084 = DAT_00302084 / 2;
//     iVar3 = DAT_00302088 % 2;
//     DAT_00302088 = DAT_00302088 / 2;
//     *(int *)(&DAT_003020a0 + (long)local_18 * 4) = iVar2;
//     (&DAT_003020e0)[local_18] = iVar2;
//     *(int *)(&DAT_00302120 + (long)local_18 * 4) = iVar3;
//     if (iVar3 == 0) {
//       *(undefined4 *)(&DAT_003021a0 + (long)local_18 * 4) = 1;
//     }
//     if (iVar2 == 0) {
//       *(undefined4 *)(&DAT_00302160 + (long)local_18 * 4) = 1;
//     }
//   }
//   DAT_00302080 = 0;
//   for (local_18 = 0; local_18 < 0x10; local_18 = local_18 + 1) {
//     *(uint *)(&DAT_00302220 + (long)local_18 * 4) =
//         *(int *)(&DAT_00302020 + (long)local_18 * 4) +
//         *(int *)(&DAT_003021a0 + (long)local_18 * 4) + DAT_00302080;
//     DAT_00302080 = (uint)(1 < *(int *)(&DAT_00302220 + (long)local_18 * 4));
//     *(int *)(&DAT_00302220 + (long)local_18 * 4) =
//         *(int *)(&DAT_00302220 + (long)local_18 * 4) % 2;
//   }
//   for (local_18 = 0xf; -1 < local_18; local_18 = local_18 + -1) {
//     *(undefined4 *)(&DAT_003021a0 + (long)local_18 * 4) =
//         *(undefined4 *)(&DAT_00302220 + (long)local_18 * 4);
//   }
//   if (param_1 < 0) {
//     DAT_00302080 = 0;
//     for (local_18 = 0xf; -1 < local_18; local_18 = local_18 + -1) {
//       *(undefined4 *)(&DAT_00302220 + (long)local_18 * 4) = 0;
//     }
//     for (local_18 = 0; local_18 < 0x10; local_18 = local_18 + 1) {
//       *(uint *)(&DAT_00302220 + (long)local_18 * 4) =
//           *(int *)(&DAT_00302020 + (long)local_18 * 4) +
//           *(int *)(&DAT_00302160 + (long)local_18 * 4) + DAT_00302080;
//       DAT_00302080 = (uint)(1 < *(int *)(&DAT_00302220 + (long)local_18 *
//       4));
//       *(int *)(&DAT_00302220 + (long)local_18 * 4) =
//           *(int *)(&DAT_00302220 + (long)local_18 * 4) % 2;
//     }
//     for (local_18 = 0xf; -1 < local_18; local_18 = local_18 + -1) {
//       *(undefined4 *)(&DAT_003020a0 + (long)local_18 * 4) =
//           *(undefined4 *)(&DAT_00302220 + (long)local_18 * 4);
//       (&DAT_003020e0)[local_18] =
//           *(undefined4 *)(&DAT_00302220 + (long)local_18 * 4);
//     }
//   }
//   if (param_2 < 0) {
//     for (local_18 = 0; local_18 < 0x10; local_18 = local_18 + 1) {
//       uVar1 = *(undefined4 *)(&DAT_00302120 + (long)local_18 * 4);
//       *(undefined4 *)(&DAT_00302120 + (long)local_18 * 4) =
//           *(undefined4 *)(&DAT_003021a0 + (long)local_18 * 4);
//       *(undefined4 *)(&DAT_003021a0 + (long)local_18 * 4) = uVar1;
//     }
//   }
//   return;
// }

// void FUN_00100f0f(int param_1, int param_2, long param_3)

// {
//   int local_14;
//   int local_10;
//   int local_c;

//   local_10 = 0;
//   FUN_001008ca(param_1, param_2);
//   for (local_14 = 0; local_14 < 0x10; local_14 = local_14 + 1) {
//     if (local_10 == *(int *)(&DAT_003020a0 + (long)local_14 * 4)) {
//       FUN_00100e5a();
//       local_10 = *(int *)(&DAT_003020a0 + (long)local_14 * 4);
//     } else if ((*(int *)(&DAT_003020a0 + (long)local_14 * 4) == 1) &&
//                (local_10 == 0)) {
//       FUN_00100d2e((long)&DAT_003021a0);
//       FUN_00100e5a();
//       local_10 = *(int *)(&DAT_003020a0 + (long)local_14 * 4);
//     } else {
//       FUN_00100d2e((long)&DAT_00302120);
//       FUN_00100e5a();
//       local_10 = *(int *)(&DAT_003020a0 + (long)local_14 * 4);
//     }
//   }
//   local_c = 0x1f;
//   for (local_14 = 0xf; -1 < local_14; local_14 = local_14 + -1) {
//     *(undefined4 *)((long)local_c * 4 + param_3) = (&DAT_003021e0)[local_14];
//     local_c = local_c + -1;
//   }
//   for (local_14 = 0xf; -1 < local_14; local_14 = local_14 + -1) {
//     *(undefined4 *)((long)local_c * 4 + param_3) = (&DAT_003020e0)[local_14];
//     local_c = local_c + -1;
//   }
//   for (local_14 = 0x1f; -1 < local_14; local_14 = local_14 + -1) {
//   }
//   return;
// }

int FUN_00101119(long param_1)

{
  int local_10;
  int local_c;

  local_10 = 0;
  for (local_c = 0x1f; -1 < local_c; local_c = local_c + -1) {
    local_10 = local_10 * 2;
    if (*(int *)(param_1 + (long)local_c * 4) == 1) {
      local_10 = local_10 + 1;
    }
  }
  return local_10;
}

ulong FUN_00101162(int param_1)

{
  long lVar1;
  char *puVar2;
  long in_FS_OFFSET;
  int local_a0;
  int local_9c;
  char local_98[128];
  long local_10;

  puVar2 = local_98;
  for (lVar1 = 0x10; lVar1 != 0; lVar1 = lVar1 + -1) {
    *puVar2 = 0;
    puVar2 = puVar2 + 1;
  }
  local_a0 = 1;
  for (local_9c = param_1 % 8 + 1; 1 < local_9c; local_9c = local_9c + -1) {
    // FUN_00100f0f(local_a0, local_9c, (long)local_98);
    local_a0 = FUN_00101119((long)local_98);
    fprintf(stderr, "local_a0 : %d \n", local_a0);
    memset(local_98, 0, 0x80);
  }
  return (long)param_1 % (long)local_a0 & 0xffffffff;
}

int main(void) {
  time_t tVar1;
  ulong uVar2;
  long in_FS_OFFSET;
  int local_28;
  int local_24;
  long local_20;

  tVar1 = time((time_t *)0x0);
  srand((uint)tVar1);
  local_24 = rand();
  printf("Your secret number: %d\n", local_24);
  puts("What do you have to say to your defense?");
  scanf("%d", &local_28);
  fprintf(stderr, "scanned\n");
  local_28 = local_24 % local_28;
  fprintf(stderr, "local_28 : %d \n", local_28);
  uVar2 = FUN_00101162(local_24);
  fprintf(stderr, "uVar2 : %d \n", uVar2);
  if (local_28 == (int)uVar2) {
    puts("WIN !!!");
  } else {
    puts("Nah.");
  }
  return 0;
}
