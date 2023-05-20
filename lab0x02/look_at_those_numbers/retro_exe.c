#include <math.h>
#include <stdio.h>

int FUN_00100999(int param_1)

{
  double dVar1;

  dVar1 = sqrt((double)param_1);
  return param_1 == (int)dVar1 * (int)dVar1;
}

int FUN_001009cf(int param_1, int param_2, int param_3)

{
  int bVar1;
  int iVar2;
  double dVar3;
  int local_1c;
  printf("Received %d and %d\n", param_2, param_3);

  dVar3 = sqrt((double)param_1);
  dVar3 = ceil(dVar3);
  local_1c = (int)dVar3;
  do {
    if (param_1 < local_1c) {
      printf("Reached here %d, %d\n", param_1, local_1c);
      return 1;
    }
    iVar2 = local_1c * local_1c - param_1;
    bVar1 = FUN_00100999(iVar2);
    if (bVar1 != 0) {
      dVar3 = sqrt((double)iVar2);
      iVar2 = local_1c - (int)dVar3;
      printf("The correct answers are %d and %d\n", iVar2, (int)dVar3 + local_1c);
      if ((((iVar2 != 1) && (iVar2 != param_1)) && (iVar2 == param_2)) &&
          ((int)dVar3 + local_1c == param_3)) {
        printf("win");
        return 0;
      }
    }
    local_1c = local_1c + 1;
  } while (1);
}

int main() {
  int local_2c, local_28;
  int local_24 = 9420;
  local_24 = local_24 % 0x10000;
  printf("%d\n", local_24);
  puts("Tell me.");
  scanf("%d-%d", &local_2c, &local_28);
  int uVar3 = FUN_001009cf(local_24, local_2c, local_28);
  if ((int)uVar3 != 0) {
    puts("Lenstra is not proud of you, yet.");
  }
}
