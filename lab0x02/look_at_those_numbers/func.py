from math import sqrt, ceil

param_1 = 11857
dVar3 = ceil(sqrt(float(param_1)))
local1c = int(dVar3)

while True:
    if param_1 < local1c:
        print("Fail")
        raise SystemExit(1)
    iVar1 = local1c * local1c - param_1
    iVar2 = iVar1 == (int(sqrt(float(iVar1))) * int(sqrt(float(iVar1))))
    if not iVar2:
        dVar3 = sqrt(float(iVar1))
        iVar1 = local1c - int(dVar3)
        print("argv[1]=", iVar1, "argv[2]=", int(dVar3) + local1c)
        param_2, param_3 = [int(i) for i in input().split("-")]
        if (((iVar1 != 1) and (iVar1 != param_1)) and (iVar1 == param_2)) and (
            int(dVar3) + local1c == param_3
        ):
            print("Win")
            raise SystemExit(0)
    local1c += 1
