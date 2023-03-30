import unicodedata

flag = open("flag").read()

string = ""
for c in flag:
    try:
        string += unicodedata.name(c)
    except ValueError:
        string += "no name for this char"
    string += " and "
string += "no more chars"
print(string)
