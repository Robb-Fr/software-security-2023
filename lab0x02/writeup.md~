# CS412 2023 Lab0x02 Writeup

The hardest challenge I solved is the Parrot challenge.

## Description

In the Parrot challenge, we face a Telegram bot that initially proposes an API of 3 commands : `/pun`, for saying a pun, `/say <user_input>` to receive an audio file that says what is written as an argument, and `/source` to receive an audio file that spells the source file of the Telegram bot handler.

## Challenge solving

The first way I tried to tackle this challenge was, of course, to ask for some puns. Seeing that they were all hilarious, I tried the other routes.

Asking for /source, we can hear that the Telegram bot is coded in a single Python file using the Telegram bot handler library. Listening is quite difficult, but the main information that tickles our ears is the way the bot handles the text to be said.
Decoding the audio files leads us to an approximate Python line of code that appears to be

```python
system(f"echo {user_input} > to_say.txt")
```

This is clearly the main vulnerability we found in the code. By tweaking the `user_input` variable and exploiting the fact that the bash `echo` command can execute arbitrary commands, we can gain execution access to the machine, and if the output produced by the command can be read, we can have an audio file that spells it out to get a response.

By sending a few commands like `/say $(ls -lah)` or `/say $(whoami)`, we learn that there are a few files in the script's location, notably one called `flag` and the file `to_say.txt` (the file where the text to be said is written to). The user of the script is a special user called `bot`, which does not appear to have any special privileges such as sudo access. Getting the flag through the bot API seems to be the most effective way to get the flag.

A simple command like `/say $(cat flag)` does not seem to work, as the bot responds with an audio file saying "some characters in flag are not pronounceable". However, tweaking this string with some commands like `/say $(cat flag | head 20)` shows that the sentence is truncated, which shows that the sentence read by the bot is probably not an error message (as it would probably be preserved by the truncation of the flag). So I figured that decoding the characters one by one should allow us to spell out each character of the full flag and get them one by one.

Although the bot user does not have sudo access, it must be able to run a python interpreter (since the bot handler is written as a python file). Sending a <command> via `/say $(python -c "<command>)` will allow us to run any command with the machine's python interpreter. This would make our job easier for the next step, as all we need to do now is create a script to help us decode the flag.

I imagined many different possible codes to get each character, but remembering that each UTF-8 character has a name that is generally described using only ASCII alphanumeric characters, I created a script that takes each letter of the flag and replaces it with a string that describes that character with its UTF-8 name, with "and" as a separator to make audio decoding easier.

## Final command

```python
/say $(python -c 'import unicodedata

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
')
```

## Flag

SoftSec{some_'characters'_in_flag_'are'_'non'_pronounceable}
