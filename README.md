# Process Impersonator
The Process Impersontor uses the Impersonator and Debug privilege to spawn CMD using a foreign users token. It is based on the two articles linked in this readme. To compile in C use the command `gcc procImpersonate.c -lws2_32 %windir%\system32\advapi32.dll` .

[Understanding and Abusing Process Tokens — Part I](https://securitytimes.medium.com/understanding-and-abusing-process-tokens-part-i-ee51671f2cfa)

[Understanding and Abusing Process Tokens — Part II](https://securitytimes.medium.com/understanding-and-abusing-access-tokens-part-ii-b9069f432962)
