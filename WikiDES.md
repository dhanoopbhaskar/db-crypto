_**Output**_
```
dhanoopbhaskar@dhanoop-laptop:~/workspace$ java DESkeygen
Key generated and saved in DESkey.txt

dhanoopbhaskar@dhanoop-laptop:~/workspace$ java DESencrypt
Usage: java <classname> <mode>
 <mode> := (ECB|CBC|OFB|CFB)

dhanoopbhaskar@dhanoop-laptop:~/workspace$ java DESencrypt ecb
Encryption done! Please check DESciphertext.txt for output!

dhanoopbhaskar@dhanoop-laptop:~/workspace$ java DESdecrypt ecb
Decryption done! Please check DESplaintext.txt for output!

dhanoopbhaskar@dhanoop-laptop:~/workspace$ java DESencrypt cbc
Encryption done! Please check DESciphertext.txt for output!

dhanoopbhaskar@dhanoop-laptop:~/workspace$ java DESdecrypt cbc
Decryption done! Please check DESplaintext.txt for output!

dhanoopbhaskar@dhanoop-laptop:~/workspace$ java DESencrypt ofb
Encryption done! Please check DESciphertext.txt for output!

dhanoopbhaskar@dhanoop-laptop:~/workspace$ java DESdecrypt ofb
Decryption done! Please check DESplaintext.txt for output!

dhanoopbhaskar@dhanoop-laptop:~/workspace$ java DESencrypt cfb
Encryption done! Please check DESciphertext.txt for output!

dhanoopbhaskar@dhanoop-laptop:~/workspace$ java DESdecrypt cfb
Decryption done! Please check DESplaintext.txt for output!

dhanoopbhaskar@dhanoop-laptop:~/workspace$ java DESdecrypt cfb
Decryption done! Please check DESplaintext.txt for output!

dhanoopbhaskar@dhanoop-laptop:~/workspace$ 
```


_**About Input/Output Files**_
```
DESkeygen.java  -
(output) DESkey.txt 

DESencrypt.java - 
(input) DESkey.txt & DESplaintext.txt 
(output) DESciphertext.txt 

DESdecrypt.java - 
(input) DESkey.txt & DESciphertext.txt 
(output) DESplaintext.txt
```