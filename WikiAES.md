_**Output**_
```
dhanoopbhaskar@dhanoop-laptop:~/workspace/Copy/crypto/run_aes$ java AESkeygen 
Key generated and saved in AESkey.txt 

dhanoopbhaskar@dhanoop-laptop:~/workspace/Copy/crypto/run_aes$ java AESencrypt 
Usage: java < classname > < mode > 
 < mode > := (ECB|CBC|OFB|CFB) 

dhanoopbhaskar@dhanoop-laptop:~/workspace/Copy/crypto/run_aes$ java AESencrypt ecb 
Encryption done! Please check AESciphertext.txt for output! 

dhanoopbhaskar@dhanoop-laptop:~/workspace/Copy/crypto/run_aes$ java AESdecrypt ecb 
Decryption done! Please check AESplaintext.txt for output! 

dhanoopbhaskar@dhanoop-laptop:~/workspace/Copy/crypto/run_aes$ java AESencrypt cbc 
Encryption done! Please check AESciphertext.txt for output! 

dhanoopbhaskar@dhanoop-laptop:~/workspace/Copy/crypto/run_aes$ java AESdecrypt cbc 
Decryption done! Please check AESplaintext.txt for output! 

dhanoopbhaskar@dhanoop-laptop:~/workspace/Copy/crypto/run_aes$ java AESencrypt ofb 
Encryption done! Please check AESciphertext.txt for output! 

dhanoopbhaskar@dhanoop-laptop:~/workspace/Copy/crypto/run_aes$ java AESdecrypt ofb 
Decryption done! Please check AESplaintext.txt for output! 

dhanoopbhaskar@dhanoop-laptop:~/workspace/Copy/crypto/run_aes$ java AESencrypt cfb 
Encryption done! Please check AESciphertext.txt for output! 

dhanoopbhaskar@dhanoop-laptop:~/workspace/Copy/crypto/run_aes$ java AESdecrypt cfb 
Decryption done! Please check AESplaintext.txt for output! 

dhanoopbhaskar@dhanoop-laptop:~/workspace/Copy/crypto/run_aes$ 
```

_**About Input/Output Files**_
```
AESkeygen.java - 
(output) AESkey.txt

AESencrypt.java - 
(input) AESkey.txt & AESplaintext.txt 
(output) AESciphertext.txt

AESdecrypt.java - 
(input) AESkey.txt & AESciphertext.txt 
(output) AESplaintext.txt
```