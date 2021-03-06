# Retos
## El dado fue echado (50pts)

```
Mxnlr Fhvdu vh ghwxyr xq lqvwdqwh dqwh hn ulr dwruohqwdgr sru ndv gxgdv. Fuxcdunr vljqlilfded frohwhu xqd lnhjdnlgdg: frqyhuwluvh hq hqholjr gh nd Uhsxenlfd h lqlfldu nd jxhuud flyln. Mxnlr Fhvdu glr nd rughq d vxv wursdv gh fuxcdu hn ulr, surqxqfldqgr hq ndwlq nd iudvh dnhd ldfwd hvw, vhjxq Vxhwrqlr hq vx reud Ylgdv gh nrv grfh fhvduhv. Gh dfxhugr frq Snxwdufr (hq vxv Ylgdv Sdudnhndv), Mxnlr Fhvdu flwr hq julhjr nd iudvh ghn gudodwxujr dwhqlhqvh Ohqdqgur, xqr gh vxv dxwruhv suhihulgrv: ¡Txh hoslhfh hn mxhjr!.

Nd fndyh sdud vxshudu hvwh uhwr hv hn ulr txh fuxcr Mxnlr Fhvdu
```

### Solución
Para la solución de este reto se identifico que el texto fue cifrado usando "Caesar Cipher", por lo que se uso el [cracker](https://www.xarg.org/2010/05/cracking-a-caesar-cipher/) el cual nos da que el valor de llave es 3, por lo que hacemos 26-3=23 y ejecutamos el caesar con key 23, lo cual nos devuelve:

```
Jukio Cesar se detuvo un instante ante ek rio atorlentado por kas dudas. Cruzarko significaba coleter una ikegakidad: convertirse en eneligo de ka Repubkica e iniciar ka guerra civik. Jukio Cesar dio ka orden a sus tropas de cruzar ek rio, pronunciando en katin ka frase akea iacta est, segun Suetonio en su obra Vidas de kos doce cesares. De acuerdo con Pkutarco (en sus Vidas Parakekas), Jukio Cesar cito en griego ka frase dek dralaturgo ateniense Lenandro, uno de sus autores preferidos: ¡Que elpiece ek juego!. Ka ckave para superar este reto es ek rio que cruzo Jukio Cesar
```

Buscamos en google el río que cruza Julio Cesar y la respuesta es Rió Rubicón.

### Flag

	flag{rubicon}

## The same challenge again? (50pts)
Wm14aFozdGZiM1JvWlhKZmVXVmhjbDl6WVcxbFgyTm9ZV3hzWlc1blpWOTk=

### Solución
Para solucionar este reto, se detecta que se usa base64 y se genera el siguiente script que rompe a varios intentos el texto:

	echo "Wm14aFozdGZiM1JvWlhKZmVXVmhjbDl6WVcxbFgyTm9ZV3hzWlc1blpWOTk=" > /tmp/f1.txt; for i in {1..10}; do printf "\nIntento %s\n" $i; cat /tmp/f1.txt | base64 -d | tee /tmp/f1.txt; done; rm /tmp/f1.txt
	
De esta manera la salida queda de la siguiente manera:

```
Intento 1
ZmxhZ3tfb3RoZXJfeWVhcl9zYW1lX2NoYWxsZW5nZV99
Intento 2
flag{_other_year_same_challenge_}
Intento 3

Intento 4

Intento 5

Intento 6

Intento 7

Intento 8

Intento 9

Intento 10

```

La flag se puede ver claramente en el intento 3.

### Flag
	flag{_other_year_same_challenge_}

## "Cifrado" custom (75pts)
Se ha usado sobre una cadena la combinación encoding base64 + algoritmo rotatorio ROT13 aplicado n veces (sabemos que menos de 100) tras el base64, pero se nos ha olvidado cuantas veces hemos realizado el proceso. Hemos intentado hacerlo a mano, pero hay muchas combinaciones, quizás exista otra forma de revertir el cifrado..... o no.

	mensaje e9967d22a874ebaf76662c152653c6bd

### Solución
Para solucionar este reto, se uso el siguiente script:

	cat mensaje > /tmp/f1.txt; for i in {1..15}; do printf "\nIntento %s\n" $i; cat /tmp/f$((i)).txt | tr '[A-Za-z]' '[N-ZA-Mn-za-m]' | base64 -d | tee /tmp/f$((i+1)).txt; done

La salida del script es la siguiente:

```
Intento 1
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
Intento 2
EHu1ZIcWL1qZZKSnJxgGoxc4M1qRZR1KEHt5H1cFZHgSFUD1FzSKFRc3G1ITq1AYExyKMHy4I1IVZHyJEySRn28mrHgnFSAWFGOWIIcVrHujE1ACFxuWAUWWpIEnHwSHE1DkG0yWLmMRFUIGpxyjZHc4LwEiF1qJGGV1IRtjH0ySZIAUERuSI0jkGIETIRSUpUu5oycYGmEkFKSCFHyOFHI4L2SirUHmFQO1H1cVEJISHzV1DIWkI0qWGJ5lH0SIpSI1AJ95L1yUoHIeExgGD0MVrH9TFRx0GQWGnKWIFGSjrHIuFQAKFHtkH1ulISLkERyKn0xjpIqUFwIfFQOGFKOGFGSOFwx1GQS5IJ9VFJISrTqUEwOwAHMUFIcTHwSGExgkE0xjqTkRFTAHFRynn29uqGSkF1qJpRcwH1cErT1SHaHkGID0naOWqJunFRyYEKu1E29uG0qTE1ACEaq4ZHqEH0SXrwyJExb1nxHjBHgUHH9KJwO0oR0kEJkWFHSKEKyGD0kVrTckF0yHFISGFRMFqQEhZwy1pHqCnSbjBIATHIZko1W5E0qXFIAVLKyMo3qCAT5uG1qjFHyHpGO5rxI5ImIUZR00ExyADJ9WDJuSrIpkGIWwAUWUFIqTq3yXEKuwI0tmI0ujFHyGFRuGHHEVqHSWZ09KGQSSIaRkDIISF3yFowOVoRSWGJkTF1AYFzS1I0HmGmISFQyKEyVkH0IgG0qirJAWEHcWH3WIrHqTHIA3EHgGFR0kDIMZFUIyEGO1ZT56AKIUZKSdExgGnRI5ImIXFRx1ExqWIIcFZH1SoH9eFIWVnaWVM1ulFSAQEGSKH0SIG1MVZH1JpyIWrRI5H0ARFUEgFGSknxMVrHqSE09UFRuSIaSUG2uZFQyYE1SGH0yuHzgRFHyGEyEKMHIEIwOhLIqVGQWaIScIrKcSF3HkFGOAExqVGJgVFRyvFayJn0tjFJqUZUSKFUtkIRc4rH9WHaIKFacanIcWpQSTFyAUEyVjn0EWEIqWFQy5o21On0DjH1MlF0yIJxgGMHI4L09hHxx1FJ1WJRMFrQOjFUSKFHywEycVZIAiFQyyExyKIz5uI1MZZKInEwSOIHHjrIqRZSAWFQSWIycVZHcjrHyKpyWWAHtjDH9TIRSKExqCAHtjGGElFUyHEyEkF0c3G1AWLIAJFQSkoxu4rIuSrIAUERuwARqWGIMnIUSUEKqOAHyVFJqWq09bGRykIxqEI2SWH2AWpxgwH0LmFTciq09JoaukIaWWL25lLIAvEzS5Fz4jqTcTITghExgGGRMIqTgWHzZ0pHcWIybkpIqjrUICFIWAAHEWrIWTIHyyEayKDHxjEIqUFJAHJwA5G28lZH9hZREdEHyAIRHjZHASE05eEmOwAUSUFIEWFQyWEGVkI25FqGElFQSdEyIGIHMEH3qSrJAJGQSOoRyYrHASFIq2DHu4nxIWGIWTFSAzEKuaE0SVFTclFTqeJyAOI0MEH0SWrJAJJxc1IRyGDHgjrIqKFxgGIHtlqJ5WF3yVpSW1n0EXAGEkFKSFEyIGE3O4qGITZRxmEmOGI0MIH2STHH41o1W5FREYrIATq1AIEJ1CAHSFGHuZZQyJExyZAD==
Intento 3
EHu1ZIcWL1qZZKSnJxgWD0MWEH9SZR1KEHt5JaWHJwOUFwSKFIWeIxWUH1IVFQDko3yKZHSII0IUZHyHpGSOJHI4rIqTZR1TGT1OIIc6DHuSrIp1Jxb4oKWVM25TH0SIE1SGDHEWL1MTFTAGpxynZKO4qIqOIIAIExcaoxu3H0uSZHEeERb5ARqWGIMnrSAUpUu5oycYGmEkFKSCFHyOFHI4L2SirUI1pyEaH3WIH1SXrTV1DIWkI0qWGJ5lH0SIpSI1AJ95L1yUoHIeExgGF0c5FGIZFR1SFKqGI0tlDHcTHIZkoau1qKWVpJcSZQxmERu1MT4jpIuhZHIKExuGoaOGFGSOFwx1GQSAJz9VFJ5jE09KGQOWZ0tlM1ElIIAWEySCLHxjqKITIQSHFRt4n29uqGOhZ09SFQS1oRyGGJISHayYowO4naOWpIITq0yzEyW5G0M4FIMAoIAhEyW1MRc4rGIWFwyJExcWH3WHpIISHHSQDHuAI3OWL1EVq1AUEKyRn0HlAIMlFKSKJauWE3O5EH9WFR1SEmOGoycIEJISrUyGFQSwEKSHM1AVLHueE0u0nz5uG1qjFKShEyW5JHI5FGIUZR1MEmOkIRHjrHgXrHSCE1WSAUOVH1MVrUIxEySCDHtmI1qjFHyGEGOGHHEVqGOhLH9KGQSSIaRkDIISFTWeEQV0naWHL2gTZUyzEKu1I0MFGHMkHHIbJyVkH0IgG0qWHx1TJxyOIRuWJzgiZIp1FJSGFR0kDIEWIH9yomAkD0SVrKIUZKSeExcOnRI5ImIXFRx0pHqWIIcFZH1SoH9eFIWVnaWVL1uZF1AUE0yWD0SIH1IVZH1JpyIWrRI5H0AOFTAWFGO5H0M4rHyTFTqKJwOSIaSVH1qnHxyXEySGDHc4GIMVZTqGEwA5IHIgIwOhLIqVGQWaIScIrKcSF3HjowOVnxqVrIcnraSbFayJn0tjFTknFKSLFUtkIRc4qJIVZ1qWpxuOIRM5DIyRFUIeFyWAI0EWGIcTZ3yOo21On0DjEIMTE01CEGNkG0c4qGITIH9IE21WnRu4rH1jFUSUFQSwEycVL1AlIKyCEIWvAHxjEIMRFHSfExgGAHHjrHgkZSAWFQSAIycVZJuTISAKpyWWJKSUH2unIKyHpRukDJ54qIqRFUSGpxu5F0I3G0SWFUSaFQN5oRyHDKySFwSUEmO5ARMHL09VFIL5
Intento 4
EHu1ZIcWL1qZZKICFIEOE0MWEH9ZrTZ0GJ1WIRkVBGSUHH41oyW1AUWEG1ITq1AYExyWF0MFLmAUZzAHEyW5ZJ8mrHgnFSAUGQSADIcVFHcSrIZ1pxuWAUSUFJgnHwSHE1DkDJ94GIMVZxSGpxynZKO4qIqOIIAIExcaoxuurTgSrUSQJxb5ARqWGIMnrSAUpUu5oycYGmEkFKSKJyI5LHMEIwSWH2AJFQS1nxuurHqjE093DHudn0qXn1EWFHSnpSI1AJ95L1MZoHInpGOWL0I3H2gTrUSIFQOaI0uuFT1THH8koau0n3OEH1ulISMeERyKn0xjpIqUFwIfFRyOFxIVMmSnFRudJxy5IJ9VFJISrTqUEQACAHMWpIcTHwSGEyDkE25VrIqWZxIGpyEOIHMEG0SnZUEeExySH1cEqTgSHaHkGHtjnaOWpIqnFRyYEyI5G0MYG0qTE0yKJyAOGRE4pHSVHxudFQOAH3WWpIISE0SQDHu0naOWL1EVq1AUEHbkD24jrTckF0yfExuWFRMFqQEhZR1SEmOGIRMFZIATHIZko1W5IaSHM1ATIUOeo3qCAHyuG1qkFJAhEyW5JHI4qGIUZR1MEmOkIRHjrHcXLKSGGIICAUSUH1MVrUIxEySCAHcII0ySFxyIFHgWZ0EVqHSWZRIJFQSAJxMVH0gSF3yUEmV0naWHL2gTZUyzEKu0n0HjGHyZZzqhJyVkH0HlZIqXHx1TJxueH3WIrHATFyAYDHukJRMWDIMZF3yAomAkD0EVFGMOE01OJxu5FUOUGmIhHxyMpHqGH1cFZHcSrUyOERb5I0EVDIAlFKS5E0yKq0SIH1MVZH1hFTSWrRIYqGShZUyTpHqAnxuWDHqSrHyKEwOAIHqgH09lITAyEJ1GG0y4FTcOHIV9
Intento 5
EHu1ZIcWL1uOITAGFIEOLxc4MmITLH91GQN5nRu4rQOUFwSKFIIKFRc3G2cTFRy1o3yKZHSGL1MAZHIJEyS5rHI4qGIkZR1TGT1AoxMVH2ASrIZ1pxuWAUSUFJgnHaxkExqCZJ94GIMVZxSGpxynZKO4qIqWZUyaFQV1IScVH1ujHayGpGOwAHjkGJkTIIAZpUu5oycVLmEZq0IcEwSkFxqUH0gWHaHmFQO1nxtkpQSXrTVkDIWkI0qWGJ5lHIAJEHg1ZHHjZIyUoHIeExgGD3O5FIqZFR1SFT1GnHyWI2ESrTAUFQOAZ0tkFIESZQtkERu1MH0jpIqWZHIKFUyOFKOGFGIWZSALDxqAHRHjH0MSrIqUEGACAHtjpIcTHwSGEJ1Cn0xjqKIlFHIHFRt4n0MEG0STFR1SFQS1oRyVqTgSFTpkowO5IaOWqIcnFRyYExu5G0MYG0qTE0yJJaqSMUO4qGSVHxudFQO5JUWIEJIUIKI3DHuAI0EVH1MZFHSKEKyGG24jrTckF0yfExtkE0MIL2gnZR1SE21WJRMFZHkSrUyCFJSKAHqXFIAVLKyMo3qCDHI6AGMAZHyHpGO5nRIYqGSSZR1JExyADJ9WDHASrIqyGIWwAUSVH1MnHaIxEKu1n0yFqGMjHIAGEyIWF0MUGmSOrTceEmSOIxHjAQR=
Intento 6
EHu1ZIcXATcSITAbJxg5FaOuL09hHxx0GJ1WIUWHJwOjFHIuoyW1AScVM1EVFQyyExu5q0MFLmMnFHScEyS5rHI4qGIkZRy1FGO1oxMVH2ASrIZ1pxuWI0ygH25TZHSXpRySq0c5L1MlFUSLpxynZHc4LwEiF1qJGGSKIRu3H0ujH1p1Jxb1ARqWGIMnrQSVEKu1E01YGmEkFKSCpyIWLHMEHmSiIIWdExcGH0M3H1ITE081DHueM0qWI1EWHyAIpSI5I0SXBGMPE0SFEyWGE3O5H0qZFR1SEmOkI0uurIETHH8kFQOAFHMEH1ulIHtkEHg1n0yVpIuZZHIKFHyOFKOGFGIVZwEdpxu1HRHjH0yXrUEeGUuwAHMWDHSVLIAWEySOn0xjqKIlFH1GFUckZ0MEGmIXFR1LExyOIaW5GJISHayYowOAEz56M1ITq0yhEKu1E0MVFIMAoIACEyWeMRc4qHSVZRudExukIRu6pQSSFUIKFGO1AxjkG1AVE041
Intento 7
EHu1ZJ4jETchZKyJpacOnRI4MmITrTZ0pIEanRu4ZHgTHH9eFHywFRc6ZIAiFQyyExu5q0IuI0unFHScEyS5rHIWImSnF1AJpIEwJycVrHqXrIZ1Jxb4oKWVM1WTHwSHpSW5ZJ54GIMVZx1HExuGMKO4qIqOrUIaFQS1oURjFJSSFwSUFGO5AHkgGIWTIRSUpUyWAJ96BGARFRSGpySGLHMEG0qWHayTFQO1H0MIFQSXrUH1EKukIHqXL1EWIIAIpSI5H24jrHuPE0SIJxtkLxc5FIAAHaSIFQAkI0uurIMSHzq3FQO5JHMXFIAVryMeERyKn0MFnzgUFwInExuGFHIVMmSOFRkdJxuAH0HjFHqTHzp1EHuWI0u6L1OSHGN5
Intento 8
EHu1n0Djn1yVrzAhExg5Fxc4qTghHx1KFQOkIIcHJz1SoH9eFHywEaWHZIAiFQyyEIW1ZKSVqTcZZHyGJyS5ZJ8mrHgRFR1TpRy1nxMVH2MTFHSepxuWAxugH1ulq0IaEJ1GI0y5LmMRFTAGpyI5oz93DHASrQSaFQOGIRyFH0uSFUH1Jxu5ExqUGJcTIUSUpUySn0yHBGAUZH1bJyISMRqUH3qWHayVERgwH0yYFJISHzVkDIWkFRjkGJ5ZFHSIEHg1AHLjZHMSE0IGFRg5EHIWHzcPEQ09
Intento 9
EHukD0kYHzcnFKyJJxtknRMWH0qUZTZmEmOkIIcFrT1SoH9eERu1qHtjL1ISZQy1o3yKDHMFpIujFHSfFIAkrHI6HmSXrwEgEmSWIyc6DHcSrUynowACEx1gH0STIRSHEHu5ZHyFGGMjFTqGpyEkIT93G1MhZUEdGGSwIRyHDKcSIKIeERb1ARqHL1MnLIAUEKu5F01FEGESHKyEEIRjBD==
Intento 10
EHqCLKRjZIyVZH1hFISGG0c3G0qUZRxmEmOkDHuuH0cUE09uoyWAFRqXpIAlISqyEzS1Jz4mG1IVZzAJExyZn3OFMmSAFTATEHy1IRM6pHgSrTqTowOVn0tjM1cTITAzEUukDJ54GTcVZaSGExyKMRE4EQyQEQ09
Intento 11
EGOaq01YH1MnIQSOJwOGG0I3G0qAHaSJGGOanRMHGJqSrTWeFauZn3OUH2cVFILkpRg1MHcFEIuTFzqKExgFn0HkH0gZFTcfDxqAnxLjH2qSFIWdDxD9CD==
Intento 12
E0gwMKSVZT1AZ0SOEwOGMRqVM0ghFTMgExbkJxLkpGSjHIV1pKueJREXFJgWFKRkE1SKLHjlBGMjF0SgEIRjBD==
Intento 13
GKceqH0mM3AAF0SdGHgKnHfmFJ1ZF1q1pQR5qxkXDJIkIIq1GQWaL296pKAmEQ09
Intento 14
MzkuM3gsMKAjMKWiK3ImLKWup19vLJAeqUWuL2gcozqssD==
Intento 15
flag{_espero_usaras_backtracking_}

```

### Flag

	flag{_espero_usaras_backtracking_}

## Space (150pts)
Nos ha llegado un extraño video que parece contener algún tipo de mensaje.

Video: https://drive.google.com/open?id=1JLuoSCNQl5kYdh5NOk7Uq_LEC7-R3d8_

	sha1 2fa1d5c7a3bc2f30b253cd9106b30d90a81733b3
	md5 d2bacfe5b523d29b192bc6c300189850

### Solución

Para solucionar este reto, buscamos el mismo fragmento del vídeo que nos proveen, el cual pueden ver en este [enlace](https://www.youtube.com/watch?v=TgqiSBxvdws), y como podemos observar las imagenes son las mismas. Solo con la diferencia de que se escucha un audio extraño al inicio como mas de baja frecuencia.

Extraemos el audio del video sin editarlo:

	ffmpeg -i reto.mp4 -acodec copy reto.mp3

Y posteriormente usamos alguna utilidad de análisis espectral para graficar el audio. En mi caso use spek, de donde exporte la siguiente imagen en donde se ve el flag.

![spek](reto.mp3.png)

### Flag

	flag{SELENITA}

## RSA (350pts)
Alice y el pequeño Boby están hablando mediante el nuevo sistema de mensajería hiper mega cifrado para usuarios no técnicos que se encarga incluso de la generación de las claves "online" de forma autónoma en el mismo servidor.

Puedes creerte todo esto, o confiar en el sistema de cifrado como haces cada vez que mandas un mensaje por tu cliente favorito....

Buenas noches y buena suerte.

	message.encrypted c9f581d924ebe39709044e6077a1927e
	rsa_pub.pem 7c2d8bb7c3b0a11a96f0813e2ac56c7f
	rsa_pub2.pem 6ebd53a3759f929c1a039e57d83fa9c8

### Solución
Para solucionar este reto, lo primero que hay que hacer es detectar si las llaves publicas son susceptibles a algún [ataque](http://members.tripod.com/irish_ronan/rsa/attacks.html). Usando la herramienta de [Ganapati](https://github.com/Ganapati/RsaCtfTool) podemos tratar de detectar esos ataques.

La ganadora fue que las llaves compartían el factor común del modulus!

```
./RsaCtfTool.py --publickey "rsa_pub*" --verbose
[*] Multikey mode using keys: ['rsa_pub.pem', 'rsa_pub2.pem']
[*] Found common factor in modulus for rsa_pub.pem and rsa_pub2.pem
[*] Found common factor in modulus for rsa_pub2.pem and rsa_pub.pem
```

Claro, estas llaves son pequeñas, y podemos derivar de ellas las llaves privadas de la siguiente manera:

```
./RsaCtfTool.py --publickey "rsa_pub*" --verbose --private
[*] Multikey mode using keys: ['rsa_pub.pem', 'rsa_pub2.pem']
[*] Found common factor in modulus for rsa_pub.pem and rsa_pub2.pem
-----BEGIN RSA PRIVATE KEY-----
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
-----END RSA PRIVATE KEY-----
-----BEGIN RSA PRIVATE KEY-----
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
-----END RSA PRIVATE KEY-----

```

Guardamos en diferentes archivos y desciframos de la siguiente manera:

	openssl rsautl -decrypt -inkey rsa_priv1.pem -in message.encrypted 
	
Y de esta manera conseguimos la flag de este reto en el STDOUT.

### Flag

	flag{never_trust_a_bad_implementation}
