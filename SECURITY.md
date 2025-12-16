# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 2.x     | :white_check_mark: |
| 1.x     | :x:                |

## Reporting a Vulnerability

Veriduct Prime is a security research tool. We take security issues seriously.

### For Vulnerabilities in Veriduct Prime Itself

If you discover a vulnerability in Veriduct Prime's code (e.g., the loader could be exploited, HMAC can be bypassed, etc.):

1. **Do NOT open a public issue**
2. Email: research@bombadil.systems
3. Include:
   - Description of the vulnerability
   - Steps to reproduce
   - Potential impact
   - Suggested fix (if any)

We will respond within 72 hours and work with you on remediation.

### For Detection/Bypass Techniques

If you discover how to detect Veriduct-processed binaries or bypass its protections:

1. **Public disclosure is welcome** — This is security research
2. Open an issue or submit a PR
3. We'll credit your work

This is the nature of security research. We want to know how this can be detected.

### For Misuse Reports

If you observe Veriduct being used maliciously:

1. Report to relevant authorities
2. We cannot control how open-source tools are used

## Scope

### In Scope
- Bugs in veriduct_prime.py
- Native loader vulnerabilities
- HMAC bypass techniques
- Keymap parsing issues
- C2 component vulnerabilities

### Out of Scope
- Detection techniques (welcome but not vulnerabilities)
- Expected behavior (format destruction is the feature)
- Social engineering
- Third-party dependencies (report upstream)

## Safe Harbor

We consider security research conducted in good faith to be authorized. We will not pursue legal action against researchers who:

- Act in good faith
- Avoid privacy violations
- Avoid data destruction
- Report findings responsibly

## PGP Key

For encrypted communication:

```
-----BEGIN PGP PUBLIC KEY BLOCK-----
Version: Keybase OpenPGP v1.0.0
Comment: https://keybase.io/crypto

xsFNBGlA7Q0BEACw4zK27oxYYTnwsUlNZIIu5lx07ndOfz838q/fXtR003CjMCpY
Nof2liCHhyib0kiQIh/84Zk3h1rOs/A/cQuKUKLnOmgE//kSgqjNMuMAhzYrEEan
xQFh9/CQt+JurDtoR4iRDt9VUkoXCO3zvNv1OniwgZqif0zHCLZhQkLFT4+OuiHg
mR4g+TSlSNKrnd7PXf5Q98uTJCqkRoXKpbZfkv5YVeUNpcI8xa6R+mAhDbS/d94U
Z8LIxgOXV7XyeB6bJiBeRKB+scFVkCkD59Oznrlr8mUOS0GmUC3kpee0kMh2ut/b
Rta2Fyg7mqXO4qZT4b1Y3PPPE4W1AdalZkfWDcE9AewPy0uvQBnz36eh7F38bSDD
UzriZ7M5rtCacB7dHadDZR38eVIpBbjijFgQSf2tT0c1kJHpI5dpAzAegEauHdkF
53oocxVSo838Q/4bMQigNGOX15Q6KhBIuHp4iuYjQpwdJn33TxJc9L2A6vRy3nX1
Y327FHbCWPTn8xeBxQllPxh7Cx3riWbDImXyLuvI3DOj4WQhuQoEzlYSrP45ibDa
rdsdd6Km2VeTuofoHZQmqBIIp6WjC4pGB79CHZCBbKnIdyNzed5SW0lp/ZoiO3zQ
nJrDNsfyGhk+jbup4hv1rBDAlJicI54loIkKwMsZld5J9kr8zd8BBGc+9wARAQAB
zSlDaHJpc3RvcGhlciBBeml6IDxjaHJpc0Bib21iYWRpbC5zeXN0ZW1zPsLBbQQT
AQoAFwUCaUDtDQIbLwMLCQcDFQoIAh4BAheAAAoJEIeUtzwWV0RP7wAP/3TvKF7g
e4QAUCYhXH/LvWHrEYrUcqPzhqNHebEddVj1cYWxHcMLQWklSVQ9CZAMM/uQj0gY
ZEovaDcrIKvI34ecN7rto3br+R1Mzd2MyGBcxQlV5cCfA6nH8AWJQ/sNQ3aU+Hb7
YGfml6IP297q5A53najfTZpq5tHKUNzRQjgLyTJ5IhOGV1lWbeci0X6hTbnnAS5l
j6PSJnCpdU/S/RxWM2HuYxT7IaYQAwlAo/jxC6j9dHvSgNM6tHfbVN33gqqzRksB
da9AbgIGCybnZv/XHK4zY38zagmFlWHxWCIQSrkSBdf9neLtA6WRuix6OFYDGiat
+jZ57n77euAehztWRpRhjDrTE6YTqJZmhQsI1W1zc07MH33R8+IYB41ehNiWnenp
EtYP6eKbYqR+liMziIQic+1mhWkZVQPd6/Vs2ljZ6qX3jYbzkdM8ddHPHe6s7u5y
fXd87IXN8neWfWCBANGGoZCQRxMH/EXrLVH2im9zvPf7/YU3U1+uE4xlWGNNmOfh
4H9998GX5alpJFi70Ay9FCQjjS3TNUzYGFRPUODwEGc5ch2Wn/AYF3mHdDHgF2KC
oW7L7ys6Rq0Z8zssWPomUf3dRs/7rK+rnYQVU680u+j7T6utvTVsGh6Dd9sbGq9F
WNvGgjaCKJM0olGMOAnVl1sdFf+9IuAUej9xzsFNBGlA7Q0BEADHgV6KEKvwqhC6
SQD4sRFIo6pTljFQ0/aA6sjbZuHkjUNeOuIcWKP3IK+9MF9Cz7QBny5ffelQPsFg
8t8FUOLKP281cespeC2SQ1ZG2tF1rPppRS+orH+yv5OhrIpZin3Vr2f8xr23b2/A
SMfZwNXidzl7C6mGBz+c61rD9+9q9jjcfo7Q141VNGjLRUKSVEszI9jV1OQVxt2Q
h1rDI+NI/VLzZ6Kh1i7EjEpEntUyf0SnA5tj7c6ZMENCTs1NQaioNGV5kAm4n5ht
o9fIobT4v0FXUoT11zlZx/SZZuhIcVUaXGTD3NUn4VWEMoaOw26TLeBzCqo2AKyy
cNzNh6zztUJn7mKQRRnxLKwupuIEcBPiCJ13qjUzEfXLOpWiGes3kNx81CJLPdGO
AJz8lk/ZHarnWQAAGURjmlz2ARWflEcu/YyplVy9ZUcYd/uS9UbEl4bP+ECAhEmN
ISb87E3fWmeSlifitg3vlAF8d3YxPGa6l2wixDW6+nC6AvHTVaz5TCleEQH6nqwj
Nb8kwJRlS5aQUX+iZZE2Yg2h2LOyBnPM/dhbMsIMzSWreTFIfc5A4oV1A5roAFnf
mhgiLyRFyHISZTGVBvOKJ76atpKnSPsAOoCwYHOORQUxNvboQOLHyszIqGG4bzSR
aEOGwpWHog5Dr56uabDJ2JvEoBh1RwARAQABwsOEBBgBCgAPBQJpQO0NBQkPCZwA
AhsuAikJEIeUtzwWV0RPwV0gBBkBCgAGBQJpQO0NAAoJELWOW9Agq3/F5oAQAL5S
X5rXucIKK1X/hyPnfD0V9tSDxeh1QMMbfdpAX4hzgIps+3CIw9SXJ4/3WN5ojEUm
2CLhpRkhuGDcStcMf1SnZE960J63lCJx4VCUwBmljUM5E6EaK9T04ocfTePxZ4CS
Zrsst/Gh68we6uYbf6yESsRwig5og7c6bRkdb0QHA/u7W/laJQ98GA2GFhDHbnVM
vLplmxzRfWufdJ5AJMf0/v9HEH4W7WbM4Ky+dxtElcImZEXY1RCfcyBiGY308DTd
kmxM3P4+IAzuqKA6/puqhTsPCnBtMZ5Tpzj5S2fhFWD1JDtWyRZy1Nc01aUpltJ9
iNlG50bXldW9ciLKdr24db82+XeM/24VWzKo9kJq51BJxO8ospBzaOFDQx8O8qaX
gbRDkpeN4YvP1jUepyPXY+WEFXtXGX5/PsIICLKFVnwbYroqBq8NZxAQoSZqtRBk
JI3W4d6u2cW+yOdlgz/w+Bm7f1XkU0jWl5IYMktQLQLmCg2fje0ZPE886NaUbkDz
M2d8bwNoVBLX03gA2weOMeKpPn7JLHHmzWzJLhyx5HEqVH9HfVWiNhKusAoX6ql1
1h4eThLSDRB0Epgi7kGpFnc95nJHT8Z+eOC3sBHfYDqu4gPCZeNpfmQ4+cqvqrz9
rrEYpZM159UsHJjL/SbWtIqafXjykFKFXWNzKkNOJJ4QAJ2UxAAy5/8uajwrjFPo
CfywYPlzfAKgukmjSfW4snEhp7SMktoMo0MeA7EG9YVka7PD8RdIPqu9+CPo4GKW
XAWIP9EAnhBSejHYgcOb9BxwzctBFswTVINrBLyjA3hdwCLajiwj7MTxMflyJ+7S
40nWlYx7+au1kUxlrgAbddq7VrjB6dczB9ZggaA0B+JuH+y1BLmvnY29D0w7u88n
9nZrTLueqGxdc/+Ha2SYmJKT3E2Km4RJA1HgyeAJFg6mQ8PmPdHvRSB47jEV79xc
X9ebovM+o5SSs+ue5NIohaA6jar21HWdbIGnISZQ1u+LusS5s1AHlJrwWrNXxqRK
iQ43Drl9kvjDPg/ZJTaaM4NchMkUBZ775QQEQvE1vBdEmxQFgp9orwaz9MgFY3lc
spFZHEnW3cEgMdFCfePC1tHdT46MuNq6o4Zl1I88IYvb7MOzXUORjn3fgM2EqS75
VcJwIGggwJhVi9OWmcUnAcfxZNP9+9++s4o+Go3/76kfH7x0NcJp0Kq4az7r/oDm
5mAtZEuG/vC6Ovfm1pG1lEuZxrmfUnvhfpMJGuE9rpD7mBh4g19zPl4bpqYGm264
05oyyWgGYSw5c9zbwGzVsTyNn3HWJAB1Rg/lDzfiRuRfJJZnXmMTCa3nN+h+U4Tq
XJySUejklzSQ8cKp/UgVQOPyzsFNBGlA7Q0BEACvtSPEP/VlqoG5mQBXNtKipwhW
ILwWmbWEjCH7F3XFexDe7dA+8NaL49j5S6v4n20bByli1FLNs9SXugmXW1yIaEMV
heXNLHnaNt0qS2sghhssB+S8HCq6V5+TyM5S55k9E4vQm+nl1Bp4Cx1AJiRL7vPJ
9M80QOEvW6d35ZKGvwDJUVoTgMkuuNymdgzpYal1t8+92AaKJCUwvv0IrWX8Dp2c
2Xg0dRPgziWZ74s1Jk1uCG9anhsEICtxhoo4HUFq4RJVhFe1CoAHyANABqR21Idr
6yYqLCOojxReaTLQkCGxX0wxWPVUtO/icaIRdiL4d2BKzrpoSq35/zpaEM0R0AqV
jsm7+fJIYHA2jKeCyZiRKnp7QktFWFe/fo/iDUUmRa4RH1sU7POBrqMJfVw17blU
iXL7iXLyGP9ITwpGXfaeLxALZcXGb7SJiXpf/QVigyJUAriOw33SYMJy2vRAYPiw
RutTfUCBMY/bDDIgKeyT+U2BuwHxQrPHMhRprKOQuIXt4611yD/4dLR7whizPA3B
7U/OVNSXl7uIY6nE+KYM1RbsFTgXz8pOd2TtKRCS92aN54S2U2CbAJ7UGSjcaevo
JJ1nPeHP0OuOhAQAnLfe5K5NYB9n2aXZ/tB5UNqr8CtZa55klpZK7xzgZirUsjL/
X+bCwJ2hS/ogvPBLOwARAQABwsOEBBgBCgAPBQJpQO0NBQkPCZwAAhsuAikJEIeU
tzwWV0RPwV0gBBkBCgAGBQJpQO0NAAoJEOh2hc3m9lEFoU4P/j7ai+TXVDlYNF85
yfKH2ZDD0yX0T3e+e4R/IVpiiEBubgFr4F+ki5nGZsRV+bX17cNG1inRf70f43/f
wpxsD+A9JhBmZ8imjCNg4szflhVspYJd53Fz04WH1P8/8IwcsMl63zsFoWqnbgz6
mw661m9HuM+ix6G+sctxB5rvBb89THkZMtUoHtpU1LIo5PjXCVzqLD2L0q0FrEzC
mR/cY7V7vzg8O3DTmAe5BHrdt0SuLC5+qxz4dhpe9ECP5IYnaiI6ea4cKWL8e+fV
swaZjCbZceiie/OfWXZ3H5s4kGzoz/Vs3otkI44237EvrQ2GeMZWsBpOe/BBZGJm
GUW7nZSyYbB+TBfY/iz6Ux+meCF4mKghQuJt0yBUjYwUm57rOPKHW2N9UmrNFByJ
LibnV9krsB0bF6tuJDujeCNUv0TFdECt4Y/jAakGUAZQWaFSraHVQYLj84GBk9Dl
YgZ6K8twEkgmMm1C3Jl+XJhG8SgC1Wcv7eCWk74ZCRXtkA8LBQcAV/yncYENRG89
S9RMEfHPhabS31/bCcODIIesvCba5gtdMKmeKv4IROP8NTvTnOfniW+nCpH3QiFs
Wl/Sc2MJUYWrh9Lv6HVMdjG7h0lnZ4euUGdoX2XzL5yeQzrg7kbvLmnKqqF80Jcr
i2qp6JNDij005hJek44WpR8iFfADQ8wP+gLptMbbIkruO6ArkiAvW137bxvK6Rde
3qp2cJnXHpVcv6doA8wlmXOkEJfc2Zqin/4Fvlt4NaVeZDliqxkZZjqXsOPaGNeZ
W5ro97NXvHmNb/O1wKvFUuHrUsNoWn4HT74gL3lMAlaJXf0usxAw4yqsZC70moBu
h7pf830MwlHCinE4y0VDlupDt3NLaHvJa5OtzVc4UwSYOR0HIM3DyyeXw03zytb9
QywPzRQpOvlkGHtoah+5AyCcOTOdNSwql6WdMCJUaVkdRfdNFJP4Bn3S5H2w4b/N
+rBqlTOfqSSBL5pDOvXi6X+dZAe6uJIhLyXrRsAgCOJeUU53rLHzTnQvbLbj/8lj
PXdrLKi41mtzzjwPjXE1i9PXxPvg/H0M03NRurPpq0MORXZBnPPB+rO7aAZH21dO
ixxZWWXbKyAx7gCPi+1/9bh2hK9F2zrD+V2mjpwHFpNQbSWA8Nq9UtK0rQe/n6Rg
ROIx4zS7tmkVwzEuSDrX0OAew+QI/sGd91ReWXdWjm/4FeC8Egp20e1jSYjpPqtk
K40ADUWnmuxAC6ttwubIqISLdWLA46dBC4nOxmdD2tXc1liAN5sgrwGIKjk2vF4k
iWsLN18fZv+MielNXIxuUWHPbCMVOBujMf6SGE2GNz3FFwRF4c9wPuaLKjvzgTdw
NTu7O6qMwDEJ
=d8oa
-----END PGP PUBLIC KEY BLOCK-----

```

## Acknowledgments

Security researchers who responsibly disclose vulnerabilities will be:
- Credited in security advisories
- Listed in SECURITY_ACKNOWLEDGMENTS.md
- Thanked publicly (unless anonymity requested)

---

Thank you for helping keep Veriduct Prime secure.
