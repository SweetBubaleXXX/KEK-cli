KEY_ID_BYTES = b"jP\xd9o\x91(\xfe\x1f"

KEY_ID = KEY_ID_BYTES.hex()

KEY_SIZE = 2048

KEY_ENCRYPTION_PASSWORD = b"testpass"

SERIALIZED_PUBLIC_KEY = b"""\
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAuUFGKKHc4TJbzzXUnWGy
yPGXGpxkf0zUrWDz8cDMX0ukUNE+4EWpDqpp6hCohzfbrWdH9AYAA76YPMZrQ6KD
eXzCJUrC+9uZJEdCMEnSfEPEqBdG949pIM6881a1uKvO2elG2UbbK4Mqn2uFR+uC
aCuJlXaD1kJ1Uv3Pp5FhXzfG48RdjnNFpIB4YSqHguEvhW9jhJW/FR008KHmfONp
Ohb6GaxZKF7fGpQbgIujdD73t0W4eMC+1M7H0HkdiTjufCkHPjYfKX/yY+IzR5g+
orjErU10zk4IbkRrf5Rjn5fxz5IUBYlgEfk2eHxeZNEFdf78QaFHB47BNyQY1gD5
2QIDAQAB
-----END PUBLIC KEY-----
"""

SERIALIZED_PRIVATE_KEY = b"""\
-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQC5QUYoodzhMlvP
NdSdYbLI8ZcanGR/TNStYPPxwMxfS6RQ0T7gRakOqmnqEKiHN9utZ0f0BgADvpg8
xmtDooN5fMIlSsL725kkR0IwSdJ8Q8SoF0b3j2kgzrzzVrW4q87Z6UbZRtsrgyqf
a4VH64JoK4mVdoPWQnVS/c+nkWFfN8bjxF2Oc0WkgHhhKoeC4S+Fb2OElb8VHTTw
oeZ842k6FvoZrFkoXt8alBuAi6N0Pve3Rbh4wL7UzsfQeR2JOO58KQc+Nh8pf/Jj
4jNHmD6iuMStTXTOTghuRGt/lGOfl/HPkhQFiWAR+TZ4fF5k0QV1/vxBoUcHjsE3
JBjWAPnZAgMBAAECggEAG+Qq9vUftzwIvJLDNwq9iylscZI4Qz5DCvN85tn7KyHN
VGmciNGUGWQo3Bez99++EEZre97nY6jvbL8G6UDvgHv7EvhFkPvH+8FKwtBqg1EE
q7YNdjo+PrVBl3VnmK0tUHuhshbL6qot4aCjiWd408wyQ7F7Oef5mAwklnr56QbQ
F1wcB6v7VKYRV92lPZSgCxJT0lM+aLSlsrAtFuvBGrENx0S4xjS3Ga8T47VL+8SP
/0mGhtbY+CkTsDNX1T+43ZM+RbSCXb8oKEZHr5v+wDqCSbWkT8uYMqHT+debN8y9
HsFaA4Tr76s6krbIe2jcpxLevUkK6SMF2gkpL2DqzQKBgQDnCf7G1+CsWQ7JjCiy
GiYhjbsdQhGoZRu7K5xkChyKlCYtixc2EyFuh7XTKx3Xi3pk5lzQtzqdb4c2FlhC
GTJWvEWx441hBOeWHYfx5EoW+WwBCUs0NMBzMIwkqkd5T5nNgQ3RYFX67wbkVK2k
/UcmXeT40aPV5/ZfeqLbz/P34wKBgQDNRP9iXJhH3NsZFC8G9VSbdDR4yK0dW1HR
K3tbmybDFT2pfy8lV5GfoLFAw2e7vmlOCiGMV434iCyrCtETQYsx7vMWBggxW72l
YHfILOghK1RuOUxtwkNn/KzEangwqjsWwCTQfYhNLIQZlMNa7vaAeWHO660B0H2O
DIuIZ/BcEwKBgH/9h4j8eti/lXOOE9Vmqw0XiTsSKNoS+SPdawv4lgsnO2crkLZC
LtkekVnknumTuUBAZdaySuSArnUGN+qWLs7iCfIcT2wZ3XnJ7k/Q2kKT9oM0dNb9
CkhF8r01H9dSg6/W+KKvLbKPzE+doXyvW0Uj6v70lECh+li2hZYkQ9FlAoGBAIiO
oVN/hDMyo3OgsNRxO3MbsJi18Cz6hoif47YClpvrspTjLqsqAY/vaFxMYuNMfmPT
a5Qg3yr69LRpQsQLs51peMArDSJBBP5TGfzKmzcNy2J0rfrK5Or19r3IkuLVLPAq
rZMiIB4vQkZ+aCRDmyvHFKGCuhrd59krUVxSwV2PAoGBAJlta11O62tfI8zygqh8
xlYADbzAlONpkEaFaslWOWsPKzqZQkZZP8wmFM6bglBodYxOt9tIpFRwYb3osLg3
XVY3slto6PXY/0HUoUalMCZy8diZ0JbzvsIDI9K6WLH+PK+yLAROkWV/B/yA0VWr
XnOlyTrYtG8p1de+sz97yEyf
-----END PRIVATE KEY-----
"""

ENCRYPTED_PRIVATE_KEY = b"""\
-----BEGIN ENCRYPTED PRIVATE KEY-----
MIIFLTBXBgkqhkiG9w0BBQ0wSjApBgkqhkiG9w0BBQwwHAQIvQPK6H6RPYgCAggA
MAwGCCqGSIb3DQIJBQAwHQYJYIZIAWUDBAEqBBC2V7+ndwQUK3agYdbYl69bBIIE
0KvetzdYGFdeDtABbAPIC0qbcUA4KrPzXSpVAjws1EAV1Waw60mUex7o1SF1tkAe
dV4XOYDGbxX7gzoQq5w1/c9/XJSSioTcKu+QvOg+CKkHm7oV2gm8ixLDvM2lvPwR
AfQOYTN8za+zAXj3pY3HhjUhIPCY5rE2eC6XZpQFWVA9vcApbZHAdaYccyj+YwSh
4QR0/R7kUCf+CyAvRIuPythyCKqtZ9i24epcDUicSZeCC932qEAqKhHTOqDUN03N
tLbJ0GjKgLR18eMnOxOkTEzsB03IzixKHkBtZ6rA/D3m+WvZWlmomXNQPHOW84B5
/7DoG69c1Ts9cCijzZWHDuHGWA1/3vA1TFpoP5ur8zEXLFENY992kTzDvGccUWjp
eTYQnHuqrv+dXHYF199BtET72jUKZs2Q2u2oFhWSdwcENJ7r1McODs7D3Bi5/U9l
HMyHvwXtiZtEJx9JwEy7mK6hHG2Dv0eQkyv6gliL0TnoBzG7bXXe8pMTu32jd538
H93uc3LK3icgundsQw+I4rTGgH5h0CSFSwjAJVQJJsPLs8ZYfGuFhWTelrN73aXP
DCY3msLWLz9LVwUt3ep4H2YvSGkFSb88/QNrBBjTfNREsjsw5K+cDQg+5bNxlQDb
dyb7da1bOCF0jnFHsV0BMZssrQtIryhjaNGbjjCiLGzVjRpTCwnHZpw8TR+RMM7z
YZgW/8iC2bk11SrNNSN1oT+fF8xMkrG067RA8zWdcAvccWmoGdXFktyr7SGPVK46
scWCpn8vdtUZskTeiUXx8K8J8Fui3FXZs3VCahHM09ebgDGQlJ6k/tVvtkh06ZjP
hlmVDyQdE6nDIE8EuXX6noWKctgPT/dEi5u+6hEQZ1J7w8eYL8Mu2xlf/GILnXuP
zoZdcHrcnlx4yWpHnU8YuidfTNC7obnB7KpuZI71l5R+Iu2aLWZkKq2V+JCDheRa
KzsCOsIERlUyF1149OOu0SYkPYbnnfVMTFu/LMq+nMMG0pfMCYoLC7ePO5L4TBzA
8Ci4/9ekaFW/HdGu0MYemFz01xekOGPgHn3/YCs12pCv/xqXkl7I5JDTrdIgXttd
er9rlLlE/tVO99ndF1V0kOUGsuHUBTaYqchjiVtRuZ3cVBXIHclnOR+2mNGNi/LS
6Iqs8JrRuRFczsuWusYahNqOHRLAPtu1yGECDE+7S0u2+ypAnbQrxHbSBaM+cszL
neWNelQ9bzGWW7v2zrXrD7RBayxoIvh/Qls15wX1ASjsQ4C3k7INC52wNLAMbAcU
Jku/kFvAbYemG2itrg3TPrKGLH4xJRl7GqnfDLj+ImS/ghi+SxHm7ONuUUX2dW7t
ecJ2obExbX4xvs87zqhwWiRmQRPnVEiCs38QuY6TrvAIyJPqTSM09qmEvGglkc8U
YxJ8R/8NmtAnSVQwHhdvoCx+GszjWX1lmFwPOgkW7A7qr4Xjobz63rNNM1Y2iGL4
bNN4q8s+OBDVUhl7es14BQGijL9HKnU9zoBhaYXuv4FQsnGqqDRfbYXA1DeaKTKW
n0FFUzf9ZstZRB1P/P1EVU12iF5ivKNiPfDtriXBQDDpJ0XyqYgDQTG1mJf92nEP
qwEFDxkVzniWYHqn5d02kqTbGzrpCMrlGtwnVrGdR9g3
-----END ENCRYPTED PRIVATE KEY-----
"""

SAMPLE_MESSAGE = b"""\
Lorem ipsum dolor sit amet, consectetur adipiscing elit.
Nam rhoncus massa non leo condimentum lobortis.
Sed accumsan ante id lectus consectetur, vel maximus urna efficitur.
Integer pulvinar arcu quis justo ultrices mollis.
Aliquam in risus eu quam condimentum faucibus varius ultricies neque.
Sed placerat diam quis aliquet dignissim.
Integer convallis dui nec leo egestas euismod.
Vivamus interdum libero sed sapien vestibulum, sed maximus justo porta.
Morbi in erat egestas, laoreet velit fringilla, dictum est.
Vestibulum pulvinar risus sit amet ultrices ullamcorper.
Duis facilisis lacus eu scelerisque bibendum.
Pellentesque a mauris vitae augue hendrerit ullamcorper.
Fusce a velit a metus ullamcorper vehicula.
Pellentesque maximus felis non faucibus rutrum.
Cras nec ante non magna commodo volutpat sed sed sapien.
"""

MESSAGE_SIGNATURE_ENCODED = (
    "OV3m/u9cfq+aOrjD96o8XVhpf1IOSPmJaQhsfvdxxJ7Okgvx74isPoTDKyBjVQNHnQTJJ/Hk8WdQed5YwS"
    "BK1xb2zOJC5ewAUOa5ezH2UdQZ+kvH6xrznfN+ys68ubKPZ1EwyNuX6aw82UDkI/JShaW42lqCx8jjlZUH"
    "ULKQdLrWmAbPAm+LXg5T1K6hs1L2/3Nmg7JQahZNkQRjdLcLvDc88WZOGub6rsER/NHk2cS92Z3nKyal5u"
    "QWXxOmfBtFYDEF5G6WQdOpX8r2NS5SgNAzgsE9lDW9Lc4hrH3JkyxIV9PUIpt+q/SKNneXFkBt5ZA0JGoA"
    "UdzG+KXcAeNizQ=="
)

ENCRYPTED_MESSAGE = (
    "AWpQ2W+RKP4fJ5PBZ7A0jtq19iCR2rJ2qIThsPcMF4kG0tx/PKqabPQ2AA/UIIjZi6QU/xbkfcPfRcYWl/"
    "/15HikGlCt3o66XV4g30W/IzrO44d3+3cgsd1ai7qAW8q6zJmE+eOEE3UchKqma9WXxrxjAOdIQ7mNt9Zc"
    "5BGjWnNKO2w/+gcpEX/h8rVhe9xb2LyDrqaSvUA3ZespTC/qUXjwN12aDQnA910iymfkk7JKTakyhNI98K"
    "uCZ8EXFcQvFhcjDezFqw+d6g71FlgZWDlRENEouxBkUCFz+jSy5EdGliMIxVql0ZdHaaTWt81dr/PJbSfG"
    "qX/UDUkx9q0odbIjuPUzj6Jw9Ior0AQa5n4JRmz7lQRPDOR/Labyg/UU+07XVjHFxaVhaRjrmw5EeGHRrK"
    "FPf3vqr7By3o+bYda1yfPwqQxITG5FybngICQpYaPallFTMxrpWi0a7xHneF6be940Z3+ssOCa9JO6qfHP"
    "Igxrn2pQY+8DWxNodSAEuap48mXEXcjWlfns/YnIrG8ZK5GuabdZfYnJPIBDNlKHPr9xSnZUUrvqyAzWkv"
    "BIbueV+AEQ0jZuoqM+NJsuSWBAktPktsM9YI5E5Yz9jvPJCQa7uhu1f+qoVS9vcP+mjpp48kHy0/NrbKPy"
    "pDc4z1TqLjA+aN8t16zOXwq/dXs25mLf+kvgw7nTx/L7Lse61Ko0Iu3f1r2mM7a38Z3l1lgCl0mM2oqxdW"
    "wLP2I221GVjhvaSCkelKBu0yFV+snM7Cf2XhUkANSpIJHZV2EGHHjzb9Zi9P4D7f/uV7IJO1b4O7KYujM3"
    "z/V3UC4dvKR86+F2siOWi24dyb0kElMG01AqseqiDCNns8nk7Q1wwCwBzXMVdts8YD8ldH/pm6DzQmFO9X"
    "/71sh+kGoSXRAdPhpLoi2jlGr72CgzNXgRwP9CCeOcPHsob7q6VYxxotyL0CPPaOYbIXOOwTJdCMrw/NKe"
    "vzBaroIoU69nJTkP4Y3z9y/2BAXkB7wgBO0d9VllxBLfD7S4yChP055p4gq5IoxBB0XIZ7hVl08Q6mhWvq"
    "ZkH6lHB5Wu6l0kfbmz31LE8zxQ7Q0ygFHtdLDSgeOn6ETa1n6eJhmO2BgZCvvESsG+nonWuT0gqfJBEkrW"
    "ESgYJJUVEBOONtvUSD15K3d8Jncxy2aquWs1QU43AcaoHcRcbh9+Vny76H77NlLwoUoPF4y2FQcsgh9j3G"
    "Wj4E9qa3H9m6IXERY75EShcGI3J8DWNdzRUyxjKNC5ol1nt6pRfotwBLnF4B6GZS/xJXJP6Y9UCH2M8rT0"
    "4TKhd9z+ftupI+vPMEYorNbBVjNjjjTn7UWXvQ+01VAyVsDBJtP6zfxgYt1jGf7KtqPjT5IR3VNl7ablaD"
    "OeNf/RfMvHOUzDSwpzKKe/7DocTxnikx71GzG0UfZWPmUSL9GFQ643g6wue6vWCpqabHM="
)

SAMPLE_SETTINGS = {
    "default": KEY_ID,
    "public": [KEY_ID],
    "private": [KEY_ID],
}
