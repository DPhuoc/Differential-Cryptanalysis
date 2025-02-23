from sage.all import *

r = 8

def fulladder(a, b, c):
    r = a + b
    s = a * b
    t = c * r 
    SUM = r + c
    c = -(-t * -s)
    return SUM, c

P = PolynomialRing(GF(2 ** 32), 'x')
x = P.gen()
f = x ** 3 + x ** 4
print(ZZ(f))