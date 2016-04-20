package io.github.hugoatease.anonymonkey;

import org.apache.commons.codec.binary.Hex;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Random;
import java.util.Vector;

public class Ring {
    private KeyPair[] k;
    private int l;
    private int n;
    private BigInteger q;
    private BigInteger p;

    public Ring(KeyPair[] k, int L) {
        this.k = k;
        this.l = L;
        this.n = k.length;
        this.q = BigInteger.valueOf(1).shiftLeft(L - 1);
    }

    public Vector<BigInteger> sign(String m, int z) {
        permut(m);
        Vector<BigInteger> s = new Vector<>(this.n);
        BigInteger u = new BigInteger(this.l, new Random());
        BigInteger v = E(u);
        BigInteger c = v;

        for (int i=0; i < this.n; i++) {
            s.add(null);
            s.set(i, new BigInteger(this.l, new Random()));
            BigInteger e = g(s.get(i), ((RSAPublicKey) this.k[i].getPublic()).getPublicExponent(), ((RSAPublicKey) this.k[i].getPublic()).getModulus());
            v = E(v.xor(e));
            if ((i+1) % this.n == 0) {
                c = v;
            }
        }

        s.set(z, g(v.xor(u), ((RSAPrivateKey) this.k[z].getPrivate()).getPrivateExponent(), ((RSAPublicKey) this.k[z].getPublic()).getModulus()));
        Vector<BigInteger> result = new Vector<>(this.n + 1);
        result.add(c);
        for (int index=1; index < this.n + 1; index++) {
            result.add(index, s.get(index-1));
        }

        return result;
    }

    private BigInteger g(BigInteger x, BigInteger e, BigInteger n) {
        BigInteger[] division = x.divideAndRemainder(n);
        BigInteger q = division[0];
        BigInteger r = division[1];

        BigInteger result;

        int comparison = q.add(BigInteger.ONE).multiply(n).compareTo((BigInteger.ONE.shiftLeft(this.l)).subtract(BigInteger.ONE));
        if (comparison == -1 || comparison == 0) {
            result = q.multiply(n).add(r.modPow(e, n));
        }
        else {
            result = x;
        }

        return result;
    }

    private BigInteger E(BigInteger x) {
        String msg = x.toString() + this.p.toString();
        try {
            MessageDigest sha1 = MessageDigest.getInstance("SHA-1");
            sha1.update(msg.getBytes());
            return new BigInteger(1, sha1.digest());
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        return null;
    }

    private void permut(String m) {
        try {
            MessageDigest sha1 = MessageDigest.getInstance("SHA-1");
            sha1.update(m.getBytes());
            this.p = new BigInteger(1, sha1.digest());
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
    }
}
