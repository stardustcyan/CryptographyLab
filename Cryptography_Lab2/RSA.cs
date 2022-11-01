using System.Numerics;
using System.Security.Cryptography;

namespace Cryptography_Lab2;

public class Rsa
{
    private const int MaxKeyLength = 128;
    
    private BigInteger _e = 3;
    private BigInteger _d;
    private BigInteger _n;

    private HashSet<BigInteger> _primeSet;

    /**
     * 求最大公约数
     *
     * @param x
     * @param y
     *
     * @return 两个参数的最大公约数
     */
    private static BigInteger Gcd(BigInteger x, BigInteger y)
    {
        if (y == 0)
        {
            return x;
        }

        return Gcd(y, x % y);
    }

    /**
     * 扩展欧几里得算法
     */
    private static void ExGCD(BigInteger a, BigInteger b, ref BigInteger x, ref BigInteger y)
    {
        if (b == 0)
        {
            x = 1;
            y = 0;
            return;
        }

        ExGCD(b, a % b, ref y, ref x);
        y -= a / b * x;
    }

    private static BigInteger GetInverse(BigInteger a, BigInteger b)
    {
        BigInteger x = 0, y = 0;
        ExGCD(a, b, ref x, ref y);

        return (x + b) % b;
    }

    /**
     * 随机大整数生成
     *
     * @param length 随机数的长度
     */
    private BigInteger RandomBigNumberGenerator(int length)
    {
        BigInteger ret = 0;
        do
        {
            ret = 0;
            for (int i = 0; i < length; i++)
            { 
                ret = ret * 10 + (new Random()).Next(0, 9);
            }
        } while (_primeSet.Contains(ret));

        return ret;
    }
    
    /**
     * Miller-Rabin算法判断质数
     *
     * @param test 被测试的大整数
     *
     * @return     该数是否为质数
     */
    private bool Miller_Rabin(BigInteger test)
    {
        if (test < 2)
        {
            return test == 2;
        }

        if (test % 2 == 0)
        {
            _primeSet.Add(test);
            return false;
        }

        var u = test - 1;
        while (u % 2 == 0)
        {
            u >>= 1;
        }

        for (int i = 1; i <= 10; i++)
        {
            var a = (new Random()).Next() % test;
            var x = BigInteger.ModPow(a, u, test);

            var tu = u;
            while (tu < u)
            {
                var y = x * x % test;
                if (y == 1 && x != 1 && x != test - 1)
                {
                    _primeSet.Add(test);
                    return false;
                }

                x = y;
                tu <<= 1;
            }

            if (x != 1)
            {
                _primeSet.Add(test);
                return false;
            }
        }

        return true;
    }

    /**
     * 生成密钥
     */
    private void GenerateKeys()
    {
        BigInteger p, q;
        Console.WriteLine("正在生成质数p...");
        p = 5;
        /*
        while (!Miller_Rabin(p))
        {
            p++;

            if (p.ToString().Length > MaxKeyLength)
            {
                BigInteger tmp;
                do
                {
                    tmp = RandomBigNumberGenerator(MaxKeyLength);
                } while (tmp >= p);

                p = tmp;
            }
        }

        Console.WriteLine("正在生成质数q...");
        */
        q = 11;
        /*
        while (!Miller_Rabin(q))
        {
            q++;

            if (q.ToString().Length > MaxKeyLength)
            {
                BigInteger tmp;
                do
                {
                    tmp = RandomBigNumberGenerator(MaxKeyLength);
                } while (tmp >= q);

                q = tmp;
            }
        }
        */

        _n = p * q;
        var phiN = (p - 1) * (q - 1);
        
        /*
        do
        {
            _e = RandomBigNumberGenerator(phiN.ToString().Length) % (phiN - 2) + 2;
        } while (Gcd(_e, phiN) != 1);
        */

        _d = GetInverse(_e, phiN);
    }

    private int CharToInt(char ch)
    {
        if (ch >= 'a' && ch <= 'z')
        {
            return ch - 'a' + 10;
        }

        if (ch <= '9' && ch >= '0')
        {
            return ch - '0';
        }

        if (ch <= 'Z' && ch >= 'A')
        {
            return ch - 'A' + 36;
        }

        if (ch == ',')
        {
            return 62;
        }

        if (ch == '=')
        {
            return 63;
        }

        return 64;
    }

    private String IntToChar(int ch)
    {
        if (ch >= 0 && ch <= 9)
        {
            return ((char)(ch + '0')).ToString();
        }

        if (ch >= 10 && ch <= 35)
        {
            return ((char)(ch - 10 + 'a')).ToString();
        }

        if (ch >= 36 && ch <= 61)
        {
            return ((char)(ch - 36 + 'A')).ToString();
        }

        if (ch == 62)
        {
            return ",";
        }

        if (ch == 63)
        {
            return "=";
        }

        return "";
    }

    public BigInteger[] Encryption(String content)
    {
        if (content.Length % 2 != 0)
        {
            content += "$";
        }

        BigInteger[] ans = new BigInteger[content.Length >> 1];
        for (int i = 0; i < content.Length; i += 2)
        {
            BigInteger contentPart = CharToInt(content[i]) * 100;
            contentPart += CharToInt(content[i + 1]) % 100;

            contentPart = BigInteger.ModPow(contentPart, _e, _n);
            ans[i >> 1] = contentPart;
        }

        return ans;
    }

    public String Decryption(BigInteger[] ciphertext)
    {
        String ret = "";
        foreach (var i in ciphertext)
        {
            var contentPart = BigInteger.ModPow(i, _d, _n);
            var content = contentPart.ToString();
            while (content.Length < 4)
            {
                content = content.Insert(0, "0");
            }
            ret += IntToChar((content[0] - '0') * 10 + (content[1] - '0'))
                   + IntToChar((content[2] - '0') * 10 + (content[3] - '0'));
        }

        return ret;
    }

    public Rsa()
    {
        _primeSet = new HashSet<BigInteger>();
        GenerateKeys();
    }
}