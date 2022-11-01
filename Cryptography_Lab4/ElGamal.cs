using System.Numerics;

namespace Cryptography_Lab4;

public class ElGamal
{
    public BigInteger P, G, Y;

    private BigInteger _x;
    
    /**
     * 从Lab2-RSA中继承下来的大随机数生成
     *
     * @param max 随机数的上限
     *
     * @return 生成的大随机整数
     */
    private BigInteger RandomBigNumberGenerator(BigInteger max)
    {
        BigInteger rLength = max.GetBitLength();
        
        BigInteger ret = 0;
        for (int i = 0; i < rLength; i++)
        { 
            ret = ret * 10 + (new Random()).Next(0, 9);
        }

        return ret % max + 1;
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
                    return false;
                }

                x = y;
                tu <<= 1;
            }

            if (x != 1)
            {
                return false;
            }
        }

        return true;
    }

    private BigInteger PrimitiveRoot(BigInteger n)
    {
        var k = (n - 1) >> 1;

        for (int i = 2; i < n; i++)
        {
            if (BigInteger.ModPow(i, k, n) != 1)
            {
                return i;
            }
        }

        return -1;
    }
    
    private static BigInteger Gcd(BigInteger x, BigInteger y)
    {
        if (y == 0)
        {
            return x;
        }

        return Gcd(y, x % y);
    }
    
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
     * 构造函数，生成公钥P, G, Y以及私钥x
     */
    public ElGamal()
    {
        do
        {
            P = RandomBigNumberGenerator(10000000000);
        } while (!Miller_Rabin(P));

        G = PrimitiveRoot(P);

        _x = RandomBigNumberGenerator(P - 1);
        Y = BigInteger.ModPow(G, _x, P);
        
        Console.WriteLine("P = {0}, G = {1}, Y = {2}", P, G, Y);
        Console.WriteLine("x = {0}", _x);
    }

    public BigInteger[] Encryption(BigInteger m, int times)
    {
        BigInteger k;
        for (k = 2; k < P - 1; k++)
        {
            if (new Random().Next() % 2 == 1 && Gcd(k, P - 1) == 1)
            {
                break;
            }
        }
        Console.Write("第{0}次加密: k = {1}, ", times, k);

        BigInteger[] ret = new BigInteger[2];
        ret[0] = BigInteger.ModPow(G, k, P);
        ret[1] = (GetInverse(k, P - 1) * (m - _x * ret[0])) % (P - 1);
        while (ret[1] < 0)
        {
            ret[1] += P - 1;
        }
        
        Console.WriteLine("r = {0}, s = {1}", ret[0], ret[1]);

        return ret;
    }

    public bool Verify(BigInteger[] c, BigInteger m)
    {
        var vLeft = (BigInteger.ModPow(Y, c[0], P) * BigInteger.ModPow(c[0], c[1], P)) % P;
        var vRight = BigInteger.ModPow(G, m, P);

        return vLeft == vRight;
    }
}