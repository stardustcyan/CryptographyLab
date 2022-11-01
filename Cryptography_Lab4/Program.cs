using System.Numerics;

namespace Cryptography_Lab4;

public static class Program
{
    public static void Main(string[] args)
    {
        BigInteger plaintext = 200110602; // 学号作为明文
        Console.WriteLine("明文信息为：{0}", plaintext);

        for (int i = 1; i <= 3; i++)
        {
            var cryptography = new ElGamal();
            var ciphertext = cryptography.Encryption(plaintext, i);

            if (i == 3)
            {
                Console.WriteLine("此时将明文修改为：300110602");
                plaintext = 300110602;
            }

            if (cryptography.Verify(ciphertext, plaintext))
            {
                Console.WriteLine("第{0}次验证结果为真", i);
            }
            else
            {
                Console.WriteLine("第{0}次验证结果为假", i);
            }
        }
    }
}