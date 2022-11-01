using System.Numerics;

namespace Cryptography_Lab2;

public class Program
{
    private const string fileName = "lab2-Plaintext.txt";

    private static string ReadPlainText()
    {
        StreamReader sr = new StreamReader(fileName);
        return sr.ReadLine() ?? "";
    }
    private static void PrintCryptionResult(BigInteger[] text)
    {
        Console.WriteLine("RSA加密结果为：");
        foreach (var i in text)
        {
            Console.Write(i + " ");
        }
    }

    private static string Remove(string original)
    {
        string ret = "";

        for (int i = 0; i < original.Length; i++)
        {
            if ((original[i] >= 'a' && original[i] <= 'z') ||
                (original[i] >= 'A' && original[i] <= 'Z') ||
                (original[i] >= '0' && original[i] <= '9') ||
                (original[i] == ',' && original[i] == '='))
            {
                ret += original[i];
            }
        }

        return ret;
    }
    
    public static void Main(string[] args)
    {
        var rsa = new Rsa();
        
        Console.WriteLine("正在读取明文...");
        var content = "9";
        
        Console.WriteLine("读取的明文内容为：{0}", content);
        content = Remove(content);
        
        var ciphertext = rsa.Encryption(content);
        PrintCryptionResult(ciphertext);
        
        Console.WriteLine("解密结果为： " + rsa.Decryption(ciphertext));
    }
}