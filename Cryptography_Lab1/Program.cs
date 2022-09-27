namespace CryptographyLab;

public class Program {
    private static string? key;
    private const int MAXN = 1024;

    private static Tuple<string, int> ReadPlainText()
    {
        string? res;
        while (true)
        {
            res = Console.ReadLine();

            if (res.Length != 0 && res.Length % 16 == 0)
            {
                Console.WriteLine("你输入的明文为：" + res);
                break;
            }
            else
            {
                Console.WriteLine("明文字符长度必须为16的倍数,现在的长度为" + res.Length.ToString());
            }
        }

        return new Tuple<string, int>(res, res.Length);
    }

    private static void AesStrToFile()
    {
        string plainText;
        Console.Write("请输入你的明文，明文字符长度必须为16的倍数:");
        Tuple<string, int> res = ReadPlainText();
        plainText = res.Item1;

        Console.WriteLine("轮密钥..................");
        string cryptoResult = AES.Aes(plainText, key);
        Console.WriteLine("进行AES加密..................");
        Console.Write("加密完后的密文的ASCCI为：");
        PrintASCCI(cryptoResult);

        Console.Write("请输入你想要写进的文件名，比如'test.txt':");
        string? fileName = Console.ReadLine();
        if (fileName != null)
        {
            WriteStrToFile(cryptoResult, fileName);
            Console.WriteLine("已经将密文写进" + fileName + "中了,可以在运行该程序的当前目录中找到它。");
        }
    }

    private static void WriteStrToFile(string str, string fileName)
    {
        StreamWriter sw = new StreamWriter(fileName);
        sw.WriteLine(str);
        sw.Close();
    }

    private static void PrintASCCI(string str)
    {
        foreach (var t in str)
        {
            var c = (int)t;
            c = c & 0x000000ff;
            Console.Write("0x" + c.ToString("x") + " ");
        }

        Console.WriteLine();
    }

    public static void Main(string[] args)
    {

        Console.WriteLine("************************$声明信息$****************************");
        Console.WriteLine("版权声明：未经授权，禁止传播、使用和用于商业用途");
        Console.WriteLine("使用说明：本程序是AES密码演示程序。");
        Console.WriteLine("**********************$声明信息$******************************");
        Console.WriteLine("================AES密码算法程序演示================\n");

        while (true)
        {
            Console.Write("请输入16个字符的密钥：");
            key = Console.ReadLine();

            if (key.Length != 16)
            {
                Console.WriteLine("请输入16个字符的密钥,当前密钥的长度为" + key.Length.ToString());
            }
            else
            {
                Console.WriteLine("你输入的密钥为：" + key);
                break;
            }
        }
        AesStrToFile();
    }
}