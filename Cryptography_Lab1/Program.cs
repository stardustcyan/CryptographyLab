namespace CryptographyLab;

public class Program {
    private static string? key;
    private const int MAXN = 1024;

    /**
     * 从控制台输入读取明文
     *
     * @ret string 读取的明文内容
     * @ret int    读取的明文长度
     */
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
    
    /**
     * 进行AES加密，并将加密结果写入本地文件
     */
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
        PrintASCII(cryptoResult);

        Console.Write("请输入你想要写进的文件名，比如'test.txt':");
        string? fileName = Console.ReadLine();
        if (fileName != null)
        {
            WriteStrToFile(cryptoResult, fileName);
            Console.WriteLine("已经将密文写进" + fileName + "中了,可以在运行该程序的当前目录中找到它。");
        }
    }
    
    /**
     * 从本地文件中读入密文
     *
     * @param fileName 本地文件地址
     * @ret   string   读取的密文内容
     */
    private static string ReadStrFromFile(string fileName)
    {
        StreamReader sr;
        try
        { 
            sr = new StreamReader(fileName);
        }
        catch (FileNotFoundException e)
        { 
            Console.WriteLine("打开文件出错，请确认文件存在当前目录下！");
            return "";
        }

        var rdData = sr.ReadLine();
        var res = rdData ?? "";
        if (res is { Length: > MAXN })
        {
            Console.WriteLine("解密文件过大！");
            return "";
        }
        sr.Close();

        return res;
    }
    
    /**
     * 对密文进行解密，并将解密结果写入本地文件中
     */
    private static void DeAesFile()
    {
        Console.WriteLine("请输入要解密的文件名，该文件必须和本程序在同一个目录");
        string? fileName = Console.ReadLine();
        if (fileName != null)
        {
            string c = ReadStrFromFile(fileName);
            Console.WriteLine("开始解密.........");
            string cryptoResult = AES.DeAes(c, key);
            Console.Write("解密后的明文ASCII为：");
            PrintASCII(cryptoResult);
            Console.WriteLine("明文为：{0}", cryptoResult);
            WriteStrToFile(cryptoResult, fileName);
            Console.WriteLine("现在可以打开{0}来查看解密后的密文了！", fileName);
        }
    }
    
    /**
     * 将字符串写入文件
     *
     * @param str      要写入的字符串内容
     * @param fileName 写入的目标文件
     */
    private static void WriteStrToFile(string str, string fileName)
    {
        StreamWriter sw = new StreamWriter(fileName);
        sw.WriteLine(str);
        sw.Close();
    }
    
    /**
     * 在控制台中输出字符串对应的ASCII值
     *
     * @param str 输出的字符串
     */
    private static void PrintASCII(string str)
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
        Console.WriteLine("是否开始解密？1.解密 2.退出");
        var choice = int.Parse(Console.ReadLine());
        switch (choice)
        {
            case 1:
                DeAesFile();
                break;
            default:
                return;
        }
    }
}