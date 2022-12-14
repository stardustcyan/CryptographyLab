namespace CryptographyLab;

public class AES {
    static int[] w;

    // Sç
    static int[,] S = new int[16, 16]
    {
        {0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76},
        {0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0},
        {0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15},
        {0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75},
        {0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84},
        {0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf},
        {0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8},
        {0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2},
        {0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73},
        {0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb},
        {0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79},
        {0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08},
        {0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a},
        {0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e},
        {0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf},
        {0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16}
    };

    // éSç
    static int[,] S2 = new int[16, 16]
    {
        {0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb},
        {0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb},
        {0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e},
        {0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25},
        {0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92},
        {0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84},
        {0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06},
        {0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b},
        {0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73},
        {0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e},
        {0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b},
        {0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4},
        {0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f},
        {0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef},
        {0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61},
        {0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d}
    };

    // ċĉ··ċèĤççİéµ
    static int[,] colM = new int[4, 4]
    {
        {2, 3, 1, 1},
        {1, 2, 3, 1},
        {1, 1, 2, 3},
        {3, 1, 1, 2}
    };

    // éċĉ··ċèĤççİéµ
    static int[,] deColM = new int[4, 4]
    {
        {0xe, 0xb, 0xd, 0x9},
        {0x9, 0xe, 0xb, 0xd},
        {0xd, 0x9, 0xe, 0xb},
        {0xb, 0xd, 0x9, 0xe}
    };

    // ċ¸¸éè½?ċĵèĦ¨ïĵċŻé?ĉċħç¨
    static uint[] Rcon = new uint[11]
    {
        0x00000000,
        0x01000000, 0x02000000,
        0x04000000, 0x08000000,
        0x10000000, 0x20000000,
        0x40000000, 0x80000000,
        0x1b000000, 0x36000000
    };

    /**
     * è·ċĉ´ċĉ°ĉ?çä½8ä½çċ·Ĥ4ä¸Şä½
     *
     * @param num è?ċ?ĉ°ĉ?
     * @ret   int è·ċè?ċ?ĉ°ĉ?çċ·Ĥċä½
     */
    private static int GetLeft4Bit(int num)
    {
        return (num & 0x000000f0) >> 4;
    }

    /**
     * è·ċĉ´ċĉ°ĉ?çä½8ä½çċ³4ä¸Şä½
     *
     * @param num è?ċ?ĉ°ĉ?
     * @ret   int è?ċ?ĉ°ĉ?çċ³ċä½
     */
    private static int GetRight4Bit(int num)
    {
        return num & 0x0000000f;
    }

    /**
     * ĉ ıĉ?ç´˘ċĵïĵäğSçä¸­è·ċ?ċç´ 
     *
     * @param index Sççä½ç½?ċĉ 
     * @ret   int   SçċŻıċşä½ç½?çĉ°ċĵ
     */
    private static int GetNumFromSBox(int index)
    {
        return S[GetLeft4Bit(index), GetRight4Bit(index)];
    }

    /**
     * ĉ ıĉ?ç´˘ċĵïĵäğéSçä¸­è·ċ?ċç´ 
     *
     * @param index éSççä½ç½?ċĉ 
     * @ret   int   éSçċŻıċşä½ç½?çĉ°ċĵ
     */
    public static int GetNumFromS1Box(int index)
    {
        return S2[GetLeft4Bit(index), GetRight4Bit(index)];
    }

    /** GF(2^8)ĉéċä¸ç2*s
     * ċ¤éĦıċĵèĦ¨ç¤şïĵx * f(x)
     * ċĉ° s: ċ¤éĦıċĵf(x)çäşèżċĥèĦ¨ç¤ş
     */
    private static int GFMul2(int s)
    {
        int result = s << 1;
        int a7 = result & 0x00000100;

        if(a7 != 0)
        {
            result = result & 0x000000ff;
            result = result ^ 0x1b;
        }

        return result;
    }

    /** GF(2^8)ä¸çäşċäıĉ³èżç?
     *  ċĉ° n: çĴĴä¸ĉä½ĉ°ïĵä¸ċ¤§äş16
     *  ċĉ° s: çĴĴäşĉä½ĉ°ïĵċŞäĵċĉä½ċ­èïĵĉŻçĞGF(2^8)ä¸­ċŞĉ8ä¸Şç³ğĉ°
     */
    private static int GFMul(int n, int s)
    {
        n &= 0x0f;
        s &= 0xff;
        int sum = s,
        result = 0;

        while (n != 0) {
            if ((n & 1u) != 0) {
                result = (result ^ sum);
            }
            n = (n >> 1);
            sum = GFMul2(sum);
        }
        return result;
    }

    /**
     * ĉä¸ä¸Şċ­çĴĤè½Ĵċĉĉ´ċ
     *
     * @param c   è?ċ?ċ­çĴĤ
     * @ret   int è?ċ?ċ­çĴĤASCIIç ċĵ
     */
    private static int GetIntFromChar(char c)
    {
        return ((int)c) & 0x000000ff;
    }

    /**
     * ĉ16ä¸Şċ­çĴĤè½Ĵċĉ4X4çĉ°çğïĵ
     * èŻ?çİéµä¸­ċ­èçĉċéĦşċşä¸şäğä¸ċ°ä¸ïĵäğċ·Ĥċ°ċ³ä?ĉĴĦĉċ?
     * pa = [
     *  [ str[0], str[4], str[8], str[12] ],
     *  [ str[1], str[5], str[9], str[13] ],
     *  [ str[2], str[6], str[10],str[14] ],
     *  [ str[3], str[7], str[11],str[15] ]
     * ]
     */
    private static int[,] ConvertToIntArray(string str)
    {
        int[,] pa = new int[4, 4];
        int k = 0;
        for (int i = 0; i < 4; i++)
        {
            for(int j = 0; j < 4; j++)
            {
                pa[j, i] = GetIntFromChar(str[k]);
                k++;
            }
        }

        return pa;
    }

    /**
     * ĉèżçğ­ç4ä¸Şċ­çĴĤċċıĥĉä¸ä¸Ş4ċ­èçĉ´ċ
     */
    public static int GetWordFromStr(string str)
    {
        var one = GetIntFromChar(str[0]);
        one = one << 24;
        var two = GetIntFromChar(str[1]);
        two = two << 16;
        var three = GetIntFromChar(str[2]);
        three = three << 8;
        var four = GetIntFromChar(str[3]);
        return one | two | three | four;
    }

    /**
     * ĉä¸ä¸Ş4ċ­èçĉ°ççĴĴä¸?äş?ä¸?ċä¸Şċ­èċċşïĵ
     * ĉ?ċ?ä¸ä¸Ş4ä¸Şċç´ çĉ´ċĉ°çğéé˘?
     */
    private static int[] SplitIntToArray(int num)
    {
        int[] array = new int[4];
        var one = num >> 24;
        array[0] = one & 0x000000ff;
        var two = num >> 16;
        array[1] = two & 0x000000ff;
        var three = num >> 8;
        array[2] = three & 0x000000ff;
        array[3] = num & 0x000000ff;

        return array;
    }

    /**
     * ĉĉ°çğä¸­ççĴĴä¸?äş?ä¸ċċċç´ ċċĞä½ä¸ş
     * 4ċ­èĉ´ċççĴĴä¸?äş?ä¸ċċċ­èïĵċċıĥĉä¸ä¸Ş4ċ­èĉ´ċ
     */
    private static int MergeArrayToInt(int[] array)
    {
        int one = array[0] << 24;
        int two = array[1] << 16;
        int three = array[2] << 8;
        int four = array[3];
        return one | two | three | four;
    }

    /**
     * ċ­èĉżĉ˘
     *
     * @param array éèĤè˘Ğĉżĉ˘çĉ°çğ
     */
    private static int[,] SubBytes(int[,] array)
    {
        for (int i = 0; i < 4; i++)
            for (int j = 0; j < 4; j++)
                array[i, j] = GetNumFromSBox(array[i, j]);
        return array;
    }

    /**
     * éċ­èĉżĉ˘
     *
     * @param array éèĤèżèĦéċ­èĉżĉ˘ççİéµ
     */
    public static int[,] DeSubBytes(int[,] array)
    {
        int[,] res = new int[4, 4];
        for (int i = 0; i < 4; i++)
        {
            for (int j = 0; j < 4; j++)
            {
                res[i, j] = GetNumFromS1Box(array[i, j]);
            }
        }

        return res;
    }

    /**
     * ċ°ĉ°çğä¸­çċç´ ċ?ŞçŻċ·Ĥç§ğstepä¸Ş
     *
     * @param array éèĤç§ğċ¨çĉ°çğ
     * @param step  ç§ğċ¨çĉ­?ĉ°
     */
    private static int[] LeftLoop4Int(int[] array, int step)
    {
        int[] newArray = new int[4];

        for (int i = 0; i < 4; i++)
            newArray[(i + 4 - step) % 4] = array[i];

        return newArray;
    }

    /**
     * ċ°ĉ°çğä¸­çċç´ ċ?ŞçŻċ³ç§ğstepĉĴĦ
     *
     * @param array éèĤç§ğċ¨çĉ°çğ
     * @param step  ç§ğċ¨çĉ­?ĉ°
     */
    private static int[] RightLoop4Int(int[] array, int step)
    {
        int[] res = new int[4];
        for (int i = 0; i < 4; i++)
        {
            res[(i + step) % 4] = array[i];
        }

        return res;
    }

    /**
     * èĦç§ğä½
     *
     * @param array éèĤèżèĦèĦç§ğä½ççİéµ
     */
    private static int[,] ShiftRows(int[,] array)
    {
        int[,] resArray = new int[4, 4];
        for (int i = 0; i < 4; i++)
            for (int j = 0; j < 4; j++)
                resArray[i, (j + 4 - i) % 4] = array[i, j];

        return resArray;
    }

    /**
     * èĦç§ğä½èżċ
     *
     * @param array éèĤèżèĦèĦç§ğä½èżċççİéµ
     */
    private static int[,] DeShiftRows(int[,] array)
    {
        int[,] res = new int[4, 4];
        for (int i = 0; i < 4; i++)
        {
            for (int j = 0; j < 4; j++)
            {
                res[i, (j + i) % 4] = array[i, j];
            }
        }

        return res;
    }

    /**
     * ċĉ··ĉ·
     *
     * @param array éèĤèżèĦċĉ··ĉ·çĉ°çğ
     */
    private static int[,] MixColumns(int[,] array)
    {
        int[,] result = new int[4, 4];

        for (int i = 0; i < 4; i++)
        {
            for (int j = 0; j < 4; j++)
            {
                var xorResult = 0;
                for (int k = 0; k < 4; k++)
                {
                    xorResult ^= GFMul(colM[i, k], array[k, j]);
                }

                result[i, j] = xorResult;
            }
        }

        return result;
    }

    /**
     * éċĉ··ĉ·
     *
     * @param array éèĤèżèĦéċĉ··ĉ·ççİéµ
     */
    private static int[,] DeMixColumns(int[,] array)
    {
        int[,] result = new int[4, 4];

        for (int i = 0; i < 4; i++)
        {
            for (int j = 0; j < 4; j++)
            {
                result[i, j] = 0;
                for (int k = 0; k < 4; k++)
                {
                    result[i, j] ^= GFMul(deColM[i, k], array[k, j]);
                }
            }
        }

        return result;
    }

    /**
     * è½?ċŻé?ċ 
     *
     * @param array éèĤċ¤çççİéµ
     * @param round è½?ĉ°
     */
    private static int[,] AddRoundKey(int[,] array, int round)
    {
        int[,] res = new int[4, 4];

        for (int i = 0; i < 4; i++)
        {
            var tmp = w[(round << 2) + i];
            for (int j = 3; j >= 0; j--)
            {
                res[j, i] = tmp & 0xff;
                tmp >>= 8;
            }
        }
        
        for (int i = 0; i < 4; i++)
        {
            for (int j = 0; j < 4; j++)
            {
                res[i, j] ^= array[i, j];
            }
        }

        return res;
    }

    /**
     * ċŻé?ĉċħä¸­çTċ½ĉ°
     */
    private static int T(int num, int round)
    {
        int[] numArray = SplitIntToArray(num);
        numArray = LeftLoop4Int(numArray, 1);

        for (int i = 0; i < 4; i++)
            numArray[i] = GetNumFromSBox(numArray[i]);

        num = MergeArrayToInt(numArray);
        return (int)((uint)num ^ Rcon[round]);
    }

    /**
     * ċŻé?ĉċħċ½ĉ°
     */
    private static void ExtendKey(string key)
    {
        w = new int[44];
        for (int i = 0; i < 4; i++)
        {
            w[i] = ((int)key[i << 2] << 24) |
                ((int)key[(i << 2) + 1] << 16) |
                ((int)key[(i << 2) + 2] << 8) |
                ((int)key[(i << 2) + 3]);
        }

        for (int i = 4; i < 44; i++)
        {
            var temp = w[i - 1];

            if (i % 4 == 0)
                temp = T(temp, i >> 2);

            w[i] = w[i - 4] ^ temp;
        }
    }

    /**
     * ĉ4X4ĉ°çğè½Ĵċċ­çĴĤä¸²
     */
    private static string ConvertArrayToStr(int[,] array)
    {
        string str = "";
        for (int i = 0; i < 4; i++)
            for (int j = 0; j < 4; j++)
                str += ((char)array[j, i]).ToString();
        return str;
    }

    /**
     * ĉ£ĉ?ċŻé?éżċşĤ
     */
    private static bool CheckKeyLen(int len)
    {
        if(len == 16)
            return true;
        else
            return false;
    }

    /**
     * ĉċ°Wĉ°çğ-ĉŻä¸è½?çċŻé?
     */
    private static void PrintW()
    {
        for(int i = 0, j = 1; i < 44; i++, j++)
        {
            Console.Write("w[" + i.ToString() + "] = 0x" + w[i].ToString("x") + " ");
            if(j % 4 == 0)
                Console.WriteLine("");
        }
        Console.WriteLine("");
    }

    /**
     * ĉŻä¸ä¸Şċçğçċ ċŻ,ċżéĦğä¸ş16çċĉ°
     * ċĉ° p: ĉĉçċ­çĴĤä¸²ĉ°çğ?
     * ċĉ° key: ċŻé?çċ­çĴĤä¸²ĉ°çğ?
     */
    public static string Aes(string p, string key)
    {

        if (p.Length == 0 || p.Length % 16 != 0)
        {
            Console.WriteLine("ĉĉċ­çĴĤéżċşĤċżéĦğä¸ş16çċĉ°ïĵ");
            return "";
        }

        if (!CheckKeyLen(key.Length))
        {
            Console.WriteLine("ċŻé?ċ­çĴĤéżċşĤéèŻŻïĵéżċşĤċżéĦğä¸ş16?ċ½ċéżċşĤä¸ş" + key.Length.ToString());
            return "";
        }

        ExtendKey(key);
        PrintW();
        string res = "";
        for (int k = 0; k < p.Length; k += 16)
        {
            var pArray = ConvertToIntArray(p.Substring(k));
            pArray = AddRoundKey(pArray, 0);

            for (int i = 1; i < 10; i++)
            {
                pArray = SubBytes(pArray);
                pArray = ShiftRows(pArray);
                pArray = MixColumns(pArray);
                pArray = AddRoundKey(pArray, i);
            }
            pArray = SubBytes(pArray);
            pArray = ShiftRows(pArray);
            pArray = AddRoundKey(pArray, 10);
            res += ConvertArrayToStr(pArray);
        }

        return res;
    }

    public static string DeAes(string c, string key)
    {
        if (c.Length == 0 || c.Length % 16 != 0)
        {
            Console.WriteLine("ċŻĉċ­çĴĤéżċşĤċżéĦğä¸ş16çċĉ°ïĵç°ċ¨çéżċşĤä¸ş{0}", c.Length);
            return "";
        }

        if (!CheckKeyLen(key.Length))
        {
            Console.WriteLine("ċŻé?ċ­çĴĤéżċşĤéèŻŻïĵéżċşĤċżéĦğä¸ş16?24ċ32?ċ½ċéżċşĤä¸ş{0}", key.Length);
            return "";
        }

        string res = "";
        for (int k = 0; k < c.Length; k += 16)
        {
            var cArray = ConvertToIntArray(c.Substring(k));
            cArray = AddRoundKey(cArray, 10);

            for (int i = 1; i < 10; i++)
            {
                cArray = DeShiftRows(cArray);
                cArray = DeSubBytes(cArray);
                cArray = AddRoundKey(cArray, 10 - i);
                cArray = DeMixColumns(cArray);
            }

            cArray = DeShiftRows(cArray);
            cArray = DeSubBytes(cArray);
            cArray = AddRoundKey(cArray, 0);
            res += ConvertArrayToStr(cArray);
        }

        return res;
    }
}