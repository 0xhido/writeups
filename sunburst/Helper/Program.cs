using System;
using System.IO;
using System.Text;
using System.IO.Compression;
using System.Text.RegularExpressions;

namespace Helper
{
    public class Program
    {
        public static void CreateUnzippedFile(string zippedFilePath, string unzippedFilePath) {
            string text = File.ReadAllText(zippedFilePath);
            
            string regexPattern = "ZipHelper\\.Unzip\\(\\\"(.*?)\\\"\\)";
            string replaced = Regex.Replace(text, regexPattern, m => "\"" +  ZipHelper.Unzip(m.Groups[1].Value).Replace("\\", "\\\\").Replace("\"", "\\\"") + "\"" );

            File.WriteAllText(unzippedFilePath, replaced);
        }

        public static void Main()
        {
            ImprovementBusinessLayer.Initialize();
        }
    }
}

