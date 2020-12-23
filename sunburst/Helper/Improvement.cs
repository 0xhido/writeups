using System;
using System.IO;
using System.Text;
using System.IO.Compression;

namespace Helper {
    public static class ZipHelper
	{
		public static byte[] Compress(byte[] input)
		{
			using MemoryStream memoryStream2 = new MemoryStream(input);
			using MemoryStream memoryStream = new MemoryStream();
			using (DeflateStream destination = new DeflateStream(memoryStream, CompressionMode.Compress))
			{
				memoryStream2.CopyTo(destination);
			}
			return memoryStream.ToArray();
		}

		public static byte[] Decompress(byte[] input)
		{
			using MemoryStream stream = new MemoryStream(input);
			using MemoryStream memoryStream = new MemoryStream();
			using (DeflateStream deflateStream = new DeflateStream(stream, CompressionMode.Decompress))
			{
				deflateStream.CopyTo(memoryStream);
			}
			return memoryStream.ToArray();
		}

		public static string Zip(string input)
		{
			if (string.IsNullOrEmpty(input))
			{
				return input;
			}
			try
			{
				return Convert.ToBase64String(Compress(Encoding.UTF8.GetBytes(input)));
			}
			catch (Exception)
			{
				return "";
			}
		}

		public static string Unzip(string input)
		{
			if (string.IsNullOrEmpty(input))
			{
				return input;
			}
			try
			{
				byte[] bytes = Decompress(Convert.FromBase64String(input));
				return Encoding.UTF8.GetString(bytes);
			}
			catch (Exception)
			{
				return input;
			}
		}
	}
}