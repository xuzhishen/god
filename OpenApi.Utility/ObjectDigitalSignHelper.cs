using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Newtonsoft.Json;

namespace OpenApi.Utility
{
    public class ObjectDigitalSignHelper
    {
        /// <summary>
        /// 获取签名字符串排序
        /// </summary>
        /// <param name="jsonObject"></param>
        /// <returns></returns>
        public static string GetObjectHashString(string jsonObject)
        {
            List<Tuple<string, string>> list = new List<Tuple<string, string>>();

            var dic = JsonConvert.DeserializeObject<Dictionary<string, string>>(jsonObject);
            foreach (var kv in dic)
            {
                if (!string.IsNullOrEmpty(kv.Value) && kv.Value.ToLower() != "null")
                    list.Add(new Tuple<string, string>(kv.Key.ToLower(), kv.Value));
            }
            StringBuilder sb = new StringBuilder();
            foreach (var entity in list.OrderBy(p => p.Item1))
            {
                sb.Append(entity.Item1);
                sb.Append(entity.Item2);
            }

            return sb.ToString();
        }
    }
}
