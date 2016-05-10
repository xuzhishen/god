using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Text;
using System.Threading.Tasks;
using Newtonsoft.Json;

namespace OpenApi.Utility
{
    public static class OpenApiClient
    {
        /// <summary>
        /// 授权地址
        /// </summary>
        private const string AUTHORIZE_URL = "https://ac.ppdai.com/oauth2/authorize";

        /// <summary>
        /// 刷新Token地址
        /// </summary>
        private const string REFRESHTOKEN_URL = "https://ac.ppdai.com/oauth2/refreshtoken ";

        /// <summary>
        /// 开始时间
        /// </summary>
        private static readonly DateTime beginDate = new DateTime(1970, 1, 1);

        /// <summary>
        /// 向拍拍贷网关发送请求
        /// </summary>
        /// <param name="url">请求地址</param>
        /// <param name="request">请求参数</param>
        /// <param name="appid">应用编号</param>
        /// <param name="privateKey">私钥</param>
        /// <param name="sign">签名</param>
        /// <param name="accessToken">授权token</param>
        /// <returns></returns>
        public static Result Send(string url, string request, string appid, string privateKey, string accessToken = null)
        {

            WebClient client = new WebClient();
            /*========================这部分为公共请求参数===========================*/
            client.Headers.Add("Content-Type", "application/json;charset=utf-8");
            string timestamp = Convert.ToUInt32((DateTime.UtcNow - OpenApiClient.beginDate).TotalSeconds).ToString();
            client.Headers.Add("X-PPD-TIMESTAMP", timestamp);
            client.Headers.Add("X-PPD-TIMESTAMP-SIGN", RsaCryptoHelper.SignByPrivateKey(privateKey, appid + timestamp));
            client.Headers.Add("X-PPD-APPID", appid);
            client.Headers.Add("X-PPD-SIGN", RsaCryptoHelper.SignByPrivateKey(privateKey,ObjectDigitalSignHelper.GetObjectHashString(request)));
            if (!string.IsNullOrEmpty(accessToken)) client.Headers.Add("X-PPD-ACCESSTOKEN", accessToken);
            /*======================================================================*/

            try
            {
                byte[] responseData = client.UploadData(url, "POST", Encoding.UTF8.GetBytes(request));//得到返回字符流  
                string strResponse = Encoding.UTF8.GetString(responseData);
                return new Result() { IsSucess = true, Context = strResponse };
            }
            catch (WebException ex)
            {
                WebResponse response = ex.Response;
                using (Stream errdata = response.GetResponseStream())
                {
                    if (errdata != null)
                    {
                        using (var reader = new StreamReader(errdata))
                        {
                            return new Result() { ErrorMessage = reader.ReadToEnd() };
                        }
                    }
                    return new Result() { ErrorMessage = ex.Message };
                }
            }
            catch (Exception ex)
            {
                return new Result() { ErrorMessage = ex.Message };
            }
        }

        /// <summary>
        /// 授权
        /// </summary>
        /// <param name="appid"></param>
        /// <param name="code"></param>
        /// <returns></returns>
        public static AuthInfo Authorize(string appid, string code)
        {
            string request = string.Format("{{\"AppID\":\"{0}\",\"code\":\"{1}\"}}", appid, code);

            WebClient client = new WebClient();
            client.Headers.Add("Content-Type", "application/json;charset=utf-8");
            byte[] responseData = client.UploadData(AUTHORIZE_URL, "POST", Encoding.UTF8.GetBytes(request));//得到返回字符流  
            string strResponse = Encoding.UTF8.GetString(responseData);
            return JsonConvert.DeserializeObject<AuthInfo>(strResponse);
        }

        /// <summary>
        /// 刷新token
        /// </summary>
        /// <param name="appid"></param>
        /// <param name="openId"></param>
        /// <param name="refreshToken"></param>
        /// <returns></returns>
        public static AuthInfo RefreshToken(string appid, string openId, string refreshToken)
        {
            string request = string.Format("{{\"AppID\":\"{0}\",\"OpenID\":\"{1}\",\"RefreshToken\":\"{2}\"}}", appid, openId, refreshToken);

            WebClient client = new WebClient();
            client.Headers.Add("Content-Type", "application/json;charset=utf-8");
            byte[] responseData = client.UploadData(REFRESHTOKEN_URL, "POST", Encoding.UTF8.GetBytes(request));//得到返回字符流  
            string strResponse = Encoding.UTF8.GetString(responseData);
            return JsonConvert.DeserializeObject<AuthInfo>(strResponse);
        }
    }
}
