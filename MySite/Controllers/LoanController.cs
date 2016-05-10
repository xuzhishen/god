using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using System.Web.Mvc;
using MySite.Models;
using Newtonsoft.Json;
using OpenApi.Utility;

namespace MySite.Controllers
{
    public class LoanController : Controller
    {
        /// <summary>
        /// 接口请求地址
        /// </summary>
        public const string Get_LoanList_URL = "http://gw.open.ppdai.com/invest/BidproductlistService/LoanList";

        /// <summary>
        /// 可投标列表获取
        /// </summary>
        /// <returns></returns>
        // GET: Loan
        public ActionResult Index()
        {
            try
            {
                AuthInfo auth = Session["auth"] as AuthInfo;
                if (auth == null)
                    return Redirect("/auth");

                var now = DateTime.Now;
                string request = string.Format("{{\"timestamp\": \"{0}\"}}", now);

                //多个参数的情况下需要按照字典排序进行拼装参数信息
                string toSignString = ObjectDigitalSignHelper.GetObjectHashString(request);

                string sign = RsaCryptoHelper.SignByPrivateKey(AppProperty.AppPrivateKey, toSignString);

                Result result = OpenApiClient.Send(Get_LoanList_URL, request, AppProperty.AppID, AppProperty.AppPrivateKey, auth.AccessToken);

                if (result.IsSucess)
                {

                    var model = JsonConvert.DeserializeObject<LoanListModels>(result.Context);

                    if (model.Result == 0)
                    {
                        string param = Request.QueryString["query"];

                        if (!string.IsNullOrEmpty(param))
                        {
                            param = param.Trim();

                            if (param == "AAA")
                            {
                                model.LoanList = model.LoanList.Where(p => p.CreditCode == "AAA").ToList();
                            }
                            else if (param == "rate")
                            {
                                model.LoanList = model.LoanList.Where(p => p.Rate >= 22).ToList();
                            }
                            else if (param == "cur") {
                                model.LoanList = model.LoanList.Where(p => p.Rate >= 22 && p.CreditCode != "E" && p.CreditCode != "F"
                                && (p.Degree == "本科" || p.Degree == "硕士" || p.Degree == "博士") && p.Age < 35).ToList();
                            }
                        }

                        model.LoanList = model.LoanList.OrderByDescending(p => p.Rate).ToList();
                        return View("List", model.LoanList);
                    }
                    else
                        return Content(model.ResultMessage);
                }
                else
                {
                    return Content(result.ErrorMessage);
                }
            }
            catch (FormatException ex)
            {
                return Content("密钥无效，请更换有效密钥");
            }
            catch (Exception ex)
            {
                return Content(ex.Message);
            }
        }


    }
}