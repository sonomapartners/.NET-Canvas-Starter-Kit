using DotNetCanvasStarterKit.Models.Canvas;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using System;
using System.Configuration;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Web.Mvc;

namespace DotNetCanvasStarterKit.Controllers
{
    /// <summary>
    /// An MVC5 based controller for handling Salesforce.com Canvas authentication.
    /// </summary>
    public class CanvasController : Controller
    {
        /// <summary>
        /// The entry point for the canvas OAuth flow. If the request was sent by canvas, there will be
        /// a _sfdc_canvas_auth = user_approval_required parameter set.
        /// </summary>
        /// 
        /// <param name="loginUrl">
        /// The url to use when authenticating against salesforce. Needed to determine if we're 
        /// authenticating against a sandbox or product/dev instance.
        /// </param>
        /// 
        /// <param name="_sfdc_canvas_auth">
        /// Set to user_approval_required if the request came from a canvas application, null otherwise.
        /// </param>
        /// 
        /// <param name="otherParams">
        /// Additional params passed in the url.
        /// </param>
        [HttpGet]
        public ActionResult Index(String loginUrl, String _sfdc_canvas_auth, String otherParams)
        {
            // check if request came from canvas
            if (_sfdc_canvas_auth == "user_approval_required")
            {
                // request came from canvas
                var clientId = ConfigurationManager.AppSettings["client_id"];
                var redirectUrl = ConfigurationManager.AppSettings["redirect_url"];

                // login page doesn't allow framing
                // since we're already in an iframe, we need to use the JS library
                // provided by Salesforce to start the OAuth prompt
                return View(new IndexViewModel
                {
                    ClientId = clientId,
                    LoginUrl = loginUrl,
                    RedirectUrl = redirectUrl,
                    State = null
                });
            }
            else
                // request didn't come from canvas, change as appropriate
                return RedirectToAction("Index", "Home");
        }

        /// <summary>
        /// The entry point for the Signed Request auth flow, and the end of the canvas OAuth flow.
        /// </summary>
        /// 
        /// <param name="signed_request">
        /// A signed, JSON blob containing all of the requested information about the user, as well 
        /// as access tokens, refresh tokens, instance urls, etc.
        /// </param>
        [HttpPost]
        public ActionResult Index(String signed_request)
        {
            if (signed_request == null)
                throw new ArgumentNullException("signed_request");

            var clientSecret = ConfigurationManager.AppSettings["client_secret"];
            // need to verify the signature to prevent man in the middle attacks
            var signedRequest = VerifyAndDecode(signed_request, clientSecret);

            // if you've reached this point, your user is authenticated
            // change as needed
            return View("DisplayResult", null, JsonConvert.SerializeObject(signedRequest));
        }

        /// <summary>
        /// Called as part of the OAuth flow. This signals that the OAuth flow has completed succesfully.
        /// In a normal application, you could handle this by logging the user in directly, but in our case
        /// we had to pop an extra window. This callback gets called from the popped window, not the original one
        /// so we need to return a page which will just close itself. The original window will ask Salesforce
        /// to resend the signed JSON blob containing everything we need when this window is closed.
        /// </summary>
        public ActionResult Callback()
        {
            return View();
        }

        private JObject VerifyAndDecode(string signed_request, string clientSecret)
        {
            if (signed_request.IndexOf('.') == -1)
                throw new ArgumentException("The 'signed request' doesn't appear to be a real signed request.");

            String[] parts = signed_request.Split('.');

            String encodedSignature = parts[0];
            String encodedEnvelope = parts[1];

            String jsonEnvelope = Encoding.UTF8.GetString(Convert.FromBase64String(encodedEnvelope));

            var envelope = JObject.Parse(jsonEnvelope);
            var algorithm = envelope["algorithm"].Value<String>() ?? "HMACSHA256";

            Verify(clientSecret, algorithm, encodedEnvelope, encodedSignature);

            return envelope;
        }

        private void Verify(string clientSecret, string algorithm, string encodedEnvelope, string encodedSignature)
        {
            HMAC mac = null;

            if (algorithm == "HMACSHA256")
                mac = new HMACSHA256(Encoding.UTF8.GetBytes(clientSecret));
            else
                throw new ArgumentException(String.Format("Unsupported algorith: {0}", algorithm));

            try
            {
                var digest = mac.ComputeHash(Encoding.UTF8.GetBytes(encodedEnvelope));
                var decodedSignature = Convert.FromBase64String(encodedSignature);

                if (!Enumerable.SequenceEqual(digest, decodedSignature))
                    throw new Exception("Digest and signature did not match");
            }
            finally
            {
                mac.Dispose();
            }
        }
    }
}