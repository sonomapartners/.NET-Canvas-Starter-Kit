using System;

namespace DotNetCanvasStarterKit.Models.Canvas
{
    /// <summary>
    /// The view model for the Canvas Index page.
    /// </summary>
    public class IndexViewModel
    {
        /// <summary>
        /// The client id (Consumer Key) of the connected application used
        /// in the OAuth flow.
        /// </summary>
        public String ClientId { get; set; }
        /// <summary>
        /// The redirect url (Redirect URI) of the connected application used
        /// in the OAuth flow.
        /// </summary>
        public String RedirectUrl { get; set; }
        /// <summary>
        /// Any extra state to pass along. Must be in the form of URL parameters 
        /// (key1=val1&key2=val2). This string will be URL encoded at run time.
        /// </summary>
        public String State { get; set; }
        /// <summary>
        /// The login url provided by Salesforce. Determines if the user is logging 
        /// in against a Sandbox instance, or a Product/Developer instance.
        /// </summary>
        public String LoginUrl { get; set; }
    }
}