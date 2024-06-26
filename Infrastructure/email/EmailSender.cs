using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.Extensions.Configuration;
using SendGrid;
using SendGrid.Helpers.Mail;

namespace Infrastructure.email
{
    public class EmailSender
    {
        private readonly IConfiguration _config;
        public EmailSender(IConfiguration config){
            this._config = config;
            
        }

        public async Task SendEmailAsync(string userEmail, string emailSubject, string msg)
        {
            var client = new SendGridClient(_config["SendGrid:Key"]);
            var message = new SendGridMessage
            {
                From = new EmailAddress("ernestdalehodge@outlook.com", _config["SendGrid:User"]),
                Subject = emailSubject,
                PlainTextContent = msg,
                HtmlContent =msg                
            };
            message.AddTo(new EmailAddress(userEmail));
            message.SetClickTracking(false, false);

            await client.SendEmailAsync(message);
        }
    }
}