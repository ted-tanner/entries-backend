use std::time::Duration;

pub struct OtpMessage {}
pub struct UserDeletionConfirmationMessage {}

impl OtpMessage {
    pub fn generate(otp_part1: &str, otp_part2: &str, otp_lifetime: Duration) -> String {
        format!(
            "<html>
               <head>
                 <style>
                   body {{
                     font-family: Arial, sans-serif;
                     text-align: center;
                   }}
                 </style>
               </head>
             <body>
               <h1>Entries App Verification Code</h1>
               <h2 style=\"font-family: 'Courier New', monospace; user-select: all; \
               -webkit-user-select: all;\"><b>{} {}</b></h2>
               <p>We will never ask you for this code over the phone or email. \
               <b>Your code expires in {} minutes.</b></p>
             </body>
             </html>",
            otp_part1,
            otp_part2,
            otp_lifetime.as_secs() / 60,
        )
    }
}

impl UserDeletionConfirmationMessage {
    pub fn generate(url: &str, token: &str, token_lifetime: Duration) -> String {
        let link = format!("{}?UserDeletionToken={}", url, token);

        format!(
            "<html>
               <head>
                 <style>
                   body {{
                     font-family: Arial, sans-serif;
                     text-align: center;
                   }}
                 </style>
               </head>
             <body>
               <h1>Entries App Account Deletion Confirmation Link</h1>
               <p>Clicking the link below will schedule your Entries App account for \
               deletion.</p>
               <p><a href=\"{}\" rel=\"nofollow\">Click here</a></p>
               <p><b>This link will expire in {} days.</b></p>
               <br />
               <p><i>Changed your mind? Just ignore this email and don't click the \
               link.</i></p>
             </body>
             </html>",
            link,
            token_lifetime.as_secs() / (60 * 60 * 24),
        )
    }
}
