use std::time::Duration;

pub struct OtpMessage {}

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
               <h2 style=\"font-family: 'Courier New', monospace; user-select: all;
               -webkit-user-select: all;\"><b>{} {}</b></h2>
               <p>We will never ask you for this code over the phone or email.
               <b>Your code expires in {} minutes.</b></p>
             </body>
             </html>",
            otp_part1,
            otp_part2,
            otp_lifetime.as_secs() / 60,
        )
    }
}
